"""
abi pass: the ABI decoder prologue of a known-name function becomes the
declaration solc regenerates from it, and the body reads typed parameters.

  run     for an entry point with a keccak-verified signature:
            * the leading decoder checks (the `if (c) revert()` chain after
              the memory seed, Panic(0x41) allocation checks included) are
              classified against the checks the target compiler's decoder
              makes for the declared parameter types: the calldata head
              size, the value validators (address, uintN, bool, intN, bytesN
              in their legacy and via-IR forms), enum ranges, the offset /
              length / bounds checks of dynamic parameters (ABI coder v2 and
              v1 forms), the Panic(0x41) checks of parameters decoded to
              memory.  A check is removed only when the target decoder makes
              the same check before the body runs (the same predicate of the
              calldata, the same payload: see _removable), or when an earlier
              check of the chain makes it unreachable; every other check
              stays where it is;
            * a `uint8` parameter whose check is an enum range `P < K`
              becomes an enum of K members (same selector: enums are uint8 in
              the ABI, and the target decoder validates the range the same
              way);
            * `bytes` / `string` / array parameters are declared `memory`
              when the original decoded them to memory (a Panic(0x41) on
              lengths the allocation cannot hold, where the calldata decoder
              reverts without data), else `calldata`;
            * the head words `calldataload(4 + 32 w)` become `Param(w)` (the
              renderer writes the declared parameter; the length word and
              the bytes of a dynamic parameter are written `p.length` / `p`);
            * return types are refined from the returned words where the
              database gave no output types: comparisons and 0 / 1
              constants -> bool, addresses, bytesN / intN / uintN cleanups;
              a constant or sliced byte string returned in the standard
              encoding -> `string memory` / `bytes memory` (the database's
              kind when it has one).
          for a routed function (no known name), the parameters are first
          declared from the decoder checks (see _route): the router decodes
          them with abi.decode, which makes the checks a declared signature's
          decoder makes; the rest is the same.  A routed function the pass
          cannot type (or with the pass switched off) is left alone: the
          router calls its private body, which reads the calldata itself.
  finish  declares the enums.

Every check the pass cannot prove redundant stays.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from scobelix.solgen import abi, ir
from scobelix.solgen.types import SolType, fits, is_boolean, low_zero_bits, max_bits, parse_type, sign_extended

LEVELS = ("full",)

_BOUND_V2 = (1 << 64) - 1  # offsets and lengths above it: ABI coder v2 decoders revert
_BOUND_V1 = 1 << 32  # ABI coder v1 (solc 0.5 - 0.7, and 0.8 with `pragma abicoder v1`)
_CDS = ir.Env("calldatasize")
_PANIC41 = ir.Panic(0x41)


# ---------------------------------------------------------------- the declared layout


@dataclasses.dataclass
class _Layout:
    total: int  # head words of the declared parameters
    values: Dict[int, Tuple[int, SolType]]  # head word -> (parameter index, value type)
    dynamic: Dict[int, Tuple[int, SolType]]  # head word -> (parameter index, dynamic type)
    # parameter index -> (first head word, head words, type) of the structs
    # and fixed-size arrays (static, inline in the head, or dynamic)
    composite: Dict[int, Tuple[int, int, SolType]] = dataclasses.field(default_factory=dict)


def _layout(params: Sequence[Tuple[SolType, str]]) -> _Layout:
    values, dynamic, composite, word = {}, {}, {}, 0
    for i, (t, _) in enumerate(params):
        if t.is_dynamic:
            dynamic[word] = (i, t)
        elif t.is_value:
            values[word] = (i, t)
        if t.kind == "tuple" or (t.kind == "array" and t.length is not None):
            composite[i] = (word, t.head_words, t)
        word += t.head_words
    return _Layout(word, values, dynamic, composite)


_stride = abi.length_stride  # bytes per element of a bounds check (bytes / string: 1, T[]: element size)


# ---------------------------------------------------------------- the prologue


def _single_revert(block: Sequence[ir.Stmt]) -> Optional[ir.Payload]:
    """The payload of a block that is one `revert()` / Panic(0x41)."""
    if len(block) == 1 and isinstance(block[0], ir.Revert) and block[0].payload in (ir.Empty(), _PANIC41):
        return block[0].payload
    return None


def _prologue(body: Sequence[ir.Stmt]) -> Tuple[List[tuple], Tuple[ir.Stmt, ...]]:
    """The leading chain of decoder checks: items ("seed", stmt) for the
    memory writes between them and the loops that copy a parameter to
    memory (abi.decoder_loop: the checks of the next parameters follow
    them), ("check", stmt, cond, payload, where) with `cond` reverting when
    it holds; and the rest of the body."""
    items: List[tuple] = []
    block = list(body)
    while block:
        s = block[0]
        if isinstance(s, ir.Mstore) or (len(block) > 1 and abi.decoder_loop(s)):
            items.append(("seed", s))
            block = block[1:]
            continue
        if isinstance(s, ir.Require) and s.payload in (ir.Empty(), _PANIC41):
            items.append(("check", s, ir.Op("iszero", (s.cond,)), s.payload, "require"))
            block = block[1:]
            continue
        if isinstance(s, ir.If) and len(block) == 1:
            p = _single_revert(s.then)
            if p is not None:
                items.append(("check", s, s.cond, p, "then"))
                block = list(s.orelse)
                continue
            p = _single_revert(s.orelse)
            if p is not None:
                items.append(("check", s, ir.Op("iszero", (s.cond,)), p, "else"))
                block = list(s.then)
                continue
        break
    return items, tuple(block)


def _rebuild(items: Sequence[tuple], removed: Set[int], rest: Tuple[ir.Stmt, ...]) -> Tuple[ir.Stmt, ...]:
    """The body with the kept checks in their original form and order."""
    tail = list(rest)
    for i in reversed(range(len(items))):
        it = items[i]
        if it[0] == "seed":
            tail = [it[1]] + tail
        elif i not in removed:
            stmt, where = it[1], it[4]
            if where == "require":
                tail = [stmt] + tail
            elif where == "then":
                tail = [ir.If(stmt.cond, stmt.then, tuple(tail))]
            else:
                tail = [ir.If(stmt.cond, tuple(tail), stmt.orelse)]
    return tuple(tail)


# ---------------------------------------------------------------- check shapes


def _add_terms(e: ir.Expr) -> Optional[List[ir.Expr]]:
    """The operands of an (n-ary, nested) add; None for anything else."""
    if not (isinstance(e, ir.Op) and e.op == "add"):
        return None
    out: List[ir.Expr] = []
    for a in e.args:
        inner = _add_terms(a)
        out.extend(inner if inner is not None else [a])
    return out


def _is(e, op: str, n: int = 2) -> bool:
    return isinstance(e, ir.Op) and e.op == op and len(e.args) == n


def _const_plus_word(e: ir.Expr, k: int) -> Optional[int]:
    """Head word w when e is `k + <head word w>`."""
    terms = _add_terms(e)
    if terms is None or len(terms) != 2:
        return None
    for a, b in ((terms[0], terms[1]), (terms[1], terms[0])):
        w = abi._head_word(b)
        if a == ir.Const(k) and w is not None:
            return w
    return None


def _length_word(e: ir.Expr) -> Optional[int]:
    """w when e is the length word of dynamic parameter w: calldataload(4 + OFF)."""
    if isinstance(e, ir.CalldataWord):
        return _const_plus_word(e.offset, 4)
    return None


def _scaled_length(e: ir.Expr) -> Optional[Tuple[int, int]]:
    """(w, stride) when e is LEN_w times a constant stride (1, 32, 64, ...:
    a shift by k for the powers of two, a multiplication otherwise)."""
    w = _length_word(e)
    if w is not None:
        return w, 1
    if isinstance(e, ir.Mask) and e.offset == 0 and isinstance(e.shl, int) and 5 <= e.shl < 16 \
            and e.size in (256, 256 - e.shl):
        w = _length_word(e.value)
        return None if w is None else (w, 1 << e.shl)
    if _is(e, "shl") and isinstance(e.args[0], ir.Const) and 5 <= e.args[0].value < 16:
        w = _length_word(e.args[1])
        return None if w is None else (w, 1 << e.args[0].value)
    if _is(e, "mul"):
        for a, b in ((e.args[0], e.args[1]), (e.args[1], e.args[0])):
            w = _length_word(b)
            if isinstance(a, ir.Const) and w is not None and a.value % 32 == 0 and 0 < a.value < 1 << 16:
                return w, a.value
    return None


def _alloc_term(e: ir.Expr) -> Optional[int]:
    """w when e is the allocation size of dynamic parameter w's data:
    ceil32(LEN_w) (bytes / string), 32 * LEN_w or ceil32(32 * LEN_w)
    (arrays); the rounding mask is mask_shl(251, 5, 0) or the optimiser's
    mask_shl(256, 5, 0) (the same word: x >> 5 has 251 bits)."""
    if isinstance(e, ir.Mask) and (e.size, e.offset, e.shl) in ((251, 5, 0), (256, 5, 0)):
        terms = _add_terms(e.value)
        if terms is not None and len(terms) == 2 and ir.Const(31) in terms:
            inner = terms[1] if terms[0] == ir.Const(31) else terms[0]
            scaled = _scaled_length(inner)
            return scaled[0] if scaled is not None and scaled[1] in (1, 32) else None
        return None
    scaled = _scaled_length(e)
    return scaled[0] if scaled is not None and scaled[1] == 32 else None


def _alloc_size(e: ir.Expr) -> Optional[Tuple[int, ...]]:
    """The dynamic words whose data sizes `e` = constant + sizes adds up."""
    terms = _add_terms(e)
    if terms is None:
        return None
    words = []
    consts = 0
    for t in terms:
        if isinstance(t, ir.Const):
            consts += 1
            continue
        w = _alloc_term(t)
        if w is None:
            return None
        words.append(w)
    return tuple(words) if consts == 1 and words else None


def _alloc_base(cond: ir.Expr) -> Optional[int]:
    """The constant of the size an allocation check (`p41_alloc`) tests: the
    free memory pointer its decoder started from, plus 32 (a length word)
    for each value allocated up to this one."""
    if _is(cond, "mul") and cond.args[0] == ir.const(-1):
        return _alloc_base(cond.args[1])
    if _is(cond, "or"):
        a, b = cond.args
        for big, wrap in ((a, b), (b, a)):
            if _is(big, "gt") and big.args[1] == ir.Const(_BOUND_V2) and _is(wrap, "lt") \
                    and wrap.args[0] == big.args[0]:
                consts = [t.value for t in _add_terms(big.args[0]) or () if isinstance(t, ir.Const)]
                return consts[0] if len(consts) == 1 else None
    return None


def _bound(e: ir.Expr) -> Optional[int]:
    return e.value if isinstance(e, ir.Const) and e.value in (_BOUND_V2, _BOUND_V1) else None


def _classify(cond: ir.Expr, payload: ir.Payload) -> Optional[tuple]:
    """What decoder check `cond` (reverting when it holds) is."""
    if _is(cond, "mul") and cond.args[0] == ir.const(-1):
        return _classify(cond.args[1], payload)  # via-IR unoptimised: the negated dirty bits
    if payload == _PANIC41:
        if _is(cond, "gt") and cond.args[1] == ir.Const(_BOUND_V2):
            w = _length_word(cond.args[0])
            return None if w is None else ("p41_length", w)
        if _is(cond, "or"):
            a, b = cond.args
            for big, wrap in ((a, b), (b, a)):
                if _is(big, "gt") and big.args[1] == ir.Const(_BOUND_V2) and _is(wrap, "lt") \
                        and wrap.args[0] == big.args[0]:
                    words = _alloc_size(big.args[0])
                    return None if words is None else ("p41_alloc", words)
        return None
    # the calldata head size: slt / lt(calldatasize - 4, 32 H)
    if _is(cond, "slt") or _is(cond, "lt"):
        a, k = cond.args
        terms = _add_terms(a)
        if isinstance(k, ir.Const) and terms is not None and len(terms) == 2 and set(terms) == {ir.const(-4), _CDS} \
                and k.value % 32 == 0 and k.value < 32 * abi._MAX_HEAD_WORDS:
            return ("head", k.value)
    # enum range, as the decoder writes it: P >= K reverts (iszero(lt(P, K)), or iszero(gt(K, P)))
    if _is(cond, "iszero", 1) and (_is(cond.args[0], "lt") or _is(cond.args[0], "gt")):
        p, k = cond.args[0].args if cond.args[0].op == "lt" else cond.args[0].args[::-1]
        w = abi._head_word(p)
        if w is not None and isinstance(k, ir.Const) and 0 < k.value <= 256:
            return ("enum", w, k.value)
    if _is(cond, "gt"):
        x, k = cond.args
        b = _bound(k)
        if b is not None:
            w = abi._head_word(x)
            if w is not None:
                return ("dyn_offset", w, b)
            w = _length_word(x)
            if w is not None:
                return ("dyn_length", w, b)
        if k == _CDS:
            terms = _add_terms(x)
            if terms is not None and len(terms) == 2 and ir.Const(36) in terms:
                w = abi._head_word(terms[1] if terms[0] == ir.Const(36) else terms[0])
                if w is not None:
                    return ("dyn_end_v1", w)
            if terms is not None and len(terms) == 3 and ir.Const(36) in terms:
                rest = [t for t in terms if t != ir.Const(36)]
                for off, ln in ((rest[0], rest[1]), (rest[1], rest[0])):
                    w, scaled = abi._head_word(off), _scaled_length(ln)
                    if w is not None and scaled is not None and scaled[0] == w:
                        return ("dyn_bounds", w, scaled[1])
    # the end of the length word: 35 + OFF >= calldatasize (signed, as solc writes it)
    if _is(cond, "iszero", 1):
        inner = cond.args[0]
        if _is(inner, "slt") and inner.args[1] == _CDS:
            w = _const_plus_word(inner.args[0], 35)
            if w is not None:
                return ("dyn_end", w)
        if _is(inner, "sgt") and inner.args[0] == _CDS:
            w = _const_plus_word(inner.args[1], 35)
            if w is not None:
                return ("dyn_end", w)
    # ABI coder v1: length bound and data bounds in one test
    if _is(cond, "or"):
        a, b = cond.args
        for ln, bounds in ((a, b), (b, a)):
            if _is(ln, "gt") and _bound(ln.args[1]) is not None:
                w = _length_word(ln.args[0])
                tail = _classify(bounds, payload)
                if w is not None and tail is not None and tail[0] == "dyn_bounds" and tail[1] == w:
                    return ("dyn_tail_v1", w, _bound(ln.args[1]), tail[2])
    v = abi.validator(cond)  # (the enum range form was taken above)
    if v is not None and v[1] != "dynamic":
        return ("value", v[0], v[1])
    # the identity validator of a full-width type, kept by unoptimised
    # builds: iszero(eq(P, P)), which never holds
    if _is(cond, "iszero", 1) and _is(cond.args[0], "eq") and cond.args[0].args[0] == cond.args[0].args[1]:
        w = abi._head_word(cond.args[0].args[0])
        if w is not None:
            return ("value", w, "identity")
    return None


# ---------------------------------------------------------------- the decision


def _locations(checks: Sequence[tuple], lay: _Layout, abi_v2: bool) -> Dict[int, str]:
    """Head word -> data location of each dynamic parameter: memory when the
    original decoded it to memory (a Panic(0x41) on its length before any
    empty revert on it), else calldata."""
    out = {}
    for w, (_, t) in lay.dynamic.items():
        loc = "calldata"
        if abi_v2 and _stride(t) is not None:
            for c in checks:
                if c is not None and c[0] == "p41_length" and c[1] == w:
                    loc = "memory"
                    break
                if c is not None and c[0] == "dyn_length" and c[1] == w:
                    break
        out[w] = loc
    return out


def _reads_inside(e: ir.Node, w: int, k: int, dynamic: bool) -> bool:
    """`e` reads a calldata word inside the parameter at head words
    [w, w + k): at an offset computed from its head offset (a dynamic
    parameter; the head offset word itself is not inside), or one of its
    head words (a static one)."""
    head = ir.CalldataWord(ir.Const(4 + 32 * w))
    for n in ir.walk(e):
        if not isinstance(n, ir.CalldataWord):
            continue
        if dynamic:
            if n != head and any(x == head for x in ir.walk(n.offset)):
                return True
        elif isinstance(n.offset, ir.Const) and 4 + 32 * w <= n.offset.value < 4 + 32 * (w + k):
            return True
    return False


def _loop_inside(loop: ir.Stmt, w: int, k: int, dynamic: bool) -> bool:
    """A copy loop that reads the parameter at head words [w, w + k): its
    calldata pointer starts inside it, or it reads inside it directly."""
    starts = {a.target.name: a.value for a in loop.init if isinstance(a, ir.Assign) and isinstance(a.target, ir.Local)}
    head = ir.CalldataWord(ir.Const(4 + 32 * w))
    for n in ir.walk(loop):
        if not isinstance(n, ir.CalldataWord):
            continue
        for x in ir.walk(n.offset):
            v = starts.get(x.name) if isinstance(x, ir.Local) else None
            if v is None:
                continue
            if dynamic and any(y == head for y in ir.walk(v)):
                return True
            if not dynamic and isinstance(v, ir.Const) and 4 + 32 * w <= v.value < 4 + 32 * (w + k):
                return True
    return _reads_inside(loop, w, k, dynamic)


def _later_decoder_check(c: Optional[tuple], lay: _Layout) -> Optional[int]:
    """The parameter a check only the decoder makes belongs to: the offset
    check of a dynamic parameter, the validator of a narrow value one."""
    if c is None:
        return None
    if c[0] == "dyn_offset" and c[1] in lay.dynamic and c[2] == _BOUND_V2:
        return lay.dynamic[c[1]][0]
    if c[0] == "value" and c[1] in lay.values and lay.values[c[1]][1].canonical == c[2]:
        return lay.values[c[1]][0]
    return None


def _panicking_decoders(metadata: Optional[dict], items: Sequence[tuple]) -> bool:
    """The original's memory decoders raise Panic(0x41) on allocation sizes
    (solc >= 0.8, by the CBOR version, else by such a check in the chain);
    earlier ones revert without data."""
    meta = metadata or {}
    nums = re.findall(r"\d+", str(meta.get("version") or ""))
    if meta.get("compiler") == "solc" and len(nums) >= 2:
        return (int(nums[0]), int(nums[1])) >= (0, 8)
    return any(it[0] == "check" and it[3] == _PANIC41 for it in items)


def _composite_locations(items: Sequence[tuple], classes: Dict[int, Optional[tuple]], lay: _Layout,
                         abi_v2: bool, panics: bool = True) -> Dict[int, str]:
    """Parameter index -> data location of each struct / fixed-size array
    parameter.  memory: the original decoded it to memory, i.e. read its
    members (a member offset or value check, a copy loop starting in it)
    before the first check the decoder makes for a later parameter (see
    _later_decoder_check).  Else calldata: the members of a calldata
    parameter are read by the body only, after every decoder check, and
    without a later decoder check the calldata declaration is exact either
    way (the target's checks are then a prefix of the original's, the
    member checks the body keeps follow them in their order).  A type with
    dynamic members stays calldata when the original's decoders do not
    panic (`panics` False, before 0.8): the target's memory decoder would
    raise Panic(0x41) on the allocations where the original reverts without
    data, and with every check of the original reverting without data the
    order of the checks is not observable."""
    out: Dict[int, str] = {}
    for i, (w, k, t) in lay.composite.items():
        loc, seen = "calldata", False
        for idx, it in enumerate(items) if abi_v2 and (panics or not t.is_dynamic) else ():
            owner = _later_decoder_check(classes.get(idx), lay)
            if owner is not None and owner > i:
                loc = "memory" if seen else "calldata"
                break
            if it[0] == "check":
                seen = seen or _reads_inside(it[2], w, k, t.is_dynamic)
            elif isinstance(it[1], (ir.While, ir.For)):
                seen = seen or _loop_inside(it[1], w, k, t.is_dynamic)
        out[i] = loc
    return out


def _removable(c: tuple, lay: _Layout, abi_v2: bool, enums: Dict[int, int]) -> bool:
    """The target decoder of the declared signature reverts on every
    calldata on which check `c` holds, before the body runs: `c` can never
    fire in the generated body, so dropping it changes nothing.  This holds
    when `c` is one of the decoder's own predicates (the same test of the
    same calldata words; which payload the decoder reverts with is decided
    by the declaration, not by the check), or is implied by them:

      head size        the decoder checks `calldatasize - 4 < 32 H` for the
                       declared head size H;
      value validator  the decoder validates the declared type the same way
                       (ABI coder v2);
      enum range       the parameter is declared as an enum of K members,
                       which the decoder rejects from K on (v2);
      dynamic offset / length word end / length bound / data bounds
                       the v2 decoder makes each of them (calldata or memory
                       location; a Panic(0x41) on the length is the length
                       bound again); the v1 decoder tests the length bound
                       and the data bounds in one `or`, which holds whenever
                       either does.  The offset and the end of the head
                       word are tested for every dynamic type (the size
                       check of a struct or a fixed-size array implies the
                       end); the length checks only for the types with a
                       length word (bytes, string, T[]): the word at the
                       head offset of a struct is its first member, that of
                       a fixed-size array its first element (an offset the
                       memory decoder checks, the calldata decoder not);
      allocation Panic the memory decoder of the target panics on at least
                       the same sizes (its free memory pointer is never
                       below the original's 0x80), and the calldata decoder
                       bounds the length by the calldata size (which no
                       transaction brings near 2**64) before.
    """
    kind = c[0]
    if kind == "head":
        return c[1] == 32 * lay.total
    if kind == "value":
        got = lay.values.get(c[1])
        if c[2] == "identity":  # a full-width type: its cleanup is the identity
            return abi_v2 and got is not None and got[1].kind in ("uint", "int", "bytes") and got[1].bits == 256
        return abi_v2 and got is not None and got[1].canonical == c[2]
    if kind == "enum":
        got = lay.values.get(c[1])
        if not (abi_v2 and got is not None and got[1].canonical == "uint8"):
            return False
        if c[2] == 256:
            return True  # P < 256: the uint8 validator itself
        if got[0] in enums:
            return False  # a second range check of the word: user code, kept
        enums[got[0]] = c[2]
        return True
    if kind == "p41_alloc":
        return abi_v2 and all(x in lay.dynamic and _stride(lay.dynamic[x][1]) is not None for x in c[1])
    w = c[1]
    if w not in lay.dynamic:
        return False
    stride = _stride(lay.dynamic[w][1])
    if kind == "dyn_offset":
        return c[2] == (_BOUND_V2 if abi_v2 else _BOUND_V1)
    if kind == "dyn_end":
        return abi_v2
    if kind == "dyn_end_v1":
        return not abi_v2
    if stride is None:
        return False  # no length word (see above)
    if kind in ("dyn_length", "p41_length"):
        return (c[2] if kind == "dyn_length" else _BOUND_V2) == (_BOUND_V2 if abi_v2 else _BOUND_V1)
    if kind == "dyn_bounds":
        return c[2] == stride
    if kind == "dyn_tail_v1":
        return not abi_v2 and c[2] == _BOUND_V1 and c[3] == stride
    return False


# ---------------------------------------------------------------- parameters


def _param_index(c: tuple, lay: _Layout) -> int:
    """The parameter a classified check belongs to (-1: the head size)."""
    if c[0] == "head":
        return -1
    if c[0] == "p41_alloc":
        return max((lay.dynamic[w][0] for w in c[1] if w in lay.dynamic), default=-1)
    got = lay.values.get(c[1]) if c[0] in ("value", "enum") else lay.dynamic.get(c[1])
    return got[0] if got is not None else -1


def _select(checks: Sequence[tuple], classes: Sequence[Optional[tuple]], lay: _Layout, abi_v2: bool,
            enums: Dict[int, int]) -> Set[int]:
    """The chain indices of the checks to remove, in chain order.  An enum
    range `P < K` is declared as an enum only where the decoder validates
    the parameter: in the leading run of removed checks, after the checks
    of the earlier parameters only, and without a value validator of the
    same word (the decoder of an enum makes none); a range check anywhere
    else is the body's own test, and declaring an enum would move it
    before the checks of the later parameters, whose payload may differ (a
    Panic(0x41) on a memory parameter)."""
    validated = {c[1] for c in classes if c is not None and c[0] == "value"}
    removed: Set[int] = set()
    decoder, last = True, -1
    for (idx, _), c in zip(checks, classes):
        ok = c is not None
        if ok and c[0] == "enum" and c[2] != 256:
            got = lay.values.get(c[1])
            ok = decoder and got is not None and got[0] >= last and c[1] not in validated
        if ok and _removable(c, lay, abi_v2, enums):
            removed.add(idx)
            last = max(last, _param_index(c, lay))
        else:
            decoder = False
    return removed


def _name_params(body, total: int):
    """calldataload(4 + 32 w) -> Param(w) for the declared head words."""

    def fx(n):
        if isinstance(n, ir.CalldataWord) and isinstance(n.offset, ir.Const):
            off = n.offset.value
            if off >= 4 and (off - 4) % 32 == 0 and (off - 4) // 32 < total:
                return ir.Param((off - 4) // 32)
        return n

    return ir.transform(body, fx)


def _enum_name(k: int) -> str:
    return f"Enum{k}"


def _enum_declaration(k: int) -> str:
    # the same text the storage pass declares for an enum of k members
    return f"enum {_enum_name(k)} {{ " + ", ".join(f"V{i}" for i in range(k)) + " }"


# ---------------------------------------------------------------- returns


def _returns(body) -> List[ir.Return]:
    return [n for n in ir.walk_all(body) if isinstance(n, ir.Return)]


def _words(data) -> Optional[List[ir.Expr]]:
    if data is None:
        return []
    parts = data.parts if isinstance(data, ir.Blob) else (data,)
    out = []
    for p in parts:
        if not (isinstance(p, ir.WordBytes) and p.width == 32):
            return None
        out.append(p.value)
    return out


_ADDRESS_ENV = frozenset({"caller", "origin", "address", "coinbase"})


def _address_shaped(e: ir.Expr, valid: Dict[int, SolType]) -> bool:
    if isinstance(e, ir.Mask) and (e.size, e.offset, e.shl) == (160, 0, 0):
        return True
    if isinstance(e, ir.Env) and e.name in _ADDRESS_ENV:
        return True
    if isinstance(e, (ir.StateRef, ir.Cast)) and e.ty == "address":
        return True
    if isinstance(e, ir.Field) and ir.field_bits(e.size) == 160 and isinstance(e.value, ir.Sload):
        return True
    if isinstance(e, ir.CallOut) and e.what == "address":
        return True
    w = abi._head_word(e)
    return w is not None and valid.get(w) is not None and valid[w].canonical == "address"


def _uint_shape(e: ir.Expr) -> Optional[int]:
    """N when e is the uintN cleanup of a word (a mask or a storage field)."""
    if isinstance(e, ir.Mask) and e.offset == 0 and e.shl == 0 and isinstance(e.size, int) \
            and e.size % 8 == 0 and 8 <= e.size < 256:
        return e.size
    if isinstance(e, ir.Field) and isinstance(e.value, ir.Sload):
        n = ir.field_bits(e.size)
        if n is not None and n % 8 == 0 and 8 <= n < 256:
            return n
    if isinstance(e, ir.StateRef):
        try:
            t = parse_type(e.ty)
        except ValueError:
            return None
        return t.bits if t.kind == "uint" and t.bits < 256 else None
    return None


def _bytes_shape(e: ir.Expr) -> Optional[int]:
    """N when e is a left-aligned bytesN word."""
    if isinstance(e, ir.Mask) and isinstance(e.size, int) and e.shl == 0 and e.size % 8 == 0 \
            and 8 <= e.size < 256 and e.offset == 256 - e.size:
        return e.size // 8
    if isinstance(e, ir.StateRef) and e.ty.startswith("bytes") and e.ty != "bytes":
        try:
            return parse_type(e.ty).bits // 8
        except ValueError:
            return None
    return None


def _column_type(words: Sequence[ir.Expr], valid: Dict[int, SolType]) -> Optional[SolType]:
    """A narrower return type every returned word provably fits, from the
    cleanups the code applies (dispatch analysis, return types) and the
    validated parameters returned as they are; None keeps uint256."""
    consts = [w for w in words if isinstance(w, ir.Const)]
    shaped = [w for w in words if not isinstance(w, ir.Const)]
    params = [valid.get(abi._head_word(w)) if abi._head_word(w) is not None else None for w in shaped]
    if shaped and all(p is not None for p in params) and len({p.canonical for p in params}) == 1 \
            and params[0].canonical != "uint256" and all(fits(c, params[0]) for c in consts):
        return params[0]
    if all(is_boolean(w) for w in words) and (shaped or any(c.value == 1 for c in consts)):
        return parse_type("bool")
    if shaped and all(max_bits(w) <= 160 for w in words) and any(_address_shaped(w, valid) for w in shaped):
        return parse_type("address")
    ns = [_bytes_shape(w) for w in shaped]
    if shaped and all(n is not None for n in ns):
        n = max(ns)
        t = parse_type(f"bytes{n}")
        if all(fits(w, t) or low_zero_bits(w) >= 256 - 8 * n for w in words):
            return t
    bs = [sign_extended(w) for w in shaped]
    if shaped and all(b is not None for b in bs) and len(set(bs)) == 1 and not consts:
        return parse_type(f"int{8 * (bs[0] + 1)}")
    ns = [_uint_shape(w) for w in shaped]
    if shaped and all(n is not None for n in ns):
        t = parse_type(f"uint{max(ns)}")
        if all(fits(w, t) for w in words):
            return t
    return None


def _standard_string(data) -> Optional[ir.Bytes]:
    """The byte string a return blob encodes as one dynamic value (offset
    32, length, data, zero padding to a word): constant, or a slice of L
    bytes padded with the lifter's zero bytes."""
    if not isinstance(data, ir.Blob) or len(data.parts) < 2:
        return None
    head, length, payload = data.parts[0], data.parts[1], data.parts[2:]
    if head != ir.WordBytes(ir.Const(32)) or not (isinstance(length, ir.WordBytes) and length.width == 32):
        return None
    n = ir.evaluate(length.value)
    if n is not None:
        raw = ir.const_bytes(ir.Blob(tuple(payload)))
        if raw is None or n > len(raw) or len(raw) != (n + 31) // 32 * 32 or any(raw[n:]):
            return None
        return ir.ConstBytes(raw[:n])
    if len(payload) == 2 and isinstance(payload[0], (ir.CalldataSlice, ir.MemSlice, ir.ReturnData)) \
            and payload[0].length == length.value and isinstance(payload[1], ir.ZeroBytes):
        pad = ir.Op("and", (ir.Op("sub", (ir.ZERO, length.value)), ir.Const(31)))
        if payload[1].length == pad:
            return payload[0]
    return None


def _refine_returns(fn: ir.Function, spec, ctx) -> ir.Function:
    """spec.returns from the returned words (see the module docstring)."""
    rets = _returns(fn.body)
    if not rets or ir.contains(fn.body, ir.Stop) or any(r.values is not None for r in rets):
        return fn
    strings = [_standard_string(r.data) for r in rets]
    if all(s is not None for s in strings):
        db = spec.db_returns
        if db is not None and len(db) == 1 and db[0].kind in ("dynbytes", "string"):
            kind = "bytes" if db[0].kind == "dynbytes" else "string"
        else:
            kind = "string"
            if any(isinstance(s, ir.ConstBytes) for s in strings):
                try:
                    b"".join(s.data for s in strings if isinstance(s, ir.ConstBytes)).decode("utf-8")
                except UnicodeDecodeError:
                    kind = "bytes"
        spec.returns = (parse_type(kind),)
        table = {id(r): ir.Return(None, (s,)) for r, s in zip(rets, strings)}
        return fn.with_body(ir.transform(fn.body, lambda n: table.get(id(n), n)))
    if spec.returns is None or spec.db_returns is not None:
        return fn  # the database's output types are the declaration (the words fit them, or are uint256)
    shapes = [_words(r.data) for r in rets]
    if any(s is None or len(s) != len(spec.returns) for s in shapes):
        return fn
    valid = _validated(spec, ctx.abi_v2)
    out = []
    for i, t in enumerate(spec.returns):
        if t.canonical == "uint256":
            col = _column_type([s[i] for s in shapes], valid)
            if col is not None:
                t = col
        out.append(t)
    spec.returns = tuple(out)
    return fn


def _validated(spec, abi_v2: bool) -> Dict[int, SolType]:
    """Head word -> value type the decoder validated (ABI coder v2)."""
    out: Dict[int, SolType] = {}
    if abi_v2 and spec.typed:
        word = 0
        for t, _ in spec.params:
            if t.is_value:
                out[word] = t
            word += t.head_words
    return out


# ---------------------------------------------------------------- routed functions

_DYNAMIC_CHECKS = frozenset({"dyn_offset", "dyn_length", "dyn_end", "dyn_end_v1", "dyn_bounds", "dyn_tail_v1",
                             "p41_length", "p41_alloc"})
_UINT256 = parse_type("uint256")
_BYTES = parse_type("bytes")
_FREE_MEMORY = 0x80  # the free memory pointer when the router's abi.decode runs


def _route(fn: ir.Function, spec, abi_v2: bool, items: Sequence[tuple],
           classes: Sequence[Optional[tuple]]) -> Optional[str]:
    """Declare the parameters of a routed function from its decoder checks
    so that the router decodes them with `abi.decode(input[4:], (T1, ...,
    Tn))` (contract.py); None when done, else why the function stays
    untyped (its private body then reads the calldata itself).

    The parameters are the head words H of the calldata size check, each
    of the type its validator checks (ABI coder v2; a word without one, and
    every word under ABI coder v1, is a uint256: no check).  A validator
    counts in the decoder's order only: a check of a word made after a
    check of a later word is the body's own and stays in the body.  For these
    types the target's abi.decode of the calldata after the selector makes
    the original decoder's checks: the size check (`calldatasize - 4 < 32
    H`, signed or not: the same for any calldata of 4 bytes or more) and
    the validators of the same words, each reverting without data like the
    original's, so these checks are removed exactly as for a declared
    signature.  The head word of a dynamic parameter (its offset) is
    handed over as the raw uint256 word: abi.decode would copy the value
    to memory and panic on lengths where a calldata parameter reverts
    without data, so the original's offset, length and bounds checks stay
    in the body, in their order, after the decoder's.  That order is not
    observable when every check of the chain reverts without data, which
    the Panic(0x41) of a parameter decoded to memory breaks.  When every
    dynamic parameter is a byte string decoded to memory (ABI coder v2:
    the Panic on its length comes first, its bounds check has stride 1),
    they are declared `bytes memory` instead: abi.decode then is the
    original's own decoder (the same checks in the same order, the same
    Panic(0x41) payloads, the same free memory pointer 0x80 when it runs:
    the constant of the original's allocation checks tells where its own
    started, above 0x80 when its compiler moved locals to memory, and such
    a decoder panics on other lengths), so its checks are removed like
    those of a declared signature.  Any other function with a Panic(0x41)
    in its chain stays untyped.
    Without a size check, a function that reads no argument takes none.
    Only the checks of the chain that revert without data or with a
    recognised Panic(0x41) count (_prologue stops at a check that halts
    otherwise, INVALID: it stays in the body, and the word it checks is a
    uint256)."""
    memory: Set[int] = set()  # head words of byte strings decoded to memory
    if any(it[0] == "check" and it[3] == _PANIC41 for it in items):
        memory = _memory_strings(spec, classes, abi_v2, [(it[2], it[3]) for it in items if it[0] == "check"])
        if not memory:
            return "memory parameter"
    sizes = {c[1] // 32 for c in classes if c is not None and c[0] == "head"}
    if len(sizes) > 1:
        return "several calldata size checks"
    if sizes:
        head = sizes.pop()
    elif abi.reads_arguments(fn) or "unstructured" in fn.flags:  # (untranslated code may read them)
        return "no calldata size check"
    else:
        head = 0
    validated: Dict[int, str] = {}  # head word -> the type its validator checks (the first one)
    words = set()  # every head word a check of the chain is about
    last = -1  # the highest head word the checks so far were about
    for c in classes:
        if c is None or c[0] == "head":
            continue
        if c[0] == "p41_alloc":
            last = max((last,) + tuple(c[1]))
            continue
        words.add(c[1])
        # a decoder checks the words in their order: a check of a word after
        # one of a later word is the body's (its own range test, a calldata
        # array member validated when read), and abi.decode would make it
        # before the later word's checks (a Panic(0x41) on a byte string)
        if c[1] >= last:
            if c[0] == "value" and c[2] != "identity":
                validated.setdefault(c[1], c[2])
            elif c[0] == "enum":
                validated.setdefault(c[1], "uint8")  # P < K: the abi pass below may declare an enum of K members
        last = max(last, c[1])
    if any(w >= head for w in words | set(spec.inferred) | set(spec.dynamic_words)):
        return "validator outside the head"
    returns = abi.declared_returns(fn, None)
    if head + (len(returns) if returns else 1) > abi.WRAP_SLOTS:
        return "too many parameters for the stack"
    params = []
    taken: set = set()
    for w in range(head):
        t = _BYTES if w in memory else _UINT256
        if abi_v2 and w in validated and w not in memory:
            try:
                t = parse_type(validated[w])
            except ValueError:
                return "unknown validator type"
        params.append((t, abi._param_name("", w, taken)))
    spec.params = tuple(params)
    spec.returns = returns
    spec.typed_route = True
    return None


FLAG_MEMORY_START = "abi:memory_start_above_0x80"


def _allocates_elsewhere(checks: Sequence[Tuple[int, tuple]], classes: Sequence[Optional[tuple]]) -> bool:
    """The original's decoder allocates the values it decodes to memory
    from a free memory pointer other than 0x80 (its compiler moved locals
    to memory): the constant of an allocation check is not 0x80 plus the
    length words allocated up to it."""
    for (_, it), c in zip(checks, classes):
        if c is not None and c[0] == "p41_alloc":
            base = _alloc_base(it[2])
            if base is not None and base != _FREE_MEMORY + 32 * len(c[1]):
                return True
    return False


def _memory_strings(spec, classes: Sequence[Optional[tuple]], abi_v2: bool,
                    checks: Sequence[Tuple[ir.Expr, ir.Payload]]) -> Set[int]:
    """The head words of the dynamic parameters of a chain with Panic(0x41)
    checks when each of them is a byte string decoded to memory (see
    _route), else the empty set.  `checks`: the (condition, payload) of
    each check of the chain."""
    if not abi_v2:
        return set()
    if any(c is None and p == _PANIC41 for c, (_, p) in zip(classes, checks)):
        return set()  # a Panic check of another form: its place in the order is unknown
    allocated: Set[int] = set()  # the words whose allocation check is the target decoder's
    for c, (cond, _) in zip(classes, checks):
        # the target's decoder allocates from _FREE_MEMORY: an original that
        # starts elsewhere (locals its compiler moved to memory) panics on
        # other lengths than abi.decode in the router would
        if c is not None and c[0] == "p41_alloc":
            if _alloc_base(cond) != _FREE_MEMORY + 32 * len(c[1]):
                return set()
            allocated.update(c[1])
    dynamic = {c[1] for c in classes if c is not None and c[0] in _DYNAMIC_CHECKS and c[0] != "p41_alloc"}
    dynamic |= {w for c in classes if c is not None and c[0] == "p41_alloc" for w in c[1]}
    dynamic |= set(spec.dynamic_words) | {w for w, t in spec.inferred.items() if t == "dynamic"}
    strides = {}
    for c in classes:
        if c is not None and c[0] == "dyn_bounds":
            strides.setdefault(c[1], c[2])
    for w in dynamic:
        first = next((c[0] for c in classes if c is not None and c[0] in ("p41_length", "dyn_length") and c[1] == w),
                     None)
        if first != "p41_length" or strides.get(w) != 1 or w not in allocated:
            # a calldata parameter, an array (its elements' checks are in the
            # copy loop), or no allocation check to tell where the memory starts
            return set()
    return dynamic


# ---------------------------------------------------------------- the pass


def run(fn: ir.Function, ctx) -> ir.Function:
    spec = ctx.specs.get(fn.key)
    if spec is None or spec.kind != "function":
        return fn
    items, rest = _prologue(fn.body)
    checks = [(i, it) for i, it in enumerate(items) if it[0] == "check"]
    classes = [_classify(it[2], it[3]) for _, it in checks]
    facts = ctx.facts.setdefault("abi", {"functions": {}, "enums": set()})
    if spec.signature is None:
        why = _route(fn, spec, ctx.abi_v2, items, classes) if not spec.typed_route else None
        if why is not None:
            facts["functions"][fn.key] = {"route": "untyped", "why": why}
            return fn
    lay = _layout(spec.params)
    locations = _locations(classes, lay, ctx.abi_v2)
    if spec.signature is not None and _allocates_elsewhere(checks, classes):
        # (a named function: the selector needs the declared parameters,
        # whose decoder runs first and allocates from 0x80: it panics on
        # fewer lengths near 2**64 than the original's; said on the function)
        spec.flags.add(FLAG_MEMORY_START)
    enums: Dict[int, int] = {}  # parameter index -> members
    removed = _select(checks, classes, lay, ctx.abi_v2, enums)
    body = _rebuild(items, removed, rest) if removed else fn.body
    body = _name_params(body, lay.total) if lay.total else body
    for i, k in enums.items():
        spec.type_names[i] = _enum_name(k)
        facts["enums"].add(k)
    for w, loc in locations.items():
        spec.locations[lay.dynamic[w][0]] = loc
    spec.locations.update(_composite_locations(items, {idx: c for (idx, _), c in zip(checks, classes)}, lay,
                                               ctx.abi_v2, _panicking_decoders(ctx.metadata, items)))
    new = fn if body == fn.body else fn.with_body(body)
    new = _refine_returns(new, spec, ctx)
    # kept: decoder-shaped checks the declaration does not account for;
    # unmatched: checks of the leading chain that are no decoder form (user
    # code such as `if (x == 7) revert()`, or a form not recognised)
    kept = sum(1 for (idx, _), c in zip(checks, classes) if c is not None and idx not in removed)
    facts["functions"][fn.key] = {
        "checks": len(checks), "removed": len(removed), "kept": kept,
        "unmatched": sum(1 for c in classes if c is None),
        "params": len(spec.params), "prologue_removed": kept == 0,
    }
    if spec.typed_route:
        facts["functions"][fn.key]["route"] = "typed"
        # head offsets of dynamic parameters handed over as raw words (the others: `bytes memory`)
        dynamic = {w for w, t in spec.inferred.items() if t == "dynamic"} | set(spec.dynamic_words) \
            | {c[1] for c in classes if c is not None and c[0] in _DYNAMIC_CHECKS and c[0] != "p41_alloc"}
        facts["functions"][fn.key]["raw_words"] = sum(
            1 for w in dynamic if w < len(spec.params) and spec.params[w][0].kind != "dynbytes")
        facts["functions"][fn.key]["memory_bytes"] = sum(1 for t, _ in spec.params if t.kind == "dynbytes")
    return new


def finish(ctx) -> None:
    for k in sorted((ctx.facts.get("abi") or {}).get("enums") or ()):
        ctx.declare("struct", _enum_declaration(k))

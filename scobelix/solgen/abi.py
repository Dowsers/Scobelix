"""
ABI facts of the entry points: what contract assembly declares and what the
renderer needs to stay exact.

  * parameters: the signature database for known selectors (a keccak-
    verified candidate whose head size and types agree with the ABI decoder
    checks of the body), else the types the decoder's validators reveal
    (the parameters of a routed function, see passes/abi.py);
  * head size: the calldata size check `slt(calldatasize - 4, 32 * H)`
    (`lt` with ABI coder v1);
  * static return words: when every return statement returns the same
    number of 32-byte words, they become declared return values;
  * mutability: pure / view / nonpayable from the effects of the body
    (dispatch-function C4), payable from the dispatcher's hoisted callvalue
    check and the body's own leading check (C3);
  * ABI coder: v2 when some decoder validates a narrow parameter or checks
    the head size signed (or the compiler is 0.8, where v2 is the default,
    unless every decoder is a v1 one: `pragma abicoder v1`).

The validator shapes recognised (P = calldata head word, revert(0) when the
condition holds):

    legacy, ABI coder v2       iszero(eq(P, mask(P)))  mask: mask_shl(160,0,0) address,
                               mask_shl(N,0,0) uintN, bool(P) bool,
                               signextend(b, P) int(8(b+1)), mask_shl(8N,256-8N,0) bytesN
    via-IR (optimised)         mask_shl(96,160,0,P) address, mask_shl(256-N,N,0,P) uintN,
                               P - bool(P) (or bool(P) - P) bool, P - signextend(b,P),
                               P - mask_shl(8N,256-8N,0,P) or mask_shl(256-8N,0,0,P) bytesN
    via-IR (unoptimised)       mul(-1, <one of the above>): the negated dirty bits
    enum                       iszero(lt(P, K)) (P >= K): an enum of K members (uint8)
    dynamic                    gt(P, 2**64-1): P is the head offset of a dynamic value
                               (ABI coder v1: gt(P, 2**32))
"""

from __future__ import annotations

import dataclasses
import re
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from scobelix.solgen import ir, sigs
from scobelix.solgen.render import reserved_name
from scobelix.solgen.types import SolType, fits, parse_type

__all__ = [
    "EntrySpec",
    "MUTABILITY_ORDER",
    "analyse_entry",
    "head_checks",
    "mutability",
    "strip_callvalue_check",
    "uses_abi_v2",
]

MUTABILITY_ORDER = ("pure", "view", "nonpayable", "payable")
# stack slots of parameters + return values above which a body does not take
# its parameters on the stack (contract assembly runs it in a private
# function reading the calldata; a routed function stays untyped)
WRAP_SLOTS = 5
_ADDRESS = parse_type("address")
_UINT256 = parse_type("uint256")


@dataclasses.dataclass
class EntrySpec:
    """What the contract declares for one entry point."""

    key: str  # "0x<selector>" | "_fallback" | "_receive"
    kind: str  # function | fallback | receive
    selector: Optional[int] = None
    name: Optional[str] = None  # known name (sigdb, keccak-verified)
    signature: Optional[str] = None
    params: Tuple[Tuple[SolType, str], ...] = ()
    inferred: Dict[int, str] = dataclasses.field(default_factory=dict)  # head word -> validator type
    head_words: Optional[int] = None
    dynamic_words: FrozenSet[int] = frozenset()
    payable: bool = False
    mutability: str = "nonpayable"
    returns: Optional[Tuple[SolType, ...]] = None  # declared return types (None: raw returns)
    db_returns: Optional[Tuple[SolType, ...]] = None  # the database's output types (None: unknown)
    db_mutability: Optional[str] = None  # trusted database prior (never above nonpayable)
    flags: set = dataclasses.field(default_factory=set)
    candidates: int = 0  # signature candidates considered
    # set by the abi pass: data location of a reference parameter (index ->
    # "calldata" | "memory"; default calldata) and the declared type text of
    # a parameter whose ABI type is not its Solidity type (an enum: "Enum3")
    locations: Dict[int, str] = dataclasses.field(default_factory=dict)
    type_names: Dict[int, str] = dataclasses.field(default_factory=dict)
    # set by the abi pass on a routed function whose parameters the router
    # decodes with abi.decode (params / returns typed from the decoder
    # checks): the private function takes typed parameters
    typed_route: bool = False
    # set by the modifiers pass: the modifiers the function declares (their
    # checks were the first statements of its body)
    modifiers: Tuple[str, ...] = ()

    @property
    def routed(self) -> bool:
        return self.kind == "function" and self.signature is None

    @property
    def typed(self) -> bool:
        """The parameters are declared: a known signature, or a routed
        function the router decodes (the target's decoder validated the
        declared value types before the body runs, under ABI coder v2)."""
        return self.signature is not None or self.typed_route


# ---------------------------------------------------------------- body prologue


def _is_plain_revert(block: Sequence[ir.Stmt]) -> bool:
    return len(block) == 1 and (
        (isinstance(block[0], ir.Revert) and isinstance(block[0].payload, ir.Empty))
        or isinstance(block[0], ir.Invalid)
    )


def _is_seed(stmt: ir.Stmt) -> bool:
    """A memory write before the body's first test: the memory state the
    decompiler seeds a function with (free memory pointer, zero slot, what
    the dispatcher path wrote).  Memory is not observable when a check
    reverts, so the checks after it are still the body's first ones."""
    return isinstance(stmt, ir.Mstore)


def _seed_prefix(body: Sequence[ir.Stmt]) -> int:
    k = 0
    while k < len(body) and _is_seed(body[k]):
        k += 1
    return k


def _test_callvalue(cond: ir.Expr) -> Optional[bool]:
    """True: cond holds iff callvalue != 0; False: iff callvalue == 0."""
    if cond == ir.Env("callvalue"):
        return True
    if isinstance(cond, ir.Op) and cond.op == "iszero":
        inner = _test_callvalue(cond.args[0])
        return None if inner is None else not inner
    if isinstance(cond, ir.Op) and cond.op == "gt" and cond.args == (ir.Env("callvalue"), ir.ZERO):
        return True
    return None


def strip_callvalue_check(fn: ir.Function) -> Tuple[ir.Function, bool]:
    """Remove the body's leading `if (callvalue) revert()` (after the memory
    seed), which solc emits again for a non-payable declaration."""
    body = fn.body
    k = _seed_prefix(body)
    if k < len(body) and isinstance(body[k], ir.If) and len(body) == k + 1:
        stmt = body[k]
        cv = _test_callvalue(stmt.cond)
        for reverting, rest in ((stmt.then, stmt.orelse), (stmt.orelse, stmt.then)):
            if cv is (reverting is stmt.then) and _is_plain_revert(reverting):
                # solc's own check reverts; a check ending in INVALID (old
                # compilers) halts differently
                extra = ("abi:callvalue_check_invalid",) if isinstance(reverting[0], ir.Invalid) else ()
                return fn.with_body(body[:k] + rest, extra), True
    return fn, False


def _is_decoder_revert(block: Sequence[ir.Stmt]) -> bool:
    """A plain revert, or the Panic(0x41) a decoder raises on the length
    of a parameter it copies to memory (the checks of the parameters after
    it follow)."""
    return _is_plain_revert(block) or (
        len(block) == 1 and isinstance(block[0], ir.Revert) and block[0].payload == ir.Panic(0x41))


_LOOP_STMTS = (ir.If, ir.Revert, ir.Require, ir.Mstore, ir.Assign, ir.Continue, ir.Break, ir.While, ir.For)


def decoder_loop(stmt: ir.Stmt) -> bool:
    """A loop that only reads, tests, writes memory and reverts (without
    data, or with the Panic(0x41) of an allocation): the decoder's copy of
    a parameter to memory, its element checks inside.  The checks of the
    parameters after it follow it."""
    if not isinstance(stmt, (ir.While, ir.For)):
        return False
    for n in ir.walk(stmt):
        if isinstance(n, ir.Stmt) and not isinstance(n, _LOOP_STMTS):
            return False
        if isinstance(n, (ir.Revert, ir.Require)) and n.payload not in (ir.Empty(), ir.Panic(0x41)):
            return False
        if isinstance(n, ir.Assign) and not isinstance(n.target, ir.Local):
            return False
    return True


def head_checks(body: Sequence[ir.Stmt]) -> List[ir.Expr]:
    """Conditions of the leading `if (c) revert()` chain (the ABI decoder's
    checks come first in a function body; its Panic(0x41) checks of memory
    parameters are part of it, and so are the checks after the loop that
    copies a parameter to memory), each normalised to "reverts when the
    condition holds"."""
    out = []
    block = list(body[_seed_prefix(body):])
    while True:
        while len(block) > 1 and (decoder_loop(block[0]) or _is_seed(block[0])):
            block = block[1:]
        if not (len(block) == 1 and isinstance(block[0], ir.If)):
            break
        stmt = block[0]
        if _is_decoder_revert(stmt.then):
            out.append(stmt.cond)
            block = list(stmt.orelse)
        elif _is_decoder_revert(stmt.orelse):
            out.append(ir.Op("iszero", (stmt.cond,)))
            block = list(stmt.then)
        else:
            break
    return out


# ---------------------------------------------------------------- validators


def _head_word(e: ir.Expr) -> Optional[int]:
    if isinstance(e, ir.CalldataWord) and isinstance(e.offset, ir.Const):
        off = e.offset.value
        if off >= 4 and (off - 4) % 32 == 0:
            return (off - 4) // 32
    if isinstance(e, ir.Param):
        return e.index
    return None


def _mask_type(m: ir.Expr, p: ir.Expr) -> Optional[str]:
    """The type whose cleanup is `m` applied to `p` (legacy validators)."""
    if isinstance(m, ir.Mask) and m.value == p and all(isinstance(x, int) for x in (m.size, m.offset, m.shl)):
        size, off, shl = m.size, m.offset, m.shl
        if off == 0 and shl == 0 and size % 8 == 0 and 8 <= size < 256:
            return "address" if size == 160 else f"uint{size}"
        if shl == 0 and size % 8 == 0 and size + off == 256 and off > 0:
            return f"bytes{size // 8}"
    if isinstance(m, ir.Op) and m.op == "iszero" and isinstance(m.args[0], ir.Op) and m.args[0].op == "iszero" \
            and m.args[0].args[0] == p:
        return "bool"
    if isinstance(m, ir.Op) and m.op == "signextend" and m.args[1] == p and isinstance(m.args[0], ir.Const) \
            and m.args[0].value < 31:
        return f"int{8 * (m.args[0].value + 1)}"
    return None


def validator(cond: ir.Expr) -> Optional[Tuple[int, str]]:
    """(head word, type) when `cond` is an ABI decoder validator."""
    if isinstance(cond, ir.Op) and cond.op == "mul" and len(cond.args) == 2 and cond.args[0] == ir.const(-1):
        return validator(cond.args[1])  # unoptimised via-IR tests the negated dirty bits
    # legacy: iszero(eq(P, cleanup(P)))
    if isinstance(cond, ir.Op) and cond.op == "iszero" and isinstance(cond.args[0], ir.Op) \
            and cond.args[0].op == "eq":
        a, b = cond.args[0].args
        for p, m in ((a, b), (b, a)):
            w = _head_word(p)
            if w is not None:
                t = _mask_type(m, p)
                if t is not None:
                    return w, t
    # via-IR: the dirty bits themselves
    if isinstance(cond, ir.Mask) and all(isinstance(x, int) for x in (cond.size, cond.offset, cond.shl)):
        w = _head_word(cond.value)
        if w is not None and cond.shl == 0 and cond.size + cond.offset == 256 and cond.offset % 8 == 0 \
                and 8 <= cond.offset < 256:
            return w, "address" if cond.offset == 160 else f"uint{cond.offset}"
        # bytesN: the dirty bits are the low 256 - 8N ones
        if w is not None and cond.shl == 0 and cond.offset == 0 and cond.size % 8 == 0 and 8 <= cond.size <= 248:
            return w, f"bytes{(256 - cond.size) // 8}"
    if isinstance(cond, ir.Op) and cond.op in ("add", "sub", "xor") and len(cond.args) == 2:
        a, b = cond.args
        if isinstance(b, ir.Op) and b.op == "mul" and len(b.args) == 2 and b.args[0] == ir.const(-1):
            b = b.args[1]
        for p, m in ((a, b), (b, a)):
            w = _head_word(p)
            if w is not None:
                t = _mask_type(m, p)
                if t is not None:
                    return w, t
    # enums: P >= K, as iszero(lt(P, K)) or iszero(gt(K, P))
    if isinstance(cond, ir.Op) and cond.op == "iszero" and isinstance(cond.args[0], ir.Op) \
            and cond.args[0].op in ("lt", "gt"):
        p, k = cond.args[0].args if cond.args[0].op == "lt" else cond.args[0].args[::-1]
        w = _head_word(p)
        if w is not None and isinstance(k, ir.Const) and 0 < k.value <= 256:
            return w, "uint8"
    if isinstance(cond, ir.Op) and cond.op == "gt" and isinstance(cond.args[1], ir.Const) \
            and cond.args[1].value == 2**64 - 1:
        w = _head_word(cond.args[0])
        if w is not None:
            return w, "dynamic"
    return None


def length_stride(t: SolType) -> Optional[int]:
    """Bytes per element the decoder's bounds check multiplies the length of
    a type with a length word by: 1 for bytes / string, the element head
    size for T[]; None for the other types."""
    if t.kind in ("dynbytes", "string"):
        return 1
    if t.kind == "array" and t.length is None:
        return 32 * t.base.head_words
    return None


def _bounds_strides(checks: Sequence[ir.Expr]) -> Dict[int, int]:
    """Head word -> stride of the bounds check the decoder makes on the data
    of the dynamic parameter at that word (the check shapes are the abi
    pass's: passes/abi._classify)."""
    from scobelix.solgen.passes import abi as decoder  # (it imports this module)

    out: Dict[int, int] = {}
    for c in checks:
        k = decoder._classify(c, ir.Empty())
        if k is not None and k[0] == "dyn_bounds":
            out.setdefault(k[1], k[2])
        elif k is not None and k[0] == "dyn_tail_v1":
            out.setdefault(k[1], k[3])
    return out


def _v1_offset(cond: ir.Expr) -> Optional[int]:
    """w when cond is gt(P, 2**32): the ABI coder v1 check of a head offset
    (under v2, a test of the code's own)."""
    if isinstance(cond, ir.Op) and cond.op == "gt" and cond.args[1] == ir.Const(1 << 32):
        return _head_word(cond.args[0])
    return None


def head_size(checks: Sequence[ir.Expr]) -> Optional[int]:
    """Head words H of the calldata size check slt(calldatasize - 4, 32 H)."""
    for c in checks:
        if isinstance(c, ir.Op) and c.op in ("slt", "lt") and isinstance(c.args[1], ir.Const):
            a = c.args[0]
            if isinstance(a, ir.Op) and a.op == "add" and set(a.args) == {ir.const(-4), ir.Env("calldatasize")}:
                k = c.args[1].value
                if k % 32 == 0 and k < 32 * 1024:
                    return k // 32
    return None


def uses_abi_v2(functions: Sequence[ir.Function]) -> bool:
    """Some decoder validates a narrow parameter, or checks the head size
    signed (`slt`; v1 decoders test `lt`): ABI coder v2."""
    for fn in functions:
        for c in head_checks(fn.body):
            if head_size([c]) is not None and c.op == "slt":
                return True
            v = validator(c)
            if v is not None and v[1] != "dynamic":
                return True
    return False


def uses_abi_v1(functions: Sequence[ir.Function]) -> bool:
    """Every decoder is an ABI coder v1 one (solc 0.8 with `pragma abicoder
    v1`): some head size check, each one unsigned (`lt`; v2 decoders test
    `slt`), and no validator."""
    seen = False
    for fn in functions:
        for c in head_checks(fn.body):
            if head_size([c]) is not None:
                if c.op == "slt":
                    return False
                seen = True
            v = validator(c)
            if v is not None and v[1] != "dynamic":
                return False
    return seen


# ---------------------------------------------------------------- mutability


_ENV_READS = frozenset({
    "caller", "origin", "callvalue", "timestamp", "number", "chainid", "difficulty", "prevrandao",
    "gasprice", "coinbase", "gaslimit", "basefee", "blobbasefee", "gas", "address", "selfbalance",
})
_READ_NODES = (ir.Sload, ir.TLoad, ir.Balance, ir.ExtCodeSize, ir.ExtCodeHash, ir.ExtCodeSlice,
               ir.BlockHash, ir.BlobHash, ir.Precompile, ir.ReturnData, ir.CallOut, ir.StateRef)
_WRITE_NODES = (ir.Sstore, ir.TStore, ir.Log, ir.Create, ir.SelfDestruct, ir.Unstructured,
                ir.UnstructuredExpr, ir.UnstructuredBytes, ir.Emit)


def mutability(fn: ir.Function) -> str:
    """pure / view / nonpayable from what the body does (payable is decided
    by the callvalue checks, not here)."""
    level = 0
    for n in ir.walk_all(fn.body):
        if isinstance(n, _WRITE_NODES):
            return "nonpayable"
        if isinstance(n, ir.ExtCall):
            if n.kind != "staticcall":
                return "nonpayable"
            level = 1
        elif isinstance(n, _READ_NODES):
            level = 1
        elif isinstance(n, ir.Env) and n.name in _ENV_READS:
            level = 1
        elif isinstance(n, ir.Assign) and not isinstance(n.target, ir.Local):
            return "nonpayable"
    return MUTABILITY_ORDER[level]


# ---------------------------------------------------------------- returns


def _returns(body) -> List[ir.Return]:
    return [n for n in ir.walk_all(body) if isinstance(n, ir.Return)]


def _static_words(data: Optional[ir.Bytes]) -> Optional[List[ir.Expr]]:
    """The words of a return blob made only of 32-byte words."""
    if data is None:
        return []
    parts = data.parts if isinstance(data, ir.Blob) else (data,)
    words = []
    for p in parts:
        if not (isinstance(p, ir.WordBytes) and p.width == 32):
            return None
        words.append(p.value)
    return words


def declared_returns(fn: ir.Function, outputs: Optional[Tuple[SolType, ...]]) -> Optional[Tuple[SolType, ...]]:
    """Return types to declare: one per word when every return statement
    returns the same number of 32-byte words; each the database's type when
    every returned word fits it, else uint256.  None: raw returns."""
    rets = _returns(fn.body)
    if not rets:
        return None
    shapes = [_static_words(r.data) for r in rets if r.values is None]
    if any(s is None for s in shapes) or not shapes:
        return None
    k = len(shapes[0])
    if k == 0 or any(len(s) != k for s in shapes):
        return None
    if ir.contains(fn.body, ir.Stop):
        return None  # STOP returns nothing: keep raw returns
    out = []
    for i in range(k):
        ty = _UINT256
        if outputs is not None and len(outputs) == k and outputs[i].is_value:
            cand = outputs[i]
            if all(fits(s[i], cand) for s in shapes):
                ty = cand
        out.append(ty)
    return tuple(out)


# ---------------------------------------------------------------- entry points


_MAX_HEAD_WORDS = 1024  # head size checks above this are not recognised either


def _needs_abi_v2(t: SolType) -> bool:
    """Structs and arrays of dynamic types only exist with ABI coder v2."""
    if t.kind == "tuple":
        return True
    if t.kind == "array":
        return t.base.is_dynamic or _needs_abi_v2(t.base)
    return False


def _leaves(t: SolType) -> List[SolType]:
    """The value type of each head word of a static type: the members of a
    struct and the elements of a fixed-size array, flattened (the decoder of
    a memory one, or the body's first reads of a calldata one, validate them
    word by word)."""
    if t.kind == "tuple":
        return [x for c in t.components for x in _leaves(c)]
    if t.kind == "array" and t.length is not None:
        return _leaves(t.base) * t.length
    return [t]


def _choose(cands: Sequence[sigs.Signature], head: Optional[int], inferred: Dict[int, str],
            dynamic: FrozenSet[int], strict: bool = False, max_words: Optional[int] = None,
            abi_v1: bool = False, strides: Optional[Dict[int, int]] = None) -> Optional[sigs.Signature]:
    """The candidate signature the decoder checks agree with best: each
    validated head word must be of the validator's type (a member of a
    static struct / array: the member's type, see _leaves).  strict (ABI
    coder v2): a narrow parameter type needs its validator.  With a head
    size check, a dynamic parameter type needs its offset check (a head
    word in `dynamic`) and the stride of its bounds check when one was
    recognised (`strides`, head word -> stride), and a word in `dynamic` a
    dynamic type.
    max_words: the most head words a candidate may have (the body of a
    function without size check that never reads its arguments: 0).
    abi_v1: the original decodes with ABI coder v1 (no struct, no array of
    dynamic types)."""
    best, best_score = None, None
    strides = strides or {}
    for c in cands:
        try:
            types = [parse_type(t) for t in c.types]
        except ValueError:
            continue
        if sum(t.head_words for t in types) > _MAX_HEAD_WORDS:
            continue  # (a huge static array would expand to millions of words below)
        if abi_v1 and any(_needs_abi_v2(t) for t in types):
            continue  # an ABI coder v1 decoder cannot have taken it (solc rejects it too)
        words: List[SolType] = []  # the parameter type of each head word
        leaves: List[SolType] = []  # its value type (the member's within a static struct / array)
        for t in types:
            words.extend([t] * t.head_words if not t.is_dynamic else [t])
            leaves.extend(_leaves(t) if not t.is_dynamic else [t])
        if len(leaves) != len(words):
            leaves = words
        if head is not None and len(words) != head:
            continue
        if max_words is not None and len(words) > max_words:
            continue
        score, ok = 0, True
        for w, inf in inferred.items():
            if w >= len(words):
                ok = False
                break
            t, leaf = words[w], leaves[w]
            if inf == "dynamic":
                ok = t.is_dynamic
            elif t.is_dynamic:
                ok = False
            elif inf == "uint8" and leaf.kind == "uint" and leaf.bits == 8:
                score += 1
            elif leaf.canonical == inf:
                score += 1
            else:
                ok = False
            if not ok:
                break
        if not ok:
            continue
        for w in dynamic:
            if w < len(words) and not words[w].is_dynamic:
                ok = False
        if head is not None:
            # a decoder that checks the calldata (solc >= 0.5) checks the head
            # offset of every dynamic parameter: a dynamic type where it reads
            # a value word would add the offset / length checks; and the
            # bounds of its data: another stride (bytes vs uint256[]), or a
            # type without a length word, would check other bounds
            for w, t in enumerate(words):
                if t.is_dynamic and (w not in dynamic or (w in strides and strides[w] != length_stride(t))):
                    ok = False
        if strict:
            for w, t in enumerate(words):
                narrow = t.is_value and not (t.kind in ("uint", "int", "bytes") and t.bits == 256)
                if narrow and w not in inferred and t.kind != "function":
                    ok = False
        if not ok:
            continue
        score += 2 * (not c.generic_names) + 3 * c.trusted
        if best_score is None or score > best_score:
            best, best_score = c, score
    return best


def _param_name(name: str, i: int, taken: set) -> str:
    """A declarable, unique parameter name for a database name: anything
    solc rejects or that the generated code declares itself gets a `_`
    suffix (a prefix could hit a helper: `byte` -> `_byte`)."""
    base = re.sub(r"[^A-Za-z0-9_$]", "_", name or "") or f"arg{i}"
    if not re.match(r"[A-Za-z_$]", base):
        base = f"p_{base}"
    while reserved_name(base, parameter=True):
        base += "_"
    out, k = base, 1
    while out in taken or reserved_name(out, parameter=True):
        k += 1
        out = f"{base}_{k}"
    taken.add(out)
    return out


def function_name_ok(name: str, reserved: FrozenSet[str] = frozenset()) -> bool:
    """A database function name can be declared (else the selector is
    routed: its name is lost, never its selector)."""
    return bool(re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", name or "")) and not reserved_name(name) \
        and name not in reserved


def reads_arguments(fn: ir.Function) -> bool:
    """The body reads calldata past the selector (or its size)."""
    for n in ir.walk_all(fn.body):
        if isinstance(n, ir.Param) or (isinstance(n, ir.Env) and n.name == "calldatasize"):
            return True
        if isinstance(n, ir.CalldataWord) and n.offset != ir.ZERO:
            return True
        if isinstance(n, ir.CalldataSlice) and not (n.start == ir.ZERO and n.length == ir.Const(4)):
            return True
    return False


def analyse_entry(fn: ir.Function, key: str, *, selector: Optional[int], payable: bool,
                  abi_v2: bool = False, lookup: bool = True,
                  reserved: FrozenSet[str] = frozenset()) -> Tuple[EntrySpec, ir.Function]:
    """The EntrySpec of one entry point and its body (fn is the lifted body,
    callvalue check already handled).  `reserved`: names the contract
    declares besides its functions (its own name)."""
    kind = "function" if selector is not None else ("receive" if key == "_receive" else "fallback")
    checks = head_checks(fn.body)
    head = head_size(checks)
    inferred: Dict[int, str] = {}
    for c in checks:
        v = validator(c)
        if v is not None:
            inferred.setdefault(v[0], v[1])
    dynamic = frozenset(w for w, t in inferred.items() if t == "dynamic")
    if not abi_v2:
        dynamic |= frozenset(w for w in (_v1_offset(c) for c in checks) if w is not None)
    spec = EntrySpec(key=key, kind=kind, selector=selector, inferred=inferred, head_words=head,
                     dynamic_words=dynamic, payable=payable)
    sig = None
    outputs: Optional[Tuple[SolType, ...]] = None
    if selector is not None and lookup:
        cands = sigs.function_candidates(selector)
        spec.candidates = len(cands)
        usable = [c for c in cands if function_name_ok(c.name, reserved)]
        # without a size check, a body that never reads its arguments takes
        # none: a declared parameter would add the decoder's checks (an
        # untranslated body reverts anyway: its name is kept)
        max_words = 0 if head is None and not reads_arguments(fn) and "unstructured" not in fn.flags else None
        sig = _choose(usable, head, {w: t for w, t in inferred.items() if t != "dynamic"}, dynamic,
                      strict=abi_v2 and head is not None, max_words=max_words, abi_v1=not abi_v2,
                      strides=_bounds_strides(checks))
        if cands and sig is None:
            spec.flags.add("signature_rejected")
            if len(usable) < len(cands):
                spec.flags.add("signature_name_reserved")  # a name solc cannot declare: routed
    if sig is not None:
        spec.name = sig.name
        spec.signature = sig.signature
        taken: set = set()
        spec.params = tuple((parse_type(t), _param_name(n, i, taken)) for i, (t, n) in enumerate(sig.inputs))
        if sig.trusted and sig.mutability in MUTABILITY_ORDER:
            spec.db_mutability = min(sig.mutability, "nonpayable", key=MUTABILITY_ORDER.index)
        if sig.outputs is not None:
            try:
                outputs = tuple(parse_type(t) for t, _ in sig.outputs)
            except ValueError:
                outputs = None
        spec.db_returns = outputs
    set_mutability(spec, fn)
    if spec.kind == "function" and spec.signature is not None:
        spec.returns = declared_returns(fn, outputs)
    return spec, fn


def _only_return(fn: ir.Function) -> Optional[ir.Return]:
    """The return statement that is all a body does (after the decoder's
    checks), if any."""
    body = list(fn.body[_seed_prefix(fn.body):])
    while len(body) == 1 and isinstance(body[0], ir.If) and _is_plain_revert(body[0].then):
        body = list(body[0].orelse)
    return body[0] if len(body) == 1 and isinstance(body[0], ir.Return) else None


def constant_getter(fn: ir.Function) -> Optional[int]:
    """The value a parameterless body returns unconditionally, if it does
    nothing else (after the decoder's checks)."""
    ret = _only_return(fn)
    if ret is not None and isinstance(ret.data, ir.WordBytes) and ret.data.width == 32 \
            and isinstance(ret.data.value, ir.Const):
        return ret.data.value.value
    return None


def constant_return(fn: ir.Function) -> Optional[bytes]:
    """The constant bytes a body returns unconditionally (a word, a string's
    encoding...), if it does nothing else (after the decoder's checks)."""
    ret = _only_return(fn)
    if ret is None or ret.data is None or getattr(ret, "values", None) is not None:
        return None
    return ir.const_bytes(ret.data)


def set_mutability(spec: EntrySpec, fn: ir.Function) -> None:
    """spec.mutability from the body's effects, the payability and the
    trusted database prior (which may only raise it, up to nonpayable)."""
    if spec.payable:
        spec.mutability = "payable"
        return
    mut = mutability(fn)
    if spec.db_mutability and MUTABILITY_ORDER.index(spec.db_mutability) > MUTABILITY_ORDER.index(mut):
        mut = spec.db_mutability
    spec.mutability = mut

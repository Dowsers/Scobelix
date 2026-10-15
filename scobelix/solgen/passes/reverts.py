"""
reverts pass: `if (c) revert(payload)` followed by the rest of the block
becomes a `require` / `assert`, and custom errors get their names.

  run     in one function:
            * `if (c) { revert(); } rest` -> `require(!c); rest`, and with
              an Error(string) payload `require(!c, "message")` (Require
              nodes: solc >= 0.8 compiles them to the same payloads, see
              render.s_Require); the test may sit in either branch;
            * `if (c) { Panic(0x01) } rest` -> `assert(!c); rest` (the
              `assert` of the original; Solidity 0.8 panics the same way);
            * a revert with a custom error whose selector the signature
              database names (keccak-verified) and whose encoded arguments
              decode as values of the declared types (static values as
              words that provably fit their types: cleaned words, validated
              parameters, constants, locals whose every assigned value is
              one; string / bytes as constant tails) ->
              `revert Name(args)` (NamedError), the `error` declared once
              per contract; the Error(string) / Panic(uint256) selectors
              are never named (a payload still carrying them is not in the
              standard form the lifter decodes).  When the database has
              several signatures for the selector, the payload chooses: the
              errors declared as errors come before the signatures of other
              namespaces, and the one signature whose types decode the
              payload is taken; when the types leave several, none is (the
              exact bytes stay).
  finish  declares the named errors.

Kept exact: the compiler's Panic guards (0x11 overflow, 0x12 division by
zero, 0x21 enum, 0x22, 0x31, 0x32 ...: the arith pass owns them), the
bubbling of a call's return data (the calls pass), raw payloads, and custom
errors that cannot be named (their exact bytes stay).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from scobelix.solgen import ir
from scobelix.solgen.render import reserved_name
from scobelix.solgen.types import SolType, fits, parse_type

LEVELS = ("full",)

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_NAMEABLE = ("uint", "int", "address", "bool", "bytes", "dynbytes", "string")
_BUILTIN_SELECTORS = (0x08C379A0, 0x4E487B71)  # Error(string), Panic(uint256)


# ---------------------------------------------------------------- argument decoding


def _head_word(e) -> Optional[int]:
    if isinstance(e, ir.Param):
        return e.index
    if isinstance(e, ir.CalldataWord) and isinstance(e.offset, ir.Const):
        off = e.offset.value
        if off >= 4 and (off - 4) % 32 == 0:
            return (off - 4) // 32
    return None


def _validated(spec, abi_v2: bool) -> Dict[int, SolType]:
    """Head word -> value type the decoder validated before the body runs."""
    out: Dict[int, SolType] = {}
    if spec is not None and abi_v2 and getattr(spec, "typed", False):
        word = 0
        for t, _ in spec.params:
            if t.is_value:
                out[word] = t
            word += t.head_words
    return out


def _within(inner: SolType, outer: SolType) -> bool:
    """Every valid `inner` value word is a valid `outer` value word."""
    if inner.canonical == outer.canonical:
        return True
    if inner.kind == "uint" and outer.kind == "uint":
        return inner.bits <= outer.bits
    if inner.kind in ("uint", "bool") and outer.kind == "address":
        return inner.kind == "bool" or inner.bits <= 160
    if inner.kind == "bool" and outer.kind == "uint":
        return True
    if inner.kind == "int" and outer.kind == "int":
        return inner.bits <= outer.bits
    return False


class Valid(dict):
    """What a function knows to be valid values: head word -> the value
    type the decoder validated (the dict), and `assigned`: local name ->
    every value the function assigns to that local (None: a name bound
    otherwise).  See `with_locals`."""

    def __init__(self, validated: Dict[int, SolType], assigned: Dict[str, Optional[Tuple[ir.Expr, ...]]]):
        super().__init__(validated)
        self.assigned = assigned


def local_values(body: Sequence[ir.Stmt]) -> Dict[str, Optional[Tuple[ir.Expr, ...]]]:
    """Local name -> every value the function assigns to it: the values of
    its plain `Assign`s (statements, loop inits, back-edge updates); None
    when the name is bound in another way too (a compound or typed
    assignment, an output of a call)."""
    values: Dict[str, Optional[List[ir.Expr]]] = {}
    for n in ir.walk_all(body):
        if isinstance(n, ir.Assign) and isinstance(n.target, ir.Local):
            name = n.target.name
            if n.op is not None or n.checked is not None:
                values[name] = None
            elif name not in values:
                values[name] = [n.value]
            elif values[name] is not None:
                values[name].append(n.value)
        else:
            bound = ()
            if isinstance(n, ir.HighCall):
                bound = n.outs
            elif isinstance(n, ir.Builtin):
                bound = (n.out,)
            elif isinstance(n, ir.ExtCall):
                bound = (n.ok, n.ret)
            elif isinstance(n, ir.Precompile):
                bound = (n.output,)
            elif isinstance(n, ir.Transfer):
                bound = (n.ok,)
            for name in bound:
                if name:
                    values[name] = None
    return {k: (None if v is None else tuple(v)) for k, v in values.items()}


def with_locals(valid: Dict[int, SolType], body: Sequence[ir.Stmt]) -> Valid:
    """`valid` (the validated head words) with the values `body` assigns to
    its locals: a local whose every assigned value is a valid value of a
    type is one too (see `_valid_word`)."""
    return Valid(valid, local_values(body))


def _valid_word(word: ir.Expr, t: SolType, valid: Dict[int, SolType], _seen: frozenset = frozenset()) -> bool:
    """`word` is a valid value of type t: provably, a parameter the decoder
    validated, or a local whose every value is (when `valid` is a `Valid`
    that knows the function's assignments)."""
    if fits(word, t):
        return True
    w = _head_word(word)
    if w is not None and w in valid and _within(valid[w], t):
        return True
    assigned = getattr(valid, "assigned", None)
    if isinstance(word, ir.Local) and assigned is not None and word.name not in _seen:
        # the local holds its initial 0 (a valid value of every value type)
        # until an assignment, then one of the assigned values; a local
        # assigned from itself (a cycle) is not followed
        values = assigned.get(word.name)
        seen = _seen | {word.name}
        return bool(values) and all(_valid_word(v, t, valid, seen) for v in values)
    return False


def _layout(parts: Sequence[ir.Bytes]) -> Optional[List[Tuple[int, int, ir.Bytes]]]:
    """(byte offset, byte length, part) of every part, when every length
    is constant."""
    out, pos = [], 0
    for p in parts:
        n = ir.byte_length(p)
        v = ir.evaluate(n) if n is not None else None
        if v is None:
            return None
        out.append((pos, v, p))
        pos += v
    return out


def _head_expr(layout: Sequence[Tuple[int, int, ir.Bytes]], at: int) -> Optional[ir.Expr]:
    """The word at byte offset `at` of the encoding: a 32-byte word part
    there, or 32 bytes of a constant part covering it."""
    for off, n, p in layout:
        if off == at and n == 32 and isinstance(p, ir.WordBytes):
            return p.value
        if off <= at and at + 32 <= off + n:
            data = ir.const_bytes(p)
            return None if data is None else ir.Const(int.from_bytes(data[at - off:at - off + 32], "big"))
    return None


def decode_arguments(types: Sequence[SolType], parts: Sequence[ir.Bytes], valid: Dict[int, SolType]) \
        -> Optional[List[ir.Node]]:
    """The error's arguments when `parts` is their standard ABI encoding:
    the head word of a value type is any word that is a valid value of the
    type (a cleaned word, a validated parameter, a constant), a string /
    bytes argument is a constant tail at the offset its head word gives,
    zero-padded to a word, with nothing else in the encoding."""
    if not all(t.is_value or t.kind in ("dynbytes", "string") for t in types):
        return None
    layout = _layout(parts)
    if layout is None:
        return _decode_tails(types, parts, valid)
    total = sum(n for _, n, _ in layout)
    head = 32 * len(types)
    if total < head or any(off < head < off + n for off, n, _ in layout):
        return None
    tail = ir.const_bytes(ir.Blob(tuple(p for off, _, p in layout if off >= head))) if total > head else b""
    if tail is None:
        return _decode_tails(types, parts, valid)
    out: List[ir.Node] = []
    expect = head
    for i, t in enumerate(types):
        w = _head_expr(layout, 32 * i)
        if w is None:
            return None
        if t.is_value:
            if not _valid_word(w, t, valid):
                return None
            out.append(w)
            continue
        v = ir.evaluate(w)
        if v != expect or len(tail) < v - head + 32:
            return None
        rel = v - head
        n = int.from_bytes(tail[rel:rel + 32], "big")
        padded = (n + 31) // 32 * 32
        if len(tail) < rel + 32 + padded or any(tail[rel + 32 + n:rel + 32 + padded]):
            return None
        out.append(ir.ConstBytes(tail[rel + 32:rel + 32 + n]))
        expect = v + 32 + padded
    return out if expect == total else None


# (an encoding whose tails are byte strings of symbolic length: a calldata
# or memory string logged or carried by an error)


def flat_parts(parts: Sequence[ir.Bytes]) -> List[ir.Bytes]:
    """`parts` with the blobs flattened, the parts of a provably zero length
    left out and each run of constant parts merged into one ConstBytes."""
    out: List[ir.Bytes] = []
    run = b""
    stack = list(reversed(parts))
    while stack:
        p = stack.pop()
        if isinstance(p, ir.Blob):
            stack.extend(reversed(p.parts))
            continue
        n = ir.byte_length(p)
        if n is not None and ir.evaluate(n) is None and ir.provably_zero(n):
            continue
        data = ir.const_bytes(p)
        if data is not None:
            run += data
            continue
        if run:
            out.append(ir.ConstBytes(run))
            run = b""
        out.append(p)
    if run:
        out.append(ir.ConstBytes(run))
    return out


def _take(parts: List[ir.Bytes], n: int) -> Optional[Tuple[bytes, List[ir.Bytes]]]:
    """The first n bytes when the first part is constant and holds them."""
    if n == 0:
        return b"", parts
    if parts and isinstance(parts[0], ir.ConstBytes) and len(parts[0].data) >= n:
        data = parts[0].data
        return data[:n], ([ir.ConstBytes(data[n:])] if len(data) > n else []) + parts[1:]
    return None


def read_word(parts: List[ir.Bytes]) -> Tuple[Optional[ir.Expr], List[ir.Bytes]]:
    """(the next word, the parts after it): a 32-byte word part, or 32
    constant bytes; (None, parts) otherwise."""
    if parts and isinstance(parts[0], ir.WordBytes) and parts[0].width == 32:
        return parts[0].value, parts[1:]
    got = _take(parts, 32)
    if got is None:
        return None, parts
    return ir.Const(int.from_bytes(got[0], "big")), got[1]


def _read_bytes(parts: List[ir.Bytes], length: ir.Expr) -> Tuple[Optional[ir.Bytes], List[ir.Bytes]]:
    """(the next `length` bytes, the parts after them): constant bytes, or
    the first parts whose lengths provably add up to `length`."""
    n = ir.evaluate(length)
    if n is not None:
        got = _take(parts, n)
        if got is not None:
            return ir.ConstBytes(got[0]), got[1]
    for k in range(1, len(parts) + 1):
        total = ir.byte_length(ir.Blob(tuple(parts[:k])))
        if total is not None and ir.same_value(total, length):
            return (parts[0] if k == 1 else ir.Blob(tuple(parts[:k]))), parts[k:]
    return None, parts


def _padding_base(n: ir.Expr) -> Optional[ir.Expr]:
    """X when the word n is provably 31 - (X mod 32): the number of zero
    bytes that pad a byte string of X - 31 bytes to whole words (0 to 31)."""
    if isinstance(n, ir.Op) and n.op == "and" and len(n.args) == 2:
        for neg, c in (n.args, n.args[::-1]):
            if c == ir.Const(31) and isinstance(neg, ir.Op) and neg.op == "sub" and neg.args[0] == ir.ZERO:
                return ir.Op("add", (ir.Const(31), neg.args[1]))  # (0 - L) & 31 = 31 - (31 + L) mod 32
    terms, const = ir.linear(n)
    if const == 31 and len(terms) == 1:
        atom, c = terms[0]
        if c == ir.WORD_MOD - 1 and isinstance(atom, ir.Mask) and (atom.size, atom.offset, atom.shl) == (5, 0, 0):
            return atom.value  # (the linear form of ((X & ~31) - X + 31): a rounded-up length minus it)
    return None


def at_most_31(n: ir.Expr) -> bool:
    """The word n is at most 31 for every value of what it reads (a padding length)."""
    v = ir.evaluate(n)
    return v <= 31 if v is not None else _padding_base(n) is not None


def _read_padding(parts: List[ir.Bytes], length: ir.Expr) -> Tuple[Optional[ir.Expr], List[ir.Bytes]]:
    """(its length, the parts after it) when the next part is the zero
    padding of `length` bytes to whole words.  The length is written
    31 - (X mod 32), X = 31 + length, whatever form the part has: the
    linear form solc's own rounding `(X & ~31) - length` has, so that the
    offsets of the next tails compare."""
    n = ir.evaluate(length)
    if n is not None:
        got = _take(parts, (-n) % 32)
        if got is not None and not any(got[0]):
            return ir.Const((-n) % 32), got[1]
    if parts and isinstance(parts[0], ir.ZeroBytes):
        x = _padding_base(parts[0].length)
        if x is not None and ir.same_value(x, ir.Op("add", (length, ir.Const(31)))):
            return ir.Op("sub", (ir.Const(31), ir.Mask(5, 0, 0, x))), parts[1:]
    return None, parts


def read_tail(parts: List[ir.Bytes]) -> Tuple[Optional[Tuple[ir.Bytes, ir.Expr]], List[ir.Bytes]]:
    """((the byte string, the tail's length in bytes), the parts after it)
    when the parts start with the ABI tail of a byte string: its length
    word L, L bytes, zero bytes to whole words."""
    length, rest = read_word(parts)
    if length is None:
        return None, parts
    payload, rest = _read_bytes(rest, length)
    if payload is None:
        return None, parts
    pad, rest = _read_padding(rest, length)
    if pad is None:
        return None, parts
    return (payload, ir.Op("add", (ir.Const(32), length, pad))), rest


def _decode_tails(types: Sequence[SolType], parts: Sequence[ir.Bytes], valid: Dict[int, SolType]) \
        -> Optional[List[ir.Node]]:
    """decode_arguments for an encoding whose string / bytes tails have a
    symbolic length: the head words at their constant places, then each
    tail in the order of the parameters, every offset word provably equal
    to the head's size plus the tails before it (linear forms), nothing
    after the last tail."""
    rest = flat_parts(parts)
    head: List[ir.Expr] = []
    for _ in types:
        w, rest = read_word(rest)
        if w is None:
            return None
        head.append(w)
    expect: ir.Expr = ir.Const(32 * len(types))
    out: List[ir.Node] = []
    for t, w in zip(types, head):
        if t.is_value:
            if not _valid_word(w, t, valid):
                return None
            out.append(w)
            continue
        if not ir.same_value(w, expect):
            return None
        tail, rest = read_tail(rest)
        if tail is None:
            return None
        out.append(tail[0])
        expect = ir.Op("add", (expect, tail[1]))
    return out if not rest else None


# ---------------------------------------------------------------- names


def _taken_names(ctx) -> Set[str]:
    """Contract-level names a declared error must not clash with."""
    taken: Set[str] = set(ctx.facts.get("declared_names") or ())
    for spec in ctx.specs.values():
        if getattr(spec, "name", None):
            taken.add(spec.name)
        for _, pname in getattr(spec, "params", ()) or ():
            taken.add(pname)
    for fn in ctx.functions.values():
        for n in ir.walk_all(fn.body):
            if isinstance(n, ir.Local):
                taken.add(n.name)
            elif isinstance(n, ir.Precompile) and n.output:
                taken.add(n.output)
    lay = ctx.facts.get("storage")
    if lay is not None:
        taken |= set(getattr(lay, "names", {}).values()) | set(getattr(lay, "structs", {}).values())
        taken |= set(getattr(lay, "enums", {}).values())
    getters = ctx.facts.get("getters") or {}
    for key, value in (getters.get("vars") or {}).items():
        if isinstance(value, tuple) and len(value) > 1:
            taken.add(value[1])
    for value in (getters.get("constants") or {}).values():
        if isinstance(value, tuple) and value:
            taken.add(value[0])
    return taken


class _Errors:
    """The custom errors named in this contract (shared by the functions)."""

    def __init__(self, ctx):
        self.ctx = ctx
        facts = ctx.facts.setdefault("reverts", {})
        # selector -> (name, canonical types, parameter names) of the named errors
        self.by_selector: Dict[int, Optional[tuple]] = facts.setdefault("errors", {})
        self.taken: Optional[Set[str]] = None

    def candidates(self, selector: int) -> List[Tuple[object, List[SolType]]]:
        """The database signatures a payload with this selector may be named
        after, with their parsed types: the errors declared as errors when
        there are any, else the other signatures with that selector."""
        lookup = getattr(self.ctx.sigs, "error_candidates", None)
        # Error(string) and Panic(uint256) are the lifter's: a payload left
        # with their selector is not in the standard form
        if lookup is None or selector in _BUILTIN_SELECTORS:
            return []
        cands = [c for c in lookup(selector) if getattr(c, "kind", "error") == "error"]
        declared = [c for c in cands if getattr(c, "declared", True)]
        out = []
        for c in declared or cands:
            if not _IDENT_RE.fullmatch(c.name) or reserved_name(c.name):
                continue
            try:
                types = [parse_type(t) for t in c.types]
            except ValueError:
                continue
            if all(t.kind in _NAMEABLE for t in types):
                out.append((c, types))
        return out

    def resolve(self, selector: int, parts: Sequence[ir.Bytes], valid: Dict[int, SolType]) \
            -> Optional[Tuple[tuple, List[ir.Node]]]:
        """((name, canonical types, parameter names), arguments) of the error
        a payload carries.  The first payload a signature decodes fixes the
        error of its selector for the contract."""
        if selector in self.by_selector:
            got = self.by_selector[selector]
            args = decode_arguments([parse_type(t) for t in got[1]], parts, valid) if got is not None else None
            return None if args is None else (got, args)
        if self.taken is None:
            self.taken = _taken_names(self.ctx)
        fitting: Dict[str, tuple] = {}  # signature -> (candidate, types, arguments)
        for c, types in self.candidates(selector):
            if c.name in self.taken or any(c.name == e[0] for e in self.by_selector.values() if e):
                continue
            args = decode_arguments(types, parts, valid)
            if args is not None:
                fitting.setdefault(c.signature, (c, types, args))
        if len(fitting) != 1:
            return None  # no signature, or several the argument types cannot tell apart
        (c, types, args), = fitting.values()
        names = [n if _IDENT_RE.fullmatch(n or "") and not reserved_name(n, parameter=True) else ""
                 for _, n in c.inputs]
        chosen = (c.name, tuple(t.canonical for t in types), tuple(names))
        self.taken.add(c.name)
        self.ctx.facts.setdefault("declared_names", set()).add(c.name)
        self.by_selector[selector] = chosen
        return chosen, args


# ---------------------------------------------------------------- the rewriter


def _requireable(block: Sequence[ir.Stmt]) -> Optional[ir.Payload]:
    """The payload when `block` is one revert that reads as a require /
    assert: empty, Error(string) or Panic(0x01)."""
    if len(block) == 1 and isinstance(block[0], ir.Revert):
        p = block[0].payload
        if isinstance(p, (ir.Empty, ir.ErrorString)) or p == ir.Panic(1):
            return p
    return None


class _Rewriter:
    def __init__(self, fn: ir.Function, ctx, errors: _Errors):
        self.errors = errors
        self.valid = with_locals(_validated(ctx.specs.get(fn.key), ctx.abi_v2), fn.body)
        self.changed = False

    def block(self, stmts: Sequence[ir.Stmt]) -> Tuple[ir.Stmt, ...]:
        out: List[ir.Stmt] = []
        for i, s in enumerate(stmts):
            if isinstance(s, ir.If):
                rest = tuple(stmts[i + 1:])
                p = _requireable(s.then)
                if p is not None:
                    out.append(self.require(ir.Op("iszero", (s.cond,)), p))
                    out.extend(self.block(tuple(s.orelse) + rest))
                    return tuple(out)
                p = _requireable(s.orelse)
                if p is not None:
                    out.append(self.require(s.cond, p))
                    out.extend(self.block(tuple(s.then) + rest))
                    return tuple(out)
                out.append(ir.If(s.cond, self.block(s.then), self.block(s.orelse)))
                continue
            out.append(self.stmt(s))
        return tuple(out)

    def require(self, cond: ir.Expr, p: ir.Payload) -> ir.Stmt:
        self.changed = True
        if isinstance(p, ir.Panic):
            return ir.Assert(cond)
        return ir.Require(cond, p)

    def stmt(self, s: ir.Stmt) -> ir.Stmt:
        if isinstance(s, ir.While):
            return ir.While(s.cond, self.block(s.body), s.init, s.loop_id)
        if isinstance(s, ir.For):
            return ir.For(self.block(s.init), s.cond, self.block(s.step), self.block(s.body), s.loop_id)
        if isinstance(s, ir.Require) and s.payload == ir.Panic(1):
            self.changed = True
            return ir.Assert(s.cond)
        if isinstance(s, (ir.Revert, ir.Require)) and isinstance(s.payload, ir.Custom):
            named = self.named(s.payload)
            if named is not None:
                self.changed = True
                return ir.Revert(named) if isinstance(s, ir.Revert) else ir.Require(s.cond, named)
        return s

    def named(self, p: ir.Custom) -> Optional[ir.NamedError]:
        got = self.errors.resolve(p.selector, p.args, self.valid)
        if got is None:
            return None
        (name, types, _), args = got
        return ir.NamedError(name, tuple(args), types)


# ---------------------------------------------------------------- the pass


def run(fn: ir.Function, ctx) -> ir.Function:
    rw = _Rewriter(fn, ctx, _Errors(ctx))
    body = rw.block(fn.body)
    if not rw.changed:
        return fn
    return fn.with_body(body)


def finish(ctx) -> None:
    errors = (ctx.facts.get("reverts") or {}).get("errors") or {}
    for selector in sorted(errors):
        got = errors[selector]
        if got is None:
            continue
        name, types, names = got
        params = ", ".join(f"{t} {n}".rstrip() for t, n in zip(types, names))
        ctx.declare("error", f"error {name}({params});")

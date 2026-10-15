"""
storage pass: raw storage accesses -> state variable accesses, and the state
variable declarations (`scobelix.solgen.storage` infers the layout).

  prepare  the contract's layout (storage.analyse: inference + L2 self-check
           against solc's storageLayout of the declarations).
  run      in one function, every access that is exactly one recovered
           value, through a path Solidity can write without changing what
           is computed, becomes a `StateRef`:
             reads   the word of the value (zero-extended uintN / address,
                     uint256 / int256 / bytes32 words; a bytesN read
                     right-aligned is `StateRef >> (256 - 8N)`, left-aligned
                     the StateRef itself; an intN under the signextend
                     that cleans it; a bool only where its byte is tested
                     against zero);
             writes  `var = value` where the conversion to the variable's
                     type keeps exactly the stored bits (uintN, intN,
                     address: the low bits; bytesN: the value shifted to
                     the high bytes; bool: only provably 0 / 1 values);
             paths   mapping keys of value types (the key word must be a
                     valid value of the key type: provably, or a parameter
                     the decoder validated), struct members, `.length` of
                     dynamic arrays, array indices below the length (a
                     constant index of a fixed array, or an index a
                     dominating test bounded: see _Rewriter).
           The engine writes one SSTORE as one store per run of changed
           bits: a value row and the zero row right above it (a narrow value
           zero-extended into a wider variable) become one write of the
           variable, a constant store over several whole variables one
           write per variable (_Rewriter.whole_variables).
  finish   declares the enums, structs and state variables (with fillers),
           names the variables (folded getters, `_<getter>`, `slot<N>`),
           and the accessors of the custom-slot namespaces (their members
           are read and written as `_namespace<hex>().m<slot>_<byte>`).

Kept in the exact form: anything the layout does not resolve to one value
(packed words read or written whole, part of a variable, string / bytes
data), enums (Solidity's conversions check the range), booleans written
from a word that may be neither 0 nor 1, keys that may not be valid values
of their type, string / bytes keys, array elements whose index is not
proven in bounds (Solidity adds a bounds check).

A packed store left raw that writes part of a recovered variable together
with bits outside it cannot be attributed to the recovered variables (they
do not describe that store): the store is exact as it is, and the function
gets the flag `engine:packed_store_suspect`.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from scobelix.solgen import ir, storage
from scobelix.solgen.render import reserved_name
from scobelix.solgen.types import SolType, fits, is_boolean, max_bits, parse_type

LEVELS = ("full",)

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_SLOT = 256


# ---------------------------------------------------------------- names


def _taken_names(ctx) -> Set[str]:
    """Names declared elsewhere in the contract: functions kept as such,
    parameters, locals."""
    folded = ctx.facts.get("getters") or {}
    folded_keys = {k for k, _ in (folded.get("vars") or {}).values()} | set(folded.get("constants") or {})
    taken: Set[str] = set()
    for key, spec in ctx.specs.items():
        if getattr(spec, "name", None) and key not in folded_keys:
            taken.add(spec.name)
        for _, pname in getattr(spec, "params", ()) or ():
            taken.add(pname)
    for fn in ctx.functions.values():
        for n in ir.walk_all(fn.body):
            if isinstance(n, ir.Local):
                taken.add(n.name)
    for name, _ in (folded.get("constants") or {}).values():
        taken.add(name)
    return taken


def assign_names(ctx, lay: storage.Layout) -> None:
    """Declared names of the variables (once per contract): the folded
    getter's name, else `_<getter>` of a pure accessor, else the stable
    `slot<N>[_<byte>]`."""
    if ctx.facts.get("storage_named"):
        return
    folded = (ctx.facts.get("getters") or {}).get("vars") or {}
    taken = _taken_names(ctx) | set(lay.structs.values()) | set(lay.enums.values())
    names: Dict[str, str] = {}
    for v in lay.vars:
        if v.vid in folded:
            names[v.vid] = folded[v.vid][1]
            taken.add(names[v.vid])
    for v in sorted(lay.vars, key=lambda v: (v.slot, v.offset)):
        if v.vid in names:
            continue
        cands = [f"_{n}" for _, n in v.accessors if n] + [v.vid]
        for c in cands + [v.vid + "_"]:
            if _IDENT_RE.fullmatch(c) and c not in taken and not reserved_name(c) and not c.startswith("__gap"):
                names[v.vid] = c
                break
        else:
            names[v.vid] = f"{v.vid}_{len(names)}"
        taken.add(names[v.vid])
    lay.names = names
    lay.public = set(folded)
    ctx.facts["storage_named"] = True


# ---------------------------------------------------------------- validated parameters


def _validated(spec, abi_v2: bool) -> Dict[int, SolType]:
    """Head word -> type of the parameters the decoder validated before the
    body runs (ABI coder v2 signatures, or the validators found in the
    body's own head checks)."""
    out: Dict[int, SolType] = {}
    if spec is None:
        return out
    if abi_v2 and getattr(spec, "typed", False):
        word = 0
        for t, _ in spec.params:
            if t.is_value:
                out[word] = t
            word += t.head_words
    for w, ty in (getattr(spec, "inferred", {}) or {}).items():
        if w not in out and ty != "dynamic":
            try:
                out[w] = parse_type(ty)
            except ValueError:
                continue
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


def _head_word(e) -> Optional[int]:
    if isinstance(e, ir.CalldataWord) and isinstance(e.offset, ir.Const):
        off = e.offset.value
        if off >= 4 and (off - 4) % 32 == 0:
            return (off - 4) // 32
    if isinstance(e, ir.Param):
        return e.index
    return None


# ---------------------------------------------------------------- the rewriter


def _facts_of(cond: ir.Expr, then: bool) -> FrozenSet[tuple]:
    """Index bounds that hold where `cond` is non-zero (then) or zero:
    (index, ("const", N)) for index < N, (index, ("len", array path)) for
    index < the length word of that array."""
    neg = False
    while isinstance(cond, ir.Op) and cond.op == "iszero":
        neg, cond = not neg, cond.args[0]
    if neg == then or not isinstance(cond, ir.Op) or len(cond.args) != 2:
        return frozenset()  # the comparison itself is false there (or no comparison)
    if cond.op == "lt":
        idx, bound = cond.args
    elif cond.op == "gt":
        bound, idx = cond.args
    else:
        return frozenset()
    if isinstance(bound, ir.Const):
        return frozenset({(idx, ("const", bound.value))})
    if isinstance(bound, ir.Sload):
        array = storage.parse_slot(bound.slot)
        if array[0] != "unk":
            return frozenset({(idx, ("len", array))})
    return frozenset()


def _mentions(e: ir.Expr, classes) -> bool:
    return any(isinstance(n, classes) for n in ir.walk(e))


class _Rewriter:
    """Rewrites one body top-down, knowing the index bounds the path to each
    statement has checked (`facts`): an array element reached by a computed
    index is written `arr[i]` only where a dominating test proved i below
    the length (so Solidity's own bounds check never fires), with no store,
    call or reassignment of the index since."""

    def __init__(self, fn: ir.Function, ctx, lay: storage.Layout):
        self.lay = lay
        self.valid = _validated(ctx.specs.get(fn.key), ctx.abi_v2)
        self.changed = False
        self.facts: FrozenSet[tuple] = frozenset()

    def index_ok(self, word: ir.Expr, length: Optional[int], dynamic: bool, array: Optional[tuple]) -> bool:
        if not dynamic and isinstance(word, ir.Const) and length is not None and word.value < length:
            return True
        for idx, bound in self.facts:
            if idx != word:
                continue
            if dynamic and bound == ("len", array):
                return True
            if not dynamic and bound[0] == "const" and length is not None and bound[1] <= length:
                return True
        return False

    # ---- paths
    def key_fits(self, word: ir.Expr, ty: SolType) -> bool:
        if fits(word, ty):
            return True
        w = _head_word(word)
        return w is not None and w in self.valid and _within(self.valid[w], ty)

    def path(self, ref: storage.Ref) -> Optional[Tuple[object, ...]]:
        out: List[object] = []
        for st in ref.steps:
            if st[0] == "key":
                word, kt = st[1], st[2]
                if not isinstance(word, ir.Expr):
                    return None  # string / bytes key
                try:
                    ty = parse_type(kt)
                except ValueError:
                    return None
                if not ty.is_value or not self.key_fits(word, ty):
                    return None
                out.append(ir.Cast(ty.canonical, word))  # a key (a mapping read never fails), even uint256
            elif st[0] == "index":
                word, length, dynamic = st[1], st[2], st[3]
                if not self.index_ok(word, length, dynamic, st[4] if len(st) > 4 else None):
                    return None  # Solidity's bounds check could fire where the original code reads on
                out.append(word)
            elif st[0] in ("member", "length"):
                out.append(st[1] if st[0] == "member" else "length")
            else:
                return None
        return tuple(out)

    def ref(self, slot: ir.Expr, off: int, bits: int) -> Optional[Tuple[storage.Ref, str, Tuple[object, ...]]]:
        r = self.lay.resolve(slot, off, bits)
        if r is None:
            return None
        ty = storage.solidity_value_type(r.ty)
        if ty is None:
            return None
        p = self.path(r)
        if p is None:
            return None
        return r, ty, p

    def state(self, r: storage.Ref, ty: str, p) -> ir.StateRef:
        self.changed = True
        return ir.StateRef(self.lay.name(r.var), p, ty)

    # ---- reads
    @staticmethod
    def window(e) -> Optional[Tuple[ir.Expr, int, int]]:
        """(slot, bit offset, bit size) of a raw read."""
        if isinstance(e, ir.Sload):
            return e.slot, 0, _SLOT
        if isinstance(e, ir.Field) and isinstance(e.value, ir.Sload):
            off, size = ir.field_bits(e.offset), ir.field_bits(e.size)
            if off is not None and size is not None and off < _SLOT and size > 0:
                return e.value.slot, off, min(size, _SLOT - off)
        return None

    def read(self, e: ir.Expr) -> ir.Expr:
        """A read of exactly one variable's bits, as its zero-extended word."""
        w = self.window(e)
        if w is None:
            return e
        slot, off, size = w
        if isinstance(e, ir.Sload):
            lr = self.lay.length_ref(slot)
            if lr is not None:
                p = self.path(lr)
                if p is not None:
                    return self.state(lr, "uint256", p)
        got = self.ref(slot, off, size)
        if got is None:
            return e
        r, ty, p = got
        t = parse_type(ty)
        if t.kind in ("uint", "address") or (t.kind in ("int", "bytes") and t.bits == _SLOT):
            return self.state(r, ty, p)
        if t.kind == "bytes":
            return ir.Op("shr", (ir.const(_SLOT - t.bits), self.state(r, ty, p)))
        return e  # intN < 256 (sign-extended word), bool (0 / 1): only in their cleanups

    def narrow(self, e: ir.Expr, bits: int) -> Optional[Tuple[storage.Ref, str, Tuple[object, ...]]]:
        """The variable of exactly `bits` bits a wider read starts with."""
        w = self.window(e)
        if w is None or w[2] < bits:
            return None
        return self.ref(w[0], w[1], bits)

    def mask(self, e: ir.Mask) -> ir.Expr:
        size, off, shl = (storage._int_field(x) for x in (e.size, e.offset, e.shl))
        if None in (size, off, shl) or not 0 < size < _SLOT or size % 8:
            return e
        if off != 0:
            return self.offset_mask(e, size, off, shl)
        got = self.narrow(e.value, size)
        if got is None:
            return e
        r, ty, p = got
        t = parse_type(ty)
        if shl == 0 and t.kind in ("uint", "address"):
            return self.state(r, ty, p)  # right-aligned cleanup of the value
        if shl == _SLOT - size and t.kind == "bytes":
            return self.state(r, ty, p)  # left-aligned: the bytesN word
        if shl == 0 and t.kind == "bytes":
            return ir.Op("shr", (ir.const(_SLOT - t.bits), self.state(r, ty, p)))
        return e

    def offset_mask(self, e: ir.Mask, size: int, off: int, shl: int) -> ir.Expr:
        """bits [off, off + size) of a slot taken straight from its read:
        moved down (the value of a uintN / address, a bytesN right-aligned)
        or to the top (a bytesN's word)."""
        if not isinstance(e.value, ir.Sload) or off < 0 or off % 8 or off + size > _SLOT:
            return e
        got = self.ref(e.value.slot, off, size)
        if got is None:
            return e
        r, ty, p = got
        t = parse_type(ty)
        if shl == -off and t.kind in ("uint", "address"):
            return self.state(r, ty, p)
        if shl == -off and t.kind == "bytes":
            return ir.Op("shr", (ir.const(_SLOT - t.bits), self.state(r, ty, p)))
        if shl == _SLOT - size - off and t.kind == "bytes":
            return self.state(r, ty, p)
        return e

    def signextend(self, e: ir.Op) -> ir.Expr:
        b = e.args[0].value if isinstance(e.args[0], ir.Const) else None
        x = e.args[1]
        if b is None or b >= 31:
            return e
        if isinstance(x, ir.StateRef) and x.ty.startswith("int"):
            try:
                if parse_type(x.ty).bits <= 8 * (b + 1):
                    return x  # already sign-extended
            except ValueError:
                return e
        got = self.narrow(x, 8 * (b + 1))
        if got is None:
            return e
        r, ty, p = got
        if ty != f"int{8 * (b + 1)}":
            return e
        return self.state(r, ty, p)

    def boolean(self, e: ir.Expr) -> Optional[ir.Expr]:
        """A bool variable's byte read exactly, used where only != 0 counts."""
        w = self.window(e)
        if w is None or w[2] != 8:
            return None
        got = self.ref(*w)
        if got is None or got[1] != "bool":
            return None
        return self.state(*got)

    # ---- writes
    def store(self, s: ir.Sstore) -> ir.Stmt:
        off, size = ir.field_bits(s.offset), ir.field_bits(s.size)
        if off is None or size is None or size <= 0 or off + size > _SLOT:
            return s
        got = self.ref(s.slot, off, size)
        if got is None:
            return s
        r, ty, p = got
        t = parse_type(ty)
        value = s.value
        if t.kind == "bool":
            if not is_boolean(value):
                return s
        elif t.kind == "bytes" and t.bits < _SLOT:
            value = _to_high_bytes(value, t.bits)
        return ir.Assign(self.state(r, ty, p), value)

    def resolves(self, s: ir.Sstore) -> bool:
        """The store is exactly one variable written through a path."""
        changed = self.changed
        try:
            return not isinstance(self.store(s), ir.Sstore)
        finally:
            self.changed = changed

    def whole_variables(self, stmts: Tuple[ir.Stmt, ...], facts: FrozenSet[tuple]) -> Tuple[ir.Stmt, ...]:
        """The raw stores of a block regrouped by variable where the bits and
        values written stay the same: a value row with the zero row right
        above it in the same run of stores (a narrow value zero-extended
        into a wider variable) becomes one store at the value row, a
        constant store over several whole variables one store each.  (A
        regrouped store the path facts of its own position do not resolve
        stays a raw store: still the same bits and values.)"""
        self.facts = facts
        merged: Dict[int, ir.Sstore] = {}
        dropped: Set[int] = set()
        for i, s in enumerate(stmts):
            if not isinstance(s, ir.Sstore) or i in dropped or _known(s) is None or _is_zero(s.value):
                continue
            for j in _zero_rows(stmts, i):
                if j in dropped or j in merged:
                    continue
                low = _mask_to(s.value, _known(s)[1])
                wide = ir.Sstore(s.slot, low, _known(s)[0], _known(s)[1] + _known(stmts[j])[1])
                if self.resolves(wide):
                    merged[i] = wide
                    dropped.add(j)
                    break
        out: List[ir.Stmt] = []
        for i, s in enumerate(stmts):
            if i in dropped:
                continue
            if i in merged:
                out.append(merged[i])
                continue
            pieces = self.split_constant(s) if isinstance(s, ir.Sstore) else None
            out.extend(pieces or (s,))
        return tuple(out)

    def split_constant(self, s: ir.Sstore) -> Optional[List[ir.Sstore]]:
        """A constant store over several whole variables, one store each (in
        offset order: disjoint bits, constant values)."""
        known = _known(s)
        c = ir.evaluate(s.value)
        if known is None or c is None or ir.contains(s.slot, (ir.Sload, ir.StateRef)):
            return None
        off, size = known
        pieces, at = [], off
        while at < off + size:
            v = self.lay._walk(storage.parse_slot(s.slot), at)
            ref = None
            if v is not None:
                loc = storage._descend(v[2], v[3], v[4], list(v[1]))
                if loc is not None and storage.is_value(loc[0]) and loc[1] == 0 and loc[2] == 0:
                    ref = storage.val_nbytes(loc[0]) * 8
            if ref is None or at + ref > off + size:
                return None
            piece = ir.Sstore(s.slot, ir.const((c >> (at - off)) & ((1 << ref) - 1)), at, ref)
            if not self.resolves(piece):
                return None
            pieces.append(piece)
            at += ref
        return pieces if len(pieces) > 1 else None

    # ---- the walk
    def body(self, stmts, facts: FrozenSet[tuple]) -> Tuple[ir.Stmt, ...]:
        out = []
        for s in self.whole_variables(tuple(stmts), facts):
            out.append(self.statement(s, facts))
            facts = self.after(s, facts)
        return tuple(out)

    def expr(self, e, facts: FrozenSet[tuple]):
        self.facts = facts
        return ir.transform(e, self.read_node)

    def cond(self, e: ir.Expr, facts: FrozenSet[tuple]) -> ir.Expr:
        self.facts = facts
        b = self.boolean(e)
        return b if b is not None else self.expr(e, facts)

    def statement(self, s: ir.Stmt, facts: FrozenSet[tuple]) -> ir.Stmt:
        if isinstance(s, ir.Sstore):
            self.facts = facts
            return self.expr(self.store(s), facts)  # decided on the analysed node, then its reads
        if isinstance(s, ir.If):
            cond = self.cond(s.cond, facts)
            return dataclasses.replace(s, cond=cond, then=self.body(s.then, facts | _facts_of(s.cond, True)),
                                       orelse=self.body(s.orelse, facts | _facts_of(s.cond, False)))
        if isinstance(s, ir.While):
            init = tuple(self.expr(a, facts) for a in s.init)
            return dataclasses.replace(s, init=init, cond=self.cond(s.cond, frozenset()),
                                       body=self.body(s.body, frozenset()))
        if isinstance(s, ir.For):
            return dataclasses.replace(s, init=self.body(s.init, facts), cond=self.cond(s.cond, frozenset()),
                                       step=self.body(s.step, frozenset()), body=self.body(s.body, frozenset()))
        if isinstance(s, (ir.Require, ir.Assert)):
            return dataclasses.replace(s, cond=self.cond(s.cond, facts))
        return self.expr(s, facts)

    @staticmethod
    def after(s: ir.Stmt, facts: FrozenSet[tuple]) -> FrozenSet[tuple]:
        """The bounds still known after statement s."""
        if isinstance(s, (ir.While, ir.For)):
            return frozenset()
        if isinstance(s, ir.Require):
            return facts | _facts_of(s.cond, True)
        if isinstance(s, ir.Assign) and isinstance(s.target, ir.Local):
            return frozenset(f for f in facts if s.target not in ir.walk(f[0]))
        if isinstance(s, (ir.Sstore, ir.ExtCall, ir.Create, ir.SelfDestruct, ir.Unstructured)):
            # a store or a call may change an array's length or the index's inputs
            return frozenset(f for f in facts if f[1][0] == "const" and not _mentions(
                f[0], (ir.Sload, ir.CallOut, ir.ReturnData, ir.StateRef)))
        if isinstance(s, ir.Mstore):
            return frozenset(f for f in facts if not _mentions(f[0], (ir.MLoad, ir.MemSlice)))
        return facts

    def read_node(self, n):
        if isinstance(n, (ir.Sload, ir.Field)):
            return self.read(n)
        if isinstance(n, ir.Mask):
            return self.mask(n)
        if isinstance(n, ir.Op) and n.op == "signextend":
            return self.signextend(n)
        if isinstance(n, ir.Op) and n.op == "iszero":
            b = self.boolean(n.args[0])
            return n if b is None else ir.Op("iszero", (b,))
        return n


def _known(s: ir.Stmt) -> Optional[Tuple[int, int]]:
    """(bit offset, bit size) of a store of known bits."""
    if not isinstance(s, ir.Sstore):
        return None
    off, size = ir.field_bits(s.offset), ir.field_bits(s.size)
    if off is None or size is None or size <= 0 or off < 0 or off + size > _SLOT:
        return None
    return off, size


def _is_zero(e: ir.Expr) -> bool:
    return ir.evaluate(e) == 0


def cuts_a_variable(s: ir.Sstore, lay: storage.Layout) -> bool:
    """The packed store writes some bits of a recovered value and bits
    outside it, without covering it: neither (part of) one variable nor
    whole variables."""
    known = _known(s)
    if known is None or known[1] >= _SLOT:
        return False
    off, size = known
    path = storage.parse_slot(s.slot)
    byte, last = off // 8, (off + size + 7) // 8
    while byte < last:
        w = lay._walk(path, 8 * byte)
        loc = storage._descend(w[2], w[3], w[4], list(w[1])) if w is not None else None
        if loc is None or not storage.is_value(loc[0]) or loc[1] != 0:
            byte += 1
            continue
        start = 8 * (byte - loc[2])
        end = start + 8 * storage.val_nbytes(loc[0])
        if not (start <= off and off + size <= end) and not (off <= start and end <= off + size):
            return True
        byte = end // 8
    return False


def _mask_to(value: ir.Expr, bits: int) -> ir.Expr:
    """The low `bits` bits of value (what a store of that width keeps)."""
    return value if max_bits(value) <= bits else ir.Mask(bits, 0, 0, value)


def _zero_rows(stmts: Tuple[ir.Stmt, ...], i: int) -> List[int]:
    """Indices of the zero stores starting right above the value row
    stmts[i] in its run of stores to the same slot, with only stores of
    other bits of that slot, whose values read no storage, in between:
    moving the zero store next to the value row writes the same bits with
    the same values (a zero store before the row also needs a row value
    that reads no storage)."""
    a = stmts[i]
    off, size = _known(a)
    if ir.contains(a.slot, (ir.Sload, ir.StateRef)):
        return []
    out = []
    for step in (1, -1):
        between: List[Tuple[int, int]] = []
        j = i + step
        while 0 <= j < len(stmts) and isinstance(stmts[j], ir.Sstore) and stmts[j].slot == a.slot:
            b, kb = stmts[j], _known(stmts[j])
            if kb is None or ir.contains(b.value, (ir.Sload, ir.StateRef)):
                break
            if kb[0] == off + size and _is_zero(b.value):
                end = kb[0] + kb[1]
                if all(e <= off or s >= end for s, e in between) and (
                        step == 1 or not ir.contains(a.value, (ir.Sload, ir.StateRef))):
                    out.append(j)
                break
            between.append((kb[0], kb[0] + kb[1]))
            j += step
    return out


def _to_high_bytes(value: ir.Expr, bits: int) -> ir.Expr:
    """The word whose high `bits` bits are the low `bits` bits of value."""
    shift = _SLOT - bits
    if isinstance(value, ir.Mask):
        size, off, shl = (storage._int_field(x) for x in (value.size, value.offset, value.shl))
        if (size, off, shl) == (bits, shift, -shift):
            return ir.Mask(bits, shift, 0, value.value)  # a bytesN word moved down: the word itself
    return ir.Op("shl", (ir.const(shift), value))


# ---------------------------------------------------------------- the pass


def prepare(ctx) -> None:
    storage.analyse(ctx)


def run(fn: ir.Function, ctx) -> ir.Function:
    lay = storage.analyse(ctx)
    if lay is None or not (lay.vars or lay.namespaces):
        return fn
    assign_names(ctx, lay)
    rw = _Rewriter(fn, ctx, lay)
    body = rw.body(fn.body, frozenset())
    flags = ("engine:packed_store_suspect",) if any(
        isinstance(n, ir.Sstore) and cuts_a_variable(n, lay) for n in ir.walk_all(body)) else ()
    if flags and not set(flags) <= set(fn.flags):
        return fn.with_body(body if rw.changed else fn.body, flags)
    return fn.with_body(body) if rw.changed else fn


def finish(ctx) -> None:
    lay = storage.analyse(ctx)
    if lay is None or not (lay.vars or lay.namespaces):
        return
    assign_names(ctx, lay)
    decls = storage.state_declarations(lay)
    if decls is None:
        ctx.warnings.append("storage: overlapping variables, no state variable declared")
        return
    for text in storage.type_declarations(lay):
        ctx.declare("struct", text)
    if decls:
        ctx.declare("state", "\n".join(decls))
    for text in storage.namespace_declarations(lay):
        ctx.declare("function", text)
    # "id": the stable id of the variable (what `excluded_storage` takes);
    # "encoding", "bytes": how solc must lay it out; "namespace": reached
    # through an accessor at a slot of its own, not a state variable
    ctx.facts["storage_declared"] = [
        dict({"name": lay.name(v), "slot": v.slot, "offset": v.offset, "type": storage.type_text(v.type, lay),
              "public": v.vid in lay.public, "id": v.vid}, **_shape(v.type))
        for v in sorted(lay.vars, key=lambda v: (v.slot, v.offset))
    ] + [{"name": lay.name(v), "slot": v.slot, "offset": 0, "type": storage.type_text(v.type, lay), "public": False,
          "id": v.vid, "namespace": True}
         for v in lay.namespaces]
    ctx.warnings.extend(lay.warnings)


def _shape(t: tuple) -> Dict[str, object]:
    encoding, size = storage._encoding(t)
    return {"encoding": encoding, "bytes": size}

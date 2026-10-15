"""
Storage layout inference: from the lifted bodies of every entry point to the
contract's state variables (exact slot, byte offset and Solidity type),
declarations that solc lays out at exactly those positions, and the lookups
the storage and getters passes use to rewrite raw storage accesses.

Input: the lifted IR (`ir.Function` per entry point, before any pass) and the
entry specs (`abi.EntrySpec`: parameter types from the keccak-verified
signature or the decoder's validators, database outputs).  Nothing here
changes the code; it only describes it.

1. Accesses.  Every `Sload(slot)` (with the `Field`, or the `Mask` from a
   positive offset, that extracts bits from it, and the nodes around it,
   whose cleanups reveal the type), every `Sstore(slot, value, offset,
   size)` except those putting back bits of a word read from the same slot
   (a read-modify-write split in parts), the Panic checks (0x21 enum range,
   0x22 string encoding) and the index bounds of each function.
2. Paths.  A slot expression becomes a path:
       ("slot", n) | ("cslot", c) | ("map", parent, key) | ("data", parent)
       | ("elem", parent, index, stride, per_slot) | ("off", parent, k)
       | ("unk",)
   keccak256(key . p) is map(p, key) (key: a word, or the hashed bytes of a
   string / bytes key), keccak256(p) is data(p).  A sum has one base (a
   hash, a constant keccak256(i) + k, or a small constant), constant member
   offsets, and index terms: a multiplier (mul, shl, mask) is the element
   stride in slots, a right shift (shr, div, mask, field) the number of
   packed elements per slot.  `off(elem(.., stride s), k)` with k outside
   [0, s) moves k into the index (pop's `len - 1`).  Constants are
   decomposed as keccak256(i) + k for i < 4096 and |k| < 2**24 (the
   optimizer folds the hash of a static slot); other constants above 2**32
   are custom slots (EIP-1967, ERC-7201).
3. Locations.  Paths with keys and indices abstracted form a tree; the
   children of a location are its map, data, elem and off descendants.
4. Fields of a slot-aligned location.  Exact intervals come from writes of
   a value that is neither a constant nor a boolean, masked reads, and
   reads whose cleanup fixes the width (bool, signextend, left alignment);
   upper bounds (start reliable, end not) from constant, zero and boolean
   writes (one constant store may cover several fields, a boolean may be
   zero-extended into a wider one), right-shift-only reads and whole-word
   reads.  Reads of bits that are not
   whole bytes (`x % 2`, `x / 2`) are arithmetic, not positions.  An exact
   interval containing another is a read-modify-write and is dropped; an
   upper bound becomes a field from its start to the next boundary when no
   field covers its start.
5. Value types, strongest evidence first: local evidence (signextend ->
   intN, left alignment -> bytesN, bool cleanups -> bool, Panic 0x21 range
   checks -> enum with N members, a call target -> contract, a write from a
   parameter of a known type, from msg.sender / tx.origin -> address); then
   how the values read are used (solc applies these operations to values of
   these types only): a 1-byte field never used as a number (arithmetic,
   ordering, compared with a constant above 1) that is only ever written
   with 0 / 1, or only ever tested against zero and written with nothing
   else -> bool; a word that is an operand of signed arithmetic or signed
   comparisons -> int256; a word written from a keccak256 hash or compared
   with one, never used in arithmetic -> bytes32; then signature database
   outputs, as priors that may only refine a default uintN of the same
   width (an untrusted one only to a type whose reads have no cleanup:
   uintN, int256, bytes32 - an intN, bytesN or bool getter would have shown
   its own - and only for a variable at a static position); then uint<size>
   (address for 160 bits).
6. Composite types: map child -> mapping(K => T); data child -> string
   (the length word decoded from the short/long encoding: tested by a Panic
   0x22 check in 0.8, masked with 256 * (bit 0 == 0) - 1 before; or Panic
   0x22 without an element location below; `bytes` has the same encoding
   and is chosen only when a curated signature returns it), or a dynamic array (stride 1:
   value, > 1: struct of `stride` slots, per > 1: packed value of 256 / per
   bits); elem without data -> fixed array T[N], N from the index bound; off
   children -> struct, members by (slot, byte offset).
7. Key types per map level, by vote: caller / origin / 160-bit masks and
   values -> address, left-aligned masks -> bytesN, right masks -> uintN,
   signextend -> intN, bool cleanups, byte strings -> string, hashes (a
   keccak256 value, a 32-byte constant that reads like one: a role id) ->
   bytes32, calldata words -> the parameter type; uint256 when nothing is
   known (same layout for every 32-byte key type).
8. Names: the getters pass folds exact auto-getters (see passes/getters.py);
   a variable takes the name of its folded getter, else `_<name>` of a pure
   accessor, else a stable synthetic name `slot<N>` / `slot<N>_<byte>`;
   members `m<slot>_<byte>`, structs `Struct<i>`, enums `Enum<i>`.
9. Declarations: variables in slot order with filler variables wherever
   solc's packing would not put the next variable at its recovered
   position; the L2 self-check compiles them (solc storageLayout) and keeps
   only the variables (and struct members) that land exactly where they
   were recovered.  Custom slots (constants above 2**32 that are not a
   keccak256(i) + k) close to each other (within 2**16, an ERC-7201
   namespace or an EIP-1967 slot) form a struct at the lowest one, reached
   through a private accessor that sets the struct's slot in assembly.

Stores: the engine writes one SSTORE as one exact store per run of bits it
changes, so a narrow value zero-extended into a wider variable is a value
row followed by a zero row (one field, from the value row's start; a
variable only ever written that way takes the zero bits above it, which
nothing else uses: a narrower variable would have kept them), and a
constant store may clear several fields at once; a store whose value has
another width than its bit range is not used to infer fields.
"""

from __future__ import annotations

import bisect
import collections
import dataclasses
import functools
import re
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from eth_utils import keccak

from scobelix.solgen import ir
from scobelix.solgen.types import max_bits

__all__ = [
    "Layout",
    "Ref",
    "StateVar",
    "analyse",
    "decompose_keccak",
    "infer_layout",
    "parse_slot",
    "type_text",
]

# static slots above this are custom slots (no contract has that many variables)
MAX_STATIC_SLOT = 1 << 32
_KECCAK_RANGE = 4096
_MAX_KECCAK_DELTA = 1 << 24
_SLOT = 256
_ADDRESS_ENV = frozenset({"caller", "origin", "address", "coinbase"})
_VALUE_KINDS = ("v", "enum", "contract")


# ---------------------------------------------------------------- keccak(i) + k


@functools.lru_cache(maxsize=1)
def _keccak_table() -> Tuple[List[int], Dict[int, int]]:
    table = {int.from_bytes(keccak(i.to_bytes(32, "big")), "big"): i for i in range(_KECCAK_RANGE)}
    return sorted(table), table


def decompose_keccak(c: int, max_delta: int = _MAX_KECCAK_DELTA) -> Optional[Tuple[int, int]]:
    """(i, k) with c == keccak256(uint256(i)) + k (mod 2**256), i < 4096 and
    |k| < max_delta, or None."""
    c %= ir.WORD_MOD
    keys, table = _keccak_table()
    pos = bisect.bisect_right(keys, c)
    for cand in (keys[pos - 1] if pos else None, keys[pos] if pos < len(keys) else None,
                 keys[0] if pos == len(keys) else None, keys[-1] if pos == 0 else None):
        if cand is None:
            continue
        k = (c - cand) % ir.WORD_MOD
        if k >= ir.WORD_MOD // 2:
            k -= ir.WORD_MOD
        if -max_delta < k < max_delta:
            return table[cand], k
    return None


# ---------------------------------------------------------------- slot expressions -> paths


def _int_field(x) -> Optional[int]:
    """A Mask field as a signed int (Python int or Const), or None."""
    if isinstance(x, bool):
        return None
    if isinstance(x, int):
        return x
    if isinstance(x, ir.Const):
        return x.value - ir.WORD_MOD if x.value >> 255 else x.value
    return None


def _const(e) -> Optional[int]:
    return e.value if isinstance(e, ir.Const) else None


def _signed(v: int) -> int:
    return v - ir.WORD_MOD if v >> 255 else v


def _index_term(t: ir.Expr) -> Tuple[int, int, ir.Expr]:
    """An additive index term of a slot -> (stride in slots, elements per
    slot, index expression)."""
    if isinstance(t, ir.Op) and t.op == "mul" and len(t.args) == 2:
        for c, x in ((t.args[0], t.args[1]), (t.args[1], t.args[0])):
            k = _const(c)
            if k is not None and 0 < k < MAX_STATIC_SLOT:
                return k, 1, x
    if isinstance(t, ir.Op) and t.op == "shl":
        k = _const(t.args[0])
        if k is not None and 0 < k < 32:
            return 1 << k, 1, t.args[1]
    if isinstance(t, ir.Op) and t.op == "shr":
        k = _const(t.args[0])
        if k is not None and 0 < k <= 5:
            return 1, 1 << k, t.args[1]
    if isinstance(t, ir.Op) and t.op == "div":
        k = _const(t.args[1])
        if k is not None and 1 < k <= 32:
            return 1, k, t.args[0]
    if isinstance(t, ir.Mask):
        size, off, shl = _int_field(t.size), _int_field(t.offset), _int_field(t.shl)
        if None not in (size, off, shl):
            if off == 0 and 0 < shl < 32 and size + shl == _SLOT:
                return 1 << shl, 1, t.value  # x << shl
            if 0 < off <= 5 and shl == -off and size + off == _SLOT:
                return 1, 1 << off, t.value  # x >> off
    if isinstance(t, ir.Field):
        off, size = ir.field_bits(t.offset), ir.field_bits(t.size)
        if off is not None and size is not None and 0 < off <= 5 and off + size == _SLOT:
            return 1, 1 << off, t.value  # len >> k (push on a packed array)
    return 1, 1, t


def _word_part(b) -> Optional[ir.Expr]:
    """The word of a 32-byte part of a hashed byte string."""
    if isinstance(b, ir.WordBytes) and b.width == 32:
        return b.value
    if isinstance(b, ir.ConstBytes) and len(b.data) == 32:
        return ir.Const(int.from_bytes(b.data, "big"))
    return None


def _parts(b) -> Tuple[ir.Bytes, ...]:
    if isinstance(b, ir.Blob):
        out: Tuple[ir.Bytes, ...] = ()
        for p in b.parts:
            out += _parts(p)
        return out
    return (b,)


def parse_slot(e: ir.Expr) -> tuple:
    """The path of a slot expression (see the module docstring)."""
    if isinstance(e, ir.Const):
        v = e.value
        if v < MAX_STATIC_SLOT:
            return ("slot", v)
        d = decompose_keccak(v)
        if d is not None:
            base = ("data", ("slot", d[0]))
            return base if d[1] == 0 else _offset(base, d[1])
        return ("cslot", v)
    if isinstance(e, ir.Keccak):
        parts = _parts(e.data)
        if not parts:
            return ("unk",)
        last = _word_part(parts[-1])
        if last is None:
            return ("unk",)
        parent = parse_slot(last)
        if parent[0] == "unk":
            return ("unk",)
        if len(parts) == 1:
            return ("data", parent)
        if len(parts) == 2 and _word_part(parts[0]) is not None:
            return ("map", parent, _word_part(parts[0]))
        return ("map", parent, ir.Blob(parts[:-1]) if len(parts) > 2 else parts[0])
    if isinstance(e, ir.Op) and e.op == "add":
        k, base, idx, small = 0, None, [], []
        for t in e.args:
            if isinstance(t, ir.Const):
                v = t.value
                if v < MAX_STATIC_SLOT or ir.WORD_MOD - v < MAX_STATIC_SLOT:
                    small.append(_signed(v))
                    continue
                d = decompose_keccak(v)
                if base is None and d is not None:
                    base, k = ("data", ("slot", d[0])), k + d[1]
                elif base is None:
                    base = ("cslot", v)
                else:
                    idx.append(t)
            elif isinstance(t, ir.Keccak) and base is None:
                base = parse_slot(t)
            else:
                idx.append(t)
        if base is None:
            if not small:
                return ("unk",)
            base = ("slot", sum(small))
            if not 0 <= base[1] < MAX_STATIC_SLOT:
                return ("unk",)
        else:
            k += sum(small)
        if base[0] == "unk":
            return ("unk",)
        while base[0] == "off":
            k, base = k + base[2], base[1]
        p = base
        for stride, per, x in sorted((_index_term(t) for t in idx), key=lambda s: -s[0]):
            p = ("elem", p, x, stride, per)
        if k and p[0] == "elem" and p[4] == 1 and not 0 <= k < p[3]:
            shift, k = divmod(k, p[3])
            p = ("elem", p[1], ir.Op("add", (p[2], ir.const(shift))), p[3], p[4])
        return _offset(p, k) if k else p
    return ("unk",)


def _offset(p: tuple, k: int) -> tuple:
    if p[0] == "slot":
        return ("slot", p[1] + k) if 0 <= p[1] + k < MAX_STATIC_SLOT else ("unk",)
    if p[0] == "off":
        return _offset(p[1], p[2] + k)
    if p[0] == "cslot":
        return ("cslot", (p[1] + k) % ir.WORD_MOD)
    if k < 0:
        return ("unk",)
    return ("off", p, k)


def abstract(p: tuple) -> tuple:
    """The location of a path: keys and indices abstracted."""
    o = p[0]
    if o in ("slot", "cslot"):
        return p
    if o == "map":
        a = abstract(p[1])
        return ("unk",) if a[0] == "unk" else ("map", a)
    if o == "data":
        a = abstract(p[1])
        return ("unk",) if a[0] == "unk" else ("data", a)
    if o == "elem":
        a = abstract(p[1])
        return ("unk",) if a[0] == "unk" else ("elem", a, p[3], p[4])
    if o == "off":
        a = abstract(p[1])
        return ("unk",) if a[0] == "unk" else ("off", a, p[2])
    return ("unk",)


def _parent(ap: tuple) -> Optional[tuple]:
    return ap[1] if ap[0] in ("map", "data", "elem", "off") else None


def _root(ap: tuple) -> tuple:
    while _parent(ap) is not None:
        ap = _parent(ap)
    return ap


def _at_static_slot(ap: tuple) -> bool:
    """A location at a constant slot (a variable or a member of a struct
    variable, not reached through a key or an index)."""
    while ap[0] == "off":
        ap = ap[1]
    return ap[0] == "slot"


def _steps(p: tuple) -> Tuple[tuple, List[tuple]]:
    """(root, steps from the root) of a concrete path."""
    steps = []
    while p[0] in ("map", "data", "elem", "off"):
        steps.append(p)
        p = p[1]
    return p, list(reversed(steps))


# ---------------------------------------------------------------- accesses


@dataclasses.dataclass(frozen=True)
class Access:
    kind: str  # "R" | "W"
    func: str  # entry point key
    path: tuple
    apath: tuple
    off: Optional[int]  # bit offset in the slot (None: symbolic)
    size: Optional[int]  # bits (None: symbolic)
    value: Optional[ir.Expr] = None  # writes: the stored value
    parents: Tuple[ir.Node, ...] = ()  # reads: enclosing nodes, innermost last
    node: Optional[ir.Node] = None  # the Sstore, or the read (Field or Sload)
    zero_extended: bool = False  # writes: zero bits right above it are cleared by the same store
    zero_end: Optional[int] = None  # writes: the end bit of those zero bits
    uses: Tuple[str, ...] = ()  # reads: how the value is used (_use_tag), through a local holding it too


def _bits(x) -> Optional[int]:
    return ir.field_bits(x) if not isinstance(x, bool) else None


def _read_window(node, parent, above=None) -> Tuple[ir.Node, Optional[int], Optional[int]]:
    """(read node, bit offset, bit size) of an Sload `node` under `parent`
    (itself under `above`): a Field, or a Mask taking bits from a positive
    offset to any place (`mask_shl(32, 88, 136, w)` is a bytes4 at byte 11,
    left-aligned) that is not the kept part of a word stored back."""
    if isinstance(parent, ir.Field) and parent.value is node:
        off, size = _bits(parent.offset), _bits(parent.size)
        if off is not None and size is not None:
            if off >= _SLOT:
                return parent, None, None
            size = min(size, _SLOT - off)
        return parent, off, size
    if _offset_mask(parent) and parent.value is node and not isinstance(above, ir.Sstore) \
            and not (isinstance(above, ir.Op) and above.op in ("or", "xor")):
        off, size = _int_field(parent.offset), _int_field(parent.size)
        return parent, off, min(size, _SLOT - off)
    return node, 0, _SLOT


def _offset_mask(e) -> bool:
    """A Mask over bits [offset, offset + size) of its value, offset > 0."""
    if not isinstance(e, ir.Mask):
        return False
    off, size, shl = _int_field(e.offset), _int_field(e.size), _int_field(e.shl)
    return None not in (off, size, shl) and 0 < off < _SLOT and size > 0


def _walk(node, parents: Tuple[ir.Node, ...]) -> Iterator[Tuple[ir.Node, Tuple[ir.Node, ...]]]:
    stack = [(node, parents)]
    while stack:
        n, par = stack.pop()
        yield n, par
        kids = list(ir.children(n))
        for c in reversed(kids):
            stack.append((c, par[-5:] + (n,)))


def _panic_payload(block) -> Optional[int]:
    if len(block) == 1 and isinstance(block[0], ir.Revert) and isinstance(block[0].payload, ir.Panic):
        return block[0].payload.code
    return None


def _plain_revert(block) -> bool:
    return len(block) == 1 and isinstance(block[0], ir.Revert) and isinstance(block[0].payload, ir.Empty)


@dataclasses.dataclass
class _FnFacts:
    key: str
    accesses: List[Access] = dataclasses.field(default_factory=list)
    panics: List[Tuple[ir.Expr, int]] = dataclasses.field(default_factory=list)  # (condition that reverts, code)
    bounds: List[Tuple[ir.Expr, int]] = dataclasses.field(default_factory=list)  # (index, N) of index < N checks
    effects: bool = False  # writes, calls, logs, creates...
    returns: List[ir.Return] = dataclasses.field(default_factory=list)


_EFFECTS = (ir.Sstore, ir.TStore, ir.Log, ir.Emit, ir.ExtCall, ir.Create, ir.SelfDestruct, ir.Precompile,
            ir.Unstructured)


def _bound_of(cond: ir.Expr) -> List[Tuple[ir.Expr, int]]:
    """(index, N) for each `index < N` test (in any form) inside cond."""
    out = []
    for n in ir.walk(cond):
        if isinstance(n, ir.Op) and n.op in ("lt", "gt") and len(n.args) == 2:
            a, b = n.args
            if n.op == "lt" and isinstance(b, ir.Const) and not isinstance(a, ir.Const):
                out.append((a, b.value))  # a < N
            elif n.op == "gt" and isinstance(a, ir.Const) and not isinstance(b, ir.Const):
                out.append((b, a.value))  # N > b
            elif n.op == "gt" and isinstance(b, ir.Const) and not isinstance(a, ir.Const) and b.value < ir.WORD_MAX:
                out.append((a, b.value + 1))  # a > N - 1
            elif n.op == "lt" and isinstance(a, ir.Const) and not isinstance(b, ir.Const) and a.value < ir.WORD_MAX:
                out.append((b, a.value + 1))  # N - 1 < b
    return out


def _loaded_locals(fn: ir.Function) -> Dict[str, ir.Sload]:
    """Locals assigned once, from a storage read."""
    counts: collections.Counter = collections.Counter()
    loads: Dict[str, ir.Sload] = {}
    for n in ir.walk_all(fn.body):
        if isinstance(n, ir.Assign) and isinstance(n.target, ir.Local):
            counts[n.target.name] += 1
            if n.op is None and isinstance(n.value, ir.Sload):
                loads[n.target.name] = n.value
    return {k: v for k, v in loads.items() if counts[k] == 1}


def _local_uses(fn: ir.Function) -> Tuple[collections.Counter, Dict[str, List[str]]]:
    """(assignments per local, the _use_tag of every other occurrence of
    each local)."""
    counts: collections.Counter = collections.Counter()
    uses: Dict[str, List[str]] = collections.defaultdict(list)
    for stmt in fn.body:
        for n, par in _walk(stmt, ()):
            if not isinstance(n, ir.Local):
                continue
            p = par[-1] if par else None
            if isinstance(p, ir.Assign) and p.target is n:
                counts[n.name] += 1
            else:
                uses[n.name].append(_use_tag(p, n))
    return counts, uses


def _read_uses(read: ir.Node, user: Optional[ir.Node], counts: collections.Counter,
               uses: Dict[str, List[str]]) -> Tuple[str, ...]:
    """How the value of a read is used: by the node above it, or, assigned to
    a local once, by every use of that local."""
    if isinstance(user, ir.Assign) and isinstance(user.target, ir.Local) and user.op is None \
            and user.value is read and counts[user.target.name] == 1:
        return tuple(uses.get(user.target.name, ()))
    return (_use_tag(user, read),)


def _write_back(st: ir.Sstore, loads: Dict[str, ir.Sload]) -> bool:
    """The store puts back bits of a word read from the same slot, where
    they were (the engine's split of a read-modify-write): no field."""
    off, size, v = _bits(st.offset), _bits(st.size), st.value
    if off is None or size is None or not isinstance(v, ir.Mask) \
            or (_int_field(v.size), _int_field(v.offset), _int_field(v.shl)) != (size, off, -off):
        return False
    x = loads.get(v.value.name) if isinstance(v.value, ir.Local) else v.value
    return isinstance(x, ir.Sload) and x.slot == st.slot


def _blocks(body: Sequence[ir.Stmt]) -> Iterator[Tuple[ir.Stmt, ...]]:
    """Every statement sequence of a body (the body, branches, loop bodies)."""
    yield tuple(body)
    for n in ir.walk_all(tuple(body)):
        if isinstance(n, ir.Stmt):
            for f in dataclasses.fields(n):
                v = getattr(n, f.name)
                if isinstance(v, tuple) and v and all(isinstance(x, ir.Stmt) for x in v):
                    yield v


def _zero_extended(fn: ir.Function) -> Dict[int, int]:
    """id -> end bit of the zero bits right above it, for the value stores
    whose bits right above them a zero store of the same run of stores to
    that slot clears.  The engine writes one SSTORE as one store per run of
    bits it changes, so a narrower value zero-extended into a wider variable
    (uint256 acc = uint8 v) reads like a narrow field followed by a cleared
    one: its start is a field boundary, its end at most the end of the
    cleared bits."""
    out: Dict[int, int] = {}
    for block in _blocks(fn.body):
        i = 0
        while i < len(block):
            j = i
            while j < len(block) and isinstance(block[j], ir.Sstore) and block[j].slot == block[i].slot:
                j += 1
            zeros: Dict[int, int] = {}
            for s in block[i:j]:
                off, size = _bits(s.offset), _bits(s.size)
                if off is not None and size is not None and _known_zero(s.value):
                    zeros[off] = off + size
            for s in block[i:j]:
                off, size = _bits(s.offset), _bits(s.size)
                if off is not None and size is not None and not _known_zero(s.value) and off + size in zeros:
                    end = off + size
                    while end in zeros and zeros[end] > end:
                        end = zeros[end]
                    out[id(s)] = min(end, _SLOT)
            i = max(j, i + 1)
    return out


def _collect(fn: ir.Function) -> _FnFacts:
    facts = _FnFacts(fn.key)
    loads = _loaded_locals(fn)
    extended = _zero_extended(fn)
    assigned, local_uses = _local_uses(fn)
    for stmt in fn.body:
        for n, par in _walk(stmt, ()):
            if isinstance(n, _EFFECTS):
                facts.effects = True
            if isinstance(n, ir.Return):
                facts.returns.append(n)
            if isinstance(n, ir.Sstore):
                off, size = _bits(n.offset), _bits(n.size)
                if size == 0 or _write_back(n, loads):
                    continue
                p = parse_slot(n.slot)
                facts.accesses.append(Access("W", fn.key, p, abstract(p), off, size, n.value, (), n,
                                             zero_extended=id(n) in extended, zero_end=extended.get(id(n))))
            elif isinstance(n, ir.Sload):
                parent = par[-1] if par else None
                read, off, size = _read_window(n, parent, par[-2] if len(par) > 1 else None)
                above = par[:-1] if read is parent else par
                p = parse_slot(n.slot)
                uses = _read_uses(read, above[-1] if above else None, assigned, local_uses)
                facts.accesses.append(Access("R", fn.key, p, abstract(p), off, size, None, tuple(above[-4:]), read,
                                             uses=uses))
            elif isinstance(n, ir.If):
                for block, cond in ((n.then, n.cond), (n.orelse, ir.Op("iszero", (n.cond,)))):
                    code = _panic_payload(block)
                    if code is not None:
                        facts.panics.append((cond, code))
                    invalid = len(block) == 1 and isinstance(block[0], ir.Invalid)
                    if code == 0x32 or invalid or _plain_revert(block):
                        facts.bounds.extend(_bound_of(n.cond))
    return facts


# ---------------------------------------------------------------- evidence


def _unwrap(v: ir.Expr) -> ir.Expr:
    """The value under right-aligned cleanup masks."""
    while isinstance(v, ir.Mask) and _int_field(v.offset) == 0 and _int_field(v.shl) == 0:
        v = v.value
    return v


def _is_bool_value(v: ir.Expr) -> bool:
    if isinstance(v, (ir.Bool, ir.Not, ir.And, ir.Or)):
        return True
    return isinstance(v, ir.Op) and v.op in ir.COMPARISONS


def _bool_wrapped(read, parents) -> bool:
    """iszero(iszero(read)): the trace's bool() cleanup."""
    return (len(parents) >= 2 and isinstance(parents[-1], ir.Op) and parents[-1].op == "iszero"
            and isinstance(parents[-2], ir.Op) and parents[-2].op == "iszero")


# how a value read is used, right above its cleanup or through the local that
# holds it (the usage evidence of _value_type: solc only applies these
# operations to values of these types)
_UNSIGNED_OPS = frozenset({"lt", "gt", "add", "sub", "mul", "div", "mod", "exp", "addmod", "mulmod"})
_SIGNED_OPS = frozenset({"slt", "sgt", "sdiv", "smod"})


def _use_tag(p: Optional[ir.Node], node: ir.Node) -> str:
    """What `p` does with its operand `node`: "truth" (tested against zero:
    iszero, a condition, bool()), "signed" / "unsigned" (arithmetic or an
    ordering comparison; signed: slt, sgt, sdiv, smod, sar), "hash"
    (compared with a keccak256 hash), "intcmp" (compared with a constant
    above 1), else "other"."""
    if isinstance(p, ir.Op) and any(x is node for x in p.args):
        if p.op == "iszero":
            return "truth"
        if p.op in _SIGNED_OPS or (p.op == "sar" and p.args[1] is node):
            return "signed"
        if p.op in _UNSIGNED_OPS:
            return "unsigned"
        if p.op == "eq" and any(isinstance(x, ir.Keccak) for x in p.args):
            return "hash"
        if p.op == "eq" and any(isinstance(x, ir.Const) and x.value > 1 for x in p.args):
            return "intcmp"
        return "other"
    if isinstance(p, (ir.If, ir.While, ir.Require, ir.Assert, ir.Ternary)) and p.cond is node:
        return "truth"
    if isinstance(p, ir.Bool) and p.value is node:
        return "truth"
    return "other"


def _truth_use(a: Access) -> bool:
    """The value read is only ever tested against zero."""
    return bool(a.uses) and all(t == "truth" for t in a.uses)


def _number_use(a: Access) -> Set[str]:
    """"signed" / "unsigned" uses of the value read."""
    return {t for t in a.uses if t in ("signed", "unsigned")}


def _integer_use(a: Access) -> bool:
    """The value read is used as a number (arithmetic, ordering, compared
    with a constant other than 0 and 1): no bool."""
    return any(t in ("signed", "unsigned", "intcmp") for t in a.uses)


def _hash_compared(a: Access) -> bool:
    """The value read is compared with a keccak256 hash."""
    return "hash" in a.uses


def read_evidence(a: Access) -> Tuple[Optional[int], Optional[str], bool]:
    """(exact width in bits or None, type hint, offset reliable) of a read."""
    node, par, packed = a.node, a.parents, False
    if _offset_mask(node):
        size, off, shl = _int_field(node.size), _int_field(node.offset), _int_field(node.shl)
        if size % 8 == 0 and off % 8 == 0 and size + off <= _SLOT and shl == _SLOT - size - off:
            return size, f"bytes{size // 8}", True  # moved to the top: bytesN
        if shl != -off:
            return None, None, True  # moved elsewhere: its bits, no type
        # moved down: the value, as a Field read (the cleanups above tell its type)
    if a.off == 0 and a.size == _SLOT and par and isinstance(par[-1], ir.Op) and par[-1].op == "div" \
            and par[-1].args[0] is node and not isinstance(par[-1].args[1], ir.Const):
        # a packed element shifted down by a symbolic amount (legacy
        # element reads): its cleanup gives the element type, not a width
        node, par, packed = par[-1], par[:-1], True
    width, hint = None, None
    if par:
        p = par[-1]
        if _bool_wrapped(node, par):
            # bool() on a wider read is an integer != 0 test, not a bool field
            # (a packed element of symbolic width: the element width decides)
            if a.size is None or packed:
                hint = "bool"
            elif a.size <= 8:
                width, hint = 8, "bool"
        elif isinstance(p, ir.Op) and p.op == "signextend":
            b = _const(p.args[0])
            if b is not None and b < 31 and p.args[1] is node:
                width, hint = 8 * (b + 1), f"int{8 * (b + 1)}"
        elif isinstance(p, ir.Mask) and p.value is node:
            size, off, shl = _int_field(p.size), _int_field(p.offset), _int_field(p.shl)
            if None not in (size, off, shl) and off == 0 and 0 < size < _SLOT and size % 8 == 0:
                if shl == _SLOT - size:
                    width, hint = size, f"bytes{size // 8}"  # left-aligned: bytesN
                elif shl == 0:
                    width = size  # right-aligned cleanup: uintN
        elif isinstance(p, ir.Op) and p.op == "eq" and any(x is not node and _address_word(x) for x in p.args):
            hint = "address"  # compared with an address: the field is one (its end is a guess)
        elif isinstance(p, ir.Op) and p.op == "shl" and p.args[1] is node:
            k = _const(p.args[0])
            if k is not None and 0 < k < _SLOT and k % 8 == 0 and a.size is not None and a.size >= _SLOT - k:
                width, hint = _SLOT - k, f"bytes{(_SLOT - k) // 8}"
    if packed:
        return None, hint, False
    return width, hint, True


def _low_bit(e: ir.Expr, word: ir.Expr) -> bool:
    """e is bit 0 of word."""
    if isinstance(e, ir.Field):
        return _bits(e.offset) == 0 and _bits(e.size) == 1 and e.value == word
    if isinstance(e, ir.Mask):
        return (_int_field(e.size), _int_field(e.offset), _int_field(e.shl)) == (1, 0, 0) and e.value == word
    return isinstance(e, ir.Op) and e.op == "and" and len(e.args) == 2 and ir.ONE in e.args and word in e.args


def _legacy_length_read(a: Access) -> bool:
    """The length word of a string / bytes before 0.8: read whole and
    masked with 256 * (bit 0 == 0) - 1 (a short value keeps 2 * length in
    its last byte, a long one 2 * length + 1 in the whole word)."""
    if a.kind != "R" or a.off != 0 or a.size != _SLOT or not a.parents:
        return False
    p = a.parents[-1]
    if not (isinstance(p, ir.Op) and p.op == "and" and len(p.args) == 2 and any(x is a.node for x in p.args)):
        return False
    other = p.args[1] if p.args[0] is a.node else p.args[0]
    return any(isinstance(n, ir.Op) and n.op == "iszero" and _low_bit(n.args[0], a.node) for n in ir.walk(other))


def _address_word(e: ir.Expr) -> bool:
    if isinstance(e, ir.Env):
        return e.name in _ADDRESS_ENV
    if isinstance(e, ir.Mask):
        return (_int_field(e.size), _int_field(e.offset), _int_field(e.shl)) == (160, 0, 0)
    return False


def _call_target(a: Access) -> bool:
    for p in a.parents[-2:]:
        if isinstance(p, ir.ExtCall):
            return any(x is a.node for x in ir.walk(p.to))
        if isinstance(p, (ir.Balance, ir.ExtCodeSize, ir.ExtCodeHash)):
            return False
    return False


def _head_word(e) -> Optional[int]:
    if isinstance(e, ir.CalldataWord) and isinstance(e.offset, ir.Const):
        off = e.offset.value
        if off >= 4 and (off - 4) % 32 == 0:
            return (off - 4) // 32
    if isinstance(e, ir.Param):
        return e.index
    return None


def write_evidence(a: Access, params: Dict[int, str]) -> Tuple[Optional[str], bool]:
    """(type hint, interval reliable) of a write.  Constant and boolean
    values give upper bounds only (a constant store may cover several
    fields, a boolean may be the low byte of a wider one)."""
    v = _unwrap(a.value)
    if isinstance(v, ir.Const) or _known_zero(v):
        return None, False
    if _is_bool_value(v):
        return "bool", False
    if isinstance(v, ir.Env) and v.name in _ADDRESS_ENV:
        return "address", True
    if isinstance(v, ir.Op) and v.op == "signextend":
        b = _const(v.args[0])
        if b is not None and b < 31:
            return f"int{8 * (b + 1)}", True
    w = _head_word(v)
    if w is not None:
        t = params.get(w)
        if t and t != "uint256":
            return t, True
    if isinstance(v, ir.Mask):
        size, off, shl = _int_field(v.size), _int_field(v.offset), _int_field(v.shl)
        if None not in (size, off, shl) and off > 0 and shl == -off and size + off == _SLOT and size % 8 == 0:
            return f"bytes{size // 8}", True  # a left-aligned bytesN moved down
    return None, True


# ---------------------------------------------------------------- fields


class _Field:
    def __init__(self, off: int, size: int):
        self.off, self.size = off, size
        self.hints: collections.Counter = collections.Counter()
        self.srcs: List[Access] = []


def partition(accs: Sequence[Access], params: Dict[str, Dict[int, str]]) -> List[_Field]:
    """The fields (bit intervals) of one slot-aligned location."""
    exact, upper = [], []
    for a in accs:
        if a.off is None or a.size is None or a.size <= 0 or a.off < 0 or a.off + a.size > _SLOT:
            continue
        if a.kind == "W":
            h, reliable = write_evidence(a, params.get(a.func, {}))
            if h and h != "bool" and a.size < _SLOT and _hint_bits(h) not in (None, a.size):
                continue  # a value of another width (truncated or widened): no evidence of the field
            iv = (a.off, a.off + a.size)
            exact_write = reliable and (a.size < _SLOT or a.off == 0) and not a.zero_extended
            (exact if exact_write else upper).append((iv, h, a))
            continue
        width, hint, off_ok = read_evidence(a)
        if (a.off % 8 or a.size % 8) and width is None and hint is None:
            continue  # arithmetic on some bits of a value (x % 2, x / 2): not its position
        if _call_target(a):
            hint = "contract"
        if width is not None:
            (exact if off_ok else upper).append(((a.off, min(_SLOT, a.off + width)), hint, a))
        elif hint == "address" and a.off + 160 <= _SLOT:
            upper.append(((a.off, a.off + 160), hint, a))  # a whole word compared with an address
        elif a.off > 0 and a.off + a.size == _SLOT:
            upper.append(((a.off, _SLOT), hint, a))  # shift-only read
        elif not off_ok:
            upper.append(((a.off, a.off + a.size), hint, a))
        elif a.off == 0 and a.size == _SLOT:
            upper.append(((0, _SLOT), hint, a))  # whole word
        else:
            exact.append(((a.off, a.off + a.size), hint, a))
    # a read of some bits of a value written whole (tag[0] of a bytes4, a
    # shifted part of a word) is no field of its own; a read of every bit the
    # value can have is one (an address stored as a whole word, then read as
    # the 160-bit variable it is)
    whole = [(iv, _value_end(a, h)) for iv, h, a in exact if a.kind == "W" and _single_value(a.value)]
    exact = [(iv, h, a) for iv, h, a in exact
             if a.kind == "W" or not any(w != iv and w[0] <= iv[0] and iv[1] <= w[1]
                                         and not (iv[0] == w[0] and end <= iv[1]) for w, end in whole)]
    ivs = {iv for iv, _, _ in exact}
    keep = {iv for iv in ivs if not any(j != iv and iv[0] <= j[0] and j[1] <= iv[1] for j in ivs)}
    fields: Dict[Tuple[int, int], _Field] = {}
    for iv in sorted(keep):
        if any(f[0] < iv[1] and iv[0] < f[1] for f in fields):
            continue
        fields[iv] = _Field(iv[0], iv[1] - iv[0])
    for iv, h, a in exact:
        for k, f in fields.items():
            if k[0] <= iv[0] < k[1]:
                f.srcs.append(a)
                if h:
                    f.hints[h] += 1
                break
    bounds = sorted({b for k in fields for b in k})
    for iv, h, a in sorted(upper, key=lambda x: (x[0][0], -x[0][1])):
        s, e = iv
        hit = [k for k in fields if k[0] <= s < k[1]]
        if hit:
            fields[hit[0]].srcs.append(a)
            if h:
                fields[hit[0]].hints[h] += 1
            continue
        if s == 0 and e == _SLOT and fields:
            continue
        e2 = min([e] + [b for b in bounds if b > s])
        f = _Field(s, e2 - s)
        f.srcs.append(a)
        if h:
            f.hints[h] += 1
        fields[(s, e2)] = f
        bounds = sorted(set(bounds) | {s, e2})
    return [fields[k] for k in sorted(fields)]


def _single_value(v: ir.Expr) -> bool:
    """A written value that is one value: not the parts of several fields
    (`or`), no storage bits copied or kept (a read-modify-write, a struct
    copy); its bit range is then one field."""
    v = _unwrap(v)
    if isinstance(v, ir.Op) and v.op in ("or", "xor"):
        return False
    return not ir.contains(v, ir.Sload)


def _value_end(a: Access, hint: Optional[str]) -> int:
    """The bit of the slot where the value a write stores ends: the end of
    the store, or lower when the value is known to be narrower (its type, or
    the bound of its bits)."""
    bits = _hint_bits(hint) if hint and hint != "bool" else None
    if bits is None:
        bits = max_bits(a.value)
    return a.off + min(a.size, bits)


def _cleared_only(f: _Field) -> bool:
    """A field after another one that is only ever written with zero (never
    read): the zero store of unused bits above a zero-extended value."""
    return f.off > 0 and bool(f.srcs) and all(a.kind == "W" and _known_zero(a.value) for a in f.srcs)


def _widened(fields: List[_Field]) -> List[_Field]:
    """The fields of a top-level slot, each value that is only ever written
    zero-extended (never read, never written at its own width) joined with
    the cleared-only bits right above it: they are its own high bits
    (`uint256 v = p` for a uint128 p: the SSTORE writes the zeros, a
    narrower variable would keep the bits above it)."""
    out: List[_Field] = []
    i = 0
    while i < len(fields):
        f, g = fields[i], fields[i + 1] if i + 1 < len(fields) else None
        if g is not None and g.off == f.off + f.size and _cleared_only(g) and f.srcs and all(
                a.kind == "W" and a.zero_extended and (a.zero_end or 0) >= g.off + g.size for a in f.srcs):
            m = _Field(f.off, g.off + g.size - f.off)
            m.srcs, m.hints = f.srcs + g.srcs, f.hints + g.hints
            out.append(m)
            i += 2
            continue
        out.append(f)
        i += 1
    return out


def _known_zero(v: ir.Expr) -> bool:
    """The stored value is provably 0."""
    return max_bits(v) == 0


def _hint_bits(h: str) -> Optional[int]:
    """The bit width a value type hint implies (None: any)."""
    if h in ("address", "contract"):
        return 160
    m = re.fullmatch(r"(u?int|bytes)(\d+)", h)
    if m:
        return int(m.group(2)) * (8 if m.group(1) == "bytes" else 1)
    return None


# ---------------------------------------------------------------- types
#
#   ("v", "uint8" | "int64" | "bytes4" | "bool" | "address" ...)
#   ("enum", n) | ("contract",) | ("map", key type, T) | ("dyn", T)
#   ("fix", T, n) | ("bytes",) | ("string",)
#   ("struct", ((slot, byte offset, T), ...), slots)


def is_value(t: tuple) -> bool:
    return t[0] in _VALUE_KINDS


def val_nbytes(t: tuple) -> int:
    if t[0] == "enum":
        return 1
    if t[0] == "contract":
        return 20
    n = t[1]
    if n == "bool":
        return 1
    if n == "address":
        return 20
    m = re.fullmatch(r"(u?int|bytes)(\d+)", n)
    if m:
        bits = int(m.group(2))
        return bits // 8 if m.group(1) != "bytes" else bits
    return 32


def nslots(t: tuple) -> int:
    if is_value(t) or t[0] in ("map", "dyn", "bytes", "string"):
        return 1
    if t[0] == "fix":
        base, n = t[1], max(1, t[2] or 1)
        if is_value(base):
            per = 32 // val_nbytes(base)
            return -(-n // per)
        return n * nslots(base)
    if t[0] == "struct":
        return t[2]
    return 1


def _no_cleanup(t: str) -> bool:
    """A read of a value of type t looks like a read of a uintN: no
    sign extension, left alignment or bool cleanup would have told it (an
    untrusted database output naming such a type is contradicted by the
    reads)."""
    return t.startswith("uint") or t in ("int256", "bytes32")


def _value_type(f: _Field, enum_n: Optional[int] = None, prior: Optional[str] = None) -> tuple:
    size = f.size
    if enum_n:
        return ("enum", enum_n)
    h = f.hints
    for kind in ("int", "bytes"):
        cands = [k for k in h if k.startswith(kind) and k[len(kind):].isdigit() and int(k[len(kind):]) * (
            1 if kind == "int" else 8) == size]
        if cands:
            return ("v", max(cands, key=lambda k: h[k]))
    if "bool" in h and size <= 8:
        return ("v", "bool")
    reads = [a for a in f.srcs if a.kind == "R"]
    ws = [_unwrap(a.value) for a in f.srcs if a.kind == "W"]
    if size == 8 and f.srcs and not any(_integer_use(a) for a in reads):
        # a 1-byte field never used as a number, only ever written with 0 / 1,
        # or only ever tested against zero (and written with nothing else)
        if all(w in (ir.ZERO, ir.ONE) or _is_bool_value(w) for w in ws) and (
                ir.ONE in ws or (reads and all(_truth_use(a) for a in reads))):
            return ("v", "bool")
    if size == _SLOT and f.srcs:
        uses = {u for a in reads for u in _number_use(a)}
        if "signed" in uses:
            return ("v", "int256")  # signed arithmetic or comparisons: solc uses them for intN only
        if "unsigned" not in uses and (any(_hash_compared(a) for a in reads)
                                       or any(isinstance(w, ir.Keccak) for w in ws)):
            return ("v", "bytes32")  # a hash: written from keccak256 or compared with one, no arithmetic
    if "contract" in h and size == 160:
        return ("contract",)
    if size == 160 or "address" in h:
        return ("v", "address") if size == 160 else ("v", f"uint{size}")
    size8 = ((size + 7) // 8) * 8
    t = ("v", f"uint{size8}") if 8 <= size8 <= _SLOT else ("v", "uint256")
    if prior and prior != "address" and val_nbytes(("v", prior)) == val_nbytes(t):
        return ("v", prior)  # a database output of the same width refines the default
    return t


def _hash_like(c: int) -> bool:
    """A 32-byte constant that reads like a keccak256 hash (a role id):
    above every address and small number, no mask (2**k - 1), no small
    negative number, no left-aligned short byte string (zero low bytes)."""
    return 1 << 160 <= c < (1 << 256) - (1 << 64) and c & 0xFFFFFFFF != 0 and c & (c + 1) != 0


def _key_type(keys: Sequence[Tuple[str, object]], params: Dict[str, Dict[int, str]]) -> str:
    votes: collections.Counter = collections.Counter()
    for func, k in keys:
        t = None
        if isinstance(k, ir.Bytes):
            t = "string"  # string or bytes: same hashing, string is the common one
        elif isinstance(k, ir.Keccak) or (isinstance(k, ir.Const) and _hash_like(k.value)):
            t = "bytes32"  # a hash
        elif isinstance(k, ir.Env) and k.name in _ADDRESS_ENV:
            t = "address"
        elif isinstance(k, ir.Mask):
            size, off, shl = _int_field(k.size), _int_field(k.offset), _int_field(k.shl)
            if None not in (size, off, shl):
                if size == 160 and off == 0 and shl == 0:
                    t = "address"
                elif shl == 0 and off > 0 and off + size == _SLOT and size % 8 == 0:
                    t = f"bytes{size // 8}"
                elif off == 0 and shl == 0 and size % 8 == 0 and 8 <= size < _SLOT:
                    t = f"uint{size}"
        elif isinstance(k, ir.Op) and k.op == "signextend" and _const(k.args[0]) is not None and _const(k.args[0]) < 31:
            t = f"int{8 * (_const(k.args[0]) + 1)}"
        elif isinstance(k, ir.Op) and k.op == "iszero" and isinstance(k.args[0], ir.Op) and k.args[0].op == "iszero":
            t = "bool"
        elif isinstance(k, ir.Field) and _bits(k.size) == 160 and _bits(k.offset) == 0:
            t = "address"
        else:
            w = _head_word(k)
            if w is not None:
                t = params.get(func, {}).get(w)
        if t and t != "dynamic":
            votes[t] += 1
    specific = [t for t in votes if t != "uint256"]
    if specific:
        return max(specific, key=lambda t: (votes[t], t))
    return "uint256"


# ---------------------------------------------------------------- results


@dataclasses.dataclass
class StateVar:
    """One recovered state variable (a top-level declaration)."""

    vid: str  # stable id: slot<N> / slot<N>_<byte>
    slot: int
    offset: int  # bytes
    type: tuple
    evidence: str = ""
    accessors: List[Tuple[str, str]] = dataclasses.field(default_factory=list)  # (function key, name) pure readers

    @property
    def end(self) -> int:
        """First slot after the variable."""
        return self.slot + nslots(self.type)


@dataclasses.dataclass(frozen=True)
class Ref:
    """A variable access: `var`, then `steps`, lead to a value of type `ty`
    stored at bits [bit_off, bit_off + bits) of its slot.

    steps: ("key", word or bytes, key type) | ("index", word, length or None,
    dynamic[, path of the dynamic array]) | ("member", name) | ("length",)."""

    var: StateVar
    steps: Tuple[tuple, ...]
    ty: tuple
    bit_off: int
    bits: int


@dataclasses.dataclass
class Layout:
    """The recovered storage layout of a contract."""

    vars: List[StateVar]
    structs: Dict[tuple, str]  # (members, slots) -> struct name
    enums: Dict[int, str]  # member count -> enum name
    namespaces: List[StateVar] = dataclasses.field(default_factory=list)  # custom slots: base slot, struct type
    dropped: List[str] = dataclasses.field(default_factory=list)  # removed by the self-check (vid: reason)
    checked: Optional[bool] = None  # True: the L2 self-check ran; None: no compiler
    names: Dict[str, str] = dataclasses.field(default_factory=dict)  # vid -> declared name
    public: Set[str] = dataclasses.field(default_factory=set)  # vids declared public (folded getters)
    warnings: List[str] = dataclasses.field(default_factory=list)

    # ---- lookups for the passes

    def var_at(self, slot: int, byte: int = 0) -> Optional[StateVar]:
        """The variable holding byte `byte` of `slot`."""
        for v in self.vars:
            if v.slot <= slot < v.end and (not is_value(v.type) or v.offset <= byte < v.offset + val_nbytes(v.type)):
                return v
        return None

    def namespace_at(self, slot: int) -> Optional[StateVar]:
        for v in self.namespaces:
            if 0 <= slot - v.slot < nslots(v.type):
                return v
        return None

    def name(self, v: StateVar) -> str:
        """The declared name; for a namespace, its accessor call."""
        if v in self.namespaces:
            return f"{namespace_accessor(v)}()"
        return self.names.get(v.vid, v.vid)

    def struct_name(self, t: tuple) -> str:
        return self.structs[(t[1], t[2])]

    def _walk(self, path: tuple, bit_off: int) -> Optional[Tuple[StateVar, List[tuple], tuple, int, int]]:
        """Follow a concrete path from its root variable: (variable, steps,
        type, slot, byte) of the position the path ends at."""
        root, steps = _steps(path)
        if root[0] == "slot":
            v = self.var_at(root[1], 0 if steps else bit_off // 8)
        elif root[0] == "cslot":
            v = self.namespace_at(root[1])
        else:
            return None
        if v is None:
            return None
        out: List[tuple] = []
        t, r, b = v.type, root[1] - v.slot, 0
        array = None
        for st in steps:
            if st[0] == "off":
                r += st[2]
                continue
            loc = _descend(t, r, 0, out, stop_at_array=True)
            if loc is None or loc[1] != 0 or loc[2] != 0:
                return None
            t = loc[0]
            if st[0] == "map" and t[0] == "map":
                out.append(("key", st[2], t[1]))
                t, r = t[2], 0
            elif st[0] == "data" and t[0] == "dyn":
                t, r, array = ("elems", t[1]), 0, st[1]
            elif st[0] == "elem" and t[0] in ("elems", "fix") and st[4] == 1 and nslots(t[1]) == st[3]:
                # a dynamic array's index step carries the array's own path
                # (whose slot holds the length the index must stay below)
                out.append(("index", st[2], t[2] if t[0] == "fix" else None, t[0] == "elems")
                           + ((array,) if t[0] == "elems" else ()))
                t, r = t[1], 0
            else:
                return None
        if t[0] == "elems":
            return None
        b = bit_off // 8 - (v.offset if not steps else 0)
        return v, out, t, r, b

    def resolve(self, slot_expr: ir.Expr, bit_off: int, bits: int) -> Optional[Ref]:
        """The variable value a raw access is exactly (slot expression, bit
        offset, bit size), or None."""
        if bit_off % 8 or bits % 8 or not 0 <= bit_off < _SLOT:
            return None
        w = self._walk(parse_slot(slot_expr), bit_off)
        if w is None:
            return None
        v, out, t, r, b = w
        loc = _descend(t, r, b, out)
        if loc is None:
            return None
        t, r, b = loc
        if r != 0 or b != 0 or not is_value(t) or val_nbytes(t) * 8 != bits:
            return None
        return Ref(v, tuple(out), t, bit_off, bits)

    def length_ref(self, slot_expr: ir.Expr) -> Optional[Ref]:
        """`arr.length` when the slot is the length word of a dynamic array."""
        w = self._walk(parse_slot(slot_expr), 0)
        if w is None:
            return None
        v, out, t, r, b = w
        loc = _descend(t, r, 0, out, stop_at_array=True)
        if loc is None or loc[1] != 0 or loc[2] != 0 or loc[0][0] != "dyn":
            return None
        return Ref(v, tuple(out) + (("length",),), ("v", "uint256"), 0, _SLOT)


def _descend(t: tuple, r: int, b: int, out: List[tuple], stop_at_array: bool = False
             ) -> Optional[Tuple[tuple, int, int]]:
    """The innermost type at slot r, byte b of a value of type t: (type, slot,
    byte) relative to that type, recording the member and constant index
    steps taken.  Mappings, dynamic arrays and bytes stop the descent (and
    fixed arrays, with stop_at_array)."""
    while True:
        if r < 0 or r >= nslots(t) or not 0 <= b < 32:
            return None
        if t[0] == "struct":
            hit = None
            for ms, mo, mt in t[1]:
                if is_value(mt):
                    if ms == r and mo <= b < mo + val_nbytes(mt):
                        hit = (ms, mo, mt)
                        break
                elif ms <= r < ms + nslots(mt):
                    hit = (ms, mo, mt)
                    break
            if hit is None:
                return None
            ms, mo, mt = hit
            out.append(("member", member_name(ms, mo)))
            if is_value(mt):
                t, r, b = mt, 0, b - mo
            else:
                t, r = mt, r - ms
            continue
        if t[0] == "fix" and not (stop_at_array and r == 0 and b == 0):
            base, n = t[1], max(1, t[2] or 1)
            if is_value(base):
                nb = val_nbytes(base)
                per = 32 // nb
                if b >= per * nb:
                    return None
                i = r * per + b // nb
                if i >= n:
                    return None
                out.append(("index", ir.const(i), n, False))
                t, r, b = base, 0, b % nb
            else:
                ns = nslots(base)
                i = r // ns
                out.append(("index", ir.const(i), n, False))
                t, r = base, r - i * ns
            continue
        return t, r, b


def member_name(slot: int, byte: int) -> str:
    return f"m{slot}_{byte}"


def namespace_accessor(v: StateVar) -> str:
    """The private function returning a custom-slot namespace (its struct at
    the base slot)."""
    return f"_namespace{v.slot >> 224:08x}"


def type_text(t: tuple, layout: Layout) -> str:
    """The Solidity type of a recovered type."""
    k = t[0]
    if k == "v":
        return t[1]
    if k == "contract":
        return "address"
    if k == "enum":
        return layout.enums[t[1]]
    if k == "map":
        return f"mapping({t[1]} => {type_text(t[2], layout)})"
    if k == "dyn":
        return f"{type_text(t[1], layout)}[]"
    if k == "fix":
        return f"{type_text(t[1], layout)}[{max(1, t[2] or 1)}]"
    if k in ("bytes", "string"):
        return k
    if k == "struct":
        return layout.struct_name(t)
    return "uint256"


def solidity_value_type(t: tuple) -> Optional[str]:
    """The Solidity value type an access of t reads and writes (enums are
    not value types here: their conversions check the range)."""
    if t[0] == "v":
        return t[1]
    if t[0] == "contract":
        return "address"
    return None


# ---------------------------------------------------------------- inference


def _param_types(spec) -> Dict[int, str]:
    """Head word -> value type of an entry's parameters: the keccak-verified
    signature's, else the decoder validators'."""
    out: Dict[int, str] = {}
    word = 0
    for t, _ in getattr(spec, "params", ()) or ():
        if t.is_value:
            out[word] = t.canonical
        word += t.head_words
    for w, ty in (getattr(spec, "inferred", {}) or {}).items():
        if w not in out and ty != "dynamic":
            out[w] = ty
    return out


def _reads_in(e) -> Iterator[Tuple[ir.Sload, Optional[int], ir.Node]]:
    """(Sload, bit offset, read node) of every storage read inside e."""
    for n, par in _walk(e, ()):
        if isinstance(n, ir.Sload):
            read, off, _ = _read_window(n, par[-1] if par else None, par[-2] if len(par) > 1 else None)
            yield n, off, read


def _outer_reads(e) -> Iterator[ir.Sload]:
    """The storage reads inside e, except those of slot expressions (an
    array element's slot holds the length it is indexed with)."""
    stack = [e]
    while stack:
        n = stack.pop()
        if isinstance(n, ir.Sload):
            yield n
        else:
            stack.extend(ir.children(n))


_CLEANUP_OPS = ("iszero", "signextend", "shl")


def _pure_read(w: ir.Expr) -> bool:
    """The word is a storage read under cleanups only (what a getter returns)."""
    while True:
        if isinstance(w, ir.Sload):
            return True
        if isinstance(w, ir.Field) or _offset_mask(w):
            return isinstance(w.value, ir.Sload)
        if isinstance(w, ir.Mask) and _int_field(w.offset) == 0:
            w = w.value
        elif isinstance(w, ir.Op) and w.op in _CLEANUP_OPS:
            w = w.args[-1]
        else:
            return False


def _return_words(ret: ir.Return) -> Optional[List[ir.Expr]]:
    if ret.values is not None:
        return list(ret.values)
    d = ret.data
    if d is None:
        return None
    parts = _parts(d)
    if all(isinstance(p, ir.WordBytes) and p.width == 32 for p in parts):
        return [p.value for p in parts]
    return None


def _enum_bound(cond: ir.Expr) -> Optional[Tuple[ir.Expr, int]]:
    """(x, N) when cond (the revert condition) is x >= N."""
    neg = False
    while isinstance(cond, ir.Op) and cond.op == "iszero":
        neg, cond = not neg, cond.args[0]
    if not isinstance(cond, ir.Op) or len(cond.args) != 2:
        return None
    a, b = cond.args
    if not neg:
        if cond.op == "gt" and isinstance(b, ir.Const) and b.value < 255:
            return a, b.value + 1  # x > N - 1
        if cond.op == "lt" and isinstance(a, ir.Const) and a.value < 255:
            return b, a.value + 1  # N - 1 < x
    else:
        if cond.op == "lt" and isinstance(b, ir.Const) and 0 < b.value <= 256:
            return a, b.value  # !(x < N)
        if cond.op == "gt" and isinstance(a, ir.Const) and 0 < a.value <= 256:
            return b, a.value  # !(N > x)
    return None


class _Inference:
    """The inference of the module docstring, over lifted functions."""

    def __init__(self, functions: Dict[str, ir.Function], specs: Dict[str, object],
                 outputs: Dict[str, Optional[Tuple[str, ...]]], trusted: Set[str] = frozenset()):
        self.facts = {k: _collect(fn) for k, fn in functions.items()}
        self.specs = specs
        self.outputs = outputs
        self.trusted = trusted  # function keys whose outputs come from a curated table
        self.params = {k: _param_types(specs.get(k)) for k in functions}
        self.names = {k: getattr(specs.get(k), "name", None) for k in functions}
        self.accs = [a for f in self.facts.values() for a in f.accesses]
        self.by_loc: Dict[tuple, List[Access]] = collections.defaultdict(list)
        for a in self.accs:
            if a.apath[0] != "unk":
                self.by_loc[a.apath].append(a)
        self.children: Dict[tuple, Set[tuple]] = collections.defaultdict(set)
        for ap in list(self.by_loc):
            p = ap
            while _parent(p) is not None:
                self.children[_parent(p)].add(p)
                p = _parent(p)
        self.enum_n = self._enums()
        self.accessors = self._accessors()
        # locations whose length word a Panic(0x22) test reads (0.8 string / bytes length decoding)
        self.length_checked: Set[tuple] = {
            abstract(parse_slot(n.slot)) for f in self.facts.values() for cond, code in f.panics if code == 0x22
            for n in _outer_reads(cond)}

    # ---- enums: Panic(0x21) range checks
    def _enums(self) -> Dict[Tuple[tuple, int], int]:
        res: Dict[Tuple[tuple, int], int] = {}
        for key, f in self.facts.items():
            for cond, code in f.panics:
                if code != 0x21:
                    continue
                b = _enum_bound(cond)
                if b is None:
                    continue
                x, n = b
                if isinstance(x, (ir.Field, ir.Sload)):
                    sl = x.value if isinstance(x, ir.Field) else x
                    off = _bits(x.offset) if isinstance(x, ir.Field) else 0
                    if isinstance(sl, ir.Sload) and off is not None:
                        res[(abstract(parse_slot(sl.slot)), off)] = n
                elif _head_word(x) is not None:
                    for a in f.accesses:
                        if a.kind == "W" and _unwrap(a.value) == x and a.off is not None:
                            res[(a.apath, a.off)] = n
        return res

    # ---- accessors: pure readers (no effects), returns read one root
    def _accessors(self) -> Dict[tuple, List[tuple]]:
        res: Dict[tuple, List[tuple]] = collections.defaultdict(list)
        for key, f in self.facts.items():
            if not key.startswith("0x") or f.effects or not f.returns:
                continue
            words = []
            for ret in f.returns:
                ws = _return_words(ret)
                if ws is None:
                    words = None
                    break
                words.extend(ws)
            if words is None:
                # returns a byte string (a string / bytes getter copies it to
                # memory): the one root it reads
                roots = {_root(a.apath) for a in f.accesses}
                if len(roots) == 1 and next(iter(roots))[0] == "slot":
                    res[("bytesroot", roots.pop())].append((self.names.get(key), key))
                continue
            if not words or not all(_pure_read(w) for w in words):
                continue
            reads = [r for w in words for r in _reads_in(w)]
            if not reads:
                continue
            name = self.names.get(key)
            paths = [(abstract(parse_slot(s.slot)), off) for s, off, _ in reads]
            roots = {_root(ap) for ap, _ in paths}
            nparams = len(getattr(self.specs.get(key), "params", ()) or ())
            if len(roots) > 1 and all(r[0] == "slot" for r in roots) and not nparams:
                nums = sorted(r[1] for r in roots)
                if nums == list(range(nums[0], nums[-1] + 1)):
                    res[("multislot", nums[0], nums[-1])].append((name, key, len(reads)))
                continue
            if len(roots) != 1:
                continue
            distinct = len(set(paths))
            for ap, off in paths:
                res[(ap, off)].append((name, key, distinct))
            depth = max(len(repr(ap)) for ap, _ in paths)
            root = roots.pop()
            if root[0] == "slot" and not nparams and len(paths) > 1 and all(ap == root for ap, _ in paths):
                # several fields of one slot returned together (bit offsets in order)
                res[("inslot", root[1])].append((name, key, tuple(off for _, off in paths)))
            res[("root", root)].append((name, key, len(reads), depth, nparams))
        return res

    # ---- helpers
    def accs_under(self, ap: tuple) -> List[Access]:
        out = []
        for k, v in self.by_loc.items():
            p = k
            while p is not None:
                if p == ap:
                    out.extend(v)
                    break
                p = _parent(p)
        return out

    @staticmethod
    def concrete_at(path: tuple, level: tuple):
        p = path
        while p[0] in ("map", "data", "elem", "off"):
            if abstract(p) == level:
                return p[2] if p[0] in ("map", "elem") else None
            p = p[1]
        return None

    def _bound(self, func: str, idx) -> Optional[int]:
        res = [n for i, n in self.facts[func].bounds if i == idx]
        return min(res) if res else None

    # ---- typing
    def loc_type(self, ap: tuple) -> tuple:
        kids = self.children.get(ap, set())
        maps = sorted((k for k in kids if k[0] == "map"), key=repr)
        datas = sorted((k for k in kids if k[0] == "data"), key=repr)
        elems = sorted((k for k in kids if k[0] == "elem"), key=lambda k: (-k[3], -k[2], repr(k)))
        if maps:
            m = maps[0]
            keys = [(a.func, self.concrete_at(a.path, m)) for a in self.accs_under(m)]
            kt = _key_type([k for k in keys if k[1] is not None], self.params)
            return ("map", kt, self.loc_type(m))
        if datas:
            d = datas[0]
            if self.is_bytes_like(ap):
                return ("string",)
            delems = sorted((k for k in self.children.get(d, set()) if k[0] == "elem"),
                            key=lambda k: (-k[3], -k[2], repr(k)))
            if delems:
                el = delems[0]
                stride, per = el[2], el[3]
                if per > 1:
                    return ("dyn", self.packed_elem_type(el, per))
                et = self.struct_or_value(el, stride)
                if et[0] == "fix" and et[2] is None:
                    return ("dyn", et[1])  # data + stride * i + j without a bound on j: flat indices
                return ("dyn", et)
            return ("dyn", self.struct_or_value(d, None))
        if elems:
            el = elems[0]
            stride, per = el[2], el[3]
            n = None
            for a in self.accs_under(el):
                idx = self.concrete_at(a.path, el)
                if idx is not None:
                    b = self._bound(a.func, idx)
                    if b is not None:
                        n = b if n is None else max(n, b)
            et = self.packed_elem_type(el, per) if per > 1 else self.struct_or_value(el, stride)
            if n is not None and n > MAX_STATIC_SLOT:
                n = None
            return ("fix", et, n)
        if self.is_bytes_like(ap):
            return ("string",)  # only the length word is accessed
        return self.struct_or_value(ap, None)

    def packed_elem_type(self, el: tuple, per: int) -> tuple:
        w = _SLOT // per
        if per not in (2, 4, 8, 16, 32):
            w = 8 * (32 // per)
        f = _Field(0, w)
        for a in self.by_loc.get(el, []):
            if a.kind == "R":
                h = read_evidence(a)[1]
            else:
                h = write_evidence(a, self.params.get(a.func, {}))[0]
            if h:
                f.hints[h] += 1
            f.srcs.append(a)
        return _value_type(f)

    def struct_or_value(self, ap: tuple, stride: Optional[int]) -> tuple:
        kids = self.children.get(ap, set())
        offs = sorted((k for k in kids if k[0] == "off"), key=lambda k: k[2])
        nonvalue = [k for k in kids if k[0] in ("map", "data", "elem")]
        fields0 = partition(self.by_loc.get(ap, []), self.params)
        if not offs and not nonvalue and len(fields0) <= 1 and stride in (None, 1):
            if not fields0:
                return ("v", "uint256")
            return self.field_type(ap, fields0[0])
        if not offs and not fields0 and len(nonvalue) == 1 and nonvalue[0][0] == "elem":
            inner = self.loc_type(ap)  # nested fixed array
            if stride in (None, 1) or nslots(inner) == stride:
                return inner
        members = []
        slots = {0: ap}
        for o in offs:
            slots[o[2]] = o
        n = max(slots) + 1
        if stride and stride > n:
            n = stride
        if n > 4096:
            return ("v", "uint256")
        for s in range(n):
            loc = slots.get(s)
            if loc is None:
                continue  # never accessed: a filler keeps the members in place
            sub = self.children.get(loc, set())
            if any(k[0] in ("map", "data", "elem") for k in sub) or (loc != ap and self.is_bytes_like(loc)):
                members.append((s, 0, self.loc_type(loc)))
                continue
            for f in partition(self.by_loc.get(loc, []), self.params):
                if f.off % 8 == 0:  # (a member only ever set to zero when the struct is built is a member)
                    members.append((s, f.off // 8, self.field_type(loc, f)))
        if n == 1 and len(members) == 1 and members[0][:2] == (0, 0) and not is_value(members[0][2]):
            return members[0][2]  # a one-slot element holding one composite (string[])
        if not members:
            return ("v", "uint256")
        return ("struct", tuple(members), n)

    def field_type(self, ap: tuple, f: _Field) -> tuple:
        # an enum takes one byte: a range-checked value stored into a wider
        # field is converted to an integer type (uint256(m))
        en = self.enum_n.get((ap, f.off)) if f.size == 8 else None
        prior = self.output_prior(ap, f)
        return _value_type(f, en, prior)

    def output_prior(self, ap: tuple, f: _Field) -> Optional[str]:
        """The database output type of the one-read accessor of this field
        (an untrusted one only for a variable at a static slot, where the
        read carries no cleanup to tell: see refine_from_outputs)."""
        for name, key, nreads in self.accessors.get((ap, f.off), []):
            outs = self.outputs.get(key)
            if name and nreads == 1 and outs and len(outs) == 1:
                t = outs[0]
                if re.fullmatch(r"(u?int\d+|bytes\d+|bool|address)", t) and (
                        key in self.trusted or (_no_cleanup(t) and _at_static_slot(ap))):
                    return t
        return None

    def is_bytes_like(self, ap: tuple) -> bool:
        """bytes / string: the length word decoded from the short / long
        encoding (0.8: tested by a Panic(0x22) check; before: masked with
        256 * (bit 0 == 0) - 1); or Panic(0x22) in a function touching a
        location whose data area is accessed without elements (string[] and
        mapping(.. => string) raise it for their elements, a struct with a
        string member for its other members too).  Reads of bit 0 or of the
        word shifted right by one alone are no evidence: `x % 2`, `x / 2`."""
        direct = self.by_loc.get(ap, [])
        if ap in self.length_checked or any(_legacy_length_read(a) for a in direct):
            return True
        data = ("data", ap)
        if data not in self.children.get(ap, set()) or any(k[0] == "elem" for k in self.children.get(data, set())):
            return False
        funcs = {a.func for a in direct}
        return any(code == 0x22 for fn in funcs for _, code in self.facts[fn].panics)

    # ---- naming candidates
    def accessors_of(self, root: tuple, field_off: Optional[int] = None) -> List[Tuple[str, str]]:
        """(function key, name) of the pure accessors of a root (or of one
        field of a static slot), best first."""
        if field_off is not None:
            c = [(key, name) for name, key, nreads in self.accessors.get((root, field_off), []) if nreads == 1]
            return sorted(c, key=lambda x: (x[1] is None, x[0]))
        cands = self.accessors.get(("root", root), [])
        # the accessor that reaches deepest below the root and takes the most
        # keys first (the getter nums(uint256) before an explicit numsLength())
        cands = sorted(cands, key=lambda c: (-c[4], -c[3], c[0] is None, c[1]))
        return [(key, name) for name, key, _, _, _ in cands]

    # ---- top level
    def state_vars(self) -> Tuple[List[StateVar], List[Tuple[int, int, tuple]]]:
        roots = sorted({_root(ap) for ap in self.by_loc if _root(ap)[0] in ("slot", "cslot")},
                       key=lambda r: (r[0] != "slot", r[1]))
        out: List[StateVar] = []
        custom: List[tuple] = []
        for r in roots:
            kids = self.children.get(r, set())
            nonvalue = [k for k in kids if k[0] in ("map", "data", "elem")]
            if r[0] == "cslot":
                custom.append(r)
                continue
            if nonvalue or self.is_bytes_like(r):
                t = self.loc_type(r)
                acc = self.accessors_of(r) + [(k, n) for n, k in self.accessors.get(("bytesroot", r), [])]
                out.append(StateVar(f"slot{r[1]}", r[1], 0, t, "composite", acc))
                continue
            for f in _widened(partition(self.by_loc.get(r, []), self.params)):
                if f.off % 8 or _cleared_only(f):
                    continue
                t = self.field_type(r, f)
                b = f.off // 8
                vid = f"slot{r[1]}" + (f"_{b}" if b else "")
                out.append(StateVar(vid, r[1], b, t, "value", self.accessors_of(r, f.off)))
        out = self.group_struct_getters(out)
        return sorted(out, key=lambda v: (v.slot, v.offset)), self.namespaces(custom)

    def namespaces(self, roots: List[tuple]) -> List[StateVar]:
        """Custom slots (EIP-1967, ERC-7201) grouped by base: constants within
        2**16 of the first one form one struct of members at their offsets."""
        out: List[StateVar] = []
        cluster: List[tuple] = []
        for r in sorted(roots, key=lambda r: r[1]) + [None]:
            if r is not None and cluster and r[1] - cluster[0][1] < (1 << 16):
                cluster.append(r)
                continue
            if cluster:
                base = cluster[0][1]
                members = []
                for c in cluster:
                    k = c[1] - base
                    kids = self.children.get(c, set())
                    if any(x[0] in ("map", "data", "elem") for x in kids) or self.is_bytes_like(c):
                        members.append((k, 0, self.loc_type(c)))
                        continue
                    for f in partition(self.by_loc.get(c, []), self.params):
                        if f.off % 8 == 0 and not _cleared_only(f):
                            members.append((k, f.off // 8, self.field_type(c, f)))
                if members:
                    n = max(s + nslots(m) for s, _, m in members)
                    acc = [(key, name) for c in cluster for key, name in self.accessors_of(c)]
                    out.append(StateVar(f"namespace{base >> 224:08x}", base, 0, ("struct", tuple(members), n),
                                        "custom slot", acc))
            cluster = [r] if r is not None else []
        return out

    def group_struct_getters(self, out: List[StateVar]) -> List[StateVar]:
        """A parameterless accessor returning members read from consecutive
        static slots: an inplace struct (solc's getter of `S public x`).
        Within one slot, a getter returning every field in order reads the
        same as one returning several packed variables: the fields are a
        struct only when the contract has a struct of exactly that shape
        elsewhere (a mapping value, an array element)."""
        for key, accs in sorted(self.accessors.items(), key=lambda kv: repr(kv[0])):
            if key[0] == "inslot":
                out = self._slot_struct(key[1], accs, out)
                continue
            if key[0] != "multislot":
                continue
            a, b = key[1], key[2]
            inside = [v for v in out if a <= v.slot <= b]
            if not inside or any(not is_value(v.type) for v in inside) or any(
                    v.slot < a <= v.end - 1 or v.slot <= b < v.end - 1 for v in out if v not in inside):
                continue
            members = tuple((v.slot - a, v.offset, v.type) for v in sorted(inside, key=lambda v: (v.slot, v.offset)))
            st = ("struct", members, b - a + 1)
            out = [v for v in out if not a <= v.slot <= b]
            out.append(StateVar(f"slot{a}", a, 0, st, "struct-getter", [(k, n) for n, k, _ in accs]))
        return out

    def _slot_struct(self, slot: int, accs: List[tuple], out: List[StateVar]) -> List[StateVar]:
        inside = sorted((v for v in out if v.slot == slot), key=lambda v: v.offset)
        if len(inside) < 2 or any(not is_value(v.type) for v in inside):
            return out
        members = tuple((0, v.offset, v.type) for v in inside)
        known: List[tuple] = []  # (members, slots) of every struct type of the other variables
        for v in out:
            if v.slot != slot:
                _collect_types(v.type, known, set())
        if (members, 1) not in known:
            return out
        getters = [(key, name) for name, key, offs in accs if list(offs) == [8 * v.offset for v in inside]]
        if not getters:
            return out
        return [v for v in out if v.slot != slot] + [StateVar(f"slot{slot}", slot, 0, ("struct", members, 1),
                                                                  "struct-getter", getters)]

    def refine_from_outputs(self, v: StateVar) -> None:
        """Database outputs of the variable's named accessor refine its leaf
        value types (priors: only default uintN of the same width, bytes vs
        string).  An untrusted output (the type some other contract gave a
        function of that signature) only refines a variable at a static
        position, not the elements of an array or mapping getter: an element
        getter's name says little of the element type (`data(uint256)`)."""
        outs, trusted = None, False
        for key, name in v.accessors:
            if name and self.outputs.get(key):
                outs, trusted = self.outputs[key], key in self.trusted
                break
        if not outs:
            return
        static = v.type[0] not in ("map", "dyn", "fix")

        def conv(o: str, cur: tuple) -> tuple:
            if cur[0] in ("bytes", "string") and o in ("bytes", "string"):
                return (o,) if trusted else cur
            if cur[0] == "v" and cur[1].startswith("uint") and re.fullmatch(r"(u?int\d+|bytes\d+)", o) \
                    and (trusted or (static and _no_cleanup(o))):
                try:
                    if val_nbytes(("v", o)) == val_nbytes(cur):
                        return ("v", o)
                except ValueError:
                    return cur
            return cur

        def leaf(t: tuple) -> tuple:
            if t[0] == "map":
                return ("map", t[1], leaf(t[2]))
            if t[0] == "dyn":
                return ("dyn", leaf(t[1]))
            if t[0] == "fix":
                return ("fix", leaf(t[1]), t[2])
            if t[0] == "struct":
                mems = list(t[1])
                vis = [i for i, m in enumerate(mems) if is_value(m[2]) or m[2][0] in ("bytes", "string")]
                if len(vis) == len(outs):
                    for i, o in zip(vis, outs):
                        s_, o_, m = mems[i]
                        mems[i] = (s_, o_, conv(o, m))
                return ("struct", tuple(mems), t[2])
            if len(outs) == 1:
                return conv(outs[0], t)
            return t

        v.type = leaf(v.type)


# ---------------------------------------------------------------- struct unification


def _shape(t: tuple) -> tuple:
    if is_value(t):
        return ("val", val_nbytes(t))
    if t[0] == "struct":
        return ("struct", tuple((s, o, _shape(m)) for s, o, m in t[1]), t[2])
    if t[0] == "map":
        return ("map", t[1], _shape(t[2]))
    if t[0] == "dyn":
        return ("dyn", _shape(t[1]))
    if t[0] == "fix":
        return ("fix", _shape(t[1]), t[2])
    return t


def _rank(t: tuple) -> int:
    if not is_value(t):
        return 0
    if t[0] in ("enum", "contract"):
        return 3
    return 2 if t[1] in ("bool", "address") or t[1].startswith(("int", "bytes")) else 1


def _loose_shape(t: tuple) -> tuple:
    """A struct's member positions and kinds (value widths left out)."""
    if t[0] == "struct":
        return ("struct", tuple((s, o, "val" if is_value(m) else _loose_shape(m)) for s, o, m in t[1]), t[2])
    if t[0] == "map":
        return ("map", _loose_shape(t[2]))
    if t[0] in ("dyn", "fix"):
        return (t[0], _loose_shape(t[1])) + ((t[2],) if t[0] == "fix" else ())
    return ("val",) if is_value(t) else t


def _merge_member(a: tuple, b: tuple) -> Optional[tuple]:
    """One member type for two structs with the same positions: equal
    widths -> the richer type; different widths -> the one with real
    evidence when the other is a default uintN (a width read off an upper
    bound, such as a constant store over several members); else None."""
    if not (is_value(a) and is_value(b)):
        return a if a == b or _shape(a) == _shape(b) else None
    if val_nbytes(a) == val_nbytes(b):
        return b if _rank(b) > _rank(a) else a
    if _rank(a) == 1 and _rank(b) > 1:
        return b
    if _rank(b) == 1 and _rank(a) > 1:
        return a
    return None


def unify_structs(svars: List[StateVar]) -> None:
    """Structs with the same member positions get one member list (the
    richest member types), when their members agree (see _merge_member)."""
    best: Dict[tuple, tuple] = {}
    conflict: Set[tuple] = set()

    def visit(t: tuple) -> None:
        if t[0] == "struct":
            sh = _loose_shape(t)
            cur = best.get(sh)
            if cur is None:
                best[sh] = t
            elif sh not in conflict:
                mem = []
                for (s1, o1, m1), (_, _, m2) in zip(cur[1], t[1]):
                    m = _merge_member(m1, m2)
                    if m is None:
                        conflict.add(sh)
                        break
                    mem.append((s1, o1, m))
                else:
                    best[sh] = ("struct", tuple(mem), cur[2])
            for _, _, m in t[1]:
                visit(m)
        elif t[0] == "map":
            visit(t[2])
        elif t[0] in ("dyn", "fix"):
            visit(t[1])

    def rewrite(t: tuple) -> tuple:
        if t[0] == "struct":
            sh = _loose_shape(t)
            u = best.get(sh, t) if sh not in conflict else t
            return ("struct", tuple((s, o, rewrite(m)) for s, o, m in u[1]), u[2])
        if t[0] == "map":
            return ("map", t[1], rewrite(t[2]))
        if t[0] == "dyn":
            return ("dyn", rewrite(t[1]))
        if t[0] == "fix":
            return ("fix", rewrite(t[1]), t[2])
        return t

    for v in svars:
        visit(v.type)
    for v in svars:
        v.type = rewrite(v.type)


# ---------------------------------------------------------------- declarations


def _advance(s: int, o: int, t: tuple) -> Tuple[int, int]:
    if is_value(t):
        e = o + val_nbytes(t)
        return (s + 1, 0) if e >= 32 else (s, e)
    return (s + nslots(t), 0)


def _natural(pos: Tuple[int, int], t: tuple) -> Tuple[int, int]:
    """Where solc puts t after the items so far (next free position pos)."""
    cs, cb = pos
    if is_value(t):
        n = val_nbytes(t)
        return (cs, cb) if cb + n <= 32 else (cs + 1, 0)
    return (cs + 1, 0) if cb > 0 else (cs, 0)


def _fillers(pos: Tuple[int, int], s: int, o: int, t: tuple) -> Optional[List[str]]:
    """The filler types that make solc put t at (s, o) (None: impossible,
    the position is already taken)."""
    if _natural(pos, t) == (s, o):
        return []
    cs, cb = pos
    out: List[str] = []
    if s == cs and o > cb:
        return [f"uint{8 * (o - cb)}"]
    if s > cs:
        if cb > 0:
            if _natural(pos, t)[0] == cs or s == cs + 1:
                out.append(f"uint{8 * (32 - cb)}")  # close the current slot
            cs, cb = cs + 1, 0
        if s > cs:
            out.append("uint256" if s - cs == 1 else f"uint256[{s - cs}]")
        if o > 0:
            out.append(f"uint{8 * o}")
        return out
    if s == cs and cb == 0 and o > 0:
        return [f"uint{8 * o}"]
    return None


def struct_body(t: tuple, layout: Layout) -> Optional[List[str]]:
    """Member declarations of a recovered struct (fillers keep every member
    at its position), or None when the members cannot be laid out."""
    body: List[str] = []
    pos = (0, 0)
    gi = 0
    for s, o, mt in t[1]:
        fill = _fillers(pos, s, o, mt)
        if fill is None:
            return None
        for ft in fill:
            body.append(f"{ft} __gap{gi};")
            gi += 1
        body.append(f"{type_text(mt, layout)} {member_name(s, o)};")
        pos = _advance(s, o, mt)
    end = pos[0] + (1 if pos[1] else 0)
    if end < t[2]:
        body.append(("uint256" if t[2] - end == 1 else f"uint256[{t[2] - end}]") + f" __gap{gi};")
    return body


def _collect_types(t: tuple, structs: List[tuple], enums: Set[int]) -> None:
    if t[0] == "struct":
        for _, _, m in t[1]:
            _collect_types(m, structs, enums)
        key = (t[1], t[2])
        if key not in structs:
            structs.append(key)
    elif t[0] == "enum":
        enums.add(t[1])
    elif t[0] == "map":
        _collect_types(t[2], structs, enums)
    elif t[0] in ("dyn", "fix"):
        _collect_types(t[1], structs, enums)


def name_types(layout: Layout) -> None:
    """Stable names for the structs and enums the variables use."""
    structs: List[tuple] = []
    enums: Set[int] = set()
    for v in layout.vars + layout.namespaces:
        _collect_types(v.type, structs, enums)
    layout.structs = {k: f"Struct{i}" for i, k in enumerate(structs)}
    layout.enums = {n: f"Enum{n}" for n in sorted(enums)}


def type_declarations(layout: Layout) -> List[str]:
    """enum and struct declarations (dependencies first)."""
    out = []
    for n, name in sorted(layout.enums.items()):
        out.append(f"enum {name} {{ " + ", ".join(f"V{i}" for i in range(n)) + " }")
    for key, name in layout.structs.items():
        body = struct_body(("struct",) + key, layout) or []
        out.append(f"struct {name} {{\n" + "\n".join("    " + line for line in body) + "\n}")
    return out


def state_declarations(layout: Layout, natspec: Optional[Dict[str, List[str]]] = None,
                       use_vids: bool = False) -> Optional[List[str]]:
    """The state variable declarations with fillers, in slot order (None
    when two variables overlap); `use_vids`: named by their stable ids."""
    lines: List[str] = []
    pos = (0, 0)
    gi = 0
    for v in sorted(layout.vars, key=lambda v: (v.slot, v.offset)):
        fill = _fillers(pos, v.slot, v.offset, v.type)
        if fill is None:
            return None
        for ft in fill:
            lines.append(f"{ft} private __gap{gi};")
            gi += 1
        for line in (natspec or {}).get(v.vid, ()):
            lines.append(line)
        vis = "public" if v.vid in layout.public and not use_vids else "internal"
        lines.append(f"{type_text(v.type, layout)} {vis} {v.vid if use_vids else layout.name(v)};")
        pos = _advance(v.slot, v.offset, v.type)
    return lines


def namespace_declarations(layout: Layout) -> List[str]:
    """The accessor of each custom-slot namespace."""
    out = []
    for v in layout.namespaces:
        struct = layout.struct_name(v.type)
        out.append(f"function {namespace_accessor(v)}() private pure returns ({struct} storage $) {{\n"
                   f"    assembly {{ $.slot := 0x{v.slot:064x} }}\n}}")
    return out


# ---------------------------------------------------------------- L2 self-check


def _encoding(t: tuple) -> Tuple[str, int]:
    if t[0] == "map":
        return "mapping", 32
    if t[0] == "dyn":
        return "dynamic_array", 32
    if t[0] in ("bytes", "string"):
        return "bytes", 32
    if is_value(t):
        return "inplace", val_nbytes(t)
    return "inplace", 32 * nslots(t)


def _uses(t: tuple, key: tuple) -> bool:
    if t[0] == "struct":
        return (t[1], t[2]) == key or any(_uses(m, key) for _, _, m in t[1])
    if t[0] == "map":
        return _uses(t[2], key)
    if t[0] in ("dyn", "fix"):
        return _uses(t[1], key)
    return False


@functools.lru_cache(maxsize=None)
def _solc_path(version: str) -> Optional[str]:
    try:
        from scobelix.verify.solc import installed_solcs
    except Exception:  # noqa: BLE001
        return None
    return installed_solcs().get(version)


def self_check(layout: Layout, solc_version: str) -> Optional[List[str]]:
    """Compile the declarations and return the vids that do not land at
    their recovered (slot, offset) with their size and encoding, or whose
    struct members do not (None: no compiler to check with)."""
    try:
        from scobelix.verify.solc import CompilationError, Settings, compile_standard_json
    except Exception:  # noqa: BLE001 - verify extras missing
        return None
    path = _solc_path(solc_version)
    if path is None:
        return None
    every = layout.vars + layout.namespaces
    decls = state_declarations(layout, use_vids=True)
    if decls is None:
        return [v.vid for v in every]
    decls += [f"{layout.struct_name(v.type)} internal {v.vid};" for v in layout.namespaces]
    src = ("// SPDX-License-Identifier: UNLICENSED\npragma solidity >=0.8.0;\ncontract __Layout {\n"
           + "\n".join("    " + line for d in type_declarations(layout) for line in d.split("\n"))
           + "\n" + "\n".join("    " + d for d in decls) + "\n}\n")
    try:
        comp = compile_standard_json(src, Settings(optimize=False), version=solc_version, solc_path=path)
    except CompilationError:
        return [v.vid for v in every]
    try:
        sl = comp.artifact("__Layout").storage_layout or {}
    except Exception:  # noqa: BLE001
        return None
    types = sl.get("types") or {}
    got = {}
    for e in sl.get("storage") or []:
        t = types.get(e.get("type")) or {}
        got[e.get("label")] = (int(e.get("slot", 0)), int(e.get("offset", 0)), t.get("encoding"),
                               int(t.get("numberOfBytes", 0)))
    bad = []
    for v in layout.vars:
        enc, size = _encoding(v.type)
        if got.get(v.vid) != (v.slot, v.offset, enc, size):
            bad.append(v.vid)
    # struct members at their recovered (slot, offset), with their size
    by_name = {name: key for key, name in layout.structs.items()}
    for t in types.values():
        name = (t.get("label") or "").rsplit(".", 1)[-1]
        if "members" not in t or name not in by_name:
            continue
        key = by_name[name]
        want = {member_name(s, o): (s, o) + _encoding(m) for s, o, m in key[0]}
        have = {}
        for m in t["members"]:
            mt = types.get(m.get("type")) or {}
            have[m.get("label")] = (int(m.get("slot", 0)), int(m.get("offset", 0)), mt.get("encoding"),
                                    int(mt.get("numberOfBytes", 0)))
        if any(have.get(k) != w for k, w in want.items()):
            bad.extend(v.vid for v in every if _uses(v.type, key) and v.vid not in bad)
    return bad


# ---------------------------------------------------------------- entry points


def infer_layout(functions: Dict[str, ir.Function], specs: Dict[str, object],
                 outputs: Optional[Dict[str, Optional[Tuple[str, ...]]]] = None,
                 solc_version: Optional[str] = None, trusted: Set[str] = frozenset()) -> Layout:
    """The storage layout of a contract from its lifted entry points.
    `outputs`: database output types per function key (priors; `trusted`:
    the keys whose outputs come from a curated table, the only ones that
    may tell string from bytes); `solc_version`: compile the declarations
    to check them (L2 self-check)."""
    inf = _Inference(functions, specs, outputs or {}, trusted)
    svars, spaces = inf.state_vars()
    for v in svars:
        inf.refine_from_outputs(v)
    unify_structs(svars + spaces)
    svars, inside = _without_overlaps(svars)
    layout = Layout(svars, {}, {}, spaces)
    layout.dropped.extend(f"{vid}: inside {outer}" for vid, outer in inside)
    name_types(layout)
    layout.inference = inf  # type: ignore[attr-defined]
    if solc_version:
        check(layout, solc_version)
    return layout


def _without_overlaps(svars: List[StateVar]) -> Tuple[List[StateVar], List[Tuple[str, str]]]:
    """Variables in slot order, without those that start inside an earlier
    one (an element of a fixed array or a member of an inplace struct read
    at a constant position is part of it: the accesses resolve through the
    composite)."""
    out: List[StateVar] = []
    dropped: List[Tuple[str, str]] = []
    end = (0, 0)  # next free (slot, byte)
    for v in sorted(svars, key=lambda v: (v.slot, v.offset, -nslots(v.type))):
        if (v.slot, v.offset) < end:
            dropped.append((v.vid, out[-1].vid if out else "?"))
            continue
        out.append(v)
        end = (v.slot, v.offset + val_nbytes(v.type)) if is_value(v.type) else (v.end, 0)
    return out, dropped


def check(layout: Layout, solc_version: str) -> None:
    """Run the L2 self-check; drop what does not land where it was recovered
    (twice at most: dropping a variable may move the fillers)."""
    for _ in range(3):
        bad = self_check(layout, solc_version)
        if bad is None:
            layout.checked = None
            layout.warnings.append("storage layout not compiled (no solc): declarations unchecked")
            return
        if not bad:
            layout.checked = True
            return
        layout.dropped.extend(bad)
        layout.vars = [v for v in layout.vars if v.vid not in bad]
        layout.namespaces = [v for v in layout.namespaces if v.vid not in bad]
        name_types(layout)
    layout.checked = True
    layout.vars, layout.namespaces = [], []
    name_types(layout)
    layout.warnings.append("storage layout self-check failed: no state variables declared")


def exclude(layout: Layout, vids: Iterable[str], solc_version: Optional[str] = None) -> None:
    """Leave the variables `vids` (stable ids) undeclared: their place
    becomes a filler and every access to them stays an access by slot."""
    vids = set(vids)
    gone = sorted(v.vid for v in layout.vars + layout.namespaces if v.vid in vids)
    if not gone:
        return
    layout.vars = [v for v in layout.vars if v.vid not in vids]
    layout.namespaces = [v for v in layout.namespaces if v.vid not in vids]
    layout.dropped.extend(f"{vid}: excluded" for vid in gone)
    name_types(layout)
    if solc_version and layout.checked:
        check(layout, solc_version)  # the fillers changed


def analyse(ctx) -> Optional[Layout]:
    """The layout of the contract a pass context describes, computed once
    (ctx.facts["storage"]).  None when the storage pass is switched off for
    the whole contract: nothing is declared then, and no other pass may
    build on a state variable."""
    lay = ctx.facts.get("storage")
    if isinstance(lay, Layout) or lay is False:
        return lay or None
    if getattr(ctx, "off_everywhere", None) is not None and ctx.off_everywhere("storage"):
        ctx.facts["storage"] = False
        return None
    outputs: Dict[str, Optional[Tuple[str, ...]]] = {}
    trusted: Set[str] = set()
    for key, spec in ctx.specs.items():
        if getattr(spec, "signature", None) and getattr(spec, "selector", None) is not None:
            try:
                for c in ctx.sigs.function_candidates(spec.selector):
                    if c.signature == spec.signature and c.outputs is not None:
                        outputs[key] = tuple(t for t, _ in c.outputs)
                        if c.trusted:
                            trusted.add(key)
                        break
            except Exception:  # noqa: BLE001 - the lookup is only a prior
                pass
    try:
        lay = infer_layout(ctx.functions, ctx.specs, outputs, ctx.target_solc, trusted)
    except RecursionError:
        ctx.facts["storage"] = False
        ctx.warnings.append("storage layout: trace too deep, not inferred")
        return None
    exclude(lay, getattr(ctx, "excluded_storage", None) or (), ctx.target_solc)
    ctx.facts["storage"] = lay
    return lay

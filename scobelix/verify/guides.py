"""
Guard-directed inputs for differential execution (input-to-state correspondence).

A call the original rejects has usually failed a guard: msg.sender compared
with an owner word, a balance compared with the amount, a flag tested for
zero, a token or an implementation held in storage that has no code.  The
instrumented executions of the original (py-evm cmp-log, see `evm.pyevm`)
trace, in execution order, its comparisons, the values it tests for zero and
its calls (with the targets it finds without code), and record the inputs it
hashes.  An operand equal to one of the call's inputs - a calldata word, a
field of a storage word the call read, the answer of an environment stub,
msg.value - locates that input, and the other operand is what to put there in
later calls (`Guide`: location := value).  A call target without code is
located the same way; the environment's generic contract (the ERC20-like
stub) is what to put there.

Operands are matched exactly.  A value of at least 2^16 is looked up among
every input, and among the fields of the storage words read - every byte
offset, the usual packed widths -, so `owner` packed with a flag is found
through its mask.  A smaller value (a flag, a state, a small amount) is
everywhere: it locates an input only when that input alone holds it (without
a taint analysis, attributing it to the word loaded last misleads: a 0 from
RETURNDATASIZE is no zero slot).

Two kinds of guides come out of a call:
  * every located guard teaches its operand's partner (constants are then
    placed with their neighbours +- 1: both sides of a `<`);
  * when the original rejected the call, the last guard before the revert -
    past the comparisons of small values and negations that the revert path
    itself makes, never past a call or a test of a computed value - is the
    one that failed: if it is located, the exact value that flips it is a
    *decisive* guide (`Lesson.decisive`).  Decisive guides are placed
    together - a guard passed on one call, the next guard fails and teaches
    its own -, so the guards of an accepting path are learned one after the
    other.

Locations and values are symbolic where the call's own context decides them
(`Ref`): an entry of a mapping keyed by the caller, by an argument or by the
selector - its slot is recomputed for every call -, the caller, an argument,
the generic contract.  The mapping entries the call read are learned too
(`Lesson.shapes`): later calls seed the entries of their own caller and
arguments.  Nothing here weakens the comparison: a guided pre-state is one
more pre-state, applied identically to both sides.
"""

from __future__ import annotations

import dataclasses
import random
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .seeds import mapping_slot

__all__ = [
    "Context",
    "Guide",
    "Lesson",
    "Loc",
    "Ref",
    "apply_call",
    "apply_storage",
    "choose",
    "learn",
    "shape_slots",
]

WORD = (1 << 256) - 1
SMALL = 1 << 16  # below: a value too common to locate an input by itself
# widths (bytes) a packed field is tried with at each byte offset, besides "up to the top"
_WIDTHS = (4, 8, 12, 16, 20, 24, 28)
_MEMBERS = 16  # struct members: a slot up to this far past a hashed slot is an entry's member
_DEPTH = 3  # nested mappings followed
_SIGN = 1 << 255

_ISZERO = 0x15
_LT, _GT, _SLT, _SGT, _EQ, _SUB, _XOR = 0x10, 0x11, 0x12, 0x13, 0x14, 0x03, 0x18
_COMPARE = (_LT, _GT, _SLT, _SGT, _EQ, _SUB, _XOR)
_TARGETS = (0xF1, 0xF2, 0xF4, 0xFA, 0x3B, 0x3C, 0x3F)  # calls and EXTCODE*: a codeless target


@dataclasses.dataclass(frozen=True)
class Context:
    """What symbolic references resolve against: one call's sender (as the contract sees it),
    its calldata words (after the selector), its selector, its calldata size and the generic
    contract."""

    sender: int
    words: Tuple[int, ...]
    selector: Optional[int]
    size: int
    contract: int

    @classmethod
    def of(cls, data: bytes, sender: int, contract: int) -> "Context":
        words = tuple(
            int.from_bytes(data[i : i + 32], "big") for i in range(4, len(data) - 31, 32)
        )
        selector = int.from_bytes(data[:4], "big") if len(data) >= 4 else None
        return cls(sender, words, selector, len(data), contract)


@dataclasses.dataclass(frozen=True)
class Ref:
    """
    A value in a call's context, plus `delta` (mod 2^256): `const` n, the
    `sender`, calldata word `arg` n, the selector shifted left by n bits
    (`sig`: a bytes4 key is left-aligned) or the generic `contract`.
    """

    kind: str
    n: int = 0
    delta: int = 0

    def resolve(self, ctx: Context) -> Optional[int]:
        if self.kind == "const":
            v: Optional[int] = self.n
        elif self.kind == "sender":
            v = ctx.sender
        elif self.kind == "contract":
            v = ctx.contract
        elif self.kind == "arg":
            v = ctx.words[self.n] if self.n < len(ctx.words) else None
        elif self.kind == "sig":
            v = None if ctx.selector is None else ctx.selector << self.n
        else:
            raise ValueError(f"unknown reference {self.kind!r}")
        return None if v is None else (v + self.delta) & WORD

    def plus(self, delta: int) -> "Ref":
        return dataclasses.replace(self, delta=self.delta + delta)


@dataclasses.dataclass(frozen=True)
class Loc:
    """
    An input of a call.  `storage`: the bits [shift, shift + bits) of a
    storage word of the contract - the word at `slot`, or, with `keys`, the
    entry of the mapping whose base slot is `slot` (outermost key first),
    `offset` words further (a struct member).  `arg`: calldata word `n`.
    `value`: msg.value.  `env`: the word at `slot` of the environment
    account `account` (the answer of a stub).
    """

    kind: str
    slot: int = 0
    keys: Tuple[Ref, ...] = ()
    offset: int = 0
    shift: int = 0
    bits: int = 256
    n: int = 0
    account: str = ""

    def storage_slot(self, ctx: Context) -> Optional[int]:
        slot = self.slot
        for key in self.keys:
            k = key.resolve(ctx)
            if k is None:
                return None
            slot = mapping_slot(k, slot)
        return (slot + self.offset) & WORD

    def put(self, word: int, v: int) -> int:
        mask = (1 << self.bits) - 1
        return (word & ~(mask << self.shift) & WORD) | ((v & mask) << self.shift)


@dataclasses.dataclass(frozen=True)
class Guide:
    """Put `value` at `loc`; a constant value is tried with its neighbours unless `exact`."""

    loc: Loc
    value: Ref
    exact: bool = False


@dataclasses.dataclass
class Lesson:
    """What one instrumented execution teaches (see the module docstring)."""

    guides: List[Guide]
    decisive: List[Guide]
    shapes: List[Loc]


def _key_ref(key: int, ctx: Context) -> Ref:
    if key == ctx.sender:
        return Ref("sender")
    if key in ctx.words:
        return Ref("arg", ctx.words.index(key))
    if ctx.selector is not None and key in (ctx.selector, ctx.selector << 224):
        return Ref("sig", 0 if key == ctx.selector else 224)
    return Ref("const", key)


def _place(slot: int, hashed: Mapping[int, Tuple[int, ...]], ctx: Context, depth: int = 0) -> Loc:
    """Where a slot of the contract lives: a mapping entry (keys resolved in `ctx`) or itself."""
    if depth < _DEPTH:
        for offset in range(_MEMBERS):
            words = hashed.get((slot - offset) & WORD)
            if words is None or len(words) != 2:
                continue
            key, base = words
            outer = _place(base, hashed, ctx, depth + 1)
            if outer.offset:  # a mapping inside a struct of a mapping entry: the base as is
                outer = Loc("storage", base)
            return Loc("storage", outer.slot, outer.keys + (_key_ref(key, ctx),), offset)
    return Loc("storage", slot)


def _index_word(index: Dict[int, List[Loc]], word: int, base: Loc) -> None:
    """
    The word and its packed fields as values locating `base`: each value
    once, at its lowest offset and narrowest width there (a repetitive word -
    all ones - holds the same field at every offset: the mask reads the low one).
    """
    index.setdefault(word, []).append(base)
    if word < SMALL:
        return
    seen = {word}
    for offset in range(32):
        for n in sorted(set(_WIDTHS + (32 - offset,))):
            if offset + n > 32:
                break
            f = (word >> (8 * offset)) & ((1 << (8 * n)) - 1)
            if f >= SMALL and f not in seen:
                seen.add(f)
                field = dataclasses.replace(base, shift=8 * offset, bits=8 * n)
                index.setdefault(f, []).append(field)


def _signed(v: int) -> int:
    return v - (1 << 256) if v & _SIGN else v


class _Reader:
    """The inputs of one instrumented call, and where an operand of its trace comes from."""

    def __init__(self, result, storage, env_storage, value: int, ctx: Context, account: str):
        self.ctx = ctx
        self.trace = list(result.trace)
        self.hashed = {h: words for h, words in result.hashes}
        self.places: Dict[int, Loc] = {}
        reads = sorted({s for a, s in result.storage_reads if a == account})
        self.shapes = [loc for loc in (self.where(s) for s in reads) if loc.keys]
        index: Dict[int, List[Loc]] = {}
        for s in reads:
            if s in storage:  # an unseeded slot reads 0: it locates nothing by its value
                _index_word(index, storage[s], self.where(s))
        for i, w in enumerate(ctx.words):
            index.setdefault(w, []).append(Loc("arg", n=i))
        if value:
            index.setdefault(value, []).append(Loc("value"))
        for addr, slots in env_storage.items():
            if slots.get(0, 0) == 0 and 1 in slots:  # the stub answers the word of its slot 1
                index.setdefault(slots[1], []).append(Loc("env", 1, account=addr))
        self.index = index
        # the calldata size and its payload size: what the ABI decoder compares, never an input
        self.skip = {ctx.size, ctx.size - 4}

    def where(self, slot: int) -> Loc:
        """A storage slot's location: symbolic when it is a mapping entry under the call's own
        sender / arguments / selector, else the slot itself."""
        loc = self.places.get(slot)
        if loc is None:
            loc = _place(slot, self.hashed, self.ctx)
            if not any(k.kind != "const" for k in loc.keys):
                loc = Loc("storage", slot)
            self.places[slot] = loc
        return loc

    def _boolean(self, at: int, x: int) -> bool:
        """Whether ISZERO event `at` tests `x`, the result of the comparison just before it."""
        if at == 0:
            return False
        op, a, b = self.trace[at - 1]
        if op == _ISZERO:
            return x == int(a == 0)
        if op in (_SLT, _SGT):
            a, b = _signed(a), _signed(b)
        results = {_LT: a < b, _GT: a > b, _SLT: a < b, _SGT: a > b, _EQ: a == b}
        return op in results and x == int(results[op])

    def locate(self, x: int, at: int) -> List[Loc]:
        """The inputs operand `x` of trace event `at` comes from: those holding it if it is
        distinctive, the only one holding it if it is small."""
        if x in self.skip:
            return []
        locs = self.index.get(x, [])
        if x < SMALL:
            boolean = self.trace[at][0] == _ISZERO and self._boolean(at, x)
            if len(locs) != 1 or boolean:
                return []
        return locs

    def noise(self, at: int) -> bool:
        """An unlocated event that decides nothing about the inputs: a comparison of small
        values (a loop counter, a length), the negation of the comparison just before it.  A
        test of anything else (a call's success, a computed value), a call: no noise."""
        op, x, y = self.trace[at]
        if op == _ISZERO:
            return self._boolean(at, x)
        return op in _COMPARE and x < SMALL and y < SMALL

    def ref(self, y: int) -> Optional[Ref]:
        """What a located operand's partner `y` is, in a later call: the caller, the generic
        contract, an argument, or a constant; None for another input's value."""
        ctx = self.ctx
        if y == ctx.sender:
            return Ref("sender")
        if y == ctx.contract:
            return Ref("contract")
        if y >= SMALL and y in ctx.words:
            return Ref("arg", ctx.words.index(y))
        if y >= SMALL and y in self.index:
            return None
        return Ref("const", y)


def _flip(op: int, a: int, b: int, located_first: bool, partner: Ref) -> Ref:
    """The value of the located operand that flips the outcome of comparison `op(a, b)` (a: top
    of the stack, a != b for EQ / SUB / XOR), `partner` standing for the other operand."""
    if op in (_EQ, _SUB, _XOR):  # equality wanted
        return partner
    if op in (_SLT, _SGT):
        a, b = _signed(a), _signed(b)
    less = op in (_LT, _SLT)
    holds = a < b if less else a > b
    if not located_first:  # the located operand is b: op(a, b) == mirrored op(b, a)
        less = not less
    if holds:  # make it fail: the located side equal to the partner
        return partner
    return partner.plus(-1 if less else 1)


def learn(
    result,
    storage: Mapping[int, int],
    env_storage: Mapping[str, Mapping[int, int]],
    value: int,
    ctx: Context,
    account: str,
    failed: bool,
) -> Lesson:
    """
    What one instrumented execution of the original teaches: `result` (a
    py-evm CallResult with cmp-log), the pre-state's `storage` of the
    contract at `account` and `env_storage` of the environment's accounts,
    msg.value and the call's context; `failed`: the original rejected the
    call (its decisive guide is then learned).
    """
    reader = _Reader(result, storage, env_storage, value, ctx, account)
    guides: Dict[Guide, None] = {}
    flips: Dict[int, List[Guide]] = {}  # trace event -> its decisive guides
    for at, (op, x, y) in enumerate(reader.trace):
        found: List[Guide] = []
        decisive: List[Guide] = []
        if op == _ISZERO:
            for loc in reader.locate(x, at):
                found.append(Guide(loc, Ref("const", 0)))
                decisive.append(Guide(loc, Ref("const", 0 if x else 1), True))
        elif op in _TARGETS and not y:  # a target without code
            for loc in reader.locate(x, at):
                found.append(Guide(loc, Ref("contract")))
                decisive.append(Guide(loc, Ref("contract"), True))
        elif op in _COMPARE:
            for first, (u, v) in ((True, (x, y)), (False, (y, x))):
                partner = reader.ref(v) if u != v or op in (_EQ, _SUB, _XOR) else None
                if partner is None:
                    continue
                for loc in reader.locate(u, at):
                    if loc.kind == "arg" and partner.kind == "arg" and loc.n == partner.n:
                        continue
                    found.append(Guide(loc, partner))
                    # equal operands most likely passed their guard (`require(a == b)`): the
                    # failure came later, from a guard that could not be located
                    if not (x == y and op in (_EQ, _SUB, _XOR)):
                        decisive.append(Guide(loc, _flip(op, x, y, first, partner), True))
        for g in found:
            guides.setdefault(g)
        if decisive:
            flips[at] = decisive
    blocking: List[Guide] = []
    if failed:  # the last guard before the revert, past the noise of the revert path
        for at in range(len(reader.trace) - 1, -1, -1):
            if at in flips:
                blocking = flips[at]
                break
            if not reader.noise(at):
                break  # a call, or a guard of computed values: nothing to place
    return Lesson(list(guides), blocking, reader.shapes)


def choose(
    rng: random.Random, guides: Mapping[Guide, int], p_loc: float = 0.75, cap: int = 8
) -> List[Guide]:
    """At most one guide per location (weighted by recurrence, at most `cap`), each location
    taken with probability `p_loc`."""
    by_loc: Dict[Loc, List[Tuple[Guide, int]]] = {}
    for g, seen in guides.items():
        by_loc.setdefault(g.loc, []).append((g, min(seen, cap)))
    out = []
    for options in by_loc.values():
        if rng.random() < p_loc:
            out.append(rng.choices([g for g, _ in options], weights=[w for _, w in options])[0])
    return out


def _value(rng: random.Random, g: Guide, ctx: Context) -> Optional[int]:
    v = g.value.resolve(ctx)
    if v is not None and g.value.kind == "const" and not g.exact:  # both sides of a boundary
        v = (v + rng.choice((0, 0, -1, 1))) & WORD
    return v


def apply_call(
    rng: random.Random,
    chosen: Sequence[Guide],
    data: bytes,
    value: Optional[int],
    ctx: Context,
    max_value: int,
) -> Tuple[bytes, Optional[int]]:
    """The calldata words and msg.value of `chosen` placed in a call (`value` None: keep it 0)."""
    out = bytearray(data)
    for g in chosen:
        if g.loc.kind == "arg" and 4 + 32 * (g.loc.n + 1) <= len(out):
            v = _value(rng, g, ctx)
            if v is not None:
                out[4 + 32 * g.loc.n : 4 + 32 * (g.loc.n + 1)] = v.to_bytes(32, "big")
        elif g.loc.kind == "value" and value is not None:
            v = _value(rng, g, ctx)
            if v is not None and v <= max_value:
                value = v
    return bytes(out), value


def apply_storage(
    rng: random.Random,
    chosen: Sequence[Guide],
    storage: Dict[int, int],
    env_storage: Dict[str, Dict[int, int]],
    ctx: Context,
    admits: Optional[Callable[[int, int, int], bool]] = None,
) -> List[int]:
    """The storage fields of `chosen` written into a pre-state; returns the slots written.
    `admits(slot, shift, bits)`: whether the layout lets a field be written there."""
    written = []
    for g in chosen:
        if g.loc.kind == "storage":
            slot = g.loc.storage_slot(ctx)
            if slot is None or (admits is not None and not admits(slot, g.loc.shift, g.loc.bits)):
                continue
            v = _value(rng, g, ctx)
            if v is not None:
                storage[slot] = g.loc.put(storage.get(slot, 0), v)
                written.append(slot)
        elif g.loc.kind == "env" and g.loc.account in env_storage:
            v = _value(rng, g, ctx)
            if v is not None:
                slots = env_storage[g.loc.account]
                slots[0] = 0  # the stub answers its word
                slots[g.loc.slot] = g.loc.put(slots.get(g.loc.slot, 0), v)
    return written


def shape_slots(shapes: Iterable[Loc], ctx: Context) -> List[int]:
    """The slots of learned mapping shapes for a call's own sender, arguments and selector."""
    out = []
    for loc in shapes:
        slot = loc.storage_slot(ctx)
        if slot is not None and slot not in out:
            out.append(slot)
    return out

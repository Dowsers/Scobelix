"""
Storage seeding for differential execution.

Seeds are raw (slot -> word) assignments applied identically to the original
and to the candidate before a call.  They derive from the ORIGINAL's layout,
never from the candidate's (a wrong candidate layout must show up as a
behavioural difference), and from the slots either side was seen reading.

Per call (`SeedPlan.per_call`):
  * every value slot of the layout gets, with probability 0.7, a word built
    field by field (packed variables included) with a value typed by the
    field: addresses (the call's msg.sender, the other senders, the contracts
    of the environment, the universe), booleans 0/1, unsigned integers from
    edge values, from the current call's arguments (u, u+-1, 2^256-u,
    2^256-u-1: the exact overflow / underflow boundaries of `x + u`, `x - u`;
    2u-1: enough for one withdrawal of u, not for a reentrant second one),
    from the constants of the code and from the call's block (timestamp /
    number +-1: deadlines);
  * mappings get entries for keys drawn from the universe and from the call's
    arguments (uint-keyed mappings use the uint arguments), nested mappings
    for key pairs, dynamic arrays a small length and their first elements,
    strings / bytes a short or long encoding;
  * slots discovered by SLOAD in earlier calls get a value too (0.8): an
    address a fifth of the time (an owner held in an unstructured slot),
    else an integer seed;
  * a few words carry dirty bits outside their declared fields: such slots
    are reported in `Seeds.dirty`, so that a divergence that only exists with
    dirty storage can be labelled as such (`Seeds.cleaned`).

`SeedPlan.reachable` builds the plausible, clean start state of a stateful
sequence instead (small balances, owner among the senders...).
"""

from __future__ import annotations

import dataclasses
import functools
import random
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from eth_utils import keccak

from .layout import BYTES, DYNAMIC_ARRAY, INPLACE, MAPPING, SlotType, Var

__all__ = ["Field", "SeedPlan", "Seeds", "clean_words", "mapping_slot", "seed_value"]

WORD = (1 << 256) - 1


@dataclasses.dataclass(frozen=True)
class Field:
    offset: int  # bytes from the low-order end of the slot
    size: int  # bytes
    # address | contract (a contract / interface type) | bool | small (untyped byte) | uint | int
    # | bytes | enum | word
    kind: str


@dataclasses.dataclass
class Seeds:
    storage: Dict[int, int]
    # slots whose word has bits outside its declared fields (or a bool not 0/1) -> those fields
    dirty: Dict[int, Tuple[Field, ...]]

    def cleaned(self) -> Dict[int, int]:
        """The storage with every dirty word reduced to its declared fields (bools to 0 / 1)."""
        return clean_words(self.storage, self.dirty)


def clean_words(storage: Dict[int, int], dirty: Dict[int, Tuple[Field, ...]]) -> Dict[int, int]:
    out = dict(storage)
    for slot, fields in dirty.items():
        if slot not in out:
            continue
        word = 0
        for f in fields:
            v = (out[slot] >> (8 * f.offset)) & ((1 << (8 * f.size)) - 1)
            word |= (v & 1 if f.kind == "bool" else v) << (8 * f.offset)
        out[slot] = word
    return out


def _kind(label: str, size: int) -> str:
    if not label:  # untyped layout (legacy stor_defs): guess from the width
        return {32: "word", 20: "address", 1: "small"}.get(size, "uint")
    if label.startswith(("contract ", "interface ")):
        return "contract"
    if label.startswith("address"):
        return "address"
    if label == "bool":
        return "bool"
    if label.startswith("enum "):
        return "enum"
    if re.fullmatch(r"int\d+", label):
        return "int"
    if re.fullmatch(r"bytes\d+", label):
        return "bytes"
    return "uint"


def _key_kind(label: Optional[str]) -> str:
    if not label:
        return "any"
    if label in ("string", "bytes"):
        return "dynamic"
    k = _kind(label, 32)
    return {"word": "uint", "enum": "uint", "contract": "address"}.get(k, k)


@functools.lru_cache(maxsize=65536)
def _keccak_words(*words: int) -> int:
    return int.from_bytes(keccak(b"".join(w.to_bytes(32, "big") for w in words)), "big")


def mapping_slot(key: int, slot: int) -> int:
    """keccak(pad32(key) . pad32(slot)) for a value-type key already in its 32-byte form."""
    return _keccak_words(key % (1 << 256), slot)


def seed_value(
    rng: random.Random,
    used: Sequence[int],
    constants: Sequence[int] = (),
    env: Sequence[int] = (),
    bits: int = 256,
) -> int:
    """
    A seed of `bits` bits: argument-aware boundaries (u, u +- 1, 2u - 1:
    enough for one withdrawal of u but not two, 2^256 - u...), a constant of
    the code or a value of the block (each +- 1), the edge values of the
    width (0 and max - where a counter's +- 1 wraps or panics - twice as
    often as 1, max - 1, the sign boundaries, 10^18 when it fits) or a
    random width.  Without arguments, the other sources share the arguments'
    part.
    """
    mx = (1 << bits) - 1
    p = rng.random()
    if not used:
        p = 0.35 + 0.65 * p
    if p < 0.35:
        u = rng.choice(used)
        return rng.choice((u, u - 1, u + 1, 2 * u - 1, (1 << 256) - u, (1 << 256) - u - 1)) & mx
    if p < 0.45 and constants:
        return (rng.choice(constants) + rng.choice((-1, 0, 0, 1))) & mx
    if p < 0.53 and env:
        return (rng.choice(env) + rng.choice((-1, 0, 0, 1))) & mx
    if p < 0.73:
        half = 1 << (bits - 1)
        big = 10**18 if 10**18 < mx else 2
        return rng.choice((0, 0, 1, mx, mx, mx - 1, half, half - 1, big))
    return rng.getrandbits(rng.choice((8, 64, 128, 256))) & mx


@dataclasses.dataclass
class _Region:
    """Storage reachable from one base slot: packed fields at base+k plus dynamic children."""

    fields: Dict[int, List[Field]] = dataclasses.field(default_factory=dict)
    mappings: List[Tuple[int, str, "_Region"]] = dataclasses.field(default_factory=list)
    # rel, elem, slots, per slot
    arrays: List[Tuple[int, "_Region", int, int]] = dataclasses.field(default_factory=list)
    strings: List[int] = dataclasses.field(default_factory=list)

    def empty(self) -> bool:
        return not (self.fields or self.mappings or self.arrays or self.strings)

    def slots(self) -> set:
        """The relative slots this region types: fields, array lengths, strings, mapping slots."""
        return (
            set(self.fields)
            | {rel for rel, _, _ in self.mappings}
            | {rel for rel, _, _, _ in self.arrays}
            | set(self.strings)
        )


_MAX_STATIC_ELEMENTS = 8


def _add(region: _Region, rel: int, offset: int, t: SlotType, depth: int = 0) -> None:
    """Adds type `t` stored at (base + rel, offset) to `region`."""
    if depth > 8:
        return
    if t.encoding == MAPPING:
        value = _Region()
        if t.value is not None:
            _add(value, 0, 0, t.value, depth + 1)
        else:
            value.fields[0] = [Field(0, 32, "word")]
        region.mappings.append((rel, _key_kind(t.key), value))
    elif t.encoding == DYNAMIC_ARRAY:
        elem, slots, per = _Region(), 1, 1
        if t.value is not None:
            size = t.value.size or 32
            if (
                t.value.encoding == INPLACE
                and not t.value.members
                and t.value.value is None
                and size <= 16
            ):
                per = 32 // size
                for i in range(per):
                    _add(elem, 0, i * size, t.value, depth + 1)
            else:
                slots = max(1, (size + 31) // 32) if t.value.encoding == INPLACE else 1
                _add(elem, 0, 0, t.value, depth + 1)
        else:
            elem.fields[0] = [Field(0, 32, "word")]
        region.arrays.append((rel, elem, slots, per))
    elif t.encoding == BYTES:
        region.strings.append(rel)
    elif t.members:  # structs always start a new slot: members keep their own offsets
        for m in t.members:
            _add(region, rel + m.slot, m.offset, m.type, depth + 1)
    elif t.value is not None:  # static array
        size = t.value.size or 32
        n = min(t.length or 1, _MAX_STATIC_ELEMENTS)
        if (
            t.value.encoding == INPLACE
            and not t.value.members
            and t.value.value is None
            and size <= 16
        ):
            per = 32 // size
            for i in range(n):
                _add(region, rel + i // per, (i % per) * size, t.value, depth + 1)
        else:
            step = max(1, (size + 31) // 32) if t.value.encoding == INPLACE else 1
            for i in range(n):
                _add(region, rel + i * step, 0, t.value, depth + 1)
    else:
        size = t.size or 32
        region.fields.setdefault(rel, []).append(
            Field(offset, min(size, 32 - offset), _kind(t.label, size))
        )


class SeedPlan:
    """Seeding plan for one (original) layout and address universe."""

    def __init__(
        self,
        layout: Sequence[Var],
        universe: Sequence[str],
        senders: Sequence[str] = (),
        max_keys: int = 10,
        dirty_ratio: float = 0.05,
        contracts: Sequence[str] = (),
    ):
        self.universe = [int(a, 16) for a in universe]
        # favoured for address fields, so that owner checks can pass
        self.senders = [int(a, 16) for a in senders]
        # favoured for address fields too: a token / oracle / target the contract calls
        self.contracts = [int(a, 16) for a in contracts]
        # per call: the current msg.sender (always a mapping key, often an address field), the
        # constants of the code and the values of the call's block
        self._priority: List[int] = []
        self._constants: Sequence[int] = ()
        self._env: Sequence[int] = ()
        self.max_keys = max_keys
        self.dirty_ratio = dirty_ratio
        self.root = _Region()
        for v in layout:
            _add(self.root, v.slot, v.offset, v.type)
        self._typed = self.root.slots()

    @property
    def empty(self) -> bool:
        return self.root.empty()

    def admits(self, slot: int, shift: int, bits: int) -> bool:
        """
        Whether a value written into bits [shift, shift + bits) of `slot` (a
        guided input) keeps the layout's invariants: a slot the layout does
        not type, or one of its value fields - never an array's length or a
        string's word (a length no contract reaches, a broken encoding: the
        viaIR and legacy codes of one source treat them differently).
        """
        if slot not in self._typed:
            return True
        return any(
            8 * f.offset <= shift and shift + bits <= 8 * (f.offset + f.size)
            for f in self.root.fields.get(slot, ())
        )

    # -- values

    def _field_value(
        self,
        rng: random.Random,
        f: Field,
        used: Sequence[int],
        addresses: Sequence[int],
        clean: bool,
    ) -> int:
        bits = 8 * f.size
        mx = (1 << bits) - 1
        if f.kind in ("address", "contract"):
            # owner checks need the call's own msg.sender, calls to a token the environment's stub
            p = rng.random()
            if self.contracts and (p < 0.2 or (f.kind == "contract" and p < 0.6)):
                return rng.choice(self.contracts) & mx
            if p < 0.55 and self._priority:
                return rng.choice(self._priority) & mx
            if p < 0.65 and self.senders:
                return rng.choice(self.senders) & mx
            if p < 0.9 and addresses:
                return rng.choice(addresses) & mx
            return 0 if p < 0.95 else rng.getrandbits(160) & mx
        if f.kind == "small":  # an untyped byte: most often a flag
            p = rng.random()
            return (
                0 if p < 0.5 else 1 if p < 0.85 else rng.choice((2, 255, rng.getrandbits(8))) & mx
            )
        if f.kind == "bool":
            return rng.choice((0, 1)) if clean or rng.random() < 0.9 else rng.randrange(2, 256) & mx
        if f.kind == "enum":
            return (
                rng.choice((0, 0, 1, 1, 2, 3))
                if clean or rng.random() < 0.9
                else rng.getrandbits(8) & mx
            )
        if clean:
            return rng.choice((0, 1, 2, 10, 1000, 10**6, 10**18)) & mx
        return seed_value(rng, used, self._constants, self._env, bits)

    def _word(self, rng, fields: Sequence[Field], used, addresses, clean: bool) -> Tuple[int, bool]:
        word, covered = 0, 0
        dirty = False
        for f in fields:
            v = self._field_value(rng, f, used, addresses, clean)
            if f.kind == "bool" and v > 1:
                dirty = True
            word |= v << (8 * f.offset)
            covered |= ((1 << (8 * f.size)) - 1) << (8 * f.offset)
        free = WORD & ~covered
        if free and not clean and rng.random() < self.dirty_ratio:
            word |= rng.getrandbits(256) & free
            dirty = True
        return word & WORD, dirty

    def _keys(
        self,
        rng: random.Random,
        kind: str,
        used: Sequence[int],
        addresses: Sequence[int],
        limit: int,
    ) -> List[int]:
        if kind == "address":
            pool = list(addresses)
            first = [a for a in self._priority if a in pool]
            if len(pool) > limit:  # the call's own msg.sender is always among the keys
                rest = [a for a in pool if a not in first]
                pool = first + rng.sample(rest, max(0, limit - len(first)))
            return pool
        elif kind in ("uint", "int", "bytes"):
            pool = [0, 1, 2] + [u for u in used]
        elif kind == "bool":
            pool = [0, 1]
        elif kind == "dynamic":
            return []  # string / bytes keys: only reached through SLOAD discovery
        else:
            pool = list(addresses) + [0, 1] + [u for u in used]
        pool = list(dict.fromkeys(pool))
        if len(pool) > limit:
            pool = rng.sample(pool, limit)
        return pool

    # -- materialisation

    def _fill(
        self,
        rng,
        region: _Region,
        base: int,
        out: Seeds,
        used,
        addresses,
        p: float,
        clean: bool,
        depth: int,
    ) -> None:
        for rel, fields in region.fields.items():
            if rng.random() < p:
                slot = (base + rel) & WORD
                word, dirty = self._word(rng, fields, used, addresses, clean)
                out.storage[slot] = word
                if dirty:
                    out.dirty[slot] = tuple(fields)
        limit = max(2, self.max_keys >> depth)
        for rel, kind, value in region.mappings:
            p_slot = (base + rel) & WORD
            for key in self._keys(rng, kind, used, addresses, limit):
                self._fill(
                    rng, value, mapping_slot(key, p_slot), out, used, addresses, p, clean, depth + 1
                )
        for rel, elem, slots, per in region.arrays:
            p_slot = (base + rel) & WORD
            if rng.random() >= p:
                continue
            length = rng.choice((0, 1, 2, 3, rng.randrange(0, 6)))
            out.storage[p_slot] = length
            data = _keccak_words(p_slot)
            for i in range(0, length, per):
                self._fill(
                    rng,
                    elem,
                    data + (i // per) * slots,
                    out,
                    used,
                    addresses,
                    1.0,
                    clean,
                    depth + 1,
                )
        for rel in region.strings:
            if rng.random() < p:
                self._string(rng, (base + rel) & WORD, out)

    @staticmethod
    def _string(rng: random.Random, slot: int, out: Seeds) -> None:
        n = rng.choice((0, 1, 5, 31, 32, 33, 64))
        data = bytes(rng.randrange(97, 123) for _ in range(n))
        if n < 32:  # short form: data left-aligned, 2*length in the low byte
            out.storage[slot] = int.from_bytes(data.ljust(31, b"\0") + bytes([2 * n]), "big")
        else:
            out.storage[slot] = 2 * n + 1
            base = _keccak_words(slot)
            for i in range(0, n, 32):
                out.storage[(base + i // 32) & WORD] = int.from_bytes(
                    data[i : i + 32].ljust(32, b"\0"), "big"
                )

    def per_call(
        self,
        rng: random.Random,
        used: Sequence[int] = (),
        used_addresses: Sequence[str] = (),
        discovered: Iterable[int] = (),
        p_layout: float = 0.7,
        p_discovered: float = 0.8,
        callers: Sequence[str] = (),
        constants: Sequence[int] = (),
        env: Sequence[int] = (),
        keyed: Iterable[int] = (),
        p_keyed: float = 0.5,
    ) -> Seeds:
        """
        Arbitrary-but-typed pre-state for one call (see the module docstring);
        `callers` (the call's msg.sender) are always among the mapping keys
        and often the value of an address field; `constants` (the code's
        dictionary) and `env` (the call's block timestamp and number) feed
        the integer fields.  `keyed`: entries of mappings under this call's
        own caller, arguments or selector, seen read by earlier calls (from
        the hashes the code computed), seeded like the discovered slots but
        only with probability `p_keyed`: an entry is zero until written - a
        flag the call needs clear as often as a balance it needs set.
        """
        addresses = list(
            dict.fromkeys(
                [int(a, 16) for a in callers] + self.universe + [int(a, 16) for a in used_addresses]
            )
        )
        self._priority = [int(a, 16) for a in callers]
        self._constants, self._env = constants, env
        out = Seeds({}, {})
        self._fill(rng, self.root, 0, out, list(used), addresses, p_layout, False, 0)
        for slot in discovered:
            # a state variable's slot left unseeded above stays 0: an untyped word there would put
            # dirty bits in its fields without `dirty` knowing it, give an array a length no
            # contract can reach (>= 2^64: viaIR code checks it, legacy code does not) or break
            # a string's encoding
            if slot in self._typed or slot in out.storage:
                continue
            if rng.random() < p_discovered:
                out.storage[slot] = self._untyped_value(rng, used, addresses)
        for slot in keyed:
            if slot not in self._typed and slot not in out.storage and rng.random() < p_keyed:
                out.storage[slot] = self._untyped_value(rng, used, addresses)
        return out

    def _untyped_value(self, rng: random.Random, used: Sequence[int], addresses) -> int:
        """
        A word for a slot outside the layout, seen by SLOAD: an address a
        fifth of the time (an owner / admin held in an unstructured slot,
        often the call's own msg.sender), else an integer seed.
        """
        if rng.random() < 0.2:
            return self._field_value(rng, Field(0, 20, "address"), used, addresses, False)
        return seed_value(rng, used, self._constants, self._env)

    def reachable(self, rng: random.Random) -> Dict[int, int]:
        """A plausible, clean start state for a stateful sequence."""
        self._priority, self._constants, self._env = list(self.senders), (), ()
        out = Seeds({}, {})
        self._fill(rng, self.root, 0, out, (), self.universe, 0.5, True, 0)
        return out.storage

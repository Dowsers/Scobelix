"""
L2: storage layout comparison.

A layout is normalised into a list of `Var` - position (slot, byte offset)
plus a recursive `SlotType` (encoding, number of bytes, element / value /
member types, mapping key).  Accepted inputs (`normalize_layout`):

  * a solc `storageLayout` object: {"storage": [...], "types": {...}};
  * the decompiler's legacy `stor_defs` list, whose entries are
    ("def", name, slot, ("mask", bits, bit_offset) | ("mapping", T) | ("array", T))
    with T a value width in bits, "struct" or ("struct", n);
  * a list of `Var`;
  * a list of dicts {"slot", "offset", "size" | "numberOfBytes", "encoding",
    "label", "name", "key", "value": <nested type dict>, "members": [...]}.
    Missing fields mean "unknown" and are not compared.

`compare_layout(expected, candidate)` checks that every expected variable
has a candidate variable at the same (slot, offset) with the same number of
bytes, encoding and nested shape (mapping value, array element, struct
members, mapping key class).  Names never matter; a type label mismatch with
an identical shape (`uint256` vs `bytes32`, `address` vs `contract C`) only
clears the informational `exact` flag.  Candidate variables that overlap no
expected one (fillers, variables the code never touches) are reported as
extras and do not fail L2.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

__all__ = [
    "LayoutComparison",
    "Member",
    "SlotType",
    "Var",
    "compare_layout",
    "normalize_layout",
]

INPLACE, MAPPING, DYNAMIC_ARRAY, BYTES = "inplace", "mapping", "dynamic_array", "bytes"


@dataclasses.dataclass(frozen=True)
class SlotType:
    encoding: str  # inplace | mapping | dynamic_array | bytes
    size: Optional[int]  # numberOfBytes (32 for mapping / dynamic_array / bytes); None = unknown
    label: str = ""  # solc type label ("uint256", "struct S", "bool[3]"); "" = unknown
    key: Optional[str] = None  # mapping key label
    value: Optional["SlotType"] = None  # mapping value type / array element type
    members: Tuple["Member", ...] = ()  # struct members (inplace)
    length: Optional[int] = None  # static array length (inplace with `value`)

    def describe(self) -> str:
        if self.encoding == MAPPING:
            inner = self.value.describe() if self.value else "?"
            return f"mapping({self.key or '?'} => {inner})"
        if self.encoding == DYNAMIC_ARRAY:
            return f"{self.value.describe() if self.value else '?'}[]"
        if self.encoding == BYTES:
            return self.label or "bytes"
        if self.label:
            return self.label
        return f"{self.size if self.size is not None else '?'} bytes"


@dataclasses.dataclass(frozen=True)
class Member:
    slot: int  # relative to the struct's first slot
    offset: int
    type: SlotType
    name: str = ""


@dataclasses.dataclass(frozen=True)
class Var:
    slot: int
    offset: int  # bytes from the low-order end of the slot
    type: SlotType
    name: str = ""

    @property
    def start(self) -> int:
        return self.slot * 32 + self.offset

    @property
    def end(self) -> int:
        """First byte (in slot*32+offset units) after the variable."""
        if self.type.encoding != INPLACE:
            return self.start + 32
        return self.start + (self.type.size or 32)


# ---------------------------------------------------------------- normalisation


def _solc_type(tid: str, types: Dict[str, dict], depth: int = 0) -> SlotType:
    t = types.get(tid, {}) or {}
    enc = t.get("encoding", INPLACE)
    size = int(t["numberOfBytes"]) if "numberOfBytes" in t else None
    label = t.get("label", "")
    if depth > 32:  # recursive struct types cannot appear in storage, but stay safe
        return SlotType(enc, size, label)
    if enc == MAPPING:
        key = (types.get(t.get("key", ""), {}) or {}).get("label") or None
        return SlotType(
            MAPPING, 32, label, key=key, value=_solc_type(t.get("value", ""), types, depth + 1)
        )
    if enc == DYNAMIC_ARRAY:
        return SlotType(
            DYNAMIC_ARRAY, 32, label, value=_solc_type(t.get("base", ""), types, depth + 1)
        )
    if enc == BYTES:
        return SlotType(BYTES, 32, label)
    if t.get("members"):
        members = tuple(
            Member(
                int(m["slot"]),
                int(m["offset"]),
                _solc_type(m["type"], types, depth + 1),
                m.get("label", ""),
            )
            for m in t["members"]
        )
        return SlotType(INPLACE, size, label, members=members)
    if t.get("base"):
        m = re.search(r"\[(\d+)\]$", label)
        return SlotType(
            INPLACE,
            size,
            label,
            value=_solc_type(t["base"], types, depth + 1),
            length=int(m.group(1)) if m else None,
        )
    return SlotType(INPLACE, size, label)


def _from_solc(storage_layout: dict) -> List[Var]:
    types = storage_layout.get("types") or {}
    return [
        Var(int(v["slot"]), int(v["offset"]), _solc_type(v["type"], types), v.get("label", ""))
        for v in storage_layout.get("storage") or []
    ]


def _legacy_value(t: Any) -> Optional[SlotType]:
    if isinstance(t, int) and t > 0:
        return SlotType(INPLACE, (t + 7) // 8)
    if isinstance(t, (list, tuple)) and len(t) == 2 and t[0] == "struct" and isinstance(t[1], int):
        return SlotType(INPLACE, 32 * t[1])
    return None


def _from_stor_defs(stor_defs: Sequence) -> List[Var]:
    out: List[Var] = []
    for d in stor_defs:
        if not (
            isinstance(d, (list, tuple)) and len(d) >= 4 and d[0] == "def" and isinstance(d[2], int)
        ):
            continue
        _, name, slot, ty = d[:4]
        if not isinstance(ty, (list, tuple)) or not ty:
            continue
        if ty[0] == "mask" and len(ty) >= 3 and isinstance(ty[1], int) and isinstance(ty[2], int):
            out.append(Var(slot, ty[2] // 8, SlotType(INPLACE, (ty[1] + 7) // 8), str(name)))
        elif ty[0] == "mapping":
            out.append(
                Var(
                    slot,
                    0,
                    SlotType(MAPPING, 32, value=_legacy_value(ty[1] if len(ty) > 1 else None)),
                    str(name),
                )
            )
        elif ty[0] == "array":
            out.append(
                Var(
                    slot,
                    0,
                    SlotType(
                        DYNAMIC_ARRAY, 32, value=_legacy_value(ty[1] if len(ty) > 1 else None)
                    ),
                    str(name),
                )
            )
    return out


def _int(x: Any) -> int:
    return int(x, 0) if isinstance(x, str) else int(x)


def _type_from_dict(d: dict) -> SlotType:
    enc = d.get("encoding", INPLACE)
    size = d.get("size", d.get("numberOfBytes", d.get("bytes")))
    size = _int(size) if size is not None else (32 if enc != INPLACE else None)
    value = d.get("value", d.get("base"))
    members = tuple(
        Member(
            _int(m.get("slot", 0)), _int(m.get("offset", 0)), _type_from_dict(m), m.get("name", "")
        )
        for m in d.get("members") or ()
    )
    return SlotType(
        enc,
        size,
        d.get("label", d.get("type", "")) or "",
        key=d.get("key"),
        value=_type_from_dict(value) if isinstance(value, dict) else None,
        members=members,
        length=d.get("length"),
    )


def normalize_layout(layout: Any) -> List[Var]:
    """Any accepted layout form -> [Var] sorted by position (see the module docstring)."""
    if not layout:
        return []
    if isinstance(layout, dict):
        if "storage" not in layout:
            raise ValueError(
                "a layout dict must be a solc storageLayout ({'storage': [...], 'types': {...}})"
            )
        out = _from_solc(layout)
    elif all(isinstance(x, Var) for x in layout):
        out = list(layout)
    elif all(isinstance(x, dict) for x in layout):
        out = [
            Var(
                _int(d["slot"]),
                _int(d.get("offset", 0)),
                _type_from_dict(d),
                d.get("name", d.get("label", "")) or "",
            )
            for d in layout
        ]
    else:
        out = _from_stor_defs(layout)
    return sorted(out, key=lambda v: (v.slot, v.offset))


# ---------------------------------------------------------------- comparison


def _key_class(label: Optional[str]) -> Optional[str]:
    """How a mapping key is hashed: what makes two key types layout-equivalent."""
    if not label:
        return None
    if label in ("string", "bytes") or label.startswith("string") or label == "bytes storage ref":
        return "dynamic"
    if re.fullmatch(r"bytes\d+", label):
        return "left-aligned"
    if re.fullmatch(r"int\d*", label):
        return "signed"
    return "unsigned"  # uintN, address, bool, enum, contract


def _shape_mismatch(a: SlotType, b: SlotType, depth: int = 0) -> Optional[str]:
    """None when `a` and `b` are layout-identical as far as both are known, else a reason."""
    if a.encoding != b.encoding:
        return f"encoding {a.encoding} vs {b.encoding}"
    if a.size is not None and b.size is not None and a.size != b.size:
        return f"size {a.size} vs {b.size} bytes"
    if depth > 32:
        return None
    if a.encoding == MAPPING:
        ka, kb = _key_class(a.key), _key_class(b.key)
        if ka and kb and ka != kb:
            return f"mapping key {a.key} vs {b.key}"
    if a.value is not None and b.value is not None:
        why = _shape_mismatch(a.value, b.value, depth + 1)
        if why:
            return ("value " if a.encoding == MAPPING else "element ") + why
    if a.length is not None and b.length is not None and a.length != b.length:
        return f"array length {a.length} vs {b.length}"
    if a.members and b.members:
        if len(a.members) != len(b.members):
            return f"{len(a.members)} vs {len(b.members)} struct members"
        for ma, mb in zip(a.members, b.members):
            if (ma.slot, ma.offset) != (mb.slot, mb.offset):
                where = f"({ma.slot}, {ma.offset}) vs ({mb.slot}, {mb.offset})"
                return f"member {ma.name or '?'} at {where}"
            why = _shape_mismatch(ma.type, mb.type, depth + 1)
            if why:
                return f"member {ma.name or mb.name or '?'}: {why}"
    return None


_NAMED = (
    ("struct ", "struct"),
    ("contract ", "address"),
    ("interface ", "address"),
    ("enum ", "enum"),
)


def _canonical_label(label: str) -> str:
    for prefix, repl in _NAMED:
        if label.startswith(prefix):
            return repl
    return {"address payable": "address"}.get(label, label)


def _labels_exact(a: SlotType, b: SlotType) -> bool:
    if a.label and b.label and _canonical_label(a.label) != _canonical_label(b.label):
        return False
    if a.key and b.key and _canonical_label(a.key) != _canonical_label(b.key):
        return False
    if a.value is not None and b.value is not None and not _labels_exact(a.value, b.value):
        return False
    return all(_labels_exact(ma.type, mb.type) for ma, mb in zip(a.members, b.members))


@dataclasses.dataclass
class LayoutComparison:
    match: bool  # every expected variable found with the same shape, no overlap
    exact: bool  # ... and every known type label identical (names ignored)
    rows: List[dict]  # one per expected variable
    extras: List[dict]  # candidate variables overlapping no expected one

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def compare_layout(expected: Any, candidate: Any) -> LayoutComparison:
    """L2 check of `candidate` (normally a solc storageLayout) against the original's `expected`."""
    exp, cand = normalize_layout(expected), normalize_layout(candidate)
    by_pos = {(v.slot, v.offset): v for v in cand}
    used = set()
    rows: List[dict] = []
    ok = exact = True
    for e in exp:
        row = {"slot": e.slot, "offset": e.offset, "name": e.name, "expected": e.type.describe()}
        c = by_pos.get((e.slot, e.offset))
        if c is not None:
            used.add((c.slot, c.offset))
            why = _shape_mismatch(e.type, c.type)
            row.update(
                candidate=c.type.describe(),
                candidate_name=c.name,
                status="match" if why is None else "mismatch",
            )
            if why:
                row["reason"] = why
                ok = False
            elif not _labels_exact(e.type, c.type):
                exact = False
        else:
            over = [x for x in cand if x.start < e.end and e.start < x.end]
            for x in over:
                used.add((x.slot, x.offset))
            row.update(candidate=None, status="overlap" if over else "missing")
            if over:
                row["reason"] = "overlaps " + ", ".join(
                    f"{x.name or '?'}@({x.slot}, {x.offset})" for x in over
                )
            ok = False
        rows.append(row)
    extras = [
        {"slot": x.slot, "offset": x.offset, "name": x.name, "type": x.type.describe()}
        for x in cand
        if (x.slot, x.offset) not in used
    ]
    return LayoutComparison(ok, ok and exact, rows, extras)

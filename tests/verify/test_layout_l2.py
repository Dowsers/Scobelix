"""scobelix.verify.layout: storage layout normalisation and the L2 comparison."""

import pytest
from verify_helpers import SOLC, compile_fixture, original_artifact, requires_solc

from scobelix.verify import solc
from scobelix.verify.layout import (
    BYTES,
    DYNAMIC_ARRAY,
    INPLACE,
    MAPPING,
    SlotType,
    Var,
    compare_layout,
    normalize_layout,
)

# the decompiler's legacy json["stor_defs"] for the SimpleToken / Vault fixtures
TOKEN_STOR_DEFS = [
    ["def", "balanceOf", 0, ["mapping", 256]],
    ["def", "totalSupply", 1, ["mask", 256, 0]],
]
VAULT_STOR_DEFS = [
    ["def", "owner", 0, ["mask", 160, 0]],
    ["def", "deposits", 1, ["mapping", 256]],
    ["def", "paused", 2, ["mask", 8, 0]],
]

RICH = """pragma solidity 0.8.19;
contract L {
    struct S { uint128 a; address b; uint256 c; }
    mapping(address => mapping(uint256 => S)) m;
    S[] arr;
    string s;
    bytes32[3] fx;
    uint8 small;
    bool flag;
    int16 neg;
}"""
RICH_CHANGED = """pragma solidity 0.8.19;
contract L {
    struct S { uint128 a; uint256 c; address b; }
    mapping(address => mapping(bytes32 => S)) m;
    S[] arr;
    bytes s;
    uint256[3] fx;
    uint8 small;
    bool flag;
    uint16 neg;
}"""


def _layout(src):
    return solc.compile_standard_json(src, version=SOLC).artifact().storage_layout


def test_legacy_stor_defs_are_normalised():
    v = normalize_layout(VAULT_STOR_DEFS)
    assert [(x.slot, x.offset, x.type.encoding, x.type.size, x.name) for x in v] == [
        (0, 0, INPLACE, 20, "owner"),
        (1, 0, MAPPING, 32, "deposits"),
        (2, 0, INPLACE, 1, "paused"),
    ]
    assert v[1].type.value == SlotType(INPLACE, 32)
    # symbolic slots are skipped
    assert normalize_layout([["def", "x", ["add", 1, 2], ["mask", 8, 0]]]) == []


def test_dict_entries_are_normalised():
    v = normalize_layout(
        [
            {"slot": "0x2", "offset": 0, "size": 20, "label": "address", "name": "owner"},
            {
                "slot": 3,
                "encoding": "mapping",
                "key": "address",
                "value": {"size": 32, "label": "uint256"},
            },
        ]
    )
    assert v[0] == Var(2, 0, SlotType(INPLACE, 20, "address"), "owner")
    assert (
        v[1].type.encoding == MAPPING
        and v[1].type.key == "address"
        and v[1].type.value.label == "uint256"
    )
    with pytest.raises(ValueError):
        normalize_layout({"not": "a layout"})


@requires_solc
def test_solc_layout_keeps_nested_types():
    v = {x.name: x for x in normalize_layout(_layout(RICH))}
    m = v["m"].type
    assert (m.encoding, m.key, m.value.encoding, m.value.key) == (
        MAPPING,
        "address",
        MAPPING,
        "uint256",
    )
    s = m.value.value
    assert [(mm.slot, mm.offset, mm.type.size, mm.name) for mm in s.members] == [
        (0, 0, 16, "a"),
        (1, 0, 20, "b"),
        (2, 0, 32, "c"),
    ]
    assert v["arr"].type.encoding == DYNAMIC_ARRAY and v["s"].type.encoding == BYTES
    assert v["fx"].type.length == 3 and v["fx"].type.size == 96
    assert [(x.slot, x.offset) for x in (v["small"], v["flag"], v["neg"])] == [
        (6, 0),
        (6, 1),
        (6, 2),
    ]
    assert v["fx"].end == 6 * 32


@requires_solc
def test_l2_matches_the_true_layout_and_the_legacy_one():
    for name, defs in (("SimpleToken", TOKEN_STOR_DEFS), ("Vault", VAULT_STOR_DEFS)):
        truth = original_artifact(name).storage_layout
        assert compare_layout(truth, truth).exact
        cmp = compare_layout(defs, truth)
        assert cmp.match and all(r["status"] == "match" for r in cmp.rows) and cmp.extras == []
    flat = compile_fixture("vault/Flattened.sol", "Vault").storage_layout
    assert compare_layout(original_artifact("Vault").storage_layout, flat).exact


@requires_solc
def test_l2_flags_swapped_slots():
    swapped = compile_fixture("token/SwappedSlots.sol", "SwappedSlots").storage_layout
    cmp = compare_layout(original_artifact("SimpleToken").storage_layout, swapped)
    assert not cmp.match
    assert [r["reason"] for r in cmp.rows] == [
        "encoding mapping vs inplace",
        "encoding inplace vs mapping",
    ]


@requires_solc
def test_l2_compares_shapes_not_labels():
    rows = {r["name"]: r for r in compare_layout(_layout(RICH), _layout(RICH_CHANGED)).rows}
    assert (
        rows["m"]["status"] == "mismatch"
        and "mapping key uint256 vs bytes32" in rows["m"]["reason"]
    )
    assert rows["arr"]["status"] == "mismatch" and "member b" in rows["arr"]["reason"]
    for same_shape in (
        "s",
        "fx",
        "small",
        "flag",
        "neg",
    ):  # string/bytes, bytes32/uint256, int16/uint16
        assert rows[same_shape]["status"] == "match", same_shape
    cmp = compare_layout(
        _layout("pragma solidity 0.8.19; contract A { int16 x; }"),
        _layout("pragma solidity 0.8.19; contract A { uint16 y; }"),
    )
    assert cmp.match and not cmp.exact


@requires_solc
def test_fillers_are_extras_and_overlaps_fail():
    expected = [Var(1, 0, SlotType(INPLACE, 32, "uint256"), "total")]
    with_filler = _layout(
        "pragma solidity 0.8.19; contract A { uint256 __gap0; uint256 total; uint8 tail; }"
    )
    cmp = compare_layout(expected, with_filler)
    assert cmp.match and {e["name"] for e in cmp.extras} == {"__gap0", "tail"}
    narrower = _layout(
        "pragma solidity 0.8.19; contract A { uint256 a; uint128 b; uint128 total; }"
    )
    cmp = compare_layout(expected, narrower)
    assert (
        not cmp.match
        and cmp.rows[0]["status"] == "mismatch"
        and cmp.rows[0]["reason"] == "size 32 vs 16 bytes"
    )
    overlapping = _layout("pragma solidity 0.8.19; contract A { uint256[2] a; }")
    cmp = compare_layout(expected, overlapping)
    assert (
        not cmp.match and cmp.rows[0]["status"] == "overlap" and "a@(0, 0)" in cmp.rows[0]["reason"]
    )
    cmp = compare_layout(expected, _layout("pragma solidity 0.8.19; contract A { uint256 a; }"))
    assert cmp.rows[0]["status"] == "missing"


def test_unknown_parts_are_not_compared():
    loose = [Var(0, 0, SlotType(MAPPING, 32), "m")]  # value type unknown
    tight = [
        Var(0, 0, SlotType(MAPPING, 32, key="address", value=SlotType(INPLACE, 20, "address")), "m")
    ]
    assert compare_layout(loose, tight).match
    assert not compare_layout(
        [Var(0, 0, SlotType(MAPPING, 32, value=SlotType(INPLACE, 32)))], tight
    ).match

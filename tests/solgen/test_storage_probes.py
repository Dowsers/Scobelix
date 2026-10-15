"""
Storage layout recovery on the storage probes (data/storage: packed fields,
mappings of every key kind, structs, dynamic / fixed / packed arrays, strings
and bytes, enums, nested composites, custom slots, a token; solc 0.5.17,
0.6.12, 0.7.6 and 0.8.19 builds of the first four).

The generated contract ("full" level) is compiled and its storageLayout
compared with the probe's own (scobelix.verify.layout: slot, offset, size,
encoding and nested shapes per variable; 32-byte mapping key types are
normalised, they hash their word whatever the type).  Expected with the
current engine: at least 21 of 22 contracts and 173 of 174 variables (all
of them today: P6Nested `pools` keeps its nested struct member `inner` as a
one-slot filler because the engine loses that member's packed writes), no
declared variable where the probe has none, and the probe's type (modulo
struct / enum / contract names) for 150 variables or more (int256 / bytes32
values and keys are uint256 without other evidence, bytes is string without
a curated signature).
"""

import functools
import json
import re
from pathlib import Path

import pytest

from conftest import compile_or_fail

DATA = Path(__file__).parent / "data" / "storage"
PROBES = sorted(p.stem for p in DATA.glob("*.json"))


@functools.lru_cache(maxsize=None)
def _probe(name):
    return json.loads((DATA / f"{name}.json").read_text())


@functools.lru_cache(maxsize=None)
def _generated(name):
    import logging

    from scobelix.decompiler import decompile_bytecode
    from scobelix.solgen.v2 import generate

    logging.disable(logging.CRITICAL)
    try:
        d = decompile_bytecode(_probe(name)["runtime"])
    finally:
        logging.disable(logging.NOTSET)
    r = generate(d, idiom_level="full", target_solc="0.8.19")
    art = compile_or_fail(r.solidity, r.target_solc)
    return r, art.storage_layout


def _label(t):
    t = re.sub(r"struct [\w.]+", "struct", t)
    t = re.sub(r"(contract|interface) [\w.]+", "address", t)
    return re.sub(r"enum [\w.]+", "enum", t)


def _same_hashing(layout):
    """The layout with its 32-byte mapping key types (bytes32, int256) shown
    as uint256: a 32-byte key is hashed as its word whatever its type, so
    these layouts are identical (scobelix.verify classes keys by type)."""
    layout = json.loads(json.dumps(layout))
    types = layout.get("types") or {}
    types.setdefault("t_uint256", {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"})
    for t in types.values():
        if t.get("encoding") == "mapping" and types.get(t["key"], {}).get("label") in ("bytes32", "int256"):
            t["key"] = "t_uint256"
            t["label"] = "mapping(uint256 => " + t["label"].split(" => ", 1)[1]
    return layout


@functools.lru_cache(maxsize=None)
def _score(name):
    from scobelix.verify.layout import compare_layout

    r, layout = _generated(name)
    truth = _probe(name)["storageLayout"]
    cmp = compare_layout(_same_hashing(truth), _same_hashing(layout))
    types = {t: v for t, v in (layout.get("types") or {}).items()}
    gen = {(int(v["slot"]), v["offset"]): _label(types[v["type"]]["label"]) for v in layout.get("storage") or []
           if not v["label"].startswith("__gap")}
    want = {(int(v["slot"]), v["offset"]): _label(truth["types"][v["type"]]["label"]) for v in truth["storage"]}
    return {
        "vars": len(cmp.rows),
        "match": sum(1 for row in cmp.rows if row["status"] == "match"),
        "typed": sum(1 for k, lab in want.items() if gen.get(k) == lab),
        "spurious": [k for k in gen if k not in want and not any(row["status"] == "match" and (
            row["slot"], row["offset"]) == k for row in cmp.rows)],
        "rows": [row for row in cmp.rows if row["status"] != "match"],
    }


# the probes built by the current compiler run by default, except the three
# longest (arrays, nested structs and edge cases: the StorageShapes and
# NestedStructMapping fixtures keep arrays and nested structs in the default
# run); those three, the builds of the first four by older compilers, and the
# totals, with `-m slow`
CURRENT = [name for name in PROBES if "_v0" not in name]
_LONG_PROBES = {"P4Arrays", "P6Nested", "P9Edge"}
_BY_BUILD = [name if name in CURRENT and name not in _LONG_PROBES else pytest.param(name, marks=pytest.mark.slow)
             for name in PROBES]

# the variables a probe may miss (see the module docstring)
_MAY_MISS = {"P6Nested": 1}


@pytest.mark.parametrize("name", _BY_BUILD)
def test_layout_exact_on_the_probe(name):
    s = _score(name)
    assert s["vars"] - s["match"] <= _MAY_MISS.get(name, 0), s["rows"]


@pytest.mark.parametrize("name", _BY_BUILD)
def test_no_spurious_variables(name):
    assert _score(name)["spurious"] == []


@pytest.mark.slow
def test_types_of_the_current_builds():
    scores = {name: _score(name) for name in CURRENT}
    assert sum(s["vars"] for s in scores.values()) == 66
    typed = sum(s["typed"] for s in scores.values())
    assert typed >= 58, {n: (s["typed"], s["vars"]) for n, s in scores.items()}


@pytest.mark.slow
def test_totals_over_every_probe():
    scores = {name: _score(name) for name in PROBES}
    contracts = sum(1 for s in scores.values() if s["match"] == s["vars"])
    variables = sum(s["match"] for s in scores.values())
    assert sum(s["vars"] for s in scores.values()) == 174
    misses = {n: s["rows"] for n, s in scores.items() if s["match"] != s["vars"]}
    assert contracts >= 21 and variables >= 173, misses
    assert set(misses) <= set(_MAY_MISS), misses
    typed = sum(s["typed"] for s in scores.values())
    assert typed >= 150, {n: (s["typed"], s["vars"]) for n, s in scores.items()}


TYPED = """
contract Typed {
    mapping(address => bool) private _allowed;
    uint8 private _initialized;
    bytes32 private _secret;
    int256 private _delta;
    uint256 private _count;
    uint256[] public data;
    uint256 private _wide;

    constructor() { _allowed[msg.sender] = true; }

    function init() external {
        require(_initialized < 1, "done");
        _initialized = 1;
    }
    function setSecret(string calldata s) external { _secret = keccak256(bytes(s)); }
    function unlock(string calldata s) external {
        require(_allowed[msg.sender], "not allowed");
        require(keccak256(bytes(s)) == _secret, "wrong");
        _count += 1;
    }
    function move(int256 d) external { _delta += d; }
    function negative() external view returns (bool) { return _delta < 0; }
    function push(uint256 v) external { data.push(v); }
    function widen(uint128 v) external { _wide = v; }
}
"""


@pytest.mark.parametrize("optimize", [True, pytest.param(False, marks=pytest.mark.slow)])
def test_types_decided_by_the_use_of_the_values(monkeypatch, optimize):
    """No getter and no output type tells these types: a byte only tested
    against zero is a bool, one compared as a number a uint8, a word written
    from a hash and compared with one a bytes32, a word in signed comparisons
    an int256, a word only written from a narrower value a uint256; the
    layout is the original's, labels included."""
    from eth_utils import keccak

    from probes import CALLER, Build, calldata_cases, compile_probe, differential, generate_probe, patch_signatures

    art = compile_probe(TYPED, Build("0.8.19", optimize=optimize), "Typed")
    patch_signatures(monkeypatch, art.abi, outputs=False)
    r = generate_probe(art.runtime)
    layout = compile_or_fail(r.solidity, r.target_solc).storage_layout

    def labels(lay):
        return sorted((int(v["slot"]), v["offset"], lay["types"][v["type"]]["label"]) for v in lay["storage"])

    assert labels(layout) == labels(art.storage_layout), r.solidity
    allowed = int.from_bytes(keccak(bytes(12) + bytes.fromhex(CALLER[2:]) + bytes(32)), "big")
    states = [None, {allowed: 1, 1: 1, 2: int.from_bytes(keccak(b"x"), "big"), 3: 2**256 - 5},
              {allowed: 0x100, 1: 0x200, 3: 7}]
    sigs = ("init()", "setSecret(string)", "unlock(string)", "move(int256)", "negative()", "push(uint256)",
            "data(uint256)", "widen(uint128)")
    calls = [(c, 0) for s in sigs for c in calldata_cases(s)] + [(keccak(text="unlock(string)")[:4] + bytes(31) + b" "
                                                                  + bytes(31) + b"\x01" + b"x" + bytes(31), 0)]
    for storage in states:
        assert not differential(art.runtime, r.solidity, r.target_solc, calls, storage)


@pytest.mark.parametrize("name", ["P1Packed", "P2Maps", "P3Structs", pytest.param("P4Arrays", marks=pytest.mark.slow),
                                  "P5Misc", "P8Token"])
def test_declared_layout_is_self_checked(name):
    r, _ = _generated(name)
    assert r.storage_layout and all({"name", "slot", "offset", "type", "public"} <= set(v) for v in r.storage_layout)
    assert not any("self-check failed" in w or "not compiled" in w for w in r.warnings), r.warnings

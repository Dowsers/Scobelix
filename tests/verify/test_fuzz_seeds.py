"""scobelix.verify.fuzz / seeds / abi: inputs, storage seeds, function specs, dispatcher scan."""

import random

import pytest
from eth_abi import decode, encode
from eth_utils import keccak
from verify_helpers import SOLC, compile_fixture, original_artifact, original_runtime, requires_solc

from scobelix.verify import solc
from scobelix.verify.bytecode import disasm
from scobelix.verify.abi import (
    FuncSpec,
    canonical_type,
    dispatcher_selectors,
    parse_selector,
    selector_key,
    specs_from_abi,
    specs_from_hint,
    split_types,
)
from scobelix.verify.fuzz import (
    ValueGen,
    comparison_constants,
    encode_call,
    head_words,
    is_dynamic,
    mutate_calldata,
    push_dictionary,
    raw_calldata,
)
from scobelix.verify.layout import INPLACE, SlotType, Var, normalize_layout
from scobelix.verify.seeds import SeedPlan, clean_words, mapping_slot, seed_value

UNIVERSE = ["0x" + "a1" * 20, "0x" + "b2" * 20, "0x" + "c0de" * 10]
TYPES = [
    "uint8",
    "int16",
    "uint256",
    "int256",
    "address",
    "bool",
    "bytes4",
    "bytes32",
    "bytes",
    "string",
    "uint256[]",
    "address[2]",
    "(uint8,bytes)[]",
    "(address,(bool,string))",
    "function",
]


def test_generated_values_encode_and_decode():
    rng = random.Random(1)
    for _ in range(40):
        vg = ValueGen(rng, UNIVERSE, [0xDEADBEEF])
        args = [vg.gen(t) for t in TYPES]
        blob = encode(TYPES, args)
        assert len(decode(TYPES, blob)) == len(TYPES)
    vg = ValueGen(random.Random(2), UNIVERSE)
    for _ in range(50):
        vg.gen("uint64")
        vg.gen("address")
    assert vg.used and all(0 <= v < 1 << 64 for v in vg.used) and vg.used_addresses


def test_value_sources():
    rng = random.Random(3)
    vg = ValueGen(rng, UNIVERSE, [12345678])
    values = {vg.uint(256) for _ in range(400)}
    assert {0, 1, 2, (1 << 256) - 1, 1 << 255, 10**18, 12345678} <= values
    addresses = {vg.address() for _ in range(200)}
    assert set(UNIVERSE) <= addresses and "0x" + "00" * 20 in addresses
    assert {vg.gen("int8") for _ in range(300)} >= {-128, -1, 0, 1, 127}


def test_head_words_and_dynamic_types():
    assert head_words(["uint8", "bytes", "(address,uint16)", "uint256[2]"]) == [
        (0, "uint8"),
        (1, "<offset>"),
        (2, "address"),
        (3, "uint16"),
        (4, "uint256"),
        (5, "uint256"),
    ]
    assert is_dynamic("string") and is_dynamic("uint256[]") and is_dynamic("(uint8,bytes)")
    assert not is_dynamic("(address,uint16)[3]") and not is_dynamic("bytes32")


def test_mutations_target_the_abi_decoder():
    spec = FuncSpec.from_signature("f(address,bool,bytes,bytes4)")
    rng = random.Random(4)
    data = encode_call(spec, ["0x" + "a1" * 20, True, b"xy", b"\x01\x02\x03\x04"])
    kinds = set()
    for _ in range(300):
        kind, out = mutate_calldata(rng, spec, data)
        kinds.add(kind)
        assert out[:4] == data[:4] and out != data
        if kind == "dirty":
            assert len(out) == len(data)
            word = next(
                i
                for i in range(4)
                if out[4 + 32 * i : 36 + 32 * i] != data[4 + 32 * i : 36 + 32 * i]
            )
            assert word in (0, 1, 3)  # address / bool / bytes4 padding (word 2 is the bytes offset)
        if kind == "offset":
            assert out[36 + 32 : 68 + 32] != data[36 + 32 : 68 + 32]
    assert kinds == {"short", "long", "selector_only", "dirty", "offset"}


def test_raw_calldata_for_unknown_parameters():
    rng = random.Random(5)
    vg = ValueGen(rng, UNIVERSE)
    blobs = [raw_calldata(rng, vg, b"\x12\x34\x56\x78") for _ in range(100)]
    assert all(b[:4] == b"\x12\x34\x56\x78" for b in blobs)
    assert {(len(b) - 4) // 32 for b in blobs} >= {0, 1, 2, 3}


def test_specs_from_abi_and_hints():
    abi = [
        {
            "type": "function",
            "name": "transfer",
            "stateMutability": "nonpayable",
            "inputs": [{"type": "address"}, {"type": "uint256"}],
        },
        {
            "type": "function",
            "name": "f",
            "payable": True,
            "constant": False,
            "inputs": [{"type": "tuple", "components": [{"type": "uint"}, {"type": "bytes"}]}],
        },
        {"type": "event", "name": "E", "inputs": []},
        {"type": "fallback"},
    ]
    specs = specs_from_abi(abi)
    t = specs[bytes.fromhex("a9059cbb")]
    assert (
        t.signature == "transfer(address,uint256)"
        and t.inputs == ["address", "uint256"]
        and t.payable is False
    )
    f = specs[keccak(text="f((uint256,bytes))")[:4]]
    assert f.inputs == ["(uint256,bytes)"] and f.payable and f.mutability == "payable"
    # decompiler json["functions"]: names checked against the selector, else typed by params
    dec = [
        {
            "hash": "0xa9059cbb",
            "abi_name": "transfer(address,uint256)",
            "payable": False,
            "params": {},
        },
        {
            "hash": "0x12345678",
            "abi_name": "unknown12345678(?)",
            "params": {"36": ["uint8", "b"], "4": ["address", "a"]},
        },
        {"hash": "0x9abcdef0", "abi_name": "unknown9abcdef0(?)", "params": {}},
        {"hash": "_fallback", "abi_name": "_fallback(?)"},
    ]
    hint = specs_from_hint(dec)
    assert set(hint) == {bytes.fromhex(x) for x in ("a9059cbb", "12345678", "9abcdef0")}
    assert hint[bytes.fromhex("12345678")].inputs == ["address", "uint8"]
    assert hint[bytes.fromhex("9abcdef0")].inputs is None
    mapping = specs_from_hint(
        {0xB4E7D02A: {"inputs": ["uint"], "payable": False}, "0x01020304": "g(uint8)"}
    )
    assert mapping[bytes.fromhex("b4e7d02a")].inputs == ["uint256"]
    g = mapping[bytes.fromhex("01020304")]
    # unverified name, selector kept
    assert g.signature == "g(uint8)" and g.selector == bytes.fromhex("01020304")


def test_type_and_selector_helpers():
    assert split_types("address,(uint8,bytes)[],uint") == ["address", "(uint8,bytes)[]", "uint"]
    assert canonical_type("(uint,int[2],byte)[]") == "(uint256,int256[2],bytes1)[]"
    assert canonical_type("address payable") == "address"
    with pytest.raises(ValueError):
        canonical_type("mapping(address => uint256)")
    assert (
        parse_selector(0xA9059CBB)
        == parse_selector("A9059CBB")
        == parse_selector(b"\xa9\x05\x9c\xbb")
    )
    assert selector_key("0x1") == "0x00000001"
    with pytest.raises(ValueError):
        parse_selector("0x123456789")


@requires_solc
def test_dispatcher_scan_finds_every_selector():
    assert sorted(dispatcher_selectors(original_runtime("SimpleToken"))) == [
        0x18160DDD,
        0x70A08231,
        0xA9059CBB,
    ]
    vault = {int(s, 16) for s in original_artifact("Vault").method_ids.values()}
    assert set(dispatcher_selectors(original_runtime("Vault"))) == vault
    # the embedded child's v() is not a selector of it
    factory = compile_fixture("misc/Factory.sol", "Factory")
    assert {f"{s:08x}" for s in dispatcher_selectors(factory.runtime)} == set(
        factory.method_ids.values()
    )
    src = (
        "pragma solidity 0.8.19; contract V { function a() external {} function b() external {}"
        " function c(uint x) external pure returns (uint) { return x; } }"
    )
    for settings in (solc.Settings(via_ir=True), solc.Settings(optimize=False, via_ir=True)):
        art = solc.compile_standard_json(src, settings, version=SOLC).artifact()
        assert {f"{s:08x}" for s in dispatcher_selectors(art.runtime)} == set(
            art.method_ids.values()
        )


def test_push_dictionary():
    code = original_runtime("SimpleToken")
    d = push_dictionary(code)
    assert 0xA9059CBB in d and 0x4E487B71 in d  # a selector, the Panic selector
    assert len(d) == len(set(d)) and not {0, 1} & set(d)
    # small constants are boundaries too (`require(x < 5)`); jump targets are not values
    assert 0x20 in d and 0x11 in d  # an ABI word size, Panic(0x11)
    jumpdests = {pc for pc, op, _ in disasm(code) if op == 0x5B}
    assert not jumpdests & set(d)


def test_comparison_constants_are_the_boundaries():
    # PUSH2 1000 DUP2 GT, PUSH1 7 EQ, PUSH1 3 NOT SLT (-4), PUSH2 1500 POP
    code = bytes.fromhex("6103e88111" "600714" "60031912" "6105dc50")
    assert comparison_constants(code) == [1000, 7, (1 << 256) - 4]
    assert push_dictionary(code) == [1000, 7, (1 << 256) - 4, 1500]
    assert comparison_constants(code, exclude=[7]) == [1000, (1 << 256) - 4]


def test_fixed_bytes_draw_constants_in_both_alignments():
    vg = ValueGen(random.Random(12), UNIVERSE, [0x150B7A02, 0xAB << 248])
    seen = {vg.gen("bytes4") for _ in range(400)}
    assert bytes.fromhex("150b7a02") in seen and bytes.fromhex("ab000000") in seen


# ---------------------------------------------------------------- seeds


def _plan(layout):
    return SeedPlan(normalize_layout(layout), UNIVERSE, senders=UNIVERSE[:2])


def test_seed_value_boundaries():
    rng = random.Random(6)
    seen = {seed_value(rng, [10]) for _ in range(600)}
    assert {10, 9, 11, (1 << 256) - 10, (1 << 256) - 11, 0, (1 << 256) - 1} <= seen
    assert all(0 <= v < 1 << 256 for v in seen)


def test_mapping_slots_follow_solidity():
    key = int(UNIVERSE[0], 16)
    assert mapping_slot(key, 3) == int.from_bytes(
        keccak(encode(["address", "uint256"], [UNIVERSE[0], 3])), "big"
    )


@requires_solc
def test_seeds_cover_the_layout_and_the_callers():
    plan = _plan(original_artifact("Vault").storage_layout)
    rng = random.Random(7)
    caller = "0x" + "7e1c" * 10
    hits = {"owner": 0, "owner is the caller": 0, "deposit": 0, "paused": 0}
    for _ in range(200):
        seeds = plan.per_call(rng, used=[5], callers=[caller])
        owner = seeds.storage.get(0)
        if owner is not None:
            owner &= (1 << 160) - 1
            hits["owner"] += owner in {int(a, 16) for a in UNIVERSE[:2] + [caller]}
            hits["owner is the caller"] += owner == int(caller, 16)
        hits["deposit"] += mapping_slot(int(caller, 16), 1) in seeds.storage
        hits["paused"] += seeds.storage.get(2, 0) & 0xFF in (0, 1)
    # owner checks pass often: the call's own sender is the favoured owner
    assert hits["owner"] > 60 and hits["owner is the caller"] > 40, hits
    assert hits["deposit"] > 100 and hits["paused"] > 100, hits


def test_packed_fields_and_dirty_words():
    layout = [
        Var(0, 0, SlotType(INPLACE, 20, "address"), "owner"),
        Var(0, 20, SlotType(INPLACE, 1, "bool"), "paused"),
        Var(0, 21, SlotType(INPLACE, 8, "uint64"), "count"),
    ]
    plan = SeedPlan(layout, UNIVERSE, dirty_ratio=0.5)
    rng = random.Random(8)
    dirty = clean = 0
    for _ in range(300):
        seeds = plan.per_call(rng, p_layout=1.0)
        word = seeds.storage[0]
        if 0 in seeds.dirty:
            dirty += 1
            cleaned = seeds.cleaned()[0]
            assert cleaned >> (29 * 8) == 0 and (cleaned >> 160) & 0xFF in (0, 1)
        else:
            clean += 1
            assert word >> (29 * 8) == 0 and (word >> 160) & 0xFF in (0, 1)
    assert dirty > 50 and clean > 50
    assert clean_words({0: (1 << 255) | (2 << 160)}, {0: tuple(plan.root.fields[0])}) == {0: 0}


def test_arrays_strings_and_nested_mappings():
    layout = [
        Var(0, 0, SlotType("dynamic_array", 32, value=SlotType(INPLACE, 32, "uint256")), "arr"),
        Var(1, 0, SlotType("bytes", 32, "string"), "name"),
        Var(
            2,
            0,
            SlotType(
                "mapping",
                32,
                key="address",
                value=SlotType(
                    "mapping", 32, key="address", value=SlotType(INPLACE, 32, "uint256")
                ),
            ),
            "allow",
        ),
    ]
    plan = SeedPlan(layout, UNIVERSE)
    rng = random.Random(9)
    lengths, strings, nested = set(), set(), 0
    a, b = (int(x, 16) for x in UNIVERSE[:2])
    for _ in range(200):
        st = plan.per_call(rng, p_layout=1.0).storage
        lengths.add(st[0])
        if st[0]:
            assert int.from_bytes(keccak((0).to_bytes(32, "big")), "big") in st
        word = st[1]
        strings.add("long" if word & 1 else "short")
        if not word & 1:
            assert (word & 0xFF) % 2 == 0 and (word & 0xFF) // 2 < 32
        nested += mapping_slot(b, mapping_slot(a, 2)) in st
    assert len(lengths) >= 3 and strings == {"long", "short"} and nested > 20


def test_discovered_slots_keep_the_layout_types():
    layout = [
        Var(0, 0, SlotType("dynamic_array", 32, value=SlotType(INPLACE, 20, "address")), "list"),
        Var(1, 0, SlotType("bytes", 32, "string"), "name"),
    ]
    plan = SeedPlan(layout, UNIVERSE, senders=UNIVERSE[:2])
    rng = random.Random(11)
    owner_slot, caller = 0xB531, "0x" + "7e1c" * 10
    callers = 0
    for _ in range(400):
        st = plan.per_call(rng, used=[7], discovered=[0, 1, owner_slot], callers=[caller]).storage
        # an array length no contract reaches (>= 2^64) or a broken string encoding would make
        # compiler pipelines differ (viaIR checks what legacy code does not)
        assert st.get(0, 0) < 8
        word = st.get(1, 0)
        assert (word & 1 and word >= 65) or (word & 0xFF) // 2 < 32
        # a slot outside the layout sometimes holds an address: often the call's sender
        callers += st.get(owner_slot) == int(caller, 16)
    assert callers > 10


@requires_solc
def test_reachable_state_is_clean():
    plan = _plan(original_artifact("Vault").storage_layout)
    rng = random.Random(10)
    for _ in range(50):
        st = plan.reachable(rng)
        assert st.get(2, 0) in (0, 1)
        assert all(v < 10**18 + 1 for s, v in st.items() if s != 0)

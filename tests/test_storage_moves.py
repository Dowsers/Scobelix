"""
Storage writes that move bits inside one slot, and bytesN fields read
left-aligned, keep their exact values in the trace (fixture StorageMoves:
solc 0.8.19 with the optimizer, via IR, and 0.5.17).

The optimizer folds `b = a; a = v` into one SSTORE whose value reads the
slot it writes. The decompiler splits such a store into one store per
field, run one after the other: a field computed from other bits of the
slot must be stored before those bits are overwritten, and fields that read
each other (a swap) stay one store of the whole word. A bytesN field at the
start of its slot is read as the field moved up to the top of the word,
never as the field itself.

Each fixture function runs on its `orig_trace` with the trace evaluator of
tests/trace_machine.py and is compared with the storage / output the
contract gives (worked out from its layout).
"""

import functools
import logging
from pathlib import Path

import pytest
from eth_hash.auto import keccak

from scobelix.core.algebra import mask_op
from scobelix.core.memloc import may_alias, order_field_stores, slot_reads, split_store
from scobelix.decompiler import decompile_bytecode
from scobelix.simplify import simplify_trace

from trace_machine import Machine

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"
BUILDS = ("StorageMoves", "StorageMovesViaIR", "StorageMovesLegacy")

M = 2**256
G0 = 0x1122334455667788990011223344556677889900AABBCCDDEEFF00112233445566
G1 = 0xF0E1D2C3B4A5968778695A4B3C2D1E0FF0E1D2C3B4A5968778695A4B3C2D1E0F


@functools.lru_cache(maxsize=None)
def _decompile(name):
    logging.disable(logging.WARNING)
    try:
        return decompile_bytecode((FIXTURES_DIR / f"{name}.hex").read_text().strip())
    finally:
        logging.disable(logging.NOTSET)


def selector(signature):
    return "0x" + keccak(signature.encode()).hex()[:8]


def word(x):
    return (x % M).to_bytes(32, "big")


def run(fixture, signature, args, storage):
    """(storage after the call, output) of the function's orig_trace."""
    trace = _decompile(fixture).functions[selector(signature)].orig_trace
    calldata = bytes.fromhex(selector(signature)[2:]) + b"".join(word(a) for a in args)
    machine = Machine(calldata, storage=storage)
    ok, out = machine.call(trace)
    assert ok, signature
    return machine.storage, out


def field(g, size, off):
    return (g >> off) & ((1 << size) - 1)


def put(g, size, off, v):
    mask = ((1 << size) - 1) << off
    return (g & ~mask % M) | ((v << off) & mask)


# ----------------------------------------------------------------- unit level

S4 = ("storage", 256, 0, 4)


def test_a_field_read_from_bits_another_field_overwrites_is_stored_first():
    # u8 = uint8(bytes1(b6)); b6 = 0 in one SSTORE: [bytes6 b6][...][uint8 u8 at 72]
    value = (
        "or",
        ("and", ((M - 1) ^ ((1 << 48) - 1)) & ~(0xFF << 72) % M, S4),
        ("mask_shl", 8, 40, 32, S4),
    )
    assert split_store(("store", 256, 0, 4, value)) == [
        ("store", 8, 72, 4, ("storage", 8, 40, 4)),
        ("store", 48, 0, 4, 0),
    ]


def test_fields_moved_up_are_stored_highest_first():
    # b = a; a = v: b reads the bits of a, which a's store overwrites
    stores = [
        ("store", 8, 0, 0, ("mask_shl", 8, 0, 0, ("cd", 4))),
        ("store", 8, 8, 0, ("storage", 8, 0, 0)),
    ]
    assert order_field_stores(stores, 0) == stores[::-1]
    # fields that only read their own bits keep the offset order
    own = [("store", 8, 0, 0, ("storage", 8, 0, 0)), ("store", 8, 8, 0, ("storage", 8, 8, 0))]
    assert order_field_stores(own, 0) == own


def test_fields_that_read_each_other_stay_one_word():
    # (a, b) = (b, a)
    value = (
        "or",
        ("mask_shl", 8, 0, 8, ("storage", 8, 0, 0)),
        ("mask_shl", 240, 16, 0, ("storage", 256, 0, 0)),
        ("storage", 8, 8, 0),
    )
    line = ("store", 256, 0, 0, value)
    assert split_store(line) == [line]


def test_reads_of_other_slots():
    # a constant distance apart: never the same slot; a computed slot may be
    assert slot_reads(("add", ("storage", 8, 8, 1), ("mask_shl", 8, 16, 0, ("storage", 256, 0, 2)))) == [
        (1, 8, 16),
        (2, 16, 24),
    ]
    stores = [("store", 8, 0, ("sha3", ("cd", 4), 2), 0),
              ("store", 8, 8, ("sha3", ("cd", 4), 2), ("storage", 8, 0, ("sha3", ("cd", 36), 2)))]
    assert order_field_stores(stores, ("sha3", ("cd", 4), 2)) == stores[::-1]
    stores = [("store", 8, 0, ("sha3", ("cd", 4), 2), 0),
              ("store", 8, 8, ("sha3", ("cd", 4), 2), ("storage", 8, 0, ("add", 1, ("sha3", ("cd", 4), 2))))]
    assert order_field_stores(stores, ("sha3", ("cd", 4), 2)) == stores


def test_slots_that_may_be_the_same():
    key = ("sha3", ("cd", 4), 2)
    assert may_alias(key, key) and may_alias(None, 3)
    assert not may_alias(3, 4)
    assert not may_alias(("add", 1, key), key)  # a constant distance apart
    assert not may_alias(5, key) and not may_alias(("add", 7, key), 5)  # layout slot vs keccak slot
    assert may_alias(("sha3", ("cd", 36), 2), key)  # two keys of one mapping


def test_a_slot_computed_from_the_bits_it_writes_stays_one_word():
    # m[m[k].a].a = 0; m[m[k].a].b = 1 folded: the slot of every field store
    # is computed again from slot bits an earlier field store may overwrite
    idx = ("sha3", ("storage", 8, 0, ("sha3", ("cd", 4), 2)), 2)
    value = ("or", ("mask_shl", 240, 16, 0, ("storage", 256, 0, idx)), ("mask_shl", 8, 0, 8, 1))
    line = ("store", 256, 0, idx, value)
    assert split_store(line) == [line]
    # a slot computed from another slot of the layout is safe
    idx = ("sha3", ("storage", 160, 0, 3), 2)
    value = ("or", ("mask_shl", 240, 16, 0, ("storage", 256, 0, idx)), ("mask_shl", 8, 0, 8, 1))
    assert split_store(("store", 256, 0, idx, value)) == [("store", 8, 0, idx, 0), ("store", 8, 8, idx, 1)]


def test_a_field_moved_up_keeps_its_shift():
    # bytes6 at bits [0, 48) returned left-aligned: shl(208, field)
    assert mask_op(S4, size=48, offset=0, shl=208) == ("mask_shl", 48, 0, 208, ("storage", 48, 0, 4))
    assert mask_op(S4, size=256, offset=0, shl=208) == ("mask_shl", 48, 0, 208, ("storage", 48, 0, 4))
    left = ("mask_shl", 48, 0, 208, S4)
    exact, shown = simplify_trace([("return", left)], display=True)
    assert exact == [("return", ("mask_shl", 48, 0, 208, ("storage", 48, 0, 4)))]
    assert shown == [("return", ("storage", 48, 0, 4))]  # the text output shows the field


def test_a_field_moved_down_keeps_only_its_bits():
    # (slot & (2**160 - 1)) >> 8: 152 bits from bit 8
    assert mask_op(S4, size=160, offset=0, shl=-8) == ("storage", 152, 8, 4)
    assert mask_op(S4, size=64, offset=0, shl=-16) == ("storage", 48, 16, 4)


# ------------------------------------------------------------ fixture level


@pytest.mark.parametrize("fx", BUILDS)
def test_a_field_moved_up_in_one_store(fx):
    # Pair: a [0, 8), b [8, 16), c [16, 32)
    after, _ = run(fx, "moveUp(uint8)", [0x5A], {0: G0})
    assert after[0] == put(put(G0, 8, 8, field(G0, 8, 0)), 8, 0, 0x5A)


@pytest.mark.parametrize("fx", BUILDS)
def test_a_swap_and_a_rotation_in_one_store(fx):
    after, _ = run(fx, "swap()", [], {0: G0})
    assert after[0] == put(put(G0, 8, 0, field(G0, 8, 8)), 8, 8, field(G0, 8, 0))
    after, _ = run(fx, "rotate()", [], {0: G0})
    want = put(G0, 8, 0, field(G0, 8, 8))
    want = put(want, 8, 8, field(G0, 8, 16))
    want = put(want, 16, 16, field(G0, 8, 0))
    assert after[0] == want


@pytest.mark.parametrize("fx", BUILDS)
def test_a_field_moved_to_a_wider_one(fx):
    # tag [0, 32) -> count [32, 96), then tag = 0
    after, _ = run(fx, "tagToCount()", [], {1: G1})
    assert after[1] == put(put(G1, 64, 32, field(G1, 32, 0)), 32, 0, 0)


@pytest.mark.parametrize("fx", BUILDS)
def test_a_field_moved_up_in_a_mapping_element(fx):
    key = 0xABCDEF0123456789ABCDEF0123456789ABCDEF01
    slot = int.from_bytes(keccak(word(key) + word(2)), "big")
    after, _ = run(fx, "moveIn(address)", [key], {slot: G0})
    assert after[slot] == put(put(G0, 8, 8, field(G0, 8, 0)), 8, 0, 0)


@pytest.mark.parametrize("fx", BUILDS)
def test_a_bytes4_field_at_the_start_of_its_slot_is_read_left_aligned(fx):
    _, out = run(fx, "tag()", [], {1: G1})
    assert out == word(field(G1, 32, 0) << 224)
    _, out = run(fx, "firstByte()", [], {1: G1})
    assert out == word(field(G1, 8, 24) << 248)

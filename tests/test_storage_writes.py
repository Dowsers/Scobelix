"""
Packed storage writes keep their exact bit ranges (fixture StorageShapes,
solc 0.8.19 with and without the optimizer, 0.7.6): a bool among other
fields is an 8-bit store, a write that keeps several separate fields of the
slot (a non-contiguous mask) gives one store per written field, a struct
push writes each member in its own bits, and a storage field is a full
word once written to memory.

Each fixture function is run on a storage word full of other bits with the
trace evaluator of tests/trace_machine.py and compared with the storage the
contract leaves (worked out from its layout).
"""

import functools
import logging
from pathlib import Path

import pytest
from eth_hash.auto import keccak

from scobelix.core.memloc import sizeof, slice_exp, split_or, split_store, value_width
from scobelix.decompiler import decompile_bytecode

from trace_machine import Machine

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"
BUILDS = ("StorageShapes", "StorageShapesNoopt", "StorageShapesLegacy")

M = 2**256
G0 = 0x1122334455667788990011223344556677889900AABBCCDDEEFF00112233445566
G1 = 0xF0E1D2C3B4A5968778695A4B3C2D1E0FF0E1D2C3B4A5968778695A4B3C2D1E0F
CALLER = Machine.ENV["caller"]
TIMESTAMP = Machine.ENV["timestamp"]


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
    """The storage after running the function on `storage`."""
    trace = _decompile(fixture).functions[selector(signature)].orig_trace
    calldata = bytes.fromhex(selector(signature)[2:]) + b"".join(word(a) for a in args)
    machine = Machine(calldata, storage=storage)
    ok, _ = machine.call(trace)
    assert ok, signature
    return machine.storage


def mask(size, off):
    return ((1 << size) - 1) << off


def keep(g, *fields):
    """`g` with the given (size, offset) fields cleared."""
    for size, off in fields:
        g &= ~mask(size, off) % M
    return g


# ----------------------------------------------------------------- unit level

STORAGE = ("storage", 256, 0, 0)


def test_a_bool_or_ed_into_a_slot_is_an_8_bit_store():
    # solc: sload & ~(0xff << 160) | (bool << 160); the bool was widened to
    # the 96 bits above it, zeroing the fields there
    value = (
        "or",
        ("mask_shl", 160, 0, 0, STORAGE),
        ("mask_shl", 88, 168, 0, STORAGE),
        ("mask_shl", 96, 0, 160, ("bool", ("cd", 4))),
    )
    assert split_store(("store", 256, 0, 0, value)) == [("store", 8, 160, 0, ("bool", ("cd", 4)))]


def test_a_non_contiguous_kept_mask_gives_one_store_per_written_field():
    # a = x; who = msg.sender in [uint32 a][uint32 b][address who]: the kept
    # bits are b and the unused top bytes
    kept = mask(32, 32) | mask(32, 224)
    value = (
        "or",
        ("mask_shl", 192, 0, 64, "caller"),
        ("and", kept, STORAGE),
        ("mask_shl", 32, 0, 0, ("cd", 4)),
    )
    assert split_store(("store", 256, 0, 0, value)) == [
        ("store", 32, 0, 0, ("mask_shl", 32, 0, 0, ("cd", 4))),
        ("store", 160, 64, 0, "caller"),
    ]


def test_rows_that_really_overlap_keep_the_whole_value():
    value = ("or", ("mask_shl", 184, 72, 0, STORAGE), ("mask_shl", 192, 0, 64, ("cd", 4)))
    assert split_or(value) == [(256, 0, value)]


def test_a_mask_of_bit_fields_keeps_the_whole_value():
    # storage fields are whole bytes: interleaved nibbles are bit arithmetic,
    # not 32 packed fields
    value = (
        "or",
        ("and", int("f0" * 32, 16), STORAGE),
        ("and", int("0f" * 32, 16), ("cd", 4)),
    )
    line = ("store", 256, 0, 0, value)
    assert split_store(line) == [line]


def test_a_row_below_bit_zero_keeps_the_whole_value():
    value = ("or", ("mask_shl", 16, 0, -8, ("cd", 4)), ("mask_shl", 8, 0, 8, ("cd", 36)))
    assert split_or(value) == [(256, 0, value)]


def test_a_zero_term_adds_no_row():
    value = ("or", ("mask_shl", 184, 72, 0, STORAGE), ("mask_shl", 192, 0, 64, 0))
    assert split_store(("store", 256, 0, 0, value)) == [("store", 72, 0, 0, 0)]


def test_value_widths():
    assert value_width(("bool", ("cd", 4))) == 1
    assert value_width("caller") == 160
    assert value_width(("mask_shl", 192, 0, 0, "caller")) == 160
    assert value_width(("mask_shl", 96, 0, 0, ("bool", ("cd", 4)))) == 1
    assert value_width(("mask_shl", 8, 160, 0, ("cd", 4))) == 168
    assert value_width(("storage", 64, 176, 0)) == 64
    assert value_width(("cd", 4)) == 256
    assert value_width(2**64) == 65


def test_a_storage_field_is_a_full_word_in_memory():
    # the field is right-aligned in the 32 bytes it is mstore'd to: slicing
    # those bytes must not shift its offset
    assert sizeof(("storage", 96, 160, 2)) == 256
    assert slice_exp(("storage", 96, 160, 2), 0, 32) == ("storage", 96, 160, 2)


# ------------------------------------------------------------ fixture level


@pytest.mark.parametrize("fx", BUILDS)
def test_bool_write_keeps_the_other_fields(fx):
    # [address owner][bool flag][uint8 small][uint64 stamp]
    assert run(fx, "setFlag(bool)", [1], {0: G0}) == {0: keep(G0, (8, 160)) | (1 << 160)}
    assert run(fx, "setFlag(bool)", [0], {0: G0}) == {0: keep(G0, (8, 160))}


@pytest.mark.parametrize("fx", BUILDS)
def test_two_fields_written_at_once(fx):
    owner = 0xABCDEF0123456789ABCDEF0123456789ABCDEF01
    assert run(fx, "setOwnerFlag(address,bool)", [owner, 1], {0: G0}) == {
        0: keep(G0, (160, 0), (8, 160)) | owner | (1 << 160)
    }
    # a = x; who = msg.sender keeps b between them and the bytes above who
    assert run(fx, "setAWho(uint32)", [0x1234], {1: G1}) == {
        1: keep(G1, (32, 0), (160, 64)) | 0x1234 | (CALLER << 64)
    }
    assert run(fx, "setAB(uint32,uint32)", [7, 9], {1: G1}) == {
        1: keep(G1, (64, 0)) | 7 | (9 << 32)
    }


@pytest.mark.parametrize("fx", BUILDS)
def test_narrow_typed_writes(fx):
    assert run(fx, "setDelta(int64)", [(-3) % M], {2: G1}) == {
        2: keep(G1, (64, 0)) | (2**64 - 3)
    }
    assert run(fx, "setTag(bytes4)", [0xDEADBEEF << 224], {2: G1}) == {
        2: keep(G1, (32, 64)) | (0xDEADBEEF << 64)
    }
    assert run(fx, "setSmall(uint8)", [0x42], {0: G0}) == {0: keep(G0, (8, 168)) | (0x42 << 168)}


@pytest.mark.parametrize("fx", BUILDS)
def test_struct_push_writes_each_member_in_its_bits(fx):
    base = int.from_bytes(keccak((3).to_bytes(32, "big")), "big")
    n = 2
    who, amount = 0x1111111111111111111111111111111111111111, 0xAAAA
    before = {3: n, base + 3 * n: G0, base + 3 * n + 1: G1, base + 3 * n + 2: G0}
    after = run(fx, "push(address,uint96)", [who, amount], before)
    assert after[3] == n + 1
    assert after[base + 3 * n] == who | (amount << 160)
    # [uint64 start][bool active]: the bytes above them are kept
    assert after[base + 3 * n + 1] == keep(G1, (72, 0)) | TIMESTAMP | (1 << 64)
    assert after[base + 3 * n + 2] == 0
    # active = false keeps the other members
    after = run(fx, "close(uint256)", [n], {3: n + 1, base + 3 * n + 1: G1})
    assert after[base + 3 * n + 1] == keep(G1, (8, 64))


@pytest.mark.parametrize("fx", BUILDS)
def test_read_modify_write_of_packed_fields(fx):
    g = keep(G0, (8, 168), (64, 176)) | (5 << 168) | (7 << 176)
    assert run(fx, "bump()", [], {0: g}) == {0: keep(G0, (8, 168), (64, 176)) | (6 << 168) | (9 << 176)}

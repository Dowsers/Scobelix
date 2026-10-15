"""
Memory state the symbolic runs start from (Loader.memory_seed).

solc's prologue stores the initial free memory pointer at 0x40 before the
dispatcher runs, and solc >= 0.4.22 keeps 0x60 as a zero slot. A function is
decompiled from its entry point, after the dispatcher, so its run must start
from that state: a wrong seed shifts every allocation and lets the first
buffer alias the zero slot.
"""

from pathlib import Path

from scobelix.decompiler import decompile_bytecode
from scobelix.loader import Loader

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"


def _loader(hex_code):
    loader = Loader()
    loader.load_binary(hex_code)
    return loader


def _seed(pos, val):
    return ("setmem", ("range", pos, 32), val)


def test_prologue_variants():
    cases = {
        "6080604052": 0x80,  # PUSH1 0x80 PUSH1 0x40 MSTORE
        "608080604052": 0x80,  # PUSH1 0x80 DUP1 PUSH1 0x40 MSTORE (via-IR)
        "60806040818152": 0x80,  # PUSH1 0x80 PUSH1 0x40 DUP2 DUP2 MSTORE
        "73" + "11" * 20 + "3014" + "6080604052": 0x80,  # library address guard first
        "6060604052": 0x60,  # solc < 0.4.22
        "610100604052": 0x100,  # memory guard moved by via-IR
        "6004361015": None,  # no prologue
        "60006000526080604052": None,  # first memory write is not the pointer
        "56": None,
        "": None,
    }
    for code, fmp in cases.items():
        assert _loader(code + "600080fd").free_memory_pointer == fmp, code


def test_seed_at_pc0_is_fresh_memory_and_function_entries_follow_the_prologue():
    loader = _loader("6080604052600080fd")
    assert loader.memory_seed(0) == [_seed(0x40, 0), _seed(0x60, 0)]
    assert loader.memory_seed(5) == [_seed(0x40, 0x80), _seed(0x60, 0)]

    # before solc 0.4.22 allocation starts at 0x60: there is no zero slot
    assert _loader("6060604052600080fd").memory_seed(5) == [_seed(0x40, 0x60)]


def test_seed_without_prologue_depends_on_the_compiler():
    ipfs_0819 = "a264697066735822" + "1220" + "00" * 32 + "64736f6c6343000813" + "0033"
    # no prologue but a solc >= 0.4.22 trailer: solc's layout
    assert _loader("600080fd" + ipfs_0819).memory_seed(5) == [_seed(0x40, 0x80), _seed(0x60, 0)]
    # no prologue, no compiler information: nothing was written yet
    assert _loader("600080fd").memory_seed(5) == [_seed(0x40, 0), _seed(0x60, 0)]


def test_functions_read_the_real_free_memory_pointer_and_zero_slot():
    d = decompile_bytecode((FIXTURES_DIR / "MemorySeed.hex").read_text().strip())

    assert d.json["problems"] == {}
    assert d.functions["0xa122b9df"].returns == [("return", 0x80)]  # freePointer()
    assert d.functions["0x109c78ca"].returns == [("return", 0)]  # zeroSlot()


def test_functions_start_from_the_memory_the_dispatcher_left():
    # The dispatcher stores constants at 0x40 and 0x60 before routing (old
    # Vyper keeps its range bounds there); the function returns mload(0x60).
    code = (
        "7f" + "%064x" % (2**127 - 1) + "604052"  # mstore(0x40, 2**127 - 1)
        "7f" + "%064x" % 0x5EED0060 + "606052"  # mstore(0x60, 0x5eed0060)
        "60003560e01c" "631122334414" "61005c57"  # selector 0x11223344 -> 0x5c
        "600080fd"  # revert(0, 0)
        "5b60605160005260206000f3"  # 0x5c: return mload(0x60)
    )
    d = decompile_bytecode(code)

    assert d.functions["0x11223344"].returns == [("return", 0x5EED0060)]

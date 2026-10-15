"""
Storage definitions of the text output (sparser.rewrite_functions): slots
whose keccak the optimizer folded into a constant, two-dimensional arrays,
bool mappings named after their getter, no state kept between contracts,
and an access the storage parser cannot resolve left raw instead of
dropping every definition.
"""

import functools
import logging
from pathlib import Path

import pytest
from eth_hash.auto import keccak

import scobelix.sparser as sparser
from scobelix.decompiler import decompile_bytecode
from scobelix.function import Function
from scobelix.utils.signatures import make_abi

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"


def _decompile(name):
    logging.disable(logging.WARNING)
    try:
        return decompile_bytecode((FIXTURES_DIR / f"{name}.hex").read_text().strip())
    finally:
        logging.disable(logging.NOTSET)


@functools.lru_cache(maxsize=None)
def stor_defs(name):
    return [tuple(d) for d in _decompile(name).json["stor_defs"]]


def keccak_slot(slot):
    return int.from_bytes(keccak(slot.to_bytes(32, "big")), "big")


def test_folded_keccak_constants_are_decomposed():
    assert sparser.rainbow_sha3(keccak_slot(1)) == ("loc", 1)
    assert sparser.rainbow_sha3(keccak_slot(1) + 2) == ("add", 2, ("loc", 1))
    assert sparser.rainbow_sha3(keccak_slot(0) - 1) == ("add", -1, ("loc", 0))
    # slots whose hash starts with a zero byte were never matched
    for slot in (5, 11):
        assert sparser.rainbow_sha3(keccak_slot(slot)) == ("loc", slot)
    assert sparser.rainbow_sha3(keccak_slot(4000) + 7) == ("add", 7, ("loc", 4000))
    other = 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
    assert sparser.rainbow_sha3(other) == other
    assert sparser.rainbow_sha3(12) == 12


@pytest.mark.parametrize("fx", ("StorageShapes", "StorageShapesLegacy"))
def test_struct_pushes_define_no_phantom_variable(fx):
    defs = stor_defs(fx)
    assert ("def", "entries", 3, ("array", "struct")) in defs
    assert all(d[2] < 2**64 for d in defs), [d for d in defs if d[2] >= 2**64]


def test_two_dimensional_array_has_a_definition():
    assert [d for d in stor_defs("StorageShapes") if d[2] == 8] == [("def", "stor8", 8, ("array", 256))]


def test_bool_mapping_is_named_after_its_getter():
    assert ("def", "isAdmin", 7, ("mapping", 8)) in stor_defs("StorageShapes")


def test_definitions_do_not_depend_on_the_contracts_decompiled_before():
    alone = stor_defs("StorageShapes")
    # SimpleToken names a mapping at slot 0; StorageShapes has a bool getter there
    _decompile("SimpleToken")
    stor_defs.cache_clear()
    assert stor_defs("StorageShapes") == alone
    assert ("def", "flag", 0, ("mask", 8, 160)) in alone


def test_slot_99_is_defined_and_a_computed_slot_is_not():
    make_abi({"0x33333333": 0, "0x44444444": 0})
    writer = Function("0x33333333", [("store", 256, 0, 99, ("cd", 4)), ("stop",)])
    # sstore(calldataload(4), calldataload(36)): no slot to define
    raw = Function("0x44444444", [("store", 256, 0, ("cd", 4), ("cd", 36)), ("stop",)])
    defs = sparser.rewrite_functions([writer, raw])
    assert defs == [("def", "stor99", 99, ("mask", 256, 0))]


def test_an_unresolvable_access_keeps_its_raw_form(monkeypatch):
    make_abi({"0x11111111": 0, "0x22222222": 0})
    writer = Function("0x11111111", [("store", 256, 0, 5, ("cd", 4)), ("stop",)])
    reader = Function("0x22222222", [("return", ("storage", 256, 0, 7))])
    bad = ("storage", 256, 0, 5)
    real = sparser._sparser

    def failing(storages):
        if bad in storages:
            raise AssertionError("deep embedding unsupported")
        return real(storages)

    monkeypatch.setattr(sparser, "_sparser", failing)
    defs = sparser.rewrite_functions([writer, reader])
    # slot 7 is still defined (and named after its getter); the excluded
    # access keeps its raw index instead of dropping every definition
    assert [d for d in defs if d[2] == 7] == [("def", "unknown22222222", 7, ("mask", 256, 0))]
    assert writer.trace[0] == ("store", 256, 0, 5, ("cd", 4))
    assert reader.trace == [("return", ("stor", 256, 0, ("name", "unknown22222222", 7)))]

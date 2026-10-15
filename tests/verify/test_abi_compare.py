"""scobelix.verify.abi.compare_abi: a custom error the candidate declares must
be a constant of the original code, in every form a compiler writes it."""

from eth_utils import keccak

from scobelix.verify import bytecode
from scobelix.verify.abi import compare_abi


def _error(name):
    return {"type": "error", "name": name, "inputs": []}


def _unknown_errors(code, *names):
    result = compare_abi({}, [_error(name) for name in names], bytes.fromhex(code))
    return result.errors["declared_not_in_original"], result.status


def test_an_error_selector_pushed_whole_is_found():
    assert keccak(text="Empty()")[:4].hex() == "3db2a12a"
    # PUSH4 selector, PUSH1 224, SHL
    assert _unknown_errors("633db2a12a60e01b", "Empty") == ([], "pass")
    # PUSH32 selector, left-aligned
    assert _unknown_errors("7f3db2a12a" + "00" * 28, "Empty") == ([], "pass")
    # an error that is nowhere in the code is still reported
    assert _unknown_errors("633db2a12a60e01b", "Empty", "Other") == (["Other()"], "fail")


def test_an_error_selector_pushed_halved_is_found():
    # the selector of Empty() is even: the constant optimiser of solc pushes
    # its half and shifts by one more bit (PUSH4 0x1ed95095, PUSH1 225, SHL)
    code = "631ed9509560e11b"
    assert bytecode.push_values(bytes.fromhex(code)) == [0x1ED95095, 225]
    assert bytecode.shifted_push_values(bytes.fromhex(code)) == [0x3DB2A12A << 224]
    assert _unknown_errors(code, "Empty") == ([], "pass")
    # the same two constants added, not shifted, do not make the selector
    assert bytecode.shifted_push_values(bytes.fromhex("631ed9509560e101")) == []
    assert _unknown_errors("631ed9509560e101", "Empty") == (["Empty()"], "fail")


def test_shifted_constants_stay_words():
    # a shift that pushes bits out of the word, and one no word holds
    assert bytecode.shifted_push_values(bytes.fromhex("60ff60f91b")) == [0xFE << 248]
    assert bytecode.shifted_push_values(bytes.fromhex("60016101001b")) == []

"""
Function traits (Function.analyse): read-only means no store, call, log or
creation; a constant function is one return of a constant with no read of
storage, calldata or the environment; the string getter hint never drops
lines from the function (fixture FunctionTraits, solc 0.8.19 and 0.5.17).
The original trace of a legacy string getter or setter keeps every length
case (empty, short in the slot, long); only the display trace folds them.
"""

import functools
import logging
from pathlib import Path

import pytest
from eth_hash.auto import keccak

from scobelix.decompiler import decompile_bytecode
from scobelix.function import Function
from scobelix.utils.signatures import make_abi

from trace_machine import Machine

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"


@functools.lru_cache(maxsize=None)
def _decompile(name):
    logging.disable(logging.WARNING)
    try:
        return decompile_bytecode((FIXTURES_DIR / f"{name}.hex").read_text().strip())
    finally:
        logging.disable(logging.NOTSET)


def selector(signature):
    return "0x" + keccak(signature.encode()).hex()[:8]


def function(fixture, signature):
    return _decompile(fixture).functions[selector(signature)]


RETURN = ("return", 42)
HASH = "0x12345678"


def build(trace):
    """A Function outside a decompilation: the signature lookup of its
    selector must be set up first."""
    make_abi({HASH: 0})
    return Function(HASH, trace)


@pytest.mark.parametrize(
    "line",
    [
        ("log", 0, 0x1234),
        ("tstore", 1, 2),
        ("create2", 0, ("mem", ("range", 128, 32)), 0),
        ("callcode", 5000, 0x1234, 0, 0, 0, 0, 0),
        ("store", 256, 0, 0, 1),
        ("call", 5000, 0x1234, 0, 0, 0, 0, 0),
        ("selfdestruct", "caller"),
    ],
)
def test_state_changing_lines_make_a_function_not_read_only(line):
    f = build([line, RETURN])
    assert f.read_only is False
    assert f.const is None


def test_a_static_call_is_read_only():
    f = build([("staticcall", 5000, 0x1234, 0, 0, 0, 0), RETURN])
    assert f.read_only is True


@pytest.mark.parametrize(
    "value",
    [("balance", "address"), "timestamp", ("storage", 256, 0, 0), ("cd", 4), ("tload", 1), "caller"],
)
def test_a_function_reading_its_environment_is_not_constant(value):
    assert build([("return", value)]).const is None


def test_a_guarded_constant_is_not_constant():
    f = build([("if", ("lt", "timestamp", 5), [("revert", None)], [RETURN])])
    assert f.const is None


def test_constants():
    assert build([RETURN]).const == RETURN
    blob = ("return", ("data", 32, 2, ("bytes", 2, 0x6869)))
    assert build([blob]).const == blob


@pytest.mark.parametrize("fx", ("FunctionTraits", "FunctionTraitsLegacy"))
def test_fixture_traits(fx):
    assert function(fx, "fortyTwo()").const == ("return", 42)
    ping = function(fx, "ping()")  # emits an event, then returns 42
    assert ping.read_only is False and ping.const is None
    assert function(fx, "ownBalance()").const is None
    assert function(fx, "stamp()").const is None
    assert function(fx, "total()").getter == ("storage", 256, 0, 0)


def lines(trace):
    for line in trace:
        yield line
        if line[0] == "if":
            yield from lines(line[2])
            yield from lines(line[3])
        elif line[0] == "while":
            yield from lines(line[2])


def test_string_getter_keeps_its_check():
    f = function("FunctionTraitsLegacy", "labelChecked()")
    label = ("storage", 256, 0, ("array", ("range", 0, ("storage", 256, 0, ("length", ("loc", 1)))), ("loc", 1)))
    assert f.getter == label
    # the original trace holds the whole copy; the display trace folds the
    # copy into the getter but keeps the require
    assert f.orig_trace[0][0] == "if" and f.orig_trace[0][1] == ("iszero", ("storage", 256, 0, 0))
    assert any(line[0] == "while" for line in lines(f.orig_trace[0][3]))
    assert f.trace[0][0] == "if" and f.trace[0][2] == [("revert", None)]
    assert f.trace[0][3][0][0] == "return" and f.trace[0][3][0][1][3][0] == "array"
    assert len(f.trace[0][3]) == 1
    # the plain getter folds to the one return
    plain = function("FunctionTraitsLegacy", "label()")
    assert plain.getter == label and plain.trace[0][0] == "return" and len(plain.trace) == 1


# ------------------------------------------------ legacy strings (solc 0.5)


def string_storage(slot, value):
    """The storage of a string state variable holding `value`: up to 31
    bytes in the slot with 2 * length, else 2 * length + 1 in the slot and
    the bytes in the slots from keccak(slot) on."""
    if len(value) < 32:
        return {slot: int.from_bytes(value.ljust(32, b"\0"), "big") | 2 * len(value)}
    base = int.from_bytes(keccak(slot.to_bytes(32, "big")), "big")
    res = {slot: 2 * len(value) + 1}
    for i in range(0, len(value), 32):
        res[base + i // 32] = int.from_bytes(value[i : i + 32].ljust(32, b"\0"), "big")
    return res


def abi_string(value):
    return (32).to_bytes(32, "big") + len(value).to_bytes(32, "big") + value + b"\0" * (-len(value) % 32)


def run(signature, args=b"", storage=None):
    """(success, output, non-zero storage) of the original trace of a
    FunctionTraitsLegacy function."""
    f = function("FunctionTraitsLegacy", signature)
    m = Machine(bytes.fromhex(selector(signature)[2:]) + args, storage=storage)
    ok, out = m.call(f.orig_trace)
    return ok, out, {k: v for k, v in m.storage.items() if v}


STRINGS = [b"", b"hi", b"x" * 31, b"y" * 32, bytes(range(1, 71))]


@pytest.mark.parametrize("value", STRINGS, ids=len)
def test_legacy_string_getter_returns_every_length(value):
    # the trace keeps the empty, short (in the slot) and long cases
    storage = string_storage(1, value)
    assert run("label()", storage=storage)[:2] == (True, abi_string(value))
    storage[0] = 1  # total != 0
    assert run("labelChecked()", storage=storage)[:2] == (True, abi_string(value))


@pytest.mark.parametrize("old", [b"", b"short", bytes(range(100, 170))], ids=len)
@pytest.mark.parametrize("value", STRINGS, ids=len)
def test_legacy_string_setter_writes_every_length(old, value):
    # label = value; total += 1, over an older label whose bytes it clears
    ok, _, after = run("setLabel(string)", abi_string(value), {**string_storage(1, old), 0: 5})
    assert ok and after == {k: v for k, v in {**string_storage(1, value), 0: 6}.items() if v}

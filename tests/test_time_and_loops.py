"""
Values that change over time and loop variables, checked by running the
decompiled traces (tests/trace_machine.py) on concrete inputs and comparing
with what the Solidity sources (tests/fixtures/sources/TimeDependence.sol,
LoopShapes.sol, TransientSwap.sol) compute.

- A read of storage, transient storage, a balance or a call result keeps
  its value when the state changes afterwards (a write, another call).
- A call copies min(output size, returndatasize) bytes to its output buffer.
- Loop-carried values are all tracked (an accumulator unchanged by the first
  iteration too), their updates are parallel, and the values after a loop are
  only replaced by closed forms where those are exact.
- A require the loop structurer makes keeps its revert payload.
- A loop index into the data of a storage array, rewritten to count from
  keccak(slot), keeps its value after the loop (StorageShapes.sol).
"""

import functools
import re

import pytest
from eth_hash.auto import keccak

from scobelix.decompiler import decompile_bytecode
from scobelix.simplify import propagate_storage_in_loops
from scobelix.utils.helpers import opcode

from test_golden_fixtures import _load
from trace_machine import Machine, NotEvaluable

M = 2**256
ERROR_STRING = bytes.fromhex("08c379a0")
PANIC = bytes.fromhex("4e487b71")


@functools.lru_cache(maxsize=None)
def _decompile(name):
    return decompile_bytecode(_load(name))


def selector(signature):
    return "0x" + keccak(signature.encode()).hex()[:8]


def word(x):
    return (x % M).to_bytes(32, "big")


def words(output):
    return [int.from_bytes(output[i : i + 32], "big") for i in range(0, len(output), 32)]


def run(fixture, signature, args=(), **machine):
    """(success, output words, machine) of one call of the decompiled function."""
    trace = _decompile(fixture).functions[selector(signature)].orig_trace
    calldata = bytes.fromhex(selector(signature)[2:]) + b"".join(word(a) for a in args)
    m = Machine(calldata, **machine)
    success, output = m.call(trace)
    return success, output, m


def calls_returning(*outputs):
    """A callee giving these (success, return data) in turn."""
    queue = list(outputs)

    def on_call(kind, address, value, payload):
        return queue.pop(0)

    return on_call


def lines(trace):
    for line in trace:
        yield line
        if opcode(line) == "if":
            yield from lines(line[2])
            yield from lines(line[3])
        elif opcode(line) == "while":
            yield from lines(line[2])


# ------------------------------------------------------------ time dependence

TIME = ["TimeDependence", "TimeDependenceNoopt"]
WHO = 0xABCDEF0123456789ABCDEF0123456789ABCDEF01


@pytest.mark.parametrize("fx", TIME)
def test_storage_read_before_a_write(fx):
    ok, out, m = run(fx, "swapX(uint256)", [9], storage={0: 7})
    assert ok and words(out) == [7] and m.storage[0] == 9

    ok, out, m = run(fx, "swapXY()", storage={0: 3, 1: 4})
    assert ok and words(out) == [3, 4] and (m.storage[0], m.storage[1]) == (4, 3)

    slot = int.from_bytes(keccak(word(WHO) + word(2)), "big")
    ok, out, m = run(fx, "withdrawAll(address)", [WHO], storage={slot: 50})
    assert ok and words(out) == [50] and m.storage[slot] == 0


@pytest.mark.parametrize("fx", TIME)
@pytest.mark.parametrize("c", [0, 1])
def test_storage_read_before_a_conditional_write(fx, c):
    ok, out, m = run(fx, "keepOld(uint256,bool)", [9, c], storage={0: 7})
    assert ok and words(out) == [8] and m.storage[0] == (9 if c else 7)


@pytest.mark.parametrize("fx", TIME)
def test_results_of_two_calls(fx):
    on_call = calls_returning((1, word(10)), (1, word(20)))
    ok, out, m = run(fx, "twoCalls(address)", [WHO], on_call=on_call)
    assert ok and words(out) == [10020]

    on_call = calls_returning((1, b""), (0, b""))
    ok, out, m = run(fx, "sendBoth(address,address)", [WHO, WHO + 1], on_call=on_call)
    assert ok and words(out) == [1, 0]

    on_call = calls_returning((1, b"abc"), (1, bytes(40)))
    ok, out, m = run(fx, "sizes(address)", [WHO], on_call=on_call)
    assert ok and words(out) == [3, 40]


@pytest.mark.parametrize("fx", TIME)
def test_storage_read_around_a_call_that_changes_it(fx):
    machine = {}

    def reenter(kind, address, value, payload):
        machine["m"].storage[0] = 99  # the callee changes x
        return 1, word(5)

    trace = _decompile(fx).functions[selector("readCallRead(address)")].orig_trace
    calldata = bytes.fromhex(selector("readCallRead(address)")[2:]) + word(WHO)
    m = machine["m"] = Machine(calldata, storage={0: 7}, on_call=reenter)
    ok, out = m.call(trace)
    assert ok and words(out) == [7, 99]


@pytest.mark.parametrize("fx", TIME)
def test_balance_before_and_after_a_transfer(fx):
    ok, out, m = run(fx, "balanceAround(address)", [WHO], balance=1000)
    assert ok and words(out) == [1000, 999]


@pytest.mark.parametrize("fx", TIME)
@pytest.mark.parametrize("fn", ["outputBuffer(address)", "delegateBuffer(address)"])
@pytest.mark.parametrize("returned", [b"", b"\x01\x02\x03\x04", bytes(range(1, 41)), bytes(range(1, 65))])
def test_call_output_buffer_keeps_what_is_not_returned(fx, fn, returned):
    ok, out, m = run(fx, fn, [WHO], on_call=calls_returning((1, returned)))
    expected = bytearray(word(0xAAAA) + word(0xBBBB))
    n = min(64, len(returned))
    expected[:n] = returned[:n]
    assert ok and out == bytes(expected)


@pytest.mark.parametrize("fx", TIME)
def test_compiled_calls_read_the_whole_buffer(fx):
    """Under the returndatasize check solc emits, the output buffer copy is
    the whole buffer (the shape without a min)."""
    trace = _decompile(fx).functions[selector("twoCalls(address)")].orig_trace
    assert "'min'" not in str(trace)


@pytest.mark.parametrize("fx", TIME)
def test_created_address_and_precompile_output_are_kept(fx):
    trace = _decompile(fx).functions[selector("twoChildren()")].orig_trace
    snaps = [l for l in lines(trace) if opcode(l) == "setvar" and l[2] == "create.new_address"]
    creates = [l for l in lines(trace) if opcode(l) == "create"]
    assert len(creates) == 2 and snaps

    trace = _decompile(fx).functions[
        selector("twoSigners(bytes32,uint8,bytes32,bytes32,uint8,bytes32,bytes32)")
    ].orig_trace
    snaps = [l for l in lines(trace) if opcode(l) == "setvar" and l[2] == ("var", "signer")]
    assert snaps  # the first signer, read before the second precompile


def test_transient_storage_read_before_a_write():
    trace = _decompile("TransientSwap").functions[selector("swap(uint256)")].orig_trace
    calldata = bytes.fromhex(selector("swap(uint256)")[2:]) + word(9)
    m = Machine(calldata)
    m.tstorage[5] = 4
    ok, out = m.call(trace)
    assert ok and words(out) == [4, 9]


# ------------------------------------------------------------ loops

LOOPS = ["LoopShapes", "LoopShapesNoopt", "LoopShapesViaIR"]


def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


CASES = [
    ("sumBelow(uint256)", [[n] for n in (0, 1, 2, 3, 10, 31)], lambda n: [n * (n - 1) // 2]),
    ("found(uint256,uint256)", [[5, 3], [5, 7], [0, 0], [1, 0]], lambda n, k: [int(k < n)]),
    ("power(uint256)", [[n] for n in (0, 1, 2, 9, 40)], lambda n: [2**n]),
    ("fromFive(uint256)", [[n] for n in (0, 3, 5, 6, 9)], lambda n: [max(n, 5)]),
    ("fib(uint256)", [[n] for n in (0, 1, 2, 3, 10, 20)], lambda n: [fib(n)]),
    (
        "nested(uint256,uint256)",
        [[0, 3], [2, 0], [3, 4], [4, 2]],
        lambda n, m: [sum(i * j + 1 for i in range(n) for j in range(m))],
    ),
    ("byTwo(uint256)", [[n] for n in (0, 1, 2, 5, 6)], lambda n: [(n + 1) // 2 * 2, (n + 1) // 2]),
    ("down(uint256)", [[n] for n in (0, 1, 4, 10)], lambda n: [n * (n + 1) // 2]),
    ("narrow(uint8)", [[n] for n in (0, 1, 7, 255)], lambda n: [n, 2 * n]),
    ("guarded(uint256,uint256)", [[5, 9], [0, 0], [4, 4]], lambda n, bad: [sum(range(n))]),
]


@pytest.mark.parametrize("fx", LOOPS)
@pytest.mark.parametrize("signature,inputs,expected", CASES, ids=[c[0] for c in CASES])
def test_loops_compute_what_the_source_does(fx, signature, inputs, expected):
    for args in inputs:
        try:
            ok, out, m = run(fx, signature, args)
        except NotEvaluable as e:  # pragma: no cover - reported with the inputs
            pytest.fail("%s%s: %s" % (signature, args, e))
        assert ok, (signature, args)
        assert words(out) == expected(*args), (signature, args)


@pytest.mark.parametrize("fx", LOOPS)
def test_require_in_a_loop_keeps_its_payload(fx):
    ok, out, m = run(fx, "guarded(uint256,uint256)", [5, 2])
    assert not ok
    assert out[:4] == ERROR_STRING and b"bad index" in out

    # a = [3, 5, 0]: stops at index 2; a = [3, 5]: reads a[2], Panic(0x32)
    fn = "firstZero(uint256[])"
    ok, out, m = run(fx, fn, [32, 3, 3, 5, 0])
    assert ok and words(out) == [2]
    ok, out, m = run(fx, fn, [32, 2, 3, 5])
    assert not ok and out == PANIC + word(0x32)

    fn = "capped(uint256)"
    for n in (0, 7, 49):
        ok, out, m = run(fx, fn, [n])
        assert ok and words(out) == [n]
    for n in (50, 51):
        ok, out, m = run(fx, fn, [n])
        assert not ok and out == b""
    trace = _decompile(fx).functions[selector(fn)].orig_trace
    requires = [l for l in lines(trace) if opcode(l) == "require"]
    assert all(len(r) == 3 and r[2] == ("revert", None) for r in requires)
    if fx != "LoopShapesViaIR":
        assert requires


@pytest.mark.parametrize("fx", LOOPS)
def test_loop_over_storage(fx):
    ok, out, m = run(fx, "bump(uint256)", [3], storage={0: 5})
    t = 5
    for i in range(3):
        t = t * 3 + i
    assert ok and words(out) == [t] and m.storage[0] == t


@pytest.mark.parametrize("fx", LOOPS)
def test_loop_condition_reads_what_the_body_changes(fx):
    """`while (i < total) { total -= 1; i++; }`: the header reads `total`
    again at every test, so the loop runs about n / 2 times, and the exit
    value of i is not a closed form of the first read."""
    for n in (0, 1, 4, 5, 9):
        ok, out, m = run(fx, "shrinkingBound(uint256)", [n])
        assert ok and words(out) == [(n + 1) // 2, n // 2] and m.storage[0] == n // 2, n
    for n in (0, 1, 3):
        ok, out, m = run(fx, "memBound(uint256)", [n])
        assert ok and words(out) == [2 if n else 0], n


@pytest.mark.parametrize("fx", LOOPS)
def test_parallel_updates_print_as_one_assignment(fx):
    """(a, b) = (b, a + b): the setvars of a continue are assigned at once,
    and the text shows them as one assignment."""
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", _decompile(fx).functions[selector("fib(uint256)")].print())
    assert re.search(r"^ *\w+, \w+, \w+ = .*, .*, ", text, re.M), text


# ----------------------------------------- loop indexes into storage arrays

ARRAY = ("sha3", 8)


def _index_loop(updates, store=("store", 256, 0, ("var", 1), ("var", 1))):
    """`for (v1 = keccak(8) + 5; v1 < keccak(8) + 8; ...) storage[v1] = v1`,
    then `storage[0] = v1`."""
    loop = (
        "while",
        ("gt", ("add", 8, ARRAY), ("var", 1)),
        [store, ("continue", "L", updates)],
        "L",
        [("setvar", 1, ("add", 5, ARRAY))],
    )
    return [loop, ("store", 256, 0, 0, ("var", 1)), ("stop",)]


def _storage_after(trace):
    m = Machine(b"")
    assert m.call(trace) == (True, b"")
    return m.storage


def test_a_loop_index_into_a_storage_array_keeps_its_value_after_the_loop():
    trace = _index_loop([("setvar", 1, ("add", 1, ("var", 1)))])
    rebased = propagate_storage_in_loops(trace)
    # in the loop the index reads `index + keccak(8)` (the storage parser's
    # form); after it, the value the loop left
    assert rebased[0][2][0][3] == ("add", ("var", "r1"), ARRAY)
    base = int.from_bytes(keccak(word(8)), "big")
    expected = {base + 5: base + 5, base + 6: base + 6, base + 7: base + 7, 0: base + 8}
    assert _storage_after(trace) == expected
    assert _storage_after(rebased) == expected


@pytest.mark.parametrize(
    "updates,store",
    [
        # another variable reads the index
        (
            [("setvar", 1, ("add", 1, ("var", 1))), ("setvar", 2, ("var", 1))],
            ("store", 256, 0, ("var", 1), ("var", 1)),
        ),
        # the index moves by something else than an addition
        ([("setvar", 1, ("mul", 2, ("var", 1)))], ("store", 256, 0, ("var", 1), ("var", 1))),
    ],
)
def test_a_loop_index_moved_in_other_ways_is_left_alone(updates, store):
    trace = _index_loop(updates, store)
    assert propagate_storage_in_loops(trace) == trace


def test_a_loop_index_with_a_changing_base_is_left_alone():
    # keccak(v2) with v2 changed by the loop: not one value for the loop
    trace = _index_loop([("setvar", 1, ("add", 1, ("var", 1))), ("setvar", 2, ("add", 1, ("var", 2)))])
    loop = trace[0]
    trace[0] = loop[:4] + ([("setvar", 1, ("add", 5, ("sha3", ("var", 2)))), ("setvar", 2, 0)],)
    assert propagate_storage_in_loops(trace) == trace


@pytest.mark.parametrize("fx", ["StorageShapes", "StorageShapesNoopt", "StorageShapesLegacy"])
def test_push_of_a_two_word_element(fx):
    """pairs.push([x, y]) on a uint256[2][] (slot 8): the copy loop writes the
    element at keccak(8) + 2 * length, the loop that clears the rest of the
    element starts where the copy stopped (unoptimized code)."""
    base = int.from_bytes(keccak(word(8)), "big")
    n = 3
    ok, out, m = run(fx, "pushPair(uint256,uint256)", [5, 7], storage={8: n, base + 2 * n: 1, base + 2 * n + 1: 2})
    assert ok and m.storage == {8: n + 1, base + 2 * n: 5, base + 2 * n + 1: 7}

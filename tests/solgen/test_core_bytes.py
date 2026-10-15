"""
Byte strings of symbolic length read back as words or cut to a width: the
engine's `bytes W mask_shl(size, off, shl, X)` and `bytes W X` for a slice
or a concatenation X longer than a word or of symbolic length (memory a
copy of calldata, return data or code wrote, read back across its ends).
The lifter keeps every bit of X (ir.MaskBytes, the `_maskBytes` helper),
and leaves the mask out when it provably keeps all of X; the generated code
behaves like the original on every call, named or routed.
"""

from __future__ import annotations

import random
import re

import pytest
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode

import callprobe
from conftest import compile_or_fail, solc_or_skip
from probes import (Build, compile_probe, function_text, generate_probe, patch_signatures, probe_calls, run_calls,
                    selector)
from scobelix.solgen import ir, render

W = 1 << 256
X = ir.CalldataWord(ir.Const(0))
Y = ir.CalldataWord(ir.Const(32))
L = ir.CalldataWord(ir.Op("add", (ir.Const(4), ir.CalldataWord(ir.Const(4)))))  # a length word


def mask(size, off, shl, v):
    return ir.Mask(size, off, shl, v)


def add(*a):
    return ir.Op("add", tuple(a))


def mul(*a):
    return ir.Op("mul", tuple(a))


MINUS = ir.Const(W - 1)
CEIL = mask(246, 5, 0, add(ir.Const(31), L))  # ceil32(L) as the engine writes it
# the fields of a read that keeps all of a copy of L bytes, as the engine writes them
SIZE = mask(253, 0, 3, L)
OFFSET = add(mask(246, 5, 3, add(ir.Const(31), L)), mul(MINUS, mask(253, 0, 3, L)),
             mul(MINUS, mask(253, 0, 3, add(CEIL, mul(MINUS, L)))))
SHL = add(mul(MINUS, mask(246, 5, 3, add(ir.Const(31), L))), mask(253, 0, 3, L),
          mask(253, 0, 3, add(CEIL, mul(MINUS, L))))


# ---------------------------------------------------------------- linear forms


def test_linear_forms_prove_the_engine_identities():
    assert ir.same_value(SIZE, mul(ir.Const(8), L))
    assert ir.same_value(OFFSET, 0) and ir.same_value(SHL, 0)
    assert ir.same_value(mask(255, 0, 1, L), add(L, L))
    assert ir.same_value(mul(ir.Const(8), CEIL), mask(246, 5, 3, add(ir.Const(31), L)))
    # not identities: the high bits of L matter
    assert not ir.same_value(mask(253, 0, 0, L), L)
    assert not ir.same_value(mask(252, 0, 3, L), mul(ir.Const(8), L))
    assert not ir.same_value(mask(253, 0, 3, L), mul(ir.Const(4), L))
    data = ir.CalldataSlice(add(ir.Const(36), ir.CalldataWord(ir.Const(4))), L)
    assert ir.mask_bytes(SIZE, OFFSET, SHL, data, L) == data
    assert ir.mask_bytes(None, 0, 0, data, L) == data
    assert isinstance(ir.mask_bytes(SIZE, OFFSET, SHL, data, add(L, ir.Const(1))), ir.MaskBytes)
    assert isinstance(ir.mask_bytes(mask(253, 0, 0, L), OFFSET, SHL, data, L), ir.MaskBytes)
    assert isinstance(ir.mask_bytes(SIZE, ir.Const(8), SHL, data, L), ir.MaskBytes)


def _random_word(rng, depth):
    if depth == 0 or rng.random() < 0.25:
        if rng.random() < 0.7:
            return rng.choice([X, Y])
        return ir.const(rng.choice([0, 1, 7, 31, 32, W - 1, W - 32, 1 << 255, rng.getrandbits(256)]))
    a = _random_word(rng, depth - 1)
    k = rng.randrange(6)
    if k == 0:
        return add(a, _random_word(rng, depth - 1))
    if k == 1:
        return ir.Op("sub", (a, _random_word(rng, depth - 1)))
    if k == 2:
        return mul(ir.const(rng.choice([2, 3, 8, 32, W - 1, W - 8, 1 << 250])), a)
    if k == 3:
        return ir.Op("shl", (ir.const(rng.choice([1, 3, 5, 8, 255, 256, 300])), a))
    if k == 4:
        return mul(a, _random_word(rng, depth - 1))  # a product of two words: an atom
    return mask(rng.choice([1, 3, 8, 64, 246, 251, 253, 255, 256, 300]), rng.choice([0, 0, 3, 5, 8, 100]),
                rng.choice([0, 0, 1, 3, 5, 8, 200, -3, -8]), a)


def _at(e, env):
    return ir.evaluate(ir.transform(e, lambda n: ir.Const(env[n]) if n in env else n))


def test_linear_forms_are_identities():
    """A form is worth its word for every value of the atoms (a form that
    assumed an equality would differ somewhere)."""
    rng = random.Random(5)
    for _ in range(500):
        e = _random_word(rng, 4)
        terms, const = ir.linear(e)
        for _ in range(4):
            env = {X: rng.getrandbits(256) >> rng.choice([0, 0, 200, 250]), Y: rng.getrandbits(256)}
            value = (const + sum(k * _at(atom, env) for atom, k in terms)) % W
            assert value == _at(e, env), e


# ---------------------------------------------------------------- reference semantics


def _naive(data: bytes, size, offset: int, shl: int, n: int) -> bytes:
    """MaskBytes bit by bit (size None: 2**255 - 1)."""
    x = int.from_bytes(data, "big")
    size = (1 << 255) - 1 if size is None else size
    out = 0
    for j in range(8 * n):
        k = j - shl
        if 0 <= k < 8 * len(data) and offset <= k < offset + size:
            out |= ((x >> k) & 1) << j
    return out.to_bytes(n, "big")


SIZES = [None, -8, 0, 1, 7, 8, 13, 64, 200, 320, 1000, (1 << 255) - 1]
OFFSETS = [-300, -9, -8, 0, 0, 3, 8, 16, 100, 320]
SHIFTS = [-320, -16, -9, -8, -3, 0, 0, 3, 8, 16, 100, 384]


def _case(rng):
    data = bytes(rng.getrandbits(8) for _ in range(rng.choice([0, 1, 5, 31, 32, 33, 40])))
    return data, rng.choice(SIZES), rng.choice(OFFSETS), rng.choice(SHIFTS), rng.choice([0, 1, 4, 32, 33, 48])


def test_reference_semantics_bit_by_bit():
    rng = random.Random(9)
    for _ in range(1500):
        case = _case(rng)
        assert ir.mask_bytes_value(*case) == _naive(*case), case
    data = bytes(range(1, 41))
    assert ir.mask_bytes_value(data, None, 0, 0, 40) == data
    assert ir.mask_bytes_value(data, None, 0, 0, 44) == bytes(4) + data
    assert ir.mask_bytes_value(data, 8 * 40, 0, 0, 8) == data[-8:]
    assert ir.mask_bytes_value(data, 16, 8, -8, 2) == data[-3:-1]
    node = ir.MaskBytes(16, 8, -8, ir.ConstBytes(data), ir.Const(2))
    assert ir.const_bytes(node) == data[-3:-1] and ir.byte_length(node) == ir.Const(2)


HELPER_PROBE = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract MaskBytesProbe {
    function run(bytes memory x, uint256 size, uint256 offset, uint256 shift, uint256 n)
        external pure returns (bytes memory)
    {
        return _maskBytes(x, size, offset, shift, n);
    }

%s
}
"""


def _helper_probe() -> bytes:
    h = render.Helpers()
    h.use("_maskBytes")
    body = "\n\n".join("\n".join("    " + line for line in src.split("\n")) for src in h.sources())
    return compile_or_fail(HELPER_PROBE % body, "0.8.19", name="MaskBytesProbe").runtime


def _run_helper(runtime, cases):
    sel = selector("run(bytes,uint256,uint256,uint256,uint256)")
    calls = []
    for data, size, off, shl, n in cases:
        s = W // 2 - 1 if size is None else size  # how the renderer writes "every bit"
        calls.append((sel + abi_encode(["bytes", "uint256", "uint256", "uint256", "uint256"],
                                       [data, s % W, off % W, shl % W, n]), 0))
    return run_calls(runtime, calls)


def test_the_helper_is_the_reference_semantics():
    runtime = _helper_probe()
    rng = random.Random(7)
    cases = [_case(rng) for _ in range(160)]
    # byte-aligned fields: the copy path
    cases += [(bytes(range(200)), s, o, h, n) for s, o, h, n in
              [(8 * 200, 0, 0, 200), (8 * 64, 8 * 100, -8 * 100, 64), (8 * 64, 8 * 100, -8 * 90, 80),
               (8 * 64, -8 * 3, 8 * 5, 100), (None, 0, 0, 230), (None, 0, 8 * 33, 70), (None, 0, -8 * 150, 60)]]
    for (ok, out, _), case in zip(_run_helper(runtime, cases), cases):
        assert ok, case
        assert abi_decode(["bytes"], out)[0] == ir.mask_bytes_value(*case), case
    # a width no gas could pay for halts, like the copy of the original
    [(ok, _, _)] = _run_helper(runtime, [(b"\x01", 8, 0, 0, 1 << 33)])
    assert not ok


# ---------------------------------------------------------------- generated code


COPIES = """
contract Copies {
    event Data(bytes data);

    function twice(bytes calldata a) external pure returns (bytes memory) {
        return abi.encodePacked(a, a);
    }

    function copyWords(bytes memory src) public pure returns (bytes memory dst) {
        assembly {
            let n := mload(src)
            dst := mload(0x40)
            mstore(dst, n)
            for { let i := 0 } lt(i, n) { i := add(i, 0x20) } {
                mstore(add(add(dst, 0x20), i), mload(add(add(src, 0x20), i)))
            }
            mstore(0x40, add(add(dst, 0x20), and(add(n, 31), not(31))))
        }
    }

    function tagged(bytes calldata a, uint256 t) external pure returns (bytes memory) {
        return abi.encodePacked(a, t);
    }

    function digest(bytes calldata a, bytes calldata b) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }

    function note(bytes calldata a) external {
        emit Data(abi.encodePacked(a, a));
    }

    function wrapped(bytes memory a) public pure returns (bytes memory) {
        return abi.encode(a, uint256(7), a);
    }

    function across(bytes calldata a) external pure returns (bytes32 w) {
        bytes memory m = abi.encodePacked(a, a);
        assembly { w := mload(add(m, 45)) }
    }
}
"""

RELAY = """
contract Relay {
    function forward(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "call failed");
        return ret;
    }

    function bubble(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) {
            assembly { revert(add(ret, 32), mload(ret)) }
        }
        return ret;
    }

    function relay(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = address(this).call(abi.encodePacked(data, msg.sender));
        if (!ok) {
            assembly { revert(add(ret, 32), mload(ret)) }
        }
        return ret;
    }

    function twice(bytes calldata a) external pure returns (bytes memory) {
        return abi.encodePacked(a, a);
    }
}
"""

MAKER = """
contract Child {
    string public name;

    constructor(string memory n) {
        name = n;
    }
}

contract Holder {
    address public first;
    address public second;
    bytes public blob;

    constructor(address a, address b, bytes memory d) {
        first = a;
        second = b;
        blob = d;
    }
}

contract Maker {
    function make(string calldata n) external returns (address) {
        return address(new Child(n));
    }

    function hold(address a, bytes memory d) public returns (address) {
        return address(new Holder(a, msg.sender, d));
    }
}
"""

PROBES = {"Copies": COPIES, "Relay": RELAY, "Maker": MAKER}
ANSWERS = {"Copies": ("true",), "Maker": ("true",),
           "Relay": ("true", "empty", "short", "long", "revert-empty", "revert-error", "revert-huge", "invalid")}


def _payloads(rng):
    return [bytes(rng.getrandbits(8) for _ in range(n)) for n in (0, 1, 5, 31, 32, 33, 63, 64, 65, 100, 200)]


def explicit_calls(name):
    rng = random.Random(len(name))
    c = callprobe.call
    out = []
    for d in _payloads(rng):
        if name == "Copies":
            out += [c("twice(bytes)", d), c("copyWords(bytes)", d), c("tagged(bytes,uint256)", d, rng.getrandbits(256)),
                    c("digest(bytes,bytes)", d, d[::-1] + b"x"), c("note(bytes)", d), c("wrapped(bytes)", d),
                    c("across(bytes)", d)]
        elif name == "Relay":
            inner = c("twice(bytes)", d)
            out += [c("forward(address,bytes)", callprobe.ECHO, d), c("bubble(address,bytes)", callprobe.ECHO, d),
                    c("relay(bytes)", inner), c("relay(bytes)", d), c("forward(address,bytes)", callprobe.EOA, d)]
        else:
            out += [c("make(string)", d.hex()), c("hold(address,bytes)", callprobe.EOA, d)]
    return [(x, 0) for x in out]


def compiled(source: str, target: str) -> bytes:
    """The runtime of the generated text, compiled as the verification does:
    the legacy pipeline, the IR one when the legacy one runs out of stack."""
    from scobelix.verify.solc import CompilationError, Settings, compile_standard_json, execution_evm_version

    path = solc_or_skip(target)
    try:
        comp = compile_standard_json(source, Settings(evm_version=execution_evm_version(target)), version=target,
                                     solc_path=path)
    except CompilationError as e:
        if "Stack too deep" not in "\n".join(e.messages):
            pytest.fail("\n".join(e.messages[:3]))
        comp = compile_standard_json(source, Settings(optimize=True, via_ir=True, evm_version=execution_evm_version(target)),
                                     version=target, solc_path=path)
    return comp.artifact("Decompiled").runtime


def check(monkeypatch, name, build, routed=False):
    art = compile_probe(PROBES[name], build, name)
    patch_signatures(monkeypatch, [] if routed else art.abi)
    res = generate_probe(art.runtime)
    calls = explicit_calls(name)
    if not routed:
        crafted, skipped = probe_calls(res)
        assert not skipped, skipped
        calls += crafted
    runtime = compiled(res.solidity, res.target_solc)
    mism = []
    for answer in ANSWERS[name]:
        echo = callprobe.ANSWERS[answer]
        for data, value in calls:
            a = callprobe.outcome(art.runtime, data, value, echo)
            b = callprobe.outcome(runtime, data, value, echo)
            if a != b:
                mism.append((data.hex(), value, answer, a, b))
    assert not mism, (name, build.label, routed, len(mism), mism[:2])
    flagged = {k: f["flags"] for k, f in res.functions.items() if "unstructured" in f["flags"]}
    assert not flagged and "_unsupported" not in res.solidity, flagged
    return res


def test_copies_of_symbolic_length(monkeypatch):
    res = check(monkeypatch, "Copies", Build("0.8.19"))
    text = res.solidity
    # the reads keep the copy whole: the parameter itself, no mask helper, no copy of the calldata
    for name, param in (("twice", "a"), ("copyWords", "src"), ("wrapped", "a")):
        body = function_text(text, name)
        returned = [line for line in body.split("\n") if "_return(" in line]
        assert returned and all(re.search(rf"[(,] ?{param}[,)]", line) for line in returned), (name, returned)
        assert "_maskBytes" not in body and "_calldata(" not in body, name


BUILDS = [Build("0.8.19", optimize=False), Build("0.8.19", via_ir=True), Build("0.8.31"), Build("0.8.31", via_ir=True)]


@pytest.mark.slow
@pytest.mark.parametrize("build", BUILDS + [Build("0.7.6"), Build("0.7.6", optimize=False), Build("0.5.17")],
                         ids=lambda b: b.label)
def test_copies_other_builds(monkeypatch, build):
    check(monkeypatch, "Copies", build)


@pytest.mark.slow
@pytest.mark.parametrize("build", [Build("0.8.19")] + BUILDS, ids=lambda b: b.label)
@pytest.mark.parametrize("name", ["Relay", "Maker"])
def test_return_data_and_constructor_arguments(monkeypatch, name, build):
    check(monkeypatch, name, build)


@pytest.mark.slow
@pytest.mark.parametrize("build", [Build("0.8.19"), Build("0.8.19", optimize=False)], ids=lambda b: b.label)
@pytest.mark.parametrize("name", ["Copies", "Relay", "Maker"])
def test_routed(monkeypatch, name, build):
    check(monkeypatch, name, build, routed=True)

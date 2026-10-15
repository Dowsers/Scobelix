"""
The engine's trace shapes, end to end on hand-written sources: the
exact output copy of a call (`min(L, returndatasize)` bytes, the rest of
the buffer kept), read snapshots split by field, the loop structurer's
require with its revert or invalid line, loop variables after the loop.

Each source is compiled, decompiled, generated at the exact and the full
level and checked against the original: the lifted shapes, scobelix.verify
L0-L3, and direct differential calls with callees that return fewer bytes
than the output buffer (which the verifier's mocks need not try).
"""

import functools
import logging

import pytest

from conftest import backend_or_skip, compile_or_fail, decompiled
from scobelix.solgen import ir, lift, sigs
from scobelix.solgen.v2 import generate

SHAPES = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Shapes {
    struct Pair { uint160 a; uint96 b; }
    Pair public pair;
    uint256 public x;

    // the callee may return fewer bytes than the output buffer holds: the
    // rest of the buffer keeps its value
    function outBuf(address t) external returns (uint256 w0, uint256 w1) {
        assembly {
            mstore(0x80, 0xaaaa)
            mstore(0xa0, 0xbbbb)
            mstore(0, shl(224, 0x33333333))
            pop(call(gas(), t, 0, 0, 4, 0x80, 64))
            w0 := mload(0x80)
            w1 := mload(0xa0)
        }
    }

    function outBufStatic(address t) external view returns (uint256 w0, uint256 w1) {
        assembly {
            mstore(0x80, 0xcccc)
            mstore(0xa0, 0xdddd)
            pop(staticcall(gas(), t, 0, 0, 0x80, 40))
            w0 := mload(0x80)
            w1 := mload(0xa0)
        }
    }

    // one storage word read for two fields before a call that may change it
    function fieldsAcrossCall(address t) external returns (uint160, uint96) {
        uint160 a = pair.a;
        uint96 b = pair.b;
        (bool ok, ) = t.call("");
        require(ok);
        return (a, b);
    }

    function setPair(uint160 a, uint96 b) external {
        pair = Pair(a, b);
    }

    function sumBelow(uint256 n) external pure returns (uint256 t) {
        for (uint256 i = 0; i < n; i++) {
            t += i;
        }
    }
}

// returns the first `n` bytes of a pattern (n: its storage slot 0)
contract Callee {
    uint256 public n;

    fallback() external payable {
        assembly {
            mstore(0, 0x1111111111111111111111111111111111111111111111111111111111111111)
            mstore(32, 0x2222222222222222222222222222222222222222222222222222222222222222)
            mstore(64, 0x3333333333333333333333333333333333333333333333333333333333333333)
            return(0, sload(0))
        }
    }
}
"""

# assert() is INVALID before 0.8: the structurer's require carries an invalid line
OLD = """
pragma solidity ^0.7.6;

contract OldCapped {
    function capped(uint256 n) external pure returns (uint256 i) {
        while (true) {
            assert(i < 50);
            if (i >= n) break;
            i++;
        }
    }
}
"""

# a memory array handed back: the engine writes its ABI tail as one node (the
# element count and a slice of 32 bytes per element, which takes no padding)
ARRAYS = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Arrays {
    function echo(uint256[] memory xs) public pure returns (uint256[] memory) {
        return xs;
    }
}
"""

CALLER, ORIGINAL, GENERATED, CALLEE = ("0x" + "a1" * 20, "0x" + "0e" * 20, "0x" + "6e" * 20, "0x" + "ca" * 20)
SOURCES = {"Shapes": (SHAPES, "0.8.19"), "OldCapped": (OLD, "0.7.6"), "Arrays": (ARRAYS, "0.8.19")}


@functools.lru_cache(maxsize=None)
def _built(name):
    """(runtime bytes, decompilation) of a probe contract."""
    from scobelix.decompiler import decompile_bytecode

    src, version = SOURCES[name]
    runtime = compile_or_fail(src, version, name).runtime
    logging.disable(logging.CRITICAL)
    try:
        return runtime, decompile_bytecode(runtime.hex())
    finally:
        logging.disable(logging.NOTSET)


@functools.lru_cache(maxsize=None)
def _generated(name, level):
    return generate(_built(name)[1], idiom_level=level)


def _lifted(name, key):
    runtime, d = _built(name)
    return lift.lift_function(key, d.functions[key].orig_trace, lift.make_context(runtime))


def _key(signature):
    return f"0x{sigs.function_selector(signature):08x}"


def _calldata(signature, *words):
    return sigs.function_selector(signature).to_bytes(4, "big") + b"".join((w % 2**256).to_bytes(32, "big")
                                                                         for w in words)


# ---------------------------------------------------------------- the lifted shapes


def test_output_copy_is_lifted_as_a_bounded_return_data_write():
    for sig, width in (("outBuf(address)", 64), ("outBufStatic(address)", 40)):
        fn = _lifted("Shapes", _key(sig))
        copies = [s for s in ir.walk_all(fn.body) if isinstance(s, ir.Mstore) and isinstance(s.data, ir.ReturnData)]
        assert len(copies) == 1, sig
        (copy,) = copies
        rds = ir.CallOut(copy.data.call_id, "returndatasize")
        assert copy.addr == ir.Const(128) and copy.data.start == ir.ZERO
        assert copy.data.length == ir.Ternary(ir.Op("lt", (rds, ir.Const(width))), rds, ir.Const(width))
        assert not fn.flags, sig


def test_split_snapshots_are_lifted_as_locals():
    fn = _lifted("Shapes", _key("fieldsAcrossCall(address)"))
    assigns = {s.target.name: s.value for s in ir.walk_all(fn.body) if isinstance(s, ir.Assign)}
    assert assigns == {"t1_160_96": ir.Field(ir.Sload(ir.ZERO), 160, 96),
                       "t1_0_160": ir.Field(ir.Sload(ir.ZERO), 0, 160)}
    rets = [s for s in ir.walk_all(fn.body) if isinstance(s, ir.Return)]
    assert rets and all([p.value for p in r.data.parts] == [ir.Local("t1_0_160"), ir.Local("t1_160_96")] for r in rets)
    assert not fn.flags


def test_invalid_require_line_is_lifted_as_its_branch():
    fn = _lifted("OldCapped", _key("capped(uint256)"))
    branches = [s for s in ir.walk_all(fn.body) if isinstance(s, ir.If) and s.orelse == (ir.Invalid(""),)]
    assert len(branches) == 2  # before the loop and in its body
    assert not ir.contains(fn.body, ir.Require)
    assert not fn.flags  # no marker either: the line is lifted whole


def test_accumulator_is_a_loop_variable():
    fn = _lifted("Shapes", _key("sumBelow(uint256)"))
    loops = [s for s in ir.walk_all(fn.body) if isinstance(s, ir.While)]
    assert len(loops) == 1
    targets = {a.target for a in loops[0].init}
    rets = [s for s in ir.walk_all(fn.body) if isinstance(s, ir.Return)]
    assert rets and all(r.data.value in targets for r in rets)  # the exit value of the accumulator
    assert not fn.flags


def test_fixtures_carry_no_engine_flags():
    for name in ("TimeDependence", "TimeDependenceNoopt", "LoopShapes", "LoopShapesNoopt", "TransientSwap", "SumLoop"):
        r = generate(decompiled(name))
        flagged = {k: f["flags"] for k, f in r.functions.items() if f["flags"]}
        assert not flagged, (name, flagged)


# ---------------------------------------------------------------- differential execution


@pytest.mark.parametrize("level", ["exact", "full"])
def test_output_copy_keeps_the_rest_of_the_buffer(level):
    backend = backend_or_skip()
    from scobelix.verify.evm import make_world

    original, _ = _built("Shapes")
    r = _generated("Shapes", level)
    generated = compile_or_fail(r.solidity, r.target_solc).runtime
    callee = compile_or_fail(SHAPES, "0.8.19", "Callee").runtime
    seen = set()
    for sig in ("outBuf(address)", "outBufStatic(address)"):
        for n in (0, 4, 40, 64, 96):
            outs = []
            for addr, code in ((ORIGINAL, original), (GENERATED, generated)):
                world = make_world(backend)
                world.set_code(addr, code)
                world.set_code(CALLEE, callee)
                world.set_storage(CALLEE, 0, n)
                res = world.call(CALLER, addr, _calldata(sig, int(CALLEE, 16)))
                outs.append((res.success, res.output))
            assert outs[0] == outs[1], (sig, n, outs)
            assert outs[0][0] and len(outs[0][1]) == 64
            seen.add(outs[0][1])
    # a short return keeps the old words: 4 distinct outputs for the 64-byte
    # buffer (0, 4, 40, >= 64 bytes returned), 3 for the 40-byte one
    assert len(seen) == 7
    world = make_world(backend)
    world.set_code(ORIGINAL, original)
    world.set_code(CALLEE, callee)
    res = world.call(CALLER, ORIGINAL, _calldata("outBuf(address)", int(CALLEE, 16)))
    assert res.output == (0xAAAA).to_bytes(32, "big") + (0xBBBB).to_bytes(32, "big")


@pytest.mark.parametrize("level", ["exact", "full"])
def test_snapshots_hold_the_value_read_before_the_call(level):
    backend = backend_or_skip()
    from scobelix.verify.evm import make_world

    original, _ = _built("Shapes")
    r = _generated("Shapes", level)
    generated = compile_or_fail(r.solidity, r.target_solc).runtime
    # a callee that writes the pair back (re-entrancy) before the read values are returned
    relay = compile_or_fail(SHAPES, "0.8.19", "Callee").runtime
    word = (7 << 160) | 12345
    for addr, code in ((ORIGINAL, original), (GENERATED, generated)):
        world = make_world(backend)
        world.set_code(addr, code)
        world.set_code(CALLEE, relay)
        world.set_storage(addr, 0, word)
        res = world.call(CALLER, addr, _calldata("fieldsAcrossCall(address)", int(CALLEE, 16)))
        assert res.success and res.output == (12345).to_bytes(32, "big") + (7).to_bytes(32, "big"), (addr, res)


@pytest.mark.parametrize("level", ["exact", "full"])
def test_a_returned_word_array_takes_no_padding(level):
    backend = backend_or_skip()
    from scobelix.verify.evm import make_world

    original, _ = _built("Arrays")
    r = _generated("Arrays", level)
    generated = compile_or_fail(r.solidity, r.target_solc).runtime
    for n in (0, 1, 2, 31, 32, 33):
        data = _calldata("echo(uint256[])", 32, n, *range(1, n + 1))
        outs = []
        for addr, code in ((ORIGINAL, original), (GENERATED, generated)):
            world = make_world(backend)
            world.set_code(addr, code)
            res = world.call(CALLER, addr, data)
            outs.append((res.success, res.output))
        assert outs[0] == outs[1], (n, outs)
        assert outs[0][0] and len(outs[0][1]) == 64 + 32 * n  # offset, count, elements: nothing after them


@pytest.mark.parametrize("name, level", [(n, lvl) for n in SOURCES for lvl in ("exact", "full")])
def test_l3_equivalent_on_the_shape_sources(name, level):
    backend_or_skip()
    from scobelix.verify import Budget, verify

    original, _ = _built(name)
    r = _generated(name, level)
    report = verify(original.hex(), r.solidity, contract_name=r.contract_name, abi_hint=r.abi_hint,
                    solc_version=r.target_solc, levels=("L0", "L1", "L3"), budget=Budget.quick(),
                    routed_selectors=r.routed_selectors)
    assert report.levels["L0"].status == "pass", report.levels["L0"].details
    assert report.levels["L1"].status == "pass", report.levels["L1"].reason
    bad = {k: (f.verdict, f.reason) for k, f in report.functions.items()
           if f.verdict not in ("EQUIVALENT", "EQUIVALENT_REVERTS_ONLY")}
    assert report.levels["L3"].status == "pass" and not bad, (report.levels["L3"].reason, bad)

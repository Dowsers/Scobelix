"""
The calls pass: differential tests on real compiler builds.  A probe making
every kind of call (high-level calls with and without return values, view
calls, calls with value and gas, several calls in one expression, send,
transfer, low-level calls) is compiled, decompiled and generated again; the
original and the text then run against callees that answer in every way
(true / false / dirty words, short / long / empty answers, every kind of
revert data, a callee halting, an account without code, a precompile),
and must behave identically: success, return and revert data, logs (the
recorder makes the calls' targets, values and calldata part of them),
storage and balances.  The builds where the compiler's scaffolding differs
(0.7.6 and 0.5.17 check the callee's code before every call, ABI coder v1
has no validators; the IR pipeline) are covered by the slow tests.
"""

from __future__ import annotations

import pytest

import callprobe as cp
from callprobe import ANSWERS, CALLER, ECHO, EOA, IDENTITY, Case, call
from probes import Build
from scobelix.solgen import ir
from scobelix.solgen.pipeline import PASS_ORDER
from scobelix.verify.mocks import ACCEPTING_CALLER, REJECTING_CALLER

PROBE = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IPair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IWETH {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

interface IMisc {
    function small() external view returns (uint8, int16, bytes4);
    function who() external view returns (address);
    function flag() external view returns (bool);
    function poke(uint256 x) external;
}

contract CallProbe {
    uint256 public last;

    function doTransfer(address token, address to, uint256 amt) external {
        require(IERC20(token).transfer(to, amt), "transfer failed");
    }

    function doTransferFrom(address token, address from, address to, uint256 amt) external returns (bool) {
        return IERC20(token).transferFrom(from, to, amt);
    }

    function bal(address token, address who) external view returns (uint256) {
        return IERC20(token).balanceOf(who);
    }

    function twoBalances(address a, address b) external view returns (uint256) {
        return IERC20(a).balanceOf(msg.sender) + IERC20(b).balanceOf(msg.sender);
    }

    function reserves(address pair) external view returns (uint256) {
        (uint112 r0, uint112 r1, ) = IPair(pair).getReserves();
        return uint256(r0) + uint256(r1);
    }

    function small(address t) external view returns (uint256) {
        (uint8 a, int16 b, bytes4 c) = IMisc(t).small();
        return uint256(a) + uint256(int256(b)) + uint256(uint32(c));
    }

    function who(address t) external view returns (address) {
        return IMisc(t).who();
    }

    function flag(address t) external view returns (bool) {
        return IMisc(t).flag();
    }

    function poke(address t, uint256 x) external {
        IMisc(t).poke(x);
        last = x;
    }

    function pokeGas(address t, uint256 x, uint256 g) external {
        IMisc(t).poke{GAS}(x);
    }

    function wrap(address weth) external payable {
        IWETH(weth).deposit{VALUE}();
    }

    function unwrap(address weth, uint256 amt) external {
        IWETH(weth).withdraw(amt);
    }

    function sendEth(address payable to, uint256 v) external returns (bool) {
        return to.send(v);
    }

    function transferEth(address payable to, uint256 v) external {
        to.transfer(v);
    }

    function callEth(address to, uint256 v) external {
        (bool ok, ) = to.call{CALLVALUE}("");
        require(ok, "eth");
    }

    function rawCall(address t, bytes calldata payload) external returns (bytes memory) {
        (bool ok, bytes memory r) = t.call(payload);
        require(ok);
        return r;
    }
}
"""


def source(build: Build) -> str:
    """The probe in the call-option syntax of the build."""
    if build.major >= (0, 7) or build.version >= "0.6.2":
        return PROBE.replace("{GAS}", "{gas: g}").replace("{VALUE}", "{value: msg.value}").replace(
            "{CALLVALUE}", "{value: v}")
    return (PROBE.replace(".poke{GAS}(x)", ".poke.gas(g)(x)").replace(".deposit{VALUE}()", ".deposit.value(msg.value)()")
            .replace("to.call{CALLVALUE}(\"\")", "to.call.value(v)(\"\")"))


ADDR = int("a1" * 20, 16)
BOOL_ANSWERS = ("true", "false", "dirty-bool", "empty", "short", "long", "revert-empty", "revert-error",
                "revert-custom", "revert-panic", "revert-huge", "invalid")
WORD_ANSWERS = ("hash", "max", "three", "three-dirty", "three-dirty-last", "address", "empty", "short", "long",
                "revert-error", "invalid")
NO_RETURN_ANSWERS = ("true", "empty", "revert-empty", "revert-error", "revert-huge", "invalid")
TRANSFER = cp.word(5)


def cases():
    # callees: the configurable Echo, an account without code, the identity precompile
    callees = (ECHO, EOA, IDENTITY)
    out = [
        Case("doTransfer", tuple((call("doTransfer(address,address,uint256)", c, CALLER, 5), 0) for c in callees)
             + ((call("doTransfer(address,address,uint256)", ECHO, CALLER, 2**255), 0),), BOOL_ANSWERS),
        Case("doTransferFrom", tuple((call("doTransferFrom(address,address,address,uint256)", c, CALLER, ECHO, 7), 0)
                                     for c in callees), BOOL_ANSWERS),
        Case("bal", tuple((call("bal(address,address)", c, w), 0) for c in callees for w in (CALLER, ECHO)),
             WORD_ANSWERS),
        Case("twoBalances", ((call("twoBalances(address,address)", ECHO, ECHO), 0),
                             (call("twoBalances(address,address)", ECHO, EOA), 0),
                             (call("twoBalances(address,address)", IDENTITY, ECHO), 0)), WORD_ANSWERS),
        Case("reserves", tuple((call("reserves(address)", c), 0) for c in callees), WORD_ANSWERS),
        Case("small", tuple((call("small(address)", c), 0) for c in callees), WORD_ANSWERS),
        Case("who", tuple((call("who(address)", c), 0) for c in callees), WORD_ANSWERS),
        Case("flag", tuple((call("flag(address)", c), 0) for c in callees), BOOL_ANSWERS),
        Case("poke", tuple((call("poke(address,uint256)", c, 3), 0) for c in callees), NO_RETURN_ANSWERS),
        Case("pokeGas", tuple((call("pokeGas(address,uint256,uint256)", c, 3, g), 0) for c in callees
                              for g in (0, 30000, 2**255)), NO_RETURN_ANSWERS),
        Case("wrap", tuple((call("wrap(address)", c), v) for c in callees for v in (0, 9)), NO_RETURN_ANSWERS),
        Case("unwrap", tuple((call("unwrap(address,uint256)", c, 4), 0) for c in callees), NO_RETURN_ANSWERS),
        Case("sendEth", tuple((call("sendEth(address,uint256)", c, v), 0)
                              for c in (EOA, ECHO, ACCEPTING_CALLER, REJECTING_CALLER, IDENTITY)
                              for v in (0, 3, 10**19)), ("true",)),
        Case("transferEth", tuple((call("transferEth(address,uint256)", c, v), 0)
                                  for c in (EOA, ECHO, ACCEPTING_CALLER, REJECTING_CALLER)
                                  for v in (0, 3, 10**19)), ("true",)),
        Case("callEth", tuple((call("callEth(address,uint256)", c, v), 0)
                              for c in (EOA, ECHO, REJECTING_CALLER) for v in (0, 3, 10**19)),
             ("true", "revert-error", "invalid")),
        Case("rawCall", tuple((call("rawCall(address,bytes)", c, p), 0) for c in (ECHO, EOA)
                              for p in (b"", call("transfer(address,uint256)", CALLER, 1))),
             ("true", "long", "revert-error", "invalid")),
    ]
    # dirty address bits and short calldata
    out.append(Case("dirty", ((call("bal(address,address)", ECHO, CALLER)[:-1], 0),
                              (call("doTransfer(address,address,uint256)", ECHO, CALLER, 1)[:4]
                               + cp.word((1 << 160) | int(ECHO, 16)) + cp.word(ADDR) + cp.word(1), 0)),
                    ("true",)))
    return out


def run_probe(build: Build, monkeypatch, off=(), answers_limit=None):
    comp = cp.compile_all(source(build), build)
    art = comp.artifact("CallProbe")
    cp.patch_lookups(monkeypatch, [a.abi for a in comp.artifacts.values()])
    result = cp.generate(art.runtime, off)
    # a function the decompiler could not translate reverts by design (flag unstructured)
    untranslated = {f["signature"].split("(")[0] for f in result.functions.values()
                    if f.get("signature") and "unstructured" in f["flags"]}
    diffs = []
    for case in cases():
        if case.name in untranslated:
            continue
        answers = case.answers if answers_limit is None else case.answers[:answers_limit]
        diffs += cp.differential(art.runtime, result.solidity, result.target_solc, case.calls, answers)
    return result, diffs


def _show(diffs):
    return "\n".join(f"{d[0][:72]} value={d[1]} answer={d[2]}\n  original {str(d[3])[:400]}\n  text     "
                     f"{str(d[4])[:400]}" for d in diffs[:4])


def test_calls_0819_opt(monkeypatch):
    build = Build("0.8.19")
    result, diffs = run_probe(build, monkeypatch)
    assert not diffs, _show(diffs)
    text = result.solidity
    # the forms the pass writes for this build
    for snippet in ("IERC20(token).transfer(to, amt)", "IERC20(token).balanceOf(who)",
                    ".getReserves()", ".deposit{value: msg.value}()", ".poke{gas: g}(x)",
                    "payable(to).send(v)", "payable(to).transfer(v)", "(bool success, ) = to.call{value: v}(\"\")",
                    "interface IERC20 {"):
        assert snippet in text, snippet
    assert "_bubble" not in text.split("contract Decompiled")[1].split("function rawCall")[0]
    assert all("calls" in f["passes"] for f in result.functions.values()
               if f.get("signature") and f["signature"].split("(")[0] in ("doTransfer", "bal", "sendEth"))


@pytest.mark.slow
def test_calls_pass_alone_and_switched_off(monkeypatch):
    """The pass works without the others, and its absence leaves the exact forms."""
    build = Build("0.8.19")
    others = [p for p in PASS_ORDER if p != "calls"]
    result, diffs = run_probe(build, monkeypatch, off=others, answers_limit=4)
    assert not diffs, _show(diffs)
    assert "IERC20(token).transfer(" in result.solidity or "IERC20(address(uint160(" in result.solidity
    result, diffs = run_probe(build, monkeypatch, off=["calls"], answers_limit=2)
    assert not diffs, _show(diffs)
    assert "interface " not in result.solidity and "bool c1_ok;" in result.solidity


@pytest.mark.slow
@pytest.mark.parametrize("build", [Build("0.8.19", optimize=False), Build("0.8.19", via_ir=True),
                                   Build("0.8.31", via_ir=True), Build("0.7.6"), Build("0.5.17"),
                                   Build("0.7.6", abicoder="v2")], ids=lambda b: b.label)
def test_calls_other_builds(build, monkeypatch):
    result, diffs = run_probe(build, monkeypatch)
    assert not diffs, _show(diffs)


PROXY = """
contract ProxyProbe {
    fallback() external payable {
        assembly {
            let impl := sload(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
"""
IMPLEMENTATION_SLOT = 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC


@pytest.mark.parametrize("build", [Build("0.8.19"), pytest.param(Build("0.8.19", via_ir=True),
                                                                  marks=pytest.mark.slow)], ids=lambda b: b.label)
def test_proxy_forwarder(build, monkeypatch):
    """The standard forwarder becomes the canonical assembly block, with the
    same calls, return data, revert data and storage writes (the Echo code
    runs in the proxy's storage)."""
    comp = cp.compile_all(PROXY, build)
    art = comp.artifact("ProxyProbe")
    cp.patch_lookups(monkeypatch, [])
    result = cp.generate(art.runtime)
    assert "delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)" in result.solidity
    calls = [(b"", 0), (b"\x01\x02\x03", 0), (call("transfer(address,uint256)", CALLER, 5), 0),
             (call("transfer(address,uint256)", CALLER, 5), 7)]
    diffs = []
    for impl in (ECHO, EOA):
        for name in ("true", "long", "revert-error", "revert-huge", "invalid", "hash"):
            storage = dict(ANSWERS[name])
            storage[IMPLEMENTATION_SLOT] = int(impl, 16)
            diffs += cp.differential(art.runtime, result.solidity, result.target_solc, calls, ("true",), storage)
    assert not diffs, _show(diffs)


HOOKED_PROXY = """
contract HookedProxy {
    fallback() external payable {
        assembly {
            if iszero(call(gas(), sload(7), 0, 0, 0, 0, 0)) { revert(0, 0) }
            let impl := sload(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
"""


def test_forwarder_after_a_low_level_call(monkeypatch):
    """The forwarder's assembly block declares its own success flag: it
    must not shadow the success flag of a low-level call made before it in
    the same scope (solc rejects the shadowing)."""
    comp = cp.compile_all(HOOKED_PROXY, Build("0.8.19"))
    art = comp.artifact("HookedProxy")
    cp.patch_lookups(monkeypatch, [])
    result = cp.generate(art.runtime)
    assert "delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)" in result.solidity
    calls = [(b"", 0), (call("transfer(address,uint256)", CALLER, 5), 0), (call("transfer(address,uint256)", CALLER, 5), 7)]
    diffs = []
    for name in ("true", "revert-error"):
        storage = dict(ANSWERS[name])
        storage[7] = int(ECHO, 16)
        storage[IMPLEMENTATION_SLOT] = int(ECHO, 16)
        diffs += cp.differential(art.runtime, result.solidity, result.target_solc, calls, ("true",), storage)
    assert not diffs, _show(diffs)


BUILTINS = """
contract BuiltinProbe {
    function rec(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(h, v, r, s);
    }
    function recIs(bytes32 h, uint8 v, bytes32 r, bytes32 s, address who) external pure returns (bool) {
        return ecrecover(h, v, r, s) == who;
    }
    function sha(bytes calldata d) external pure returns (bytes32) { return sha256(d); }
    function sha2(uint256 a, uint256 b) external pure returns (bytes32) { return sha256(abi.encodePacked(a, b)); }
    function rip(uint256 a) external pure returns (bytes20) { return ripemd160(abi.encodePacked(a)); }
}
"""


@pytest.mark.parametrize("build", [Build("0.8.19"), pytest.param(Build("0.8.31", via_ir=True), marks=pytest.mark.slow),
                                   pytest.param(Build("0.7.6"), marks=pytest.mark.slow)], ids=lambda b: b.label)
def test_builtins(build, monkeypatch):
    comp = cp.compile_all(BUILTINS, build)
    art = comp.artifact("BuiltinProbe")
    cp.patch_lookups(monkeypatch, [art.abi])
    result = cp.generate(art.runtime)
    if build == Build("0.8.19"):
        for snippet in ("ecrecover(h, v, r, s)", "sha256(abi.encodePacked(a, b))", "ripemd160(abi.encodePacked(a))"):
            assert snippet in result.solidity, snippet
    h = bytes(range(32))
    r = int.from_bytes(bytes(range(1, 33)), "big")
    calls = []
    for v in (27, 28, 0, 1, 255):
        for s in (1, 2**255, r):
            calls.append((call("rec(bytes32,uint8,bytes32,bytes32)", h, v, cp.word(r), cp.word(s)), 0))
            calls.append((call("recIs(bytes32,uint8,bytes32,bytes32,address)", h, v, cp.word(r), cp.word(s), CALLER), 0))
    calls += [(call("sha(bytes)", d), 0) for d in (b"", b"abc", bytes(100))]
    calls += [(call("sha2(uint256,uint256)", 1, 2), 0), (call("rip(uint256)", 7), 0)]
    diffs = cp.differential(art.runtime, result.solidity, result.target_solc, calls)
    assert not diffs, _show(diffs)


GUARDED = """
interface IWETH {
    function withdraw(uint256 amount) external;
}

contract GuardProbe {
    function sum(address t, uint256 a, uint256 b) external {
        require(t.code.length > 0);
        uint256 s = a + b;
        assembly {
            mstore(0, shl(224, 0x2e1a7d4d))
            mstore(4, s)
            if iszero(call(gas(), t, 0, 0, 36, 0, 0)) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
    }
}
"""


def test_code_check_before_a_halting_operand(monkeypatch):
    """A code check made BEFORE an operand that may end the call (a checked
    addition) is not the one the target writes, after the operands: it is
    kept, so that a callee without code still wins over the overflow."""
    comp = cp.compile_all(GUARDED, Build("0.8.19"))
    art = comp.artifact("GuardProbe")
    cp.patch_lookups(monkeypatch, [a.abi for a in comp.artifacts.values()])
    result = cp.generate(art.runtime)
    assert ".withdraw(a + b);" in result.solidity
    calls = [(call("sum(address,uint256,uint256)", c, a, b), 0)
             for c in (ECHO, EOA) for a, b in ((1, 2), (2**255, 2**255))]
    diffs = cp.differential(art.runtime, result.solidity, result.target_solc, calls, ("true", "revert-error"))
    assert not diffs, _show(diffs)


BATCH = """
contract Batch {
    function run(address[] calldata targets, bytes[] calldata payloads) external {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, ) = targets[i].call(payloads[i]);
            require(ok, "call failed");
        }
    }
}
"""


def test_a_call_declaring_its_locals_keeps_its_arithmetic_unchecked(monkeypatch):
    """A low-level call declaring its success flag and return data, in a
    function with checked operations: its wrapping offsets are written in
    an `unchecked` block (the locals declared just before it), not through
    nested wrapping helpers, which leave solc no stack for this loop.
    (Without the loops pass: with it the checked increment is in the `for`
    header and the body is one `unchecked` block.)"""
    comp = cp.compile_all(BATCH, Build("0.8.19"))
    art = comp.artifact("Batch")
    cp.patch_lookups(monkeypatch, [])
    calls = [(call("run(address[],bytes[])", [ECHO, EOA], [b"\x01\x02\x03\x04", b""]), 0),
             (call("run(address[],bytes[])", [], []), 0), (call("run(address[],bytes[])", [ECHO], [b""]), 0)]
    result = cp.generate(art.runtime, off=("loops",))
    assert "bool success;" in result.solidity  # (the naming pass's name for the flag)
    for res in (result, cp.generate(art.runtime)):
        diffs = cp.differential(art.runtime, res.solidity, res.target_solc, calls, ("true", "revert-error"))
        assert not diffs, _show(diffs)


def test_high_level_call_nodes():
    """The IR the pass produces: one HighCall per call, its values as Results."""
    from scobelix.solgen import pipeline
    from scobelix.solgen.passes import calls

    body = (
        ir.ExtCall(1, "staticcall", None, ir.Param(0), None, None,
                   ir.Blob((ir.WordBytes(ir.Const(0x70A08231), 4), ir.WordBytes(ir.Env("caller"))))),
        ir.If(ir.Op("iszero", (ir.CallOut(1, "success"),)), (ir.Revert(ir.Bubble(1)),), (
            ir.If(ir.Op("slt", (ir.CallOut(1, "returndatasize"), ir.Const(32))), (ir.Revert(),), (
                ir.Return(ir.ReturnData(1, ir.ZERO, ir.Const(32))),)),)),
    )

    class _Sig:
        name = "balanceOf"
        types = ("address",)
        inputs = (("address", "account"),)
        outputs = (("uint256", ""),)

    class _Sigs:
        @staticmethod
        def function_candidates(sel):
            return (_Sig,) if sel == 0x70A08231 else ()

    ctx = pipeline.PassContext(specs={}, metadata=None, dispatcher=None, target_solc="0.8.19", abi_v2=True,
                               idiom_level="full", sigs=_Sigs)
    fn = calls.run(ir.Function("0x12345678", body), ctx)
    assert isinstance(fn.body[0], ir.HighCall) and fn.body[0].kind == "staticcall"
    assert fn.body[1] == ir.Return(ir.WordBytes(ir.Result(1, 0, "uint256")))
    calls.finish(ctx)
    assert ctx.declarations["interface"] == [
        "interface IERC20 {\n    function balanceOf(address account) external view returns (uint256);\n}"]

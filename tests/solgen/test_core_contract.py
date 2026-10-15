"""
Contract assembly and the v2 entry point: target compiler and pragmas,
known names vs routed selectors, receive / fallback rules, header and
NatSpec, the pass manager hooks, the degraded JSON mode.
"""

import re
import types

import pytest

from conftest import backend_or_skip, compile_or_fail, decompiled, fixture_hex, installed, solc_or_skip
from scobelix.solgen import abi, ir, pipeline, sigs
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.contract import ContractInput, Unit, assemble
from scobelix.solgen.types import parse_type
from scobelix.solgen.v2 import choose_target, generate


# ---------------------------------------------------------------- target compiler


def test_target_follows_the_original_08_compiler():
    if "0.8.19" not in installed():
        pytest.skip("solc 0.8.19 is not installed")
    assert choose_target({"compiler": "solc", "version": "0.8.19"}) == "0.8.19"


def test_target_for_older_or_unknown_compilers_is_the_newest_08():
    newest = max((v for v in installed() if v.startswith("0.8.")), key=lambda v: tuple(map(int, v.split("."))),
                 default=None)
    if newest is None:
        pytest.skip("no solc 0.8 installed")
    assert choose_target({"compiler": "solc", "version": "0.7.6"}) == newest
    assert choose_target(None) == newest
    assert choose_target({"compiler": "solc", "version": "0.8.19"}, requested="0.8.31") == "0.8.31"


def test_pre_08_without_validators_uses_abi_coder_v1():
    r = generate(decompiled("DispatchFallbackOld"))  # solc 0.5.17
    assert "pragma abicoder v1;" in r.solidity
    assert "original compiler : solc 0.5.17" in r.solidity
    r = generate(decompiled("SimpleToken"))
    assert "pragma abicoder v1;" not in r.solidity
    assert re.search(r"pragma solidity \^0\.8\.\d+;", r.solidity)


def test_header_and_natspec():
    r = generate(decompiled("Vault"))
    assert "target compiler   : solc " + r.target_solc in r.solidity
    assert "Legend" in r.solidity
    n_entries = sum(1 for f in r.functions.values() if f["kind"] == "function" or f["kind"] == "receive")
    assert r.solidity.count("/// @custom:scobelix tier=exact verdict=unverified") >= n_entries


# ---------------------------------------------------------------- names and routing


def _unit(sel, body, payable=False, signature=None, params=()):
    key = f"0x{sel:08x}"
    spec = EntrySpec(key=key, kind="function", selector=sel, payable=payable, signature=signature,
                     name=signature.split("(")[0] if signature else None, params=params,
                     mutability="payable" if payable else "nonpayable")
    return Unit(key, ir.Function(key, tuple(body)), spec)


def test_router_checks_value_for_non_payable_routes():
    units = [_unit(0x11111111, [ir.Stop()], payable=True), _unit(0x22222222, [ir.Stop()])]
    src, _ = assemble(ContractInput(units=units, target="0.8.19", original="test"))
    assert "fallback() external payable" in src
    route = src[src.index("0x22222222) {"):]
    assert route.splitlines()[1].strip() == "if (msg.value != 0) revert();"
    compile_or_fail(src, "0.8.19")


def test_solc_default_fallback_is_not_written():
    fallback = Unit("_fallback", ir.Function("_fallback", (ir.Revert(),)), EntrySpec("_fallback", "fallback"))
    named = _unit(0x18160DDD, [ir.Return(ir.WordBytes(ir.ONE))], signature="totalSupply()")
    src, _ = assemble(ContractInput(units=[fallback, named], target="0.8.19", original="test",
                                    fallback_present=False))
    assert "fallback() external" not in src and "function totalSupply() external" in src


def test_known_name_needs_a_consistent_decoder():
    """A database name whose head size disagrees with the calldata size
    check is not used: the selector is routed."""
    body = (ir.If(ir.Op("slt", (ir.Op("add", (ir.const(-4), ir.Env("calldatasize"))), ir.Const(64))),
                  (ir.Revert(),), (ir.Stop(),)),)
    fn = ir.Function("0x18160ddd", body)  # totalSupply() takes no argument
    spec, _ = abi.analyse_entry(fn, "0x18160ddd", selector=0x18160DDD, payable=False)
    if not sigs.function_candidates(0x18160DDD):
        pytest.skip("no signature database")
    assert spec.signature is None and "signature_rejected" in spec.flags and spec.routed


def test_validators_reject_mismatching_parameter_types():
    p = ir.CalldataWord(ir.Const(4))
    check = ir.Op("iszero", (ir.Op("eq", (p, ir.Mask(160, 0, 0, p))),))
    head = ir.Op("slt", (ir.Op("add", (ir.const(-4), ir.Env("calldatasize"))), ir.Const(32)))
    assert abi.validator(check) == (0, "address")
    assert abi.head_size([head]) == 1
    cands = [sigs.Signature("function", "f", (("uint256", "x"),), "f(uint256)"),
             sigs.Signature("function", "g", (("address", "a"),), "g(address)")]
    assert abi._choose(cands, 1, {0: "address"}, frozenset()).name == "g"
    assert abi._choose(cands[:1], 1, {0: "address"}, frozenset()) is None
    # ABI coder v2: a narrow type needs its validator
    assert abi._choose(cands[1:], 1, {}, frozenset(), strict=True) is None
    assert abi._choose(cands[1:], 1, {}, frozenset(), strict=False).name == "g"


def test_external_signatures_hash_to_their_selectors():
    r = generate(decompiled("NestedStructMapping"))
    art = compile_or_fail(r.solidity, r.target_solc)
    for sig, sel in art.method_ids.items():
        assert sigs.function_selector(sig) == int(sel, 16)
        assert r.functions[f"0x{sel}"]["signature"] == sig


def test_tuple_parameters_get_structs():
    t = parse_type("(uint8,(address,bytes))[]")
    units = [_unit(sigs.function_selector("f((uint8,(address,bytes))[])"), [ir.Stop()],
                   signature="f((uint8,(address,bytes))[])", params=((t, "items"),))]
    src, _ = assemble(ContractInput(units=units, target="0.8.19", original="test"))
    assert "struct S" in src and "calldata items" in src
    art = compile_or_fail(src, "0.8.19")
    assert list(art.method_ids) == ["f((uint8,(address,bytes))[])"]


def test_failed_functions_keep_their_selector():
    d = decompiled("SimpleToken")
    js = dict(d.json)
    js["functions"] = [f for f in js["functions"] if f["hash"] != "0xa9059cbb"]
    js["problems"] = {"0xa9059cbb": "transfer(address,uint256)"}
    r = generate(js)
    assert r.functions["0xa9059cbb"]["flags"] and "problem" in r.functions["0xa9059cbb"]["flags"]
    assert "function transfer(address to, uint256 amount) external" in r.solidity
    compile_or_fail(r.solidity, r.target_solc)


# ---------------------------------------------------------------- degraded json mode


def test_json_only_decompilation():
    d = decompiled("Vault")
    r = generate(d.json)
    assert any("JSON traces" in w for w in r.warnings)
    compile_or_fail(r.solidity, r.target_solc)
    assert all("json_trace" in f["flags"] for f in r.functions.values() if f["kind"] == "function")


def test_json_only_decompilation_behaves_like_the_original():
    backend_or_skip()
    from scobelix.verify import Budget, verify

    r = generate(decompiled("Vault").json)
    solc_or_skip(r.target_solc)
    report = verify(fixture_hex("Vault"), r.solidity, contract_name=r.contract_name, abi_hint=r.abi_hint,
                    solc_version=r.target_solc, levels=("L0", "L1", "L3"), budget=Budget.quick(),
                    routed_selectors=r.routed_selectors)
    assert report.levels["L3"].status == "pass", report.levels["L3"].reason


# ---------------------------------------------------------------- passes


def test_exact_level_runs_no_pass_and_full_runs_the_available_ones(monkeypatch):
    def run(fn, ctx):
        def drop_seed(n):
            return n

        if fn.key == "0x18160ddd":
            return fn.with_body(fn.body, extra_flags=("seen-by-test-pass",))
        return fn

    fake = types.ModuleType("scobelix.solgen.passes.naming")
    fake.run = run
    monkeypatch.setitem(pipeline._LOADED, "naming", fake)
    d = decompiled("SimpleToken")
    real = {"storage", "getters"}  # the passes that exist, off for this test
    exact = generate(d)
    full = generate(d, idiom_level="full", disabled_passes={"*": real})
    assert exact.functions["0x18160ddd"]["passes"] == []
    assert full.functions["0x18160ddd"]["passes"] == ["naming"]
    assert "seen-by-test-pass" in full.functions["0x18160ddd"]["flags"]
    off = generate(d, idiom_level="full", disabled_passes={"*": real, "0x18160ddd": {"naming"}})
    assert off.functions["0x18160ddd"]["passes"] == []
    assert pipeline.available_passes("exact") == []


def test_a_failing_pass_keeps_the_previous_form(monkeypatch):
    def run(fn, ctx):
        raise RuntimeError("boom")

    fake = types.ModuleType("scobelix.solgen.passes.arith")
    fake.run = run
    monkeypatch.setitem(pipeline._LOADED, "arith", fake)
    r = generate(decompiled("SimpleToken"), idiom_level="full")
    assert any("pass arith failed" in w for w in r.warnings)
    compile_or_fail(r.solidity, r.target_solc)


def test_checked_operations_split_the_unchecked_blocks():
    """A pass's checked arithmetic is never placed inside `unchecked`: a
    statement with one keeps Solidity's checks and its wrapping operations
    go through helpers; a statement without one gets its own block."""
    a, b = ir.CalldataWord(ir.Const(4)), ir.CalldataWord(ir.Const(36))
    checked = ir.Typed("add", (a, b), "uint256", checked=True)
    wrapping = ir.Op("add", (checked, ir.Op("mul", (a, b))))
    units = [_unit(0x33333333, [ir.Assign(ir.Local("x"), ir.Op("mul", (a, a))),
                                ir.Return(ir.Blob((ir.WordBytes(wrapping), ir.WordBytes(ir.Local("x")))))])]
    src, _ = assemble(ContractInput(units=units, target="0.8.19", original="test"))
    body = src[src.index("function _fn_33333333"):].split("\n    }\n")[0]
    assert "unchecked {" in body and "_wmul(" in body and "_wadd(" in body
    art = compile_or_fail(src, "0.8.19")
    from conftest import backend_or_skip
    from scobelix.verify.evm import make_world

    world = make_world(backend_or_skip())
    world.set_code("0x" + "c0" * 20, art.runtime)
    m = 2**256 - 1
    r = world.call("0x" + "a1" * 20, "0x" + "c0" * 20, bytes.fromhex("33333333") + (3).to_bytes(32, "big")
                   + m.to_bytes(32, "big"))
    assert not r.success and r.output[:4] == bytes.fromhex("4e487b71")  # 3 + m overflows: checked
    r = world.call("0x" + "a1" * 20, "0x" + "c0" * 20, bytes.fromhex("33333333") + (2**255).to_bytes(32, "big")
                   + (5).to_bytes(32, "big"))
    want = ((2**255 + 5 + 2**255 * 5) % 2**256).to_bytes(32, "big") + ((2**510) % 2**256).to_bytes(32, "big")
    assert r.success and r.output == want


def test_declared_return_types_and_addresses_with_constants():
    """Constant words shown as narrow types (conversions of literals)."""
    ret = parse_type("address")
    big = ir.Const(2**200 + 0x1111)  # a dirty constant address: only its low 160 bits count
    fn_body = [ir.ExtCall(1, "call", None, big, ir.ZERO, None, None),
               ir.Return(ir.Blob((ir.WordBytes(ir.Const(0x00AB)),)))]
    unit = _unit(sigs.function_selector("owner()"), fn_body, signature="owner()")
    unit.spec.returns = (ret,)
    unit2 = _unit(sigs.function_selector("x()"), [ir.Return(ir.WordBytes(ir.const(-7)))], signature="x()")
    unit2.spec.returns = (parse_type("int256"),)
    unit3 = _unit(sigs.function_selector("h()"), [ir.Return(ir.WordBytes(ir.Const(5)))], signature="h()")
    unit3.spec.returns = (parse_type("bytes32"),)
    src, _ = assemble(ContractInput(units=[unit, unit2, unit3], target="0.8.19", original="test"))
    compile_or_fail(src, "0.8.19")


def test_receive_reading_calldata_runs_in_a_private_function():
    """solc rejects msg.data in receive(); a receive running the fallback's
    forwarding code still compiles and keeps its behaviour."""
    body = (ir.ExtCall(1, "delegatecall", None, ir.Sload(ir.ZERO), None, None,
                       ir.CalldataSlice(ir.ZERO, ir.Env("calldatasize"))),
            ir.If(ir.Op("iszero", (ir.CallOut(1, "success"),)), (ir.Revert(ir.Bubble(1)),),
                  (ir.Return(ir.ReturnData(1, ir.ZERO, ir.CallOut(1, "returndatasize"))),)))
    units = [Unit(k, ir.Function(k, body), EntrySpec(k, kind)) for k, kind in
             (("_fallback", "fallback"), ("_receive", "receive"))]
    src, _ = assemble(ContractInput(units=units, target="0.8.19", original="test", fallback_present=True,
                                    fallback_payable=True, receive_present=True))
    assert "_receive_body();" in src
    art = compile_or_fail(src, "0.8.19")
    assert {i["type"] for i in art.abi} >= {"receive", "fallback"}


def test_legacy_decoders_copying_dynamic_parameters_are_flagged():
    trace = [["return", ["cd", ["add", 4, ["cd", 4]]]]]  # the length of a dynamic parameter
    js = {"functions": [{"hash": "0x12345678", "trace": trace, "payable": True}],
          "metadata": {"compiler": "solc", "version": "0.4.26"}}
    assert "abi:legacy_memory_copy" in generate(js).functions["0x12345678"]["flags"]
    js["metadata"] = {"compiler": "solc", "version": "0.8.19"}  # ABI coder v2 checks the bounds
    assert "abi:legacy_memory_copy" not in generate(js).functions["0x12345678"]["flags"]

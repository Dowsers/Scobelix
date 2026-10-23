"""
solgen v2 on the repository fixtures:

  L0  the generated source compiles with the target compiler;
  L1  the external ABI matches the original source's: named selectors with
      the original mutability, the other selectors routed through
      fallback(), receive / fallback presence;
  L3  differential execution (scobelix.verify) finds no divergence.
"""

import json

import pytest

from conftest import (FIXTURES, backend_or_skip, compile_or_fail, decompiled, differential_fixtures, fixture_hex,
                      fixture_params, installed, solc_or_skip)
from scobelix.solgen import sigs
from scobelix.solgen.v2 import generate

FIXTURE_INFO = json.loads((FIXTURES / "fixtures.json").read_text())


# functions whose only difference is the gas the original spends: a memory
# expansion the generated code does not need (the engine keeps no memory
# write that is never read), so a huge argument runs the original out of even
# a block's gas where the generated function returns.  The verifier reports
# them INCONCLUSIVE ("env: gas: ..."), never DIVERGENT; the exception holds
# only while it does.
_GAS_DEPENDENT = {
    "LoopShapes": {"0x77822421": "memBound: new uint256[](n) expands memory by 32 n bytes"},
    "LoopShapesNoopt": {"0x77822421": "memBound: new uint256[](n) expands memory by 32 n bytes"},
    "LoopShapesViaIR": {"0x77822421": "memBound: new uint256[](n) expands memory by 32 n bytes"},
}


def _gas_dependent(name, report):
    """The documented gas-only differences of the fixture's report."""
    out = {}
    for key, why in _GAS_DEPENDENT.get(name, {}).items():
        f = report.functions.get(key)
        if f is not None and f.verdict == "INCONCLUSIVE" and f.reason.startswith("env: gas:"):
            out[key] = why
    return out


def _original_abi(name):
    """ABI of the fixture's own source, compiled as it was built."""
    from scobelix.verify.solc import Settings, compile_standard_json

    info = FIXTURE_INFO[name]
    path = installed().get(info["solc"])
    if path is None:
        pytest.skip(f"solc {info['solc']} is not installed")
    sources = {p.name: p.read_text() for p in (FIXTURES / "sources").glob("*.sol")}
    wanted = {info["source"]: sources[info["source"]]}
    for imp in ("Ownable.sol",):
        if f'"./{imp}"' in wanted[info["source"]]:
            wanted[imp] = sources[imp]
    settings = Settings(optimize=info["optimizer"], runs=info["runs"], via_ir=info["via_ir"],
                        evm_version=info.get("evm_version"))
    comp = compile_standard_json(wanted, settings, version=info["solc"], solc_path=path)
    return comp.artifact(info["contract"]).abi


def _mutability(item):
    m = item.get("stateMutability")
    if m:
        return m
    return "payable" if item.get("payable") else ("view" if item.get("constant") else "nonpayable")


def _abi_functions(abi):
    out = {}
    for item in abi:
        if item.get("type") == "function":
            types = ",".join(_canonical(i) for i in item.get("inputs", []))
            sig = f"{item['name']}({types})"
            out[sigs.function_selector(sig)] = (sig, _mutability(item))
    return out


def _canonical(inp):
    t = inp["type"]
    if t.startswith("tuple"):
        return "(" + ",".join(_canonical(c) for c in inp["components"]) + ")" + t[5:]
    return t


@pytest.fixture(scope="module")
def results():
    return {}


def _generate(name, results):
    if name not in results:
        results[name] = generate(decompiled(name))
    return results[name]


@pytest.mark.parametrize("name", fixture_params())
def test_l0_compiles_with_the_target(name, results):
    r = _generate(name, results)
    compile_or_fail(r.solidity, r.target_solc)
    assert "pragma solidity ^0.8." in r.solidity


def test_the_cancun_builtins_need_a_release_that_compiles_them_as_is(results):
    # solc 0.8.24 knows tload/tstore, blobhash and block.blobbasefee but
    # targets Shanghai unless told otherwise: 0.8.25 is the first release
    # that compiles them with its default EVM version, so the pragma floor
    # and the target of a text using them are at least 0.8.25
    r = _generate("TransientSwap", results)
    assert "_tload(" in r.solidity and "_tstore(" in r.solidity
    assert "pragma solidity ^0.8.25;" in r.solidity
    assert tuple(int(x) for x in r.target_solc.split(".")) >= (0, 8, 25)
    compile_or_fail(r.solidity, r.target_solc)


@pytest.mark.parametrize("name", fixture_params())
def test_l1_external_abi(name, results):
    r = _generate(name, results)
    art = compile_or_fail(r.solidity, r.target_solc)
    original = _abi_functions(_original_abi(name))
    generated = _abi_functions(art.abi)
    routed = {int(k, 16) for k in r.routed_selectors}
    specials = {i["type"] for i in _original_abi(name) if i.get("type") in ("receive", "fallback")}
    # every original selector is either declared or routed; a routed selector
    # that is no function of the original is a `msg.sig` test of its fallback
    # that the optimizer merged into the dispatcher (routing it through
    # fallback() is the same behaviour and leaves the ABI unchanged)
    extra = routed - set(original)
    assert set(generated) | (routed - extra) == set(original), (sorted(map(hex, generated)), sorted(map(hex, routed)))
    assert not extra or "fallback" in specials, sorted(map(hex, extra))
    assert not set(generated) & routed
    for sel, (sig, mut) in generated.items():
        assert sigs.function_selector(sig) == sel
        assert mut == original[sel][1], (sig, mut, original[sel][1])
    for sel in routed - extra:
        f = r.functions[f"0x{sel:08x}"]
        assert f["routed"] and (f["payable"] == (original[sel][1] == "payable"))
    gen_specials = {i["type"] for i in art.abi if i.get("type") in ("receive", "fallback")}
    if routed:
        assert "fallback" in gen_specials  # the router
        gen_specials.discard("fallback")
        specials.discard("fallback")
    assert gen_specials == specials


@pytest.mark.parametrize("name", differential_fixtures())
def test_l3_equivalent(name, results):
    backend_or_skip()
    from scobelix.verify import Budget, verify

    r = _generate(name, results)
    solc_or_skip(r.target_solc)
    report = verify(fixture_hex(name), r.solidity, contract_name=r.contract_name, abi_hint=r.abi_hint,
                    solc_version=r.target_solc, levels=("L0", "L1", "L3"), budget=Budget.quick(),
                    routed_selectors=r.routed_selectors)
    assert report.levels["L0"].status == "pass", report.levels["L0"].details
    # without selector functions the abi_hint is empty, and it is authoritative:
    # msg.sig tests inside a fallback are no entry points (only reported)
    assert report.levels["L1"].status == "pass", report.levels["L1"].reason
    gas_only = _gas_dependent(name, report)
    bad = {k: (f.verdict, f.reason) for k, f in report.functions.items()
           if f.verdict not in ("EQUIVALENT", "EQUIVALENT_REVERTS_ONLY") and k not in gas_only}
    assert not bad, (report.levels["L3"].reason, bad)
    assert report.levels["L3"].status == "pass" or gas_only, report.levels["L3"].reason


def test_verify_option_fills_the_verdicts():
    backend_or_skip()
    solc_or_skip(FIXTURE_INFO["SimpleToken"]["solc"])
    from scobelix.verify import Budget

    r = generate(decompiled("SimpleToken"), verify=True, budget=Budget.quick())
    assert r.verification is not None and r.verification.levels["L3"].status == "pass"
    assert r.functions["0xa9059cbb"]["verdict"] == "EQUIVALENT"
    assert "verdict=EQUIVALENT" in r.solidity and "verification: L0=pass" in r.solidity

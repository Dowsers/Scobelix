"""
The storage and getters passes on the repository fixtures ("full" level):

  L0  the source compiles with the target compiler;
  L1  the external ABI still matches the original's (folded getters are
      `public` state variables with the same selector and view mutability);
  L2  every state variable of the fixture's source that the runtime code
      touches is declared at its slot and offset, with its size and
      encoding (scobelix.verify.layout); the variables the code never
      touches (constructor-only) may be fillers;
  L3  differential execution finds no divergence the exact tier does not
      have (the passes keep the EVM semantics).
"""

import json

import pytest

from conftest import (FIXTURES, backend_or_skip, compile_or_fail, decompiled, differential_fixtures, fixture_hex,
                      fixture_params, installed, solc_or_skip)
from scobelix.solgen.v2 import generate
from test_core_fixtures import _abi_functions, _gas_dependent, _original_abi

FIXTURE_INFO = json.loads((FIXTURES / "fixtures.json").read_text())


@pytest.fixture(scope="module")
def results():
    return {}


def _generate(name, results, level="full"):
    if (name, level) not in results:
        results[(name, level)] = generate(decompiled(name), idiom_level=level)
    return results[(name, level)]


def _original_layout(name):
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
    return comp.artifact(info["contract"]).storage_layout


@pytest.mark.parametrize("name", fixture_params())
def test_full_level_compiles_and_keeps_the_abi(name, results):
    r = _generate(name, results)
    art = compile_or_fail(r.solidity, r.target_solc)
    original = _abi_functions(_original_abi(name))
    generated = _abi_functions(art.abi)
    routed = {int(k, 16) for k in r.routed_selectors}
    extra = routed - set(original)
    assert set(generated) | (routed - extra) == set(original)
    for sel, (sig, mut) in generated.items():
        assert mut == original[sel][1], (sig, mut, original[sel][1])
    for key, f in r.functions.items():
        if f["folded"]:
            assert f["kind"] == "function" and not f["routed"] and f["mutability"] == "view"
            assert int(key, 16) in generated  # solc generated the getter


# what the bytecode cannot tell: the type the source declares differs from
# the one the code's own accesses show
_L2_AMBIGUOUS = {
    "DispatchGuarded": "assembly reads the address slot as a whole word (compared through a subtraction): uint256",
}


@pytest.mark.parametrize("name", fixture_params())
def test_l2_touched_variables_at_their_positions(name, results, request):
    from scobelix.verify.layout import compare_layout

    if name in _L2_AMBIGUOUS:
        request.node.add_marker(pytest.mark.xfail(reason=_L2_AMBIGUOUS[name], strict=True))
    original = _original_layout(name)
    if not original or not original.get("storage"):
        pytest.skip("no state variables")
    r = _generate(name, results)
    art = compile_or_fail(r.solidity, r.target_solc)
    cmp = compare_layout(original, art.storage_layout)
    # a variable is touched when some recovered variable starts at its position
    declared = {(v["slot"], v["offset"]) for v in r.storage_layout}
    bad = [row for row in cmp.rows if row["status"] != "match" and (row["slot"], row["offset"]) in declared]
    assert not bad, bad
    for row in cmp.rows:
        if row["status"] == "match":
            continue
        # untouched variables: nothing was recovered there
        assert (row["slot"], row["offset"]) not in declared, row


# The dispatcher fixtures (Dispatch*) have trivial bodies: the passes'
# differential run on them is in `-m slow` (test_core_fixtures executes their
# dispatch in the default run).
@pytest.mark.parametrize("name", [
    pytest.param(p, marks=pytest.mark.slow) if isinstance(p, str) and p.startswith("Dispatch") else p
    for p in differential_fixtures()
])
def test_l3_the_passes_keep_the_behaviour(name, results):
    backend_or_skip()
    from scobelix.verify import Budget, verify

    r = _generate(name, results)
    solc_or_skip(r.target_solc)
    report = verify(fixture_hex(name), r.solidity, contract_name=r.contract_name, abi_hint=r.abi_hint,
                    solc_version=r.target_solc, levels=("L0", "L1", "L3"), budget=Budget.quick(),
                    routed_selectors=r.routed_selectors)
    assert report.levels["L0"].status == "pass", report.levels["L0"].details
    # the interface holds at this level too, with the events and errors the
    # passes name (see test_core_fixtures)
    assert report.levels["L1"].status == "pass", report.levels["L1"].reason
    gas_only = _gas_dependent(name, report)
    bad = {k: (f.verdict, f.reason) for k, f in report.functions.items()
           if f.verdict not in ("EQUIVALENT", "EQUIVALENT_REVERTS_ONLY") and k not in gas_only}
    assert not bad, bad

"""scobelix.verify.verify(): every level end to end, on reconstructions and mutants."""

import functools
import json

import pytest
from eth_utils import keccak
from verify_helpers import (
    REPO_FIXTURES,
    SOLC,
    compile_fixture,
    fixture_source,
    original_artifact,
    original_runtime,
    requires_backend,
    requires_pyevm,
    requires_pyrevm,
    requires_solc,
    solc_path,
)

from scobelix.verify import Budget, Verdict, core, solc, verify
from scobelix.verify.bytecode import patch_immutables, push_values, shifted_push_values

TRANSFER, BALANCE_OF, TOTAL_SUPPLY = "0xa9059cbb", "0x70a08231", "0x18160ddd"
SET_PAUSED, WITHDRAW = "0x16c38b3c", "0x2e1a7d4d"
# detection power: as many calls as a real run, but stop a function at its 3rd divergence
FAST = Budget(
    calls_per_function=300,
    probe_calls=40,
    sequences=10,
    sequence_length=10,
    max_divergences=3,
    coverage_calls=16,
    l4_search=False,
)
# plumbing: enough calls for the behaviour under test
QUICK = Budget(
    calls_per_function=80,
    probe_calls=20,
    sequences=4,
    sequence_length=6,
    max_divergences=2,
    coverage_calls=8,
    l4_search=False,
)
pytestmark = requires_solc


def _token(rel, name, **kw):
    ref = original_artifact("SimpleToken")
    kw.setdefault("budget", FAST)
    return verify(
        original_runtime("SimpleToken"),
        fixture_source(rel),
        contract_name=name,
        layout=ref.storage_layout,
        abi_hint=ref.abi,
        **kw,
    )


@functools.lru_cache(maxsize=None)
def _token_report(rel, name):
    """The FAST-budget report of a token candidate, shared by the tests that read it."""
    return _token(rel, name)


def _vault(rel, **kw):
    ref = original_artifact("Vault")
    kw.setdefault("budget", FAST)
    return verify(
        original_runtime("Vault"),
        fixture_source(rel),
        contract_name="Vault",
        layout=ref.storage_layout,
        abi_hint=ref.abi,
        **kw,
    )


def _statuses(report):
    return {k: v.status for k, v in report.levels.items()}


# ---------------------------------------------------------------- reconstructions


@requires_backend
def test_a_faithful_reconstruction_passes_every_level():
    r = _token_report("token/Recon.sol", "Recon")
    assert _statuses(r) == {"L0": "pass", "L1": "pass", "L2": "pass", "L3": "pass", "L4": "pass"}
    assert r.passed and r.summary == {"EQUIVALENT": 3, "EQUIVALENT_REVERTS_ONLY": 2}
    f = r.functions[TRANSFER]
    assert (f.abi, f.verdict, f.calls, f.divergences) == ("MATCH", Verdict.EQUIVALENT, 300, 0)
    assert 0 < f.original_success < f.calls and f.payable == {
        "original": False,
        "candidate": False,
        "oracle": False,
    }
    assert (
        r.functions["fallback"].verdict
        == r.functions["receive"].verdict
        == Verdict.EQUIVALENT_REVERTS_ONLY
    )
    assert r.levels["L4"].details["matching"] == ["opt200"]
    assert r.candidate["solc"] == SOLC and r.original["metadata"]["version"] == SOLC
    blob = json.dumps(r.to_json())
    assert '"passed": true' in blob and "transfer(address,uint256)" in r.to_text()


@requires_backend
def test_restyled_source_is_equivalent_but_not_identical():
    r = _token("token/Restyled.sol", "Restyled")
    assert _statuses(r) == {"L0": "pass", "L1": "pass", "L2": "pass", "L3": "pass", "L4": "fail"}
    assert "instr_similarity" in r.levels["L4"].reason
    assert all(f.verdict in Verdict.OK for f in r.functions.values())


@requires_backend
@pytest.mark.parametrize(
    "settings", [solc.Settings(optimize=False), solc.Settings(via_ir=True)], ids=["noopt", "viaIR"]
)
def test_other_compiler_settings_are_no_false_alarm(settings):
    r = _token("token/Recon.sol", "Recon", settings=settings)
    assert r.levels["L3"].status == "pass" and r.levels["L4"].status == "fail"
    assert r.candidate["settings"] == settings.label


# ---------------------------------------------------------------- mutants

TOKEN_MUTANTS = [
    # (fixture, contract, {function key: verdict}, failing levels besides L3 / L4)
    ("UncheckedAdd", {TRANSFER: Verdict.DIVERGENT}, set()),
    ("AliasBug", {TRANSFER: Verdict.DIVERGENT}, set()),
    ("OffByOne", {TRANSFER: Verdict.DIVERGENT}, set()),
    ("WrongMessage", {TRANSFER: Verdict.DIVERGENT}, set()),
    ("PayableTransfer", {TRANSFER: Verdict.DIVERGENT}, {"L1"}),
    (
        "NarrowParam",
        {
            TRANSFER: Verdict.MISSING,
            "0x" + keccak(text="transfer(address,uint128)")[:4].hex(): Verdict.EXTRA,
        },
        {"L1"},
    ),
    (
        "SwappedSlots",
        {
            TRANSFER: Verdict.DIVERGENT,
            BALANCE_OF: Verdict.DIVERGENT,
            TOTAL_SUPPLY: Verdict.DIVERGENT,
        },
        {"L2"},
    ),
    ("InternalSupply", {TOTAL_SUPPLY: Verdict.MISSING}, {"L1"}),
    ("ExtraEvent", {TRANSFER: Verdict.DIVERGENT}, {"L1"}),
    ("CustomError", {TRANSFER: Verdict.DIVERGENT}, {"L1"}),
]


# one mutant of each kind of change runs by default, the others with `-m slow`
_SLOW_TOKEN_MUTANTS = {"InternalSupply", "NarrowParam", "SwappedSlots", "WrongMessage"}


@requires_backend
@pytest.mark.parametrize(
    "name, verdicts, failing",
    [pytest.param(*m, marks=pytest.mark.slow) if m[0] in _SLOW_TOKEN_MUTANTS else m for m in TOKEN_MUTANTS],
    ids=[m[0] for m in TOKEN_MUTANTS],
)
def test_token_mutants_are_caught(name, verdicts, failing):
    r = _token_report(f"token/{name}.sol", name)
    for key, verdict in verdicts.items():
        assert r.functions[key].verdict == verdict, (key, r.functions[key])
    assert r.levels["L3"].status == "fail"
    for level in ("L0", "L1", "L2"):
        assert r.levels[level].status == ("fail" if level in failing else "pass"), (
            level,
            r.levels[level],
        )
    others = [f for k, f in r.functions.items() if k not in verdicts]
    assert all(f.verdict in Verdict.OK for f in others), others


@requires_backend
def test_l1_explains_interface_mutants():
    assert (
        "mutability: 0xa9059cbb"
        in _token_report("token/PayableTransfer.sol", "PayableTransfer").levels["L1"].reason
    )
    l1 = _token_report("token/ExtraEvent.sol", "ExtraEvent").levels["L1"].details
    assert l1["events"]["declared_not_in_original"] == ["Transfer(address,address,uint256)"]
    l1 = _token_report("token/CustomError.sol", "CustomError").levels["L1"].details
    assert l1["errors"]["declared_not_in_original"] == ["InsufficientBalance()"]


@requires_backend
def test_counterexamples_are_shrunk_and_explained():
    f = _token_report("token/UncheckedAdd.sol", "UncheckedAdd").functions[TRANSFER]
    ce = f.counterexample
    assert ce["call"]["calldata"].startswith("0xa9059cbb")
    assert len(ce["prestate"]["storage"]) <= 2  # the receiver's balance near 2^256 (+ the sender's)
    # a caller mock may relay
    orig, cand = (ce[side].get("contract", ce[side]) for side in ("original", "candidate"))
    assert orig["success"] is False and orig["output"].startswith("0x4e487b71")  # Panic(0x11)
    assert cand["success"] is True and "storage" in f.kinds


@requires_backend
@pytest.mark.parametrize(
    "rel, key",
    [
        ("vault/NoAccessControl.sol", SET_PAUSED),
        ("vault/IgnoredCallResult.sol", WITHDRAW),
        ("vault/TransferStipend.sol", WITHDRAW),
    ],
)
def test_vault_mutants_are_caught(rel, key):
    r = _vault(rel)
    assert r.functions[key].verdict == Verdict.DIVERGENT
    assert [k for k, f in r.functions.items() if f.verdict == Verdict.DIVERGENT] == [key]


@requires_backend
def test_flattened_vault_is_equivalent_and_identical():
    r = _vault("vault/Flattened.sol")
    assert _statuses(r) == {"L0": "pass", "L1": "pass", "L2": "pass", "L3": "pass", "L4": "pass"}
    assert r.functions["0xd0e30db0"].payable["oracle"] is True  # deposit()
    assert r.functions[SET_PAUSED].payable["oracle"] is False


@pytest.mark.slow
@requires_backend
def test_reentrancy_mutant_needs_more_calls():
    # interaction before effect: divergent only when a reentrant caller withdraws a deposit in
    # [amount, 2 * amount) from a contract holding 2 * amount - about one call in a thousand
    budget = Budget(calls_per_function=3000, sequences=0, l4_search=False)
    caught = [
        _vault(
            "vault/EffectAfterCall.sol",
            budget=Budget(**dict(budget.__dict__, seed=s)),
            selectors=[WITHDRAW],
        ).functions[WITHDRAW]
        for s in (1, 2)
    ]
    assert any(f.verdict == Verdict.DIVERGENT for f in caught)
    ce = next(f.counterexample for f in caught if f.counterexample)
    assert ce["call"]["via"] == "reentrant"


@pytest.mark.slow
@requires_backend
@pytest.mark.skipif(solc_path("0.8.31") is None, reason="solc 0.8.31 not installed")
@pytest.mark.parametrize(
    "settings", [solc.Settings(optimize=False), solc.Settings(via_ir=True)], ids=["noopt", "viaIR"]
)
def test_a_newer_compiler_is_no_false_alarm(settings):
    for rel, name in (("token/Recon.sol", "Recon"), ("token/Restyled.sol", "Restyled")):
        r = _token(
            rel,
            name,
            settings=settings,
            solc_version="0.8.31",
            budget=Budget(calls_per_function=600, l4_search=False),
        )
        assert r.levels["L3"].status == "pass", r.to_text()


# ---------------------------------------------------------------- environment, creation, routing


@requires_backend
def test_routed_selectors_are_checked_through_fallback():
    orig = compile_fixture("misc/Routed.sol", "Routed")
    common = dict(
        contract_name="RoutedRebuilt", abi_hint=orig.abi, layout=orig.storage_layout, budget=QUICK
    )
    src = fixture_source("misc/RoutedRebuilt.sol")
    r = verify(orig.runtime, src, routed_selectors=["0xb4e7d02a"], **common)
    f = r.functions["0xb4e7d02a"]
    assert (f.abi, f.verdict, r.levels["L1"].status, r.levels["L3"].status) == (
        "ROUTED",
        Verdict.EQUIVALENT,
        "pass",
        "pass",
    )
    assert r.levels["L1"].details["routed"] == ["0xb4e7d02a"]
    r = verify(orig.runtime, src, routed_selectors=[0xB4E7D02A], levels=("L0", "L1"), **common)
    assert r.functions["0xb4e7d02a"].verdict == Verdict.ROUTED
    r = verify(orig.runtime, src, levels=("L1",), **common)
    assert r.functions["0xb4e7d02a"].verdict == Verdict.MISSING and r.levels["L1"].status == "fail"


@requires_backend
def test_creations_compare_effects_not_child_code():
    orig = compile_fixture("misc/Factory.sol", "Factory")
    common = dict(contract_name="Factory", abi_hint=orig.abi, budget=QUICK)
    r = verify(
        orig.runtime,
        fixture_source("misc/Factory.sol"),
        settings=solc.Settings(optimize=False),
        **common,
    )
    assert r.levels["L3"].status == "pass"  # other child code, CREATE2 addresses differ: mapped
    r = verify(orig.runtime, fixture_source("misc/FactoryMutant.sol"), **common)
    assert {r.functions[k].verdict for k in ("0x516517ab", "0xa5dcd9a2")} == {Verdict.DIVERGENT}


@requires_pyrevm
def test_gas_and_self_code_without_a_deterministic_backend_are_inconclusive():
    orig = compile_fixture("misc/Env.sol", "Env")
    r = verify(
        orig.runtime,
        fixture_source("misc/Env.sol"),
        contract_name="Env",
        abi_hint=orig.abi,
        backend="pyrevm",
        settings=solc.Settings(optimize=False),
        budget=QUICK,
    )
    assert r.levels["L3"].status == "inconclusive"
    assert {k for k, f in r.functions.items() if f.verdict == Verdict.INCONCLUSIVE} == {
        "0xe2179b8e",
        "0x86b714e2",
        "0xb8c9d365",
    }
    assert r.functions["0xe2179b8e"].reason.startswith("env:")
    # block.timestamp: same environment
    assert r.functions["0xafe29f71"].verdict == Verdict.EQUIVALENT


@requires_pyevm
@pytest.mark.parametrize("backend", ["auto", "pyevm"])
def test_the_deterministic_environment_settles_gas_and_self_code(backend):
    orig = compile_fixture("misc/Env.sol", "Env")
    r = verify(
        orig.runtime,
        fixture_source("misc/Env.sol"),
        contract_name="Env",
        abi_hint=orig.abi,
        backend=backend,
        settings=solc.Settings(optimize=False),
        budget=QUICK,
    )
    assert r.levels["L3"].status == "pass"
    if backend == "auto" and r.backend["bulk"] == "pyrevm":
        assert (
            r.functions["0xe2179b8e"].env_divergences > 0
            and r.levels["L3"].details["env_divergences"] > 0
        )


@requires_backend
def test_immutables_are_filled_in():
    art = compile_fixture("misc/Immutables.sol", "Imm")
    ids = {name: ast_id for ast_id, name in art.immutable_names.items()}
    owner = "0x" + "a1" * 20
    deployed = patch_immutables(
        art.runtime, art.immutable_refs, {ids["owner"]: int(owner, 16), ids["cap"]: 1000}
    )
    common = dict(contract_name="Imm", abi_hint=art.abi, budget=QUICK)
    # values read from the lined-up original
    r = verify(deployed, fixture_source("misc/Immutables.sol"), **common)
    assert _statuses(r)["L3"] == "pass" and _statuses(r)["L4"] == "pass" and not r.warnings[:-1]
    rebuilt = fixture_source("misc/ImmutablesRebuilt.sol")
    r = verify(deployed, rebuilt, **common)
    assert r.levels["L3"].status == "fail" and any("immutables" in w for w in r.warnings)
    r = verify(deployed, rebuilt, immutables={"owner": owner, "cap": 1000}, **common)
    assert r.levels["L3"].status == "pass"


@requires_backend
def test_divergences_needing_dirty_storage_are_labelled():
    orig = compile_fixture("misc/Flag.sol", "Flag")
    r = verify(
        orig.runtime,
        fixture_source("misc/FlagRaw.sol"),
        contract_name="Flag",
        abi_hint=orig.abi,
        layout=orig.storage_layout,
        budget=QUICK,
    )
    f = r.functions["0x890eba68"]  # flag()
    assert f.verdict == Verdict.DIVERGENT and f.counterexample["label"] == "dirty_storage"
    assert r.functions["0x06661abd"].verdict == Verdict.EQUIVALENT  # count()


def _misc(original_rel, contract, candidate_rel, **kw):
    """verify() of a misc fixture's candidate against the compiled original fixture."""
    orig = compile_fixture(original_rel, contract)
    kw.setdefault("budget", FAST)
    report = verify(
        orig.runtime,
        fixture_source(candidate_rel),
        contract_name=contract,
        abi_hint=orig.abi,
        layout=orig.storage_layout,
        **kw,
    )
    return orig, report


def _divergent(report):
    return sorted(k for k, f in report.functions.items() if f.verdict == Verdict.DIVERGENT)


@requires_backend
def test_hard_coded_environment_values_are_divergent():
    # one block environment holds these values, the other does not
    orig, r = _misc("misc/Block.sol", "Block", "misc/BlockConstants.sol", budget=QUICK)
    keys = {"0x" + orig.method_ids[s] for s in ("chain()", "miner()", "random()", "limit()")}
    assert set(_divergent(r)) == keys
    assert r.functions["0x" + orig.method_ids["previous()"]].verdict == Verdict.EQUIVALENT


@requires_backend
def test_an_owner_in_an_unstructured_slot_is_exercised():
    # the hashed slot is seeded from the first call although a failed owner check reveals no
    # storage read on pyrevm
    orig, r = _misc("misc/Unstructured.sol", "Unstructured", "misc/UnstructuredMutant.sol")
    f = r.functions["0x" + orig.method_ids["set(uint256)"]]
    assert f.verdict == Verdict.DIVERGENT and f.original_success > 0


@requires_backend
@pytest.mark.parametrize("rel", ["misc/LedgerSilent.sol", "misc/LedgerInclusive.sol"])
def test_event_mutants_are_caught(rel):
    # a missing event, and a threshold moved by one (an event at exactly 1000)
    orig, r = _misc("misc/Ledger.sol", "Ledger", rel)
    assert _divergent(r) == ["0x" + orig.method_ids["debit(uint256)"]]


@requires_backend
@pytest.mark.parametrize(
    "rel, contract, settings",
    [
        pytest.param("misc/Loop.sol", "Loop", solc.Settings(optimize=False), marks=pytest.mark.slow),
        ("misc/Proxy.sol", "Proxy", solc.Settings(optimize=False)),
        ("misc/Proxy.sol", "Proxy", solc.Settings(via_ir=True)),
        ("misc/Ledger.sol", "Ledger", solc.Settings(via_ir=True)),
    ],
    ids=["gas-hungrier-loops", "proxy-noopt", "proxy-viaIR", "array-push-viaIR"],
)
def test_equivalent_builds_are_no_false_alarm(rel, contract, settings):
    # one side running out of gas, a proxy delegatecalling the mocks, array lengths seeded
    # beyond what viaIR code accepts: none of them is a behavioural divergence
    _, r = _misc(rel, contract, rel, settings=settings)
    assert r.levels["L3"].status == "pass", r.to_text()


@requires_backend
def test_an_original_out_of_a_block_s_gas_is_reported_apart():
    # spin(n) loops n times in the original, the candidate computes the sum in closed form: where
    # the loop exhausts even a whole block's gas, no block can observe what the original computes
    orig = compile_fixture("misc/Loop.sol", "Loop")
    spin = "0x" + orig.method_ids["spin(uint256)"]
    _, r = _misc("misc/Loop.sol", "Loop", "misc/LoopClosed.sol", budget=QUICK, selectors=[spin])
    f = r.functions[spin]
    assert (f.verdict, f.divergences) == (Verdict.INCONCLUSIVE, 0), r.to_text()
    assert f.reason.startswith("env: gas:") and f.gas_divergences > 0 and f.counterexample
    assert r.levels["L3"].status == "inconclusive"
    # the other way round, the candidate cannot do the original's work within a block: divergent
    _, r = _misc("misc/LoopClosed.sol", "Loop", "misc/Loop.sol", budget=QUICK, selectors=[spin])
    assert r.functions[spin].verdict == Verdict.DIVERGENT, r.to_text()


@requires_backend
@pytest.mark.parametrize("seed", [6, 12, 17])
def test_calls_the_original_runs_out_of_gas_on_never_end_the_search(seed):
    # a candidate wrong on every call the loop finishes: however many random arguments make
    # the original run out of a block's gas first, the search goes on and finds the difference
    # (an INCONCLUSIVE 'env: gas' verdict would say there is no other one)
    orig = compile_fixture("misc/Loop.sol", "Loop")
    spin = "0x" + orig.method_ids["spin(uint256)"]
    budget = Budget.quick()
    budget.seed = seed
    _, r = _misc("misc/Loop.sol", "Loop", "misc/LoopClosedWrong.sol", budget=budget, selectors=[spin],
                 levels=("L0", "L3"))
    f = r.functions[spin]
    assert f.verdict == Verdict.DIVERGENT and f.divergences > 0, (f.verdict, f.reason, f.calls)


@requires_backend
def test_solc_versions_are_normalised():
    r = _token("token/Recon.sol", "Recon", solc_version="v0.8.19+commit.7dd6d404", backend="none")
    assert r.levels["L0"].status == "pass" and r.candidate["solc"] == SOLC
    r = _token("token/Recon.sol", "Recon", solc_version="latest", backend="none")
    assert r.levels["L0"].status == "skipped" and "not a solc release" in r.levels["L0"].reason


@requires_backend
def test_stack_too_deep_falls_back_to_via_ir():
    n = 17
    src = (
        "pragma solidity 0.8.19; contract Deep { function f("
        + ", ".join(f"uint256 a{i}" for i in range(n))
        + ") external pure returns (uint256) { return "
        + " + ".join(f"a{i}" for i in range(n))
        + "; } }"
    )
    orig = solc.compile_standard_json(src, solc.Settings(via_ir=True), version=SOLC).artifact()
    r = verify(orig.runtime, src, contract_name="Deep", abi_hint=orig.abi, budget=QUICK)
    assert r.levels["L3"].status == "pass" and r.levels["L4"].status == "pass"
    assert r.candidate["settings"] == "viaIR-opt200" and any("viaIR" in w for w in r.warnings)


# ---------------------------------------------------------------- inputs, restrictions, determinism


@requires_solc
def test_l1_finds_the_constants_the_optimiser_does_not_push():
    # computed error selectors, and an event topic stored after the code: the original declares
    # them although no PUSH carries them (the hint names the functions only, as a decompiler's)
    orig = compile_fixture("misc/Constants.sol", "Constants")
    pushed = set(push_values(orig.runtime)) | set(shifted_push_values(orig.runtime))
    topic = int.from_bytes(keccak(text="Moved(address,uint256)"), "big")
    selectors = [int.from_bytes(keccak(text=f"Denied{n}(address)")[:4], "big")
                 for n in (3253, 6680, 23516)]
    assert topic not in pushed and not any(s in pushed or s << 224 in pushed for s in selectors)
    hint = {"0x" + orig.method_ids["f(uint256)"]: "f(uint256)"}
    r = verify(orig.runtime, fixture_source("misc/Constants.sol"), contract_name="Constants",
               abi_hint=hint, levels=("L0", "L1"), backend="none")
    assert r.levels["L1"].status == "pass", r.levels["L1"].reason


@requires_solc
def test_selectors_a_fallback_tests_itself_are_no_entry_points():
    # an admin-routed proxy: its fallback compares msg.sig with a PUSH4 for the admin only; the
    # decompiler finds no function (an empty hint), and the scan's selector is only reported
    name = "DispatchGuardedProxy"
    source = (REPO_FIXTURES / "sources" / "DispatchGuarded.sol").read_text()
    r = verify(original_runtime(name), source, contract_name=name, abi_hint={},
               levels=("L0", "L1"), backend="none")
    l1 = r.levels["L1"]
    assert l1.status == "pass" and l1.details["scan_only"] == ["0x3659cfe6"], l1.reason


@requires_backend
def test_without_hints_the_dispatcher_is_scanned():
    r = verify(
        original_runtime("SimpleToken"),
        fixture_source("token/Recon.sol"),
        contract_name="Recon",
        budget=QUICK,
    )
    assert r.levels["L1"].details["source"] == "dispatcher scan" and r.levels["L1"].status == "pass"
    assert r.levels["L2"].status == "skipped" and r.levels["L3"].status == "pass"
    assert any("no reference layout" in w for w in r.warnings)


@requires_backend
def test_legacy_decompiler_hints_are_accepted():
    stor_defs = [
        ["def", "balanceOf", 0, ["mapping", 256]],
        ["def", "totalSupply", 1, ["mask", 256, 0]],
    ]
    functions = [
        {"hash": TRANSFER, "abi_name": "transfer(address,uint256)", "payable": True, "params": {}},
        {"hash": BALANCE_OF, "abi_name": "balanceOf(address)", "payable": True, "params": {}},
        {"hash": TOTAL_SUPPLY, "abi_name": "totalSupply()", "payable": True, "params": {}},
        {"hash": "_fallback", "abi_name": "_fallback(?)", "payable": True},
    ]
    r = verify(
        original_runtime("SimpleToken"),
        fixture_source("token/Recon.sol"),
        contract_name="Recon",
        layout=stor_defs,
        abi_hint=functions,
        budget=QUICK,
    )
    # the hint's payable flags are wrong (the callvalue check is hoisted): the oracle overrides them
    assert _statuses(r) == {"L0": "pass", "L1": "pass", "L2": "pass", "L3": "pass", "L4": "pass"}
    assert r.functions[TRANSFER].payable == {"original": True, "candidate": False, "oracle": False}


@requires_backend
def test_selectors_restrict_l3():
    r = _token("token/OffByOne.sol", "OffByOne", selectors=[BALANCE_OF, "fallback"], budget=QUICK)
    assert (
        r.functions[BALANCE_OF].verdict == Verdict.EQUIVALENT
        and r.functions["fallback"].calls == 20
    )
    assert (
        r.functions[TRANSFER].verdict == Verdict.SKIPPED
        and r.functions[TRANSFER].reason == "not selected"
    )
    assert r.levels["L3"].status == "pass" and r.sequences == {}


def _without_timings(obj):
    if isinstance(obj, dict):
        return {
            k: _without_timings(v)
            for k, v in obj.items()
            if k not in ("elapsed", "executions_per_second")
        }
    if isinstance(obj, list):
        return [_without_timings(v) for v in obj]
    return obj


@requires_backend
def test_same_seed_same_report():
    a = _without_timings(_token_report("token/OffByOne.sol", "OffByOne").to_json())
    b = _without_timings(_token("token/OffByOne.sol", "OffByOne").to_json())
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


_REPORT_SCRIPT = """
import json, sys
sys.path.insert(0, sys.argv[1])
from verify_helpers import original_artifact, original_runtime, fixture_source
from scobelix.verify import Budget, verify
ref = original_artifact("SimpleToken")
r = verify(original_runtime("SimpleToken"), fixture_source("token/AliasBug.sol"),
           contract_name="AliasBug", layout=ref.storage_layout, abi_hint=ref.abi, levels=("L3",),
           budget=Budget(calls_per_function=60, probe_calls=5, sequences=3, coverage_calls=8))
print(json.dumps(r.to_json(), sort_keys=True))
"""


@requires_backend
def test_reports_do_not_depend_on_the_process():
    # set iteration order changes with PYTHONHASHSEED: it must never reach the random streams
    import os
    import subprocess
    import sys
    from pathlib import Path

    here = str(Path(__file__).parent)
    outs = []
    for seed in ("1", "2"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        p = subprocess.run(
            [sys.executable, "-c", _REPORT_SCRIPT, here],
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
        )
        assert p.returncode == 0, p.stderr[-2000:]
        outs.append(_without_timings(json.loads(p.stdout.strip().splitlines()[-1])))
    assert outs[0] == outs[1]


@requires_backend
def test_restricting_selectors_reproduces_the_full_run():
    full = _token_report("token/OffByOne.sol", "OffByOne").functions[TRANSFER]
    part = _token("token/OffByOne.sol", "OffByOne", selectors=[TRANSFER]).functions[TRANSFER]
    for attr in (
        "verdict",
        "calls",
        "original_success",
        "divergences",
        "coverage",
        "counterexample",
    ):
        assert getattr(part, attr) == getattr(full, attr), attr
    assert part.sequence_divergences == 0  # no stateful sequences in a restricted run


@requires_backend
def test_l1_only_still_measures_payability():
    r = _token("token/PayableTransfer.sol", "PayableTransfer", levels=("L0", "L1"), budget=QUICK)
    assert r.levels["L1"].status == "fail" and r.levels["L3"].reason == "not requested"
    assert (
        r.functions[TRANSFER].payable["oracle"] is False
        and r.functions[TRANSFER].verdict == Verdict.SKIPPED
    )


# ---------------------------------------------------------------- degradation


def test_no_backend_skips_l3_only(monkeypatch):
    monkeypatch.setattr(core, "available_backends", lambda: [])
    r = _token("token/Recon.sol", "Recon", budget=QUICK)
    assert _statuses(r) == {"L0": "pass", "L1": "pass", "L2": "pass", "L3": "skipped", "L4": "pass"}
    assert "scobelix[verify]" in r.levels["L3"].reason
    assert {f.verdict for f in r.functions.values()} == {Verdict.SKIPPED}
    assert r.passed


def test_backend_none_and_unknown_levels():
    r = _token("token/Recon.sol", "Recon", backend="none", levels=("L1", "L3"))
    assert r.levels["L3"].status == "skipped" and r.levels["L2"].reason == "not requested"
    with pytest.raises(ValueError):
        _token("token/Recon.sol", "Recon", levels=("L5",))
    with pytest.raises(ValueError):
        _token("token/Recon.sol", "Recon", backend="evmone")


def test_no_compiler_skips_everything(monkeypatch):
    monkeypatch.setattr(
        core,
        "solc_for_source",
        lambda *a, **k: (_ for _ in ()).throw(solc.SolcNotFound("none here")),
    )
    r = _token("token/Recon.sol", "Recon")
    assert r.levels["L0"].status == "skipped" and r.levels["L0"].reason == "none here"
    assert {r.levels[k].reason for k in ("L1", "L2", "L3", "L4")} == {"no compiler"}
    assert not r.passed and r.functions == {}


def test_compile_errors_fail_l0():
    r = verify(
        original_runtime("SimpleToken"),
        "pragma solidity ^0.8.0; contract X { function f() { } }",
        contract_name="X",
        budget=FAST,
    )
    assert r.levels["L0"].status == "fail" and r.levels["L0"].details["errors"]
    assert r.levels["L3"].reason == "L0 failed"


def test_unknown_contract_is_an_l0_error():
    r = _token("token/Recon.sol", "NotThere", backend="none")
    assert r.levels["L0"].status == "error" and "not found" in r.levels["L0"].reason


def test_quick_budget_is_small():
    quick, default = Budget.quick(), Budget()
    assert quick.calls_per_function < default.calls_per_function and not quick.l4_search
    r = _token(
        "token/Recon.sol", "Recon", budget=quick, levels=("L0", "L3"), selectors=[TOTAL_SUPPLY]
    )
    assert r.functions[TOTAL_SUPPLY].calls in (0, quick.calls_per_function)


def test_budget_from_a_dict():
    r = _token(
        "token/Recon.sol",
        "Recon",
        budget={"calls_per_function": 5, "sequences": 0, "probe_calls": 2, "l4_search": False},
        backend="none",
    )
    assert r.levels["L0"].status == "pass"

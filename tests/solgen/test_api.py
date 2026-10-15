"""The public entry point `scobelix.solgen.generate_solidity`: its inputs
(a decompilation, its JSON alone), its result (text, confidence, warnings,
per-function table), the static guards of the default level, the seam a
verification loop regenerates through, and what happens when the tools a
verification needs are missing."""

import json
import logging
import sys

import pytest
from conftest import backend_or_skip, compile_or_fail, decompiled, fixture_hex, installed, solc_or_skip

from scobelix.solgen import SolgenResult, generate_solidity, validate
from scobelix.solgen import lift, pipeline
from scobelix.solgen.v2 import CONFIDENCE_LEVELS, RISK_FLAGS, Generator, derive_confidence, generate

TRANSFER = "0xa9059cbb"


class JsonOnly:
    """A decompilation of which only the JSON form is left."""

    def __init__(self, js):
        self.json = js


class _Function:
    def __init__(self, trace, payable):
        self.orig_trace = trace
        self.payable = payable


class Edited:
    """The decompilation `d` with the trace of one function edited."""

    def __init__(self, d, key, edit):
        self.json, self.metadata, self.dispatcher, self.bytecode = d.json, d.metadata, d.dispatcher, d.bytecode
        self.functions = {
            k: _Function(edit(f.orig_trace) if k == key else f.orig_trace, f.payable) for k, f in d.functions.items()
        }


def _with_unknown_statement(trace):
    return [("statement_of_no_known_kind", 1)] + list(trace)


def _decompile(code, only=None):
    """A decompilation made for the test (of `only` that function when given)."""
    from scobelix.decompiler import decompile_bytecode

    logging.disable(logging.CRITICAL)
    try:
        return decompile_bytecode(code, only)
    finally:
        logging.disable(logging.NOTSET)


def _check_shape(r):
    assert isinstance(r, SolgenResult)
    assert isinstance(r.solidity, str) and "contract Decompiled" in r.solidity
    assert isinstance(r.confidence, dict) and set(r.confidence) == set(r.functions)
    assert set(r.confidence.values()) <= set(CONFIDENCE_LEVELS)
    assert isinstance(r.warnings, list) and all(isinstance(w, str) for w in r.warnings)
    assert r.target_solc.startswith("0.8.")
    for key, f in r.functions.items():
        assert f["confidence"] == r.confidence[key]
        assert f["tier"] in ("exact", "partial", "idiomatic")
        assert isinstance(f["disabled_passes"], list) and (f["tier"] == "partial") == bool(
            f["passes"] and f["disabled_passes"])
    json.dumps(r.to_json())  # everything public is JSON data


# ---------------------------------------------------------------- inputs


def test_a_decompilation_alone_is_enough():
    r = generate_solidity(decompiled("SimpleToken"))
    _check_shape(r)
    assert r.idiom_level == "full"
    assert r.original_compiler == "solc 0.8.19"
    assert r.functions[TRANSFER]["signature"] == "transfer(address,uint256)"
    assert r.functions[TRANSFER]["tier"] == "idiomatic" and r.functions[TRANSFER]["passes"]
    assert [v["name"] for v in r.storage_layout]  # the state variables were declared
    # the declarations are compiled to check their positions when the target compiler is there
    unchecked = [] if r.target_solc in installed() else [
        "storage layout not compiled (no solc): declarations unchecked"]
    assert r.warnings == unchecked


def test_nothing_is_presented_as_verified_without_a_verification():
    r = generate_solidity(decompiled("SimpleToken"))
    assert r.verification is None and r.verification_json() is None
    assert {f["verdict"] for f in r.functions.values()} == {"unverified"}
    assert "EQUIVALENT" not in r.solidity.split("contract Decompiled")[1]
    assert "verification:" not in r.solidity
    # the text read alone says so
    assert "//   verification      : not run (" in r.solidity.split("// Legend")[0]
    tags = [line for line in r.solidity.split("\n") if "@custom:scobelix tier=" in line]
    assert tags and all("verdict=unverified" in line for line in tags)
    # nothing that was not checked is rated "high", at either level
    assert "high" not in r.confidence.values()
    exact = generate_solidity(decompiled("SimpleToken"), idiom_level="exact")
    assert {f["tier"] for f in exact.functions.values()} == {"exact"}
    assert set(exact.confidence.values()) == {"medium"}


def test_arguments_after_the_decompilation_are_keyword_only():
    with pytest.raises(TypeError):
        generate_solidity(decompiled("SimpleToken"), True)


@pytest.mark.parametrize("arguments", [
    {"idiom_level": "fancy"},
    {"target_solc": "latest"},
    {"target_solc": "0.8"},
    {"contract_name": "contract"},
    {"contract_name": "not a name"},
])
def test_unusable_arguments_are_refused(arguments):
    with pytest.raises(ValueError):
        generate_solidity(decompiled("SimpleToken"), **arguments)


def test_target_compiler_level_and_name_are_honoured():
    r = generate_solidity(decompiled("SimpleToken"), target_solc="0.8.21", idiom_level="exact", contract_name="Token")
    assert r.target_solc == "0.8.21" and r.idiom_level == "exact" and r.contract_name == "Token"
    assert "target compiler   : solc 0.8.21" in r.solidity
    assert "contract Token {" in r.solidity
    assert {f["tier"] for f in r.functions.values()} == {"exact"}
    assert {f["passes"] == [] for f in r.functions.values()} == {True}


def test_a_target_too_old_for_the_text_is_reported():
    r = generate_solidity(decompiled("SimpleToken"), target_solc="0.8.0")
    assert r.target_solc == "0.8.0"
    assert any("does not compile it" in w for w in r.warnings)


@pytest.mark.parametrize("wrap", [JsonOnly, dict], ids=["json_only_decompilation", "bare_json_dict"])
def test_the_json_form_alone_is_accepted_degraded(wrap):
    js = decompiled("SimpleToken").json
    r = generate_solidity(wrap(js))
    _check_shape(r)
    assert set(r.functions) == set(generate_solidity(decompiled("SimpleToken")).functions)
    assert any("degraded" in w for w in r.warnings)
    # the JSON traces lost information: nothing is rewritten on top of them
    for f in r.functions.values():
        assert "json_trace" in f["flags"] and "json_trace" in f["guards"]
        assert f["tier"] == "exact" and f["passes"] == [] and f["confidence"] != "high"
    assert r.storage_layout == []  # and no state variable is declared from them
    exact = generate_solidity(wrap(js), idiom_level="exact")
    assert r.solidity.replace("idiom level       : full", "idiom level       : exact").replace(
        "reconstructed tier=full", "reconstructed tier=exact").replace(" guards=json_trace", "") == exact.solidity
    compile_or_fail(r.solidity, "0.8.19")


def test_the_two_json_forms_give_the_same_text():
    js = decompiled("Vault").json
    assert generate_solidity(JsonOnly(js)).solidity == generate_solidity(js).solidity


def test_a_function_the_decompiler_failed_on_is_a_visible_stub():
    js = {"stor_defs": [], "functions": [], "problems": {"0xdeadbeef": "someFunction(uint256)"}}
    r = generate_solidity(JsonOnly(js))
    _check_shape(r)
    assert r.confidence == {"0xdeadbeef": "none"}
    assert "problem" in r.functions["0xdeadbeef"]["flags"]
    assert "0xdeadbeef" in r.solidity and "the decompiler failed on this function" in r.solidity
    compile_or_fail(r.solidity, "0.8.19")
    # and the reader of the warnings alone learns it too, at both levels
    for level in ("full", "exact"):
        warnings = generate_solidity(JsonOnly(js), idiom_level=level).warnings
        assert [w for w in warnings if "the decompiler failed on 1 function(s)" in w and "0xdeadbeef" in w]


def test_an_empty_decompilation_gives_an_empty_contract():
    r = generate_solidity({})
    _check_shape(r)
    assert r.functions == {} and r.confidence == {}
    assert "no function in the decompilation: the text is an empty contract" in r.warnings
    compile_or_fail(r.solidity, "0.8.19")
    # so does the decompilation of no code at all
    r = generate_solidity(_decompile(""))
    _check_shape(r)
    assert r.functions == {} and any("empty contract" in w for w in r.warnings)


def test_functions_the_decompilation_leaves_out_are_reported_not_stubbed():
    # a decompilation of one function only: the dispatcher still lists the others
    d = _decompile(fixture_hex("SimpleToken"), "transfer")
    assert set(d.functions) == {TRANSFER} and not d.json["problems"]
    r = generate_solidity(d)
    _check_shape(r)
    assert set(r.functions) == {TRANSFER} and r.functions[TRANSFER]["tier"] == "idiomatic"
    body = r.solidity.split("contract Decompiled")[1]
    assert body.count("function ") == 1 and "function transfer(" in body
    assert "the decompiler failed" not in r.solidity  # it did not: it was not asked
    left_out = [w for w in r.warnings if "not in the decompilation" in w]
    assert len(left_out) == 1 and left_out[0].startswith("2 entry point(s)")
    assert "0x18160ddd" in left_out[0] and "0x70a08231" in left_out[0]
    header = r.solidity.split("// Legend")[0]
    assert "not decompiled    : 2 entry point(s) of the original are absent from this text" in header
    assert "0x18160ddd" in header and "0x70a08231" in header
    # a verification is told about them: the interface of the text lacks them
    assert set(r.abi_hint) == {TRANSFER, "0x18160ddd", "0x70a08231"} and r.abi_hint["0x18160ddd"] == {}
    compile_or_fail(r.solidity, r.target_solc)
    # a complete decompilation says nothing of the kind
    whole = generate_solidity(decompiled("SimpleToken"))
    assert "not decompiled" not in whole.solidity and not [w for w in whole.warnings if "left out" in w]


def test_the_json_form_reports_what_it_leaves_out_too():
    js = dict(decompiled("DispatchBoth").json)
    assert js["dispatcher"]["fallback"]["present"] and js["dispatcher"]["receive"]
    js["functions"] = [f for f in js["functions"] if f["hash"].startswith("0x")][:1]
    kept = js["functions"][0]["hash"]
    r = generate_solidity(js)
    _check_shape(r)
    assert set(r.functions) == {kept}
    left_out = [w for w in r.warnings if "not in the decompilation" in w]
    assert len(left_out) == 1 and "_fallback" in left_out[0] and "_receive" in left_out[0]
    body = r.solidity.split("contract Decompiled")[1]
    assert "fallback()" not in body and "receive()" not in body
    compile_or_fail(r.solidity, "0.8.19")


@pytest.mark.parametrize("damage", [
    {"dispatcher": []},
    {"dispatcher": 7},
    {"dispatcher": {"selectors": 3, "fallback": [], "receive": "x", "exits": {}, "duplicates": [1]}},
    {"metadata": [1]},
    {"metadata": {"compiler": "solc", "version": 8}},
    {"metadata": {"compiler": "solc", "version_range": ["0.4.0"]}},
    {"metadata": {"compiler": ["solc"], "version_range": 5}},
    {"problems": 3},
    {"problems": ["0x12345678"]},
    {"stor_defs": 2},
    {"stor_defs": [None, {}, ["def"], 1.5]},
    {"functions": 1.5},
    {"functions": [[], 7, {"hash": 5}, {"hash": "0x12345678", "params": [], "trace": None}]},
], ids=lambda damage: json.dumps(damage)[:60])
def test_json_parts_of_the_wrong_type_are_read_as_missing(damage):
    r = generate_solidity(dict(decompiled("SimpleToken").json, **damage))
    _check_shape(r)
    compile_or_fail(r.solidity, "0.8.19")


def test_a_default_exit_that_halts_is_a_fallback_of_its_own():
    # INVALID as the whole code: not the revert solc generates when a contract has no fallback
    r = generate_solidity(_decompile("0xfe"))
    _check_shape(r)
    body = r.solidity.split("contract Decompiled")[1]
    assert "fallback() external" in body and "invalid()" in body
    compile_or_fail(r.solidity, "0.8.19")
    # that revert, and it only, leaves the text without a fallback
    r = generate_solidity(_decompile("0x60006000fd"))
    _check_shape(r)
    assert "fallback()" not in r.solidity.split("contract Decompiled")[1]
    compile_or_fail(r.solidity, "0.8.19")


def test_a_default_exit_that_halts_verifies():
    solc_or_skip("0.8.19")
    backend_or_skip()
    from scobelix.verify import Budget

    r = generate_solidity(_decompile("0xfe"), verify=True, target_solc="0.8.19", budget=Budget.quick())
    assert r.verification.levels["L3"].status == "pass"
    assert r.functions["_fallback"]["verdict"] in ("EQUIVALENT", "EQUIVALENT_REVERTS_ONLY")
    assert not [w for w in r.warnings if w.startswith("verification")]


@pytest.mark.parametrize("name", ["Eip1967Proxy", "SumLoop", "EventsEmitter", "Vault"])
def test_the_default_output_compiles(name):
    r = generate_solidity(decompiled(name))
    _check_shape(r)
    solc_or_skip(r.target_solc)
    compile_or_fail(r.solidity, r.target_solc)
    v = validate(r)
    assert v.status == "valid" and v.solc_version == r.target_solc


# ---------------------------------------------------------------- static guards


def test_a_function_with_a_risk_flag_keeps_the_exact_form():
    d = decompiled("SimpleToken")
    plain = generate_solidity(d)
    marked = Edited(d, TRANSFER, _with_unknown_statement)
    r = generate_solidity(marked)
    f = r.functions[TRANSFER]
    assert "unstructured" in f["flags"] and f["guards"] == ["unstructured"]
    assert f["tier"] == "exact" and f["passes"] == [] and f["confidence"] == "low"
    assert "guards=unstructured" in r.solidity
    assert any("static guards" in w and TRANSFER in w for w in r.warnings)
    assert any("could not be written as Solidity" in w and TRANSFER in w for w in r.warnings)
    # the other functions are written as without the marked one
    for key, other in r.functions.items():
        if key != TRANSFER:
            assert (other["tier"], other["passes"], other["guards"]) == (
                plain.functions[key]["tier"], plain.functions[key]["passes"], [])
    compile_or_fail(r.solidity, r.target_solc)
    # the guard is what kept it exact: without it the passes rewrite the function
    unguarded = generate(marked, idiom_level="full", static_guards=False)
    assert unguarded.functions[TRANSFER]["passes"] and unguarded.functions[TRANSFER]["guards"] == []


def test_the_exact_level_has_nothing_to_guard():
    r = generate_solidity(Edited(decompiled("SimpleToken"), TRANSFER, _with_unknown_statement), idiom_level="exact")
    assert r.functions[TRANSFER]["guards"] == [] and "unstructured" in r.functions[TRANSFER]["flags"]
    assert not any("static guards" in w for w in r.warnings)
    # the code left out is still named to the reader of the warnings
    assert any("could not be written as Solidity" in w and TRANSFER in w for w in r.warnings)
    assert not any("could not be written" in w for w in generate_solidity(
        decompiled("SimpleToken"), idiom_level="exact").warnings)


def test_a_risk_flag_only_the_idiomatic_form_shows_is_guarded_too(monkeypatch):
    storage_pass = dict(pipeline.available_passes("full"))["storage"]
    real_run = storage_pass.run
    lifts = []
    real_lift = lift.lift_function

    def run(fn, ctx):
        new = real_run(fn, ctx)
        return new.with_body(new.body, ("engine:marker_of_the_test",)) if fn.key == TRANSFER else new

    def counted(key, *args, **kwargs):
        lifts.append(key)
        return real_lift(key, *args, **kwargs)

    monkeypatch.setattr(storage_pass, "run", run)
    monkeypatch.setattr(lift, "lift_function", counted)
    d = decompiled("SimpleToken")
    r = generate_solidity(d)
    f = r.functions[TRANSFER]
    assert f["tier"] == "exact" and f["passes"] == [] and f["guards"] == ["engine:marker_of_the_test"]
    assert f["confidence"] == "low"
    assert sorted(lifts) == sorted(d.functions)  # generated twice, lifted once
    assert all(o["guards"] == [] for k, o in r.functions.items() if k != TRANSFER)


def test_every_engine_marker_is_a_risk_flag():
    from scobelix.solgen.v2 import risk_flags

    assert risk_flags({"engine:anything", "arr_expanded", "unstructured", "abi:legacy_memory_copy"}) == (
        "engine:anything", "unstructured")
    assert {"problem", "unstructured", "json_trace"} <= RISK_FLAGS


# ---------------------------------------------------------------- the regeneration seam


def test_regeneration_switches_passes_off_without_lifting_again(monkeypatch):
    d = decompiled("SimpleToken")
    g = Generator(d, idiom_level="full")
    assert g.risky == {}
    first = g.regenerate()
    assert first.solidity == generate_solidity(d).solidity

    def no_lift(*args, **kwargs):
        raise AssertionError("regeneration lifted a function again")

    monkeypatch.setattr(lift, "lift_function", no_lift)
    exact = g.regenerate({TRANSFER: set(pipeline.PASS_ORDER)})
    assert exact.functions[TRANSFER]["tier"] == "exact" and exact.functions[TRANSFER]["passes"] == []
    for key, f in exact.functions.items():
        if key != TRANSFER:
            assert (f["tier"], f["passes"]) == (first.functions[key]["tier"], first.functions[key]["passes"])
    one_off = g.regenerate({TRANSFER: {"compound"}})
    assert "compound" not in one_off.functions[TRANSFER]["passes"]
    assert set(one_off.functions[TRANSFER]["passes"]) == set(first.functions[TRANSFER]["passes"]) - {"compound"}
    # a generation leaves nothing behind in the generator
    assert g.regenerate().solidity == first.solidity
    assert g.regenerate({"*": set(pipeline.PASS_ORDER)}).functions[TRANSFER]["tier"] == "exact"
    for r in (exact, one_off):
        compile_or_fail(r.solidity, r.target_solc)


def test_regenerated_variants_can_be_verified_one_function_at_a_time():
    solc_or_skip("0.8.19")
    backend_or_skip()
    from scobelix.verify import Budget

    g = Generator(decompiled("SimpleToken"), "0.8.19", "full")
    r = g.regenerate({TRANSFER: set(pipeline.PASS_ORDER)})
    g.verify(r, Budget.quick(), selectors=[TRANSFER])
    assert r.functions[TRANSFER]["verdict"] == "EQUIVALENT" and r.confidence[TRANSFER] == "high"
    assert r.functions["0x70a08231"]["verdict"] == "SKIPPED"
    assert r.confidence["0x70a08231"] == "medium"  # not checked: rated as unverified


# ---------------------------------------------------------------- confidence


@pytest.mark.parametrize("entry, expected", [
    ({"tier": "exact", "flags": [], "verdict": "unverified"}, "medium"),  # exact, yet not observed
    ({"tier": "exact", "flags": ["arr_expanded", "codecopy_blob"], "verdict": "unverified"}, "medium"),
    ({"tier": "idiomatic", "flags": [], "verdict": "unverified"}, "medium"),
    ({"tier": "exact", "flags": ["abi:short_calldata_check"], "verdict": "unverified"}, "medium"),
    ({"tier": "exact", "flags": ["json_trace"], "guards": ["json_trace"], "verdict": "unverified"}, "medium"),
    ({"tier": "exact", "flags": ["unstructured"], "verdict": "unverified"}, "low"),
    ({"tier": "exact", "flags": [], "guards": ["engine:dangling_var"], "verdict": "unverified"}, "low"),
    ({"tier": "idiomatic", "flags": ["engine:packed_store_suspect"], "verdict": "unverified"}, "low"),
    ({"tier": "exact", "flags": ["problem", "unstructured"], "verdict": "unverified"}, "none"),
    ({"tier": "exact", "flags": ["problem", "unstructured"], "verdict": "EQUIVALENT"}, "none"),
    ({"tier": "idiomatic", "flags": [], "verdict": "EQUIVALENT"}, "high"),
    ({"tier": "idiomatic", "flags": ["abi:legacy_memory_copy"], "verdict": "EQUIVALENT"}, "high"),
    ({"tier": "exact", "flags": ["unstructured"], "verdict": "EQUIVALENT"}, "medium"),
    ({"tier": "exact", "flags": [], "verdict": "EQUIVALENT_REVERTS_ONLY"}, "medium"),
    ({"tier": "exact", "flags": [], "verdict": "INCONCLUSIVE"}, "medium"),
    ({"tier": "exact", "flags": [], "verdict": "DIVERGENT"}, "low"),
    ({"tier": "idiomatic", "flags": [], "verdict": "MISSING"}, "low"),
    ({"tier": "exact", "flags": [], "verdict": "EXTRA"}, "low"),
    ({"tier": "exact", "flags": [], "verdict": "EQUIVALENT"}, "high"),
    ({"tier": "exact", "flags": ["arr_expanded"], "verdict": "EQUIVALENT"}, "high"),
    ({"tier": "exact", "flags": [], "guards": ["engine:dangling_var"], "verdict": "EQUIVALENT"}, "medium"),
    ({"tier": "exact", "flags": [], "verdict": "SKIPPED"}, "medium"),
    ({"tier": "idiomatic", "flags": [], "verdict": "ROUTED"}, "medium"),
    ({"tier": "exact", "flags": ["unstructured"], "verdict": "SKIPPED"}, "low"),
])
def test_confidence_rule(entry, expected):
    assert derive_confidence(entry) == expected


# ---------------------------------------------------------------- verification


def test_verification_fills_verdicts_confidence_and_header():
    solc_or_skip("0.8.19")
    backend_or_skip()
    from scobelix.verify import Budget

    r = generate_solidity(decompiled("SimpleToken"), verify=True, budget=Budget.quick())
    _check_shape(r)
    assert r.verification is not None and r.verification.passed
    # every level in the header, L2 (the state variables where they were inferred) and L4 (the bytecode) too
    assert "verification: L0=pass  L1=pass  L2=pass  L3=pass  L4=" in r.solidity
    assert r.functions[TRANSFER]["tier"] == "idiomatic" and r.functions[TRANSFER]["disabled_passes"] == []
    assert r.functions[TRANSFER]["verdict"] == "EQUIVALENT" and r.confidence[TRANSFER] == "high"
    assert "verdict=EQUIVALENT" in r.solidity and "verdict=unverified" not in r.solidity
    header = r.solidity.split("// Legend")[0].split("\n")
    assert not [line for line in header if "not run" in line]
    row = [line for line in header if TRANSFER in line]  # the table: one line per function checked
    assert len(row) == 1 and "EQUIVALENT" in row[0] and row[0].endswith("calls  transfer(address,uint256)")
    assert r.functions[TRANSFER]["calls"] == r.verification.functions[TRANSFER].calls > 0
    report = r.verification_json()
    assert report["passed"] is True and set(report["levels"]) == {"L0", "L1", "L2", "L3", "L4"}
    assert report["search"]["final_check"] is True and report["search"]["budget_exhausted"] is False
    assert not [w for w in r.warnings if w.startswith("verification")]


def test_a_function_found_divergent_does_not_read_as_fine():
    solc_or_skip("0.8.19")
    backend_or_skip()
    from scobelix.verify import Budget

    # transfer() rewritten into a function that does nothing: not what the bytecode does
    changed = Edited(decompiled("SimpleToken"), TRANSFER, lambda trace: [("stop",)])
    r = generate_solidity(changed, verify=True, target_solc="0.8.19", budget=Budget.quick())
    _check_shape(r)
    assert r.functions[TRANSFER]["verdict"] == "DIVERGENT" and r.confidence[TRANSFER] == "low"
    assert r.functions[TRANSFER]["counterexample"]
    assert r.verification.levels["L3"].status == "fail" and r.verification.passed is False
    # the warnings, the header and the function itself say so
    assert [w for w in r.warnings if w.startswith("verification L3 fail") and TRANSFER in w]
    header = r.solidity.split("// Legend")[0]
    assert "verification: L0=pass" in header and "L3=fail" in header
    assert [line for line in header.split("\n") if "NOT EQUIVALENT: on 1 entry point(s)" in line and TRANSFER in line]
    lines = r.solidity.split("\n")
    at = next(i for i, line in enumerate(lines) if f"@notice selector {TRANSFER}" in line)
    assert "@dev NOT EQUIVALENT" in lines[at + 1] and "DIVERGENT" in lines[at + 1]
    # the call that shows it, shortened
    assert lines[at + 2].strip().startswith(f"/// @dev counterexample: calldata {TRANSFER}")
    # no pass can repair a loss of the decompilation: the exact form, with its verdict
    assert "tier=exact verdict=DIVERGENT" in lines[at + 3] and r.functions[TRANSFER]["tier"] == "exact"
    assert r.solidity.count("@dev NOT EQUIVALENT") == 1  # the functions that agree carry no such line
    compile_or_fail(r.solidity, "0.8.19")


def test_verifying_a_result_again_replaces_its_verification_warnings():
    solc_or_skip("0.8.19")
    backend_or_skip()
    from scobelix.verify import Budget

    g = Generator(Edited(decompiled("SimpleToken"), TRANSFER, lambda trace: [("stop",)]), "0.8.19", "full")
    r = g.regenerate()
    before = list(r.warnings)
    g.verify(r, Budget.quick())
    first = list(r.warnings)
    assert len([w for w in first if w.startswith("verification L3 fail")]) == 1
    g.verify(r, Budget.quick())
    assert r.warnings == first and first[:len(before)] == before
    assert r.solidity.count("@dev NOT EQUIVALENT") == 1
    # one run that annotates, no search: no "loop:" line, which the legend names as the sign of the search
    assert "//   loop:" not in r.solidity and "The verification loop (a 'loop:' line above)" in r.solidity


def test_a_text_only_the_ir_pipeline_compiles_is_reported(monkeypatch):
    solc_or_skip("0.8.19")
    import scobelix.verify as verify_package

    real = verify_package.verify

    def out_of_stack(*args, **kwargs):
        # what the verifier records when it had to compile again with the IR pipeline
        report = real(*args, **kwargs)
        report.warnings.append("stack too deep with the legacy pipeline: compiled with viaIR")
        return report

    monkeypatch.setattr(verify_package, "verify", out_of_stack)
    budget = {"calls_per_function": 2, "probe_calls": 2, "sequences": 0, "coverage_calls": 1, "l4_search": False}
    r = generate_solidity(decompiled("SimpleToken"), verify=True, target_solc="0.8.19", budget=budget)
    assert [w for w in r.warnings if w.startswith("verification L0") and "--via-ir --optimize only" in w]
    monkeypatch.setattr(verify_package, "verify", real)
    r = generate_solidity(decompiled("SimpleToken"), verify=True, target_solc="0.8.19", budget=budget)
    assert not [w for w in r.warnings if "--via-ir" in w]


def test_budget_may_be_given_as_plain_fields():
    solc_or_skip("0.8.19")
    backend_or_skip()
    budget = {"calls_per_function": 8, "probe_calls": 4, "sequences": 1, "sequence_length": 2, "coverage_calls": 2,
              "l4_search": False}
    r = generate_solidity(decompiled("SimpleToken"), verify=True, budget=budget)
    assert r.verification is not None and r.verification.functions[TRANSFER].calls <= 8 + 2


def _no_solc(monkeypatch):
    from scobelix.verify import solc

    monkeypatch.setattr(solc, "installed_solcs", lambda extra_dirs=(): {})
    monkeypatch.delenv(solc.DOWNLOAD_ENV, raising=False)


def test_verification_without_a_compiler_leaves_a_warning(monkeypatch):
    _no_solc(monkeypatch)
    plain = generate_solidity(decompiled("SimpleToken"))
    r = generate_solidity(decompiled("SimpleToken"), verify=True)
    _check_shape(r)
    assert [w for w in r.warnings if w.startswith("verification L0 skipped") and "not installed" in w]
    # nothing could be run: the rewritten functions are written in exact form, and a warning says so
    exact = [w for w in r.warnings if w.startswith("verification: 3 function(s) could not be run") and TRANSFER in w]
    assert exact and len([w for w in r.warnings if w.startswith("verification")]) == 2
    assert {f["tier"] for f in r.functions.values()} == {"exact"}
    assert "off=abi,storage,reverts,arith,compound" in r.solidity
    assert {f["verdict"] for f in r.functions.values()} == {"unverified"}
    assert r.confidence == plain.confidence
    assert r.verification_json()["levels"]["L0"]["status"] == "skipped"
    assert r.verification_json()["passed"] is False


def test_validation_without_a_compiler_is_skipped(monkeypatch):
    _no_solc(monkeypatch)
    v = validate(generate_solidity(decompiled("SimpleToken")))
    assert v.status == "skipped" and v.errors == [] and v.warnings


def test_verification_without_an_evm_backend_leaves_a_warning(monkeypatch):
    solc_or_skip("0.8.19")
    from scobelix.verify import core

    monkeypatch.setattr(core, "available_backends", lambda: [])
    r = generate_solidity(decompiled("SimpleToken"), verify=True, target_solc="0.8.19")
    _check_shape(r)
    assert r.verification.levels["L0"].status == "pass"
    assert r.verification.levels["L3"].status == "skipped"
    assert [w for w in r.warnings if w.startswith("verification L3 skipped") and "scobelix[verify]" in w]
    assert not {"EQUIVALENT", "EQUIVALENT_REVERTS_ONLY"} & {f["verdict"] for f in r.functions.values()}
    assert "high" not in r.confidence.values()  # compiled, not executed: nothing was observed


def test_verification_without_the_verify_package_leaves_a_warning(monkeypatch):
    for name in [m for m in sys.modules if m == "scobelix.verify" or m.startswith("scobelix.verify.")]:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setitem(sys.modules, "scobelix.verify", None)
    r = generate_solidity(decompiled("SimpleToken"), verify=True)
    _check_shape(r)
    assert r.verification is None
    assert [w for w in r.warnings if w.startswith("verification unavailable")]
    assert {f["verdict"] for f in r.functions.values()} == {"unverified"}


def test_verification_needs_the_bytecode():
    r = generate_solidity(decompiled("SimpleToken").json, verify=True)
    assert r.verification is None
    assert "verification skipped: no original bytecode" in r.warnings


def test_a_text_that_does_not_compile_is_reported_not_raised(monkeypatch):
    solc_or_skip("0.8.19")
    from scobelix.solgen import v2

    real = v2.assemble

    def broken(ci):
        text, ctx = real(ci)
        return text.replace("contract Decompiled {", "contract Decompiled { this is not Solidity", 1), ctx

    monkeypatch.setattr(v2, "assemble", broken)
    r = generate_solidity(decompiled("SimpleToken"), verify=True, target_solc="0.8.19")
    assert r.verification.levels["L0"].status == "fail"
    assert [w for w in r.warnings if w.startswith("verification L0 fail")]
    assert {f["verdict"] for f in r.functions.values()} == {"unverified"}
    assert validate(r).status == "invalid"

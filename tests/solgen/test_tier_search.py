"""The verification loop of the generator (`generate_solidity(verify=True)`,
`scobelix.solgen.tiers`): a function keeps a rewritten form only when it was
seen to behave like the original; a pass that breaks a function (its
behaviour, its compilation, the storage layout) is backed off for what it
broke and nothing else; what cannot be repaired or run is written in exact
form and says so."""

import dataclasses
import importlib
import itertools
import json
import time

import pytest
from conftest import backend_or_skip, compile_or_fail, decompiled, fixture_params, solc_or_skip

from scobelix.solgen import SearchBudget, generate_solidity, pipeline, tiers
from scobelix.solgen import ir
from scobelix.solgen import storage as storage_model
from scobelix.solgen import v2
from scobelix.solgen.contract import entry_spans
from scobelix.solgen.v2 import Generator

SOLC = "0.8.19"
TRANSFER, BALANCE_OF, TOTAL_SUPPLY = "0xa9059cbb", "0x70a08231", "0x18160ddd"
OK = ("EQUIVALENT", "EQUIVALENT_REVERTS_ONLY")
QUICK = {"calls_per_function": 60, "probe_calls": 20, "sequences": 6, "sequence_length": 8, "coverage_calls": 16,
         "max_divergences": 3, "l4_search": False}


def tools():
    solc_or_skip(SOLC)
    backend_or_skip()


def verified(decompilation, **budget):
    return generate_solidity(decompilation, verify=True, target_solc=SOLC, budget=dict(QUICK, **budget))


def break_pass(monkeypatch, name, key, edit):
    """Make pass `name` rewrite function `key` wrongly: `edit` is applied
    to what the pass returns for it."""
    module = importlib.import_module(f"scobelix.solgen.passes.{name}")
    real = module.run

    def run(fn, ctx):
        out = real(fn, ctx)
        return edit(out) if fn.key == key else out

    monkeypatch.setattr(module, "run", run)


def flip_comparisons(fn):
    """`<` for `>` and back, everywhere in the function."""
    other = {"lt": "gt", "gt": "lt"}

    def flip(node):
        if isinstance(node, (ir.Op, ir.Typed)) and node.op in other:
            return dataclasses.replace(node, op=other[node.op])
        return node

    return fn.with_body(ir.transform(fn.body, flip))


def use_an_undeclared_name(fn):
    """A first statement that solc rejects."""
    return fn.with_body((ir.Require(ir.StateRef("a_variable_nobody_declared")),) + tuple(fn.body))


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


def returning_false(trace):
    """The trace with `return 1` turned into `return 0`: what a wrong
    decompilation of the function would be."""
    if isinstance(trace, (list, tuple)):
        if tuple(trace) == ("return", 1):
            return ("return", 0)
        return type(trace)(returning_false(x) for x in trace)
    return trace


def code_of(text):
    """The text without its comments."""
    return [line for line in text.split("\n") if not line.strip().startswith("//")]


def check_invariants(r):
    """What holds for every result of the loop."""
    for key, f in r.functions.items():
        assert f["tier"] in tiers.TIERS
        assert (f["tier"] == "exact") == (not f["passes"])
        assert (f["tier"] == "partial") == bool(f["passes"] and f["disabled_passes"])
        if f["tier"] != "exact":  # nothing rewritten without a run that accepted it
            assert f["verdict"] in OK, (key, f["tier"], f["verdict"])
        assert ("counterexample" in f) == (f["verdict"] == "DIVERGENT")
    json.dumps(r.to_json())


# ---------------------------------------------------------------- delta debugging


def minimal(universe, passes):
    """Drive the search: `passes(off)` says whether switching `off` off is
    enough; returns what it found and how many candidates it tried."""
    search = tiers._ddmin(universe)
    tried = []
    try:
        candidate = next(search)
        while True:
            tried.append(candidate)
            candidate = search.send(passes(set(candidate)))
    except StopIteration as stop:
        return stop.value, tried


@pytest.mark.parametrize("size", [1, 2, 3, 5, 8, 11])
def test_the_search_finds_exactly_the_passes_at_fault(size):
    universe = tuple(f"p{i}" for i in range(size))
    for count in (1, 2, 3):
        for culprits in itertools.combinations(universe, min(count, size)):
            found, tried = minimal(universe, lambda off: set(culprits) <= off)
            assert found is not None and set(found) == set(culprits)
            assert found == tuple(p for p in universe if p in culprits)  # in the order of the pipeline
            assert len(tried) == len(set(tried))  # no candidate asked twice
            assert tried[0] == universe  # everything off first: is there a repair at all?
    assert len(minimal(universe, lambda off: universe[-1] in off)[1]) <= 2 * size.bit_length() + 2


def test_the_search_says_when_nothing_repairs():
    assert minimal(("abi", "storage", "arith"), lambda off: False) == (None, [("abi", "storage", "arith")])
    assert minimal((), lambda off: True) == (None, [])


def test_the_result_of_the_search_is_minimal_whatever_the_test():
    # no element of the answer can be put back, for tests that are not monotone either
    universe = tuple("abcdef")
    for accepted in ({"a", "b", "c", "d", "e", "f"}, {"b", "e"}, {"a"}, {"c", "d", "f"}, {"a", "f"}):
        good = [set(universe), accepted]
        found, _ = minimal(universe, lambda off: off in good)
        assert set(found) in good
        assert not any(set(found) - {x} in good for x in found)


def test_several_functions_are_searched_in_the_same_rounds():
    culprit = {"f": "arith", "g": "abi", "h": "compound"}
    universe = {key: ("abi", "storage", "arith", "compound") for key in culprit}
    rounds = []

    def run_round(candidates):
        rounds.append(dict(candidates))
        return {key: culprit[key] in off for key, off in candidates.items()}

    found = tiers._minimise(sorted(culprit), universe, run_round)
    assert found == {key: (name,) for key, name in culprit.items()}
    assert len(rounds) <= 5 and len(rounds[0]) == 3  # as many rounds as one function needs, not three times that


def test_a_search_that_is_stopped_keeps_the_last_set_that_passed():
    answers = iter([{"f": True}, {"f": None}])
    assert tiers._minimise(["f"], {"f": ("abi", "storage", "arith")}, lambda c: next(answers)) == {
        "f": ("abi", "storage", "arith")}
    assert tiers._minimise(["f"], {"f": ("abi", "storage")}, lambda c: None) == {"f": None}


# ---------------------------------------------------------------- budgets


def test_budget_forms():
    from scobelix.verify import Budget

    assert SearchBudget.of(None) == SearchBudget()
    assert SearchBudget().time_limit == 300.0 and SearchBudget().max_rounds >= 8
    quick = Budget.quick()
    assert SearchBudget.of(quick).verify is quick
    mixed = SearchBudget.of({"time_limit": 5, "max_rounds": 3, "calls_per_function": 7, "seed": 2})
    assert (mixed.time_limit, mixed.max_rounds, mixed.verify) == (5, 3, {"calls_per_function": 7, "seed": 2})
    assert SearchBudget.of({"verify": quick, "l4": False}) == SearchBudget(l4=False, verify=quick)
    own = SearchBudget(time_limit=None)
    assert SearchBudget.of(own) == own and SearchBudget.of(own) is not own


@pytest.mark.parametrize("fields", [{"time_limit": 0}, {"time_limit": -1}, {"max_rounds": 0}, {"max_rounds": 1.5},
                                    {"time_limit": "soon"}, {"verify": {"seed": 1}, "seed": 2},
                                    # no limit is None: infinity would also be no valid JSON in the result
                                    {"time_limit": float("inf")}, {"time_limit": float("nan")},
                                    {"time_limit": True}, {"max_rounds": True}])
def test_unusable_budgets_are_refused(fields):
    with pytest.raises(ValueError):
        generate_solidity(decompiled("SimpleToken"), verify=True, budget=fields)


# ---------------------------------------------------------------- where the entry points are written


@pytest.mark.parametrize("name", fixture_params())
def test_every_written_entry_point_is_located(name):
    r = generate_solidity(decompiled(name))
    ci = r._assembly
    spans = entry_spans(r.solidity, ci)
    lines = r.solidity.split("\n")
    assert len({key for _, _, key in spans}) == len(spans)
    assert all(a_last < b_first for (_, a_last, _), (b_first, _, _) in zip(spans, spans[1:]))  # in order, apart
    by_key = {key: (first, last) for first, last, key in spans}
    written = {u.key for u in ci.units if not (u.folded and u.spec.kind == "function" and not u.spec.routed)}
    assert set(by_key) <= written
    for unit in ci.units:
        if unit.spec.kind == "function" and unit.key in written:
            first, last = by_key[unit.key]
            assert f"0x{unit.spec.selector:08x}" in lines[first - 1]
            body = "\n".join(lines[first - 1:last])
            assert body.count("{") == body.count("}") and "@custom:scobelix tier=" in body
    # nothing of the declarations, of the helpers or of the header lies in a span
    inside = {n for first, last, _ in spans for n in range(first, last + 1)}
    for number, line in enumerate(lines, 1):
        if line.startswith(("//", "pragma ", "contract ")) or "---- EVM-exact helpers" in line:
            assert number not in inside


def test_compiler_errors_are_mapped_to_functions_and_declarations(monkeypatch):
    solc_or_skip(SOLC)
    from scobelix.verify import solc

    break_pass(monkeypatch, "compound", TRANSFER, use_an_undeclared_name)
    r = Generator(decompiled("SimpleToken"), SOLC, "full").regenerate()
    with pytest.raises(solc.CompilationError) as failure:
        solc.compile_standard_json(r.solidity, version=SOLC)
    where = tiers.locate_errors(r, failure.value.errors)
    assert list(where.functions) == [TRANSFER] and not where.passes and not where.rest
    assert "a_variable_nobody_declared" in where.functions[TRANSFER][0] or "Undeclared" in where.functions[TRANSFER][0]
    # an error in the declaration that stands for a folded function is that function's
    broken = r.solidity.replace("uint256 public totalSupply;", "uint256 public totalSupply = nothing;")
    assert broken != r.solidity
    with pytest.raises(solc.CompilationError) as failure:
        solc.compile_standard_json(broken, version=SOLC)
    where = tiers.locate_errors(dataclasses.replace(r, solidity=broken), failure.value.errors)
    assert list(where.functions) == [TOTAL_SUPPLY] and not where.passes
    # an error in a declaration nothing is folded into is the declaring pass's
    declared_twice(monkeypatch)
    r = Generator(decompiled("Vault"), SOLC, "full").regenerate({"*": {"getters"}})
    with pytest.raises(solc.CompilationError) as failure:
        solc.compile_standard_json(r.solidity, version=SOLC)
    where = tiers.locate_errors(r, failure.value.errors)
    assert list(where.passes) == ["storage"] and not where.functions and not where.rest
    assert "already declared" in where.passes["storage"][0]


def declared_twice(monkeypatch):
    """The storage pass declares its last variable twice."""
    real = storage_model.state_declarations

    def twice(layout, natspec=None, use_vids=False):
        lines = real(layout, natspec, use_vids)
        return lines if use_vids or not lines else lines + [lines[-1]]

    monkeypatch.setattr(storage_model, "state_declarations", twice)


# ---------------------------------------------------------------- nothing to repair


def test_a_sound_contract_is_verified_in_one_run():
    tools()
    r = verified(decompiled("SimpleToken"))
    check_invariants(r)
    done = r.verification.search
    assert done["rounds"] == 1 and done["compilations"] == 1 and done["final_check"] is True
    assert done["budget_exhausted"] is False and done["exhausted_by"] is None
    assert done["repaired"] == [] and done["backed_off"] == {} and done["divergent"] == [] and done["l0"] == []
    assert done["tiers"] == {"idiomatic": 3, "partial": 0, "exact": 1}
    assert done["verdicts"] == dict(r.verification.summary) and done["elapsed"] >= 0
    assert {r.functions[k]["tier"] for k in (TRANSFER, BALANCE_OF, TOTAL_SUPPLY)} == {"idiomatic"}
    assert all(f["disabled_passes"] == [] for f in r.functions.values())
    assert r.verification.passed and not [w for w in r.warnings if w.startswith("verification")]
    # every level has a status, in the result and in the header
    assert set(done["levels"]) == {"L0", "L1", "L2", "L3", "L4"}
    assert [done["levels"][k] for k in ("L0", "L1", "L2", "L3")] == ["pass"] * 4
    assert r.verification.levels["L2"].details["variables"] == 2
    header = r.solidity.split("pragma solidity")[0]
    assert "verification: L0=pass  L1=pass  L2=pass  L3=pass  L4=" in header
    assert "tiers: 3 idiomatic, 0 partial, 1 exact" in header
    assert "loop: 1 run(s) against the original, 1 text(s) compiled" in header
    for verdict in ("EQUIVALENT ", "EQUIVALENT_REVERTS_ONLY ", "DIVERGENT ", "MISSING, EXTRA ", "ROUTED ",
                    "INCONCLUSIVE ", "SKIPPED "):
        assert f"//     {verdict}" in header  # the legend says what each verdict lets the reader conclude
    assert "tier=partial" in header and "//   levels " in header
    assert r.verification.lines == [line[5:] for line in header.split("\n") if line.startswith("//   ")][
        4:4 + len(r.verification.lines)]


def test_without_verify_nothing_changes_and_the_header_says_so():
    r = generate_solidity(decompiled("SimpleToken"))
    assert r.verification is None
    header = r.solidity.split("pragma solidity")[0]
    assert "//   verification      : not run (nothing in this text was executed against the original)" in header
    assert "tier=partial" not in header and "EQUIVALENT_REVERTS_ONLY" not in header
    assert all(f["disabled_passes"] == [] and f["verdict"] == "unverified" for f in r.functions.values())


def test_simple_token_compiles_back_to_the_original_bytecode():
    tools()
    r = verified(decompiled("SimpleToken"))
    assert r.original_compiler == f"solc {SOLC}"
    l4 = r.verification.levels["L4"]
    assert l4.status == "pass" and l4.details["compiled"]["identical"] is True
    assert r.verification.search["l4"]["settings"] == ["opt200"]
    assert "L4: the original bytecode, apart from metadata and immutables, with the settings opt200" in r.solidity
    # with a function at another tier the bytecode is no longer the original's: said, and no failure
    exact = generate_solidity(decompiled("SimpleToken"), verify=True, target_solc=SOLC, idiom_level="exact",
                              budget=QUICK)
    l4 = exact.verification.levels["L4"]
    assert l4.status == "fail" and "not identical" in l4.reason and exact.verification.search["l4"]["settings"] == []
    assert exact.verification.passed and exact.verification.to_json()["passed"] is True
    assert f"L4: {l4.reason}" in exact.solidity
    assert not [w for w in exact.warnings if "L4" in w]


def test_the_search_for_the_original_bytecode_tries_the_usual_settings():
    tools()
    budget = dict(QUICK, l4_search=True)
    exact = generate_solidity(decompiled("SimpleToken"), verify=True, target_solc=SOLC, idiom_level="exact",
                              budget=budget)
    l4 = exact.verification.levels["L4"]
    assert l4.status == "fail" and "under any tried settings" in l4.reason
    assert len(l4.details["search"]["variants"]) >= 6
    off = generate_solidity(decompiled("SimpleToken"), verify=True, target_solc=SOLC, budget=dict(budget, l4=False))
    assert off.verification.levels["L4"].status == "skipped"
    small = generate_solidity(decompiled("SimpleToken"), verify=True, target_solc=SOLC,
                              budget=dict(budget, l4_max_size=100))
    assert small.verification.levels["L4"].status == "skipped" and "bytes" in small.verification.levels["L4"].reason
    forced = generate_solidity(decompiled("SimpleToken"), verify=True, target_solc=SOLC,
                               budget=dict(budget, l4_max_size=100, l4=True))
    assert forced.verification.levels["L4"].status == "pass"


# ---------------------------------------------------------------- a pass that breaks a function


def test_a_pass_that_breaks_one_function_is_backed_off_for_that_function_only(monkeypatch):
    tools()
    sound = verified(decompiled("SimpleToken"))
    break_pass(monkeypatch, "compound", TRANSFER, flip_comparisons)
    plain = generate_solidity(decompiled("SimpleToken"), target_solc=SOLC)
    assert "compound" in plain.functions[TRANSFER]["passes"]  # without verification the broken text goes out
    r = verified(decompiled("SimpleToken"))
    check_invariants(r)
    transfer = r.functions[TRANSFER]
    assert transfer["verdict"] == "EQUIVALENT" and r.confidence[TRANSFER] == "high"
    assert transfer["tier"] == "partial" and transfer["disabled_passes"] == ["compound"]
    assert transfer["passes"] == [p for p in sound.functions[TRANSFER]["passes"] if p != "compound"]
    for key in (BALANCE_OF, TOTAL_SUPPLY):  # the others are left as they were
        assert r.functions[key]["tier"] == "idiomatic" and r.functions[key]["disabled_passes"] == []
        assert r.functions[key]["passes"] == sound.functions[key]["passes"]
        assert r.functions[key]["verdict"] == "EQUIVALENT"
    done = r.verification.search
    assert done["repaired"] == [TRANSFER] and done["backed_off"] == {TRANSFER: ["compound"]}
    assert done["divergent"] == [] and done["final_check"] is True and done["budget_exhausted"] is False
    assert done["tiers"] == {"idiomatic": 2, "partial": 1, "exact": 1}
    assert 3 <= done["rounds"] <= 10  # the first run, the search, the final run of the whole text
    assert r.verification.levels["L3"].status == "pass" and r.verification.passed
    # the reader is told: a warning, the header, the tag of the function
    assert [w for w in r.warnings if w.startswith("verification L3: 1 function(s) did not behave like the original")
            and f"{TRANSFER} (compound: now EQUIVALENT)" in w]
    assert f"backed off: {TRANSFER} (compound)" in r.solidity
    tag = next(line for line in r.solidity.split("\n") if "tier=partial" in line and "@custom:scobelix" in line)
    assert "verdict=EQUIVALENT" in tag and tag.rstrip().endswith("off=compound")
    assert "NOT EQUIVALENT" not in r.solidity
    compile_or_fail(r.solidity, SOLC)


def test_a_broken_pass_is_found_whichever_it_is(monkeypatch):
    tools()
    break_pass(monkeypatch, "arith", TRANSFER, flip_comparisons)
    r = verified(decompiled("SimpleToken"))
    check_invariants(r)
    assert r.functions[TRANSFER]["verdict"] == "EQUIVALENT"
    assert "arith" in r.functions[TRANSFER]["disabled_passes"]
    assert set(r.functions[TRANSFER]["passes"]) >= {"abi", "storage"}  # no more is backed off than it takes
    assert r.verification.search["repaired"] == [TRANSFER]


def test_two_functions_broken_by_different_passes_are_searched_together(monkeypatch):
    tools()
    break_pass(monkeypatch, "reverts", "0x2e1a7d4d", flip_comparisons)  # withdraw(uint256)
    break_pass(monkeypatch, "arith", "0xd0e30db0", subtract_instead_of_adding)  # deposit()
    r = verified(decompiled("Vault"))
    check_invariants(r)
    done = r.verification.search
    assert done["repaired"] == ["0x2e1a7d4d", "0xd0e30db0"] and done["divergent"] == []
    assert "reverts" in done["backed_off"]["0x2e1a7d4d"] and "arith" in done["backed_off"]["0xd0e30db0"]
    assert set(done["backed_off"]) == {"0x2e1a7d4d", "0xd0e30db0"}
    assert done["rounds"] <= 10 and done["final_check"] is True


def test_a_difference_only_sequences_show_is_searched_with_runs_of_the_whole_contract(monkeypatch):
    tools()
    real = v2._check
    runs = []

    def sequences_only(result, code, budget, allow_download, options=None):
        # transfer() as the compound pass writes it differs only after other calls: a run restricted
        # to some entry points (single calls, no sequence) cannot see it
        report, why = real(result, code, budget, allow_download, options)
        options = options or {}
        if "levels" not in options:  # the runs of the loop (not its static and L4 checks)
            runs.append(sorted(options.get("selectors") or ["*"]))
            if report is not None and "compound" in result.functions[TRANSFER]["passes"] \
                    and not options.get("selectors"):
                seen = report.functions[TRANSFER]
                report.functions[TRANSFER] = dataclasses.replace(seen, verdict="DIVERGENT", divergences=0,
                                                                 sequence_divergences=1)
        return report, why

    monkeypatch.setattr(v2, "_check", sequences_only)
    r = verified(decompiled("SimpleToken"), l4=False)
    check_invariants(r)
    transfer = r.functions[TRANSFER]
    assert transfer["verdict"] == "EQUIVALENT" and transfer["tier"] == "partial"
    assert "compound" not in transfer["passes"]
    assert len(runs) >= 3 and all(keys == ["*"] for keys in runs)  # every run of the search is of the whole
    done = r.verification.search
    assert done["repaired"] == [TRANSFER] and done["final_check"] is True and done["rounds"] == len(runs)
    for key in (BALANCE_OF, TOTAL_SUPPLY):
        assert r.functions[key]["tier"] == "idiomatic"


def subtract_instead_of_adding(fn):
    def edit(node):
        return dataclasses.replace(node, op="sub") if isinstance(node, ir.Typed) and node.op == "add" else node

    return fn.with_body(ir.transform(fn.body, edit))


# ---------------------------------------------------------------- L0: a text that does not compile


def test_a_pass_that_breaks_compilation_is_backed_off_for_that_function(monkeypatch):
    tools()
    break_pass(monkeypatch, "compound", TRANSFER, use_an_undeclared_name)
    plain = generate_solidity(decompiled("SimpleToken"), target_solc=SOLC)
    assert "a_variable_nobody_declared" in plain.solidity
    r = verified(decompiled("SimpleToken"))
    check_invariants(r)
    assert "a_variable_nobody_declared" not in r.solidity
    compile_or_fail(r.solidity, SOLC)
    assert r.verification.levels["L0"].status == "pass"
    transfer = r.functions[TRANSFER]
    assert transfer["tier"] == "partial" and transfer["disabled_passes"] == ["compound"]
    assert transfer["verdict"] == "EQUIVALENT"
    assert {r.functions[k]["tier"] for k in (BALANCE_OF, TOTAL_SUPPLY)} == {"idiomatic"}
    done = r.verification.search
    assert len(done["l0"]) == 1 and done["l0"][0]["function"] == TRANSFER and done["l0"][0]["passes"] == ["compound"]
    assert "Undeclared identifier" in done["l0"][0]["message"]  # the compiler's message is reported
    assert done["repaired"] == []  # never run broken: nothing to say about its behaviour before
    assert [w for w in r.warnings if w.startswith("verification L0: the text did not compile")
            and "Undeclared identifier" in w and f"compound for {TRANSFER}" in w]
    assert "L0: the text first written did not compile" in r.solidity and f"{TRANSFER} (compound)" in r.solidity


def test_a_text_no_backing_off_makes_compile_is_returned_with_a_warning(monkeypatch):
    solc_or_skip(SOLC)
    real = v2.assemble

    def broken(ci):
        text, ctx = real(ci)
        return text.replace("contract Decompiled {", "contract Decompiled { this is not Solidity", 1), ctx

    monkeypatch.setattr(v2, "assemble", broken)
    r = verified(decompiled("SimpleToken"))
    assert r.verification.levels["L0"].status == "fail"
    assert [w for w in r.warnings if w.startswith("verification L0 fail")]
    assert {f["verdict"] for f in r.functions.values()} == {"unverified"}
    assert {f["tier"] for f in r.functions.values()} == {"exact"}  # the last resort was tried
    assert r.verification.passed is False
    assert [e for e in r.verification.search["l0"] if e["function"] == "*"]
    assert {r.verification.search["levels"][k] for k in ("L1", "L2", "L3", "L4")} == {"skipped"}


def test_without_the_bytecode_a_text_that_does_not_compile_says_so_too(monkeypatch):
    solc_or_skip(SOLC)
    real = v2.assemble

    def broken(ci):
        text, ctx = real(ci)
        return text.replace("contract Decompiled {", "contract Decompiled { this is not Solidity", 1), ctx

    monkeypatch.setattr(v2, "assemble", broken)
    r = generate_solidity(decompiled("SimpleToken").json, verify=True, target_solc=SOLC)  # traces only
    assert r.verification is None and "verification skipped: no original bytecode" in r.warnings
    # the loop compiled the text: what it learnt is not kept from the reader
    assert [w for w in r.warnings if w.startswith("verification L0 fail: the text does not compile")]


def test_a_text_that_cannot_even_be_written_falls_back_to_the_exact_tier(monkeypatch):
    tools()

    def three_operands(fn):  # not something the renderer writes
        def edit(node):
            if isinstance(node, ir.Typed) and node.op == "add":
                return dataclasses.replace(node, args=node.args + (ir.const(1),))
            return node

        return fn.with_body(ir.transform(fn.body, edit))

    break_pass(monkeypatch, "arith", TRANSFER, three_operands)
    with pytest.raises(ValueError):
        generate_solidity(decompiled("SimpleToken"), target_solc=SOLC)
    r = verified(decompiled("SimpleToken"))
    check_invariants(r)
    assert {f["tier"] for f in r.functions.values()} == {"exact"}
    assert {f["verdict"] for f in r.functions.values()} <= set(OK)
    done = r.verification.search
    assert done["l0"][0]["function"] == "*" and "the text could not be written: ValueError" in done["l0"][0]["message"]
    assert [w for w in r.warnings if w.startswith("verification L0") and "every pass, for the whole contract" in w]
    compile_or_fail(r.solidity, SOLC)


def test_an_offending_declaration_switches_its_pass_off_for_the_contract(monkeypatch):
    tools()
    declared_twice(monkeypatch)
    r = verified(decompiled("Vault"))
    check_invariants(r)
    compile_or_fail(r.solidity, SOLC)
    done = r.verification.search
    assert done["l0"] and done["l0"][-1]["passes"] == ["storage"] and done["contract"] == ["storage"]
    assert "already declared" in done["l0"][-1]["message"]
    assert r.storage_layout == [] and " internal " not in r.solidity.split("contract Decompiled")[1].split("///")[0]
    assert {f["verdict"] for f in r.functions.values()} <= set(OK)
    assert all("storage" not in f["passes"] for f in r.functions.values())


# ---------------------------------------------------------------- L2: a declaration at the wrong place


def swapped(monkeypatch, first, second):
    """The storage pass declares two variables in the wrong order (its own
    check of the layout, made on other names, does not see it)."""
    real = storage_model.state_declarations

    def declarations(layout, natspec=None, use_vids=False):
        lines = real(layout, natspec, use_vids)
        if use_vids or lines is None:
            return lines
        at = {name: i for i, line in enumerate(lines) for name in (first, second) if line.endswith(f" {name};")}
        if len(at) == 2:
            lines[at[first]], lines[at[second]] = lines[at[second]], lines[at[first]]
        return lines

    monkeypatch.setattr(storage_model, "state_declarations", declarations)


def test_a_variable_declared_at_the_wrong_slot_goes_back_to_its_slot_number(monkeypatch):
    tools()
    sound = verified(decompiled("Vault"))
    assert [v["name"] for v in sound.storage_layout] == ["owner", "deposits", "paused"]
    assert sound.verification.levels["L2"].status == "pass" and sound.verification.search["excluded_storage"] == []
    assert [(v["slot"], v["offset"]) for v in sound.storage_layout] == [(0, 0), (1, 0), (2, 0)]
    # declared before the mapping, the bool is packed after the address of slot 0
    swapped(monkeypatch, "deposits", "paused")
    plain = generate_solidity(decompiled("Vault"), target_solc=SOLC)
    layout = compile_or_fail(plain.solidity, SOLC).storage_layout
    assert {v["label"]: (int(v["slot"]), v["offset"]) for v in layout["storage"]} == {
        "owner": (0, 0), "paused": (0, 20), "deposits": (1, 0)}
    rows = tiers.layout_rows(plain.storage_layout, layout)
    assert {row["name"]: row["status"] for row in rows} == {"owner": "match", "deposits": "match", "paused": "moved"}
    assert [row["found"] for row in rows if row["name"] == "paused"] == [[0, 20]]
    r = verified(decompiled("Vault"))
    check_invariants(r)
    # that variable is reached by slot, the two others keep their declarations and their places
    assert [(v["name"], v["slot"]) for v in r.storage_layout] == [("owner", 0), ("deposits", 1)]
    layout = compile_or_fail(r.solidity, SOLC).storage_layout
    assert {v["label"]: int(v["slot"]) for v in layout["storage"]} == {"owner": 0, "deposits": 1}
    done = r.verification.search
    assert done["excluded_storage"] == ["slot2"] and done["levels"]["L2"] == "pass"
    assert r.verification.levels["L2"].details["variables"] == 2
    assert r.verification.levels["L2"].details["repairs"][0]["variables"] == ["paused"]
    assert [w for w in r.warnings if w.startswith("verification L2: 1 state variable(s) were not where")
            and "paused" in w and "reached by slot" in w]
    assert "L2: state variables not where they were inferred are reached by slot: paused" in r.solidity
    # nothing is lost in behaviour, and no function is left out
    assert set(r.functions) == set(sound.functions)
    assert {f["verdict"] for f in r.functions.values()} <= set(OK)
    assert r.verification.levels["L3"].status == "pass" and r.verification.passed
    assert r.functions["0x8da5cb5b"]["folded"] == "owner"  # owner() is still the getter of its variable
    assert r.functions["0x5c975abb"]["folded"] is None and r.functions["0x5c975abb"]["verdict"] == "EQUIVALENT"
    assert "paused" not in r.solidity.split("contract Decompiled")[1].split("/// @notice")[0]


def test_a_variable_declared_with_another_size_is_found_too(monkeypatch):
    tools()
    real = storage_model.state_declarations

    def narrower(layout, natspec=None, use_vids=False):
        lines = real(layout, natspec, use_vids)
        if use_vids or lines is None:
            return lines
        return [line.replace("uint256 public totalSupply;", "uint128 public totalSupply;") for line in lines]

    monkeypatch.setattr(storage_model, "state_declarations", narrower)
    plain = generate_solidity(decompiled("SimpleToken"), target_solc=SOLC)
    rows = tiers.layout_rows(plain.storage_layout, compile_or_fail(plain.solidity, SOLC).storage_layout)
    assert {row["name"]: row["status"] for row in rows} == {"balanceOf": "match", "totalSupply": "shape"}
    r = verified(decompiled("SimpleToken"))
    check_invariants(r)
    assert [v["name"] for v in r.storage_layout] == ["balanceOf"]
    assert r.verification.search["excluded_storage"] == ["slot1"]
    assert r.functions[TOTAL_SUPPLY]["folded"] is None and r.functions[TOTAL_SUPPLY]["verdict"] == "EQUIVALENT"
    assert r.functions[BALANCE_OF]["folded"] == "balanceOf"


def test_every_variable_out_of_place_leaves_none_declared(monkeypatch):
    tools()
    real = storage_model.state_declarations

    def shifted(layout, natspec=None, use_vids=False):
        lines = real(layout, natspec, use_vids)
        return lines if use_vids or not lines else ["uint256 private __one_slot_too_many;"] + lines

    monkeypatch.setattr(storage_model, "state_declarations", shifted)
    r = verified(decompiled("Vault"))
    check_invariants(r)
    done = r.verification.search
    assert done["excluded_storage"] == ["slot0", "slot1", "slot2"] and r.storage_layout == []
    level = r.verification.levels["L2"]
    assert level.status == "skipped" and "no state variable declared" in level.reason and "owner" in level.reason
    assert all(f["folded"] is None for f in r.functions.values())
    assert {f["verdict"] for f in r.functions.values()} <= set(OK)
    compile_or_fail(r.solidity, SOLC)


def test_a_layout_that_exclusions_do_not_repair_switches_the_storage_pass_off(monkeypatch):
    tools()
    swapped(monkeypatch, "deposits", "paused")
    monkeypatch.setattr(storage_model, "exclude", lambda layout, vids, solc_version=None: None)  # no way out
    r = verified(decompiled("Vault"))
    check_invariants(r)
    done = r.verification.search
    assert done["contract"] == ["storage"] and r.storage_layout == []
    assert len(r.verification.levels["L2"].details["repairs"]) == tiers._Loop.L2_ATTEMPTS + 1
    assert done["levels"]["L2"] == "skipped" and "no state variable declared" in r.verification.levels["L2"].reason
    assert [w for w in r.warnings if w.startswith("verification L2") and "the storage pass is switched off" in w]
    assert all("storage" not in f["passes"] for f in r.functions.values())
    assert {f["verdict"] for f in r.functions.values()} <= set(OK)
    compile_or_fail(r.solidity, SOLC)


# ---------------------------------------------------------------- contract-level passes


def test_a_wrong_getter_is_written_out_again_and_the_others_are_run_again(monkeypatch):
    tools()
    from scobelix.solgen.passes import getters

    real = getters._constant_fold

    def wrong(fn, spec):  # totalSupply() taken for a constant
        return ("uint256", 5) if fn.key == TOTAL_SUPPLY else real(fn, spec)

    monkeypatch.setattr(getters, "_constant_fold", wrong)
    plain = generate_solidity(decompiled("SimpleToken"), target_solc=SOLC)
    assert "uint256 public constant totalSupply = 5;" in plain.solidity
    r = verified(decompiled("SimpleToken"))
    check_invariants(r)
    assert "constant totalSupply" not in r.solidity
    supply = r.functions[TOTAL_SUPPLY]
    assert supply["folded"] is None and supply["verdict"] == "EQUIVALENT" and "getters" in supply["disabled_passes"]
    assert r.verification.search["repaired"] == [TOTAL_SUPPLY]
    # the functions built on the declarations were verified with the new ones
    assert r.functions[BALANCE_OF]["folded"] == "balanceOf" and r.functions[BALANCE_OF]["verdict"] == "EQUIVALENT"
    assert r.functions[TRANSFER]["tier"] == "idiomatic" and r.functions[TRANSFER]["verdict"] == "EQUIVALENT"
    assert r.verification.search["final_check"] is True
    compile_or_fail(r.solidity, SOLC)


def test_what_a_switch_means_for_the_passes_of_the_whole_contract():
    g = Generator(decompiled("SimpleToken"), SOLC, "full")
    full = g.regenerate()
    assert g.full_passes() == {key: tuple(f["passes"]) for key, f in full.functions.items()}
    # off for one function: the declarations stay, the function reaches the same slots by number
    local = g.regenerate({TRANSFER: {"storage"}})
    assert local.storage_layout == full.storage_layout
    assert "balanceOf[" not in local.solidity.split("function transfer")[1]
    assert local.functions[TRANSFER]["tier"] == "partial"
    assert "storage" in local.functions[TRANSFER]["disabled_passes"]
    assert local.functions[BALANCE_OF] == full.functions[BALANCE_OF]
    # off for the whole contract: no declaration, and no function folded into a variable
    nowhere = g.regenerate({"*": {"storage"}})
    assert nowhere.storage_layout == []
    assert all(f["folded"] is None and "storage" not in f["passes"] for f in nowhere.functions.values())
    assert "mapping(" not in nowhere.solidity
    # every pass off for the whole contract is the exact tier
    assert code_of(g.regenerate({"*": set(pipeline.PASS_ORDER)}).solidity) == code_of(
        Generator(decompiled("SimpleToken"), SOLC, "exact").regenerate().solidity)
    # a variable left undeclared: a filler keeps the others in place, its accesses are by slot
    without = g.regenerate(excluded_storage=["slot0"])
    assert [v["name"] for v in without.storage_layout] == ["totalSupply"]
    assert without.functions[BALANCE_OF]["folded"] is None and without.functions[TOTAL_SUPPLY]["folded"]
    for r in (local, nowhere, without):
        compile_or_fail(r.solidity, SOLC)


# ---------------------------------------------------------------- a loss no pass can repair


def test_a_function_that_differs_in_exact_form_too_is_kept_exact_with_its_counterexample():
    tools()
    wrong = Edited(decompiled("SimpleToken"), TRANSFER, returning_false)
    assert Generator(wrong, SOLC, "full").regenerate().functions[TRANSFER]["passes"]  # the passes still apply
    r = verified(wrong)
    check_invariants(r)
    transfer = r.functions[TRANSFER]
    assert transfer["tier"] == "exact" and transfer["passes"] == [] and transfer["verdict"] == "DIVERGENT"
    assert set(transfer["disabled_passes"]) >= {"abi", "storage"}
    assert r.confidence[TRANSFER] == "low"
    cx = transfer["counterexample"]
    assert cx["call"]["calldata"].startswith(TRANSFER) and "value" in cx["call"] and cx["call"]["sender"]
    assert cx["original"]["output"] != cx["candidate"]["output"] or cx["original"] != cx["candidate"]
    assert cx["kinds"]
    done = r.verification.search
    assert done["divergent"] == [TRANSFER] and done["repaired"] == [] and done["final_check"] is True
    assert r.verification.levels["L3"].status == "fail" and r.verification.passed is False
    assert {r.functions[k]["tier"] for k in (BALANCE_OF, TOTAL_SUPPLY)} == {"idiomatic"}  # the others are untouched
    # the text says it where the function is, with the call in short
    lines = r.solidity.split("\n")
    at = next(i for i, line in enumerate(lines) if f"@notice selector {TRANSFER}" in line)
    assert "@dev NOT EQUIVALENT" in lines[at + 1] and "DIVERGENT" in lines[at + 1]
    assert lines[at + 2].strip().startswith(f"/// @dev counterexample: calldata {TRANSFER}")
    assert "value 0" in lines[at + 2] and "caller 0x" in lines[at + 2]
    assert "the original returned 0x" in lines[at + 2] and "this text returned 0x" in lines[at + 2]
    assert len(lines[at + 2]) < 520
    assert "tier=exact verdict=DIVERGENT" in lines[at + 3]
    assert [w for w in r.warnings if w.startswith("verification L3 fail") and TRANSFER in w]
    assert [w for w in r.warnings if "did not behave like the original as first written" in w
            and "now DIVERGENT" in w]
    compile_or_fail(r.solidity, SOLC)


def test_a_counterexample_fits_on_one_line():
    cx = {"kinds": ["output", "storage"], "call": {"sender": "0x" + "ab" * 20, "via": "contract caller", "value": 7,
                                                   "calldata": "0x" + "cd" * 500},
          "original": {"success": True, "output": "0x" + "00" * 31 + "01"},
          "candidate": {"success": False, "output": "0x"}, "sequence": [{}, {}]}
    text = v2.short_counterexample(cx)
    assert "\n" not in text and len(text) < 400
    assert "(500 bytes)" in text and "value 7" in text and "through contract caller" in text
    assert "the original returned 0x" in text and "this text reverted (differs in: output, storage)" in text
    assert text.endswith("last of a sequence of 2 calls")
    assert v2.short_counterexample({}) == "calldata 0x, value 0, caller None: the original reverted, this text reverted"
    # a side that stopped without reverting is not said to have reverted
    halted = dict(cx, original={"success": False, "error": "halt:OutOfGas(Basic)", "output": "0x"},
                  candidate={"success": False, "error": "halt:InvalidInstruction", "output": "0x"})
    text = v2.short_counterexample(halted)
    assert "the original halted (OutOfGas(Basic)), this text halted (InvalidInstruction)" in text
    assert "reverted" not in text


# ---------------------------------------------------------------- budgets run out


def test_out_of_runs_the_function_not_repaired_is_exact_and_unverified(monkeypatch):
    tools()
    break_pass(monkeypatch, "compound", TRANSFER, flip_comparisons)
    r = verified(decompiled("SimpleToken"), max_rounds=1)
    check_invariants(r)
    done = r.verification.search
    assert done["rounds"] == 1 and done["budget_exhausted"] is True and done["exhausted_by"] == "rounds"
    assert done["final_check"] is False
    transfer = r.functions[TRANSFER]
    assert transfer["tier"] == "exact" and transfer["verdict"] == "SKIPPED" and transfer["calls"] == 0
    assert "budget exhausted (1 run(s))" in transfer["reason"]
    assert r.confidence[TRANSFER] == "medium"  # rated like a function that was not verified
    assert done["unverified"] == [TRANSFER, "_fallback"] or TRANSFER in done["unverified"]
    # the others keep the verdict of the run that was made of exactly their code
    for key in (BALANCE_OF, TOTAL_SUPPLY):
        assert r.functions[key]["tier"] == "idiomatic" and r.functions[key]["verdict"] == "EQUIVALENT"
        assert r.functions[key]["calls"] > 0
    assert r.verification.levels["L3"].status == "inconclusive"
    assert "budget exhausted (1 run(s))" in r.verification.levels["L3"].reason
    assert [w for w in r.warnings if w.startswith("verification: budget exhausted (1 run(s))")
            and "the final text was not run as a whole" in w]
    assert "the final text was not run as a whole" in r.solidity and "budget exhausted (1 run(s))" in r.solidity
    assert "verdict=SKIPPED" in r.solidity
    compile_or_fail(r.solidity, SOLC)
    # two runs: no search, but the exact form is run
    r = verified(decompiled("SimpleToken"), max_rounds=2)
    check_invariants(r)
    assert r.functions[TRANSFER]["tier"] == "exact" and r.functions[TRANSFER]["verdict"] == "EQUIVALENT"
    done = r.verification.search
    assert done["rounds"] == 2 and done["exhausted_by"] == "rounds" and done["final_check"] is True


def test_out_of_time_the_function_not_repaired_is_exact_and_unverified(monkeypatch):
    tools()
    break_pass(monkeypatch, "compound", TRANSFER, flip_comparisons)
    # the first run takes all the time there is
    monkeypatch.setattr(tiers._Loop, "_remaining", lambda self: 60.0 if self.rounds == 0 else -1.0)
    r = verified(decompiled("SimpleToken"), time_limit=60)
    check_invariants(r)
    done = r.verification.search
    assert done["rounds"] == 1 and done["exhausted_by"] == "time" and done["final_check"] is False
    assert r.functions[TRANSFER]["tier"] == "exact" and r.functions[TRANSFER]["verdict"] == "SKIPPED"
    assert r.functions[BALANCE_OF]["verdict"] == "EQUIVALENT"
    assert "budget exhausted (time limit of 60 s)" in r.solidity
    assert done["levels"]["L4"] == "skipped"
    compile_or_fail(r.solidity, SOLC)


def test_with_no_time_at_all_everything_is_exact_and_nothing_is_called_verified():
    tools()
    r = verified(decompiled("SimpleToken"), time_limit=1e-9)
    check_invariants(r)  # whatever the few calls made: nothing rewritten without an accepted run
    done = r.verification.search
    assert done["budget_exhausted"] is True and done["exhausted_by"] == "time"
    if done["rounds"] == 1 and not done["final_check"]:
        assert all(f["verdict"] in OK + ("SKIPPED",) for f in r.functions.values())
    compile_or_fail(r.solidity, SOLC)


def cut_short(monkeypatch, cut, *, takes_its_time=False):
    """The runs after the first one have a fraction of a second left, and
    scobelix.verify reports what such a run shows when its time limit stops
    it: `cut(result, report)` edits the report of the run made in full (the
    real run is not limited, so that the test does not depend on timing).
    `takes_its_time`: the run lasts as long as its limit, as a cut run does."""
    real = v2._check

    def check(result, code, budget, allow_download, options=None):
        limit = budget.l3_time_limit
        report, why = real(result, code, dataclasses.replace(budget, l3_time_limit=None), allow_download, options)
        if report is not None and "levels" not in (options or {}) and limit is not None and limit < 10:
            if takes_its_time:
                time.sleep(limit)
            cut(result, report, options or {})
        return report, why

    monkeypatch.setattr(v2, "_check", check)
    monkeypatch.setattr(tiers._Loop, "_remaining", lambda self: 60.0 if self.rounds == 0 else 0.3)


def test_an_agreement_on_the_few_calls_a_cut_run_made_accepts_nothing(monkeypatch):
    tools()
    break_pass(monkeypatch, "compound", TRANSFER, flip_comparisons)

    def one_call(result, report, options):
        # the time limit fell during the calls of transfer(): one call was made, it did not differ
        seen = report.functions[TRANSFER]
        report.functions[TRANSFER] = dataclasses.replace(
            seen, verdict="EQUIVALENT", reason="", calls=1, original_success=1, divergences=0,
            sequence_divergences=0, kinds={}, counterexample=None)

    cut_short(monkeypatch, one_call)
    r = verified(decompiled("SimpleToken"), time_limit=60, l4=False, max_rounds=8)
    check_invariants(r)
    transfer = r.functions[TRANSFER]
    assert "compound" not in transfer["passes"]  # the broken form is not kept on the strength of one call
    assert transfer["tier"] == "exact" and transfer["verdict"] == "SKIPPED"
    assert "this form was not run in full: budget exhausted (time limit of 60 s)" in transfer["reason"]
    done = r.verification.search
    assert done["budget_exhausted"] is True and done["exhausted_by"] == "time"
    assert done["final_check"] is False  # the last run of the whole text was cut too: it checked nothing
    assert r.verification.levels["L3"].status == "inconclusive" and not r.verification.passed
    for key in (BALANCE_OF, TOTAL_SUPPLY):  # run in full: they keep their form and its verdict
        assert r.functions[key]["tier"] == "idiomatic" and r.functions[key]["verdict"] == "EQUIVALENT"
    assert "the final text was not run as a whole" in r.solidity
    compile_or_fail(r.solidity, SOLC)


def test_a_difference_seen_in_a_form_is_not_undone_by_a_later_run_that_did_not_meet_it(monkeypatch):
    # the same form of a function (same code, same declarations) runs in several texts, and a run of
    # another text may not meet the sequence that showed its difference (an earlier call of the
    # sequence differed and ended it): what was seen of that form must stay seen, since a text that
    # is not run as a whole carries it
    tools()
    g = Generator(decompiled("SimpleToken"), SOLC, "full")
    loop = tiers._Loop(g, SearchBudget.of(QUICK), None)
    result = g.regenerate()
    real = v2._check
    runs = []

    def first_meets_the_sequence(result, code, budget, allow_download, options=None):
        report, why = real(result, code, budget, allow_download, options)
        runs.append(1)
        if len(runs) == 1:
            seen = report.functions[TRANSFER]
            report.functions[TRANSFER] = dataclasses.replace(seen, verdict="DIVERGENT", divergences=0,
                                                             sequence_divergences=1)
        return report, why

    monkeypatch.setattr(v2, "_check", first_meets_the_sequence)
    assert loop._execute(result).functions[TRANSFER].verdict == "DIVERGENT"
    assert loop._execute(result).functions[TRANSFER].verdict == "EQUIVALENT"
    state = loop._state(result)
    assert state[TRANSFER].verdict == "DIVERGENT" and state[BALANCE_OF].verdict == "EQUIVALENT"


def test_a_function_the_first_run_did_not_run_is_not_said_to_have_differed(monkeypatch):
    tools()
    real = v2._check
    runs = []

    def first_skips_transfer(result, code, budget, allow_download, options=None):
        report, why = real(result, code, budget, allow_download, options)
        if report is not None and "levels" not in (options or {}):
            runs.append(1)
            if len(runs) == 1:  # the first run did not reach transfer(): no call, no verdict
                seen = report.functions[TRANSFER]
                report.functions[TRANSFER] = dataclasses.replace(
                    seen, verdict="SKIPPED", reason="behaviour not checked", calls=0, original_success=0,
                    divergences=0, sequence_divergences=0, kinds={}, counterexample=None, coverage=None)
        return report, why

    monkeypatch.setattr(v2, "_check", first_skips_transfer)
    r = verified(decompiled("SimpleToken"), l4=False)
    check_invariants(r)
    transfer = r.functions[TRANSFER]
    assert transfer["tier"] == "exact" and transfer["verdict"] == "EQUIVALENT"  # run in exact form afterwards
    done = r.verification.search
    assert done["repaired"] == []  # nothing differed: nothing was repaired
    assert not [w for w in r.warnings if "did not behave like the original" in w]
    assert [w for w in r.warnings if w.startswith("verification: 1 function(s) could not be run against the "
                                                  "original") and TRANSFER in w]


def test_a_run_its_time_limit_stopped_before_the_sequences_is_no_run_of_the_whole_contract(monkeypatch):
    tools()

    def no_sequence(result, report, options):
        pass  # every function got its calls; the sequences, made last, did not run

    cut_short(monkeypatch, no_sequence, takes_its_time=True)
    cut_check = v2._check

    def sequences_only(result, code, budget, allow_download, options=None):
        # transfer() as the compound pass writes it differs only after other calls, which only the
        # runs of the whole contract that are not cut short make
        cut = budget.l3_time_limit is not None and budget.l3_time_limit < 10
        report, why = cut_check(result, code, budget, allow_download, options)
        options = options or {}
        if report is not None and "levels" not in options and not options.get("selectors") and not cut \
                and "compound" in result.functions[TRANSFER]["passes"]:
            seen = report.functions[TRANSFER]
            report.functions[TRANSFER] = dataclasses.replace(seen, verdict="DIVERGENT", divergences=0,
                                                             sequence_divergences=1)
        return report, why

    monkeypatch.setattr(v2, "_check", sequences_only)
    r = verified(decompiled("SimpleToken"), time_limit=60, l4=False, max_rounds=8)
    check_invariants(r)
    transfer = r.functions[TRANSFER]
    assert "compound" not in transfer["passes"]  # not accepted by runs that made no sequence
    done = r.verification.search
    assert done["final_check"] is False and done["exhausted_by"] == "time"
    assert r.verification.levels["L3"].status == "inconclusive"
    compile_or_fail(r.solidity, SOLC)


# ---------------------------------------------------------------- determinism, cost


def test_two_runs_give_the_same_text(monkeypatch):
    tools()
    break_pass(monkeypatch, "compound", TRANSFER, flip_comparisons)
    first, second = verified(decompiled("SimpleToken")), verified(decompiled("SimpleToken"))
    assert first.solidity == second.solidity
    assert first.functions_json() == second.functions_json() and first.warnings == second.warnings
    a, b = first.verification.search, second.verification.search
    assert {k: v for k, v in a.items() if k != "elapsed"} == {k: v for k, v in b.items() if k != "elapsed"}
    other = verified(decompiled("SimpleToken"), seed=7)
    assert other.functions[TRANSFER]["disabled_passes"] == ["compound"]


def test_no_text_is_compiled_twice_and_no_form_is_run_twice(monkeypatch):
    tools()
    from scobelix.verify import solc

    solc.clear_compile_cache()
    compiled, runs = [], []
    real_compile, real_check = solc._standard_json_output, v2._check

    def counting_compile(path, std_json, version, timeout):
        compiled.append(json.loads(std_json)["sources"]["Decompiled.sol"]["content"])
        return real_compile(path, std_json, version, timeout)

    def counting_check(result, code, budget, allow_download, options=None):
        runs.append(sorted((options or {}).get("selectors") or ["*"]))
        return real_check(result, code, budget, allow_download, options)

    monkeypatch.setattr(solc, "_standard_json_output", counting_compile)
    monkeypatch.setattr(v2, "_check", counting_check)
    break_pass(monkeypatch, "compound", TRANSFER, flip_comparisons)
    r = verified(decompiled("SimpleToken"), l4=False)
    done = r.verification.search
    whole = [keys for keys in runs if keys == ["*"]]
    assert len(whole) == 2 and runs[0] == ["*"] and runs[-1] == ["*"]  # the first run and the final check
    assert all(keys == [TRANSFER] for keys in runs[1:-1])  # in between, only the function searched is run
    assert done["rounds"] == len(runs)
    assert done["compilations"] == len(set(done_texts(compiled)))


def done_texts(compiled):
    # the storage pass compiles its declarations apart: not texts of the loop
    return [text for text in compiled if "contract Decompiled" in text]


def test_the_number_of_runs_is_bounded(monkeypatch):
    tools()
    for name in ("abi", "storage", "reverts", "arith", "compound"):
        break_pass(monkeypatch, name, TRANSFER, flip_comparisons)
    r = verified(decompiled("SimpleToken"), max_rounds=4)
    check_invariants(r)
    assert r.verification.search["rounds"] <= 4
    assert r.verification.search["max_rounds"] == 4


# ---------------------------------------------------------------- missing tools


def test_without_a_compiler_everything_is_exact_and_a_warning_says_why(monkeypatch):
    from scobelix.verify import solc

    monkeypatch.setattr(solc, "installed_solcs", lambda extra_dirs=(): {})
    monkeypatch.delenv(solc.DOWNLOAD_ENV, raising=False)
    storage_model._solc_path.cache_clear()
    try:
        r = generate_solidity(decompiled("SimpleToken"), verify=True)
    finally:
        storage_model._solc_path.cache_clear()
    check_invariants(r)
    assert {f["tier"] for f in r.functions.values()} == {"exact"}
    assert {f["verdict"] for f in r.functions.values()} == {"unverified"}
    assert [w for w in r.warnings if w.startswith("verification L0 skipped") and "not installed" in w]
    assert [w for w in r.warnings if w.startswith("verification: 3 function(s) could not be run against the "
                                                  "original and are written in exact form")]
    assert r.verification.levels["L0"].status == "skipped" and r.verification.passed is False
    assert r.verification.search["final_check"] is False and r.verification.search["rounds"] == 0
    assert r.verification.search["compilations"] == 0  # tried, but nothing could be compiled
    assert "verification: L0=skipped" in r.solidity and "0 text(s) compiled" in r.solidity


def test_without_an_evm_backend_everything_is_exact_and_a_warning_says_why(monkeypatch):
    solc_or_skip(SOLC)
    from scobelix.verify import core

    monkeypatch.setattr(core, "available_backends", lambda: [])
    r = generate_solidity(decompiled("SimpleToken"), verify=True, target_solc=SOLC)
    check_invariants(r)
    assert {f["tier"] for f in r.functions.values()} == {"exact"}
    assert r.verification.levels["L0"].status == "pass" and r.verification.levels["L3"].status == "skipped"
    assert [w for w in r.warnings if w.startswith("verification L3 skipped") and "scobelix[verify]" in w]
    assert [w for w in r.warnings if "could not be run against the original and are written in exact form" in w]
    assert not set(OK) & {f["verdict"] for f in r.functions.values()}
    assert r.verification.search["final_check"] is False
    compile_or_fail(r.solidity, SOLC)  # the levels that need no execution were checked on the text returned
    assert r.verification.levels["L1"].status == "pass"


def test_a_loop_that_fails_does_not_lose_the_text(monkeypatch):
    def boom(self):
        raise RuntimeError("no luck")

    monkeypatch.setattr(tiers._Loop, "run", boom)
    r = generate_solidity(decompiled("SimpleToken"), verify=True)
    assert r.verification is None and "contract Decompiled {" in r.solidity
    assert [w for w in r.warnings if w.startswith("verification unavailable: RuntimeError: no luck")]
    assert {f["tier"] for f in r.functions.values()} == {"exact"}


# ---------------------------------------------------------------- the report object


def test_the_verification_reads_like_the_report_of_the_last_run():
    tools()
    r = verified(decompiled("SimpleToken"))
    v = r.verification
    assert isinstance(v, tiers.Verification) and v.report.functions is v.functions
    assert v.functions[TRANSFER].verdict == "EQUIVALENT" and v.summary == v.report.summary
    assert v.to_json()["search"] == v.search and set(v.to_json()) >= {"passed", "levels", "summary", "functions"}
    assert r.verification_json()["search"]["rounds"] == 1
    assert set(r.verification_json()["levels"]) == {"L0", "L1", "L2", "L3", "L4"}
    with pytest.raises(AttributeError):
        v.no_such_attribute
    import copy
    import pickle

    assert copy.deepcopy(v).search == v.search
    assert pickle.loads(pickle.dumps(v.search)) == v.search


def test_bytecode_that_differs_does_not_fail_the_verification():
    from scobelix.verify.report import LevelResult, VerificationReport

    def report(l4):
        levels = {"L0": LevelResult("pass"), "L1": LevelResult("pass"), "L2": LevelResult("skipped", "x"),
                  "L3": LevelResult("pass"), "L4": LevelResult(l4)}
        return VerificationReport(levels, {}, {}, {}, {})

    assert report("fail").passed is False  # the verifier's own rule
    assert tiers.Verification(report("fail"), {}, []).passed is True
    assert tiers.Verification(report("pass"), {}, []).passed is True
    failed = report("pass")
    failed.levels["L3"] = LevelResult("fail")
    assert tiers.Verification(failed, {}, []).passed is False

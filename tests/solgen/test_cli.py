"""The command line around the Solidity generator: its flags, the combined
JSON object and the keys its callers rely on, and the environments in which
a compiler or an EVM backend is missing."""

import json
import logging

import pytest
from conftest import backend_or_skip, fixture_hex, solc_or_skip

from scobelix.__main__ import parse_args, print_decompilation

RETURN_42 = "602a60005260206000f3"  # a contract that returns 42 to every call
BASE_KEYS = {"text", "json", "solidity", "solgen_confidence", "solgen_warnings"}
NO_VERIFICATION = {"passed": False, "levels": {}, "summary": {}, "functions": {}}


def _run(capsys, *flags, code=RETURN_42):
    args = parse_args(list(flags) + [code])
    print_decompilation(code, args)
    captured = capsys.readouterr()
    return captured.out, captured.err


def _combined(capsys, *flags, code=RETURN_42):
    out, err = _run(capsys, "--combined-json", *flags, code=code)
    assert out.count("\n") == 1  # one line: the caller parses the whole output at once
    return json.loads(out), err


def _no_solc(monkeypatch):
    from scobelix.verify import solc

    monkeypatch.setattr(solc, "installed_solcs", lambda extra_dirs=(): {})
    monkeypatch.delenv(solc.DOWNLOAD_ENV, raising=False)


def _no_backend(monkeypatch):
    from scobelix.verify import core

    monkeypatch.setattr(core, "available_backends", lambda: [])


# ---------------------------------------------------------------- flags


def test_defaults():
    args = parse_args([RETURN_42])
    assert (args.solidity, args.verify, args.validate_solidity, args.combined_json) == (False, False, False, False)
    assert (args.idiom_level, args.target_solc, args.allow_solc_download) == ("full", None, False)


def test_generator_flags_are_parsed():
    args = parse_args(["--solidity", "--verify", "--target-solc", "0.8.21", "--allow-solc-download",
                       "--idiom-level", "exact", "--validate-solidity", RETURN_42])
    assert (args.solidity, args.verify, args.validate_solidity) == (True, True, True)
    assert (args.idiom_level, args.target_solc, args.allow_solc_download) == ("exact", "0.8.21", True)


@pytest.mark.parametrize("flags", [
    ["--target-solc", "latest"],
    ["--target-solc", "0.8"],
    ["--idiom-level", "fancy"],
])
def test_unusable_values_are_usage_errors(flags, capsys):
    with pytest.raises(SystemExit) as e:
        parse_args(flags + [RETURN_42])
    assert e.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_solidity_prints_the_source_and_nothing_else(capsys):
    out, err = _run(capsys, "--solidity")
    assert "pragma solidity" in out and "contract Decompiled {" in out
    assert "idiom level       : full" in out and "verdict=unverified" in out
    assert err == ""


def test_idiom_level_and_target_reach_the_generator(capsys):
    out, _ = _run(capsys, "--solidity", "--idiom-level", "exact", "--target-solc", "0.8.21")
    assert "idiom level       : exact" in out and "target compiler   : solc 0.8.21" in out
    full, _ = _run(capsys, "--solidity", code=fixture_hex("SimpleToken"))
    exact, _ = _run(capsys, "--solidity", "--idiom-level", "exact", code=fixture_hex("SimpleToken"))
    assert "tier=idiomatic" in full and "tier=idiomatic" not in exact.split("contract Decompiled")[1]


def test_function_restricts_the_text_and_says_what_is_left_out(capsys):
    code = fixture_hex("SimpleToken")
    out, err = _run(capsys, "--solidity", "--function", "transfer", code=code)
    body = out.split("contract Decompiled")[1]
    assert body.count("function ") == 1 and "function transfer(" in body
    assert "not decompiled    : 2 entry point(s)" in out and "the decompiler failed" not in out
    assert err == ""
    payload, _ = _combined(capsys, "--solidity", "--function", "transfer", code=code)
    assert set(payload["solgen_confidence"]) == set(payload["solgen_functions"]) == {"0xa9059cbb"}
    assert [w for w in payload["solgen_warnings"] if "left out of the text" in w and "0x70a08231" in w]


def test_generator_flags_do_nothing_without_solidity(capsys):
    plain, _ = _run(capsys)
    out, err = _run(capsys, "--verify", "--validate-solidity", "--idiom-level", "exact")
    assert out == plain and err == ""


# ---------------------------------------------------------------- combined JSON


def test_combined_json_keeps_its_keys_and_types(capsys):
    payload, err = _combined(capsys, "--solidity")
    assert set(payload) == BASE_KEYS | {"solgen_functions"}
    assert isinstance(payload["text"], str) and isinstance(payload["json"], dict)
    assert isinstance(payload["solidity"], str) and "contract Decompiled {" in payload["solidity"]
    confidence = payload["solgen_confidence"]
    assert isinstance(confidence, dict) and confidence
    assert set(confidence.values()) <= {"high", "medium", "low", "none"}
    assert isinstance(payload["solgen_warnings"], list)
    assert all(isinstance(w, str) for w in payload["solgen_warnings"])
    assert err == ""


def test_combined_json_function_table(capsys):
    payload, _ = _combined(capsys, "--solidity", code=fixture_hex("SimpleToken"))
    functions = payload["solgen_functions"]
    assert set(functions) == set(payload["solgen_confidence"])
    transfer = functions["0xa9059cbb"]
    assert transfer["signature"] == "transfer(address,uint256)" and transfer["selector"] == "0xa9059cbb"
    assert transfer["tier"] == "idiomatic" and transfer["verdict"] == "unverified"
    assert isinstance(transfer["passes"], list) and isinstance(transfer["flags"], list)
    assert transfer["confidence"] == payload["solgen_confidence"]["0xa9059cbb"]


def test_combined_json_without_solidity_has_no_generator_key(capsys):
    payload, _ = _combined(capsys, "--verify", "--validate-solidity")
    assert set(payload) == {"text", "json"}


def test_combined_json_validation(capsys):
    payload, _ = _combined(capsys, "--solidity", "--validate-solidity")
    assert set(payload) == BASE_KEYS | {"solgen_functions", "solgen_validation"}
    validation = payload["solgen_validation"]
    assert set(validation) == {"status", "errors", "warnings"}
    assert validation["status"] in ("valid", "skipped") and validation["errors"] == []


def test_combined_json_verification(capsys):
    solc_or_skip("0.8.19")
    backend_or_skip()
    payload, err = _combined(capsys, "--solidity", "--verify", "--target-solc", "0.8.19")
    assert set(payload) == BASE_KEYS | {"solgen_functions", "solgen_verification"}
    report = payload["solgen_verification"]
    assert report["passed"] is True
    assert {k: report["levels"][k]["status"] for k in ("L0", "L1", "L3")} == {"L0": "pass", "L1": "pass", "L3": "pass"}
    assert report["functions"]["fallback"]["verdict"] == "EQUIVALENT"
    assert payload["solgen_functions"]["_fallback"]["verdict"] == "EQUIVALENT"
    assert payload["solgen_confidence"]["_fallback"] == "high"
    assert "verdict=EQUIVALENT" in payload["solidity"]
    assert err == ""


# ---------------------------------------------------------------- verification on the terminal


def test_verify_prints_the_source_and_a_summary_on_stderr(capsys):
    solc_or_skip("0.8.19")
    backend_or_skip()
    out, err = _run(capsys, "--solidity", "--verify", "--target-solc", "0.8.19")
    # no state variable to check (L2); L4 is tried and its outcome stated, whatever it is
    assert "verdict=EQUIVALENT" in out and "verification: L0=pass  L1=pass  L2=skipped  L3=pass  L4=" in out
    lines = err.splitlines()
    assert lines[0].startswith("# verification: L0=pass  L1=pass  L2=skipped  L3=pass  L4=")
    assert lines[1].startswith("#   verdicts: ") and "EQUIVALENT" in lines[1]
    assert "#   tiers: 0 idiomatic, 0 partial, 1 exact" in lines and lines[-1].startswith("#   time: ")


def test_verify_timeout_is_the_time_limit_of_the_loop(monkeypatch, capsys):
    import scobelix.solgen as solgen

    real, seen = solgen.generate_solidity, {}

    def generate_solidity(decompilation, **kwargs):
        seen.update(kwargs)
        return real(decompilation, **dict(kwargs, verify=False))

    monkeypatch.setattr(solgen, "generate_solidity", generate_solidity)
    _run(capsys, "--solidity", "--verify", "--verify-timeout", "7.5")
    assert seen["verify"] is True and seen["budget"] == {"time_limit": 7.5}
    _run(capsys, "--solidity", "--verify")
    assert seen["budget"] is None  # the default limits of the loop
    for value in ("0", "-1", "inf", "soon"):
        with pytest.raises(SystemExit):
            parse_args(["--solidity", "--verify", "--verify-timeout", value, RETURN_42])
    capsys.readouterr()


# ---------------------------------------------------------------- generation failures


def _failing_generator(monkeypatch, error):
    import scobelix.solgen as solgen

    def generate_solidity(decompilation, **kwargs):
        raise error

    monkeypatch.setattr(solgen, "generate_solidity", generate_solidity)


def test_combined_json_keeps_text_and_ast_when_the_generation_fails(monkeypatch, capsys, caplog):
    _failing_generator(monkeypatch, RuntimeError("boom"))
    with caplog.at_level(logging.ERROR, logger="scobelix.__main__"):
        payload, _ = _combined(capsys, "--solidity")  # no SystemExit, no exception
    assert set(payload) == BASE_KEYS | {"solgen_functions", "solgen_error"}
    assert payload["text"] and isinstance(payload["json"], dict) and payload["json"]["functions"]
    assert payload["solidity"] == "" and payload["solgen_confidence"] == {} and payload["solgen_functions"] == {}
    assert payload["solgen_warnings"] == ["RuntimeError: boom"]
    assert payload["solgen_error"] == "RuntimeError: boom"
    # the traceback is logged (the command sends its log to stderr), never printed on stdout
    assert [r for r in caplog.records if r.levelno == logging.ERROR and r.exc_info and "boom" in str(r.exc_info[1])]


def test_combined_json_keeps_its_keys_when_the_generation_fails(monkeypatch, capsys):
    _failing_generator(monkeypatch, ValueError("no"))
    payload, _ = _combined(capsys, "--solidity", "--verify", "--validate-solidity")
    assert list(payload) == ["text", "json", "solidity", "solgen_confidence", "solgen_warnings", "solgen_functions",
                             "solgen_verification", "solgen_validation", "solgen_error"]
    assert payload["solgen_verification"] == dict(NO_VERIFICATION, warnings=["ValueError: no"])
    assert payload["solgen_validation"] == {"status": "skipped", "errors": [], "warnings": ["ValueError: no"]}
    assert payload["solgen_error"] == "ValueError: no"


def test_combined_json_keeps_the_source_when_the_validation_fails(monkeypatch, capsys):
    import scobelix.solgen as solgen

    def validate(result, allow_download=None, **kwargs):
        raise OSError("solc exploded")

    monkeypatch.setattr(solgen, "validate", validate)
    payload, _ = _combined(capsys, "--solidity", "--validate-solidity")
    assert set(payload) == BASE_KEYS | {"solgen_functions", "solgen_validation", "solgen_error"}
    assert "contract Decompiled {" in payload["solidity"] and payload["solgen_confidence"]
    assert payload["solgen_validation"] == {"status": "skipped", "errors": [], "warnings": ["OSError: solc exploded"]}
    assert payload["solgen_error"] == "OSError: solc exploded"


def test_combined_json_survives_an_interrupted_generation(monkeypatch, capsys):
    from scobelix.decompiler import TimeoutInterrupt

    _failing_generator(monkeypatch, TimeoutInterrupt("too long"))  # a BaseException
    payload, _ = _combined(capsys, "--solidity")
    assert payload["text"] and payload["solidity"] == ""
    assert payload["solgen_error"] == "TimeoutInterrupt: 'too long'"


def test_solidity_alone_still_fails_when_the_generation_fails(monkeypatch, capsys):
    # nothing usable to print: the exception propagates (exit status 1 under the command)
    _failing_generator(monkeypatch, RuntimeError("boom"))
    with pytest.raises(RuntimeError):
        _run(capsys, "--solidity")
    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------- the time budget


def _clock_reading(monkeypatch, values):
    """decompiler._clock gives `values` one by one, then the last one. A
    decompilation reads it three times for RETURN_42 (the budget starts,
    the discovery, one function); the command reads it before the
    generation and before the validation."""
    import scobelix.decompiler as decompiler

    values = list(values)
    monkeypatch.setattr(decompiler, "_clock", lambda: values.pop(0) if len(values) > 1 else values[0])


def test_the_budget_reaches_the_decompiler_and_the_payload(monkeypatch, capsys):
    import scobelix.__main__ as cli
    from scobelix.decompiler import decompile_bytecode

    seen = []

    def spy(code, only_func_name=None, *, time_budget=None):
        seen.append(time_budget)
        return decompile_bytecode(code, only_func_name, time_budget=time_budget)

    monkeypatch.setattr(cli, "decompile_bytecode", spy)
    monkeypatch.delenv("SCOBELIX_TIME_BUDGET", raising=False)
    payload, _ = _combined(capsys)
    assert seen == [None] and "time_budget" not in payload
    payload, err = _combined(capsys, "--solidity", "--time-budget", "100")
    assert seen[-1] == 100.0 and err == ""
    assert list(payload)[-1] == "time_budget"
    assert payload["time_budget"] == {"seconds": 100.0, "exhausted": False, "skipped": []}
    assert "contract Decompiled {" in payload["solidity"]
    monkeypatch.setenv("SCOBELIX_TIME_BUDGET", "50")
    payload, _ = _combined(capsys)
    assert seen[-1] == 50.0 and payload["time_budget"]["seconds"] == 50.0


def test_the_generation_is_skipped_when_the_budget_is_exhausted(monkeypatch, capsys):
    import scobelix.solgen as solgen

    calls = []
    monkeypatch.setattr(solgen, "generate_solidity", lambda decompilation, **kwargs: calls.append(kwargs))
    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 99.0])  # 1 s left after the decompilation
    payload, _ = _combined(capsys, "--solidity", "--verify", "--validate-solidity", "--time-budget", "100")
    assert calls == []
    message = "time budget exhausted before the Solidity generation"
    assert payload["text"] and payload["json"]["functions"]
    assert payload["solidity"] == "" and payload["solgen_confidence"] == {} and payload["solgen_functions"] == {}
    assert payload["solgen_warnings"] == [message] and payload["solgen_error"] == message
    assert payload["solgen_verification"] == dict(NO_VERIFICATION, warnings=[message])
    assert payload["solgen_validation"] == {"status": "skipped", "errors": [], "warnings": [message]}
    assert payload["time_budget"] == {"seconds": 100.0, "exhausted": True, "skipped": []}


def test_the_generation_is_interrupted_when_it_outlives_the_budget(monkeypatch, capsys):
    import signal
    import time

    import scobelix.__main__ as cli
    import scobelix.solgen as solgen

    def sleeping(decompilation, **kwargs):
        time.sleep(2)
        raise AssertionError("not interrupted")

    monkeypatch.setattr(solgen, "generate_solidity", sleeping)
    monkeypatch.setattr(cli, "OUTPUT_RESERVE", 0.05)
    monkeypatch.setattr(cli, "SOLGEN_MIN_SECONDS", 0.05)
    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 99.7])  # 0.3 s left: 0.25 s for the generation
    payload, _ = _combined(capsys, "--solidity", "--time-budget", "100")
    assert payload["text"] and payload["solidity"] == ""
    assert payload["solgen_error"] == "Solidity generation interrupted by the time budget"
    assert payload["time_budget"]["exhausted"] is True
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)  # the alarm is disarmed afterwards


def test_the_verification_and_the_validation_are_capped_by_the_budget(monkeypatch, capsys):
    import scobelix.solgen as solgen

    real, seen = solgen.generate_solidity, {}

    def generate_solidity(decompilation, **kwargs):
        seen["budget"] = kwargs["budget"]
        return real(decompilation, **dict(kwargs, verify=False))

    real_validate = solgen.validate

    def validate(result, allow_download=None, **kwargs):
        seen["validate"] = kwargs
        return real_validate(result, allow_download=allow_download, **kwargs)

    monkeypatch.setattr(solgen, "generate_solidity", generate_solidity)
    monkeypatch.setattr(solgen, "validate", validate)
    monkeypatch.delenv("SCOBELIX_TIME_BUDGET", raising=False)
    flags = ["--solidity", "--verify", "--validate-solidity", "--time-budget", "100"]
    # 20 s left, 2 of them for the output: 18 s for the generation, its
    # verification loop stopping 4.5 s (a quarter) before them
    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 80.0])
    _combined(capsys, *flags, "--verify-timeout", "1000")
    assert seen["budget"] == {"time_limit": 13.5} and seen["validate"] == {"timeout": 18.0}
    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 80.0])
    _combined(capsys, *flags, "--verify-timeout", "7.5")
    assert seen["budget"] == {"time_limit": 7.5} and seen["validate"] == {"timeout": 18.0}
    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 80.0])
    _combined(capsys, *flags)
    assert seen["budget"] == {"time_limit": 13.5}
    # 6 s left: 4 for the generation, of which the loop gets all but the 2 s of the output reserve
    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 94.0])
    _combined(capsys, *flags)
    assert seen["budget"] == {"time_limit": 2.0}
    # plenty of time left: the loop keeps its own limit, 300 s by default
    _clock_reading(monkeypatch, [0.0])
    _combined(capsys, "--solidity", "--verify", "--time-budget", "3600")
    assert seen["budget"] == {"time_limit": 300.0}
    _clock_reading(monkeypatch, [0.0])
    _combined(capsys, "--solidity", "--verify", "--time-budget", "1000", "--verify-timeout", "1000")
    assert seen["budget"] == {"time_limit": (1000 - 2) * 0.75}
    _combined(capsys, "--solidity", "--verify", "--validate-solidity")  # no budget: as before
    assert seen["budget"] is None and seen["validate"] == {}


def test_under_a_budget_the_verification_loop_stops_before_the_alarm(monkeypatch, capsys):
    # Every run of the loop lasts as long as the time it is given: the loop
    # runs out of it, stops by itself and writes the functions it did not
    # accept in exact form, before the alarm of the generation - the source
    # is printed, the budget marked exhausted.
    import dataclasses
    import time

    import scobelix.__main__ as cli
    import scobelix.solgen.v2 as v2

    solc_or_skip("0.8.19")
    backend_or_skip()
    real_check = v2._check

    def slow_check(result, code, budget, allow_download, options=None):
        limit = getattr(budget, "l3_time_limit", None)
        if limit:
            time.sleep(limit)
            budget = dataclasses.replace(budget, l3_time_limit=1e-3)
        return real_check(result, code, budget, allow_download, options)

    monkeypatch.setattr(v2, "_check", slow_check)
    monkeypatch.setattr(cli, "OUTPUT_RESERVE", 4.0)
    # SimpleToken: the budget starts, the discovery, 4 functions, then the
    # generation, with 9 s left: 5 s for it, 1 s for its loop
    _clock_reading(monkeypatch, [0.0] * 6 + [91.0])
    flags = ["--solidity", "--verify", "--target-solc", "0.8.19", "--time-budget", "100"]
    started = time.monotonic()
    payload, _ = _combined(capsys, *flags, code=fixture_hex("SimpleToken"))
    assert time.monotonic() - started < 30
    assert "solgen_error" not in payload and "contract Decompiled {" in payload["solidity"]
    search = payload["solgen_verification"]["search"]
    assert search["time_limit"] == 1.0 and search["exhausted_by"] == "time"
    assert payload["solgen_functions"]["0xa9059cbb"]["tier"] == "exact"
    assert payload["time_budget"]["exhausted"] is True


def test_the_budget_is_exhausted_when_the_time_it_left_cuts_the_compiler_short(monkeypatch, capsys):
    import scobelix.solgen as solgen
    from scobelix.solgen.validate import ValidationResult

    out_of_time = ValidationResult("skipped", [], ["solc timed out after 3.0s"], "0.8.19", out_of_time=True)
    monkeypatch.setattr(solgen, "validate", lambda result, allow_download=None, **kwargs: out_of_time)
    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 95.0])
    payload, _ = _combined(capsys, "--solidity", "--validate-solidity", "--time-budget", "100")
    assert payload["solgen_validation"] == {"status": "skipped", "errors": [], "warnings": ["solc timed out after 3.0s"]}
    assert payload["time_budget"]["exhausted"] is True and "solgen_error" not in payload
    # a compiler that ends in time leaves the budget as it is
    valid = ValidationResult("valid", [], [], "0.8.19")
    monkeypatch.setattr(solgen, "validate", lambda result, allow_download=None, **kwargs: valid)
    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 95.0])
    payload, _ = _combined(capsys, "--solidity", "--validate-solidity", "--time-budget", "100")
    assert payload["time_budget"]["exhausted"] is False


def test_the_validation_is_skipped_when_no_time_is_left(monkeypatch, capsys):
    import scobelix.solgen as solgen

    calls = []
    monkeypatch.setattr(solgen, "validate", lambda result, allow_download=None, **kwargs: calls.append(kwargs))
    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 95.0, 99.5])  # 3 s for the generation, none for the validation
    payload, _ = _combined(capsys, "--solidity", "--validate-solidity", "--time-budget", "100")
    assert calls == [] and "solgen_error" not in payload
    assert "contract Decompiled {" in payload["solidity"]
    assert payload["solgen_validation"] == {"status": "skipped", "errors": [],
                                            "warnings": ["time budget exhausted before the Solidity validation"]}
    assert payload["time_budget"]["exhausted"] is True
    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 95.0, 99.5])
    out, err = _run(capsys, "--solidity", "--validate-solidity", "--time-budget", "100")
    assert "contract Decompiled {" in out
    assert err.splitlines() == ["# solc validation: skipped",
                                "#   time budget exhausted before the Solidity validation"]


def test_a_budget_too_long_for_an_alarm_sets_no_limit(capsys):
    # signal.setitimer refuses about 9.2e9 s and more: the alarm of the
    # generation is capped (31 years)
    payload, err = _combined(capsys, "--solidity", "--time-budget", "1e10")
    assert "contract Decompiled {" in payload["solidity"] and "solgen_error" not in payload
    assert payload["time_budget"] == {"seconds": 1e10, "exhausted": False, "skipped": []}
    out, _ = _run(capsys, "--solidity", "--time-budget", "1e10")
    assert "contract Decompiled {" in out


def test_solidity_alone_fails_when_the_budget_leaves_no_time_for_the_generation(monkeypatch, capsys):
    from scobelix.decompiler import TimeoutInterrupt

    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 99.0])
    with pytest.raises(TimeoutInterrupt):
        _run(capsys, "--solidity", "--time-budget", "100")
    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------- missing tools


def test_verify_without_a_compiler_degrades_to_a_warning(monkeypatch, capsys):
    _no_solc(monkeypatch)
    out, err = _run(capsys, "--solidity", "--verify")
    assert "contract Decompiled {" in out and "verdict=unverified" in out
    lines = err.splitlines()
    assert lines[0].startswith("# verification: L0=skipped")
    assert any(line.startswith("#   verification L0 skipped") and "not installed" in line for line in lines)
    assert "Traceback" not in err


def test_combined_json_verify_without_a_compiler(monkeypatch, capsys):
    _no_solc(monkeypatch)
    payload, err = _combined(capsys, "--solidity", "--verify", "--validate-solidity")
    assert set(payload) == BASE_KEYS | {"solgen_functions", "solgen_verification", "solgen_validation"}
    report = payload["solgen_verification"]
    assert report["passed"] is False and report["levels"]["L0"]["status"] == "skipped"
    assert report["functions"] == {}
    assert any(w.startswith("verification L0 skipped") for w in payload["solgen_warnings"])
    assert payload["solgen_functions"]["_fallback"]["verdict"] == "unverified"
    assert payload["solgen_validation"]["status"] == "skipped"
    assert payload["solgen_validation"]["warnings"]
    assert err == ""


def test_verify_without_an_evm_backend_degrades_to_a_warning(monkeypatch, capsys):
    solc_or_skip("0.8.19")
    _no_backend(monkeypatch)
    out, err = _run(capsys, "--solidity", "--verify", "--target-solc", "0.8.19")
    assert "contract Decompiled {" in out and "verdict=EQUIVALENT" not in out
    assert err.splitlines()[0].startswith("# verification: L0=pass")
    assert "L3=skipped" in err.splitlines()[0]
    assert any(line.startswith("#   verification L3 skipped") for line in err.splitlines())
    assert "Traceback" not in err


def test_verify_without_the_verify_package(monkeypatch, capsys):
    import sys

    for name in [m for m in sys.modules if m.startswith("scobelix.verify.")]:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setitem(sys.modules, "scobelix.verify", None)
    payload, err = _combined(capsys, "--solidity", "--verify")
    report = payload["solgen_verification"]
    assert report["passed"] is False and report["levels"] == {} and report["functions"] == {}
    assert report["warnings"] and report["warnings"][0].startswith("verification unavailable")
    assert err == ""
    out, err = _run(capsys, "--solidity", "--verify")
    assert "contract Decompiled {" in out
    assert err.splitlines()[0] == "# verification: unavailable"
    assert "Traceback" not in err


def test_validate_without_a_compiler_is_skipped(monkeypatch, capsys):
    _no_solc(monkeypatch)
    out, err = _run(capsys, "--solidity", "--validate-solidity")
    assert "contract Decompiled {" in out
    assert err.splitlines() == ["# solc validation: skipped"]


def test_validate_reports_on_stderr(capsys):
    solc_or_skip("0.8.19")
    out, err = _run(capsys, "--solidity", "--validate-solidity", "--target-solc", "0.8.19")
    assert "contract Decompiled {" in out
    assert err.splitlines() == ["# solc validation: valid"]


def test_validate_names_the_pipeline_a_text_needs(monkeypatch, capsys):
    import scobelix.solgen as solgen
    from scobelix.solgen.validate import VIA_IR_ONLY, ValidationResult

    def only_with_the_ir_pipeline(result, allow_download=None):
        return ValidationResult("valid", [], [VIA_IR_ONLY], "0.8.19", via_ir=True)

    monkeypatch.setattr(solgen, "validate", only_with_the_ir_pipeline)
    _, err = _run(capsys, "--solidity", "--validate-solidity")
    assert err.splitlines() == ["# solc validation: valid", "#   " + VIA_IR_ONLY]
    payload, err = _combined(capsys, "--solidity", "--validate-solidity")
    assert payload["solgen_validation"] == {"status": "valid", "errors": [], "warnings": [VIA_IR_ONLY]}
    assert err == ""


def test_a_failed_verification_is_named_on_stderr_and_in_the_warnings(capsys):
    solc_or_skip("0.8.19")
    backend_or_skip()
    # the text of one function only does not behave like the whole original
    flags = ["--solidity", "--verify", "--target-solc", "0.8.19", "--function", "transfer"]
    out, err = _run(capsys, *flags, code=fixture_hex("SimpleToken"))
    lines = err.splitlines()
    assert lines[0].startswith("# verification: L0=pass  L1=fail  L2=pass  L3=fail  L4=")
    # the interface lacks the two functions that were not decompiled, and the calls to them differ
    assert any(line.startswith("#   verification L1 fail: missing") and "0x70a08231" in line for line in lines)
    assert any(line.startswith("#   verification L3 fail") and "0x70a08231" in line for line in lines)
    assert "NOT EQUIVALENT: on 2 entry point(s)" in out
    payload, _ = _combined(capsys, *flags, code=fixture_hex("SimpleToken"))
    report = payload["solgen_verification"]
    assert report["passed"] is False
    assert {report["functions"][k]["verdict"] for k in ("0x18160ddd", "0x70a08231")} == {"MISSING"}
    assert any(w.startswith("verification L3 fail") for w in payload["solgen_warnings"])
    assert payload["solgen_functions"]["0xa9059cbb"]["verdict"] == "EQUIVALENT"

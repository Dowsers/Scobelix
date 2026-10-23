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

import json

import pytest

from scobelix.__main__ import parse_args, print_decompilation

FIXTURE_BYTECODE = "602a60005260206000f3"  # trivial "return 42"


@pytest.fixture(autouse=True)
def _no_time_budget_from_the_environment(monkeypatch):
    """The command reads SCOBELIX_TIME_BUDGET at every invocation: these
    tests run without it, whatever the environment they run in."""
    monkeypatch.delenv("SCOBELIX_TIME_BUDGET", raising=False)


def test_combined_json_with_solidity_has_all_expected_keys(capsys):
    args = parse_args(["--combined-json", "--solidity", FIXTURE_BYTECODE])
    print_decompilation(FIXTURE_BYTECODE, args)

    out = capsys.readouterr().out
    payload = json.loads(out)

    assert set(payload.keys()) == {
        "text",
        "json",
        "solidity",
        "solgen_confidence",
        "solgen_warnings",
        "solgen_functions",
    }
    assert "Reconstructed from runtime bytecode by Scobelix" in payload["solidity"]
    assert payload["solgen_confidence"]
    assert isinstance(payload["solgen_warnings"], list)
    assert set(payload["solgen_functions"]) == set(payload["solgen_confidence"])


def test_combined_json_without_solidity_only_has_text_and_json(capsys):
    args = parse_args(["--combined-json", FIXTURE_BYTECODE])
    print_decompilation(FIXTURE_BYTECODE, args)

    out = capsys.readouterr().out
    payload = json.loads(out)

    assert set(payload.keys()) == {"text", "json"}


def test_combined_json_output_is_valid_single_line_json(capsys):
    # the worker parses this with json.loads() on the whole stdout - it must
    # not be pretty-printed/multi-line like --json alone is.
    args = parse_args(["--combined-json", FIXTURE_BYTECODE])
    print_decompilation(FIXTURE_BYTECODE, args)

    out = capsys.readouterr().out
    assert out.count("\n") == 1  # the single trailing newline from print()

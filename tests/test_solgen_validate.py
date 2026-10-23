import pytest

from scobelix.solgen.validate import VIA_IR_NO_TIME, VIA_IR_ONLY, validate, validate_solidity
from scobelix.verify.solc import installed_solcs, versions_matching

# validate_solidity pins the compiler to a release the pragma accepts (never the solc-select shim)
SOLC = (versions_matching(["^0.8.19"], installed_solcs()) or [None])[-1]

# seventeen values live at once: more than the stack window of the default pipeline
STACK_TOO_DEEP = """
pragma solidity ^0.8.19;
contract C {
    function f(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e, uint256 g, uint256 h, uint256 i)
        external pure returns (uint256 r)
    {
        uint256 j = a + 1; uint256 k = b + 2; uint256 l = c + 3; uint256 m = d + 4;
        uint256 n = e + 5; uint256 o = g + 6; uint256 p = h + 7; uint256 q = i + 8;
        r = a + b + c + d + e + g + h + i + j + k + l + m + n + o + p + q;
    }
}
"""


def test_skipped_when_solc_binary_not_found():
    r = validate_solidity("pragma solidity ^0.8.0; contract C {}", solc_path="/no/such/solc")
    assert r.status == "skipped"
    assert r.errors == []


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_valid_source_reports_valid():
    r = validate_solidity(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.19;\n"
        "contract C { function f() external pure returns (uint256) { return 1; } }\n"
    )
    assert r.status == "valid"
    assert r.errors == []
    assert r.solc_version == SOLC
    assert r.via_ir is False and VIA_IR_ONLY not in r.warnings


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_a_source_valid_for_the_ir_pipeline_only_says_so():
    r = validate_solidity(STACK_TOO_DEEP)
    assert r.status == "valid" and r.errors == []
    # `solc file.sol` rejects it: the caller is told which options it takes
    assert r.via_ir is True and r.warnings[0] == VIA_IR_ONLY


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_requested_version_is_used_when_the_pragma_accepts_it():
    versions = versions_matching(["^0.8.0"], installed_solcs())
    r = validate_solidity("pragma solidity ^0.8.0; contract C {}", solc_version=versions[0])
    assert r.status == "valid"
    assert r.solc_version == versions[0]
    # a version the pragma refuses is not forced on the source
    r = validate_solidity("pragma solidity ^0.8.19; contract C {}", solc_version="0.7.6")
    assert r.status == "valid"
    assert r.solc_version == SOLC


def test_skipped_when_no_installed_solc_fits_and_downloads_are_off():
    r = validate_solidity("pragma solidity =0.3.1; contract C {}", allow_download=False)
    assert r.status == "skipped"
    assert r.errors == []
    assert r.warnings and "validation skipped" in r.warnings[0]


def test_validate_takes_a_result_and_the_download_switch():
    class Result:
        solidity = "pragma solidity =0.3.1; contract C {}"
        target_solc = "0.3.1"

    r = validate(Result(), allow_download=False)
    assert r.status == "skipped"


def test_validate_caps_the_compiler_time_by_a_time_left(monkeypatch):
    import importlib

    module = importlib.import_module("scobelix.solgen.validate")  # the package exports the function of that name
    seen = []
    monkeypatch.setattr(module, "validate_solidity", lambda source, **kwargs: seen.append(kwargs))

    class Result:
        solidity = "pragma solidity ^0.8.0; contract C {}"
        target_solc = None

    validate(Result())
    assert "timeout" not in seen[-1] and "total_timeout" not in seen[-1]  # the defaults of validate_solidity
    validate(Result(), timeout=5)
    assert seen[-1]["timeout"] == 5 and seen[-1]["total_timeout"] == 5
    validate(Result(), timeout=1000)
    assert seen[-1]["timeout"] == module.DEFAULT_TIMEOUT == 30 and seen[-1]["total_timeout"] == 1000


def _compiler_runs(monkeypatch, durations, timed_out=()):
    """solc replaced by a recorder: every run reports 'Stack too deep' after
    the next of `durations` (seconds of the validation's clock), the runs
    numbered in `timed_out` (from 1) time out instead; the recorder lists
    (with --via-ir, time limit) of every run."""
    import importlib
    import subprocess

    module = importlib.import_module("scobelix.solgen.validate")
    now, runs, durations = [0.0], [], list(durations)
    monkeypatch.setattr(module, "_clock", lambda: now[0])
    monkeypatch.setattr(module, "solc_for_source", lambda source, version, allow: ("0.8.19", "/no/such/solc"))

    def run(cmd, *, timeout, **kwargs):
        runs.append(("--via-ir" in cmd, timeout))
        now[0] += durations.pop(0)
        if len(runs) in timed_out:
            raise subprocess.TimeoutExpired(cmd, timeout)
        return subprocess.CompletedProcess(cmd, 1, "", "Error: Stack too deep. Try compiling with --via-ir.\n")

    monkeypatch.setattr(subprocess, "run", run)
    return runs


def test_a_total_time_bounds_both_runs_of_the_compiler(monkeypatch):
    # 10 s for the whole validation: the first run takes 6 of them, the run
    # with --via-ir gets the 4 left
    runs = _compiler_runs(monkeypatch, [6.0, 1.0])
    r = validate_solidity(STACK_TOO_DEEP, total_timeout=10)
    assert runs == [(False, 10.0), (True, 4.0)]
    assert r.status == "invalid" and not r.out_of_time
    # nothing left after the first run: the second one is not made
    runs = _compiler_runs(monkeypatch, [10.0])
    r = validate_solidity(STACK_TOO_DEEP, total_timeout=10)
    assert runs == [(False, 10.0)]
    assert (r.status, r.errors, r.warnings, r.out_of_time) == ("skipped", [], [VIA_IR_NO_TIME], True)
    # the second run cut short by what was left
    runs = _compiler_runs(monkeypatch, [6.0, 4.0], timed_out={2})
    r = validate_solidity(STACK_TOO_DEEP, total_timeout=10)
    assert runs == [(False, 10.0), (True, 4.0)]
    assert (r.status, r.warnings, r.out_of_time) == ("skipped", ["solc timed out after 4.0s"], True)
    # a run cut short by its own time limit, not by the total: not out of time
    runs = _compiler_runs(monkeypatch, [30.0], timed_out={1})
    r = validate_solidity(STACK_TOO_DEEP, total_timeout=100)
    assert runs == [(False, 30)] and r.warnings == ["solc timed out after 30s"] and not r.out_of_time


def test_without_a_total_time_every_run_has_its_own_limit(monkeypatch):
    runs = _compiler_runs(monkeypatch, [25.0, 25.0])
    r = validate_solidity(STACK_TOO_DEEP)
    assert runs == [(False, 30), (True, 30)] and r.status == "invalid" and not r.out_of_time
    runs = _compiler_runs(monkeypatch, [30.0], timed_out={1})
    r = validate_solidity(STACK_TOO_DEEP, timeout=12)
    assert runs == [(False, 12)] and r.warnings == ["solc timed out after 12s"] and not r.out_of_time


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_validate_prefers_the_target_of_the_result():
    versions = versions_matching(["^0.8.0"], installed_solcs())

    class Result:
        solidity = "pragma solidity ^0.8.0; contract C {}"
        target_solc = versions[0]

    assert validate(Result()).solc_version == versions[0]

    class Untargeted:
        solidity = Result.solidity

    assert validate(Untargeted()).solc_version == versions[-1]


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_invalid_source_reports_invalid_with_errors():
    r = validate_solidity("this is not solidity at all {{{")
    assert r.status == "invalid"
    assert len(r.errors) > 0

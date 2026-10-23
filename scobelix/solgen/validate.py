"""
Optional validation of solgen's generated Solidity: does it actually parse
with a real solc, not just look plausible?

solc is NOT a dependency of this package (pyproject.toml declares none).
The binary is located by `scobelix.verify.solc`: a release build whose
version the source's `pragma solidity` accepts, identified by running it
(the solc-select shim on PATH is never used: it silently compiles with
whatever version is globally selected).  This module degrades gracefully
(status="skipped") when no installed solc fits, so callers can opt in
without Scobelix itself requiring a solc install; with
SCOBELIX_ALLOW_SOLC_DOWNLOAD=1 the official build is downloaded instead.
"""

import dataclasses
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from scobelix.verify.solc import SolcNotFound, solc_for_source, version_key


VIA_IR_ONLY = (
    "compiles with --via-ir --optimize only: the default pipeline of solc reports 'Stack too deep'"
)
VIA_IR_NO_TIME = (
    "no time left to compile with --via-ir --optimize: the default pipeline of solc reports 'Stack too deep'"
)

# seconds one solc run may take
DEFAULT_TIMEOUT = 30

# the clock of `total_timeout` (an indirection, so that the tests can move it)
_clock = time.monotonic


@dataclasses.dataclass
class ValidationResult:
    status: str  # "valid" | "invalid" | "skipped"
    errors: list
    warnings: list
    solc_version: Optional[str] = None  # the compiler version that was used, when known
    # the source is valid for the IR pipeline only (`warnings` then starts with VIA_IR_ONLY)
    via_ir: bool = False
    # the time all the runs of solc had together (total_timeout) ran out: one was
    # cut short by it, or none was left for the run with --via-ir (status "skipped")
    out_of_time: bool = False


def validate_solidity(
    source: str,
    solc_path: str = None,
    timeout: float = DEFAULT_TIMEOUT,
    *,
    solc_version: Optional[str] = None,
    allow_download: Optional[bool] = None,
    total_timeout: Optional[float] = None,
) -> ValidationResult:
    """
    Compiles `source` with solc --bin and reports whether it's valid.

    Only checks that solc accepts the source (parses/type-checks and can
    produce bytecode) - it says nothing about whether the generated code is
    a *faithful* reconstruction of the original bytecode (that is what
    `scobelix.verify.verify` checks).  A source the default pipeline rejects
    with "Stack too deep" is compiled again with --via-ir --optimize (solc
    >= 0.8.13): when that succeeds the status is "valid", `via_ir` is set
    and the first warning says so.  `solc_path` forces a binary; by
    default `solc_version` is used when the pragmas accept it and it is
    installed, else the newest installed solc they accept.  `allow_download`
    lets a missing release be fetched (default: the
    SCOBELIX_ALLOW_SOLC_DOWNLOAD environment variable).  `timeout` bounds
    every run of solc; `total_timeout`, when given, bounds them all
    together: a run gets the smaller of `timeout` and what is left of it,
    the run with --via-ir is not made when nothing is left (status
    "skipped", warning VIA_IR_NO_TIME), and `out_of_time` tells that it
    ran out.
    """
    version = None
    via_ir = False
    if solc_path is None:
        try:
            version, solc_path = solc_for_source(source, solc_version, allow_download)
        except SolcNotFound as e:
            return ValidationResult(
                status="skipped", errors=[], warnings=[f"{e} - validation skipped"]
            )
    deadline = None if total_timeout is None else _clock() + total_timeout

    def run_limit():
        """The time limit of the next run of solc, and whether the total
        time sets it."""
        if deadline is None:
            return timeout, False
        left = deadline - _clock()
        return (left, True) if left < timeout else (timeout, False)

    with tempfile.TemporaryDirectory() as tmpdir:
        sol_path = Path(tmpdir) / "Decompiled.sol"
        sol_path.write_text(source, encoding="utf-8")

        limit, by_total = run_limit()
        try:
            result = subprocess.run(
                [solc_path, "--bin", str(sol_path)],
                capture_output=True,
                text=True,
                timeout=limit,
            )
            if (
                result.returncode != 0
                and "tack too deep" in result.stderr
                and version is not None
                and version_key(version) >= (0, 8, 13)
            ):
                # like scobelix.verify: the legacy pipeline ran out of stack slots
                limit, by_total = run_limit()
                if limit <= 0:
                    return ValidationResult(
                        status="skipped",
                        errors=[],
                        warnings=[VIA_IR_NO_TIME],
                        solc_version=version,
                        out_of_time=True,
                    )
                result = subprocess.run(
                    [solc_path, "--via-ir", "--optimize", "--bin", str(sol_path)],
                    capture_output=True,
                    text=True,
                    timeout=limit,
                )
                via_ir = result.returncode == 0
        except subprocess.TimeoutExpired:
            return ValidationResult(
                status="skipped",
                errors=[],
                warnings=[f"solc timed out after {round(limit, 3) if by_total else limit}s"],
                solc_version=version,
                out_of_time=by_total,
            )
        except OSError as e:
            return ValidationResult(
                status="skipped",
                errors=[],
                warnings=[f"solc invocation failed: {e}"],
                solc_version=version,
            )

    stderr_lines = result.stderr.splitlines()
    errors = [line for line in stderr_lines if line.strip().startswith("Error")]
    warnings = [line for line in stderr_lines if line.strip().startswith("Warning")]

    if result.returncode != 0 or errors:
        return ValidationResult(
            status="invalid",
            errors=errors or [result.stderr],
            warnings=warnings,
            solc_version=version,
        )

    if via_ir:
        warnings.insert(0, VIA_IR_ONLY)
    return ValidationResult(
        status="valid", errors=[], warnings=warnings, solc_version=version, via_ir=via_ir
    )


def validate(solgen_result, allow_download: Optional[bool] = None, *,
             timeout: Optional[float] = None) -> ValidationResult:
    """Convenience wrapper: solgen_result is a SolgenResult (has .solidity;
    its target compiler, when it names one, is the preferred solc).
    `timeout` is what is left of a time budget: the time the whole
    validation may take, both runs of solc together when the first one
    reports 'Stack too deep' (`total_timeout` of validate_solidity), each
    run taking DEFAULT_TIMEOUT at most."""
    limits = {} if timeout is None else {"timeout": min(DEFAULT_TIMEOUT, timeout), "total_timeout": timeout}
    return validate_solidity(
        solgen_result.solidity,
        solc_version=getattr(solgen_result, "target_solc", None) or None,
        allow_download=allow_download,
        **limits,
    )

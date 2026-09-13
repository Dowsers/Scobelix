"""
Optional validation of solgen's generated Solidity: does it actually parse
with a real solc, not just look plausible?

solc is NOT a dependency of this package (pyproject.toml declares none) -
this module degrades gracefully (status="skipped") when it isn't on PATH,
so callers can opt in without Scobelix itself requiring a solc install.
"""

import dataclasses
import shutil
import subprocess
import tempfile
from pathlib import Path


@dataclasses.dataclass
class ValidationResult:
    status: str  # "valid" | "invalid" | "skipped"
    errors: list
    warnings: list


def validate_solidity(source: str, solc_path: str = None, timeout: int = 30) -> ValidationResult:
    """
    Compiles `source` with solc --bin and reports whether it's valid.

    Only checks that solc accepts the source (parses/type-checks and can
    produce bytecode) - it says nothing about whether the generated code is
    a *faithful* reconstruction of the original bytecode, which solgen
    cannot guarantee (see the "// approximation:" comments it emits inline).
    """
    solc = solc_path or shutil.which("solc")
    if solc is None:
        return ValidationResult(
            status="skipped", errors=[], warnings=["solc not found on PATH - validation skipped"]
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        sol_path = Path(tmpdir) / "Decompiled.sol"
        sol_path.write_text(source, encoding="utf-8")

        try:
            result = subprocess.run(
                [solc, "--bin", str(sol_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return ValidationResult(
                status="skipped", errors=[], warnings=[f"solc timed out after {timeout}s"]
            )
        except OSError as e:
            return ValidationResult(
                status="skipped", errors=[], warnings=[f"solc invocation failed: {e}"]
            )

    stderr_lines = result.stderr.splitlines()
    errors = [line for line in stderr_lines if line.strip().startswith("Error")]
    warnings = [line for line in stderr_lines if line.strip().startswith("Warning")]

    if result.returncode != 0 or errors:
        return ValidationResult(
            status="invalid", errors=errors or [result.stderr], warnings=warnings
        )

    return ValidationResult(status="valid", errors=[], warnings=warnings)


def validate(solgen_result) -> ValidationResult:
    """Convenience wrapper: solgen_result is a SolgenResult (has .solidity)."""
    return validate_solidity(solgen_result.solidity)

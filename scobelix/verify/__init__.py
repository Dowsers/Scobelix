"""
Verification of reconstructed Solidity against the original runtime bytecode.

    from scobelix.verify import verify
    report = verify(runtime_hex, source, contract_name="Token", layout=..., abi_hint=...)
    report.levels["L3"].status, report.functions["0xa9059cbb"].verdict, report.to_json()

Levels: L0 compiles, L1 same external ABI, L2 same storage layout, L3
behaviourally equivalent (differential execution, per function), L4
bytecode-identical modulo metadata.  See `core.verify` for the parameters
and `report` for the verdicts.

Modules: `solc` (find / download / run solc), `bytecode` (masking, L4),
`layout` (L2), `abi` (L1, function specs), `evm` (pyrevm and py-evm
backends), `fuzz` / `seeds` (inputs and storage), `mocks` (environment
contracts), `equiv` (the differential executor), `oracle` (payability and
parameter widths of the original), `report`.

solc is an external binary (never a Python dependency); the EVM backends
are the optional extra `pip install 'scobelix[verify]'`.  Without them every
level but L3 still works.
"""

import importlib

# Public names and the module defining each.  They are imported on first use,
# so that `scobelix.verify.solc` (used by solgen's compile check) stays light.
_EXPORTS = {
    "Budget": "core",
    "verify": "core",
    "BackendUnavailable": "evm",
    "available_backends": "evm",
    "FunctionReport": "report",
    "LevelResult": "report",
    "VerificationReport": "report",
    "Verdict": "report",
    "CompilationError": "solc",
    "Settings": "solc",
    "SolcNotFound": "solc",
    "compile_standard_json": "solc",
    "find_solc": "solc",
    "installed_solcs": "solc",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name):
    if name in _EXPORTS:
        value = getattr(importlib.import_module(f"{__name__}.{_EXPORTS[name]}"), name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | set(_EXPORTS))

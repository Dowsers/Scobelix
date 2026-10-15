"""
Shared helpers of the scobelix.verify tests (imported by the test modules of this directory).

The originals are the repo's pinned fixtures (tests/fixtures/bytecode, built
by solc 0.8.19 --optimize --optimize-runs 200 from tests/fixtures/sources);
the candidates - reconstructions and mutants - live in tests/verify/fixtures.
Tests needing a compiler or an EVM backend skip themselves when it is
missing.
"""

import functools
from pathlib import Path

import pytest

from scobelix.verify import solc
from scobelix.verify.evm import available_backends

HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures"
REPO_FIXTURES = HERE.parent / "fixtures"
SOLC = "0.8.19"


@functools.lru_cache(maxsize=None)
def solc_path(version: str = SOLC):
    return solc.installed_solcs().get(version)


requires_solc = pytest.mark.skipif(solc_path() is None, reason=f"solc {SOLC} not installed")
requires_backend = pytest.mark.skipif(
    not available_backends(), reason="pip install 'scobelix[verify]'"
)
requires_pyrevm = pytest.mark.skipif(
    "pyrevm" not in available_backends(), reason="pyrevm not installed"
)
requires_pyevm = pytest.mark.skipif(
    "pyevm" not in available_backends(), reason="py-evm not installed"
)
BACKENDS = [
    pytest.param(
        b, marks=pytest.mark.skipif(b not in available_backends(), reason=f"{b} not installed")
    )
    for b in ("pyrevm", "pyevm")
]


def fixture_source(rel: str) -> str:
    return (FIXTURES / rel).read_text()


@functools.lru_cache(maxsize=None)
def compile_fixture(
    rel: str, contract: str, settings: solc.Settings = solc.Settings(), version: str = SOLC
):
    """Artifact of `contract` from tests/verify/fixtures/<rel> (cached for the session)."""
    return solc.compile_standard_json(
        {Path(rel).name: fixture_source(rel)}, settings, version=version
    ).artifact(contract)


@functools.lru_cache(maxsize=None)
def original_runtime(name: str) -> bytes:
    """A pinned fixture runtime (tests/fixtures/bytecode/<name>.hex)."""
    return bytes.fromhex((REPO_FIXTURES / "bytecode" / f"{name}.hex").read_text().strip())


@functools.lru_cache(maxsize=None)
def original_artifact(name: str):
    """The pinned fixture recompiled from its source: ground-truth ABI and storage layout."""
    sources_dir = REPO_FIXTURES / "sources"
    sources = {p.name: p.read_text() for p in sources_dir.glob("*.sol")}
    wanted = {f"{name}.sol": sources[f"{name}.sol"]}
    for line in sources[f"{name}.sol"].splitlines():  # local imports ("./Ownable.sol")
        if line.startswith("import"):
            dep = line.split('"')[1].split("/")[-1]
            wanted[dep] = sources[dep]
    return solc.compile_standard_json(wanted, solc.Settings(), version=SOLC).artifact(name)

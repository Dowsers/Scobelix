"""Shared fixtures of the solgen tests: the repository's fixture contracts,
the installed compilers and EVM backends (tests that need one that is not
installed skip themselves), signature databases built for a test."""

import contextlib
import functools
import logging
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def fixture_names():
    return sorted(p.stem for p in (FIXTURES / "bytecode").glob("*.hex"))


# Other builds (no optimiser, legacy or IR pipeline) of a source whose main
# build is a fixture too: their fixture-wide tests run with `-m slow`, the
# main build in the default run. The default run keeps a build of every
# pipeline: DispatchBothViaIR, DispatchFallbackOnlyViaIRNoopt and
# StorageMovesViaIR (IR), StorageMovesLegacy and the 0.4.26, 0.5.17 and 0.7.6
# main builds (older compilers), EncodingShapesNoopt (no optimiser),
# EncodingShapesRecent and TransientSwap (0.8.31).
BUILD_VARIANTS = frozenset({
    "BatchStringsNoopt",
    "DispatchAllNonPayableViaIR",
    "EngineSemanticsNoopt",
    "FunctionTraitsLegacy",
    "LoopShapesNoopt",
    "LoopShapesViaIR",
    "ParamTypesLegacy",
    "ParamTypesViaIR",
    "StorageShapesLegacy",
    "StorageShapesNoopt",
    "TimeDependenceNoopt",
})


def fixture_params():
    """The fixtures as the parameters of a fixture-wide test: the build
    variants carry the `slow` mark."""
    return [pytest.param(name, marks=pytest.mark.slow) if name in BUILD_VARIANTS else name
            for name in fixture_names()]


# Main builds whose differential execution is the longest: their L3 tests run
# with `-m slow` too. Their areas keep differential tests in the default run:
# loops with SumLoop, the loops pass's probes and the engine shape sources;
# byte strings with test_core_bytes and test_routed; function traits with the
# mutability check of L1 and tests/test_function_traits.py.
LONG_DIFFERENTIAL = frozenset({"BatchStrings", "FunctionTraits", "LoopShapes"})


def differential_fixtures():
    """The fixtures as the parameters of a differential-execution test: the
    build variants (see fixture_params) and the longest main builds carry the
    `slow` mark."""
    return [pytest.param(name, marks=pytest.mark.slow) if name in BUILD_VARIANTS | LONG_DIFFERENTIAL else name
            for name in fixture_names()]


def fixture_hex(name):
    return (FIXTURES / "bytecode" / f"{name}.hex").read_text().strip()


@functools.lru_cache(maxsize=None)
def decompiled(name):
    """The decompilation of a fixture (cached for the session)."""
    from scobelix.decompiler import decompile_bytecode

    logging.disable(logging.CRITICAL)
    try:
        return decompile_bytecode(fixture_hex(name))
    finally:
        logging.disable(logging.NOTSET)


@functools.lru_cache(maxsize=None)
def installed():
    try:
        from scobelix.verify.solc import installed_solcs

        return installed_solcs()
    except Exception:  # noqa: BLE001
        return {}


def solc_or_skip(version):
    path = installed().get(version)
    if path is None:
        pytest.skip(f"solc {version} is not installed")
    return path


def compile_or_fail(source, version, name="Decompiled"):
    """The runtime bytecode of contract `name` compiled by solc `version`."""
    from scobelix.verify.solc import CompilationError, Settings, compile_standard_json, execution_evm_version

    path = solc_or_skip(version)
    try:
        comp = compile_standard_json(source, Settings(evm_version=execution_evm_version(version)), version=version,
                                     solc_path=path)
    except CompilationError as e:
        pytest.fail(f"solc {version} rejected the source:\n" + "\n".join(e.messages[:5]) + "\n----\n" + source)
    return comp.artifact(name)


def backend_or_skip():
    from scobelix.verify.evm import available_backends

    have = available_backends()
    if not have:
        pytest.skip("no EVM backend installed (pip install 'scobelix[verify]')")
    return have[0]


@contextlib.contextmanager
def default_sigdb(path):
    """The signature database file `path` as the default one, the lookup
    caches of the generator cleared on both sides."""
    from scobelix.solgen import sigs
    from scobelix.utils import sigdb

    def clear():
        for f in (sigs.function_candidates, sigs.event_candidates, sigs.error_candidates):
            f.cache_clear()

    db = sigdb.SigDB(path)
    sigdb.set_default(db)
    clear()
    try:
        yield db
    finally:
        sigdb.set_default(None)
        db.close()
        clear()


@pytest.fixture(scope="session")
def bundled_sigdb_path(tmp_path_factory):
    """A database of the small tables shipped with the package (built-in,
    curated and local signatures, without the large dump)."""
    from scobelix.utils import sigdb

    path = tmp_path_factory.mktemp("sigdb") / "bundled.sqlite"
    sigdb.build(path, dict(sigdb.default_sources(), dump=None))
    return path


@pytest.fixture
def bundled_sigdb(bundled_sigdb_path):
    """The lookups of the test answer from the small bundled tables."""
    with default_sigdb(bundled_sigdb_path) as db:
        yield db

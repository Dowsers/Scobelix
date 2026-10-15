"""
The bytecode fixtures are reproducible: tests/fixtures/fixtures.json lists the
exact compilation of every tests/fixtures/bytecode/*.hex, and
tests/fixtures/build_fixtures.py rebuilds each one byte for byte (metadata
hash included). Fixtures whose solc version is not installed are skipped.
"""

import importlib.util
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

_spec = importlib.util.spec_from_file_location("build_fixtures", FIXTURES / "build_fixtures.py")
build_fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_fixtures)

SPECS = build_fixtures.load_specs()


def test_every_bytecode_fixture_is_registered():
    on_disk = {p.stem for p in (FIXTURES / "bytecode").glob("*.hex")}
    assert on_disk == set(SPECS)
    for name, spec in SPECS.items():
        assert (FIXTURES / "sources" / spec["source"]).is_file(), name
        keys = {"source", "contract", "solc", "optimizer", "runs", "via_ir", "evm_version"}
        assert set(spec) == keys, name


@pytest.mark.parametrize("name", sorted(SPECS))
def test_fixture_rebuilds_byte_identical(name):
    spec = SPECS[name]
    try:
        build_fixtures.find_solc(spec["solc"])
    except build_fixtures.SolcNotFound:
        pytest.skip("solc %s not installed" % spec["solc"])

    code = build_fixtures.compile_fixture(spec)
    assert code == (FIXTURES / "bytecode" / f"{name}.hex").read_text()

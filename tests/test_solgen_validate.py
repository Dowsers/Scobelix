import shutil

import pytest

from scobelix.solgen.validate import validate_solidity

SOLC = shutil.which("solc")


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


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_invalid_source_reports_invalid_with_errors():
    r = validate_solidity("this is not solidity at all {{{")
    assert r.status == "invalid"
    assert len(r.errors) > 0

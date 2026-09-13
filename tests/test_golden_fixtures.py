"""
Golden tests running the full decompile_bytecode() pipeline against real,
solc-compiled bytecode fixtures pinned under tests/fixtures/.

These replace the previous "test" setup (Jenkinsfile + decompile_link.sh),
which fetched a single hardcoded contract (LINK token) from a live RPC
endpoint at run time - flaky by construction, and it only checked that some
non-empty output was produced, never that decompilation was structurally
correct. Sources used to (re)generate these fixtures live in
tests/fixtures/sources/ (solc 0.8.19, --optimize --optimize-runs 200 unless
noted otherwise).
"""

import re
from pathlib import Path

import pytest

from scobelix.decompiler import decompile_bytecode

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _load(name: str) -> str:
    return (FIXTURES_DIR / f"{name}.hex").read_text().strip()


def _plain(decompilation_text: str) -> str:
    """Strip ANSI colour codes, as decompile_link.sh/scobelix_runner.py do."""
    return _ANSI_RE.sub("", decompilation_text)


def test_simple_token_storage_and_selectors_resolved():
    d = decompile_bytecode(_load("SimpleToken"))

    assert d.json["problems"] == {}

    stor_defs = d.json["stor_defs"]
    assert len(stor_defs) == 2

    kinds = {(loc, kind[0]) for (_, _, loc, kind) in stor_defs}
    assert (0, "mapping") in kinds  # balanceOf
    assert (1, "mask") in kinds  # totalSupply

    # Selectors resolved from the built-in local signature DB, with the
    # actual parameter names Solidity's ABI carries (not just "unknown_...").
    text = _plain(d.text)
    assert "balanceOf(address account)" in text
    assert "transfer(address to, uint256 amount)" in text
    assert "totalSupply()" in text
    assert "insufficient balance" in text


def test_eip1967_proxy_detected_and_delegatecall_reconstructed():
    d = decompile_bytecode(_load("Eip1967Proxy"))

    assert d.json["problems"] == {}

    assert len(d.proxy_hints) == 1
    assert d.proxy_hints[0]["name"] == "eip1967.proxy.implementation"
    assert d.json["proxy_hints"] == d.proxy_hints

    text = _plain(d.text)
    assert "Detected known proxy storage slot(s)" in text
    assert "delegate" in text


def test_loop_is_structured_as_while_not_raw_gotos():
    d = decompile_bytecode(_load("SumLoop"))

    assert d.json["problems"] == {}
    text = _plain(d.text)
    assert "while" in text
    assert "continue" in text
    # the loop's counter variable is tracked and used as the while condition
    assert "idx" in text


@pytest.mark.xfail(
    reason=(
        "known limitation (see plan axis 1, loop structuring): whiles.py only "
        "tracks the loop's counter variable through to the return value, not "
        "a second accumulator (`total`) updated in the same loop body - the "
        "decompiled SumLoop.sumTo() currently returns a literal 0 instead of "
        "the accumulated sum. Documented here as a regression baseline, not "
        "silently papered over."
    ),
    strict=True,
)
def test_loop_accumulator_value_is_tracked():
    d = decompile_bytecode(_load("SumLoop"))
    assert "return 0" not in _plain(d.text)

"""
Golden tests running the full decompile_bytecode() pipeline against real,
solc-compiled bytecode fixtures pinned under tests/fixtures/.

These replace the previous "test" setup (Jenkinsfile + decompile_link.sh),
which fetched a single hardcoded contract (LINK token) from a live RPC
endpoint at run time - flaky by construction, and it only checked that some
non-empty output was produced, never that decompilation was structurally
correct. The fixtures are built from tests/fixtures/sources/ by
tests/fixtures/build_fixtures.py, with the compiler settings listed in
tests/fixtures/fixtures.json.
"""

import re
from pathlib import Path

import pytest

from scobelix.decompiler import decompile_bytecode

from trace_machine import Machine

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _load(name: str) -> str:
    return (FIXTURES_DIR / f"{name}.hex").read_text().strip()


def _plain(decompilation_text: str) -> str:
    """Strip ANSI colour codes, as decompile_link.sh does."""
    return _ANSI_RE.sub("", decompilation_text)


# selectors of each fixture (solc methodIdentifiers)
SELECTORS = {
    "SimpleToken": {"0x70a08231", "0x18160ddd", "0xa9059cbb"},
    "SumLoop": {"0xef0baad9"},
    "Eip1967Proxy": set(),
    "Vault": {
        "0xd0e30db0", "0xfc7e286d", "0x8da5cb5b", "0x5c975abb",
        "0x16c38b3c", "0xf2fde38b", "0x2e1a7d4d",
    },
    "EventsEmitter": {"0x773acdef", "0xa9059cbb"},
    "MiniDiamond": {"0xcdffacc6", "0x3dc23d0c"},
    "NestedStructMapping": {"0x5e5c06e2", "0x55b6ed5c", "0x095ea7b3", "0x54469aea", "0x23b872dd"},
    "YulHeavy": {"0x749e448f", "0x61bc221a", "0x75039190", "0x09acaa96", "0x5ec9f2a0"},
}


@pytest.mark.parametrize("name", sorted(SELECTORS))
def test_one_function_per_selector_plus_fallback(name):
    d = decompile_bytecode(_load(name))

    assert d.json["problems"] == {}
    functions = {f["hash"]: f for f in d.json["functions"]}
    assert set(functions) == SELECTORS[name] | {"_fallback"}
    assert {s["selector"] for s in d.dispatcher["selectors"]} == SELECTORS[name]
    # none of these contracts has a fallback or receive function of its own,
    # except the proxy, whose whole code is its fallback
    assert d.dispatcher["receive"] is None
    assert d.dispatcher["fallback"]["present"] is (name in ("Eip1967Proxy", "MiniDiamond"))


def test_simple_token_function_shapes():
    d = decompile_bytecode(_load("SimpleToken"))
    functions = {f["hash"]: f for f in d.json["functions"]}

    transfer = functions["0xa9059cbb"]
    assert transfer["name"] == "transfer(address to, uint256 amount)"
    assert "insufficient balance" in transfer["print"]
    assert "insufficient balance" not in functions["0x70a08231"]["print"]
    assert functions["0x18160ddd"]["getter"] is not None  # totalSupply
    # no payable entry point: solc hoists the callvalue check
    assert d.dispatcher["callvalue_hoisted"] is True
    assert not any(f["payable"] for f in functions.values())
    assert _plain(functions["_fallback"]["print"]).strip().endswith("revert")


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
    sum_to = _plain(d.functions["0xef0baad9"].print())
    assert "while" in sum_to
    assert "continue" in sum_to
    # the loop's counter variable is tracked and used as the while condition
    assert "idx" in sum_to
    assert "label" not in sum_to and "goto" not in sum_to


def test_loop_accumulator_value_is_tracked():
    """`total += i` leaves the accumulator unchanged on the first iteration
    (0 + 0): the VM must still make it a loop variable. The decompiled
    sumTo() is run on concrete inputs and returns the real sum."""
    d = decompile_bytecode(_load("SumLoop"))
    trace = d.functions["0xef0baad9"].orig_trace
    for n in (0, 1, 2, 3, 10, 57):
        calldata = bytes.fromhex("ef0baad9") + n.to_bytes(32, "big")
        success, output = Machine(calldata).call(trace)
        assert success
        assert int.from_bytes(output, "big") == n * (n - 1) // 2
    assert "return 0" not in _plain(d.text)

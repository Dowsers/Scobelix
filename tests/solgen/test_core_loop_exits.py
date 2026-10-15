"""
A continue of an enclosing loop taken from a loop nested in it (the engine
writes `continue` to the outer loop where the source breaks out of the
inner loop and then skips to the next iteration): the inner loops are left
with `break` through a word naming the target loop, then the target loop
continues; the generated code behaves like the original.
"""

from __future__ import annotations

import itertools

import pytest
from eth_abi import encode as abi_encode

from probes import Build, compile_probe, differential, function_text, generate_probe, patch_signatures, selector

EXITS = """
contract Exits {
    function skipRows(uint256 n, uint256 m) external pure returns (uint256 c) {
        for (uint256 i = 0; i < n; i++) {
            bool skip = false;
            for (uint256 j = 0; j < m; j++) {
                if ((i + 1) * (j + 2) == 12) {
                    skip = true;
                    break;
                }
                c += j;
            }
            if (skip) continue;
            c += 100;
        }
    }

    function shared(uint256 n, uint256 m) external pure returns (uint256 c) {
        uint256 j = 0;
        for (uint256 i = 0; i < n; i++) {
            for (; j < m; j++) {
                c += i;
                if (c % 7 == 3) break;
            }
            c += j;
        }
    }

    function threeLevels(uint256 n, uint256 m) external pure returns (uint256 c) {
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = 0; j < m; j++) {
                bool leave = false;
                for (uint256 k = 0; k < m; k++) {
                    if (i + j + k == 4) {
                        leave = true;
                        break;
                    }
                    c += k;
                }
                if (leave) break;
                c += 10;
            }
            c += 1000;
        }
    }
}
"""

SIGNATURES = ["skipRows(uint256,uint256)", "shared(uint256,uint256)", "threeLevels(uint256,uint256)"]


def calls():
    out = []
    for sig in SIGNATURES:
        for n, m in itertools.product(range(7), repeat=2):
            out.append((selector(sig) + abi_encode(["uint256", "uint256"], [n, m]), 0))
    return out


def check(monkeypatch, build, off=()):
    art = compile_probe(EXITS, build, "Exits")
    patch_signatures(monkeypatch, art.abi)
    res = generate_probe(art.runtime, off=off)
    text = res.solidity
    assert "unsupported control flow" not in text and "loop_exit_unstructured" not in text
    mism = differential(art.runtime, text, res.target_solc, calls())
    assert not mism, (build.label, len(mism), mism[:2])
    return res


def test_outer_continue(monkeypatch):
    res = check(monkeypatch, Build("0.8.19"))
    # the shape is reached: an inner loop leaves through the word naming the outer loop
    assert any("_go" in function_text(res.solidity, f) for f in ("skipRows", "shared", "threeLevels"))


@pytest.mark.slow
@pytest.mark.parametrize("build", [Build("0.8.19", optimize=False), Build("0.8.19", via_ir=True), Build("0.8.31"),
                                   Build("0.7.6")], ids=lambda b: b.label)
def test_outer_continue_other_builds(monkeypatch, build):
    check(monkeypatch, build)


@pytest.mark.slow
def test_outer_continue_exact_form(monkeypatch):
    from scobelix.solgen import pipeline

    check(monkeypatch, Build("0.8.19"), off=tuple(pipeline.PASS_ORDER))

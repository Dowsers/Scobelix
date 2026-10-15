"""
A function no pass rewrites because its exact form needs nothing the exact
form brings (no helper, no `unchecked`, no assembly, no emulated memory) is
already the usual Solidity of its behaviour: it is reported at the
idiomatic tier, with no passes.  Bodies that need the exact machinery stay
exact, and the `exact` idiom level keeps every function exact.
"""

from __future__ import annotations

import re

from probes import Build, compile_probe, function_text, generate_probe, patch_signatures

TRIVIAL = """
contract Trivial {
    uint256 public total;

    function answer() external pure returns (uint256) {
        return 42;
    }

    function nothing() external {}

    function funds() external view returns (uint256) {
        return address(this).balance;
    }

    function me() external view returns (address) {
        return msg.sender;
    }

    function head() external pure returns (uint256 r) {
        assembly { r := calldataload(0) }
    }

    receive() external payable {}
}
"""


def _tag(text: str, name: str) -> str:
    m = re.search(r"/// @custom:scobelix (.*)\n\s*(?:function " + name + r"\(|" + name + r"\()", text)
    return m.group(1) if m else ""


def test_trivial_bodies_are_reported_idiomatic(monkeypatch):
    art = compile_probe(TRIVIAL, Build("0.8.19"), "Trivial")
    patch_signatures(monkeypatch, art.abi)
    res = generate_probe(art.runtime)
    by_name = {f.get("name"): (k, f) for k, f in res.functions.items()}
    for name in ("answer", "nothing", "funds", "me"):
        key, f = by_name[name]
        assert f["tier"] == "idiomatic" and not f["passes"], (name, f["tier"], f["passes"])
        assert "tier=idiomatic" in _tag(res.solidity, name), name
    assert res.functions["_receive"]["tier"] == "idiomatic"
    assert "tier=idiomatic" in _tag(res.solidity, "receive")
    # a raw calldata read no pass rewrites keeps its helper: exact
    head = by_name["head"][1]
    assert head["tier"] == "exact" and not head["passes"] and "_calldataload(" in function_text(res.solidity, "head")


def test_a_time_limited_function_is_flagged_and_never_promoted(monkeypatch):
    # the decompiler's simplification stopped at its time limit (at once here): the code is
    # exact but not fully simplified; the generator says so on every such function (flag,
    # NatSpec, warning), from the decompilation and from its JSON form, and does not report
    # the less simplified body as the usual Solidity of its behaviour
    import logging

    import scobelix.decompiler as decompiler
    from scobelix.solgen.v2 import generate

    art = compile_probe(TRIVIAL, Build("0.8.19"), "Trivial")
    patch_signatures(monkeypatch, art.abi)
    monkeypatch.setattr(decompiler, "WHILES_TIMEOUT", 1e-9)
    logging.disable(logging.CRITICAL)
    try:
        d = decompiler.decompile_bytecode(art.runtime.hex())
    finally:
        logging.disable(logging.NOTSET)
    assert d.functions and all(f.time_limited for f in d.functions.values())
    for res in (generate(d), generate(d.json)):
        for key, f in res.functions.items():
            assert "time_limited" in f["flags"], (key, f["flags"])
            assert f["passes"] or f["tier"] == "exact", (key, f["tier"])
        assert "the decompiler stopped simplifying this function at its time limit" in res.solidity
        assert re.search(r"flags=\S*time_limited", _tag(res.solidity, "answer")), _tag(res.solidity, "answer")
        assert any("time limit" in w for w in res.warnings), res.warnings


def test_the_exact_level_keeps_every_function_exact(monkeypatch):
    art = compile_probe(TRIVIAL, Build("0.8.19"), "Trivial")
    patch_signatures(monkeypatch, art.abi)
    res = generate_probe(art.runtime, level="exact")
    assert {f["tier"] for f in res.functions.values()} == {"exact"}

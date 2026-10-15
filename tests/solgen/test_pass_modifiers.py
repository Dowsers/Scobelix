"""
The modifiers pass (scobelix/solgen/passes/modifiers.py): a check several
functions start with becomes a modifier applied to them, with the same
behaviour (differential runs of the original and the generated text).
"""

import pytest
from eth_utils import keccak

import callprobe
from probes import Build, compile_probe, function_text, generate_probe, patch_signatures, probe_calls
from scobelix.solgen import ir, pipeline
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.passes import modifiers

MODS = """
contract Mods {
    address public owner;
    bool public paused;
    uint256 public value;
    mapping(address => bool) public isAdmin;
    error NotOwner(address who);

    function setValue(uint256 v) external { require(msg.sender == owner, "not owner"); value = v; }
    function early(uint256 v) external returns (uint256) {
        require(msg.sender == owner, "not owner");
        if (v > 10) return 1;
        value = v;
        return 2;
    }
    function failing(uint256 v) external {
        require(msg.sender == owner, "not owner");
        require(v != 7, "seven");
        value = v;
    }
    function setPaused(bool p) external { require(msg.sender == owner, "not owner"); paused = p; }
    function pay() external payable { require(!paused, "paused"); value = msg.value; }
    function pay2(uint256 v) external payable returns (uint256) {
        require(!paused, "paused");
        value = msg.value + v;
        return value;
    }
    function admin1(uint256 v) external { require(isAdmin[msg.sender], "admin"); value = v; }
    function admin2() external { require(isAdmin[msg.sender], "admin"); value = 0; }
    function custom1() external { if (msg.sender != owner) revert NotOwner(msg.sender); value = 1; }
    function custom2(uint256 v) external { if (msg.sender != owner) revert NotOwner(msg.sender); value = v; }
    function once(uint256 v) external { require(msg.sender == address(0x1234), "x"); value = v; }
    function param1(uint256 v) external { require(v != 0, "zero"); value = v; }
    function param2(uint256 v) external { require(v != 0, "zero"); value = v + 1; }
}
"""

CALLER = int(callprobe.CALLER, 16)
# (owner and paused share slot 0, value is slot 1, isAdmin slot 2)
ADMIN_KEY = int.from_bytes(keccak(CALLER.to_bytes(32, "big") + (2).to_bytes(32, "big")), "big")


def presets():
    """Storage of the runs: the caller owner or not, paused or not, admin or not."""
    out = []
    for owner, paused, admin in ((True, False, True), (False, True, False), (True, True, False), (False, False, True)):
        s = {0: (CALLER if owner else 0xBEEF) | (int(paused) << 160)}
        if admin:
            s[ADMIN_KEY] = 1
        out.append(s)
    return out


def generated(monkeypatch, build=Build("0.8.19"), off=()):
    art = compile_probe(MODS, build, "Mods")
    patch_signatures(monkeypatch, art.abi)
    return art, generate_probe(art.runtime, off=off)


def mismatches(art, res):
    calls, skipped = probe_calls(res)
    assert not skipped, skipped
    paid, _ = probe_calls(res, value=3)
    calls += [c for c in paid if c[1]]
    out = []
    for storage in presets():
        out += callprobe.differential(art.runtime, res.solidity, res.target_solc, calls, ("true",), storage)
    return out


def test_repeated_checks_become_modifiers_with_the_same_behaviour(monkeypatch):
    art, res = generated(monkeypatch)
    text = res.solidity
    assert "modifier onlyOwner() {\n        require(msg.sender == owner, \"not owner\");\n        _;\n    }" in text
    assert "modifier whenNotPaused() {" in text and "modifier onlyAdmin() {" in text
    for name in ("setValue", "early", "failing", "setPaused"):
        assert " external onlyOwner " in function_text(text, name).split("\n")[0], name
    assert "external payable whenNotPaused {" in function_text(text, "pay")
    assert "external payable whenNotPaused returns (uint256) {" in function_text(text, "pay2")
    assert " onlyAdmin {" in function_text(text, "admin2").split("\n")[0]
    # the custom error form is another check: a modifier of its own
    assert "revert NotOwner(msg.sender);" in text.split("function setValue")[0]
    assert function_text(text, "custom1").split("\n")[0].endswith(" onlyOwner_2 {")
    # once only, or reading a parameter: the check stays where it is
    assert "require(" in function_text(text, "once") and "require(" in function_text(text, "param1")
    assert "require(v != 7, \"seven\");" in function_text(text, "failing")
    facts = [f["modifiers"] for f in res.functions.values() if f.get("modifiers")]
    assert len(facts) == 10
    assert not mismatches(art, res)


def test_the_differential_sees_a_missing_check(monkeypatch):
    art, res = generated(monkeypatch)
    wrong = res.solidity.replace("external payable whenNotPaused {", "external payable {")
    assert wrong != res.solidity
    calls, _ = probe_calls(res, value=3)
    assert callprobe.differential(art.runtime, wrong, res.target_solc, calls, ("true",), presets()[1])


def test_a_custom_error_only_a_modifier_uses_still_sets_the_pragma(monkeypatch):
    # custom1 / custom2 share `revert NotOwner(msg.sender)`: the modifier is
    # the only code that uses the error, which needs solc 0.8.4
    _, res = generated(monkeypatch)
    text = res.solidity
    assert "revert NotOwner(" not in text.split("modifier onlyOwner_2()")[1].split("    }\n")[1]
    assert "pragma solidity ^0.8.4;" in text and "error NotOwner(address who);" in text


def test_switched_off_the_checks_stay_in_the_bodies(monkeypatch):
    art, res = generated(monkeypatch, off=("modifiers",))
    assert "modifier " not in res.solidity
    assert "require(msg.sender == owner, \"not owner\");" in function_text(res.solidity, "setValue")
    assert all("modifiers" not in f["passes"] for f in res.functions.values())


@pytest.mark.slow
@pytest.mark.parametrize("build", [Build("0.8.19", optimize=False), Build("0.8.31", via_ir=True)],
                         ids=lambda b: b.label)
def test_modifiers_on_other_builds(monkeypatch, build):
    art, res = generated(monkeypatch, build)
    assert "modifier onlyOwner()" in res.solidity
    assert not mismatches(art, res)


# ---------------------------------------------------------------- the rules, on IR

OWNER = ir.StateRef("owner", (), "address")
SENDER = ir.Env("caller")


def _require(cond, msg=b"no"):
    return ir.Require(cond, ir.ErrorString(msg))


def test_names_come_from_the_check():
    eq = ir.Op("eq", (SENDER, OWNER))
    assert modifiers.check_name(_require(eq)) == "onlyOwner"
    assert modifiers.check_name(_require(ir.Op("eq", (ir.StateRef("_minter", (), "address"), SENDER)))) \
        == "onlyMinter"
    paused = ir.StateRef("paused", (), "bool")
    assert modifiers.check_name(_require(ir.Op("iszero", (paused,)))) == "whenNotPaused"
    assert modifiers.check_name(_require(paused)) == "whenPaused"
    # if (paused) revert: the condition that must hold is !paused
    assert modifiers.check_name(ir.If(paused, (ir.Revert(),), ())) == "whenNotPaused"
    admins = ir.StateRef("isAdmin", (ir.Cast("address", SENDER),), "bool")
    assert modifiers.check_name(_require(admins)) == "onlyAdmin"
    assert modifiers.check_name(_require(ir.StateRef("operators", (ir.Cast("address", SENDER),), "bool"))) \
        == "onlyOperator"
    # nothing to name it after
    assert modifiers.check_name(_require(ir.Op("eq", (SENDER, ir.StateRef("slot3", (), "address"))))) is None
    assert modifiers.check_name(_require(ir.Op("gt", (ir.Env("timestamp"), ir.StateRef("start"))))) is None


def test_only_plain_first_checks_move():
    eq = ir.Op("eq", (SENDER, OWNER))
    assert modifiers._plain(eq) and modifiers._plain(ir.Op("gt", (ir.Env("timestamp"), ir.StateRef("start"))))
    assert not modifiers._plain(ir.Op("eq", (SENDER, ir.Param(0))))  # a parameter: a modifier argument
    assert not modifiers._plain(ir.Op("eq", (SENDER, ir.Local("v0"))))
    assert not modifiers._plain(ir.Op("lt", (ir.Op("add", (ir.StateRef("a"), ir.Const(1))), ir.StateRef("b"))))
    assert not modifiers._plain(ir.Op("eq", (ir.CalldataWord(ir.Const(4)), OWNER)))
    store = ir.Sstore(ir.Const(1), ir.Const(2))
    assert modifiers.first_check((store, _require(eq))) is None  # not the first statement
    check, rest = modifiers.first_check((ir.If(eq, (ir.Revert(),), (store,)), ir.Stop()))
    assert check == ir.If(eq, (ir.Revert(),), ()) and rest == (store, ir.Stop())


def _ctx(keys, kind="function"):
    specs = {k: EntrySpec(k, kind, int(k, 16) if kind == "function" else None, name=f"f{i}") for i, k in enumerate(keys)}
    return pipeline.PassContext(specs=specs, metadata=None, dispatcher=None, target_solc="0.8.19", abi_v2=True,
                                idiom_level="full")


def test_run_moves_a_repeated_check_and_finish_declares_it_once():
    check = _require(ir.Op("eq", (SENDER, OWNER)))
    body = (check, ir.Sstore(ir.Const(1), ir.Const(2)), ir.Stop())
    ctx = _ctx(["0x00000001", "0x00000002", "0x00000003"])
    ctx.functions = {k: ir.Function(k, body) for k in ctx.specs}
    modifiers.prepare(ctx)
    assert ctx.facts["modifiers"]["repeated"] == set(ctx.specs)
    out = [modifiers.run(fn, ctx) for fn in ctx.functions.values()]
    assert all(f.body == body[1:] for f in out)
    assert all(s.modifiers == ("onlyOwner",) for s in ctx.specs.values())
    modifiers.finish(ctx)
    assert ctx.declarations["modifier"] == [
        '\nmodifier onlyOwner() {\n    require(msg.sender == owner, "no");\n    _;\n}']


def test_a_check_of_one_function_or_of_the_fallback_stays():
    check = _require(ir.Op("eq", (SENDER, OWNER)))
    ctx = _ctx(["0x00000001", "0x00000002"])
    ctx.functions = {"0x00000001": ir.Function("0x00000001", (check, ir.Stop())),
                     "0x00000002": ir.Function("0x00000002", (ir.Stop(),))}
    modifiers.prepare(ctx)
    fn = ctx.functions["0x00000001"]
    assert modifiers.run(fn, ctx) is fn
    fb = _ctx(["_fallback", "_receive"], kind="fallback")
    fb.functions = {k: ir.Function(k, (check, ir.Stop())) for k in fb.specs}
    modifiers.prepare(fb)
    assert all(modifiers.run(f, fb) is f for f in fb.functions.values())

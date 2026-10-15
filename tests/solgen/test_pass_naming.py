"""
The naming pass (scobelix/solgen/passes/naming.py) and the names the
generator declares: stable, collision-free, never a change of behaviour.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import callprobe
from conftest import compile_or_fail
from probes import Build, compile_probe, function_text, generate_probe, patch_signatures, probe_calls
from scobelix.solgen import ir, pipeline, render
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.passes import naming
from scobelix.solgen.types import parse_type

U256 = parse_type("uint256")
ADDRESS = parse_type("address")

# ---------------------------------------------------------------- the helpers' own names


def test_every_assembly_variable_of_the_helpers_is_a_reserved_name():
    # an assembly variable that shadows any declaration of the contract (a
    # state variable `to`, a function `size`) makes solc reject the text:
    # no declaration may take the helpers' assembly names
    seen = set()
    for name, (source, _) in render._HELPERS.items():
        for var in re.findall(r"\blet\s+([A-Za-z_$][\w$]*)", source):
            seen.add(var)
            assert render.reserved_name(var), (name, var)
            assert render.reserved_name(var, parameter=True), (name, var)
    assert {"$to", "$from", "$i", "$size", "$avail"} <= seen


# common short names, and every parameter / local name the helpers use
_CONTRACT_NAMES = ("to", "size", "avail", "i", "p", "n", "r", "m", "s", "d", "o", "v", "x", "a", "b", "w", "c",
                   "g", "t0", "t1", "dst", "src", "end", "cap", "code", "offset", "shift", "slot", "salt")


@pytest.mark.parametrize("version", ["0.8.19", "0.8.31"])
def test_the_helpers_compile_next_to_contract_names_like_their_variables(version):
    helpers = render.Helpers()
    for name in render._HELPERS:
        if version >= "0.8.24" or name not in ("_tload", "_tstore"):  # (transient storage: solc 0.8.24)
            helpers.use(name)
    state = "\n".join(f"    uint256 public {n};" for n in _CONTRACT_NAMES)
    text = ("// SPDX-License-Identifier: UNLICENSED\npragma solidity ^0.8.19;\n\ncontract Names {\n"
            "    bytes private constant _ORIGINAL_CODE = hex\"6001\";\n" + state + "\n"
            "    event from(uint256 size);\n"
            "    function library_(uint256 i) external pure returns (uint256) { return i; }\n"
            + "\n".join("    " + s.replace("\n", "\n    ") for s in helpers.sources()) + "\n}\n")
    art = compile_or_fail(text, version, "Names")
    assert art.runtime


# ---------------------------------------------------------------- locals, on IR

KEY = "0x00000001"


def _ctx(params=(("n", U256),), declared=(), typed_route=False, signature="f(uint256)"):
    spec = EntrySpec(KEY, "function", 1, name=None if typed_route else "f", signature=None if typed_route else signature,
                     params=tuple((t, n) for n, t in params), typed_route=typed_route)
    ctx = pipeline.PassContext(specs={KEY: spec}, metadata=None, dispatcher=None, target_solc="0.8.19", abi_v2=True,
                               idiom_level="full")
    ctx.facts["declared_names"] = set(declared)
    return ctx


def _for(var, bound, body):
    return ir.For((ir.Assign(ir.Local(var), ir.ZERO, declare=True),), ir.Op("lt", (ir.Local(var), bound)),
                  (ir.Assign(ir.Local(var), ir.ONE, "++"),), tuple(body))


SUM = (
    ir.Assign(ir.Local("v1"), ir.ZERO, declare=True),
    _for("v0", ir.Param(0), [ir.Assign(ir.Local("v1"), ir.Local("v0"), "+")]),
    ir.Assign(ir.Local("t2"), ir.StateRef("balances", (ir.Cast("address", ir.Env("caller")),)), declare=True),
    ir.Assign(ir.Local("t3"), ir.StateRef("totalSupply"), declare=True),
    ir.Assign(ir.Local("t4"), ir.StateRef("pools", (ir.Local("t3"), "reserve")), declare=True),
    ir.Sstore(ir.Local("t2"), ir.Op("add", (ir.Local("t3"), ir.Local("t4")))),
    ir.Return(values=(ir.Local("v1"),)),
)


def _names(fn):
    return [n.name for n in ir.walk_all(fn.body) if isinstance(n, ir.Local)]


def _renamed(body, ctx):
    fn = ir.Function(KEY, body)
    out = naming.run(fn, ctx)
    mapping = {}
    for a, b in zip(ir.walk_all(fn.body), ir.walk_all(out.body)):
        if isinstance(a, ir.Local):
            assert mapping.setdefault(a.name, b.name) == b.name  # one name each
    assert len(set(mapping.values())) == len(mapping)  # two locals never share one
    inverse = {v: k for k, v in mapping.items()}
    back = ir.transform(out.body, lambda n: ir.Local(inverse[n.name]) if isinstance(n, ir.Local) else n)
    assert back == fn.body  # nothing but the names changed
    return mapping, out


def test_locals_are_named_from_what_they_hold():
    mapping, out = _renamed(SUM, _ctx())
    assert mapping == {"v0": "i", "v1": "result", "t2": "balance", "t3": "_totalSupply", "t4": "reserve"}
    assert out.body[0].declare and out.body[1].init[0].declare  # (in-place declarations kept)
    assert naming.run(ir.Function(KEY, SUM), _ctx()) == out  # stable


def test_names_avoid_the_contract_the_parameters_and_reserved_words():
    # `i`, `result` and `balance` are declared by the contract, `j` is a parameter
    mapping, _ = _renamed(SUM, _ctx(params=(("j", U256),), declared=("i", "result", "balance", "reserve")))
    assert mapping["v0"] == "k" and mapping["v1"] == "result_2" and mapping["t2"] == "_balance"
    assert mapping["t4"] == "_reserve"
    for name in mapping.values():
        assert not render.reserved_name(name, parameter=True)
    # a callee named like a keyword or a builtin: the next candidate
    assert naming.value_name("getAddress") == "address" and render.reserved_name("address")
    call = ir.HighCall(1, "staticcall", "IThing", "getAddress", ir.Const(5), None, None, (), (), ("address",),
                       ("result",))
    out = naming.run(ir.Function(KEY, (call, ir.Return(values=(ir.Result(1, 0, "address"),)))), _ctx())
    assert out.body[0].outs == ("result",)


def test_three_hundred_locals_get_three_hundred_names():
    body = tuple(ir.Assign(ir.Local(f"v{k}"), ir.StateRef("balances", (ir.Const(k),)), declare=True)
                 for k in range(300))
    body += tuple(_for(f"v{300 + k}", ir.Const(3), [ir.Sstore(ir.Const(k), ir.Local(f"v{300 + k}"))]) for k in range(8))
    body += (ir.Sstore(ir.ZERO, ir.Op("add", tuple(ir.Local(f"v{k}") for k in range(300)))), ir.Stop())
    mapping, _ = _renamed(body, _ctx(declared=("balance_7",)))
    assert sum(1 for k, v in mapping.items() if k != v) == 306 and "balance_7" not in mapping.values()
    assert [mapping[f"v{300 + k}"] for k in range(6)] == ["i", "j", "k", "i2", "j2", "k2"]
    assert mapping["v0"] == "balance" and mapping["v1"] == "_balance" and mapping["v2"] == "currentBalance"


def test_calls_outputs_temporaries_and_flags():
    call = ir.HighCall(1, "staticcall", "IERC20", "balanceOf", ir.Const(5), None, None, (ir.Env("caller"),),
                       ("address",), ("uint256",), ("result",))
    low = ir.ExtCall(2, "call", None, ir.Const(6), ir.ZERO, ok="ok", ret="ret")
    body = (call, low, ir.Assign(ir.Local("v0"), ir.ZERO),
            ir.While(ir.Op("lt", (ir.Local("v0"), ir.Const(9))), (
                ir.Assign(ir.Local("v0_next"), ir.Op("add", (ir.Local("v0"), ir.ONE))),
                ir.Continue("L", (ir.Assign(ir.Local("v0"), ir.Local("v0_next")),))), (), "L"),
            ir.Sstore(ir.Result(1, 0, "uint256"), ir.CallOut(2, "success")), ir.Stop())
    out = naming.run(ir.Function(KEY, body), _ctx(params=(("data", U256),)))
    assert out.body[0].outs == ("balance",)
    assert (out.body[1].ok, out.body[1].ret) == ("success", "returnData")  # (`data` is a parameter)
    assert {n.name for n in ir.walk_all(out.body) if isinstance(n, ir.Local)} == {"v0", "v0_next"}  # no counter


# ---------------------------------------------------------------- parameters

IERC20 = {"IERC20": {0xa9059cbb: "function transfer(address to, uint256 amount) external returns (bool);"}}


def test_parameters_without_a_name_take_the_names_their_uses_give():
    ctx = _ctx(params=(("arg0", ADDRESS), ("arg1", U256), ("arg2", U256), ("arg3", ADDRESS), ("arg4", U256)),
               typed_route=True)
    ctx.facts["calls"] = {"interfaces": IERC20}
    ctx.facts["events"] = {"decls": {"event Log_12345678(bytes32 indexed topic0, uint256 indexed topic1);": "Log_12345678"}}
    body = (
        ir.Require(ir.Op("eq", (ir.Env("caller"), ir.Param(3)))),  # compared with msg.sender: neutral
        ir.HighCall(1, "call", "IERC20", "transfer", ir.Const(7), None, None, (ir.Param(0), ir.Param(1)),
                    ("address", "uint256"), ("bool",), (None,)),
        ir.Assign(ir.StateRef("fee"), ir.Param(2)),
        ir.Emit("Log_12345678", (ir.Const(1), ir.Param(4)), ("bytes32", "uint256")),  # the events pass's own names
        ir.Stop())
    naming.run(ir.Function(KEY, body), ctx)
    assert [n for _, n in ctx.specs[KEY].params] == ["to", "amount", "_fee", "arg3", "arg4"]
    assert ctx.facts["naming"]["functions"][KEY]["params"] == 3
    # a declaration made later takes a name back: the parameter returns to its own
    ctx.declarations["event"] = ["event amount(uint256 x);"]
    naming.finish(ctx)
    assert [n for _, n in ctx.specs[KEY].params] == ["to", "arg1", "_fee", "arg3", "arg4"]


def test_known_parameter_names_are_kept():
    ctx = _ctx(params=(("who", ADDRESS), ("value", U256)))
    ctx.facts["calls"] = {"interfaces": IERC20}
    call = ir.HighCall(1, "call", "IERC20", "transfer", ir.Const(7), None, None, (ir.Param(0), ir.Param(1)),
                       ("address", "uint256"), ("bool",), (None,))
    naming.run(ir.Function(KEY, (call, ir.Stop())), ctx)
    assert [n for _, n in ctx.specs[KEY].params] == ["who", "value"]


# ---------------------------------------------------------------- whole contracts

NAMED = """
interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }

contract Named {
    uint256 public fee;
    mapping(address => uint256) public balances;
    uint256 private total;

    function pay(address token, address to, uint256 amount) external { IERC20(token).transfer(to, amount); }
    function put(uint256 f) external { fee = f; }
    function sum(uint256 n) external pure returns (uint256 s) { for (uint256 i = 0; i < n; i++) s += i; }
    function twice(address a) external view returns (uint256) { uint256 b = balances[a]; return b * 2 + b; }
    function addTotal(uint256 x) external returns (uint256) { total += x; return total; }
}
"""


def test_a_contract_reads_with_names_and_behaves_the_same(monkeypatch):
    art = compile_probe(NAMED, Build("0.8.19"), "Named")
    # `pay` and `put` have no name in the database: routed, typed
    abi = [i for i in art.abi if i.get("name") not in ("pay", "put")]
    abi.append({"type": "function", "name": "transfer", "stateMutability": "nonpayable",
                "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}],
                "outputs": [{"name": "", "type": "bool"}]})
    patch_signatures(monkeypatch, abi)
    res = generate_probe(art.runtime)
    text = res.solidity
    assert re.search(r"function _fn_[0-9a-f]{8}\(address arg0, address to, uint256 amount\) private \{", text)
    assert re.search(r"\(address arg0, address to, uint256 amount\) = abi\.decode\(input\[4:\]", text)
    assert re.search(r"function _fn_[0-9a-f]{8}\(uint256 _fee\) private \{\n        fee = _fee;\n    \}", text)
    body = function_text(text, "sum")
    assert "uint256 result = 0;" in body and "for (uint256 i = 0; i < n; i++) {" in body and "result += i;" in body
    assert "return;" not in text.split("---- EVM-exact helpers")[0]
    assert "uint256 var_2;" in text or "uint256 internal var_2;" in text  # the variable without a getter
    calls, skipped = probe_calls(res)
    assert not skipped, skipped
    assert not callprobe.differential(art.runtime, text, res.target_solc, calls, ("true",))
    off = generate_probe(art.runtime, off=("naming",))
    assert "slot2" in off.solidity and "uint256 _fee" not in off.solidity
    assert "result" not in function_text(off.solidity, "sum")


ROLES = """
contract Roles {
    address private boss;
    uint256 private count;
    uint256[] private items;
    mapping(address => uint256) private credit;

    function bump() external { require(msg.sender == boss, "boss"); count += 1; }
    function push(uint256 x) external { require(msg.sender == boss, "boss"); items.push(x); credit[msg.sender] = x; }
    function size() external view returns (uint256) { return items.length + count + credit[msg.sender]; }
}
"""


def test_state_variables_without_a_getter_get_role_or_stable_names(monkeypatch):
    art = compile_probe(ROLES, Build("0.8.19"), "Roles")
    patch_signatures(monkeypatch, art.abi)
    res = generate_probe(art.runtime)
    text = res.solidity
    # the address every first check compares with msg.sender: owner
    assert "address internal owner;" in text and "modifier onlyOwner() {" in text
    assert "uint256 internal var_1;" in text and "uint256[] internal arr_2;" in text
    assert "mapping(address => uint256) internal map_3;" in text
    calls, skipped = probe_calls(res)
    assert not skipped, skipped
    caller = int(callprobe.CALLER, 16)
    for storage in ({0: caller}, {0: 0xBEEF, 1: 5, 2: 1}):
        assert not callprobe.differential(art.runtime, text, res.target_solc, calls, ("true",), storage)
    off = generate_probe(art.runtime, off=("naming",))
    assert "address internal slot0;" in off.solidity and "map_3" not in off.solidity


# ---------------------------------------------------------------- constants


def test_literal_forms():
    assert render.address_literal(0) == "address(0)" and render.address_literal(1) == "address(uint160(1))"
    assert render.address_literal(0xdac17f958d2ee523a2206206994597c13d831ec7) \
        == "address(0xdAC17F958D2ee523a2206206994597C13D831ec7)"  # EIP-55
    assert render.max_literal(2**64 - 1) == "type(uint64).max" and render.max_literal(2**63 - 1) is None
    assert render.max_literal(2**256 - 1) is None and render.max_literal(255) == "type(uint8).max"
    assert render.time_literal(86400) == "1 days" and render.time_literal(30 * 86400) == "30 days"
    assert render.time_literal(5400) == "90 minutes" and render.time_literal(7200) == "2 hours"
    assert render.time_literal(59) is None and render.time_literal(0) is None


CONSTS = """
contract Consts {
    address public owner;
    uint256 public deadline;
    mapping(address => uint256) public m;
    error Bad(address who, uint8 code);

    function lock() external { deadline = block.timestamp + 1 days; }
    function lock30() external view returns (uint256) { return block.timestamp + 30 days; }
    function zero(address a) external { if (a == address(0)) revert Bad(address(0), 64); owner = a; }
    function big(uint256 x) external pure returns (bool) { return x > type(uint64).max; }
    function bound(uint256 x) external pure returns (bool) { return x <= type(uint64).max; }
    function pick(bool b) external pure returns (address) {
        return b ? 0xdAC17F958D2ee523a2206206994597C13D831ec7 : address(0);
    }
    function digest(bytes32 a) external pure returns (bytes32) { return keccak256(abi.encodePacked(bytes2(0x1901), a)); }
    function neg(int256 x) external pure returns (bool) { return x < -5; }
    function prefix(bytes32 a) external pure returns (bytes32) {
        // 20 constant bytes: never written as 40 hex digits (solc would read an address literal)
        return keccak256(abi.encodePacked(hex"3d602d80600a3d3981f3363d3d373d3d3d363d73", a));
    }
}
"""


def test_constants_read_like_source(monkeypatch):
    art = compile_probe(CONSTS, Build("0.8.19"), "Consts")
    patch_signatures(monkeypatch, art.abi)
    res = generate_probe(art.runtime)
    text = res.solidity.split("---- EVM-exact helpers")[0]
    assert "deadline = block.timestamp + 1 days;" in text and "block.timestamp + 30 days" in text
    assert "revert Bad(address(0), uint8(64));" in text and "uint256(0)" not in text
    assert "type(uint64).max" in function_text(text, "big") and "<= type(uint64).max" in function_text(text, "bound")
    assert "address(0xdAC17F958D2ee523a2206206994597C13D831ec7)" in function_text(text, "pick")
    assert "bytes2(0x1901)" in function_text(text, "digest") and "int256(-5)" in function_text(text, "neg")
    calls, skipped = probe_calls(res)
    assert not skipped, skipped
    assert not callprobe.differential(art.runtime, res.solidity, res.target_solc, calls, ("true",))


_SEED_SCRIPT = """
import logging, sys
from pathlib import Path
from scobelix.decompiler import decompile_bytecode
from scobelix.solgen.v2 import generate
logging.disable(logging.CRITICAL)
hexcode = Path(sys.argv[1]).read_text().strip()
print(generate(decompile_bytecode(hexcode), None, False, "full").solidity)
"""


def test_the_text_does_not_depend_on_the_hash_seed():
    fixture = Path(__file__).resolve().parent.parent / "fixtures" / "bytecode" / "NestedStructMapping.hex"
    texts = []
    for seed in ("1", "2"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        run = subprocess.run([sys.executable, "-c", _SEED_SCRIPT, str(fixture)], capture_output=True, text=True,
                             env=env, timeout=300)
        assert run.returncode == 0, run.stderr[-2000:]
        texts.append(run.stdout)
    assert texts[0] == texts[1] and "contract " in texts[0]


# ---------------------------------------------------------------- adversarial cases


def test_a_derived_name_never_takes_the_name_of_a_kept_local():
    # a state variable `_t1`: the local caching it would be `t1`, the name of
    # another local the pass keeps (assigned twice): one name for two
    # locals would merge them
    body = (ir.Assign(ir.Local("v0"), ir.StateRef("_t1"), declare=True),
            ir.Assign(ir.Local("t1"), ir.Param(0), declare=True),
            ir.Assign(ir.Local("t1"), ir.Op("add", (ir.Local("t1"), ir.Local("v0")))),
            ir.Assign(ir.Local("v2"), ir.StateRef("_v3_next"), declare=True),
            ir.Assign(ir.Local("v3_next"), ir.Local("v2"), declare=True),
            ir.Sstore(ir.ZERO, ir.Op("add", (ir.Local("t1"), ir.Local("v3_next")))), ir.Stop())
    mapping, _ = _renamed(body, _ctx())
    assert mapping["t1"] == "t1" and mapping["v0"] not in ("t1", "v0")
    assert mapping["v3_next"] == "v3_next" and mapping["v2"] != "v3_next"


def test_singular_keeps_a_final_s_that_is_not_a_plural():
    words = ("accounts", "entries", "status", "bonus", "basis", "address", "users", "authorities")
    assert [naming.singular(w) for w in words] == \
        ["account", "entry", "status", "bonus", "basis", "address", "user", "authority"]
    # a local caching an entry of `status`, a modifier checking `status[msg.sender]`
    assert naming.cached_names("status", element=True) == ["_status", "currentStatus"]
    from scobelix.solgen.passes import modifiers

    check = ir.Require(ir.StateRef("status", (ir.Cast("address", ir.Env("caller")),), "bool"), ir.Empty())
    assert modifiers.check_name(check) == "onlyStatus"


# a private address the callbacks compare with msg.sender, beside the
# owner (named by its getter) that the other first checks compare with
CALLBACKS = """
contract Callbacks {
    address public owner;
    address private pool;
    uint256 public total;
    function setPool(address p) external { require(msg.sender == owner, "o"); pool = p; }
    function cb1(uint256 a) external { require(msg.sender == pool, "pool"); total += a; }
    function cb2(uint256 a) external { require(msg.sender == pool, "pool"); total -= a; }
}
"""

# a two-step ownership transfer: accept() compares the pending owner with msg.sender
TWO_STEP = """
contract TwoStep {
    address public owner;
    address private pending;
    uint256 public value;
    function setValue(uint256 v) external { require(msg.sender == owner, "o"); value = v; }
    function propose(address p) external { require(msg.sender == owner, "o"); pending = p; }
    function accept() external { require(msg.sender == pending, "p"); owner = pending; pending = address(0); }
}
"""


@pytest.mark.parametrize("source,contract,modifier",
                         [(CALLBACKS, "Callbacks", "check1"), (TWO_STEP, "TwoStep", "onlyOwner")],
                         ids=["callbacks", "two-step"])
def test_owner_names_only_the_one_address_first_checks_compare_with_the_sender(monkeypatch, source, contract,
                                                                               modifier):
    art = compile_probe(source, Build("0.8.19"), contract)
    patch_signatures(monkeypatch, art.abi)
    text = generate_probe(art.runtime).solidity
    # two addresses are compared with msg.sender: the unnamed one is not an owner
    assert "_owner" not in text and "address internal var_1;" in text
    checks = re.findall(r"modifier (\w+)\(\) \{\n\s+require\(msg\.sender == (\w+),", text)
    assert modifier in [m for m, _ in checks]
    assert all((m == "onlyOwner") == (who == "owner") for m, who in checks), checks


DEPOSITS = """
contract Deposits {
    struct Info { uint128 amount; uint64 time; }
    mapping(address => Info) public deposits;
    event Deposit(address indexed user, uint256 amount);
    function deposit() external payable {
        deposits[msg.sender].amount += uint128(msg.value);
        deposits[msg.sender].time = uint64(block.timestamp);
        emit Deposit(msg.sender, msg.value);
    }
}
"""


def test_a_struct_named_after_its_variable_leaves_an_event_its_name(monkeypatch):
    # `deposits` would name its struct `Deposit`, the name of an event the
    # contract emits: the event keeps it (its topic is the hash of its name)
    art = compile_probe(DEPOSITS, Build("0.8.19"), "Deposits")
    callprobe.patch_lookups(monkeypatch, [art.abi])
    res = generate_probe(art.runtime)
    text = res.solidity
    assert "emit Deposit(msg.sender, msg.value);" in text and "event Deposit(address indexed user" in text
    assert "struct Deposit " not in text and "mapping(address => Struct0) public deposits;" in text
    calls, skipped = probe_calls(res, value=5)
    assert not skipped, skipped
    assert not callprobe.differential(art.runtime, text, res.target_solc, calls, ("true",))

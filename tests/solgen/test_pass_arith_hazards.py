"""
Hazards of the arith and compound passes: locals that could shadow state
variables, checked operations that must not move into a require's payload
or into an operand the statement may skip, on real solc builds through the
probe harness (arithprobe) or on hand-written IR.
"""

import pytest

import arithprobe
from probes import Build, compile_probe, function_text, generate_probe, patch_signatures
from scobelix.solgen import ir
from test_pass_arith import A, B, C, SUM, guard, op, ret, run

PROBE_NAMES = """
contract Names {
    uint256 public sum;
    uint256 public product;
    uint256 public diff;
    uint256 public quotient;
    event E(uint256 v);
    function addTo(uint256 a, uint256 b) external returns (uint256) { uint256 s = a + b; sum = s; emit E(s); return s; }
    function mulTo(uint256 a, uint256 b) external returns (uint256) { uint256 p = a * b; product = p + 1; return p; }
    function subTo(uint256 a, uint256 b) external returns (uint256) { uint256 d = a - b; diff += d; return diff + d; }
    function divTo(uint256 a, uint256 b) external returns (uint256) {
        uint256 q = a / b; quotient = q; emit E(q); return q * 2;
    }
    function readSum(uint256 a, uint256 b) external view returns (uint256) {
        uint256 s = a + b; if (s > 100) return sum; return s + sum;
    }
}
"""


def _differential(monkeypatch, source, contract, build, limit=60, presets=4, via_ir=False):
    art = compile_probe(source, build, contract)
    patch_signatures(monkeypatch, art.abi)
    res = generate_probe(art.runtime)
    calls, skipped = arithprobe.all_calls(res, limit=limit)
    pre = arithprobe.storage_presets(art.storage_layout)[:presets]
    return res, calls, skipped, arithprobe.differential(art.runtime, res.solidity, res.target_solc, calls, pre,
                                                        via_ir=via_ir)


@pytest.mark.parametrize("build", [Build("0.8.19"), Build("0.8.31", via_ir=True)], ids=lambda b: b.label)
def test_bound_results_do_not_shadow_state_variables(monkeypatch, build):
    """The local a checked result is bound to (`sum`, `product`, `diff`,
    `quotient`, ...) must not take the name of a state variable: declared at
    the top of the function, it would shadow it (`sum = sum;` writing the
    local, `return s + sum` reading it)."""
    res, calls, skipped, mism = _differential(monkeypatch, PROBE_NAMES, "Names", build)
    assert calls and not skipped
    assert mism == []
    text = function_text(res.solidity, "addTo")
    assert "uint256 sum;" not in text and "sum = sum;" not in text


def test_declared_names_cover_every_contract_level_declaration():
    from scobelix.solgen import contract

    ci = contract.ContractInput(units=[], target="0.8.19", original="solc 0.8.19", declarations={
        "state": ["/// @notice the sum\nuint256 public sum;\nmapping(address => mapping(uint256 => uint8)) internal "
                  "product;\nuint256[2] private __gap0;"],
        "constant": ['string public constant quotient = "a;b";', "uint256 public constant diff = 5;"],
        "struct": ["struct Struct0 {\n    uint64 remainder;\n}"],
        "event": ["event negated(uint256 v);"], "error": ["error Bad(uint256 v);"],
        "function": ["function _ns_0() private pure returns (Struct0 storage $) {\n}"],
    })
    names = contract._declared_names(ci)
    assert {"sum", "product", "__gap0", "quotient", "diff", "Struct0", "negated", "Bad", "_ns_0", "Decompiled"} <= names
    assert "remainder" not in names  # a struct member is not declared at the top level


def _checked(node):
    return [n for n in ir.walk(node) if isinstance(n, ir.Typed) and n.checked]


@pytest.mark.parametrize("payload", [
    ir.Custom(0x12345678, (ir.WordBytes(SUM),)),
    ir.NamedError("Bad", (SUM,), ("uint256",)),
    ir.Raw(ir.WordBytes(SUM)),
], ids=["custom", "named", "raw"])
def test_a_require_payload_is_not_where_the_check_moves(payload):
    """A Require's payload is evaluated only when its condition fails
    (`if (!c) revert E(...)`): a checked operation whose only use is there
    would panic only then, while the original's guard fires on every path.
    The result is computed at the guard and the payload reads it."""
    out, facts = run([guard(op("gt", A, SUM), [ir.Require(op("gt", C, 5), payload), ret(C)])])
    assert facts["absorbed"] == {0x11: 1}
    first, req = out.body[0], out.body[1]
    assert isinstance(first, ir.Assign) and _checked(first.value)
    assert isinstance(req, ir.Require) and not _checked(req.payload)


def test_a_bounds_check_is_not_dropped_for_an_access_in_a_require_payload():
    """Panic(0x32) before a Require whose payload alone reads arr[i]: the
    access would check the index only when the condition fails."""
    arr_i = ir.StateRef("arr", (B,), "uint256")
    length = ir.StateRef("arr", ("length",), "uint256")
    body = [guard(op("iszero", op("lt", B, length)), [ir.Require(op("gt", C, 5), ir.Raw(ir.WordBytes(arr_i))),
                                                       ret(C)], code=0x32)]
    out, facts = run(body)
    assert facts["kept"] == {0x32: 1} and out.body == tuple(body)


ARR_I = ir.StateRef("arr", (B,), "uint256")
ARR_LEN = ir.StateRef("arr", ("length",), "uint256")


@pytest.mark.parametrize("value", [
    op("and", op("gt", C, 5), op("gt", ARR_I, 3)),  # rendered `(c > 5) && (arr[b] > 3)`: arr[b] skipped when c <= 5
    op("or", op("gt", C, 5), op("gt", ARR_I, 3)),
    ir.Ternary(op("gt", C, 5), ARR_I, ir.Const(7)),
], ids=["and", "or", "ternary"])
def test_a_bounds_check_is_not_dropped_for_an_access_the_statement_may_skip(value):
    """Panic(0x32) before a statement that reads arr[i] only on some paths
    (the right operand of a boolean && / ||, a branch of a ternary): the
    original's check runs on every path, Solidity's own check of the access
    would not."""
    body = [guard(op("iszero", op("lt", B, ARR_LEN)), [ret(value)], code=0x32)]
    out, facts = run(body)
    assert facts["kept"] == {0x32: 1} and out.body == tuple(body)
    # evaluated on every path: the duplicate check goes
    out, facts = run([guard(op("iszero", op("lt", B, ARR_LEN)), [ret(op("and", op("gt", ARR_I, 3), op("gt", C, 5)))],
                            code=0x32)])
    assert facts["absorbed"] == {0x32: 1}


def test_a_check_is_not_moved_into_a_ternary_branch():
    """A checked operation used once, in a branch of a ternary only: bound
    at the guard (the branch may not run)."""
    out, facts = run([guard(op("gt", A, SUM), [ret(ir.Ternary(op("gt", C, 5), SUM, ir.Const(7)))])])
    assert facts["absorbed"] == {0x11: 1}
    assert isinstance(out.body[0], ir.Assign) and _checked(out.body[0].value) and not _checked(out.body[1])

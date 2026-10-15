"""
The compound pass is the last tidy-up: `x = x op y` -> `x op= y`, `x += 1`
-> `x++`, constants to the right of commutative operations and comparisons,
divisions by constants as Solidity's operator, `if (c) return true; else
return false;` -> `return c;`.  None of it may change behaviour or the order
of the possible failures.

Tests: each rewrite and each refusal on hand-written IR; the rendered
compound forms executed against the plain forms on the bounds of their
types; the rule that `x++` / `x--` and `x += 1` / `x -= 1` are the same
statement in every integer type, checked and unchecked, verified on solc
0.8.19 and 0.8.31 (differential execution); the probes of test_pass_arith
cover compound forms on packed storage fields, mappings of structs and
arrays (run with every pass).
"""

import pytest

from conftest import compile_or_fail
from probes import run_calls, selector
from scobelix.solgen import ir, pipeline
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.contract import ContractInput, Unit, assemble
from scobelix.solgen.passes import compound
from scobelix.solgen.types import parse_type

W = 1 << 256


def op(name, *args):
    return ir.Op(name, tuple(a if isinstance(a, ir.Node) else ir.const(a) for a in args))


def cd(i):
    return ir.CalldataWord(ir.Const(4 + 32 * i))


def run(body, key="0x00000001"):
    fn = ir.Function(key, tuple(body))
    ctx = pipeline.PassContext(specs={key: EntrySpec(key=key, kind="function", selector=int(key, 16))},
                               metadata=None, dispatcher=None, target_solc="0.8.19", abi_v2=True,
                               idiom_level="full", functions={key: fn})
    return compound.run(fn, ctx).body


X = ir.Local("x")
U8 = ir.StateRef("small", (), "uint8")
I8 = ir.StateRef("tiny", (), "int8")
BAL = ir.StateRef("bal", (ir.Cast("address", ir.Mask(160, 0, 0, cd(0))),), "uint256")


def T(o, a, b, ty="uint256", checked=True):
    return ir.Typed(o, (a, b), ty, checked)


def test_typed_compound_assignments():
    assert run([ir.Assign(X, T("add", X, cd(0)))]) == (ir.Assign(X, cd(0), "+", True),)
    assert run([ir.Assign(BAL, T("sub", BAL, cd(1)))]) == (ir.Assign(BAL, cd(1), "-", True),)
    assert run([ir.Assign(U8, T("mul", U8, ir.Mask(8, 0, 0, cd(0)), "uint8", False))]) == \
        (ir.Assign(U8, ir.Mask(8, 0, 0, cd(0)), "*", False),)
    # the target on the right of a commutative operation
    assert run([ir.Assign(X, T("add", cd(0), X))]) == (ir.Assign(X, cd(0), "+", True),)
    # not for a non-commutative one, nor another type, nor another variable
    for value in (T("sub", cd(0), X), T("add", X, cd(0), "uint128"), T("add", ir.Local("y"), cd(0))):
        assert run([ir.Assign(X, value)]) == (ir.Assign(X, value),)


def test_increments():
    assert run([ir.Assign(U8, T("add", U8, ir.ONE, "uint8"))]) == (ir.Assign(U8, ir.ONE, "++", True),)
    assert run([ir.Assign(I8, T("sub", I8, ir.ONE, "int8"))]) == (ir.Assign(I8, ir.ONE, "--", True),)
    assert run([ir.Assign(X, op("add", X, 1))]) == (ir.Assign(X, ir.ONE, "++"),)
    assert run([ir.Assign(X, op("add", X, W - 1))]) == (ir.Assign(X, ir.ONE, "--"),)


def test_evm_compound_assignments_of_uint256_targets():
    assert run([ir.Assign(X, op("add", X, cd(0)))]) == (ir.Assign(X, cd(0), "+"),)
    assert run([ir.Assign(X, op("add", X, op("mul", W - 1, cd(0))))]) == (ir.Assign(X, cd(0), "-"),)
    assert run([ir.Assign(X, op("xor", cd(0), X))]) == (ir.Assign(X, cd(0), "^"),)
    # a division by a constant is Solidity's `/` first, then `/=` with its semantics
    assert run([ir.Assign(X, op("div", X, 7))]) == (ir.Assign(X, ir.Const(7), "/", False),)
    # a division by a word keeps the EVM meaning (0 for a zero divisor)
    assert run([ir.Assign(X, op("div", X, cd(0)))]) == (ir.Assign(X, op("div", X, cd(0))),)
    # narrow targets keep the plain assignment (the narrowing of the EVM value)
    v = op("add", U8, cd(0))
    assert run([ir.Assign(U8, v)]) == (ir.Assign(U8, v),)


def test_target_that_may_fail_is_not_evaluated_once():
    """The lvalue `m[a + b]` (a checked key) is evaluated twice in `x = x +
    y`, once in `x += y`: the pass only rewrites targets that cannot fail."""
    key = ir.Typed("add", (cd(0), cd(1)), "uint256", True)
    m = ir.StateRef("m", (key,), "uint256")
    value = T("add", m, cd(2))
    assert run([ir.Assign(m, value)]) == (ir.Assign(m, value),)


def test_narrowing_mask_of_a_narrow_target_is_dropped():
    value = T("add", I8, ir.Op("signextend", (ir.ZERO, cd(0))), "int8")
    assert run([ir.Assign(I8, ir.Mask(8, 0, 0, value))]) == \
        (ir.Assign(I8, ir.Op("signextend", (ir.ZERO, cd(0))), "+", True),)
    assert run([ir.Assign(U8, ir.Mask(8, 0, 0, cd(0)))]) == (ir.Assign(U8, cd(0)),)
    # a uint256 target or a mask of another width: kept
    assert run([ir.Assign(X, ir.Mask(8, 0, 0, cd(0)))]) == (ir.Assign(X, ir.Mask(8, 0, 0, cd(0))),)
    assert run([ir.Assign(U8, ir.Mask(16, 0, 0, cd(0)))]) == (ir.Assign(U8, ir.Mask(16, 0, 0, cd(0))),)


def test_constants_go_to_the_right():
    r = ir.Return(ir.WordBytes(op("add", 1, cd(0))))
    assert run([r]) == (ir.Return(ir.WordBytes(op("add", cd(0), 1))),)
    r = ir.Require(op("lt", 5, cd(0)))
    assert run([r]) == (ir.Require(op("gt", cd(0), 5)),)
    r = ir.Return(ir.WordBytes(T("mul", ir.Const(3), cd(0))))
    assert run([r]) == (ir.Return(ir.WordBytes(T("mul", cd(0), ir.Const(3)))),)
    r = ir.Return(ir.WordBytes(T("sub", ir.Const(3), cd(0))))
    assert run([r]) == (r,)  # not commutative


def test_bool_returns():
    c = op("gt", cd(0), 5)
    one, zero = ir.Return(ir.WordBytes(ir.ONE)), ir.Return(ir.WordBytes(ir.ZERO))
    assert run([ir.If(c, (one,), (zero,))]) == (ir.Return(ir.WordBytes(c)),)
    assert run([ir.If(c, (zero,), (one,))]) == (ir.Return(ir.WordBytes(op("iszero", c))),)
    # a word condition: its != 0, as a 0/1 word
    assert run([ir.If(cd(0), (one,), (zero,))]) == (ir.Return(ir.WordBytes(op("iszero", op("iszero", cd(0))))),)
    vals = ir.If(c, (ir.Return(None, (ir.ONE,)),), (ir.Return(None, (ir.ZERO,)),))
    assert run([vals]) == (ir.Return(None, (c,)),)
    # not a pair of constant 0 / 1 words
    other = ir.If(c, (one,), (ir.Return(ir.WordBytes(ir.Const(2))),))
    assert run([other]) == (other,)


def test_constant_tests():
    r = ir.Return(ir.WordBytes(cd(0)))
    assert run([ir.Require(op("iszero", op("iszero", 1))), r]) == (r,)  # require(1 != 0)
    assert run([ir.Assert(ir.ONE), r]) == (r,)
    assert run([ir.If(op("lt", 1, 2), (r,), (ir.Revert(),))]) == (r,)
    assert run([ir.If(ir.ZERO, (r,), (ir.Revert(),))]) == (ir.Revert(),)
    always = ir.Require(ir.ZERO)  # always reverts: kept
    assert run([always, r]) == (always, r)


def test_loop_updates_are_left_to_the_loops_pass():
    w = ir.While(op("lt", X, cd(0)), (ir.Continue("L", (ir.Assign(X, op("add", X, 1)),)),), (), "L")
    assert run([w]) == (ir.While(op("lt", X, cd(0)), w.body, (), "L"),)


# ---------------------------------------------------------------- execution


def _contract(units):
    src, _ = assemble(ContractInput(units=units, target="0.8.19", original="test", abi_v2=True, idiom_level="full"))
    return src


def _unit(sel, body, checked_name):
    key = f"0x{sel:08x}"
    spec = EntrySpec(key=key, kind="function", selector=sel, signature=f"{checked_name}(uint256,uint256)",
                     name=checked_name, params=((parse_type("uint256"), "a"), (parse_type("uint256"), "b")),
                     mutability="pure", returns=(parse_type("uint256"),))
    return Unit(key, ir.Function(key, tuple(body)), spec)


def test_rendered_compound_forms_execute_like_the_plain_ones():
    a, b = ir.Param(0), ir.Param(1)
    cases = []
    for o in ("add", "sub", "mul", "div", "mod"):
        for checked in (True, False):
            if o in ("div", "mod") and checked:
                continue
            plain = [ir.Assign(X, a), ir.Assign(X, T(o, X, b, checked=checked)), ir.Return(ir.WordBytes(X))]
            cases.append((o, checked, plain))
    units_plain, units_compound = [], []
    for i, (o, checked, plain) in enumerate(cases):
        name = f"f{i}"
        units_plain.append(_unit(i + 1, plain, name))
        compact = run(plain, key=f"0x{i + 1:08x}")
        assert any(isinstance(s, ir.Assign) and s.op for s in compact), (o, checked)
        units_compound.append(_unit(i + 1, compact, name))
    src_plain, src_compound = _contract(units_plain), _contract(units_compound)
    assert "x += b;" in src_compound and "x -= b;" in src_compound and "x %= b;" in src_compound
    words = [0, 1, 2, 7, W - 1, W - 2, 1 << 255, (1 << 128) + 3]
    calls = []
    for i in range(len(cases)):
        sel = selector(f"f{i}(uint256,uint256)")
        calls += [sel + x.to_bytes(32, "big") + y.to_bytes(32, "big") for x in words for y in words]
    p = compile_or_fail(src_plain, "0.8.19").runtime
    c = compile_or_fail(src_compound, "0.8.19").runtime
    assert run_calls(p, [(d, 0) for d in calls]) == run_calls(c, [(d, 0) for d in calls])


INCREMENTS = """
contract Inc {
    uint8 public u8; int8 public i8; uint256 public u; int256 public i;
    function a1() external { u8 += 1; }            function a2() external { u8++; }
    function b1() external { u8 -= 1; }            function b2() external { u8--; }
    function c1() external { i8 += 1; }            function c2() external { i8++; }
    function d1() external { i8 -= 1; }            function d2() external { i8--; }
    function e1() external { u += 1; }             function e2() external { u++; }
    function f1() external { i -= 1; }             function f2() external { i--; }
    function g1() external { unchecked { u8 += 1; } }   function g2() external { unchecked { u8++; } }
    function h1() external { unchecked { i8 -= 1; } }   function h2() external { unchecked { i8--; } }
    function k1(uint8 x) external pure returns (uint8) { x += 1; return x; }
    function k2(uint8 x) external pure returns (uint8) { x++; return x; }
    function l1(int256 x) external pure returns (int256) { x -= 1; return x; }
    function l2(int256 x) external pure returns (int256) { x--; return x; }
}
"""


@pytest.mark.parametrize("version", ["0.8.19", "0.8.31"])
def test_increment_statements_are_the_compound_assignments(version):
    """The rule behind `x += 1` -> `x++`: as statements they behave the same
    for every integer type, checked or not (same success, data, storage)."""
    from scobelix.verify.solc import Settings, compile_standard_json, execution_evm_version

    from conftest import solc_or_skip

    path = solc_or_skip(version)
    for optimize in (True, False):
        comp = compile_standard_json(f"pragma solidity ^{version};\n" + INCREMENTS,
                                     Settings(optimize=optimize, evm_version=execution_evm_version(version)),
                                     version=version, solc_path=path)
        code = comp.artifact("Inc").runtime
        # storage: slot 0 = u8 | i8 << 8, slot 1 = u, slot 2 = i
        presets = [{0: 0, 1: 0, 2: 0}, {0: 0xFFFF, 1: W - 1, 2: W - 1}, {0: 0x80FF, 1: W - 2, 2: 1 << 255},
                   {0: 0x7F00, 1: 1, 2: (1 << 255) - 1}, {0: 0x01FE, 1: 2, 2: 1}]
        for pre in presets:
            for n in "abcdefgh":
                one = run_calls(code, [(selector(f"{n}1()"), 0)], pre)
                two = run_calls(code, [(selector(f"{n}2()"), 0)], pre)
                assert one == two, (version, optimize, n, pre)
        for x in (0, 1, 127, 128, 254, 255):
            data = x.to_bytes(32, "big")
            assert run_calls(code, [(selector("k1(uint8)") + data, 0)]) == \
                run_calls(code, [(selector("k2(uint8)") + data, 0)])
        for x in (0, 1, W - 1, 1 << 255, (1 << 255) + 1):
            data = x.to_bytes(32, "big")
            assert run_calls(code, [(selector("l1(int256)") + data, 0)]) == \
                run_calls(code, [(selector("l2(int256)") + data, 0)])

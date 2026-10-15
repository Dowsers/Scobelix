"""
The loops pass writes the recovered loops as a developer does (`for` with
its header, sequential assignments instead of parallel ones, `break`, no
trailing `continue`) and marks the assignments that can declare their local.
None of it may change what a call does, nor which failure comes first.

Tests: the ordering of parallel assignments against their definition
(random assignments evaluated both ways); each rewrite and each refusal on
hand-written IR; hand-written loops compiled before and after the pass and
executed on the same inputs (failure orders no compiler output shows); the
declaration sites and the renderer's own check of the marks; probe
contracts with every loop form, compiled by several solc builds, decompiled,
generated and executed against the original on crafted and small inputs,
with logs, storage of every account and the calls made compared.
"""

import itertools
import random
import re
from typing import Optional

import pytest
from eth_abi import encode as abi_encode
from eth_utils import keccak

import callprobe
from conftest import backend_or_skip, compile_or_fail
from probes import (Build, compile_probe, function_text, generate_probe, patch_signatures, probe_calls,
                    selector)
from scobelix.solgen import ir, pipeline, scopes
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.contract import ContractInput, Unit, assemble
from scobelix.solgen.passes import loops

W = 1 << 256
LID = "Node((7, 3, ('1',)))"
LID2 = "Node((9, 4, ('1',)))"
A, B, C = (ir.CalldataWord(ir.Const(o)) for o in (4, 36, 68))
I, J, X, Y, Z, S = (ir.Local(n) for n in ("i", "j", "x", "y", "z", "s"))


def op(name, *args):
    return ir.Op(name, tuple(a if isinstance(a, ir.Node) else ir.const(a) for a in args))


def T(name, a, b, checked=True, ty="uint256"):
    return ir.Typed(name, tuple(x if isinstance(x, ir.Node) else ir.const(x) for x in (a, b)), ty, checked)


def let(target, value, **kw):
    return ir.Assign(target, value if isinstance(value, ir.Node) else ir.const(value), **kw)


def cont(*updates, lid=LID):
    return ir.Continue(lid, tuple(updates))


def ret(*words):
    return ir.Return(ir.Blob(tuple(ir.WordBytes(w) for w in words)))


def run(body, key="0x00000001"):
    fn = ir.Function(key, tuple(body))
    ctx = pipeline.PassContext(specs={key: EntrySpec(key=key, kind="function", selector=int(key, 16))},
                               metadata=None, dispatcher=None, target_solc="0.8.19", abi_v2=True,
                               idiom_level="full", functions={key: fn})
    return loops.run(fn, ctx).body, ctx.facts.get("loops", {}).get("functions", {}).get(key, {})


def unmarked(node):
    """The node without its declaration marks."""
    return ir.transform(node, lambda n: ir.Assign(n.target, n.value, n.op, n.checked) if isinstance(n, ir.Assign) else n)


# ---------------------------------------------------------------- parallel -> sequential


def value_of(e, env):
    if isinstance(e, ir.Const):
        return e.value
    if isinstance(e, ir.Local):
        return env[e.name]
    a, b = (value_of(x, env) for x in e.args)
    return (a + b) % W if e.op == "add" else (a * b) % W


def parallel(updates, env):
    new = {a.target.name: value_of(a.value, env) for a in updates}
    return dict(env, **new)


def sequential(assigns, env):
    env = dict(env)
    for a in assigns:
        env[a.target.name] = value_of(a.value, env)
    return env


def test_sequential_order_without_temporary():
    # s reads the old i: it is written before i
    got, temps = loops.sequence([let(I, op("add", I, 1)), let(S, op("add", S, I))], set())
    assert temps == 0 and got == [let(S, op("add", S, I)), let(I, op("add", I, 1))]
    # nothing forces another order: the given one
    ups = [let(I, op("add", I, 1)), let(S, op("add", S, 2))]
    assert loops.sequence(ups, set()) == (ups, 0)
    # x = x is nothing
    assert loops.sequence([let(X, X), let(I, op("add", I, 1))], set()) == ([let(I, op("add", I, 1))], 0)


def test_cycles_take_the_fewest_temporaries():
    swap = [let(X, Y), let(Y, X)]
    got, temps = loops.sequence(swap, {"x", "y"})
    assert temps == 1 and got == [let(ir.Local("x_next"), Y), let(Y, X), let(X, ir.Local("x_next"))]
    rotation = [let(X, Y), let(Y, Z), let(Z, X)]
    got, temps = loops.sequence(rotation, {"x", "y", "z"})
    assert temps == 1 and len(got) == 4
    two_swaps = [let(X, Y), let(Y, X), let(I, J), let(J, I)]
    assert loops.sequence(two_swaps, set())[1] == 2
    # the name of a temporary is new
    taken = {"x", "y", "x_next"}
    got, _ = loops.sequence(swap, taken)
    assert got[0].target == ir.Local("x_next2") and "x_next2" in taken


def test_random_parallel_assignments_keep_their_values():
    rng = random.Random(5)
    names = ["i", "j", "x", "y", "z", "s"]
    for _ in range(400):
        targets = rng.sample(names, rng.randint(1, 6))
        ups = []
        for t in targets:
            a, b = (ir.Local(rng.choice(names)) if rng.random() < 0.7 else ir.const(rng.randint(0, 9)) for _ in "ab")
            ups.append(let(ir.Local(t), a if rng.random() < 0.3 else op(rng.choice(["add", "mul"]), a, b)))
        env = {n: rng.randint(0, 50) for n in names}
        got, temps = loops.sequence(ups, set(names))
        after = sequential(got, env)
        assert {n: after[n] for n in names} == parallel(ups, env), ups
        assert temps < max(2, len(ups)), ups
        last = rng.choice(targets)
        fixed = loops.sequence(ups, set(names), last=last)
        if fixed is not None:
            assert fixed[0][-1].target.name == last
            after = sequential(fixed[0], env)
            assert {n: after[n] for n in names} == parallel(ups, env), ups


def test_failures_keep_their_order():
    overflow = T("add", X, Y)  # Panic(0x11)
    zero = T("div", X, Y, False)  # Panic(0x12)
    # y's value must be read before x is set, and x's value fails first: a temporary keeps both
    got, temps = loops.sequence([let(X, overflow), let(Y, zero)], {"x", "y"})
    assert temps == 1 and got[0] == let(ir.Local("x_next"), overflow) and got[1] == let(Y, zero)
    # two overflows are one failure: any order
    got, temps = loops.sequence([let(X, T("add", X, 1)), let(Y, T("mul", X, 3))], {"x", "y"})
    assert temps == 0 and got == [let(Y, T("mul", X, 3)), let(X, T("add", X, 1))]
    # a step that fails in another way than a value after it cannot go last
    ups = [let(I, T("add", I, 1)), let(S, T("div", S, op("sub", A, I), False))]
    assert loops.sequence(ups, {"i", "s"}, last="i") is None
    got, temps = loops.sequence(ups, {"i", "s"})
    assert temps == 1 and got[0].value == T("add", I, 1)
    # a value that reads another target cannot go last either
    assert loops.sequence([let(I, op("add", I, S)), let(S, op("add", S, 1))], set(), last="i") is None


# ---------------------------------------------------------------- the rewrites on IR


def sum_loop(step, cond=None, extra=()):
    return (ir.While(cond if cond is not None else op("lt", I, A),
                     tuple(extra) + (cont(let(I, step), let(S, T("add", S, I))),),
                     (let(I, 0), let(S, 0)), LID),
            ret(S))


def test_induction_variable_becomes_a_for_header():
    body, facts = run(sum_loop(T("add", I, 1)))
    assert body == (
        let(S, 0, declare=True),
        ir.For((let(I, 0, declare=True),), op("lt", I, A), (let(I, T("add", I, 1)),), (let(S, T("add", S, I)),), LID),
        ret(S),
    )
    assert facts == {"loops": 1, "for": 1, "declared": 2}


def test_a_counter_read_after_the_loop_is_not_declared_in_the_header():
    w, _ = sum_loop(T("add", I, 1))
    body, facts = run((w, ret(I)))
    assert body[1].init == (let(I, 0),)  # for (i = 0; ...), i declared at the top
    assert facts["hoisted"] == 1


def test_steps_that_differ_or_read_the_loop_stay_in_the_body():
    # two paths with different steps
    w = ir.While(op("lt", I, A), (ir.If(B, (cont(let(I, op("add", I, 1))),), (cont(let(I, op("add", I, 2))),)),),
                 (let(I, 0),), LID)
    body, facts = run((w, ret(I)))
    assert isinstance(body[-2], ir.For) and not body[-2].step and facts["while"] == 1
    assert body[-2].body == (ir.If(B, (let(I, op("add", I, 1)),), (let(I, op("add", I, 2)),)),)
    # the step reads a variable the loop changes
    w = ir.While(op("lt", I, A), (cont(let(I, op("add", I, S)), let(S, op("add", S, 1))),), (let(I, 0), let(S, 1)), LID)
    body, facts = run((w, ret(I)))
    assert not body[-2].step and "temporaries" not in facts
    assert body[-2].body == (let(I, op("add", I, S)), let(S, op("add", S, 1)))
    # the counter is not in the condition: no header
    w = ir.While(op("lt", S, A), (cont(let(I, op("add", I, 1)), let(S, op("mul", S, 2))),), (let(I, 0), let(S, 1)), LID)
    body, _ = run((w, ret(I)))
    assert body[-2].step == (let(S, op("mul", S, 2)),) and body[-2].body == (let(I, op("add", I, 1)),)


def test_a_counter_the_body_sets_keeps_its_step_in_the_body():
    """`i < bound` says nothing about `i + 1` once the body has set i (here
    to a word that the wrapping step takes to 0): no header, the step stays
    in the body where it wraps."""
    reset = ir.If(op("eq", I, B), (let(I, C),))
    w = ir.While(op("lt", I, A), (reset, cont(let(I, op("add", I, 1)), let(S, T("add", S, 1)))),
                 (let(I, 0), let(S, 0)), LID)
    body, facts = run((w, ret(S)))
    assert isinstance(body[-2], ir.For) and not body[-2].step and facts["while:set_in_body"] == 1
    assert body[-2].body == (reset, let(I, op("add", I, 1)), let(S, T("add", S, 1)))
    # the same counter set by a nested loop
    inner = ir.While(op("lt", J, B), (cont(let(J, op("add", J, 1)), let(I, C), lid=LID2),), (let(J, 0),), LID2)
    w = ir.While(op("lt", I, A), (inner, cont(let(I, op("add", I, 1)), let(S, T("add", S, 1)))),
                 (let(I, 0), let(S, 0)), LID)
    body, facts = run((w, ret(S)))
    assert isinstance(body[-2], ir.For) and not body[-2].step and facts["while:set_in_body"] == 1
    assert body[-2].body[-2:] == (let(I, op("add", I, 1)), let(S, T("add", S, 1)))


def test_a_continue_of_the_loop_inside_a_nested_loop_keeps_the_lifted_form():
    """`continue` cannot leave a nested loop (the renderer reports such a
    path): with a step in the header the update it carries would also run
    the step, so the outer loop stays as it was lifted."""
    outer_next = cont(let(J, op("add", J, 1)), lid=LID2)
    inner = ir.While(op("lt", I, A), (ir.If(op("eq", I, B), (ir.Sstore(ir.Const(5), I), outer_next),
                                            (cont(let(I, op("add", I, 1))),)),), (let(I, 0),), LID)
    w = ir.While(op("lt", J, C), (inner, ir.Sstore(ir.Const(6), J), outer_next), (let(J, 0),), LID2)
    body, facts = run((w, ir.Stop()))
    assert isinstance(body[0], ir.While) and body[0].loop_id == LID2 and body[0].body[1:] == w.body[1:]
    assert isinstance(body[0].body[0], ir.For) and ir.contains(body[0].body[0].body, ir.Continue)
    assert facts["for"] == 1 and facts["while"] == 1


def test_wrapping_step_in_a_checked_function():
    """`unchecked { ++i; }` (or the increment solc >= 0.8.22 leaves
    unchecked): the checked increment when `i < bound` proves them equal,
    otherwise the step stays in the body, where it wraps."""
    body, _ = run(sum_loop(op("add", I, 1)))
    assert body[1].step == (let(I, T("add", I, 1)),)
    body, _ = run(sum_loop(op("add", 1, I)))
    assert body[1].step == (let(I, T("add", I, 1)),)
    # i + 2 may wrap under i < bound; i != bound proves nothing
    for step, cond in ((op("add", I, 2), None), (op("add", I, 1), op("iszero", op("eq", I, A)))):
        body, facts = run(sum_loop(step, cond))
        assert not body[-2].step and body[-2].body[-1] == let(I, step) and facts["while"] == 1
    # i - 1 under i != 0 / i > k
    for cond in (I, op("gt", I, 3), op("lt", A, I)):
        for step in (op("add", I, W - 1), op("sub", I, 1)):
            body, _ = run(sum_loop(step, cond))
            assert body[1].step == (let(I, T("sub", I, 1)),), (cond, step)
    body, _ = run(sum_loop(op("sub", I, 1)))  # i < bound says nothing about i - 1
    assert not body[-2].step
    # a uint8 counter: uint8(i) < bound <= 255
    narrow = ir.Mask(8, 0, 0, I)
    body, _ = run(sum_loop(ir.Mask(8, 0, 0, op("add", I, 1)), op("lt", narrow, ir.Mask(8, 0, 0, A))))
    assert body[1].step == (let(I, T("add", narrow, 1, ty="uint8")),)
    body, _ = run(sum_loop(ir.Mask(8, 0, 0, op("add", I, 1)), op("lt", narrow, A)))  # the bound may exceed 255
    assert not body[-2].step
    # without checked operations the whole function wraps: the step as it is
    w = ir.While(op("lt", I, A), (cont(let(I, op("add", I, 2)), let(S, op("add", S, I))),), (let(I, 0), let(S, 0)), LID)
    body, _ = run((w, ret(S)))
    assert body[1].step == (let(I, op("add", I, 2)),)


def test_trailing_continue_and_branches():
    skip = ir.If(op("eq", I, B), (cont(let(I, op("add", I, 1)), let(S, S)),),
                 (cont(let(I, op("add", I, 1)), let(S, op("add", S, I))),))
    body, _ = run((ir.While(op("lt", I, A), (skip,), (let(I, 0), let(S, 0)), LID), ret(S)))
    assert body[1].body == (ir.If(op("iszero", op("eq", I, B)), (let(S, op("add", S, I)),)),)
    # the branch that leaves comes first, the rest of the body follows it
    leave = ir.If(op("eq", I, B), (cont(let(I, op("add", I, 1)), let(S, op("add", S, I))),), (ret(I),))
    body, _ = run((ir.While(op("lt", I, A), (leave,), (let(I, 0), let(S, 0)), LID), ret(S)))
    assert body[1].body == (ir.If(op("iszero", op("eq", I, B)), (ret(I),), (let(S, op("add", S, I)),)),)
    # a long second branch: the first keeps its `continue`
    long = tuple(ir.Sstore(ir.Const(k), I) for k in range(4))
    both = ir.If(B, (ir.Sstore(ir.Const(9), I), cont(let(I, op("add", I, 1)))), long + (cont(let(I, op("add", I, 1))),))
    body, _ = run((ir.While(op("lt", I, A), (both,), (let(I, 0),), LID), ir.Stop()))
    assert body[0].body == (ir.If(B, (ir.Sstore(ir.Const(9), I), cont()), long),)


def test_exit_paths_that_repeat_the_code_after_the_loop_break():
    after = (ir.Sstore(ir.Const(1), S), ret(S))
    w = ir.While(op("lt", I, A),
                 (ir.If(op("eq", I, B), (ir.Sstore(ir.Const(2), I),) + after,
                        (cont(let(I, op("add", I, 1)), let(S, op("add", S, I))),)),),
                 (let(I, 0), let(S, 0)), LID)
    body, facts = run((w,) + after)
    assert facts["breaks"] == 1
    # (the renderer writes the branch that goes on after the `if`)
    assert unmarked(body[1].body) == (ir.If(op("eq", I, B), (ir.Sstore(ir.Const(2), I), ir.Break(LID)),
                                            (let(S, op("add", S, I)),)),)
    # one short statement is not worth a break
    w = ir.While(op("lt", I, A), (ir.If(op("eq", I, B), (ret(S),), (cont(let(I, op("add", I, 1))),)),), (let(I, 0),), LID)
    body, facts = run((w, ret(S)))
    assert "breaks" not in facts and not ir.contains(body, ir.Break)
    # an inner path that goes on with the outer loop has no other translation
    outer_next = cont(let(J, op("add", J, 1)), lid=LID2)
    inner = ir.While(op("lt", I, A), (ir.If(op("eq", I, B), (outer_next,), (cont(let(I, op("add", I, 1))),)),),
                     (let(I, 0),), LID)
    body, facts = run((ir.While(op("lt", J, C), (inner, outer_next), (let(J, 0),), LID2), ir.Stop()))
    assert facts["breaks"] == 1 and facts["for"] == 2
    assert body[0].body[0].body == (ir.If(op("eq", I, B), (ir.Break(LID),)),)


def test_guards_the_condition_implies():
    cond = op("lt", I, ir.Sload(ir.Const(0)))
    guard = ir.If(op("iszero", cond), (ir.Revert(ir.Panic(0x32)),), (cont(let(I, op("add", I, 1))),))
    body, facts = run((ir.While(cond, (guard,), (let(I, 0),), LID), ir.Stop()))
    assert facts["guards"] == 1 and body[0].body == ()
    # not when the condition reads something that changes by itself
    cond = op("lt", I, ir.Env("gas"))
    guard = ir.If(op("iszero", cond), (ir.Revert(ir.Panic(0x32)),), (cont(let(I, op("add", I, 1))),))
    body, facts = run((ir.While(cond, (guard,), (let(I, 0),), LID), ir.Stop()))
    assert "guards" not in facts and isinstance(body[0].body[0], ir.If)
    # nor after a statement of the body
    cond = op("lt", I, ir.Sload(ir.Const(0)))
    guard = ir.If(op("iszero", cond), (ir.Revert(ir.Panic(0x32)),), (cont(let(I, op("add", I, 1))),))
    body, facts = run((ir.While(cond, (ir.Sstore(ir.Const(0), A), guard), (let(I, 0),), LID), ir.Stop()))
    assert "guards" not in facts


def test_loops_left_in_their_lifted_form():
    # a compound update is not a plain parallel assignment
    w = ir.While(op("lt", I, A), (cont(ir.Assign(I, ir.ONE, "++")),), (let(I, 0),), LID)
    body, facts = run((w, ret(I)))
    assert body == (w, ret(I)) and facts == {"loops": 1, "while": 1, "hoisted": 1}
    # an unstructured loop (label): while (true), counted
    w = ir.While(ir.ONE, (ir.If(op("lt", I, A), (cont(let(I, op("add", I, 1))),), (ret(I),)),), (let(I, 0),), LID)
    body, facts = run((w,))
    assert facts["labels"] == 1 and facts["while"] == 1
    assert body[-1] == ir.For((), ir.ONE, (), (ir.If(op("iszero", op("lt", I, A)), (ret(I),), (let(I, op("add", I, 1)),)),), LID)
    # nothing to do: the same object
    fn = ir.Function("0x00000001", (ir.Sstore(ir.Const(0), A), ir.Stop()))
    ctx = pipeline.PassContext(specs={}, metadata=None, dispatcher=None, target_solc="0.8.19", abi_v2=True,
                               idiom_level="full")
    assert loops.run(fn, ctx) is fn and "loops" not in ctx.facts


# ---------------------------------------------------------------- declaration sites


def test_declaration_sites():
    first = let(X, A)
    assert scopes.sites((first, let(X, op("add", X, 1)), ret(X))) == {"x": [first]}
    # read before it is set in the block, or set from itself: no site
    assert scopes.sites((ir.Sstore(ir.Const(0), X), let(X, A))) == {}
    assert scopes.sites((let(X, op("add", X, 1)), ret(X))) == {}
    # set in a branch, read after it: no site; each branch on its own: one site each
    a, b = let(X, A), let(X, B)
    assert scopes.sites((ir.If(C, (a,), (b,)), ret(X))) == {}
    assert scopes.sites((ir.If(C, (a, ret(X)), (b, ret(X))),)) == {"x": [a, b]}
    assert scopes.sites((ir.If(X, (a, ret(X)), (b, ret(X))),)) == {}
    # a loop body declares what it sets first on every iteration; a header does when nothing outside reads it
    init = let(I, 0)
    loop = ir.For((init,), op("lt", I, A), (let(I, op("add", I, 1)),), (a, ir.Sstore(I, X)), LID)
    assert scopes.sites((loop, ir.Stop())) == {"i": [init], "x": [a]}
    assert scopes.sites((loop, ret(I))) == {"x": [a]}
    assert scopes.sites((ir.For((), op("lt", X, A), (), (a,), LID),)) == {}
    w = ir.While(op("lt", I, A), (a, cont(let(I, X))), (init,), LID)
    assert scopes.sites((w, ir.Stop())) == {"x": [a]}
    # the output of a precompile call is not an assignment
    pre = [ir.Precompile(1, 1, "erecover", ir.Blob(()), "x")]
    assert scopes.sites((let(X, A),) + tuple(pre) + (ret(X),)) == {}


def _render(body):
    key = "0x00000001"
    unit = Unit(key, ir.Function(key, tuple(body)), EntrySpec(key=key, kind="function", selector=1))
    source, _ = assemble(ContractInput(units=[unit], target="0.8.19", original="test", original_code=b""))
    return source


def test_renderer_declares_only_at_checked_sites():
    body, _ = run(sum_loop(T("add", I, 1)))
    text = _render(body)
    assert "uint256 s = 0;" in text and "for (uint256 i = 0; i < _calldataload(4); i = i + 1) {" in text
    assert "uint256 i;" not in text and "uint256 s;" not in text
    compile_or_fail(text, "0.8.19")
    # a mark that is not a site (a statement moved after the pass): declared at the top as before
    moved = (ret(S),) + body
    text = _render(moved)
    assert "uint256 s;" in text and "uint256 s = 0;" not in text
    compile_or_fail(text, "0.8.19")
    # a marked copy inside the scope of the site
    text = _render((body[0], body[0]) + body[1:])
    assert "uint256 s;" in text
    compile_or_fail(text, "0.8.19")
    # a wrapping assignment in a function with checked operations has an unchecked block of its own
    text = _render((let(X, op("add", A, B), declare=True), let(Y, T("add", X, 1), declare=True), ret(X, Y)))
    assert "uint256 x;" in text and "uint256 y = x + 1;" in text
    compile_or_fail(text, "0.8.19")


# ---------------------------------------------------------------- hand-written loops, before and after

N = op("and", A, 7)  # at most 7 iterations


def _loop(init, cond, body, after, lid=LID):
    return (ir.While(cond, tuple(body), tuple(init), lid),) + tuple(after)


INC = let(I, T("add", I, 1))
IR_LOOPS = {
    # the sum overflows (0x11) before the division by zero (0x12), whatever the order of the assignments
    "swap_two_failures": _loop(
        [let(I, 0), let(X, B), let(Y, C)], op("lt", I, N),
        [cont(INC, let(X, T("add", X, Y)), let(Y, T("div", X, op("sub", Y, 5), False)))], [ret(X, Y)]),
    "swap_two_failures_reversed": _loop(
        [let(I, 0), let(X, B), let(Y, C)], op("lt", I, N),
        [cont(let(Y, T("div", X, op("sub", Y, 5), False)), let(X, T("add", X, Y)), INC)], [ret(X, Y)]),
    # the step overflows before the division fails
    "step_then_division": _loop(
        [let(I, 0), let(S, 1000)], op("lt", I, C),
        [cont(let(I, T("add", I, B)), let(S, T("div", S, op("sub", A, I), False)))], [ret(I, S)]),
    "rotation": _loop(
        [let(I, 0), let(X, A), let(Y, B), let(Z, C)], op("lt", I, N),
        [cont(INC, let(X, Y), let(Y, Z), let(Z, op("add", X, I)))], [ret(X, Y, Z)]),
    "dependent_init": _loop(
        [let(I, B), let(S, I), let(X, op("add", S, 3))], op("lt", I, op("add", B, N)),
        [cont(let(I, op("add", I, 1)), let(S, op("add", S, X)), let(X, S))], [ret(I, S, X)]),
    "break_with_code_after": _loop(
        [let(I, 0), let(S, 0)], op("lt", I, N),
        [ir.If(op("eq", I, B), (ir.Sstore(ir.Const(2), I), ir.Sstore(ir.Const(1), S), ret(S, I)),
               (cont(INC, let(S, T("add", S, op("mul", I, C)))),))],
        [ir.Sstore(ir.Const(1), S), ret(S, I)]),
    "skip_and_store": _loop(
        [let(I, 0), let(S, 0)], op("lt", I, N),
        [ir.If(op("eq", op("and", I, 1), op("and", B, 1)), (cont(INC, let(S, S)),),
               (ir.Sstore(I, S), ir.Require(op("lt", I, C)), cont(INC, let(S, T("add", S, I)))))],
        [ret(S)]),
    "guard_of_the_condition": _loop(
        [let(I, 0), let(S, 0)], op("lt", I, N),
        [ir.If(op("iszero", op("lt", I, N)), (ir.Revert(ir.Panic(0x32)),),
               (cont(let(I, op("add", I, 1)), let(S, T("add", S, B))),))],
        [ret(S)]),
    "wrapping_step_checked_body": _loop(
        [let(I, B), let(S, 0)], op("lt", I, C),
        [ir.If(op("gt", S, 40), (ret(S, I),), (cont(let(I, op("add", I, 1)), let(S, T("add", S, I))),))], [ret(S, I)]),
    # the body sets the counter (to 2**256 - 1 with c): the wrapping step takes it back to 0
    "counter_set_by_the_body": _loop(
        [let(I, 0), let(S, 0)], op("lt", I, N),
        [ir.If(op("gt", S, 20), (ret(S, I),)), ir.If(op("eq", I, B), (let(I, C),)),
         cont(let(I, op("add", I, 1)), let(S, T("add", S, 1)))], [ret(S, I)]),
    "countdown": _loop(
        [let(I, N), let(S, B)], I,
        [cont(let(I, op("add", I, W - 1)), let(S, T("mul", S, I)))], [ret(S, I)]),
    "nested": _loop(
        [let(J, 0), let(S, 0)], op("lt", J, N),
        [ir.While(op("lt", I, op("and", B, 3)),
                  (ir.If(op("eq", op("add", I, J), C), (ir.Sstore(J, X), ret(X, I)),
                         (cont(let(I, T("add", I, 1)), let(X, T("add", X, op("mul", I, J)))),)),),
                  (let(I, 0), let(X, S)), LID),
         cont(let(J, T("add", J, 1)), let(S, X), lid=LID2)],
        [ret(S, J)], lid=LID2),
}
IR_OPERANDS = [(0, 0, 0), (5, 2, 3), (7, 1, 5), (7, W - 1, 5), (7, W - 3, 6), (3, 1 << 255, 1 << 255), (6, 3, W - 1),
               (7, 9, 9), (4, 5, 1), (7, 2, 4), (7, W - 2, W - 1), (5, 0, 5), (7, 1, 0), (2, 77, 3),
               (1 << 255, 1 << 255, W - 1), (0, 1, 9), (40, 7, 30)]


@pytest.fixture(scope="module")
def ir_loops():
    backend = backend_or_skip()
    units, keys = [], {}
    for k, (name, body) in enumerate(IR_LOOPS.items()):
        for variant in (0, 1):
            sel = 0x30000000 + 2 * k + variant
            key = f"0x{sel:08x}"
            fn = ir.Function(key, body)
            if variant:
                ctx = pipeline.PassContext(specs={}, metadata=None, dispatcher=None, target_solc="0.8.19",
                                           abi_v2=True, idiom_level="full")
                new = loops.run(fn, ctx)
                assert new is not fn and ir.contains(new.body, ir.For), name
                fn = new
            units.append(Unit(key, fn, EntrySpec(key=key, kind="function", selector=sel)))
            keys[name, variant] = sel
    source, _ = assemble(ContractInput(units=units, target="0.8.19", original="test", original_code=b""))
    return backend, compile_or_fail(source, "0.8.19").runtime, keys, source


@pytest.mark.parametrize("name", list(IR_LOOPS))
def test_rewritten_loop_behaves_as_the_lifted_one(ir_loops, name):
    from scobelix.verify.evm import make_world

    backend, runtime, keys, source = ir_loops
    assert "parallel assignment" not in source.split(f"_fn_{keys[name, 1]:08x}")[-1].split("function ")[0]
    for a, b, c in IR_OPERANDS:
        got = []
        for variant in (0, 1):
            world = make_world(backend)
            world.set_balance(callprobe.CALLER, 10**20)
            world.set_code(callprobe.TARGET, runtime)
            data = keys[name, variant].to_bytes(4, "big") + b"".join(x.to_bytes(32, "big") for x in (a, b, c))
            r = world.call(callprobe.CALLER, callprobe.TARGET, data)
            got.append((r.success, bytes(r.output), tuple(sorted((k[1], v[1]) for k, v in r.storage_diff.items()))))
        assert got[0] == got[1], (name, (a, b, c), got)


def test_the_two_failures_are_both_reached(ir_loops):
    """The operands of the failure-order cases do reach both Panics (the
    comparison above is then a real one)."""
    from scobelix.verify.evm import make_world

    backend, runtime, keys, _ = ir_loops
    seen = set()
    for name in ("swap_two_failures", "swap_two_failures_reversed", "step_then_division"):
        for a, b, c in IR_OPERANDS:
            world = make_world(backend)
            world.set_balance(callprobe.CALLER, 10**20)
            world.set_code(callprobe.TARGET, runtime)
            data = keys[name, 1].to_bytes(4, "big") + b"".join(x.to_bytes(32, "big") for x in (a, b, c))
            r = world.call(callprobe.CALLER, callprobe.TARGET, data)
            if not r.success and r.output:
                seen.add((name, bytes(r.output)[-1]))
    assert {(n, code) for n in ("swap_two_failures", "swap_two_failures_reversed", "step_then_division")
            for code in (0x11, 0x12)} <= seen, seen


# ---------------------------------------------------------------- probes on real compilers

FORMS = """
contract Forms {
    function sum(uint256 n) external pure returns (uint256 s) {
        for (uint256 i = 0; i < n; i++) { s += i; }
    }
    function fib(uint256 n) external pure returns (uint256 a) {
        uint256 b = 1;
        for (uint256 i = 0; i < n; i++) { (a, b) = (b, a + b); }
    }
    function rot(uint256 n, uint256 x, uint256 y, uint256 z) external pure returns (uint256, uint256, uint256) {
        for (uint256 i = 0; i < n; i++) { (x, y, z) = (y, z, x); }
        return (x, y, z);
    }
    function mutual(uint256 n, uint256 a, uint256 b) external pure returns (uint256, uint256) {
        for (uint256 i = 0; i < n; i++) { (a, b) = (b + i, a * 2 + b); }
        return (a, b);
    }
    function doWhile(uint256 n) external pure returns (uint256 c) {
        uint256 i = n;
        do { c += i; i /= 2; } while (i > 0);
    }
    function withBreak(uint256 n, uint256 k) external pure returns (uint256 s) {
        for (uint256 i = 0; i < n; i++) {
            if (i == k) break;
            s += i;
        }
        s = s * 3 + k % 7;
    }
    function withContinue(uint256 n, uint256 k) external pure returns (uint256 s) {
        for (uint256 i = 0; i < n; i++) {
            if (i % 3 == k) continue;
            s += i;
        }
    }
    function early(uint256 n, uint256 k) external pure returns (uint256) {
        for (uint256 i = 0; i < n; i++) {
            if (i * i == k) return i;
        }
        return ~uint256(0);
    }
    function nested(uint256 n, uint256 m) external pure returns (uint256 t) {
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = 0; j < m; j++) { t += i * j + 1; }
        }
    }
    function byTwo(uint256 n) external pure returns (uint256 c, uint256 i) {
        for (i = 0; i < n; i += 2) { c++; }
    }
    function bigStep(uint256 a, uint256 b) external pure returns (uint256 c) {
        for (uint256 i = a; i < b; i += 1 << 255) { c++; }
    }
    function down(uint256 n) external pure returns (uint256 c) {
        for (uint256 i = n; i > 0; i--) { c += i; }
    }
    function downTwo(uint256 n) external pure returns (uint256 c) {
        uint256 i = n;
        while (i > 1) { i -= 2; c++; }
    }
    function signedDown(int256 n) external pure returns (uint256 c) {
        for (int256 i = n; i >= 0; i--) {
            c++;
            if (c > 40) break;
        }
    }
    function signedUp(int256 a, int256 b) external pure returns (uint256 c) {
        for (int256 i = a; i < b; i += 3) {
            c++;
            if (c > 30) break;
        }
    }
    function small(uint8 n) external pure returns (uint256 c) {
        for (uint8 i = 0; i < n; i++) { c += 2; }
    }
    function smallStep(uint8 n) external pure returns (uint256 c) {
        for (uint8 i = 0; i < n; i += 100) { c++; }
    }
    function u64(uint64 a, uint64 b) external pure returns (uint256 c) {
        for (uint64 i = a; i < b; i += 0x4000000000000000) { c++; }
    }
    function sumCalldata(uint256[] calldata a) external pure returns (uint256 s) {
        for (uint256 i = 0; i < a.length; i++) { s += a[i]; }
    }
    function prologue(uint256 n) external pure returns (uint256 i) {
        while (i * i + 1 < n) { i++; }
    }
    function twoCounters(uint256 n) external pure returns (uint256 i, uint256 j) {
        for (j = n; i < j; i++) { j--; }
    }
}
"""

EFFECTS = """
contract Effects {
    uint256[] public items;
    uint256 public total;
    mapping(uint256 => uint256) public seen;
    event Step(uint256 i, uint256 t);

    function writes(uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            seen[i] = total;
            total += i;
            emit Step(i, total);
        }
    }
    function midRevert(uint256 n, uint256 bad) external returns (uint256 s) {
        for (uint256 i = 0; i < n; i++) {
            total = i;
            require(i != bad, "bad");
            s += i;
        }
    }
    function callsOut(address t, uint256 n) external returns (uint256 s) {
        for (uint256 i = 0; i < n; i++) {
            total = i;
            (bool ok, ) = t.call(abi.encodeWithSelector(0x11223344, i));
            require(ok, "callee");
            emit Step(i, s);
            s += i + 1;
        }
    }
    function sumStorage() external view returns (uint256 s) {
        for (uint256 i = 0; i < items.length; i++) { s += items[i]; }
    }
    function sumCached() external view returns (uint256 s) {
        uint256 n = items.length;
        for (uint256 i = 0; i < n; ++i) { s += items[i]; }
    }
    function find(uint256 v) external view returns (uint256) {
        for (uint256 i = 0; i < items.length; i++) {
            if (items[i] == v) return i;
        }
        return ~uint256(0);
    }
    function bumpAll(uint256 d) external {
        for (uint256 i = 0; i < items.length; i++) { items[i] += d; }
    }
    function shrink(uint256 n) external returns (uint256 i) {
        total = n;
        while (i < total) {
            total -= 1;
            i++;
        }
    }
    function getItems() external view returns (uint256[] memory) {
        return items;
    }
}
"""

UNCHECKED = """
contract Unchecked {
    function inc(uint256 n) external pure returns (uint256 s) {
        for (uint256 i = 0; i < n; ) {
            s += i;
            unchecked { ++i; }
        }
    }
    function incFar(uint256 a, uint256 n) external pure returns (uint256 c) {
        for (uint256 i = a; i < n; ) {
            c++;
            if (c > 20) break;
            unchecked { i += 1 << 255; }
        }
    }
    function dec(uint256 n) external pure returns (uint256 s) {
        for (uint256 i = n; i != 0; ) {
            s += i;
            unchecked { --i; }
        }
    }
    function around(uint256 a) external pure returns (uint256 c) {
        uint256 i = a;
        while (i != 5) {
            unchecked { i += 3; }
            c++;
            if (c > 20) break;
        }
    }
    function allUnchecked(uint256 n) external pure returns (uint256 s) {
        unchecked {
            for (uint256 i = 0; i < n; i++) { s += i * i; }
        }
    }
    function narrow(uint8 n) external pure returns (uint256 c) {
        for (uint8 i = 0; i < n; ) {
            c += 2;
            unchecked { ++i; }
        }
    }
    function narrowAround(uint8 a, uint8 n) external pure returns (uint256 c) {
        for (uint8 i = a; i != n; ) {
            c++;
            if (c > 300) break;
            unchecked { i += 7; }
        }
    }
}
"""

# `if (items[i] > 5)` whose branches do the same thing: the test decides
# nothing, but the access checks i against items.length (Panic 0x32), and
# the arith pass removes the explicit guard before it, leaving the check to
# the access: neither the renderer (a moot `if`) nor the loops pass (an
# empty `if` at the end of an iteration) may drop it
SAME_BRANCHES = """
contract SameBranches {
    uint256[] public items;
    uint256 public total;

    function skipBig(uint256 n) external view {
        for (uint256 i = 0; i < n; i++) { if (items[i] > 5) continue; }
    }
    function countAndSkip(uint256 n) external {
        for (uint256 i = 0; i < n; i++) { total += 1; if (items[i] > 5) continue; }
    }
    function bothSteps(uint256 n) external view returns (uint256 s) {
        uint256 i = 0;
        while (i < n) { if (items[i] > 5) { i++; } else { i++; } }
        s = i;
    }
    function emptyBranches(uint256 n) external returns (uint256 s) {
        for (uint256 i = 0; i < n; i++) { s += i; if (items[i] > 5) { } else { } }
        total = s;
    }
}
"""

PROBES = {"Forms": FORMS, "Effects": EFFECTS, "Unchecked": UNCHECKED, "SameBranches": SAME_BRANCHES}
MODERN = [Build("0.8.19"), Build("0.8.19", optimize=False), Build("0.8.19", via_ir=True), Build("0.8.31", via_ir=True),
          Build("0.8.31")]
LEGACY = [Build("0.7.6"), Build("0.7.6", optimize=False), Build("0.5.17")]
ITEMS = [5, 7, 11, 2, 7]
ITEMS_AT = int.from_bytes(keccak((0).to_bytes(32, "big")), "big")
STORAGE = {"Effects": dict([(0, len(ITEMS)), (1, 3)] + [(ITEMS_AT + k, v) for k, v in enumerate(ITEMS)])}
STORAGE["SameBranches"] = STORAGE["Effects"]
_POOL = {"uint256": [0, 1, 2, 3, 7, 20, 41], "uint8": [0, 1, 2, 9, 201, 255], "uint64": [0, 3, (1 << 64) - 2, 1 << 62],
         "int256": [0, 1, -1, 5, -7, 100], "address": [callprobe.ECHO, callprobe.EOA, callprobe.IDENTITY],
         "uint256[]": [[], [5], [3, 1, 4, 1, 5], [W - 1, 1], [W - 1, 0]]}


def small_calls(abi):
    """Calls with few iterations: the crafted words are 0, 1 and the bounds
    of the types, where a loop does not run or runs out of gas."""
    out = []
    for item in abi:
        if item.get("type") != "function" or not item["inputs"]:
            continue
        types = [i["type"] for i in item["inputs"]]
        sel = selector(f"{item['name']}({','.join(types)})")
        pools = [_POOL[t] for t in types]
        indices = [range(len(p)) for p in pools]
        rows = set(itertools.islice(itertools.product(*indices), 0, None, max(1, len(pools) * 3 - 2)))
        rows |= {tuple((k + 2 * j) % len(p) for j, p in enumerate(pools)) for k in range(7)}
        out += [(sel + abi_encode(types, [p[i] for p, i in zip(pools, row)]), 0) for row in sorted(rows)]
    return out


def check(monkeypatch, name, build, off=(), answers=("true", "revert-empty")):
    art = compile_probe(PROBES[name], build, name)
    patch_signatures(monkeypatch, art.abi)
    res = generate_probe(art.runtime, off=off)
    compile_or_fail(res.solidity, res.target_solc)
    calls, skipped = probe_calls(res)
    assert not skipped, skipped
    calls += small_calls(art.abi)
    mism = callprobe.differential(art.runtime, res.solidity, res.target_solc, calls,
                                  answers if name == "Effects" else ("true",), STORAGE.get(name))
    assert not mism, (name, build.label, len(mism), mism[:2])
    return res


def counted_for(text: str, bound: str) -> Optional[str]:
    """The counter of a `for (uint256 x = 0; x < bound; x++) {` header in
    `text` (whatever its name: the naming pass may rename it), or None."""
    m = re.search(rf"for \(uint256 (\w+) = 0; \1 < {re.escape(bound)}; \1\+\+\) \{{", text)
    return m.group(1) if m else None


@pytest.mark.parametrize("name", ["Forms", "Effects", "Unchecked"])
def test_probe_same_behaviour(monkeypatch, name):
    res = check(monkeypatch, name, Build("0.8.19"))
    if "loops" not in pipeline.PASS_ORDER:
        return
    text = res.solidity
    assert "parallel assignment" not in text
    assert name == "Effects" or "continue;" not in text
    if name == "Forms":
        body = function_text(text, "sum")
        counter = counted_for(body, "n")
        acc = re.search(rf"(\w+) \+= {counter};", body).group(1)
        assert f"uint256 {acc} = 0;" in body and f"uint256 {acc};" not in body
        assert "_next = " in function_text(text, "fib") and function_text(text, "fib").count("_next") == 2
        assert counted_for(function_text(text, "nested"), "m")
        assert re.search(r"\w+--\) \{", function_text(text, "down"))
        facts = [f["loops"] for f in res.functions.values() if f.get("loops") and f["loops"].get("loops")]
        assert sum(f["loops"] for f in facts) == 22 and sum(f.get("for", 0) for f in facts) >= 19
    if name == "Effects":
        assert counted_for(function_text(text, "sumStorage"), "items.length")
        assert "_panic(50)" not in function_text(text, "sumStorage")  # the bounds check the loop condition implies
        assert "emit" in function_text(text, "writes") and counted_for(function_text(text, "writes"), "n")
    if name == "Unchecked":
        # the unchecked increment under `i < n` is the checked one
        assert counted_for(function_text(text, "inc"), "n")
        assert re.search(r"\w+--\) \{", function_text(text, "dec"))
        # i += 2**255 and `i != 5` prove nothing: the step wraps where it stands
        for fn in ("incFar", "around"):
            assert "unchecked {" in function_text(text, fn)


def test_pass_can_be_switched_off_and_runs_alone(monkeypatch):
    art = compile_probe(FORMS, Build("0.8.19"), "Forms")
    patch_signatures(monkeypatch, art.abi)
    off = generate_probe(art.runtime, off=["loops"])
    assert "for (" not in off.solidity and "while (v0 < n) {" in function_text(off.solidity, "sum")
    assert "uint256 v0;" in function_text(off.solidity, "sum")
    assert all("loops" not in f["passes"] for f in off.functions.values())
    on = generate_probe(art.runtime)
    assert "loops" in on.functions["0x" + selector("sum(uint256)").hex()]["passes"]
    alone = generate_probe(art.runtime, off=[p for p in pipeline.PASS_ORDER if p != "loops"])
    assert "for (uint256 v0 = 0; " in alone.solidity
    calls = probe_calls(alone)[0] + small_calls(art.abi)
    for res in (off, alone):
        assert callprobe.differential(art.runtime, res.solidity, res.target_solc, calls) == []


def test_differential_sees_a_wrong_loop(monkeypatch):
    """The harness is sensitive to what the pass may get wrong: an update
    written in the wrong order, a step run before the body."""
    art = compile_probe(FORMS, Build("0.8.19"), "Forms")
    patch_signatures(monkeypatch, art.abi)
    res = generate_probe(art.runtime)
    calls = probe_calls(res)[0] + small_calls(art.abi)
    fib = function_text(res.solidity, "fib")
    lines = fib.split("\n")
    k = next(i for i, line in enumerate(lines) if "_next = " in line)
    swapped = "\n".join(lines[:k] + [lines[k + 1], lines[k]] + lines[k + 2:])
    assert swapped != fib
    assert callprobe.differential(art.runtime, res.solidity.replace(fib, swapped), res.target_solc, calls)
    text = function_text(res.solidity, "sum")
    c = counted_for(text, "n")
    acc = re.search(rf"(\w+) \+= {c};", text).group(1)
    wrong = text.replace(f"{c} < n; {c}++", f"{c} < n; ").replace(f"{acc} += {c};", f"{c}++; {acc} += {c};")
    assert wrong != text
    assert callprobe.differential(art.runtime, res.solidity.replace(text, wrong), res.target_solc, calls)


@pytest.mark.slow
@pytest.mark.parametrize("build", MODERN[1:] + LEGACY, ids=lambda b: b.label)
@pytest.mark.parametrize("name", ["Forms", "Effects"])
def test_probe_same_behaviour_on_other_builds(monkeypatch, name, build):
    check(monkeypatch, name, build)


@pytest.mark.parametrize("build", [Build("0.8.19"), Build("0.8.19", via_ir=True)], ids=lambda b: b.label)
def test_same_branches_keep_the_bounds_check(monkeypatch, build):
    # 0.8.19: bothSteps returned n where the original reverted with
    # Panic(0x32); via-IR: skipBig and countAndSkip too
    res = check(monkeypatch, "SameBranches", build)
    for fn in ("skipBig", "countAndSkip", "bothSteps"):
        body = function_text(res.solidity, fn)
        assert "items[" in body or "_panic(50)" in body, fn  # the access, or its explicit guard


def test_a_short_circuit_keeps_the_bounds_check():
    # `and` / `or` of two booleans whose right operand reads an array element: the AND opcode
    # evaluated it, and its bounds check (Panic 0x32) may be the only one left once the arith
    # pass dropped the original's guard: no `&&` / `||` may skip it
    i, n = ir.CalldataWord(ir.Const(4)), ir.CalldataWord(ir.Const(36))
    element = ir.Op("gt", (ir.StateRef("items", (i,), "uint256"), ir.Const(5)))
    keyed = ir.Op("gt", (ir.StateRef("balances", (ir.Cast("address", i),), "uint256"), ir.Const(5)))
    units = []
    for k, (op, right) in enumerate((("and", element), ("or", element), ("and", keyed))):
        sel = 0x51000000 + k
        cond = ir.Op(op, (ir.Op("gt", (n, ir.Const(3))), right))
        body = (ir.If(cond, (ir.Return(ir.WordBytes(ir.ONE)),), (ir.Return(ir.WordBytes(ir.Const(2))),)),)
        key = f"0x{sel:08x}"
        units.append(Unit(key, ir.Function(key, body), EntrySpec(key=key, kind="function", selector=sel)))
    source, _ = assemble(ContractInput(units=units, target="0.8.19", original="test"))
    texts = [function_text(source, f"_fn_{0x51000000 + k:08x}") or source for k in range(3)]
    assert not re.search(r"&&[^;{]*items\[", source) and not re.search(r"\|\|[^;{]*items\[", source), source
    assert "items[" in texts[0] and "items[" in texts[1]
    assert "&&" in source  # a mapping read never fails: the short-circuit stays where it is safe


@pytest.mark.slow
@pytest.mark.parametrize("build", MODERN[2:] + LEGACY[:2], ids=lambda b: b.label)
def test_same_branches_keep_the_bounds_check_on_other_builds(monkeypatch, build):
    check(monkeypatch, "SameBranches", build)


@pytest.mark.slow
@pytest.mark.parametrize("build", MODERN[1:], ids=lambda b: b.label)
def test_unchecked_steps_on_other_builds(monkeypatch, build):
    res = check(monkeypatch, "Unchecked", build)
    if build.label == "0.8.31-opt-ir":
        # the increment solc >= 0.8.22 leaves unchecked in a `for` header
        assert counted_for(function_text(res.solidity, "inc"), "n")


@pytest.mark.slow
@pytest.mark.parametrize("build", [Build("0.8.19"), Build("0.8.31", via_ir=True), Build("0.7.6")], ids=lambda b: b.label)
@pytest.mark.parametrize("name", ["Forms", "Effects"])
def test_probe_with_the_pass_alone_and_switched_off(monkeypatch, name, build):
    check(monkeypatch, name, build, off=["loops"])
    check(monkeypatch, name, build, off=[p for p in pipeline.PASS_ORDER if p != "loops"])


@pytest.mark.slow
def test_callee_answers_in_a_loop(monkeypatch):
    """A loop that calls out: every answer of the callee (the calls made
    are recorded, so their number and order are compared)."""
    check(monkeypatch, "Effects", Build("0.8.19"), answers=tuple(callprobe.ANSWERS))

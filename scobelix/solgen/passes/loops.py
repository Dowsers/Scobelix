"""
solgen v2 pass `loops`: the loops the decompiler recovered, written as a
developer writes them, and locals declared where they are first set.

The lifted form of a loop is `While(cond, body, init)`: `init` and the
updates of every `Continue` are PARALLEL assignments of the loop variables
(each value reads the variables as they were before the statement), and
every path of the body ends in a `Continue` or leaves the function.  The
code after the loop is duplicated on the paths that leave it from inside.
Each loop is rewritten, the inner ones first, by steps that keep its
behaviour exactly; a step whose condition does not hold is skipped.

  break     a path of the body that ends with the very statements that
            follow the loop, when those never fall through, runs them from
            the same state as `break` does: it becomes `...; break;` (only
            when that saves text, or when the statements end with the
            `continue` of an outer loop, which has no other translation).
  guards    an `if` at the head of the body that tests the loop condition
            again (or its negation: the bounds check of `a[i]` under
            `i < a.length`) takes the known branch: nothing happens between
            the two evaluations, and the condition reads nothing that
            changes by itself (gas, msize).
  updates   parallel assignments become sequential ones.  A value is
            evaluated before the assignment of every variable it reads, so
            an order without temporary exists when the "is read by" relation
            has no cycle; otherwise the smallest set of variables is found
            whose new values, computed first into temporaries
            (`x_next`) and assigned last, break the cycles (a swap: one).
            An assignment of a variable to itself is dropped.  The values
            are then evaluated in another order than the IR's: two of them
            may be swapped only when at most one can fail, or when both can
            only fail with the same Panic (overflow, or division by zero).
            When no order qualifies, every value goes through a temporary,
            in the IR's order.
  for       an induction variable is a loop variable set by `init`, read by
            the condition, and updated by the same expression of itself on
            every `Continue` (an expression of nothing else the loop
            changes).  Its update becomes the step of `for (init; cond;
            step)`: evaluated last on every path that continues, which is
            where a `for` runs it.  Its initial value goes to the header when
            it reads no other loop variable.  The trailing `continue` of the
            body is then implied; the branches of a trailing `if` are
            arranged so that the one that leaves comes first.
            A step with wrapping arithmetic (an `unchecked` increment, or
            the increment solc >= 0.8.22 leaves unchecked in a `for` header)
            in a function that has checked operations is written as the
            checked operation when the loop condition proves it cannot
            overflow (`i < bound` for `i + 1`, `i != 0` / `i > k` for
            `i - 1`: the two are then the same function); when it does not,
            the step stays in the body (the renderer gives it its
            `unchecked` block) and the loop a `while`.
            A loop without induction variable becomes a `For` without
            header: `while (cond) { body }` whose body may fall through.
  labels    a loop the engine could not structure reaches the IR as
            `While(1, body)` (flag label_lowered): it gets the same
            treatment and stays `while (true)`; such loops are counted.

Locals: once the loops are rewritten, the assignments that can declare
their local are marked (`Assign.declare`, see scobelix/solgen/scopes.py):
`uint256 sum = 0;`, `for (uint256 i = 0; ...)`.  Names do not change; the
temporaries are new locals named after their variable (`v1_next`).

Calls: a statement is never moved across another statement, only the
updates of one `Continue` among themselves (they hold no call), so a call
stays next to the statements that read its values.

Facts: ctx.facts["loops"]["functions"][key] = {"loops", "for" (written
with a header), "while" (the others; "while:<reason>" says why a loop the
pass rewrote has no header), "labels", "temporaries" (temporaries
introduced), "with_temporaries" (loops that needed some), "breaks",
"guards", "declared" (locals declared where set), "hoisted" (the others)},
zero counts left out.
"""

from __future__ import annotations

import collections
import dataclasses
import itertools
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from scobelix.solgen import ir, scopes
from scobelix.solgen.passes.arith import OVERFLOW, ZERO_DIVISION, _deps, _failures
from scobelix.solgen.render import _is_checked, _is_wrapping, _terminates, reserved_name
from scobelix.solgen.types import max_bits

LEVELS = ("full",)

__all__ = ["LEVELS", "run", "sequence"]

_SEARCH = 10  # parallel assignments of more variables are not searched for a minimal set of temporaries
_LOOPS = (ir.While, ir.For)


def _names(n) -> FrozenSet[str]:
    nodes = n if isinstance(n, tuple) else (n,)
    return frozenset(x.name for x in ir.walk_all(nodes) if isinstance(x, ir.Local))


def _swappable(a: Set[object], b: Set[object]) -> bool:
    """Two evaluations with the failures `a` and `b` may run in either
    order: at most one can fail, or both only with one same Panic."""
    return not a or not b or (len(a | b) == 1 and not (a | b) - {OVERFLOW, ZERO_DIVISION})


def _plain(updates: Sequence[ir.Stmt]) -> bool:
    """Assignments of distinct locals, none of them compound."""
    names = [a.target.name for a in updates
             if isinstance(a, ir.Assign) and isinstance(a.target, ir.Local) and a.op is None]
    return len(names) == len(updates) == len(set(names))


def sequence(updates: Sequence[ir.Assign], taken: Set[str], last: Optional[str] = None) \
        -> Optional[Tuple[List[ir.Assign], int]]:
    """The parallel assignments `updates` (plain assignments of distinct
    locals) as sequential ones, and the number of temporaries they needed
    (new locals, their names added to `taken`).  With `last` (a target), that
    assignment comes last and nothing else of the result reads or sets its
    target after it is set; None when no such order exists."""
    ups = [a for a in updates if a.value != a.target]  # x = x: nothing
    n = len(ups)
    target = [a.target.name for a in ups]
    reads = [_names(a.value) for a in ups]
    fails = [_failures(a.value) for a in ups]
    fixed = target.index(last) if last in target else None
    if last is not None and fixed is None:
        return None
    if fixed is not None and any(t in reads[fixed] for k, t in enumerate(target) if k != fixed):
        return None  # evaluated last, it would read the new values

    def order(temps: Tuple[int, ...]) -> Optional[List[int]]:
        """An evaluation order: the temporaries first, then the others,
        each before the assignment of what it reads, the IR's order kept
        where nothing forces another."""
        rest = [k for k in range(n) if k not in temps]
        out: List[int] = []
        while rest:
            # k is ready when no other pending value reads its target
            ready = [k for k in rest if not any(target[k] in reads[j] for j in rest if j != k)]
            if fixed is not None and len(rest) > 1:
                ready = [k for k in ready if k != fixed]
            if not ready:
                return None
            out.append(ready[0])
            rest.remove(ready[0])
        evaluated = list(temps) + out
        position = {k: p for p, k in enumerate(evaluated)}
        for a in range(n):
            for b in range(a + 1, n):
                if position[a] > position[b] and not _swappable(fails[a], fails[b]):
                    return None
        return out

    sizes = range(0, n) if n <= _SEARCH else range(0, 1)
    for size in sizes:
        for temps in itertools.combinations(range(n), size):
            if fixed in temps:
                continue
            got = order(temps)
            if got is None:
                continue
            names = {k: _fresh(target[k] + "_next", taken) for k in temps}
            out = [ir.Assign(ir.Local(names[k]), ups[k].value) for k in temps]
            out += [ups[k] for k in got]
            # the temporaries are assigned before a `last` assignment
            tail = [ir.Assign(ups[k].target, ir.Local(names[k])) for k in temps]
            if fixed is not None:
                out = out[:-1] + tail + out[-1:]
            else:
                out += tail
            return out, size
    if fixed is not None:
        return None
    # every value into a temporary, in the IR's order
    names = {k: _fresh(target[k] + "_next", taken) for k in range(n)}
    out = [ir.Assign(ir.Local(names[k]), ups[k].value) for k in range(n)]
    return out + [ir.Assign(ups[k].target, ir.Local(names[k])) for k in range(n)], n


def _fresh(base: str, taken: Set[str]) -> str:
    name, k = base, 1
    while name in taken or reserved_name(name, parameter=True):
        k += 1
        name = f"{base}{k}"
    taken.add(name)
    return name


def _not(c: ir.Expr) -> ir.Expr:
    """A condition that holds exactly when `c` does not."""
    if isinstance(c, ir.Op) and c.op == "iszero":
        return c.args[0]
    if isinstance(c, ir.Not):
        return c.value
    return ir.Op("iszero", (c,))


def _simple_end(rest: Sequence[ir.Stmt]) -> bool:
    """One statement that ends the call and is as short as `break`."""
    return len(rest) == 1 and isinstance(rest[0], ir.TERMINATORS + (ir.Require,))


def _nested(block: Sequence[ir.Stmt]) -> bool:
    return any(isinstance(s, (ir.If,) + _LOOPS) for s in block)


class _Loops:
    def __init__(self, fn: ir.Function):
        self.taken: Set[str] = set()
        for n in ir.walk_all(fn.body):
            if isinstance(n, ir.Local):
                self.taken.add(n.name)
            elif isinstance(n, ir.Precompile) and n.output:
                self.taken.add(n.output)
        # the function is written outside `unchecked` (see the renderer)
        self.checked = any(_is_checked(n) for n in ir.walk_all(fn.body))
        self.facts = collections.Counter()

    # ---- traversal
    def block(self, stmts: Sequence[ir.Stmt]) -> Tuple[ir.Stmt, ...]:
        out: List[ir.Stmt] = []
        for k, s in enumerate(stmts):
            if isinstance(s, ir.If):
                out.append(ir.If(s.cond, self.block(s.then), self.block(s.orelse)))
            elif isinstance(s, ir.While):
                out.extend(self.loop(s, tuple(stmts[k + 1:])))
            else:
                out.append(s)
        return tuple(out)

    # ---- one loop
    def loop(self, w: ir.While, rest: Tuple[ir.Stmt, ...]) -> List[ir.Stmt]:
        self.facts["loops"] += 1
        if w.cond == ir.ONE:
            self.facts["labels"] += 1
        lid = w.loop_id
        body = w.body
        if rest and _terminates(rest) and (not _simple_end(rest) or ir.contains(rest, ir.Continue)):
            body = self.breaks(body, rest, lid)
        body = self.block(body)
        if not _plain(w.init) or not self.regular(body, lid):
            self.facts["while"] += 1
            return [ir.While(w.cond, body, w.init, lid)]  # the lifted form
        body = self.implied(w.cond, body)
        step = self.induction(w, body, self.assigned(body, lid)) if w.cond != ir.ONE else None
        temps = self.facts["temporaries"]
        new = self.continues(body, lid, step[0] if step else None)
        if new is None:  # the step cannot be the last thing of an iteration
            self.facts["temporaries"] = temps
            self.facts["while:step_order"] += 1
            step = None
            new = self.continues(body, lid, None)
        body = self.tail(new, lid)
        init_stmt: Tuple[ir.Stmt, ...] = ()
        before = None
        if step is not None:
            before = sequence(w.init, self.taken, last=step[0])
            if before is not None and not (self.checked and any(_is_wrapping(n) for n in ir.walk(before[0][-1].value))):
                init_stmt = (before[0][-1],)
                before = before[0][:-1], before[1]
            else:
                before = None
        if before is None:
            before = sequence(w.init, self.taken)
        self.facts["temporaries"] += before[1]
        if self.facts["temporaries"] > temps:
            self.facts["with_temporaries"] += 1
        self.facts["for" if step is not None else "while"] += 1
        loop = ir.For(init_stmt, w.cond, (step[1],) if step else (), body, lid)
        return list(before[0]) + [loop]

    def regular(self, body: Sequence[ir.Stmt], lid: str) -> bool:
        """Every `Continue` of the loop has plain updates and stands outside
        the loops nested in the body."""
        for s in body:
            if isinstance(s, ir.Continue) and s.loop_id == lid and not _plain(s.updates):
                return False
            if isinstance(s, ir.If) and not (self.regular(s.then, lid) and self.regular(s.orelse, lid)):
                return False
            if isinstance(s, _LOOPS) and any(isinstance(n, ir.Continue) and n.loop_id == lid for n in ir.walk(s)):
                return False
        return True

    def assigned(self, body: Sequence[ir.Stmt], lid: str) -> Set[str]:
        """The locals the statements of the loop body set (the updates of the
        loop's own `Continue`s are not statements of the body)."""
        seen: collections.Counter = collections.Counter()
        out: Set[str] = set()
        for n in ir.walk_all(body):
            if isinstance(n, ir.Assign) and isinstance(n.target, ir.Local):
                seen[n.target.name] += 1
            elif isinstance(n, ir.Precompile) and n.output:
                out.add(n.output)
        own = collections.Counter(a.target.name for c in self.conts(body, lid) for a in c.updates)
        return out | {name for name, k in seen.items() if k > own[name]}

    # ---- break
    def breaks(self, block: Sequence[ir.Stmt], rest: Tuple[ir.Stmt, ...], lid: str) -> Tuple[ir.Stmt, ...]:
        """`block` (of the loop body, outside nested loops) with every path
        that ends with `rest` ending in a Break instead."""
        n = len(rest)
        if len(block) >= n and tuple(block[len(block) - n:]) == rest:
            self.facts["breaks"] += 1
            return tuple(block[:len(block) - n]) + (ir.Break(lid),)
        out = []
        for s in block:
            if isinstance(s, ir.If):
                s = ir.If(s.cond, self.breaks(s.then, rest, lid), self.breaks(s.orelse, rest, lid))
            out.append(s)
        return tuple(out)

    # ---- guards the loop condition implies
    def implied(self, cond: ir.Expr, body: Tuple[ir.Stmt, ...]) -> Tuple[ir.Stmt, ...]:
        if _deps(cond) is None:
            return body
        while body:
            s = body[0]
            if isinstance(s, ir.If) and s.cond == cond:
                body = s.then + body[1:]
            elif isinstance(s, ir.If) and (s.cond == ir.Op("iszero", (cond,)) or cond == ir.Op("iszero", (s.cond,))):
                body = s.orelse + body[1:]
            elif isinstance(s, (ir.Require, ir.Assert)) and s.cond == cond:
                body = body[1:]
            else:
                break
            self.facts["guards"] += 1
        return body

    # ---- induction variable
    def induction(self, w: ir.While, body: Sequence[ir.Stmt], inside: Set[str]) -> Optional[Tuple[str, ir.Assign]]:
        """(name, step assignment) of the loop's induction variable."""
        conts = self.conts(body, w.loop_id)
        in_cond = _names(w.cond)
        updated = {a.target.name for c in conts for a in c.updates}
        why = "no_continue" if not conts else "no_counter_in_condition"
        for a in w.init if conts else ():
            name = a.target.name
            if name not in in_cond:
                continue
            values = set()
            for c in conts:
                values.add(next((u.value for u in c.updates if u.target.name == name), None))
            value = next(iter(values))
            if name in inside:
                why = "set_in_body"
            elif len(values) != 1:
                why = "steps_differ"
            elif value is None or value == a.target:
                why = "constant_in_loop"
            elif name not in _names(value):
                why = "step_from_another_local"  # v = sum, the sum bound earlier in the body
            elif (_names(value) - {name}) & (inside | updated):
                why = "step_reads_the_loop"
            elif self.header_step(w.cond, name, value) is None:
                why = "wrapping_step"
            else:
                return name, ir.Assign(a.target, self.header_step(w.cond, name, value))
        self.facts["while:" + why] += 1
        return None

    def conts(self, body: Sequence[ir.Stmt], lid: str) -> List[ir.Continue]:
        out: List[ir.Continue] = []
        for s in body:
            if isinstance(s, ir.Continue) and s.loop_id == lid:
                out.append(s)
            elif isinstance(s, ir.If):
                out += self.conts(s.then, lid) + self.conts(s.orelse, lid)
        return out

    def header_step(self, cond: ir.Expr, name: str, value: ir.Expr) -> Optional[ir.Expr]:
        """The step value as a `for` header can hold it: itself, or, for a
        wrapping step in a function written outside `unchecked`, the checked
        operation it equals under the loop condition (None: neither)."""
        if not self.checked or not any(_is_wrapping(n) for n in ir.walk(value)):
            return value
        i = ir.Local(name)
        if isinstance(value, ir.Mask) and (value.offset, value.shl) == (0, 0) and value.size in range(8, 256, 8) \
                and value.value in (ir.Op("add", (i, ir.ONE)), ir.Op("add", (ir.ONE, i))):
            # a uintN counter: uintN(i) < bound <= 2**N - 1, so uintN(i) + 1 does not overflow in uintN
            narrow = ir.Mask(value.size, 0, 0, i)
            if isinstance(cond, ir.Op) and cond.op == "lt" and cond.args[0] == narrow \
                    and max_bits(cond.args[1]) <= value.size:
                return ir.Typed("add", (narrow, ir.ONE), f"uint{value.size}", True)
            return None
        if isinstance(value, ir.Op) and value.op == "add" and len(value.args) == 2 and i in value.args:
            other = value.args[1] if value.args[0] == i else value.args[0]
            # i < bound <= 2**256 - 1: i + 1 does not overflow
            if other == ir.ONE and isinstance(cond, ir.Op) and cond.op == "lt" and cond.args[0] == i:
                return ir.Typed("add", (i, ir.ONE), "uint256", True)
            if other == ir.Const(ir.WORD_MAX) and self.positive(cond, i):
                return ir.Typed("sub", (i, ir.ONE), "uint256", True)
        if isinstance(value, ir.Op) and value.op == "sub" and value.args == (i, ir.ONE) and self.positive(cond, i):
            return ir.Typed("sub", (i, ir.ONE), "uint256", True)
        return None

    @staticmethod
    def positive(cond: ir.Expr, i: ir.Local) -> bool:
        """The condition holds only when the word `i` is not zero."""
        if cond == i or cond == ir.Bool(i) or cond == ir.Op("iszero", (ir.Op("iszero", (i,)),)):
            return True
        if isinstance(cond, ir.Op) and cond.op == "gt" and cond.args[0] == i:
            return True  # i > x
        return isinstance(cond, ir.Op) and cond.op == "lt" and cond.args[1] == i  # x < i

    # ---- the updates of the Continues
    def continues(self, block: Sequence[ir.Stmt], lid: str, step: Optional[str]) -> Optional[Tuple[ir.Stmt, ...]]:
        """The block with the updates of every `Continue` of the loop as
        sequential assignments before it (without the step: the `for` runs
        it); None when a step cannot be taken out of one of them."""
        out: List[ir.Stmt] = []
        for s in block:
            if isinstance(s, ir.Continue) and s.loop_id == lid:
                got = sequence(s.updates, self.taken, last=step)
                if got is None:
                    return None
                assigns, temps = got
                self.facts["temporaries"] += temps
                out += assigns[:-1] if step is not None else assigns
                out.append(ir.Continue(lid))
            elif isinstance(s, ir.If):
                then, orelse = self.continues(s.then, lid, step), self.continues(s.orelse, lid, step)
                if then is None or orelse is None:
                    return None
                out.append(ir.If(s.cond, then, orelse))
            else:
                out.append(s)
        return tuple(out)

    # ---- the end of an iteration
    def tail(self, block: Tuple[ir.Stmt, ...], lid: str) -> Tuple[ir.Stmt, ...]:
        """`block` ends an iteration of loop `lid`: falling out of it goes on
        with the next one, so its trailing `continue` is implied."""
        if not block:
            return block
        last = block[-1]
        if isinstance(last, ir.Continue) and last.loop_id == lid and not last.updates:
            return block[:-1]
        if not isinstance(last, ir.If):
            return block
        a, b = self.tail(last.then, lid), self.tail(last.orelse, lid)
        if _terminates(a):
            new: Optional[ir.Stmt] = ir.If(last.cond, a, b)
        elif _terminates(b):
            new = ir.If(_not(last.cond), b, a)  # the branch that leaves first
        elif not a and not b:
            # the test stays when evaluating it can fail (an indexed state
            # read: its bounds check may be the only one left)
            keep = _failures(last.cond) or ir.reads_indexed_state(last.cond)
            new = ir.If(last.cond, (), ()) if keep else None
        elif not a:
            new = ir.If(_not(last.cond), b)
        elif not b:
            new = ir.If(last.cond, a)
        elif _nested(b) or len(b) > 3:
            new = ir.If(last.cond, last.then, b)  # `...; continue;` keeps the rest of the body flat
        else:
            new = ir.If(last.cond, a, b)
        return block[:-1] + ((new,) if new is not None else ())


def _mark(body: Tuple[ir.Stmt, ...], facts) -> Tuple[ir.Stmt, ...]:
    """The body with the declaration sites of its locals marked."""
    found = scopes.sites(body)
    ids = {id(a) for where in found.values() for a in where}
    names = {n.name for n in ir.walk_all(body) if isinstance(n, ir.Local)}
    facts["declared"] = len(found)
    facts["hoisted"] = len(names) - len(found)
    if not ids:
        return body

    def fn(n):
        if isinstance(n, ir.Assign) and id(n) in ids and not n.declare:
            return dataclasses.replace(n, declare=True)
        return n

    return ir.transform(body, fn)


def run(fn: ir.Function, ctx) -> ir.Function:
    p = _Loops(fn)
    body = p.block(fn.body) if ir.contains(fn.body, ir.While) else fn.body
    body = _mark(body, p.facts)
    counts = {k: v for k, v in p.facts.items() if v}
    if counts:
        facts: Dict[str, object] = ctx.facts.setdefault("loops", {"functions": {}})
        facts["functions"][fn.key] = counts
    return fn if body == fn.body else fn.with_body(body)

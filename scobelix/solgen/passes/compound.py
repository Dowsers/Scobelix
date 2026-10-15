"""
compound pass: the last tidy-up of a function, on whatever the passes before
it produced.  Every rewrite keeps the order of the observable effects and of
the possible failures.

  run   * `x = x op y` -> `x op= y` (Assign.op) for locals, state variables,
          mapping / array elements and struct members, when the lvalue's
          path cannot fail (it is then evaluated once instead of twice, with
          the same value):
            - a checked or unchecked operation of the target's own integer
              type (`Typed`, from the arith pass): Solidity's `op=` in that
              type (Assign.checked), for + - * / % & | ^; the target may be
              the right operand of + * & | ^ (its read cannot fail, so the
              other operand's failures come first either way; an array
              element whose bounds check replaced a Panic(0x32) guard fails
              only in statements where nothing else fails in another way,
              see arith);
            - an EVM operation on a uint256 target (wrapping + - *, & | ^,
              / and % by a non-zero constant): the EVM-meaning compound
              form, rendered in `unchecked` like the operation;
          a narrowing mask of the stored value is dropped first where the
          assignment narrows anyway (into a uintN / intN variable the low N
          bits are stored either way);
        * `x += 1` / `x -= 1` -> `x++` / `x--`: as statements they are the
          same operation in every integer type and context (checked: Panic
          0x11 exactly when x is the type's maximum / minimum, unchecked:
          both wrap); loop updates are left to the loops pass;
        * a constant on the left of a commutative operation or of a
          comparison goes to the right (`5 + x` -> `x + 5`, `5 < x` -> `x >
          5`): a constant cannot fail, so the order of what can is unchanged;
        * a division or modulo by a non-zero constant becomes Solidity's `/`
          / `%` (a Typed uint256 operation: the opcode's value, it cannot
          fail), so that it reads with the precedence of the operations
          around it;
        * `if (c) { return true; } else { return false; }` (one word, 1 / 0)
          -> `return c;` with c as a 0/1 word;
        * constant tests (pure constant expressions): `require(true)` /
          `assert(true)` dropped, `if (constant)` replaced by the branch it
          takes.

Facts: ctx.facts["compound"]["functions"][key] = {"compound": n (op=),
"increments": n (++ / --), "reordered": n, "bool_returns": n}.
"""

from __future__ import annotations

import collections
from typing import Optional, Sequence, Tuple

from scobelix.solgen import ir
from scobelix.solgen.passes.arith import _failures
from scobelix.solgen.types import SolType, is_boolean, parse_type

LEVELS = ("full",)

_TYPED_OPS = {"add": "+", "sub": "-", "mul": "*", "div": "/", "mod": "%", "and": "&", "or": "|", "xor": "^"}
_EVM_OPS = {"add": "+", "mul": "*", "and": "&", "or": "|", "xor": "^"}
_COMMUTATIVE = frozenset({"add", "mul", "and", "or", "xor"})
_SWAP = {"lt": "gt", "gt": "lt", "slt": "sgt", "sgt": "slt", "eq": "eq"}

__all__ = ["LEVELS", "run"]


def _int_type(target: ir.Expr) -> Optional[SolType]:
    """The integer type of an assignment target (a local is a uint256)."""
    if isinstance(target, ir.Local):
        return SolType("uint", 256)
    if isinstance(target, ir.StateRef):
        try:
            t = parse_type(target.ty)
        except ValueError:
            return None
        return t if t.kind in ("uint", "int") else None
    return None


def _same_target(a: ir.Expr, target: ir.Expr) -> bool:
    """`a` reads exactly the variable `target` writes (same path and type)."""
    return isinstance(a, (ir.Local, ir.StateRef)) and type(a) is type(target) and a == target


def _negated(e: ir.Expr) -> Optional[ir.Expr]:
    """y when e is -y (`mul(-1, y)` or a negative constant)."""
    if isinstance(e, ir.Const) and e.value >> 255:
        return ir.Const(ir.WORD_MOD - e.value)
    if isinstance(e, ir.Op) and e.op == "mul" and len(e.args) == 2:
        for c, y in (e.args, e.args[::-1]):
            if c == ir.Const(ir.WORD_MAX):
                return y
    return None


def _returned_bit(block: Sequence[ir.Stmt]) -> Optional[Tuple[int, bool]]:
    """(0 or 1, as `values`) when block is exactly `return <that one word>`."""
    if len(block) != 1 or not isinstance(block[0], ir.Return):
        return None
    r = block[0]
    if r.values is not None:
        if len(r.values) == 1 and r.values[0] in (ir.ZERO, ir.ONE):
            return r.values[0].value, True
        return None
    d = r.data
    if isinstance(d, ir.WordBytes) and d.width == 32 and d.value in (ir.ZERO, ir.ONE):
        return d.value.value, False
    return None


class _Compound:
    def __init__(self):
        self.facts = collections.Counter()

    def block(self, stmts: Sequence[ir.Stmt]) -> Tuple[ir.Stmt, ...]:
        out = []
        for s in stmts:
            c = ir.evaluate(s.cond) if isinstance(s, (ir.If, ir.Require, ir.Assert)) else None
            if c is not None and isinstance(s, ir.If):
                self.facts["constant_tests"] += 1
                out.extend(self.block(s.then if c else s.orelse))  # a constant test: the branch it takes
                continue
            if c and isinstance(s, (ir.Require, ir.Assert)):
                self.facts["constant_tests"] += 1
                continue  # require(true): nothing
            out.append(self.stmt(s))
        return tuple(out)

    def stmt(self, s: ir.Stmt) -> ir.Stmt:
        if isinstance(s, ir.If):
            got = self.bool_return(s)
            if got is not None:
                return got
            return ir.If(self.expr(s.cond), self.block(s.then), self.block(s.orelse))
        if isinstance(s, ir.While):
            return ir.While(self.expr(s.cond), self.block(s.body), s.init, s.loop_id)
        if isinstance(s, ir.For):
            return ir.For(self.block(s.init), self.expr(s.cond), self.block(s.step), self.block(s.body), s.loop_id)
        if isinstance(s, ir.Assign):
            return self.assign(ir.Assign(s.target, self.expr(s.value), s.op, s.checked, s.declare))
        if isinstance(s, ir.Require):
            return ir.Require(self.expr(s.cond), s.payload)
        if isinstance(s, ir.Assert):
            return ir.Assert(self.expr(s.cond))
        if isinstance(s, ir.Return) and s.values is not None:
            return ir.Return(s.data, tuple(self.expr(v) for v in s.values))
        if isinstance(s, ir.Return) and isinstance(s.data, ir.WordBytes):
            return ir.Return(ir.WordBytes(self.expr(s.data.value), s.data.width), s.values)
        return s

    # ---- x = x op y
    def assign(self, s: ir.Assign) -> ir.Assign:
        t = _int_type(s.target)
        if s.op is not None or t is None or _failures(s.target):
            return s
        value = s.value
        if isinstance(s.target, ir.StateRef) and t.bits < 256 and isinstance(value, ir.Mask) \
                and (value.size, value.offset, value.shl) == (t.bits, 0, 0):
            value = value.value  # the assignment keeps the same low bits
        out = self.typed_compound(s.target, t, value)
        if out is None and t.canonical == "uint256":
            out = self.evm_compound(s.target, value)
        if out is None:
            return ir.Assign(s.target, value) if value is not s.value else s
        self.facts["increments" if out.op in ("++", "--") else "compound"] += 1
        return out

    @staticmethod
    def typed_compound(target: ir.Expr, t: SolType, value: ir.Expr) -> Optional[ir.Assign]:
        if not (isinstance(value, ir.Typed) and value.ty == t.canonical and value.op in _TYPED_OPS
                and len(value.args) == 2):
            return None
        a, b = value.args
        if _same_target(a, target):
            other = b
        elif value.op in _COMMUTATIVE and _same_target(b, target):
            other = a
        else:
            return None
        sym = _TYPED_OPS[value.op]
        if sym in ("+", "-") and other == ir.ONE:
            return ir.Assign(target, ir.ONE, sym * 2, value.checked)
        return ir.Assign(target, other, sym, value.checked)

    @staticmethod
    def evm_compound(target: ir.Expr, value: ir.Expr) -> Optional[ir.Assign]:
        """`target = target op y` with EVM operations, uint256 target."""
        if not isinstance(value, ir.Op):
            return None
        op, args = value.op, value.args
        if op in _EVM_OPS:
            i = next((i for i, x in enumerate(args) if _same_target(x, target)), None)
            if i is None:
                return None
            others = args[:i] + args[i + 1:]
            other = others[0] if len(others) == 1 else ir.Op(op, others)
            if op == "add":
                neg = _negated(other)
                if neg is not None:
                    return ir.Assign(target, ir.ONE, "--") if neg == ir.ONE else ir.Assign(target, neg, "-")
                if other == ir.ONE:
                    return ir.Assign(target, ir.ONE, "++")
            return ir.Assign(target, other, _EVM_OPS[op])
        if op == "sub" and _same_target(args[0], target):
            return ir.Assign(target, ir.ONE, "--") if args[1] == ir.ONE else ir.Assign(target, args[1], "-")
        if op in ("div", "mod") and _same_target(args[0], target) and isinstance(args[1], ir.Const) and args[1].value:
            return ir.Assign(target, args[1], "/" if op == "div" else "%")
        return None

    # ---- operand order, divisions by constants
    def expr(self, e: ir.Expr) -> ir.Expr:
        def fn(n):
            if isinstance(n, ir.Op) and n.op in ("div", "mod") and isinstance(n.args[1], ir.Const) \
                    and n.args[1].value and not isinstance(n.args[0], ir.Const):
                # Solidity's `/` and `%` by a non-zero constant: the opcode's value, no failure
                self.facts["divisions"] += 1
                return ir.Typed(n.op, n.args, "uint256", False)
            if not isinstance(n, (ir.Typed, ir.Op)) or len(n.args) < 2 or not isinstance(n.args[0], ir.Const) \
                    or all(isinstance(a, ir.Const) for a in n.args):
                return n
            if isinstance(n, ir.Typed) and len(n.args) == 2 and (n.op in _COMMUTATIVE or n.op in _SWAP):
                self.facts["reordered"] += 1
                return ir.Typed(_SWAP.get(n.op, n.op), (n.args[1], n.args[0]), n.ty, n.checked)
            if isinstance(n, ir.Op) and n.op in _SWAP:
                self.facts["reordered"] += 1
                return ir.Op(_SWAP[n.op], (n.args[1], n.args[0]))
            if isinstance(n, ir.Op) and n.op in _COMMUTATIVE:
                self.facts["reordered"] += 1
                consts = tuple(a for a in n.args if isinstance(a, ir.Const))
                return ir.Op(n.op, tuple(a for a in n.args if not isinstance(a, ir.Const)) + consts)
            return n
        return ir.transform(e, fn)

    # ---- if (c) return true; else return false;
    def bool_return(self, s: ir.If) -> Optional[ir.Stmt]:
        a, b = _returned_bit(s.then), _returned_bit(s.orelse)
        if a is None or b is None or a[0] == b[0] or a[1] != b[1]:
            return None
        cond = s.cond if a[0] == 1 else ir.Op("iszero", (s.cond,))
        word = self.expr(cond if is_boolean(cond) else ir.Op("iszero", (ir.Op("iszero", (cond,)),)))
        self.facts["bool_returns"] += 1
        return ir.Return(None, (word,)) if a[1] else ir.Return(ir.WordBytes(word, 32))


def run(fn: ir.Function, ctx) -> ir.Function:
    c = _Compound()
    body = c.block(fn.body)
    if body == fn.body:
        return fn
    facts = ctx.facts.setdefault("compound", {"functions": {}})
    facts["functions"][fn.key] = dict(c.facts)
    return fn.with_body(body)

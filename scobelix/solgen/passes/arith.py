"""
arith pass: the checked arithmetic of solc >= 0.8.

  run   in every function of an original that is not known to predate solc
        0.8 (CBOR version), through blocks, branches and loop bodies.  A
        compiler guard

            if (P) { Panic(0x11) }  rest        (or the swapped `if`, or
            Require(!P, Panic(0x11)) followed by rest)

        whose condition P is exactly the check solc emits for one operation
        `x op y` on an integer type T (expected_guards: + - * of uintN /
        intN of every width, ++ / --, unary minus, the int256 product's two
        guards, signed division overflow; legacy and IR code generator,
        optimised or not, as the decompiler simplifies them) is removed, and
        the wrapping operation it guards becomes ONE checked operation
        `Typed(op, (x, y), T, checked=True)`.  A Panic(0x12) guard `if (y ==
        0)` before `x / y` or `x % y` makes the division a `Typed` division
        (Solidity's `/` and `%` panic on a zero divisor even in unchecked
        code; a signed division also needs its overflow guard after it, an
        unchecked signed division keeps its EVM-exact helper).  Conditions:

          * the operands are valid values of T: any word for a 256-bit type;
            for a narrower one a cleaned word, a storage field of that type,
            a constant in range, a parameter the decoder validated, a checked
            result of that type (types.fits);
          * the guarded value is used: the statements after the guard
            evaluate the wrapping operation on the same operands, before
            anything that may change their values (a store, a call, a write
            of a local they read; loops stop the search).  Every such use
            becomes the checked result: the operation itself when it is used
            once, in the first statement after the guard (the engine's
            writes of the scratch space aside: they cannot fail and nothing
            observes them once the call reverts), at a place that statement
            evaluates on every path (not a require's payload, a branch of a
            ternary or an operand after the first of a `&&` / `||`), where
            nothing that fails in another way can be evaluated before it;
            otherwise a local
            assigned at the guard's position, so that the Panic is raised
            there, before anything the original does after the guard;
          * the operands fail in at most one way (no evaluation order can
            change which failure comes first), and they depend on nothing
            that changes by itself (gas, msize).

        A Panic(0x32) guard `if (i >= arr.length)` (or `i >= N` of a
        fixed-size array) right before the storage access `arr[i]` the
        storage pass wrote (scratch-space writes aside), evaluated on every
        path of that statement, where nothing that fails in another way
        comes first, is a duplicate: Solidity's own
        bounds check of the access makes the same test and raises the same
        Panic at the same point.  Such an access may then fail in its
        statement: a guard before it moves its operation into that
        statement only when the operation's operands read the access too
        (the guard's condition read it, so its check had passed).
        A guard that can never fire (its condition is constant false, such
        as `x > x` left by the decompiler's simplifications) is dropped.
        Everything else stays exact: arithmetic without a guard wraps (the
        original had `unchecked`, or is pre-0.8 code), `**` and the checked
        exponentiation loops keep their explicit checks, and the other Panic
        guards (0x01 assert: reverts pass; 0x21, 0x22, 0x31, the other
        0x32, 0x41, 0x51) are only counted.

Facts: ctx.facts["arith"]["functions"][key] = {"guards": {code: n} (guard
sites before the pass), "absorbed": {code: n}, "dead": n, "bound": n (checked
results bound to a local), "kept": {code: n}, "reasons": {why kept: n}},
surfaced as result.functions[key]["arith"].
"""

from __future__ import annotations

import collections
import dataclasses
import itertools
import re
from typing import Callable, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from scobelix.solgen import ir
from scobelix.solgen.storage import Layout, member_name
from scobelix.solgen.types import SolType, fits, is_boolean, parse_type

LEVELS = ("full",)

OVERFLOW, ZERO_DIVISION, OUT_OF_BOUNDS = 0x11, 0x12, 0x32
_M = ir.WORD_MOD
_MAX = ir.WORD_MAX
_MIN256 = 1 << 255
_DIGITS = re.compile(r"\d+")

__all__ = ["LEVELS", "Normaliser", "expected_guards", "prepare", "run"]


# ---------------------------------------------------------------- small builders


def _op(name: str, *args) -> ir.Op:
    return ir.Op(name, tuple(a if isinstance(a, ir.Node) else ir.const(a) for a in args))


def _signed(t: SolType) -> bool:
    return t.kind == "int"


def _bounds(t: SolType) -> Tuple[int, int]:
    """(MIN, MAX) of an integer type, MIN as a word."""
    if _signed(t):
        return (_M - (1 << (t.bits - 1))) % _M, (1 << (t.bits - 1)) - 1
    return 0, (1 << t.bits) - 1


def _cleanup(t: SolType, e: ir.Expr) -> ir.Expr:
    """solc's cleanup of a word of type t (mask / sign extension)."""
    if t.bits == 256:
        return e
    if _signed(t):
        return _op("signextend", t.bits // 8 - 1, e)
    return ir.Mask(t.bits, 0, 0, e)


# ---------------------------------------------------------------- normal form


def _bit_field(f) -> Optional[int]:
    if isinstance(f, int) and not isinstance(f, bool):
        return f
    if isinstance(f, ir.Const):
        return ir.to_signed(f.value)
    return None


class Normaliser:
    """A canonical form of word expressions, equal for equal values under
    the algebra the guards need: add / mul / and / or / xor flattened, their
    constants folded and operands sorted; `sub` as `add(a, -1 * b)`; `gt` /
    `sgt` as `lt` / `slt` with the operands swapped; `x == 0` as `iszero(x)`
    and `iszero(a + b - c + K)` as `a + b == c - K`; `iszero` pushed through
    `and` / `or` of 0/1 words; `x << k` masks as products.  Every rewrite
    keeps the word's value (the expressions are pure)."""

    def __init__(self):
        self._memo: Dict[int, Tuple[ir.Node, ir.Node]] = {}
        self._keys: Dict[int, Tuple[ir.Node, str]] = {}

    def key(self, n: ir.Node) -> str:
        """The sort key of a node: its text, numbers compared as numbers
        (calldata words and parameters in their order)."""
        got = self._keys.get(id(n))
        if got is not None and got[0] is n:
            return got[1]
        k = _DIGITS.sub(lambda m: m.group().zfill(80), repr(n))
        self._keys[id(n)] = (n, k)
        return k

    def __call__(self, e):
        if not isinstance(e, ir.Expr):
            return e
        got = self._memo.get(id(e))
        if got is not None and got[0] is e:
            return got[1]
        out = self._norm(e)
        self._memo[id(e)] = (e, out)
        return out

    def cond(self, e: ir.Expr) -> ir.Expr:
        """The normal form of `e != 0` (a 0/1 word)."""
        n = self(e)
        return n if is_boolean(n) else self.not_(self.not_(n))

    def _norm(self, e: ir.Expr) -> ir.Expr:
        if isinstance(e, ir.Op):
            if e.op == "sub":
                return self.assoc("add", [self(e.args[0]), self.neg(self(e.args[1]))])
            args = [self(a) for a in e.args]
            op = e.op
            if op in ("add", "mul", "and", "or", "xor"):
                return self.assoc(op, args)
            if op == "iszero":
                return self.not_(args[0])
            if op == "eq":
                return self.eq(args[0], args[1])
            if op == "gt":
                return self.cmp("lt", args[1], args[0])
            if op == "sgt":
                return self.cmp("slt", args[1], args[0])
            if op in ("lt", "slt"):
                return self.cmp(op, args[0], args[1])
            if op in ("div", "mod", "sdiv", "smod") and args[0] == ir.ZERO:
                return ir.ZERO  # 0 / x and 0 % x are 0 for every x (0 included)
            if op == "shl" and isinstance(args[0], ir.Const):
                k = args[0].value
                return ir.ZERO if k >= 256 else self.assoc("mul", [ir.Const(1 << k), args[1]])  # x << k
            if op == "signextend":
                b, x = args
                if isinstance(b, ir.Const) and isinstance(x, ir.Op) and x.op == "signextend" \
                        and isinstance(x.args[0], ir.Const) and x.args[0].value <= b.value:
                    return x
            out = ir.Op(op, tuple(args))
            v = ir.evaluate(out) if all(isinstance(a, ir.Const) for a in args) else None
            return ir.Const(v) if v is not None else out
        if isinstance(e, ir.Field):
            off, size = ir.field_bits(e.offset), ir.field_bits(e.size)
            if off == 0 and size is not None and size >= 256:
                return self(e.value)  # every bit
            if off == 0 and size is not None and size > 0:
                return self(ir.Mask(size, 0, 0, e.value))  # (v >> 0) & (2**n - 1): the low n bits
            return ir.Field(self(e.value), e.offset, e.size)
        if isinstance(e, ir.Mask):
            v = self(e.value)
            size, off, shl = _bit_field(e.size), _bit_field(e.offset), _bit_field(e.shl)
            if None not in (size, off, shl):
                if isinstance(v, ir.Const):
                    return ir.Const(ir.mask_value(size, off, shl, v.value))
                if (size, off, shl) == (256, 0, 0):
                    return v
                if off == 0 and 0 < shl < 256 and size in (256, 256 - shl):
                    return self.assoc("mul", [ir.Const(1 << shl), v])  # x << k, as x * 2**k
            return ir.Mask(e.size, e.offset, e.shl, v)
        return e

    def neg(self, b: ir.Expr) -> ir.Expr:
        return self.assoc("mul", [ir.Const(_MAX), b])

    def assoc(self, op: str, args: Sequence[ir.Expr]) -> ir.Expr:
        flat: List[ir.Expr] = []
        for a in args:
            if isinstance(a, ir.Op) and a.op == op:
                flat.extend(a.args)
            else:
                flat.append(a)
        rest = [a for a in flat if not isinstance(a, ir.Const)]
        neutral = {"add": 0, "mul": 1, "and": _MAX, "or": 0, "xor": 0}[op]
        k = neutral
        for a in flat:
            if isinstance(a, ir.Const):
                k = ir.EVM_OPS[op](k, a.value)
        if op in ("mul", "and") and k == 0:
            return ir.ZERO
        if op == "or" and k == _MAX:
            return ir.Const(_MAX)
        if op == "and" and len(rest) == 1 and k != _MAX and (k + 1) & k == 0 and not is_boolean(rest[0]):
            return self(ir.Mask(k.bit_length(), 0, 0, rest[0]))  # x & (2**n - 1): the low n bits
        if op == "mul":
            expanded = self._expand([ir.Const(k)] + rest)
            if expanded is not None:
                return expanded
        if op == "add":
            rest = self._like_terms(rest)
        if op == "and" and k == 1 and rest and all(is_boolean(a) for a in rest):
            k = _MAX  # 1 & b == b for a 0/1 word
        if k != neutral:
            rest.append(ir.Const(k))
        if not rest:
            return ir.Const(neutral)
        if len(rest) == 1:
            return rest[0]
        rest.sort(key=self.key)
        return ir.Op(op, tuple(rest))

    _MAX_TERMS = 16

    def _expand(self, factors: List[ir.Expr]) -> Optional[ir.Expr]:
        """A product with a sum among its factors as the sum of the products
        (mod 2**256), when that has at most _MAX_TERMS terms."""
        if not any(isinstance(f, ir.Op) and f.op == "add" for f in factors):
            return None
        options = [list(f.args) if isinstance(f, ir.Op) and f.op == "add" else [f] for f in factors]
        n = 1
        for o in options:
            n *= len(o)
        if n > self._MAX_TERMS:
            return None
        terms = []
        for combo in itertools.product(*options):
            terms.append(self.assoc("mul", list(combo)))
        return self.assoc("add", terms)

    def _like_terms(self, terms: List[ir.Expr]) -> List[ir.Expr]:
        """The terms of a sum with equal monomials combined (coefficients
        added mod 2**256, the zero ones dropped)."""
        coef: Dict[str, int] = {}
        mono: Dict[str, ir.Expr] = {}
        for t in terms:
            c, m = 1, t
            if isinstance(t, ir.Op) and t.op == "mul" and any(isinstance(a, ir.Const) for a in t.args):
                c = 1
                for a in t.args:
                    if isinstance(a, ir.Const):
                        c = c * a.value % _M
                others = [a for a in t.args if not isinstance(a, ir.Const)]
                m = others[0] if len(others) == 1 else ir.Op("mul", tuple(others))
            key = self.key(m)
            coef[key] = (coef.get(key, 0) + c) % _M
            mono.setdefault(key, m)
        out = []
        for key, c in coef.items():
            if c == 0:
                continue
            m = mono[key]
            out.append(m if c == 1 else ir.Op("mul", tuple(sorted((m.args if isinstance(m, ir.Op) and m.op == "mul"
                                                                    else (m,)) + (ir.Const(c),), key=self.key))))
        return out

    def not_(self, x: ir.Expr) -> ir.Expr:
        """iszero(x), x in normal form."""
        if isinstance(x, ir.Const):
            return ir.Const(int(x.value == 0))
        if isinstance(x, ir.Op):
            if x.op == "iszero" and is_boolean(x.args[0]):
                return x.args[0]
            if x.op in ("or", "and") and all(is_boolean(a) for a in x.args):
                return self.assoc("and" if x.op == "or" else "or", [self.not_(a) for a in x.args])
            if x.op == "add":
                got = self._zero_sum(x)
                if got is not None:
                    return got
        return ir.Op("iszero", (x,))

    def _zero_sum(self, x: ir.Op) -> Optional[ir.Expr]:
        """`x == 0` for a sum with a constant or negated terms, as positive
        terms == negated terms - constant."""
        k, pos, neg = 0, [], []
        for t in x.args:
            if isinstance(t, ir.Const):
                k = t.value
                continue
            n = self.negated(t)
            if n is not None:
                neg.append(n)
            else:
                pos.append(t)
        if not k and not neg:
            return None
        left = self.assoc("add", pos) if pos else ir.ZERO
        right = self.assoc("add", neg + [ir.Const((-k) % _M)])
        return self.eq(left, right)

    def negated(self, t: ir.Expr) -> Optional[ir.Expr]:
        """y when t is -y written with a negative constant factor or as a
        negative constant."""
        if isinstance(t, ir.Const):
            return ir.Const((-t.value) % _M) if t.value >> 255 else None
        if isinstance(t, ir.Op) and t.op == "mul":
            for i, c in enumerate(t.args):
                if isinstance(c, ir.Const) and c.value >> 255:
                    others = list(t.args[:i]) + list(t.args[i + 1:])
                    return self.assoc("mul", others + [ir.Const((-c.value) % _M)])
        return None

    def eq(self, a: ir.Expr, b: ir.Expr) -> ir.Expr:
        if isinstance(a, ir.Const) and isinstance(b, ir.Const):
            return ir.Const(int(a.value == b.value))
        if a == b:
            return ir.ONE
        if b == ir.ZERO or a == ir.ZERO:
            other = a if b == ir.ZERO else b
            if isinstance(other, ir.Op) and other.op == "add":
                got = self._zero_sum(other)
                return got if got is not None else ir.Op("iszero", (other,))
            return self.not_(other)
        return ir.Op("eq", tuple(sorted((a, b), key=self.key)))

    def cmp(self, op: str, a: ir.Expr, b: ir.Expr) -> ir.Expr:
        if isinstance(a, ir.Const) and isinstance(b, ir.Const):
            return ir.Const(ir.EVM_OPS[op](a.value, b.value))
        if a == b:
            return ir.ZERO
        if op == "lt":
            if b == ir.ZERO or a == ir.Const(_MAX):
                return ir.ZERO  # nothing is below 0 or above the maximum
            if b == ir.ONE:
                return self.not_(a)
        return ir.Op(op, (a, b))


# ---------------------------------------------------------------- the compiler's checks


def expected_guards(op: str, t: SolType, x: ir.Expr, y: Optional[ir.Expr]) \
        -> List[Tuple[ir.Expr, ir.Expr, Optional[ir.Expr]]]:
    """The panic conditions solc emits (Panic 0x11) for `x op y` on type t,
    x and y being valid t values, as (condition, x, y): one entry per form
    of the code generators (legacy and IR, optimised or not, after the
    decompiler's simplifications); the x and y of an entry are the operands
    in the order its form names them (the source's, for the 256-bit sum).
    Each condition holds exactly when the operation overflows t.  The
    int256 product needs two guards (see _Arith.mul_special)."""
    lo, hi = _bounds(t)
    n, signed = t.bits, _signed(t)
    out: List[Tuple[ir.Expr, ir.Expr, Optional[ir.Expr]]] = []
    if op == "add":
        for a, b in ((x, y), (y, x)):
            s = _op("add", a, b)
            if not signed and n == 256:
                out.append((_op("gt", a, s), a, b))  # a + b < a
            elif signed and n == 256:
                # overflow if a >= 0 and a + b < b, underflow if a < 0 and a + b >= b
                out.append((_op("or", _op("and", _op("iszero", _op("slt", a, 0)), _op("slt", s, b)),
                                _op("and", _op("slt", a, 0), _op("iszero", _op("slt", s, b)))), a, b))
            if b == ir.ONE:
                out.append((_op("eq", a, hi), a, b))  # increment: value == max
        s = _op("add", x, y)
        if n < 256:
            out.append((_op("gt", s, hi) if not signed else _op("or", _op("slt", s, lo), _op("sgt", s, hi)), x, y))
    elif op == "sub":
        d = _op("add", x, _op("mul", _MAX, y))
        if not signed:
            out.append((_op("gt", d, x) if n == 256 else _op("gt", d, hi), x, y))
            out.append((_op("lt", x, y), x, y))
            if y == ir.ONE:
                out.append((_op("iszero", x), x, y))  # decrement: value == 0
        elif n == 256:
            # underflow if y >= 0 and x - y > x, overflow if y < 0 and x - y < x
            out.append((_op("or", _op("and", _op("iszero", _op("slt", y, 0)), _op("sgt", d, x)),
                            _op("and", _op("slt", y, 0), _op("slt", d, x))), x, y))
        else:
            out.append((_op("or", _op("slt", d, lo), _op("sgt", d, hi)), x, y))
        if signed and y == ir.ONE:
            out.append((_op("eq", x, lo), x, y))  # decrement: value == min
    elif op == "mul":
        m = _op("mul", x, y)
        if n <= 128:
            # the exact product fits 256 bits: overflow iff its cleanup changes it
            out.append((_op("iszero", _op("eq", _cleanup(t, m), m)), x, y))
        elif n < 256 or not signed:
            div = "sdiv" if signed else "div"
            for a, b in ((x, y), (y, x)):
                # a != 0 && (cleaned product) / a != b
                out.append((_op("and", _op("iszero", _op("iszero", a)),
                                _op("iszero", _op("eq", b, _op(div, _cleanup(t, _op("mul", a, b)), a)))), a, b))
            if not signed and n == 256:
                for a, b in ((x, y), (y, x)):
                    if isinstance(b, ir.Const) and b.value > 1 and b.value & (b.value - 1) == 0:
                        # a * 2**k overflows 256 bits iff a has a bit at 256 - k or above
                        k = b.value.bit_length() - 1
                        out.append((_op("iszero", _op("eq", a, ir.Mask(256 - k, 0, 0, a))), a, b))
    elif op == "neg" and signed:
        out.append((_op("eq", x, lo), x, None))  # -min overflows
    return out


def _int_types(n: ir.Node) -> Set[Tuple[str, int]]:
    """Integer types a node hints at: its own type, or the type whose
    maximum / minimum a constant is."""
    out: Set[Tuple[str, int]] = set()
    if isinstance(n, ir.Const):
        v = n.value
        if v and (v + 1) & v == 0:
            if v.bit_length() % 8 == 0:
                out.add(("uint", v.bit_length()))  # 2**N - 1
            if (v.bit_length() + 1) % 8 == 0:
                out.add(("int", v.bit_length() + 1))  # 2**(N-1) - 1
        if v >> 255:
            m = _M - v  # -2**(N-1)
            if m & (m - 1) == 0 and m.bit_length() % 8 == 0:
                out.add(("int", m.bit_length()))
    elif isinstance(n, ir.Mask) and (n.offset, n.shl) == (0, 0) and isinstance(n.size, int) and n.size % 8 == 0 \
            and 8 <= n.size < 256:
        out.add(("uint", n.size))
    elif isinstance(n, ir.Op) and n.op == "signextend" and isinstance(n.args[0], ir.Const) and n.args[0].value < 31:
        out.add(("int", 8 * (n.args[0].value + 1)))
    elif isinstance(n, (ir.StateRef, ir.Typed, ir.Cast)):
        try:
            t = parse_type(n.ty)
        except ValueError:
            return out
        if t.kind in ("uint", "int"):
            out.add((t.kind, t.bits))
    return out


# ---------------------------------------------------------------- effects and failures

_STATE_READS = {
    ir.Sload: "storage", ir.MLoad: "memory", ir.MemSlice: "memory", ir.TLoad: "transient",
    ir.CallOut: "calls", ir.ReturnData: "calls", ir.Balance: "balance", ir.ExtCodeSize: "code",
    ir.ExtCodeHash: "code", ir.ExtCodeSlice: "code",
}
_VOLATILE_ENV = frozenset({"gas", "msize", "selfbalance"})
_EVERYTHING = frozenset({"storage", "memory", "transient", "calls", "balance", "code"})
_ENDS = ir.TERMINATORS + (ir.Continue, ir.Break)


def _conflict(writes: FrozenSet[object], deps: FrozenSet[object]) -> bool:
    """A statement writing `writes` may change a value reading `deps`.  Storage
    is tracked per state variable (("storage", name): declared variables never
    share bits) and as a whole ("storage": a raw slot)."""
    if writes & deps:
        return True
    if "storage" in writes and any(isinstance(d, tuple) and d[0] == "storage" for d in deps):
        return True
    return "storage" in deps and any(isinstance(w, tuple) and w[0] == "storage" for w in writes)


def _deps(e: ir.Node) -> Optional[FrozenSet[object]]:
    """What the value of `e` depends on that statements may change (None: a
    value that changes by itself, such as gas, or that is not understood)."""
    out: Set[object] = set()
    for n in ir.walk(e):
        tag = _STATE_READS.get(type(n))
        if tag is not None:
            out.add(tag)
        elif isinstance(n, ir.StateRef):
            out.add(("storage", n.var))
        elif isinstance(n, ir.Local):
            out.add(("local", n.name))
        elif isinstance(n, ir.Env) and n.name in _VOLATILE_ENV:
            return None
        elif isinstance(n, (ir.UnstructuredExpr, ir.UnstructuredBytes)):
            return None
    return frozenset(out)


def _writes(s: ir.Stmt) -> Optional[FrozenSet[object]]:
    """What statement `s` may change for the values evaluated after it
    (None: a loop or a statement not understood)."""
    if isinstance(s, ir.Assign):
        if isinstance(s.target, ir.Local):
            return frozenset({("local", s.target.name)})
        if isinstance(s.target, ir.StateRef):
            return frozenset({("storage", s.target.var)})
        return frozenset({"storage"})
    if isinstance(s, ir.Sstore):
        return frozenset({"storage"})
    if isinstance(s, ir.Mstore):
        return frozenset({"memory"})
    if isinstance(s, ir.TStore):
        return frozenset({"transient"})
    if isinstance(s, (ir.ExtCall, ir.Create)):
        return _EVERYTHING
    if isinstance(s, ir.Precompile):
        return frozenset({"calls", "memory"} | ({("local", s.output)} if s.output else set()))
    if isinstance(s, ir.If):
        out: Set[object] = set()
        for t in s.then + s.orelse:
            w = _writes(t)
            if w is None:
                return None
            out |= w
        return frozenset(out)
    if isinstance(s, (ir.Log, ir.Emit, ir.Require, ir.Assert) + _ENDS):
        return frozenset()
    return None


def _failure(n: ir.Node) -> Optional[object]:
    """How evaluating node `n` itself may end the call in the rendered code
    (None: it cannot)."""
    if isinstance(n, ir.Typed):
        if n.op in ("div", "mod"):
            d = n.args[1] if len(n.args) == 2 else None
            overflow = n.checked and n.op == "div" and n.ty.startswith("int")
            if isinstance(d, ir.Const) and d.value and not (overflow and d.value == _MAX):
                return None  # a constant divisor other than 0 (and -1 for a checked signed division)
            return "sdiv" if overflow else ZERO_DIVISION
        return OVERFLOW if n.checked and n.op in ("add", "sub", "mul") else None
    if isinstance(n, (ir.UnstructuredExpr, ir.UnstructuredBytes)):
        return "other"
    if isinstance(n, ir.MLoad) and not (isinstance(n.addr, ir.Const) and n.addr.value <= 0xFFFFFFFF):
        return "other"
    if isinstance(n, (ir.CalldataSlice, ir.ReturnData, ir.CodeSlice, ir.ExtCodeSlice, ir.ZeroBytes, ir.WordSlice,
                      ir.MemSlice, ir.MaskBytes)):
        small = isinstance(n.length, ir.Const) and n.length.value <= 0xFFFFFFFF
        if isinstance(n, ir.MemSlice):
            small = small and isinstance(n.start, ir.Const) and n.start.value <= 0xFFFFFFFF
        return None if small else "other"
    return None


def _failures(e: ir.Node) -> Set[object]:
    return {f for f in (_failure(n) for n in ir.walk(e)) if f is not None}


def _scratch(s: ir.Stmt) -> bool:
    """A write of the scratch space (memory 0 - 63, the engine's hashing of a
    slot before a storage access) that cannot fail: when a failure moves
    after it, the call reverts and nothing observes it."""
    return isinstance(s, ir.Mstore) and isinstance(s.addr, ir.Const) and s.addr.value < 64 \
        and not _failures(s.data) and _deps(s.data) is not None


def _stmt_exprs(s: ir.Stmt) -> List[ir.Node]:
    """The expressions statement `s` evaluates before its own effect (not
    the statements of its branches or body)."""
    if isinstance(s, (ir.If, ir.Assert)):
        return [s.cond]
    if isinstance(s, ir.Require):
        return [s.cond, s.payload]
    if isinstance(s, ir.Assign):
        return [s.value] + ([s.target] if isinstance(s.target, ir.StateRef) else [])
    if isinstance(s, ir.Sstore):
        return [x for x in (s.slot, s.value, s.offset, s.size) if isinstance(x, ir.Node)]
    if isinstance(s, ir.Mstore):
        return [s.addr, s.data]
    if isinstance(s, ir.TStore):
        return [s.slot, s.value]
    if isinstance(s, ir.Log):
        return list(s.topics) + ([s.data] if s.data is not None else [])
    if isinstance(s, ir.Emit):
        return list(s.args)
    if isinstance(s, ir.ExtCall):
        return [x for x in (s.gas, s.to, s.value, s.selector, s.args) if x is not None]
    if isinstance(s, ir.Create):
        return [x for x in (s.value, s.code, s.salt) if x is not None]
    if isinstance(s, ir.Precompile):
        return [s.args]
    if isinstance(s, ir.SelfDestruct):
        return [s.beneficiary]
    if isinstance(s, ir.Return):
        return ([s.data] if s.data is not None else []) if s.values is None else list(s.values)
    if isinstance(s, ir.Revert):
        return [s.payload]
    if isinstance(s, ir.Continue):
        return [a.value for a in s.updates] + [a.target for a in s.updates if isinstance(a.target, ir.StateRef)]
    return []


def _eager_exprs(s: ir.Stmt) -> List[ir.Node]:
    """The expressions of _stmt_exprs that statement `s` evaluates on every
    path: all of them but a Require's payload, built only when its
    condition fails (`if (!c) revert E(...)`).  A check moved into an
    expression must run there whenever the guard ran."""
    if isinstance(s, ir.Require):
        return [s.cond]
    return _stmt_exprs(s)


def _eager_nodes(e: ir.Node) -> Iterable[ir.Node]:
    """The nodes of `e` evaluated whenever `e` is: all of them but the
    operands after the first of an `and` / `or` (the renderer writes `&&` /
    `||` when they cannot fail, Solidity then skips them) and the branches
    of a ternary."""
    stack = [e]
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, ir.Op) and n.op in ("and", "or") or isinstance(n, (ir.And, ir.Or)):
            stack.append(n.args[0])
        elif isinstance(n, ir.Ternary):
            stack.append(n.cond)
        else:
            stack.extend(ir.children(n))


def _map_exprs(s: ir.Stmt, f: Callable[[ir.Node], ir.Node]) -> ir.Stmt:
    """`s` with f applied to the expressions it evaluates itself."""
    rep = dataclasses.replace
    if isinstance(s, (ir.If, ir.Assert)):
        return rep(s, cond=f(s.cond))
    if isinstance(s, ir.Require):
        return rep(s, cond=f(s.cond), payload=f(s.payload))
    if isinstance(s, ir.Assign):
        return rep(s, value=f(s.value), target=f(s.target) if isinstance(s.target, ir.StateRef) else s.target)
    if isinstance(s, ir.Sstore):
        return rep(s, slot=f(s.slot), value=f(s.value),
                   offset=f(s.offset) if isinstance(s.offset, ir.Node) else s.offset,
                   size=f(s.size) if isinstance(s.size, ir.Node) else s.size)
    if isinstance(s, ir.Mstore):
        return rep(s, addr=f(s.addr), data=f(s.data))
    if isinstance(s, ir.TStore):
        return rep(s, slot=f(s.slot), value=f(s.value))
    if isinstance(s, ir.Log):
        return rep(s, topics=tuple(f(t) for t in s.topics), data=f(s.data) if s.data is not None else None)
    if isinstance(s, ir.Emit):
        return rep(s, args=tuple(f(a) for a in s.args))
    if isinstance(s, ir.ExtCall):
        fields = ("gas", "to", "value", "selector", "args")
        return rep(s, **{k: f(getattr(s, k)) for k in fields if getattr(s, k) is not None})
    if isinstance(s, ir.Create):
        return rep(s, value=f(s.value), code=f(s.code), salt=f(s.salt) if s.salt is not None else None)
    if isinstance(s, ir.Precompile):
        return rep(s, args=f(s.args))
    if isinstance(s, ir.SelfDestruct):
        return rep(s, beneficiary=f(s.beneficiary))
    if isinstance(s, ir.Return):
        if s.values is not None:
            return rep(s, values=tuple(f(v) for v in s.values))
        return rep(s, data=f(s.data)) if s.data is not None else s
    if isinstance(s, ir.Revert):
        return rep(s, payload=f(s.payload))
    if isinstance(s, ir.Continue):
        return rep(s, updates=tuple(rep(a, value=f(a.value),
                                        target=f(a.target) if isinstance(a.target, ir.StateRef) else a.target)
                                    for a in s.updates))
    return s


# ---------------------------------------------------------------- guards


def _panic_code(block: Sequence[ir.Stmt]) -> Optional[int]:
    if len(block) == 1 and isinstance(block[0], ir.Revert) and isinstance(block[0].payload, ir.Panic):
        return block[0].payload.code
    return None


@dataclasses.dataclass
class _Guard:
    stmt: ir.Stmt
    code: int
    cond: ir.Expr  # the call panics when cond != 0
    rest: Tuple[ir.Stmt, ...]  # what runs when it does not
    side: str  # the If's branch that holds `rest` ("orelse" / "then"), "" for a Require

    def rebuild(self, rest: Tuple[ir.Stmt, ...]) -> Tuple[ir.Stmt, ...]:
        s = self.stmt
        if self.side == "orelse":
            return (ir.If(s.cond, s.then, tuple(rest)),)
        if self.side == "then":
            return (ir.If(s.cond, tuple(rest), s.orelse),)
        return (s,) + tuple(rest)


def _guard(stmts: Sequence[ir.Stmt], i: int) -> Optional[_Guard]:
    s = stmts[i]
    after = tuple(stmts[i + 1:])
    if isinstance(s, ir.If):
        code = _panic_code(s.then)
        if code is not None:
            return _Guard(s, code, s.cond, tuple(s.orelse) + after, "orelse")
        code = _panic_code(s.orelse)
        if code is not None:
            return _Guard(s, code, ir.Op("iszero", (s.cond,)), tuple(s.then) + after, "then")
    if isinstance(s, ir.Require) and isinstance(s.payload, ir.Panic):
        return _Guard(s, s.payload.code, ir.Op("iszero", (s.cond,)), after, "")
    return None


@dataclasses.dataclass(frozen=True)
class _Op:
    """A checked operation a guard protects: `wrapping` is the EVM value the
    original computes (normal form), `typed` the operation replacing it."""

    op: str  # add sub mul neg div mod
    wrapping: ir.Expr
    typed: ir.Typed
    guards: int = 1  # guard statements it absorbs (the int256 product and signed division: 2)
    # read from a comparison of the guard rather than from the operation's own
    # shape (operands the decompiler merged): only taken where a use anchors it
    derived: bool = False


_NAMES = {"add": "sum", "sub": "diff", "mul": "product", "neg": "negated", "div": "quotient", "mod": "remainder"}

# (local, the value it holds, what that value reads) for the locals valid at a point
_Avail = Tuple[Tuple[ir.Local, ir.Expr, FrozenSet[object]], ...]


def _after(s: ir.Stmt, avail: _Avail) -> _Avail:
    """The locals still holding their values after statement s (and the one
    s assigns, when its value is pure and stable)."""
    w = _writes(s)
    if w is None:
        return ()
    out = [(loc, v, d) for loc, v, d in avail if not _conflict(w, d) and ("local", loc.name) not in w]
    if isinstance(s, ir.Assign) and isinstance(s.target, ir.Local) and not isinstance(s.value, ir.Const):
        d = _deps(s.value)
        if d is not None and ("local", s.target.name) not in d and not _failures(s.value):
            out.append((s.target, s.value, d))
    return tuple(out)


# ---------------------------------------------------------------- the rewriter


class _Arith:
    def __init__(self, fn: ir.Function, ctx):
        self.norm = Normaliser()
        self.valid = _validated(ctx.specs.get(fn.key), ctx.abi_v2)
        lay = ctx.facts.get("storage")  # the storage pass's layout, when it ran
        self.layout: Optional[Layout] = lay if isinstance(lay, Layout) else None
        self.names: Set[str] = {n.name for n in ir.walk_all(fn.body) if isinstance(n, ir.Local)}
        # the storage accesses whose own bounds check replaced a Panic(0x32) guard
        self.taken: Set[ir.StateRef] = set()
        self.facts = {"guards": collections.Counter(), "absorbed": collections.Counter(), "dead": 0, "bound": 0,
                      "unused": 0, "kept": collections.Counter(), "reasons": collections.Counter()}
        self.changed = False

    # ---- operands
    def valid_in(self, e: ir.Expr, t: SolType) -> bool:
        if t.bits == 256 or fits(e, t):
            return True
        w = _head_word(e)
        return w is not None and w in self.valid and _within(self.valid[w], t)

    @staticmethod
    def operands_ok(*xs: Optional[ir.Expr]) -> bool:
        """The operands depend on nothing that changes by itself and fail in
        at most one way (no evaluation order can change the first failure)."""
        kinds: Set[object] = set()
        for x in xs:
            if x is None:
                continue
            if _deps(x) is None:
                return False
            kinds |= _failures(x)
        return len(kinds) <= 1

    # ---- blocks
    def block(self, stmts: Sequence[ir.Stmt], avail: _Avail = ()) -> Tuple[ir.Stmt, ...]:
        """`avail`: (local, value, inputs) of the locals that hold their value
        (an engine snapshot of a read, an earlier result) at the block's
        start."""
        stmts = tuple(stmts)
        for i in range(len(stmts)):
            g = _guard(stmts, i)
            if g is None:
                continue
            head = []
            for s in stmts[:i]:
                head.append(self.stmt(s, avail))
                avail = _after(s, avail)
            self.facts["guards"][g.code] += 1
            # the guards after this one first: their operations may take this one's result as an operand
            rest = self.block(g.rest, avail)
            return tuple(head) + self.absorb(g, rest, avail)
        out = []
        for s in stmts:
            out.append(self.stmt(s, avail))
            avail = _after(s, avail)
        return tuple(out)

    def stmt(self, s: ir.Stmt, avail: _Avail) -> ir.Stmt:
        if isinstance(s, ir.If):
            return ir.If(s.cond, self.block(s.then, avail), self.block(s.orelse, avail))
        if isinstance(s, ir.While):
            return ir.While(s.cond, self.block(s.body), s.init, s.loop_id)
        if isinstance(s, ir.For):
            return ir.For(self.block(s.init, avail), s.cond, s.step, self.block(s.body), s.loop_id)
        return s

    # ---- one guard
    def absorb(self, g: _Guard, rest: Tuple[ir.Stmt, ...], avail: _Avail = ()) -> Tuple[ir.Stmt, ...]:
        if _failures(g.cond) or _deps(g.cond) is None:
            return self.keep(g, rest, "condition may halt")
        p = self.norm.cond(g.cond)
        if g.code in (OVERFLOW, ZERO_DIVISION):
            # the condition as written, then read through the locals that hold
            # the same values (the uses may read the engine's snapshot of a
            # value the guard reads again)
            conds = [p]
            sub = self.through_locals(g.cond, avail)
            if sub is not None and self.norm.cond(sub) != p:
                conds.append(self.norm.cond(sub))
            unused = None  # the first operation the guard checks, when none has a use
            for q in conds:
                for cand, tail in self.candidates(g, q, rest):
                    if cand.guards == 1 and _never_overflows(cand.typed):
                        # the check of an operation that cannot overflow (x * 1, x + 0): it never fires
                        self.facts["dead"] += 1
                        self.changed = True
                        return tail
                    got = self.use(cand, tail)
                    if got is None:
                        if not cand.derived:
                            unused = unused or (cand, tail)
                        continue
                    return self.absorbed(g, cand, got)
            if unused is not None:
                # a result nothing uses (an unused local in the source): the checked
                # operation, computed at the guard's position, raises the same Panic
                cand, tail = unused
                self.facts["unused"] += 1
                return self.absorbed(g, cand, (ir.Assign(self.bind(cand), cand.typed),) + tail)
        if g.code == OUT_OF_BOUNDS and self.bounds(p, rest):
            # the storage access right after the guard makes the same check
            self.facts["absorbed"][g.code] += 1
            self.changed = True
            return rest
        if p == ir.ZERO:
            self.facts["dead"] += 1
            self.changed = True
            return rest  # can never fire
        if g.code in (OVERFLOW, ZERO_DIVISION):
            return self.keep(g, rest, "no matching check")
        return self.keep(g, rest, f"panic 0x{g.code:02x}")

    def absorbed(self, g: _Guard, cand: _Op, out: Tuple[ir.Stmt, ...]) -> Tuple[ir.Stmt, ...]:
        self.facts["absorbed"][g.code] += 1
        if cand.guards == 2:
            # the second guard of the pair: counted as kept when it was seen alone
            self.facts["absorbed"][OVERFLOW] += 1
            self.facts["kept"][OVERFLOW] -= 1
            self.facts["reasons"]["no matching check"] -= 1
        self.changed = True
        return out

    def bind(self, cand: _Op) -> ir.Local:
        self.facts["bound"] += 1
        return ir.Local(self.fresh(_NAMES.get(cand.op, "value")))

    def through_locals(self, e: ir.Expr, avail: _Avail) -> Optional[ir.Expr]:
        """`e` with the sub-expressions that a local holds replaced by the
        local (same values where e is evaluated), or None."""
        if not avail:
            return None
        table = {self.norm.key(self.norm(v)): loc for loc, v, _ in avail}
        changed = []

        def fn(n):
            if isinstance(n, ir.Expr) and not isinstance(n, (ir.Const, ir.Local)):
                loc = table.get(self.norm.key(self.norm(n)))
                if loc is not None:
                    changed.append(n)
                    return loc
            return n

        out = ir.transform(e, fn)
        return out if changed else None

    def keep(self, g: _Guard, rest: Tuple[ir.Stmt, ...], reason: str) -> Tuple[ir.Stmt, ...]:
        self.facts["kept"][g.code] += 1
        self.facts["reasons"][reason] += 1
        return g.rebuild(rest)

    # ---- candidates
    def candidates(self, g: _Guard, p: ir.Expr, rest: Tuple[ir.Stmt, ...]):
        """(operation, the statements after its guards) for every operation
        whose compiler check the guard condition `p` is."""
        if g.code == ZERO_DIVISION:
            yield from self.divisions(p, rest)
            return
        seen: Set[Tuple[str, ...]] = set()
        for op, x, y, derived in self.shapes(p):
            for kind, bits in sorted(self.types(p, x, y)):
                t = SolType(kind, bits)
                key = (op, t.canonical, self.norm.key(x), self.norm.key(y) if y is not None else "")
                if key in seen:
                    continue
                seen.add(key)
                if not (self.valid_in(x, t) and (y is None or self.valid_in(y, t))) or not self.operands_ok(x, y):
                    continue
                for form, a, b in expected_guards(op, t, x, y):
                    if self.norm.cond(form) == p:
                        yield dataclasses.replace(self.make(op, t, a, b), derived=derived), rest
                        break
                else:
                    if op == "mul" and t.canonical == "int256":
                        pair = self.mul_pair(p, x, y, rest)
                        if pair is not None:
                            yield pair
        special = self.mul_special(p)
        if special is not None and rest:
            # the int256 product: `x < 0 && y == min` first, the generic check next
            x, y = special
            nxt = _guard(rest, 0)
            if nxt is not None and nxt.code == OVERFLOW and self.is_mul_sdiv(self.norm.cond(nxt.cond), x, y) \
                    and self.operands_ok(x, y):
                yield self.make("mul", SolType("int", 256), x, y, guards=2), nxt.rest

    def shapes(self, p: ir.Expr) -> List[Tuple[str, ir.Expr, Optional[ir.Expr], bool]]:
        """(op, x, y, derived) suggested by the sums, products and comparisons
        of a guard condition; `derived`: read from the algebra of the
        condition rather than from the operation's own shape (operands the
        decompiler merged or distributed), tried last and only taken where a
        use anchors it (otherwise an exact but meaningless reading such as
        255 - (255 - s) for `s > 255` could be chosen)."""
        out: List[Tuple[str, ir.Expr, Optional[ir.Expr], bool]] = []
        last: List[Tuple[str, ir.Expr, Optional[ir.Expr], bool]] = []
        for n in ir.walk(p):
            if not isinstance(n, ir.Op):
                continue
            if n.op == "add":
                args = list(n.args)
                for i, t in enumerate(args):
                    others = self.norm.assoc("add", args[:i] + args[i + 1:])
                    ny = self.norm.negated(t)
                    if ny is not None:
                        out.append(("sub", others, ny, False))  # first: `x - 5` reads better than `x + -5`
                    out.append(("add", t, others, False))
                    if len(args) > 2:
                        # x - (a - b): the decompiler distributes the negation (x - a + b)
                        last.append(("sub", t, self.norm.neg(others), True))
            elif n.op == "mul":
                args = list(n.args)
                for i, t in enumerate(args):
                    out.append(("mul", t, self.norm.assoc("mul", args[:i] + args[i + 1:]), False))
            elif n.op in ("lt", "slt"):
                # x < difference: x - y with y = x - difference; sum < x: the sum of x and
                # y = sum - x (operands the decompiler's algebra merged); not for a
                # constant x, which the structural shapes cover
                a, b = n.args
                diff = self.norm.assoc("add", [a, self.norm.neg(b)])
                if not isinstance(a, ir.Const):
                    last.append(("sub", a, diff, True))
                if not isinstance(b, ir.Const):
                    last.append(("add", b, diff, True))
            elif n.op == "eq":
                a, b = n.args
                if isinstance(a, ir.Const) != isinstance(b, ir.Const):
                    x = b if isinstance(a, ir.Const) else a
                    out += [("add", x, ir.ONE, False), ("sub", x, ir.ONE, False), ("neg", x, None, False)]
                for u, v in ((a, b), (b, a)):
                    if isinstance(v, ir.Mask) and v.value == u and (v.offset, v.shl) == (0, 0) \
                            and isinstance(v.size, int) and 0 < v.size < 256:
                        out.append(("mul", u, ir.Const(1 << (256 - v.size)), False))
                    if isinstance(v, ir.Op) and v.op in ("div", "sdiv"):
                        out.append(("mul", v.args[1], u, False))  # y != product / x
            elif n.op == "iszero" and not is_boolean(n.args[0]):
                out.append(("sub", n.args[0], ir.ONE, False))
        return out + last

    @staticmethod
    def types(p: ir.Expr, x: Optional[ir.Expr], y: Optional[ir.Expr]) -> Set[Tuple[str, int]]:
        out = {("uint", 256), ("int", 256)}
        for n in ir.walk(p):
            out |= _int_types(n)
        for o in (x, y):
            if o is not None:
                out |= _int_types(o)
        return out

    def make(self, op: str, t: SolType, x: ir.Expr, y: Optional[ir.Expr], guards: int = 1,
             checked: bool = True) -> _Op:
        if op == "add":
            w, typed = _op("add", x, y), ir.Typed("add", (x, y), t.canonical, checked)
        elif op == "sub":
            w, typed = _op("add", x, _op("mul", _MAX, y)), ir.Typed("sub", (x, y), t.canonical, checked)
        elif op == "mul":
            w, typed = _op("mul", x, y), ir.Typed("mul", (x, y), t.canonical, checked)
        elif op == "neg":
            w, typed = _op("mul", _MAX, x), ir.Typed("sub", (ir.ZERO, x), t.canonical, checked)
        else:  # div / mod
            w = ir.Op(("s" if _signed(t) else "") + op, (x, y))
            typed = ir.Typed(op, (x, y), t.canonical, checked)
        return _Op(op, self.norm(w), typed, guards)

    # the int256 product: two guards, either order
    def mul_special(self, p: ir.Expr) -> Optional[Tuple[ir.Expr, ir.Expr]]:
        """(x, y) when p is `x < 0 && y == min(int256)`."""
        if not (isinstance(p, ir.Op) and p.op == "and" and len(p.args) == 2):
            return None
        neg = next((a for a in p.args if isinstance(a, ir.Op) and a.op == "slt" and a.args[1] == ir.ZERO), None)
        low = next((a for a in p.args if isinstance(a, ir.Op) and a.op == "eq" and ir.Const(_MIN256) in a.args), None)
        if neg is None or low is None:
            return None
        return neg.args[0], (low.args[0] if low.args[1] == ir.Const(_MIN256) else low.args[1])

    def is_mul_sdiv(self, p: ir.Expr, x: ir.Expr, y: ir.Expr) -> bool:
        """p is `x != 0 && sdiv(x * y, x) != y`."""
        quotient = _op("sdiv", _op("mul", x, y), x)
        form = _op("and", _op("iszero", _op("iszero", x)), _op("iszero", _op("eq", y, quotient)))
        return self.norm.cond(form) == p

    def mul_pair(self, p: ir.Expr, x: ir.Expr, y: ir.Expr, rest: Tuple[ir.Stmt, ...]):
        """The generic int256 check first, the special case next."""
        for a, b in ((x, y), (y, x)):
            if not rest or not self.is_mul_sdiv(p, a, b):
                continue
            nxt = _guard(rest, 0)
            if nxt is None or nxt.code != OVERFLOW:
                continue
            special = self.mul_special(self.norm.cond(nxt.cond))
            if special is not None and special == (a, b):
                return self.make("mul", SolType("int", 256), a, b, guards=2), nxt.rest
        return None

    # division and modulo
    def divisions(self, p: ir.Expr, rest: Tuple[ir.Stmt, ...]):
        """Panic(0x12) `if (y == 0)`: a checked signed division when the
        overflow guard `x == min && y == -1` follows, else each division or
        modulo by y the statements after it evaluate (an unsigned one, or a
        signed modulo; an unchecked signed division wraps min / -1 where the
        renderer could not always keep it unchecked: left exact)."""
        if not (isinstance(p, ir.Op) and p.op == "iszero"):
            return
        y = p.args[0]
        nxt = _guard(rest, 0) if rest else None
        if nxt is not None and nxt.code == OVERFLOW:
            q = self.norm.cond(nxt.cond)
            for kind, bits in sorted(self.types(q, y, None)):
                if kind != "int":
                    continue
                t = SolType(kind, bits)
                x = self._dividend(q, y, _bounds(t)[0])
                if x is not None and self.valid_in(x, t) and self.valid_in(y, t) and self.operands_ok(x, y):
                    yield self.make("div", t, x, y, guards=2), nxt.rest
        deps = _deps(y)
        if deps is None:
            return
        for x, ev in self._dividends(rest, y, deps):
            if ev == "sdiv":
                continue
            # the guard tests y alone: a dividend that can fail (a checked
            # operation whose guard comes after this one) would fail first
            t = self._division_type(x, y, signed=ev == "smod")
            if t is not None and not _failures(x) and self.operands_ok(x, y):
                yield self.make("div" if ev == "div" else "mod", t, x, y, checked=False), rest

    def _dividend(self, q: ir.Expr, y: ir.Expr, lo: int) -> Optional[ir.Expr]:
        """x when q is `x == lo && y == -1`."""
        if not (isinstance(q, ir.Op) and q.op == "and" and len(q.args) == 2):
            return None
        want = self.norm.eq(y, ir.Const(_MAX))
        if want not in q.args:
            return None
        other = q.args[1] if q.args[0] == want else q.args[0]
        if isinstance(other, ir.Op) and other.op == "eq" and ir.Const(lo) in other.args:
            return other.args[0] if other.args[1] == ir.Const(lo) else other.args[1]
        return None

    def _dividends(self, rest: Sequence[ir.Stmt], y: ir.Expr, deps: FrozenSet[object]) \
            -> List[Tuple[ir.Expr, str]]:
        """(x, opcode) of the div / mod / sdiv / smod by y the statements of
        `rest` evaluate (up to a change of y's inputs), in order."""
        out: List[Tuple[ir.Expr, str]] = []
        for e in self._scan(rest, deps):
            for n in ir.walk(e):
                if isinstance(n, ir.Op) and n.op in ("div", "mod", "sdiv", "smod") and self.norm(n.args[1]) == y:
                    item = (self.norm(n.args[0]), n.op)
                    if item not in out:
                        out.append(item)
        return out

    def _scan(self, rest: Sequence[ir.Stmt], deps: FrozenSet[object]) -> Iterable[ir.Node]:
        for s in rest:
            yield from _stmt_exprs(s)
            if isinstance(s, ir.If):
                yield from self._scan(s.then, deps)
                yield from self._scan(s.orelse, deps)
            w = _writes(s)
            if w is None or _conflict(w, deps) or isinstance(s, _ENDS):
                return

    def _division_type(self, x: ir.Expr, y: ir.Expr, signed: bool) -> Optional[SolType]:
        """The narrowest of the operands' own types that both fit (every
        width gives the same quotient and remainder)."""
        kind = "int" if signed else "uint"
        widths = sorted(b for k, b in _int_types(x) | _int_types(y) if k == kind)
        for bits in widths + [256]:
            t = SolType(kind, bits)
            if self.valid_in(x, t) and self.valid_in(y, t):
                return t
        return None

    # ---- the uses of the guarded value
    def use(self, cand: _Op, rest: Tuple[ir.Stmt, ...]) -> Optional[Tuple[ir.Stmt, ...]]:
        deps = _deps(cand.wrapping)
        if deps is None or not rest:
            return None
        total = self.count(rest, cand, deps)
        if not total:
            return None
        k = self.lead(rest, lambda n: self.match(n, cand), deps)
        if k is not None and total == 1 \
                and sum(self.occurrences(e, cand, eager=True) for e in _eager_exprs(rest[k])) == 1 \
                and self.first_failure(rest[k], cand):
            s = _map_exprs(rest[k], lambda e: self.replace(e, cand, cand.typed))
            return tuple(rest[:k]) + (s,) + tuple(rest[k + 1:])
        # the checked result in a local assigned at the guard's position
        local = self.bind(cand)
        return (ir.Assign(local, cand.typed),) + self.replace_block(rest, cand, local, deps)

    def count(self, rest: Sequence[ir.Stmt], cand: _Op, deps: FrozenSet[object]) -> int:
        """The uses of the guarded value in `rest` (branches included), up to
        a statement that may change its operands."""
        n = 0
        for s in rest:
            n += sum(self.occurrences(e, cand) for e in _stmt_exprs(s))
            if isinstance(s, ir.If):
                n += self.count(s.then, cand, deps) + self.count(s.orelse, cand, deps)
            w = _writes(s)
            if w is None or _conflict(w, deps) or isinstance(s, _ENDS):
                break
        return n

    def occurrences(self, e: ir.Node, cand: _Op, eager: bool = False) -> int:
        """The uses of the guarded value in `e` (eager: only where every
        evaluation of `e` evaluates them, see _eager_nodes)."""
        nodes = _eager_nodes(e) if eager else ir.walk(e)
        return sum(1 for node in nodes if isinstance(node, ir.Expr) and self.match(node, cand) is not None)

    def match(self, node: ir.Expr, cand: _Op):
        """"whole" when node is the guarded value, the other operands when it
        is a sum / product that contains it, else None."""
        if not isinstance(node, (ir.Op, ir.Mask)):
            return None
        w = cand.wrapping
        nn = self.norm(node)
        if nn == w:
            return "whole"
        if isinstance(w, ir.Op) and w.op in ("add", "mul") and isinstance(nn, ir.Op) and nn.op == w.op \
                and len(nn.args) > len(w.args):
            left = list(nn.args)
            for a in w.args:
                k = self.norm.key(a)
                j = next((j for j, b in enumerate(left) if self.norm.key(b) == k), None)
                if j is None:
                    return None
                del left[j]
            return tuple(left)
        return None

    def replace(self, e: ir.Node, cand: _Op, by: ir.Expr) -> ir.Node:
        def fn(node):
            if not isinstance(node, (ir.Op, ir.Mask)):
                return node
            m = self.match(node, cand)
            if m is None:
                return _clean(node)
            if m == "whole":
                return by
            return ir.Op(cand.wrapping.op, (by,) + m)
        return ir.transform(e, fn)

    def replace_block(self, rest: Sequence[ir.Stmt], cand: _Op, by: ir.Expr,
                      deps: FrozenSet[object]) -> Tuple[ir.Stmt, ...]:
        out: List[ir.Stmt] = []
        for i, s in enumerate(rest):
            s2 = _map_exprs(s, lambda e: self.replace(e, cand, by))
            if isinstance(s2, ir.If):
                s2 = ir.If(s2.cond, self.replace_block(s2.then, cand, by, deps),
                           self.replace_block(s2.orelse, cand, by, deps))
            out.append(s2)
            w = _writes(s)
            if w is None or _conflict(w, deps) or isinstance(s, _ENDS):
                return tuple(out) + tuple(rest[i + 1:])
        return tuple(out)

    def first_failure(self, s: ir.Stmt, cand: _Op) -> bool:
        """In statement s, nothing fails in another way than the guarded
        operation before it: other failures are of its kind, or belong to
        its ancestors (evaluated after it); its operands passed
        operands_ok.  A storage access whose check replaced a Panic(0x32)
        guard counts as a failure, unless the operands read it too (the
        guard's condition did: the check had passed)."""
        safe = frozenset(n for n in ir.walk(cand.typed) if isinstance(n, ir.StateRef))
        return self.fails_first(s, lambda n: self.match(n, cand), _failure(cand.typed), safe)

    def fails_first(self, s: ir.Stmt, occ: Callable[[ir.Expr], object], mine,
                    safe: FrozenSet[ir.StateRef] = frozenset()) -> bool:
        """occ(node): None, "whole" (an occurrence) or the other operands of
        a sum / product that contains one."""
        if isinstance(s, (ir.While, ir.For)):
            return False
        return all(self._first(e, occ, mine, safe) for e in _stmt_exprs(s))

    def _first(self, e: ir.Node, occ: Callable[[ir.Expr], object], mine, safe: FrozenSet[ir.StateRef]) -> bool:
        m = occ(e) if isinstance(e, ir.Expr) else None
        if m == "whole":
            return True  # an occurrence: its operands are evaluated before it
        if m is not None:
            # a sum containing it: the other operands are its siblings, in any order
            return all(self._first(x, occ, mine, safe) for x in m)
        f = _failure(e)
        if f is None and isinstance(e, ir.StateRef) and e in self.taken and e not in safe:
            f = OUT_OF_BOUNDS
        if f is not None and f != mine and not any(isinstance(n, ir.Expr) and occ(n) is not None for n in ir.walk(e)):
            return False  # fails in another way, in an unknown order with the occurrence
        return all(self._first(c, occ, mine, safe) for c in ir.children(e))

    def lead(self, rest: Sequence[ir.Stmt], occ: Callable[[ir.Expr], object],
             deps: Optional[FrozenSet[object]]) -> Optional[int]:
        """The position of the first statement of `rest` that is not a
        scratch-space write (_scratch) without an occurrence and without an
        effect on the values `deps` reads: a failure may move after such
        writes."""
        for k, s in enumerate(rest):
            if deps is None or not _scratch(s) or _conflict(_writes(s), deps) \
                    or any(occ(x) is not None for e in _stmt_exprs(s) for x in ir.walk(e) if isinstance(x, ir.Expr)):
                return k
        return None

    # ---- Panic(0x32): a storage access that checks its own index
    def bounds(self, p: ir.Expr, rest: Tuple[ir.Stmt, ...]) -> bool:
        """p is `i >= length` of a storage array (its `.length`, or the size
        of a fixed-size array), and the first statement after the guard
        (scratch-space writes aside) accesses that array at index i before
        anything that can fail in another way: Solidity's own bounds check
        of the access is the same test with the same Panic, raised at the
        same point.  The accesses are recorded in `taken`."""
        if not rest or not (isinstance(p, ir.Op) and p.op == "iszero" and isinstance(p.args[0], ir.Op)
                            and p.args[0].op == "lt"):
            return False
        i, n = p.args[0].args

        def occ(node: ir.Expr) -> Optional[str]:
            return "whole" if isinstance(node, ir.StateRef) and self.indexes(node, i, n) else None

        k = self.lead(rest, occ, _deps(p))
        if k is None:
            return False
        found = {x for e in _eager_exprs(rest[k]) for x in _eager_nodes(e) if isinstance(x, ir.Expr) and occ(x)}
        if not found or not self.fails_first(rest[k], occ, OUT_OF_BOUNDS):
            return False
        self.taken |= found
        return True

    def indexes(self, ref: ir.StateRef, i: ir.Expr, n: ir.Expr) -> bool:
        """`ref` reads an element of the array whose bound `n` is, at index i."""
        for k, el in enumerate(ref.path):
            if not isinstance(el, ir.Expr) or isinstance(el, ir.Cast) or self.norm(el) != i:
                continue
            prefix = ref.path[:k]
            if isinstance(n, ir.StateRef) and n.var == ref.var and n.path == prefix + ("length",):
                return True
            if isinstance(n, ir.Const) and self.layout is not None:
                t = _type_at(self.layout, ref.var, prefix)
                if t is not None and t[0] == "fix" and t[2] == n.value:
                    return True
        return False

    def fresh(self, base: str) -> str:
        name, k = base, 1
        while name in self.names:
            k += 1
            name = f"{base}{k}"
        self.names.add(name)
        return name


def _never_overflows(t: ir.Typed) -> bool:
    """x * 1, x * 0, x + 0, x - 0: no valid operands overflow."""
    a, b = t.args
    if t.op == "mul":
        return any(x in (ir.ZERO, ir.ONE) for x in (a, b))
    if t.op == "add":
        return ir.ZERO in (a, b)
    return t.op == "sub" and b == ir.ZERO


def _clean(node: ir.Node) -> ir.Node:
    """The cleanup of a checked result that already has the type is the
    result: signextend(b, x) of an intN result (N <= 8 (b + 1)), the low-N
    mask of a uintM result (M <= N)."""
    if isinstance(node, ir.Op) and node.op == "signextend" and isinstance(node.args[0], ir.Const) \
            and isinstance(node.args[1], ir.Typed) and node.args[0].value < 31:
        if fits(node.args[1], SolType("int", 8 * (node.args[0].value + 1))):
            return node.args[1]
    if isinstance(node, ir.Mask) and (node.offset, node.shl) == (0, 0) and isinstance(node.size, int) \
            and isinstance(node.value, ir.Typed) and 0 < node.size < 256 and node.value.ty.startswith("uint"):
        if fits(node.value, SolType("uint", node.size)):
            return node.value
    return node


def _type_at(lay: Layout, name: str, prefix: Tuple[object, ...]) -> Optional[tuple]:
    """The storage type (storage.py's tuples) reached from variable `name`
    through a StateRef path prefix."""
    v = next((v for v in lay.vars if lay.name(v) == name), None)
    if v is None:
        return None
    t = v.type
    for el in prefix:
        if t[0] == "map" and not isinstance(el, str):
            t = t[2]
        elif t[0] == "struct" and isinstance(el, str):
            t = next((mt for ms, mo, mt in t[1] if member_name(ms, mo) == el), None)
            if t is None:
                return None
        elif t[0] in ("fix", "dyn") and not isinstance(el, str):
            t = t[1]
        else:
            return None
    return t


def _head_word(e) -> Optional[int]:
    if isinstance(e, ir.Param):
        return e.index
    if isinstance(e, ir.CalldataWord) and isinstance(e.offset, ir.Const):
        off = e.offset.value
        if off >= 4 and (off - 4) % 32 == 0:
            return (off - 4) // 32
    return None


def _validated(spec, abi_v2: bool) -> Dict[int, SolType]:
    """Head word -> value type the ABI coder v2 decoder validated."""
    out: Dict[int, SolType] = {}
    if spec is not None and abi_v2 and getattr(spec, "typed", False):
        word = 0
        for t, _ in spec.params:
            if t.is_value:
                out[word] = t
            word += t.head_words
    return out


def _within(inner: SolType, outer: SolType) -> bool:
    """Every valid `inner` word is a valid `outer` word (integers)."""
    if inner.kind == outer.kind and inner.kind in ("uint", "int"):
        return inner.bits <= outer.bits
    return inner.kind == "bool" and outer.kind == "uint"


# ---------------------------------------------------------------- the pass


def _pre_08(metadata: Optional[dict]) -> bool:
    """The original is known to come from solc before 0.8, which has no
    checked arithmetic: nothing may become checked."""
    if not metadata or metadata.get("compiler") != "solc":
        return False
    v = metadata.get("version") or ((metadata.get("version_range") or (None, None))[1])
    if not v:
        return False
    try:
        return tuple(int(x) for x in str(v).split(".")[:2]) < (0, 8)
    except ValueError:
        return False


def prepare(ctx) -> None:
    ctx.facts.setdefault("arith", {"functions": {}})


def run(fn: ir.Function, ctx) -> ir.Function:
    facts = ctx.facts.setdefault("arith", {"functions": {}})
    if _pre_08(ctx.metadata):
        return fn
    a = _Arith(fn, ctx)
    body = a.block(fn.body)
    facts["functions"][fn.key] = {
        "guards": dict(a.facts["guards"]), "absorbed": dict(a.facts["absorbed"]), "dead": a.facts["dead"],
        "bound": a.facts["bound"], "unused": a.facts["unused"], "kept": {k: v for k, v in a.facts["kept"].items() if v},
        "reasons": {k: v for k, v in a.facts["reasons"].items() if v},
    }
    if not a.changed:
        return fn
    return fn.with_body(body)

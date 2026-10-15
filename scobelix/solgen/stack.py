"""
Stack slots of the generated code under solc's legacy code generator, and
the operands to evaluate first into locals so that a statement fits.

The legacy code generator keeps every pending operand on the EVM stack and
reaches 16 slots down at most (DUP16 / SWAP16): a statement whose operands
nest deeper than that over the function's variables does not compile
("Stack too deep").  Reading the deepest variable (the first parameter)
takes need + (the other variables) <= 16 slots, `need` counting the read
itself.  `StackModel.need` estimates the slots the rendered form of an IR
operand takes, the way solc evaluates it: a call pushes its return label,
then its arguments from left to right, each over the ones before it
(abi.encodePacked and keccak256 the same, without a label); a binary
operator evaluates its right operand first, then the left one over it;
conversions take nothing; a node the renderer writes as a name (a declared
parameter) what the callback says (a calldata `bytes` parameter is two
slots, its offset and its length).  `StackModel.plan` then picks the
operands to write into locals, each in a scope of its own when its own
evaluation needs locals too.

Moving an operand before the others changes the order of evaluation inside
the statement: `reorder_safe` only allows it when nothing in the statement
can end the call but by halting (a memory or copy size no gas could pay
for), where the order cannot be seen.
"""

from __future__ import annotations

import dataclasses
from typing import Callable, Dict, List, Optional, Set, Tuple

from scobelix.solgen import ir

__all__ = ["WINDOW", "StackModel", "roots", "reorder_safe"]

WINDOW = 16  # DUP16 / SWAP16: the deepest slot the legacy code generator reaches
_CALL_OPS = frozenset({"div", "mod", "sdiv", "smod", "exp", "addmod", "mulmod", "signextend", "byte", "sar"})
_TRIES = 3  # candidates tried at each step of a plan
_SEARCH = 60  # candidates tried for one statement in all (beyond: the statement is left as it is)
_MAX_ENTRIES = 32  # entries of memory arrays for one statement


def roots(s: ir.Stmt) -> List[ir.Node]:
    """The operands a statement evaluates before it acts (an `If`: its
    condition only)."""
    if isinstance(s, ir.If):
        return [s.cond]
    out: List[ir.Node] = []
    for f in dataclasses.fields(s):
        v = getattr(s, f.name)
        for x in (v if isinstance(v, tuple) else (v,)):
            if isinstance(x, ir.Node) and not isinstance(x, ir.Stmt):
                out.append(x)
    return out


def reorder_safe(nodes: List[ir.Node]) -> bool:
    """No call result written where it is used (the call itself happens
    there: nothing may move across it)."""
    return not ir.contains(tuple(nodes), ir.Result)


_SIZED = (ir.CalldataSlice, ir.ReturnData, ir.CodeSlice, ir.ExtCodeSlice, ir.ZeroBytes, ir.WordSlice,
          ir.MemSlice, ir.MaskBytes)


def _small(e) -> bool:
    return isinstance(e, ir.Const) and e.value <= 0xFFFFFFFF


def failure(n: ir.Node) -> Optional[str]:
    """How evaluating `n` itself (its operands evaluated) may end the call:
    "halt" (a memory or copy size no gas could pay for, as the helpers
    halt), "index" (Panic 0x32), "overflow" (0x11), "division" (0x12),
    "unsupported" (the revert of an untranslated part); None: it cannot."""
    if isinstance(n, (ir.UnstructuredExpr, ir.UnstructuredBytes)):
        return "unsupported"
    if isinstance(n, ir.Typed):
        kinds = []
        if n.op in ("div", "mod") and not (isinstance(n.args[-1], ir.Const) and n.args[-1].value):
            kinds.append("division")
        if n.checked and n.op in ("add", "sub", "mul", "exp", "div"):
            kinds.append("overflow")
        return "|".join(kinds) or None
    if isinstance(n, ir.StateRef) and any(isinstance(p, ir.Expr) and not isinstance(p, ir.Cast) for p in n.path):
        return "index"
    if isinstance(n, ir.MLoad) and not _small(n.addr):
        return "halt"
    if isinstance(n, _SIZED) and not (_small(n.length) and (not isinstance(n, ir.MemSlice) or _small(n.start))):
        return "halt"
    return None


def _order(n, est: Set[int], out: list, conditional: bool) -> None:
    """Append (node, failure, conditional) for every node of `n` that may
    fail, in the order solc evaluates the rendered `n`: arguments of calls
    and abi.encodePacked from left to right, the right operand of a binary
    operator first; the operands in `est` (locals) are not evaluated."""
    if not isinstance(n, ir.Node) or id(n) in est:
        return
    if isinstance(n, ir.Ternary):
        kids = [(n.cond, conditional), (n.if_true, True), (n.if_false, True)]
    elif isinstance(n, (ir.And, ir.Or)):
        kids = [(n.args[0], conditional)] + [(a, True) for a in n.args[1:]]
    elif (isinstance(n, ir.Op) and n.op not in _CALL_OPS or isinstance(n, ir.Typed)) and len(n.args) >= 2:
        kids = [(a, conditional) for a in reversed(n.args)]
    elif isinstance(n, ir.Blob):
        kids = [(p, conditional or cond) for p, cond in blob_parts(n)]
    elif isinstance(n, ir.MaskBytes):
        kids = [(c, conditional) for c in (n.data, n.size, n.offset, n.shl, n.length)]
    else:
        kids = [(c, conditional) for c in ir.children(n) if not isinstance(c, ir.Stmt)]
    for c, cond in kids:
        _order(c, est, out, cond)
    k = failure(n)
    if k is not None:
        out.append((n, k, conditional))


class Index:
    """The nodes of a statement's operands numbered by value: equal subtrees
    get the same number (interned bottom-up, once), so the operands equal to
    one in a local are found without comparing trees."""

    def __init__(self, nodes: List[ir.Node]):
        self.nodes = nodes
        self.canon: Dict[int, int] = {}  # id(node) -> number of its value
        self.groups: Dict[int, Set[int]] = {}  # number -> ids of the nodes of that value
        table: Dict[tuple, int] = {}
        todo = [(n, False) for n in reversed(nodes)]
        while todo:
            n, ready = todo.pop()
            if not isinstance(n, ir.Node) or (id(n) in self.canon and not ready):
                continue
            if not ready:
                todo.append((n, True))
                todo.extend((c, False) for c in ir.children(n) if id(c) not in self.canon)
                continue
            if id(n) in self.canon:
                continue
            key = (type(n).__name__,) + tuple(self._rep(getattr(n, f.name)) for f in dataclasses.fields(n))
            c = table.setdefault(key, len(table))
            self.canon[id(n)] = c
            self.groups.setdefault(c, set()).add(id(n))
        self._old: Optional[tuple] = None
        self._uncertain: Optional[bool] = None

    def _rep(self, v):
        if isinstance(v, ir.Node):
            return ("n", self.canon[id(v)])
        if isinstance(v, tuple):
            return ("t",) + tuple(self._rep(x) for x in v)
        return ("v", type(v).__name__, v)

    def occurrences(self, x: ir.Node) -> Set[int]:
        """ids of the nodes equal to x."""
        c = self.canon.get(id(x))
        if c is None:
            return {id(n) for n in ir.walk_all(tuple(self.nodes)) if n == x}
        return self.groups[c]

    def order_safe(self, plan: list) -> bool:
        """See order_safe."""
        if self._old is None:
            old: list = []
            for r in self.nodes:
                _order(r, set(), old, False)
            first: Dict[int, int] = {}
            anywhere: Dict[int, int] = {}
            for i, (n, _, cond) in enumerate(old):
                c = self.canon.get(id(n), -1 - i)
                anywhere.setdefault(c, i)
                if not cond:
                    first.setdefault(c, i)
            self._old = (old, first, anywhere)
        old, first, anywhere = self._old
        if not old:
            return True
        if self._uncertain is None:
            self._uncertain = _uncertain_order(self.nodes)
        if self._uncertain:
            # two operands that fail differently whose order `_order` cannot be sure of (a
            # shift evaluates its amount first, wrapping arithmetic outside `unchecked` goes
            # through helpers evaluated left to right, `_add` writes the subtracted terms last):
            # no operand that can fail moves; operands that cannot fail move freely
            return not _moves_failure(plan)
        new: list = []

        def emit(p: list, est: Set[int]) -> Set[int]:
            """The evaluations of a plan level, in order; the locals in scope
            after it (an operand's own plan ends with its scope)."""
            est = set(est)
            for x, sub in p:
                _order(x, emit(sub, est), new, False)
                est |= self.occurrences(x)
            return est

        est = emit(plan, set())
        for r in self.nodes:
            _order(r, est, new, False)
        seen: List[tuple] = []
        for n, k, _ in new:
            c = self.canon.get(id(n))
            w = first.get(c, anywhere.get(c, len(old))) if c is not None else len(old)
            if any(k2 != k and w2 > w for w2, k2 in seen):
                return False
            seen.append((w, k))
        return True


def _moves_failure(plan: list) -> bool:
    """An operand of `plan` (or of the plans of its own evaluation) can fail."""
    return any(any(failure(n) is not None for n in ir.walk(x)) or _moves_failure(sub) for x, sub in plan)


_UNSURE_OPS = frozenset({"add", "sub", "mul", "shl", "shr"})


def _unsure(n: ir.Node) -> bool:
    """A node whose operands the renderer may write in another order than
    `_order` assumes (see Index.order_safe)."""
    if isinstance(n, ir.Op):
        return n.op in _UNSURE_OPS
    if isinstance(n, (ir.Mask, ir.Field)):
        fields = (n.size, n.offset) + ((n.shl,) if isinstance(n, ir.Mask) else ())
        return any(isinstance(f, ir.Node) for f in fields)  # a helper call: its own argument order
    return isinstance(n, ir.Typed)


def _uncertain_order(nodes: List[ir.Node]) -> bool:
    """Two operands of an `_unsure` node fail differently (two kinds, or one
    that fails in several ways), so their order of evaluation decides which
    failure comes first, and `_order` may not know it."""
    kinds: Dict[int, frozenset] = {}  # id(node) -> the failure kinds of its subtree
    todo = [(n, False) for n in nodes]
    while todo:
        n, ready = todo.pop()
        if not isinstance(n, ir.Node) or (id(n) in kinds and not ready):
            continue
        kids = [c for c in ir.children(n) if not isinstance(c, ir.Stmt)]
        if not ready:
            todo.append((n, True))
            todo.extend((c, False) for c in kids if id(c) not in kinds)
            continue
        own = failure(n)
        out = set([own] if own is not None else ())
        parts = [kinds.get(id(c), frozenset()) for c in kids]
        for p in parts:
            out |= p
        kinds[id(n)] = frozenset(out)
        if _unsure(n):
            failing = [p for p in parts if p]
            if len(failing) > 1:
                every = frozenset().union(*failing)
                if len(every) > 1 or any("|" in k for k in every):
                    return True
    return False


def order_safe(nodes: List[ir.Node], plan: list) -> bool:
    """Writing the operands of `plan` into locals first changes the order in
    which the operands of `nodes` are evaluated; the first failure decides
    how the call ends, so no two operands that fail differently may swap
    (operands that fail the same way may: which one fails first cannot be
    seen).  When the statement can fail in more than one way, no operand that
    can fail moves at all.  An operand in a local is evaluated where its
    first certain occurrence was (an equal operand in a branch that may not
    run reads the local)."""
    return Index(nodes).order_safe(plan)


def flat_parts(parts) -> List[ir.Bytes]:
    out: List[ir.Bytes] = []
    for p in parts:
        out.extend(flat_parts(p.parts) if isinstance(p, ir.Blob) else (p,))
    return out


def blob_parts(b: ir.Blob) -> List[Tuple[ir.Bytes, bool]]:
    """(part, written only when its length is not negative) for the parts of
    a byte string as the renderer writes them (render._signed_blob: a part
    whose length may be negative is evaluated only when it is not)."""
    parts = flat_parts(b.parts)
    lengths = [ir.byte_length(p) for p in parts]
    if len(parts) < 2 or None in lengths:
        return [(p, False) for p in parts]
    return [(p, not isinstance(n, ir.Const) and ir.may_be_negative(n)) for p, n in zip(parts, lengths)]


def _unconditional(n: ir.Node) -> List[ir.Node]:
    """The operands every evaluation of `n` computes (a byte string's parts
    as the renderer writes them)."""
    if isinstance(n, ir.Ternary):
        return [n.cond]
    if isinstance(n, (ir.And, ir.Or)):
        return [n.args[0]]
    if isinstance(n, ir.Blob):
        return [p for p, cond in blob_parts(n) if not cond]
    return [c for c in ir.children(n) if not isinstance(c, ir.Stmt)]


def occurrences(nodes: List[ir.Node], x: ir.Node) -> Set[int]:
    """ids of the nodes of `nodes` equal to x."""
    return {id(n) for n in ir.walk_all(tuple(nodes)) if n == x}


@dataclasses.dataclass
class StackModel:
    """leaf: node -> (slots to evaluate, slots of the value) of a node the
    renderer writes as a name (None when it does not); chain: arguments per
    abi.encodePacked."""

    leaf: Optional[Callable[[ir.Node], Optional[Tuple[int, int]]]] = None
    chain: int = 6
    held: int = 1  # slots to read an operand kept in a local (an entry of a memory array: 2)
    index: Optional["Index"] = None  # the statement's nodes by value (else found by comparing trees)

    def occ(self, nodes: List[ir.Node], x: ir.Node) -> Set[int]:
        """ids of the nodes equal to x (in the statement: an operand of a
        sub-plan only ever looks inside its own operand)."""
        return self.index.occurrences(x) if self.index is not None else occurrences(nodes, x)

    # ------------------------------------------------------------ slots

    def need(self, n, est: Set[int], memo: Dict[int, int]) -> int:
        """The slots evaluating the rendered `n` takes, the read of its value
        included (the operands in `est`, written into locals, take `held`)."""
        if id(n) in est:
            return self.held
        if not isinstance(n, ir.Node):
            return 1
        k = id(n)
        if k not in memo:
            r = self.leaf(n) if self.leaf is not None else None
            memo[k] = r[0] if r is not None else self._need(n, est, memo)
        return memo[k]

    def width(self, n, est: Set[int]) -> int:
        """The slots the value of `n` keeps on the stack (a calldata `bytes`
        parameter: its offset and its length)."""
        if not isinstance(n, ir.Node) or id(n) in est or self.leaf is None:
            return 1
        r = self.leaf(n)
        return r[1] if r is not None else 1

    def args(self, args, est: Set[int], memo: Dict[int, int], below: int) -> int:
        """Arguments evaluated from left to right, each over the values of the
        ones before it, over `below` slots."""
        out = below
        for a in args:
            out = max(out, below + self.need(a, est, memo))
            below += self.width(a, est)
        return out

    def call(self, args, est: Set[int], memo: Dict[int, int], extra: int = 0) -> int:
        """A call: its return label, then its arguments (`extra` leading
        arguments are plain locals)."""
        return self.args(args, est, memo, 1 + extra)

    def packed(self, parts, est: Set[int], memo: Dict[int, int]) -> int:
        """abi.encodePacked as render._packed_tree writes it."""
        if len(parts) <= self.chain:
            return self.args(parts, est, memo, 0)
        groups = [parts[i:i + self.chain] for i in range(0, len(parts), self.chain)]
        out, below = 0, 0
        for g in groups:
            out = max(out, below + self.packed(g, est, memo))
            below += 1
        return out

    def binary(self, args, est: Set[int], memo: Dict[int, int]) -> int:
        """`a op b op c ...` (left to right): solc evaluates the right operand
        first, then the left one over its value."""
        acc = self.need(args[0], est, memo)
        for b in args[1:]:
            acc = max(self.need(b, est, memo), 1 + acc)
        return acc

    def _need(self, n: ir.Node, est: Set[int], memo: Dict[int, int]) -> int:
        need = self.need
        if isinstance(n, (ir.Const, ir.Local, ir.ConstBytes, ir.Env, ir.CallOut, ir.Result)):
            return 1
        if isinstance(n, ir.CalldataWord):
            return self.call([n.offset], est, memo)
        if isinstance(n, ir.MLoad):
            return self.call([n.addr], est, memo, 1)
        if isinstance(n, ir.MemSlice):
            return self.call([n.start, n.length], est, memo, 1)
        if isinstance(n, ir.Op):
            if n.op in _CALL_OPS:
                return self.call(n.args, est, memo)
            if len(n.args) == 1:
                return 1 + need(n.args[0], est, memo)
            return self.binary(n.args, est, memo)
        if isinstance(n, (ir.Mask, ir.Field)):
            fields = [n.size, n.offset] + ([n.shl] if isinstance(n, ir.Mask) else [])
            if any(isinstance(f, ir.Node) for f in fields):
                return self.call(fields + [n.value], est, memo)
            return 2 + need(n.value, est, memo)  # (x >> o) & m, its constants evaluated first
        if isinstance(n, ir.Keccak):
            return need(n.data, est, memo)
        if isinstance(n, ir.Ternary):
            return max(need(x, est, memo) for x in (n.cond, n.if_true, n.if_false))
        if isinstance(n, ir.StateRef):
            return 1 + max((need(p, est, memo) for p in n.path if isinstance(p, ir.Node)), default=0)
        if isinstance(n, (ir.Typed, ir.And, ir.Or)):
            return self.binary(n.args, est, memo) if len(n.args) > 1 else 1 + need(n.args[0], est, memo)
        if isinstance(n, (ir.Bool, ir.Not)):
            return 1 + need(n.value, est, memo)
        if isinstance(n, (ir.Cast, ir.WordBytes)):
            return need(n.value, est, memo)
        if isinstance(n, ir.Blob):
            return self.packed(flat_parts(n.parts), est, memo)
        kids = list(ir.children(n))
        return self.call(kids, est, memo) if kids else 1

    def stmt_need(self, s: ir.Stmt, operands: List[ir.Node], est: Set[int]) -> int:
        """The slots a statement takes to evaluate its operands."""
        memo: Dict[int, int] = {}
        if isinstance(s, ir.Mstore):
            return self.call([s.addr, s.data], est, memo, 1)
        if isinstance(s, ir.ExtCall):
            # `to.call{value: v, gas: g}(payload)`: the address and the options,
            # then the payload (its selector and arguments packed) over them
            parts = ([ir.WordBytes(s.selector, 4)] if s.selector is not None else []) \
                + ([s.args] if s.args is not None else [])
            pending = [x for x in (s.to, s.value, s.gas) if x is not None]
            return 1 + self.args(pending + ([ir.Blob(tuple(parts))] if parts else []), est, memo, 0)
        if isinstance(s, (ir.If, ir.Require, ir.Assert, ir.Assign)):
            return 1 + max((self.need(r, est, memo) for r in operands), default=0)
        return self.call(operands, est, memo)

    # ------------------------------------------------------------ locals

    def candidates(self, nodes: List[ir.Node], need, frame: int, est: Set[int], skip: Set[int],
                   top: bool) -> List[ir.Node]:
        """The words and byte strings worth a local, on the deepest path of
        `nodes` (never into a branch that may not run) and among the operands
        of `nodes`: those whose local (and equal operands') lowers need() most
        first, then those evaluated without locals of their own (one more
        slot over `frame`), the larger first; a node of `nodes` itself last,
        and only when `top` (a statement acts on its operand's local; a value
        assigned to a local is not worth another)."""
        memo: Dict[int, int] = {}
        after: Dict[int, int] = {}

        def lowered(n: ir.Node) -> int:
            if id(n) not in after:
                after[id(n)] = need(est | self.occ(nodes, n))
            return after[id(n)]

        path: List[ir.Node] = []
        level = [r for r in nodes if id(r) not in est]
        while level:
            level = [c for c in level if self.need(c, est, memo) >= 3]
            if not level:
                break
            node = min(level, key=lambda c: (lowered(c), -self.need(c, est, memo)))  # the deepest path
            path.append(node)
            level = [c for c in _unconditional(node) if isinstance(c, ir.Node) and id(c) not in est]
        # and the operands of the roots, in the order they are evaluated (a
        # local for each, in that order, never changes the order of failures)
        for r in nodes:
            if id(r) not in est:
                path += [c for c in _unconditional(r) if isinstance(c, ir.Node) and id(c) not in est
                         and self.need(c, est, memo) >= 3 and all(c is not p for p in path)]
        movable = [n for n in path if isinstance(n, (ir.Expr, ir.Bytes)) and not isinstance(n, ir.WordBytes)
                   and id(n) not in skip and (top or all(n is not r for r in nodes))]

        def rank(n: ir.Node):
            root = any(n is r for r in nodes)  # (its local only saves what the statement adds over it)
            alone = 1 + self.need(n, est, memo) + frame + 1 <= WINDOW  # evaluated without locals of its own
            return root, lowered(n), not alone, -self.need(n, est, memo)

        # (an operand whose local lowers nothing yet is kept: another one ties
        # with it on the deepest path, the next local lowers both)
        return sorted(movable, key=rank)

    def plan(self, nodes: List[ir.Node], need, frame: int, est: Set[int], skip: Set[int],
             top: bool, budget: Optional[List[int]] = None, validate=None, prefix: tuple = ()) -> Optional[list]:
        """Operands of `nodes` to write into locals, in order, so that
        need(est) (the slots `nodes` take, those operands reading their
        locals) fits over `frame` and the locals: [(operand, plan of its own
        evaluation), ...]; an operand too deep to evaluate over them gets a
        plan of its own, in a scope of its own (its locals end before the
        next operand).  A bounded search: a few candidates at each step, and
        a whole plan `validate` refuses is not one.  None when the operands
        cannot be made to fit."""
        budget = budget if budget is not None else [_SEARCH]
        if need(est) + frame <= WINDOW:
            return [] if validate is None or validate(list(prefix)) else None
        if frame >= WINDOW or budget[0] <= 0:
            return None
        cands = self.candidates(nodes, need, frame, est, skip, top)
        if validate is not None:  # (a plan that already reorders failures stays wrong whatever follows)
            cands = [x for x in cands if validate(list(prefix) + [(x, [])])]
        for x in cands[:_TRIES]:
            budget[0] -= 1
            if budget[0] < 0:
                return None

            def own(e, x=x):  # the assignment `local = x`, its local declared first
                return 1 + self.need(x, e, {})

            sub: Optional[list] = []
            if own(est) + frame + 1 > WINDOW:
                sub = self.plan([x], own, frame + 1, est, skip, False, budget)
            if sub is None:
                continue
            rest = self.plan(nodes, need, frame + 1, est | self.occ(nodes, x), skip, top, budget, validate,
                             prefix + ((x, sub),))
            if rest is not None:
                return [(x, sub)] + rest
        return None

    def plan_memory(self, nodes: List[ir.Node], need, frame: int, skip: Set[int], top: bool,
                    validate=None) -> Optional[List[ir.Node]]:
        """Operands of `nodes` to write, in order, into entries of memory
        arrays (`frame` counts the arrays' own slots: any number of entries
        costs no more), each evaluated in place over `frame` (reading the
        entries before it) and lowering need(); the model's `held` is the
        cost of reading an entry.  None when need() cannot be made to fit."""
        est: Set[int] = set()
        out: List[ir.Node] = []
        while need(est) + frame > WINDOW:
            if len(out) >= _MAX_ENTRIES:
                return None
            memo: Dict[int, int] = {}
            for x in self.candidates(nodes, need, frame, est, skip, top):
                # (`entry = x`: the array and the index under its value)
                if self.need(x, est, memo) + 2 + frame <= WINDOW and (
                        validate is None or validate([(y, []) for y in out + [x]])):
                    break
            else:
                return None
            out.append(x)
            est |= self.occ(nodes, x)
        return out if validate is None or validate([(y, []) for y in out]) else None

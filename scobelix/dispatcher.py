"""
Function dispatcher recognition.

The loader runs the VM once from pc 0 in `just_fdests` mode. While doing so,
the VM recognises every jumpi that compares the 4-byte selector of the
calldata with a constant (`selector_test`) and replaces the branch taken on
a match with a `("funccall", selector, target, stack)` leaf, so the function
body is cut out of that run and decompiled on its own afterwards.

`analyse()` then walks the resulting dispatcher tree with the path condition
of every branch in mind, and returns:

  - the selector entries, with their target, entry stack and the memory
    writes made on the way (the state the function starts from);
  - the default exits, classified by what the path knows about the calldata
    size: EMPTY (no calldata), SHORT (fewer than 4 bytes) and NOMATCH (no
    selector matched). Their code is compared structurally to find the
    fallback and, when the empty-calldata exit runs different code, the
    receive function;
  - the callvalue checks that solc hoists above the whole dispatcher when
    no entry point is payable, so that every function behind such a check
    is reported non-payable.

The dispatcher is the code before the functions that only tests the
selector, the calldata size and (hoisted) the callvalue, and only writes
memory. Any other condition (an access check, a value-dependent path...) or
side effect (storage write, call, log...) ends it: the selector tests below
it run only after that code, so they are not entry points of their own, and
the whole sub-tree is decompiled as default code, with its selector tests
inline. When the default exits do not all run the same code, `_fallback` is
the whole code from pc 0, so that no path is lost.

In `just_fdests` mode every VM node starts with a `("jd", start, stack)`
marker: that is where a default exit starts and with which stack, even when
the optimizer inlined the default code instead of jumping to a shared tag.
"""

import dataclasses
import logging
from typing import List, Optional, Tuple

from scobelix.matcher import match
from scobelix.utils.helpers import opcode

logger = logging.getLogger(__name__)

UINT_256_MOD = 2**256
SELECTOR_LIMIT = 2**32

# Function keys used for the dispatcher's default exits.
FALLBACK = "_fallback"
RECEIVE = "_receive"


def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


#
#   Selector expression and selector tests (used by the VM while running)
#


def is_selector_expr(exp):
    """
    True for the expressions compilers use to read the 4-byte selector,
    i.e. the top 4 bytes of calldata word 0:

        ("mask_shl", 32, 224, -224, ("cd", 0))   div(calldataload(0), 2**224)
                                                  [& 0xffffffff], and SHR once
                                                  it is encoded as a mask
        ("mask_shl", 256, -224, -224, ("cd", 0)) shr(224, calldataload(0)) as
                                                  the VM currently encodes SHR
        ("div", ("cd", 0), 2**224)

    possibly wrapped in masks that keep at least the low 32 bits
    (`and(selector, 0xffffffff)`).
    """
    while True:
        m = match(exp, ("mask_shl", ":size", 0, 0, ":inner"))
        if m and _is_int(m.size) and m.size >= 32:
            exp = m.inner
        else:
            break

    if m := match(exp, ("mask_shl", ":size", ":off", ":shl", ("cd", 0))):
        if not (_is_int(m.size) and _is_int(m.off) and _is_int(m.shl)):
            return False
        if m.off == 224 and m.shl == -224 and m.size >= 32:
            return True
        if m.size == 256 and m.off == -224 and m.shl == -224:
            return True
        return False

    if m := match(exp, ("div", ("cd", 0), ":d")):
        return m.d == 2**224

    return False


def selector_test(cond):
    """
    Recognises a jumpi condition comparing the selector with a constant.

    Returns (selector, matches) where `matches` is True when the condition
    holds iff the selector equals the constant (the function is in the true
    branch) and False when it holds iff they differ (the function is in the
    false branch, e.g. via-IR's last `switch` case). Returns None otherwise.

    Shapes: eq(K, S) in both operand orders, iszero(...) of any recognised
    test, sub forms K - S = ("add", K, ("mul", -1, S)) and S - K =
    ("add", -K, S), and xor(K, S).
    """
    if m := match(cond, ("iszero", ":inner")):
        res = selector_test(m.inner)
        return (res[0], not res[1]) if res else None

    if m := match(cond, ("bool", ":inner")):
        return selector_test(m.inner)

    op = opcode(cond)
    if op in ("eq", "xor") and len(cond) == 3:
        a, b = cond[1], cond[2]
        if _is_int(b):
            a, b = b, a
        if _is_int(a) and is_selector_expr(b):
            k = a % UINT_256_MOD
            if k < SELECTOR_LIMIT:
                return k, op == "eq"
        return None

    if op == "add" and len(cond) == 3:
        a, b = cond[1], cond[2]
        if _is_int(b):
            a, b = b, a
        if not _is_int(a):
            return None
        if (m := match(b, ("mul", -1, ":s"))) and is_selector_expr(m.s):
            k = a % UINT_256_MOD  # K - S
        elif is_selector_expr(b):
            k = (-a) % UINT_256_MOD  # S - K
        else:
            return None
        if k < SELECTOR_LIMIT:
            return k, False
        return None

    return None


_COMPARISONS = ("lt", "gt", "le", "ge", "slt", "sgt", "sle", "sge", "eq")


def is_selector_range_test(cond):
    """A comparison of the selector with a constant that is not an equality
    with a valid selector: the binary-search splits of large dispatchers."""
    if m := match(cond, ("iszero", ":inner")):
        return is_selector_range_test(m.inner)
    if m := match(cond, ("bool", ":inner")):
        return is_selector_range_test(m.inner)
    if opcode(cond) in _COMPARISONS and len(cond) == 3:
        a, b = cond[1], cond[2]
        return (_is_int(a) and is_selector_expr(b)) or (
            _is_int(b) and is_selector_expr(a)
        )
    return False


#
#   Calldata size and callvalue tests
#

# An interval of possible calldata sizes: (lo, hi), hi None = unbounded.
Interval = Tuple[int, Optional[int]]
_ANY: Interval = (0, None)


def _intersect(a: Interval, b: Interval) -> Optional[Interval]:
    lo = max(a[0], b[0])
    if a[1] is None:
        hi = b[1]
    elif b[1] is None:
        hi = a[1]
    else:
        hi = min(a[1], b[1])
    if hi is not None and lo > hi:
        return None
    return lo, hi


def _cds_true_set(cond):
    """
    (true_set, false_set) of calldata sizes for a condition that only
    depends on calldatasize, each a list of intervals; None for any other
    condition.
    """
    if cond == "calldatasize":
        return [(1, None)], [(0, 0)]

    if m := match(cond, ("iszero", ":inner")):
        res = _cds_true_set(m.inner)
        return (res[1], res[0]) if res else None

    if m := match(cond, ("bool", ":inner")):
        return _cds_true_set(m.inner)

    op = opcode(cond)
    if op not in _COMPARISONS or len(cond) != 3:
        return None

    a, b = cond[1], cond[2]
    if a == "calldatasize" and _is_int(b):
        k, flipped = b, False
    elif b == "calldatasize" and _is_int(a):
        k, flipped = a, True
    else:
        return None

    if k < 0 or k >= 2**255:
        return None  # calldatasize is small: such tests are not size tests

    if op == "eq":
        if k == 0:
            return [(0, 0)], [(1, None)]
        return [(k, k)], [(0, k - 1), (k + 1, None)]

    base = op[1:] if op[0] == "s" else op  # signed ops behave the same here
    if flipped:  # k OP cds  ->  cds OP' k
        base = {"lt": "gt", "gt": "lt", "le": "ge", "ge": "le"}[base]

    if base == "lt":  # cds < k
        true = [(0, k - 1)] if k > 0 else []
        false = [(k, None)]
    elif base == "le":  # cds <= k
        true, false = [(0, k)], [(k + 1, None)]
    elif base == "gt":  # cds > k
        true, false = [(k + 1, None)], [(0, k)]
    else:  # ge: cds >= k
        true = [(k, None)]
        false = [(0, k - 1)] if k > 0 else []

    return true, false


def calldatasize_test(cond):
    """(true_set, false_set) for a test on the calldata size, else None."""
    return _cds_true_set(cond)


def callvalue_test(cond):
    """True if `cond` holds iff callvalue != 0, False if it holds iff
    callvalue == 0, None for any other condition."""
    if cond == "callvalue":
        return True
    if m := match(cond, ("bool", ":inner")):
        return callvalue_test(m.inner)
    if m := match(cond, ("iszero", ":inner")):
        res = callvalue_test(m.inner)
        return None if res is None else not res
    if match(cond, ("gt", "callvalue", 0)) or match(cond, ("lt", 0, "callvalue")):
        return True
    if match(cond, ("eq", "callvalue", 0)) or match(cond, ("eq", 0, "callvalue")):
        return False
    return None


#
#   Trace helpers
#


def is_marker(line):
    return opcode(line) == "jd"


def _is_noop(line):
    """Lines without effect: node markers, debug strings, and loop labels
    without loop variables (a fall-through into a JUMPDEST re-enters the
    same node, which the VM records as a label)."""
    if is_marker(line) or isinstance(line, str):
        return True
    if opcode(line) == "label" and len(line) >= 3 and not line[2]:
        return True
    return False


def _head(lines):
    """(start, stack) recorded by the marker of the node `lines` starts with."""
    if lines and is_marker(lines[0]) and len(lines[0]) >= 3:
        _, start, stack = lines[0][:3]
        if _is_int(start):
            return start, tuple(stack) if stack is not None else ()
    return None


_REVERT_LINES = (("revert", None), ("invalid",), ("assert_fail",))


def is_plain_revert(lines):
    """True when `lines` only reverts without data (or hits INVALID),
    possibly after an `if callvalue` check that reverts the same way: the
    behaviour of solc's built-in default when no fallback is defined.
    Memory writes before the revert are not observable and are ignored."""
    body = [l for l in lines if not _is_noop(l) and opcode(l) not in ("setmem", "setvar")]
    if len(body) == 1 and body[0] in _REVERT_LINES:
        return True
    if len(body) == 1 and opcode(body[0]) == "if" and callvalue_test(body[0][1]) is not None:
        return is_plain_revert(body[0][2]) and is_plain_revert(body[0][3])
    return False


def _const_range(r):
    """("range", pos, len) with a constant position and length."""
    return opcode(r) == "range" and _is_int(r[1]) and _is_int(r[2])


def memory_seed(writes):
    """
    `setmem` lines that recreate the memory left by the dispatcher `writes`
    (in execution order), for a run that starts where they stop. A write
    replaced by a later constant write of the same constant range is dropped
    (the zeroed words of pc 0 the prologue overwrites); when what remains
    are constants stored in distinct 32-byte words, they are sorted by
    address.
    """
    kept = []
    for k, w in enumerate(writes):
        replaced = _const_range(w[1]) and any(
            later[1] == w[1] and _is_int(later[2]) for later in writes[k + 1 :]
        )
        if not replaced:
            kept.append(w)
    if all(
        _const_range(w[1]) and w[1][2] == 32 and w[1][1] % 32 == 0 and _is_int(w[2])
        for w in kept
    ):
        kept.sort(key=lambda w: w[1][1])
    return kept


def canonical(lines):
    """
    Structural form of a dispatcher sub-tree, used to tell whether two exits
    run the same code: node markers, debug strings and variable-less labels
    are dropped, and VM-generated variable names and loop nodes are numbered
    in order of appearance (they depend on the VM's counters and on where in
    the dispatcher the code was reached, not on the code).
    """
    names = {}
    nodes = {}

    def var(name):
        if name not in names:
            names[name] = len(names)
        return names[name]

    def node(n):
        if id(n) not in nodes:
            nodes[id(n)] = len(nodes)
        return ("node", nodes[id(n)])

    def exp(e):
        if type(e).__name__ == "Node":
            return node(e)
        if isinstance(e, list):
            return [exp(x) for x in e if not _is_noop(x)]
        if isinstance(e, tuple):
            if len(e) == 2 and e[0] == "var":
                return ("var", var(e[1]))
            if len(e) == 3 and e[0] == "setvar":
                return ("setvar", var(e[1]), exp(e[2]))
            return tuple(exp(x) for x in e)
        return e

    return repr(exp(list(lines)))


#
#   Dispatcher analysis
#


@dataclasses.dataclass
class _Path:
    cds: Interval = _ANY
    selector_tested: bool = False
    cds_tested: bool = False
    callvalue_guarded: bool = False
    # memory writes (setmem lines) made on the way, in execution order
    memory: tuple = ()

    def but(self, **kw):
        return dataclasses.replace(self, **kw)


@dataclasses.dataclass
class Entry:
    """A selector of the dispatcher."""

    selector: int
    target: int
    stack: tuple
    callvalue_guarded: bool
    # memory writes of the dispatcher before the jump to the function
    memory: tuple = ()

    @property
    def key(self):
        return "0x%08x" % self.selector


@dataclasses.dataclass
class Exit:
    """A dispatcher branch that runs no selector function."""

    kind: str  # "empty" | "short" | "nomatch" | "other"
    start: Optional[int]
    stack: tuple
    lines: list
    callvalue_guarded: bool
    # the exit starts at code that is not part of the dispatcher (an
    # unrecognised condition or a side effect), selector tests included
    irregular: bool
    cds: Interval
    memory: tuple = ()

    _code: Optional[str] = None

    @property
    def code(self):
        """Structural form of what runs from here: the code, and the memory
        it starts from."""
        if self._code is None:
            self._code = canonical(self.lines) + repr(memory_seed(self.memory))
        return self._code


@dataclasses.dataclass
class Dispatcher:
    entries: List[Entry]
    exits: List[Exit]
    # the exit decompiled as `_fallback`; None: the whole code from pc 0
    fallback: Optional[Exit]
    receive: Optional[Exit]  # the exit decompiled as `_receive`
    fallback_is_default: bool  # solc's built-in revert, no user fallback
    # every non-empty exit runs the fallback code and every empty one the
    # receive (or fallback) code; when not, `fallback` is None
    fallback_consistent: bool
    callvalue_hoisted: bool
    # no exit had to start at an unrecognised condition or side effect
    regular: bool
    duplicates: List[Tuple[int, int, int]]  # (selector, kept target, other target)
    guard_reverts: int
    fallback_guarded: bool = False  # every path to the fallback code is guarded
    receive_guarded: bool = False

    def callvalue_guarded_keys(self):
        """Function keys whose every path crosses a hoisted callvalue check."""
        keys = {e.key for e in self.entries if e.callvalue_guarded}
        if self.fallback is not None and self.fallback_guarded:
            keys.add(FALLBACK)
        if self.receive is not None and self.receive_guarded:
            keys.add(RECEIVE)
        return keys

    def to_dict(self):
        """JSON-safe summary (no stacks: they are symbolic expressions)."""

        def exit_info(ex, key):
            if ex is None:
                return None
            return {"function": key, "target": ex.start, "kind": ex.kind}

        def runs(ex):
            """The decompiled default function whose code this exit runs."""
            if self.fallback is None:
                return FALLBACK  # the whole code, every exit included
            for key, ref in ((FALLBACK, self.fallback), (RECEIVE, self.receive)):
                if ref is not None and ex.code == ref.code:
                    return key
            return None

        exits = [{"kind": ex.kind, "target": ex.start, "function": runs(ex)} for ex in self.exits]

        fallback = exit_info(self.fallback, FALLBACK)
        if fallback is None:
            fallback = {"function": FALLBACK, "target": 0, "kind": "whole_code"}
        fallback["present"] = not self.fallback_is_default
        fallback["default_revert"] = self.fallback_is_default
        fallback["consistent"] = self.fallback_consistent

        return {
            "selectors": [
                {
                    "selector": e.key,
                    "function": e.key,
                    "target": e.target,
                    "callvalue_hoisted": e.callvalue_guarded,
                }
                for e in self.entries
            ],
            "fallback": fallback,
            "receive": exit_info(self.receive, RECEIVE),
            "callvalue_hoisted": self.callvalue_hoisted,
            "regular": self.regular,
            "exits": exits,
            "guard_reverts": self.guard_reverts,
            "duplicates": [
                {"selector": "0x%08x" % s, "target": t, "ignored_target": o}
                for s, t, o in self.duplicates
            ],
        }


class _Walker:
    def __init__(self):
        self.entries = []
        self.exits = []
        self.guard_reverts = 0
        self._has_fc = {}

    def has_funccall(self, lines):
        key = id(lines)
        if key not in self._has_fc:
            found = False
            for line in lines:
                op = opcode(line)
                if op == "funccall":
                    found = True
                    break
                if op == "if" and (self.has_funccall(line[2]) or self.has_funccall(line[3])):
                    found = True
                    break
            self._has_fc[key] = found
        return self._has_fc[key]

    def walk(self, lines, path):
        """`lines` (a node and the nodes it falls into) leads to functions."""
        memory = path.memory
        for k, line in enumerate(lines):
            op = opcode(line)
            if op == "funccall":
                m = match(line, ("funccall", ":sel", ":target", ":stack"))
                self.entries.append(
                    Entry(m.sel, m.target, tuple(m.stack), path.callvalue_guarded, memory)
                )
                return
            if op == "if" and k == len(lines) - 1:
                break
            if op == "setmem":
                memory += (line,)
            elif not _is_noop(line):
                # a side effect (storage write, call, log, loop...): the code
                # from here is not a dispatcher, and the selector tests below
                # it only run after that effect
                self.exit(lines, path, irregular=True)
                return
        else:
            return  # no final `if`

        _, cond, if_true, if_false = lines[-1]
        sub = path.but(memory=memory)

        if selector_test(cond) is not None or is_selector_range_test(cond):
            sub = sub.but(selector_tested=True)
            self.branch(if_true, sub)
            self.branch(if_false, sub)
            return

        cds = calldatasize_test(cond)
        if cds is not None:
            for branch, sets in ((if_true, cds[0]), (if_false, cds[1])):
                self.cds_branch(branch, sub, sets)
            return

        cv = callvalue_test(cond)
        if cv is not None:
            reverting, other = (if_true, if_false) if cv else (if_false, if_true)
            if is_plain_revert(reverting) and self.has_funccall(other):
                self.guard_reverts += 1
                self.branch(other, sub.but(callvalue_guarded=True))
                return

        # Any other condition (an access check, a value-dependent path...) is
        # not part of a dispatcher: the selector tests below it only run when
        # it holds, so their functions are not entry points of their own. The
        # whole node is default code, decompiled in one piece.
        self.exit(lines, path, irregular=True)

    def cds_branch(self, branch, path, sets):
        feasible = [iv for iv in (_intersect(path.cds, s) for s in sets) if iv is not None]
        if not feasible:
            # contradicts the calldata size known on the path: dead code
            return
        lo = min(iv[0] for iv in feasible)
        hi = None if any(iv[1] is None for iv in feasible) else max(iv[1] for iv in feasible)
        self.branch(branch, path.but(cds=(lo, hi), cds_tested=True))

    def branch(self, lines, path):
        if self.has_funccall(lines):
            self.walk(lines, path)
        else:
            self.exit(lines, path)

    def exit(self, lines, path, irregular=False):
        # an exit may still split on the calldata size (receive vs fallback)
        body = [l for l in lines if not _is_noop(l)]
        if not irregular and body and opcode(body[-1]) == "if" and len(body) == 1:
            cds = calldatasize_test(body[0][1])
            if cds is not None:
                for branch, sets in ((body[0][2], cds[0]), (body[0][3], cds[1])):
                    self.cds_branch(branch, path, sets)
                return

        head = _head(lines)
        if not (path.selector_tested or path.cds_tested):
            kind = "other"
        elif path.cds[1] == 0:
            kind = "empty"
        elif path.cds[1] is not None and path.cds[1] < 4:
            kind = "short"
        else:
            kind = "nomatch"
        self.exits.append(
            Exit(
                kind=kind,
                start=head[0] if head else None,
                stack=head[1] if head else (),
                lines=lines,
                callvalue_guarded=path.callvalue_guarded,
                irregular=irregular,
                cds=path.cds,
                memory=path.memory,
            )
        )


def analyse(trace):
    """Analyses the `just_fdests` trace of a whole contract. Returns None
    when the code has no selector dispatch at all (the whole code is then
    the fallback), including when every selector test sits behind code that
    is not a dispatcher."""
    walker = _Walker()
    if not walker.has_funccall(trace):
        return None
    walker.walk(trace, _Path())

    entries, seen, duplicates = [], {}, []
    for e in walker.entries:
        first = seen.get(e.selector)
        if first is None:
            seen[e.selector] = e
            entries.append(e)
        elif first.target != e.target:
            duplicates.append((e.selector, first.target, e.target))
        else:
            # the same entry on another path: payable if that path is not guarded
            first.callvalue_guarded = first.callvalue_guarded and e.callvalue_guarded

    if not entries:
        return None

    exits = walker.exits
    nonempty = [x for x in exits if x.kind != "empty"]
    empty = [x for x in exits if x.kind == "empty"]

    fallback = receive = None
    if nonempty:
        nomatch = [x for x in nonempty if x.kind == "nomatch"]
        fallback = (nomatch or nonempty)[0]
    if empty and (fallback is None or empty[0].code != fallback.code):
        receive = empty[0]
    if fallback is None and receive is not None:
        # no non-empty exit: whatever runs on empty calldata is all there is
        fallback, receive = receive, None

    # every default path must run the fallback code, or the receive code on
    # empty calldata; otherwise only the whole code tells what runs where
    consistent = all(x.start is not None for x in exits)
    if fallback is not None:
        consistent = consistent and all(x.code == fallback.code for x in nonempty)
        on_empty = receive if receive is not None else fallback
        consistent = consistent and all(x.code == on_empty.code for x in empty)
    if not consistent:
        logger.warning(
            "Dispatcher exits run different code: the fallback is the whole code."
        )
        fallback = receive = None

    def guarded(ref):
        return ref is not None and all(
            x.callvalue_guarded for x in exits if x.code == ref.code
        )

    return Dispatcher(
        entries=entries,
        exits=exits,
        fallback=fallback,
        receive=receive,
        fallback_is_default=fallback is not None and is_plain_revert(fallback.lines),
        fallback_consistent=consistent,
        callvalue_hoisted=all(e.callvalue_guarded for e in entries),
        regular=not any(x.irregular for x in exits),
        duplicates=duplicates,
        guard_reverts=walker.guard_reverts,
        fallback_guarded=guarded(fallback),
        receive_guarded=guarded(receive),
    )


def routes_selectors(trace):
    """True when the `just_fdests` trace holds selector tests at all: with
    no dispatcher (analyse() is None), they sit inside the default code."""
    return _Walker().has_funccall(trace)


def no_dispatch_summary(whole_code_is_revert=False, regular=True):
    """`Decompilation.dispatcher` for code without selector dispatch;
    regular=False when the code still routes selectors, behind code that is
    not a dispatcher (they are part of the fallback)."""
    return {
        "selectors": [],
        "fallback": {
            "function": FALLBACK,
            "target": 0,
            "kind": "whole_code",
            "present": not whole_code_is_revert,
            "default_revert": whole_code_is_revert,
            "consistent": True,
        },
        "receive": None,
        "callvalue_hoisted": False,
        "regular": regular,
        "exits": [],
        "guard_reverts": 0,
        "duplicates": [],
    }

import logging
import math
import os
import time
import sys
from copy import copy

from scobelix.call_output import output_write
from scobelix.core import arithmetic
import scobelix.utils.opcode_dict as opcode_dict
from scobelix.core.algebra import (
    add_op,
    bits,
    lt_op,
    mask_op,
    mul_op,
    or_op,
    safe_le_op,
    sub_op,
    CannotCompare,
)
from scobelix.core.arithmetic import is_zero, simplify_bool
from scobelix.dispatcher import selector_test
from scobelix.matcher import match
from scobelix.prettify import pprint_trace
from scobelix.utils.helpers import (
    C,
    EasyCopy,
    all_concrete,
    allow_int_digits,
    opcode,
    precompiled,
    precompiled_var_names,
)

from .stack import Stack, StackUnderflow, fold_stacks

logger = logging.getLogger(__name__)


"""

    A symbolic EVM.

    It executes the contract, and returns the resulting `trace` of execution - which is the decompiled form.


    The most difficult part of this module is the loop detection and simplification algorithm.
    In over 10 iterations I didn't find a simpler way that is just as effective.

    Unfortunately, because of the complexity, I don't fully understand how it works.
    Ergo, I cannot explain it to you :) Good luck!

    On the upside, some stuff, like apply_stack is quite straightforward.

"""


def mem_load(pos, size=32):
    return ("mem", ("range", pos, size))


def call_payload(arg_start, arg_len):
    """
    (fname, fparams) fields of a call node. The payload is kept whole as one
    memory range: fname is None and fparams is the payload (None when it is
    empty), whatever its length; the selector, when there is one, is the
    first 4 bytes of fparams once memory is resolved (the text printer shows
    it as the function name).
    """
    if arg_len == 0:
        return None, None
    return None, mem_load(arg_start, arg_len)


def find_nodes(node, f):
    """Recursively find nodes where f(node) returns true."""
    assert type(node) == Node

    if f(node):
        res = [node]
    else:
        res = []

    for n in node.next:
        res.extend(find_nodes(n, f))

    return res


def loop_var_depth(node, depth):
    """
    The `depth` part of the variable ids (stack position from the top +
    depth * 1000, see fold_stacks) of the loop that `node` jumps back to.

    The exploration depth alone does not make the ids unique: an inner loop
    whose back-edge sits at the depth where the enclosing loop's did gets
    the same ids, and the inner loop's variable then overwrites the outer
    one (the loop counter read after the inner loop is the inner pointer).
    So the depth part of every other loop label on the path to `node`
    (enclosing loops, and earlier ones whose variables the code after them
    may still read) is skipped.
    """
    used = set()
    for jd, label in node.label_history.items():
        if jd == node.jd:
            continue  # this loop's own label (a widening)
        for v in getattr(label, "begin_vars", None) or ():
            used.add(v[1] // 1000)
    while depth in used:
        depth += 1
    return depth


MAX_NODE_COUNT = int(os.environ.get("PANORAMIX_MAX_NODE_COUNT", "500000"))
node_count = 0

# CODECOPY of a constant range up to this many bytes gives the copied value
# itself; longer or symbolic copies stay ("code.data", offset, length)
MAX_CONCRETE_CODECOPY = 1 << 16
# such a value as decimal text (str, json): 8 * 2**16 bits, 157 827 digits
allow_int_digits(int(8 * MAX_CONCRETE_CODECOPY * math.log10(2)) + 2)


class Node:
    def __str__(self):
        return f"Node({self.jd})"

    def __repr__(self):
        # technically not a proper _repr_, but some trace printout functions use this
        # instead of a proper str
        return self.__str__()

    # A node left in a trace is an identity marker (its text is Node(jd)):
    # the execution graph behind it (the prev chain back to the root, the
    # VM, the loader) is never copied with the trace. Copying it recursed
    # once per node of the chain and took down the functions whose chains
    # were long (RecursionError in Function.__init__).
    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    def __init__(self, vm, start, safe, stack, condition=True, trace=None):
        global node_count

        node_count += 1

        self.vm = vm
        self.prev = []
        self.next = []
        self.trace = trace
        self.start = start
        self.safe = safe
        self.stack = stack
        self.history = {}
        self.depth = 0
        self.label_history = {}
        self.label = None

        self.condition = condition

        # Stack on entry, kept for the dispatcher analysis (see make_trace):
        # set_label() later replaces self.stack with the folded loop stack.
        self.entry_stack = tuple(stack) if vm.just_fdests else None

        stack_obj = Stack(stack)
        self.jd = (start, len(stack), tuple(stack_obj.jump_dests(vm.loader.jump_dests)))

    def make_trace(self):
        if self.vm.just_fdests:
            # Every node of the dispatcher run starts with a marker telling
            # where it starts and with which stack: the dispatcher analysis
            # decompiles the default exits (fallback, receive) from there.
            begin = [("jd", self.start, self.entry_stack)]
        else:
            begin = []

        if self.trace is None:
            return begin + [("undefined", "decompilation didn't finish")]

        if self.is_label():
            begin_vars = []
            for _, var_idx, var_val, _ in self.label.begin_vars:
                begin_vars.append(("setvar", var_idx, var_val))

            begin.append(("label", self, tuple(begin_vars)))

        last = self.trace[-1]

        if opcode(last) == "jump":
            return begin + self.trace[:-1] + last[1].make_trace()

        if m := match(last, ("if", ":cond", ":if_true", ":if_false")):
            if_true = m.if_true.make_trace()
            if_false = m.if_false.make_trace()
            return begin + self.trace[:-1] + [("if", m.cond, if_true, if_false)]

        return begin + self.trace

    def set_label(self, loop_dest, vars, stack):
        self.label = loop_dest
        loop_dest.begin_vars = vars

        assert len(self.stack) == len(stack)
        self.stack = stack
        loop_dest.prev_trace = loop_dest.trace
        loop_dest.trace = [("jump", self)]
        loop_dest.next = []
        self.set_prev(loop_dest)

    def set_prev(self, prev):
        self.prev = prev
        self.depth = prev.depth + 1

        self.history = copy(prev.history)
        self.history[prev.jd] = prev

        self.label_history = copy(prev.label_history)
        if prev.label:
            self.label_history[prev.jd] = prev.label

        prev.next.append(self)

    def is_label(self):
        return self.label is not None

    def run(self):
        logger.debug("Node.run(%s)", self)
        self.prev_trace = self.trace
        self.trace = self.vm._run(self.start, self.safe, self.stack, self.condition)

        last = self.trace[-1]

        if opcode(last) == "jump":
            if isinstance(last[1], Node):
                last[1].set_prev(self)

        elif opcode(last) == "if":
            _, _, t, f = last
            if isinstance(t, Node):
                t.set_prev(self)
            if isinstance(f, Node):
                f.set_prev(self)




class VM(EasyCopy):
    def __init__(self, loader, just_fdests=False, protocol_safe=True):
        self.loader = loader

        self.lines = loader.lines

        self.just_fdests = just_fdests
        self.protocol_safe = protocol_safe

        self.counter = 0
        self._stop_now = False

        global node_count
        node_count = 0


    def run(
        self, start, history={}, condition=None, re_run=False, stack=(), timeout=0, memory=None
    ):
        """memory: setmem lines describing memory at `start` (the writes the
        dispatcher made on the way to a function); Loader.memory_seed when
        None."""
        time_start = time.monotonic()
        last_progress = time_start

        def should_quit():
            if MAX_NODE_COUNT is not None and node_count > MAX_NODE_COUNT:
                return True
            return timeout and (time.monotonic() - time_start > timeout)

        func_node = Node(vm=self, start=start, safe=True, stack=list(stack))
        seed = list(memory) if memory is not None else self.loader.memory_seed(start)
        trace = seed + [
            ("jump", func_node, "safe", tuple()),
        ]

        root = Node(vm=self, trace=trace, start=start, safe=True, stack=list(stack))
        func_node.set_prev(root)
        """

            BFS symbolic execution, ends up with a decompiled
            code, with labels and gotos.

            Depth-first would be way easier to implement, but it tends
            to work way slower because of the loops.

        """

        for j in range(20):
            for i in range(200):
                """

                Find all the jumps, and expand them until
                the next jump.

                """
                self.expand_trace(root)
                """
                    find all the jumps that lead to an already
                    reached jumpdest (with similar stack, otherwise
                    we'd catch function calls as all).

                    replace them with 'loop' identifier
                """
                self.replace_loops(root)
                """
                    repeat until there are no more jumps
                    to explore (so, until the trace didn't change)

                """

                nodes = find_nodes(root, lambda n: n.trace is None)
                if len(nodes) == 0 or should_quit():
                    break
                now = time.monotonic()
                if now - last_progress >= 2:
                    if MAX_NODE_COUNT:
                        pct = min(int(node_count * 100 / MAX_NODE_COUNT), 100)
                        filled = int(pct / 5)
                        bar = "#" * filled + "-" * (20 - filled)
                        logger.info("VM progress [%s] %s%% (%s nodes)", bar, pct, node_count)
                    else:
                        logger.info("VM progress %s nodes", node_count)
                    last_progress = now

            trace = self.continue_loops(root)
            # tr = root.make_trace()
            nodes = find_nodes(root, lambda n: n.trace is None)

            if len(nodes) == 0 or should_quit():
                break

        if should_quit():
            logger.warning(
                "VM stopped prematurely. Node count %i, after %.2f seconds.",
                node_count,
                time.monotonic() - time_start,
            )

        tr = root.make_trace()
        return tr


    def expand_trace(self, root):
        nodes = find_nodes(root, lambda n: n.trace is None)

        for node in nodes:
            node.run()

    def replace_loops(self, root):
        # A jump back to a jumpdest of the path (same stack length) is a
        # loop: the stack positions that differ become loop variables. A
        # position equal on this first back-edge but not on a later one (an
        # accumulator that the first iteration leaves unchanged) is added by
        # the widening in continue_loops.
        nodes = find_nodes(root, lambda n: n.trace is None)

        for node in nodes:
            if (
                node.jd in node.history
                and node.jd[1] > 0
                and len(node.history[node.jd].stack) == len(node.stack)
            ):  # jd[1] == stack_len
                folded, vars = fold_stacks(
                    node.history[node.jd].stack, node.stack, loop_var_depth(node, node.depth)
                )
                loop_line = (
                    "loop",
                    node.history[node.jd],
                    node.stack,
                    folded,
                    tuple(vars),
                )
                node.trace = [loop_line]

    def continue_loops(self, root):
        loop_list = find_nodes(
            root,
            lambda n: n.trace is not None
            and len(n.trace) == 1
            and opcode(n.trace[0]) == "loop",
        )

        # nodes of a subtree discarded by a widening below
        dead = set()

        def mark_dead(n):
            todo = [n]
            while todo:
                x = todo.pop()
                if id(x) not in dead:
                    dead.add(id(x))
                    todo.extend(x.next)

        for node in loop_list:
            if id(node) in dead:
                continue
            (line,) = node.trace
            op, loop_dest, stack, new_stack, vars = line
            assert op == "loop"

            if loop_dest.is_label():
                old_stack = loop_dest.stack
                beginvars = loop_dest.label.begin_vars

                # Widening: a position where this back-edge brings another
                # value than the label's stack, and that is not a loop
                # variable yet, is loop-carried too (e.g. an accumulator
                # that a first iteration left unchanged, 0 + 0). It becomes
                # a variable and the loop body runs again from the label.
                # This terminates: the variables of a label only grow.
                covered = {pos for (_, _, _, pos) in beginvars}
                extra = [
                    p
                    for p in range(len(old_stack))
                    if p not in covered and old_stack[p] != stack[p]
                ]
                if beginvars and extra:
                    depth_part = beginvars[0][1] // 1000
                    widened_vars = list(beginvars)
                    widened = list(old_stack)
                    for p in extra:
                        var_idx = len(old_stack) - p + depth_part * 1000
                        widened_vars.append(("var", var_idx, old_stack[p], p))
                        widened[p] = ("var", var_idx)
                    loop_dest.label.begin_vars = tuple(widened_vars)
                    for child in loop_dest.next:
                        mark_dead(child)
                    loop_dest.stack = widened
                    loop_dest.trace = None
                    loop_dest.next = []
                    continue

                set_vars = []

                for _, var_idx, val, stack_pos in beginvars:
                    sv = ("setvar", var_idx, stack[stack_pos])
                    set_vars.append(sv)

                if not set_vars:
                    folded, var_list = fold_stacks(
                        old_stack, stack, loop_var_depth(node, loop_dest.label.depth)
                    )
                    node.trace = None
                    node.set_label(loop_dest, tuple(var_list), folded)
                    continue

                node.trace = [("goto", loop_dest, tuple(set_vars))]

            else:
                node.trace = None
                node.set_label(loop_dest, tuple(vars), new_stack)

    def _run(self, start, safe, stack, condition):
        logger.debug("VM._run stack=%s", stack)

        self._stop_now = False #reset each node run

        self.stack = Stack(stack)
        trace = []

        i = start
        lines = self.lines

        if i not in lines:
            if type(i) != int:
                return [("undefined", "jump to a parameter computed at runtime", i)]
            elif safe:
                return [self._past_code(i)]
            elif i in self.loader.trailer_jump_dests:
                return [("undefined", "jump into the metadata trailer", i)]
            else:
                return [("invalid", "jumdest", i)]

        if not safe:
            if lines[i][1] == "jumpdest":
                i = self.loader.next_line(i)
                if i not in lines:
                    return [self._past_code(i)]
            else:
                return [("invalid", "jump")]

        while True:
            try:
                line = lines[i]
            except KeyError:
                trace.append(self._past_code(i))
                return trace

            try:
                res = self.handle_jumps(trace, line, condition)
                if res is not None:
                    return res

                if line[1] == "jumpdest":
                    n = Node(
                        self,
                        start=i,
                        safe=False,
                        stack=tuple(self.stack.stack),
                        condition=condition,
                    )
                    logger.debug("jumpdest %s", n)
                    trace.append(("jump", n))
                    return trace

                stop = self.apply_stack(trace, line)
            except StackUnderflow:
                # The VM ran out of stack items: the entry stack of this
                # run is incomplete, which says nothing about the bytecode.
                stop = ("undefined", "stack underflow", i)

            if stop is not None:
                # never continue past an instruction the VM could not model
                trace.append(stop)
                return trace

            i = self.loader.next_line(i)


    def _past_code(self, i):
        """Trace line for execution reaching pc `i` without a jump where the
        disassembly has no instruction: past the end of the code the EVM
        stops; in the metadata trailer it would run the trailer bytes."""
        if self.loader.runs_into_trailer(i):
            return ("undefined", "execution runs into the metadata trailer", i)
        if type(i) == int and i >= len(self.loader.binary):
            return ("stop",)
        return ("invalid", "jumpdest")

    def handle_jumps(self, trace, line, condition):
        i, op = line[0], line[1]
        stack = self.stack

        if "--explain" in sys.argv and op in (
            "jump",
            "jumpi",
            "selfdestruct",
            "stop",
            "return",
            "invalid",
            "assert_fail",
            "revert",
        ):
            trace.append(C.asm(f"       {stack}"))
            trace.append("")
            trace.append(f"[{line[0]}] {C.asm(op)}")

        if op in (
            "jump",
            "jumpi",
            "selfdestruct",
            "stop",
            "return",
            "invalid",
            "assert_fail",
            "revert",
        ):
            logger.debug("[%s] %s", i, op)

        if op == "jump":
            target = stack.pop()

            n = Node(
                self,
                start=target,
                safe=False,
                stack=tuple(self.stack.stack),
                condition=condition,
            )

            trace.append(("jump", n))
            return trace

        elif op == "jumpi":
            target = stack.pop()
            if_condition = simplify_bool(stack.pop())

            tuple_stack = tuple(self.stack.stack)

            n_true = Node(
                self,
                start=target,
                safe=False,
                stack=tuple_stack,
                condition=if_condition,
            )

            n_false = Node(
                self,
                start=self.loader.next_line(i),
                safe=True,
                stack=tuple_stack,
                condition=is_zero(if_condition),
            )

            if self.just_fdests:
                # A selector comparison: cut the function out of the
                # dispatcher run, it is decompiled on its own afterwards.
                sel = selector_test(if_condition)
                if sel is not None:
                    fx_hash, in_true_branch = sel
                    if in_true_branch:
                        jumpdest = self.lines.get(target, (None, None))[1] == "jumpdest"
                        if type(target) == int and jumpdest:
                            n_true.trace = [("funccall", fx_hash, target, tuple_stack)]
                    elif n_false.start is not None:
                        # via-IR: the function body follows the jumpi
                        n_false.trace = [
                            ("funccall", fx_hash, n_false.start, tuple_stack)
                        ]

            bool_condition = arithmetic.eval_bool(if_condition, condition, symbolic=False)
            if bool_condition is not None:
                trace.append(("jump", n_true if bool_condition else n_false))
                return trace

            # protocol-safe pruning: past 60% of the node budget the false
            # branch of a symbolic jumpi is not explored any more. It is
            # reported as such, never as a plain `stop` (a successful end).
            if self.protocol_safe and node_count > int(MAX_NODE_COUNT * 0.6):
                pruned_false = Node(
                    self,
                    start=self.loader.next_line(i),
                    safe=True,
                    stack=tuple_stack,
                    condition=is_zero(if_condition),
                    trace=[("undefined", "branch pruned")],
                )
                trace.append(("if", if_condition, n_true, pruned_false))
                return trace

            trace.append(("if", if_condition, n_true, n_false))
            return trace


        elif op in ["return", "revert"]:
            p = stack.pop()
            n = stack.pop()

            if n == 0:
                # empty return / revert data; (op, 0) is one zero word
                trace.append((op, None))
            else:
                return_data = mem_load(p, n)
                trace.append((op, return_data))

            return trace

        elif op == "selfdestruct":
            trace.append(("selfdestruct", stack.pop()))
            return trace

        elif op in ["stop", "assert_fail", "invalid"]:
            trace.append((op,))
            return trace

        elif op == "UNKNOWN":
            trace.append(("invalid",))
            return trace

        return None



    def snapshot(self, trace, value):
        """Binds a read of mutable state (storage, balance, a call result...)
        to a fresh variable at the line where it happens: `("setvar", "_N",
        value)`, and returns `("var", "_N")` for the stack. The simplifier
        moves the value to its uses only where nothing changed it in between
        (core/effects.py), so a value read before a write or a call is never
        mistaken for the one read after it."""
        self.counter += 1
        vname = f"_{self.counter}"
        trace(("setvar", vname, value))
        return ("var", vname)

    def apply_stack(self, ret, line):
        def trace(exp, *format_args):
            if logger.isEnabledFor(logging.DEBUG):
                try:
                    logger.debug("Trace: %s", str(exp).format(*format_args))
                except Exception:
                    pass

            if type(exp) == str:
                ret.append(exp.format(*format_args))
            else:
                ret.append(exp)

        stack = self.stack

        def snapshot(value):
            return self.snapshot(trace, value)

        op = line[1]

        previous_len = stack.len()

        if "--verbose" in sys.argv or "--explain" in sys.argv:
            trace(C.asm("       " + str(stack)))
            trace("")

            if "push" not in op and "dup" not in op and "swap" not in op:
                trace("[{}] {}", line[0], C.asm(op))
            else:
                if type(line[2]) == str:
                    trace("[{}] {} {}", line[0], C.asm(op), C.asm(" ”" + line[2] + "”"))
                elif line[2] > 0x1000000000:
                    trace("[{}] {} {}", line[0], C.asm(op), C.asm(hex(line[2])))
                else:
                    trace("[{}] {} {}", line[0], C.asm(op), C.asm(str(line[2])))

        param = 0
        if len(line) > 2:
            param = line[2]

        if op in [
            "exp",
            "and",
            "eq",
            "div",
            "lt",
            "gt",
            "slt",
            "sgt",
            "mod",
            "xor",
            "signextend",
            "smod",
            "sdiv",
        ]:
            stack.append(
                arithmetic.eval(
                    (
                        op,
                        stack.pop(),
                        stack.pop(),
                    )
                )
            )

        elif op[:4] == "push":
            stack.append(param)

        elif op == "pop":
            stack.pop()

        elif op.startswith("dup"):
            # dup1..dup16
            if op == "dup":
                n = param
            else:
                n = int(op[3:])
            stack.dup(n)

        elif op == "mul":
            stack.append(mul_op(stack.pop(), stack.pop()))

        elif op == "or":
            stack.append(or_op(stack.pop(), stack.pop()))

        elif op == "add":
            stack.append(add_op(stack.pop(), stack.pop()))

        elif op == "sub":
            left = stack.pop()
            right = stack.pop()

            if type(left) == int and type(right) == int:
                stack.append(arithmetic.sub(left, right))
            else:
                stack.append(sub_op(left, right))

        elif op in ["mulmod", "addmod"]:
            # (op, a, b, N): a + b (or a * b) modulo N, 0 when N == 0;
            # concrete operands are folded by Stack.simplify
            stack.append((op, stack.pop(), stack.pop(), stack.pop()))

        elif op == "shl":
            off = stack.pop()
            exp = stack.pop()
            if all_concrete(off, exp):
                stack.append(arithmetic.shl(off, exp))
            elif type(off) == int and off >= 256:
                stack.append(0)
            else:
                stack.append(mask_op(exp, shl=off))

        elif op == "shr":
            off = stack.pop()
            exp = stack.pop()
            if all_concrete(off, exp):
                stack.append(arithmetic.shr(off, exp))
            elif type(off) == int:
                # x >> k keeps bits [k, 256) and moves them down: the same
                # mask as div(x, 2**k)
                if off >= 256:
                    stack.append(0)
                elif off == 0:
                    stack.append(exp)
                else:
                    stack.append(mask_op(exp, size=256 - off, offset=off, shr=off))
            else:
                stack.append(("shr", off, exp))

        elif op == "sar":
            off = stack.pop()
            exp = stack.pop()
            if all_concrete(off, exp):
                stack.append(arithmetic.sar(off, exp))
            else:
                # arithmetic shift: sign bits come in, no mask expresses it
                stack.append(("sar", off, exp))

        elif op in ["not", "iszero"]:
            stack.append((op, stack.pop()))

        elif op == "sha3":
            p = stack.pop()
            n = stack.pop()
            res = mem_load(p, n)

            self.counter += 1
            vname = f"_{self.counter}"
            vval = (
                "sha3",
                res,
            )

            trace(("setvar", vname, vval))
            stack.append(("var", vname))

        elif op == "calldataload":
            stack.append(
                (
                    "cd",
                    stack.pop(),
                )
            )

        elif op == "byte":
            # BYTE(i, x): byte i of x, counted from the most significant one
            num = stack.pop()
            val = stack.pop()
            if all_concrete(num, val):
                stack.append(arithmetic.byte_op(num, val))
            elif type(num) == int:
                if num >= 32:
                    stack.append(0)
                else:
                    off = 248 - 8 * num
                    stack.append(mask_op(val, size=8, offset=off, shr=off))
            else:
                stack.append(("byte", num, val))

        elif op == "selfbalance":
            stack.append(snapshot(("balance", "address")))

        elif op == "prevrandao":
            stack.append("prevrandao")

        elif op == "blobbasefee":
            stack.append("blobbasefee")

        elif op == "blobhash":
            stack.append(
                (
                    "blobhash",
                    stack.pop(),
                )
            )

        elif op == "tload":
            stack.append(snapshot(("tload", stack.pop())))

        elif op == "tstore":
            tloc = stack.pop()
            val = stack.pop()
            trace(("tstore", tloc, val))

        elif op == "mcopy":
            dst = stack.pop()
            src = stack.pop()
            size = stack.pop()
            if size != 0:
                trace(
                    (
                        "setmem",
                        ("range", dst, size),
                        mem_load(src, size),
                    )
                )

        elif op == "balance":
            addr = stack.pop()
            if type(addr) == tuple and addr[:4] == ("mask_shl", 160, 0, 0):
                addr = addr[4]
            stack.append(snapshot(("balance", addr)))

        elif op.startswith("swap"):
            # swap1..swap16
            if op == "swap":
                n = param
            else:
                n = int(op[4:])
            stack.swap(n)

        elif op[:3] == "log":
            p = stack.pop()
            s = stack.pop()
            topics = []
            param = int(op[3])
            for i in range(param):
                el = stack.pop()
                topics.append(el)

            trace(
                (
                    "log",
                    mem_load(p, s),
                )
                + tuple(topics)
            )

        elif op == "sload":
            sloc = stack.pop()
            stack.append(snapshot(("storage", 256, 0, sloc)))

        elif op == "sstore":
            sloc = stack.pop()
            val = stack.pop()
            trace(("store", 256, 0, sloc, val))

        elif op == "mload":
            memloc = stack.pop()

            self.counter += 1
            vname = f"_{self.counter}"
            trace(("setvar", vname, ("mem", ("range", memloc, 32))))
            stack.append(("var", vname))

        elif op == "mstore":
            memloc = stack.pop()
            val = stack.pop()
            trace(
                (
                    "setmem",
                    ("range", memloc, 32),
                    val,
                )
            )

        elif op == "mstore8":
            # one byte: the low byte of the value
            memloc = stack.pop()
            val = stack.pop()

            trace(
                (
                    "setmem",
                    ("range", memloc, 1),
                    val & 0xFF if type(val) == int else mask_op(val, size=8),
                )
            )

        elif op == "extcodecopy":
            addr = stack.pop()
            mem_pos = stack.pop()
            code_pos = stack.pop()
            data_len = stack.pop()

            trace(
                (
                    "setmem",
                    ("range", mem_pos, data_len),
                    ("extcodecopy", addr, ("range", code_pos, data_len)),
                )
            )

        elif op == "codecopy":
            mem_pos = stack.pop()
            call_pos = stack.pop()
            data_len = stack.pop()

            if data_len == 0:
                pass  # copies nothing

            elif (
                type(call_pos) == int
                and type(data_len) == int
                and data_len <= MAX_CONCRETE_CODECOPY
            ):
                # the copied bytes, zero past the end of the code (the whole
                # runtime, metadata trailer included); setmem gives the width
                code = bytes(self.loader.binary[call_pos : call_pos + data_len])
                res = int.from_bytes(code.ljust(data_len, b"\0"), "big")
                trace(("setmem", ("range", mem_pos, data_len), res))

            else:
                trace(
                    (
                        "setmem",
                        ("range", mem_pos, data_len),
                        (
                            "code.data",
                            call_pos,
                            data_len,
                        ),
                    )
                )

        elif op == "codesize":
            stack.append(len(self.loader.binary))

        elif op == "calldatacopy":
            mem_pos = stack.pop()
            call_pos = stack.pop()
            data_len = stack.pop()

            if data_len != 0:
                call_data = ("call.data", call_pos, data_len)
                #                call_data = mask_op(('call.data', bits(add_op(data_len, call_pos))), size=bits(data_len), shl=bits(call_pos))
                trace(("setmem", ("range", mem_pos, data_len), call_data))

        elif op == "returndatacopy":
            mem_pos = stack.pop()
            ret_pos = stack.pop()
            data_len = stack.pop()

            if data_len != 0:
                return_data = ("ext_call.return_data", ret_pos, data_len)
                #                return_data = mask_op(('ext_call.return_data', bits(add_op(data_len, ret_pos))), size=bits(data_len), shl=bits(ret_pos))
                trace(("setmem", ("range", mem_pos, data_len), return_data))

        elif op in ("call", "staticcall"):
            stop = self.handle_call(op, trace, line[0])
            if stop is not None:
                return stop

        elif op == "delegatecall":
            gas = stack.pop()
            addr = stack.pop()

            arg_start = stack.pop()
            arg_len = stack.pop()
            ret_start = stack.pop()
            ret_len = stack.pop()

            #symbolic delegatecall
            self.counter += 1
            call_id = f"delegatecall_{self.counter}"

            fname, fparams = call_payload(arg_start, arg_len)

            trace((
                "delegatecall",
                gas,
                addr,
                fname,
                fparams,
            ))

            # the success of this delegatecall, read now
            success_var = f"{call_id}.success"
            stack.append(snapshot(("var", success_var)))

            # the output buffer: min(ret_len, returndatasize) bytes of the
            # return data (see call_output.py)
            if ret_len != 0:
                trace(output_write(ret_start, ret_len, "delegate.return_data", addr))



        elif op == "callcode":
            gas = stack.pop()
            addr = stack.pop()
            value = stack.pop()

            arg_start = stack.pop()
            arg_len = stack.pop()
            ret_start = stack.pop()
            ret_len = stack.pop()

            call_trace = (
                "callcode",
                gas,
                addr,
                value,
            )

            call_trace += call_payload(arg_start, arg_len)

            trace(call_trace)

            self.call_len = ret_len
            stack.append(snapshot("callcode.return_code"))

            if 0 != ret_len:
                trace(output_write(ret_start, ret_len, "callcode.return_data"))

        elif op == "create":
            wei, mem_start, mem_len = stack.pop(), stack.pop(), stack.pop()

            call_trace = ("create", wei)

            code = mem_load(mem_start, mem_len)
            call_trace += (code,)

            trace(call_trace)

            stack.append(snapshot("create.new_address"))

        elif op == "create2":
            wei, mem_start, mem_len, salt = (
                stack.pop(),
                stack.pop(),
                stack.pop(),
                stack.pop(),
            )

            call_trace = ("create2", wei, ("mem", ("range", mem_start, mem_len)), salt)

            trace(call_trace)

            stack.append(snapshot("create2.new_address"))

        elif op == "pc":
            stack.append(line[0])

        elif op == "msize":
            self.counter += 1
            vname = f"_{self.counter}"
            trace(("setvar", vname, "msize"))
            stack.append(("var", vname))

        elif op in ("extcodesize", "extcodehash"):
            # the code of an account changes when a call or a creation
            # deploys or destroys it
            stack.append(snapshot((op, stack.pop())))

        elif op == "blockhash":
            stack.append(
                (
                    op,
                    stack.pop(),
                )
            )

        elif op == "returndatasize":
            stack.append(snapshot(op))

        elif op in [
            "callvalue",
            "caller",
            "address",
            "number",
            "gas",
            "origin",
            "timestamp",
            "chainid",
            "difficulty",
            "prevrandao",
            "gasprice",
            "coinbase",
            "gaslimit",
            "calldatasize",
            "basefee",
        ]:
            stack.append(op)

        else:
            # every opcode of the disassembler has a handler above or in
            # handle_jumps: reaching this is a VM bug, not a property of the
            # code, and the path is not continued with a wrong stack
            logger.warning("unsupported opcode %s at %s", op, line[0])
            return ("undefined", f"unsupported opcode {op}", line[0])

        if stack.len() - previous_len != opcode_dict.stack_diffs.get(op):
            logger.warning(
                "opcode %s at %s: stack effect %s, expected %s",
                op,
                line[0],
                stack.len() - previous_len,
                opcode_dict.stack_diffs.get(op),
            )
            return ("undefined", f"stack effect of {op} not modelled", line[0])

        stack.cleanup()
        return None

    def handle_call(self, op, trace, line_pc):
        """CALL / STATICCALL. Returns an `undefined` line when the call
        cannot be modelled (the path stops there), None otherwise."""
        stack = self.stack

        gas = stack.pop()
        addr = stack.pop()
        if op == "call":
            wei = stack.pop()
        else:
            assert op == "staticcall"
            wei = 0

        arg_start = stack.pop()
        arg_len = stack.pop()
        ret_start = stack.pop()
        ret_len = stack.pop()

        if addr == 4:  # Identity
            # the output is the input; the call writes min(input, output
            # buffer) bytes of it
            if arg_len == ret_len or safe_le_op(arg_len, ret_len) is True:
                n = arg_len
            elif safe_le_op(ret_len, arg_len) is True:
                n = ret_len
            else:
                return (
                    "undefined",
                    "identity precompile: copied length unknown",
                    line_pc,
                )
            if n != 0:
                trace(("setmem", ("range", ret_start, n), mem_load(arg_start, n)))

            stack.append("memcopy.success")

        elif type(addr) == int and addr in precompiled:
            args = mem_load(arg_start, arg_len)
            var_name = precompiled_var_names[addr]

            trace(("precompiled", var_name, precompiled[addr], args))
            stack.append(self.snapshot(trace, "{}.result".format(precompiled[addr])))
            trace(("setmem", ("range", ret_start, ret_len), ("var", var_name)))

        else:
            assert op in ("call", "staticcall")
            call_trace = (
                op,
                gas,
                addr,
                wei,
            )

            call_trace += call_payload(arg_start, arg_len)

            trace(call_trace)
            #           trace(('comment', mem_load(arg_start, arg_len)))

            self.call_len = ret_len

            stack.append(self.snapshot(trace, "ext_call.success"))

            # the call copies min(ret_len, returndatasize) bytes of its
            # return data to the output buffer (see call_output.py)
            try:
                if lt_op(0, ret_len):
                    trace(output_write(ret_start, ret_len))
            except CannotCompare:
                trace(output_write(ret_start, ret_len))

"""
The output buffer of CALL / STATICCALL / DELEGATECALL / CALLCODE.

A call with an output buffer [p, p + L) copies min(L, returndatasize) bytes
of its return data there; the rest of the buffer keeps its previous value.
The VM writes exactly that, right after the call line:

    ("setmem", ("range", p, ("min", L, "returndatasize")),
               ("ext_call.return_data", 0, ("min", L, "returndatasize")))

(`("delegate.return_data", ADDR, n)` after a delegatecall and
`("callcode.return_data", 0, n)` after a callcode, their usual return data
nodes.) ("min", a, b) is the smaller of two words. Compiled code checks the
return data size before it reads the buffer (solc >= 0.4.22:
`returndatasize < L` reverts, or the decoder bounds the read by it). Under
such a check the copy is the whole buffer, the shape every high-level call
had before:

    ("setmem", ("range", p, L), ("ext_call.return_data", 0, L))

`resolve_call_outputs` moves each copy down the trace, past lines that
neither read memory it may write nor make another call, into both branches
of an `if`, and writes the whole buffer in a branch whose condition proves
returndatasize >= L. Elsewhere (assembly, code compiled before the
RETURNDATASIZE opcode existed) the exact copy stays.
"""

from scobelix.core.effects import RESULT, changes
from scobelix.core.memloc import range_overlaps
from scobelix.utils.helpers import find_f_list, opcode

RDS = "returndatasize"
RETURN_DATA = ("ext_call.return_data", "delegate.return_data", "callcode.return_data")


def output_write(ret_start, ret_len, head="ext_call.return_data", target=0):
    """The line a call writes its output buffer with: `head` the return data
    node of the call kind, `target` its second field (the callee of a
    delegatecall, else 0)."""
    n = ("min", ret_len, RDS)
    return ("setmem", ("range", ret_start, n), (head, target, n))


def _partial(line):
    """L when `line` is a call output write of L bytes, else None."""
    if (
        opcode(line) == "setmem"
        and opcode(line[1]) == "range"
        and opcode(line[1][2]) == "min"
        and len(line[1][2]) == 3
        and line[1][2][2] == RDS
        and opcode(line[2]) in RETURN_DATA
        and len(line[2]) == 3
        and line[2][2] == line[1][2]
    ):
        return line[1][2][1]
    return None


def _full(line, n):
    p = line[1][1]
    return ("setmem", ("range", p, n), (line[2][0], line[2][1], n))


def resolve_call_outputs(trace, bound=0, sizes=None):
    """`trace` with the call output writes made whole where the code checks
    the return data size first (see the module docstring). `bound`: a lower
    bound of returndatasize known at the start of `trace` (from the ifs
    around it since the last call); `sizes`: the variables bound to the
    return data size since that call."""
    sizes = dict(sizes or {})
    res = []
    for idx, line in enumerate(trace):
        if RESULT in changes(line) or opcode(line) == "label":
            # a call (another return data buffer), or a loop head that later
            # iterations reach after other calls
            bound, sizes = 0, {}
        n = _partial(line)
        if n is not None:
            if type(n) == int and bound >= n:
                res.append(_full(line, n))
                continue
            res.extend(_sink(line, n, trace[idx + 1 :], sizes, bound))
            return res
        if opcode(line) == "setvar" and line[2] == RDS:
            sizes[line[1]] = True
        if opcode(line) == "if":
            _, cond, if_true, if_false = line
            branches = [
                resolve_call_outputs(branch, _bound(cond, holds, sizes, bound), sizes)
                for branch, holds in ((if_true, True), (if_false, False))
            ]
            line = ("if", cond, branches[0], branches[1])
        elif opcode(line) == "while":
            line = line[:2] + (resolve_call_outputs(line[2]),) + line[3:]
        res.append(line)
    return res


def _bound(cond, holds, sizes, bound):
    k = _size_at_least(cond, holds, sizes)
    return bound if k is None else max(bound, k)


def _reads_buffer(exp, rng):
    """True when `exp` may read memory in `rng`."""
    for m in find_f_list(exp, lambda e: [e] if opcode(e) == "mem" else []):
        if opcode(m[1]) != "range" or range_overlaps(m[1], rng) is not False:
            return True
    return False


def _sink(write, n, rest, sizes, bound):
    """`write` (a call output write of n bytes) followed by `rest`, the write
    moved down as far as it can go: past lines that neither read the buffer
    nor change memory its address reads, nor make a call. `sizes`, `bound`:
    as in resolve_call_outputs."""
    rng = ("range", write[1][1], n)
    out = []
    for idx, line in enumerate(rest):
        op = opcode(line)
        if type(line) == str:  # assembly listing (--explain)
            out.append(line)
            continue
        if (
            op == "setmem"
            and opcode(line[1]) == "range"
            and range_overlaps(line[1], rng) is False
            and not _reads_buffer(line[1:], rng)
            and not _reads_buffer(write[1:], line[1])
        ):
            # a write elsewhere in memory, which neither reads the buffer nor
            # changes the memory the copy's own address reads: they commute
            out.append(line)
            continue
        if op == "setvar" and not _reads_buffer(line[2], rng):
            if line[2] == RDS:
                sizes = dict(sizes)
                sizes[line[1]] = True
            out.append(line)
            continue
        if op == "if" and idx == len(rest) - 1 and not _reads_buffer(line[1], rng):
            _, cond, if_true, if_false = line
            branches = []
            for branch, holds in ((if_true, True), (if_false, False)):
                k = _bound(cond, holds, sizes, bound)
                if type(n) == int and k >= n:
                    branches.append([_full(write, n)] + resolve_call_outputs(branch, k, sizes))
                else:
                    branches.append(_sink(write, n, branch, sizes, k))
            out.append(("if", cond, branches[0], branches[1]))
            return out
        # anything else may read the buffer or change the return data
        out.append(write)
        out.extend(resolve_call_outputs(rest[idx:], bound, sizes))
        return out
    out.append(write)
    return out


def _is_size(e, sizes):
    return e == RDS or (opcode(e) == "var" and sizes.get(e[1]) is True)


def _size_at_least(cond, holds, sizes):
    """k when `cond` being `holds` proves returndatasize >= k, else None.
    The return data size is far below 2**255, so signed and unsigned
    comparisons with a small constant agree."""
    while opcode(cond) == "iszero":
        cond, holds = cond[1], not holds
    if opcode(cond) not in ("lt", "gt", "slt", "sgt", "le", "ge", "sle", "sge") or len(cond) != 3:
        return None
    _, a, b = cond
    if opcode(cond) in ("gt", "sgt", "le", "sle"):
        a, b = b, a
    if opcode(cond) in ("le", "ge", "sle", "sge"):
        holds = not holds  # a >= b is not (a < b)
    # cond, when `holds`, is now a < b
    if _is_size(a, sizes) and type(b) == int and 0 <= b < 2**64 and not holds:
        return b  # not (size < b)
    if _is_size(b, sizes) and type(a) == int and 0 <= a < 2**64 and holds:
        return a + 1  # a < size
    return None

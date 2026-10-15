import collections
import logging

from scobelix.core import arithmetic
from scobelix.core.algebra import (
    _max_op,
    add_ge_zero,
    add_op,
    apply_mask,
    apply_mask_to_storage,
    bits,
    calc_max,
    div_op,
    divisible_bytes,
    flatten_adds,
    ge_zero,
    get_sign,
    le_op,
    lt_op,
    mask_op,
    max_op,
    max_to_add,
    min_op,
    minus_op,
    mul_op,
    neg_mask_op,
    or_op,
    safe_ge_zero,
    safe_le_op,
    safe_lt_op,
    safe_max_op,
    safe_min_op,
    simplify,
    simplify_max,
    sub_op,
    to_bytes,
    try_add,
)
from scobelix.core.arithmetic import is_zero, to_real_int
from scobelix.core.masks import get_bit, to_mask, to_neg_mask
from scobelix.core.memloc import (
    apply_mask_to_range,
    fill_mem,
    memloc_overwrite,
    range_overlaps,
    split_setmem,
    split_store,
    splits_mem,
)
from scobelix.matcher import Any, match
from scobelix.prettify import (
    explain,
    pformat_trace,
    pprint_repr,
    pprint_trace,
    pretty_repr,
)
from scobelix.simplify import simplify_trace
from scobelix.utils.helpers import (
    C,
    contains,
    find_f_list,
    find_f_set,
    find_op_list,
    opcode,
    replace,
    replace_f,
    replace_f_stop,
    rewrite_trace,
    rewrite_trace_full,
    rewrite_trace_ifs,
    rewrite_trace_multiline,
    to_exp2,
    walk_trace,
)

from scobelix.postprocess import cleanup_mul_1

logger = logging.getLogger(__name__)

"""

    Rube Goldberg would be proud.

"""


def make_whiles(trace, timeout=0, display=False, deadline=None):
    """
    The structured, simplified trace. display: return (trace, display_trace)
    instead, the second one for the text output; timeout, deadline: the time
    limits of the simplification (see simplify_trace).
    """
    trace = make(trace)
    explain("Loops -> whiles", trace)

    # clean up jumpdests
    trace = rewrite_trace(
        trace, lambda line: [] if opcode(line) == "jumpdest" else [line]
    )
    return simplify_trace(trace, timeout=timeout, display=display, deadline=deadline)


"""

    make whiles

"""


def make(trace):
    res = []

    for idx, line in enumerate(trace):
        if m := match(line, ("if", ":cond", ":if_true", ":if_false")):
            res.append((
                "if",
                m.cond,
                make(m.if_true),
                make(m.if_false),
            ))

        #potential while
        elif m := match(line, ("label", ":jd", ":vars", ...)):
            jd, vars = m.jd, m.vars

            res_while = to_while(trace[idx + 1:], jd)

            # no goood while -> we keep same label 
            if res_while is None:
                res.append(line)
                continue

            before, inside, remaining, cond = res_while

            #récursion
            inside = make(inside)
            remaining = make(remaining)

            before = replace_vars(before, vars)

            before = make(before)

            res.extend(before)
            res.append(("while", cond, inside, repr(jd), vars))
            res.extend(remaining)

            return res

        elif m := match(line, ("goto", ":jd", ":setvars")):
            res.append(("continue", repr(m.jd), m.setvars))

        else:
            res.append(line)

    return res



def replace_vars(trace, setvars):
    """`trace` with every variable of `setvars` (("setvar", idx, value)...)
    replaced by its value, simultaneously: a value that names another of
    the variables keeps meaning the old one."""
    values = {sv[1]: sv[2] for sv in setvars}
    if not values:
        return trace

    def sub(e):
        if type(e) == tuple and len(e) == 2 and e[0] == "var":
            if type(e[1]) in (int, str) and e[1] in values:
                return values[e[1]]
        if type(e) in (tuple, list):
            return type(e)(sub(x) for x in e)
        return e

    return sub(trace)


def get_jds(line):
    if m := match(line, ("goto", ":jd", ...)):
        return [m.jd]
    return []


def is_revert(trace):
    """True for a branch that only reverts (or hits INVALID). A `return`
    never is one: `("return", 0)` returns one zero word, `("return", None)`
    nothing (a void function under via-IR)."""
    if len(trace) != 1:
        return False

    return opcode(trace[0]) in ("revert", "invalid")


def to_while(trace, jd, path=None):
    path = path or []

    while True:
        if not trace:
            return None #if no good while we skip properly
        line, *trace = trace

        if m := match(line, ("if", ":cond", ":if_true", ":if_false")):
            cond, if_true, if_false = m.cond, m.if_true, m.if_false

            # ("require", C, LINE): when C is false, LINE runs (the revert
            # or invalid line of the branch, payload included)
            if is_revert(if_true):
                path.append(("require", is_zero(cond), if_true[0]))
                trace = if_false
                continue
            if is_revert(if_false):
                path.append(("require", cond, if_false[0]))
                trace = if_true
                continue

            jds_true = find_f_list(if_true, get_jds)
            jds_false = find_f_list(if_false, get_jds)

            #assert (jd in jds_true) != (jd in jds_false), (jd, jds_true, jds_false)

            if (jd in jds_true) == (jd in jds_false):
                return None # if it's ambigu or absent -> no while then

            def add_path(line):
                if m := match(line, ("goto", Any, ":svs")):
                    # the loop header runs again with the new values: all
                    # the setvars of a goto at once (a, b = b, a + b)
                    path2 = replace_vars(path, m.svs)
                    return path2 + [line]
                else:
                    return [line]

            if jd in jds_true:
                if_true = rewrite_trace(if_true, add_path)
                return path, if_true, if_false, cond
            else:
                if_false = rewrite_trace(if_false, add_path)
                return path, if_false, if_true, is_zero(cond)

        else:
            path.append(line)
    return None
    #assert False, f"no if after label?{jd}"

import collections
import time
import logging
import sys
from copy import copy

import scobelix.core.arithmetic as arithmetic
from scobelix.call_output import resolve_call_outputs
from scobelix.core.algebra import (
    _max_op,
    add_ge_zero,
    add_op,
    apply_mask,
    apply_mask_to_storage,
    bits,
    calc_max,
    div_op,
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
    try_add,
)
from scobelix.core.arithmetic import is_zero, to_real_int
from scobelix.core.effects import clobbers, kinds
from scobelix.core.masks import get_bit, to_mask, to_neg_mask
from scobelix.core.memloc import (
    fill_mem,
    memloc_overwrite,
    part_width,
    range_overlaps,
    self_width,
    split_setmem,
    split_store,
    splits_mem,
    with_width,
)
from scobelix.matcher import Any, match
from scobelix.prettify import (
    explain,
    pformat_trace,
    pprint_repr,
    pprint_trace,
    pretty_repr,
)
from scobelix.utils.helpers import (
    C,
    cached,
    contains,
    find_f_list,
    find_f_set,
    find_op_list,
    is_array,
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
from scobelix.rewriter import postprocess_exp, postprocess_trace, rewrite_string_stores

logger = logging.getLogger(__name__)


"""

    Simplifier engine.

    It takes the trace, and performs rewrites in the following loop:
        - simplify expressions
        - inline and cleanup variables (when possible)
        - inline and cleanup memory (when possible)
        - split setmems
        - split storage writes into separate lines
        - replace msize with actual values if possible
        - if there are any obvious always-fulfilled conditions, remove them
        - look for loops that are really setmems and clean those too
        - for loops that access storage, rewrite them so they are easier to parse by storage parser

    Finally, after all the processing is done:
    - replace `max(2+x, 3+y)` with `2 + max(x, 1+y)` - more human-readable, but would cause problems in the loop
    - do some other stuff that is human readable but would make the processing in the loop difficult


    If you want to see the engine in all it's glory, try:
        scobelix.py kitties tokenMetadata

    If you want to figure out exactly what happens, pprint_trace(trace) and pprint_repr(trace)
    are your friend. Put them in various places in simplify_trace and and see how the code changes.

"""

"""

    Pro tips:

        - rules in simplifier are quite independent. you can disable and move around a lot of the stuff
          and still maintain the mathematical correctedness of the output

        - the worst that will happen is that some edge cases in some contracts won't get simplified, but they
          will still be correct

        - bulk_compare.py is your friend for testing your changes. in Eveem I use something like it for initial
          tests and then do a huge integration comparison before each release, checking thousands of contracts for
          changes

        - if you like this approach, be sure to check out the work of people from Kestrel Institute, and their use
          of ACL2. They built a decompiler with a similar structure, but with simplification rules formally proven(!).

"""


LARGE_TRACE_THRESHOLD = 2000
MAX_SIMPLIFY_PASSES_LARGE = 20
MAX_MEM_CLEANUP_TRACE_LEN = 2000

# The time limit of the running simplify_trace (a time.monotonic() value;
# None: no limit). Past it, the rewrites whose cost grows with the square of
# the trace (cleanup_mems, replace_mem, cleanup_vars) leave the rest of their
# trace as it is, and the passes stop. Every rewrite keeps the semantics, so
# the result stays exact, only less simplified: the limit bounds the whole
# simplification, not only the time between two passes. (replace_var always
# runs to its end: the loop rewrites need its substitutions.)
_deadline = None
# whether the last simplify_trace stopped at its limit
last_run_timed_out = False


def _out_of_time():
    global last_run_timed_out
    if _deadline is not None and time.monotonic() > _deadline:
        last_run_timed_out = True
        return True
    return False


def simplify_trace(trace, timeout=0, display=False, deadline=None):
    """
    The simplified `trace`, with the same semantics. `timeout` (seconds, 0:
    none) and `deadline` (a time.monotonic() value, None: none) bound the
    simplification (see _deadline); last_run_timed_out tells whether it
    stopped there. See _simplify_trace.
    """
    global _deadline, last_run_timed_out
    outer = _deadline
    start = time.monotonic()
    limits = [t for t in (outer, deadline) if t is not None]
    if timeout:
        limits.append(start + timeout)
    _deadline = min(limits) if limits else None
    seconds = None if _deadline is None else round(_deadline - start)
    last_run_timed_out = False
    try:
        res = _simplify_trace(trace, display=display)
    finally:
        _deadline = outer
    if last_run_timed_out:
        logger.warning(
            "simplification stopped at its time limit (%s s): the trace is exact but not fully simplified",
            seconds,
        )
    return res


def _simplify_trace(trace, display=False):
    """
    The simplified `trace`, with the same semantics.

    display: also return the form for the text output, as a pair (trace,
    display_trace). The display form goes through the readability heuristics
    of rewriter.py too (string length cases and padding branches folded into
    their main case, string copies to storage into one line), which drop
    branches: never use it as the function's semantics.
    """
    max_passes = (
        MAX_SIMPLIFY_PASSES_LARGE
        if len(trace) > LARGE_TRACE_THRESHOLD
        else 40
    )

    def should_quit():
        return _out_of_time()  # the time limit of simplify_trace

    old_trace = None
    count = 0
    while trace != old_trace and count < max_passes and not should_quit():
        count += 1
        if count % 5 == 0:
            pct = int(count * 100 / max_passes)
            logger.info(
                "Simplify progress %s%% (pass %s/%s)",
                pct,
                count,
                max_passes,
            )

        old_trace = trace

        # fun fact:
        # you can do prettify.pprint_trace(trace) or prettify.pprint_repr(trace)
        # between every stage here to see changes that happen to the code.

        trace = replace_f(trace, simplify_exp)
        explain("simplify expressions", trace)

        trace = cleanup_vars(trace)
        explain("cleanup variables", trace)

        trace = cleanup_mems(trace)
        explain("cleanup mems", trace)

        trace = resolve_call_outputs(trace)
        explain("call output buffers", trace)

        trace = rewrite_trace(trace, split_setmem)
        trace = rewrite_trace_full(trace, split_store)
        explain("split setmems & storages", trace)

        trace = cleanup_vars(trace)
        explain("cleanup vars", trace)

        trace = narrow_snapshots(trace)
        explain("storage fields read into variables", trace)

        trace = replace_f(trace, simplify_exp)
        explain("simplify expressions", trace)

        trace = cleanup_mul_1(trace)
        explain("simplify expressions", trace)

        trace = cleanup_msize(trace)
        explain("calculate msize", trace)

        trace = replace_bytes_or_string_length(trace)
        explain("replace storage with length", trace)

        trace = cleanup_conds(trace)
        explain("cleanup unused ifs", trace)

        trace = rewrite_trace(trace, loop_to_setmem)
        explain("convert loops to setmems", trace)

        trace = propagate_storage_in_loops(trace)
        explain("move loop indexes outside of loops", trace)

        # there is a logic to this ordering, but it would take a long
        # time to explain. if you play with it, just run through bulk_compare.py
        # and see how it affects the code.

    # final lightweight postprocessing
    # introduces new variables, simplifies code for human readability
    # and does other stuff that would break the above loop

    trace = replace_f(trace, max_to_add)

    trace = replace_f(trace, postprocess_exp)
    trace = replace_f(trace, postprocess_exp)

    exact = _final_cleanup(trace)
    if not display:
        return exact

    # the heuristics of rewriter.py: for the text output only
    shown = rewrite_trace_ifs(trace, postprocess_trace)
    shown = rewrite_trace_multiline(shown, rewrite_string_stores, 3)
    explain("using heuristics to clean up some things", shown)

    shown = exact if shown == trace else _final_cleanup(shown)
    return exact, replace_f(shown, _shown_field)


def _shown_field(exp):
    """
    The text output shows a storage field moved up by a byte or more (a
    bytesN field read left-aligned) as the field itself, as it always did;
    the exact trace keeps the shift.
    """
    if (
        (m := match(exp, ("mask_shl", ":size", 0, ":int:shl", ("storage", Any, 0, ":loc"))))
        and m.shl >= 8
        and exp[4][1] == m.size
    ):
        return ("storage", m.size, 0, m.loc)
    return exp


def _final_cleanup(trace):
    for _ in range(3):
        trace = cleanup_mems(trace)

    trace = cleanup_conds(trace)
    explain("final setmem/condition cleanup", trace)

    # (storage reads keep their offsets: a negative one is never produced,
    # a field moved up is a mask_shl around it, see apply_mask_to_storage)
    trace = cleanup_conds(trace)
    explain("cleaning up storages slightly", trace)

    trace = readability(trace)
    explain("adding nicer variable names", trace)

    return cleanup_mul_1(trace)


@cached
def simplify_exp(exp):
    """
    Simplifies an expression. The result keeps the byte length `exp` has
    when it stands for bytes (memloc.part_width): a word never becomes a
    slice of another length, which would change a payload or a blob.
    """
    res = _simplify_exp(exp)
    if res is not exp and type(exp) == tuple:
        width = self_width(exp)
        if width is None:
            new_width = self_width(res)
            if new_width is not None and sub_op(new_width, 32) != 0:
                res = ("bytes", 32, res)
        elif sub_op(part_width(res), width) != 0:
            res = ("bytes", width, res)
    return res


def _is_zero_blob(exp):
    return opcode(exp) == "data" and all(
        e == 0 or match(e, ("bytes", Any, 0)) for e in exp[1:]
    )


def _simplify_exp(exp):
    if type(exp) == list:
        return exp

    if opcode(exp) == "and":
        _, *terms = exp
        real = 2**256 - 1
        symbols = []
        for t in terms:
            if type(t) == int and t >= 0:
                real = real & t
            elif opcode(t) == "and":
                symbols += t[1:]
            else:
                symbols.append(t)

        if real != 2**256 - 1:
            res = (real,)
        else:
            res = tuple()

        res += tuple(symbols)
        exp = ("and",) + res

    if exp == ("data",):
        return None  # no bytes

    if m := match(exp, ("iszero", ("iszero", ":e"))):
        exp = ("bool", m.e)

    if m := match(exp, ("bool", ("bool", ":e"))):
        exp = ("bool", m.e)

    if (m := match(exp, ("eq", ":sth", 0))) or (m := match(exp, ("eq", 0, ":sth"))):
        exp = ("iszero", m.sth)

    if (
        (m := match(exp, ("mask_shl", ":int:size", 5, 0, ("add", ":int:num", ...))))
        and m.size >= 251
        and m.num % 32 == 31
        and m.num > 32
    ):
        # floor32(32k + 31 + x) == 32k + floor32(31 + x) (mod 2**256)
        add_terms = exp[-1][2:]  # the "..."
        exp = (
            "add",
            32 * (m.num // 32),
            (
                "mask_shl",
                256,
                5,
                0,
                (
                    "add",
                    31,
                )
                + add_terms,
            ),
        )

    if (
        (m := match(exp, ("mask_shl", ":int:size", 5, 0, ("add", 31, ":inner"))))
        and m.size >= 251
        and (mi := match(m.inner, ("mask_shl", ":int:isize", 5, 0, ("add", 31, ...))))
        and mi.isize >= 251
    ):
        # ceil32(ceil32(x)) == ceil32(x): a multiple of 32 plus 31 does not wrap
        exp = m.inner

    if (
        (m := match(exp, ("iszero", ("mask_shl", ":int:size", ":int:off", ":int:shl", ":val"))))
        and m.off >= 0
        and ((m.shl >= 0 and m.off + m.size + m.shl <= 256) or (m.shl < 0 and m.off + m.shl >= 0))
    ):
        exp = ("iszero", ("mask_shl", m.size, m.off, 0, m.val))

    if (
        opcode(exp) in ("iszero", "bool")
        and len(exp) == 2
        and (m := match(exp[1], ("mask_shl", ":int:size", ":int:off", ":int:shl", ":val")))
        and opcode(m.val) == "storage"
        and m.off >= 0
        and ((m.shl >= 0 and m.off + m.size + m.shl <= 256) or (m.shl < 0 and m.off + m.shl >= 0))
    ):
        # a field of a storage word tested against zero (no bit shifted out):
        # the field itself, as when the VM masks the read directly
        field = mask_op(m.val, size=m.size, offset=m.off, shl=-m.off)
        if opcode(field) == "storage":
            exp = (exp[0], field)

    if m := match(exp, ("max", ":single")):
        exp = m.single

    if m := match(exp, ("mem", ("range", Any, 0))):
        return None  # sic. this happens usually in params to logs etc, we probably want None here

    if (
        (m := match(exp, ("mod", ":exp2", ":int:num")))
        and (size := to_exp2(m.num))
        and size > 1
    ):
        return mask_op(m.exp2, size=size)

    if m := match(exp, ("mod", 0, Any)):
        exp = 0

    # same thing is added in both expressions? a + c == b + c iff a == b
    # modulo 2**256; the orderings (lt, gt...) do not cancel (wrap-around)
    if match(exp, ("eq", ("add", ...), ("add", ...))):
        t1, t2 = list(exp[1][1:]), list(exp[2][1:])
        for t in exp[1][1:]:
            if t in t2:
                t1.remove(t)
                t2.remove(t)
        exp = ("eq", add_op(*t1), add_op(*t2))

    if m := match(exp, ("add", ":e")):
        logger.debug("single add")
        return simplify_exp(m.e)

    if m := match(exp, ("mul", 1, ":e")):
        return simplify_exp(m.e)

    if m := match(exp, ("div", ":e", 1)):
        return simplify_exp(m.e)

    if (m := match(exp, ("mask_shl", 256, 0, 0, ":val"))) and self_width(m.val) is None:
        return simplify_exp(m.val)

    if m := match(exp, ("mask_shl", ":size", ":off", ":shl", ("bytes", ":w", ":x"))):
        # a mask of a byte string part: of its word value
        return simplify_exp(mask_op(mask_op(m.x, size=bits(m.w)), m.size, m.off, m.shl))

    if (
        (m := match(exp, ("mask_shl", ":int:size", ":int:off", ":int:shl", ("storage", 256, 0, ":slot"))))
        and m.size > 0
        and m.off >= 0
        and 0 < m.off + m.shl < 8
        and m.size + m.off + m.shl < 256
    ):
        # a narrow storage field shifted by a few bits (x * 2 of a uint32):
        # the field read, then the shift, the shape the VM gives when it
        # masks a read directly. A whole word times 2 (mask_shl(255, 0, 1,
        # w), the shifted field reaching bit 255) stays as it is.
        return ("mask_shl", m.size, 0, m.off + m.shl, ("storage", m.size, m.off, m.slot))

    if m := match(exp, ("mask_shl", ":int:size", ":int:offset", ":int:shl", ":e")):
        exp = mask_op(simplify_exp(m.e), m.size, m.offset, m.shl)

    if m := match(
        exp, ("mask_shl", ":size", 0, 0, ("div", ":expr", ("exp", 256, ":shr")))
    ):
        exp = mask_op(simplify_exp(m.expr), m.size, bits(m.shr), shr=bits(m.shr))

    if (
        m := match(exp, ("mask_shl", Any, Any, ":shl", ("storage", ":size", Any, Any)))
    ) and safe_le_op(m.size, minus_op(m.shl)):
        return 0

    if m := match(exp, ("or", ":sth", 0)):
        return m.sth

    if opcode(exp) == "add":
        terms = exp[1:]
        res = 0
        for el in terms:
            el = simplify_exp(el)
            if opcode(el) == "add":
                for e in el[1:]:
                    res = add_op(res, e)
            else:
                res = add_op(res, el)
        exp = res

    if opcode(exp) == "mask_shl":
        exp = cleanup_mask_data(exp)

    if opcode(exp) == "data":
        return simplify_blob(exp)

    if opcode(exp) == "bytes":
        return simplify_part(exp)

    if opcode(exp) == "sha3" and len(exp) == 2:
        return ("sha3", simplify_bytes(exp[1]))

    if type(exp) == int and to_real_int(exp) > -(
        8**22
    ):  # if it's larger than 30 bytes, it's probably
        # an address, not a negative number
        return to_real_int(exp)

    if m := match(exp, ("and", ":num", ":num2")):
        num = arithmetic.eval(m.num)
        num2 = arithmetic.eval(m.num2)
        if type(num) == int or type(num2) == int:
            return simplify_mask(exp)

    if type(exp) == list:
        r = simplify_exp(tuple(exp))
        return list(r)

    if type(exp) != tuple:
        return exp

    if m := match(
        exp, ("mask_shl", ":int:size", ":int:offset", ":int:shl", ":int:val")
    ):
        return apply_mask(m.val, m.size, m.offset, m.shl)

    if m := match(
        exp,
        ("mask_shl", ":size", 5, ":shl", ("add", 31, ("mask_shl", 251, 0, 5, ":val"))),
    ):
        # 31 + 32 * v: bits 0..4 are the 31, the rest is 32 * v
        return simplify_exp(mask_op(("mask_shl", 251, 0, 5, m.val), m.size, 5, m.shl))

    if opcode(exp) == "mul":
        terms = exp[1:]
        res = 1
        for e in terms:
            res = mul_op(res, simplify_exp(e))

        if m := match(res, ("mul", 1, ":res")):
            res = m.res

        return res

    if opcode(exp) == "max":
        terms = exp[1:]
        els = [simplify_exp(e) for e in terms]
        res = 0
        for e in els:
            res = _max_op(res, e)
        return res

    res = tuple()
    for e in exp:
        res += (simplify_exp(e),)

    if opcode(res) == "setmem" and len(res) == 3 and _is_zero_blob(res[2]):
        res = (res[0], res[1], 0)  # zero bytes, whatever the length

    return res


def simplify_mask(exp):
    op = opcode(exp)

    if op in arithmetic.OPCODES:
        exp = arithmetic.eval(exp)

    if m := match(exp, ("and", ":left", ":right")):
        left, right = m.left, m.right

        if mask := to_mask(left):
            exp = mask_op(right, *mask)

        elif mask := to_mask(right):
            exp = mask_op(left, *mask)

        elif bounds := to_neg_mask(left):
            exp = neg_mask_op(right, *bounds)

        elif bounds := to_neg_mask(right):
            exp = neg_mask_op(left, *bounds)

    elif (m := match(exp, ("div", ":left", ":int:right"))) and (
        shift := to_exp2(m.right)
    ):
        exp = mask_op(m.left, size=256 - shift, offset=shift, shr=shift)

    elif (m := match(exp, ("mul", ":int:left", ":right"))) and (
        shift := to_exp2(m.left)
    ):
        exp = mask_op(m.right, size=256 - shift, shl=shift)

    elif (m := match(exp, ("mul", ":left", ":int:right"))) and (
        shift := to_exp2(m.right)
    ):
        exp = mask_op(m.left, size=256 - shift, shl=shift)

    return exp


def cleanup_mask_data(exp):
    # if there is a mask over some data,
    # it removes pieces of data that for sure won't
    # fit into the mask (doesn't truncate if something)
    # partially fits
    # e.g. mask(200, 8, 8 data(123, ("bytes", 25, sth), ("bytes", 1, sth_else)))
    #      -> mask(200, 0, 16, ("bytes", 25, sth)))
    # Element widths are exact (memloc.part_width): a plain word is 32 bytes.

    def _cleanup_right(exp):
        # removes elements that are cut off by offset
        m = match(exp, ("mask_shl", ":size", ":offset", ":shl", ":val"))
        assert m
        size, offset, shl, val = m.size, m.offset, m.shl, m.val

        if opcode(val) != "data":
            return exp

        last = bits(part_width(val[-1]))
        if safe_le_op(last, offset) is True:
            offset = sub_op(offset, last)
            shl = add_op(shl, last)
            if len(val) == 3:
                val = val[1]
            else:
                val = val[:-1]

            return mask_op(val, size, offset, shl)

        return exp

    def _cleanup_left(exp):
        # removes elements that are cut off by size+offset
        m = match(exp, ("mask_shl", ":size", ":offset", ":shl", ":val"))
        assert m
        size, offset, shl, val = m.size, m.offset, m.shl, m.val

        if opcode(val) != "data":
            return exp

        total_size = add_op(size, offset)  # simplify_exp

        sum_sizes = 0
        val = list(val[1:])
        res = []
        while len(val) > 1:
            last = val.pop()
            sum_sizes = simplify_exp(add_op(sum_sizes, bits(part_width(last))))
            res.insert(0, last)
            if safe_le_op(total_size, sum_sizes) is True:
                return exp[:4] + (("data",) + tuple(res),)

        return exp

    assert opcode(exp) == "mask_shl"

    prev_exp = None
    while prev_exp != exp:
        prev_exp = exp
        exp = _cleanup_right(exp)

    prev_exp = None
    while prev_exp != exp:
        prev_exp = exp
        exp = _cleanup_left(exp)

    if match(exp, ("mask_shl", 256, 0, 0, ("data", ...))):
        # a whole word of data is the data itself (both 32 bytes)
        if sub_op(part_width(exp[4]), 32) == 0:
            return exp[4]

    return exp


def simplify_part(exp):
    """
    One element of a byte string (a data blob part or a whole payload),
    simplified without changing its byte length (memloc.part_width): a
    rewrite that gives an expression of another length is width-tagged.
    """
    if exp is None:
        return None

    if opcode(exp) == "data":
        return simplify_blob(exp)

    if opcode(exp) == "bytes":
        width = simplify_exp(exp[1])
        val = simplify_exp(exp[2])
        if type(width) == int and type(val) == int and width > 0:
            if val < 0:
                val %= 2**256  # a word
            if 8 * width < val.bit_length():  # bounded by the value itself
                val %= 1 << (8 * width)
        return with_width(val, width)

    width = part_width(exp)
    res = simplify_exp(exp)
    if sub_op(part_width(res), width) != 0:
        res = ("bytes", width, res)
    return res


def simplify_bytes(exp):
    """A byte string expression (payload of a return, revert, log, sha3,
    call...) simplified without changing its length."""
    return simplify_part(exp)


def _merge_parts(left, right):
    """Two adjacent blob parts as one when they are pieces of the same word
    (or constants), else None."""
    if opcode(left) != "bytes" or opcode(right) != "bytes":
        return None
    w1, a = left[1], left[2]
    w2, b = right[1], right[2]
    if type(w1) != int or type(w2) != int or w1 + w2 > 32:
        return None
    if type(a) == int and type(b) == int:
        return with_width((a << (8 * w2)) + b, w1 + w2)
    ma = match(a, ("mask_shl", ":size", ":off", ":shl", ":val"))
    mb = match(b, ("mask_shl", ":size", ":off", ":shl", ":val"))
    if (
        ma
        and mb
        and ma.val == mb.val
        and ma.size == 8 * w1
        and mb.size == 8 * w2
        and type(mb.off) == int
        and ma.off == mb.off + 8 * w2
        and ma.shl == -ma.off
        and mb.shl == -mb.off
    ):
        merged = mask_op(ma.val, size=8 * (w1 + w2), offset=mb.off, shr=mb.off)
        return with_width(merged, w1 + w2)
    return None


def simplify_blob(exp):
    """("data", ...): parts simplified with their widths kept, nested blobs
    flattened, empty parts dropped, pieces of one word merged back."""
    parts = []
    for e in exp[1:]:
        e = simplify_part(e)
        if e is None:
            continue
        if opcode(e) == "data":
            parts.extend(e[1:])
        else:
            parts.append(e)

    merged = []
    for e in parts:
        if merged and (m := _merge_parts(merged[-1], e)) is not None:
            merged[-1] = m
        else:
            merged.append(e)

    if len(merged) == 0:
        return None
    if len(merged) == 1:
        return merged[0]
    return ("data",) + tuple(merged)


def replace_while_var(rest, counter_idx, new_idx):
    while contains(rest, ("var", new_idx)):
        new_idx += 1

    def r(exp):
        if exp == ("var", counter_idx):
            return ("var", new_idx)

        elif m := match(exp, ("setvar", counter_idx, ":val")):
            return ("setvar", new_idx, m.val)

        else:
            return exp

    return simplify_exp(replace_f(rest, r)), new_idx


def canonise_max(exp):
    if opcode(exp) == "max":
        args = []
        for e in exp[1:]:
            if m := match(e, ("mul", 1, ":num")):
                args.append(m.num)
            else:
                args.append(e)

        args.sort(key=lambda x: str(x) if type(x) != int else " " + str(x))
        return ("max",) + tuple(args)
    else:
        return exp


def readability(trace):
    """
    - replaces variable names with nicer ones,
    - fixes empty memory in calls
    - replaces 'max..' in setmems with msize variable
        (max can only appear because of this)
    """

    trace = replace_f(trace, canonise_max)

    res = []
    for idx, line in enumerate(trace):
        if m := match(line, ("setmem", ("range", ("add", ...), Any), ":mem_val")):
            add_params = line[1][1][1:]  # the "..."
            for m in add_params:
                if opcode(m) == "max":
                    res.append(("setvar", "_msize", m))

                    def x(line):
                        return [replace(line, m, ("var", "_msize"))]

                    rest = rewrite_trace(trace[idx:], x)
                    res.extend(readability(rest))
                    return res

        elif m := match(line, ("if", ":cond", ":if_true", ":if_false")):
            cond, if_true, if_false = m.cond, m.if_true, m.if_false

            # if if_false ~ [('revert', ...)]: # no lists in Tilde... yet :,)
            if len(if_false) == 1 and opcode(if_false[0]) == "revert":
                res.append(
                    ("if", is_zero(cond), readability(if_false), readability(if_true))
                )
            else:
                res.append(("if", cond, readability(if_true), readability(if_false)))

            continue

        elif opcode(line) == "while":
            # for whiles, normalize variable names

            a = parse_counters(line)

            rest = trace[idx:]

            if "counter" in a:
                counter_idx = a["counter"]
                rest, _ = replace_while_var(rest, counter_idx, 0)

            else:
                counter_idx = -1

            new_idx = 1

            cond, path, jds, vars = line[1:]

            for _, v_idx, _ in vars:
                if v_idx != counter_idx:
                    rest, new_idx = replace_while_var(rest, v_idx, new_idx)

            line, rest = rest[0], rest[1:]
            cond, path, jds, vars = line[1:]

            path = readability(path)
            res.append(("while", cond, path, jds, vars))

            res.extend(readability(rest))
            return res

        res.append(line)

    return res


def replace_bytes_or_string_length(trace):
    # see unicorn contract, version/name

    def replace(expr):
        m = match(
            expr,
            (
                "mask_shl",
                ":size",
                ":offset",
                -1,
                (
                    "and",
                    ("storage", Any, 0, ":key"),
                    (
                        "add",
                        -1,
                        (
                            "mask_shl",
                            Any,
                            Any,
                            Any,
                            ("iszero", ("storage", Any, 0, ":key")),
                        ),
                    ),
                ),
            ),
        ) or match(
            expr,
            (
                "mask_shl",
                ":size",
                ":offset",
                -1,
                (
                    "and",
                    (
                        "add",
                        -1,
                        (
                            "mask_shl",
                            Any,
                            Any,
                            Any,
                            ("iszero", ("storage", Any, 0, ":key")),
                        ),
                    ),
                    ("storage", Any, 0, ":key"),
                ),
            ),
        )
        if not m:
            return
        key, size, offset = m.key, m.size, m.offset

        if type(key) == int:
            key = ("loc", key)

        if size == 255 and offset == 1:
            return ("storage", 256, 0, ("length", key))
        assert offset >= 1
        return ("mask_shl", size, offset - 1, 0, ("storage", 256, 0, ("length", key)))

    return replace_f_stop(trace, replace)


def loop_to_setmem(line):
    if opcode(line) == "while":
        r = _loop_to_setmem(line)

        if r is not None:
            return r

        r = loop_to_setmem_from_storage(line)

        if r is not None:
            return r

    return [line]


def vars_in_expr(expr):
    if m := match(expr, ("var", ":var_id")):
        return frozenset([m.var_id])

    s = frozenset()

    if type(expr) not in (tuple, list):
        return s

    for e in expr:
        s = s | vars_in_expr(e)
    return s


def only_add_in_expr(op):
    if m := match(op, ("setvar", ":idx", ":val")):
        return only_add_in_expr(m.val)
    if opcode(op) == "add":
        terms = op[1:]
        return all(only_add_in_expr(o) for o in terms)
    if match(op, ("var", Any)):
        return True
    if m := match(op, ("sha3", ":term")):  # sha3(constant) is allowed.
        return opcode(m.term) is None
    if opcode(op) is not None:
        return False
    return True


def _loop_body_writes(path, jd):
    """
    What the body `path` of the loop `jd` assigns: (updates, assigned,
    closed). `updates` are the setvars of its continue lines, at any depth;
    `assigned` the variables set by any other line (nested loop headers
    included); `closed` is False when a continue leaves for an outer loop or
    the body holds an unstructured label.
    """
    updates, assigned, targets, loops = [], set(), set(), {jd}
    closed = True

    def walk(lines):
        nonlocal closed
        for line in lines:
            op = opcode(line)
            if op == "continue":
                targets.add(line[1])
                updates.extend(line[2])
            elif op == "setvar":
                assigned.add(line[1])
            elif op == "if":
                walk(line[2])
                walk(line[3])
            elif op == "while":
                loops.add(line[3])
                assigned.update(sv[1] for sv in line[4])
                walk(line[2])
            elif op == "label":
                closed = False

    walk(path)
    return updates, assigned, closed and targets <= loops


def propagate_storage_in_loop(line):
    """
    Rebases a loop variable that starts at `X + sha3(K)` (an index into the
    data of a storage array) to start at X, so that the storage parser sees
    `sha3(K) + index` in the loop: the loop gets a fresh variable that starts
    at X, the loop reads `fresh + sha3(K)` where it read the variable, and a
    `setvar var = fresh + sha3(K)` right after the loop gives the rest of the
    function the value it reads.

    Only done when this keeps the semantics: sha3(K) has the same value in
    every iteration, every update of the variable (the continue setvars) is
    `var + terms` and no update of another variable reads it, no other line
    of the body assigns it, and every continue goes back to this loop or to
    one nested in it.
    """
    op, cond, path, jds, setvars = line
    assert op == "while"

    def storage_sha3(value):
        if opcode(value) == "add":
            terms = value[1:]
            for op in terms:
                if storage_sha3(op) is not None:
                    return storage_sha3(op)

        if m := match(value, ("sha3", ":val")):
            if type(m.val) != int or m.val < 1000:  # used to be int:val here, why?
                return value

    updates, assigned, closed = _loop_body_writes(path, jds)
    if not closed:
        return None
    changed = assigned | {sv[1] for sv in setvars} | {sv[1] for sv in updates}

    def self_updates(var_id):
        # the variable only moves by `var + terms` (terms not reading it)
        for sv in updates:
            if sv[1] != var_id:
                if contains(sv[2], ("var", var_id)):
                    return False
                continue
            value = sv[2]
            if opcode(value) != "add" or ("var", var_id) not in value[1:]:
                return False
            rest = list(value[1:])
            rest.remove(("var", var_id))
            if contains(rest, ("var", var_id)):
                return False
        return True

    new_setvars, restores = [], []

    for setvar in setvars:
        op, var_id, value = setvar
        assert op == "setvar"

        sha3 = storage_sha3(value)
        if (
            not sha3
            or not _loop_invariant(line, sha3, {})
            or var_id in assigned
            or not self_updates(var_id)
        ):
            new_setvars.append(setvar)
            continue

        fresh = f"r{var_id}"
        if contains(line, ("var", fresh)) or fresh in changed:
            new_setvars.append(setvar)
            continue

        new_setvars.append(("setvar", fresh, sub_op(value, sha3)))
        restores.append(("setvar", var_id, add_op(("var", fresh), sha3)))

        def rebase(t, var_id=var_id, fresh=fresh, sha3=sha3):
            if t == ("var", var_id):
                return add_op(("var", fresh), sha3)
            if opcode(t) == "continue":
                svs = [
                    ("setvar", fresh, replace(sv[2], ("var", var_id), ("var", fresh)))
                    if sv[1] == var_id
                    else sv
                    for sv in t[2]
                ]
                return (t[0], t[1], type(t[2])(svs)) + tuple(t[3:])

        path = replace_f_stop(path, rebase)
        cond = replace_f_stop(cond, rebase)

    if not restores:
        return None

    return [("while", cond, path, jds, new_setvars)] + restores


def propagate_storage_in_loops(trace):
    def touch(line):
        if opcode(line) == "while":
            r = propagate_storage_in_loop(line)
            if r is not None:
                return r

        return [line]

    return rewrite_trace(trace, touch)


def _loop_to_setmem(line):
    def memidx_to_memrange(mem_idx, setvars, stepvars, endvars):
        mem_idx_next = mem_idx
        for v in stepvars:
            op, v_idx, v_val = v
            assert op == "setvar"
            mem_idx_next = replace(mem_idx_next, ("var", v_idx), v_val)

        diff = sub_op(mem_idx_next, mem_idx)

        if diff not in (32, -32):
            return None, None

        mem_idx_last = mem_idx
        for v_idx, v_val in endvars.items():
            mem_idx_last = replace(mem_idx_last, ("var", v_idx), v_val)

        mem_idx_first = mem_idx
        for v in setvars:
            op, v_idx, v_val = v
            assert op == "setvar"

            mem_idx_first = replace(mem_idx_first, ("var", v_idx), v_val)

        if diff == 32:
            mem_len = sub_op(mem_idx_last, mem_idx_first)

            return ("range", mem_idx_first, mem_len), diff

        else:
            assert diff == -32

            mem_idx_last = add_op(32, mem_idx_last)
            mem_idx_first = add_op(32, mem_idx_first)

            mem_len = sub_op(mem_idx_first, mem_idx_last)

            return ("range", mem_idx_last, mem_len), diff

    op, cond, path, jds, setvars = line
    assert op == "while"

    if len(path) != 2:
        return None

    if opcode(path[1]) != "continue":
        return None

    if opcode(path[0]) != "setmem":
        return None

    setmem = path[0]
    cont = path[1]

    mem_idx, mem_val = setmem[1], setmem[2]

    op, i, l = mem_idx
    assert op == "range"
    if l != 32:
        return None
    mem_idx = i

    stepvars = cont[2]

    a = parse_counters(line)
    if "memvars" not in a:
        return None

    setvars, endvars = a["setvars"], a["memvars"]

    rng, diff = memidx_to_memrange(mem_idx, setvars, stepvars, endvars)

    if rng is None:
        return None

    if mem_val == 0:
        res = [("setmem", rng, 0)]

    elif opcode(mem_val) == "mem":
        mem_val_idx = mem_val[1]
        op, i, l = mem_val_idx
        assert op == "range"
        mem_val_idx = i
        if l != 32:
            return None

        val_rng, val_diff = memidx_to_memrange(mem_val_idx, setvars, stepvars, endvars)

        if val_rng is None:
            return None

        if val_diff != diff:
            return None  # possible but unsupported

        # we should check for overwrites here, but skipping for now
        # if the part of memcopy loop overwrites source before it's copied,
        # we can end up with unexpected behaviour, could at least show some warning,
        # or set that mem to 'complicated' or sth

        res = [("setmem", rng, ("mem", val_rng))]

    else:
        return None

    for v_idx, v_val in endvars.items():
        res.append(("setvar", v_idx, v_val))

    return res


def loop_to_setmem_from_storage(line):
    assert opcode(line) == "while"
    cond, path, jds, setvars = line[1:]

    if len(path) != 2 or opcode(path[0]) != "setmem" or opcode(path[1]) != "continue":
        return None

    setmem = path[0]
    cont = path[1]

    logger.debug("loop_to setmem_from_storage: %s\n%s\n%s", setmem, cont, cond)

    # (setmem, mem_idx, mem_val)
    mem_idx, mem_val = setmem[1], setmem[2]

    # Extract the interesting variable from mem_idx
    vars_in_idx = vars_in_expr(mem_idx)
    if len(vars_in_idx) != 1:
        return
    if not only_add_in_expr(mem_idx):
        return
    memory_index_var = next(iter(vars_in_idx))

    # Same from mem_val
    vars_in_val = vars_in_expr(mem_val)
    if len(vars_in_val) != 1:
        return
    storage_key_var = next(iter(vars_in_val))
    if opcode(mem_val) != "storage":
        return
    if mem_val[1] != 256 or mem_val[2] != 0:
        return
    storage_key = mem_val[3]
    if not only_add_in_expr(storage_key):
        return

    logger.debug("now look at the continue")
    update_memory_index = (
        "setvar",
        memory_index_var,
        ("add", 32, ("var", memory_index_var)),
    )
    update_storage_key = (
        "setvar",
        storage_key_var,
        ("add", 1, ("var", storage_key_var)),
    )
    if set(cont[2]) != {update_memory_index, update_storage_key}:
        return

    logger.debug("setvars")
    memory_index_start = None
    storage_key_start = None
    memory_index_init = None
    for setvar in setvars:
        if setvar[1] == memory_index_var:
            memory_index_start = replace(mem_idx, ("var", memory_index_var), setvar[2])
            memory_index_init = setvar[2]
        elif setvar[1] == storage_key_var:
            storage_key_start = replace(
                storage_key, ("var", storage_key_var), setvar[2]
            )
        else:
            return

    logger.debug("while condition")
    if memory_index_var not in vars_in_expr(cond):
        return
    if opcode(cond) != "gt":
        return

    mem_count = ("add", cond[1], ("mul", -1, cond[2]))
    mem_count = replace(mem_count, ("var", memory_index_var), memory_index_init)

    mem_rng = ("range", memory_index_start, mem_count)
    storage_rng = ("range", storage_key_start, ("div", mem_count, 32))

    logger.debug("mem_rng: %s, storage_rng: %s", mem_rng, storage_rng)
    return [("setmem", mem_rng, ("storage", 256, 0, storage_rng))]


"""

    simplifier

"""


def apply_constraint(exp, constr):
    # for constraints like "isZero XX % 32", applies them to expression

    return exp

    if match(constr, ("mask_shl", 5, 0, 0, Any)):

        def f(x):
            if m := match(
                x, ("mask_shl", ":int:size", 5, ":int:shl", ("add", 31, ":val"))
            ):
                return ("add", 32 * (2**m.shl), ("mask_shl", m.size, 5, m.shl, m.val))
            if m := match(x, ("mask_shl", ":int:size", 5, 0, ":val")):
                return ("mask_shl", m.size, 5, 0, m.val)

            return x

        return replace_f(exp, f)

    if match(constr, ("iszero", ("mask_shl", 5, 0, 0, Any))):

        def f(x):
            if m := match(x, ("mask_shl", ":int:size", 5, 0, ("add", 31, ":val"))):
                return ("mask_shl", m.size + 5, 0, 0, m.val)
            if m := match(x, ("mask_shl", ":int:size", 5, 0, ":val")):
                return ("mask_shl", m.size + 5, 0, 0, m.val)
            if match(x, ("mask_shl", 5, 0, 0, ":val")):
                return 0

            return x

        return replace_f(exp, f)

    return exp


def cleanup_conds(trace):
    """

    removes ifs/whiles with conditions that are obviously true
    and replace variables that need to be equal to a constant by that constant

    """

    res = []

    for line in trace:
        if opcode(line) == "while":
            _, cond, path, jds, setvars = line
            # we're not evaluating symbolically, otherwise stuff like
            # stor0 <= stor0 + 1 gets evaluated to `True` - this happens
            # because we're truncating mask256. it should really be
            # mask(256, stor0) <= mask(256, stor0 + 1)
            # which is not always true
            # see 0x014B50466590340D41307Cc54DCee990c8D58aa8.transferFrom
            path = cleanup_conds(path)
            ev = arithmetic.eval_bool(cond, symbolic=False)
            if ev is True:
                res.append(("while", ("bool", 1), path, jds, setvars))
            elif ev is False:
                pass  # removing loop altogether
            else:
                res.append(("while", cond, path, jds, setvars))

        elif opcode(line) == "if":
            _, cond, if_true, if_false = line
            if_true = cleanup_conds(if_true)
            if_false = cleanup_conds(if_false)

            # If the condition is always true/false, remove the if.
            ev = arithmetic.eval_bool(cond, symbolic=False)
            if ev is True:
                res.extend(if_true)
            elif ev is False:
                res.extend(if_false)
            else:
                res.append(("if", cond, if_true, if_false))

        else:
            res.append(line)

    return res


def sizeof(exp):  # returns size of expression in *bits*
    if m := match(exp, ("storage", ":size", ...)):
        return m.size

    if m := match(exp, ("mask_shl", ":size", ...)):
        return m.size

    if (m := match(exp, (":op", Any, ":size_bytes"))) and is_array(m.op):
        return bits(m.size_bytes)

    if m := match(exp, ("mem", ("range", Any, ":size_bytes"))):
        return bits(m.size_bytes)

    assert not match(exp, ("mem", ":idx"))

    return None


@cached
def find_mems(exp):
    def f(exp):
        if opcode(exp) == "mem":
            return set([exp])
        else:
            return set()

    return find_f_set(exp, f)


def _eval_msize(cond):
    if opcode(cond) not in ("lt", "le", "gt", "ge"):
        return None

    left, right = cond[1], cond[2]

    if opcode(left) != "max" and opcode(right) != "max":
        return None

    if opcode(left) == "max" and opcode(right) == "max":
        return None

    if opcode(right) == "max":
        cond = swap_cond(cond)
        left, right = cond[1], cond[2]

    assert opcode(left) == "max"

    if opcode(cond) in ("lt", "le"):
        if opcode(cond) == "le":
            cond = ("lt", left, add_op(1, right))
            left, right = cond[1], cond[2]

        # max(2,3) <= 3
        # max(2,3) < 4

        # cond == (lt, max(....), right)
        # any .... > right -> True
        # any .... ? right -> ?
        # else -> all ... < right -> False

        if all([safe_lt_op(l, right) is True for l in left[1:]]):
            return False

        if any([safe_lt_op(right, l) is False for l in left[1:]]):
            return False

        if all([safe_le_op(right, l) is True for l in left[1:]]):
            return True

    if opcode(cond) in ("gt", "ge"):
        assert False, cond  # unsupported yet

    return None


def cleanup_msize(trace, current_msize=0):
    if "msize" not in str(trace):
        # the running maximum of written memory only replaces MSIZE reads:
        # without them, computing it is wasted (and costly) work
        return trace

    res = []

    for line in trace:
        if opcode(line) == "setmem":
            line = replace(line, "msize", current_msize)

            mem_right = memloc_right(line)

            current_msize = _max_op(current_msize, mem_right)

            res.append(line)

        elif opcode(line) == "while":
            new_one = while_max_memidx(line)
            current_msize = _max_op(current_msize, new_one)
            res.append(line)

        elif opcode(line) == "if":
            cond, if_true, if_false = line[1:]
            if "msize" in str(cond) and opcode(current_msize) == "max":
                tmp_cond = replace(cond, "msize", current_msize)

                tmp_evald = _eval_msize(tmp_cond)

                if tmp_evald is not None:
                    cond = 1 if tmp_evald is True else 0

            else:
                new_msize = max_to_add(current_msize)
                cond = replace(cond, "msize", new_msize)

            if_true = cleanup_msize(if_true, current_msize)
            if_false = cleanup_msize(if_false, current_msize)
            res.append(("if", cond, if_true, if_false))

        else:
            line = replace(line, "msize", current_msize)
            res.append(line)

    #    print('done')
    return res


def overwrites_mem(line, mem_idx):
    """
    for a given line, returns True if it potentially
    overwrites *any part* of memory index, False if it *for sure* doesn't

    """
    if m := match(line, ("setmem", ":set_idx", Any)):
        return range_overlaps(m.set_idx, mem_idx) is not False

    if opcode(line) == "while":
        return while_touches_mem(line, mem_idx)

    return False


def affects(line, exp):
    """True when `line` can give `exp` another value: a write to memory that
    `exp` reads, or a change of the state it reads (storage, balances, call
    results..., see core/effects.py)."""
    if clobbers(line, exp):
        return True

    if type(exp) != tuple and exp != "msize":
        return False

    s = str(exp)

    if "msize" in s:
        if overwrites_mem(line, ("range", 0, "undefined")):
            return True

    if "mem" not in s:
        return False

    mems = find_mems(exp)

    for m in mems:
        m_idx = m[1]
        if overwrites_mem(line, m_idx):
            return True

    return False


def _kept_in_memory(trace, var_id, var_val):
    """True when the variable var_id, bound to a time-dependent read var_val
    (see core/effects.py), is written to memory that is read again after a
    line that changes var_val: there the inlined read would mean the new
    value. Such a variable is kept everywhere, so that memory addresses
    computed from it stay comparable."""
    if not kinds(var_val):
        return False

    def used_after_change(trace, rng):
        for i, line in enumerate(trace):
            if opcode(line) == "if":
                return used_after_change(line[2], rng) or used_after_change(line[3], rng)
            if affects(line, var_val):
                # the operands of a store or a call are read before its effect
                start = i if opcode(line) == "while" else i + 1
                return trace_uses_mem(trace[start:], rng)
        return False

    def check(trace):
        for i, line in enumerate(trace):
            if opcode(line) == "if":
                return check(line[2]) or check(line[3])
            if opcode(line) == "setmem" and contains(line, var_id):
                rng = line[1]
                if opcode(rng) != "range" or used_after_change(trace[i + 1 :], rng):
                    return True
            if affects(line, var_val):
                return False
        return False

    return check(trace)


def narrow_snapshots(trace):
    """A storage word read into a variable (`setvar _N (storage 256 0 slot)`)
    of which every use takes a field (mask_shl(size, off, -off, _N)): the
    variable holds that field, ("storage", size, off, slot), as a direct read
    of the field would; with several fields, one variable per field
    (`_N_<off>`), all read at the same place."""
    res = []
    for idx, line in enumerate(trace):
        if (
            (m := match(line, ("setvar", ":name", ("storage", 256, 0, ":slot"))))
            and type(m.name) == str
            and (fields := _fields_used(trace[idx + 1 :], ("var", m.name)))
        ):
            var = ("var", m.name)
            rest = trace[idx + 1 :]
            for size, off in sorted(fields):
                name = m.name if len(fields) == 1 else "%s_%d_%d" % (m.name, off, size)
                res.append(("setvar", name, ("storage", size, off, m.slot)))
                rest = replace(rest, ("mask_shl", size, off, -off, var), ("var", name))
            res.extend(narrow_snapshots(rest))
            return res
        if opcode(line) == "if":
            line = ("if", line[1], narrow_snapshots(line[2]), narrow_snapshots(line[3]))
        elif opcode(line) == "while":
            line = line[:2] + (narrow_snapshots(line[2]),) + line[3:]
        res.append(line)
    return res


def _fields_used(trace, var):
    """The fields (size, off) of `var` that `trace` uses, when every use is
    mask_shl(size, off, -off, var) with constants (off < 256) and the
    variable is not bound again (a loop header read); else None."""
    fields = set()

    def walk(e):
        if e == var:
            return False  # a use of the whole word
        if type(e) not in (tuple, list):
            return True
        if type(e) == tuple and len(e) == 3 and e[0] == "setvar" and e[1] == var[1]:
            return False  # bound again: the two bindings must stay alike
        if (
            type(e) == tuple
            and len(e) == 5
            and e[0] == "mask_shl"
            and e[4] == var
            and type(e[1]) == int
            and type(e[2]) == int
            and e[3] == -e[2]
            and 0 < e[1]
            and 0 <= e[2] < 256
        ):
            fields.add((e[1], e[2]))
            return True
        return all(walk(x) for x in e)

    if not walk(trace) or not fields:
        return None
    return fields


def trace_affects(trace, exp):
    """True when a line of `trace`, or of the branches of its ifs, can give
    `exp` another value."""
    for line in trace:
        if affects(line, exp):
            return True
        if opcode(line) == "if" and (
            trace_affects(line[2], exp) or trace_affects(line[3], exp)
        ):
            return True
    return False


def _stops_at_label(rest, exps):
    """A `label` line starts a loop body that runs again after each
    `continue`: a value from before the label can only be moved into it
    when nothing in the rest of the trace changes it."""
    return any(trace_affects(rest, e) for e in exps)


def _rebinds(path, var_idx):
    """The values the lines of `path` (branches and the setvars of continues
    included) bind the variable var_idx to again."""
    return find_f_list(path, lambda l: [l[2]] if opcode(l) == "setvar" and l[1] == var_idx else [])


"""

    Memory cleanup

"""


def trace_uses_mem(trace, mem_idx):
    """

    checks if memory is used anywhere in the trace

    """

    for idx, line in enumerate(trace):
        if m := match(line, ("setmem", ":memloc", ":memval")):
            memloc, memval = m.memloc, m.memval
            memval = simplify_exp(memval)

            # a read of mem_idx in the value or in the address of the write
            if exp_uses_mem(memval, mem_idx) or exp_uses_mem(memloc, mem_idx):
                return True

            if affects(line, mem_idx):
                # the write changes memory the address of mem_idx is computed
                # from: later, the same expression names other bytes
                return True

            split = memloc_overwrite(
                mem_idx, memloc
            )  # returns range that we're confident wasn't overwritten by memloc
            res2 = trace[idx + 1 :]
            for s_idx in split:
                if trace_uses_mem(res2, s_idx):
                    return True

            return False

        elif opcode(line) == "while":
            if while_uses_mem(line, mem_idx) or affects(line, mem_idx):
                return True

        elif m := match(line, ("if", ":cond", ":if_true", ":if_false")):
            if (
                exp_uses_mem(m.cond, mem_idx)
                or trace_uses_mem(m.if_true, mem_idx)
                or trace_uses_mem(m.if_false, mem_idx)
            ):
                return True

        elif opcode(line) == "continue":
            return True

        else:
            if exp_uses_mem(line, mem_idx):
                return True

    return False


def cleanup_mems(trace, known=None):
    """
    for every setmem, replace future occurences of it with it's value,
    if possible

    known: temporaries bound above to stable values (see replace_mem)
    """
    known = dict(known or {})

    if _out_of_time():
        return trace  # the rest stays as it is (exact, see _deadline)

    if len(trace) > MAX_MEM_CLEANUP_TRACE_LEN:
        logger.debug(
            "cleanup_mems skipped (trace len %s > %s)",
            len(trace),
            MAX_MEM_CLEANUP_TRACE_LEN,
        )
        return trace

    res = []

    for idx, line in enumerate(trace):
        if match(line, ("setmem", ":rng", ("mem", ":rng"))):
            continue

        if m := match(line, ("setmem", ":mem_idx", ":mem_val")):
            mem_idx, mem_val = m.mem_idx, m.mem_val

            # find all the future occurences of var and replace if possible
            if affects(line, mem_val):
                remaining_trace = trace[idx + 1 :]
            else:
                # The following line is the cause for O(N^2) complexity,
                # as here we iterate over the trace, and below we call `replace_mem`
                # over everything that's left in the trace.
                remaining_trace = replace_mem(trace[idx + 1 :], mem_idx, mem_val, known)

            if trace_uses_mem(remaining_trace, mem_idx):
                res.append(line)

            res.extend(cleanup_mems(remaining_trace, known))

            break

        elif opcode(line) == "while":
            _, cond, path, *rest = line
            path = cleanup_mems(path, known)
            res.append(
                (
                    "while",
                    cond,
                    path,
                )
                + tuple(rest)
            )

        elif opcode(line) == "if":
            _, cond, if_true, if_false = line
            if_true = cleanup_mems(if_true, known)
            if_false = cleanup_mems(if_false, known)
            res.append(("if", cond, if_true, if_false))

        else:
            _learn_var(line, known)
            res.append(line)

    return res


@cached
def replace_mem_exp(exp, mem_idx, mem_val):
    if type(exp) != tuple:
        return exp

    res = tuple(
        replace_mem_exp(e, mem_idx, mem_val) if type(e) == tuple else e for e in exp
    )

    if res != exp:
        res = simplify_exp(res)

    if opcode(res) == "mem":
        assert len(res) == 2
        res = fill_mem(res, mem_idx, mem_val)

    return res


# values that do not depend on memory, storage, calls or other variables:
# a temporary bound to one of them names the same word anywhere later
_STATEFUL_ATOMS = ("mem", "storage", "var", "ext_call", "returndatasize", "return_data",
                   "balance", "tload", "msize", "gas", "code.data", "extcode", "create")


def _stable_value(exp):
    s = str(exp)
    return not any(a in s for a in _STATEFUL_ATOMS)


def _known_vars(exp, known):
    """`exp` with the temporaries of `known` replaced by their values."""
    if not known:
        return exp
    return replace_f(exp, lambda e: known.get(e[1], e) if opcode(e) == "var" else e)


def _learn_var(line, known):
    """Records a temporary ("_N", assigned once) bound to a stable value."""
    if (m := match(line, ("setvar", ":name", ":val"))) and type(m.name) == str:
        val = simplify_exp(_known_vars(m.val, known))
        if _stable_value(val):
            known[m.name] = val
        else:
            known.pop(m.name, None)


def replace_mem(trace, mem_idx, mem_val, known=None):
    """

    replaces any reference to mem_idx in the trace
    with a value of mem_val, up until a point of that mem being
    overwritten

    mem[64] = 'X'
    log mem[64]
    mem[65] = 'Y'
    log mem[64 len 1]
    log mem[65]
    mem[63] = 'Z'
    ...

    into

    mem[64] = 'X'
    log 'X'
    mem[65] = 'Y'
    log mask(1, 'X')
    log mem[65]
    ... (the rest unchanged)

    """
    if _out_of_time():
        return trace  # nothing replaced: the caller keeps the write (exact)

    mem_idx = simplify_exp(mem_idx)
    mem_val = simplify_exp(mem_val)
    mem_id = ("mem", mem_idx)
    # temporaries ("_N", assigned once) bound above to stable values: the
    # addresses written below are compared with mem_idx through them
    known = dict(known or {})

    if type(mem_val) is tuple and opcode(mem_val) != "mem":
        mem_val = arithmetic.eval(mem_val)

    res = []

    for idx, line in enumerate(trace):
        if match(line, ("setmem", Any, Any)):
            # replace in the address and the value: both are computed before
            # the write, when mem_idx still holds mem_val
            line = replace_mem_exp(line, mem_idx, mem_val)
            res.append(line)
            memloc = simplify_exp(line[1])
            # None: cannot tell, the write may overwrite mem_idx (splits_mem
            # keeps only the bytes it is sure were not overwritten). The test
            # sees through the known temporaries.
            if range_overlaps(memloc, mem_idx) is not False and (
                not known
                or range_overlaps(
                    simplify_exp(_known_vars(memloc, known)),
                    simplify_exp(_known_vars(mem_idx, known)),
                )
                is not False
            ):
                split = splits_mem(mem_idx, memloc, mem_val)
                res2 = trace[idx + 1 :]
                for s in split:
                    # a piece whose value or address reads memory this write
                    # changes means something else past it (e.g. a copy of
                    # bytes the write overwrites)
                    if not (
                        affects(line, mem_idx)
                        or affects(line, s[0])
                        or affects(line, s[1])
                    ):
                        res2 = replace_mem(res2, s[0], s[1])

                res.extend(res2)
                return res
            # the write changes what mem_val or the address of mem_idx are
            # computed from: later expressions mean other values
            if affects(line, mem_val) or affects(line, mem_idx):
                res.extend(copy(trace[idx + 1 :]))
                return res

        elif opcode(line) == "label" and _stops_at_label(trace[idx + 1 :], (mem_val, mem_id)):
            res.extend(copy(trace[idx:]))
            return res

        elif affects(line, mem_val) or affects(line, mem_id):
            if opcode(line) != "while":
                # a store or a call: its operands are read before its effect
                line = replace_mem_exp(line, mem_idx, mem_val)
            res.append(line)
            res.extend(copy(trace[idx + 1 :]))
            return res

        elif opcode(line) == "while":
            _, cond, path, jds, vars = line
            # shouldn't this go above the affects if above? and also update vars even if
            # the loops affects the memidx?

            vars = [replace_mem_exp(v, mem_idx, mem_val) for v in vars]

            if not affects(line, ("mem", mem_idx)) and not affects(line, (mem_val)):
                cond = replace_mem_exp(cond, mem_idx, mem_val)
                path = replace_mem(path, mem_idx, mem_val)

            res.append(("while", cond, path, jds, vars))

        elif opcode(line) == "if":
            _, cond, if_true, if_false = line
            cond = replace_mem_exp(cond, mem_idx, mem_val)
            mem_idx_true = apply_constraint(mem_idx, cond)
            mem_val_true = apply_constraint(mem_val, cond)
            mem_idx_false = apply_constraint(mem_idx, is_zero(cond))
            mem_val_false = apply_constraint(mem_val, is_zero(cond))

            if_true = replace_mem(if_true, mem_idx_true, mem_val_true, known)
            if_false = replace_mem(if_false, mem_idx_false, mem_val_false, known)

            res.append(("if", cond, if_true, if_false))
            if idx + 1 < len(trace) and (
                trace_affects([line], mem_val) or trace_affects([line], mem_id)
            ):
                # lines after an if run after either branch
                res.extend(copy(trace[idx + 1 :]))
                return res

        else:
            # speed
            test = "mem" in str(line)
            if (
                test
                and (m := match(mem_idx, ("add", Any, ("var", ":num"))))
                and str(("var", m.num)) not in str(line)
            ):
                test = False
            # / speed

            if test:
                l = replace_mem_exp(line, mem_idx, mem_val)
            else:
                l = line

            _learn_var(l, known)
            res.append(l)

    return res


"""

    Variables cleanup

"""


def cleanup_vars(trace, required_after=None):
    required_after = required_after or []
    """
        for every var = mem declaration, replace future
        occurences of it, if possible

        var1 = mem[64]
        log var1
        mem[65] = 'Y'
        log var1

        into

        var1 = mem[64]
        log mem[64]
        mem[65] = 'Y'
        log var1

        for var declarations that are no longer in use, remove them

    """
    if _out_of_time():
        return trace  # the rest stays as it is (exact, see _deadline)

    res = []

    for idx, line in enumerate(trace):
        if opcode(line) == "setvar":
            _, var_idx, var_val = line
            # find all the future occurences of var and replace if possible

            remaining_trace = replace_var(trace[idx + 1 :], var_idx, var_val)
            if (
                contains(remaining_trace, ("var", var_idx))
                or ("var", var_idx) in required_after
            ):
                res.append(line)

            res.extend(cleanup_vars(remaining_trace, required_after=required_after))
            return res

        elif opcode(line) == "while":
            _, cond, path, *rest = line
            # the condition runs after the body at every iteration: a
            # variable it reads (a state read of the loop header, bound
            # again before each continue) is needed after the path too
            path = cleanup_vars(
                path,
                required_after=required_after
                + find_op_list(cond, "var")
                + find_op_list(trace[idx + 1 :], "var"),
            )
            res.append(
                (
                    "while",
                    cond,
                    path,
                )
                + tuple(rest)
            )

            a = parse_counters(line)

            if "endvars" in a:
                remaining_trace = trace[idx + 1 :]
                for var_idx, var_val in a["endvars"].items():
                    remaining_trace = replace_var(remaining_trace, var_idx, var_val)

                res.extend(
                    cleanup_vars(
                        remaining_trace,
                        required_after=required_after
                        + find_op_list(trace[idx + 1 :], "var"),
                    )
                )
                return res

        elif opcode(line) == "if":
            _, cond, if_true, if_false = line
            if_true = cleanup_vars(if_true, required_after=required_after)
            if_false = cleanup_vars(if_false, required_after=required_after)
            res.append(("if", cond, if_true, if_false))
        else:
            res.append(line)

    return res


def replace_var(trace, var_idx, var_val):
    """
    replace occurences of var, if possible

    """

    var_id = ("var", var_idx)
    res = []

    if _kept_in_memory(trace, var_id, var_val):
        return trace

    for idx, line in enumerate(trace):
        if m := match(line, ("setmem", ":mem_idx", Any)):
            # this all seems incorrect, (plus 'affects' checks below, needs to be revisited)
            # memloc = ("mem", m.mem_idx)
            # replace in val
            res.append(replace(line, var_id, var_val))

            if affects(line, var_val):
                res.extend(copy(trace[idx + 1 :]))
                return res
            else:
                continue

        if opcode(line) == "label" and _stops_at_label(trace[idx + 1 :], (var_val,)):
            # the label's own setvars are evaluated before the loop
            res.append(replace(line, var_id, var_val))
            res.extend(copy(trace[idx + 1 :]))
            return res

        if opcode(line) == "setvar" and line[1] == var_idx:
            # bound again: the lines after it read that binding (its own
            # value is computed before)
            res.append(replace(line, var_id, var_val))
            res.extend(copy(trace[idx + 1 :]))
            return res

        if opcode(line) == "while":
            _, cond, path, jd, setvars = line
            setvars = replace(setvars, var_id, var_val)

            again = _rebinds(path, var_idx)
            if again and (affects(line, var_val) or any(v != var_val for v in again)):
                # the loop header binds the variable again before each
                # continue, to another value (a state read the body may
                # change, or one already forwarded to a value): the
                # condition, the body and the lines after the loop read
                # that binding
                res.append(("while", cond, path, jd, setvars))
                res.extend(copy(trace[idx + 1 :]))
                return res

            if not affects(line, var_val):
                cond = replace(cond, var_id, var_val)
                path = replace_var(path, var_idx, var_val)

            line = ("while", cond, path, jd, setvars)

        if affects(line, var_val):
            if opcode(line) != "while":
                # a store or a call: its operands are read before its effect
                line = replace(line, var_id, var_val)
            res.append(line)
            res.extend(copy(trace[idx + 1 :]))
            return res

        elif opcode(line) == "while":
            assert not affects(line, var_val)
            res.append(line)  # could replace vars inside of while, skipping for now

        elif opcode(line) == "if":
            _, cond, if_true, if_false = line
            cond = replace(cond, var_id, var_val)
            if_true = replace_var(if_true, var_idx, var_val)
            if_false = replace_var(if_false, var_idx, var_val)
            res.append(("if", cond, if_true, if_false))
            if idx + 1 < len(trace) and trace_affects([line], var_val):
                # lines after an if run after either branch
                res.extend(copy(trace[idx + 1 :]))
                return res

        else:
            res.append(replace(line, var_id, var_val))

    return res


"""

    loop parsing

"""


def find_conts(trace):
    def check(line):
        if opcode(line) == "continue":
            return [line]
        else:
            return []

    return find_f_list(trace, check)


def swap_cond(cond):
    replacement = {
        "lt": "gt",
        "le": "ge",
        "gt": "lt",
        "ge": "le",
    }

    return (replacement[cond[0]], cond[2], cond[1])


def move_right(left, right, exp):
    """right with the terms of `left` other than `exp` moved over to it;
    None when `exp` is not a term of `left`."""
    if left == exp:
        return right

    if opcode(left) == "add":
        terms = left[1:]
        if exp not in terms:  # deep embedding unsupported
            return None
        for e in terms:
            if e != exp:
                if type(e) == int:
                    e = to_real_int(e)
                right = sub_op(right, e)

        return right

    if opcode(left) == "mul":
        terms = left[1:]
        if exp not in terms:  # deep embedding unsupported
            return None
        for e in terms:
            if e != exp:
                right = div_op(right, e)

        return right

    return None


def normalize(cond):
    cond = tuple(cleanup_mul_1(cond))

    if opcode(cond) not in ("lt", "le", "gt", "ge"):
        cond = ("lt", 0, cond)
        return normalize(cond)

    left, right = cond[1], cond[2]
    vars_left = find_op_list(left, "var")
    vars_right = find_op_list(right, "var")

    left_vars = tuple(
        [e for e in vars_left if match(e, ("var", int))]
    )  # int = loop vars
    right_vars = tuple([e for e in vars_right if match(e, ("var", int))])

    if len(left_vars) + len(right_vars) != 1:
        return None

    if len(right_vars) == 1:
        return normalize(swap_cond(cond))

    var = left_vars[0]

    if opcode(left) != "var":
        right = move_right(left, right, var)
        if right is None:
            return None
        left = var
        cond = (cond[0], left, right)

    if m := match(cond, ("lt", ":left", ":right")):
        cond = ("le", m.left, sub_op(m.right, 1))

    if m := match(cond, ("gt", ":left", ":right")):
        cond = ("ge", m.left, add_op(m.right, 1))

    return cond  # we end up with (gt/lt (var int) sth)


def find_setmems(trace):
    def check(line):
        if m := match(line, ("while", Any, ":path", ...)):
            sm = find_setmems(m.path)
            if len(sm) == 0:
                return []

            # for s in sm:
            #     s_idx = s[1]
            #                if 'var' in str(s_idx):
            #                    print(s_idx)
            #                    assert False

            return sm

        elif opcode(line) == "setmem":
            return [line]

        else:
            return []

    return walk_trace(trace, check)


def memloc_left(setmem):
    assert opcode(setmem) in ("setmem", "mem")
    memloc = setmem[1]
    op, loc, _ = memloc
    assert op == "range"
    return loc


def memloc_right(setmem):
    assert opcode(setmem) in ("setmem", "mem")
    memloc = setmem[1]

    op, loc, rlen = memloc
    assert op == "range"
    return add_op(loc, rlen)


def make_range(left, right):
    r_len = sub_op(right, left)

    if safe_ge_zero(r_len) is False:
        return ("range", left, 0)
    else:
        return ("range", left, r_len)


def while_max_memidx(line):
    # returns the rightmost memory index for a setmem

    a = parse_counters(line)
    op, cond, path, jds, setvars = line
    assert op == "while"

    try:
        setmems = find_setmems(path)
    except Exception:
        logger.exception("Error in find_setmems")
        return "unknown"

    if len(setmems) == 0:
        return 0

    collected = 0

    if "memvars" not in a:
        for s in setmems:
            collected = _max_op(collected, memloc_right(s))

        return collected

    setmems_begin = setmems_end = setmems

    for v in a["setvars"]:
        v_idx, v_start = v[1], v[2]
        v_end = a["memvars"][v_idx]

        setmems_begin = replace_var(setmems_begin, v_idx, v_start)
        setmems_end = replace_var(setmems_end, v_idx, v_end)

    for idx, _ in enumerate(setmems):
        collected = _max_op(collected, memloc_right(setmems_begin[idx]))
        collected = _max_op(collected, memloc_right(setmems_end[idx]))

    return collected


def extract_paths(while_exp):
    op, _, trace, jd, setvars = while_exp
    assert op == "while"

    def f(trace, jd, so_far):
        # extract all the paths leading up to jd
        if len(trace) == 0:
            return []

        line = trace[0]

        # assert opcode(line) != 'while'

        if opcode(line) == "if":
            _, cond, if_true, if_false = line
            res_true = f(if_true, jd, so_far + [("require", cond)])
            res_false = f(if_false, jd, so_far + [("require", is_zero(cond))])
            return res_true + res_false

        if len(trace) == 1:
            if opcode(line) == "continue":
                return [so_far]
            else:
                return []

        return f(trace[1:], jd, so_far + [line])

    return f(trace, jd, [])


def extract_setmems(while_exp):
    paths = extract_paths(while_exp)
    res = []
    for p in paths:
        res += find_setmems(p)
    return res


def extract_mems(while_exp):
    paths = extract_paths(while_exp)
    res = []
    for p in paths:
        res += find_mems(p)
    return res


#        mems = extract_mems(path)


def while_touches_mem(line, mem_idx):
    a = parse_counters(line)
    op, cond, path, jds, setvars = line
    assert op == "while"

    #    try:
    setmems = extract_setmems(line)
    #    setmems = find_setmems(path)
    #    except Exception:
    #        return True

    if len(setmems) == 0:
        return False

    setmems_begin = setmems_end = setmems

    if "memvars" not in a:
        for (
            s
        ) in (
            setmems
        ):  # if no endvars, comparing just with a 'var' assumes 'var' is any natural number
            if range_overlaps(mem_idx, s[1]) is not False:
                return True

        return False

    for v in a["setvars"]:
        v_idx, v_start = v[1], v[2]
        v_end = a["memvars"][v_idx]

        setmems_begin = replace_var(setmems_begin, v_idx, v_start)
        setmems_end = replace_var(setmems_end, v_idx, v_end)

    for idx, _ in enumerate(setmems):
        r_begin = memloc_left(setmems_begin[idx])
        r_end = memloc_right(setmems_end[idx])

        r = make_range(r_begin, r_end)
        if range_overlaps(mem_idx, r) is not False:
            return True

        r_begin = memloc_left(setmems_end[idx])
        r_end = memloc_right(setmems_begin[idx])

        r = make_range(r_begin, r_end)
        if range_overlaps(mem_idx, r) is not False:
            return True

    return False


def while_uses_mem(line, mem_idx):
    op, cond, path, jds, setvars = line
    assert op == "while"
    a = parse_counters(line)

    mems = find_mems(line)

    #    mems = extract_mems(line)

    if len(mems) == 0:
        return False

    mems_begin = mems_end = mems

    if "memvars" not in a:
        for s in mems:
            if range_overlaps(mem_idx, s[1]) is not False:
                return True

        return False

    for v in a["setvars"]:
        v_idx, v_start = v[1], v[2]
        v_end = a["memvars"][v_idx]

        mems_begin = replace_var(mems_begin, v_idx, v_start)
        mems_end = replace_var(mems_end, v_idx, v_end)

    for idx, _ in enumerate(mems):
        r_begin = memloc_left(mems_begin[idx])
        r_end = memloc_right(mems_end[idx])

        r = make_range(r_begin, r_end)
        if range_overlaps(mem_idx, r) is not False:
            return True

        r_begin = memloc_left(mems_end[idx])
        r_end = memloc_right(mems_begin[idx])

        r = make_range(r_begin, r_end)
        if range_overlaps(mem_idx, r) is not False:
            return True

    return False


def exp_uses_mem(exp, mem_idx):
    mems = find_mems([exp])

    for m in mems:
        op, m_idx = m
        assert op == "mem"
        if range_overlaps(m_idx, mem_idx) is not False:
            return True

    return False


def parse_counters(line):
    a = {}
    op, cond, path, jds, setvars = line
    assert op == "while"

    a["setvars"] = setvars
    a["jds"] = jds

    conts = find_conts(path)
    if not conts:
        return {}

    startvars = {}
    for v in setvars:
        if not (m := match(v, ("setvar", ":vidx", ":vval"))):
            return {}
        startvars[m.vidx] = m.vval

    cond = normalize(cond)
    if cond is None:
        return {}

    cont = conts[0]

    stepvars = {}
    for v in cont[2]:
        var_idx, var_val = v[1], v[2]
        stepvars[var_idx] = var_val

    a["stepvars"] = stepvars

    counter = cond[1][1]
    counter_stop = cond[2]
    if counter not in startvars:
        logger.debug("counter %s not in %s", counter, startvars)
        return {}
    counter_start = startvars[counter]
    a["counter"] = counter
    a["start"] = counter_start
    a["stop"] = counter_stop
    if counter not in stepvars:
        logger.debug("counter not in stepvars")
        counter_diff = 0
    else:
        counter_diff = stepvars[counter]

    if len(conts) > 1:
        return a

    counter_step = _linear_step(counter_diff, counter)
    if counter_step is None:
        # not `counter + constant` (a narrow counter's wrapping update, a
        # product...): no closed form
        return a

    a["step"] = counter_step

    num_loops = div_op(
        add_op(sub_op(counter_stop, counter_start), counter_step), counter_step
    )

    if opcode(num_loops) == "div":  # so, no obvious divider
        a["counter_stop"] = counter_stop
        a["counter_start"] = counter_start
        a["counter_step"] = counter_step
        return a

    a["num_loops"] = num_loops

    # start + step * num_loops for every variable that moves by a constant
    # per iteration (none when one does not)
    closed = {}
    for v in setvars:
        var_idx, var_val = v[1], to_real_int(v[2])
        var_diff = _linear_step(stepvars.get(var_idx, ("var", var_idx)), var_idx)
        if var_diff is None:
            return a
        closed[var_idx] = add_op(var_val, mul_op(var_diff, num_loops))

    # "memvars": the closed forms where the loop runs as the formula assumes
    # (start <= bound): the memory analyses use them for the range a loop
    # writes, as they always did.
    a["memvars"] = closed

    # "endvars": the values after the loop, which replace the variables in
    # the code after it. Exact only when the loop runs num_loops times: a
    # counter compared as it is, from 0 up to a bound the loop does not
    # change (num_loops = ceil(bound / step), an exact division above), or
    # down from a start known to be above the bound. Otherwise the variables
    # stay as they are after the loop.
    raw_cond = line[1]
    direct = opcode(raw_cond) in ("lt", "gt") and ("var", counter) in raw_cond[1:]
    if not direct:
        # the counter inside an expression (i + 1 < n): the bound was moved
        # across the comparison, which is not exact modulo 2**256
        return a
    if not (
        (counter_step > 0 and counter_start == 0 and cond[0] == "le")
        or (
            counter_step < 0
            and cond[0] == "ge"
            and safe_le_op(counter_stop, counter_start) is True
        )
    ):
        return a
    if not _loop_invariant(line, counter_stop, stepvars):
        return a

    a["endvars"] = closed
    return a


def _linear_step(update, var_idx):
    """c when `update` (the value a loop variable gets at a `continue`) is
    var + c with a constant c, 0 when it is the variable itself, else None."""
    if update == ("var", var_idx):
        return 0
    if opcode(update) != "add" or len(update) != 3:
        return None
    _, c, x = update
    if type(c) != int:
        c, x = x, c
    if type(c) != int:
        return None
    # ('mul', 1, X) -> X
    if opcode(x) == "mul" and len(x) == 3 and x[1] == 1:
        x = x[2]
    if x != ("var", var_idx):
        return None
    return to_real_int(c)


def _loop_invariant(while_line, exp, stepvars):
    """True when `exp` has the same value at every test of the loop: no
    variable the loop sets, and nothing in the loop changes what it reads."""
    _, _, path, _, setvars = while_line
    names = {v[1] for v in setvars}
    names |= set(find_f_list(path, lambda l: [l[1]] if opcode(l) == "setvar" else []))
    if any(e[1] in names for e in find_op_list(exp, "var")):
        return False
    if clobbers(while_line, exp):
        return False
    # memory: a write of the loop that may overlap a read of exp
    # (affects() would come back here through while_touches_mem)
    if "msize" in str(exp):
        return False
    reads = find_op_list(exp, "mem")
    if reads:
        for s in find_f_list(path, lambda l: [l] if opcode(l) == "setmem" else []):
            for r in reads:
                if not _write_misses(r[1], s[1], setvars, stepvars):
                    return False
    return True


def _write_misses(read, write, setvars, stepvars):
    """True when a write of a loop to the range `write` never touches the
    range `read`. A write address `c + v + ...` made of loop variables that
    start at 0 and only grow stays at or above c: below it (without
    wrapping around 2**256, which no loop runs long enough to reach)."""
    if opcode(read) != "range" or opcode(write) != "range":
        return False
    if range_overlaps(read, write) is False:
        return True
    start = write[1]
    terms = start[1:] if opcode(start) == "add" else (start,)
    starts = {v[1]: v[2] for v in setvars}
    low = 0
    for t in terms:
        if type(t) == int:
            low += t
        elif opcode(t) == "var" and starts.get(t[1]) == 0 and (_linear_step(stepvars.get(t[1]), t[1]) or 0) > 0:
            pass
        else:
            return False
    read_end = add_op(read[1], read[2])
    return type(read_end) == int and 0 <= read_end <= low < 2**255

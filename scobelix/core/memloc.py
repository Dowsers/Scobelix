import logging
import sys

from scobelix.matcher import Any, match
from scobelix.utils.helpers import (
    cached,
    contains,
    is_array,
    opcode,
    replace,
)

from scobelix.core.algebra import (
    CannotCompare,
    add_ge_zero,
    add_op,
    all_concrete,
    apply_mask,
    apply_mask_to_storage,
    bits,
    calc_max,
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
    safe_gt_zero,
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
from scobelix.core.masks import find_mask, mask_runs

logger = logging.getLogger(__name__)


def apply_mask_to_range(memloc, size, offset):
    op, range_pos, range_len = memloc
    assert op == "range"

    size_bytes, size_bits = to_bytes(size)
    offset_bytes, offset_bits = to_bytes(offset)

    assert offset_bits == size_bits == 0, (offset_bits, size_bits)  # for now
    assert safe_le_op(add_op(size_bytes, offset_bytes), range_len) is True, (
        size_bytes,
        offset_bytes,
        range_len,
    )  # otherwise we need to learn to handle that

    range_pos = add_op(range_pos, sub_op(range_len, add_op(size_bytes, offset_bytes)))
    range_len = size_bytes  # sub_op(range_len, add_op(offset_bytes, size_bytes))

    return ("range", range_pos, range_len)


assert apply_mask_to_range(("range", 212, 32), 160, 0) == ("range", 224, 20)
assert apply_mask_to_range(("range", 212, 32), 160, 96) == ("range", 212, 20)


def cmp_to_key(mycomp):
    class K:
        def __init__(self, obj):
            self.obj = obj

        def __lt__(self, other):
            return lt_op(self.obj, other.obj)

    return K(mycomp)


ADDRESS_ATOMS = ("caller", "origin", "address", "coinbase")
BOOLEAN_OPS = ("bool", "iszero", "lt", "gt", "le", "ge", "slt", "sgt", "sle", "sge", "eq")


def value_width(exp):
    """
    An upper bound, in bits, of the value of `exp`: its bits at and above
    that position are zero. 256 when nothing is known (any word).
    """
    if type(exp) == int:
        return max(0, min(exp.bit_length(), 256)) if exp >= 0 else 256
    if exp in ADDRESS_ATOMS:
        return 160
    op = opcode(exp)
    if op in BOOLEAN_OPS:
        return 1
    if (m := match(exp, ("storage", ":int:size", Any, Any))) and 0 <= m.size <= 256:
        return m.size
    if (m := match(exp, ("mem", ("range", Any, ":int:n")))) and 0 <= m.n <= 32:
        return bits(m.n)
    if (m := match(exp, ("bytes", ":int:n", Any))) and 0 <= m.n <= 32:
        return bits(m.n)
    if m := match(exp, ("mask_shl", ":int:size", ":int:off", ":int:shl", ":inner")):
        # the bits [off, off + size) of the inner value, moved by shl
        top = min(m.off + m.size, value_width(m.inner)) + m.shl
        return max(0, min(top, 256))
    if op == "or":
        return max(value_width(e) for e in exp[1:])
    return 256


def narrow(value, size):
    """`value` as a value of `size` bits: itself when it already fits (a
    wider mask around a value that fits is dropped), else its low bits."""
    while (
        (m := match(value, ("mask_shl", ":int:size", 0, 0, ":inner")))
        and m.size >= size
        and value_width(m.inner) <= size
    ):
        value = m.inner
    if value_width(value) <= size:
        return value
    return mask_op(value, size=size)


def split_or(value):
    orig_value = value

    if opcode(value) not in ("or", "mask_shl"):
        return [(256, 0, value)]

    if opcode(value) == "mask_shl":
        value = ("or", value)

    opcode_, *terms = value
    assert opcode_ == "or"

    ret_rows = []

    for row in terms:
        if m := match(row, ("bool", ":arg")):
            row = (
                "mask_shl",
                8,
                0,
                0,
                ("bool", m.arg),
            )  # does weird things if size == 1, in loops.activateSafeMode

        if row == "caller":
            row = (
                "mask_shl",
                160,
                0,
                0,
                "caller",
            )  # does weird things if size == 1, in loops.activateSafeMode

        if m := match(row, ("mul", 1, ":val")):
            row = m.val

        if (
            (m := match(row, ("and", ":int:mask", ":inner")))
            or (m := match(row, ("and", ":inner", ":int:mask")))
        ) and -(2**256) < m.mask < 2**256:
            # and(M, x) with a mask M of several runs of ones (the fields a
            # packed write keeps): one row per run, the field of x it keeps.
            # (A single run is folded into a mask_shl by the simplifier.)
            # Fields are whole bytes: any other mask is bit arithmetic, and
            # the value stays whole.
            runs = mask_runs(m.mask % 2**256)  # a negative int is a two's complement word
            if runs and all(size % 8 == 0 and start % 8 == 0 for size, start in runs):
                for size, start in runs:
                    ret_rows.append(
                        (size, start, mask_op(m.inner, size=size, offset=start, shr=start))
                    )
                continue

        if opcode(row) == "mask_shl" and all_concrete(row):
            row = apply_mask(row[4] if row[4] < 256 else 256, row[1], row[2], row[3])

        if type(row) in [int, float]:
            if row == 0:
                continue  # contributes no bits (find_mask would give an empty row at 256)
            size, offset = find_mask(row)
            shl = 0
            row = ("mask_shl", size, offset, 0, row)

        if m := match(row, ("mem", ":mem_idx")):
            if opcode(m.mem_idx) != "range":
                m.mem_idx = ("range", m.mem_idx, 32)

            # mem_begin = m.mem_idx[1]
            mem_len = m.mem_idx[2]
            ret_rows.append((bits(mem_len), 0, row))
            continue

        if m := match(row, ("storage", ":size", ":off", ":idx")):
            ret_rows.append((m.size, 0, row))
            continue

        if opcode(row) != "mask_shl":
            # the whole value, never one of its terms (`value` is reused
            # for the rows below)
            return [(256, 0, orig_value)]

        assert opcode(row) == "mask_shl"
        _, size, offset, shl, value = row

        stor_size = size
        stor_offset = add_op(offset, shl)
        shl = sub_op(shl, stor_offset)
        if type(value) == int:
            value = apply_mask(value, size, offset, shl)
            if value == 0:
                continue  # no bits: the hole is filled with zeroes below

        elif (
            (m := match(value, ("mem", ":idx")))
            and add_op(offset, shl) == 0
            and type(size) == int
            and type(offset) == int
            and size % 8 == 0
            and offset % 8 == 0
            and safe_le_op(add_op(to_bytes(size)[0], to_bytes(offset)[0]), m.idx[2]) is True
        ):
            new_memloc = apply_mask_to_range(m.idx, size, offset)
            value = ("mem", new_memloc)

        else:
            value = mask_op(value, size=size, offset=offset, shl=shl)

        ret_rows.append(
            (
                stor_size,
                stor_offset,
                value,
            )
        )

    if len(ret_rows) == 2:
        """
        a special case where rows are symbolic and complimentary. happens often
        (('mask_shl', 5, 0, 3, ('cd', ('add', 4, ('cd', 68)))), 0, ('mem', ('range', ('add', 160, ('mask_shl', 251, 5, 0, ('cd', ('add', 4, ('cd', 68)))), ('mul', -1, ('mask_shl', 5, 0, 0, ('cd', ('add', 4, ('cd', 68)))))), ('mask_shl', 5, 0, 0, ('cd', ('add', 4, ('cd', 68)))))))
        (('mask_shl', 253, 0, 3, ('add', 32, ('mul', -1, ('mask_shl', 5, 0, 0, ('cd', ('add', 4, ('cd', 68))))))), ('add', 256, ('mul', -1, ('mask_shl', 253, 0, 3, ('add', 32, ('mul', -1, ('mask_shl', 5, 0, 0, ('cd', ('add', 4, ('cd', 68))))))))), ('mem', ('range', ('add', 185, ('mask_shl', 251, 5, 0, ('add', 31, ('cd', ('add', 4, ('cd', 68))))), ('mask_shl', 251, 5, 0, ('add', 31, ('cd', ('add', 4, ('cd', 164))))), ('mask_shl', 251, 5, 0, ('cd', ('add', 4, ('cd', 68)))), ('mask_shl', 251, 0, 5, 1)), ('add', 32, ('mul', -1, ('mask_shl', 5, 0, 0, ('cd', ('add', 4, ('cd', 68)))))))))
        """
        first = ret_rows[0]
        second = ret_rows[1]
        if first[1] != 0 and second[1] == 0:
            second, first = first, second

        f_size, f_off, f_val = first
        s_size, s_off, s_val = second

        try:
            if f_off == 0 and s_off == (
                "add",
                256,
                (
                    "mul",
                    -1,
                    (
                        "mask_shl",
                        253,
                        0,
                        3,
                        ("add", 32, ("mul", -1, ("mask_shl", 5, 0, 0, f_size[4]))),
                    ),
                ),
            ):
                assert match(
                    s_size, ("mask_shl", Any, Any, Any, ("add", 32, ("mul", -1, ...)))
                )
                return ret_rows
        except (TypeError, IndexError):
            pass

    try:
        ret_rows.sort(key=lambda row: cmp_to_key(row[1]))  # sort by offsets, descending
    except Exception:
        return [(256, 0, orig_value)]

    # insert zeroes into empty spaces

    result = []

    pos = 0

    for r in ret_rows:
        if type(r[1]) != int or type(r[0]) != int:
            return [(256, 0, orig_value)]  # rows of runtime size: not split
        if r[1] < pos:
            # the row starts inside the previous one: when the previous row's
            # value fits below it (a bool, an address or a narrow field shifted
            # into place, whose or'ed bits above are zero), the previous row
            # ends where this one starts; otherwise the rows really overlap and
            # the value stays whole
            if not result:
                return [(256, 0, orig_value)]  # a row below bit 0: not split
            p_size, p_off, p_val = result[-1]
            fit = r[1] - p_off
            if fit <= 0 or value_width(p_val) > fit:
                return [(256, 0, orig_value)]
            result[-1] = (fit, p_off, narrow(p_val, fit))
            pos = r[1]
        if r[1] > pos:
            result.append((r[1] - pos, pos, 0))

        result.append(r)
        pos = r[1] + r[0]

    if pos < 256:
        result.append((256 - pos, pos, 0))

    return result


def sizeof(exp):  # returns size of expression in *bits*
    if match(exp, ("storage", ":size", ...)):
        # a storage field is a right-aligned value that fills a whole word
        # once written to memory (its own width would shift a slice's offset)
        return 256

    if m := match(exp, ("mask_shl", ":size", ":off", ":shl", Any)):
        return add_op(m.size, m.off, m.shl)

    if (m := match(exp, (":op", Any, ":size_bytes"))) and is_array(m.op):
        return bits(m.size_bytes)

    if m := match(exp, ("mem", ("range", Any, ":size_bytes"))):
        return bits(m.size_bytes)

    if m := match(exp, ("bytes", ":size_bytes", Any)):
        return bits(m.size_bytes)

    assert not match(exp, ("mem", ":idx"))
    assert not match(exp, ("arr", ":l", Any))

    #    if exp ~ ('bytes', :l, _):
    #        return bits(l)

    if type(exp) == int and exp > 2**256:
        return bits(
            ((exp).bit_length() + 7) // 8
        )  # number of bytes needed to contain the number, rounded up

    return 256
    return None


def self_width(exp):
    """
    Byte length of a node that carries its own length when it stands for a
    byte string: memory and array slices, ("bytes", n, x) parts and
    ("data", ...) blobs. None for a plain word expression.
    """
    op = opcode(exp)
    if op == "bytes":
        return exp[1]
    if op == "mem" and opcode(exp[1]) == "range":
        return exp[1][2]
    if is_array(op) and len(exp) == 3:
        return exp[2]
    if op == "extcodecopy" and opcode(exp[2]) == "range":
        return exp[2][2]
    if op == "data":
        return add_op(*[part_width(e) for e in exp[1:]])
    return None


def part_width(exp):
    """Byte length of `exp` as a part of a byte string: its own length, 32
    for a plain word, 0 for None (no bytes)."""
    if exp is None:
        return 0
    w = self_width(exp)
    return 32 if w is None else w


def with_width(value, width):
    """
    `value` as a byte string of exactly `width` bytes. A plain word is 32
    bytes and a slice or blob its own length; any other width is explicit:
    ("bytes", width, value) = the low `width` bytes of the word `value`.
    """
    if width == 0:
        return None
    if value is None:
        return ("bytes", width, 0)
    if (m := match(value, ("mask_shl", ":size", 0, 0, ":inner"))) and sub_op(
        m.size, bits(width)
    ) == 0 and self_width(m.inner) is not None and sub_op(self_width(m.inner), width) == 0:
        value = m.inner  # the mask keeps all of a byte string of that length
    w = self_width(value)
    if (w is None and width == 32) or (w is not None and sub_op(w, width) == 0):
        return value
    if opcode(value) == "bytes":
        # the low `width` bytes of the low w bytes of x
        if safe_le_op(width, value[1]) is True:
            return ("bytes", width, value[2])
        return ("bytes", width, mask_op(value[2], size=bits(value[1])))
    return ("bytes", width, value)


def split_setmem(line):
    if opcode(line) != "setmem":
        return [line]

    _, mem_idx, mem_val = line

    if opcode(mem_val) != "or":
        return [line]

    if opcode(mem_idx) == "range" and safe_le_op(mem_idx[2], 32) is not True:
        # the rows below cover the 256 bits of one word: a longer range also
        # holds the zero bytes the word is extended with on the left
        return [line]

    post_split = split_or(mem_val)

    res = []
    for size, offset, split_val in post_split:
        if opcode(mem_idx) == "range":
            size_bytes, size_bits = to_bytes(size)
            offset_bytes, offset_bits = to_bytes(offset)
            if (
                size_bits != 0
                or offset_bits != 0
                or safe_le_op(add_op(size_bytes, offset_bytes), mem_idx[2]) is not True
            ):
                return [line]
        try:
            split_idx = apply_mask_to_range(mem_idx, size, offset)
        except Exception:
            logger.exception("problem with split_setmem")
            return [line]
        res.append(("setmem", split_idx, split_val))

    return res


def split_store(line):
    logger.debug("split_store %s", line)

    if (
        m := match(
            line,
            (
                "store",
                256,
                0,
                ":int:idx",
                ("mask_shl", ":int:size", ":int:off", 0, ("storage", 256, 0, ":idx")),
            ),
        )
    ) and m.size < 256:
        off, idx, size = m.off, m.idx, m.size

        lines = []
        if off > 0:
            lines.append(("store", off, 0, idx, 0))
        #        lines.append(('store', size, off, idx, ('storage', size, off, idx)))
        if size + off < 256:
            lines.append(("store", (256 - size - off), size + off, idx, 0))

        return lines

    if m := match(line, ("store", 256, 0, ":idx", ":val")):
        size = 256
        off = 0
        idx, val = m.idx, m.val
        splitted = split_or(val)

        res = []
        for s_size, s_off, s_val in splitted:
            if safe_le_op(off, s_off) and safe_le_op(
                add_op(s_size, s_off), add_op(off, size)
            ):
                if s_val != (
                    "storage",
                    s_size,
                    s_off,
                    idx,
                ):  # ignore writing the same to the same storage
                    res.append(("store", s_size, s_off, idx, s_val))
            else:
                logger.warning("unusual store")
                return [line]

        # the fields are written one after the other, and a store reads the
        # slot as the stores before it left it: a field computed from other
        # bits of the slot (b = a; a = 0 in one SSTORE) must be written first
        ordered = order_field_stores(res, idx)
        if ordered is None:
            return [line]  # fields that read each other (a swap): the whole word
        return ordered
    else:
        return [line]


def slot_reads(exp):
    """
    The storage reads the value of `exp` depends on, as (slot, low, high):
    the bits [low, high) of `slot`; (None, 0, 256) when the bits are not
    known (any slot). A mask around a field read narrows it to the bits the
    mask keeps.
    """
    reads = []

    def walk(e, keep=None):
        if type(e) not in (list, tuple) or len(e) == 0:
            return
        if m := match(e, ("storage", ":size", ":off", ":slot")):
            walk(m.slot)
            if (
                type(m.size) == int
                and type(m.off) == int
                and 0 <= m.off
                and 0 <= m.size
                and m.off + m.size <= 256
            ):
                low, high = m.off, m.off + m.size
                if keep is not None:  # the bits [k_off, k_off + k_size) of the field
                    low, high = low + keep[0], min(high, low + keep[0] + keep[1])
                if low < high:
                    reads.append((m.slot, low, high))
            else:
                reads.append((None, 0, 256))
            return
        if (
            (m := match(e, ("mask_shl", ":int:size", ":int:off", Any, ":inner")))
            and opcode(m.inner) == "storage"
            and m.size >= 0
            and m.off >= 0
        ):
            walk(m.inner, (m.off, m.size))
            return
        for x in e[1:] if type(e[0]) == str else e:
            walk(x)

    walk(exp)
    return reads


def _keccak_slot(exp):
    """A slot computed with keccak: a mapping value or the data of an array."""
    if opcode(exp) == "sha3":
        return True
    return opcode(exp) == "add" and any(opcode(t) == "sha3" for t in exp[1:])


def may_alias(slot, idx):
    """False only when the storage slots `slot` and `idx` are provably
    different: two constants, a constant distance apart, or a constant slot
    of the layout and a slot computed with keccak (solc's layout relies on
    them never meeting)."""
    if slot is None or slot == idx:
        return True
    if type(slot) == int and type(idx) == int:
        return False
    for a, b in ((slot, idx), (idx, slot)):
        if type(a) == int and 0 <= a < 2**64 and _keccak_slot(b):
            return False
    try:
        diff = sub_op(slot, idx)
    except Exception:
        return True
    return not (type(diff) == int and diff != 0)


def order_field_stores(stores, idx):
    """
    `stores` (field stores of the slot `idx` that come from one SSTORE) in
    an order where a store whose value reads bits of the slot runs before
    the stores that write those bits: the given order unless such a read
    forces another one. None when no order works (two fields that read each
    other, a swap).
    """
    if len(stores) < 2:
        return stores
    reads = [
        [(low, high) for slot, low, high in slot_reads(line[4]) if may_alias(slot, idx)]
        for line in stores
    ]
    # every store computes the slot again: a slot computed from bits of
    # itself that the stores write has no safe order
    slot_bits = [(low, high) for slot, low, high in slot_reads(idx) if may_alias(slot, idx)]
    if not any(reads) and not slot_bits:
        return stores
    if not all(type(line[1]) == int and type(line[2]) == int for line in stores):
        return None
    for line in stores:
        if any(low < line[2] + line[1] and line[2] < high for low, high in slot_bits):
            return None

    before = [set() for _ in stores]  # before[j]: the stores that must run before store j
    for i, ranges in enumerate(reads):
        for j, line in enumerate(stores):
            w_low, w_high = line[2], line[2] + line[1]
            if i != j and any(low < w_high and w_low < high for low, high in ranges):
                before[j].add(i)

    order, placed = [], set()
    while len(order) < len(stores):
        for j in range(len(stores)):
            if j not in placed and before[j] <= placed:
                order.append(stores[j])
                placed.add(j)
                break
        else:
            return None
    return order


def memloc_overwrite(memloc, split):
    # returns mem ranges excluding the ones that are *for sure* overwritten by 'split'
    # e.g. overwrites(('range', 64, 32), ('range', 70, 10)) -> [('range', 64, 6), (range, 80, 16)]
    # e.g. overwrites(('range', 64, 32), ('range', 70, 'unknown')) -> [('range', 64, 32)], bc. 'unknown' can be 0

    op, m_left, m_len = memloc
    assert op == "range"
    op, s_left, s_len = split
    assert op == "range"

    m_right = add_op(m_left, m_len)
    s_right = add_op(s_left, s_len)

    if safe_le_op(m_right, s_left) is True:  # split after memory - no overlap
        return [memloc]
    if safe_le_op(s_right, m_left) is True:  # split before memory - no overlap
        return [memloc]

    left_len = sub_op(s_left, m_left)
    right_len = sub_op(m_right, s_right)

    range_left = ("range", m_left, left_len)
    range_right = ("range", s_right, right_len)

    left_ge_zero, right_ge_zero = safe_ge_zero(left_len), safe_ge_zero(right_len)

    if left_ge_zero is None or right_ge_zero is None:
        # we can't compare some numbers, conservatively return whole range
        return [memloc]

    res = []

    if safe_ge_zero(left_len) is True and left_len != 0:
        res.append(range_left)

    if safe_ge_zero(right_len) is True and right_len != 0:
        res.append(range_right)

    return res


assert memloc_overwrite(("range", 64, 32), ("range", 70, 10)) == [
    ("range", 64, 6),
    ("range", 80, 16),
]
assert memloc_overwrite(("range", 64, 32), ("range", 70, add_op("unknown", 100))) == [
    ("range", 64, 6)
]
assert memloc_overwrite(("range", 64, "x"), ("range", 70, add_op("unknown", 100))) == [
    ("range", 64, "x")
]


def slice_exp(exp, left, right, total=None):
    """
    Bytes [left, right) of `exp`, the value of a memory range of `total`
    bytes: a slice node when `exp` is a slice, else an expression whose
    value is those bytes (the caller gives it its width, see with_width).
    A word stored in `total` bytes is its low `total` bytes, whatever its
    own natural width (an mstore'd int or mask fills the whole 32 bytes).
    `total` None: the natural width of `exp` (memloc.sizeof).
    None when the bytes cannot be expressed.
    """
    size = sub_op(right, left)

    logger.debug("slicing %s, offset %s bytes, until %s bytes", exp, left, right)
    # e.g. mem[32 len 10], 2, 4 == mem[34,2]

    if (m := match(exp, ("mem", ("range", ":rleft", ":rlen")))) or (
        (m := match(exp, (":op", ":rleft", ":rlen"))) and is_array(m.op)
    ):
        rleft, rlen = m.rleft, m.rlen
        # a slice shorter than its range is right-aligned in it (a word)
        pad = 0 if total is None else sub_op(total, rlen)
        if pad != 0:
            if safe_le_op(pad, left) is not True:
                return None  # the bytes include the zero padding
            left, right = sub_op(left, pad), sub_op(right, pad)
        if safe_le_op(add_op(left, size), rlen) is not True:
            return None
        if opcode(exp) == "mem":
            return ("mem", ("range", add_op(rleft, left), size))
        return (m.op, add_op(rleft, left), size)

    if opcode(exp) == "bytes" and total is None:
        total = exp[1]

    if total is not None and left == 0 and sub_op(right, total) == 0:
        return exp  # all of it

    exp_bits = bits(total) if total is not None else sizeof(exp)
    off = sub_op(exp_bits, bits(right))
    logger.debug("applying mask, size 8*%s, offset %s", size, off)

    m = mask_op(exp, size=bits(size), offset=off, shr=off)
    logger.debug("result %s", m)
    return m


assert slice_exp(("mem", ("range", 32, 10)), 2, 4) == ("mem", ("range", 34, 2))
assert slice_exp(("mask_shl", 32, 0, 0, ("cd", 0)), 0, 4) == (
    "mask_shl",
    32,
    0,
    0,
    ("cd", 0),
)
assert slice_exp(("mask_shl", 32, 0, 0, ("cd", 0)), 2, 4) == (
    "mask_shl",
    16,
    0,
    0,
    ("cd", 0),
)
assert slice_exp(("mask_shl", 32, 0, 0, ("cd", 0)), 0, 2) == (
    "mask_shl",
    16,
    16,
    -16,
    ("cd", 0),
)


def splits_mem(memloc, split, memval, split_val=None):
    # returns memory values we can be confident of, after overwriting the split part of memory

    op, m_left, m_len = memloc
    assert op == "range"
    op, s_left, s_len = split
    assert op == "range"

    m_right = add_op(m_left, m_len)
    s_right = add_op(s_left, s_len)

    logger.debug("applying split [%s (len %s) %s]", s_left, s_len, s_right)
    logger.debug("            to [%s (len %s) %s]", m_left, m_len, m_right)

    if not safe_ge_zero(s_len):
        s_len = "undefined"
        s_right = add_op(s_left, s_len)

    if safe_le_op(m_right, s_left) is True:  # split after memory - no overlap
        return [(memloc, memval)]

    if safe_le_op(s_right, m_left) is True:  # split before memory - no overlap
        return [(memloc, memval)]

    left = safe_max_op(s_left, m_left)
    right = safe_min_op(s_right, m_right)

    logger.debug("split overwrites memory from %s to %s", left, right)

    if left is None:
        return []  # where the overwritten part begins is unknown

    # left/right relative to beginning of memory location
    in_left = sub_op(left, m_left)
    in_right = sub_op(right, m_left) if right is not None else None

    logger.debug("that is, relative to memloc %s to %s", in_left, in_right)
    if safe_le_op(in_left, m_len) is not True:
        logger.debug(
            "we are not sure that m_len: %s is bigger than beginning of split, returning []",
            m_len,
        )
        return []

    assert in_left == 0 if right is not None and safe_le_op(right, m_left) else True

    if right is not None and safe_le_op(m_left, right) is not True:
        # the split may end before memloc begins (the two may not overlap at
        # all: replace_mem also splits when it cannot tell): [right, m_right)
        # would then reach outside memloc, so nothing is known on the right
        right = None

    val_left = slice_exp(memval, 0, in_left, total=m_len) if left is not None else None
    val_right = (
        slice_exp(memval, in_right, sub_op(m_right, m_left), total=m_len)
        if right is not None
        else None
    )
    res = []

    left_len = sub_op(left, m_left)  # sizeof(val_left)
    right_len = sub_op(m_right, right) if right is not None else None

    if safe_ge_zero(left_len) is True and left_len != 0 and val_left is not None:
        res.append((("range", m_left, left_len), val_left))

    if split_val is not None:
        center_left = safe_max_op(m_left, s_left)
        center_right = safe_min_op(m_right, s_right)

        center_len = sub_op(center_right, center_left)

        if is_array(opcode(split_val)):  # in ARRAY_OPCODES:
            # mem[a len b] = calldata[x len b]
            # log mem[c len d]
            # -> calldata[x+ c - a, center_len]
            arr_offset, arr_len = split_val[1:]
            center_offset = add_op(arr_offset, sub_op(center_left, s_left))
            center_val = (opcode(split_val), center_offset, center_len)

        else:
            center_offset = sub_op(s_right, center_right)
            center_val = mask_op(
                split_val,
                size=mul_op(center_len, 8),
                offset=mul_op(center_offset, 8),
                shr=mul_op(center_offset, 8),
            )

        center_range = ("range", center_left, center_len)

        if safe_ge_zero(center_len) and center_len != 0:
            res.append((center_range, center_val))

    if (
        right_len is not None
        and safe_ge_zero(right_len) is True
        and right_len != 0
        and val_right is not None
    ):
        res.append((("range", right, right_len), val_right))

    return res


assert splits_mem(("range", 66, 32), ("range", 65, 32), "a") == [
    (("range", 97, 1), ("mask_shl", 8, 0, 0, "a"))
], splits_mem(("range", 66, 32), ("range", 65, 32), "a")
assert splits_mem(("range", 64, 32), ("range", 65, 32), "a") == [
    (("range", 64, 1), ("mask_shl", 8, 248, -248, "a"))
], splits_mem(("range", 64, 32), ("range", 65, 32), "a")
assert splits_mem(("range", 4, 32), ("range", 65, 32), "a") == [(("range", 4, 32), "a")]
assert splits_mem(("range", 104, 32), ("range", 65, 32), "a") == [
    (("range", 104, 32), "a")
]
assert splits_mem(("range", 64, 32), ("range", 65, 30), "a") == [
    (("range", 64, 1), ("mask_shl", 8, 248, -248, "a")),
    (("range", 95, 1), ("mask_shl", 8, 0, 0, "a")),
]

assert (
    splits_mem(("range", 64, 32), ("range", "x", 32), "a") == []
)  # not sure means return empty
assert splits_mem(("range", 64, 32), ("range", 65, "x"), "a") == [
    (("range", 64, 1), ("mask_shl", 8, 248, -248, "a"))
]
assert (
    splits_mem(("range", 64, "x"), ("range", 65, sub_op("x", 2)), "a") == []
), splits_mem(
    ("range", 64, "x"), ("range", 65, sub_op("x", 2)), "a"
)  # because it's either '1' if x>=1 or '0' if x == 0

assert splits_mem(("range", 64, 32), ("range", 65, 30), "a", "b") == [
    (("range", 64, 1), ("mask_shl", 8, 248, -248, "a")),
    (("range", 65, 30), ("mask_shl", 240, 0, 0, "b")),
    (("range", 95, 1), ("mask_shl", 8, 0, 0, "a")),
]

assert splits_mem(("range", "x", 32), ("range", "y", 32), "a", "b") == []

assert splits_mem(("range", 64, 32), ("range", 65, 32), "a", "b") == [
    (("range", 64, 1), ("mask_shl", 8, 248, -248, "a")),
    (("range", 65, 31), ("mask_shl", 248, 8, -8, "b")),
]
assert splits_mem(("range", 64, 32), ("range", 63, 32), "a", "b") == [
    (("range", 64, 31), ("mask_shl", 248, 0, 0, "b")),
    (("range", 95, 1), ("mask_shl", 8, 0, 0, "a")),
]
assert splits_mem(("range", 64, 32), ("range", 630, 32), "a", "b") == [
    (("range", 64, 32), "a")
]
assert splits_mem(("range", 64, 32), ("range", 1, 32), "a", "b") == [
    (("range", 64, 32), "a")
]

# assert splits_mem(('range', 64, 'x'), ('range', 64, 'x'), 'a', ('array', 10, 'x')) == [(('range', 64, 'x'), ('array', 10, 'x'))]

"""
#assert splits_mem(('range', 64, 32), ('add', 10, 'x')), ('range', 70, ('add', 10, 'x')), 'a', ('array', 10, ('add', 10, 'x'))) == [(('range', 64, 6), ('mask_shl', 48, ('mask_shl', 253, 0, 3, ('add', 4, 'x')), ('mul', -1, ('mask_shl', 253, 0, 3, ('add', 4, 'x'))), 'a')), (('range', 70, ('add', 4, 'x')), ('array', 10, ('add', 4, 'x')))]
"""


def splits_len(split_list):
    sum_range = 0
    for el in split_list:
        el_range = el[0]
        sum_range = add_op(sum_range, el_range[2])

    return sum_range


"""
test_s = splits_mem(('range', 64, 32), ('range', 65, 32), 'a','b')
assert splits_len(test_s) == 32

test_s = splits_mem(('range', 64, 32), ('range', 65, 30), 'a','b')
assert splits_len(test_s) == 32, test_s
"""


def replace_max_with_MAX(exp):
    if opcode(exp) != "max":
        return exp, None

    exp = max_to_add(exp)

    res = exp

    for e in exp:
        if opcode(e) == "max":
            res = e

    exp = replace(exp, res, "MAX")
    exp = simplify(exp)
    return exp, res


def fill_mem(exp, split, split_val):
    """
    The memory read `exp` (("mem", range)) after the write of `split_val`
    to the range `split`: `exp` unchanged when they cannot be compared, the
    written value when they are the same range, else ("data", ...) of the
    parts read before, inside and after the written range. Every part has an
    explicit byte width (see with_width).
    """
    if exp == ("mem", split):
        return with_width(split_val, split[2])

    op, memloc = exp
    assert op == "mem"
    op, m_left, m_len = memloc
    assert op == "range"
    op, s_left, s_len = split
    assert op == "range"

    m_right = add_op(m_left, m_len)
    s_right = add_op(s_left, s_len)

    logger.debug("orig memloc: %s len %s right %s", m_left, m_len, m_right)
    logger.debug("split memloc: %s len %s right %s", s_left, s_len, s_right)

    if (
        safe_le_op(m_right, s_left) is not False
    ):  # if the split is before memory, or we can't compare - not replacing
        logger.debug("split before memory or can't compare - not replacing")
        return exp

    if safe_le_op(s_right, m_left) is not False:  # -,,- after memory
        logger.debug("split after memory or can't compare - not replacing")
        return exp

    left = safe_max_op(s_left, m_left)
    right = safe_min_op(s_right, m_right)

    logger.debug("split begins at %s ends at %s", left, right)

    if left is None or right is None:
        return exp  # if we can't figure out which one is smaller/larger, we're not replacing

    memloc, memloc_max = replace_max_with_MAX(memloc)
    split, split_max = replace_max_with_MAX(split)
    # 'max' op tends to mess up with all the algebra stuff, so we're replacing
    # it with a variable 'MAX' for the time being

    if split_max != memloc_max:
        logger.warning("different maxes")
        return exp

    # by now we know:
    # - the split overlaps memory for sure
    # - we know the boundaries of split
    # - so we now return data (before_split, split_val, after_split)

    res_left = slice_exp(exp, 0, sub_op(left, m_left))
    if res_left is None:
        return exp
    logger.debug("value left untouched on left: %s", res_left)

    res_right = slice_exp(exp, sub_op(right, m_left), sub_op(m_right, m_left))
    if res_right is None:
        return exp

    logger.debug("value right untouched on right: %s", res_right)

    res = []

    if safe_gt_zero(sizeof(res_left)) is True:
        logger.debug("size of left untouched > 0, adding to output")
        res.append(res_left)

    elif safe_gt_zero(sizeof(res_left)) is None:
        logger.debug("we don't know if left size > 0, aborting")
        return exp

    center_in_start = sub_op(left, s_left)
    center_in_end = sub_op(right, s_left)

    logger.debug("inserted value offset %s, end %s", center_in_start, center_in_end)
    logger.debug("cutting this out of %s", split_val)

    res_center = slice_exp(split_val, center_in_start, center_in_end, total=s_len)

    logger.debug("inserted value after slicing: %s", res_center)

    if res_center is None:
        return exp

    res_center = with_width(res_center, sub_op(right, left))
    if res_center is None:
        return exp

    res.append(res_center)

    if safe_ge_zero(sizeof(res_right)) is True:
        if sizeof(res_right) != 0:
            res.append(res_right)
    elif safe_ge_zero(sizeof(res_right)) is None:
        return exp

    assert None not in res

    return ("data",) + tuple(res)


@cached
def range_overlaps(range1, range2):
    op, r1_begin, r1_len = range1
    assert op == "range"
    op, r2_begin, r2_len = range2
    assert op == "range"

    r1_end = add_op(r1_begin, r1_len)
    r2_end = add_op(r2_begin, r2_len)

    try:
        if lt_op(r2_begin, r1_begin):
            r1_begin, r1_end, r2_begin, r2_end = r2_begin, r2_end, r1_begin, r1_end

        # r1 begins before r2 for sure now
        return le_op(r1_end, r2_begin) is not True

    except CannotCompare:
        return None


@cached
def range_contains(outer, inner):
    # checks if outer range *fully* contains inner range
    op, outer_begin, outer_len = outer
    assert op == "range"
    op, inner_begin, inner_len = inner
    assert op == "range"

    outer_end = add_op(outer_begin, outer_len)
    inner_end = add_op(inner_begin, inner_len)

    try:
        if not le_op(outer_begin, inner_begin):
            return False

        if not le_op(inner_end, outer_end):
            return False

        return True

    except CannotCompare:
        return None


assert (
    range_overlaps(
        (
            "range",
            ("add", 256, ("mask_shl", 246, 5, 0, ("ext_call.return_data", 128, 32))),
            32,
        ),
        ("range", 160, 96),
    )
    == False
)

assert range_overlaps(("range", 260, 32), ("range", 292, 32)) == False
assert range_overlaps(("range", 324, 32), ("range", 292, 32)) == False
assert range_overlaps(("range", 292, 32), ("range", 300, 32)) == True
assert range_overlaps(("range", 300, 32), ("range", 292, 32)) == True


assert range_contains(("range", 64, 10), ("range", 64, 32)) == False
assert range_contains(("range", 64, 32), ("range", 64, 10)) == True
assert range_contains(("range", 64, 32), ("range", 64, 32)) == True
assert range_contains(("range", 64, 32), ("range", ("var", 1), 32)) == None
assert range_contains(("range", 10, 32), ("range", 100, "x")) == False

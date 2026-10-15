"""
Soundness of the algebra, the condition evaluator and the memory model:
each case is a rewrite that used to change the value of an expression, or a
memory access that was resolved to the wrong bytes.

Values are checked with the concrete evaluator of test_simplify_fuzz (EVM
word semantics), shapes only where the shape is the contract (byte widths).
"""

import pytest

from scobelix.core import arithmetic
from scobelix.core.algebra import add_op, apply_mask, mul_op
from scobelix.core.masks import to_mask
from scobelix.core.memloc import (
    part_width,
    self_width,
    slice_exp,
    split_or,
    split_setmem,
    split_store,
    splits_mem,
    with_width,
)
from scobelix.simplify import cleanup_mems, simplify_exp, trace_uses_mem
from scobelix.stack import Stack
from scobelix.utils.helpers import to_exp2

from test_simplify_fuzz import M, evaluate

X, Y = ("cd", 4), ("cd", 36)
ENVS = [
    {X: x, Y: y}
    for x in (0, 1, 31, 32, 0xFF, 0x1200, 0x1234, 2**160 - 1, 2**255 + 7, M - 1, M - 32)
    for y in (0, 3, 2**64 + 1, M - 1)
]


def same_value(a, b):
    return all(evaluate(a, env) == evaluate(b, env) for env in ENVS)


def keeps_value(e):
    return same_value(e, simplify_exp(e))


PANIC = 0x4E487B71
CEIL32_TWICE = ("mask_shl", 256, 5, 0, ("add", 31, ("mask_shl", 251, 5, 0, ("add", 31, X))))


# ------------------------------------------------------------------ algebra


def test_powers_of_two_are_exact():
    assert to_exp2(2**224) == 224
    assert to_exp2(2**256 - 1) is None  # log2 rounds it to 256.0
    assert to_exp2(2**224 + 2) is None
    assert to_exp2(2**128 + 1) is None
    assert keeps_value(("mul", 2**224 + 2, X))
    assert keeps_value(("mod", X, M - 1))
    assert keeps_value(("div", X, 2**128 + 1))


@pytest.mark.parametrize(
    "exp",
    [
        ("add", X, ("mul", 32, X)),  # x + 32x
        ("add", ("mul", 2, X), X),
        ("add", X, ("mul", -1, ("mul", 32, X))),  # x - 32x
        ("add", ("mul", 256, X), X),
        ("add", ("mul", 2, X), ("mul", 2**224, X)),
        ("add", ("mask_shl", 8, 0, 8, X), ("mask_shl", 16, 0, 0, X)),
        ("add", ("mul", -1, X), ("mul", 3, ("mask_shl", 251, 0, 5, X))),  # -x + 3 * (x << 5)
        ("add", ("mask_shl", 32, 0, 0, X), ("mul", -1, ("mask_shl", 8, 0, 0, X))),
    ],
)
def test_additions_of_multiples(exp):
    assert keeps_value(exp)


def test_concrete_masks_are_words():
    assert apply_mask(2**255, 256, 0, 1) == 0  # shifted out of the word
    assert apply_mask(-1, 256, 8, -8) == 2**248 - 1  # -1 is the word 2**256 - 1
    assert apply_mask(5, 0, 0, 0) == 0
    assert apply_mask(0xABCD, 8, -4, 0) == 0xD  # a negative offset: the low 4 bits


def test_hostile_mask_sizes_stay_small():
    # sizes, offsets and shifts taken from the code: 2**size would need
    # gigabytes, the clamped evaluation is instant and exact
    huge = 2**255 + 12345
    assert apply_mask(M - 1, huge, 0, 0) == M - 1
    assert apply_mask(M - 1, 8, huge, 0) == 0
    assert apply_mask(M - 1, huge, 8, -8) == 2**248 - 1
    assert apply_mask(M - 1, 8, 0, huge) == 0
    assert apply_mask(M - 1, 8, 248, -huge) == 0
    code = int.from_bytes(bytes(range(1, 101)), "big")  # 100 bytes of copied code
    assert apply_mask(code, huge, 0, 0) == code
    assert apply_mask(code, 16, 8 * 98, -8 * 98) == 0x0102  # its first two bytes
    assert apply_mask(code, 8, 0, huge) == 0
    assert apply_mask(256 * 2**255, 32, 224, 96) == 0  # an unreduced product, shifted out
    assert to_mask(huge) is None or to_mask(huge)[0] <= 256
    assert simplify_exp(("bytes", huge, 5)) == ("bytes", huge, 5)
    assert simplify_exp(("bytes", 2, code)) == ("bytes", 2, 0x6364)
    assert arithmetic.to_real_int(code) == code  # not a two's complement word
    assert simplify_exp(("mask_shl", 8, 0, huge, X)) in (0, ("mask_shl", 8, 0, huge, X))


@pytest.mark.parametrize(
    "exp",
    [
        ("mask_shl", 246, 5, 0, X),  # was widened to 251 bits
        ("mask_shl", 8, 8, -8, X),  # was taken as the low byte of a calldata word
        ("mask_shl", 64, 3, -3, Y),
        ("mask_shl", 251, 5, 0, ("add", 95, X)),  # floor32(x + 95) == 64 + floor32(x + 31)
        ("mask_shl", 246, 5, 0, ("add", 95, X)),
        ("iszero", ("mask_shl", 16, 0, 248, X)),  # the shift drops bits
        ("iszero", ("mask_shl", 8, 0, -3, X)),
        ("lt", ("add", X, 1), ("add", Y, 1)),  # no cancelling in orderings
        ("gt", ("add", X, Y), ("add", Y, 3)),
        ("eq", ("add", X, X, 1), ("add", X, Y)),  # multisets: x + 1 == y
        ("mul", -1, ("mask_shl", 16, 0, 0, ("mul", -1, X))),
        ("mask_shl", 251, 5, 0, ("add", 31, ("mask_shl", 251, 0, 5, X))),  # ceil32(32 x)
        ("mask_shl", 16, 0, 0, ("div", X, ("exp", 256, 2))),  # bits 16..31
        CEIL32_TWICE,
        ("mask_shl", 256, 5, 0, ("add", 31, ("mask_shl", 251, 5, 0, ("add", 31, X, Y)))),
        ("mask_shl", 251, 5, 0, ("add", 31, ("mask_shl", 246, 5, 0, ("add", 31, X)))),
    ],
)
def test_simplifier_rewrites_keep_values(exp):
    assert keeps_value(exp)


def test_ceil32_is_idempotent():
    # ceil32(ceil32(x)) == ceil32(x): a multiple of 32 plus 31 never wraps
    assert simplify_exp(CEIL32_TWICE) == simplify_exp(("mask_shl", 251, 5, 0, ("add", 31, X)))


def test_symbolic_low_bit_masks():
    # 256**k - 1 is the low 8k bits, like its concrete counterpart
    assert to_mask(("sub", ("exp", 256, Y), 1)) == (mul_op(8, Y), 0)
    assert to_mask(2**24 - 1) == (24, 0)
    # x & ~(256**k - 1): the top bits, the low 8k bits cleared
    k = 3
    exp = Stack.simplify(("and", X, ("not", ("add", -1, ("exp", 256, k)))))
    assert same_value(exp, ("and", X, (M - 1) ^ (256**k - 1)))


# ------------------------------------------------------------------ conditions


def test_conditions_are_words():
    assert arithmetic.eval_bool(-1) is True  # a two's complement word, non-zero
    assert arithmetic.eval_bool(False) is False
    assert arithmetic.eval_bool(0) is False
    assert arithmetic.eval(("lt", 5, -1)) == 1  # 5 < 2**256 - 1
    assert arithmetic.eval(("eq", -1, M - 1)) == 1
    assert arithmetic.eval(("addmod", M - 1, 2, 7)) == (M + 1) % 7
    assert arithmetic.eval(("sdiv", -6, 3)) == M - 2
    assert arithmetic.eval(("sar", 300, M - 1)) == M - 1
    assert arithmetic.eval(("add", 1, 2, 3)) == 6
    assert arithmetic.eval(("or", 1, 2, 4)) == 7


def test_known_conditions_do_not_assume_no_wrap():
    # x < n does not give x < n + 1: n + 1 wraps to 0 for n = 2**256 - 1
    known = ("lt", X, Y)
    assert arithmetic.eval_bool(("lt", X, add_op(1, Y)), known, symbolic=False) is None


def test_negation_of_a_bitwise_and():
    # !(a & b) is !a | !b for 0/1 values only (1 & 2 == 0)
    neg = arithmetic.is_zero(("and", X, Y))
    assert same_value(neg, ("iszero", ("and", X, Y)))
    neg = arithmetic.is_zero(("and", ("lt", X, 5), ("iszero", Y)))
    assert same_value(neg, ("iszero", ("and", ("lt", X, 5), ("iszero", Y))))


# ------------------------------------------------------------------ memory


def resolve(trace):
    """cleanup_mems until nothing changes (simplify_trace runs it in a loop)."""
    trace = [tuple(line) for line in trace]
    for _ in range(5):
        new = cleanup_mems(trace)
        if new == trace:
            break
        trace = new
    return trace


def test_byte_widths():
    assert self_width(("mem", ("range", 0, 20))) == 20
    assert self_width(("call.data", 4, 3)) == 3
    assert self_width(("bytes", 4, 7)) == 4
    assert self_width(X) is None
    assert part_width(("data", ("bytes", 4, 7), X)) == 36
    assert with_width(X, 32) == X
    assert with_width(7, 4) == ("bytes", 4, 7)
    assert with_width(("mem", ("range", 0, 20)), 32) == ("bytes", 32, ("mem", ("range", 0, 20)))
    assert simplify_exp(("bytes", 4, 2**32 + 1)) == ("bytes", 4, 1)
    assert simplify_exp(("bytes", 32, X)) == X


def test_slices_use_the_width_they_were_stored_with():
    # the top 4 bytes of a 4-byte value are the value, not 0
    assert simplify_exp(slice_exp(PANIC, 0, 4, total=4)) == PANIC
    # the 32 bytes of a masked word stored by mstore are the masked word
    assert simplify_exp(slice_exp(("mask_shl", 160, 0, 0, X), 0, 32, total=32)) == (
        "mask_shl", 160, 0, 0, X,
    )
    # a 20-byte slice stored in a 32-byte word is right-aligned (zero padding)
    assert slice_exp(("mem", ("range", 0, 20)), 0, 4, total=32) is None
    assert slice_exp(("mem", ("range", 0, 20)), 12, 32, total=32) == ("mem", ("range", 0, 20))


def test_revert_payloads_keep_their_selector():
    panic = resolve([
        ("setmem", ("range", 0, 32), PANIC << 224),
        ("setmem", ("range", 4, 32), 17),
        ("revert", ("mem", ("range", 0, 36))),
    ])
    assert panic == [("revert", ("data", ("bytes", 4, PANIC), 17))]
    custom = resolve([
        ("setmem", ("range", 0, 32), 0x3DB2A12A << 224),
        ("revert", ("mem", ("range", 0, 4))),
    ])
    assert custom == [("revert", ("bytes", 4, 0x3DB2A12A))]


def test_masked_words_are_not_shifted():
    words = resolve([
        ("setmem", ("range", 128, 32), ("mask_shl", 160, 0, 0, X)),
        ("setmem", ("range", 160, 32), 0),
        ("return", ("mem", ("range", 128, 64))),
    ])
    assert words == [("return", ("data", ("mask_shl", 160, 0, 0, X), 0))]


def test_packed_parts_have_their_width():
    # abi.encodePacked(address, uint256): 20 + 32 bytes
    packed = resolve([
        ("setmem", ("range", 128, 32), ("mask_shl", 160, 0, 96, X)),
        ("setmem", ("range", 148, 32), Y),
        ("return", ("mem", ("range", 128, 52))),
    ])
    assert packed == [("return", ("data", ("bytes", 20, ("mask_shl", 160, 0, 0, X)), Y))]


def test_single_byte_writes():
    word = resolve([
        ("setmem", ("range", 0, 32), 0),
        ("setmem", ("range", 0, 1), 0x42),
        ("setmem", ("range", 1, 1), 0x43),
        ("return", ("mem", ("range", 0, 32))),
    ])
    assert word == [("return", 0x4243 << 240)]


def test_zero_words_keep_their_count():
    assert resolve([
        ("setmem", ("range", 0, 32), 0),
        ("setmem", ("range", 32, 32), 0),
        ("return", ("mem", ("range", 0, 64))),
    ]) == [("return", ("data", 0, 0))]


def test_writes_that_may_overlap_stop_the_replacement():
    # mem[cd[4]] may be mem[0]: the read cannot be the first value
    trace = resolve([
        ("setmem", ("range", 0, 32), 1),
        ("setmem", ("range", X, 32), 2),
        ("return", ("mem", ("range", 0, 32))),
    ])
    assert trace[-1] != ("return", 1)


def test_addresses_computed_from_memory():
    # mem[mem[64]] = 7; mem[64] = 224; mem[mem[64]] = 9: the first write is
    # at 128 and stays there
    trace = resolve([
        ("setmem", ("range", 64, 32), 128),
        ("setmem", ("range", ("mem", ("range", 64, 32)), 32), 7),
        ("setmem", ("range", 64, 32), 224),
        ("setmem", ("range", ("mem", ("range", 64, 32)), 32), 9),
        ("return", ("mem", ("range", 128, 32))),
    ])
    assert trace[-1] == ("return", 7)
    # a write whose length is read from memory uses that memory
    later = [("setmem", ("range", 256, ("mem", ("range", 128, 32))), 0), ("stop",)]
    assert trace_uses_mem(later, ("range", 128, 32)) is True


def test_simplification_keeps_payload_lengths():
    # a 32-byte word whose value is a 20-byte slice stays 32 bytes long
    word = ("mask_shl", 256, 0, 0, ("mem", ("range", 0, 20)))
    assert part_width(simplify_exp(word)) == 32
    assert part_width(simplify_exp(("data", ("bytes", 4, 1), word))) == 36


def test_folded_constants_are_words():
    # a constant product or sum past 2**256 is reduced: an int that wide
    # would read as a byte string (copied code) under a mask
    assert mul_op(2**200, 2**100) == 0
    assert add_op(2**255, 2**255) == 0
    assert add_op(2**255, 2**255, X) == X
    for e in (("mask_shl", 256, 0, 0, ("mul", 2**200, 2**60)), ("mask_shl", 8, 296, -296, ("mul", 2**200, 2**100))):
        assert simplify_exp(e) == 0


# ------------------------------------------------------------------ splits

OFF5 = ("mask_shl", 5, 0, 0, ("cd", 132))  # a byte offset known at runtime
TAIL = ("mask_shl", 253, 0, 3, ("add", 32, ("mul", -1, OFF5)))  # 8 * (32 - OFF5)
# the last word of a memory copy: high bytes from X, low bytes from Y
COPY_TAIL = ("or", ("mask_shl", ("add", 256, ("mul", -1, TAIL)), TAIL, 0, X), ("mask_shl", TAIL, 0, 0, Y))


def test_or_of_runtime_sized_fields_is_kept_whole():
    # the fields cannot be placed: never one term alone
    assert split_or(COPY_TAIL) == [(256, 0, COPY_TAIL)]
    line = ("setmem", ("range", 128, 32), COPY_TAIL)
    assert split_setmem(line) == [line]
    # (a << n) | b with n from calldata, written to storage
    shifted = ("or", ("mask_shl", 256, 0, ("mask_shl", 8, 0, 0, ("cd", 68)), X), Y)
    store = ("store", 256, 0, 3, shifted)
    assert split_store(store) == [store]


def test_a_word_written_over_more_than_32_bytes_is_not_split():
    # 32 zero bytes, then the word: the fields of the word do not say so
    value = ("or", ("mask_shl", 128, 128, 0, X), ("mask_shl", 64, 0, 0, Y))
    line = ("setmem", ("range", 132, 64), value)
    assert split_setmem(line) == [line]
    assert len(split_setmem(("setmem", ("range", 132, 32), value))) == 3


def test_split_pieces_stay_inside_the_written_range():
    # mem[160 + off5 len 32] = Y, then mem[140 len 32] is overwritten: when
    # off5 > 12 the two do not overlap, so [172, ...) is not known to be Y
    written = ("range", ("add", 160, OFF5), 32)
    assert splits_mem(written, ("range", 140, 32), Y) == []
    # when they surely overlap, the bytes past the write are still known
    assert splits_mem(("range", 160, 32), ("range", 140, 32), Y) == [
        (("range", 172, 20), ("mask_shl", 160, 0, 0, Y))
    ]

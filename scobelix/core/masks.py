from scobelix.utils.helpers import cached, cleanup_mul_1, opcode, to_exp2

from scobelix.core.algebra import mul_op


def type_to_mask(s):
    """The width in bits of a value of the elementary type `s`, else None."""
    lookup = {
        "bool": 1,
        "address": 160,
        "int": 256,
        "uint": 256,
    }

    if s in lookup:
        return lookup[s]

    for prefix, unit in (("uint", 1), ("int", 1), ("bytes", 8)):
        if s.startswith(prefix) and s[len(prefix) :].isdigit():
            n = int(s[len(prefix) :]) * unit
            if 0 < n <= 256:
                return n

    return None


def mask_to_type(num, force=False):
    # force causes to always return some soft of type,
    # if it's not found in the lookup then the smallest
    # one that fits

    lookup = {
        1: "bool",
        8: "uint8",
        16: "uint16",
        32: "uint32",
        64: "uint64",
        128: "uint128",
        160: "address",
        256: "uint256",
    }

    if type(num) != int:
        return num

    if num in lookup:
        return lookup[num]

    if 0 < num < 256 and num % 8 == 0:
        return "uint%d" % num  # any byte count is a Solidity width

    if force:
        if num > 256:
            return "big" + str(num)

        for mask, res in lookup.items():
            if mask > num:
                return lookup[mask]

        assert False

    else:
        return None


def get_bit(num, pos):
    return (num >> pos) & 1


def mask_to_int(size, offset):
    """
    (2**size - 1) << offset (a negative offset shifts right) as bits of a
    256-bit word: size and offset come from the code and are clamped to the
    word, so that hostile ones cannot build huge ints.
    """
    assert type(size) == int, size
    assert type(offset) == int, offset

    if offset < 0:
        size, offset = size + offset, 0
    size = min(size, 256 - offset)
    if size <= 0:
        return 0
    return ((1 << size) - 1) << offset


def mask_runs(num):
    """The runs of ones of the 256-bit word `num`, lowest first, as
    (size, offset) pairs: 0x00ff00ff -> [(8, 0), (8, 16)]."""
    assert type(num) == int

    runs = []
    bit = 0
    while bit < 256:
        if get_bit(num, bit):
            start = bit
            while bit < 256 and get_bit(num, bit):
                bit += 1
            runs.append((bit - start, start))
        else:
            bit += 1
    return runs


assert mask_runs(0x00FF00FF) == [(8, 0), (8, 16)]
assert mask_runs(2**256 - 1) == [(256, 0)]
assert mask_runs(0) == []


def find_mask(num):
    # finds a mask that encompasses the number

    assert type(num) == int

    i = 0
    while get_bit(num, i) == 0 and i < 256:
        i += 1
    mask_pos = i - i % 8

    mask_pos_plus_len = 256

    while i < 256:
        if get_bit(num, i) != 0:
            mask_pos_plus_len = i - i % 8 + 8
        i += 1

    return (mask_pos_plus_len - mask_pos, mask_pos)


assert find_mask(0xFABBA10000) == (24, 16)
assert find_mask(0xFABBA10000) == (24, 16)
assert find_mask(0x7ABBA20000) == (24, 16)  # rounding to eights


@cached
def to_mask(num):
    num = cleanup_mul_1(num)

    if opcode(num) == "not":
        return to_neg_mask(num[1])

    if opcode(num) == "sub":
        if opcode(num[1]) == "exp" and num[2] == 1:
            # (2**m)**k - 1: the low m*k bits, like the concrete case below
            mul = to_exp2(num[1][1])
            if mul == None:
                return None

            mask_len = mul_op(mul, num[1][2])

            # add type assert, that num[1][2] < 32?

            return (mask_len, 0)

    if opcode(num) == "add" and num[1] == -1:
        return to_mask(
            (
                "sub",
                num[2],
                1,
            )
        )

    if type(num) != int:
        return None

    i = 0
    while get_bit(num, i) == 0 and i < 256:
        i += 1
    mask_pos = i

    while get_bit(num, i) == 1 and i < 256:
        i += 1
    mask_pos_plus_len = i

    while i < 256:
        if get_bit(num, i) != 0:
            return None
        i += 1

    return mask_pos_plus_len - mask_pos, mask_pos


def to_neg_mask(num):
    if opcode(num) == "not":
        return to_mask(num[1])

    if type(num) != int:
        return None

    i = 0
    while get_bit(num, i) == 1 and i < 256:
        i += 1
    mask_pos = i

    while get_bit(num, i) == 0 and i < 256:
        i += 1
    mask_pos_plus_len = i

    while i < 256:
        if get_bit(num, i) != 1:
            return None
        i += 1

    return mask_pos_plus_len - mask_pos, mask_pos

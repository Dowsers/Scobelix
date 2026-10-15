import itertools

from scobelix.utils.helpers import is_array, opcode

"""

    for a given expression, returns variants of it with each value being 0 or 2^256-1

    e.g. for ('ADD', ('mem', 64), ('mem', 256))
         returns
            ('ADD', 0, 0),
            ('ADD', 0, MAX_number),
            ('ADD', MAX_number, 0),
            ('ADD', MAX_number, MAX_number)

    The variants are every combination of the candidate values of the
    variables (their cartesian product), and each one replaces all the
    variables at once: the result does not depend on the order in which the
    variables are found, nor on hashing (a decompilation must not depend on
    PYTHONHASHSEED).

"""


MAX_number = 2**230 - 1
MAX_number2 = 2**230 - 1

FREE_MEMORY_POINTER = ("mem", ("range", 64, 32))


def variants(exp):
    var = extract_variables(exp)
    for p in possibilities(var):
        yield replace_dict(exp, p)


"""

    implementation

"""


def extract_variables(exp):
    """The variables of `exp`, each once, in the order of their first
    occurrence (a list)."""
    found = {}
    _collect_variables(exp, found)
    return list(found)


def _collect_variables(exp, found):
    if type(exp) == int:
        return

    if opcode(exp) in (
        "var",
        "mem",
        "cd",
        "storage",
        "call.data",
        "sha3",
        "calldatasize",
    ) or is_array(opcode(exp)):
        found[exp] = True
        return

    if type(exp) == str and exp in (
        "x",
        "y",
        "z",
        "sth",
        "unknown",
        "undefined",
        "callvalue",
        "number",
        "timestamp",
        "address",
    ):
        found[exp] = True
        return

    if type(exp) == str and exp != "data" and "data" in exp:
        found[exp] = True
        return

    if type(exp) != tuple:
        found[exp] = True
        return

    for e in exp[1:]:
        _collect_variables(e, found)


def candidate_values(var):
    """The values a variable takes in the variants (each once)."""
    if var == FREE_MEMORY_POINTER:
        low = 96
    elif var == "calldatasize":
        low = 6  # nasty hack for `sweeper` contract, try to remove and see what happens
    else:  # can theoretically cause bugs in other ones
        low = 0
    return tuple(dict.fromkeys((MAX_number, MAX_number2, low)))


def possibilities(var):
    """Every assignment of candidate values to the variables `var` (a
    sequence): the cartesian product of their candidate values."""
    var = list(var)
    if not var:
        return
    for values in itertools.product(*(candidate_values(v) for v in var)):
        yield dict(zip(var, values))


def replace(exp, idx, val):
    if exp == idx:
        return val

    if type(exp) != tuple:
        return exp

    return tuple(replace(e, idx, val) for e in exp)


def replace_dict(exp, dic):
    """`exp` with every occurrence of a key of `dic` replaced by its value,
    all at once and outermost first (a variable inside another one, such as
    a `var` in the index of a `mem`, goes with it): the result does not
    depend on the order of `dic`."""
    return _replace_all(exp, tuple(dic.items()))


def _replace_all(exp, items):
    # equality tests, not a dict lookup: hashing every subexpression of a
    # large expression costs more than comparing it with the few variables
    for idx, val in items:
        if exp == idx:
            return val

    if type(exp) != tuple:
        return exp

    return tuple(_replace_all(e, items) for e in exp)

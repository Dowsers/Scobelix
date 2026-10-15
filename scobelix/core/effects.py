"""
Time-dependent values and the trace lines that change them.

A read of mutable state means the value the state has when the read
happens. The VM therefore binds every such read to a fresh variable at the
line where it happens, `("setvar", "_N", read)` (see VM.apply_stack): storage
(`storage`), transient storage (`tload`), balances (`balance`), the code of
an account (`extcodesize`, `extcodehash`, `extcodecopy`) and the results of
the last external call (its success flag, return data and size, a created
address, a precompile output).

The simplifier may move such a value to the places where the variable is
used, but never past a line that can change it. `changes(line)` and
`kinds(exp)` tell which: `changes(line) & kinds(exp)` is not empty when
`line` can give `exp` another value.

Hence the meaning of the final trace: an atom means its value at the line
where it appears (operands of a line are evaluated before the line's own
effect), and a call result atom refers to the most recent call of its kind
before that line on the path. A value read earlier and used after a change
stays bound to its `setvar` at the place of the read.
"""

import functools

from scobelix.utils.helpers import opcode, precompiled, precompiled_var_names

STORAGE = "storage"
TRANSIENT = "transient"
BALANCE = "balance"
CODE = "code"
RESULT = "result"  # success, return data and returndatasize of the last call

ALL = frozenset((STORAGE, TRANSIENT, BALANCE, CODE, RESULT))
NONE = frozenset()

# What a line can change. A static call changes only the return data buffer;
# any other call (and a contract creation) can re-enter this contract and
# change everything. A precompile replaces the return data buffer.
_LINE_EFFECTS = {
    "store": frozenset((STORAGE,)),
    "tstore": frozenset((TRANSIENT,)),
    "staticcall": frozenset((RESULT,)),
    "precompiled": frozenset((RESULT,)),
    "call": ALL,
    "callcode": ALL,
    "delegatecall": ALL,
    "create": ALL,
    "create2": ALL,
    "selfdestruct": ALL,
}

# Atoms naming a result of the last call of their kind.
RESULT_ATOMS = frozenset(
    (
        "ext_call.success",
        "callcode.return_code",
        "returndatasize",
        "create.new_address",
        "create2.new_address",
    )
    + tuple(f"{name}.result" for name in precompiled.values())
)

# Expression heads and the state they read.
_HEADS = {
    "storage": STORAGE,
    "tload": TRANSIENT,
    "balance": BALANCE,
    "extcodesize": CODE,
    "extcodehash": CODE,
    "extcodecopy": CODE,
    "ext_call.return_data": RESULT,
    "delegate.return_data": RESULT,
    "callcode.return_data": RESULT,
}

# Variables the VM names after a call: a precompile output, the success of a
# delegatecall ("delegatecall_N.success").
_RESULT_VARS = frozenset(precompiled_var_names.values())

def changes(line):
    """The kinds of state `line` can change; a `while` with its body. An `if`
    changes nothing by itself: callers look into its branches (see
    trace_changes), which run instead of the rest of the trace."""
    op = opcode(line)
    if op == "while":
        return trace_changes(line[2])
    return _LINE_EFFECTS.get(op, NONE)


def trace_changes(trace):
    """The kinds of state any line of `trace` can change, the branches of its
    ifs included."""
    res = NONE
    for line in trace:
        if opcode(line) == "if":
            res = res | trace_changes(line[2]) | trace_changes(line[3])
        else:
            res = res | changes(line)
        if res == ALL:
            break
    return res


def kinds(exp):
    """The kinds of mutable state the value of `exp` depends on."""
    try:
        return _kinds(exp)
    except TypeError:  # a list somewhere inside: not hashable
        return _kinds.__wrapped__(exp)


@functools.lru_cache(maxsize=1 << 14)
def _kinds(exp):
    if type(exp) == str:
        return frozenset((RESULT,)) if exp in RESULT_ATOMS else NONE
    if type(exp) not in (tuple, list) or not exp:
        return NONE
    head = exp[0]
    if head == "var" and len(exp) == 2 and type(exp[1]) == str:
        name = exp[1]
        if name in _RESULT_VARS or (
            name.startswith("delegatecall_") and name.endswith(".success")
        ):
            return frozenset((RESULT,))
        return NONE
    res = NONE
    kind = _HEADS.get(head) if type(head) == str else None
    if kind is not None:
        res = frozenset((kind,))
    for e in exp[1:]:
        if type(e) in (tuple, list, str):
            res = res | kinds(e)
    return res


def clobbers(line, exp):
    """True when `line` can change the value of `exp` (an `if`: never, see
    changes). A store changes the storage reads of `exp` only when its slot
    may be one of theirs (see disjoint_slots)."""
    k = kinds(exp)
    if not k:
        return False
    hit = changes(line) & k
    if not hit:
        return False
    if hit == STORAGE_ONLY and changes(line) == STORAGE_ONLY:
        # only stores: they matter when one may write a field exp reads
        targets = _store_fields([line])
        fields = storage_slots(exp)
        if targets is not None and fields is not None:
            return not all(_disjoint_fields(t, f) for t in targets for f in fields)
    return True


def _store_fields(trace):
    """The fields the stores of `trace` write (loops and branches included),
    None when one is unknown."""
    res = []
    for line in trace:
        op = opcode(line)
        if op == "store":
            f = _field(line[1], line[2], line[3])
            if f is None:
                return None
            res.append(f)
        elif op in ("while", "if"):
            for part in line[1:]:
                if isinstance(part, list):
                    sub = _store_fields(part)
                    if sub is None:
                        return None
                    res.extend(sub)
    return res


def _field(size, off, slot):
    """(slot, first bit, end bit) of a `storage`/`store` node, the slot
    moved by whole words of the offset; None when unknown."""
    s = _effective_slot(slot, off)
    if s is None:
        return None
    if type(size) == int and 0 < size <= 256 and off % 256 + size <= 256:
        return s, off % 256, off % 256 + size
    return s, 0, 256


def _disjoint_fields(a, b):
    if disjoint_slots(a[0], b[0]):
        return True
    return a[0] == b[0] and (a[2] <= b[1] or b[2] <= a[1])


STORAGE_ONLY = frozenset((STORAGE,))
_WORD = 2**256


def _effective_slot(slot, off):
    """The slot a `storage`/`store` node really reads or writes: an offset of
    256 bits or more moves to the next slots. None when unknown."""
    if type(off) != int:
        return None
    k = off // 256
    if k == 0:
        return slot
    if type(slot) == int:
        return (slot + k) % _WORD
    return ("add", k, slot)


def storage_slots(exp):
    """The fields (slot, first bit, end bit) of the storage reads in `exp`,
    None when one is unknown."""
    res = []

    def walk(e):
        if type(e) not in (tuple, list):
            return True
        if len(e) == 4 and e[0] == "storage":
            f = _field(e[1], e[2], e[3])
            if f is None:
                return False
            res.append(f)
        return all(walk(x) for x in e[1:] if type(x) in (tuple, list))

    return res if walk(exp) else None


def _split_const(e):
    """e as (symbolic base or None, constant offset mod 2**256)."""
    if type(e) == int:
        return None, e % _WORD
    if type(e) == tuple and e and e[0] == "add":
        k = sum(t for t in e[1:] if type(t) == int) % _WORD
        rest = tuple(t for t in e[1:] if type(t) != int)
        if not rest:
            return None, k
        return (rest[0] if len(rest) == 1 else ("add",) + rest), k
    return e, 0


def _is_hash(e):
    return type(e) == tuple and len(e) == 2 and e[0] == "sha3"


def _words(p):
    """The 32-byte words of a hashed byte string, None when not all known."""
    if type(p) == tuple and p and p[0] == "data":
        parts = p[1:]
    else:
        parts = (p,)
    for x in parts:
        if type(x) == tuple and x and x[0] in _BYTE_STRINGS:
            return None
    return parts


# parts of a byte string that are not one 32-byte word
_BYTE_STRINGS = ("bytes", "mem", "data", "call.data", "code.data", "extcodecopy",
                 "ext_call.return_data", "delegate.return_data", "callcode.return_data")


def _distinct_words(a, b):
    """True when the words a and b are certainly different values (hashes
    are taken as collision-free, and never equal to a constant)."""
    if a == b:
        return False
    if type(a) == int and type(b) == int:
        return a % _WORD != b % _WORD
    if _is_hash(a) and _is_hash(b):
        return _distinct_preimages(a[1], b[1])
    return (type(a) == int and _is_hash(b)) or (type(b) == int and _is_hash(a))


def _distinct_preimages(p, q):
    wp, wq = _words(p), _words(q)
    if wp is None or wq is None:
        return False
    if len(wp) != len(wq):
        return True
    return any(_distinct_words(x, y) for x, y in zip(wp, wq))


def _hash_based(base, k):
    """True when base is a hash, or a hash plus other terms (an element of a
    dynamic array or mapping at a computed index), and k a small constant
    slot (< 2**64): Solidity places such elements away from the declared
    slots."""
    if _is_hash(base):
        return True
    return (
        k < 2**64
        and type(base) == tuple
        and base[0] == "add"
        and any(_is_hash(t) for t in base[1:])
    )


def disjoint_slots(a, b):
    """True when slots a and b are certainly different. Same symbolic base:
    different constant offsets. A hash (mapping, dynamic array), plus an
    index or not, never equals a small constant slot, nor a hash of another
    preimage plus a constant: the assumptions the Solidity storage layout
    itself rests on."""
    base_a, ka = _split_const(a)
    base_b, kb = _split_const(b)
    if base_a == base_b:
        return ka != kb
    if base_a is None:
        return _hash_based(base_b, ka)
    if base_b is None:
        return _hash_based(base_a, kb)
    if _is_hash(base_a) and _is_hash(base_b):
        return _distinct_preimages(base_a[1], base_b[1])
    return False

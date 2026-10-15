import collections
import json
import logging
from copy import deepcopy

from scobelix.core.arithmetic import simplify_bool
from scobelix.core.masks import mask_to_type, type_to_mask
from scobelix.matcher import Any, match
from scobelix.prettify import explain_text, pprint_logic, prettify
from scobelix.utils.helpers import (
    COLOR_BLUE,
    COLOR_BOLD,
    COLOR_GRAY,
    COLOR_GREEN,
    COLOR_HEADER,
    COLOR_OKGREEN,
    COLOR_UNDERLINE,
    COLOR_WARNING,
    ENDC,
    FAIL,
    C,
    EasyCopy,
    color,
    contains,
    find_f,
    find_f_list,
    opcode,
    replace_f,
)
from scobelix.utils.signatures import (
    get_abi_name,
    get_func_name,
    get_func_params,
    set_func,
    set_func_params_if_none,
)

logger = logging.getLogger(__name__)


def _memory_seed_length(trace):
    """Number of leading memory writes: the memory state the VM seeds a run
    with (free memory pointer, zero slot, other writes of the dispatcher)
    when the simplifier could not prove it dead. A callvalue check that
    follows them still makes the function non-payable: memory writes are
    not observable when the check reverts."""
    k = 0
    while k < len(trace) and opcode(trace[k]) == "setmem":
        k += 1
    return k


def find_parents(exp, child):
    if type(exp) not in (list, tuple):
        return []

    res = []

    for e in exp:
        if e == child:
            res.append(exp)
        res.extend(find_parents(e, child))

    return res


BARE_REVERT = [("revert", None)]
WORD_MAX = 2**64 - 1  # the bound of the ABI v2 offset and length checks
MAX_HEAD_WORDS = 1024  # largest head (static part of the arguments) given a slot per word

# lines that change state or emit an event: a function with one is not view
STATE_CHANGING_OPS = (
    "store",
    "tstore",
    "selfdestruct",
    "call",
    "delegatecall",
    "callcode",
    "create",
    "create2",
    "log",
)

# operators whose value depends on their operands only
PURE_OPS = frozenset(
    [
        "data", "bytes", "arr", "mask_shl", "add", "mul", "sub", "div", "sdiv", "mod",
        "smod", "exp", "addmod", "mulmod", "signextend", "and", "or", "xor", "not",
        "shl", "shr", "sar", "byte", "bool", "iszero", "eq", "lt", "gt", "le", "ge",
        "slt", "sgt", "sle", "sge", "max", "min", "sha3",
    ]
)

# a return of a string or bytes copied out of storage (solc < 0.8 getters)
STRING_COPY_RETURN = (
    "return",
    ("data", ("arr", ("storage", 256, 0, ("length", ":loc")), ...)),
)


def is_constant(exp):
    """True when `exp` is a constant: ints, byte strings and pure operators
    over them; no storage, calldata, memory or environment read."""
    if exp is None or type(exp) == int:
        return True
    if type(exp) in (list, tuple) and len(exp) > 0 and exp[0] in PURE_OPS:
        return all(is_constant(e) for e in exp[1:])
    return False


def fold_string_copies(trace, getter):
    """
    The display form of a string getter: a block whose only lines are the
    memory copy of the string (setmem, setvar, while) and its return becomes
    `return getter`; other lines (checks, stores, calls) and the branches of
    `if`s are kept.
    """
    if not trace:
        return trace
    res = []
    for line in trace:
        if m := match(line, ("if", ":cond", ":if_true", ":if_false")):
            line = (
                "if",
                m.cond,
                fold_string_copies(m.if_true, getter),
                fold_string_copies(m.if_false, getter),
            )
        res.append(line)
    folded = [("return", getter)]
    last = res[-1]
    # the copy ends in the return, or in a test of the length whose branches
    # both end in it (short and long strings are copied differently)
    ends_in_return = bool(match(last, STRING_COPY_RETURN)) or (
        opcode(last) == "if" and last[2] == folded and last[3] == folded
    )
    if ends_in_return and all(
        opcode(line) in ("setmem", "setvar", "while") for line in res[:-1]
    ):
        return folded
    return res


def _uint_type(size):
    if size == 160:
        return "address"
    if type(size) == int and 0 < size <= 256 and size % 8 == 0:
        return "uint%d" % size
    return mask_to_type(size, force=True)


def _revert_condition(line):
    """
    The condition under which `line` reverts with no payload (an `if` with a
    bare revert in one branch, a `require` of one), with the lines that run
    otherwise; (None, None) for any other line.
    """
    if m := match(line, ("if", ":cond", ":if_true", ":if_false")):
        if m.if_true == BARE_REVERT:
            return m.cond, m.if_false
        if m.if_false == BARE_REVERT:
            return ("iszero", m.cond), m.if_true
    if m := match(line, ("require", ":cond", ("revert", None))):
        return ("iszero", m.cond), None
    return None, None


def _prologue_conditions(trace):
    """
    The conditions of the leading checks that revert without a payload: the
    ABI decoder's (calldata size, offsets and lengths of dynamic parameters,
    the type validators of ABI coder v2), each as the condition under which
    the function reverts, in the order tested. Stops at the first other line.
    """
    conds = []
    lines = trace
    while lines:
        line = lines[0]
        if opcode(line) == "setmem":  # the memory seed
            lines = lines[1:]
            continue
        cond, rest = _revert_condition(line)
        if cond is None:
            break
        conds.append(cond)
        lines = rest if rest is not None else lines[1:]
    return conds


def _is_head_word(idx):
    """True for the calldata offset of a head word: 4 + 32 * j."""
    return type(idx) == int and idx >= 4 and (idx - 4) % 32 == 0


def _cleaned_type(exp, word):
    """The type whose cleanup of the head word `word` is `exp`, or None."""
    if exp == word:
        return "uint256"  # the cleanup of a 256-bit type keeps every bit
    if exp == ("bool", word):
        return "bool"
    if m := match(exp, ("mask_shl", ":int:size", ":int:off", 0, word)):
        if m.off == 0:
            return _uint_type(m.size)
        if m.size + m.off == 256 and m.size % 8 == 0:
            return "bytes%d" % (m.size // 8)
    if (m := match(exp, ("signextend", ":int:b", word))) and 0 <= m.b < 32:
        return "int%d" % (8 * (m.b + 1))
    return None


def _validator(cond):
    """
    (head word offset, type, coder_v2) when `cond`, a revert condition of the
    ABI decoder, is a type validator: the word differs from its cleanup
    (legacy ABI coder v2: iszero(eq(P, clean(P))); unoptimized code checks
    256-bit types too, against themselves: iszero(eq(P, P))), its bits above
    the type are set (via IR: mask_shl(256 - N, N, 0, P), also negated), or
    it is at or past the number of members of an enum (ge(P, K); coder_v2
    False: v1 checks enums too).
    """
    while True:
        if m := match(cond, ("iszero", ("iszero", ":x"))):
            cond = m.x
        elif m := match(cond, ("bool", ":x")):
            cond = m.x
        elif m := match(cond, ("mul", -1, ":x")):
            cond = m.x
        else:
            break

    if m := match(cond, ("iszero", ("eq", ":a", ":b"))):
        for word, exp in ((m.a, m.b), (m.b, m.a)):
            if (w := match(word, ("cd", ":int:idx"))) and (t := _cleaned_type(exp, word)):
                return w.idx, t, True

    if (
        m := match(cond, ("mask_shl", ":int:size", ":int:off", 0, ("cd", ":int:idx")))
    ) and m.size + m.off == 256 and 0 < m.off < 256:
        return m.idx, _uint_type(m.off), True

    if m := match(cond, ("add", ":a", ("mul", -1, ":b"))):
        for word, exp in ((m.a, m.b), (m.b, m.a)):
            if (w := match(word, ("cd", ":int:idx"))) and (t := _cleaned_type(exp, word)):
                return w.idx, t, True

    if (
        (m := match(cond, ("ge", ("cd", ":int:idx"), ":int:k")))
        or (m := match(cond, ("le", ":int:k", ("cd", ":int:idx"))))
    ) and 0 < m.k < 256:
        return m.idx, "uint8", False  # an enum: its ABI type

    return None


def _dynamic_check(cond):
    """
    (head word offset, kind) when `cond` is a decoder check of a dynamic
    parameter: its offset bound (kind "array", refined by the length bound to
    "bytes" when the length counts bytes, "array" when it counts words).
    """
    if (m := match(cond, ("gt", ("cd", ":int:idx"), ":int:k"))) and m.k in (WORD_MAX, 2**32):
        return m.idx, "array"
    if m := match(cond, ("gt", ("add", 36, ("cd", ":int:idx"), ":len"), "calldatasize")):
        length = ("cd", ("add", 4, ("cd", m.idx)))
        if m.len == length:
            return m.idx, "bytes"
        if m.len in (("mask_shl", 256, 0, 5, length), ("mul", 32, length)):
            return m.idx, "array"
    return None


def has_validators(trace):
    """True when the ABI decoder of the function checks a parameter's type
    (ABI coder v2 or via IR): then the contract decodes with coder v2."""
    return any((v := _validator(cond)) and v[2] for cond in _prologue_conditions(trace))


def _indexes_storage(trace, idx):
    """True when the head word `idx` is part of a storage slot expression
    (an array index, not an enum value)."""
    word = ("cd", idx)

    def slots(exp):
        if m := match(exp, ("storage", Any, Any, ":slot")):
            return [m.slot]
        if m := match(exp, ("store", Any, Any, ":slot", Any)):
            return [m.slot]
        return []

    return any(contains(slot, word) for slot in find_f_list(trace, slots))


def infer_params(trace, abi_coder_v2=None):
    """
    The parameter types of a function whose selector is unknown, from its
    code: {head word offset: (type, name)}.

    Evidence, strongest first: the validators of the ABI decoder (coder v2 and
    via IR check every value against its type: address, bool, uintN, intN,
    bytesN, enum), the decoder's offset and length checks (dynamic
    parameters), a head word used as an offset into calldata (dynamic), and,
    when the function has no validator (ABI coder v1 masks values where they
    are used), the narrowest mask, sign extension or boolean use of the word.
    A word of a function with validators but without one of its own is a
    256-bit type; so is every unchecked word when the contract is known to
    use ABI coder v2 (`abi_coder_v2`: another function of it has a
    validator). The calldata size check gives the number of head words, so an
    unused word keeps its place.
    """
    conds = _prologue_conditions(trace)
    heads = None
    validated = {}
    dynamic = {}
    coder_v2 = bool(abi_coder_v2)
    for cond in conds:
        if (
            (m := match(cond, (":op", ("add", -4, "calldatasize"), ":int:k")))
            and m.op in ("slt", "lt")
            and m.k % 32 == 0
        ):
            if 0 <= m.k <= 32 * MAX_HEAD_WORDS:  # (a bound from the code: kept sane)
                heads = m.k // 32
        elif v := _validator(cond):
            if not _is_head_word(v[0]):
                continue  # not a check of the decoder
            if not v[2] and _indexes_storage(trace, v[0]):
                continue  # the bound of an array index (a getter), not an enum
            validated[v[0]] = v[1]
            coder_v2 = coder_v2 or v[2]
        elif d := _dynamic_check(cond):
            if _is_head_word(d[0]) and (d[1] != "array" or d[0] not in dynamic):
                dynamic[d[0]] = d[1]

    def f(exp):
        if match(exp, ("mask_shl", Any, Any, Any, ("cd", Any))) or match(
            exp, ("cd", Any)
        ):
            return [exp]
        if (
            match(exp, ("signextend", ":int:b", ("cd", Any)))
            or match(exp, ("call.data", ("add", 36, ("cd", Any)), Any))
        ):
            return [exp]
        return []

    occurrences = find_f_list(trace, f)

    sizes = {}  # head word offset -> narrowest use-site type width, or a kind
    used = {}  # head word offset -> use-site type when narrower than a mask

    def narrower(idx, kind):
        # a dynamic kind wins over a width; "bytes" over "array"
        if kind in ("bytes", "array"):
            if sizes.get(idx) != "bytes":
                sizes[idx] = kind
            return
        if type(sizes.get(idx)) == str:
            return
        if idx not in sizes or kind < sizes[idx]:
            sizes[idx] = kind

    for o in occurrences:
        idx = None
        if m := match(o, ("mask_shl", ":size", ":off", ":shl", ("cd", ":idx"))):
            size, idx = m.size, m.idx
            if type(size) != int or type(m.off) != int:
                size = 256  # a mask of runtime width says nothing of the type
            elif type(m.shl) != int or m.shl < 0:
                # bits moved down (x >> k, a byte of x): a field read
                # out of the word, not a cleanup of the parameter
                size = 256
            elif m.off != 0:
                if m.size + m.off == 256 and m.size % 8 == 0 and m.shl == 0 and type(idx) == int:
                    used[idx] = "bytes%d" % (m.size // 8)  # a left-aligned value
                size = 256
            elif size + m.shl >= 256:
                # x << k (x * 2**k) keeps the bits the word has room for:
                # the shift's own truncation, not a cleanup
                size = 256
        elif m := match(o, ("signextend", ":int:b", ("cd", ":idx"))):
            idx, size = m.idx, 256
            if 0 <= m.b < 32 and type(idx) == int:
                used[idx] = "int%d" % (8 * (m.b + 1))
        elif m := match(o, ("call.data", ("add", 36, ("cd", ":int:idx")), ":len")):
            # the bytes of a dynamic parameter copied whole: by their count
            # (bytes, string) or by 32 per element (an array)
            idx = m.idx
            size = "bytes" if m.len == ("cd", ("add", 4, ("cd", idx))) else "array"
        elif m := match(o, ("cd", ":idx")):
            idx = m.idx
            size = 256

        if idx == 0:
            continue

        if m := match(idx, ("add", 4, ("cd", ":in_idx"))):
            # this is a mark of 'cd' being used as a pointer
            idx, size = m.in_idx, "array"
        elif opcode(idx) == "add" and any(type(t) == int and t >= 4 for t in idx[1:]):
            heads_in = [t[1] for t in idx[1:] if opcode(t) == "cd" and type(t[1]) == int]
            if len(heads_in) == 1:
                # a read past the offset a head word holds: the bytes
                # of a dynamic parameter (e.g. data[0] at 36 + offset)
                idx, size = heads_in[0], "array"

        if type(idx) != int:
            # a read at a computed offset: the bytes of a dynamic parameter
            # (the words its offset is computed from are occurrences too)
            continue
        if not _is_head_word(idx):
            logger.warning("unusual cd (not aligned)")
            return {}

        narrower(idx, size)

    for idx, kind in dynamic.items():
        narrower(idx, kind)

    kinds = {}
    for idx, size in sizes.items():
        if idx in validated:
            kinds[idx] = validated[idx]
        elif type(size) == str:
            kinds[idx] = size
        elif coder_v2:
            kinds[idx] = "uint256"  # ABI coder v2: no validator, a 256-bit type
        elif idx in used and type_to_mask(used[idx]) <= size:
            kinds[idx] = used[idx]
        else:
            # a word only ever tested as a condition is a bool
            parents = find_parents(trace, ("cd", idx))
            if parents and all(opcode(e) in ("bool", "if", "iszero") for e in parents):
                kinds[idx] = "bool"
            else:
                kinds[idx] = _uint_type(size)
    for idx, kind in validated.items():
        kinds.setdefault(idx, kind)

    if heads is not None:
        for j in range(heads):
            kinds.setdefault(4 + 32 * j, "uint256")  # a head word the code never reads

    res = {}
    for count, idx in enumerate(sorted(kinds), 1):
        res[idx] = (kinds[idx], f"_param{count}")
    return res


class Function(EasyCopy):
    # the simplification of the trace stopped at its time limit (the trace
    # is exact but not fully simplified; set by the decompiler)
    time_limited = False

    def __init__(self, hash, trace, callvalue_guarded=False, abi_coder_v2=None, display_trace=None):
        """
        trace: the function's simplified trace, kept as `orig_trace`.
        callvalue_guarded: the dispatcher only reaches this function after
        a `callvalue == 0` check of its own (solc hoists the check above the
        selector dispatch when no entry point is payable), so the function
        is not payable even though its body does not check callvalue.
        abi_coder_v2: True when the code is known to decode its parameters
        with ABI coder v2 (solc >= 0.8), False for coder v1 (solc 0.4), None
        when unknown; it steers the parameter type inference.
        display_trace: the form of the trace the text output starts from
        (simplify_trace(display=True)); `trace` when None.
        """
        self.hash = hash
        self.name = get_func_name(hash)
        self.color_name = get_func_name(hash, add_color=True)
        self.abi_name = get_abi_name(hash)

        self.const = None
        self.read_only = None
        self.payable = None
        self.callvalue_guarded = callvalue_guarded
        self.abi_coder_v2 = abi_coder_v2

        self.hash = hash

        self.orig_trace = deepcopy(trace)
        self.trace = deepcopy(trace if display_trace is None else display_trace)

        # A list of (kind, name)
        self.inferred_params = self.make_params()

        if "unknown" in self.name:
            self.make_names()

        self.trace = self.cleanup_masks(self.trace)
        self.ast = None

        self.analyse()

        assert self.payable is not None

        self.is_regular = self.const is None and self.getter is None

    def cleanup_masks(self, trace):
        def rem_masks(exp):
            if m := match(exp, ("bool", ("cd", ":int:idx"))):
                idx = m.idx
                if (
                    idx in self.inferred_params
                    and self.inferred_params[idx][0] == "bool"
                ):
                    return ("cd", idx)

            elif m := match(exp, ("mask_shl", ":size", 0, 0, ("cd", ":int:idx"))):
                size, idx = m.size, m.idx
                if idx in self.inferred_params:
                    kind = self.inferred_params[idx][0]
                    def_size = type_to_mask(kind)
                    if size == def_size:
                        return ("cd", idx)

            return exp

        return replace_f(trace, rem_masks)

    def make_names(self):
        new_name = self.name.split("(")[0]

        self.name = "{}({})".format(
            new_name,
            ", ".join((p[0] + " " + p[1]) for p in self.inferred_params.values()),
        )
        self.color_name = "{}({})".format(
            new_name,
            ", ".join(
                (p[0] + " " + COLOR_GREEN + p[1] + ENDC)
                for p in self.inferred_params.values()
            ),
        )

        self.abi_name = "{}({})".format(
            new_name, ",".join(p[0] for p in self.inferred_params.values())
        )

    def ast_length(self):
        if self.trace is None:
            return 0, 0
        return len((self.print().split("\n"))), len(self.print())

    def priority(self):
        # sorts functions in this order:
        # - self-destructs
        # - (read-only? would be nice, but some read-only funcs can be very long, e.g. etherdelta)
        # - length

        if self.trace is None:
            return 0

        if "selfdestruct" in str(self.trace):
            return -1

        else:
            return self.ast_length()[1]

    def make_params(self):
        """
        Parameter types and names: from the signature database when the
        selector is known, else inferred from the function code (see
        infer_params).
        """

        params = get_func_params(self.hash)
        if params:
            res = {}
            idx = 4
            for p in params:
                res[idx] = (p["type"], p["name"])
                idx += 32
            return res

        return infer_params(self.orig_trace, self.abi_coder_v2)

    def serialize(self):
        trace = self.trace
        def json_safe(obj):
            if obj is None or isinstance(obj, (str, int, float, bool)):
                return obj
            if isinstance(obj, dict):
                return {str(k): json_safe(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple, set)):
                return [json_safe(v) for v in obj]
            if obj.__class__.__name__ == "Node":
                return str(obj)
            return str(obj)

        res = {
            "hash": self.hash,
            "name": self.name,
            "color_name": self.color_name,
            "abi_name": self.abi_name,
            "length": self.ast_length(),
            "getter": self.getter,
            "const": self.const,
            "payable": self.payable,
            "print": self.print(),
            "trace": json_safe(trace),
            "params": json_safe(self.inferred_params),
        }
        if self.time_limited:
            res["time_limited"] = True
        try:
            assert json.dumps(res)  # check if serialisation works well
        except Exception:
            logger.error("failed serialization %s", self.name)
            raise

        return res

    def print(self):
        out = self._print()
        return "\n".join(out)

    def _print(self):
        set_func(self.hash)
        set_func_params_if_none(self.inferred_params)

        if self.const is not None:
            val = self.const
            if opcode(val) == "return":
                val = val[1]

            return [
                COLOR_HEADER
                + "const "
                + ENDC
                + str(self.color_name.split("()")[0])
                + " = "
                + COLOR_BOLD
                + prettify(val)
                + ENDC
            ]

        else:
            comment = ""

            if not self.payable:
                comment = "# not payable"

            if self.name == "_fallback(?)":
                if self.payable:
                    comment = "# default function"
                else:
                    comment = "# not payable, default function"  # qweqw

            if self.name == "_receive(?)":
                comment = "# receive function (empty calldata)"

            header = [
                color("def ", C.header)
                + self.color_name
                + (color(" payable", C.header) if self.payable else "")
                + ": "
                + color(comment, C.gray)
            ]

            if self.ast is not None:
                res = list(pprint_logic(self.ast))
            else:
                res = list(pprint_logic(self.trace))

            if len(res) == 0:
                res = ["  stop"]

            return header + res

    def find_string_getter(self):
        """
        The whole-string form of a function that returns a string or bytes
        copied out of storage (solc < 0.8 getters): the storage node
        ("storage", 256, 0, ("array", ("range", 0, LENGTH), LOC)) when every
        return is such a copy of the same location, else None. A hint for
        the storage names and the text printer; the trace is kept.

        test cases: unicorn
                    0xF7dF66B1D0203d362D7a3afBFd6728695Ae22619 name
                    0xf8e386EDa857484f5a12e4B5DAa9984E06E73705 version
        """

        if not self.read_only or len(self.returns) == 0:
            return None

        loc = None
        for r in self.returns:
            m = match(r, STRING_COPY_RETURN)
            if not m or (loc is not None and m.loc != loc):
                return None
            loc = m.loc

        return (
            "storage",
            256,
            0,
            ("array", ("range", 0, ("storage", 256, 0, ("length", loc))), loc),
        )

    def analyse(self):
        assert len(self.trace) > 0

        def find_returns(exp):
            if opcode(exp) == "return":
                return [exp]
            else:
                return []

        exp_text = []

        self.returns = find_f_list(self.trace, find_returns)

        exp_text.append(("possible return values", prettify(self.returns)))

        # the callvalue check is the first statement after the memory state
        # the VM seeds every run with (see Loader.memory_seed)
        k = _memory_seed_length(self.trace)
        first = self.trace[k] if k < len(self.trace) else None

        if (
            opcode(first) == "if"
            and simplify_bool(first[1]) == "callvalue"
            and (first[2][0] == ("revert", None) or opcode(first[2][0]) == "invalid")
        ):
            self.trace = self.trace[:k] + first[3]
            self.payable = False
        elif (
            opcode(first) == "if"
            and simplify_bool(first[1]) == ("iszero", "callvalue")
            and (first[3][0] == ("revert", None) or opcode(first[3][0]) == "invalid")
        ):
            self.trace = self.trace[:k] + first[2]
            self.payable = False
        else:
            self.payable = not self.callvalue_guarded

        exp_text.append(("payable", self.payable))

        # every line that changes state or emits: a store (storage or
        # transient), a call that may change state, a creation, a log
        self.read_only = True
        for op in STATE_CHANGING_OPS:
            if f"'{op}'" in str(self.trace):
                self.read_only = False

        exp_text.append(("read_only", self.read_only))

        """
            const func detection: the body is one return of a constant
            (no storage, calldata or environment read, no other line)
        """

        body = self.trace[k:]
        self.const = None
        if (
            self.read_only
            and len(body) == 1
            and (m := match(body[0], ("return", ":val")))
            and m.val is not None
            and is_constant(m.val)
        ):
            self.const = body[0]

        if self.const:
            exp_text.append(("const", self.const))

        """
            getter detection (hints for the storage names; the trace is kept)
        """

        self.getter = self.find_string_getter()
        if self.getter is not None:
            self.trace = fold_string_copies(self.trace, self.getter)
        elif self.const is None and self.read_only and len(self.returns) == 1:
            ret = self.returns[0][1]
            if match(ret, ("bool", ("storage", Any, Any, ":loc"))):
                self.getter = (
                    ret  # we have to be careful when using this for naming purposes,
                )
                # because sometimes the storage can refer to array length

            elif opcode(ret) == "mask_shl" and opcode(ret[4]) == "storage":
                self.getter = ret[4]
            elif opcode(ret) == "storage":
                self.getter = ret
            elif opcode(ret) == "data":
                terms = ret[1:]
                # for structs, we check if all the parts of the struct are storage from the same
                # location. if so, we return the location number

                t0 = terms[0]  # 0xFAFfea71A6da719D6CAfCF7F52eA04Eb643F6De2 - documents
                if m := match(t0, ("storage", 256, 0, ":loc")):
                    loc = m.loc
                    for e in terms[1:]:
                        if not match(e, ("storage", 256, 0, ("add", Any, loc))):
                            break
                    else:
                        self.getter = t0

                # kitties getKitten - with more cases this and the above could be uniformed
                if self.getter is None:
                    prev_loc = -1
                    for e in terms:

                        def l2(x):
                            if m := match(x, ("sha3", ("data", Any, ":l"))):
                                if type(m.l) == int and m.l < 1000:
                                    return m.l
                            if (
                                opcode(x) == "sha3"
                                and type(x[1]) == int
                                and x[1] < 1000
                            ):
                                return x[1]
                            return None

                        loc = find_f(e, l2)
                        if not loc or (prev_loc != -1 and prev_loc != loc):
                            break
                        prev_loc = loc

                    else:
                        self.getter = ("struct", ("loc", loc))

            else:
                pass

        if self.getter:
            exp_text.append((f"getter for", prettify(self.getter)))

        explain_text("function traits", exp_text)

        return self

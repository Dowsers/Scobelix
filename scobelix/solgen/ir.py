"""
Typed intermediate representation of solgen v2: the contract between the
lifter (`lift.py`), the analyses and passes, and the renderer (`render.py`).

Every node is an immutable dataclass (hashable, comparable), so passes
rebuild trees with `transform` / `dataclasses.replace` and never mutate them.

Three node families:

  Expr   a 256-bit EVM word.  Unless documented as idiomatic, an Expr has
         EXACT EVM semantics: arithmetic wraps modulo 2**256, division by
         zero gives 0, comparisons give 0 or 1, shifts by 256 or more give 0
         (`sar`: 0 or all ones), ...  `Op` carries the EVM opcode name.
  Bytes  a byte string (calldata or return data slices, memory ranges,
         concatenations).  Lengths are in BYTES and may be symbolic.
  Stmt   a statement.  Bodies are tuples of statements; the lifter keeps the
         decompiler's tree shape: nothing follows an `If` in a block, every
         path ends in a terminator or a `Continue`.

Idiomatic nodes (`StateRef`, `Typed`, `Cast`, `Bool`, `Not`, `And`, `Or`,
`For`, `Break`, `Require`, `Assert`, `Emit`, `NamedError`, `Return.values`,
`HighCall`, `Result`, `Transfer`, `Forward`, `Builtin`, the local names of
`ExtCall`)
are introduced by passes once they have proven the idiomatic form
equivalent; the lifter never produces them, except `Require` for the
decompiler's own `require` nodes (see lift.py).

`Unstructured` (statement) and `UnstructuredExpr` (word) stand for anything
the lifter did not understand.  They are always flagged: a function that
contains one can only be called verified by differential execution.

Deviations from the DESIGN sketch (section 6.3), on purpose:

  * byte strings are a node family of their own (`Bytes`): `Blob` parts are
    `Bytes` nodes, a word part being `WordBytes(value, width)` (the low
    `width` bytes of the word, big-endian; `WordSlice` for a symbolic
    width), so every part has an explicit byte width;
  * `keccak` is `Keccak(data: Bytes)`, not an `Op` (its operand is bytes);
  * memory is the ORIGINAL code's memory: `MLoad` / `MemSlice` / `Mstore`
    address it with the original's absolute offsets (the renderer emulates
    it exactly when it is read, see render.py);
  * `Continue.updates` is a tuple of `Assign` executed in parallel (every
    right-hand side reads the values from before the update);
  * `Precompile` has its own statement; `Revert` payloads are nodes
    (`Empty`, `ErrorString`, `Panic`, `Custom`, `Raw`, `Bubble`);
  * `Field(value, offset, size)` is a plain bit-field extraction (packed
    storage reads are `Field(Sload(slot), offset, size)`);
  * the synthetic comparisons of the trace (`le`, `ge`, `sle`, `sge`,
    `bool`) are lowered to EVM opcodes by the lifter, `max` to a `Ternary`.
"""

from __future__ import annotations

import dataclasses
import functools
from typing import Callable, FrozenSet, Iterator, Optional, Tuple, Union

WORD_BITS = 256
WORD_MOD = 1 << WORD_BITS
WORD_MAX = WORD_MOD - 1


class Node:
    """Base class of every IR node."""

    __slots__ = ()


class Expr(Node):
    """A 256-bit word."""

    __slots__ = ()


class Bytes(Node):
    """A byte string."""

    __slots__ = ()


class Stmt(Node):
    """A statement."""

    __slots__ = ()


class Payload(Node):
    """What a `Revert` reverts with."""

    __slots__ = ()


def _frozen(cls):
    return dataclasses.dataclass(frozen=True)(cls)


# ---------------------------------------------------------------- words


@_frozen
class Const(Expr):
    """A constant word, 0 <= value < 2**256 (use `const()` to reduce)."""

    value: int

    def __post_init__(self):
        if isinstance(self.value, bool) or not isinstance(self.value, int) or not 0 <= self.value < WORD_MOD:
            raise ValueError(f"Const out of range: {self.value!r}")


def const(value: int) -> Const:
    """The word `value` modulo 2**256 (negative ints are two's complement)."""
    return Const(int(value) % WORD_MOD)


ZERO = Const(0)
ONE = Const(1)


# Environment words.  `codesize` and `pc` never appear (the decompiler
# folds them into constants of the original code).
ENV_NAMES = frozenset({
    "caller", "callvalue", "calldatasize", "address", "origin", "timestamp", "number",
    "gas", "gaslimit", "gasprice", "chainid", "basefee", "coinbase", "prevrandao",
    "difficulty", "blobbasefee", "selfbalance", "msize",
})


@_frozen
class Env(Expr):
    """An environment word (`name` in ENV_NAMES): CALLER, CALLVALUE, ..."""

    name: str


@_frozen
class CalldataWord(Expr):
    """calldataload(offset): 32 bytes of calldata, zero past its end."""

    offset: Expr


@_frozen
class Param(Expr):
    """Head word `index` of the ABI parameters: CalldataWord(4 + 32 * index).
    Introduced by the abi pass; same semantics as the calldata word."""

    index: int


@_frozen
class Local(Expr):
    """A local variable (a `uint256` in the rendered code)."""

    name: str


@_frozen
class Sload(Expr):
    """sload(slot): the word in storage when the expression is evaluated."""

    slot: Expr


@_frozen
class Field(Expr):
    """(value >> offset) & (2**size - 1); offset and size are bits, each a
    Python int or a word, read as UNSIGNED integers modulo 2**256 (an
    offset of 256 or more gives 0, a size of 256 or more keeps every bit;
    the lifter only produces 0 <= offset < 256)."""

    value: Expr
    offset: Union[int, Expr]
    size: Union[int, Expr]


# EVM opcodes `Op` may carry, with their arity (None: n-ary, >= 2).
OP_ARITY = {
    "add": None, "mul": None, "and": None, "or": None, "xor": None,
    "sub": 2, "div": 2, "sdiv": 2, "mod": 2, "smod": 2, "exp": 2,
    "addmod": 3, "mulmod": 3, "signextend": 2,
    "lt": 2, "gt": 2, "slt": 2, "sgt": 2, "eq": 2, "iszero": 1, "not": 1,
    "byte": 2, "shl": 2, "shr": 2, "sar": 2,
}
# operand order is the EVM's stack order: sub(a, b) = a - b, div(a, b) = a / b,
# exp(base, exponent), signextend(byte_index, x), byte(index, x), shl(shift, x),
# shr(shift, x), sar(shift, x), addmod(a, b, m), mulmod(a, b, m)
COMPARISONS = frozenset({"lt", "gt", "slt", "sgt", "eq", "iszero"})


@_frozen
class Op(Expr):
    """An EVM opcode applied to words; `op` in OP_ARITY (add/mul/and/or/xor
    may take more than two operands: they are associative)."""

    op: str
    args: Tuple[Expr, ...]

    def __post_init__(self):
        if self.op not in OP_ARITY:
            raise ValueError(f"unknown EVM op {self.op!r}")
        arity = OP_ARITY[self.op]
        if (arity is None and len(self.args) < 2) or (arity is not None and len(self.args) != arity):
            raise ValueError(f"wrong arity for {self.op}: {len(self.args)}")


@_frozen
class Mask(Expr):
    """The decompiler's mask_shl, exactly: ((value & ((2**size-1) << offset))
    << shl) modulo 2**256, a negative shl shifting right (and a negative
    offset shifting the mask right).  size/offset/shl are Python ints
    (signed) or words read as SIGNED 256-bit integers (so the trace's
    `mul(-1, s)` is a shift by -s)."""

    size: Union[int, Expr]
    offset: Union[int, Expr]
    shl: Union[int, Expr]
    value: Expr


@_frozen
class Keccak(Expr):
    """keccak256 of a byte string."""

    data: "Bytes"


@_frozen
class MLoad(Expr):
    """mload(addr) of the ORIGINAL code's memory."""

    addr: Expr


@_frozen
class BytesWord(Expr):
    """The big-endian value of a byte string of at most 32 bytes (a 4-byte
    selector read from memory or calldata, ...)."""

    data: "Bytes"


@_frozen
class CallOut(Expr):
    """A result of the external call / create / precompile `call_id` (see
    the statements carrying a call_id): `what` is "success" (the 0/1 word
    the opcode pushed), "returndatasize" or "address" (new contract)."""

    call_id: int
    what: str


@_frozen
class Balance(Expr):
    """balance(addr) (the low 160 bits of addr)."""

    addr: Expr


@_frozen
class ExtCodeSize(Expr):
    addr: Expr


@_frozen
class ExtCodeHash(Expr):
    addr: Expr


@_frozen
class BlockHash(Expr):
    number: Expr


@_frozen
class BlobHash(Expr):
    index: Expr


@_frozen
class TLoad(Expr):
    """tload(slot) (EIP-1153 transient storage)."""

    slot: Expr


@_frozen
class Ternary(Expr):
    """cond != 0 ? if_true : if_false."""

    cond: Expr
    if_true: Expr
    if_false: Expr


@_frozen
class UnstructuredExpr(Expr):
    """A word the lifter could not translate (`raw` is the trace node, as a
    short string)."""

    raw: str
    reason: str = ""


# ---------------------------------------------------------------- idiomatic words


@_frozen
class StateRef(Expr):
    """A state variable access `var` + `path` (keys / indices as words,
    member names as str) whose Solidity value type is `ty` ("uint8",
    "address", "bool", "bytes4", ...).  Read as the word of that value
    (zero-extended, sign-extended for intN, left-aligned for bytesN); as an
    `Assign` target the renderer converts the assigned word to `ty` (uintN,
    intN, address: the low bits; bytesN: the high bytes; bool: != 0), so
    the storage pass only builds assignments whose value keeps the stored
    bits.  A path element `Cast(K, w)` is a key of value type K whose word
    is w (w must be a valid K value: the key is hashed as it is); other
    words are uint256 keys or indices.  Introduced by the storage pass."""

    var: str
    path: Tuple[Node, ...] = ()
    ty: str = "uint256"


@_frozen
class Typed(Expr):
    """`op` with SOLIDITY semantics on operands of type `ty` ("uint256",
    "uint8", "int128", ...): the operand words must be valid `ty` values,
    the result is the word of the `ty` result (comparisons: 0 / 1).
    `checked` marks Solidity's checked (0.8) arithmetic (Panic 0x11 on
    overflow); unchecked arithmetic wraps in `ty`; division and modulo by
    zero Panic (0x12) either way.  ops: add sub mul div mod lt gt eq and or
    xor."""

    op: str
    args: Tuple[Expr, ...]
    ty: str
    checked: bool = False


@_frozen
class Cast(Expr):
    """A Solidity conversion to `ty` whose value equals the word."""

    ty: str
    value: Expr


@_frozen
class Bool(Expr):
    """A Solidity bool (word 0 or 1) equal to value != 0."""

    value: Expr


@_frozen
class Not(Expr):
    """Logical negation (!x) of a 0/1 word."""

    value: Expr


@_frozen
class And(Expr):
    """Logical conjunction of 0/1 words (operands have no side effects)."""

    args: Tuple[Expr, ...]


@_frozen
class Or(Expr):
    """Logical disjunction of 0/1 words (operands have no side effects)."""

    args: Tuple[Expr, ...]


# ---------------------------------------------------------------- bytes


@_frozen
class WordBytes(Bytes):
    """The low `width` bytes (1..32) of a word, big-endian."""

    value: Expr
    width: int = 32

    def __post_init__(self):
        if not 1 <= self.width <= 32:
            raise ValueError(f"WordBytes width out of range: {self.width}")


@_frozen
class WordSlice(Bytes):
    """The low `length` bytes of a word, big-endian, for a symbolic length
    (zero bytes on the left past 32): the engine's `bytes W V`."""

    value: Expr
    length: Expr


@_frozen
class MaskBytes(Bytes):
    """The low `length` bytes, big-endian (zero bytes on the left past its
    value), of the integer ((X & ((2**size-1) << offset)) << shl), where X
    is the big-endian value of ALL the bytes of `data` (8 * len(data) bits)
    and nothing is reduced modulo 2**256: the engine's `bytes W mask_shl(..)`
    of a byte string longer than a word or of symbolic length (a memory copy
    of calldata or return data read back across its ends).  `size` None
    stands for 2**255 - 1, the largest signed size: every bit from `offset`
    on (with offset and shl 0, the engine's `bytes W X`: the last W bytes of
    X).
    size / offset / shl are as in `Mask` (Python ints or words read as
    SIGNED; a negative shl shifts right, a negative offset shifts the mask
    right).  Build it with `mask_bytes`, which leaves out a mask that keeps
    all of `data` when `length` is its length."""

    size: Union[None, int, Expr]
    offset: Union[int, Expr]
    shl: Union[int, Expr]
    data: Bytes
    length: Expr


@_frozen
class ConstBytes(Bytes):
    """Literal bytes."""

    data: bytes


@_frozen
class ZeroBytes(Bytes):
    """`length` zero bytes."""

    length: Expr


@_frozen
class CalldataSlice(Bytes):
    """calldatacopy semantics: calldata[start:start+length], zero past its end."""

    start: Expr
    length: Expr


@_frozen
class MemSlice(Bytes):
    """The ORIGINAL code's memory [start, start+length)."""

    start: Expr
    length: Expr


@_frozen
class ReturnData(Bytes):
    """Return data of call `call_id` [start, start+length), zero past its end."""

    call_id: int
    start: Expr
    length: Expr


@_frozen
class CodeSlice(Bytes):
    """codecopy of the ORIGINAL runtime code, zero past its end."""

    start: Expr
    length: Expr


@_frozen
class ExtCodeSlice(Bytes):
    """extcodecopy(addr, start, length), zero past the code's end."""

    addr: Expr
    start: Expr
    length: Expr


@_frozen
class Blob(Bytes):
    """The concatenation of its parts."""

    parts: Tuple[Bytes, ...]


@_frozen
class UnstructuredBytes(Bytes):
    """A byte string the lifter could not translate."""

    raw: str
    reason: str = ""


# ---------------------------------------------------------------- revert payloads


@_frozen
class Empty(Payload):
    """No data: revert(0, 0)."""


@_frozen
class ErrorString(Payload):
    """Error(string): what require(c, "...") / revert("...") produce."""

    message: bytes


@_frozen
class Panic(Payload):
    """Panic(uint256 code)."""

    code: int


@_frozen
class Custom(Payload):
    """A 4-byte selector followed by `args` (concatenated as given)."""

    selector: int
    args: Tuple[Bytes, ...] = ()


@_frozen
class Raw(Payload):
    """Arbitrary bytes."""

    data: Bytes


@_frozen
class Bubble(Payload):
    """The whole return data of call `call_id` (re-thrown revert)."""

    call_id: int


@_frozen
class NamedError(Payload):
    """Idiomatic `revert Name(args)` (reverts pass): the ABI encoding of
    `args` behind the declared error's selector.  `types` are the Solidity
    types of the error's parameters: a value type's arg is a word that is a
    valid value of the type, a `string` / `bytes` arg is a byte string
    (`Bytes` node).  The error is declared by the pass."""

    name: str
    args: Tuple[Node, ...] = ()
    types: Tuple[str, ...] = ()


# ---------------------------------------------------------------- statements


@_frozen
class If(Stmt):
    cond: Expr
    then: Tuple[Stmt, ...]
    orelse: Tuple[Stmt, ...] = ()


@_frozen
class Assign(Stmt):
    """target = value.  `op` (set by passes) makes it the compound form
    `target op= value`, i.e. target = target op value with the EVM meaning
    of the operator: "+", "-", "*" wrap modulo 2**256, "/" and "%" give 0
    for a zero divisor, "&", "|", "^", "<<", ">>" as the opcodes; "++" and
    "--" are `target += 1` and `target -= 1` written as increments (value
    is 1).

    `checked` (compound pass) gives the compound form Solidity's semantics
    in the target's integer type instead of the EVM meaning: True is
    `target = Typed(op, (target, value), type, checked=True)` (Panic 0x11 on
    overflow, 0x12 on a zero divisor), False the same unchecked (wrapping in
    the type; "/" and "%" still Panic 0x12 on a zero divisor); `value` is
    then a valid value of the target's type.  None: the EVM meaning.

    `declare` (loops pass) allows the renderer to declare the target local
    where this assignment stands (`uint256 x = value;`) instead of at the
    top of the function.  It changes nothing else: the renderer does so
    only when `scopes.sites` confirms that every mention of the local is in
    the scope of its marked assignments."""

    target: Expr  # Local, or StateRef once the storage pass ran
    value: Expr
    op: Optional[str] = None
    checked: Optional[bool] = None
    declare: bool = False


@_frozen
class While(Stmt):
    """`init` (parallel assignments), then: while (cond != 0) body.  The
    body's paths end in a `Continue` of this loop or leave the function; the
    statements after the While run when cond is 0."""

    cond: Expr
    body: Tuple[Stmt, ...]
    init: Tuple[Assign, ...] = ()
    loop_id: str = ""


@_frozen
class Continue(Stmt):
    """Back-edge of loop `loop_id`: `updates` assigned in parallel, then the
    next iteration."""

    loop_id: str
    updates: Tuple[Assign, ...] = ()


@_frozen
class For(Stmt):
    """Idiomatic loop (loops pass) with Solidity's semantics: `init`, then
    while (cond != 0) { body; step }.  The body may fall through (to the
    step); a `Continue` of this loop runs its updates, then the step; a
    `Break` of this loop goes to the statement after it.  `step` is empty or
    one `Assign`; an `init` of one `Assign` of a local is written in the
    header (other statements: before the loop); with neither header part the
    loop is written `while (cond) { body }`."""

    init: Tuple[Stmt, ...]
    cond: Expr
    step: Tuple[Stmt, ...]
    body: Tuple[Stmt, ...]
    loop_id: str = ""


@_frozen
class Break(Stmt):
    loop_id: str = ""


@_frozen
class Sstore(Stmt):
    """Bits [offset, offset+size) of storage `slot` := the low `size` bits
    of value (offset/size in bits: Python ints with 0 <= offset and
    offset + size <= 256, or words)."""

    slot: Expr
    value: Expr
    offset: Union[int, Expr] = 0
    size: Union[int, Expr] = 256


@_frozen
class Mstore(Stmt):
    """The ORIGINAL code's memory [addr, addr+len(data)) := data."""

    addr: Expr
    data: Bytes


@_frozen
class TStore(Stmt):
    slot: Expr
    value: Expr


@_frozen
class Log(Stmt):
    """LOGn: `topics` (0 to 4 words, topic0 first) and `data` (None: empty)."""

    topics: Tuple[Expr, ...]
    data: Optional[Bytes] = None


@_frozen
class Emit(Stmt):
    """Idiomatic `emit event(args)` (events pass): `types` are the Solidity
    types of the event's parameters (empty: every parameter is a uint256).
    A value type's arg is a word that is a valid value of the type; a
    `string` / `bytes` arg is a byte string (`Bytes` node: its bytes, or,
    for an indexed parameter, the bytes whose keccak256 is the topic).  The
    event is declared by the pass, with the `indexed` flags that put the
    args in the original's topics and data."""

    event: str
    args: Tuple[Node, ...]
    types: Tuple[str, ...] = ()


CALL_KINDS = ("call", "staticcall", "delegatecall", "callcode")


@_frozen
class ExtCall(Stmt):
    """An external call.  The payload is the 4-byte `selector` (a word; None:
    no selector part) followed by `args` (None: nothing).  `gas` None: all
    available gas; `value` None: no value field (staticcall /
    delegatecall).

    `ok` / `ret` (calls pass, presentation only): the names of the locals
    the low-level call declares where it is made, for its success flag
    (`CallOut(call_id, "success")`) and for the whole of its return data
    (`ReturnData(call_id, 0, CallOut(call_id, "returndatasize"))`); None:
    the success flag is a local of the function and the return data is
    read where it is used."""

    call_id: int
    kind: str
    gas: Optional[Expr]
    to: Expr
    value: Optional[Expr]
    selector: Optional[Expr] = None
    args: Optional[Bytes] = None
    ret_words: Optional[int] = None  # static return words, when known (calls pass)
    ok: Optional[str] = None
    ret: Optional[str] = None


@_frozen
class HighCall(Stmt):
    """Idiomatic high-level call (calls pass): `iface(to).name{value: value,
    gas: gas}(args)`, the function declared in interface `iface` with the
    parameter types `types`, the return types `returns`, and `view` when
    `kind` is "staticcall" (`payable` when `value` is not None).

    It means what the target compiler makes of that source line: the
    payload is the selector of `name(types)` followed by the ABI encoding of
    `args` (each a word that is a valid value of its type); the call is a
    CALL (STATICCALL) with all the gas left unless `gas` is given; the
    contract is checked to have code first when the function returns
    nothing; a failed call reverts with the callee's revert data; then the
    return data must hold the static words of `returns` and each word must
    be a valid value of its type (ABI coder v2), else the call reverts with
    empty data.  The pass rewrites a call only when the original's
    scaffolding around it is exactly that.

    The returned values are `Result(call_id, i, returns[i])`; `outs` names
    the local each one is bound to (None: not used)."""

    call_id: int
    kind: str  # "call" | "staticcall"
    iface: str
    name: str
    to: Expr
    value: Optional[Expr]
    gas: Optional[Expr]
    args: Tuple[Expr, ...] = ()
    types: Tuple[str, ...] = ()
    returns: Tuple[str, ...] = ()
    outs: Tuple[Optional[str], ...] = ()


@_frozen
class Result(Expr):
    """The `index`-th value returned by the `HighCall` `call_id`, a valid
    value of the Solidity value type `ty`, as a word (idiomatic, calls
    pass)."""

    call_id: int
    index: int
    ty: str


@_frozen
class Builtin(Stmt):
    """Idiomatic `ecrecover(h, v, r, s)` / `sha256(data)` / `ripemd160(data)`
    (calls pass): the call of precompile 1 / 2 / 3 that solc writes for the
    builtin `name` (a failure bubbles the revert data), with `args` of the
    types `types` (value types: words; `bytes`: a byte string).  Its value
    is `Result(call_id, 0, ty)`, bound to the local `out` (None: unused)."""

    call_id: int
    name: str
    args: Tuple[Node, ...]
    types: Tuple[str, ...]
    ty: str
    out: Optional[str] = None


@_frozen
class Forward(Stmt):
    """The standard proxy forwarder (calls pass): DELEGATECALL of `to` with
    all the gas left and the whole calldata, then return with its return
    data, or revert with it when the call failed.  Ends the call."""

    call_id: int
    to: Expr


@_frozen
class Transfer(Stmt):
    """Idiomatic `payable(to).transfer(value)` / `payable(to).send(value)`
    (calls pass): a CALL of `to` with `value` and no payload, with the gas
    stipend only (gas 2300 when value is 0, else 0: the EVM adds the
    stipend).  transfer (send False) reverts with the callee's revert data
    when the call fails; send binds the success flag
    (`CallOut(call_id, "success")`) to the local `ok`."""

    call_id: int
    to: Expr
    value: Expr
    send: bool = False
    ok: Optional[str] = None


@_frozen
class Create(Stmt):
    """CREATE (salt None) or CREATE2 with init code `code`."""

    call_id: int
    value: Expr
    code: Bytes
    salt: Optional[Expr] = None


PRECOMPILES = {
    "erecover": 1, "sha256hash": 2, "ripemd160hash": 3, "memcopy": 4,
    "bigModExp": 5, "bn256Add": 6, "bn256ScalarMul": 7, "bn256Pairing": 8,
}


@_frozen
class Precompile(Stmt):
    """A call to precompile `address` (`name` as the decompiler calls it)
    with input `args`; `output` is the local bound to its first output word
    (None: not used)."""

    call_id: int
    address: int
    name: str
    args: Bytes
    output: Optional[str] = None


@_frozen
class SelfDestruct(Stmt):
    beneficiary: Expr


@_frozen
class Return(Stmt):
    """Successful end of the call: `data` (None: empty return data), or the
    idiomatic `values` the declared return types ABI-encode: a word for a
    value type (a valid value of its type), a `Bytes` node for a `bytes` /
    `string` return type (without a matching declaration: one word each,
    byte strings not allowed)."""

    data: Optional[Bytes] = None
    values: Optional[Tuple[Expr, ...]] = None


@_frozen
class Revert(Stmt):
    payload: Payload = Empty()


@_frozen
class Stop(Stmt):
    """STOP: success with empty return data."""


@_frozen
class Invalid(Stmt):
    """INVALID (also unknown opcodes and bad jumps)."""

    reason: str = ""


@_frozen
class Require(Stmt):
    """if (cond == 0) revert with `payload`."""

    cond: Expr
    payload: Payload = Empty()


@_frozen
class Assert(Stmt):
    """Idiomatic assert(cond)."""

    cond: Expr


@_frozen
class Unstructured(Stmt):
    """A statement the lifter could not translate (`raw`: the trace node as
    a short string).  Rendered as a flagged revert."""

    raw: str
    reason: str = ""


TERMINATORS = (Return, Revert, Stop, Invalid, SelfDestruct, Unstructured, Forward)


# ---------------------------------------------------------------- functions


@_frozen
class Function:
    """One entry point: `key` is "0x<selector>", "_fallback" or "_receive".
    `flags` record what the lifter or a pass knows the code may get wrong
    (see lift.py for the list)."""

    key: str
    body: Tuple[Stmt, ...]
    flags: FrozenSet[str] = frozenset()

    def with_body(self, body, extra_flags=()) -> "Function":
        return dataclasses.replace(self, body=tuple(body), flags=self.flags | frozenset(extra_flags))


# ---------------------------------------------------------------- traversal


def children(node: Node) -> Iterator[Node]:
    """The direct sub-nodes of `node`, in field order (tuples flattened)."""
    for f in dataclasses.fields(node):
        v = getattr(node, f.name)
        if isinstance(v, Node):
            yield v
        elif isinstance(v, tuple):
            for x in v:
                if isinstance(x, Node):
                    yield x


def walk(node: Node) -> Iterator[Node]:
    """Every node of the tree rooted at `node` (pre-order)."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(list(children(n))))


def walk_all(nodes) -> Iterator[Node]:
    for n in nodes:
        yield from walk(n)


def transform(node, fn: Callable[[Node], Node]):
    """Bottom-up rewrite: children first, then `fn` on the rebuilt node.
    `node` may also be a tuple of nodes."""
    if isinstance(node, tuple):
        return tuple(transform(x, fn) for x in node)
    if not isinstance(node, Node):
        return node
    changes = {}
    for f in dataclasses.fields(node):
        v = getattr(node, f.name)
        if isinstance(v, (Node, tuple)):
            nv = transform(v, fn)
            if nv is not v and nv != v:
                changes[f.name] = nv
    if changes:
        node = dataclasses.replace(node, **changes)
    return fn(node)


def contains(node, cls) -> bool:
    """True if a node of class `cls` occurs in `node` (a node or a tuple)."""
    nodes = node if isinstance(node, tuple) else (node,)
    return any(isinstance(n, cls) for n in walk_all(nodes))


def reads_indexed_state(node) -> bool:
    """`node` reads a state variable through a word of its path that is not
    a mapping key (the storage pass writes every key as a Cast to its key
    type): an array index.  Solidity checks an
    array index (Panic 0x32), and the arith pass may remove the explicit
    bounds guard that preceded the access, leaving the check to it: such a
    read must be evaluated where the original evaluates it, even when its
    value is not used."""
    for n in walk(node):
        if isinstance(n, StateRef) and any(isinstance(p, Expr) and not isinstance(p, Cast) for p in n.path):
            return True
    return False


# ---------------------------------------------------------------- reference semantics


def to_signed(x: int) -> int:
    """The two's complement value of a word."""
    return x - WORD_MOD if x >> 255 else x


def _bits(x) -> Optional[int]:
    """A bit-position field of a Mask: Python int as is, a constant word
    read signed."""
    if isinstance(x, int) and not isinstance(x, bool):
        return x
    v = evaluate(x)
    return None if v is None else to_signed(v)


def field_bits(x) -> Optional[int]:
    """A bit-position field of a Field: unsigned, modulo 2**256 (None when
    it is not constant)."""
    if isinstance(x, int) and not isinstance(x, bool):
        return x % WORD_MOD
    return evaluate(x)


def _sdiv(a: int, b: int) -> int:
    if b == 0:
        return 0
    a, b = to_signed(a), to_signed(b)
    q = abs(a) // abs(b)
    return (-q if (a < 0) != (b < 0) else q) % WORD_MOD


def _smod(a: int, b: int) -> int:
    if b == 0:
        return 0
    a, b = to_signed(a), to_signed(b)
    r = abs(a) % abs(b)
    return (-r if a < 0 else r) % WORD_MOD


def _signextend(b: int, x: int) -> int:
    if b >= 31:
        return x
    bit = 8 * b + 7
    return x | (WORD_MAX ^ ((1 << bit) - 1)) if (x >> bit) & 1 else x & ((1 << bit) - 1)


def _sar(s: int, x: int) -> int:
    v = to_signed(x)
    if s >= 256:
        return 0 if v >= 0 else WORD_MAX
    return (v >> s) % WORD_MOD


EVM_OPS = {
    "add": lambda *a: sum(a) % WORD_MOD,
    "mul": lambda *a: _product(a),
    "and": lambda *a: _fold(lambda x, y: x & y, a),
    "or": lambda *a: _fold(lambda x, y: x | y, a),
    "xor": lambda *a: _fold(lambda x, y: x ^ y, a),
    "sub": lambda a, b: (a - b) % WORD_MOD,
    "div": lambda a, b: a // b if b else 0,
    "sdiv": _sdiv,
    "mod": lambda a, b: a % b if b else 0,
    "smod": _smod,
    "exp": lambda a, b: pow(a, b, WORD_MOD),
    "addmod": lambda a, b, m: (a + b) % m if m else 0,
    "mulmod": lambda a, b, m: (a * b) % m if m else 0,
    "signextend": _signextend,
    "lt": lambda a, b: int(a < b),
    "gt": lambda a, b: int(a > b),
    "slt": lambda a, b: int(to_signed(a) < to_signed(b)),
    "sgt": lambda a, b: int(to_signed(a) > to_signed(b)),
    "eq": lambda a, b: int(a == b),
    "iszero": lambda a: int(a == 0),
    "not": lambda a: WORD_MAX ^ a,
    "byte": lambda i, x: (x >> (8 * (31 - i))) & 0xFF if i < 32 else 0,
    "shl": lambda s, x: (x << s) % WORD_MOD if s < 256 else 0,
    "shr": lambda s, x: x >> s if s < 256 else 0,
    "sar": _sar,
}


def _fold(f, args):
    r = args[0]
    for a in args[1:]:
        r = f(r, a)
    return r


def _product(args):
    r = 1
    for a in args:
        r = (r * a) % WORD_MOD
    return r


def mask_value(size: int, offset: int, shl: int, value: int) -> int:
    """mask_shl on integers, as `Mask` defines it.

    `value` is a word (< 2**256), so bits outside the word never matter:
    sizes, offsets and shifts are clamped before building any integer, which
    keeps hostile constants (e.g. a 2**200-bit shift) from allocating
    gigabytes."""
    if offset >= 0:
        if offset >= WORD_BITS:
            return 0
        size = min(size, WORD_BITS - offset)
    else:
        size, offset = min(size + offset, WORD_BITS), 0
    if size <= 0 or shl >= WORD_BITS or shl <= -WORD_BITS:
        return 0
    r = value & (((1 << size) - 1) << offset)
    r = r << shl if shl >= 0 else r >> -shl
    return r % WORD_MOD


def evaluate(e) -> Optional[int]:
    """The value of a closed constant word expression, None when it depends
    on anything but constants.  This is the reference semantics of the
    word nodes it covers (the renderer's tests compare against it)."""
    if isinstance(e, Const):
        return e.value
    if isinstance(e, Op):
        args = [evaluate(a) for a in e.args]
        if any(a is None for a in args):
            return None
        return EVM_OPS[e.op](*args)
    if isinstance(e, Mask):
        size, off, shl, v = _bits(e.size), _bits(e.offset), _bits(e.shl), evaluate(e.value)
        if None in (size, off, shl, v):
            return None
        return mask_value(size, off, shl, v)
    if isinstance(e, Field):
        v, off, size = evaluate(e.value), field_bits(e.offset), field_bits(e.size)
        if None in (v, off, size):
            return None
        return (v >> off) & ((1 << min(size, WORD_BITS)) - 1) if off < WORD_BITS else 0
    if isinstance(e, Ternary):
        c = evaluate(e.cond)
        if c is None:
            return None
        return evaluate(e.if_true if c else e.if_false)
    if isinstance(e, BytesWord):
        data = const_bytes(e.data)
        if data is None or len(data) > 32:
            return None
        return int.from_bytes(data, "big")
    if isinstance(e, Keccak):
        data = const_bytes(e.data)
        if data is None:
            return None
        from eth_utils import keccak

        return int.from_bytes(keccak(data), "big")
    return None


def const_bytes(b) -> Optional[bytes]:
    """The value of a closed constant byte string, else None."""
    if isinstance(b, ConstBytes):
        return b.data
    if isinstance(b, WordBytes):
        v = evaluate(b.value)
        return None if v is None else (v % (1 << (8 * b.width))).to_bytes(b.width, "big")
    if isinstance(b, WordSlice):
        v, n = evaluate(b.value), evaluate(b.length)
        if v is None or n is None or n > 1 << 20:
            return None
        return (v % (1 << (8 * n))).to_bytes(n, "big") if n <= 32 else bytes(n - 32) + v.to_bytes(32, "big")
    if isinstance(b, ZeroBytes):
        n = evaluate(b.length)
        return None if n is None or n > 1 << 20 else bytes(n)
    if isinstance(b, Blob):
        out = b""
        for p in b.parts:
            d = const_bytes(p)
            if d is None:
                return None
            out += d
        return out
    if isinstance(b, MaskBytes):
        data, n = const_bytes(b.data), evaluate(b.length)
        fields = [None if b.size is None else _bits(b.size), _bits(b.offset), _bits(b.shl)]
        if data is None or n is None or n > 1 << 20 or None in fields[1:] or (b.size is not None and fields[0] is None):
            return None
        return mask_bytes_value(data, fields[0], fields[1], fields[2], n)
    return None


def byte_length(b) -> Optional[Expr]:
    """The length of a byte string as a word expression (None if unknown)."""
    if isinstance(b, WordBytes):
        return Const(b.width)
    if isinstance(b, ConstBytes):
        return Const(len(b.data))
    if isinstance(b, (ZeroBytes, WordSlice)):
        return b.length
    if isinstance(b, (CalldataSlice, MemSlice, ReturnData, CodeSlice, ExtCodeSlice)):
        return b.length
    if isinstance(b, Blob):
        total = 0
        sym = []
        for p in b.parts:
            n = byte_length(p)
            if n is None:
                return None
            v = evaluate(n)
            if v is None:
                sym.append(n)
            else:
                total += v
        if not sym:
            return Const(total % WORD_MOD)
        return Op("add", tuple(sym) + (Const(total % WORD_MOD),)) if total or len(sym) > 1 else sym[0]
    if isinstance(b, MaskBytes):
        return b.length
    return None


# ---------------------------------------------------------------- linear forms


def _two_adic(c: int) -> int:
    """The exponent of the largest power of two dividing c (256 for 0)."""
    return WORD_BITS if c == 0 else (c & -c).bit_length() - 1


def _mask_atom(n) -> Optional[Tuple[int, int, Expr]]:
    """(size, offset, value) of Mask(size, offset, 0, value) with constant
    non-negative offset and positive size, else None."""
    if not isinstance(n, Mask):
        return None
    size, off, shl = _bits(n.size), _bits(n.offset), _bits(n.shl)
    if None in (size, off, shl) or shl != 0 or off < 0 or size <= 0:
        return None
    return size, off, n.value


@functools.lru_cache(maxsize=8192)  # (a pure function of a value: the renderer asks again and again)
def linear(e) -> Tuple[Tuple[Tuple[Expr, int], ...], int]:
    """`e` (a word, or a Python int as a Mask field holds) as a linear
    combination modulo 2**256 of opaque words: (((atom, coefficient), ...),
    constant), atoms sorted by their text, no zero coefficient.  Two words
    with the same form are equal for every value of their atoms: every
    rewrite is an identity modulo 2**256 (add, sub, mul and shl by a
    constant, a mask whose bits a coefficient pushes past the word), so a
    form proves equalities and never assumes one; anything else is an atom
    compared as a tree."""
    terms: dict = {}
    const = _linear_into(e, 1, terms) + _settle(terms)
    return tuple(sorted(terms.items(), key=lambda kv: repr(kv[0]))), const % WORD_MOD


def _add_term(terms: dict, atom, c: int) -> None:
    v = (terms.get(atom, 0) + c) % WORD_MOD
    if v:
        terms[atom] = v
    else:
        terms.pop(atom, None)


def _linear_into(e, k: int, terms: dict) -> int:
    """Add k * e into terms; return k * (the constant part of e)."""
    k %= WORD_MOD
    if k == 0:
        return 0
    if isinstance(e, int) and not isinstance(e, bool):
        return k * e
    if isinstance(e, Const):
        return k * e.value
    if isinstance(e, Op):
        if e.op == "add":
            return sum(_linear_into(a, k, terms) for a in e.args)
        if e.op == "sub":
            return _linear_into(e.args[0], k, terms) + _linear_into(e.args[1], -k, terms)
        if e.op == "mul":
            consts = [a.value for a in e.args if isinstance(a, Const)]
            rest = [a for a in e.args if not isinstance(a, Const)]
            factor = k
            for c in consts:
                factor = factor * c % WORD_MOD
            if not rest:
                return factor
            if len(rest) == 1:
                return _linear_into(rest[0], factor, terms)
        if e.op == "shl" and isinstance(e.args[0], Const):
            s = e.args[0].value
            return _linear_into(e.args[1], k << s, terms) if s < WORD_BITS else 0
    if isinstance(e, Mask):
        size, off, shl = _bits(e.size), _bits(e.offset), _bits(e.shl)
        if None not in (size, off, shl) and 0 < shl < WORD_BITS and off >= 0 and size > 0:
            # ((v & m) << shl) mod 2**256 = 2**shl * (v & m) mod 2**256
            return _linear_into(Mask(size, off, 0, e.value), k << shl, terms)
        if None not in (size, off, shl) and shl == 0 and off >= 0 and 0 < size and off + size < WORD_BITS:
            low = _known_low(e.value, off + size)
            if low is not None:  # the bits the mask keeps do not depend on the atoms
                return k * (low & (((1 << size) - 1) << off))
    _add_term(terms, e, k)
    return 0


def _known_low(e, bits: int) -> Optional[int]:
    """The low `bits` bits of the word `e` (a word or a Python int) when
    they do not depend on what it reads, else None (exact: carries only go
    up, so the low bits of a sum, a product or a shift are those of the low
    bits of its operands)."""
    if bits <= 0:
        return 0
    bits = min(bits, WORD_BITS)
    m = (1 << bits) - 1
    if isinstance(e, int) and not isinstance(e, bool):
        return e & m
    if isinstance(e, Const):
        return e.value & m
    if isinstance(e, Op):
        if e.op in ("add", "sub", "mul"):
            vals = []
            for a in e.args:
                if e.op == "mul" and isinstance(a, Const) and _two_adic(a.value) >= bits:
                    return 0
                v = _known_low(a, bits)
                if v is None:
                    return None
                vals.append(v)
            if e.op == "add":
                return sum(vals) & m
            if e.op == "sub":
                return (vals[0] - vals[1]) & m
            r = 1
            for v in vals:
                r = r * v & m
            return r
        if e.op == "shl" and isinstance(e.args[0], Const):
            s = e.args[0].value
            if s >= bits:
                return 0
            v = _known_low(e.args[1], bits - s)
            return None if v is None else (v << s) & m
        if e.op == "and":
            consts = [a.value for a in e.args if isinstance(a, Const)]
            if any(c & m == 0 for c in consts):
                return 0
            vals = [_known_low(a, bits) for a in e.args]
            if None in vals:
                return None
            r = m
            for v in vals:
                r &= v
            return r
    if isinstance(e, Mask):
        size, off, shl = _bits(e.size), _bits(e.offset), _bits(e.shl)
        if None in (size, off, shl) or size <= 0 or off < 0 or shl < 0:
            return None
        if off + shl >= bits:
            return 0  # the kept bits all land at or above bit `bits`
        v = _known_low(e.value, min(off + size, bits - shl))
        if v is None:
            return None
        return ((v & (((1 << min(size, bits)) - 1) << off)) << shl) & m
    return None


def _interval(e, bits: int) -> Tuple[int, int]:
    """Bounds of the word `e` read as a signed integer where every word it
    reads is below 2**bits and nothing wraps (constants read as signed)."""
    top = (1 << bits) - 1
    if isinstance(e, int) and not isinstance(e, bool):
        return e, e
    if isinstance(e, Const):
        v = to_signed(e.value)
        return v, v
    if isinstance(e, Op):
        if e.op == "add":
            bounds = [_interval(a, bits) for a in e.args]
            return sum(b[0] for b in bounds), sum(b[1] for b in bounds)
        if e.op == "sub":
            (a0, a1), (b0, b1) = _interval(e.args[0], bits), _interval(e.args[1], bits)
            return a0 - b1, a1 - b0
        if e.op == "mul" and len(e.args) == 2 and any(isinstance(a, Const) for a in e.args):
            c, x = (e.args[0], e.args[1]) if isinstance(e.args[0], Const) else (e.args[1], e.args[0])
            k, (x0, x1) = to_signed(c.value), _interval(x, bits)
            return (k * x0, k * x1) if k >= 0 else (k * x1, k * x0)
        if e.op == "shl" and isinstance(e.args[0], Const) and e.args[0].value < bits:
            x0, x1 = _interval(e.args[1], bits)
            return x0 << e.args[0].value, x1 << e.args[0].value
    if isinstance(e, Mask):
        size, off, shl = _bits(e.size), _bits(e.offset), _bits(e.shl)
        if None not in (size, off, shl) and size > 0 and off >= 0 and 0 <= shl < bits:
            x0, x1 = _interval(e.value, bits)
            if x0 >= 0 and x1 < 1 << min(off + size, 2 * bits):  # the mask only rounds down
                return (x0 >> off) << (off + shl), (x1 >> off) << (off + shl)
            return 0, min(top, ((1 << min(size, bits)) - 1) << off) << shl
    return 0, top


def _settle(terms: dict) -> int:
    """Rewrite c * Mask(size, offset, 0, v) when c * 2**(offset + size) is 0
    modulo 2**256 (the bits the mask drops above it vanish anyway): c * v,
    minus c * (v mod 2**offset) when offset > 0.  Returns the constant the
    rewrites add."""
    extra = 0
    for _ in range(64):  # each rewrite removes a mask: a few rounds suffice
        for atom, c in list(terms.items()):
            m = _mask_atom(atom)
            if m is not None and _two_adic(c) + m[1] + m[0] >= WORD_BITS:
                size, off, value = m
                terms.pop(atom)
                extra += _linear_into(value, c, terms)
                if off > 0:
                    extra += _linear_into(Mask(off, 0, 0, value), -c, terms)
                break
        else:
            break
    return extra


def same_value(a, b) -> bool:
    """`a` and `b` (words or Python ints) are provably equal modulo 2**256."""
    return linear(Op("sub", (_as_word(a), _as_word(b)))) == ((), 0)


def provably_zero(e) -> bool:
    """The word `e` is 0 for every value of what it reads: its linear form,
    or an `and` with constants whose bits the other operand provably has
    clear (the padding `(0 - n) & 31` of a length n rounded up to words)."""
    v = evaluate(e)
    if v is not None:
        return v == 0
    if same_value(e, ZERO):
        return True
    if isinstance(e, Op) and e.op == "and":
        mask = WORD_MOD - 1
        for a in e.args:
            if isinstance(a, Const):
                mask &= a.value
        bits = mask.bit_length()
        for a in e.args:
            if not isinstance(a, Const):
                low = _known_low(a, bits)
                if low is not None and low & mask == 0:
                    return True
    return False


def _as_word(x) -> Expr:
    return const(x) if isinstance(x, int) and not isinstance(x, bool) else x


def _low_bits_cleared(atom, bits: int) -> Optional[Tuple[int, Expr]]:
    """(o, y) when `atom` is y with its low o bits cleared (o >= 0) and every
    bit kept from o up to bit 128 at least: y rounded down to a multiple of
    2**o, for words below 2**bits (a Mask or an `and` with a constant)."""
    m = _mask_atom(atom)
    if m is not None and m[0] + m[1] >= 128 and (m[1] > 0 or m[0] >= bits):
        return m[1], m[2]
    if isinstance(atom, Op) and atom.op == "and" and len(atom.args) == 2:
        for c, y in (atom.args, atom.args[::-1]):
            if isinstance(c, Const) and c.value:
                o = _two_adic(c.value)
                if (c.value >> o) & ((1 << (128 - o)) - 1) == (1 << (128 - o)) - 1 and o < 128:
                    return o, y
    return None


@functools.lru_cache(maxsize=8192)
def may_be_negative(e, bits: int = 64) -> bool:
    """A byte length `e` can be negative (read as signed) where every word
    it reads is below 2**bits, as memory offsets and sizes are: a mask that
    rounds down (Mask(size, offset, 0, y), offset > 0, offset + size >= 128)
    counts as y minus 0 .. 2**offset - 1, one that keeps the low bits as y,
    any other word as 0 .. 2**bits - 1.  (The engine guesses where a write
    ends inside a range it splits, and can leave a negative length.)"""
    terms, const = linear(e)
    low = to_signed(const)
    work = [(atom, to_signed(c)) for atom, c in terms]
    base: dict = {}
    for _ in range(256):
        if not work:
            break
        atom, c = work.pop()
        m = _low_bits_cleared(atom, bits)
        if m is not None:
            off, value = m
            inner, k = linear(value)
            low += c * to_signed(k)
            work.extend((a, c * to_signed(x)) for a, x in inner)
            if off > 0:
                cut = _known_low(value, off)  # what rounding down removes: known, or 0 .. 2**off - 1
                if cut is not None:
                    low -= c * cut
                elif c > 0:
                    low -= c * ((1 << off) - 1)
            continue
        base[atom] = base.get(atom, 0) + c
    else:
        return True
    if work:
        return True
    if low + sum(c * _atom_max(a, bits) for a, c in base.items() if c < 0) >= 0:
        return False
    return _interval(e, bits)[0] < 0  # (a second bound, blind to cancellations but not to roundings)


def _atom_max(atom, bits: int) -> int:
    """The largest value of a word below 2**bits, or of a bit field of one."""
    top = (1 << bits) - 1
    if isinstance(atom, Mask):
        size, off, shl = _bits(atom.size), _bits(atom.offset), _bits(atom.shl)
        if None not in (size, off, shl) and size >= 0 and off >= 0:
            m = (((1 << min(size, WORD_BITS)) - 1) << off) % WORD_MOD
            return min(top, m << shl if shl >= 0 else m >> -shl)
    if isinstance(atom, Op) and atom.op == "and":
        consts = [a.value for a in atom.args if isinstance(a, Const)]
        if consts:
            return min(top, min(consts))
    return top


MAX_MASK_SIZE = (1 << 255) - 1  # MaskBytes.size None: every bit


def mask_bytes(size, offset, shl, data: Bytes, length: Expr) -> Bytes:
    """MaskBytes(size, offset, shl, data, length), or `data` itself when
    the mask provably keeps all of it in place (offset and shl 0, size 8
    times its length or None) and `length` is provably its length.  (A
    length of 2**253 bytes or more would make the size wrap: no such byte
    string is ever built, the copy halts first, in the original and in the
    generated code.)"""
    n = byte_length(data)
    if n is not None and same_value(length, n) and same_value(offset, 0) and same_value(shl, 0) and (
            size is None or same_value(size, Op("mul", (Const(8), n)))):
        return data
    return MaskBytes(size, offset, shl, data, length)


def mask_bytes_value(data: bytes, size: Optional[int], offset: int, shl: int, length: int) -> bytes:
    """MaskBytes on constants (the reference semantics): size / offset / shl
    signed Python ints, size None for 2**255 - 1."""
    x = int.from_bytes(data, "big")
    bits = 8 * len(data)
    if size is None:
        size = MAX_MASK_SIZE
    if size <= 0:
        return bytes(length)
    lo, hi = max(offset, 0), min(offset + size, bits)
    out = 8 * length
    if hi <= lo or shl >= out or shl <= -hi:
        return bytes(length)
    v = (x >> lo) & ((1 << (hi - lo)) - 1)  # bits [lo, hi) of X, moved down to 0
    p = lo + shl  # where they go
    v = v << p if p >= 0 else v >> -p
    return (v % (1 << out)).to_bytes(length, "big")

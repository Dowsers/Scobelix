"""
Typed input generation for differential execution.

Argument values come, by priority, from:
  * edge values per type (0, 1, 2, max, max-1, 2^(n-1), 2^(n-1)-1, 10^18,
    small numbers; signed: min, -1);
  * an address universe shared by arguments, senders and storage keys, so
    that aliasing such as `transfer(to == msg.sender)` actually happens, with
    the contracts of the environment (the ERC20-like stub) favoured;
  * a dictionary: PUSH constants of the original (small ones included: a
    `require(x < 5)` boundary is one) plus environment values (block
    timestamp / number +-1), and, in a pool of their own, the boundaries:
    the values the function's inputs were compared with at run time
    (cmp-log), or until there are some the constants the original compares
    something with; a value comes with its neighbours v +- 1, and `bytesN`
    arguments draw from both too (interface ids, roles);
  * values already produced for the current call (v, v+-1: argument-aware);
  * uniform random values of a random width.

A share of the calls is malformed (`mutate_calldata`): short or long
calldata, selector only, dirty padding of a narrow static parameter, a
corrupted dynamic offset.  Those exercise the compiler-generated ABI decoder,
whose checks are part of the behaviour to preserve.
"""

from __future__ import annotations

import random
import re
from typing import Dict, List, Optional, Sequence, Tuple

from eth_abi import encode

from .abi import FuncSpec, split_types
from .bytecode import disasm, strip_all_metadata

__all__ = [
    "ValueGen",
    "call_value",
    "comparison_constants",
    "encode_call",
    "head_words",
    "is_dynamic",
    "mutate_calldata",
    "push_dictionary",
    "raw_calldata",
]

_ARRAY_RE = re.compile(r"^(.*)\[(\d*)\]$")
_UINT_RE = re.compile(r"^uint(\d+)$")
_INT_RE = re.compile(r"^int(\d+)$")
_BYTES_RE = re.compile(r"^bytes(\d+)$")


_WORD = (1 << 256) - 1
# opcodes whose operands are boundaries: LT GT SLT SGT EQ, and SUB / XOR (solc's `x != c` is often
# `jumpi(.., sub(x, c))`, and `x - c` underflows at c)
_BOUNDARY_OPS = {0x10, 0x11, 0x12, 0x13, 0x14, 0x03, 0x18}


def _data_constants(code: bytes) -> List[Tuple[int, bool]]:
    """
    (value, feeds a comparison) for every PUSH of a runtime that is not a
    code offset (a PUSH1 / PUSH2 of the offset of a JUMPDEST: jump targets and
    return addresses, most of a runtime's pushes), in code order, metadata
    excluded.  A PUSH followed by NOT counts as the complement (solc builds
    negative constants and masks so); "feeds a comparison": a boundary opcode
    follows within three DUP / SWAP.
    """
    ins = disasm(strip_all_metadata(code))
    jumpdests = {pc for pc, op, _ in ins if op == 0x5B}
    out: List[Tuple[int, bool]] = []
    for i, (_pc, op, v) in enumerate(ins):
        if v is None or (op <= 0x61 and v in jumpdests):
            continue
        j = i + 1
        if j < len(ins) and ins[j][1] == 0x19:  # NOT
            v, j = ~v & _WORD, j + 1
        k = j
        while k < len(ins) and k < j + 3 and 0x80 <= ins[k][1] <= 0x9F:  # DUPn / SWAPn
            k += 1
        out.append((v, k < len(ins) and ins[k][1] in _BOUNDARY_OPS))
    return out


def push_dictionary(code: bytes, limit: int = 64) -> List[int]:
    """
    Distinct data constants of a runtime (see `_data_constants`), in code
    order; 0 and 1 are left out (edge values anyway), small constants kept.
    """
    seen: Dict[int, None] = {}
    for v, _ in _data_constants(code):
        if v > 1 and v not in seen:
            seen[v] = None
            if len(seen) >= limit:
                break
    return list(seen)


def comparison_constants(code: bytes, exclude: Sequence[int] = (), limit: int = 64) -> List[int]:
    """
    The data constants a runtime compares something with (`x < 100`, `x != 7`,
    `x > -5`...), `exclude` (the dispatcher's selectors) left out: the
    boundaries an input most likely has to hit exactly.
    """
    skip = set(exclude)
    seen: Dict[int, None] = {}
    for v, compared in _data_constants(code):
        if compared and v > 1 and v not in skip and v not in seen:
            seen[v] = None
            if len(seen) >= limit:
                break
    return list(seen)


def call_value(rng: random.Random) -> int:
    """msg.value: 0 for 80 % of the calls, 1 for 10 %, random up to 1 ether otherwise."""
    p = rng.random()
    if p < 0.8:
        return 0
    if p < 0.9:
        return 1
    return rng.randrange(1, 10**18)


class ValueGen:
    """
    Generates the arguments of one call; `used` collects the integers it
    produced.  `dictionary`: constants of the code and of the environment;
    `learned`: comparison operands observed at run time (a pool of its own,
    so that the few relevant ones are not drowned among the constants);
    `contracts`: addresses with code worth calling (favoured for addresses).
    """

    def __init__(
        self,
        rng: random.Random,
        addresses: Sequence[str],
        dictionary: Sequence[int] = (),
        edge_bias: float = 0.45,
        *,
        learned: Sequence[int] = (),
        contracts: Sequence[str] = (),
    ):
        self.rng = rng
        self.addresses = list(addresses)
        self.dictionary = list(dictionary)
        self.learned = list(learned)
        self.contracts = list(contracts)
        self.edge_bias = edge_bias
        self.used: List[int] = []  # integers produced for the current call (argument-aware seeding)
        self.used_addresses: List[str] = []

    def constant(self) -> Optional[int]:
        """A dictionary or learned value (half of the time a learned one when there are some)."""
        r = self.rng
        if self.learned and (not self.dictionary or r.random() < 0.5):
            return r.choice(self.learned)
        return r.choice(self.dictionary) if self.dictionary else None

    def uint(self, bits: int) -> int:
        r, mx = self.rng, (1 << bits) - 1
        p = r.random()
        if p < self.edge_bias:
            v = r.choice(
                (
                    0,
                    1,
                    2,
                    mx,
                    mx - 1,
                    1 << (bits - 1),
                    (1 << (bits - 1)) - 1,
                    10**18,
                    r.randrange(0, 1000),
                )
            )
        elif p < self.edge_bias + 0.3 and (self.dictionary or self.learned):
            # a constant, or a neighbour of it: both sides of a `<` / `<=` boundary
            v = self.constant() + r.choice((-1, 0, 0, 1))
        elif p < self.edge_bias + 0.4 and self.used:
            v = r.choice(self.used) + r.choice((-1, 0, 1))
        else:
            v = r.getrandbits(r.choice((8, 32, 64, bits)))
        return v & mx

    def address(self) -> str:
        r = self.rng
        p = r.random()
        if p < 0.15 and self.contracts:
            a = r.choice(self.contracts)
        elif p < 0.8 and self.addresses:
            a = r.choice(self.addresses)
        elif p < 0.88:
            a = "0x" + "00" * 20
        else:
            a = "0x" + r.getrandbits(160).to_bytes(20, "big").hex()
        self.used_addresses.append(a)
        return a

    def fixed_bytes(self, n: int) -> bytes:
        r = self.rng
        p = r.random()
        if p < 0.3 and (self.dictionary or self.learned):
            # a constant as a right-aligned value (PUSH4 id then shifted) or a left-aligned word
            low = 8 * (32 - n)
            fits = [
                v
                for v in self.dictionary + self.learned
                if v and (v < 1 << (8 * n) or not v & ((1 << low) - 1))
            ]
            if fits:
                v = r.choice(fits)
                return (v if v < 1 << (8 * n) else v >> low).to_bytes(n, "big")
        return r.choice((bytes(n), b"\xff" * n, bytes(r.getrandbits(8) for _ in range(n))))

    def gen(self, t: str):
        """A random value of canonical ABI type `t`, in the form eth_abi.encode expects."""
        r = self.rng
        m = _ARRAY_RE.match(t)
        if m and not t.endswith(")"):
            inner, n = m.group(1), m.group(2)
            k = int(n) if n else r.choice((0, 1, 2, 3, r.randrange(0, 8)))
            return [self.gen(inner) for _ in range(k)]
        if t.startswith("(") and t.endswith(")"):
            return tuple(self.gen(x) for x in split_types(t[1:-1]))
        if t == "address":
            return self.address()
        if t == "bool":
            return r.random() < 0.5
        m = _UINT_RE.match(t)
        if m:
            v = self.uint(int(m.group(1)))
            self.used.append(v)
            return v
        m = _INT_RE.match(t)
        if m:
            bits = int(m.group(1))
            u = self.uint(bits)
            self.used.append(u)
            return u - (1 << bits) if u >> (bits - 1) else u
        m = _BYTES_RE.match(t)
        if m:
            return self.fixed_bytes(int(m.group(1)))
        if t == "function":
            return bytes(r.getrandbits(8) for _ in range(24))
        if t in ("bytes", "string"):
            n = r.choice((0, 1, 31, 32, 33, 64, r.randrange(0, 200)))
            if t == "bytes":
                return bytes(r.getrandbits(8) for _ in range(n))
            alphabet = (
                "abcdefghijklmnopqrstuvwxyz0123456789 " if r.random() < 0.9 else "é中\U0001f600a"
            )
            return "".join(r.choice(alphabet) for _ in range(n))
        raise ValueError(f"unsupported ABI type {t!r}")


def encode_call(spec: FuncSpec, args: Sequence) -> bytes:
    return spec.selector + encode(list(spec.inputs or []), list(args))


def raw_calldata(rng: random.Random, vg: ValueGen, selector: bytes) -> bytes:
    """Calldata for a selector whose parameter types are unknown: 0-4 plausible words."""
    words = []
    for _ in range(rng.choice((0, 1, 1, 2, 2, 3, 4))):
        p = rng.random()
        if p < 0.35:
            w = int(vg.address(), 16)
        elif p < 0.5:
            w = rng.choice((0, 1))
        else:
            w = vg.uint(256)
            vg.used.append(w)
        words.append(w.to_bytes(32, "big"))
    tail = (
        bytes(rng.getrandbits(8) for _ in range(rng.choice((1, 31)))) if rng.random() < 0.1 else b""
    )
    return selector + b"".join(words) + tail


def is_dynamic(t: str) -> bool:
    if t in ("bytes", "string"):
        return True
    m = _ARRAY_RE.match(t)
    if m and not t.endswith(")"):
        return m.group(2) == "" or is_dynamic(m.group(1))
    if t.startswith("("):
        return any(is_dynamic(x) for x in split_types(t[1:-1]))
    return False


def _static_leaves(t: str, word: int) -> Tuple[List[Tuple[int, str]], int]:
    """(word index, basic type) of every word a static type occupies, and its word count."""
    m = _ARRAY_RE.match(t)
    if m and not t.endswith(")"):
        out: List[Tuple[int, str]] = []
        for _ in range(int(m.group(2))):
            leaves, n = _static_leaves(m.group(1), word)
            out += leaves
            word += n
        return out, len(out)
    if t.startswith("("):
        out = []
        for x in split_types(t[1:-1]):
            leaves, n = _static_leaves(x, word)
            out += leaves
            word += n
        return out, len(out)
    return [(word, t)], 1


def head_words(types: Sequence[str]) -> List[Tuple[int, str]]:
    """(head word index, basic type or '<offset>') of every head word of a parameter list."""
    out: List[Tuple[int, str]] = []
    word = 0
    for t in types:
        if is_dynamic(t):
            out.append((word, "<offset>"))
            word += 1
        else:
            leaves, n = _static_leaves(t, word)
            out += leaves
            word += n
    return out


def _padding(t: str) -> Optional[Tuple[int, int]]:
    """[start, end) bytes of a head word that a valid encoding of basic type `t` keeps clean."""
    if t in ("address",):
        return 0, 12
    if t == "bool":
        return 0, 31
    m = _UINT_RE.match(t) or _INT_RE.match(t)
    if m and int(m.group(1)) < 256:
        return 0, 32 - int(m.group(1)) // 8
    m = _BYTES_RE.match(t)
    if m and int(m.group(1)) < 32:
        return int(m.group(1)), 32
    if t == "function":
        return 24, 32
    return None


def mutate_calldata(rng: random.Random, spec: FuncSpec, data: bytes) -> Tuple[str, bytes]:
    """One malformed variant of a well-formed call: (mutation kind, calldata)."""
    words = head_words(spec.inputs or [])
    dirty = [(w, t) for w, t in words if t != "<offset>" and _padding(t)]
    offsets = [w for w, t in words if t == "<offset>"]
    kinds = ["short", "long", "selector_only"]
    if dirty:
        kinds += ["dirty", "dirty"]
    if offsets:
        kinds.append("offset")
    kind = rng.choice(kinds)
    if kind == "short":
        return kind, data[: max(4, len(data) - rng.choice((1, 31, 32)))]
    if kind == "long":
        return kind, data + bytes(rng.getrandbits(8) for _ in range(rng.choice((1, 32))))
    if kind == "selector_only":
        return kind, data[:4]
    out = bytearray(data)
    if kind == "dirty":
        w, t = rng.choice(dirty)
        start, end = _padding(t)
        pos = 4 + 32 * w + rng.randrange(start, end)
        if t == "bool" and rng.random() < 0.5:
            pos, value = 4 + 32 * w + 31, rng.randrange(2, 256)  # value byte outside {0, 1}
        else:
            value = out[pos] ^ rng.randrange(1, 256)
        if pos < len(out):
            out[pos] = value
        return kind, bytes(out)
    w = rng.choice(offsets)
    pos = 4 + 32 * w
    bad = rng.choice((0, 1, 31, len(data), 1 << 64, (1 << 256) - 32))
    out[pos : pos + 32] = bad.to_bytes(32, "big")
    return kind, bytes(out)

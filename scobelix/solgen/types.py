"""
Solidity type model and the value facts the renderer relies on.

Types: `parse_type` reads canonical ABI type strings ("uint256",
"address[]", "(uint8,bytes)[2]") into `SolType` trees, which know their
canonical spelling, ABI head size, dynamism and Solidity declaration.

Value facts (`max_bits`, `is_boolean`, `low_zero_bits`, `sign_extended`)
are sound over-approximations of what an IR word can hold.  They decide
when a word can be shown as a narrower Solidity type without changing its
value (`fits`): an `address` view of a word is exact only if the word is
below 2**160, a `bool` view only if it is 0 or 1, and so on.  Anything not
provable stays a `uint256`.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Callable, List, Optional, Tuple

from scobelix.solgen import ir

__all__ = [
    "SolType",
    "parse_type",
    "split_types",
    "canonical",
    "max_bits",
    "is_boolean",
    "low_zero_bits",
    "sign_extended",
    "fits",
]


# ---------------------------------------------------------------- types


@dataclasses.dataclass(frozen=True)
class SolType:
    """A Solidity / ABI type.

    kind: "uint" | "int" | "address" | "bool" | "bytes" (fixed bytesN) |
          "dynbytes" | "string" | "array" | "tuple" | "function"
    bits: width for uint/int (8..256) and bytesN (8*N)
    base: element type of an array; length: None for T[]
    components: members of a tuple
    """

    kind: str
    bits: int = 0
    base: Optional["SolType"] = None
    length: Optional[int] = None
    components: Tuple["SolType", ...] = ()

    @property
    def canonical(self) -> str:
        if self.kind in ("uint", "int"):
            return f"{self.kind}{self.bits}"
        if self.kind == "bytes":
            return f"bytes{self.bits // 8}"
        if self.kind == "dynbytes":
            return "bytes"
        if self.kind == "array":
            return f"{self.base.canonical}[{'' if self.length is None else self.length}]"
        if self.kind == "tuple":
            return "(" + ",".join(c.canonical for c in self.components) + ")"
        if self.kind == "function":
            return "function"
        return self.kind  # address, bool, string

    @property
    def is_dynamic(self) -> bool:
        if self.kind in ("dynbytes", "string"):
            return True
        if self.kind == "array":
            return self.length is None or self.base.is_dynamic
        if self.kind == "tuple":
            return any(c.is_dynamic for c in self.components)
        return False

    @property
    def is_value(self) -> bool:
        """One 32-byte word in the ABI encoding (elementary static types)."""
        return self.kind in ("uint", "int", "address", "bool", "bytes", "function")

    @property
    def head_words(self) -> int:
        """Words this type takes in the head of an ABI encoding."""
        if self.is_dynamic:
            return 1
        if self.kind == "array":
            return self.length * self.base.head_words
        if self.kind == "tuple":
            return sum(c.head_words for c in self.components)
        return 1

    def solidity(self, location: str = "", struct_name: Optional[Callable[["SolType"], str]] = None) -> str:
        """Declaration of a variable of this type (`location`: "calldata",
        "memory" or "" for value types); tuples are named by `struct_name`."""
        if self.kind == "tuple":
            name = struct_name(self) if struct_name else "/* tuple */"
            return f"{name} {location}".rstrip() if location else name
        if self.kind == "array":
            inner = self.base.solidity("", struct_name)
            text = f"{inner}[{'' if self.length is None else self.length}]"
            return f"{text} {location}".rstrip() if location else text
        if self.kind == "function":
            text = "function() external"  # ABI "function" = 24 bytes; any external function type
            return text
        text = self.canonical
        if self.kind in ("dynbytes", "string") and location:
            return f"{text} {location}"
        return text

    @property
    def needs_location(self) -> bool:
        return self.kind in ("dynbytes", "string", "array", "tuple")


_ELEMENTARY_RE = re.compile(r"(uint|int)(\d*)|address|bool|string|bytes(\d*)|function|byte")


def split_types(text: str) -> List[str]:
    """'address,(uint8,bytes)[],uint256' -> ['address', '(uint8,bytes)[]', 'uint256']."""
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        depth += ch == "("
        depth -= ch == ")"
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def parse_type(text: str) -> SolType:
    """SolType of an ABI type string; raises ValueError when unsupported."""
    t = text.strip()
    suffixes = []
    while t.endswith("]"):
        i = t.rindex("[")
        dim = t[i + 1 : -1].strip()
        if dim and not dim.isdigit():
            raise ValueError(f"bad array dimension in {text!r}")
        suffixes.append(int(dim) if dim else None)
        t = t[:i].strip()
    if t.startswith("(") and t.endswith(")"):
        base = SolType("tuple", components=tuple(parse_type(c) for c in split_types(t[1:-1])))
        if not base.components:
            raise ValueError(f"empty tuple in {text!r}")
    elif t.startswith("tuple"):
        raise ValueError(f"tuple type without components: {text!r}")
    else:
        m = _ELEMENTARY_RE.fullmatch(t)
        if not m:
            raise ValueError(f"unsupported type {text!r}")
        if m.group(1):
            bits = int(m.group(2)) if m.group(2) else 256
            if bits % 8 or not 8 <= bits <= 256:
                raise ValueError(f"bad integer width in {text!r}")
            base = SolType(m.group(1), bits)
        elif t == "byte":
            base = SolType("bytes", 8)
        elif t.startswith("bytes"):
            if m.group(3):
                n = int(m.group(3))
                if not 1 <= n <= 32:
                    raise ValueError(f"bad bytes width in {text!r}")
                base = SolType("bytes", 8 * n)
            else:
                base = SolType("dynbytes")
        else:
            base = SolType(t)
    for length in reversed(suffixes):
        base = SolType("array", base=base, length=length)
    return base


def canonical(text: str) -> str:
    """Canonical spelling of an ABI type ('uint' -> 'uint256', ...)."""
    return parse_type(text).canonical


# ---------------------------------------------------------------- value facts


def _int(e) -> Optional[int]:
    """A constant bit-position field (Python int, or a Const read signed)."""
    if isinstance(e, int) and not isinstance(e, bool):
        return e
    if isinstance(e, ir.Const):
        return e.value - ir.WORD_MOD if e.value >> 255 else e.value
    return None


def _uint(e) -> Optional[int]:
    """The value of a constant word operand."""
    return e.value if isinstance(e, ir.Const) else None


_ADDRESS_ENV = frozenset({"caller", "origin", "address", "coinbase"})


def max_bits(e: ir.Expr) -> int:
    """An upper bound on the bit length of the word `e` (256 when unknown)."""
    if isinstance(e, ir.Const):
        return e.value.bit_length()
    if isinstance(e, ir.Env):
        return 160 if e.name in _ADDRESS_ENV else 256
    if isinstance(e, (ir.Bool, ir.Not, ir.And, ir.Or)):
        return 1
    if isinstance(e, ir.Op):
        if e.op in ir.COMPARISONS:
            return 1
        if e.op == "and":
            return min(max_bits(a) for a in e.args)
        if e.op in ("or", "xor"):
            return max(max_bits(a) for a in e.args)
        if e.op == "byte":
            return 8
        if e.op == "shr":
            k = _uint(e.args[0])
            if k is not None:
                return max(0, max_bits(e.args[1]) - k)
        if e.op == "mod":
            m = _uint(e.args[1])
            if m:
                return min(max_bits(e.args[0]), (m - 1).bit_length())
        if e.op == "div":
            return max_bits(e.args[0])
        return 256
    if isinstance(e, ir.Mask):
        size, off, shl = _int(e.size), _int(e.offset), _int(e.shl)
        if None not in (size, off, shl) and off >= 0:
            top = min(size + off, max_bits(e.value))  # highest bit kept + 1, before shifting
            return max(0, min(256, top + shl))
        return 256
    if isinstance(e, ir.Field):
        size = ir.field_bits(e.size)  # unsigned, like the renderer's _field
        if size is not None:
            return min(size, 256)
        return 256
    if isinstance(e, ir.CallOut) and e.what == "success":
        return 1
    if isinstance(e, ir.CallOut) and e.what == "address":
        return 160
    if isinstance(e, ir.Ternary):
        return max(max_bits(e.if_true), max_bits(e.if_false))
    if isinstance(e, (ir.Cast, ir.StateRef, ir.Result)):
        return _cast_bits(e.ty)
    if isinstance(e, ir.Typed):
        return 1 if e.op in ("lt", "gt", "eq") else _cast_bits(e.ty)
    return 256


def _cast_bits(ty: str) -> int:
    try:
        t = parse_type(ty)
    except ValueError:
        return 256
    if t.kind == "uint":
        return t.bits
    if t.kind == "address":
        return 160
    if t.kind == "bool":
        return 1
    return 256


def is_boolean(e: ir.Expr) -> bool:
    """The word is provably 0 or 1."""
    return max_bits(e) <= 1


def low_zero_bits(e: ir.Expr) -> int:
    """A lower bound on the number of low-order zero bits of `e` (the word
    is a left-aligned bytesN when 256 - 8N low bits are zero)."""
    if isinstance(e, ir.Const):
        if e.value == 0:
            return 256
        return (e.value & -e.value).bit_length() - 1
    if isinstance(e, ir.Mask):
        size, off, shl = _int(e.size), _int(e.offset), _int(e.shl)
        if None not in (size, off, shl) and off >= 0:
            return max(0, min(256, off + shl))
    if isinstance(e, ir.Op) and e.op == "shl":
        k = _uint(e.args[0])
        if k is not None:
            return min(256, k)
    if isinstance(e, ir.Op) and e.op == "and":
        return max(low_zero_bits(a) for a in e.args)
    if isinstance(e, ir.Result) and e.ty.startswith("bytes") and e.ty != "bytes":
        try:
            return 256 - parse_type(e.ty).bits
        except ValueError:
            return 0
    return 0


def sign_extended(e: ir.Expr) -> Optional[int]:
    """Byte index b when `e` is signextend(b, x) (an int(8*(b+1)) value)."""
    if isinstance(e, ir.Op) and e.op == "signextend":
        b = _uint(e.args[0])
        if b is not None and b < 31:
            return b
    return None


def fits(e: ir.Expr, ty: SolType) -> bool:
    """True if `ty`'s ABI word for the value of `e` is `e` itself, i.e. a
    `ty` view of the word loses nothing."""
    if ty.kind == "uint":
        return ty.bits == 256 or max_bits(e) <= ty.bits
    if ty.kind == "address":
        return max_bits(e) <= 160
    if ty.kind == "bool":
        return is_boolean(e)
    if ty.kind == "bytes":
        return ty.bits == 256 or low_zero_bits(e) >= 256 - ty.bits
    if ty.kind == "int":
        if ty.bits == 256:
            return True
        if isinstance(e, ir.Const):  # a constant word that is a valid intN value (sign-extended)
            return -(1 << (ty.bits - 1)) <= ir.to_signed(e.value) < 1 << (ty.bits - 1)
        comparison = isinstance(e, ir.Typed) and e.op in ("lt", "gt", "eq")
        if isinstance(e, (ir.StateRef, ir.Typed, ir.Cast, ir.Result)) and not comparison:
            # a typed value: the word of an intM value is sign-extended
            own = _int_bits(e.ty)
            return own is not None and own <= ty.bits
        b = sign_extended(e)
        return b is not None and 8 * (b + 1) <= ty.bits
    return False


def _int_bits(ty: str) -> Optional[int]:
    try:
        t = parse_type(ty)
    except ValueError:
        return None
    return t.bits if t.kind == "int" else None

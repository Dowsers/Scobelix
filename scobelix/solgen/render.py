"""
IR -> Solidity text, under the exactness contract (DESIGN section 6.4).

Every word is a `uint256` and every construct keeps the EVM meaning the IR
gives it:

  * wrapping arithmetic (add, sub, mul) runs inside `unchecked`: the body
    of a function without checked operations is one `unchecked` block;
    with checked operations (`ir.Typed(checked=True)`, from passes) each
    statement without checked operations gets an `unchecked` block of its
    own, and the wrapping operations of the other statements go through
    the `_wadd` / `_wsub` / `_wmul` helpers (expressions, so they wrap in
    conditions, loop tests and operands of checked operations, and are
    evaluated exactly where the IR evaluates them);
  * comparisons are `bool` expressions; a bool used as a word becomes
    `(c ? 1 : 0)` and a word used as a condition `w != 0`; `&&` / `||` only
    when the right operands cannot end the call (the opcodes evaluate
    them);
  * idiomatic nodes: `Typed` runs Solidity's operator on its operands
    converted to `ty` (in the context its `checked` flag needs),
    `StateRef` reads are widened to the word of their `ty` and assignments
    to them narrowed from it;
  * signed comparisons go through `int256(...)` (a reinterpretation);
  * operations whose Solidity meaning differs from the EVM's go through
    tiny private helpers with inline assembly, emitted only when used:
    div/mod/sdiv/smod (division by zero gives 0, int256 overflow wraps),
    exp, addmod/mulmod (modulus 0), signextend, byte, sar, symbolic masks;
    division and modulo by a non-zero constant stay `/` and `%`;
  * storage is read and written by slot through `_sload` / `_sstore`
    (packed fields: `_sstoreField`), logs through `_logN`, return data
    through `_returndata` / `_returndatasize`, calldata through
    `_calldataload` / `_calldata` (zero past its end, like the EVM), and
    reverts / returns of raw bytes, Panic codes, `invalid` and `stop`
    through assembly helpers;
  * the original code's memory, when it is read back, is emulated byte for
    byte in a private buffer (`_vm`, see the `_vm*` helpers): its absolute
    addresses never meet the memory Solidity manages.  Memory that is never
    read is not observable and its writes are dropped;
  * string literals and comments only carry characters solc accepts in
    source text (string_literal, comment_text), and no declared name
    shadows a keyword, a builtin or a generated name (reserved_name).

Known limits (not exact, documented): a call's output area past the
return data is zero where the original keeps the old memory, a
RETURNDATACOPY past the end of the return data reads zeros where the
original halts, and a memory read far past everything written (megabytes)
costs the original gas the emulation does not spend.

Narrower views are used only when they are value-preserving (types.fits):
`uint256(uint160(msg.sender))`, the declared parameters of a known
signature under ABI coder v2 (the decoder validated them), declared return
types whose values provably fit.
"""

from __future__ import annotations

import dataclasses
import re
import unicodedata
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from scobelix.solgen import ir, scopes, stack
from scobelix.solgen.types import SolType, is_boolean, max_bits, parse_type

__all__ = ["RenderContext", "EntryRender", "Helpers", "render_function_body", "literal", "string_literal",
           "comment_text", "reserved_name", "exact_machinery"]

W, B = "word", "bool"


# ---------------------------------------------------------------- helpers registry


_HELPERS: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    # name: (source, dependencies)
    "_div": ("function _div(uint256 a, uint256 b) private pure returns (uint256 r) { assembly { r := div(a, b) } }", ()),
    "_sdiv": ("function _sdiv(uint256 a, uint256 b) private pure returns (uint256 r) { assembly { r := sdiv(a, b) } }", ()),
    "_mod": ("function _mod(uint256 a, uint256 b) private pure returns (uint256 r) { assembly { r := mod(a, b) } }", ()),
    "_smod": ("function _smod(uint256 a, uint256 b) private pure returns (uint256 r) { assembly { r := smod(a, b) } }", ()),
    "_exp": ("function _exp(uint256 a, uint256 b) private pure returns (uint256 r) { assembly { r := exp(a, b) } }", ()),
    "_addmod": ("function _addmod(uint256 a, uint256 b, uint256 m) private pure returns (uint256 r) "
                "{ assembly { r := addmod(a, b, m) } }", ()),
    "_mulmod": ("function _mulmod(uint256 a, uint256 b, uint256 m) private pure returns (uint256 r) "
                "{ assembly { r := mulmod(a, b, m) } }", ()),
    "_signextend": ("function _signextend(uint256 b, uint256 x) private pure returns (uint256 r) "
                    "{ assembly { r := signextend(b, x) } }", ()),
    "_byte": ("function _byte(uint256 i, uint256 x) private pure returns (uint256 r) { assembly { r := byte(i, x) } }", ()),
    "_sar": ("function _sar(uint256 s, uint256 x) private pure returns (uint256 r) { assembly { r := sar(s, x) } }", ()),
    "_maskShl": ("""function _maskShl(uint256 size, uint256 offset, uint256 shift, uint256 x) private pure returns (uint256 r) {
        // the decompiler's mask_shl: (x & ((2**size - 1) << offset)) << shift,
        // size, offset and shift read as signed (negative: to the right)
        unchecked {
            int256 s = int256(size);
            int256 o = int256(offset);
            if (s <= 0) return 0;
            if (o < 0) {
                s += o; // the mask shifted right keeps its low size + offset bits
                o = 0;
                if (s <= 0) return 0;
            }
            if (o >= 256) return 0;
            uint256 m = s >= 256 ? type(uint256).max : (uint256(1) << uint256(s)) - 1;
            r = x & (m << uint256(o));
            r = int256(shift) >= 0 ? r << shift : r >> uint256(-int256(shift));
        }
    }""", ()),
    "_wadd": ("function _wadd(uint256 a, uint256 b) private pure returns (uint256) { unchecked { return a + b; } }", ()),
    "_wsub": ("function _wsub(uint256 a, uint256 b) private pure returns (uint256) { unchecked { return a - b; } }", ()),
    "_wmul": ("function _wmul(uint256 a, uint256 b) private pure returns (uint256) { unchecked { return a * b; } }", ()),
    "_field": ("""function _field(uint256 x, uint256 offset, uint256 size) private pure returns (uint256) {
        // (x >> offset) & (2**size - 1)
        unchecked {
            uint256 m = size >= 256 ? type(uint256).max : (uint256(1) << size) - 1;
            return (x >> offset) & m;
        }
    }""", ()),
    "_sload": ("function _sload(uint256 slot) private view returns (uint256 v) { assembly { v := sload(slot) } }", ()),
    "_sstore": ("function _sstore(uint256 slot, uint256 v) private { assembly { sstore(slot, v) } }", ()),
    "_sstoreField": ("""function _sstoreField(uint256 slot, uint256 offset, uint256 size, uint256 v) private {
        // bits [offset, offset + size) of the slot := the low `size` bits of v
        unchecked {
            uint256 m = (size >= 256 ? type(uint256).max : (uint256(1) << size) - 1) << offset;
            _sstore(slot, (_sload(slot) & ~m) | ((v << offset) & m));
        }
    }""", ("_sload", "_sstore")),
    "_tload": ("function _tload(uint256 slot) private view returns (uint256 v) { assembly { v := tload(slot) } }", ()),
    "_tstore": ("function _tstore(uint256 slot, uint256 v) private { assembly { tstore(slot, v) } }", ()),
    "_callvalue": ("function _callvalue() private view returns (uint256 v) { assembly { v := callvalue() } }", ()),
    "_calldataload": ("function _calldataload(uint256 p) private pure returns (uint256 v) "
                      "{ assembly { v := calldataload(p) } }", ()),
    "_alloc": ("""function _alloc(uint256 n) private pure returns (bytes memory) {
        // n zero bytes; a size no gas could pay for halts like the original
        if (n > 0xffffffff) _invalid();
        return new bytes(n);
    }""", ("_invalid",)),
    "_calldata": ("""function _calldata(uint256 p, uint256 n) private pure returns (bytes memory r) {
        // calldatacopy: zero past the end of the calldata
        r = _alloc(n);
        assembly { calldatacopy(add(r, 32), p, n) }
    }""", ("_alloc",)),
    "_returndatasize": ("function _returndatasize() private pure returns (uint256 n) { assembly { n := returndatasize() } }", ()),
    "_returndata": ("""function _returndata(uint256 p, uint256 n) private pure returns (bytes memory r) {
        // the last call's return data [p, p + n), zero past its end
        r = _alloc(n);
        assembly {
            let $size := returndatasize()
            if lt(p, $size) {
                let $avail := sub($size, p)
                if gt($avail, n) { $avail := n }
                returndatacopy(add(r, 32), p, $avail)
            }
        }
    }""", ("_alloc",)),
    "_returndataWord": ("""function _returndataWord(uint256 p) private pure returns (uint256 v) {
        bytes memory b = _returndata(p, 32);
        assembly { v := mload(add(b, 32)) }
    }""", ("_returndata",)),
    "_extcode": ("""function _extcode(uint256 a, uint256 p, uint256 n) private view returns (bytes memory r) {
        r = _alloc(n);
        assembly { extcodecopy(a, add(r, 32), p, n) }
    }""", ("_alloc",)),
    "_code": ("""function _code(uint256 p, uint256 n) private pure returns (bytes memory r) {
        // codecopy of the ORIGINAL runtime code, zero past its end
        bytes memory c = _ORIGINAL_CODE;
        r = _alloc(n);
        if (p < c.length) _copy(r, 0, c, p, c.length - p < n ? c.length - p : n);
    }""", ("_alloc", "_copy")),
    "_copy": ("""function _copy(bytes memory dst, uint256 d, bytes memory src, uint256 s, uint256 n) private pure {
        // dst[d, d + n) = src[s, s + n), both ranges inside their arrays
        assembly {
            let $to := add(add(dst, 32), d)
            let $from := add(add(src, 32), s)
            for { let $i := 0 } lt(add($i, 31), n) { $i := add($i, 32) } { mstore(add($to, $i), mload(add($from, $i))) }
            for { let $i := and(n, not(31)) } lt($i, n) { $i := add($i, 1) } {
                mstore8(add($to, $i), byte(0, mload(add($from, $i))))
            }
        }
    }""", ()),
    "_wordSlice": ("""function _wordSlice(uint256 v, uint256 n) private pure returns (bytes memory r) {
        // the low n bytes of v, big-endian (zero bytes on the left past 32)
        r = _alloc(n);
        if (n == 0) return r;
        assembly {
            switch lt(n, 32)
            case 1 { mstore(add(r, 32), shl(mul(8, sub(32, n)), v)) }
            default { mstore(add(add(r, 32), sub(n, 32)), v) }
        }
    }""", ("_alloc",)),
    "_maskBytes": ("""function _maskBytes(bytes memory x, uint256 size, uint256 offset, uint256 shift, uint256 n)
        private pure returns (bytes memory r)
    {
        // the low n bytes (big-endian, zero bytes on the left) of the integer
        // (X & ((2**size - 1) << offset)) << shift, X the big-endian value of
        // ALL the bytes of x (nothing is cut to a word); size, offset and
        // shift read as signed (negative: to the right)
        r = _alloc(n);
        unchecked {
            int256 h = int256(shift);
            int256 a = int256(offset); // the bits [a, b) of X the mask keeps
            int256 b = int256(x.length << 3);
            {
                int256 s = int256(size);
                if (s <= 0 || a >= b) return r;
                if (a >= 0 && s > b) s = b;
                if (a + s < b) b = a + s;
                if (a < 0) a = 0;
            }
            // moved by h and cut to r: the bits [a, b) of r are the bits [a - h, b - h) of X
            if (b <= a || h >= int256(n << 3) || h <= -b) return r;
            a = a + h > 0 ? a + h : int256(0);
            b = b + h < int256(n << 3) ? b + h : int256(n << 3);
            if (b <= a) return r;
            if (((a | b | h) & 7) == 0) {
                _copy(r, n - uint256(b >> 3), x, x.length - uint256((b - h) >> 3), uint256((b - a) >> 3));
            } else {
                _maskBits(r, x, a, b, h);
            }
        }
    }""", ("_alloc", "_copy", "_maskBits")),
    "_maskBits": ("""function _maskBits(bytes memory r, bytes memory x, int256 a, int256 b, int256 h) private pure {
        // the bits [a, b) of r := the bits [a - h, b - h) of x (big-endian values), byte by
        // byte: r's byte q from the right is (X >> (8 q - h)) & 0xff
        assembly {
            let $len := mload(x)
            for { let $q := sar(3, a) } slt($q, sar(3, add(b, 7))) { $q := add($q, 1) } {
                let $t := sub(shl(3, $q), h)
                let $u := sar(3, $t)
                let $v := 0
                if and(sgt($u, not(0)), slt($u, $len)) { $v := byte(0, mload(add(add(x, 31), sub($len, $u)))) }
                $u := add($u, 1)
                if and(sgt($u, not(0)), slt($u, $len)) {
                    $v := or($v, shl(8, byte(0, mload(add(add(x, 31), sub($len, $u))))))
                }
                $v := shr(and($t, 7), $v)
                let $lo := sub(a, shl(3, $q))
                if slt($lo, 0) { $lo := 0 }
                let $hi := sub(b, shl(3, $q))
                if sgt($hi, 8) { $hi := 8 }
                mstore8(add(add(r, 31), sub(mload(r), $q)), and($v, sub(shl($hi, 1), shl($lo, 1))))
            }
        }
    }""", ()),
    "_join": ("""function _join(bytes memory a, uint256 la, bytes memory b, uint256 lb) private pure returns (bytes memory r) {
        // a, then b from the offset la, cut to la + lb bytes; the lengths read
        // as signed (a negative part has no bytes and the next part starts that
        // much earlier): the parts of a range the original's memory holds, split
        // where a write was guessed to end
        unchecked {
            int256 n = int256(la) + int256(lb);
            r = _alloc(n > 0 ? uint256(n) : 0);
            if (n <= 0) return r;
            if (a.length > 0) _copy(r, 0, a, 0, a.length < uint256(n) ? a.length : uint256(n));
            int256 s = int256(la) < 0 ? -int256(la) : int256(0); // b's first byte that lands in r
            if (s >= int256(b.length) || int256(la) + s >= n) return r;
            int256 m = int256(b.length) - s;
            if (int256(la) + s + m > n) m = n - int256(la) - s;
            _copy(r, uint256(int256(la) + s), b, uint256(s), uint256(m));
        }
    }""", ("_alloc", "_copy")),
    "_bytesWord": ("""function _bytesWord(bytes memory b) private pure returns (uint256 v) {
        // big-endian value of at most 32 bytes
        uint256 n = b.length;
        if (n == 0) return 0;
        assembly { v := shr(sub(256, mul(8, n)), mload(add(b, 32))) }
    }""", ()),
    "_revert": ("function _revert(bytes memory d) private pure { assembly { revert(add(d, 32), mload(d)) } }", ()),
    "_return": ("function _return(bytes memory d) private pure { assembly { return(add(d, 32), mload(d)) } }", ()),
    "_bubble": ("function _bubble() private pure { assembly { returndatacopy(0, 0, returndatasize()) "
                "revert(0, returndatasize()) } }", ()),
    "_panic": ("""function _panic(uint256 code) private pure {
        assembly {
            mstore(0, shl(224, 0x4e487b71))
            mstore(4, code)
            revert(0, 0x24)
        }
    }""", ()),
    "_stop": ("function _stop() private pure { assembly { stop() } }", ()),
    "_invalid": ("function _invalid() private pure { assembly { invalid() } }", ()),
    "_unsupported": ("""function _unsupported() private pure returns (uint256) {
        // a construct of the decompiled code that has no translation (flagged)
        revert("scobelix: unsupported construct");
    }""", ()),
    "_log0": ("function _log0(bytes memory d) private { assembly { log0(add(d, 32), mload(d)) } }", ()),
    "_log1": ("function _log1(bytes memory d, uint256 t0) private { assembly { log1(add(d, 32), mload(d), t0) } }", ()),
    "_log2": ("function _log2(bytes memory d, uint256 t0, uint256 t1) private "
              "{ assembly { log2(add(d, 32), mload(d), t0, t1) } }", ()),
    "_log3": ("function _log3(bytes memory d, uint256 t0, uint256 t1, uint256 t2) private "
              "{ assembly { log3(add(d, 32), mload(d), t0, t1, t2) } }", ()),
    "_log4": ("function _log4(bytes memory d, uint256 t0, uint256 t1, uint256 t2, uint256 t3) private "
              "{ assembly { log4(add(d, 32), mload(d), t0, t1, t2, t3) } }", ()),
    "_callcode": ("""function _callcode(uint256 g, uint256 a, uint256 v, bytes memory d) private returns (bool ok) {
        assembly { ok := callcode(g, a, v, add(d, 32), mload(d), 0, 0) }
    }""", ()),
    "_create": ("""function _create(uint256 v, bytes memory code) private returns (uint256 a) {
        assembly { a := create(v, add(code, 32), mload(code)) }
    }""", ()),
    "_create2": ("""function _create2(uint256 v, bytes memory code, uint256 salt) private returns (uint256 a) {
        assembly { a := create2(v, add(code, 32), mload(code), salt) }
    }""", ()),
    "_vmGrow": ("""function _vmGrow(bytes memory m, uint256 p, uint256 n) private pure returns (bytes memory r) {
        // the original's memory, emulated: grow the buffer to cover [p, p + n)
        if (n == 0) return m; // an empty range touches no memory, at any offset
        if (p > 0xffffffff || n > 0xffffffff) _invalid(); // the original runs out of gas
        uint256 end = p + n;
        if (end <= m.length) return m;
        uint256 cap = 2 * m.length + 1024;
        if (cap < end) cap = end;
        cap = (cap + 31) & ~uint256(31);
        r = new bytes(cap);
        for (uint256 i = 0; i < m.length; i += 32) {
            assembly { mstore(add(add(r, 32), i), mload(add(add(m, 32), i))) }
        }
    }""", ("_invalid",)),
    "_vmStore": ("""function _vmStore(bytes memory m, uint256 p, uint256 v) private pure returns (bytes memory) {
        m = _vmGrow(m, p, 32);
        assembly { mstore(add(add(m, 32), p), v) }
        return m;
    }""", ("_vmGrow",)),
    "_vmWrite": ("""function _vmWrite(bytes memory m, uint256 p, bytes memory d) private pure returns (bytes memory) {
        m = _vmGrow(m, p, d.length);
        _copy(m, p, d, 0, d.length);
        return m;
    }""", ("_vmGrow", "_copy")),
    "_vmSlice": ("""function _vmSlice(bytes memory m, uint256 p, uint256 n) private pure returns (bytes memory r) {
        // the original's memory [p, p + n): zero where it was never written
        if (n == 0) return r; // an empty range touches no memory, at any offset
        if (p > 0xffffffff) _invalid();
        r = _alloc(n);
        if (p < m.length) _copy(r, 0, m, p, m.length - p < n ? m.length - p : n);
    }""", ("_invalid", "_alloc", "_copy")),
    "_vmLoad": ("""function _vmLoad(bytes memory m, uint256 p) private pure returns (uint256 v) {
        bytes memory w = _vmSlice(m, p, 32);
        assembly { v := mload(add(w, 32)) }
    }""", ("_vmSlice",)),
}


_MACHINERY_RE = re.compile(r"\bunchecked\b|\bassembly\b|\b(?:_vm|_l|_ok)\b|\b(?:"
                           + "|".join(sorted(map(re.escape, _HELPERS), key=len, reverse=True)) + r")\(")


def exact_machinery(text: str) -> bool:
    """`text` (a rendered body) uses what only the exact form needs: a
    helper, an `unchecked` block, inline assembly, the emulated memory or
    locals kept in memory.  A body without any is already the usual
    Solidity of its behaviour."""
    return bool(_MACHINERY_RE.search(text))


class Helpers:
    """The helper functions a contract uses (emitted once, in a fixed order)."""

    def __init__(self):
        self.used: Set[str] = set()

    def use(self, name: str) -> str:
        if name not in self.used:
            self.used.add(name)
            for dep in _HELPERS[name][1]:
                self.use(dep)
        return name

    def sources(self) -> List[str]:
        out = []
        for n in _HELPERS:
            if n in self.used:
                lines = _HELPERS[n][0].split("\n")
                out.append("\n".join(lines[:1] + [l[4:] if l.startswith("    ") else l for l in lines[1:]]))
        return out


# ---------------------------------------------------------------- literals


def literal(v: int) -> str:
    """A uint256 literal (hex for large values; never an address-looking
    40-digit hex literal)."""
    if v == ir.WORD_MAX:
        return "type(uint256).max"
    if v < 1 << 32 and (v < 0x10000 or not re.fullmatch(r"(f|0)+", f"{v:x}")):
        return str(v)
    h = f"{v:x}"
    if len(h) % 2:
        h = "0" + h
    if len(h) == 40:
        h = "00" + h
    return "0x" + h


def address_literal(v: int) -> str:
    """The address whose word is v (v < 2**160): `address(0)`, a small
    number through uint160, else the EIP-55 checksummed literal solc wants."""
    if v == 0:
        return "address(0)"
    if v < 1 << 32:
        return f"address(uint160({v}))"
    from eth_utils import keccak

    h = f"{v:040x}"
    k = keccak(h.encode()).hex()
    return "address(0x" + "".join(c.upper() if c.isalpha() and int(k[i], 16) >= 8 else c
                                  for i, c in enumerate(h)) + ")"


def max_literal(v: int) -> Optional[str]:
    """`type(uintN).max` for 2**N - 1 (N a multiple of 8 below 256)."""
    n = (v + 1).bit_length() - 1
    return f"type(uint{n}).max" if 8 <= n < 256 and n % 8 == 0 and v == (1 << n) - 1 else None


_TIME_UNITS = (("days", 86400), ("hours", 3600), ("minutes", 60))


def time_literal(v: int) -> Optional[str]:
    """A whole number of days, hours or minutes as Solidity's time units
    (the same rational literal: `1 days` is 86400)."""
    for unit, seconds in _TIME_UNITS:
        if v >= seconds and v % seconds == 0 and v // seconds < 100000:
            return f"{v // seconds} {unit}"
    return None


def _is_timestamp(e) -> bool:
    while isinstance(e, ir.Cast):
        e = e.value
    return isinstance(e, ir.Env) and e.name == "timestamp"


_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def string_literal(data: bytes) -> str:
    """A Solidity expression of type string whose bytes are `data`: a
    literal, or `string(bytes(hex"..."))` when `data` is not UTF-8.  Only
    printable characters are written as they are; the others (controls,
    line and paragraph separators, bidirectional overrides, which solc
    rejects in source text) become escape sequences of their bytes."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return f'string(bytes(hex"{data.hex()}"))'
    out, uni = [], False
    for ch in text:
        o = ord(ch)
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif 0x20 <= o < 0x7F:
            out.append(ch)
        elif o > 0x7F and (unicodedata.category(ch)[0] in "LMNPS" or unicodedata.category(ch) == "Zs"):
            out.append(ch)
            uni = True
        else:
            out.append("".join(f"\\x{b:02x}" for b in ch.encode("utf-8")))
    return ("unicode" if uni else "") + '"' + "".join(out) + '"'


def comment_text(text, limit: Optional[int] = None) -> str:
    """`text` as the content of a `//` comment: printable ASCII only (a line
    separator ends a comment for solc, bidirectional controls and other
    characters are rejected), cut to `limit` characters."""
    s = "".join(c if " " <= c <= "~" else "?" for c in str(text))
    return s if limit is None else s[:limit]


# ---------------------------------------------------------------- reserved names

# words solc rejects as function or parameter names (keywords, reserved
# words, units, elementary types)
_KEYWORDS = frozenset("""
abstract after alias anonymous apply as assembly auto bool break byte bytes calldata case catch constant
constructor continue contract copyof days default define delete do else emit enum ether event external
false final fixed for function gwei hex hours if immutable implements import in indexed inline interface
internal is let library macro mapping match memory minutes modifier mutable new null of override partial
payable pragma private promise public pure reference relocatable return returns sealed seconds sizeof
static storage string struct supports switch true try type typedef typeof ufixed uint int unchecked unicode
using var view virtual wei weeks while years address
""".split())
# builtins the generated code calls or reads: a declaration of the same
# name would shadow them
_BUILTINS = frozenset("""
abi addmod assert block blobhash blockhash ecrecover gasleft keccak256 msg mulmod require revert
ripemd160 selfdestruct sha256 super this tx
""".split())
# contextual words: accepted by solc as names, avoided for parameters
_CONTEXTUAL = frozenset("error fallback receive global transient layout at from leave now suicide sha3 throw "
                        "szabo finney _".split())
_TYPE_NAME_RE = re.compile(r"(u?int|bytes)\d*|u?fixed(\d+x\d+)?")
# names the contract assembly and the renderer declare; the helpers' own
# assembly variables (`$`: no source name has it) are declared in the
# contract's scope too: an assembly variable that shadows any declaration
# of the contract (a state variable `to`, a function `size`) is an error
_YUL_NAMES = frozenset({"$size", "$avail", "$to", "$from", "$i", "$len", "$q", "$t", "$u", "$v", "$lo", "$hi"})
_GENERATED_NAMES = frozenset({"_vm", "_l", "_ok", "_ORIGINAL_CODE", "_receive_body"}) | _YUL_NAMES
_GENERATED_RE = re.compile(r"_fn_[0-9a-f]{8}|_next\d+|S\d+|c\d+_(ok|addr)|_\w+_[0-9a-f]{8}")


def reserved_name(name: str, parameter: bool = False) -> bool:
    """True if `name` cannot be declared in the generated contract: a solc
    keyword or type name, a builtin the generated code uses, or a name the
    generator declares itself (helpers, routed functions, structs, locals).
    `parameter`: also the contextual words that cannot name a parameter."""
    return (name in _KEYWORDS or name in _BUILTINS or name in _HELPERS or name in _GENERATED_NAMES
            or bool(_TYPE_NAME_RE.fullmatch(name)) or bool(_GENERATED_RE.fullmatch(name))
            or (parameter and name in _CONTEXTUAL))


# ---------------------------------------------------------------- contexts


@dataclasses.dataclass
class RenderContext:
    """Contract-level rendering facts."""

    target: Tuple[int, int, int] = (0, 8, 19)
    helpers: Helpers = dataclasses.field(default_factory=Helpers)
    abi_v2: bool = True
    uses_code_constant: bool = False
    features: Dict[str, Tuple[int, int, int]] = dataclasses.field(default_factory=dict)
    # a function no pass rewrote whose exact form needs no helper is reported idiomatic
    trivial_idiomatic: bool = True

    def at_least(self, *version) -> bool:
        return self.target >= tuple(version)

    def need(self, feature: str, version: Tuple[int, int, int]) -> None:
        """Record that the text uses `feature`, available from solc `version`."""
        self.features[feature] = version


@dataclasses.dataclass
class EntryRender:
    """How one entry point is declared, as far as its body is concerned."""

    kind: str  # "external" | "fallback" | "receive" | "internal"
    payable: bool = False
    # declared return types; () for the fallback of a typed router (it
    # declares `returns (bytes memory)`: stops and empty returns are `return "";`)
    returns: Optional[Tuple[SolType, ...]] = None
    word_views: Dict[int, str] = dataclasses.field(default_factory=dict)  # head word -> uint256 expression
    reserved: Set[str] = dataclasses.field(default_factory=set)  # names already taken (parameters)
    stack_slots: int = 0  # stack slots the parameters and return values take
    stack_margin: int = 0  # slots counted on top of them, for the choice of memory locals only (may be negative)
    word_bits: Dict[int, int] = dataclasses.field(default_factory=dict)  # head word -> bit width of its view
    # head word -> (name, type) of a declared dynamic parameter: its length
    # word and its bytes are read through the parameter (see x_CalldataWord
    # and bytes_)
    dynamic_views: Dict[int, Tuple[str, SolType]] = dataclasses.field(default_factory=dict)
    # head word -> (name, type) of a declared value parameter that carries
    # the word itself (validated, or full-width): a typed use of the word
    # in that type is the parameter (see typed)
    word_params: Dict[int, Tuple[str, SolType]] = dataclasses.field(default_factory=dict)
    # (name, stack slots) of each parameter, in declaration order (the first
    # one deepest), when the function body holds them on the stack under its
    # locals (an external function's); empty: every statement is counted as
    # reaching the deepest slot of stack_slots (see _FunctionRenderer._frame_for)
    param_slots: Tuple[Tuple[str, int], ...] = ()


# ---------------------------------------------------------------- the renderer


def _strip(s: str) -> str:
    """Drop one pair of outer parentheses enclosing the whole expression."""
    if s.startswith("(") and s.endswith(")"):
        depth = 0
        for i, ch in enumerate(s):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0 and i < len(s) - 1:
                return s
        return s[1:-1]
    return s


_ADDRESS_ATOMS = {"caller": "msg.sender", "address": "address(this)", "origin": "tx.origin",
                  "coinbase": "block.coinbase"}

_LITERAL_RE = re.compile(r"(0x[0-9a-fA-F]+|[0-9]+)")
_ADDRESS_VIEW_RE = re.compile(r"uint256\(uint160\(([A-Za-z_$][A-Za-z0-9_$]*)\)\)")  # see contract._word_views


def _typed_word(text: str) -> bool:
    """The rendered expression is uint256-typed (not a bare literal)."""
    return not _LITERAL_RE.fullmatch(_strip(text))


def _call_arg(text: str, name: str) -> Optional[str]:
    """The argument text when `text` is exactly `name(<argument>)`."""
    if not (text.startswith(name + "(") and text.endswith(")")):
        return None
    depth = 0
    for i in range(len(name), len(text)):
        depth += text[i] == "("
        depth -= text[i] == ")"
        if depth == 0:
            return text[len(name) + 1:-1] if i == len(text) - 1 else None
    return None


def _atom(s: str) -> str:
    """`s` usable as an operand: parenthesised when it has an operator at
    its top level (the renderer writes binary operators between spaces)."""
    depth = 0
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == " " and depth == 0:
            return f"({s})"
    return s


def _is_wrapping(n) -> bool:
    """Wrapping (EVM) arithmetic that Solidity 0.8 checks outside `unchecked`
    (an unchecked signed division wraps min / -1)."""
    if isinstance(n, ir.Op):
        return n.op in ("add", "sub", "mul")
    if isinstance(n, ir.Typed):
        return not n.checked and (n.op in ("add", "sub", "mul") or n.op == "div" and n.ty.startswith("int"))
    if isinstance(n, ir.Assign):
        if n.checked is True:
            return False
        signed = n.checked is False and isinstance(n.target, ir.StateRef) and n.target.ty.startswith("int")
        return n.op in ("+", "-", "*", "++", "--") or (n.op == "/" and signed)
    return False


def _is_checked(n) -> bool:
    return (isinstance(n, ir.Typed) and n.checked) or (isinstance(n, ir.Assign) and n.checked is True)


_SIZED = (ir.CalldataSlice, ir.ReturnData, ir.CodeSlice, ir.ExtCodeSlice, ir.ZeroBytes, ir.WordSlice, ir.MemSlice,
          ir.MaskBytes)


def _small(e) -> bool:
    return isinstance(e, ir.Const) and e.value <= 0xFFFFFFFF


def _may_halt(e) -> bool:
    """Evaluating `e` can end the call: an untranslated part, a checked or
    Solidity division, memory or a copy no gas could pay for, a state
    variable read at an index (Solidity's bounds check, Panic 0x32: the
    arith pass leaves it the only one when it drops the original's guard).
    Such an operand must be evaluated even where a short-circuit would skip
    it."""
    if ir.reads_indexed_state(e):
        return True
    for n in ir.walk(e):
        if isinstance(n, (ir.UnstructuredExpr, ir.UnstructuredBytes)):
            return True
        if isinstance(n, ir.Typed) and n.op in ("div", "mod") and isinstance(n.args[1], ir.Const) \
                and n.args[1].value and not (n.checked and n.ty.startswith("int") and n.args[1].value == ir.WORD_MAX):
            continue  # a constant divisor other than 0 (and -1 for a checked signed division)
        if isinstance(n, ir.Typed) and (n.checked or n.op in ("div", "mod")):
            return True
        if isinstance(n, ir.MLoad) and not _small(n.addr):
            return True
        if isinstance(n, _SIZED) and not (_small(n.length) and (not isinstance(n, ir.MemSlice) or _small(n.start))):
            return True
    return False


def _moot(s) -> bool:
    """`if (c) {X} else {X}`: the test can be left out, written once.  Not
    when evaluating c can end the call (_may_halt), nor when c reads a state
    variable at an index (ir.reads_indexed_state: its bounds check may be
    the only one left)."""
    return s.then == s.orelse and not _may_halt(s.cond) and not ir.reads_indexed_state(s.cond)


def _value_type(ty: str) -> Optional[SolType]:
    """The SolType of a value type name (None for anything else)."""
    try:
        t = parse_type(ty)
    except ValueError:
        return None
    return t if t.kind in ("uint", "int", "address", "bool", "bytes") else None


_UINT256 = parse_type("uint256")
_BOOL = parse_type("bool")
_ADDRESS = parse_type("address")


_CHAIN = 6  # operands of one flat chain (the legacy code generator keeps one slot per level)
_HOIST_CHAIN = 3  # arguments of one abi.encodePacked in a statement that needs locals (stack.py)
_STACK_BUDGET = 11  # locals + parameters + return values kept on the stack, beyond: memory arrays


def _balanced(items: List[str], sym: str) -> str:
    """items joined by an associative operator, as a balanced tree."""
    if len(items) <= _CHAIN:
        return "(" + sym.join(items) + ")"
    half = len(items) // 2
    return f"({_balanced(items[:half], sym)}{sym}{_balanced(items[half:], sym)})"


def _packed_tree(args: List[str], chain: int = _CHAIN) -> str:
    """abi.encodePacked of many arguments, nested so no call takes more than
    `chain` (the packed encoding of bytes is the bytes themselves)."""
    if len(args) <= chain:
        return "abi.encodePacked(" + ", ".join(args) + ")"
    chunks = [_packed_tree(args[i:i + chain], chain) for i in range(0, len(args), chain)]
    return _packed_tree(chunks, chain)


def _uses(name: str, text: str) -> int:
    """Occurrences of a local (`_h_2`) or of an entry of a memory array
    (`_t[3]`: its closing bracket ends it) in `text`."""
    if name.endswith("]"):
        return text.count(name)
    return len(re.findall(rf"\b{re.escape(name)}\b", text))


def _unread(names: Sequence[Tuple[ir.Node, str, int]], text: str) -> List[ir.Node]:
    """The operands of `names` (operand, local, occurrences that define it)
    whose local `text` never reads: it occurs no more often than it is
    defined (`uint256 _h = e;` once, `uint256 _h; { ...; _h = e; }` twice)."""
    return [x for x, name, defs in names if _uses(name, text) <= defs]


def _outer_continues(body, loops: Tuple[str, ...]) -> bool:
    """`body` (inside the loops `loops`) continues a loop from a loop nested in it."""
    for s in body:
        if isinstance(s, ir.Continue) and s.loop_id in loops[:-1]:
            return True
        if isinstance(s, (ir.While, ir.For)) and _outer_continues(s.body, loops + (s.loop_id,)):
            return True
        if isinstance(s, ir.If) and (_outer_continues(s.then, loops) or _outer_continues(s.orelse, loops)):
            return True
    return False


def _loop_exits(loop: ir.Stmt) -> Set[str]:
    """The loops a continue in `loop` goes to, other than `loop` and the
    loops in it."""
    inner = {loop.loop_id}
    out: Set[str] = set()

    def walk(body):
        for s in body:
            if isinstance(s, ir.Continue) and s.loop_id not in inner:
                out.add(s.loop_id)
            elif isinstance(s, (ir.While, ir.For)):
                inner.add(s.loop_id)
                walk(s.body)
            elif isinstance(s, ir.If):
                walk(s.then)
                walk(s.orelse)

    walk(loop.body)
    return out


def _count_locals(body) -> Tuple[int, int]:
    """(word locals, bool call results) a function body declares."""
    words, bools = set(), set()
    for n in ir.walk_all(body):
        if isinstance(n, ir.Local):
            words.add(n.name)
        elif isinstance(n, (ir.ExtCall, ir.Precompile)):
            bools.add(n.call_id)
            if isinstance(n, ir.Precompile) and n.output:
                words.add(n.output)
            if isinstance(n, ir.ExtCall) and n.ret:
                words.add(f"c{n.call_id}_ret")
        elif isinstance(n, ir.Create):
            words.add(f"c{n.call_id}_addr")
        elif isinstance(n, ir.HighCall):
            words.update(f"c{n.call_id}_r{i}" for i, out in enumerate(n.outs) if out)
        elif isinstance(n, ir.Transfer) and n.send and n.ok:
            bools.add(n.call_id)
        elif isinstance(n, ir.Builtin) and n.out:
            words.add(f"c{n.call_id}_r0")
    return len(words), len(bools)


def _live_in_place(body: Sequence[ir.Stmt], sites: Set[int]) -> Tuple[Dict[int, int], Dict[int, int]]:
    """(id(statement) -> the locals declared in place that are in scope
    where it runs, id(loop) -> the same in its condition and body).  Such a
    local (one of the assignments `sites`, `uint256 x = value;`) is in scope
    from its declaration to the end of its block; a `for` header's (its one
    `init` assignment) in the loop.  The other locals are declared at the
    top of the function and always count.  A statement met in several
    places keeps the most."""
    at: Dict[int, int] = {}
    loops: Dict[int, int] = {}

    def block(stmts: Sequence[ir.Stmt], live: int) -> None:
        for s in stmts:
            at[id(s)] = max(at.get(id(s), 0), live)
            inner = live
            if isinstance(s, (ir.For, ir.While)):
                if isinstance(s, ir.For) and len(s.init) == 1 and id(s.init[0]) in sites:
                    inner = live + 1
                loops[id(s)] = max(loops.get(id(s), 0), inner)
            for f in dataclasses.fields(s):
                v = getattr(s, f.name)
                if isinstance(v, tuple) and v and all(isinstance(x, ir.Stmt) for x in v):
                    block(v, inner if f.name in ("body", "step") else live)
            if id(s) in sites:
                live += 1

    block(body, 0)
    return at, loops


def _const(e) -> Optional[int]:
    return e.value if isinstance(e, ir.Const) else None


def _head_word(e) -> Optional[int]:
    """The ABI head word index `e` reads (a Param, or calldataload(4 + 32 w))."""
    if isinstance(e, ir.Param):
        return e.index
    if isinstance(e, ir.CalldataWord) and isinstance(e.offset, ir.Const):
        off = e.offset.value
        if off >= 4 and (off - 4) % 32 == 0:
            return (off - 4) // 32
    return None


def _cleaned(e: ir.Expr, t: SolType) -> ir.Expr:
    """x when e is the cleanup of type t applied to x (the mask of a uintN /
    address / bytesN, the bool normalisation, the sign extension of an
    intN), else e."""
    if isinstance(e, ir.Mask) and (e.offset, e.shl) == (0, 0) and t.kind in ("uint", "address") \
            and e.size == (160 if t.kind == "address" else t.bits):
        return e.value
    if isinstance(e, ir.Mask) and t.kind == "bytes" and (e.size, e.offset, e.shl) == (t.bits, 256 - t.bits, 0):
        return e.value
    if t.kind == "bool" and isinstance(e, ir.Op) and e.op == "iszero" and isinstance(e.args[0], ir.Op) \
            and e.args[0].op == "iszero":
        return e.args[0].args[0]
    if t.kind == "int" and isinstance(e, ir.Op) and e.op == "signextend" and e.args[0] == ir.Const(t.bits // 8 - 1):
        return e.args[1]
    return e


def _bits_field(f) -> Optional[int]:
    if isinstance(f, int) and not isinstance(f, bool):
        return f
    v = ir.evaluate(f) if isinstance(f, ir.Expr) else None
    return None if v is None else ir.to_signed(v)


class _FunctionRenderer:
    def __init__(self, fn: ir.Function, entry: EntryRender, ctx: RenderContext):
        self.fn = fn
        self.entry = entry
        self.ctx = ctx
        self.h = ctx.helpers
        self.flags: Set[str] = set()
        self.memory = ir.contains(fn.body, (ir.MLoad, ir.MemSlice))
        self.loops: List[str] = []
        self.taken = set(entry.reserved)
        self.locals: Dict[str, str] = {}
        self.decls: List[str] = []
        # too many locals for the EVM stack window: keep them in memory arrays
        words, bools = _count_locals(fn.body)
        self.array_mode = words + bools + entry.stack_slots + int(self.memory) > _STACK_BUDGET
        self.stack_locals = 2 if self.array_mode else words + bools
        # subexpressions written into locals before the statement that uses
        # them (see hoist_plan): id(node) -> (local, kind W | B | "bytes")
        self.hoist_ids: Dict[int, Tuple[str, str]] = {}
        # the locals of the statement being written: (operand, name, occurrences that define it)
        self.hoisted_names: List[Tuple[ir.Node, str, int]] = []
        self.scope_slots = 0  # stack slots of such locals the current statement sits under
        # the plans already made, by statement or loop condition, frame and
        # skipped operands: a statement is written again whenever an
        # enclosing one is (stmt, _hoisted); the node is kept with its plan
        self.plans: Dict[tuple, Tuple[ir.Node, Optional[Tuple[str, list]]]] = {}
        self.packed_chain = _CHAIN  # arguments per abi.encodePacked (fewer in a statement with locals)
        # a continue of an enclosing loop from an inner one: the word naming
        # that loop while the inner loops are left (s_Continue, _after_loop)
        self.go_name: Optional[str] = None
        self.go_slot = int(_outer_continues(fn.body, ()))
        # the bool a condition with locals goes into: one for the function (an
        # outer `if` has jumped when an inner one sets it), its slot reserved
        # when a condition may need it
        self.cond_name: Optional[str] = None
        self.cond_slot = 0
        model, base = stack.StackModel(self._leaf, _CHAIN), self._frame()
        self.cond_slot = int(any(model.need(n.cond, set(), {}) + 2 + base > stack.WINDOW
                                 for n in ir.walk_all(fn.body) if isinstance(n, (ir.If, ir.While, ir.For))))
        self.n_words = self.n_bools = 0
        self.checked = any(_is_checked(n) for n in ir.walk_all(fn.body))
        # Without checked operations the body is one `unchecked` block.  With
        # them, `wrapping` tells whether the text being written is inside an
        # `unchecked` block: a statement without checked operations gets
        # one of its own (see stmt), and wrapping arithmetic anywhere else
        # goes through the _wadd / _wsub / _wmul helpers, so that it wraps
        # in every position (conditions, loop tests, operands of checked
        # operations) and is evaluated exactly where the IR evaluates it.
        self.wrapping = not self.checked
        self._facts: Dict[int, Tuple[bool, bool]] = {}  # id(node) -> (has checked, has wrapping)
        # locals the calls declare where they are made (calls pass): call id ->
        # name of the success flag / of the return data; (call id, index) ->
        # (text, type) of a returned value (type None: a uint256 word)
        self.declared_ok: Dict[int, str] = {}
        self.declared_ret: Dict[int, str] = {}
        self.results: Dict[Tuple[int, int], Tuple[str, Optional[SolType]]] = {}
        # (call id, index) -> the call written where its only value is used
        self.deferred: Dict[Tuple[int, int], ir.Stmt] = {}
        self._result_uses: Optional[Dict[Tuple[int, int], int]] = None
        self.in_place = self._in_place()
        # the locals declared in place that are in scope at each statement,
        # and in each loop's condition (its header's local too): _frame
        sites = scopes.sites(self.fn.body) if self.in_place else {}
        self.live_at, self.loop_live = _live_in_place(
            self.fn.body, {id(a) for name in self.in_place for a in sites.get(name, ())})

    # ------------------------------------------------------------ names

    def _in_place(self) -> Set[str]:
        """The locals declared where they are set (`uint256 x = value;`):
        those whose marked assignments (Assign.declare, loops pass) are
        exactly the sites scopes.sites finds in this body, none of which
        needs an `unchecked` block of its own (the local would end with it)."""
        marked: Dict[str, int] = {}
        for n in ir.walk_all(self.fn.body):
            if isinstance(n, ir.Assign) and n.declare and isinstance(n.target, ir.Local):
                marked[n.target.name] = marked.get(n.target.name, 0) + 1
        if not marked or self.array_mode:
            return set()
        out = set()
        for name, where in scopes.sites(self.fn.body).items():
            if marked.get(name) == len(where) and all(a.declare for a in where) \
                    and (self.wrapping or all(self.facts((a,)) != (False, True) for a in where)):
                out.add(name)
        return out

    def local(self, name: str) -> str:
        if name not in self.locals:
            if self.array_mode:
                self.locals[name] = f"_l[{self.n_words}]"
                self.n_words += 1
                return self.locals[name]
            out, k = name, 1
            # (c<N>_addr is the renderer's own name for a created address)
            while out in self.taken or (reserved_name(out, parameter=True) and not _GENERATED_RE.fullmatch(out)):
                k += 1
                out = f"{name}_{k}"
            self.taken.add(out)
            self.locals[name] = out
            if name not in self.in_place:
                self.decls.append(f"uint256 {out};")
        return self.locals[name]

    def fresh(self, base: str) -> str:
        """A new name for a local declared where it is set (`base`, or
        `base_2`, ...: unique in the function, never a reserved name)."""
        out, k = base, 1
        while out in self.taken or reserved_name(out, parameter=True):
            k += 1
            out = f"{base}_{k}"
        self.taken.add(out)
        return out

    def call_ok(self, cid: int) -> str:
        if cid in self.declared_ok:
            return self.declared_ok[cid]
        name = f"c{cid}_ok"
        if self.array_mode:
            if name not in self.locals:
                self.locals[name] = f"_ok[{self.n_bools}]"
                self.n_bools += 1
            return self.locals[name]
        if name not in self.taken:
            self.taken.add(name)
            self.decls.append(f"bool {name};")
        return name

    def call_addr(self, cid: int) -> str:
        return self.local(f"c{cid}_addr")

    # ------------------------------------------------------------ expressions

    def w(self, e: ir.Expr) -> str:
        """`e` as a uint256-typed Solidity expression."""
        s, kind = self.expr(e)
        if kind == B:
            return f"uint256({_strip(s)} ? 1 : 0)"
        return s

    def _bool_param(self, e: ir.Expr) -> Optional[str]:
        """The name of the declared bool parameter whose word `e` is (the
        decoder validated it: 0 or 1)."""
        w = _head_word(_cleaned(e, _BOOL))
        if w is not None and w in self.entry.word_params and self.entry.word_params[w][1].kind == "bool":
            return self.entry.word_params[w][0]
        return None

    def b(self, e: ir.Expr) -> str:
        """`e != 0` as a bool Solidity expression."""
        got = self.hoist_ids.get(id(e)) if self.hoist_ids else None
        if got is not None and got[1] != "bytes":
            return got[0] if got[1] == B else f"({got[0]} != 0)"
        if isinstance(e, ir.Const):
            return "true" if e.value else "false"
        name = self._bool_param(e)
        if name is not None:
            return name
        diff = _difference(e)
        if diff is not None:  # a - b != 0
            return self._compare_addresses(diff[0], diff[1], "!=") or f"({self.w(diff[0])} != {self.w(diff[1])})"
        s, kind = self.expr(e)
        return s if kind == B else f"({s} != 0)"

    def expr(self, e: ir.Expr) -> Tuple[str, str]:
        got = self.hoist_ids.get(id(e)) if self.hoist_ids else None
        if got is not None and got[1] != "bytes":
            return got
        if isinstance(e, (ir.Op, ir.Mask, ir.Field, ir.Ternary, ir.BytesWord)):
            v = ir.evaluate(e)
            if v is not None:
                return literal(v), W
        method = getattr(self, "x_" + type(e).__name__, None)
        if method is None:
            self.flags.add("unstructured")
            return f"{self.h.use('_unsupported')}()", W
        return method(e)

    def x_Const(self, e):
        return literal(e.value), W

    def x_Env(self, e):
        n = e.name
        if n == "caller":
            return "uint256(uint160(msg.sender))", W
        if n == "callvalue":
            if self.entry.payable and self.entry.kind != "internal":
                return "msg.value", W
            return f"{self.h.use('_callvalue')}()", W
        if n == "calldatasize":
            return "msg.data.length", W
        if n == "address":
            return "uint256(uint160(address(this)))", W
        if n == "origin":
            return "uint256(uint160(tx.origin))", W
        if n == "timestamp":
            return "block.timestamp", W
        if n == "number":
            return "block.number", W
        if n == "gas":
            return "gasleft()", W
        if n == "gaslimit":
            return "block.gaslimit", W
        if n == "gasprice":
            return "tx.gasprice", W
        if n == "chainid":
            return "block.chainid", W
        if n == "basefee":
            self.ctx.need("block.basefee", (0, 8, 7))
            return "block.basefee", W
        if n == "coinbase":
            return "uint256(uint160(address(block.coinbase)))", W
        if n in ("prevrandao", "difficulty"):
            if self.ctx.at_least(0, 8, 18):
                self.ctx.need("block.prevrandao", (0, 8, 18))
                return "block.prevrandao", W
            return "block.difficulty", W
        if n == "blobbasefee":
            self.ctx.need("block.blobbasefee", (0, 8, 24))
            return "block.blobbasefee", W
        if n == "selfbalance":
            return "address(this).balance", W
        self.flags.add("unstructured")
        return f"{self.h.use('_unsupported')}()", W

    def x_CalldataWord(self, e):
        off = _const(e.offset)
        if off is not None and off >= 4 and (off - 4) % 32 == 0:
            view = self.entry.word_views.get((off - 4) // 32)
            if view is not None:
                return view, W
        dyn = self._dynamic_param(e.offset, 4)
        if dyn is not None:
            name, t = dyn  # the length word of a declared dynamic parameter
            return (f"bytes({name}).length" if t.kind == "string" else f"{name}.length"), W
        return f"{self.h.use('_calldataload')}({_strip(self.w(e.offset))})", W

    def x_Param(self, e):
        return self.x_CalldataWord(ir.CalldataWord(ir.Const(4 + 32 * e.index)))

    def _dynamic_param(self, e: ir.Expr, k: int) -> Optional[Tuple[str, SolType]]:
        """(name, type) when `e` is `k + offset word` of a declared dynamic
        parameter (its length word is at calldata 4 + offset, its data at
        36 + offset)."""
        if not self.entry.dynamic_views or not (isinstance(e, ir.Op) and e.op == "add" and len(e.args) == 2):
            return None
        for a, b in ((e.args[0], e.args[1]), (e.args[1], e.args[0])):
            w = _head_word(b)
            if a == ir.Const(k) and w is not None and w in self.entry.dynamic_views:
                return self.entry.dynamic_views[w]
        return None

    def x_Local(self, e):
        return self.local(e.name), W

    def x_Sload(self, e):
        return f"{self.h.use('_sload')}({_strip(self.w(e.slot))})", W

    def x_Field(self, e):
        off, size = ir.field_bits(e.offset), ir.field_bits(e.size)  # unsigned, like _field
        if off == 0 and size is not None and self.bits(e.value) <= size:
            return self.expr(e.value)
        if off is not None and size is not None and (off >= 256 or size == 0):
            return "0", W
        v = self.w(e.value)
        if off is not None and size is not None:
            shifted = v if off == 0 else f"({v} >> {off})"
            if off + size >= 256:
                return shifted, W
            if size % 8 == 0:
                return f"uint256(uint{size}({_strip(shifted)}))", W
            return f"({shifted} & {literal((1 << size) - 1)})", W
        o = _strip(self._bitfield(e.offset))
        s = _strip(self._bitfield(e.size))
        return f"{self.h.use('_field')}({_strip(v)}, {o}, {s})", W

    def _bitfield(self, f) -> str:
        if isinstance(f, int) and not isinstance(f, bool):
            return literal(f % ir.WORD_MOD)
        return self.w(f)

    def x_Op(self, e):
        op, args = e.op, e.args
        folded = ir.evaluate(e) if all(isinstance(a, ir.Const) for a in args) else None
        if folded is not None:
            return literal(folded), W
        if op == "add":
            return self._add(args), W
        if op == "mul":
            neg = _negation(e)
            if neg is not None:
                return self._sub("0", self.w(neg)), W
            return self._chain([self.w(a) for a in args], " * ", "_wmul"), W
        if op == "sub":
            return self._sub(self.w(args[0]), self.w(args[1])), W
        if op in ("div", "mod"):
            d = _const(args[1])
            if d:
                return f"({self.w(args[0])} {'/' if op == 'div' else '%'} {literal(d)})", W
            return self._helper("_" + op, args), W
        if op in ("sdiv", "smod", "exp", "signextend", "byte", "sar"):
            return self._helper("_" + op, args), W
        if op in ("addmod", "mulmod"):
            m = _const(args[2])
            if m:
                return f"{op}({self.w(args[0])}, {self.w(args[1])}, {literal(m)})", W
            return self._helper("_" + op, args), W
        if op == "shl":
            return f"({self._shift_base(args[1])} << {self.w(args[0])})", W
        if op == "shr":
            return f"({self._shift_base(args[1])} >> {self.w(args[0])})", W
        if op in ("lt", "gt"):
            return f"({self._cmp_operand(args[0])} {'<' if op == 'lt' else '>'} {self._cmp_operand(args[1])})", B
        if op in ("slt", "sgt"):
            return f"({self.signed(args[0])} {'<' if op == 'slt' else '>'} {self.signed(args[1])})", B
        if op == "eq":
            return self._compare_addresses(args[0], args[1], "==") or f"({self.w(args[0])} == {self.w(args[1])})", B
        if op == "iszero":
            return self._iszero(args[0]), B
        if op in ("and", "or"):
            # && / || skip their right operands, which the opcode evaluates
            if all(is_boolean(a) for a in args) and not any(_may_halt(a) for a in args[1:]):
                sym = " && " if op == "and" else " || "
                return _balanced([self.b(a) for a in args], sym), B
            sym = " & " if op == "and" else " | "
            return _balanced([self.w(a) for a in args], sym), W
        if op == "xor":
            if len(args) == 2 and all(is_boolean(a) for a in args):
                return f"({self.b(args[0])} != {self.b(args[1])})", B
            return _balanced([self.w(a) for a in args], " ^ "), W
        if op == "not":
            return f"(~{self._shift_base(args[0])})", W
        self.flags.add("unstructured")
        return f"{self.h.use('_unsupported')}()", W

    def _shift_base(self, e) -> str:
        """`e` as an expression of type uint256 (a literal gets a conversion:
        shifts, `~`, ternaries and conversions take their type from it)."""
        s = self.w(e)
        return s if _typed_word(s) else f"uint256({_strip(s)})"

    def signed(self, e) -> str:
        """The word reinterpreted as int256 (two's complement)."""
        if isinstance(e, ir.Const):
            v = ir.to_signed(e.value)  # a constant: its signed value
            return f"int256({literal(v)})" if v >= 0 else f"int256(-{literal(-v)})"
        return f"int256({_strip(self._shift_base(e))})"

    def _helper(self, name, args) -> str:
        return f"{self.h.use(name)}(" + ", ".join(_strip(self.w(a)) for a in args) + ")"

    def _chain(self, items: List[str], sym: str, helper: str) -> str:
        """Wrapping `sym` over items: the operator inside `unchecked`, else a
        balanced tree of helper calls."""
        if self.wrapping:
            return _balanced(items, sym)
        if len(items) == 1:
            return items[0]
        half = len(items) // 2
        left, right = self._chain(items[:half], sym, helper), self._chain(items[half:], sym, helper)
        return f"{self.h.use(helper)}({_strip(left)}, {_strip(right)})"

    def _sub(self, a: str, b: str) -> str:
        if self.wrapping:
            return f"({a} - {b})"
        return f"{self.h.use('_wsub')}({_strip(a)}, {_strip(b)})"

    def _add(self, args) -> str:
        """add with readable subtractions (x + (-y) and x + K, K >= 2**255)."""
        pos, neg = [], []
        clock = any(_is_timestamp(a) for a in args)  # block.timestamp + 1 days

        def const(v: int) -> str:
            return (time_literal(v) if clock else None) or literal(v)

        for a in args:
            if _negation(a) is not None:
                neg.append(self.w(_negation(a)))
            elif isinstance(a, ir.Const) and a.value >> 255:
                neg.append(const(ir.WORD_MOD - a.value))
            elif isinstance(a, ir.Const):
                pos.append(const(a.value))
            else:
                pos.append(self.w(a))
        if not self.wrapping:
            total = self._chain(pos, " + ", "_wadd") if pos else "0"
            return self._sub(total, self._chain(neg, " + ", "_wadd")) if neg else total
        if not pos:
            return f"(0 - {_balanced(neg, ' + ')})" if len(neg) > 1 else f"(0 - {neg[0]})"
        if len(pos) + len(neg) <= _CHAIN:
            return "(" + " + ".join(pos) + "".join(f" - {n}" for n in neg) + ")"
        total = _balanced(pos, " + ")
        return f"({total} - {_balanced(neg, ' + ')})" if neg else total

    def _cmp_operand(self, e: ir.Expr) -> str:
        """An operand of an unsigned comparison: 2**N - 1 as type(uintN).max
        (the comparison converts it to uint256: the same value)."""
        return (max_literal(e.value) if isinstance(e, ir.Const) else None) or self.w(e)

    def _iszero(self, a) -> str:
        if isinstance(a, ir.Const):
            return "false" if a.value else "true"
        got = self.hoist_ids.get(id(a)) if self.hoist_ids else None
        if got is not None and got[1] != "bytes":  # an operand in a local: the local
            return f"(!{got[0]})" if got[1] == B else f"({got[0]} == 0)"
        name = self._bool_param(a)
        if name is not None:
            return f"(!{name})"
        diff = _difference(a)
        if diff is not None:  # a - b == 0
            return self._compare_addresses(diff[0], diff[1], "==") or f"({self.w(diff[0])} == {self.w(diff[1])})"
        if isinstance(a, ir.Op):
            if a.op == "iszero":
                return self.b(a.args[0])
            if a.op == "eq":
                return self._compare_addresses(a.args[0], a.args[1], "!=") or \
                    f"({self.w(a.args[0])} != {self.w(a.args[1])})"
            if a.op in ("lt", "gt"):
                sym = ">=" if a.op == "lt" else "<="
                return f"({self._cmp_operand(a.args[0])} {sym} {self._cmp_operand(a.args[1])})"
            if a.op in ("slt", "sgt"):
                sym = ">=" if a.op == "slt" else "<="
                return f"({self.signed(a.args[0])} {sym} {self.signed(a.args[1])})"
        s, kind = self.expr(a)
        return f"(!{s})" if kind == B else f"({s} == 0)"

    def bits(self, e: ir.Expr) -> int:
        """types.max_bits, knowing the widths of the validated parameter views."""
        w = _head_word(e)
        if w is not None and w in self.entry.word_bits:
            return self.entry.word_bits[w]
        return max_bits(e)

    def x_Mask(self, e):
        size, off, shl = _bits_field(e.size), _bits_field(e.offset), _bits_field(e.shl)
        if None not in (size, off, shl) and off == 0 and shl == 0 and 0 < size and self.bits(e.value) <= size:
            return self.expr(e.value)  # the value already fits: the mask keeps everything
        if None in (size, off, shl):
            args = [self._bitfield(e.size), self._bitfield(e.offset), self._bitfield(e.shl), self.w(e.value)]
            return f"{self.h.use('_maskShl')}(" + ", ".join(_strip(a) for a in args) + ")", W
        # the mask of ir.mask_value, clamped to the word before any integer is
        # built (a hostile constant such as a 2**40-bit size costs nothing)
        if off < 0:
            size, off = size + off, 0
        if size <= 0 or off >= 256 or shl >= 256 or shl <= -256:
            return "0", W
        size = min(size, 256 - off)
        x = self.w(e.value)
        m = ((1 << size) - 1) << off
        # readable exact shapes first
        if off == 0 and shl == 0 and size < 256 and size % 8 == 0:
            return f"uint256(uint{size}({_strip(x)}))", W
        if off > 0 and shl == -off:
            shifted = f"({x} >> {off})"
            return (shifted if size + off >= 256 else f"({shifted} & {literal((1 << size) - 1)})"), W
        # the mask is redundant when it keeps every bit the shift keeps
        kept = ir.WORD_MAX >> shl if shl >= 0 else ir.WORD_MAX ^ ((1 << -shl) - 1)
        masked = x if m & kept == kept else f"({x} & {literal(m)})"
        if shl > 0:
            return f"({masked} << {shl})", W
        if shl < 0:
            return f"({masked} >> {-shl})", W
        return masked, W

    def x_Keccak(self, e):
        return f"uint256(keccak256({self.bytes_(e.data)}))", W

    def x_MLoad(self, e):
        return f"{self.h.use('_vmLoad')}(_vm, {_strip(self.w(e.addr))})", W

    def x_BytesWord(self, e):
        d = e.data
        if isinstance(d, ir.CalldataSlice) and d.start == ir.ZERO and d.length == ir.Const(4):
            return "uint256(uint32(msg.sig))", W
        if isinstance(d, ir.WordBytes):
            return self.w(d.value) if d.width == 32 else f"uint256(uint{8 * d.width}({_strip(self.w(d.value))}))", W
        if isinstance(d, ir.ReturnData) and d.length == ir.Const(32):
            return f"{self.h.use('_returndataWord')}({_strip(self.w(d.start))})", W  # a return data word
        return f"{self.h.use('_bytesWord')}({self.bytes_(d)})", W

    def x_CallOut(self, e):
        if e.what == "success":
            return self.call_ok(e.call_id), B
        if e.what == "returndatasize":
            return f"{self.h.use('_returndatasize')}()", W
        if e.what == "address":
            return self.call_addr(e.call_id), W
        self.flags.add("unstructured")
        return f"{self.h.use('_unsupported')}()", W

    def x_Result(self, e):
        got = self.results.get((e.call_id, e.index))
        if got is None:
            return self._unsupported()  # a value of a call this text does not make
        text, t = self._result_text((e.call_id, e.index)), got[1]
        if t is None:
            return text, W
        if t.kind == "bool":
            return text, B
        return self._word_of(text, t), W

    def _result_text(self, key: Tuple[int, int]) -> str:
        """The text of a returned value: its local, or the call itself when
        the value is used once, right after it (see _inlined)."""
        if key in self.deferred:
            text = self._call_text(self.deferred.pop(key))
            self.results[key] = (text, self.results[key][1])
            return text
        return self.results[key][0]

    def _inlined(self, s: ir.Stmt, nxt: Optional[ir.Stmt]) -> bool:
        """The one value of the call `s` is used once, by the next statement,
        as the first thing it evaluates (`require(value, ...)`, `return
        value`): the call is written there instead of into a local.  The
        operands of the call carry no checked operation (the next statement
        may be written inside `unchecked`) and, outside `unchecked`, no
        wrapping arithmetic either (the call keeps its statement, see
        _set_unchecked)."""
        if self.array_mode or nxt is None:
            return False
        if isinstance(s, ir.HighCall) and len(s.returns) == 1 and s.outs and s.outs[0]:
            ty, operands = s.returns[0], list(s.args) + [x for x in (s.to, s.value, s.gas) if x is not None]
        elif isinstance(s, ir.Builtin) and s.out:
            ty, operands = s.ty, list(s.args)
        else:
            return False
        if self._result_uses is None:
            self._result_uses = {}
            for n in ir.walk_all(self.fn.body):
                if isinstance(n, ir.Result):
                    k = (n.call_id, n.index)
                    self._result_uses[k] = self._result_uses.get(k, 0) + 1
        r = ir.Result(s.call_id, 0, ty)
        checked, wrapping = self.facts(tuple(operands)) if operands else (False, False)
        if self._result_uses.get((s.call_id, 0)) != 1 or checked or (wrapping and not self.wrapping):
            return False
        if not ((isinstance(nxt, ir.Require) and nxt.cond == r)
                or (isinstance(nxt, ir.Return) and (nxt.values == (r,) or nxt.data == ir.WordBytes(r)))):
            return False
        self.deferred[(s.call_id, 0)] = s
        self.results[(s.call_id, 0)] = ("", _value_type(ty))
        return True

    def addr(self, e: ir.Expr) -> str:
        """The address of the low 160 bits of `e` (what CALL, BALANCE, ... use)."""
        if isinstance(e, ir.Env) and e.name in _ADDRESS_ATOMS:
            return _ADDRESS_ATOMS[e.name]
        got = self.hoist_ids.get(id(e)) if self.hoist_ids else None
        if got is not None and got[1] == W:  # an operand in a local: its low 160 bits
            return f"address(uint160({got[0]}))"
        if isinstance(e, ir.Mask) and (e.size, e.offset, e.shl) == (160, 0, 0):
            return self.addr(e.value)
        if isinstance(e, (ir.CalldataWord, ir.Param)):
            m = _ADDRESS_VIEW_RE.fullmatch(self.expr(e)[0])
            if m:
                return m.group(1)  # a declared address parameter
        if isinstance(e, ir.Field) and (e.offset, e.size) == (0, 160):
            return f"address(uint160({_strip(self._shift_base(e.value))}))"
        if isinstance(e, ir.StateRef) and e.ty == "address":
            return self._state_path(e)  # an address state variable: itself
        if isinstance(e, ir.Const):
            return address_literal(e.value & ((1 << 160) - 1))
        return f"address(uint160({_strip(self._shift_base(e))}))"

    def _address_value(self, e: ir.Expr) -> Optional[str]:
        """The address `e` holds when its word is exactly that address (an
        address of the environment, an address state variable, a validated
        address parameter): equal words are equal addresses."""
        if isinstance(e, ir.Env) and e.name in _ADDRESS_ATOMS:
            return _ADDRESS_ATOMS[e.name]
        if isinstance(e, ir.StateRef) and e.ty == "address":
            return self._state_path(e)
        if isinstance(e, ir.Mask) and (e.size, e.offset, e.shl) == (160, 0, 0):
            # (the low 160 bits of a word: the word of the address of them)
            got = self._address_value(e.value) if max_bits(e.value) <= 160 else None
            return got if got is not None else self.addr(e.value)
        if isinstance(e, ir.Const) and e.value < 1 << 160:
            return address_literal(e.value)
        if isinstance(e, ir.Result) and _value_type(e.ty) == _ADDRESS:
            return self.typed(e, _ADDRESS)  # an address a call returned
        w = _head_word(_cleaned(e, _ADDRESS))
        if w is not None and w in self.entry.word_params and self.entry.word_params[w][1].kind == "address":
            return self.entry.word_params[w][0]
        return None

    def _compare_addresses(self, a: ir.Expr, b: ir.Expr, sym: str) -> Optional[str]:
        """`a sym b` (== / !=) as a comparison of addresses, when both words
        are addresses."""
        x, y = self._address_value(a), self._address_value(b)
        return f"({x} {sym} {y})" if x is not None and y is not None else None

    def x_Balance(self, e):
        return f"{self.addr(e.addr)}.balance", W

    def x_ExtCodeSize(self, e):
        return f"{self.addr(e.addr)}.code.length", W

    def x_ExtCodeHash(self, e):
        return f"uint256({self.addr(e.addr)}.codehash)", W

    def x_BlockHash(self, e):
        return f"uint256(blockhash({_strip(self.w(e.number))}))", W

    def x_BlobHash(self, e):
        self.ctx.need("blobhash", (0, 8, 24))
        return f"uint256(blobhash({_strip(self.w(e.index))}))", W

    def x_TLoad(self, e):
        self.ctx.need("tload", (0, 8, 24))
        return f"{self.h.use('_tload')}({_strip(self.w(e.slot))})", W

    def x_Ternary(self, e):
        return f"({self.b(e.cond)} ? {self._shift_base(e.if_true)} : {self._shift_base(e.if_false)})", W

    def x_UnstructuredExpr(self, e):
        self.flags.add("unstructured")
        return f"{self.h.use('_unsupported')}()", W

    # idiomatic words (passes): rendered by value
    def x_Cast(self, e):
        return self.expr(e.value)

    def x_Bool(self, e):
        return self.b(e.value), B

    def x_Not(self, e):
        return f"(!{self.b(e.value)})", B

    def x_And(self, e):
        return "(" + " && ".join(self.b(a) for a in e.args) + ")", B

    def x_Or(self, e):
        return "(" + " || ".join(self.b(a) for a in e.args) + ")", B

    def _state_path(self, e: ir.StateRef) -> str:
        text = e.var
        for p in e.path:
            if isinstance(p, ir.Cast) and _value_type(p.ty) is not None:
                text += f"[{_strip(self.typed(p.value, _value_type(p.ty)))}]"  # a key of that type
            elif isinstance(p, ir.Expr):
                text += f"[{_strip(self.w(p))}]"
            else:
                text += f".{p}"
        return text

    def x_StateRef(self, e):
        t = _value_type(e.ty)
        if t is None:
            return self._unsupported()
        text = self._state_path(e)
        if t.kind == "bool":
            return text, B
        return self._word_of(text, t), W

    @staticmethod
    def _word_of(text: str, t: SolType) -> str:
        """The uint256 word of a Solidity value `text` of type t."""
        if t.kind == "uint":
            return text if t.bits == 256 else f"uint256({_strip(text)})"
        if t.kind == "int":
            return f"uint256({_strip(text)})" if t.bits == 256 else f"uint256(int256({_strip(text)}))"
        if t.kind == "address":
            return f"uint256(uint160({_strip(text)}))"
        if t.kind == "bool":
            return f"uint256({_strip(text)} ? 1 : 0)"
        return f"uint256(bytes32({_strip(text)}))" if t.bits < 256 else f"uint256({_strip(text)})"

    @staticmethod
    def _of_word(word: str, t: SolType) -> str:
        """The Solidity value of type t whose word is the uint256 `word` (a
        valid t value: the conversions only drop bits that are zero, or
        copies of the sign bit).  The word of a value of type t written as
        such (`uint256(uint8(x))`, `uint256(int256(int8(x)))`) gives the
        value back."""
        w = _strip(word)
        inner = _call_arg(w, "uint256")
        if inner is not None and t.kind == "uint" and t.bits < 256 and _call_arg(inner, t.canonical) is not None:
            return inner
        if inner is not None and t.kind == "int":
            value = inner if t.bits == 256 else _call_arg(inner, "int256")
            if value is not None and _call_arg(value, t.canonical) is not None:
                return value
        if t.kind == "uint":
            return w if t.bits == 256 else f"uint{t.bits}({w})"
        if t.kind == "int":
            return f"int256({w})" if t.bits == 256 else f"int{t.bits}(int256({w}))"
        if t.kind == "address":
            return f"address(uint160({w}))"
        if t.kind == "bool":
            return f"({w} != 0)"
        return f"bytes32({w})" if t.bits == 256 else f"bytes{t.bits // 8}(bytes32({w}))"

    _TYPED = {"add": "+", "sub": "-", "mul": "*", "div": "/", "mod": "%", "lt": "<", "gt": ">", "eq": "==",
              "and": "&", "or": "|", "xor": "^"}

    def x_Typed(self, e):
        sym, t = self._TYPED.get(e.op), _value_type(e.ty)
        if sym is None or len(e.args) != 2 or t is None or t.kind not in ("uint", "int") \
                or (e.checked and self.wrapping):
            return self._unsupported()
        if e.op in ("lt", "gt", "eq"):
            literals = all(ir.evaluate(x) is not None for x in e.args)
            a, b = (_atom(self._operand(x, t, literals)) for x in e.args)
            return f"({a} {sym} {b})", B
        if not e.checked and not self.wrapping:
            # unchecked arithmetic outside `unchecked` (a checked function)
            if e.op in ("add", "sub", "mul"):
                # the word wraps, the conversion to the type wraps it in the type
                helper = {"add": "_wadd", "sub": "_wsub", "mul": "_wmul"}[e.op]
                words = [_strip(self._shift_base(x)) for x in e.args]
                return self._word_of(self._of_word(f"{self.h.use(helper)}({words[0]}, {words[1]})", t), t), W
            if e.op == "div" and t.kind == "int":
                return self._unsupported()  # int.min / -1 would panic here instead of wrapping
        # Solidity's semantics in the current context: checked operations
        # are only written outside `unchecked`, unchecked ones inside
        return self._word_of(self._typed_value(e, t), t), W

    def _typed_value(self, e: ir.Typed, t: SolType) -> str:
        """The Solidity value, of type t, of the arithmetic Typed e (rendered
        where its `checked` flag holds: see x_Typed); `0 - x` of a signed
        type is the negation `-x` (the same check: only min overflows)."""
        literals = all(ir.evaluate(x) is not None for x in e.args)
        if e.op == "sub" and t.kind == "int" and e.args[0] == ir.ZERO:
            return f"(-{_atom(self._operand(e.args[1], t, literals))})"
        a, b = (_atom(self._operand(x, t, literals)) for x in e.args)
        if e.op in ("add", "sub") and not literals and any(_is_timestamp(x) for x in e.args):
            # block.timestamp + 1 days (the same literal as 86400)
            a, b = ((time_literal(x.value) or text) if isinstance(x, ir.Const) else text
                    for x, text in zip(e.args, (a, b)))
        # parentheses the precedence of a nested operation of the type makes
        # redundant: (a + b) + c, (a * b) + c, a + (b * c)
        prec = self._PRECEDENCE.get(e.op)
        x, y = e.args
        if prec and isinstance(x, ir.Typed) and self._PRECEDENCE.get(x.op, 0) >= prec and _value_type(x.ty) == t \
                and self._typed_here(x):
            a = _strip(a)
        if prec and isinstance(y, ir.Typed) and self._PRECEDENCE.get(y.op, 0) > prec and _value_type(y.ty) == t \
                and self._typed_here(y) and not (y.op == "sub" and y.args[0] == ir.ZERO and t.kind == "int"):
            b = _strip(b)
        return f"({a} {self._TYPED[e.op]} {b})"

    _PRECEDENCE = {"add": 1, "sub": 1, "mul": 2, "div": 2, "mod": 2}

    def _typed_here(self, e: ir.Typed) -> bool:
        """The arithmetic Typed e is written as Solidity's operator in the
        current context (checked ones outside `unchecked`, unchecked ones
        inside, and the operations that are the same in both: unsigned
        division, modulo); see x_Typed for the other cases."""
        if e.op not in ("add", "sub", "mul", "div", "mod"):
            return False
        if e.op == "mod" or (e.op == "div" and e.ty.startswith("uint")):
            return not (e.checked and self.wrapping)
        return e.checked != self.wrapping

    def _operand(self, x: ir.Expr, t: SolType, typed_literal: bool = False) -> str:
        """An operand of a Typed node (a valid t value) as a value of type
        t: a constant as its literal (converted to t when `typed_literal`:
        an operation of literals only would be a compile-time constant
        expression, without t's checks), else as typed() writes it (a state
        variable or a nested operation of that type as itself, a validated
        parameter as the parameter)."""
        c = x.value if isinstance(x, ir.Const) else (ir.evaluate(x) if typed_literal else None)
        if c is not None and t.kind in ("uint", "int"):
            v = ir.to_signed(c) if t.kind == "int" else c
            text = literal(v) if v >= 0 else f"(-{literal(-v)})"
            return f"{t.canonical}({_strip(text)})" if typed_literal else text
        if isinstance(x, ir.Typed) and _value_type(x.ty) == t and self._typed_here(x):
            return self._typed_value(x, t)
        return self.typed(x, t)

    def _unsupported(self) -> Tuple[str, str]:
        self.flags.add("unstructured")
        return f"{self.h.use('_unsupported')}()", W

    # ------------------------------------------------------------ bytes

    def bytes_(self, b: ir.Bytes) -> str:
        """`b` as a `bytes memory` expression."""
        got = self.hoist_ids.get(id(b)) if self.hoist_ids else None
        if got is not None and got[1] == "bytes":
            return got[0]
        if isinstance(b, ir.Blob):
            parts = self._flatten(b.parts)
            if not parts:
                return '""'
            if len(parts) == 1 and not isinstance(parts[0], ir.WordBytes):
                return self.bytes_(parts[0])
            lengths = [ir.byte_length(p) for p in parts]
            if None not in lengths and any(not isinstance(n, ir.Const) and ir.may_be_negative(n) for n in lengths):
                return self._signed_blob(parts, lengths)
            return _packed_tree([self.packed(p) for p in parts], self.packed_chain)
        if isinstance(b, ir.WordBytes):
            return f"abi.encodePacked({self.packed(b)})"
        if isinstance(b, ir.ConstBytes):
            return f'bytes(hex"{b.data.hex()}")' if b.data else '""'
        if isinstance(b, ir.ZeroBytes):
            return f"{self.h.use('_alloc')}({_strip(self.w(b.length))})"
        if isinstance(b, ir.WordSlice):
            return f"{self.h.use('_wordSlice')}({_strip(self.w(b.value))}, {_strip(self.w(b.length))})"
        if isinstance(b, ir.MaskBytes):
            size = "uint256(type(int256).max)" if b.size is None else _strip(self._bitfield(b.size))
            args = [self.bytes_(b.data), size, _strip(self._bitfield(b.offset)), _strip(self._bitfield(b.shl)),
                    _strip(self.w(b.length))]
            return f"{self.h.use('_maskBytes')}(" + ", ".join(args) + ")"
        if isinstance(b, ir.CalldataSlice):
            if b.start == ir.ZERO and b.length == ir.Env("calldatasize"):
                return "msg.data"
            view = self._dynamic_bytes(b)
            if view is not None:
                return view
            return f"{self.h.use('_calldata')}({_strip(self.w(b.start))}, {_strip(self.w(b.length))})"
        if isinstance(b, ir.MemSlice):
            return f"{self.h.use('_vmSlice')}(_vm, {_strip(self.w(b.start))}, {_strip(self.w(b.length))})"
        if isinstance(b, ir.ReturnData):
            if b.call_id in self.declared_ret and b.start == ir.ZERO \
                    and b.length == ir.CallOut(b.call_id, "returndatasize"):
                return self.declared_ret[b.call_id]  # the whole return data, copied at the call
            return f"{self.h.use('_returndata')}({_strip(self.w(b.start))}, {_strip(self.w(b.length))})"
        if isinstance(b, ir.CodeSlice):
            self.ctx.uses_code_constant = True
            return f"{self.h.use('_code')}({_strip(self.w(b.start))}, {_strip(self.w(b.length))})"
        if isinstance(b, ir.ExtCodeSlice):
            return (f"{self.h.use('_extcode')}({_strip(self.w(b.addr))}, {_strip(self.w(b.start))}, "
                    f"{_strip(self.w(b.length))})")
        self.flags.add("unstructured")
        return f"abi.encodePacked({self.h.use('_unsupported')}())"

    def _signed_blob(self, parts: List[ir.Bytes], lengths: List[ir.Expr]) -> str:
        """The concatenation of `parts` when a length may be negative: the
        engine split a range of the original's memory where it guessed a
        write ends, and a wrong guess leaves a negative length.  Each part is
        laid at the (signed) sum of the lengths before it, a negative one has
        no bytes, and the whole is cut to the sum of all the lengths (the
        range's own length): the bytes the range really holds (`_join`).
        With non-negative lengths this is the plain concatenation."""
        groups: List[Tuple[str, ir.Expr]] = []
        run: List[ir.Bytes] = []

        def flush():
            if run:
                n = ir.byte_length(ir.Blob(tuple(run)))
                text = self.bytes_(run[0]) if len(run) == 1 and not isinstance(run[0], ir.WordBytes) \
                    else _packed_tree([self.packed(p) for p in run], self.packed_chain)
                groups.append((text, n))
                run.clear()

        for p, n in zip(parts, lengths):
            if isinstance(n, ir.Const) or not ir.may_be_negative(n):
                run.append(p)
                continue
            flush()
            groups.append((f"(int256({_strip(self.w(n))}) < 0 ? new bytes(0) : {self.bytes_(p)})", n))
        flush()
        text, total = groups[0]
        for part, n in groups[1:]:
            text = f"{self.h.use('_join')}({text}, {_strip(self.w(total))}, {part}, {_strip(self.w(n))})"
            total = ir.Op("add", (total, n))
        return text

    def _dynamic_bytes(self, b: ir.CalldataSlice) -> Optional[str]:
        """The declared `bytes` / `string` parameter whose bytes `b` is:
        the calldata from 36 + offset word, of the length word's length."""
        dyn = self._dynamic_param(b.start, 36)
        if dyn is None or not isinstance(b.length, ir.CalldataWord) or self._dynamic_param(b.length.offset, 4) != dyn:
            return None
        name, t = dyn
        if t.kind == "dynbytes":
            return name
        if t.kind == "string":
            return f"bytes({name})"
        return None

    def dynamic_value(self, v: ir.Node, t: SolType) -> str:
        """A `bytes` / `string` value (a Bytes node) as a Solidity expression
        of type t."""
        data = ir.const_bytes(v) if isinstance(v, ir.Bytes) else None
        if t.kind == "string":
            if data is not None:
                return string_literal(data)
            b = self.bytes_(v)
            inner = _call_arg(b, "bytes")
            if inner is not None and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", inner):
                return inner  # a declared string parameter: bytes(s) is the view of s
            return f"string({b})"
        if data is not None:
            return f'hex"{data.hex()}"' if data else '""'
        return self.bytes_(v)

    def _flatten(self, parts) -> List[ir.Bytes]:
        out = []
        for p in parts:
            if isinstance(p, ir.Blob):
                out.extend(self._flatten(p.parts))
            else:
                out.append(p)
        return out

    def packed(self, p: ir.Bytes) -> str:
        """One argument of abi.encodePacked producing exactly the bytes of `p`."""
        if isinstance(p, ir.WordBytes):
            if isinstance(p.value, ir.Const) and 0 < p.width < 32 and p.width != 20:
                # the low bytes of a constant: a hex literal of exactly 2N digits is a bytesN value
                # (not 40 digits: solc reads them as an address and wants its checksum)
                low = p.value.value & ((1 << (8 * p.width)) - 1)
                return f"bytes{p.width}(0x{low:0{2 * p.width}x})"
            v = _strip(self._shift_base(p.value))
            if p.width == 32:
                return v
            return f"bytes{p.width}(uint{8 * p.width}({v}))"
        return self.bytes_(p)

    # ------------------------------------------------------------ statements

    def facts(self, nodes) -> Tuple[bool, bool]:
        """(has checked operations, has wrapping arithmetic) of the nodes'
        trees, memoised per node (iterative: traces nest deeply)."""
        memo = self._facts
        stack = [(n, False) for n in nodes]
        while stack:
            n, ready = stack.pop()
            if id(n) in memo:
                continue
            kids = list(ir.children(n))
            if not ready:
                stack.append((n, True))
                stack.extend((c, False) for c in kids if id(c) not in memo)
                continue
            checked, wrapping = _is_checked(n), _is_wrapping(n)
            for c in kids:
                cc, cw = memo[id(c)]
                checked, wrapping = checked or cc, wrapping or cw
            memo[id(n)] = (checked, wrapping)
        out = (False, False)
        for n in nodes:
            c, w = memo[id(n)]
            out = (out[0] or c, out[1] or w)
        return out

    def guarded(self, nodes, ind: int, render) -> List[str]:
        """render(indent): inside an `unchecked` block of its own when, in a
        function with checked operations, `nodes` have wrapping arithmetic
        and no checked operation (solc rejects nested `unchecked` blocks)."""
        if not self.wrapping:
            checked, wrapping = self.facts(nodes)
            if wrapping and not checked:
                self.wrapping = True
                try:
                    lines = render(ind + 1)
                finally:
                    self.wrapping = False
                return [_i(ind) + "unchecked {"] + lines + [_i(ind) + "}"]
        return render(ind)

    def block(self, stmts: Sequence[ir.Stmt], indent: int) -> List[str]:
        saved = self.scope_slots  # (locals a declaring statement left in the block end with it)
        try:
            return self._block(stmts, indent)
        finally:
            self.scope_slots = saved

    def _block(self, stmts: Sequence[ir.Stmt], indent: int) -> List[str]:
        out: List[str] = []
        if any(isinstance(s, (ir.HighCall, ir.Builtin)) for s in stmts):
            # a call whose value only the next statement uses is written there
            stmts = [s for i, s in enumerate(stmts)
                     if not (isinstance(s, (ir.HighCall, ir.Builtin))
                             and self._inlined(s, stmts[i + 1] if i + 1 < len(stmts) else None))]
        if self.wrapping:
            for s in stmts:
                out.extend(self.stmt(s, indent))
            return out
        # a function with checked operations: consecutive statements that
        # need `unchecked` (wrapping arithmetic, no checked operation) share
        # one block
        i = 0
        while i < len(stmts):
            j = i
            while j < len(stmts) and self.facts((stmts[j],)) == (False, True) and not self._declares(stmts[j]):
                j += 1
            if j - i >= 2:
                run = tuple(stmts[i:j])
                out.extend(self.guarded(run, indent, lambda ind: [x for s in run for x in self.stmt(s, ind)]))
                i = j
                continue
            out.extend(self.stmt(stmts[i], indent))
            i += 1
        return out

    def stmt(self, s: ir.Stmt, ind: int) -> List[str]:
        method = getattr(self, "s_" + type(s).__name__, None)
        if method is None:
            self.flags.add("unstructured")
            return [_i(ind) + 'revert("scobelix: unsupported construct");']
        skip: Set[int] = set()
        slots = self.scope_slots  # (a declaring statement adds its locals: once, for the rendering kept)
        frame: Optional[int] = None  # (None: every variable, see hoist_plan)
        if self._measured(s) and self.hoist_plan(s, skip) is not None:
            # too deep over every variable: plan over the ones it names (an
            # `if` by its condition: its branches are statements of their own)
            if isinstance(s, ir.If):
                frame = self._frame_for(self.b(s.cond), self._live(s))
            else:
                plain = self._plain(s, ind, method)
                self.scope_slots = slots
                frame = self._frame_for("\n".join(plain), self._live(s))
                if self.hoist_plan(s, skip, frame) is None:
                    return plain
        best: Optional[Tuple[int, List[str], int]] = None  # (locals never read, lines, scope slots)
        for _ in range(4):
            plan = self.hoist_plan(s, skip, frame)
            if plan is None:
                break
            # (the statements of an `if`'s branches have locals of their own)
            outer, self.hoisted_names = self.hoisted_names, []
            self.scope_slots = slots
            self.packed_chain = _HOIST_CHAIN
            try:
                if plan[1]:
                    lines = self._hoisted(s, ind, method, plan)
                elif self.wrapping or self._declares(s):
                    lines = method(s, ind)
                else:
                    lines = self.guarded((s,), ind, lambda i: method(s, i))
                names = self.hoisted_names
            finally:
                self.packed_chain = _CHAIN
                self.hoisted_names = outer
            if frame is not None and not isinstance(s, ir.If) \
                    and self._frame_for("\n".join(lines), self._live(s)) > frame:
                frame = None  # (written so, it names a deeper variable: plan again over every variable)
                continue
            unused = _unread(names, "\n".join(lines))
            if not unused:
                return lines
            if best is None or len(unused) < best[0]:
                best = (len(unused), lines, self.scope_slots)
            skip.update(id(x) for x in unused)  # its parent writes it from its parts: the local is never read
        if best is not None:  # (no plan without an unread local: the one with the fewest, not none)
            self.scope_slots = best[2]
            return best[1]
        self.scope_slots = slots
        return self._plain(s, ind, method)

    def _plain(self, s: ir.Stmt, ind: int, method) -> List[str]:
        """`s` written as it is (no operand in a local)."""
        if self.wrapping or self._declares(s):  # (one frame less per nesting level: traces nest deeply)
            return method(s, ind)
        return self.guarded((s,), ind, lambda i: method(s, i))

    # ------------------------------------------------------------ stack depth

    # Statements whose operands may be written into locals first (the others
    # declare locals, loop, or write calls where their value is used).
    _HOISTED_STMTS = ("Assign", "Mstore", "Sstore", "TStore", "Log", "Emit", "Return", "Revert", "Require", "Assert",
                      "SelfDestruct", "Create", "ExtCall", "Precompile", "Transfer", "Forward", "If")

    def _leaf(self, n: ir.Node) -> Optional[Tuple[int, int]]:
        """(slots to evaluate, slots of the value) of a node the renderer
        writes as a name: a word or the length of a declared parameter (1,
        1), a declared bytes or string parameter (2, 2: its calldata offset
        and length), a local in memory (2, 1); else None."""
        if isinstance(n, ir.CalldataWord):
            off = _const(n.offset)
            if off is not None and off >= 4 and (off - 4) % 32 == 0 and (off - 4) // 32 in self.entry.word_views:
                return 1, 1
            if self._dynamic_param(n.offset, 4) is not None:
                return 1, 1
        if isinstance(n, ir.CalldataSlice) and self._dynamic_bytes(n) is not None:
            return 2, 2
        if isinstance(n, ir.Local) and self.array_mode:
            return 2, 1
        return None

    def _frame(self, live: Optional[int] = None) -> int:
        """Stack slots over the deepest variable: the other parameters and
        return values, the emulated memory, the locals on the stack and the
        locals of the enclosing statement (the return address and the
        deepest variable itself do not count).  `live`: how many of the
        locals declared in place are in scope there (see _live_in_place;
        None: all of them, wherever they are declared)."""
        params = self.entry.stack_slots - self.entry.stack_margin
        locals_ = self.stack_locals if live is None else self.stack_locals - len(self.in_place) + live
        return max(params + int(self.memory) + locals_ + self.cond_slot + self.go_slot + self.scope_slots - 1, 0)

    def _live(self, s: ir.Node) -> Optional[int]:
        """The locals declared in place that are in scope where statement
        `s` runs (None: not known, see _frame)."""
        return self.live_at.get(id(s)) if self.in_place else None

    def _frame_for(self, text: str, live: Optional[int] = None) -> int:
        """_frame(live) for code written `text`: the slots over the deepest
        variable it names.  The parameters below the first one it names
        are never reached; when it names none, neither are the return
        values, unless it returns (a `return` assigns them).  Without
        param_slots (the parameters' order unknown): _frame(live)."""
        frame = self._frame(live)
        if not self.entry.param_slots:
            return frame
        below = 0
        for name, slots in self.entry.param_slots:
            if name and re.search(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", text):
                return frame - below
            below += slots
        if re.search(r"(?<![\w$])return(?![\w$])", text):
            return frame - below
        returns = self.entry.stack_slots - self.entry.stack_margin - below
        return max(frame - below - returns, 0)

    def _measured(self, s: ir.Stmt) -> bool:
        """A statement planned over the variables its text names (_frame_for):
        one written again without new names (the other statements, the
        calls and the statements declaring locals, are planned over every
        variable: writing them again would rename what they declare)."""
        return type(s).__name__ in self._MEASURED and not self._declares(s)

    _MEASURED = ("Assign", "Mstore", "Sstore", "TStore", "Log", "Emit", "Return", "Revert", "Require", "Assert",
                 "SelfDestruct", "If")

    def hoist_plan(self, s: ir.Stmt, skip: Set[int], frame: Optional[int] = None) -> Optional[Tuple[str, list]]:
        """The operands of `s` to write into locals before it, when its
        operands would need more stack slots than the legacy code generator
        reaches (16 from the deepest local): ("stack", [(operand, the plan of
        its own evaluation, in a scope of its own), ...]) (StackModel.plan),
        or, when locals on the stack cannot make it fit, ("memory",
        [operand, ...]) kept in memory arrays (StackModel.plan_memory).
        Only operands every evaluation of `s` computes (not a ternary's
        branch, not the right side of && / ||), never across a call written
        in place, and only when no two operands that fail differently (a
        halt, a Panic, ...) change order (stack.order_safe): the first failure
        decides how the call ends.  An operand equal to one in a local reads
        the local (they have the same value: nothing changes state while a
        statement evaluates its operands).  None when `s` fits as it is, or
        when nothing can be moved.  `frame`: the slots over the deepest
        variable `s` reaches (default: every variable in scope there)."""
        if type(s).__name__ not in self._HOISTED_STMTS or (isinstance(s, ir.If) and _moot(s)):
            return None
        if frame is None:
            frame = self._frame(self._live(s))
        key = ("stmt", id(s), frame, frozenset(skip))
        hit = self.plans.get(key)
        if hit is not None and hit[0] is s:
            return hit[1]
        roots = stack.roots(s)
        if stack.StackModel(self._leaf, _CHAIN).stmt_need(s, roots, set()) + frame <= stack.WINDOW \
                or not stack.reorder_safe(roots):
            plan = None
        else:
            plan = self._plan_operands(roots, lambda m: (lambda est: m.stmt_need(s, roots, est)), frame, skip,
                                       not isinstance(s, ir.If))
        self.plans[key] = (s, plan)
        return plan

    def _plan_operands(self, roots: List[ir.Node], need_of, frame: int, skip: Set[int],
                       top: bool) -> Optional[Tuple[str, list]]:
        """Locals on the stack, or else entries of memory arrays (two slots
        at most, whatever their number: a word array and a bytes array)."""
        index = stack.Index(roots)
        model = stack.StackModel(self._leaf, _HOIST_CHAIN, index=index)  # (how a statement with locals is written)
        plan = model.plan(roots, need_of(model), frame, set(), skip, top, validate=index.order_safe)
        if plan is not None:
            return "stack", plan  # (empty: the narrower abi.encodePacked alone makes it fit)
        model = stack.StackModel(self._leaf, _HOIST_CHAIN, held=2, index=index)
        entries = model.plan_memory(roots, need_of(model), frame + 2, skip, top, validate=index.order_safe)
        return ("memory", entries) if entries else None

    def _cond_var(self) -> str:
        """The function's bool for conditions evaluated through locals."""
        if self.cond_name is None:
            self.cond_name = self.fresh("_c")
            self.decls.append(f"bool {self.cond_name};")
        return self.cond_name

    def _loop_check(self, loop: ir.Stmt, ind: int) -> Optional[List[str]]:
        """A loop condition too deep for the stack, evaluated through locals at
        the top of the body (`{ ...; _c = cond; } if (!_c) break;`: the same
        test at the same point of every iteration), when that is needed and
        possible (see hoist_plan); else None."""
        cond = loop.cond
        roots = [cond]
        live = self.loop_live.get(id(loop)) if self.in_place else None  # (its header's local too)
        frame = self._frame(live)
        if stack.StackModel(self._leaf, _CHAIN).need(cond, set(), {}) + 1 + frame > stack.WINDOW:
            frame = self._frame_for(self.b(cond), live)  # (too deep over every variable: over the ones it names)
        skip: Set[int] = set()
        best: Optional[Tuple[int, List[str]]] = None  # (locals never read, lines)
        for _ in range(4):
            key = ("loop", id(cond), frame, frozenset(skip))
            hit = self.plans.get(key)
            if hit is not None and hit[0] is cond:
                plan = hit[1]
            elif stack.StackModel(self._leaf, _CHAIN).need(cond, set(), {}) + 1 + frame <= stack.WINDOW \
                    or not stack.reorder_safe(roots):
                plan = None
            else:
                plan = self._plan_operands(roots, lambda m: (lambda est: 1 + m.need(cond, est, {})), frame, skip,
                                           False)
            self.plans[key] = (cond, plan)
            if not plan:
                break
            saved, outer = self.hoist_ids, self.hoisted_names
            self.hoist_ids, self.hoisted_names = dict(saved), []
            self.packed_chain = _HOIST_CHAIN
            try:
                name = self._cond_var()
                decls = self._emit(plan, roots, ind + 1)
                decls.append(_i(ind + 1) + f"{name} = {_strip(self.b(cond))};")
                names = self.hoisted_names
            finally:
                self.hoist_ids, self.hoisted_names = saved, outer
                self.packed_chain = _CHAIN
            lines = [_i(ind) + "{"] + decls + [_i(ind) + "}", _i(ind) + f"if (!{name}) break;"]
            unused = _unread(names, "\n".join(lines))
            if not unused:
                return lines
            if best is None or len(unused) < best[0]:
                best = (len(unused), lines)
            skip.update(id(x) for x in unused)
        return best[1] if best is not None else None

    def _hoist_text(self, x: ir.Node) -> str:
        return self.bytes_(x) if isinstance(x, ir.Bytes) else _strip(self.w(x))

    def _emit(self, plan: Tuple[str, list], roots: List[ir.Node], ind: int) -> List[str]:
        mode, items = plan
        return self._emit_hoisted(items, roots, ind) if mode == "stack" else self._emit_memory(items, roots, ind)

    def _emit_memory(self, items: List[ir.Node], roots: List[ir.Node], ind: int) -> List[str]:
        """The memory arrays of a plan of entries (`uint256[K] memory _t`,
        `bytes[M] memory _tb`) and their entries, in order; every occurrence
        of an operand in `roots` reads its entry from then on."""
        words = [x for x in items if not isinstance(x, ir.Bytes)]
        blobs = [x for x in items if isinstance(x, ir.Bytes)]
        out: List[str] = []
        t = self.fresh("_t") if words else ""
        tb = self.fresh("_tb") if blobs else ""
        if t:
            out.append(_i(ind) + f"uint256[{len(words)}] memory {t}; // operands kept in memory: the stack is full")
        if tb:
            out.append(_i(ind) + f"bytes[{len(blobs)}] memory {tb};")
        counts = {"bytes": 0, W: 0}
        for x in items:
            kind = "bytes" if isinstance(x, ir.Bytes) else W
            name = f"{tb if kind == 'bytes' else t}[{counts[kind]}]"
            counts[kind] += 1
            self.hoisted_names.append((x, name, 1))  # (set once: read when it occurs again)
            out.append(_i(ind) + f"{name} = {self._hoist_text(x)};")
            for n in ir.walk_all(tuple(roots)):
                if n == x:
                    self.hoist_ids[id(n)] = (name, kind)
        return out

    def _emit_hoisted(self, plan: list, roots: List[ir.Node], ind: int) -> List[str]:
        """The locals of `plan`, in order (an operand with a plan of its own
        is set in a scope of its own, whose locals end there); every
        occurrence of an operand in `roots` reads its local from then on."""
        out = []
        for x, sub in plan:
            decl = "bytes memory" if isinstance(x, ir.Bytes) else "uint256"
            name = self.fresh("_h")
            # (written once with its value, or declared then set in a scope of its own: twice)
            self.hoisted_names.append((x, name, 2 if sub else 1))
            if sub:
                saved = self.hoist_ids
                self.hoist_ids = dict(saved)
                try:
                    inner = self._emit_hoisted(sub, [x], ind + 1)
                    inner.append(_i(ind + 1) + f"{name} = {self._hoist_text(x)};")
                finally:
                    self.hoist_ids = saved
                out += [_i(ind) + f"{decl} {name};", _i(ind) + "{"] + inner + [_i(ind) + "}"]
            else:
                out.append(_i(ind) + f"{decl} {name} = {self._hoist_text(x)};")
            kind = "bytes" if isinstance(x, ir.Bytes) else W
            for n in ir.walk_all(tuple(roots)):
                if n == x:
                    self.hoist_ids[id(n)] = (name, kind)
        return out

    def _hoisted(self, s: ir.Stmt, ind: int, method, plan: Tuple[str, list]) -> List[str]:
        roots = stack.roots(s)

        if self._declares(s):
            # the locals it declares are read after it: no scope around it; the
            # locals of the plan stay until the end of the block
            saved = self.hoist_ids
            self.hoist_ids = dict(saved)
            try:
                lines = self._emit(plan, roots, ind) + method(s, ind)
            finally:
                self.hoist_ids = saved
            mode, items = plan
            self.scope_slots += len(items) if mode == "stack" else len({isinstance(x, ir.Bytes) for x in items})
            return lines

        def render(i: int) -> List[str]:
            saved = self.hoist_ids
            self.hoist_ids = dict(saved)
            try:
                if not isinstance(s, ir.If):
                    return [_i(i) + "{"] + self._emit(plan, roots, i + 1) + method(s, i + 1) + [_i(i) + "}"]
                # the condition into the function's bool (cond_slot): the branches
                # never read the hoisted locals, which end before them
                cond = self._cond_var()
                decls = self._emit(plan, roots, i + 1)
                decls.append(_i(i + 1) + f"{cond} = {_strip(self.b(s.cond))};")
            finally:
                self.hoist_ids = saved
            return [_i(i) + "{"] + decls + [_i(i) + "}"] + self.s_If(s, i, cond_text=cond)

        if self.wrapping:
            return render(ind)
        return self.guarded((s,), ind, render)

    def s_If(self, s, ind, cond_text: Optional[str] = None):
        if _moot(s):
            # both branches run the same code: the test is moot
            return self.block(s.then, ind)
        out = [_i(ind) + f"if ({cond_text or _strip(self.b(s.cond))}) {{"]
        out += self.block(s.then, ind + 1)
        if s.orelse and _terminates(s.then):
            # the then-branch never falls through: the else-branch follows it
            out.append(_i(ind) + "}")
            return out + self.block(s.orelse, ind)
        if s.orelse:
            out.append(_i(ind) + "} else {")
            out += self.block(s.orelse, ind + 1)
        out.append(_i(ind) + "}")
        return out

    def target(self, e: ir.Expr) -> Tuple[Optional[str], SolType]:
        """The text of an assignment target and its type (None: not one)."""
        if isinstance(e, ir.Local):
            return self.local(e.name), _UINT256
        if isinstance(e, ir.StateRef) and _value_type(e.ty) is not None:
            return self._state_path(e), _value_type(e.ty)
        return None, _UINT256

    _COMPOUND = {"+": ("+", "_wadd"), "-": ("-", "_wsub"), "*": ("*", "_wmul"), "/": ("/", "_div"),
                 "%": ("%", "_mod"), "&": ("&", None), "|": ("|", None), "^": ("^", None), "<<": ("<<", None),
                 ">>": (">>", None)}

    def compound(self, target: str, op: str, value: ir.Expr) -> Optional[str]:
        """The uint256 expression `target op value` (EVM meaning of op), or
        None for an unknown operator."""
        if op not in self._COMPOUND:
            return None
        sym, helper = self._COMPOUND[op]
        v = _strip(self.w(value))
        if op in ("/", "%") and not _const(value):
            return f"{self.h.use(helper)}({target}, {v})"  # x / 0 is 0, not a Panic
        if op in ("+", "-", "*") and not self.wrapping:
            return f"{self.h.use(helper)}({target}, {v})"
        return f"({target} {sym} {v})"

    _TYPED_COMPOUND = {"+": "add", "-": "sub", "*": "mul", "/": "div", "%": "mod", "&": "and", "|": "or", "^": "xor",
                       "++": "add", "--": "sub"}

    def s_Assign(self, s, ind):
        target, t = self.target(s.target)
        if target is not None and s.op is not None and s.checked is not None:
            line = self._typed_compound(target, t, s)
            if line is not None:
                return [_i(ind) + line]
            target = None
        if target is None or (s.op is not None and not (t.kind == "uint" and t.bits == 256)):
            self.flags.add("unstructured")
            return [_i(ind) + 'revert("scobelix: unsupported construct");']
        if s.op is None:
            decl = "uint256 " if self._declares(s) else ""
            return [_i(ind) + f"{decl}{target} = {self.typed(s.value, t)};"]
        op = {"++": "+", "--": "-"}.get(s.op, s.op)
        operand = ir.ONE if s.op in ("++", "--") else s.value
        value = self.compound(target, op, operand)
        if value is None:
            self.flags.add("unstructured")
            return [_i(ind) + 'revert("scobelix: unsupported construct");']
        if s.op in ("++", "--") and self.wrapping:
            return [_i(ind) + f"{target}{s.op};"]
        if (op not in ("+", "-", "*") or self.wrapping) and (op not in ("/", "%") or _const(operand)):
            return [_i(ind) + f"{target} {op}= {_strip(self.w(operand))};"]
        return [_i(ind) + f"{target} = {_strip(value)};"]

    def _typed_compound(self, target: str, t: SolType, s: ir.Assign) -> Optional[str]:
        """`target op= value` with Solidity's semantics in the target's type
        (Assign.checked set), or None when the current context cannot give
        them (a checked operation inside `unchecked`, or an unchecked one that
        Solidity would check outside it)."""
        if t.kind not in ("uint", "int") or s.op not in self._TYPED_COMPOUND:
            return None
        if s.checked == self.wrapping:
            same_anywhere = s.op in ("%", "&", "|", "^") or (s.op == "/" and t.kind == "uint")
            if s.checked or not same_anywhere:
                return None
        if s.op in ("++", "--"):
            return f"{target}{s.op};"
        return f"{target} {s.op}= {_strip(self._operand(s.value, t))};"

    def _assigned(self, a: ir.Assign) -> Optional[ir.Expr]:
        """The value a compound assignment with Solidity's semantics stores,
        as a Typed expression reading the target."""
        t = self.target(a.target)[1]
        op = self._TYPED_COMPOUND.get(a.op or "")
        if op is None or t.kind not in ("uint", "int"):
            return None
        return ir.Typed(op, (a.target, ir.ONE if a.op in ("++", "--") else a.value), t.canonical, bool(a.checked))

    def parallel(self, assigns: Sequence[ir.Assign], ind: int) -> List[str]:
        """Assignments that all read the values from before any of them."""
        dependent = False
        for i, a in enumerate(assigns):
            if any(_depends(a, b.target) for b in assigns[:i]):
                dependent = True
                break
        if not dependent:
            return [line for a in assigns for line in self.s_Assign(a, ind)]
        # every new value first, from the old ones; then the assignments
        out = [_i(ind) + "{ // parallel assignment"]
        targets = []
        for k, a in enumerate(assigns):
            target, t = self.target(a.target)
            if a.op is not None and a.checked is not None and target is not None:
                typed = self._assigned(a)
                value = _strip(self.w(typed)) if typed is not None else None
            elif a.op is not None and target is not None:
                op = {"++": "+", "--": "-"}.get(a.op, a.op)
                operand = ir.ONE if a.op in ("++", "--") else a.value
                value = self.compound(target, op, operand) if t.kind == "uint" and t.bits == 256 else None
                t = _UINT256
            else:
                value = _strip(self.w(a.value)) if t.kind != "bool" else _strip(self.b(a.value))
            if target is None or value is None:
                self.flags.add("unstructured")
                return [_i(ind) + 'revert("scobelix: unsupported construct");']
            decl = "bool" if t.kind == "bool" else "uint256"
            out.append(_i(ind + 1) + f"{decl} _next{k} = {_strip(value)};")
            targets.append((target, t))
        for k, (target, t) in enumerate(targets):
            v = f"_next{k}" if t.kind in ("bool",) or (t.kind == "uint" and t.bits == 256) else \
                self._of_word(f"_next{k}", t)
            out.append(_i(ind + 1) + f"{target} = {v};")
        return out + [_i(ind) + "}"]

    def s_While(self, s, ind):
        out = self.guarded(s.init, ind, lambda i: self.parallel(s.init, i)) if s.init else []
        self.loops.append(s.loop_id)
        check = None if s.cond == ir.ONE else self._loop_check(s, ind + 1)
        cond = "true" if s.cond == ir.ONE or check else _strip(self.b(s.cond))
        out.append(_i(ind) + f"while ({cond}) {{")
        body = (check or []) + self.block(s.body, ind + 1)
        self.loops.pop()
        return out + body + [_i(ind) + "}"] + self._after_loop(s, ind)

    def s_Continue(self, s, ind):
        if self.loops and self.loops[-1] == s.loop_id:
            return self.parallel(s.updates, ind) + [_i(ind) + "continue;"]
        if s.loop_id in self.loops:
            # a loop that encloses this one: its updates, then out of the inner
            # loops up to it (_go names it by its depth, see _after_loop)
            depth = self.loops.index(s.loop_id) + 1
            return self.parallel(s.updates, ind) + [_i(ind) + f"{self._go_var()} = {depth};", _i(ind) + "break;"]
        self.flags.add("unstructured")
        return [_i(ind) + 'revert("scobelix: unsupported control flow");']

    def _go_var(self) -> str:
        """The function's word naming the loop a continue leaves inner loops for."""
        if self.go_name is None:
            self.go_name = self.fresh("_go")
            self.decls.append(f"uint256 {self.go_name};")
        return self.go_name

    def _after_loop(self, s: ir.Stmt, ind: int) -> List[str]:
        """After an inner loop a continue of an enclosing loop leaves: continue
        the loop that encloses it when the continue is its, else leave it too."""
        exits = {self.loops.index(x) + 1 for x in _loop_exits(s) if x in self.loops}
        if not exits:
            return []
        go, depth = self._go_var(), len(self.loops)
        if exits == {depth}:
            return [_i(ind) + f"if ({go} != 0) {{", _i(ind + 1) + f"{go} = 0;", _i(ind + 1) + "continue;",
                    _i(ind) + "}"]
        if depth not in exits:
            return [_i(ind) + f"if ({go} != 0) break;"]
        return [_i(ind) + f"if ({go} != 0) {{", _i(ind + 1) + f"if ({go} == {depth}) {{",
                _i(ind + 2) + f"{go} = 0;", _i(ind + 2) + "continue;", _i(ind + 1) + "}", _i(ind + 1) + "break;",
                _i(ind) + "}"]

    def s_Break(self, s, ind):
        return [_i(ind) + "break;"]

    def s_For(self, s, ind):
        # one assignment of a local as `init` is the header's; anything else runs before the loop
        in_header = len(s.init) == 1 and isinstance(s.init[0], ir.Assign) and isinstance(s.init[0].target, ir.Local)
        out = [] if in_header else self.block(s.init, ind)
        header = []
        for part in (s.init if in_header else (), s.step):
            line = self.s_Assign(part[0], 0) if len(part) == 1 and isinstance(part[0], ir.Assign) else None
            if part and (line is None or len(line) != 1 or line[0].startswith("revert")):
                self.flags.add("unstructured")
                return [_i(ind) + 'revert("scobelix: unsupported control flow");']
            header.append(line[0].rstrip(";") if line else "")
        self.loops.append(s.loop_id)
        check = None if s.cond == ir.ONE else self._loop_check(s, ind + 1)
        cond = "true" if s.cond == ir.ONE or check else _strip(self.b(s.cond))
        if in_header or s.step:
            out.append(_i(ind) + f"for ({header[0]}; {'' if check else cond}; {header[1]}) {{")
        else:
            out.append(_i(ind) + f"while ({cond}) {{")
        out += (check or []) + self.block(s.body, ind + 1)
        self.loops.pop()
        return out + [_i(ind) + "}"] + self._after_loop(s, ind)

    def s_Sstore(self, s, ind):
        off, size = _bits_field(s.offset), _bits_field(s.size)
        slot = _strip(self.w(s.slot))
        if off == 0 and size is not None and size >= 256:
            return [_i(ind) + f"{self.h.use('_sstore')}({slot}, {_strip(self.w(s.value))});"]
        o = _strip(self._bitfield(s.offset))
        n = _strip(self._bitfield(s.size))
        return [_i(ind) + f"{self.h.use('_sstoreField')}({slot}, {o}, {n}, {_strip(self.w(s.value))});"]

    def s_Mstore(self, s, ind):
        if not self.memory:
            return []  # never read back: not observable
        addr = _strip(self.w(s.addr))
        d = s.data
        if isinstance(d, ir.WordBytes) and d.width == 32:
            return [_i(ind) + f"_vm = {self.h.use('_vmStore')}(_vm, {addr}, {_strip(self.w(d.value))});"]
        return [_i(ind) + f"_vm = {self.h.use('_vmWrite')}(_vm, {addr}, {self.bytes_(d)});"]

    def s_TStore(self, s, ind):
        self.ctx.need("tstore", (0, 8, 24))
        return [_i(ind) + f"{self.h.use('_tstore')}({_strip(self.w(s.slot))}, {_strip(self.w(s.value))});"]

    def s_Log(self, s, ind):
        n = len(s.topics)
        data = self.bytes_(s.data) if s.data is not None else '""'
        args = [data] + [_strip(self.w(t)) for t in s.topics]
        return [_i(ind) + f"{self.h.use(f'_log{n}')}(" + ", ".join(args) + ");"]

    def s_Emit(self, s, ind):
        args: List[str] = []
        if not s.types:
            args = [_strip(self.w(a)) if isinstance(a, ir.Expr) else self.bytes_(a) for a in s.args]
        elif len(s.types) == len(s.args):
            for a, ty in zip(s.args, s.types):
                if ty in ("string", "bytes") and isinstance(a, ir.Bytes):
                    args.append(self.dynamic_value(a, parse_type(ty)))
                    continue
                t = _value_type(ty)
                if t is None or not isinstance(a, ir.Expr):
                    break
                args.append(self.typed(a, t))
        if len(args) != len(s.args):
            self.flags.add("unstructured")
            return [_i(ind) + 'revert("scobelix: unsupported construct");']
        return [_i(ind) + f"emit {s.event}(" + ", ".join(args) + ");"]

    def payload(self, s: ir.ExtCall) -> str:
        parts: List[ir.Bytes] = []
        if s.selector is not None:
            parts.append(ir.WordBytes(s.selector, 4))
        if s.args is not None:
            parts.append(s.args)
        if not parts:
            return '""'
        if s.ok is not None:
            # (calls pass) a constant selector and whole words: the ABI
            # encoding of uint256 values behind the selector, the same bytes
            flat = self._flatten(parts)
            head = flat[0]
            if isinstance(head, ir.WordBytes) and head.width == 4 and isinstance(head.value, ir.Const) \
                    and all(isinstance(p, ir.WordBytes) and p.width == 32 for p in flat[1:]):
                words = [_strip(self.w(p.value)) for p in flat[1:]]
                return f"abi.encodeWithSelector({', '.join([f'bytes4(0x{head.value.value & 0xFFFFFFFF:08x})'] + words)})"
        return self.bytes_(ir.Blob(tuple(parts)))

    def _declares(self, s: ir.Stmt) -> bool:
        """`s` declares locals where it is written (calls pass): it must not
        sit in an `unchecked` block of its own (its locals would end there).
        When it needs one (see _set_unchecked), it declares its locals first
        and sets them inside the block."""
        if self.array_mode:
            return False
        if isinstance(s, ir.Assign):
            return s.declare and s.op is None and isinstance(s.target, ir.Local) and s.target.name in self.in_place
        if isinstance(s, ir.ExtCall):
            return s.ok is not None and s.kind != "callcode"
        if isinstance(s, ir.HighCall):
            return any(s.outs)
        if isinstance(s, ir.Builtin):
            return s.out is not None
        return isinstance(s, ir.Transfer) and s.send and s.ok is not None

    def _set_unchecked(self, s: ir.Stmt) -> bool:
        """A statement that declares locals (see _declares) and has wrapping
        arithmetic but no checked operation, outside `unchecked`: written
        `T x; unchecked { x = ...; }` (its operators wrap there; the
        wrapping helpers instead nest the expression, and solc can run out
        of stack slots for it)."""
        return not self.wrapping and self.facts((s,)) == (False, True)

    def _unchecked(self, decls: List[str], assign: Callable[[], str], ind: int) -> List[str]:
        """The declarations `decls`, then `assign()` (rendered with wrapping
        operators) as the one statement of an `unchecked` block."""
        saved, self.wrapping = self.wrapping, True
        try:
            line = assign()
        finally:
            self.wrapping = saved
        return [_i(ind) + d for d in decls] + [_i(ind) + "unchecked {", _i(ind + 1) + line, _i(ind) + "}"]

    def s_Builtin(self, s, ind):
        t = _value_type(s.ty)
        if t is None:
            self.flags.add("unstructured")
            return [_i(ind) + 'revert("scobelix: unsupported construct");']
        if s.out is not None and not self.array_mode and self._set_unchecked(s):
            name = self.fresh(s.out)
            lines = self._unchecked([f"{t.solidity()} {name};"], lambda: f"{name} = {self._call_text(s)};", ind)
            self.results[(s.call_id, 0)] = (name, t)
            return lines
        call = self._call_text(s)
        if s.out is None:
            return [_i(ind) + call + ";"]
        if self.array_mode:
            slot = self.local(f"c{s.call_id}_r0")
            self.results[(s.call_id, 0)] = (slot, None)
            return [_i(ind) + f"{slot} = {self._word_of(call, t)};"]
        name = self.fresh(s.out)
        self.results[(s.call_id, 0)] = (name, t)
        return [_i(ind) + f"{t.solidity()} {name} = {call};"]

    def _ext_call_text(self, s: ir.ExtCall) -> str:
        """`to.call{gas: g, value: v}(payload)` (or staticcall / delegatecall)."""
        to = self.addr(s.to)
        data = self.payload(s)
        opts = []
        if s.gas is not None:
            opts.append(f"gas: {_strip(self.w(s.gas))}")
        if s.kind == "call" and s.value is not None and s.value != ir.ZERO:
            opts.append(f"value: {_strip(self.w(s.value))}")
        o = "{" + ", ".join(opts) + "}" if opts else ""
        return f"{to}.{s.kind}{o}({data})"

    def s_ExtCall(self, s, ind):
        if s.kind == "callcode":
            data = self.payload(s)
            ok = self.call_ok(s.call_id)
            gas = _strip(self.w(s.gas)) if s.gas is not None else "gasleft()"
            value = _strip(self.w(s.value)) if s.value is not None else "0"
            return [_i(ind) + f"{ok} = {self.h.use('_callcode')}({gas}, {_strip(self.w(s.to))}, {value}, {data});"]
        if self._declares(s):
            # the success flag (and the return data) declared at the call
            if self._set_unchecked(s):
                ok = self.fresh(s.ok)
                ret = self.fresh(s.ret) if s.ret else ""
                decls = [f"bool {ok};"] + ([f"bytes memory {ret};"] if ret else [])
                lines = self._unchecked(decls, lambda: f"({ok}, {ret}) = {self._ext_call_text(s)};", ind)
            else:
                call = self._ext_call_text(s)
                ok = self.fresh(s.ok)
                ret = self.fresh(s.ret) if s.ret else ""
                lines = [_i(ind) + f"(bool {ok}, {'bytes memory ' + ret if ret else ''}) = {call};"]
            self.declared_ok[s.call_id] = ok
            if ret:
                self.declared_ret[s.call_id] = ret
            return lines
        call = self._ext_call_text(s)
        ok = self.call_ok(s.call_id)
        return [_i(ind) + f"({ok}, ) = {call};"]

    def _call_text(self, s: ir.Stmt) -> str:
        """The call expression of a HighCall / Builtin (None: its operands
        have no translation)."""
        if isinstance(s, ir.Builtin):
            args = []
            for a, ty in zip(s.args, s.types):
                if ty == "bytes" and isinstance(a, ir.Bytes):
                    args.append(self.bytes_(a))
                elif _value_type(ty) is not None and isinstance(a, ir.Expr):
                    args.append(self.typed(a, _value_type(ty)))
            if len(args) != len(s.args):
                return self._unsupported()[0]
            return f"{s.name}({', '.join(args)})"
        types = [_value_type(t) for t in s.types]
        if None in types or len(types) != len(s.args):
            return self._unsupported()[0]
        args = [self.typed(a, t) for a, t in zip(s.args, types)]
        opts = []
        if s.value is not None:
            opts.append(f"value: {_strip(self.w(s.value))}")
        if s.gas is not None:
            opts.append(f"gas: {_strip(self.w(s.gas))}")
        o = "{" + ", ".join(opts) + "}" if opts else ""
        return f"{s.iface}({self.addr(s.to)}).{s.name}{o}(" + ", ".join(args) + ")"

    def s_HighCall(self, s, ind):
        types = [_value_type(t) for t in s.types]
        rets = [_value_type(t) for t in s.returns]
        if None in types or None in rets or len(types) != len(s.args) \
                or (s.outs and len(s.outs) != len(s.returns)):
            self.flags.add("unstructured")
            return [_i(ind) + 'revert("scobelix: unsupported construct");']
        used = [i for i, out in enumerate(s.outs) if out]
        if used and not self.array_mode and self._set_unchecked(s):
            names = {}
            for i in used:
                names[i] = self.fresh(s.outs[i])
                self.results[(s.call_id, i)] = (names[i], rets[i])
            target = names[0] if len(rets) == 1 else \
                "(" + ", ".join(names.get(i, "") for i in range(len(rets))) + ")"
            return self._unchecked([f"{rets[i].solidity()} {names[i]};" for i in used],
                                   lambda: f"{target} = {self._call_text(s)};", ind)
        call = self._call_text(s)
        if not used:
            return [_i(ind) + call + ";"]
        if self.array_mode:
            # the values in typed locals of a block of their own, their words
            # in the memory array of the locals
            names = {i: self.fresh(f"r{i}") for i in used}
            if len(rets) == 1:
                lines = [_i(ind + 1) + f"{rets[0].solidity()} {names[0]} = {call};"]
            else:
                decl = ", ".join(f"{rets[i].solidity()} {names[i]}" if i in names else "" for i in range(len(rets)))
                lines = [_i(ind + 1) + f"({decl}) = {call};"]
            for i in used:
                slot = self.local(f"c{s.call_id}_r{i}")
                lines.append(_i(ind + 1) + f"{slot} = {self._word_of(names[i], rets[i])};")
                self.results[(s.call_id, i)] = (slot, None)
            return [_i(ind) + "{"] + lines + [_i(ind) + "}"]
        names = {}
        for i in used:
            names[i] = self.fresh(s.outs[i])
            self.results[(s.call_id, i)] = (names[i], rets[i])
        if len(rets) == 1:
            return [_i(ind) + f"{rets[0].solidity()} {names[0]} = {call};"]
        decl = ", ".join(f"{rets[i].solidity()} {names[i]}" if i in names else "" for i in range(len(rets)))
        return [_i(ind) + f"({decl}) = {call};"]

    def s_Forward(self, s, ind):
        impl = next((n for n in ("implementation", "impl") if n not in self.taken and not reserved_name(n)), None)
        impl = self.fresh(impl or "implementation")  # (a contract with an `implementation()` getter: impl)
        ok = self.fresh("ok")  # (an assembly variable must not shadow a name of the function or contract)
        lines = [
            f"address {impl} = {self.addr(s.to)};",
            "// the standard proxy forwarder: delegatecall with the whole calldata, then",
            "// return the return data, or revert with it when the call failed",
            "assembly {",
            "    calldatacopy(0, 0, calldatasize())",
            f"    let {ok} := delegatecall(gas(), {impl}, 0, calldatasize(), 0, 0)",
            "    returndatacopy(0, 0, returndatasize())",
            f"    switch {ok}",
            "    case 0 { revert(0, returndatasize()) }",
            "    default { return(0, returndatasize()) }",
            "}",
        ]
        return [_i(ind) + line for line in lines]

    def s_Transfer(self, s, ind):
        if s.send and s.ok is not None and not self.array_mode and self._set_unchecked(s):
            ok = self.fresh(s.ok)
            self.declared_ok[s.call_id] = ok
            return self._unchecked([f"bool {ok};"],
                                   lambda: f"{ok} = payable({self.addr(s.to)}).send({_strip(self.w(s.value))});", ind)
        target = f"payable({self.addr(s.to)})"
        value = _strip(self.w(s.value))
        if not s.send:
            return [_i(ind) + f"{target}.transfer({value});"]
        if s.ok is None:
            return [_i(ind) + f"{target}.send({value});"]
        if self.array_mode:
            return [_i(ind) + f"{self.call_ok(s.call_id)} = {target}.send({value});"]
        ok = self.fresh(s.ok)
        self.declared_ok[s.call_id] = ok
        return [_i(ind) + f"bool {ok} = {target}.send({value});"]

    def s_Create(self, s, ind):
        a = self.call_addr(s.call_id)
        if s.salt is None:
            call = f"{self.h.use('_create')}({_strip(self.w(s.value))}, {self.bytes_(s.code)})"
        else:
            call = f"{self.h.use('_create2')}({_strip(self.w(s.value))}, {self.bytes_(s.code)}, {_strip(self.w(s.salt))})"
        return [_i(ind) + f"{a} = {call};"]

    def s_Precompile(self, s, ind):
        ok = self.call_ok(s.call_id)
        out = [_i(ind) + f"({ok}, ) = address({s.address}).staticcall({self.bytes_(s.args)});"]
        if s.output is not None:
            out.append(_i(ind) + f"{self.local(s.output)} = {self.h.use('_returndataWord')}(0);")
        return out

    def s_SelfDestruct(self, s, ind):
        return [_i(ind) + f"selfdestruct(payable({self.addr(s.beneficiary)}));"]

    def s_Return(self, s, ind):
        e = self.entry
        if s.values is not None:
            if e.kind != "internal" and e.returns and len(e.returns) == len(s.values):
                vals = [self.dynamic_value(v, t) if t.kind in ("dynbytes", "string") else self.typed(v, t)
                        for v, t in zip(s.values, e.returns)]
                return [_i(ind) + "return " + (vals[0] if len(vals) == 1 else "(" + ", ".join(vals) + ")") + ";"]
            # no matching declaration: the same bytes, one word per value (a
            # byte string encodes as a dynamic value either way)
            words = ", ".join(self.bytes_(v) if isinstance(v, ir.Bytes) else _strip(self.w(v)) for v in s.values)
            return [_i(ind) + f"{self.h.use('_return')}(abi.encode({words}));"]
        if e.returns and s.data is not None:  # (returns=(): a `bytes memory` the body never sets)
            words = _words(s.data)
            if words is not None and len(words) == len(e.returns):
                vals = [self.typed(v, t) for v, t in zip(words, e.returns)]
                return [_i(ind) + "return " + (vals[0] if len(vals) == 1 else "(" + ", ".join(vals) + ")") + ";"]
        if s.data is None or (isinstance(s.data, ir.Blob) and not s.data.parts):
            if e.kind == "fallback" and e.returns == ():
                return [_i(ind) + 'return "";']  # the fallback's `bytes memory`, empty
            if e.kind == "internal" or e.returns is not None:
                return [_i(ind) + f"{self.h.use('_return')}(\"\");"]
            return [_i(ind) + "return;"]
        return [_i(ind) + f"{self.h.use('_return')}({self.bytes_(s.data)});"]

    def typed(self, v: ir.Expr, t: SolType) -> str:
        """The word v as a Solidity value of type t (a value type; v is a
        valid t value: types.fits(v, t), or the producer's guarantee)."""
        r = _cleaned(v, t)
        if isinstance(r, ir.Result) and _value_type(r.ty) == t:
            got = self.results.get((r.call_id, r.index))
            if got is not None and got[1] is not None:
                return self._result_text((r.call_id, r.index))  # the value the call returned, itself
        w = _head_word(r)
        if w is not None and w in self.entry.word_params and self.entry.word_params[w][1].canonical == t.canonical:
            # the declared parameter itself (the word, or t's cleanup of it,
            # which is the word: the decoder rejected any other)
            return self.entry.word_params[w][0]
        if isinstance(v, ir.StateRef) and _value_type(v.ty) == t:
            return self._state_path(v)  # a state variable of that type: itself
        if isinstance(v, ir.Typed) and _value_type(v.ty) == t and self._typed_here(v):
            return _strip(self._typed_value(v, t))  # an operation of that type: its value
        c = v.value if isinstance(v, ir.Const) else None
        if c is not None and t.kind == "bool" and c in (0, 1):
            return "true" if c else "false"
        if t.kind == "address":
            return self.addr(v)
        if t.kind == "bool":
            return _strip(self.b(v))
        if t.kind == "bytes" and isinstance(v, ir.Const) and (v.value >> (256 - t.bits)) << (256 - t.bits) == v.value \
                and t.bits != 160:
            # a hex literal of exactly 2N digits is a bytesN value (not 40 digits: an address literal)
            return f"bytes{t.bits // 8}(0x{v.value >> (256 - t.bits):0{t.bits // 4}x})"
        if c is not None and t.kind == "uint" and t.bits < 256 and c < 1 << t.bits:
            # a literal that fits converts as it is: uint8(64), type(uint64).max
            top = max_literal(c)
            return top if top == f"type({t.canonical}).max" else f"{t.canonical}({literal(c)})"
        if c is not None and t.kind == "int" and -(1 << (t.bits - 1)) <= ir.to_signed(c) < 1 << (t.bits - 1):
            s = ir.to_signed(c)
            return f"{t.canonical}({s})" if s >= 0 else f"{t.canonical}(-{literal(-s)})"
        if t.kind in ("uint", "int", "bytes") and not (t.kind == "uint" and t.bits == 256):
            return self._of_word(self._shift_base(v), t)
        return _strip(self.w(v))

    def s_Revert(self, s, ind):
        p = s.payload
        if isinstance(p, ir.Empty):
            return [_i(ind) + "revert();"]
        if isinstance(p, ir.ErrorString):
            return [_i(ind) + f"revert({string_literal(p.message)});"]
        if isinstance(p, ir.Panic):
            return [_i(ind) + f"{self.h.use('_panic')}({literal(p.code)});"]
        if isinstance(p, ir.Custom):
            parts = (ir.WordBytes(ir.Const(p.selector), 4),) + tuple(p.args)
            return [_i(ind) + f"{self.h.use('_revert')}({self.bytes_(ir.Blob(parts))});"]
        if isinstance(p, ir.Raw):
            return [_i(ind) + f"{self.h.use('_revert')}({self.bytes_(p.data)});"]
        if isinstance(p, ir.Bubble):
            return [_i(ind) + f"{self.h.use('_bubble')}();"]
        if isinstance(p, ir.NamedError):
            args = self._error_args(p)
            if args is not None:
                self.ctx.need("custom errors", (0, 8, 4))
                return [_i(ind) + f"revert {p.name}({', '.join(args)});"]
        self.flags.add("unstructured")
        return [_i(ind) + 'revert("scobelix: unsupported construct");']

    def _error_args(self, p: ir.NamedError) -> Optional[List[str]]:
        """The arguments of `revert Name(...)` in the error's parameter types."""
        if len(p.args) != len(p.types):
            return None
        out = []
        for a, ty in zip(p.args, p.types):
            if ty in ("string", "bytes"):
                if not isinstance(a, ir.Bytes):
                    return None
                out.append(self.dynamic_value(a, parse_type(ty)))
                continue
            t = _value_type(ty)
            if t is None or not isinstance(a, ir.Expr):
                return None
            out.append(self.typed(a, t))
        return out

    def s_Stop(self, s, ind):
        e = self.entry
        if e.kind == "fallback" and e.returns == ():
            return [_i(ind) + 'return "";']  # the fallback's `bytes memory`, empty: as STOP
        if e.kind == "internal" or e.returns is not None:
            return [_i(ind) + f"{self.h.use('_stop')}();"]
        return [_i(ind) + "return;"]

    def s_Invalid(self, s, ind):
        return [_i(ind) + f"{self.h.use('_invalid')}();"]

    def s_Require(self, s, ind):
        # require(c) / require(c, "...") / assert(c) revert with exactly the
        # payloads Empty / Error(string) / Panic(0x01) (solc >= 0.8)
        p = s.payload
        if isinstance(p, ir.Empty):
            return [_i(ind) + f"require({_strip(self.b(s.cond))});"]
        if isinstance(p, ir.ErrorString):
            return [_i(ind) + f"require({_strip(self.b(s.cond))}, {string_literal(p.message)});"]
        if isinstance(p, ir.Panic) and p.code == 1:
            return [_i(ind) + f"assert({_strip(self.b(s.cond))});"]
        inner = self.s_Revert(ir.Revert(p), ind + 1)
        return [_i(ind) + f"if ({_strip(self._iszero(s.cond))}) {{"] + inner + [_i(ind) + "}"]

    def s_Assert(self, s, ind):
        return [_i(ind) + f"assert({_strip(self.b(s.cond))});"]

    def s_Unstructured(self, s, ind):
        self.flags.add("unstructured")
        why = comment_text(s.reason or "unsupported", 100)
        return [_i(ind) + f"// scobelix: not translated ({why}): {comment_text(s.raw, 120)}",
                _i(ind) + 'revert("scobelix: unsupported construct");']

    # ------------------------------------------------------------ the function

    def _tail(self, stmts: Tuple[ir.Stmt, ...]) -> Tuple[ir.Stmt, ...]:
        """`stmts` (the end of the function) without the STOP the text would
        end with: falling off the end of a function that s_Stop writes as
        `return;` is the same empty success.  The else-branch of an `if`
        whose then-branch never falls through is written after it (s_If):
        its end is the end of the text."""
        if not stmts:
            return stmts
        last = stmts[-1]
        if isinstance(last, ir.Stop):
            return stmts[:-1]
        if isinstance(last, ir.If) and _moot(last):
            same = self._tail(last.then)  # (a moot test: written once)
            return stmts[:-1] + (dataclasses.replace(last, then=same, orelse=same),)
        if isinstance(last, ir.If) and last.orelse and _terminates(last.then):
            return stmts[:-1] + (dataclasses.replace(last, orelse=self._tail(last.orelse)),)
        return stmts

    def render(self, indent: int) -> List[str]:
        stmts = self.fn.body
        e = self.entry
        if not (e.kind == "fallback" and e.returns == ()) and e.kind != "internal" and e.returns is None:
            stmts = self._tail(stmts)  # (s_Stop: `return;`)
        # one `unchecked` block around the body unless it has checked
        # operations (then the wrapping statements have blocks of their own)
        # or no arithmetic that Solidity would check
        wrap = not self.checked and self.facts(stmts)[1]
        inner = indent + 1 if wrap else indent
        body = self.block(stmts, inner)
        decls = list(self.decls)
        if self.array_mode:
            names = ", ".join(n for n, v in self.locals.items() if v.startswith("_l["))
            if self.n_bools:
                decls.insert(0, f"bool[{self.n_bools}] memory _ok; // call results")
            if self.n_words:
                decls.insert(0, f"uint256[{self.n_words}] memory _l; // locals (in memory: too many for the stack)"
                                f" {names}"[:200])
        if self.memory:
            decls.insert(0, "bytes memory _vm; // the original code's memory (emulated)")
        lines = [_i(inner) + d for d in decls] + body
        if not wrap:
            return lines
        return [_i(indent) + "unchecked {"] + lines + [_i(indent) + "}"]


def _difference(e) -> Optional[Tuple[ir.Expr, ir.Expr]]:
    """(a, b) when `e` is the word a - b (`sub`, or `add(a, mul(-1, b))` /
    `add(a, K)` with K >= 2**255): zero exactly when a == b, so a test of
    the difference reads as an equality."""
    out = None
    if isinstance(e, ir.Op) and e.op == "sub":
        out = e.args[0], e.args[1]
    elif isinstance(e, ir.Op) and e.op == "add" and len(e.args) == 2:
        for a, b in ((e.args[0], e.args[1]), (e.args[1], e.args[0])):
            if _negation(b) is not None:
                out = a, _negation(b)
                break
            if isinstance(b, ir.Const) and b.value >> 255 and not isinstance(a, ir.Const):
                out = a, ir.Const(ir.WORD_MOD - b.value)
                break
    if out is not None and isinstance(out[0], ir.Const) and not isinstance(out[1], ir.Const):
        out = out[1], out[0]  # the constant on the right: x == 7
    return out


def _negation(e) -> Optional[ir.Expr]:
    """y when `e` is the word -y written `mul(-1, y)` (either operand order)."""
    if isinstance(e, ir.Op) and e.op == "mul" and len(e.args) == 2:
        if _const(e.args[0]) == ir.WORD_MAX:
            return e.args[1]
        if _const(e.args[1]) == ir.WORD_MAX:
            return e.args[0]
    return None


def _depends(a: ir.Assign, target: ir.Expr) -> bool:
    """True if assignment `a` reads what an assignment to `target` writes."""
    nodes = list(ir.walk(a.value))
    if a.op is not None or isinstance(a.target, ir.StateRef):
        nodes.extend(ir.walk(a.target))  # target op= value, and the keys of a target path
    if isinstance(target, ir.Local):
        return any(isinstance(n, ir.Local) and n.name == target.name for n in nodes)
    return any(isinstance(n, (ir.StateRef, ir.Sload)) for n in nodes)


_ENDS = (ir.Return, ir.Revert, ir.Stop, ir.Invalid, ir.SelfDestruct, ir.Unstructured, ir.Continue, ir.Break,
         ir.Forward)


def _terminates(block: Sequence[ir.Stmt]) -> bool:
    """Control never falls out of `block` (every path ends in a terminator,
    a continue or a break)."""
    if not block:
        return False
    last = block[-1]
    if isinstance(last, _ENDS):
        return True
    if isinstance(last, ir.If):
        return _terminates(last.then) and _terminates(last.orelse)
    if isinstance(last, ir.Require):
        return False
    return False


def _words(data: ir.Bytes) -> Optional[List[ir.Expr]]:
    parts = data.parts if isinstance(data, ir.Blob) else (data,)
    out = []
    for p in parts:
        if not (isinstance(p, ir.WordBytes) and p.width == 32):
            return None
        out.append(p.value)
    return out


def _i(n: int) -> str:
    return "    " * n


def render_function_body(fn: ir.Function, entry: EntryRender, ctx: RenderContext,
                         indent: int = 2) -> Tuple[List[str], Set[str]]:
    """The lines of `fn`'s body (inside the function's braces) and the
    flags rendering added ("unstructured" when something had no
    translation)."""
    r = _FunctionRenderer(fn, entry, ctx)
    lines = r.render(indent)
    return lines, r.flags

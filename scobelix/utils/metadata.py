"""
Compiler metadata trailer of EVM runtime bytecode (solc CBOR / Vyper).

solc appends a CBOR-encoded map to the code it emits, followed by the
big-endian 2-byte length of that map. The trailer is data, not code: it must
not be disassembled, and it is the only place where the bytecode says which
compiler (and, for solc >= 0.5.9, which exact version) produced it.

Formats observed on real compilers:

  solc 0.4.7 .. 0.5.8   a1 65"bzzr0" 5820<32B>                      0029
          + experimental a2 65"bzzr0" 5820<32B> 6c"experimental" f5  0037
  solc 0.5.9 .. 0.5.17  a2 65"bzzr1" 5820<32B> 64"solc" 43<M m p>    0032
  solc >= 0.6.0         a2 64"ipfs"  5822 1220<32B> 64"solc" 43<M m p> 0033
     --metadata-hash none            a1 64"solc" 43<M m p>          000a
     --metadata-hash swarm           a2 65"bzzr1" ...  64"solc" ... 0032
     --no-cbor-metadata (>=0.8.18)   nothing at all
  "solc" is a 3-byte string for release builds and a text string for
  prerelease / nightly builds (e.g. "0.8.20-nightly.2023.1.1+commit.xxx").

  vyper <= 0.3.3        nothing
  vyper 0.3.4           a1 65"vyper" 83 00 03 04          (no length suffix)
  vyper 0.3.6 .. 0.3.9  a1 65"vyper" 83 00 03 0X          000b
  vyper >= 0.3.10       nothing in the runtime; the initcode ends (after the
                        runtime and its data section) with a CBOR array
                        [runtime_size, [data_sizes], immutables_size,
                        {"vyper": [M, m, p]}] (>= 0.4.1: a 32-byte integrity
                        hash first) and a 2-byte length that counts itself.

Before 0.5.9 the trailer carries no version. The byte right before it is
STOP (0x00) for solc 0.4.x and INVALID (0xfe) for 0.5.x, which gives a
version range.

Dependency-free: a small CBOR subset decoder is enough, since the trailer
only ever holds maps/arrays of text keys, byte strings, small integers,
text and booleans.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any, List, Optional, Tuple, Union

# Nesting deeper than this is never produced by a compiler; the limit keeps a
# crafted trailer from exhausting the recursion budget.
_MAX_DEPTH = 8

_SOLC_KEYS = {"ipfs", "bzzr0", "bzzr1", "solc", "experimental"}


class CBORError(ValueError):
    pass


def _cbor_decode(buf: bytes, i: int = 0, depth: int = 0) -> Tuple[Any, int]:
    """Decodes one CBOR item at buf[i:]; returns (value, next_index)."""
    if depth > _MAX_DEPTH:
        raise CBORError("nesting too deep")
    if i >= len(buf):
        raise CBORError("truncated")
    ib = buf[i]
    major, info = ib >> 5, ib & 0x1F
    i += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        if i + n > len(buf):
            raise CBORError("truncated argument")
        arg = int.from_bytes(buf[i : i + n], "big")
        i += n
    else:
        # indefinite lengths and reserved values are never emitted by compilers
        raise CBORError("unsupported additional info %d" % info)

    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major in (2, 3):
        if i + arg > len(buf):
            raise CBORError("truncated string")
        raw = bytes(buf[i : i + arg])
        i += arg
        if major == 3:
            try:
                return raw.decode("utf-8"), i
            except UnicodeDecodeError as e:
                raise CBORError("bad utf-8") from e
        return raw, i
    if major == 4:
        out = []
        for _ in range(arg):
            v, i = _cbor_decode(buf, i, depth + 1)
            out.append(v)
        return out, i
    if major == 5:
        res = {}
        for _ in range(arg):
            k, i = _cbor_decode(buf, i, depth + 1)
            v, i = _cbor_decode(buf, i, depth + 1)
            if not isinstance(k, (str, int)):
                raise CBORError("unhashable key")
            res[k] = v
        return res, i
    if major == 7:
        if info == 20:
            return False, i
        if info == 21:
            return True, i
        if info == 22:
            return None, i
        raise CBORError("unsupported simple value %d" % info)
    raise CBORError("unsupported major type %d" % major)


def cbor_loads_exact(buf: bytes) -> Any:
    """Decodes `buf`, which must hold exactly one CBOR item."""
    v, end = _cbor_decode(buf, 0)
    if end != len(buf):
        raise CBORError("trailing bytes (%d)" % (len(buf) - end))
    return v


def _json_safe(obj: Any) -> Any:
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return obj


@dataclasses.dataclass
class Metadata:
    compiler: str  # "solc" | "vyper"
    version: Optional[str]  # exact "0.8.19" when encoded, else None
    version_range: Optional[Tuple[str, str]]  # when only a range can be inferred
    prerelease: Optional[str]  # full text of a non-release "solc" entry
    hash_kind: Optional[str]  # "ipfs" | "bzzr0" | "bzzr1" | None
    hash_hex: Optional[str]
    experimental: bool
    start: int  # offset of the first byte of the trailer (CBOR + length)
    end: int  # == len(code) for the outer trailer
    raw: Any  # decoded CBOR

    @property
    def length(self) -> int:
        return self.end - self.start

    def to_dict(self) -> dict:
        """JSON-safe view (byte strings as hex)."""
        return {
            "compiler": self.compiler,
            "version": self.version,
            "version_range": list(self.version_range) if self.version_range else None,
            "prerelease": self.prerelease,
            "hash_kind": self.hash_kind,
            "hash": self.hash_hex,
            "experimental": self.experimental,
            "offset": self.start,
            "length": self.length,
            "raw": _json_safe(self.raw),
        }


def _solc_meta(m: dict, start: int, end: int, prev_byte: Optional[int]) -> Optional[Metadata]:
    if not m or not set(m) <= _SOLC_KEYS:
        return None
    version = prerelease = None
    vrange = None
    solc = m.get("solc")
    if isinstance(solc, bytes) and len(solc) == 3:
        version = "%d.%d.%d" % tuple(solc)
    elif isinstance(solc, str):
        prerelease = solc
        mm = re.match(r"(\d+\.\d+\.\d+)", solc)
        version = mm.group(1) if mm else None
    elif solc is None:
        if "bzzr0" in m:
            vrange = ("0.5.0", "0.5.8") if prev_byte == 0xFE else ("0.4.7", "0.4.26")
    else:
        return None
    kind = next((k for k in ("ipfs", "bzzr1", "bzzr0") if k in m), None)
    h = m.get(kind) if kind else None
    if kind and not isinstance(h, bytes):
        return None
    return Metadata(
        compiler="solc",
        version=version,
        version_range=vrange,
        prerelease=prerelease,
        hash_kind=kind,
        hash_hex=h.hex() if isinstance(h, bytes) else None,
        experimental=bool(m.get("experimental", False)),
        start=start,
        end=end,
        raw=m,
    )


def _vyper_meta(obj: Any, start: int, end: int) -> Optional[Metadata]:
    d = None
    if isinstance(obj, dict) and set(obj) == {"vyper"}:
        d = obj
    elif isinstance(obj, list) and obj and isinstance(obj[-1], dict) and set(obj[-1]) == {"vyper"}:
        d = obj[-1]
    if d is None or not isinstance(d["vyper"], list):
        return None
    if not all(isinstance(x, int) for x in d["vyper"]):
        return None
    return Metadata(
        compiler="vyper",
        version=".".join(str(x) for x in d["vyper"]),
        version_range=None,
        prerelease=None,
        hash_kind=None,
        hash_hex=None,
        experimental=False,
        start=start,
        end=end,
        raw=obj,
    )


def _as_bytes(code: Union[bytes, bytearray, str, List[int]]) -> bytes:
    if isinstance(code, str):
        code = code.strip()
        if code[:2] in ("0x", "0X"):
            code = code[2:]
        return bytes.fromhex(code)
    return bytes(code)


def parse_metadata(code) -> Optional[Metadata]:
    """Parses the trailer at the very end of `code` (runtime or initcode).

    `code` is bytes, a list of byte values or a hex string. Returns None when
    the code does not end with a recognised trailer.
    """
    code = _as_bytes(code)
    n = len(code)
    # 1. length-suffixed trailer (solc >= 0.4.7, vyper 0.3.6..0.3.9 and
    #    >= 0.3.10 initcode). solc and vyper < 0.3.10 count the CBOR bytes
    #    only; vyper >= 0.3.10 counts the 2-byte suffix too.
    if n >= 2:
        ln = int.from_bytes(code[-2:], "big")
        for start in (n - 2 - ln, n - ln):
            if not (0 <= start < n - 2) or ln == 0:
                continue
            try:
                obj = cbor_loads_exact(code[start : n - 2])
            except CBORError:
                continue
            prev = code[start - 1] if start > 0 else None
            md = None
            if isinstance(obj, dict):
                md = _solc_meta(obj, start, n, prev)
            md = md or _vyper_meta(obj, start, n)
            if md:
                return md
    # 2. vyper 0.3.4: unsuffixed `a1 65 "vyper" 83 M m p` (M, m, p < 24)
    if n >= 11 and code[-11:-3] == bytes.fromhex("a1657679706572") + b"\x83":
        if all(b < 24 for b in code[-3:]):
            return _vyper_meta({"vyper": list(code[-3:])}, n - 11, n)
    return None


def strip_metadata(code) -> Tuple[bytes, Optional[Metadata]]:
    """Returns (code without the outer trailer, metadata or None)."""
    code = _as_bytes(code)
    md = parse_metadata(code)
    return (code[: md.start] if md else code), md


# Embedded trailers: a runtime that does `new Child()` or reads
# `type(C).creationCode` contains the child's whole initcode, i.e. the
# child's runtime AND its trailer, before its own trailer.
_EMBEDDED_PATTERNS = [
    re.compile(
        re.escape(bytes.fromhex("a2646970667358221220"))
        + rb".{32}"
        + re.escape(b"\x64solcC")
        + rb".{3}\x00\x33",
        re.S,
    ),
    re.compile(
        re.escape(bytes.fromhex("a265627a7a72315820"))
        + rb".{32}"
        + re.escape(b"\x64solcC")
        + rb".{3}\x00\x32",
        re.S,
    ),
    re.compile(re.escape(bytes.fromhex("a165627a7a72305820")) + rb".{32}\x00\x29", re.S),
    re.compile(
        re.escape(bytes.fromhex("a265627a7a72305820"))
        + rb".{32}"
        + re.escape(b"\x6cexperimental\xf5")
        + rb"\x00\x37",
        re.S,
    ),
    re.compile(
        re.escape(bytes.fromhex("a3"))
        + rb"\x65bzzr1\x58\x20.{32}\x6cexperimental\xf5\x64solcC.{3}\x00\x40",
        re.S,
    ),
    re.compile(re.escape(b"\xa1\x64solcC") + rb".{3}\x00\x0a", re.S),
]


def find_all_metadata(code) -> List[Tuple[int, int]]:
    """All (start, end) byte ranges that look like a solc trailer, outer and embedded."""
    code = _as_bytes(code)
    spans = set()
    for pat in _EMBEDDED_PATTERNS:
        for m in pat.finditer(code):
            spans.add((m.start(), m.end()))
    md = parse_metadata(code)
    if md:
        spans.add((md.start, md.end))
    return sorted(spans)

"""
Runtime bytecode normalisation and comparison (L4: "bytecode-identical modulo
metadata, immutables and link placeholders"), plus the L4 settings search.

Masking before a comparison:
  * every CBOR metadata trailer (the outer one is dropped, embedded ones -
    the initcode of a `new Child()` carries its own - are zeroed);
  * immutable spans (`immutableReferences`: solc leaves zeros there, the
    deployed code holds the values);
  * library link placeholders (`linkReferences`);
  * the deployed-library call guard `PUSH20 <own address> ADDRESS EQ` at
    offset 0 (solc emits zeros, the deployer patches the real address).

`compare_runtime` reports byte identity and, on mismatch, two difflib
similarity ratios: over the opcode sequence and over (opcode, push argument)
pairs (`instr_similarity`).  A search over compiler settings that keeps the
variant with the highest similarity is how L4 is approached.
"""

from __future__ import annotations

import dataclasses
import difflib
import time
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from scobelix.utils.metadata import find_all_metadata

from .solc import (
    CompilationError,
    Settings,
    SolcNotFound,
    compile_standard_json,
    optimizer_variants,
)

__all__ = [
    "BytecodeComparison",
    "L4Search",
    "compare_runtime",
    "disasm",
    "immutable_spans",
    "instr_sim",
    "library_self_address_span",
    "link_spans",
    "mask",
    "own_code",
    "patch_immutables",
    "push_values",
    "read_immutables",
    "search_l4",
    "shifted_push_values",
    "strip_all_metadata",
    "to_bytes",
]

Span = Tuple[int, int]
Instr = Tuple[int, int, Optional[int]]  # (pc, opcode, push argument or None)


def to_bytes(code: Union[bytes, bytearray, memoryview, str]) -> bytes:
    """Bytecode from bytes or a hex string (optional 0x prefix, surrounding whitespace ignored)."""
    if isinstance(code, (bytes, bytearray, memoryview)):
        return bytes(code)
    text = code.strip()
    if text[:2] in ("0x", "0X"):
        text = text[2:]
    return bytes.fromhex(text)


def disasm(code: bytes) -> List[Instr]:
    """Linear sweep; a PUSH truncated by the end of the code is zero-padded."""
    out: List[Instr] = []
    i, n = 0, len(code)
    while i < n:
        op = code[i]
        if 0x60 <= op <= 0x7F:
            width = op - 0x5F
            out.append(
                (i, op, int.from_bytes(code[i + 1 : i + 1 + width].ljust(width, b"\0"), "big"))
            )
            i += 1 + width
        else:
            out.append((i, op, None))
            i += 1
    return out


def immutable_spans(
    immutable_refs: Optional[Mapping[str, Sequence[Mapping[str, int]]]],
) -> List[Span]:
    return sorted(
        (r["start"], r["start"] + r["length"])
        for refs in (immutable_refs or {}).values()
        for r in refs
    )


def link_spans(
    link_refs: Optional[Mapping[str, Mapping[str, Sequence[Mapping[str, int]]]]],
) -> List[Span]:
    return sorted(
        (r["start"], r["start"] + r["length"])
        for libs in (link_refs or {}).values()
        for refs in libs.values()
        for r in refs
    )


def library_self_address_span(code: bytes) -> List[Span]:
    """Deployed libraries start with PUSH20 <own address> ADDRESS EQ (delegatecall guard)."""
    if len(code) > 22 and code[0] == 0x73 and code[21] == 0x30 and code[22] == 0x14:
        return [(1, 21)]
    return []


def mask(code: bytes, spans: Iterable[Span]) -> bytes:
    """Zeroes the given [start, end) byte ranges (ranges past the end are clipped)."""
    out = bytearray(code)
    for start, end in spans:
        start, end = max(0, start), min(len(out), end)
        if start < end:
            out[start:end] = bytes(end - start)
    return bytes(out)


def strip_all_metadata(code: bytes) -> bytes:
    """Zeroes every embedded metadata trailer and drops the outer one."""
    spans = find_all_metadata(code)
    out = mask(code, spans)
    if spans and spans[-1][1] == len(code):
        out = out[: spans[-1][0]]
    return out


# PUSH1 0x80/0x60 PUSH1 0x40 MSTORE
_INITCODE_PROLOGUES = (
    b"\x60\x80\x60\x40\x52",
    b"\x60\x60\x60\x40\x52",
)


def own_code(code: bytes) -> bytes:
    """
    The contract's own instructions: the runtime without its metadata and
    without the initcode of the contracts it creates (`new C()` embeds C's
    whole initcode, with its own dispatcher and trailer, after the code).
    The cut is the first solc initcode prologue before the first embedded
    trailer (or that trailer itself).
    """
    spans = find_all_metadata(code)
    outer = spans[-1] if spans and spans[-1][1] == len(code) else None
    embedded = [sp for sp in spans if sp != outer]
    end = outer[0] if outer else len(code)
    if embedded:
        first = embedded[0][0]
        starts = [i for p in _INITCODE_PROLOGUES for i in [code.find(p, 1, first)] if i > 0]
        end = min(starts) if starts else first
    return bytes(code[:end])


def push_values(code: bytes) -> List[int]:
    """Every PUSH1..PUSH32 argument outside metadata trailers, in code order (with repeats)."""
    return [arg for _, op, arg in disasm(strip_all_metadata(code)) if arg is not None]


_WORD = (1 << 256) - 1
# what solc's constant optimiser computes a constant with (top of the stack first: a, then b)
_CONST_OPS = {
    0x01: lambda a, b: a + b,
    0x02: lambda a, b: a * b,
    0x03: lambda a, b: a - b,
    0x04: lambda a, b: a // b if b else 0,
    0x0A: lambda a, b: pow(a, b, 1 << 256),
    0x16: lambda a, b: a & b,
    0x17: lambda a, b: a | b,
    0x18: lambda a, b: a ^ b,
    0x1B: lambda a, b: b << a if a < 256 else 0,
    0x1C: lambda a, b: b >> a if a < 256 else 0,
}


def computed_values(code: bytes, window: int = 8) -> List[int]:
    """
    Every word the code computes from constants alone within `window`
    instructions of a PUSH (PUSH / DUP / SWAP and ADD MUL SUB DIV EXP AND OR
    XOR NOT SHL SHR on those values only), in code order: how solc's constant
    optimiser writes a constant cheaper than its PUSH - an error selector as
    `~((c << s) - 1)`, a mask as `2**n - 1`...
    """
    ins = disasm(strip_all_metadata(code))
    out: List[int] = []
    for i, (_, op, first) in enumerate(ins):
        if first is None and op != 0x5F:
            continue
        stack = [first or 0]
        for _, op, arg in ins[i + 1 : i + window]:
            if arg is not None or op == 0x5F:  # PUSHn, PUSH0
                stack.append(arg or 0)
                continue
            if op == 0x19 and stack:  # NOT
                stack[-1] = ~stack[-1] & _WORD
            elif op in _CONST_OPS and len(stack) >= 2:
                a, b = stack.pop(), stack.pop()
                stack.append(_CONST_OPS[op](a, b) & _WORD)
            elif 0x80 <= op <= 0x8F and len(stack) > op - 0x80:  # DUPn
                stack.append(stack[-(op - 0x7F)])
            elif 0x90 <= op <= 0x9F and len(stack) > op - 0x8F:  # SWAPn
                n = op - 0x8F
                stack[-1], stack[-1 - n] = stack[-1 - n], stack[-1]
            else:
                break
            out.append(stack[-1])
    return out


def shifted_push_values(code: bytes) -> List[int]:
    """Every word the code builds as `PUSH c, PUSH s, SHL` (c << s), in code
    order: how solc's constant optimiser writes a constant that ends in zero
    bits.  A left-aligned selector with an even last byte is pushed halved
    and shifted by one more bit, so neither it nor its 32-byte form is a
    PUSH argument."""
    ins = disasm(strip_all_metadata(code))
    out = []
    for (_, _, value), (_, _, shift), (_, op, _) in zip(ins, ins[1:], ins[2:]):
        if value is not None and shift is not None and op == 0x1B and shift < 256:
            out.append((value << shift) & ((1 << 256) - 1))
    return out


@dataclasses.dataclass
class BytecodeComparison:
    identical: bool  # byte-identical after masking
    same_length: bool
    opcode_similarity: float  # difflib ratio over the opcode sequence (push arguments ignored)
    instr_similarity: float  # difflib ratio over (opcode, push argument) pairs
    first_diff: Optional[int]  # first differing byte offset of the masked codes
    len_original: int
    len_candidate: int

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _similarity(a: Sequence[Instr], b: Sequence[Instr]) -> Tuple[float, float]:
    """(opcode ratio, instruction ratio) of two disassemblies."""
    ops = difflib.SequenceMatcher(
        None, [x[1] for x in a], [x[1] for x in b], autojunk=False
    ).ratio()
    ins = difflib.SequenceMatcher(
        None, [(x[1], x[2]) for x in a], [(x[1], x[2]) for x in b], autojunk=False
    ).ratio()
    return round(ops, 4), round(ins, 4)


def compare_runtime(
    original: Union[bytes, str],
    compiled: Union[bytes, str],
    immutable_refs: Optional[dict] = None,
    link_refs: Optional[dict] = None,
) -> BytecodeComparison:
    """
    Compares a deployed runtime with a compiled one.  `immutable_refs` /
    `link_refs` are the compiled artifact's references; their spans are
    masked on both sides (meaningful when the two codes line up).
    """
    original, compiled = to_bytes(original), to_bytes(compiled)
    spans = (
        immutable_spans(immutable_refs)
        + link_spans(link_refs)
        + library_self_address_span(compiled)
    )
    a = strip_all_metadata(mask(original, spans))
    b = strip_all_metadata(mask(compiled, spans))
    if a == b:
        return BytecodeComparison(True, True, 1.0, 1.0, None, len(a), len(b))
    first = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
    ops, ins = _similarity(disasm(a), disasm(b))
    return BytecodeComparison(False, len(a) == len(b), ops, ins, first, len(a), len(b))


def instr_sim(original: Union[bytes, str], compiled: Union[bytes, str]) -> float:
    """
    Similarity of two runtimes over their (opcode, push argument) sequences,
    metadata masked: 1.0 when identical.  The figure an L4 search maximises.
    """
    return compare_runtime(original, compiled).instr_similarity


def read_immutables(
    original_runtime: bytes, immutable_refs: Mapping[str, Sequence[Mapping[str, int]]]
) -> Dict[str, bytes]:
    """
    The deployed value of each immutable (AST id -> bytes), read from the
    original at the candidate's reference offsets.  Only meaningful when both
    codes line up, i.e. after a masked comparison found them identical.
    """
    out: Dict[str, bytes] = {}
    for ast_id, refs in immutable_refs.items():
        if refs:
            start, length = refs[0]["start"], refs[0]["length"]
            out[ast_id] = bytes(original_runtime[start : start + length])
    return out


def patch_immutables(
    runtime: bytes,
    immutable_refs: Mapping[str, Sequence[Mapping[str, int]]],
    values: Mapping[str, Union[int, bytes]],
) -> bytes:
    """Writes values[ast_id] (int or big-endian bytes) at every reference of that immutable."""
    out = bytearray(runtime)
    for ast_id, refs in immutable_refs.items():
        if ast_id not in values:
            continue
        value = values[ast_id]
        for r in refs:
            start, length = r["start"], r["length"]
            if isinstance(value, int):
                word = (value % (1 << (8 * length))).to_bytes(length, "big")
            else:
                word = bytes(value)[-length:].rjust(length, b"\0")
            out[start : start + length] = word
    return bytes(out)


@dataclasses.dataclass
class L4Search:
    """Outcome of compiling one source under several settings and comparing each result."""

    best: Optional[BytecodeComparison]
    best_settings: Optional[Settings]
    matching: List[Settings]  # every tried variant that is byte-identical
    variants: List[dict]  # per variant: label, identical / instr_similarity or error
    complete: bool  # False when the time limit stopped the search early
    elapsed: float

    @property
    def identical(self) -> bool:
        return bool(self.matching)

    def to_dict(self) -> dict:
        return {
            "identical": self.identical,
            "best": self.best.to_dict() if self.best else None,
            "best_settings": self.best_settings.label if self.best_settings else None,
            "matching": [s.label for s in self.matching],
            "variants": self.variants,
            "complete": self.complete,
            "elapsed": round(self.elapsed, 3),
        }


def search_l4(
    original: Union[bytes, str],
    sources: Union[str, Mapping[str, str]],
    contract_name: str,
    version: str,
    *,
    variants: Optional[Sequence[Settings]] = None,
    solc_path: Optional[str] = None,
    time_limit: Optional[float] = None,
) -> L4Search:
    """
    Compiles `contract_name` with each settings variant (default:
    `optimizer_variants(version)`) and compares it with `original`.  Every
    identical variant is listed (on small contracts several settings yield the
    same bytes); otherwise the best one is the highest `instr_similarity`.
    """
    original = to_bytes(original)
    variants = list(variants) if variants is not None else optimizer_variants(version)
    t0 = time.monotonic()
    best: Optional[BytecodeComparison] = None
    best_settings: Optional[Settings] = None
    matching: List[Settings] = []
    rows: List[dict] = []
    complete = True
    for settings in variants:
        if time_limit is not None and rows and time.monotonic() - t0 > time_limit:
            complete = False
            break
        try:
            art = compile_standard_json(
                sources, settings, version=version, solc_path=solc_path
            ).artifact(contract_name)
        except (CompilationError, SolcNotFound, KeyError) as e:
            rows.append({"settings": settings.label, "error": str(e).splitlines()[0][:200]})
            continue
        cmp = compare_runtime(original, art.runtime, art.immutable_refs, art.link_refs)
        rows.append(
            {
                "settings": settings.label,
                "identical": cmp.identical,
                "instr_similarity": cmp.instr_similarity,
            }
        )
        if cmp.identical:
            matching.append(settings)
        if best is None or (cmp.identical, cmp.instr_similarity) > (
            best.identical,
            best.instr_similarity,
        ):
            best, best_settings = cmp, settings
    return L4Search(best, best_settings, matching, rows, complete, time.monotonic() - t0)

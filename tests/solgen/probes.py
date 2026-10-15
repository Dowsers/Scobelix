"""
Harness of the pass tests that work on real compilers: a probe contract is
compiled with a given solc build, decompiled, generated again by solgen v2
with a chosen set of passes, compiled with the target compiler, and both
runtimes are executed on crafted calldata (dirty high bits, values out of
range, short calldata, bad offsets and lengths of dynamic parameters).  The
outcomes (success, return / revert data, storage writes) must be identical:
a pass that removes a check or changes a form is wrong as soon as one input
behaves differently.

The signature lookups are patched with the probe's own ABI (keccak-verified
through sigs._from_entry), so the passes see the names and types a signature
database would give.
"""

from __future__ import annotations

import dataclasses
import itertools
import logging
import random
from typing import Dict, List, Optional, Sequence, Tuple

import pytest
from eth_abi import encode as abi_encode
from eth_utils import keccak

from conftest import backend_or_skip, compile_or_fail, installed
from scobelix.solgen import sigs
from scobelix.solgen.types import parse_type, split_types

CALLER = "0x" + "a1" * 20
ORIGINAL = "0x" + "0e" * 20
CANDIDATE = "0x" + "c0" * 20


@dataclasses.dataclass(frozen=True)
class Build:
    version: str
    optimize: bool = True
    via_ir: bool = False
    abicoder: Optional[str] = None  # "v2" adds `pragma abicoder v2` (0.7.x)

    @property
    def label(self) -> str:
        out = self.version + ("-opt" if self.optimize else "-noopt")
        if self.via_ir:
            out += "-ir"
        if self.abicoder:
            out += "-" + self.abicoder
        return out

    @property
    def major(self) -> Tuple[int, int]:
        a, b = self.version.split(".")[:2]
        return int(a), int(b)

    @property
    def v2(self) -> bool:
        """The build decodes with ABI coder v2 (validators)."""
        return self.major >= (0, 8) or self.abicoder == "v2"


def pragma(build: Build) -> str:
    out = f"pragma solidity ^{build.version};\n"
    if build.abicoder == "v2":
        out += "pragma abicoder v2;\n"
    return out


def compile_probe(source: str, build: Build, contract: str):
    """The Artifact (runtime, abi) of `contract` compiled by the build; the
    test is skipped when the compiler is not installed."""
    from scobelix.verify.solc import CompilationError, Settings, compile_standard_json, execution_evm_version

    path = installed().get(build.version)
    if path is None:
        pytest.skip(f"solc {build.version} is not installed")
    settings = Settings(optimize=build.optimize, runs=200, via_ir=build.via_ir,
                        evm_version=execution_evm_version(build.version))
    try:
        comp = compile_standard_json(pragma(build) + source, settings, version=build.version, solc_path=path)
    except CompilationError as e:
        pytest.fail(f"solc {build.version} rejected the probe:\n" + "\n".join(e.messages[:5]))
    return comp.artifact(contract)


def patch_signatures(monkeypatch, abi: list, outputs: bool = True) -> None:
    """Make the signature lookups answer with the probe's ABI (functions and
    errors), as a curated database would.  outputs=False hides the return
    types (the generator must infer them)."""
    functions: Dict[int, tuple] = {}
    errors: Dict[int, tuple] = {}
    for item in abi:
        if item.get("type") == "function":
            entry = dict(item)
            if not outputs:
                entry["outputs"] = None
            sig = sigs._from_entry("function", entry, "curated")
            if sig is not None:
                functions.setdefault(sigs.function_selector(sig.signature), []).append(sig)
        elif item.get("type") == "error":
            sig = sigs._from_entry("error", dict(item), "curated")
            if sig is not None:
                errors.setdefault(sigs.function_selector(sig.signature), []).append(sig)
    monkeypatch.setattr(sigs, "function_candidates", lambda sel: tuple(functions.get(sel, ())))
    monkeypatch.setattr(sigs, "error_candidates", lambda sel, types=None: tuple(errors.get(sel, ())))
    monkeypatch.setattr(sigs, "event_candidates", lambda topic, n=None: ())


def generate_probe(runtime: bytes, off: Sequence[str] = (), level: str = "full"):
    """Decompile `runtime` and generate it with every pass but `off`."""
    from scobelix.decompiler import decompile_bytecode
    from scobelix.solgen.v2 import generate

    logging.disable(logging.CRITICAL)
    try:
        d = decompile_bytecode(runtime.hex())
    finally:
        logging.disable(logging.NOTSET)
    return generate(d, idiom_level=level, disabled_passes={"*": set(off)} if off else None)


def run_calls(runtime: bytes, calls: Sequence[Tuple[bytes, int]], storage: Optional[Dict[int, int]] = None,
              addr: str = CANDIDATE):
    """(success, output, storage writes) of every (calldata, value) on a
    fresh world holding `runtime` at `addr`."""
    from scobelix.verify.evm import make_world

    backend = backend_or_skip()
    out = []
    for data, value in calls:
        world = make_world(backend)
        world.set_code(addr, runtime)
        if storage:
            world.set_storage_many(addr, storage)
        world.set_balance(CALLER, 10**20)
        r = world.call(CALLER, addr, data, value=value)
        out.append((r.success, r.output, tuple(sorted((k[1], v[1]) for k, v in r.storage_diff.items()))))
    return out


def differential(original: bytes, generated_source: str, target: str, calls: Sequence[Tuple[bytes, int]],
                 storage: Optional[Dict[int, int]] = None) -> List[tuple]:
    """The calls on which the original and the generated runtime differ."""
    art = compile_or_fail(generated_source, target)
    a = run_calls(original, calls, storage, ORIGINAL)
    b = run_calls(art.runtime, calls, storage, CANDIDATE)
    return [(data.hex(), value, x, y) for (data, value), x, y in zip(calls, a, b) if x != y]


def selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


# ---------------------------------------------------------------- crafted calldata

W = 1 << 256


def _words(t) -> Tuple[List[int], List[int]]:
    """(clean, dirty) head words of a value type."""
    k = t.kind
    if k == "uint":
        n = t.bits
        clean = [0, 1, (1 << n) - 1]
        dirty = [] if n == 256 else [1 << n, W - 1, ((1 << n) - 1) | (1 << min(255, n + 5))]
    elif k == "int":
        n = t.bits
        clean = [0, 1, (1 << (n - 1)) - 1, W - (1 << (n - 1)), W - 1]
        dirty = [] if n == 256 else [1 << (n - 1), (1 << n) - 1, 1 << 255]
    elif k == "address":
        clean = [0, 1, (1 << 160) - 1, int("a1" * 20, 16)]
        dirty = [1 << 160, W - 1, (1 << 200) | 7]
    elif k == "bool":
        clean = [0, 1]
        dirty = [2, W - 1, (1 << 128) | 1]
    elif k == "bytes":
        n = t.bits // 8
        top = ((1 << t.bits) - 1) << (256 - t.bits)
        clean = [0, top, int(("12" * n).ljust(64, "0"), 16)]
        dirty = [] if n == 32 else [1, top | 1, W - 1]
    else:
        clean, dirty = [0], []
    return clean, dirty


def _value(word: int, t):
    """The Python value eth_abi encodes as `word` for a value type."""
    k = t.kind
    if k == "uint":
        return word
    if k == "int":
        return word - W if word >> 255 else word
    if k == "address":
        return "0x" + word.to_bytes(32, "big")[12:].hex()
    if k == "bool":
        return bool(word)
    if k == "bytes":
        return word.to_bytes(32, "big")[: t.bits // 8]
    raise ValueError(t.canonical)


def _dynamic_samples(t, rng: random.Random) -> list:
    """Sample values of a dynamic type."""
    if t.kind in ("dynbytes", "string"):
        vals = [b"", b"\x01", bytes(31), bytes(range(32)), bytes(33), bytes(100)]
        return [v.decode("latin-1") if t.kind == "string" else v for v in vals]
    if t.kind == "array" and t.length is None and t.base.is_value:
        clean, _ = _words(t.base)
        return [[], [_value(clean[1], t.base)], [_value(w, t.base) for w in clean[:3]],
                [_value(rng.choice(clean), t.base) for _ in range(5)]]
    raise ValueError(t.canonical)


def calldata_cases(signature: str, seed: int = 11, short: bool = True, mutate: bool = True) -> List[bytes]:
    """Crafted calldata for `signature`: clean values, dirty high bits of
    every value parameter (one at a time and mixed), bad offsets and lengths
    of every dynamic parameter (`mutate`), truncated (`short`) and extended
    encodings."""
    rng = random.Random(seed)
    name, rest = signature.split("(", 1)
    types = [parse_type(t) for t in split_types(rest[:-1])] if rest[:-1] else []
    sel = selector(signature)
    canon = [t.canonical for t in types]
    out: List[bytes] = []

    def encode(words: Sequence[object]) -> bytes:
        """ABI encoding where a value parameter given as an int is written
        as that word (dirty bits kept)."""
        vals = []
        for t, w in zip(types, words):
            vals.append(_value(0, t) if t.is_value and isinstance(w, int) else w)  # placeholder, patched below
        data = abi_encode(canon, vals) if types else b""
        head = bytearray(data)
        for i, (t, w) in enumerate(zip(types, words)):
            if t.is_value and isinstance(w, int):
                head[32 * i:32 * i + 32] = w.to_bytes(32, "big")  # the exact word
        return bytes(head)

    samples = []
    for t in types:
        if t.is_value:
            clean, dirty = _words(t)
            samples.append((clean, dirty))
        else:
            samples.append((_dynamic_samples(t, rng), []))
    if not types:
        base = [b""]
    else:
        base = []
        for i in range(3):
            base.append(encode([s[0][min(i, len(s[0]) - 1)] for s in samples]))
        mid = [s[0][min(1, len(s[0]) - 1)] for s in samples]
        for i, (clean, dirty) in enumerate(samples):
            for w in clean + dirty:
                vec = list(mid)
                vec[i] = w
                base.append(encode(vec))
        for _ in range(6):
            base.append(encode([rng.choice(c + d) for c, d in samples]))
    out.extend(sel + b for b in base)
    # dynamic parameters: bad offsets and lengths
    word = 0
    for i, t in enumerate(types):
        if t.is_dynamic and mutate:
            data = encode([s[0][min(1, len(s[0]) - 1)] for s in samples])
            size = len(data)
            offset = int.from_bytes(data[32 * word:32 * word + 32], "big")
            for alt in (offset + 32, offset - 32 if offset >= 32 else 0, 1 << 64, (1 << 64) - 1, 1 << 255, W - 1,
                        0, 4, 1, 33, size, size - 31, size - 32, (1 << 32) - 1, 1 << 32):
                if alt < 0:
                    continue
                mutated = bytearray(data)
                mutated[32 * word:32 * word + 32] = (alt % W).to_bytes(32, "big")
                out.append(sel + bytes(mutated))
            remaining = size - offset - 32
            for alt in (0, 1, 31, 32, 33, 64, remaining + 1, remaining * 2 + 1, (1 << 64) - 1, 1 << 64, 1 << 255,
                        W - 1, (1 << 32) - 1, 1 << 32, (1 << 251) + 1):
                mutated = bytearray(data)
                mutated[offset:offset + 32] = (alt % W).to_bytes(32, "big")
                out.append(sel + bytes(mutated))
            # data shorter than its length word says
            out.append(sel + data[:offset + 32 + 1])
        word += t.head_words
    if short:
        data = base[1] if len(base) > 1 else base[0]
        cuts = {0, 3, 4, len(data) + 4 - 1, len(data) + 4 - 32, len(data) + 4 - 33}
        for w in range(word):
            cuts |= {4 + 32 * w - 1, 4 + 32 * w, 4 + 32 * w + 1}
        for c in sorted(cuts):
            if 0 <= c < len(data) + 4:
                out.append((sel + data)[:c])
    out.append(sel + base[0] + bytes(32))  # extra bytes after the arguments
    out.append(sel + base[0] + b"\xff" * 7)
    seen, uniq = set(), []
    for c in out:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def all_cases(signatures: Sequence[str], value: int = 0, short: bool = True, mutate: bool = True) \
        -> List[Tuple[bytes, int]]:
    return [(c, value) for s in signatures for c in calldata_cases(s, short=short, mutate=mutate)]


def probe_calls(result, value: int = 0) -> Tuple[List[Tuple[bytes, int]], List[str]]:
    """Crafted calls for every named function of a result that has a
    translation, and the signatures left out: functions flagged
    `unstructured` (no translation: they revert by design) and, for the
    malformed inputs, functions flagged `abi:short_calldata_check` (a 0.4
    decoder reads zeros past the calldata end, the target's reverts: a
    documented difference)."""
    calls, skipped = [], []
    for f in named_functions(result).values():
        if "unstructured" in f["flags"]:
            skipped.append(f["signature"])
            continue
        legacy = "abi:short_calldata_check" in f["flags"]
        calls.extend((c, value) for c in calldata_cases(f["signature"], short=not legacy, mutate=not legacy))
    return calls, skipped


def named_functions(result) -> Dict[str, dict]:
    """The result's entries that have a known name (not routed)."""
    return {k: f for k, f in result.functions.items() if f["kind"] == "function" and not f["routed"]}


def function_text(source: str, name: str) -> str:
    """The text of the function `name` of a generated source (declaration
    to closing brace), '' when absent."""
    key = f"function {name}("
    i = source.find(key)
    if i < 0:
        return ""
    depth, j = 0, source.index("{", i)
    for k in range(j, len(source)):
        depth += source[k] == "{"
        depth -= source[k] == "}"
        if depth == 0:
            return source[i:k + 1]
    return source[i:]


def combos(*lists):
    return list(itertools.product(*lists))

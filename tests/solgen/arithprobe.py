"""
Harness of the arith and compound pass tests.  A probe contract is compiled
by a real solc build, decompiled, generated again by solgen v2 with a chosen
set of passes, compiled with the target compiler, and both runtimes are run
on the same calls: every function on a grid of words at the bounds of each
parameter type (0, 1, 2, max / 2, max - 1, max for uintN; 0, +-1, +-2, max,
max - 1, min, min + 1 for intN; dirty words too), each with every storage
preset (the slots the original's storage layout declares, mapping entries
of the addresses the grids use, the first elements of arrays, filled with
0, 1, max, max - 1, 2**255, 2**255 - 1 and mixed patterns).  The outcomes
(success, return or revert data, storage writes, logs) must be identical:
a pass that changes any of them on any input is wrong.  The generated
source is compiled by the legacy pipeline, or (via_ir) by the IR pipeline:
Solidity leaves the evaluation order of operands unspecified, and the two
differ (legacy: the right operand of a binary operation first).
"""

from __future__ import annotations

import itertools
import random
from typing import Dict, List, Optional, Sequence, Tuple

import pytest
from eth_utils import keccak

from conftest import backend_or_skip, compile_or_fail, solc_or_skip
from probes import CALLER, CANDIDATE, ORIGINAL, selector
from scobelix.solgen.types import parse_type, split_types

W = 1 << 256
OTHER = "0x" + "b2" * 20
ADDRESSES = [int(CALLER, 16), int(OTHER, 16)]


def _word(v: int) -> int:
    return v % W


def grid(t, small: bool = False) -> List[int]:
    """Words of a value type at its bounds (and a few dirty ones)."""
    if t.kind == "uint":
        m = (1 << t.bits) - 1
        vals = [0, 1, 2, 3, m >> 1, (m >> 1) + 1, m - 1, m]
        if small:
            vals = [0, 1, 2, m >> 1, m - 1, m]
        if t.bits < 256 and not small:
            vals.append(m + 1)  # dirty: the decoder rejects it
        return sorted(set(vals))
    if t.kind == "int":
        hi, lo = (1 << (t.bits - 1)) - 1, -(1 << (t.bits - 1))
        vals = [0, 1, -1, 2, -2, 3, hi, hi - 1, lo, lo + 1]
        if small:
            vals = [0, 1, -1, 2, hi, lo, lo + 1]
        return [_word(v) for v in vals]
    if t.kind == "address":
        return ADDRESSES[:]
    if t.kind == "bool":
        return [0, 1]
    if t.kind == "bytes":
        return [0, ((1 << t.bits) - 1) << (256 - t.bits)]
    return [0]


def calls_for(signature: str, limit: int = 600, seed: int = 7) -> List[bytes]:
    """Calldata of `signature` for the grid of its value parameters (all
    combinations, or a deterministic sample of them past `limit`)."""
    name, rest = signature.split("(", 1)
    types = [parse_type(x) for x in split_types(rest[:-1])] if rest[:-1] else []
    sel = selector(signature)
    if not types:
        return [sel]
    if any(not t.is_value for t in types):
        return []
    grids = [grid(t) for t in types]
    total = 1
    for g in grids:
        total *= len(g)
    if total > limit:
        grids = [grid(t, small=True) for t in types]
    combos = list(itertools.product(*grids))
    if len(combos) > limit:
        rng = random.Random(seed)
        combos = rng.sample(combos, limit)
    return [sel + b"".join(w.to_bytes(32, "big") for w in c) for c in combos]


def _h(*words: int) -> int:
    return int.from_bytes(keccak(b"".join(w.to_bytes(32, "big") for w in words)), "big")


def layout_slots(layout: Optional[dict], keys: Sequence[int] = tuple(ADDRESSES) + (0, 1, 2)) \
        -> Tuple[List[int], List[int]]:
    """(value slots, array length slots) of a solc storage layout: every
    word of the declared variables, of mapping entries at `keys`, of the
    first elements of dynamic arrays."""
    if not layout:
        return [], []
    types = layout.get("types") or {}
    words: List[int] = []
    lengths: List[int] = []

    def walk(slot: int, tname: str, depth: int) -> None:
        t = types.get(tname) or {}
        enc = t.get("encoding")
        if enc == "inplace":
            n = (int(t.get("numberOfBytes", 32)) + 31) // 32
            words.extend(range(slot, slot + n))
        elif enc == "mapping" and depth < 3:
            for k in keys:
                walk(_h(k, slot), t["value"], depth + 1)
        elif enc == "dynamic_array" and depth < 3:
            lengths.append(slot)
            base = _h(slot)
            per = (int((types.get(t["base"]) or {}).get("numberOfBytes", 32)) + 31) // 32
            for i in range(3):
                walk(base + i * per, t["base"], depth + 1)
        elif enc == "bytes":
            words.append(slot)

    for v in layout.get("storage") or []:
        walk(int(v["slot"]), v["type"], 0)
    return sorted(set(words)), sorted(set(lengths))


PATTERNS = [0, 1, W - 1, W - 2, 1 << 255, (1 << 255) - 1, int("7f" * 32, 16), int("80" * 32, 16),
            int("ff00" * 16, 16), int("01" * 32, 16)]


def storage_presets(layout: Optional[dict], seed: int = 3) -> List[Dict[int, int]]:
    """Storage contents: each pattern in every declared word (array lengths
    3, and once the maximum), plus two random fillings."""
    words, lengths = layout_slots(layout)
    if not words and not lengths:
        return [{}]
    out = []
    for p in PATTERNS:
        st = {s: p for s in words}
        st.update({s: 3 for s in lengths})
        out.append(st)
    st = {s: W - 1 for s in words}
    st.update({s: W - 1 for s in lengths})
    out.append(st)
    rng = random.Random(seed)
    for _ in range(2):
        st = {s: rng.choice(PATTERNS) ^ rng.getrandbits(8) for s in words}
        st.update({s: 3 for s in lengths})
        out.append(st)
    return out


def run_calls(runtime: bytes, calls: Sequence[bytes], storage: Dict[int, int], addr: str) -> list:
    """(success, output, storage writes, logs) of each call on one world
    holding `runtime` with `storage` (reset between calls)."""
    from scobelix.verify.evm import make_world

    world = make_world(backend_or_skip())
    world.set_code(addr, runtime)
    if storage:
        world.set_storage_many(addr, storage)
    world.set_balance(CALLER, 10**20)
    snap = world.snapshot()
    out = []
    for data in calls:
        r = world.call(CALLER, addr, data)
        logs = tuple((tuple(lg[1]), bytes(lg[2])) for lg in r.logs)  # (topics, data); the address differs
        out.append((r.success, r.output, tuple(sorted((k[1], v[1]) for k, v in r.storage_diff.items())), logs))
        world.revert(snap)
        snap = world.snapshot()
    return out


def compile_via_ir(source: str, version: str, name: str = "Decompiled"):
    """The artifact of `name` compiled by solc `version`'s IR pipeline (optimised)."""
    from scobelix.verify.solc import CompilationError, Settings, compile_standard_json, execution_evm_version

    settings = Settings(via_ir=True, evm_version=execution_evm_version(version))
    try:
        comp = compile_standard_json(source, settings, version=version, solc_path=solc_or_skip(version))
    except CompilationError as e:
        pytest.fail(f"solc {version} (via IR) rejected the source:\n" + "\n".join(e.messages[:5]))
    return comp.artifact(name)


def differential(original: bytes, source: str, target: str, calls: Sequence[bytes],
                 presets: Sequence[Dict[int, int]], via_ir: bool = False) -> List[tuple]:
    """The (preset index, calldata, original outcome, generated outcome) of
    every call on which the two runtimes differ."""
    art = compile_via_ir(source, target) if via_ir else compile_or_fail(source, target)
    out = []
    for i, st in enumerate(presets):
        a = run_calls(original, calls, st, ORIGINAL)
        b = run_calls(art.runtime, calls, st, CANDIDATE)
        out.extend((i, c.hex(), x, y) for c, x, y in zip(calls, a, b) if x != y)
    return out


def all_calls(result, limit: int = 600) -> Tuple[List[bytes], List[str]]:
    """Grid calls of every named function of a generation result, and the
    signatures left out (untranslated functions, or with dynamic parameters)."""
    calls, skipped = [], []
    for f in result.functions.values():
        if f["kind"] != "function" or f["routed"] or not f["signature"]:
            continue
        got = calls_for(f["signature"], limit)
        if "unstructured" in f["flags"] or not got:
            skipped.append(f["signature"])
            continue
        calls.extend(got)
    return calls, skipped

"""
Harness of the calls and events pass tests: a probe contract and the text
generated from its bytecode run side by side, at the same address, in
worlds holding the same environment (an EOA, accepting / rejecting / reentrant
callers, the ERC20-like stub and the configurable Echo callee of this file,
the recorder of the verification mocks), and every observable is compared:
success, return or revert data, the logs of every contract with their order
and emitter (the external calls a contract makes reach the logs through the
recorder: target, value, calldata), the storage changes of every account
and the balances.

Echo answers a call with calldata according to its storage: slot 0 the mode
(0 return, 1 revert, 2 invalid opcode: all the gas of the call is spent,
3 return the keccak256 of the calldata: the answer to a static call, which
cannot be recorded, depends on its arguments), slot 1 the length of the
answer, slots 2... its words.  A plain value transfer is accepted without
touching storage (the 2300 gas of a stipend).
"""

from __future__ import annotations

import dataclasses
import functools
import logging
from typing import Dict, List, Optional, Sequence, Tuple

import pytest
from eth_abi import encode as abi_encode
from eth_utils import keccak

from conftest import backend_or_skip, compile_or_fail, installed
from probes import Build, pragma
from scobelix.solgen import sigs

TARGET = "0x" + "0e" * 20
CALLER = "0x" + "a1" * 20
ECHO = "0x" + "ec40" * 10
EOA = "0x" + "e0a0" * 10
IDENTITY = "0x" + "00" * 19 + "04"  # the identity precompile: no code, answers with its input

ECHO_SOLIDITY = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

address constant RECORDER = 0x7eC07ec07Ec07ec07EC07EC07eC07EC07ec07Ec0;

contract Echo {
    fallback() external payable {
        if (msg.data.length == 0) return;
        (bool recorded, ) = RECORDER.call{gas: 6000 + 16 * msg.data.length}(abi.encode(msg.sender, msg.value, msg.data));
        recorded;
        assembly {
            let mode := sload(0)
            if eq(mode, 3) {
                calldatacopy(0, 0, calldatasize())
                mstore(0, keccak256(0, calldatasize()))
                return(0, 32)
            }
            let n := sload(1)
            for { let i := 0 } lt(i, n) { i := add(i, 32) } { mstore(i, sload(add(2, div(i, 32)))) }
            if eq(mode, 1) { revert(0, n) }
            if eq(mode, 2) { invalid() }
            return(0, n)
        }
    }
}
"""


@functools.lru_cache(maxsize=None)
def echo_runtime() -> bytes:
    return compile_or_fail(ECHO_SOLIDITY, "0.8.19", name="Echo").runtime


def answer(data: bytes, mode: int = 0) -> Dict[int, int]:
    """The storage of Echo for an answer (`mode` 0 return, 1 revert, 2 invalid)."""
    out = {0: mode, 1: len(data)}
    padded = data + bytes(-len(data) % 32)
    for i in range(0, len(padded), 32):
        out[2 + i // 32] = int.from_bytes(padded[i:i + 32], "big")
    return out


def word(v: int) -> bytes:
    return (v % (1 << 256)).to_bytes(32, "big")


def error_string(msg: str) -> bytes:
    return bytes.fromhex("08c379a0") + abi_encode(["string"], [msg])


# answers of a callee, by name: what a returned word, a short or long answer,
# every kind of revert data and a callee halting do to the caller
ANSWERS = {
    "true": answer(word(1)),
    "false": answer(word(0)),
    "dirty-bool": answer(word(2)),
    "max": answer(word(-1)),
    "address": answer(word(int("a1" * 20, 16))),
    "three": answer(word(5) + word(7) + word(9)),
    "three-dirty": answer(word(1 << 120) + word(7) + word(1 << 40)),
    "three-dirty-last": answer(word(5) + word(7) + word(1 << 40)),
    "hash": {0: 3},
    "empty": answer(b""),
    "short": answer(bytes(31)),
    "long": answer(word(1) + word(2) + word(3) + bytes(200)),
    "revert-empty": answer(b"", 1),
    "revert-error": answer(error_string("callee says no"), 1),
    "revert-custom": answer(bytes.fromhex("82b42900") + word(42), 1),
    "revert-panic": answer(bytes.fromhex("4e487b71") + word(0x11), 1),
    "revert-huge": answer(bytes(range(256)) * 20, 1),
    "invalid": answer(b"", 2),
}


def load_mocks(world, echo: Optional[Dict[int, int]] = None) -> None:
    from scobelix.verify.mocks import MOCKS

    for m in MOCKS.values():
        world.set_code(m.address, m.runtime)
    world.set_code(ECHO, echo_runtime())
    if echo:
        world.set_storage_many(ECHO, echo)


def outcome(runtime: bytes, data: bytes, value: int, echo: Optional[Dict[int, int]],
            storage: Optional[Dict[int, int]] = None):
    from scobelix.verify.evm import make_world

    world = make_world(backend_or_skip())
    load_mocks(world, echo)
    world.set_code(TARGET, runtime)
    if storage:
        world.set_storage_many(TARGET, storage)
    world.set_balance(CALLER, 10**20)
    world.set_balance(TARGET, 10**18)
    r = world.call(CALLER, TARGET, data, value=value)
    logs = tuple((a.lower(), tuple(t), bytes(d)) for a, t, d in r.logs)
    diff = tuple(sorted((a.lower(), k, v[1]) for (a, k), v in r.storage_diff.items()))
    balances = tuple(sorted((a.lower(), b) for a, b in r.balances.items()))
    return r.success, bytes(r.output), logs, diff, balances


def differential(original: bytes, generated_source: str, target: str,
                 calls: Sequence[Tuple[bytes, int]], answers: Sequence[str] = ("true",),
                 storage: Optional[Dict[int, int]] = None) -> List[tuple]:
    """The (calldata, value, answer) on which the original and the text differ."""
    art = compile_or_fail(generated_source, target)
    out = []
    for name in answers:
        echo = ANSWERS[name]
        for data, value in calls:
            a = outcome(original, data, value, echo, storage)
            b = outcome(art.runtime, data, value, echo, storage)
            if a != b:
                out.append((data.hex(), value, name, a, b))
    return out


def compile_all(source: str, build: Build):
    """The compilation of a probe (every contract and interface)."""
    from scobelix.verify.solc import CompilationError, Settings, compile_standard_json, execution_evm_version

    path = installed().get(build.version)
    if path is None:
        pytest.skip(f"solc {build.version} is not installed")
    settings = Settings(optimize=build.optimize, runs=200, via_ir=build.via_ir,
                        evm_version=execution_evm_version(build.version))
    try:
        return compile_standard_json(pragma(build) + source, settings, version=build.version, solc_path=path)
    except CompilationError as e:
        pytest.fail(f"solc {build.version} rejected the probe:\n" + "\n".join(e.messages[:5]))


def patch_lookups(monkeypatch, abis: Sequence[list]) -> None:
    """The signature lookups answer with the ABIs given (functions, events,
    errors of the probe and of the interfaces it calls), as a curated
    database would."""
    functions: Dict[int, list] = {}
    events: Dict[int, list] = {}
    errors: Dict[int, list] = {}
    for abi in abis:
        for item in abi:
            kind = item.get("type")
            if kind not in ("function", "event", "error"):
                continue
            sig = sigs._from_entry(kind, dict(item), "curated")
            if sig is None:
                continue
            if kind == "event":
                table, key = events, sigs.event_topic(sig.signature)
            else:
                table, key = (functions if kind == "function" else errors), sigs.function_selector(sig.signature)
            if all(s.signature != sig.signature or s.indexed != sig.indexed for s in table.get(key, [])):
                table.setdefault(key, []).append(sig)
    monkeypatch.setattr(sigs, "function_candidates", lambda sel: tuple(functions.get(sel, ())))
    monkeypatch.setattr(sigs, "error_candidates", lambda sel, types=None: tuple(errors.get(sel, ())))
    monkeypatch.setattr(sigs, "event_candidates", lambda topic, n=None: tuple(
        e for e in events.get(topic, ()) if n is None or sum(e.indexed) == n))


def generate(runtime: bytes, off: Sequence[str] = (), level: str = "full", target: Optional[str] = None):
    from scobelix.decompiler import decompile_bytecode
    from scobelix.solgen.v2 import generate as v2_generate

    logging.disable(logging.CRITICAL)
    try:
        d = decompile_bytecode(runtime.hex())
    finally:
        logging.disable(logging.NOTSET)
    return v2_generate(d, target, idiom_level=level, disabled_passes={"*": set(off)} if off else None)


def call(signature: str, *args) -> bytes:
    name, rest = signature.split("(", 1)
    types = [t for t in rest[:-1].split(",") if t]
    return keccak(text=signature)[:4] + (abi_encode(types, list(args)) if types else b"")


@dataclasses.dataclass(frozen=True)
class Case:
    """A function of a probe and the calls that exercise it."""

    name: str
    calls: Tuple[Tuple[bytes, int], ...]
    answers: Tuple[str, ...] = ("true",)

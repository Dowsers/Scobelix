"""
Types shared by the execution backends.

A `World` is one EVM state: accounts with code, storage and balances, on
which calls are executed.  Every backend returns a `CallResult` carrying the
observables the equivalence checker compares (success, output, logs, storage
changes, balances, created contracts) plus the diagnostics it can provide:
exact storage reads, the internal call tree, branch coverage and comparison
operands (py-evm only).  Addresses are lowercase 0x-hex strings everywhere.
"""

from __future__ import annotations

import abc
import dataclasses
from typing import Dict, List, Set, Tuple

__all__ = [
    "BackendUnavailable",
    "BlockSpec",
    "CallResult",
    "DEFAULT_GAS",
    "HarnessError",
    "World",
    "lower",
]

# per top-level call: large enough that out-of-gas never decides an outcome
DEFAULT_GAS = 10_000_000

Addr = str
Log = Tuple[Addr, Tuple[int, ...], bytes]  # (address, topics, data)


class BackendUnavailable(RuntimeError):
    """The Python package behind a backend is not installed."""


class HarnessError(RuntimeError):
    """The harness asked for an invalid transaction (unfunded sender, caller with code...)."""


@dataclasses.dataclass(frozen=True)
class BlockSpec:
    """Block environment, identical on both sides of a comparison."""

    number: int = 18_000_000
    timestamp: int = 1_700_000_000
    coinbase: Addr = "0x" + "c0" * 20
    prevrandao: bytes = b"\x01" * 32
    basefee: int = 0  # 0: gas price 0 is valid, so balances only move by call values
    gas_limit: int = 30_000_000
    chain_id: int = 1

    def later(self, seconds: int, blocks: int) -> "BlockSpec":
        return dataclasses.replace(
            self, number=self.number + blocks, timestamp=self.timestamp + seconds
        )


@dataclasses.dataclass
class CallResult:
    success: bool
    output: bytes  # returndata, or revert data
    error: str  # "" | "revert" | "halt:<reason>"
    logs: List[Log]
    # (address, slot) -> (before, after), changed slots only
    storage_diff: Dict[Tuple[Addr, int], Tuple[int, int]]
    storage_reads: Set[Tuple[Addr, int]]  # exact SLOADs on py-evm; every journaled slot on pyrevm
    balances: Dict[Addr, int]  # post-call balance of every touched account
    created: List[Tuple[Addr, bytes]]  # (address, runtime) of contracts created, in creation order
    gas_used: int = 0
    # py-evm only: internal calls (depth, kind, target, value, calldata)
    calls: List[Tuple[int, str, Addr, int, bytes]] = dataclasses.field(default_factory=list)
    # py-evm only: (pc, taken) of the JUMPIs of the covered code
    jumpis: Set[Tuple[int, bool]] = dataclasses.field(default_factory=set)
    # py-evm only: comparison operands of the covered code (cmp-log)
    compared: List[int] = dataclasses.field(default_factory=list)
    # py-evm only (cmp-log): the covered code's guard events in execution order, (opcode, x, y):
    # a comparison (EQ LT GT SLT SGT SUB XOR: its operands, top of the stack first), ISZERO (x),
    # a call (x: its target, y: 1 if the target has code) and an EXTCODE* opcode whose target x
    # has no code (y = 0) - precompiles excluded; the first events of a call, then its last ones
    trace: List[Tuple[int, int, int]] = dataclasses.field(default_factory=list)
    # py-evm only (cmp-log): the 32 / 64-byte inputs the covered code hashed: (hash, input words)
    hashes: List[Tuple[int, Tuple[int, ...]]] = dataclasses.field(default_factory=list)

    @property
    def halted(self) -> bool:
        return self.error.startswith("halt")


class World(abc.ABC):
    """One EVM state.  Backends: `PyRevmWorld` (fast, no hooks), `PyEvmWorld` (hooks)."""

    name = "abstract"
    exact_reads = False  # storage_reads lists SLOADs only (not seeded-but-unread slots)
    has_hooks = False  # call tree, coverage, comparison operands, deterministic environment

    @abc.abstractmethod
    def set_code(self, addr: Addr, code: bytes) -> None:
        """Installs `code` at `addr` (balance and storage kept)."""

    @abc.abstractmethod
    def set_storage(self, addr: Addr, slot: int, value: int) -> None:
        """Writes one storage word, outside any call."""

    def set_storage_many(self, addr: Addr, slots: Dict[int, int]) -> None:
        for slot, value in slots.items():
            self.set_storage(addr, slot, value)

    @abc.abstractmethod
    def set_balance(self, addr: Addr, wei: int) -> None:
        """Sets the ETH balance of `addr`."""

    @abc.abstractmethod
    def get_storage(self, addr: Addr, slot: int) -> int:
        """The current value of one storage word."""

    @abc.abstractmethod
    def get_balance(self, addr: Addr) -> int:
        """The current ETH balance of `addr`."""

    @abc.abstractmethod
    def snapshot(self):
        """A token `revert` returns the state to."""

    @abc.abstractmethod
    def revert(self, token) -> None:
        """Back to the state of `snapshot()`."""

    @abc.abstractmethod
    def call(
        self,
        caller: Addr,
        to: Addr,
        data: bytes,
        value: int = 0,
        gas: int = DEFAULT_GAS,
        static: bool = False,
    ) -> CallResult:
        """
        Executes one message call from `caller` (an EOA) and returns
        everything observed.  Each call is a transaction of its own: it starts
        with empty transient storage.
        """


def lower(addr) -> Addr:
    """Lowercase 0x-hex form of an address given as bytes or (checksummed) text."""
    if isinstance(addr, (bytes, bytearray)):
        return "0x" + bytes(addr).hex()
    return str(addr).lower()

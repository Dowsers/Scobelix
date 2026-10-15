"""
Differential execution: the original runtime against the candidate runtime.

Both run at the same address, from the same pre-state, under the same block
environment, for the same calls.  Every observable is compared - never gas:
  * success, and halt (invalid opcode, out of gas...) vs revert;
  * the exact returndata / revert data (Error(string), Panic(code) and custom
    errors are all distinct byte strings);
  * logs in order: (address, topics, data);
  * the final value of every changed slot of every account;
  * post balances of every touched account;
  * the number of contracts created.  A CREATE2 address hashes the
    metadata-bearing initcode, so the candidate's created addresses are
    mapped to the original's by creation order before anything is compared
    (their constructors' storage writes and logs are compared, their code
    is not: other compiler settings create other, equivalent, code);
  * on py-evm, the internal call list (depth, kind, target, value, calldata).

Calls are generated per function (`Differ.fuzz_function`): typed arguments
with a share of malformed calldata, msg.value 80 / 10 / 10, a sender from
the universe or - for `via_ratio` of the calls - a contract caller mock
(accepting, rejecting or reentrant, see `mocks`), storage seeded from the
ORIGINAL's layout plus every slot either side was seen reading, the
contract's own ETH balance, the mode of the ERC20-like stub, and one of two
block environments (`BLOCKS`: a year apart, on two chains, with different
coinbase, randomness and gas limit).  `Differ.fuzz_sequences` chains calls
from a plausible state instead (reachable states).

Gas is a resource, not behaviour: a divergence where a side halted or burnt
over half of the call's gas is re-run with the block's whole gas limit, and
if it disappears there it only meant that one side needed more gas than the
other (`env_divergences`, like the next case).  If it persists only because
the original runs out of even that gas while the candidate finishes (a loop
over a length no state reaches), what the original would compute no block
can observe: `gas_divergences`, reported apart (INCONCLUSIVE), never as a
divergence; a candidate running out of a block's gas where the original
finishes stays divergent.  When the original looks at
its environment (gas, its own code), a divergence found by pyrevm is
replayed on py-evm with a deterministic environment (gas and
self-introspection virtualised) when py-evm is available: if it disappears
there, it is environment-only (`env_divergences`).
Divergences are shrunk on the bulk backend (seeds dropped, value / caller
simplified), labelled `dirty_storage` when they need seeded bits outside the
declared fields, and the reported counterexample is replayed on py-evm for
its call tree (unless it burns more than HEAVY_GAS).
"""

from __future__ import annotations

import collections
import dataclasses
import random
import time
from typing import Dict, FrozenSet, List, Mapping, Optional, Sequence, Set, Tuple

from eth_abi.exceptions import EncodingError
from eth_utils import keccak

from .abi import FuncSpec, dispatcher_selectors
from .bytecode import disasm, own_code
from .evm import DEFAULT_GAS, BlockSpec, CallResult, World, make_world
from .fuzz import (
    ValueGen,
    call_value,
    comparison_constants,
    encode_call,
    head_words,
    mutate_calldata,
    push_dictionary,
    raw_calldata,
)
from .guides import Context, Guide, Loc, apply_call, apply_storage, choose, learn, shape_slots
from .layout import Var
from .mocks import (
    ACCEPTING_CALLER,
    CALLERS,
    MOCKS,
    REENTRANT_CALLER,
    REJECTING_CALLER,
    RETURN_STUB,
    encode_fwd,
)
from .seeds import Field, SeedPlan, clean_words

__all__ = [
    "CALLER_KINDS",
    "CONTRACT",
    "OTHERS",
    "SENDERS",
    "Call",
    "Differ",
    "Divergence",
    "FunctionStats",
    "Learned",
    "PreState",
    "compare_results",
    "contract_success",
    "env_sensitivity",
    "hardcoded_addresses",
    "out_of_gas",
]

CONTRACT = "0x" + "c0de" * 10
CALLER_KINDS = {
    ACCEPTING_CALLER: "accepting",
    REJECTING_CALLER: "rejecting",
    REENTRANT_CALLER: "reentrant",
}
SENDERS = ["0x" + "a1" * 20, "0x" + "b2" * 20, "0x" + "c3" * 20]
OTHERS = ["0x" + "00" * 19 + "01", "0x" + "dead" * 10]  # a precompile and an unrelated EOA
SENDER_BALANCE = 10**20
GAS_CAP = 4_000_000  # deterministic environment: GAS pushes at most this / 4**depth
# calls burning more gas than this (a loop fed a huge bound...) take seconds on py-evm: they are
# not replayed there for coverage or for the call tree of a counterexample
HEAVY_GAS = 2_000_000
MAX_LEARNED = 256  # comparison operands kept per function
WEIGHT_CAP = 8  # a learned value drawn at most this many times as often as a one-off one
MAX_GUIDES = 64  # guard-directed inputs kept per function (see `guides`)
MAX_SHAPES = 16  # mapping entries keyed by the call's own context, per function
GUIDE_RATIO = 0.5  # share of the calls that place the learned guides
YEAR = 365 * 86400
# the two block environments: a year apart, and every other value a candidate could hard-code
# (chain id, coinbase, randomness, gas limit) different too
BLOCKS = (
    BlockSpec(),
    dataclasses.replace(
        BlockSpec().later(YEAR, 2_628_000),
        coinbase="0x" + "c1" * 20,
        prevrandao=bytes(range(1, 33)),
        gas_limit=45_000_000,
        chain_id=10,
    ),
)
# gas re-checks (whole block gas limit, both sides) per function / per sequence run: on py-evm
# one costs seconds
MAX_GAS_CHECKS = {"pyrevm": 8, "pyevm": 2}

_CALL_OPS = {0xF1, 0xF2, 0xF4, 0xFA}
_WORD = (1 << 256) - 1
_DISPATCHER_PCS: Dict[tuple, frozenset] = {}  # see Differ.dispatcher_pcs


@dataclasses.dataclass
class PreState:
    storage: Dict[int, int]  # the contract's raw slots
    balances: Dict[str, int]
    # mocks' storage
    env_storage: Dict[str, Dict[int, int]] = dataclasses.field(default_factory=dict)
    dirty: Dict[int, Tuple[Field, ...]] = dataclasses.field(default_factory=dict)  # see seeds.Seeds
    block: int = 0  # index into Differ.blocks
    stubs: bool = False  # the original's hard-coded addresses carry the ReturnStub code

    def without(self, slot: int) -> "PreState":
        return dataclasses.replace(
            self,
            storage={k: v for k, v in self.storage.items() if k != slot},
            dirty={k: v for k, v in self.dirty.items() if k != slot},
        )


@dataclasses.dataclass
class Call:
    sender: str
    value: int
    data: bytes
    mutation: str = ""  # malformed-calldata kind, "" for a well-formed call
    # contract caller: sender -> via.fwd(CONTRACT, data, reentry) -> CONTRACT
    via: Optional[str] = None
    reentry: bytes = b""  # calldata a reentrant caller calls back with


@dataclasses.dataclass
class Divergence:
    key: str  # function key ("0xa9059cbb", "fallback", "receive")
    kinds: List[str]
    call: Call
    pre: PreState
    original: CallResult
    candidate: CallResult
    backend: str
    sequence: List[Call] = dataclasses.field(default_factory=list)  # earlier calls (stateful mode)
    label: str = "per_call"  # per_call | sequence | dirty_storage


@dataclasses.dataclass
class FunctionStats:
    key: str
    label: str
    calls: int = 0
    original_success: int = 0
    divergences: int = 0  # confirmed (or unconfirmable) divergent calls
    sequence_divergences: int = 0  # stateful sequences whose last call (to this function) diverged
    # divergent only because of the environment: under pyrevm but not in the deterministic
    # environment, or because one side ran out of gas (equivalent with the whole block gas limit)
    env_divergences: int = 0
    # divergent only because the original runs out of gas even with the block's whole gas limit
    # where the candidate does not: what the original computes there no block can observe
    gas_divergences: int = 0
    kinds: Dict[str, int] = dataclasses.field(default_factory=collections.Counter)
    first: Optional[Divergence] = None
    first_env: Optional[Divergence] = None
    first_gas: Optional[Divergence] = None
    gas_checks: int = 0  # divergences re-run with more gas
    covered: Set[Tuple[int, bool]] = dataclasses.field(default_factory=set)
    jumpi_pcs: Set[int] = dataclasses.field(default_factory=set)
    sample: List[Tuple[PreState, Call]] = dataclasses.field(default_factory=list)
    success_base: Optional[Tuple[PreState, Call]] = None  # a value-0 EOA call the original accepts
    elapsed: float = 0.0


@dataclasses.dataclass
class Learned:
    """
    What cmp-log taught about one function, value -> number of calls that
    showed it: `partners`, the values its inputs (calldata words, seeded
    storage, msg.value) were compared with - the boundaries to hit exactly -
    and `others`, operands of comparisons between two non-input values.
    Values are drawn in proportion to that count (`weighted`): a boundary
    shows up call after call, a value derived from one call's inputs
    (`balance - amount` compared with `balance` by a checked subtraction)
    once.  Per function only (see `guides`): `guides`, guard-directed inputs
    (where to put which value), `decisive`, the value flipping the guard that
    last rejected a call, per location (the latest), and `shapes`, mapping
    entries keyed by a call's own caller, arguments or selector.
    """

    partners: Dict[int, int] = dataclasses.field(default_factory=dict)
    others: Dict[int, int] = dataclasses.field(default_factory=dict)
    guides: Dict[Guide, int] = dataclasses.field(default_factory=dict)
    decisive: Dict[Loc, Guide] = dataclasses.field(default_factory=dict)
    shapes: Dict[Loc, int] = dataclasses.field(default_factory=dict)
    # the calldata words guides may touch: a typed function's static head words (offsets,
    # lengths and dynamic data are the decoder's: a guide there breaks the encoding); None: any
    words: Optional[FrozenSet[int]] = None

    @staticmethod
    def weighted(pool: Mapping[int, int]) -> List[int]:
        """Every value repeated as many times as calls showed it, at most WEIGHT_CAP."""
        return [v for v, seen in pool.items() for _ in range(min(seen, WEIGHT_CAP))]


def hardcoded_addresses(code: bytes, limit: int = 8) -> List[str]:
    """
    PUSH20 constants that look like addresses: not 0, not the 160-bit mask,
    not small, and not text (a 20-character string constant is a PUSH20 too).
    """
    out: List[str] = []
    for _pc, op, arg in disasm(own_code(code)):
        if op != 0x73 or arg is None or not 1 << 32 < arg < (1 << 160) - 1:
            continue
        raw = arg.to_bytes(20, "big")
        if all(0x20 <= b < 0x7F for b in raw):
            continue
        a = "0x" + raw.hex()
        if a not in out:
            out.append(a)
            if len(out) >= limit:
                break
    return out


def slot_constants(code: bytes, limit: int = 32) -> List[int]:
    """
    Storage slots written as constants in the code, seeded from the first
    call on: a PUSH feeding SLOAD / SSTORE (through at most three DUP / SWAP),
    and every 32-byte constant of at least 2^64 that is not a bit mask - the
    unstructured slots (EIP-1967, ERC-7201 namespaces) a dispatcher-level
    revert would otherwise hide, since a reverted call's reads are unknown to
    pyrevm.  A constant that is no slot only seeds a word nobody reads.
    """
    ins = disasm(own_code(code))
    out: Dict[int, None] = {}
    for i, (_pc, op, arg) in enumerate(ins):
        if arg is None:
            continue
        j = i + 1
        while j < len(ins) and j <= i + 3 and 0x80 <= ins[j][1] <= 0x9F:
            j += 1
        feeds = j < len(ins) and ins[j][1] in (0x54, 0x55)
        mask = arg & (arg + 1) == 0 or (~arg & _WORD) & ((~arg & _WORD) + 1) == 0
        if feeds or (op == 0x7F and arg >= 1 << 64 and not mask):
            out.setdefault(arg)
            if len(out) >= limit:
                break
    return list(out)


def env_sensitivity(code: bytes) -> List[str]:
    """
    Opcodes of `code` through which a recompiled candidate can legitimately
    behave differently when the environment is not virtualised: gas
    introspection (GAS not feeding a call), self code size / hash / copy,
    and opcodes the Cancun backends cannot execute.
    """
    ins = disasm(own_code(code))
    reasons = set()
    for i, (_pc, op, _arg) in enumerate(ins):
        if op == 0x5A and not (i + 1 < len(ins) and ins[i + 1][1] in _CALL_OPS):
            reasons.add("gasleft()")
        elif op == 0x38:
            reasons.add("codesize")
        elif op in (0x3B, 0x3C, 0x3F):
            reasons.add("extcode* (possibly of itself)")
        elif op == 0x1E:
            reasons.add("CLZ (post-Cancun opcode)")
    return sorted(reasons)


def _heavy(r: CallResult) -> bool:
    return r.halted or r.gas_used > HEAVY_GAS


def out_of_gas(r: Optional[CallResult], gas: int) -> bool:
    """
    Whether call result `r` (given `gas`) ran out of gas: an out-of-gas
    halt, or - through a caller mock, which catches the contract's failure -
    all but the 64th of the gas burnt.
    """
    if r is None:
        return False
    if r.error.startswith(("halt:OutOfGas", "halt:MemoryLimitOOG")):
        return True
    return r.success and 64 * r.gas_used >= 63 * gas


def contract_success(call: Call, r: CallResult) -> bool:
    """Whether the contract call itself succeeded (through a caller mock: the `ok` of its fwd)."""
    if call.via is None:
        return r.success
    return r.success and len(r.output) >= 32 and r.output[31] == 1


def _swap_addresses(blob: bytes, mapping: Dict[bytes, bytes]) -> bytes:
    for a, b in mapping.items():
        blob = blob.replace(a, b)
    return blob


def _translate(r: CallResult, mapping: Dict[bytes, bytes]) -> CallResult:
    """`r` with the candidate's created addresses replaced by the original's."""
    if not mapping:
        return r
    by_text = {"0x" + a.hex(): "0x" + b.hex() for a, b in mapping.items()}
    by_int = {int.from_bytes(a, "big"): int.from_bytes(b, "big") for a, b in mapping.items()}

    def word(v: int) -> int:
        if v in by_int:
            return by_int[v]
        return int.from_bytes(_swap_addresses(v.to_bytes(32, "big"), mapping), "big")

    return dataclasses.replace(
        r,
        output=_swap_addresses(r.output, mapping),
        logs=[
            (by_text.get(a, a), tuple(word(t) for t in ts), _swap_addresses(d, mapping))
            for a, ts, d in r.logs
        ],
        storage_diff={
            (by_text.get(a, a), s): (b, word(v)) for (a, s), (b, v) in r.storage_diff.items()
        },
        balances={by_text.get(a, a): v for a, v in r.balances.items()},
        calls=[
            (d, k, by_text.get(t, t), v, _swap_addresses(c, mapping)) for d, k, t, v, c in r.calls
        ],
        created=[(by_text.get(a, a), c) for a, c in r.created],
    )


def compare_results(
    a: CallResult,
    b: CallResult,
    balances_before: Mapping[str, int],
    compare_calls: bool,
    mapping: Optional[Dict[bytes, bytes]] = None,
) -> List[str]:
    """
    Divergence kinds between the original's result `a` and the candidate's
    `b` ([] = same).  `balances_before`: balances before the call (accounts
    one side did not touch kept them).  `mapping`: the candidate's created
    addresses -> the original's, extended with this call's creations; pass
    the same dict for every call of a sequence (later calls see the accounts).
    """
    kinds: List[str] = []
    # created contracts: matched by creation order (their CREATE2 addresses hash metadata-bearing
    # initcode); their constructors' effects are compared below like any storage / log / balance,
    # their code is not (a candidate compiled with other settings creates other, equivalent, code)
    mapping = {} if mapping is None else mapping
    for (ca, _), (cb, _) in zip(a.created, b.created):
        if ca != cb:
            mapping[bytes.fromhex(cb[2:])] = bytes.fromhex(ca[2:])
    b = _translate(b, mapping)
    if len(a.created) != len(b.created):
        kinds.append("created")
    if a.success != b.success:
        kinds.append("success")
    elif not a.success and a.halted != b.halted:
        kinds.append("halt")
    if a.success == b.success and a.output != b.output:
        kinds.append("returndata" if a.success else "revert_data")
    if a.logs != b.logs:
        kinds.append("logs")
    if {k: v[1] for k, v in a.storage_diff.items()} != {k: v[1] for k, v in b.storage_diff.items()}:
        kinds.append("storage")
    keys = set(a.balances) | set(b.balances)
    if any(
        a.balances.get(k, balances_before.get(k, 0)) != b.balances.get(k, balances_before.get(k, 0))
        for k in keys
    ):
        kinds.append("balance")
    if compare_calls and a.calls != b.calls:
        kinds.append("calls")
    return kinds


class Differ:
    """Differential executor for one (original, candidate) pair; see the module docstring."""

    def __init__(
        self,
        original: bytes,
        candidate: bytes,
        *,
        specs: Sequence[FuncSpec] = (),
        layout: Sequence[Var] = (),
        backend: str = "pyrevm",
        confirm_backend: Optional[str] = None,
        seed: int = 1,
        via_ratio: float = 0.4,
        mutate_ratio: float = 0.15,
        max_discovered: int = 256,
        max_divergences: int = 25,
        gas: int = DEFAULT_GAS,
        deadline: Optional[float] = None,
    ):
        self.original, self.candidate = bytes(original), bytes(candidate)
        self.backend = backend
        self.confirm_backend = confirm_backend if confirm_backend not in (None, backend) else None
        self.seed = seed
        self.via_ratio, self.mutate_ratio = via_ratio, mutate_ratio
        self.max_discovered, self.max_divergences = max_discovered, max_divergences
        self.gas, self.deadline = gas, deadline
        # typed specs: what stateful sequences and reentrant callers call
        self.specs = [s for s in specs if s.inputs is not None]
        self.blocks = BLOCKS
        self._sequence_gas_checks = 0
        # sequences whose last call differs only because the original runs out of a block's gas
        self.gas_sequences: List[Divergence] = []
        self._guided = False  # whether the last generated call placed guides
        self.hardcoded = hardcoded_addresses(self.original)
        self.static_slots = slot_constants(self.original)  # seeded like discovered slots
        self.universe = (
            SENDERS + [CONTRACT] + list(CALLERS) + [RETURN_STUB] + OTHERS + self.hardcoded
        )
        # the generic external contract is favoured for address arguments and fields: a token or a
        # target held in storage then answers (and records) the calls the contract makes to it
        self.contracts = [RETURN_STUB]
        self.plan = SeedPlan(layout, self.universe, SENDERS, contracts=self.contracts)
        # only an original that looks at its gas or its own code can make a pyrevm divergence
        # environment-made: only then are divergences replayed in the deterministic environment
        self.env_sensitive = bool(env_sensitivity(self.original))
        # per block: the values storage seeds take for deadlines and the like (+-1 added there)
        self.block_values = [(blk.timestamp, blk.number) for blk in self.blocks]
        env_values = [x + d for values in self.block_values for x in values for d in (-1, 0, 1)]
        # value dictionary: PUSH constants + environment values; each function learns, in a pool
        # of its own, the comparison operands it observes, so that its calls never depend on the
        # other functions
        self.base_dictionary = list(dict.fromkeys(push_dictionary(self.original) + env_values))
        # the constants the original - then the candidate - compares something with: the
        # boundaries tried first, until cmp-log has learned the function's own (a candidate's
        # literal may be a constant the original's optimiser computes, or a boundary of its own)
        self.static_partners = list(
            dict.fromkeys(
                comparison_constants(self.original, exclude=dispatcher_selectors(self.original))
                + comparison_constants(
                    self.candidate, exclude=dispatcher_selectors(self.candidate)
                )
            )
        )
        self.generic = int(RETURN_STUB, 16)  # what a guide puts where a contract is called
        self.learned = Learned()  # every function's (stateful sequences use them all)
        self._hooks = {
            "covered": CONTRACT,
            "gas_cap": GAS_CAP,
            "self_code": (len(self.original), keccak(self.original)),
        }
        self._worlds: Dict[Tuple[str, str, int, bool], World] = {}

    # ------------------------------------------------------------ worlds

    def _new_world(self, backend: str, side: str, block: int, stubs: bool) -> World:
        hooks = dict(self._hooks, cmplog=side == "o") if backend == "pyevm" else {}
        w = make_world(backend, self.blocks[block], **hooks)
        w.set_code(CONTRACT, self.original if side == "o" else self.candidate)
        for mock in MOCKS.values():
            w.set_code(mock.address, mock.runtime)
        if stubs:
            for a in self.hardcoded:
                w.set_code(a, MOCKS["ReturnStub"].runtime)
        return w

    @staticmethod
    def _apply(w: World, pre: PreState) -> None:
        w.set_storage_many(CONTRACT, pre.storage)
        for addr, slots in pre.env_storage.items():
            w.set_storage_many(addr, slots)
        for addr, wei in pre.balances.items():
            w.set_balance(addr, wei)

    def _call(self, w: World, call: Call, gas: Optional[int] = None) -> CallResult:
        gas = gas or self.gas
        if call.via:
            return w.call(
                call.sender,
                call.via,
                encode_fwd(CONTRACT, call.data, call.reentry),
                call.value,
                gas,
            )
        return w.call(call.sender, CONTRACT, call.data, call.value, gas)

    def execute(
        self,
        side: str,
        pre: PreState,
        call: Call,
        backend: Optional[str] = None,
        gas: Optional[int] = None,
    ) -> CallResult:
        """One call on a world in state `pre` ("o": original, "c": candidate)."""
        backend = backend or self.backend
        if backend == "pyevm":  # long-lived worlds + snapshot / revert (py-evm journals everything)
            key = (backend, side, pre.block, pre.stubs)
            if key not in self._worlds:
                self._worlds[key] = self._new_world(backend, side, pre.block, pre.stubs)
            w = self._worlds[key]
            token = w.snapshot()
            try:
                self._apply(w, pre)
                return self._call(w, call, gas)
            finally:
                w.revert(token)
        # pyrevm seeds bypass revert: fresh world
        w = self._new_world(backend, side, pre.block, pre.stubs)
        self._apply(w, pre)
        return self._call(w, call, gas)

    def check(
        self,
        pre: PreState,
        call: Call,
        backend: Optional[str] = None,
        gas: Optional[int] = None,
    ) -> Tuple[List[str], CallResult, CallResult]:
        backend = backend or self.backend
        ro = self.execute("o", pre, call, backend, gas)
        rc = self.execute("c", pre, call, backend, gas)
        return compare_results(ro, rc, pre.balances, backend == "pyevm"), ro, rc

    def _gas_bound(self, d: Divergence) -> bool:
        """A side of `d` halted or burnt over half of the call's gas: maybe a nested out-of-gas."""
        return any(
            r is not None and (r.halted or 2 * r.gas_used > self.gas)
            for r in (d.original, d.candidate)
        )

    def _gas_check(self, d: Divergence) -> str:
        """
        The gas-bound divergence `d` re-run with the block's whole gas limit
        (3 to 4.5 times a call's gas) for the call, or for every call of its
        sequence: "vanishes" when it disappears there (one side merely needed
        more gas than the other), "original" when it persists only because
        the original runs out of even that gas while the candidate does not
        (no block can observe what the original computes there), "" when it
        is behavioural.  A candidate that runs out of a whole block's gas where
        the original finishes stays divergent: it cannot do the original's work.
        """
        more = self.blocks[d.pre.block].gas_limit
        if d.label == "sequence":
            _, kinds, ro, rc = self.replay_sequence(
                d.pre, d.sequence + [d.call], d.backend, gas=more
            )
        else:
            kinds, ro, rc = self.check(d.pre, d.call, d.backend, gas=more)
        if not kinds:
            return "vanishes"
        if out_of_gas(ro, more) and not out_of_gas(rc, more):
            return "original"
        return ""

    # ------------------------------------------------------------ call generation

    def _stub_storage(self, rng: random.Random, used: Sequence[int]) -> Dict[int, int]:
        """The ReturnStub's mode and word (see `mocks`)."""
        # mode 5 (revert with data) is the only one telling a caller that bubbles revert data up
        mode = rng.choices((0, 1, 2, 3, 4, 5), weights=(40, 12, 10, 8, 15, 15))[0]
        if mode == 4:  # the answer is keccak256(calldata) & word: a bool, a byte, an address...
            value = rng.choice((1, 0xFF, (1 << 64) - 1, (1 << 160) - 1, (1 << 256) - 1))
        else:
            value = rng.choice([1, 1, 1, 0, 10**18, (1 << 256) - 1] + list(used[:2]))
        return {0: mode, 1: value % (1 << 256)}

    def _unknown_calldata(self, rng: random.Random, vg: ValueGen) -> bytes:
        if rng.random() < 0.25:
            # shorter than a selector
            return bytes(rng.getrandbits(8) for _ in range(rng.randrange(1, 4)))
        selector = rng.getrandbits(32).to_bytes(4, "big")
        return raw_calldata(rng, vg, selector)

    def _calldata(
        self,
        rng: random.Random,
        vg: ValueGen,
        spec: Optional[FuncSpec],
        probe: Optional[str],
        mutate: bool = True,
    ) -> Tuple[str, bytes]:
        if probe == "receive":
            return "", b""
        if probe == "fallback" or spec is None:
            return "", self._unknown_calldata(rng, vg)
        if spec.inputs is None:
            return "", raw_calldata(rng, vg, spec.selector)
        try:
            data = encode_call(spec, [vg.gen(t) for t in spec.inputs])
        except (EncodingError, ValueError, OverflowError, TypeError):
            return "", raw_calldata(rng, vg, spec.selector)
        if mutate and rng.random() < self.mutate_ratio:
            return mutate_calldata(rng, spec, data)
        return "", data

    def _values(self, rng: random.Random, learned: Optional[Learned]) -> ValueGen:
        """
        A value generator: the constants, the boundaries (the code's
        comparison constants at full weight, the learned partners weighted by
        recurrence), the environment's contracts.
        """
        learned = learned or Learned()
        return ValueGen(
            rng,
            self.universe,
            self.base_dictionary + list(learned.others),
            learned=self.static_partners * WEIGHT_CAP + Learned.weighted(learned.partners),
            contracts=self.contracts,
        )

    def _caller(self, rng: random.Random, data: bytes, vg: ValueGen) -> Tuple[Optional[str], bytes]:
        if rng.random() >= self.via_ratio:
            return None, b""
        # the reentrant caller also accepts ETH and answers callbacks like the accepting one: it
        # gets the largest share (interaction-before-effect bugs need it and a narrow pre-state)
        via = rng.choices(
            (ACCEPTING_CALLER, REJECTING_CALLER, REENTRANT_CALLER), weights=(1, 1, 2)
        )[0]
        if via != REENTRANT_CALLER:
            return via, b""
        if self.specs and rng.random() < 0.3:  # cross-function reentrancy
            other = rng.choice(self.specs)
            try:
                return via, encode_call(other, [vg.gen(t) for t in other.inputs])
            except (EncodingError, ValueError, OverflowError, TypeError):
                pass
        return via, data  # the same call again: the classic reentrancy

    def generate(
        self,
        rng: random.Random,
        spec: Optional[FuncSpec],
        discovered: Sequence[int] = (),
        probe: Optional[str] = None,
        plain: bool = False,
        learned: Optional[Learned] = None,
    ) -> Tuple[PreState, Call]:
        """
        One random (pre-state, call) for a function or a probe ("fallback" /
        "receive").  `plain`: well-formed calldata, no value, an EOA sender.
        `learned`: what cmp-log observed so far for this function; its
        mapping shapes add the entries of this call's own caller, arguments
        and selector to the slots seeded, and for GUIDE_RATIO of the calls
        its guides place their values (see `guides`).
        """
        vg = self._values(rng, learned)
        mutation, data = self._calldata(rng, vg, spec, probe, mutate=not plain)
        if plain:
            value = 0
        elif probe == "receive" or (spec is not None and spec.payable):
            value = rng.choice((0, 0, 1, 10**18, rng.randrange(1, 10**18)))
        else:
            value = call_value(rng)
        stubs = bool(self.hardcoded) and rng.random() < 0.5
        senders = SENDERS + ([] if stubs else self.hardcoded)
        sender = rng.choice(senders)
        via, reentry = (None, b"") if plain else self._caller(rng, data, vg)
        block = rng.randrange(len(self.blocks))
        ctx = Context.of(data, int(via or sender, 16), self.generic)
        chosen: List[Guide] = []
        if (
            learned is not None
            and (learned.guides or learned.decisive)
            and rng.random() < GUIDE_RATIO
        ):
            chosen = choose(rng, learned.guides)
            if learned.decisive and rng.random() < 0.5:
                # every decisive guide (the guards of the path learned so far), others at random
                chosen = [g for g in chosen if g.loc not in learned.decisive]
                chosen += learned.decisive.values()
            guided, guided_value = apply_call(
                rng, chosen, data, None if plain else value, ctx, SENDER_BALANCE // 2
            )
            value = value if guided_value is None else guided_value
            if guided != data:
                reentry = guided if reentry == data else reentry
                data = guided
                old = set(ctx.words)
                ctx = Context.of(data, ctx.sender, self.generic)
                vg.used.extend(w for w in ctx.words if w not in old)  # argument-aware seeds
        seeds = self.plan.per_call(
            rng,
            vg.used,
            vg.used_addresses,
            discovered,
            callers=[via or sender],
            constants=vg.dictionary + vg.learned,
            env=self.block_values[block],
            keyed=shape_slots(learned.shapes, ctx) if learned is not None else (),
        )
        balances = {a: SENDER_BALANCE for a in senders}
        # the contract's ETH: also one or two times an argument (a withdrawal it can pay, once)
        small = [v for v in vg.used if 0 < v < 10**30][:2]
        balances[CONTRACT] = rng.choice(
            [0, 10**18, 10**20, rng.getrandbits(80)] + small + [2 * v for v in small]
        )
        env_storage = {RETURN_STUB: self._stub_storage(rng, vg.used)}
        if stubs:
            for a in self.hardcoded:
                env_storage[a] = self._stub_storage(rng, vg.used)
        if chosen:
            apply_storage(rng, chosen, seeds.storage, env_storage, ctx, self.plan.admits)
        self._guided = bool(chosen)
        pre = PreState(seeds.storage, balances, env_storage, seeds.dirty, block, stubs)
        return pre, Call(sender, value, data, mutation, via, reentry)

    # ------------------------------------------------------------ per-function fuzzing

    def _expired(self) -> bool:
        return self.deadline is not None and time.monotonic() > self.deadline

    def fuzz_function(
        self,
        key: str,
        spec: Optional[FuncSpec],
        n: int,
        probe: Optional[str] = None,
        sample_size: int = 64,
    ) -> FunctionStats:
        """
        `n` random calls of one function (or probe), from a per-key RNG (so
        results do not depend on the other keys).  When the bulk backend has
        no hooks and py-evm is the confirming one, each of the first
        `sample_size` calls is replayed on the original under py-evm as soon
        as it ran: that measures branch coverage and feeds the original's
        comparison operands (cmp-log) to the learned values and guides of the
        next calls - a guard learned on one call is passed on the next ones,
        which then reach and teach the guard after it.  While the original
        has accepted no call, up to `sample_size` later guided calls it
        rejects are replayed the same way.
        """
        rng = random.Random(f"{self.seed}:{key}")
        stats = FunctionStats(key, spec.label if spec else f"<{probe}>")
        discovered: Dict[int, None] = dict.fromkeys(self.static_slots)
        learned = Learned()
        if spec is not None and spec.inputs is not None:
            learned.words = frozenset(i for i, t in head_words(spec.inputs) if t != "<offset>")
        replay = self.backend != "pyevm" and self.confirm_backend == "pyevm"
        extra = 0  # rejected calls replayed after the sample
        t0 = time.monotonic()
        for _ in range(n):
            # only real divergences stop the search: a function the original runs out of a
            # block's gas on (an INCONCLUSIVE verdict at best) keeps its calls, which may still
            # find a behavioural difference (beyond MAX_GAS_CHECKS no call is re-run)
            if self._expired() or stats.divergences >= self.max_divergences:
                break
            pre, call = self.generate(rng, spec, list(discovered), probe, learned=learned)
            guided = self._guided
            kinds, ro, rc = self.check(pre, call)
            stats.calls += 1
            stats.original_success += contract_success(call, ro)
            if len(stats.sample) < sample_size and not _heavy(ro):
                stats.sample.append((pre, call))
                if replay and not self._expired():
                    self._instrument(stats, learned, discovered, pre, call)
            elif (
                replay
                and guided
                and not stats.original_success
                and extra < sample_size
                and not _heavy(ro)
                and not self._expired()
            ):
                extra += 1  # the guard after those the guides passed
                self._instrument(stats, learned, discovered, pre, call)
            if (
                ro.success
                and call.value == 0
                and call.via is None
                and not call.mutation
                and stats.success_base is None
            ):
                stats.success_base = (pre, call)
            self._discover(discovered, pre, ro.storage_reads | rc.storage_reads)
            self._observe(stats, pre, call, ro, learned)
            if kinds:
                self._record(stats, Divergence(key, kinds, call, pre, ro, rc, self.backend))
        stats.elapsed = time.monotonic() - t0
        return stats

    def _discover(self, discovered: Dict[int, None], pre: PreState, reads) -> None:
        """
        Slots of the contract read but not seeded join `discovered` (pyrevm
        reports seeded slots as read: known anyway, and no read at all for a
        reverted call).  Sorted: set order varies between processes (str
        hashing), the RNG stream must not.
        """
        for addr, slot in sorted(reads):
            if addr == CONTRACT and slot not in pre.storage and slot not in discovered:
                if len(discovered) < self.max_discovered:
                    discovered[slot] = None

    def _observe(
        self, stats: FunctionStats, pre: PreState, call: Call, r: CallResult, learned: Learned
    ) -> None:
        """Coverage, comparison operands and guides of an instrumented execution of the original."""
        if r.jumpis:
            stats.covered |= r.jumpis
            stats.jumpi_pcs |= {pc for pc, _ in r.jumpis}
        self._learn(learned, r.compared, pre, call)
        if r.trace:
            self._guide(learned, pre, call, r)

    def _guide(self, learned: Learned, pre: PreState, call: Call, r: CallResult) -> None:
        """The guides and mapping shapes one instrumented execution teaches (see `guides`)."""
        ctx = Context.of(call.data, int(call.via or call.sender, 16), self.generic)
        failed = not contract_success(call, r) and not call.mutation
        lesson = learn(r, pre.storage, pre.env_storage, call.value, ctx, CONTRACT, failed)
        words = learned.words

        def usable(g: Guide) -> bool:  # no calldata word of the decoder's, as a place or a value
            return words is None or not (
                (g.loc.kind == "arg" and g.loc.n not in words)
                or (g.value.kind == "arg" and g.value.n not in words)
            )

        pools = (
            (learned.guides, [g for g in lesson.guides if usable(g)], MAX_GUIDES),
            (learned.shapes, lesson.shapes, MAX_SHAPES),
        )
        for pool, items, cap in pools:
            for item in items:
                if item in pool:
                    pool[item] += 1
                elif len(pool) < cap:
                    pool[item] = 1
        for g in lesson.decisive:
            if usable(g):
                learned.decisive.pop(g.loc, None)  # the latest last
                if len(learned.decisive) < MAX_GUIDES:
                    learned.decisive[g.loc] = g

    def _instrument(
        self,
        stats: FunctionStats,
        learned: Learned,
        discovered: Dict[int, None],
        pre: PreState,
        call: Call,
    ) -> None:
        """A sample call replayed on the original under py-evm: coverage, cmp-log, exact reads."""
        r = self.execute("o", pre, call, "pyevm")
        self._observe(stats, pre, call, r, learned)
        self._discover(discovered, pre, r.storage_reads)

    def find_success(
        self, key: str, spec: Optional[FuncSpec], tries: int = 400
    ) -> Optional[Tuple[PreState, Call]]:
        """A plain call the ORIGINAL accepts (only the original is executed), or None."""
        rng = random.Random(f"{self.seed}:accepted:{key}")
        discovered: Dict[int, None] = dict.fromkeys(self.static_slots)
        learned = Learned()
        for _ in range(tries):
            if self._expired():
                break
            pre, call = self.generate(rng, spec, list(discovered), plain=True, learned=learned)
            r = self.execute("o", pre, call)
            if r.success:
                return pre, call
            self._discover(discovered, pre, r.storage_reads)
            self._learn(learned, r.compared, pre, call)
        return None

    def dispatcher_pcs(self, selectors: Sequence[bytes], backend: str = "pyevm") -> Set[int]:
        """
        JUMPI pcs of the original's dispatcher: those executed by calls that
        reach no function - empty / short calldata, the neighbours s - 1 and
        s + 1 of every known selector (they walk the same binary-search path
        as s) and selectors spread over the whole range.  Deterministic, so
        cached per (original, selectors, backend): a pipeline verifying one
        function at a time asks for the same set again and again.
        """
        key = (keccak(self.original), frozenset(selectors), backend)
        if key in _DISPATCHER_PCS:
            return set(_DISPATCHER_PCS[key])
        pcs = self._dispatcher_pcs(selectors, backend)
        if len(_DISPATCHER_PCS) >= 64:
            _DISPATCHER_PCS.clear()
        _DISPATCHER_PCS[key] = frozenset(pcs)
        return pcs

    def _dispatcher_pcs(self, selectors: Sequence[bytes], backend: str) -> Set[int]:
        known = {int.from_bytes(sel, "big") for sel in selectors}
        probes = {(s + d) % (1 << 32) for s in known for d in (-1, 1)} | {
            k * 0x10000000 + 0x0BADF00D for k in range(16)
        }
        datas = [b"", b"\x01", b"\x01\x02\x03"] + [
            p.to_bytes(4, "big") for p in sorted(probes - known)
        ]
        pcs: Set[int] = set()
        pre = PreState({}, {SENDERS[0]: SENDER_BALANCE})
        for data in datas:
            pcs |= {
                pc for pc, _ in self.execute("o", pre, Call(SENDERS[0], 0, data), backend).jumpis
            }
        return pcs

    def _learn(self, learned: Learned, operands: Sequence[int], pre: PreState, call: Call) -> None:
        """
        cmp-log (input-to-state): of each compared pair, a value compared with
        one of the call's own inputs (calldata words, seeded storage words,
        msg.value) is a partner - a boundary the later calls try to hit, +- 1;
        the operands of a pair without input are kept as other values.  The
        dispatcher's selector tests and the ABI decoder's calldata-size checks
        are skipped.  Each value counts once per call.
        """
        if not operands:
            return
        inputs = {
            int.from_bytes(call.data[i : i + 32], "big") for i in range(4, len(call.data), 32)
        }
        inputs.update(pre.storage.values())
        inputs.add(call.value)
        shape = {len(call.data), len(call.data) - 4, int.from_bytes(call.data[:4], "big")}
        partners: Dict[int, None] = {}
        others: Dict[int, None] = {}
        for a, b in zip(operands[0::2], operands[1::2]):
            if a in shape or b in shape:
                continue
            ia, ib = a in inputs, b in inputs
            if ia != ib:
                partners.setdefault(b if ia else a)
            elif not ia:
                others.setdefault(a)
                others.setdefault(b)
        for v in partners:
            self._keep(learned.partners, self.learned.partners, v)
        for v in others:
            self._keep(learned.others, self.learned.others, v)

    @staticmethod
    def _keep(pool: Dict[int, int], everyone: Dict[int, int], v: int) -> None:
        """Counts `v` in a function's pool and in the pool of every function (sequences)."""
        if v <= 1:
            return
        for p, cap in ((pool, MAX_LEARNED), (everyone, 4 * MAX_LEARNED)):
            if v in p:
                p[v] += 1
            elif len(p) < cap:
                p[v] = 1

    def _confirm(self, d: Divergence) -> Optional[Divergence]:
        """The divergence seen in the deterministic py-evm environment, or None if it vanishes."""
        if not self.confirm_backend:
            return d
        if d.label == "sequence":
            calls = d.sequence + [d.call]
            index, kinds, ro, rc = self.replay_sequence(d.pre, calls, self.confirm_backend)
            if not kinds:
                return None
            return dataclasses.replace(
                d,
                kinds=kinds,
                call=calls[index],
                sequence=calls[:index],
                original=ro,
                candidate=rc,
                backend=self.confirm_backend,
            )
        kinds, ro, rc = self.check(d.pre, d.call, self.confirm_backend)
        if not kinds:
            return None
        return dataclasses.replace(
            d, kinds=kinds, original=ro, candidate=rc, backend=self.confirm_backend
        )

    def _record(self, stats: FunctionStats, d: Divergence) -> None:
        gas = ""
        if self._gas_bound(d):
            if stats.gas_checks < MAX_GAS_CHECKS.get(d.backend, 2):
                stats.gas_checks += 1
                gas = self._gas_check(d)
            elif (
                stats.gas_divergences
                and not stats.divergences
                and out_of_gas(d.original, self.gas)
                and not out_of_gas(d.candidate, self.gas)
            ):
                gas = "original"  # the pattern the re-checks confirmed, without one more re-run
        if gas == "vanishes":
            stats.env_divergences += 1
            stats.first_env = stats.first_env or d
            return
        if gas == "original":
            stats.gas_divergences += 1
            stats.first_gas = stats.first_gas or d
            return
        confirmed = self._confirm(d) if self.env_sensitive else d
        if confirmed is None:
            stats.env_divergences += 1
            stats.first_env = stats.first_env or d
            return
        stats.divergences += 1
        for k in confirmed.kinds:
            stats.kinds[k] += 1
        if stats.first is None:
            stats.first = self.explain(d, confirmed)

    def explain(self, d: Divergence, confirmed: Optional[Divergence] = None) -> Divergence:
        """
        The counterexample to report for a divergence found by the bulk
        backend: shrunk there (fast), then replayed on the confirming backend
        (instrumented results: call tree...) when there is one.
        """
        small = self.shrink(d)
        if not self.confirm_backend or (not self.env_sensitive and _heavy(small.original)):
            return small
        replayed = self._confirm(small)
        if replayed is not None:
            return replayed
        # the shrunk call diverges only outside the deterministic environment: report the
        # divergence as confirmed before shrinking
        if confirmed is not None and confirmed.backend == self.confirm_backend:
            return confirmed
        return self._confirm(d) or small

    # ------------------------------------------------------------ shrinking

    def _still(self, d: Divergence, pre: PreState, call: Call) -> Optional[Divergence]:
        kinds, ro, rc = self.check(pre, call, d.backend)
        return (
            dataclasses.replace(d, kinds=kinds, pre=pre, call=call, original=ro, candidate=rc)
            if kinds
            else None
        )

    def shrink(self, d: Divergence, max_checks: int = 96) -> Divergence:
        """Greedy reduction of a per-call divergence: fewer seeds, no value, an EOA caller."""
        if d.label == "sequence":
            return self.shrink_sequence(d)
        checks = 0
        slots = list(d.pre.storage)
        chunk = max(1, len(slots) // 2)
        while chunk >= 1 and checks < max_checks:  # drop seeds by halves, then one at a time
            i = 0
            while i < len(slots) and checks < max_checks:
                trial = d.pre
                for s in slots[i : i + chunk]:
                    trial = trial.without(s)
                checks += 1
                smaller = self._still(d, trial, d.call)
                if smaller is not None:
                    d = smaller
                    slots = slots[:i] + slots[i + chunk :]
                else:
                    i += chunk
            chunk //= 2
        for simpler in (
            dataclasses.replace(d.call, value=0),
            dataclasses.replace(d.call, via=None, reentry=b""),
        ):
            if checks >= max_checks or simpler == d.call:
                continue
            checks += 1
            d = self._still(d, d.pre, simpler) or d
        if d.pre.dirty and checks < max_checks:
            clean = dataclasses.replace(
                d.pre, storage=clean_words(d.pre.storage, d.pre.dirty), dirty={}
            )
            if self._still(d, clean, d.call) is None:
                d = dataclasses.replace(d, label="dirty_storage")
        return d

    # ------------------------------------------------------------ stateful sequences

    def _reachable_pre(self, rng: random.Random) -> PreState:
        balances = {a: SENDER_BALANCE for a in SENDERS}
        balances[CONTRACT] = rng.choice((0, 10**18, 10**20))
        return PreState(
            self.plan.reachable(rng),
            balances,
            {RETURN_STUB: {0: 0, 1: 1}},
            {},
            rng.randrange(len(self.blocks)),
        )

    def _sequence_call(self, rng: random.Random, spec: FuncSpec, learned: Learned) -> Call:
        vg = self._values(rng, learned)
        data = encode_call(spec, [vg.gen(t) for t in spec.inputs])
        if rng.random() < 0.05:
            _, data = mutate_calldata(rng, spec, data)
        via, reentry = self._caller(rng, data, vg)
        value = (
            rng.choice((0, 1, 10**18, rng.randrange(1, 10**18)))
            if spec.payable
            else call_value(rng)
        )
        return Call(rng.choice(SENDERS), value, data, "", via, reentry)

    def replay_sequence(
        self,
        pre: PreState,
        calls: Sequence[Call],
        backend: Optional[str] = None,
        gas: Optional[int] = None,
    ) -> Tuple[int, List[str], Optional[CallResult], Optional[CallResult]]:
        """
        Runs `calls` in order on fresh worlds from `pre` and stops at the first
        divergent one: (its index, kinds, original result, candidate result);
        kinds is [] when no call diverges.  `gas`: per call (default the Differ's).
        """
        backend = backend or self.backend
        wo = self._new_world(backend, "o", pre.block, pre.stubs)
        wc = self._new_world(backend, "c", pre.block, pre.stubs)
        self._apply(wo, pre)
        self._apply(wc, pre)
        ro = rc = None
        balances, mapping = dict(pre.balances), {}
        for index, call in enumerate(calls):
            ro, rc = self._call(wo, call, gas), self._call(wc, call, gas)
            kinds = compare_results(ro, rc, balances, backend == "pyevm", mapping)
            if kinds:
                return index, kinds, ro, rc
            balances.update(ro.balances)
        return len(calls), [], ro, rc

    def fuzz_sequences(self, n_seq: int, seq_len: int) -> Tuple[List[Divergence], int]:
        """
        `n_seq` sequences of `seq_len` calls over the typed functions, from a
        plausible start state, without reverting between calls.  Returns the
        confirmed divergences (at most one per sequence, as found by the bulk
        backend) and the number of calls made; the sequences that differ only
        because the original runs out of a block's gas go to `gas_sequences`.
        """
        out: List[Divergence] = []
        made = 0
        if not self.specs:
            return out, made
        learned = Learned(dict(self.learned.partners), dict(self.learned.others))
        for i in range(n_seq):
            if self._expired():
                break
            rng = random.Random(f"{self.seed}:sequence:{i}")
            pre = self._reachable_pre(rng)
            wo = self._new_world(self.backend, "o", pre.block, pre.stubs)
            wc = self._new_world(self.backend, "c", pre.block, pre.stubs)
            self._apply(wo, pre)
            self._apply(wc, pre)
            history: List[Call] = []
            balances, mapping = dict(pre.balances), {}
            for _ in range(seq_len):
                spec = rng.choice(self.specs)
                try:
                    call = self._sequence_call(rng, spec, learned)
                except (EncodingError, ValueError, OverflowError, TypeError):
                    continue
                ro, rc = self._call(wo, call), self._call(wc, call)
                made += 1
                kinds = compare_results(ro, rc, balances, self.backend == "pyevm", mapping)
                if kinds:
                    d = Divergence(
                        spec.key, kinds, call, pre, ro, rc, self.backend, list(history), "sequence"
                    )
                    gas = ""
                    if (
                        self._sequence_gas_checks < MAX_GAS_CHECKS.get(self.backend, 2)
                        and self._gas_bound(d)
                    ):
                        self._sequence_gas_checks += 1
                        gas = self._gas_check(d)
                    if gas == "original":
                        self.gas_sequences.append(d)
                    elif not gas and (not self.env_sensitive or self._confirm(d) is not None):
                        out.append(d)  # unshrunk: `explain` it when it becomes a counterexample
                    break
                history.append(call)
                balances.update(ro.balances)
        return out, made

    def shrink_sequence(self, d: Divergence, max_checks: int = 48) -> Divergence:
        """Drops earlier calls of a sequence one at a time while the last call still diverges."""
        calls = list(d.sequence)
        checks, i = 0, 0
        while i < len(calls) and checks < max_checks:
            trial = calls[:i] + calls[i + 1 :]
            checks += 1
            index, kinds, ro, rc = self.replay_sequence(d.pre, trial + [d.call], d.backend)
            if kinds and index == len(trial):  # still diverging, and still on the final call
                calls = trial
                d = dataclasses.replace(
                    d, kinds=kinds, original=ro, candidate=rc, sequence=list(trial)
                )
            else:
                i += 1
        return d

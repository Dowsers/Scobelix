"""
py-evm backend (~3-6k raw calls/s, a few hundred with every hook on): the
instrumented executor.

Messages run at the State level (no chain, no transaction validation) and
every observation is a Python hook:
  * storage reads and before-values through a State subclass (exact);
  * the internal call tree from `computation.children` (depth, kind, target,
    value, calldata) and the contracts created, in creation order;
  * branch coverage - (pc, taken) of every JUMPI - and comparison operands
    (EQ/LT/GT/SLT/SGT/SUB/XOR, a "cmp-log" dictionary, in operand pairs) of
    the covered contract, and, in execution order, its comparisons, what it
    tests for zero (ISZERO), its calls and the EXTCODE* targets it finds
    without code, with the 32 / 64-byte inputs it hashes (mapping slots):
    what guard-directed inputs are learned from (`verify.guides`);
  * a deterministic environment: GAS pushes min(real, gas_cap / 4**depth),
    and CODESIZE / EXTCODESIZE / EXTCODEHASH of the covered contract report
    the given (original's) values.  A recompiled candidate uses different gas
    and has a different size: with this, `gasleft()`, forwarded gas and
    `address(this).code` no longer distinguish it from the original.

BLOCKHASH(n) of the 256 previous blocks is keccak256 of n in decimal, the
value revm's empty database (hence pyrevm) answers: both backends see the
same environment.
"""

from __future__ import annotations

import collections
import functools
import importlib
from typing import Deque, Dict, List, Optional, Set, Tuple

from .base import DEFAULT_GAS, BackendUnavailable, BlockSpec, CallResult, HarnessError, World, lower

__all__ = ["FORKS", "PyEvmWorld"]

FORKS = {
    "shanghai": ("eth.vm.forks.shanghai.state", "ShanghaiState"),
    "cancun": ("eth.vm.forks.cancun.state", "CancunState"),
    "prague": ("eth.vm.forks.prague.state", "PragueState"),
}
# LT GT SLT SGT EQ, and SUB / XOR: solc compiles many `x != c` as `jumpi(.., sub(x, c))`
_CMP_OPS = (0x10, 0x11, 0x12, 0x13, 0x14, 0x03, 0x18)
_MAX_OPERANDS = 512  # per call, an even number: operands come in pairs
# guard trace events kept per call: the first ones, and the last ones (what made it revert)
_MAX_TRACE = 4096
_TRACE_TAIL = 512
_MAX_HASHES = 256  # per call
# CALL CALLCODE DELEGATECALL STATICCALL (target: second operand), EXTCODESIZE EXTCODECOPY
# EXTCODEHASH (target: first operand)
_TARGET_OPERAND = {0xF1: 2, 0xF2: 2, 0xF4: 2, 0xFA: 2, 0x3B: 1, 0x3C: 1, 0x3F: 1}
_PRECOMPILES = 0xFFFF  # addresses up to this one: precompiles (present and future), never stubbed
_ADDRESS = (1 << 160) - 1


def _int(v) -> int:
    return v if isinstance(v, int) else int.from_bytes(v, "big")


@functools.lru_cache(maxsize=16)
def _prev_hashes(number: int) -> Tuple[bytes, ...]:
    """The 256 hashes before block `number`, most recent first, as revm's empty DB has them."""
    from eth_utils import keccak

    return tuple(keccak(text=str(number - 1 - i)) for i in range(min(256, number)))


class PyEvmWorld(World):
    name = "pyevm"
    exact_reads = True
    has_hooks = True

    def __init__(
        self,
        block: BlockSpec = BlockSpec(),
        fork: str = "cancun",
        *,
        covered: Optional[str] = None,
        gas_cap: Optional[int] = None,
        self_code: Optional[Tuple[int, bytes]] = None,
        cmplog: bool = False,
    ):
        """
        covered: address whose JUMPIs / comparisons are recorded and whose
        self-introspection `self_code` = (code size, code hash) virtualises;
        gas_cap: GAS pushes min(real, gas_cap / 4**depth) in every frame.
        """
        try:
            from eth.constants import BLANK_ROOT_HASH
            from eth.db.atomic import AtomicDB
            from eth.vm.execution_context import ExecutionContext
            from eth.vm.message import Message
            from eth_utils import to_canonical_address
        except ImportError as e:  # pragma: no cover - depends on the environment
            raise BackendUnavailable(
                "py-evm is not installed (pip install 'scobelix[verify]')"
            ) from e
        if fork not in FORKS:
            raise ValueError(f"unsupported fork {fork!r} (one of {sorted(FORKS)})")
        module, cls_name = FORKS[fork]
        base_state = getattr(importlib.import_module(module), cls_name)
        self._canon = to_canonical_address
        self._Message = Message
        self._covered = to_canonical_address(covered) if covered else None
        self._reads: Set[Tuple[bytes, int]] = set()
        self._first: Dict[Tuple[bytes, int], int] = {}
        self._jumpis: Set[Tuple[int, bool]] = set()
        self._compared: List[int] = []
        self._trace: List[Tuple[int, int, int]] = []
        self._tail: Deque[Tuple[int, int, int]] = collections.deque(maxlen=_TRACE_TAIL)
        self._hashes: List[Tuple[int, Tuple[int, ...]]] = []
        self._balance_touched: Set[bytes] = set()
        self._recording = False
        self._cmplog = cmplog
        comp_cls = self._hooked_computation(base_state.computation_class, gas_cap, self_code)
        world = self

        class RecordingState(base_state):
            computation_class = comp_cls

            # the hooks record only while a call runs (not while the pre-state is written)
            def get_storage(self, address, slot, from_journal=True):
                v = super().get_storage(address, slot, from_journal)
                if world._recording:
                    world._reads.add((address, slot))
                    world._first.setdefault((address, slot), v)
                return v

            def set_storage(self, address, slot, value):
                if world._recording and (address, slot) not in world._first:
                    world._first[(address, slot)] = super().get_storage(address, slot)
                return super().set_storage(address, slot, value)

            def set_balance(self, address, balance):  # every balance change (selfdestruct included)
                if world._recording:
                    world._balance_touched.add(address)
                return super().set_balance(address, balance)

        ctx = ExecutionContext(
            coinbase=to_canonical_address(block.coinbase),
            timestamp=block.timestamp,
            block_number=block.number,
            difficulty=0,
            mix_hash=block.prevrandao,
            gas_limit=block.gas_limit,
            prev_hashes=_prev_hashes(block.number),
            chain_id=block.chain_id,
            base_fee_per_gas=block.basefee,
            excess_blob_gas=0,
        )
        self.state = RecordingState(AtomicDB(), ctx, BLANK_ROOT_HASH)

    def _hooked_computation(
        self, base_comp, gas_cap: Optional[int], self_code: Optional[Tuple[int, bytes]]
    ):
        world = self
        ops = dict(base_comp.opcodes)

        def wrap(code: int, fn, mnemonic: str):
            fn.mnemonic = mnemonic
            ops[code] = fn

        orig_jumpi = base_comp.opcodes[0x57]

        # the hooks read operands only when they are there: on a stack underflow the original
        # opcode raises the EVM's own error
        def jumpi(computation):
            vals = computation._stack.values
            if computation.msg.code_address == world._covered and len(vals) >= 2:
                world._jumpis.add((computation.code.program_counter - 1, bool(_int(vals[-2]))))
            return orig_jumpi(computation=computation)

        wrap(0x57, jumpi, "JUMPI")

        if self._cmplog:
            for code in _CMP_OPS:
                orig = base_comp.opcodes[code]

                def cmp(computation, _orig=orig, _code=code):
                    vals = computation._stack.values
                    if computation.msg.code_address == world._covered and len(vals) >= 2:
                        a, b = _int(vals[-1]), _int(vals[-2])
                        if len(world._compared) < _MAX_OPERANDS:
                            world._compared.append(a)
                            world._compared.append(b)
                        world._event((_code, a, b))
                    return _orig(computation=computation)

                wrap(code, cmp, orig.mnemonic)

        if gas_cap is not None:
            orig_gas = base_comp.opcodes[0x5A]

            def gas(computation):
                # cap / 4**depth: a frame forwarded the cap of its depth still reads the (smaller)
                # cap of the next depth unless it burnt 3/4 of it - so values never leak real gas
                orig_gas(computation=computation)
                cap = gas_cap >> (2 * computation.msg.depth)
                computation.stack_push_int(min(computation.stack_pop1_int(), cap))

            wrap(0x5A, gas, "GAS")

        if self_code is not None:
            size, code_hash = self_code
            orig_cs = base_comp.opcodes[0x38]

            def codesize(computation):
                orig_cs(computation=computation)
                if computation.msg.code_address == world._covered:
                    computation.stack_pop1_int()
                    computation.stack_push_int(size)

            def ext(orig, value):
                def hook(computation):
                    vals = computation._stack.values
                    target = (
                        (_int(vals[-1]) & ((1 << 160) - 1)).to_bytes(20, "big") if vals else None
                    )
                    orig(computation=computation)
                    if target == world._covered:
                        computation.stack_pop1_any()
                        if isinstance(value, int):
                            computation.stack_push_int(value)
                        else:
                            computation.stack_push_bytes(value)

                return hook

            wrap(0x38, codesize, "CODESIZE")
            wrap(0x3B, ext(base_comp.opcodes[0x3B], size), "EXTCODESIZE")
            wrap(0x3F, ext(base_comp.opcodes[0x3F], code_hash), "EXTCODEHASH")

        if self._cmplog:  # after the hooks above: these wrap whatever opcode is installed
            self._guard_hooks(ops, wrap)

        return type("HookedComputation", (base_comp,), {"opcodes": ops})

    def _event(self, e: Tuple[int, int, int]) -> None:
        if len(self._trace) < _MAX_TRACE:
            self._trace.append(e)
        else:
            self._tail.append(e)

    def _guard_hooks(self, ops: dict, wrap) -> None:
        """Records what guard-directed inputs learn from (see the module docstring)."""
        world = self
        orig_iszero, orig_sha3 = ops[0x15], ops[0x20]

        def iszero(computation):
            vals = computation._stack.values
            if computation.msg.code_address == world._covered and vals:
                world._event((0x15, _int(vals[-1]), 0))
            return orig_iszero(computation=computation)

        def sha3(computation):
            vals = computation._stack.values
            start = size = -1
            if computation.msg.code_address == world._covered and len(vals) >= 2:
                start, size = _int(vals[-1]), _int(vals[-2])
            orig_sha3(computation=computation)  # extends the memory read below
            if size in (32, 64) and len(world._hashes) < _MAX_HASHES:
                data = bytes(computation.memory_read_bytes(start, size))
                words = tuple(int.from_bytes(data[i : i + 32], "big") for i in range(0, size, 32))
                world._hashes.append((_int(computation._stack.values[-1]), words))

        def target(orig, code: int, position: int):
            # every call: (code, target, 1 if it has code else 0); EXTCODE*: targets without code
            def hook(computation):
                vals = computation._stack.values
                if computation.msg.code_address == world._covered and len(vals) >= position:
                    to = _int(vals[-position]) & _ADDRESS
                    if to > _PRECOMPILES:
                        has = bool(computation.state.get_code(to.to_bytes(20, "big")))
                        if not has or position == 2:
                            world._event((code, to, int(has)))
                return orig(computation=computation)

            return hook

        wrap(0x15, iszero, "ISZERO")
        wrap(0x20, sha3, "SHA3")
        for code, position in _TARGET_OPERAND.items():
            wrap(code, target(ops[code], code, position), ops[code].mnemonic)

    def set_code(self, addr: str, code: bytes) -> None:
        self.state.set_code(self._canon(addr), bytes(code))

    def set_storage(self, addr: str, slot: int, value: int) -> None:
        self.state.set_storage(self._canon(addr), slot, value)

    def set_storage_many(self, addr: str, slots: Dict[int, int]) -> None:
        canon, store = self._canon(addr), self.state.set_storage  # one address conversion
        for slot, value in slots.items():
            store(canon, slot, value)

    def set_balance(self, addr: str, wei: int) -> None:
        self.state.set_balance(self._canon(addr), wei)

    def get_storage(self, addr: str, slot: int) -> int:
        return self.state.get_storage(self._canon(addr), slot)

    def get_balance(self, addr: str) -> int:
        return self.state.get_balance(self._canon(addr))

    def get_code(self, addr: str) -> bytes:
        return self.state.get_code(self._canon(addr))

    def snapshot(self):
        return self.state.snapshot()

    def revert(self, token) -> None:
        self.state.revert(token)

    def call(
        self,
        caller: str,
        to: str,
        data: bytes,
        value: int = 0,
        gas: int = DEFAULT_GAS,
        static: bool = False,
    ) -> CallResult:
        from eth.exceptions import InsufficientFunds

        st = self.state
        self._reads, self._first, self._jumpis, self._compared = set(), {}, set(), []
        self._trace, self._hashes = [], []
        self._tail.clear()
        self._balance_touched = set()
        sender, target = self._canon(caller), self._canon(to)
        touched = {sender, target}
        msg = self._Message(
            gas=gas,
            to=target,
            sender=sender,
            value=value,
            data=data,
            code=st.get_code(target),
            is_static=static,
        )
        tx = st.get_transaction_context_class()(gas_price=0, origin=sender)
        try:  # a new transaction: no transient storage left by the previous call
            st.clear_transient_storage()
        except AttributeError:  # forks before Cancun have none
            pass
        self._recording = True
        try:
            comp = st.computation_class.apply_message(st, msg, tx)
        except InsufficientFunds as e:
            raise HarnessError(f"sender cannot pay the call value: {e}") from e
        finally:
            self._recording = False
        calls: List[Tuple[int, str, str, int, bytes]] = []
        created: List[Tuple[str, bytes]] = []

        def walk(c):
            for ch in c.children:
                m = ch.msg
                if m.is_create:
                    kind = "create"
                elif m.is_static and not c.msg.is_static:
                    kind = "static"
                elif m.storage_address != m.code_address:
                    kind = "delegate"
                else:
                    kind = "call"
                calls.append(
                    (
                        m.depth,
                        kind,
                        lower(m.code_address or m.storage_address),
                        m.value,
                        bytes(m.data),
                    )
                )
                touched.add(m.storage_address)
                if m.is_create and ch.is_success:
                    created.append(
                        (lower(m.storage_address), bytes(st.get_code(m.storage_address)))
                    )
                walk(ch)

        walk(comp)
        success = comp.is_success
        diff = {}
        if success:
            for (a, s), before in self._first.items():
                after = st.get_storage(a, s)
                if before != after:
                    diff[(lower(a), s)] = (before, after)
        if success:
            error = ""
        else:
            error = (
                "revert"
                if type(comp.error).__name__ == "Revert"
                else "halt:" + type(comp.error).__name__
            )
        logs = (
            [(lower(a), tuple(t), bytes(d)) for a, t, d in comp.get_log_entries()]
            if success
            else []
        )
        balances = {lower(a): st.get_balance(a) for a in touched | self._balance_touched}
        return CallResult(
            success,
            bytes(comp.output),
            error,
            logs,
            diff,
            {(lower(a), s) for a, s in self._reads},
            balances,
            created if success else [],
            gas - comp.get_gas_remaining(),  # a revert returns its unused gas, a halt burns it all
            calls,
            set(self._jumpis),
            list(self._compared),
            self._trace + list(self._tail),
            list(self._hashes),
        )

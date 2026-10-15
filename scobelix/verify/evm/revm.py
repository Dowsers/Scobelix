"""
revm backend, through pyrevm (~100k raw calls/s): the bulk executor.

pyrevm 0.3.7 traps, all handled here:
  * `spec_id` is matched case-sensitively against revm's names ("Cancun");
    anything else, including the documented "SHANGHAI", silently means
    LATEST - fork names are validated before use;
  * GASLIMIT reports the `gas_limit` given to `EVM()` (default 2^64 - 1),
    not the block's: the block's is passed there (a call may then not ask
    for more gas than the block holds);
  * a revert or halt raises RuntimeError and the revert data only exists in
    the message text ("Revert { gas_used: N, output: 0x.. }");
  * there is no state-diff API: storage writes, balances and created
    contracts are parsed from `journal_str` (a Rust Debug dump), whose slot
    list also contains seeded-but-unread slots, so reads are approximate;
  * `insert_account_storage` bypasses snapshot / revert: use a fresh world
    per independent call;
  * EIP-3607 is enforced: a caller with code is rejected.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .base import DEFAULT_GAS, BackendUnavailable, BlockSpec, CallResult, HarnessError, World, lower

__all__ = ["PyRevmWorld", "SPECS"]

SPECS = {"shanghai": "Shanghai", "cancun": "Cancun", "prague": "Prague"}

_ACCOUNT = re.compile(
    r"(0x[0-9a-f]{40}): Account \{ info: AccountInfo \{ balance: (\d+), nonce: \d+, "
    r"code_hash: 0x[0-9a-f]{64}, code: "
)
_SLOT = re.compile(r"(\d+): StorageSlot \{ previous_or_original_value: \d+, present_value: (\d+)")
_CODE = re.compile(
    r"Some\(Bytecode \{ bytecode: 0x([0-9a-f]*), state: (?:Analysed \{ len: (\d+)|(\w+))"
)
_CREATED = re.compile(r"AccountCreated \{ address: (0x[0-9a-f]{40})")
_REVERT = re.compile(r"output: 0x([0-9a-f]*)")


_ACCOUNT_INFOS: Dict[bytes, object] = {}  # code -> AccountInfo(code), reused by every fresh world


class PyRevmWorld(World):
    name = "pyrevm"
    exact_reads = False
    has_hooks = False

    def __init__(self, block: BlockSpec = BlockSpec(), fork: str = "cancun"):
        try:
            import pyrevm
        except ImportError as e:  # pragma: no cover - depends on the environment
            raise BackendUnavailable(
                "pyrevm is not installed (pip install 'scobelix[verify]')"
            ) from e
        if fork not in SPECS:
            raise ValueError(f"unsupported fork {fork!r} (one of {sorted(SPECS)})")
        self._pyrevm = pyrevm
        env = pyrevm.Env(
            cfg=pyrevm.CfgEnv(chain_id=block.chain_id),
            block=pyrevm.BlockEnv(
                number=block.number,
                coinbase=block.coinbase,
                timestamp=block.timestamp,
                prevrandao=block.prevrandao,
                basefee=block.basefee,
                gas_limit=block.gas_limit,
            ),
        )
        self.evm = pyrevm.EVM(env=env, spec_id=SPECS[fork], gas_limit=block.gas_limit)
        # what this world's state is known to be outside the journal: the before-values of a diff
        self._storage: Dict[Tuple[str, int], int] = {}
        self._balances: Dict[str, int] = {}
        self._codes: Dict[str, bytes] = {}

    def set_code(self, addr: str, code: bytes) -> None:
        addr, code = lower(addr), bytes(code)
        balance = self._balances.get(addr, 0)
        if balance:
            info = self._pyrevm.AccountInfo(code=code, balance=balance)
        else:  # building an AccountInfo hashes the code: share one per code
            info = _ACCOUNT_INFOS.get(code)
            if info is None:
                if len(_ACCOUNT_INFOS) > 256:
                    _ACCOUNT_INFOS.clear()
                info = _ACCOUNT_INFOS[code] = self._pyrevm.AccountInfo(code=code)
        self.evm.insert_account_info(addr, info)
        self._codes[addr] = code

    def set_storage(self, addr: str, slot: int, value: int) -> None:
        addr = lower(addr)
        self.evm.insert_account_storage(addr, slot, value)
        self._storage[(addr, slot)] = value

    def set_storage_many(self, addr: str, slots: Dict[int, int]) -> None:
        addr = lower(addr)
        insert = self.evm.insert_account_storage
        for slot, value in slots.items():
            insert(addr, slot, value)
            self._storage[(addr, slot)] = value

    def set_balance(self, addr: str, wei: int) -> None:
        self.evm.set_balance(lower(addr), wei)
        self._balances[lower(addr)] = wei

    def get_storage(self, addr: str, slot: int) -> int:
        return self.evm.storage(lower(addr), slot)

    def get_balance(self, addr: str) -> int:
        return self.evm.get_balance(lower(addr))

    def snapshot(self):
        return self.evm.snapshot(), dict(self._storage), dict(self._balances), dict(self._codes)

    def revert(self, token) -> None:
        checkpoint, self._storage, self._balances, self._codes = token
        self.evm.revert(checkpoint)

    def _journal(self) -> Tuple[Dict[str, Tuple[int, Dict[int, int], Optional[bytes]]], List[str]]:
        """
        {address: (balance, {slot: present value}, code)} of the journaled
        state and the addresses created (code is parsed for those only).
        """
        js = self.evm.journal_str
        end = js.find("}}, transient_storage:")
        state, tail = (js[: end + 1], js[end:]) if end > 0 else (js, "")
        created = list(dict.fromkeys(a for a in _CREATED.findall(tail) if a not in self._codes))
        heads = list(_ACCOUNT.finditer(state))
        accounts: Dict[str, Tuple[int, Dict[int, int], Optional[bytes]]] = {}
        for i, m in enumerate(heads):
            seg_end = heads[i + 1].start() if i + 1 < len(heads) else len(state)
            code = None
            if m.group(1) in created:
                cm = _CODE.match(state, m.end())
                if cm:
                    code = bytes.fromhex(cm.group(1))
                    if cm.group(2) is not None:  # analysed code is padded: keep its real length
                        code = code[: int(cm.group(2))]
            k = state.rfind("storage: {", m.end(), seg_end)
            slots = {int(s): int(v) for s, v in _SLOT.findall(state, k, seg_end)} if k >= 0 else {}
            accounts[m.group(1)] = (int(m.group(2)), slots, code)
        return accounts, created

    def call(
        self,
        caller: str,
        to: str,
        data: bytes,
        value: int = 0,
        gas: int = DEFAULT_GAS,
        static: bool = False,
    ) -> CallResult:
        caller, to = lower(caller), lower(to)
        error, success = "", True
        self.evm.reset_transient_storage()  # a new transaction (pyrevm keeps it between calls)
        try:
            out = bytes(self.evm.message_call(caller, to, data, value, gas=gas, is_static=static))
        except RuntimeError as e:
            msg = str(e)
            success = False
            if msg.startswith("Revert"):
                m = _REVERT.search(msg)
                out, error = (bytes.fromhex(m.group(1)) if m else b""), "revert"
            elif msg.startswith("Halt"):
                reason = msg.split("reason: ", 1)[-1].split(",", 1)[0].split(" ", 1)[0]
                out, error = b"", "halt:" + reason
            else:
                raise HarnessError(f"pyrevm rejected the transaction: {msg[:300]}") from e
        res = self.evm.result
        logs = []
        if success and res is not None:
            for lg in res.logs:
                topics, ldata = lg.data
                logs.append(
                    (
                        lower(lg.address),
                        tuple(int.from_bytes(t, "big") for t in topics),
                        bytes(ldata),
                    )
                )
        accounts, created_addrs = self._journal()
        diff: Dict[Tuple[str, int], Tuple[int, int]] = {}
        reads = set()
        balances: Dict[str, int] = {}
        for addr, (bal, slots, _code) in accounts.items():
            for slot, present in slots.items():
                reads.add((addr, slot))
                before = self._storage.get((addr, slot), 0)
                if present != before:
                    diff[(addr, slot)] = (before, present)
                self._storage[(addr, slot)] = present
            balances[addr] = bal
            self._balances[addr] = bal
        created = []
        for addr in created_addrs:
            acc = accounts.get(addr)
            if acc is not None and acc[2]:
                created.append((addr, acc[2]))
                self._codes[addr] = acc[2]
        return CallResult(
            success, out, error, logs, diff, reads, balances, created, res.gas_used if res else 0
        )

"""
Empirical ABI oracle on the ORIGINAL bytecode: what the dispatcher and the
ABI decoder accept, measured by execution.  It feeds L1 (mutability) and can
feed the generator before any candidate exists (`probe_original`).

  * payability: a call the original accepts is replayed with msg.value = 1;
    success means payable, an EMPTY revert means the compiler's callvalue
    check (non-payable), anything else stays undecided (a require on
    msg.value is not the ABI's business);
  * static parameter widths: on top of an accepted call, one padding byte of
    one head word is flipped at a time.  The byte is checked when the call
    then fails with an empty revert before any storage read of the contract:
    that is the ABI decoder's validator, whereas a require() failing on the
    changed value reads storage or carries revert data.  Typical counts:
    address 12, uint8 / bool / bytes1-likes 31, uint256 / bytes32 0.  Needs
    exact storage reads (py-evm).  ABI coder v1 masks instead of checking,
    so every count reads 0 there.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional, Sequence

from .abi import FuncSpec
from .equiv import CONTRACT, Differ
from .layout import Var

__all__ = ["OracleResult", "WIDTH_GUESSES", "probe_original", "probe_payable", "probe_widths"]

WIDTH_GUESSES = {
    0: "256-bit (uint256 / int256 / bytes32, or an offset)",
    12: "160-bit (address)",
    16: "128-bit",
    24: "64-bit",
    28: "32-bit (uint32 / bytes4-like)",
    30: "16-bit",
    31: "8-bit (uint8 / bool / bytes1-like)",
}


@dataclasses.dataclass
class OracleResult:
    key: str
    payable: Optional[bool]  # None: no accepted call found, or undecided
    # per head word: padding bytes the decoder checks (None: not measured)
    checked_bytes: Optional[List[int]]
    note: str = ""

    def to_dict(self) -> dict:
        out = dataclasses.asdict(self)
        if self.checked_bytes is not None:
            out["widths"] = [
                WIDTH_GUESSES.get(n, f"{(32 - n) * 8}-bit") for n in self.checked_bytes
            ]
        return out


def probe_payable(differ: Differ, base: Optional[tuple]) -> Optional[bool]:
    """Payability from one accepted (pre-state, call) of the original."""
    if base is None:
        return None
    pre, call = base
    r = differ.execute("o", pre, dataclasses.replace(call, value=1))
    if r.success:
        return True
    if r.error == "revert" and r.output == b"":
        return False
    return None


def probe_widths(
    differ: Differ, base: Optional[tuple], backend: str = "pyevm"
) -> Optional[List[int]]:
    """Checked padding bytes per head word of an accepted call (exact storage reads needed)."""
    if base is None:
        return None
    pre, call = base
    out: List[int] = []
    for w in range((len(call.data) - 4) // 32):
        checked = 0
        for b in range(31):  # byte 31 is the value byte itself
            data = bytearray(call.data)
            data[4 + 32 * w + b] ^= 0x01
            r = differ.execute("o", pre, dataclasses.replace(call, data=bytes(data)), backend)
            if (
                not r.success
                and r.output == b""
                and not any(a == CONTRACT for a, _ in r.storage_reads)
            ):
                checked += 1
        out.append(checked)
    return out


def probe_original(
    original: bytes,
    specs: Sequence[FuncSpec],
    *,
    layout: Sequence[Var] = (),
    backend: str = "pyevm",
    widths: bool = True,
    tries: int = 400,
    seed: int = 1,
) -> Dict[str, OracleResult]:
    """
    Oracle results for every spec of `original`, keyed like the report
    ("0xa9059cbb").  Only the original is executed.  Width probing requires
    the py-evm backend; with pyrevm only payability is measured.
    """
    differ = Differ(original, original, specs=specs, layout=layout, backend=backend, seed=seed)
    results: Dict[str, OracleResult] = {}
    for spec in specs:
        base = differ.find_success(spec.key, spec, tries)
        if base is None:
            results[spec.key] = OracleResult(
                spec.key, None, None, f"no accepted call in {tries} tries"
            )
            continue
        checked = probe_widths(differ, base, backend) if widths and backend == "pyevm" else None
        results[spec.key] = OracleResult(spec.key, probe_payable(differ, base), checked)
    return results

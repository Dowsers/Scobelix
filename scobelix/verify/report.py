"""
The verification report: per-level results, per-function verdicts, JSON.

Per-function verdicts (`Verdict`):

  EQUIVALENT               no divergence over every call made, and the
                           original accepted some of them
  EQUIVALENT_REVERTS_ONLY  no divergence, but the original never accepted a
                           call (e.g. an owner check never passed): weak
  DIVERGENT                at least one confirmed divergence; the first one,
                           shrunk, is the `counterexample`
  MISSING                  a selector of the original that the candidate
                           neither exposes nor routes (L1)
  EXTRA                    a selector of the candidate unknown to the
                           original (L1)
  ROUTED                   a selector of the original that the candidate
                           dispatches from fallback(); L3 did not run for it
                           (when it does, the verdict is the behavioural one
                           and `abi` says ROUTED)
  INCONCLUSIVE             divergent only in ways the execution environment
                           can explain (`reason` starts with "env:"): gas or
                           self-code introspection that no deterministic
                           backend was available to virtualise, or
                           ("env: gas: ...") the original running out of
                           even a whole block's gas where the candidate
                           finishes (`gas_divergences`, with its
                           `counterexample`)
  SKIPPED                  not checked (`reason`)

Function keys: "0x<selector>" for selector functions, "fallback" for calls
with an unknown selector or shorter than 4 bytes, "receive" for empty
calldata.  Level statuses: pass | fail | inconclusive | skipped | error.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional, Sequence, Tuple

from eth_abi import decode

from .equiv import CALLER_KINDS, Divergence, FunctionStats, PreState
from .evm import CallResult

__all__ = [
    "FunctionReport",
    "LEVELS",
    "LevelResult",
    "VerificationReport",
    "Verdict",
    "counterexample_to_dict",
    "derive_verdict",
]

LEVELS = ("L0", "L1", "L2", "L3", "L4")


class Verdict:
    EQUIVALENT = "EQUIVALENT"
    EQUIVALENT_REVERTS_ONLY = "EQUIVALENT_REVERTS_ONLY"
    DIVERGENT = "DIVERGENT"
    MISSING = "MISSING"
    EXTRA = "EXTRA"
    ROUTED = "ROUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    SKIPPED = "SKIPPED"

    ALL = (
        EQUIVALENT,
        EQUIVALENT_REVERTS_ONLY,
        DIVERGENT,
        MISSING,
        EXTRA,
        ROUTED,
        INCONCLUSIVE,
        SKIPPED,
    )
    OK = (EQUIVALENT, EQUIVALENT_REVERTS_ONLY)


_MAX_BYTES = 1024  # hex dumps in counterexamples are truncated to this many bytes
_MAX_ITEMS = 32


def _hex(b: bytes) -> str:
    h = "0x" + b[:_MAX_BYTES].hex()
    return h + ("..." if len(b) > _MAX_BYTES else "")


def _result_to_dict(r: Optional[CallResult], via: Optional[str] = None) -> Optional[dict]:
    if r is None:
        return None
    out = {}
    # through a caller mock: what the contract itself returned (fwd's `ok, ret`)
    if via and r.success:
        try:
            ok, ret = decode(["bool", "bytes"], r.output)
            out["contract"] = {"success": ok, "output": _hex(ret)}
        except Exception:  # noqa: BLE001 - not an ABI-encoded (bool, bytes): leave it raw
            pass
    out.update(
        {
            "success": r.success,
            "error": r.error,
            "output": _hex(r.output),
            "logs": [
                {"address": a, "topics": [f"0x{t:064x}" for t in ts], "data": _hex(d)}
                for a, ts, d in r.logs[:_MAX_ITEMS]
            ],
            "storage_changes": {
                f"{a}:{s:#x}": f"{after:#x}"
                for (a, s), (_before, after) in list(r.storage_diff.items())[:_MAX_ITEMS]
            },
        }
    )
    if r.calls:
        out["calls"] = [
            {"depth": d, "kind": k, "to": t, "value": v, "data": _hex(c)}
            for d, k, t, v, c in r.calls[:_MAX_ITEMS]
        ]
    if r.created:
        out["created"] = [a for a, _ in r.created]
    return out


def _call_to_dict(call) -> dict:
    return {
        "sender": call.sender,
        "via": CALLER_KINDS.get(call.via, call.via) if call.via else None,
        "value": call.value,
        "calldata": _hex(call.data),
        "mutation": call.mutation or None,
        "reentry": _hex(call.reentry) if call.reentry else None,
    }


def _pre_to_dict(pre: PreState) -> dict:
    return {
        "storage": {f"{s:#x}": f"{v:#x}" for s, v in list(pre.storage.items())[: _MAX_ITEMS * 2]},
        "balances": dict(pre.balances),
        "mocks": {
            a: {f"{s:#x}": f"{v:#x}" for s, v in slots.items()}
            for a, slots in pre.env_storage.items()
        },
        "block": pre.block,
        "stub_code_at_hardcoded_addresses": pre.stubs,
    }


def counterexample_to_dict(d: Divergence) -> dict:
    """A JSON-safe, size-bounded view of a (shrunk) divergence."""
    out = {
        "kinds": list(d.kinds),
        "label": d.label,
        "backend": d.backend,
        "call": _call_to_dict(d.call),
        "prestate": _pre_to_dict(d.pre),
        "original": _result_to_dict(d.original, d.call.via),
        "candidate": _result_to_dict(d.candidate, d.call.via),
    }
    if d.sequence:
        out["sequence"] = [_call_to_dict(c) for c in d.sequence]
    return out


@dataclasses.dataclass
class FunctionReport:
    key: str  # "0x<selector>", "fallback" or "receive"
    signature: Optional[str]
    origin: str  # both | original | candidate | routed | scan | probe
    abi: Optional[str]  # L1 status: MATCH | MISSING | EXTRA | ROUTED; None for probes / without L1
    verdict: str
    reason: str = ""
    calls: int = 0
    original_success: int = 0
    divergences: int = 0  # divergent calls (each from its own random pre-state)
    sequence_divergences: int = 0  # stateful sequences that diverged on a call to this function
    # divergent only outside the deterministic environment, or only because one side ran out of
    # gas (equivalent with the block's whole gas limit); not counted as divergences
    env_divergences: int = 0
    # divergent only because the original runs out of even the block's whole gas limit where the
    # candidate finishes; not counted as divergences (verdict INCONCLUSIVE "env: gas: ...")
    gas_divergences: int = 0
    kinds: Dict[str, int] = dataclasses.field(default_factory=dict)
    # {"covered": (pc, direction) pairs reached, "seen": 2 * distinct JUMPIs reached}
    coverage: Optional[Dict[str, int]] = None
    payable: Dict[str, Optional[bool]] = dataclasses.field(default_factory=dict)
    checked_bytes: Optional[List[int]] = None  # oracle: checked padding bytes per head word
    counterexample: Optional[dict] = None
    elapsed: float = 0.0

    @property
    def selector(self) -> Optional[str]:
        return self.key if self.key.startswith("0x") else None

    def to_dict(self) -> dict:
        out = dataclasses.asdict(self)
        out["selector"] = self.selector
        out["elapsed"] = round(self.elapsed, 3)
        return out


def derive_verdict(
    abi_status: Optional[str],
    stats: Optional[FunctionStats],
    *,
    env_reasons: Sequence[str] = (),
    skipped_reason: str = "",
) -> Tuple[str, str]:
    """(verdict, reason) of one function from its L1 status and L3 statistics (None: not run)."""
    if abi_status == "MISSING":
        return Verdict.MISSING, "selector of the original absent from the candidate"
    if abi_status == "EXTRA":
        return Verdict.EXTRA, "selector unknown to the original"
    if stats is None or (stats.calls == 0 and not stats.sequence_divergences):
        if abi_status == "ROUTED":
            return (
                Verdict.ROUTED,
                "dispatched from the candidate's fallback(); behaviour not checked",
            )
        return Verdict.SKIPPED, skipped_reason or "behaviour not checked"
    if stats.divergences or stats.sequence_divergences:
        if env_reasons:
            return (
                Verdict.INCONCLUSIVE,
                "env: the original uses "
                + ", ".join(env_reasons)
                + " (virtualised on py-evm only)",
            )
        return Verdict.DIVERGENT, ", ".join(sorted(stats.kinds))
    if stats.gas_divergences:
        return (
            Verdict.INCONCLUSIVE,
            "env: gas: the original runs out of gas even with a whole block's gas limit where the "
            f"candidate finishes ({stats.gas_divergences} calls); no other difference",
        )
    if stats.original_success == 0:
        return Verdict.EQUIVALENT_REVERTS_ONLY, "the original rejected every call"
    note = f"{stats.env_divergences} environment-only divergences" if stats.env_divergences else ""
    return Verdict.EQUIVALENT, note


@dataclasses.dataclass
class LevelResult:
    status: str  # pass | fail | inconclusive | skipped | error
    reason: str = ""
    details: dict = dataclasses.field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.status == "pass"

    def to_dict(self) -> dict:
        return {"status": self.status, "reason": self.reason, **self.details}


@dataclasses.dataclass
class VerificationReport:
    levels: Dict[str, LevelResult]
    functions: Dict[str, FunctionReport]
    original: dict
    candidate: dict
    backend: dict
    warnings: List[str] = dataclasses.field(default_factory=list)
    sequences: dict = dataclasses.field(default_factory=dict)
    elapsed: float = 0.0

    def level(self, name: str) -> LevelResult:
        return self.levels[name]

    @property
    def summary(self) -> Dict[str, int]:
        counts = {v: 0 for v in Verdict.ALL}
        for f in self.functions.values():
            counts[f.verdict] += 1
        return {k: v for k, v in counts.items() if v}

    @property
    def passed(self) -> bool:
        """Every level that ran passed (skipped levels do not count against it)."""
        return all(r.status in ("pass", "skipped") for r in self.levels.values()) and any(
            r.status == "pass" for r in self.levels.values()
        )

    def to_json(self) -> dict:
        return {
            "passed": self.passed,
            "levels": {k: v.to_dict() for k, v in self.levels.items()},
            "summary": self.summary,
            "functions": {k: f.to_dict() for k, f in self.functions.items()},
            "sequences": self.sequences,
            "original": self.original,
            "candidate": self.candidate,
            "backend": self.backend,
            "warnings": self.warnings,
            "elapsed": round(self.elapsed, 3),
        }

    def to_text(self) -> str:
        lines = ["levels: " + "  ".join(f"{k}={v.status}" for k, v in self.levels.items())]
        for k, v in self.levels.items():
            if v.reason:
                lines.append(f"  {k}: {v.reason}")
        header = (
            f"{'function':<12} {'signature':<36} {'abi':<8} {'verdict':<24} "
            f"{'calls':>6} {'ok':>6} {'div':>5} {'cov':>9}"
        )
        lines += ["", header, "-" * len(header)]
        for f in self.functions.values():
            cov = f"{f.coverage['covered']}/{f.coverage['seen']}" if f.coverage else "-"
            div = f.divergences + f.sequence_divergences
            lines.append(
                f"{f.key:<12} {(f.signature or '?')[:36]:<36} {(f.abi or '-'):<8} {f.verdict:<24} "
                f"{f.calls:>6} {f.original_success:>6} {div:>5} {cov:>9}"
            )
            if f.reason and f.verdict not in Verdict.OK:
                lines.append(f"{'':<12} {f.reason}")
        if self.sequences:
            seq = self.sequences
            lines.append(
                f"\nsequences: {seq.get('run', 0)} x {seq.get('length', 0)} calls, "
                f"{seq.get('divergent', 0)} divergent"
            )
        for w in self.warnings:
            lines.append(f"warning: {w}")
        return "\n".join(lines)

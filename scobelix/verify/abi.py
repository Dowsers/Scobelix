"""
L1 (external ABI) and the function specs that drive input generation.

The original's function set comes from an `abi_hint` when the caller has one
(see `specs_from_hint` for the accepted forms: a JSON ABI, the decompiler's
`json["functions"]`, or a {selector: signature | dict | FuncSpec} map), else
from a scan of the dispatcher (`dispatcher_selectors`: PUSH4 constants
compared with EQ/GT/LT/SUB/XOR and followed by a JUMPI).

`compare_abi` classifies every selector of either side:

    MATCH    present in the original and in the candidate's ABI
    ROUTED   present in the original, absent from the candidate's ABI, but
             declared routed: the candidate dispatches it from fallback()
    MISSING  present in the original only
    EXTRA    present in the candidate only (or routed but unknown to the original)

and checks mutability (payable or not, the only part of it that bytecode
encodes) plus the events / custom errors the candidate declares: each
declared topic0 / error selector must appear as a PUSH constant of the
original (or as the constant a PUSH, PUSH, SHL sequence builds), otherwise
the candidate's interface is not the original's.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

from eth_utils import keccak

from .bytecode import (
    computed_values,
    disasm,
    own_code,
    push_values,
    shifted_push_values,
    strip_all_metadata,
)

__all__ = [
    "FuncSpec",
    "L1Result",
    "MATCH",
    "MISSING",
    "EXTRA",
    "ROUTED",
    "canonical_type",
    "compare_abi",
    "dispatcher_selectors",
    "parse_selector",
    "selector_key",
    "specs_from_abi",
    "specs_from_hint",
    "split_types",
]

MATCH, MISSING, EXTRA, ROUTED = "MATCH", "MISSING", "EXTRA", "ROUTED"

Selector = Union[int, str, bytes]


def parse_selector(sel: Selector) -> bytes:
    """4-byte selector from an int, a (0x-)hex string or bytes."""
    if isinstance(sel, (bytes, bytearray)):
        if len(sel) != 4:
            raise ValueError(f"selector must be 4 bytes, got {len(sel)}")
        return bytes(sel)
    if isinstance(sel, int):
        if not 0 <= sel < 1 << 32:
            raise ValueError(f"selector out of range: {sel:#x}")
        return sel.to_bytes(4, "big")
    text = sel.strip().lower()
    text = text[2:] if text.startswith("0x") else text
    if not re.fullmatch(r"[0-9a-f]{1,8}", text):
        raise ValueError(f"not a selector: {sel!r}")
    return bytes.fromhex(text.rjust(8, "0"))


def selector_key(sel: Selector) -> str:
    """'0xa9059cbb' (the key functions are reported under)."""
    return "0x" + parse_selector(sel).hex()


def split_types(args: str) -> List[str]:
    """'address,(uint8,bytes)[],uint256' -> ['address', '(uint8,bytes)[]', 'uint256']."""
    out, depth, cur = [], 0, ""
    for ch in args:
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        depth += ch == "("
        depth -= ch == ")"
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


_ALIASES = {"uint": "uint256", "int": "int256", "byte": "bytes1", "address payable": "address"}
_BASIC_RE = re.compile(
    r"(u?int\d*|address|bool|bytes\d*|string|function|byte|address payable)((?:\[\d*\])*)"
)


def canonical_type(t: str) -> str:
    """Canonical ABI spelling: aliases expanded (uint -> uint256), tuples recursively."""
    t = t.strip()
    if t.startswith("("):
        depth = 0
        for i, ch in enumerate(t):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0:
                inner, suffix = t[1:i], t[i + 1 :]
                return (
                    "("
                    + ",".join(canonical_type(x) for x in split_types(inner))
                    + ")"
                    + suffix.replace(" ", "")
                )
        raise ValueError(f"unbalanced tuple type {t!r}")
    m = _BASIC_RE.fullmatch(t.replace(" [", "["))
    if not m:
        raise ValueError(f"unsupported ABI type {t!r}")
    base = _ALIASES.get(m.group(1), m.group(1))
    return base + m.group(2)


@dataclasses.dataclass
class FuncSpec:
    """What is known of one external function (of either side)."""

    selector: bytes
    signature: Optional[str] = None  # canonical "transfer(address,uint256)" when known
    inputs: Optional[List[str]] = None  # canonical ABI types; None = unknown (raw calldata fuzzing)
    payable: Optional[bool] = None
    mutability: Optional[str] = None  # ABI stateMutability when known

    @property
    def key(self) -> str:
        return "0x" + self.selector.hex()

    @property
    def label(self) -> str:
        return self.signature or self.key

    @classmethod
    def from_signature(
        cls, signature: str, payable: Optional[bool] = None, selector: Optional[bytes] = None
    ) -> "FuncSpec":
        """From 'name(type,...)'; `selector` defaults to keccak(signature)[:4]."""
        m = re.fullmatch(r"\s*([A-Za-z_$][\w$]*)\s*\((.*)\)\s*", signature)
        if not m:
            raise ValueError(f"not a function signature: {signature!r}")
        types = [canonical_type(t) for t in split_types(m.group(2))]
        sig = f"{m.group(1)}({','.join(types)})"
        return cls(selector or keccak(text=sig)[:4], sig, types, payable)


def _abi_input_type(inp: Mapping[str, Any]) -> str:
    t = inp["type"]
    if t.startswith("tuple"):
        return "(" + ",".join(_abi_input_type(c) for c in inp.get("components", [])) + ")" + t[5:]
    return canonical_type(t)


def _abi_signature(item: Mapping[str, Any]) -> str:
    return f"{item['name']}({','.join(_abi_input_type(i) for i in item.get('inputs', []))})"


def _mutability(item: Mapping[str, Any]) -> str:
    m = item.get("stateMutability")
    if m:
        return m
    if item.get("payable"):
        return "payable"
    return "view" if item.get("constant") else "nonpayable"


def specs_from_abi(abi: Iterable[Mapping[str, Any]]) -> Dict[bytes, FuncSpec]:
    """selector -> FuncSpec for every function of a JSON ABI."""
    out: Dict[bytes, FuncSpec] = {}
    for item in abi:
        if item.get("type", "function") != "function" or "name" not in item:
            continue
        sig = _abi_signature(item)
        mut = _mutability(item)
        out[keccak(text=sig)[:4]] = FuncSpec(
            keccak(text=sig)[:4],
            sig,
            split_types(sig[sig.index("(") + 1 : -1]),
            mut == "payable",
            mut,
        )
    return out


def _spec_from_decompiler(f: Mapping[str, Any]) -> Optional[FuncSpec]:
    """One entry of the decompiler's json['functions'] (selector functions only)."""
    h = f.get("hash")
    if not isinstance(h, str) or not h.startswith("0x"):
        return None
    sel = parse_selector(h)
    payable = f.get("payable") if isinstance(f.get("payable"), bool) else None
    abi_name = f.get("abi_name") or ""
    if "(" in abi_name and not abi_name.startswith("unknown") and "?" not in abi_name:
        try:
            spec = FuncSpec.from_signature(abi_name, payable, selector=sel)
            if keccak(text=spec.signature)[:4] == sel:
                return spec
        except ValueError:
            pass
    params = f.get("params")
    if isinstance(params, dict) and params:
        try:
            types = [canonical_type(params[k][0]) for k in sorted(params, key=lambda k: int(k))]
            return FuncSpec(sel, None, types, payable)
        except (ValueError, TypeError, IndexError, KeyError):
            pass
    return FuncSpec(sel, None, None, payable)  # parameters unknown: raw calldata fuzzing


def specs_from_hint(hint: Any) -> Dict[bytes, FuncSpec]:
    """
    Normalises an ABI hint into selector -> FuncSpec.  Accepted forms:
      * a JSON ABI (list of {"type": "function", "name", "inputs", ...});
      * the decompiler's json["functions"] (dicts with "hash", "abi_name", "params", "payable");
      * a list of FuncSpec;
      * {selector: signature string | FuncSpec | {"signature"?, "inputs"?, "payable"?}}, with
        selectors as int, hex string or bytes.  A signature whose keccak differs from its
        selector keeps the selector and the parameter types (routed functions' names are often
        unknown).
    """
    if not hint:
        return {}
    out: Dict[bytes, FuncSpec] = {}
    if isinstance(hint, Mapping):
        for sel, v in hint.items():
            s = parse_selector(sel)
            if isinstance(v, FuncSpec):
                out[s] = dataclasses.replace(v, selector=s)
            elif isinstance(v, str):
                out[s] = FuncSpec.from_signature(v, selector=s)
            elif isinstance(v, Mapping):
                spec = (
                    FuncSpec.from_signature(v["signature"], selector=s)
                    if v.get("signature")
                    else FuncSpec(s)
                )
                if v.get("inputs") is not None:
                    spec.inputs = [canonical_type(t) for t in v["inputs"]]
                if v.get("payable") is not None:
                    spec.payable = bool(v["payable"])
                out[s] = spec
            elif v is None:
                out[s] = FuncSpec(s)
            else:
                raise ValueError(f"unsupported hint value for {sel!r}: {type(v).__name__}")
        return out
    items = list(hint)
    if all(isinstance(x, FuncSpec) for x in items):
        return {x.selector: x for x in items}
    if any(isinstance(x, Mapping) and "hash" in x for x in items):
        for f in items:
            spec = _spec_from_decompiler(f) if isinstance(f, Mapping) else None
            if spec is not None:
                out[spec.selector] = spec
        return out
    return specs_from_abi(items)


def hint_events_errors(hint: Any) -> Tuple[Dict[int, str], Dict[int, str]]:
    """(topic0 -> signature, error selector -> signature) when the hint is a JSON ABI."""
    events: Dict[int, str] = {}
    errors: Dict[int, str] = {}
    if not hint or isinstance(hint, Mapping):
        return events, errors
    for item in hint:
        if not isinstance(item, Mapping) or "name" not in item:
            continue
        if item.get("type") == "event" and not item.get("anonymous"):
            sig = _abi_signature(item)
            events[int.from_bytes(keccak(text=sig), "big")] = sig
        elif item.get("type") == "error":
            sig = _abi_signature(item)
            errors[int.from_bytes(keccak(text=sig)[:4], "big")] = sig
    return events, errors


# ---------------------------------------------------------------- original side

_SELECTOR_TESTS = {0x14, 0x11, 0x10, 0x03, 0x18}  # EQ GT LT SUB XOR
_JUMPI = 0x57


def dispatcher_selectors(code: bytes) -> List[int]:
    """
    Selectors of a dispatcher, by bytecode pattern: PUSH4 K, then (DUPs allowed)
    a comparison EQ/GT/LT/SUB/XOR, then a JUMPI within the next few instructions.
    Covers legacy solc (eq chains and binary-search splits), 0.4 (`PUSH4 K DUP2 EQ`),
    via-IR (`sub` last case) and Vyper (`xor`).  Masks (0xffffffff) are skipped.
    """
    ins = disasm(own_code(code))  # not the dispatchers of embedded child initcode
    out: List[int] = []
    for i, (_pc, op, arg) in enumerate(ins):
        if op != 0x63 or arg is None or arg == 0xFFFFFFFF:
            continue
        window = [o for _, o, _ in ins[i + 1 : i + 6]]
        j = 0
        while j < len(window) and 0x80 <= window[j] <= 0x8F:  # DUPn
            j += 1
        if j >= len(window) or window[j] not in _SELECTOR_TESTS:
            continue
        if _JUMPI in window[j + 1 : j + 4] and arg not in out:
            out.append(arg)
    return out


# ---------------------------------------------------------------- L1


@dataclasses.dataclass
class L1Result:
    status: str  # "pass" | "fail"
    functions: Dict[str, dict]  # selector key -> {"status", "signature", "payable": {...}}
    events: dict
    errors: dict
    source: str  # where the original's selectors came from: "hint" | "dispatcher scan"
    scan_only: List[str]  # dispatcher-scan selectors absent from the hint (reported, not judged)

    def keys_with(self, status: str) -> List[str]:
        return sorted(k for k, f in self.functions.items() if f["status"] == status)

    @property
    def mutability_mismatches(self) -> List[str]:
        return sorted(k for k, f in self.functions.items() if f.get("mutability_mismatch"))

    def failures(self) -> Dict[str, List[str]]:
        """What makes L1 fail, by category (empty: L1 passes)."""
        found = (
            ("missing", self.keys_with(MISSING)),
            ("extra", self.keys_with(EXTRA)),
            ("mutability", self.mutability_mismatches),
            ("events", self.events["declared_not_in_original"]),
            ("errors", self.errors["declared_not_in_original"]),
        )
        return {label: items for label, items in found if items}

    def apply_oracle(self, measured: Mapping[str, Optional[bool]]) -> None:
        """
        Re-judges payability with the values measured on the original (they
        win over the hint's) and recomputes the status.
        """
        for key, row in self.functions.items():
            m = measured.get(key)
            if m is not None:
                row["payable"]["oracle"] = m
            original = m if m is not None else row["payable"]["original"]
            candidate = row["payable"]["candidate"]
            row["mutability_mismatch"] = (
                row["status"] == MATCH
                and None not in (original, candidate)
                and original != candidate
            )
        self.status = "fail" if self.failures() else "pass"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "source": self.source,
            "missing": self.keys_with(MISSING),
            "extra": self.keys_with(EXTRA),
            "routed": self.keys_with(ROUTED),
            "mutability_mismatches": self.mutability_mismatches,
            "scan_only": self.scan_only,
            "events": self.events,
            "errors": self.errors,
            "functions": self.functions,
        }


def compare_abi(
    original_specs: Mapping[bytes, FuncSpec],
    candidate_abi: Sequence[Mapping[str, Any]],
    original_code: bytes,
    *,
    routed: Iterable[bytes] = (),
    source: str = "hint",
    scan: Sequence[int] = (),
    hint: Any = None,
) -> L1Result:
    """
    L1 verdict of a candidate ABI against the original's function set.
    `original_specs[s].payable` (from the hint, or an empirical oracle) is
    compared with the candidate's stateMutability when both are known.
    """
    cand = specs_from_abi(candidate_abi)
    routed_set: Set[bytes] = set(routed)
    functions: Dict[str, dict] = {}
    for sel in sorted(set(original_specs) | set(cand) | routed_set):
        o, c = original_specs.get(sel), cand.get(sel)
        if o is not None and c is not None:
            status = MATCH
        elif o is not None:
            status = ROUTED if sel in routed_set else MISSING
        else:
            status = EXTRA
        row: dict = {
            "status": status,
            "signature": (c.signature if c else None) or (o.signature if o else None),
            "payable": {
                "original": o.payable if o else None,
                "candidate": c.payable if c else None,
            },
        }
        if status == EXTRA and c is None:
            row["routed"] = True
        functions["0x" + sel.hex()] = row
    constants = set(push_values(original_code))
    constants.update(shifted_push_values(original_code))  # and the constants written as a shift
    constants.update(computed_values(original_code))  # or computed (`~((c << s) - 1)`...)
    data = strip_all_metadata(original_code)

    def written(word: int) -> bool:
        """`word` is a constant of the original's code: pushed, computed from constants, or a
        32-byte word stored after the code (the optimiser reads a constant used in many places
        with CODECOPY)."""
        return word in constants or word.to_bytes(32, "big") in data

    hint_events, hint_errors = hint_events_errors(hint)
    events = {"declared_not_in_original": [], "original_not_declared": []}
    errors = {"declared_not_in_original": [], "original_not_declared": []}
    cand_topics: Set[int] = set()
    cand_errors: Set[int] = set()
    for item in candidate_abi:
        if item.get("type") == "event" and not item.get("anonymous") and "name" in item:
            sig = _abi_signature(item)
            topic = int.from_bytes(keccak(text=sig), "big")
            cand_topics.add(topic)
            if not written(topic) and topic not in hint_events:
                events["declared_not_in_original"].append(sig)
        elif item.get("type") == "error" and "name" in item:
            sig = _abi_signature(item)
            sel = int.from_bytes(keccak(text=sig)[:4], "big")
            cand_errors.add(sel)
            if sel not in constants and not written(sel << 224) and sel not in hint_errors:
                errors["declared_not_in_original"].append(sig)
    events["original_not_declared"] = sorted(
        sig for t, sig in hint_events.items() if t not in cand_topics
    )
    errors["original_not_declared"] = sorted(
        sig for s, sig in hint_errors.items() if s not in cand_errors
    )
    scan_only = sorted(f"0x{s:08x}" for s in scan if s.to_bytes(4, "big") not in original_specs)
    result = L1Result("pass", functions, events, errors, source, scan_only)
    result.apply_oracle({})
    return result

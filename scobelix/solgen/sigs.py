"""
Signature lookups for solgen: names and types of function selectors, event
topics and custom-error selectors.

The answers come from the signature database `scobelix.utils.sigdb`
(separate namespaces for functions, events and errors).  Every candidate
returned is keccak-verified here again: its canonical signature hashes to
the queried selector (or topic); placeholder names, library signatures and
types that cannot be parsed are dropped.  A database that cannot be opened
gives no candidate: generation goes on unnamed.
"""

from __future__ import annotations

import dataclasses
import functools
import logging
import re
from typing import List, Optional, Sequence, Tuple

from eth_utils import keccak

from scobelix.solgen.types import parse_type
from scobelix.utils import sigdb as _sigdb

logger = logging.getLogger(__name__)

__all__ = [
    "Signature",
    "error_candidates",
    "event_candidates",
    "function_candidates",
    "function_selector",
    "event_topic",
]

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_PLACEHOLDER_RE = re.compile(r"unknown_?(0x)?[0-9a-fA-F]{8}$")
TRUSTED_SOURCES = ("builtin", "curated")


@dataclasses.dataclass(frozen=True)
class Signature:
    """One keccak-verified candidate.

    inputs / outputs: ((canonical type, parameter name), ...); outputs None
    when unknown.  indexed: per input, for events.  trusted: from a curated
    or built-in table (its mutability / outputs can be relied on).  declared:
    the database has the signature in the namespace asked for (an error
    declared as an error); False for a signature of another namespace that
    merely hashes to the key."""

    kind: str  # function | event | error
    name: str
    inputs: Tuple[Tuple[str, str], ...]
    signature: str
    outputs: Optional[Tuple[Tuple[str, str], ...]] = None
    mutability: Optional[str] = None
    indexed: Tuple[bool, ...] = ()
    anonymous: bool = False
    generic_names: bool = False
    trusted: bool = False
    source: str = ""
    declared: bool = True

    @property
    def types(self) -> Tuple[str, ...]:
        return tuple(t for t, _ in self.inputs)


def function_selector(signature: str) -> int:
    return int.from_bytes(keccak(text=signature)[:4], "big")


def event_topic(signature: str) -> int:
    return int.from_bytes(keccak(text=signature), "big")


def _param_type(p: dict) -> str:
    t = p.get("type", "")
    if t.startswith("tuple"):
        inner = ",".join(_param_type(c) for c in p.get("components") or [])
        return parse_type("(" + inner + ")" + t[len("tuple"):]).canonical
    return parse_type(t).canonical


def _params(raw) -> Optional[Tuple[Tuple[str, str], ...]]:
    if raw is None:
        return None
    out = []
    for p in raw:
        out.append((_param_type(p), str(p.get("name") or "")))
    return tuple(out)


def _from_entry(kind: str, entry: dict, source: str) -> Optional[Signature]:
    name = entry.get("name") or ""
    if not _IDENT_RE.fullmatch(name) or _PLACEHOLDER_RE.match(name):
        return None
    try:
        inputs = _params(entry.get("inputs") or [])
        outputs = _params(entry.get("outputs")) if entry.get("outputs") is not None else None
    except ValueError:  # library types such as "Lib.Data storage", "tuple" without components
        return None
    signature = f"{name}({','.join(t for t, _ in inputs)})"
    sources = entry.get("sources") or source
    if isinstance(sources, str):
        sources = sources.split(",")
    sources = [str(x) for x in sources]
    return Signature(
        kind=kind,
        name=name,
        inputs=inputs,
        signature=signature,
        outputs=outputs,
        mutability=entry.get("stateMutability"),
        indexed=tuple(bool(p.get("indexed")) for p in entry.get("inputs") or []),
        anonymous=bool(entry.get("anonymous")),
        generic_names=bool(entry.get("generic_names"))
        or all(re.fullmatch(r"_?param\d+|", n or "") for _, n in inputs),
        trusted=any(x in TRUSTED_SOURCES for x in sources),
        source=",".join(sources),
        declared=not entry.get("untyped"),
    )


def _lookup(kind: str, key: int, *args) -> list:
    try:
        return getattr(_sigdb, "lookup_" + kind)(key, *args)
    except Exception:  # noqa: BLE001 - a broken database must not stop generation
        logger.exception("signature database lookup failed")
        return []


@functools.lru_cache(maxsize=4096)
def function_candidates(selector: int) -> Tuple[Signature, ...]:
    """Function signatures whose selector is `selector`, best first."""
    out: List[Signature] = []
    for e in _lookup("function", selector):
        if e.get("library"):
            continue
        sig = _from_entry("function", e, "sigdb")
        if sig is not None and function_selector(sig.signature) == selector:
            out.append(sig)
    return tuple(out)


@functools.lru_cache(maxsize=4096)
def event_candidates(topic0: int, num_indexed: Optional[int] = None) -> Tuple[Signature, ...]:
    """Event signatures whose full topic0 is `topic0`, best first; with
    `num_indexed` (the topics after topic0), those that index as many."""
    out = []
    for e in _lookup("event", topic0, num_indexed):
        sig = _from_entry("event", e, "sigdb")
        if sig is not None and event_topic(sig.signature) == topic0:
            out.append(sig)
    return tuple(out)


@functools.lru_cache(maxsize=4096)
def error_candidates(selector: int, types: Optional[Sequence[str]] = None) -> Tuple[Signature, ...]:
    """Custom-error signatures whose selector is `selector`: the declared
    errors first, then the signatures of the other namespaces with that
    selector (`declared` False).  With `types`, only the signatures with
    exactly these canonical types."""
    out = []
    for e in _lookup("error", selector, list(types) if types is not None else None):
        sig = _from_entry("error", e, "sigdb")
        if sig is not None and function_selector(sig.signature) == selector:
            out.append(sig)
    return tuple(out)

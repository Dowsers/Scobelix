"""
The solgen v2 pass manager.

Passes run in the fixed order of `PASS_ORDER`, each one imported from
`scobelix/solgen/passes/<name>.py` when that module exists (see the
`passes` package for the interface).  The "exact" idiom level runs none of
them: the lifted IR is rendered as is, with EVM-exact semantics.  The
"full" level runs every available pass, except those disabled for a
function through `disabled_passes` ({function key or "*": {pass names}}),
which is how a verification loop backs off to a less idiomatic tier.

What the switches mean for the passes that work on the whole contract:

  * a pass switched off for one function does not rewrite that function;
    its contract-level work (`prepare`, `finish`: the storage layout and
    the state variable declarations, the declared errors...) is still
    done for the others.  The function then reads and writes the same
    storage by slot number: the switch is local to it;
  * a pass switched off for "*" does nothing at all: neither rewriting
    nor contract-level work nor declarations (`storage` off for "*" means
    no state variable, every access by slot; the getters pass then folds
    no function into a variable);
  * `excluded_storage` names state variables (their stable ids,
    `slot<N>` / `slot<N>_<byte>`) that the storage pass must leave
    undeclared: every function reaches them by slot.
"""

from __future__ import annotations

import dataclasses
import importlib
import logging
from types import ModuleType
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from scobelix.solgen import ir, sigs
from scobelix.solgen.abi import EntrySpec

logger = logging.getLogger(__name__)

__all__ = ["DECLARATION_KINDS", "PASS_ORDER", "PassContext", "available_passes", "run_passes", "IDIOM_LEVELS"]

PASS_ORDER = (
    "abi", "storage", "reverts", "arith", "calls", "events", "loops", "getters", "naming", "compound",
    "modifiers",
)
IDIOM_LEVELS = ("exact", "full")
# what PassContext.declare accepts, in the order contract assembly writes
# them: interfaces before the contract; then, inside it, structs, events,
# errors, constants, state variables, modifiers; internal functions after
# the entry points
DECLARATION_KINDS = ("interface", "struct", "event", "error", "constant", "state", "modifier", "function")


@dataclasses.dataclass
class PassContext:
    """Contract-level facts shared by the passes."""

    specs: Dict[str, EntrySpec]
    metadata: Optional[dict]
    dispatcher: Optional[dict]
    target_solc: str
    abi_v2: bool
    idiom_level: str
    bytecode: bytes = b""
    functions: Dict[str, ir.Function] = dataclasses.field(default_factory=dict)  # lifted bodies, before passes
    sigs: ModuleType = sigs
    facts: Dict[str, object] = dataclasses.field(default_factory=dict)  # per pass, from prepare()
    declarations: Dict[str, List[str]] = dataclasses.field(default_factory=dict)
    warnings: List[str] = dataclasses.field(default_factory=list)
    disabled_passes: Mapping[str, Iterable[str]] = dataclasses.field(default_factory=dict)
    folded: Dict[str, str] = dataclasses.field(default_factory=dict)  # entry key -> declaration providing it
    excluded_storage: Iterable[str] = ()  # state variables (stable ids) to leave undeclared
    running: str = ""  # the pass whose prepare / run / finish is being called
    declared_by: Dict[Tuple[str, str], str] = dataclasses.field(default_factory=dict)  # (kind, text) -> pass

    def enabled(self, key: str, name: str) -> bool:
        off: Set[str] = set(self.disabled_passes.get("*", ())) | set(self.disabled_passes.get(key, ()))
        return name not in off

    def off_everywhere(self, name: str) -> bool:
        """Pass `name` is switched off for the whole contract ("*")."""
        return name in set(self.disabled_passes.get("*", ()))

    def fold(self, key: str, provider: str) -> None:
        """Entry point `key` is provided by a declaration (`provider`: the
        state variable or constant whose getter solc generates): contract
        assembly does not write the function out."""
        self.folded[key] = provider

    def declare(self, kind: str, text: str) -> None:
        """Add a contract-level declaration (Solidity text, one per call,
        kept once) of a kind in DECLARATION_KINDS."""
        if kind not in DECLARATION_KINDS:
            raise ValueError(f"unknown declaration kind {kind!r} (one of {', '.join(DECLARATION_KINDS)})")
        items = self.declarations.setdefault(kind, [])
        if text not in items:
            items.append(text)
            self.declared_by[(kind, text)] = self.running


_LOADED: Dict[str, Optional[ModuleType]] = {}


def _load(name: str) -> Optional[ModuleType]:
    if name not in _LOADED:
        try:
            _LOADED[name] = importlib.import_module(f"scobelix.solgen.passes.{name}")
        except ModuleNotFoundError as e:
            if e.name != f"scobelix.solgen.passes.{name}":
                raise
            _LOADED[name] = None
    return _LOADED[name]


def available_passes(idiom_level: str = "full") -> List[Tuple[str, ModuleType]]:
    """(name, module) of the passes that exist and run at `idiom_level`, in order."""
    if idiom_level not in IDIOM_LEVELS:
        raise ValueError(f"unknown idiom level {idiom_level!r} (one of {', '.join(IDIOM_LEVELS)})")
    if idiom_level == "exact":
        return []
    out = []
    for name in PASS_ORDER:
        mod = _load(name)
        if mod is not None and idiom_level in getattr(mod, "LEVELS", ("full",)):
            out.append((name, mod))
    return out


def prepare(passes: Sequence[Tuple[str, ModuleType]], ctx: PassContext) -> None:
    for name, mod in passes:
        if hasattr(mod, "prepare") and not ctx.off_everywhere(name):
            ctx.running = name
            try:
                mod.prepare(ctx)
            except Exception:  # noqa: BLE001 - a broken pass must not lose the contract
                logger.exception("pass %s: prepare failed", name)
                ctx.warnings.append(f"pass {name}: prepare failed")
    ctx.running = ""


def run_passes(fn: ir.Function, passes: Sequence[Tuple[str, ModuleType]],
               ctx: PassContext) -> Tuple[ir.Function, Tuple[str, ...]]:
    """`fn` after every enabled pass, and the names of the passes that changed it."""
    applied = []
    for name, mod in passes:
        if not ctx.enabled(fn.key, name):
            continue
        ctx.running = name
        try:
            new = mod.run(fn, ctx)
        except Exception:  # noqa: BLE001 - keep the previous (exact) form
            logger.exception("pass %s failed on %s", name, fn.key)
            ctx.warnings.append(f"pass {name} failed on {fn.key}: kept the previous form")
            continue
        if new is not fn and new != fn:
            applied.append(name)
            fn = new
    ctx.running = ""
    return fn, tuple(applied)


def finish(passes: Sequence[Tuple[str, ModuleType]], ctx: PassContext) -> None:
    for name, mod in passes:
        if hasattr(mod, "finish") and not ctx.off_everywhere(name):
            ctx.running = name
            try:
                mod.finish(ctx)
            except Exception:  # noqa: BLE001
                logger.exception("pass %s: finish failed", name)
                ctx.warnings.append(f"pass {name}: finish failed")
    ctx.running = ""

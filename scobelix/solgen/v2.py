"""
The implementation of the Solidity generator (the public entry point is
`scobelix.solgen.generate_solidity`).

    from scobelix.solgen.v2 import generate
    r = generate(decompilation)                     # idiom_level="exact"
    r.solidity, r.target_solc, r.functions["0xa9059cbb"], r.warnings
    r = generate(decompilation, verify=True)        # + r.verification (the verification loop)

`decompilation` is a `scobelix.decompiler.Decompilation`: its in-memory
`functions` (raw traces, see lift.py), `dispatcher`, `metadata` and
`bytecode` are used.  A decompilation without `functions` (or its `json`
dict alone) is accepted in a degraded mode that lifts the JSON traces.

Pipeline: lift every entry point (lift.py) -> ABI facts (abi.py) ->
passes (pipeline.py; none at the "exact" level) -> contract assembly and
rendering (contract.py, render.py) -> optional verification loop
(tiers.py, on scobelix.verify).

`Generator` holds what depends on the decompilation only (the lifted
bodies and the ABI facts); its `regenerate(disabled_passes)` runs the
passes and the assembly again, with some passes switched off for some
functions, without decompiling or lifting anything again.  That is what
the verification loop builds on to back a function off to a less
idiomatic form; `verify(result)` is one run of scobelix.verify on one
text, `search(budget)` the whole loop.

Tiers.  A function is written at the tier "exact" (no pass rewrote it),
"idiomatic" (the passes that apply to it rewrote it) or "partial"
(rewritten, but with some of those passes switched off: its
`disabled_passes`).

Static guards.  At the "full" level a function keeps the exact form (no
pass runs on it) when its code carries one of `RISK_FLAGS` or an
`engine:*` marker: the decompiler or the lifter said that this code may
not be the original's, and nothing is rewritten on top of it without a
verification.  The flags that kept a function exact are its `guards`.

Confidence (`SolgenResult.confidence`, one of "high", "medium", "low",
"none" per function) is derived, see `derive_confidence`.
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import logging
import re
import sys
from typing import Dict, Iterable, List, Mapping, Optional, Set, Tuple

from scobelix.solgen import abi, ir, lift, pipeline
from scobelix.solgen.contract import DIFFERING, FLAG_TIME_LIMITED, ContractInput, Unit, assemble
from scobelix.solgen.render import RenderContext, reserved_name

logger = logging.getLogger(__name__)

__all__ = ["CONFIDENCE_LEVELS", "Generator", "RISK_FLAGS", "SolgenResult", "choose_target", "derive_confidence",
           "generate"]

DEFAULT_TARGET = "0.8.19"
CONTRACT_NAME = "Decompiled"
# the lifter and the renderer recurse once or twice per nesting level of the
# decompiled tree; decompiled traces can nest a few thousand levels deep
RECURSION_FLOOR = 10000

CONFIDENCE_LEVELS = ("high", "medium", "low", "none")
# flags saying that the code of a function may not be the original's: the
# decompiler failed or left a part out, a value the engine cannot have meant,
# a degraded input.  Every `engine:*` flag counts as one of them.
RISK_FLAGS = frozenset({
    "problem", "unstructured", "loop_exit_unstructured", "wide_int", "code_unknown", "json_trace",
    "json_storage_ambiguous",
})
_INCOMPLETE_FLAGS = frozenset({"unstructured", "loop_exit_unstructured"})
_GUARD_ROUNDS = 3  # generations at most to settle the guards found after rendering


def risk_flags(flags: Iterable[str]) -> Tuple[str, ...]:
    """The flags among `flags` that the static guards act on, sorted."""
    return tuple(sorted(f for f in flags if f in RISK_FLAGS or f.startswith("engine:")))


def derive_confidence(entry: Mapping[str, object]) -> str:
    """How far the text written for one function can be trusted to behave
    like the original (`entry`: a value of `SolgenResult.functions`).

      none    the decompiler failed on the function (flag `problem`): there
              is no code to trust.
      low     the differential execution found a difference (verdict
              DIVERGENT, MISSING or EXTRA); or, without such a verdict, a
              part of the code is left out (`unstructured`,
              `loop_exit_unstructured`) or carries a marker of the
              decompiler (`engine:*`).
      high    the differential execution agreed (verdict EQUIVALENT) on
              code free of those flags.  Nothing is rated "high" without
              that evidence: the exact form is exact by construction, not
              by observation.
      medium  everything else: a function that was not verified, in exact
              form or rewritten; an agreement seen on reverting calls only
              (EQUIVALENT_REVERTS_ONLY) or an inconclusive verification;
              also EQUIVALENT on code with a `low` flag (the calls tried may
              not have reached the missing part).

    The verdicts ROUTED and SKIPPED mean "not checked": the function is
    rated as if no verification had run."""
    flags = set(entry.get("flags") or ()) | set(entry.get("guards") or ())  # type: ignore[call-overload]
    if "problem" in flags:
        return "none"
    verdict = entry.get("verdict")
    doubtful = bool(flags & _INCOMPLETE_FLAGS) or any(f.startswith("engine:") for f in flags)
    if verdict in DIFFERING:
        return "low"
    if verdict == "EQUIVALENT":
        return "medium" if doubtful else "high"
    return "low" if doubtful else "medium"


def _jsonable(x):
    """`x` with only what JSON holds (tuples and sets as lists, bytes as hex)."""
    if x is None or isinstance(x, (bool, int, float, str)):
        return x
    if isinstance(x, Mapping):
        return {str(k): _jsonable(v) for k, v in x.items()}
    if isinstance(x, (set, frozenset)):
        return sorted((_jsonable(v) for v in x), key=repr)
    if isinstance(x, (list, tuple)):
        return [_jsonable(v) for v in x]
    if isinstance(x, (bytes, bytearray)):
        return "0x" + bytes(x).hex()
    return str(x)


@dataclasses.dataclass
class SolgenResult:
    """What the generator produces.

    solidity: the source text.
    confidence: function key -> "high" | "medium" | "low" | "none"
        (`derive_confidence`: from the verification verdict and the flags
        of the function; "high" only for a function verified EQUIVALENT).
    warnings: what the reader of the whole text should know (degraded
        input, a pass that failed, a verification that could not run).
    functions: function key ("0x<selector>", "_fallback", "_receive") ->
        {"name", "signature", "selector", "kind", "routed", "payable",
         "mutability", "tier", "verdict", "passes", "disabled_passes",
         "flags", "guards", "calls", "coverage", "folded", "confidence",
         "abi", "arith"}
        ("tier": "exact", "idiomatic" or "partial" (rewritten, but
        without the passes of "disabled_passes" that the full tier
        applies); "verdict": "unverified" or a scobelix.verify verdict;
        "guards": the flags for which the static guards kept the function
        exact; "calls", "coverage": how many calls the verification
        compared and what they covered, plus a "counterexample" (the call,
        its sender and value, what each side did) when it found a
        difference and a "reason" when the verifier gave one; "folded":
        the declaration whose generated getter replaces the function, or
        None)
    target_solc: the compiler version the text is written for.
    verification: with verify=True, when the verification could run, the
        scobelix.verify report of the last run of the returned text
        (`levels`, `functions`, `summary`, `passed`, `to_json()`); after
        the verification loop it also carries the levels L2 and L4 and
        `search`, what the loop did (see tiers.py).  None otherwise.
    storage_layout: the state variables the storage pass declared
        ({"name", "slot", "offset", "type", "public", "id", "encoding",
        "bytes"}, slot order).
    original_compiler: the compiler of the original, from its metadata."""

    solidity: str
    confidence: Dict[str, str]
    warnings: List[str]
    functions: Dict[str, dict] = dataclasses.field(default_factory=dict)
    target_solc: str = ""
    verification: Optional[object] = None
    contract_name: str = CONTRACT_NAME
    original_compiler: str = ""
    idiom_level: str = "exact"
    routed_selectors: List[str] = dataclasses.field(default_factory=list)
    abi_hint: Dict[str, dict] = dataclasses.field(default_factory=dict)
    storage_layout: List[dict] = dataclasses.field(default_factory=list)  # declared state variables
    # the assembly the text was rendered from (Generator.verify writes the verdicts into it)
    _assembly: Optional[ContractInput] = dataclasses.field(default=None, repr=False, compare=False)
    # (declaration kind, text) -> the pass that declared it
    _declared_by: Dict[Tuple[str, str], str] = dataclasses.field(default_factory=dict, repr=False, compare=False)

    def functions_json(self) -> dict:
        """The per-function table as JSON data."""
        return _jsonable(self.functions)

    def verification_json(self) -> Optional[dict]:
        """The verification report as JSON data (None when there is none)."""
        if self.verification is None:
            return None
        return _jsonable(self.verification.to_json())  # type: ignore[attr-defined]

    def to_json(self) -> dict:
        """Everything but the private fields, as JSON data."""
        return {
            "solidity": self.solidity,
            "confidence": dict(self.confidence),
            "warnings": [str(w) for w in self.warnings],
            "functions": self.functions_json(),
            "target_solc": self.target_solc,
            "contract_name": self.contract_name,
            "original_compiler": self.original_compiler,
            "idiom_level": self.idiom_level,
            "storage_layout": _jsonable(self.storage_layout),
            "verification": self.verification_json(),
        }


# ---------------------------------------------------------------- inputs


@dataclasses.dataclass
class _FnInput:
    key: str
    trace: object
    payable: bool
    params: Dict[str, tuple] = dataclasses.field(default_factory=dict)  # json: name -> (offset, type)
    problem: bool = False
    # the decompiler stopped simplifying the trace at its time limit (exact, not fully simplified)
    time_limited: bool = False


@dataclasses.dataclass
class _Inputs:
    bytecode: bytes
    metadata: Optional[dict]
    dispatcher: Optional[dict]
    functions: List[_FnInput]
    vocabulary: str
    array_bases: Tuple[int, ...] = ()
    absent: Tuple[str, ...] = ()  # entry points of the original that the decompilation does not hold


def _hex_bytes(h) -> bytes:
    if isinstance(h, (bytes, bytearray)):
        return bytes(h)
    if not h or not isinstance(h, str):
        return b""
    h = h[2:] if h.startswith("0x") else h
    try:
        return bytes.fromhex(h)
    except ValueError:
        return b""


def _items(x) -> list:
    return list(x) if isinstance(x, (list, tuple)) else []


def _clean_metadata(meta) -> Optional[dict]:
    """The compiler metadata with the fields the generator reads, each of
    the expected type or left out."""
    if not isinstance(meta, Mapping):
        return None
    out = dict(meta)
    for name in ("compiler", "version"):
        if not isinstance(out.get(name), str):
            out.pop(name, None)
    rng = out.get("version_range")
    if not (isinstance(rng, (list, tuple)) and len(rng) == 2 and all(isinstance(v, str) for v in rng)):
        out.pop("version_range", None)
    return out


def _clean_dispatcher(disp) -> Optional[dict]:
    """The dispatcher analysis with the parts the generator reads, each of
    the expected type or empty."""
    if not isinstance(disp, Mapping):
        return None
    out = dict(disp)
    for name in ("selectors", "exits", "duplicates"):
        out[name] = [x for x in _items(disp.get(name)) if isinstance(x, Mapping)]
    for name in ("fallback", "receive"):
        out[name] = disp.get(name) if isinstance(disp.get(name), Mapping) else None
    return out


def _collect(decompilation) -> _Inputs:
    """Traces and contract facts from a Decompilation (or its json dict).
    A part of the JSON form that does not have the expected type is read as
    if it were missing."""
    if isinstance(decompilation, Mapping):
        js, functions, meta, disp, code = decompilation, {}, None, None, b""
    else:
        js = getattr(decompilation, "json", None)
        js = js if isinstance(js, Mapping) else {}
        functions = getattr(decompilation, "functions", None)
        functions = functions if isinstance(functions, Mapping) else {}
        meta = getattr(decompilation, "metadata", None)
        disp = getattr(decompilation, "dispatcher", None)
        code = _hex_bytes(getattr(decompilation, "bytecode", ""))
    meta = _clean_metadata(meta if meta is not None else js.get("metadata"))
    disp = _clean_dispatcher(disp if disp is not None else js.get("dispatcher"))
    problems = js.get("problems")
    problems = [key for key in problems if isinstance(key, str)] if isinstance(problems, Mapping) else []
    out: List[_FnInput] = []
    vocabulary = "raw"
    if functions:
        for key, f in functions.items():
            out.append(_FnInput(key, getattr(f, "orig_trace", None), bool(getattr(f, "payable", True)),
                                time_limited=getattr(f, "time_limited", False) is True))
    else:
        vocabulary = "json"
        for f in _items(js.get("functions")):
            key = f.get("hash") if isinstance(f, Mapping) else None
            if not isinstance(key, str):
                continue
            params = {}
            declared = f.get("params")
            for off, val in (declared.items() if isinstance(declared, Mapping) else ()):
                try:
                    params[str(val[1])] = (int(off), str(val[0]))
                except (TypeError, ValueError, IndexError, KeyError):
                    pass
            out.append(_FnInput(key, f.get("trace"), bool(f.get("payable", True)), params,
                                time_limited=f.get("time_limited") is True))
    have = {f.key for f in out}
    for key in problems:  # the decompiler failed on them: a stub says so
        if key not in have:
            out.append(_FnInput(key, None, False, problem=True))
            have.add(key)
    # what the dispatcher routes to but the decompilation does not hold (a
    # decompilation restricted to some functions): left out, and reported
    fallback, receive = (disp or {}).get("fallback") or {}, (disp or {}).get("receive") or {}
    listed = [sel.get("function") or sel.get("selector") for sel in (disp or {}).get("selectors") or []]
    if fallback.get("present"):
        listed.append(fallback.get("function") or "_fallback")
    if receive:
        listed.append(receive.get("function") or "_receive")
    absent: List[str] = []
    for key in listed:
        if isinstance(key, str) and key and key not in have and key not in absent:
            absent.append(key)
    bases = []
    for d in _items(js.get("stor_defs")):
        try:
            if d[0] == "def" and isinstance(d[3], (list, tuple)) and d[3][0] == "array" and isinstance(d[2], int):
                bases.append(d[2])
        except (TypeError, IndexError, KeyError):
            continue
    return _Inputs(code, meta, disp, out, vocabulary, tuple(bases), tuple(absent))


def _shown(keys, limit: int = 8) -> str:
    keys = list(keys)
    return ", ".join(str(k) for k in keys[:limit]) + (", ..." if len(keys) > limit else "")


def _selector(key: str) -> Optional[int]:
    if isinstance(key, str) and re.fullmatch(r"0x[0-9a-fA-F]{1,8}", key):
        return int(key, 16)
    return None


def _original(meta: Optional[dict]) -> str:
    if not meta:
        return "unknown (no compiler metadata)"
    comp = meta.get("compiler") or "unknown"
    if meta.get("version"):
        return f"{comp} {meta['version']}"
    rng = meta.get("version_range")
    if rng:
        return f"{comp} {rng[0]} - {rng[1]}"
    return comp


def _vkey(v: str) -> Tuple[int, int, int]:
    try:
        parts = [int(x) for x in v.split(".")[:3]]
    except (ValueError, AttributeError):
        return (0, 0, 0)
    return tuple(parts + [0] * (3 - len(parts)))  # type: ignore[return-value]


def choose_target(metadata: Optional[dict], requested: Optional[str] = None, allow_download: Optional[bool] = None,
                  minimum: Tuple[int, int, int] = (0, 8, 2)) -> str:
    """The solc version to target (DESIGN 6.4): the requested one, else the
    original's when it is 0.8 (and installed, or downloadable), else the
    newest installed 0.8.x, at least `minimum`."""
    if requested:
        return requested
    try:
        from scobelix.verify.solc import download_allowed, installed_solcs

        installed = [v for v in installed_solcs() if _vkey(v)[:2] == (0, 8) and _vkey(v) >= minimum]
        download = download_allowed(allow_download)
    except Exception:  # noqa: BLE001 - no resolver: fall back to the default
        installed, download = [], False
    v = (metadata or {}).get("version") if (metadata or {}).get("compiler") == "solc" else None
    if v and _vkey(v)[:2] == (0, 8) and _vkey(v) >= minimum and (v in installed or download):
        return v
    if installed:
        return max(installed, key=_vkey)
    if v and _vkey(v)[:2] == (0, 8) and _vkey(v) >= minimum:
        return v
    return max(DEFAULT_TARGET, ".".join(str(x) for x in minimum), key=_vkey)


def _original_abi_v2(meta: Optional[dict], fns: Iterable[ir.Function]) -> bool:
    if meta and meta.get("compiler") == "solc":
        if meta.get("version") and _vkey(meta["version"]) >= (0, 8, 0):
            return not abi.uses_abi_v1(list(fns))  # v2 unless `pragma abicoder v1`
        if meta.get("experimental"):
            return True
    return abi.uses_abi_v2(list(fns))


def _default_revert(fn: ir.Function) -> bool:
    """`fn` only reverts without data, possibly behind a call value test
    whose two sides do: what solc generates for a contract that defines no
    fallback, so the text needs none either.  A default exit that halts
    (INVALID: older compilers, hand-written code, data that is not code)
    is not that one and is written out as a fallback of its own."""

    def only_reverts(block) -> bool:
        block = block[abi._seed_prefix(block):]
        if len(block) != 1:
            return False
        stmt = block[0]
        if isinstance(stmt, ir.Revert):
            return isinstance(stmt.payload, ir.Empty)
        if isinstance(stmt, ir.If) and abi._test_callvalue(stmt.cond) is not None:
            return only_reverts(stmt.then) and only_reverts(stmt.orelse)
        return False

    return only_reverts(fn.body)


# ---------------------------------------------------------------- generation


def generate(
    decompilation,
    target_solc: Optional[str] = None,
    verify: bool = False,
    idiom_level: str = "exact",
    *,
    disabled_passes: Optional[Mapping[str, Iterable[str]]] = None,
    allow_download: Optional[bool] = None,
    budget=None,
    contract_name: str = CONTRACT_NAME,
    static_guards: bool = True,
) -> SolgenResult:
    """Solidity for `decompilation` (see the module docstring).

    target_solc     compiler version to write for (default: choose_target)
    verify          run the verification loop (tiers.py): the text is
                    compiled and executed against the original bytecode,
                    and every function is written in its most idiomatic
                    form that was seen to behave like the original
    idiom_level     "exact" (no pass) or "full" (every available pass)
    disabled_passes {function key or "*": {pass names}} not to run
    allow_download  let the verifier / target choice fetch a solc release
    budget          for verify=True: a scobelix.verify.Budget, a
                    tiers.SearchBudget, or the fields of both in a dict
    static_guards   keep the functions whose code carries a risk flag in
                    exact form (module docstring)
    """
    generator = Generator(decompilation, target_solc, idiom_level, allow_download=allow_download,
                          contract_name=contract_name, static_guards=static_guards)
    if verify:
        return generator.search(budget, disabled_passes)
    return generator.regenerate(disabled_passes)


@contextlib.contextmanager
def _deep_recursion():
    limit = sys.getrecursionlimit()
    if limit < RECURSION_FLOOR:
        sys.setrecursionlimit(RECURSION_FLOOR)
    try:
        yield
    finally:
        if limit < RECURSION_FLOOR:
            sys.setrecursionlimit(limit)


class Generator:
    """One decompilation, ready to be written out any number of times.

    The constructor does what depends on the decompilation only: it
    collects the traces, lifts every entry point and derives the ABI facts.
    `regenerate` runs the passes and assembles the contract;
    `verify` checks one result against the original bytecode;
    `search` is the verification loop: it regenerates and verifies until
    every function is in its most idiomatic verified form.

    risky: function key -> the risk flags of its lifted code (the functions
        the static guards keep in exact form at the "full" level).
    """

    def __init__(self, decompilation, target_solc: Optional[str] = None, idiom_level: str = "exact", *,
                 allow_download: Optional[bool] = None, contract_name: str = CONTRACT_NAME,
                 static_guards: bool = True):
        if idiom_level not in pipeline.IDIOM_LEVELS:
            raise ValueError(f"idiom_level must be one of {pipeline.IDIOM_LEVELS}")
        if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", contract_name or "") or reserved_name(contract_name):
            raise ValueError(f"contract_name {contract_name!r} is not a name solc accepts for the contract")
        if target_solc is not None and not re.fullmatch(r"\d+\.\d+\.\d+", str(target_solc)):
            raise ValueError(f"target_solc {target_solc!r} is not a compiler version (expected X.Y.Z)")
        self.requested_target = target_solc
        self.idiom_level = idiom_level
        self.allow_download = allow_download
        self.contract_name = contract_name
        self.static_guards = static_guards
        self._reference: Dict[bool, Dict[str, Tuple[str, ...]]] = {}  # guards on -> the full tier's passes
        with _deep_recursion():
            self._prepare(decompilation)

    # ------------------------------------------------------------ once

    def _prepare(self, decompilation) -> None:
        warnings: List[str] = []
        inputs = _collect(decompilation)
        disp = inputs.dispatcher or {}
        lctx = lift.make_context(inputs.bytecode, inputs.vocabulary, inputs.array_bases)
        if not inputs.bytecode:
            warnings.append("no bytecode in the decompilation: copies of the code read as zeros (flag code_unknown) "
                            "and nothing can be verified")
        if inputs.vocabulary == "json":
            warnings.append("no in-memory functions: lifted from the JSON traces (degraded)")
        if inputs.absent:
            warnings.append(f"{len(inputs.absent)} entry point(s) of the original are not in the decompilation and "
                            f"are left out of the text: {_shown(inputs.absent)}")
        elif not inputs.functions:
            warnings.append("no function in the decompilation: the text is an empty contract")

        # ---- lift
        lifted: Dict[str, ir.Function] = {}
        payable: Dict[str, bool] = {}
        for f in inputs.functions:
            if f.problem or f.trace is None:
                fn = ir.Function(f.key, (ir.Unstructured(f.key, "the decompiler failed on this function"),),
                                 frozenset({"problem", "unstructured"}))
            else:
                fn = lift.lift_function(f.key, f.trace, lctx, f.params)
                if f.time_limited:  # (exact: no risk flag, but the reader must know it)
                    fn = fn.with_body(fn.body, (FLAG_TIME_LIMITED,))
            lifted[f.key] = fn
            payable[f.key] = True if f.key == "_receive" else f.payable
        abi_v2 = _original_abi_v2(inputs.metadata, lifted.values())

        fb = disp.get("fallback") or {}
        # the dispatcher analysis also files a default exit that halts on
        # INVALID under "no fallback": the lifted code decides
        fallback_present = bool(fb.get("present")) or (
            "_fallback" in lifted and not _default_revert(lifted["_fallback"]))
        receive_present = "_receive" in lifted
        if not receive_present and fallback_present and "_fallback" in lifted and any(
                x.get("kind") == "empty" and x.get("function") == "_fallback" for x in disp.get("exits") or []):
            # solc only tests for empty calldata when there is a receive(): one
            # that runs the fallback's code (the analysis reports it as fallback)
            lifted["_receive"] = ir.Function("_receive", lifted["_fallback"].body, lifted["_fallback"].flags)
            payable["_receive"] = True
            receive_present = True

        # ---- ABI facts
        specs: Dict[str, abi.EntrySpec] = {}
        for key, fn in lifted.items():
            spec, fn = abi.analyse_entry(fn, key, selector=_selector(key), payable=payable[key], abi_v2=abi_v2,
                                         reserved=frozenset({self.contract_name}))
            lifted[key] = fn
            specs[key] = spec
        routed = [k for k, s in specs.items() if s.routed]
        _dispatch_flags(specs, disp, inputs.metadata)
        _legacy_decoder_flags(specs, lifted, abi_v2)
        fallback_payable = payable.get("_fallback", False) if fallback_present else False
        our_fallback_payable = fallback_payable or any(specs[k].payable for k in routed)
        for key, spec in specs.items():
            if spec.payable:
                continue
            if key == "_fallback" and our_fallback_payable:
                continue  # the original's own check stays in the body
            fn, stripped = abi.strip_callvalue_check(lifted[key])
            if stripped:
                lifted[key] = fn
                abi.set_mutability(spec, fn)
        # (after the strip: with a payable function in the contract, every
        # other function checks the call value itself, a read that makes the
        # body `view` until the check is gone)
        for key, spec in specs.items():
            _constant_getter_mutability(spec, lifted[key], lctx)

        self.bytecode = inputs.bytecode
        self.metadata = inputs.metadata
        self.dispatcher = inputs.dispatcher
        self.abi_v2 = abi_v2
        self.original_compiler = _original(inputs.metadata)
        self.target_solc = choose_target(inputs.metadata, self.requested_target, self.allow_download)
        self.routed = sorted(routed)
        self.risky: Dict[str, Tuple[str, ...]] = {}
        for key, fn in lifted.items():
            flags = risk_flags(set(fn.flags) | specs[key].flags)
            if flags:
                self.risky[key] = flags
        self._lifted = lifted
        self._specs = specs  # as analysed: every generation works on a copy (the passes edit them)
        self._warnings = warnings
        self._fallback = (fallback_payable, fallback_present, receive_present)
        self._left_out = inputs.absent

    # ------------------------------------------------------------ each generation

    def regenerate(self, disabled_passes: Optional[Mapping[str, Iterable[str]]] = None, *,
                   static_guards: Optional[bool] = None, excluded_storage: Iterable[str] = ()) -> SolgenResult:
        """The contract with the passes of `disabled_passes` ({function key
        or "*": pass names}) switched off, from the bodies lifted once.
        (pipeline.py says what a switch means for the passes that work on
        the whole contract.)

        static_guards (default: the generator's setting): also switch every
        pass off for the functions carrying a risk flag, those known from
        the lifted code and those only the rendering of the idiomatic form
        reveals (the contract is then generated once more).
        excluded_storage: state variables (the "id" of their entry in
        `SolgenResult.storage_layout`) to leave undeclared: every function
        reaches them by slot."""
        guards_on = self.static_guards if static_guards is None else static_guards
        guards_on = guards_on and self.idiom_level != "exact"
        disabled: Dict[str, Set[str]] = {k: set(v) for k, v in (disabled_passes or {}).items() if v}
        excluded = tuple(sorted(set(excluded_storage or ())))
        plain = not disabled and not excluded
        # the passes every function gets with nothing switched off: what a
        # variant is compared with to call it "partial"
        reference = None
        if not plain:
            try:
                reference = self.full_passes(guards_on)
            except Exception:  # noqa: BLE001 - the full tier cannot be written out: nothing to compare with
                logger.debug("generation of the full tier failed", exc_info=True)
                self._reference.setdefault(guards_on, {})
        guarded: Dict[str, Tuple[str, ...]] = dict(self.risky) if guards_on else {}
        with _deep_recursion():
            for attempt in range(_GUARD_ROUNDS):
                off = dict(disabled)
                for key in guarded:
                    off[key] = set(pipeline.PASS_ORDER)
                result, units = self._run(off, guarded, excluded, reference)
                if not guards_on or attempt == _GUARD_ROUNDS - 1:
                    break
                late = {u.key: risk_flags(u.flags) for u in units if u.tier != "exact" and risk_flags(u.flags)}
                if not late:
                    break
                guarded.update(late)
        if plain:
            self._reference[guards_on] = {key: tuple(entry["passes"]) for key, entry in result.functions.items()}
        return result

    def full_passes(self, static_guards: Optional[bool] = None) -> Dict[str, Tuple[str, ...]]:
        """Function key -> the passes that rewrite it when nothing is
        switched off (the full tier of this generator)."""
        guards_on = self.static_guards if static_guards is None else static_guards
        guards_on = guards_on and self.idiom_level != "exact"
        if guards_on not in self._reference:
            self.regenerate(static_guards=guards_on)
        return self._reference[guards_on]

    def _run(self, disabled: Mapping[str, Iterable[str]], guarded: Mapping[str, Tuple[str, ...]],
             excluded: Iterable[str] = (),
             reference: Optional[Mapping[str, Tuple[str, ...]]] = None) -> Tuple[SolgenResult, List[Unit]]:
        warnings = list(self._warnings)
        specs = copy.deepcopy(self._specs)
        fallback_payable, fallback_present, receive_present = self._fallback
        target = self.target_solc
        pctx = pipeline.PassContext(specs=specs, metadata=self.metadata, dispatcher=self.dispatcher,
                                    target_solc=target, abi_v2=self.abi_v2, idiom_level=self.idiom_level,
                                    bytecode=self.bytecode, functions=dict(self._lifted),
                                    disabled_passes=dict(disabled), excluded_storage=tuple(excluded))
        passes = pipeline.available_passes(self.idiom_level)
        if self._lifted and all(key in guarded for key in self._lifted):
            passes = []  # nothing to rewrite: no contract-level declaration either
        pipeline.prepare(passes, pctx)
        units: List[Unit] = []
        for key, fn in self._lifted.items():
            fn2, applied = pipeline.run_passes(fn, passes, pctx)
            units.append(Unit(key, fn2, specs[key], passes=applied, flags=set(fn2.flags) | specs[key].flags,
                              guards=tuple(guarded.get(key, ()))))
        pipeline.finish(passes, pctx)
        warnings.extend(pctx.warnings)
        for unit in units:
            if unit.key in pctx.folded:
                unit.folded = pctx.folded[unit.key]
                if "getters" not in unit.passes:
                    unit.passes = unit.passes + ("getters",)
            if unit.spec.typed_route and "abi" not in unit.passes:
                # the abi pass typed a routed function (its declaration only,
                # the body may be the same): switching `abi` off is the untyped route
                unit.passes = tuple(p for p in pipeline.PASS_ORDER if p in unit.passes or p == "abi")
            # what the full tier applies to the function and this variant does not
            lost = set((reference or {}).get(unit.key, ())) - set(unit.passes)
            unit.disabled = tuple(p for p in pipeline.PASS_ORDER if p in lost)
            unit.tier = "exact" if not unit.passes else "partial" if lost else "idiomatic"
        kept = sorted(u.key for u in units if u.guards)
        if kept:
            shown = ", ".join(kept[:8]) + (", ..." if len(kept) > 8 else "")
            warnings.append(f"{len(kept)} function(s) kept in exact form by the static guards (risk flags): {shown}")

        ci = ContractInput(
            units=units, target=target, original=self.original_compiler, abi_v2=self.abi_v2,
            idiom_level=self.idiom_level, contract_name=self.contract_name, original_code=self.bytecode,
            fallback_payable=fallback_payable, fallback_present=fallback_present, receive_present=receive_present,
            declarations=pctx.declarations, left_out=self._left_out,
        )
        solidity, rctx = _assemble(ci, self.requested_target, self.allow_download, self.metadata)
        # what the reader of the whole text must not miss about single functions
        failed = sorted(u.key for u in units if "problem" in u.flags)
        if failed:
            warnings.append(f"the decompiler failed on {len(failed)} function(s), written as stubs that revert: "
                            f"{_shown(failed)}")
        limited = sorted(u.key for u in units if FLAG_TIME_LIMITED in u.flags)
        if limited:
            warnings.append(f"the decompiler stopped simplifying {len(limited)} function(s) at its time limit: "
                            f"exact, but not fully simplified (flag {FLAG_TIME_LIMITED}): {_shown(limited)}")
        partial = sorted(u.key for u in units if "problem" not in u.flags and u.flags & _INCOMPLETE_FLAGS)
        if partial:
            warnings.append(f"{len(partial)} function(s) hold code that could not be written as Solidity (flags "
                            f"unstructured, loop_exit_unstructured) and may revert where the original does not: "
                            f"{_shown(partial)}")
        need = max(list(rctx.features.values()) + [(0, 8, 2)])
        if _vkey(ci.target) < need:
            warnings.append(f"the text needs solc >= {'.'.join(str(x) for x in need)}: "
                            f"the requested target {ci.target} does not compile it")

        functions = _table(units, pctx.facts)
        result = SolgenResult(
            solidity=solidity,
            confidence={key: entry["confidence"] for key, entry in functions.items()},
            warnings=warnings,
            functions=functions,
            target_solc=ci.target,
            contract_name=self.contract_name,
            original_compiler=ci.original,
            idiom_level=self.idiom_level,
            routed_selectors=list(self.routed),
            abi_hint=_abi_hint(specs, self._left_out),
            storage_layout=_storage_layout(pctx),
        )
        result._assembly = ci
        result._declared_by = dict(pctx.declared_by)
        return result, units

    # ------------------------------------------------------------ verification

    def verify(self, result: SolgenResult, budget=None, **options) -> None:
        """Compile `result` and compare it with the original bytecode, once
        (scobelix.verify, levels L0, L1 and L3; `options` go to
        `scobelix.verify.verify`, e.g. `selectors` to check some functions
        only).  Fills `result.verification`, the verdict and the confidence
        of every function, and writes the verdicts into the text; the text
        is otherwise left as it is, whatever the verdicts.  A verification
        that cannot run (no compiler, no EVM backend, no bytecode) leaves a
        warning, never an exception."""
        _verify(result, self.bytecode, budget, self.allow_download, options)

    def search(self, budget=None, disabled_passes: Optional[Mapping[str, Iterable[str]]] = None) -> SolgenResult:
        """The verification loop (tiers.py): the text in which every
        function has its most idiomatic form that was observed to behave
        like the original, the others being written in exact form, with
        the verdicts and what the loop did (`result.verification`).

        budget: a `scobelix.verify.Budget` for each run, a
        `tiers.SearchBudget` (limits of the loop), or the fields of both in
        one dict.  `disabled_passes`: switches the loop starts from and
        never turns back on."""
        from scobelix.solgen import tiers

        return tiers.search(self, budget, disabled_passes)


def _constant_getter_mutability(spec: abi.EntrySpec, fn: ir.Function, lctx) -> None:
    """A parameterless function returning a constant (a word, a string) is
    `pure` by its code, but public constants (UPPER_CASE) and immutables (a
    narrow value pushed by PUSH32, filled in at deployment) are `view` in
    the ABI."""
    if spec.kind != "function" or spec.mutability != "pure" or spec.params or spec.signature is None:
        return
    data = abi.constant_return(fn)
    if data is None:
        return
    value = abi.constant_getter(fn)
    if (spec.name.upper() == spec.name and any(c.isalpha() for c in spec.name)) \
            or (value is not None and value in lctx.push32_narrow):
        spec.mutability = "view"


def _dispatch_flags(specs: Dict[str, abi.EntrySpec], disp: dict, meta: Optional[dict]) -> None:
    """Flags for what the dispatcher analysis or the target decoder cannot
    reproduce exactly."""
    fb = disp.get("fallback") or {}
    if fb and fb.get("consistent") is False and "_fallback" in specs:
        # the original runs different code on short and on unmatched calldata
        specs["_fallback"].flags.add("dispatcher_inconsistent")
    for d in disp.get("duplicates") or []:
        if d.get("selector") in specs:
            specs[d["selector"]].flags.add("dispatcher_duplicate")
    rng = (meta or {}).get("version_range") or ()
    old = (meta or {}).get("compiler") == "solc" and (
        (meta.get("version") and _vkey(meta["version"]) < (0, 5, 0)) or (rng and _vkey(rng[1]) < (0, 5, 0)))
    if old:
        for spec in specs.values():
            if spec.signature and spec.params:
                # solc >= 0.5 decoders revert on short calldata, 0.4 ones read zeros
                spec.flags.add("abi:short_calldata_check")


def _indirect_calldata(n: ir.Node) -> bool:
    """A calldata read at an offset read from calldata (a dynamic parameter)."""
    if isinstance(n, ir.CalldataWord):
        return ir.contains(n.offset, ir.CalldataWord)
    if isinstance(n, ir.CalldataSlice):
        return ir.contains(n.start, ir.CalldataWord)
    return False


def _legacy_decoder_flags(specs: Dict[str, abi.EntrySpec], lifted: Dict[str, ir.Function], abi_v2: bool) -> None:
    """ABI coder v1 decoders copy dynamic parameters to memory without the
    bounds checks of v2: a length too large to copy runs out of gas in the
    original, while the generated code reads the calldata in place."""
    if abi_v2:
        return
    for key, fn in lifted.items():
        if key in specs and any(_indirect_calldata(n) for n in ir.walk_all(fn.body)):
            specs[key].flags.add("abi:legacy_memory_copy")


def _assemble(ci: ContractInput, requested: Optional[str], allow_download, meta) -> Tuple[str, RenderContext]:
    """Render; when the text needs a newer compiler than the target, pick
    one that has every feature and render again."""
    for unit in ci.units:
        unit.flags = set(unit.fn.flags) | unit.spec.flags
    solidity, rctx = assemble(ci)
    need = max(list(rctx.features.values()) + [(0, 8, 2)])
    if _vkey(ci.target) < need and not requested:
        ci.target = choose_target(meta, None, allow_download, need)
        for unit in ci.units:
            unit.flags = set(unit.fn.flags) | unit.spec.flags
        solidity, rctx = assemble(ci)
    return solidity, rctx


def _table(units: List[Unit], facts: Optional[dict] = None) -> Dict[str, dict]:
    abi_facts = ((facts or {}).get("abi") or {}).get("functions") or {}  # the abi pass: decoder checks removed
    arith_facts = ((facts or {}).get("arith") or {}).get("functions") or {}  # the arith pass: Panic guards
    loop_facts = ((facts or {}).get("loops") or {}).get("functions") or {}  # the loops pass: loop forms, locals
    naming_facts = ((facts or {}).get("naming") or {}).get("functions") or {}  # the naming pass: names given
    modifier_facts = ((facts or {}).get("modifiers") or {}).get("functions") or {}  # modifiers applied
    out = {}
    for u in units:
        s = u.spec
        out[u.key] = {
            "name": s.name,
            "signature": s.signature,
            "selector": None if s.selector is None else f"0x{s.selector:08x}",
            "kind": s.kind,
            "routed": s.routed,
            "payable": s.payable,
            "mutability": s.mutability,
            "tier": u.tier,
            "verdict": u.verdict,
            "passes": list(u.passes),
            "disabled_passes": list(u.disabled),
            "flags": sorted(u.flags),
            "guards": list(u.guards),
            "calls": 0,
            "coverage": None,
            "folded": u.folded,
            "abi": abi_facts.get(u.key),
            "arith": arith_facts.get(u.key),
            "loops": loop_facts.get(u.key),
            "naming": naming_facts.get(u.key),
            "modifiers": modifier_facts.get(u.key),
        }
        out[u.key]["confidence"] = derive_confidence(out[u.key])
    return out


def _storage_layout(pctx: pipeline.PassContext) -> List[dict]:
    """The declared state variables (when the storage pass ran)."""
    lay = pctx.facts.get("storage_declared")
    return list(lay) if isinstance(lay, list) else []


def _abi_hint(specs: Dict[str, abi.EntrySpec], left_out: Iterable[str] = ()) -> Dict[str, dict]:
    """The original's functions as scobelix.verify takes them (abi_hint):
    those of the text and, with nothing known but their selector, those the
    decompilation left out (the interface check must find them missing)."""
    out: Dict[str, dict] = {}
    for key in left_out:
        sel = _selector(key)
        if sel is not None:
            out[f"0x{sel:08x}"] = {}
    for key, s in specs.items():
        if s.selector is None:
            continue
        hint: dict = {"payable": s.payable}
        if s.signature:
            hint["signature"] = s.signature
        elif s.head_words is not None:
            types = []
            for w in range(s.head_words):
                t = s.inferred.get(w, "uint256")
                types.append("bytes" if t == "dynamic" else t)
            hint["inputs"] = types
        out[f"0x{s.selector:08x}"] = hint
    return out


# ---------------------------------------------------------------- one verification run

VERIFY_LEVELS = ("L0", "L1", "L3")


def _check(result: SolgenResult, code: bytes, budget, allow_download,
           options: Optional[dict] = None) -> Tuple[Optional[object], str]:
    """One run of scobelix.verify on the text of `result`: (report, ""), or
    (None, why it could not run).  `options` go to `scobelix.verify.verify`
    (`selectors`, `levels`, `backend`...)."""
    ci = result._assembly
    if ci is None:
        return None, "verification skipped: the result does not come from a generator"
    if not code:
        return None, "verification skipped: no original bytecode"
    opts = dict({"levels": VERIFY_LEVELS}, **(options or {}))
    try:
        from scobelix.verify import verify as run_verify

        report = run_verify(code, result.solidity, contract_name=ci.contract_name, abi_hint=result.abi_hint,
                            solc_version=ci.target, budget=budget, routed_selectors=result.routed_selectors,
                            allow_download=allow_download, **opts)
    except Exception as e:  # noqa: BLE001 - verification must not lose the source
        logger.debug("verification failed", exc_info=True)
        return None, f"verification unavailable: {type(e).__name__}: {e}"
    return report, ""


def _level_warnings(report) -> List[str]:
    """What the reader of the whole text must know about the levels of a
    verification report: every one that did not pass."""
    out: List[str] = []
    compiled = report.levels.get("L0")
    if compiled is not None and compiled.status != "pass":  # the later levels then only say "no compiler"
        errors = [str(e).strip().split("\n")[0] for e in (compiled.details.get("errors") or [])[:1]]
        out.append(f"verification L0 {compiled.status}: " + "; ".join([compiled.reason or "no reason given"] + errors))
        return out
    if any("stack too deep" in str(w).lower() for w in getattr(report, "warnings", None) or ()):
        # the verifier compiled again with the IR pipeline: the default one ran out of stack
        out.append("verification L0: the text compiles with --via-ir --optimize only (the default pipeline of solc "
                   "reports 'Stack too deep')")
    for name in VERIFY_LEVELS[1:]:
        level = report.levels.get(name)
        if level is not None and level.status != "pass":  # a failure as much as a level that did not run
            out.append(f"verification {name} {level.status}: {level.reason or 'no reason given'}")
    return out


def report_keys(units: Iterable[Unit]) -> Dict[str, Tuple[str, ...]]:
    """Unit key -> the keys of a scobelix.verify report that speak for it:
    its selector; "fallback" (calls matching no selector) for the fallback,
    which also answers the calls without calldata ("receive") when the
    contract has no receive of its own."""
    units = list(units)
    has_receive = any(u.spec.kind == "receive" for u in units)
    out: Dict[str, Tuple[str, ...]] = {}
    for u in units:
        if u.spec.kind == "receive":
            out[u.key] = ("receive",)
        elif u.spec.kind == "fallback":
            out[u.key] = ("fallback",) if has_receive else ("fallback", "receive")
        else:
            out[u.key] = (u.key if u.spec.selector is None else f"0x{u.spec.selector:08x}",)
    return out


def speaking(report, keys: Iterable[str]):
    """The function report to show for a unit whose report keys are `keys`:
    the first one, unless only a later one found a difference."""
    found = [report.functions[k] for k in keys if k in report.functions]
    if not found:
        return None
    if found[0].verdict not in DIFFERING:
        for other in found[1:]:
            if other.verdict in DIFFERING:
                return other
    return found[0]


def _cut(data, limit: int = 72) -> str:
    data = str(data or "0x")
    return data if len(data) <= limit + 2 else f"{data[:limit + 2]}... ({(len(data) - 2) // 2} bytes)"


def short_counterexample(cx: Mapping[str, object]) -> str:
    """One line for a counterexample of scobelix.verify: the call (calldata,
    value, caller) and what each side did with it."""
    call = cx.get("call") or {}
    parts = [f"calldata {_cut(call.get('calldata'))}", f"value {call.get('value', 0)}",  # type: ignore[union-attr]
             f"caller {call.get('sender')}"]  # type: ignore[union-attr]
    if call.get("via"):  # type: ignore[union-attr]
        parts.append(f"through {call['via']}")  # type: ignore[index]

    def outcome(side: str) -> str:
        r = cx.get(side) or {}
        r = r.get("contract") or r  # type: ignore[union-attr]  # through a caller: what the contract itself did
        out = str(r.get("output") or "0x")  # type: ignore[union-attr]
        if r.get("success"):  # type: ignore[union-attr]
            return "returned " + _cut(out)
        error = str(r.get("error") or "")  # type: ignore[union-attr]
        if error.startswith("halt:"):  # no revert: out of gas, an invalid instruction...
            return f"halted ({error[5:45]})"
        return "reverted" + ("" if out == "0x" else " with " + _cut(out))

    text = ", ".join(parts) + f": the original {outcome('original')}, this text {outcome('candidate')}"
    kinds = [str(k) for k in cx.get("kinds") or ()]  # type: ignore[union-attr]
    if kinds:
        text += f" (differs in: {', '.join(kinds)})"
    if cx.get("sequence"):
        text += f"; last of a sequence of {len(cx['sequence'])} calls"  # type: ignore[arg-type]
    return text


def summary_lines(report, more: Iterable[str] = ()) -> List[str]:
    """The lines that sum a verification report up (the header of the text
    shows them, then one line per entry point): the status of every level
    that was asked for, the verdict counts, `more`, the entry points found
    to differ."""
    differing = [key for key, fr in report.functions.items() if fr.verdict in DIFFERING]
    lines = [
        "verification: " + "  ".join(f"{k}={v.status}" for k, v in report.levels.items()
                                     if v.reason != "not requested"),
        "verdicts: " + (", ".join(f"{k} {n}" for k, n in sorted(report.summary.items())) or "none"),
    ]
    lines.extend(more)
    if differing:
        lines.append(f"NOT EQUIVALENT: on {len(differing)} entry point(s) this text does not behave like the "
                     f"original ({_shown(differing)})")
    return lines


def record(result: SolgenResult, report, lines: Optional[List[str]] = None) -> None:
    """Write a verification report of the text of `result` into it: the
    verdict, the calls, the coverage, the counterexample and the confidence
    of every function, the summary in the header and the verdicts in the
    comments of the text (the code is not touched).  `lines`: the summary
    lines, default `summary_lines(report)`."""
    ci = result._assembly
    assert ci is not None
    keys = report_keys(ci.units)
    for unit in ci.units:
        fr = speaking(report, keys[unit.key])
        entry = result.functions[unit.key]
        entry.pop("counterexample", None)
        entry.pop("reason", None)
        unit.counterexample = unit.reason = ""
        if fr is not None:
            unit.verdict = fr.verdict
            entry["calls"], entry["coverage"] = fr.calls, fr.coverage
            if fr.reason:
                entry["reason"] = fr.reason
                unit.reason = fr.reason if fr.verdict == "INCONCLUSIVE" else ""
            if fr.counterexample is not None:
                entry["counterexample"] = fr.counterexample
                unit.counterexample = short_counterexample(fr.counterexample)
    ci.verification_summary = list(summary_lines(report) if lines is None else lines) + [
        f"  {key:<10} {fr.verdict:<23} {fr.calls:>5} calls  {fr.signature or ''}".rstrip()
        for key, fr in report.functions.items()
    ]
    with _deep_recursion():
        result.solidity, _ = assemble(ci)  # same code, verdicts in the comments
    for unit in ci.units:
        entry = result.functions[unit.key]
        entry["verdict"] = unit.verdict
        entry["confidence"] = result.confidence[unit.key] = derive_confidence(entry)


def _verify(result: SolgenResult, code: bytes, budget, allow_download, options: Optional[dict] = None) -> None:
    # a result verified again keeps the warnings of its last verification only
    result.warnings[:] = [w for w in result.warnings if not w.startswith("verification")]
    report, why = _check(result, code, budget, allow_download, options)
    if report is None:
        result.warnings.append(why)
        return
    result.verification = report
    result.warnings.extend(_level_warnings(report))
    record(result, report)

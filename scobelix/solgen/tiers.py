"""
The verification loop: every function in its most idiomatic form that was
seen to behave like the original.

    from scobelix.solgen.v2 import Generator
    result = Generator(decompilation, idiom_level="full").search(budget)

(`scobelix.solgen.generate_solidity(decompilation, verify=True)` is that.)

The rule of the result.  A function keeps a rewritten form (tier
"idiomatic" or "partial") only when a run of exactly that form against the
original bytecode found no difference: verdict EQUIVALENT, or
EQUIVALENT_REVERTS_ONLY when the original rejected every call tried.  Any
other function is written at the tier "exact", with the verdict of that
exact form (DIVERGENT with its counterexample when the exact form differs
too: the loss is in the decompilation, no pass can repair it), or SKIPPED
when it could not be run.  That holds when nothing could be run at all (no
compiler, no EVM backend, no bytecode): every function is then exact, and
a warning says so.  A verdict is never changed: it is what scobelix.verify
reported for the text that is returned.

What the loop does, in order.

  L0  The full tier is compiled.  When solc rejects it, the error
      locations are mapped to the entry points (`contract.entry_spans`) and
      to the declarations (to the entry point folded into one, else to the
      pass that made it: `PassContext.declared_by`).  For an entry point,
      the smallest set of its passes whose removal clears its errors is
      searched (ddmin, the compiler as the test); the pass of an offending
      declaration is switched off for the whole contract; and when nothing
      of that helps, every pass is switched off (the exact tier).  A text
      that still does not compile is returned with a warning that says so.
  L2  solc's storage layout of the text is compared with the layout the
      storage pass inferred: every declared variable must be found under
      its name at its slot and offset, with its size and encoding.  The
      variables that are not are left undeclared (`excluded_storage`: their
      accesses stay accesses by slot); after three tries the storage pass
      is switched off for the whole contract.
  L3  The text is run against the original (scobelix.verify: levels L0, L1
      and L3).  For every rewritten entry point that is not accepted, ddmin
      looks for a smallest set of its passes to switch off that makes it
      accepted; the candidates of all those entry points are tried
      together, one text per round, and only the entry points under test
      are run (`selectors`).  Entry points that end with no accepted run
      are set to the exact form.  Then the whole contract is run once more
      with the final text; if that run does not accept a rewritten entry
      point, the loop goes on from there.  Each step only ever switches
      more passes off, so it ends.
  L4  When the original is small (or on request), the compiled text is
      compared with the original bytecode, metadata and immutables left
      aside, under the usual optimizer settings when the original was built
      by the target compiler (scobelix.verify, `search_l4`).  Identical
      bytecode is a bonus: its absence is no failure.

Passes shared by functions.  The switches are per entry point, but two
passes work on the whole contract (pipeline.py states what a switch means
for them):

  * storage: its declarations do not depend on the switches, and an entry
    point with the pass off reaches the same slots by number.  Switching it
    off for one entry point is therefore local; excluding a variable (L2)
    changes every entry point that used it.
  * getters: switching it off for an entry point writes that function out
    again instead of the `public` variable or constant; the variable may
    then change its name, its visibility and its type, which changes the
    text of every entry point built on it.

So a run is evidence for an entry point only as long as its own text AND
the declarations stay the same: every run is recorded under a fingerprint
of both (of the text alone for an entry point in exact form, which uses no
declaration), a form that was already run is not run again, and a change
of the declarations makes every rewritten entry point be run again.  The
final run of the whole contract (with sequences of calls, which the runs
restricted to some entry points do not make) is what the result reports.
A difference seen by the sequences only is searched with runs of the whole
contract.

Budget (`SearchBudget`).  `time_limit` bounds the wall clock of the loop
and `max_rounds` the number of runs; each run also gets what is left of
the time as its own limit.  When one of them runs out, entry points still
being searched keep their last accepted form, or the exact form when they
have none; if the final text can then not be run as a whole, each entry
point carries the verdict of the last run of exactly its final form, and
the others are SKIPPED: `search["final_check"]` is False and the header
says so.  A run that its time limit cuts short (scobelix.verify stops
calling: the function under way keeps the calls made so far, the later
ones and the sequences get none) counts for the differences it saw and
nothing else: an entry point that did not get all its calls is not
accepted by it, and it is neither a run of the whole contract for the
search nor the final check.  Texts are compiled once (by their hash).
With the same input and budget the result is the same, as long as no time
limit cuts a run.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import re
import time
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from scobelix.solgen import pipeline, v2
from scobelix.solgen.contract import DIFFERING, entry_spans, router_spans

logger = logging.getLogger(__name__)

__all__ = ["OK_VERDICTS", "SearchBudget", "Verification", "search"]

# the verdicts with which a rewritten form is kept (scobelix.verify.report.Verdict.OK)
OK_VERDICTS = ("EQUIVALENT", "EQUIVALENT_REVERTS_ONLY")
TIERS = ("idiomatic", "partial", "exact")


@dataclasses.dataclass
class SearchBudget:
    """How much work the verification loop may do.

    time_limit   seconds of wall clock for the whole loop (None: no limit).
                 Every run gets what is left of it as its own time limit.
    max_rounds   runs of scobelix.verify at most, the first one and the
                 final check of the whole text included.
    l4           look for the original bytecode: True, False, or None to do
                 it only when the original is at most `l4_max_size` bytes.
    l4_max_size  see `l4`.
    verify       the `scobelix.verify.Budget` of every run (calls per
                 function, sequences, seed, `l4_search`...), or its fields
                 in a dict; None: `Budget()`.
    """

    time_limit: Optional[float] = 300.0
    max_rounds: int = 20
    l4: Optional[bool] = None
    l4_max_size: int = 4096
    verify: object = None

    def __post_init__(self):
        limit = self.time_limit
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, (int, float))
                                  or not 0 < limit < float("inf")):  # (infinity: None; NaN: no number)
            raise ValueError("time_limit must be a positive number of seconds, or None")
        if isinstance(self.max_rounds, bool) or not isinstance(self.max_rounds, int) or self.max_rounds < 1:
            raise ValueError("max_rounds must be an integer, at least 1")

    @classmethod
    def of(cls, budget) -> "SearchBudget":
        """A SearchBudget from what `generate_solidity(budget=...)` takes:
        None, a SearchBudget, a `scobelix.verify.Budget`, or a dict holding
        fields of either (those of the verify budget directly or under
        "verify")."""
        if budget is None:
            return cls()
        if isinstance(budget, cls):
            return dataclasses.replace(budget)
        if isinstance(budget, Mapping):
            own = {f.name for f in dataclasses.fields(cls)}
            mine = {k: v for k, v in budget.items() if k in own}
            rest = {k: v for k, v in budget.items() if k not in own}
            if rest and mine.get("verify") is not None:
                raise ValueError("budget: the fields of the verify budget go either directly or under 'verify'")
            if rest:
                mine["verify"] = rest
            return cls(**mine)
        return cls(verify=budget)


class Verification:
    """What the verification loop established about the text it returned.

    It reads like the scobelix.verify report of the last run of that text
    (`levels`, `functions`, `summary`, `warnings`, `to_text()`...: every
    attribute not defined here is the report's, which is `report`), with

      levels  L2 and L4 as the loop checked them, next to L0, L1 and L3;
      passed  every level that ran passed, L4 left aside (bytecode
              identical to the original is a bonus, not a requirement);
      search  what the loop did, as JSON data (see `search()`);
      lines   the summary lines written in the header of the text.
    """

    def __init__(self, report, search: dict, lines: List[str]):
        self.report = report
        self.search = search
        self.lines = lines

    def __getattr__(self, name: str):
        if name in ("report", "search", "lines") or name.startswith("__"):
            raise AttributeError(name)
        return getattr(self.report, name)

    @property
    def passed(self) -> bool:
        ran = [level.status for name, level in self.report.levels.items() if name != "L4"]
        return all(s in ("pass", "skipped") for s in ran) and any(s == "pass" for s in ran)

    def to_json(self) -> dict:
        out = self.report.to_json()
        out["passed"] = self.passed
        out["search"] = self.search
        return out


def search(generator, budget=None, disabled_passes: Optional[Mapping[str, Iterable[str]]] = None):
    """The verification loop on a `v2.Generator` (module docstring): a
    `SolgenResult` whose `verification` is a `Verification`.

    `verification.search` holds: "levels" (status of L0..L4), "verdicts"
    (count per verdict), "tiers" (count per tier), "rounds" and
    "max_rounds", "compilations" (texts compiled), "elapsed" and
    "time_limit" (seconds), "budget_exhausted" and "exhausted_by" ("time",
    "rounds" or None), "final_check" (the returned text was run as a
    whole, and no time limit cut that run short), "repaired" (entry
    points a run showed to differ at the full tier, that are accepted
    in the returned form), "divergent" (those that differ in
    the returned form), "unverified" (those with no run of their returned
    form), "backed_off" (entry point -> the passes of the full tier it is
    written without), "contract" (passes switched off for the whole
    contract), "excluded_storage", "l0" (what was backed off to make the
    text compile, with the compiler's message), "l2" and "l4" (those
    levels in full; "l4" names the settings that give the original
    bytecode)."""
    limits = SearchBudget.of(budget)
    try:
        import scobelix.verify  # noqa: F401 - the loop is built on it

        loop = _Loop(generator, limits, disabled_passes)
    except Exception as e:  # noqa: BLE001 - no verification must not lose the source
        logger.debug("verification unavailable", exc_info=True)
        return _unverified(generator, f"verification unavailable: {type(e).__name__}: {e}")
    try:
        return loop.run()
    except Exception as e:  # noqa: BLE001
        logger.debug("verification loop failed", exc_info=True)
        return _unverified(generator, f"verification unavailable: {type(e).__name__}: {e}")


ALL_OFF = {"*": frozenset(pipeline.PASS_ORDER)}


def _unverified(generator, why: str):
    """The exact tier, with the reason nothing was verified."""
    result = generator.regenerate(ALL_OFF)
    result.warnings.append(why)
    rewritten = sorted(key for key, entry in result.functions.items() if entry["disabled_passes"])
    if rewritten:
        result.warnings.append(_exact_warning(rewritten))
    return result


def _exact_warning(keys: Sequence[str]) -> str:
    return (f"verification: {len(keys)} function(s) could not be run against the original and are written in exact "
            f"form, not in the rewritten one: {v2._shown(keys)}")


def _verify_budget(spec):
    from scobelix.verify import Budget

    if spec is None:
        return Budget()
    if isinstance(spec, Mapping):
        return Budget(**spec)
    return spec


# ---------------------------------------------------------------- delta debugging


def _ddmin(items: Sequence[str]):
    """Delta debugging (ddmin) as a coroutine.  It yields candidate sets
    (tuples, in the order of `items`) and is sent True when switching that
    set off makes the function pass; it returns a set no element of which
    can be put back (1-minimal), or None when even the whole of `items`
    does not pass."""
    full = tuple(items)
    known: Dict[frozenset, bool] = {}

    def ask(candidate: Sequence[str]):
        key = frozenset(candidate)
        if key not in known:
            known[key] = bool((yield tuple(candidate)))
        return known[key]

    if not full or not (yield from ask(full)):
        return None
    current = list(full)
    n = 2
    while len(current) >= 2:
        size = len(current)
        chunks = [current[size * i // n: size * (i + 1) // n] for i in range(n)]
        reduced = False
        for chunk in chunks:  # one part alone
            if (yield from ask(chunk)):
                current, n, reduced = list(chunk), 2, True
                break
        if not reduced and n > 2:  # all but one part (with two parts: the other one, just tried)
            for chunk in chunks:
                rest = [p for p in current if p not in chunk]
                if (yield from ask(rest)):
                    current, n, reduced = rest, max(n - 1, 2), True
                    break
        if not reduced:
            if n >= len(current):
                break
            n = min(2 * n, len(current))
    return tuple(current)


def _minimise(keys: Sequence[str], universe: Mapping[str, Sequence[str]],
              run_round: Callable[[Dict[str, Tuple[str, ...]]], Optional[Dict[str, Optional[bool]]]]
              ) -> Dict[str, Optional[Tuple[str, ...]]]:
    """ddmin for several functions at once: every round tries one candidate
    per function still searching.  `run_round(candidates)` answers, per
    function, True (passes), False, or None / no entry (could not be told:
    asked again); None as a whole stops the search.  Returns, per function,
    the set to switch off: the smallest found, the last one that passed
    when the search was stopped, None when none passed."""
    searches, pending = {}, {}
    best: Dict[str, Tuple[str, ...]] = {}
    found: Dict[str, Optional[Tuple[str, ...]]] = {}
    for key in keys:
        gen = _ddmin(universe[key])
        try:
            pending[key] = next(gen)
            searches[key] = gen
        except StopIteration as stop:
            found[key] = stop.value
    while pending:
        outcomes = run_round(dict(pending))
        if outcomes is None:
            break
        progressed = False
        for key in sorted(pending):
            ok = outcomes.get(key)
            if ok is None:
                continue
            progressed = True
            if ok:
                best[key] = pending[key]
            try:
                pending[key] = searches[key].send(ok)
            except StopIteration as stop:
                found[key] = stop.value
                del pending[key]
        if not progressed:
            break
    for key in pending:  # stopped before the end
        found[key] = best.get(key)
    return found


# ---------------------------------------------------------------- compiler errors, layouts

_ARROW_RE = re.compile(r"-->\s+[^:\n]+:(\d+):\d+")


def _message(error: Mapping[str, object]) -> str:
    """The first line of a solc error."""
    text = str(error.get("formattedMessage") or error.get("message") or "").strip()
    return text.split("\n")[0] or "compilation error"


def _error_line(error: Mapping[str, object], raw: bytes) -> Optional[int]:
    """The line (from 1) of the text `raw` a solc error points at."""
    where = error.get("sourceLocation")
    start = where.get("start") if isinstance(where, Mapping) else None
    if isinstance(start, int) and 0 <= start <= len(raw):
        return raw.count(b"\n", 0, start) + 1
    m = _ARROW_RE.search(str(error.get("formattedMessage") or ""))
    return int(m.group(1)) if m else None


@dataclasses.dataclass
class _Located:
    """The errors of a text by what they are in."""

    functions: Dict[str, List[str]] = dataclasses.field(default_factory=dict)  # unit key -> messages
    passes: Dict[str, List[str]] = dataclasses.field(default_factory=dict)  # declaring pass -> messages
    rest: List[str] = dataclasses.field(default_factory=list)


def locate_errors(result, errors: Sequence[Mapping[str, object]]) -> _Located:
    """Map solc's errors on the text of `result` to its entry points and to
    the passes whose declarations they are in."""
    ci = result._assembly
    out = _Located()
    raw = result.solidity.encode()
    lines = result.solidity.split("\n")
    spans = router_spans(result.solidity, ci) + entry_spans(result.solidity, ci)  # (a route's lines first)
    declared: List[Tuple[Set[str], str]] = []  # (the lines of a declaration, the pass that made it)
    for kind, texts in ci.declarations.items():
        for text in texts:
            declared.append(({line.strip() for line in text.split("\n") if line.strip()},
                             result._declared_by.get((kind, text), "")))
    for error in errors:
        message = _message(error)
        number = _error_line(error, raw)
        key = next((k for first, last, k in spans if number is not None and first <= number <= last), None)
        if key is not None:
            out.functions.setdefault(key, []).append(message)
            continue
        source = lines[number - 1].strip() if number is not None and 0 < number <= len(lines) else ""
        folded = [u.key for u in ci.units
                  if u.folded and source and re.search(rf"(?<![\w$]){re.escape(u.folded)}(?![\w$])", source)]
        if folded:  # the declaration that stands for these entry points
            for k in folded:
                out.functions.setdefault(k, []).append(message)
            continue
        owner = next((name for texts, name in declared if source and source in texts and name), None)
        if owner is not None:
            out.passes.setdefault(owner, []).append(message)
        else:
            out.rest.append(message)
    return out


def layout_rows(declared: Sequence[Mapping[str, object]], layout: Optional[Mapping[str, object]]
                ) -> Optional[List[dict]]:
    """Each declared state variable (an entry of `SolgenResult.storage_layout`)
    against solc's storage layout of the text: {"name", "id", "slot",
    "offset", "found" ([slot, offset] or None), "status"} with status
    "match", "moved" (another position), "shape" (another size or
    encoding) or "missing".  None when solc gave no layout."""
    if layout is None:
        return None
    types = layout.get("types") or {}
    found: Dict[object, tuple] = {}
    for entry in layout.get("storage") or []:  # type: ignore[union-attr]
        t = types.get(entry.get("type")) or {}  # type: ignore[union-attr]
        found[entry.get("label")] = (int(entry.get("slot", 0)), int(entry.get("offset", 0)), t.get("encoding"),
                                     int(t.get("numberOfBytes", 0)))
    rows = []
    for v in declared:
        if v.get("namespace"):
            continue  # reached through an accessor at a slot of its own: not a state variable
        got = found.get(v["name"])
        if got is None:
            status = "missing"
        elif got[:2] != (v["slot"], v["offset"]):
            status = "moved"
        elif v.get("encoding") is not None and got[2:] != (v.get("encoding"), v.get("bytes")):
            status = "shape"
        else:
            status = "match"
        rows.append({"name": v["name"], "id": v.get("id"), "slot": v["slot"], "offset": v["offset"],
                     "found": list(got[:2]) if got else None, "status": status})
    return rows


# ---------------------------------------------------------------- the loop


@dataclasses.dataclass
class _Compiled:
    status: str  # "ok", "error" (solc rejected the text) or "unavailable" (no compiler)
    artifact: object = None
    errors: List[dict] = dataclasses.field(default_factory=list)
    reason: str = ""


@dataclasses.dataclass
class _Evidence:
    """What a run showed about one form of an entry point."""

    verdict: str
    entries: Dict[str, object]  # report key -> scobelix.verify FunctionReport
    whole: bool  # seen in a run of the whole contract (sequences of calls included)


def _sequence_only(e: Optional[_Evidence]) -> bool:
    """The difference was seen in sequences of calls only: the single calls
    a run restricted to the function makes cannot show it."""
    if e is None or not e.whole:
        return False
    failing = [fr for fr in e.entries.values() if fr.verdict not in OK_VERDICTS]  # type: ignore[attr-defined]
    return bool(failing) and all(fr.divergences == 0 and fr.sequence_divergences > 0  # type: ignore[attr-defined]
                                 for fr in failing)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _requested(budget, fr) -> int:
    """The calls a run of scobelix.verify makes of one entry of its report
    when no time limit stops it (the rule of `scobelix.verify.core.verify`:
    a probe gets `probe_calls`, a function `calls_per_function`, a quarter
    of it when L1 or a dispatcher scan already decided)."""
    from scobelix.verify.core import PROBES

    n = budget.probe_calls if fr.key in PROBES else budget.calls_per_function
    if fr.abi in ("EXTRA", "MISSING") or fr.origin == "scan":
        n = max(1, n // 4)
    return n


class _Loop:
    L0_ATTEMPTS = 6  # rounds of error attribution before the whole contract goes exact
    L2_ATTEMPTS = 3  # rounds of variable exclusion before the storage pass goes off

    def __init__(self, generator, limits: SearchBudget, disabled: Optional[Mapping[str, Iterable[str]]]):
        self.g = generator
        self.limits = limits
        self.budget = _verify_budget(limits.verify)
        self.t0 = time.monotonic()
        self.rounds = 0
        self.texts: Dict[str, _Compiled] = {}  # text hash -> its compilation
        self.whole: Dict[str, object] = {}  # text hash -> the report of its run as a whole
        self.disabled: Dict[str, Set[str]] = {k: set(v) for k, v in (disabled or {}).items() if v}
        self.excluded: Set[str] = set()
        self.evidence: Dict[Tuple[str, str], _Evidence] = {}  # (unit key, fingerprint) -> what a run showed
        self.exhausted = ""  # "time" or "rounds": what stopped the loop early (or cut a run short)
        self.cut_limit: Optional[float] = None  # the time limit per run that cut a run short, if it was that one
        self.problem = ""  # why a run could not be made
        self.first: Dict[str, str] = {}  # unit key -> its verdict in the first run
        self.reference: Dict[str, List[str]] = {}  # unit key -> its passes at the full tier
        self.l0_log: List[dict] = []
        self.l2_log: List[dict] = []
        self.unrun: List[str] = []  # set exact because no run could be made of them
        self.last = None  # the report of the last run
        self.result = None

    # ------------------------------------------------------------ budget

    def _remaining(self) -> Optional[float]:
        if self.limits.time_limit is None:
            return None
        return self.limits.time_limit - (time.monotonic() - self.t0)

    def _out_of(self, reserve: int = 0) -> str:
        """What a further run would exceed ("" when it fits), `reserve`
        runs being kept for later."""
        if self.rounds + reserve >= self.limits.max_rounds:
            return "rounds"
        left = self._remaining()
        if left is not None and left <= 0:
            return "time"
        return ""

    def _run_limit(self) -> Optional[float]:
        """The time limit of the next run: its own, within what is left."""
        own = self.budget.l3_time_limit
        left = self._remaining()
        if left is None:
            return own
        left = max(left, 1e-3)
        return left if own is None else min(own, left)

    # ------------------------------------------------------------ texts

    def _generate(self, disabled: Optional[Mapping[str, Iterable[str]]] = None):
        return self.g.regenerate(self.disabled if disabled is None else disabled, excluded_storage=self.excluded)

    def _with(self, trial: Mapping[str, Sequence[str]]) -> Dict[str, Set[str]]:
        out = {k: set(v) for k, v in self.disabled.items()}
        for key, passes in trial.items():
            out.setdefault(key, set()).update(passes)
        return out

    def _exact(self, key: str) -> None:
        self.disabled[key] = set(pipeline.PASS_ORDER)

    def _compile(self, result) -> _Compiled:
        """The compilation of a text, made once per text; with the settings
        scobelix.verify compiles with, so that its runs find it done."""
        digest = _digest(result.solidity)
        if digest in self.texts:
            return self.texts[digest]
        from scobelix.verify import solc

        version = result.target_solc
        try:
            path = solc.find_solc(solc.normalize_version(version), self.g.allow_download)
        except (solc.SolcNotFound, ValueError) as e:
            out = _Compiled("unavailable", reason=str(e))
        else:
            sources = {f"{result.contract_name}.sol": result.solidity}
            settings = solc.Settings(evm_version=solc.execution_evm_version(version))
            try:
                try:
                    comp = solc.compile_standard_json(sources, settings, version=version, solc_path=path)
                except solc.CompilationError as e:
                    if not (e.stack_too_deep and solc.version_key(version) >= (0, 8, 13)):
                        raise
                    comp = solc.compile_standard_json(sources, dataclasses.replace(settings, via_ir=True),
                                                      version=version, solc_path=path)
                out = _Compiled("ok", artifact=comp.artifact(result.contract_name))
            except solc.CompilationError as e:
                out = _Compiled("error", errors=list(e.errors), reason=f"{len(e.errors)} compilation error(s)")
            except (KeyError, solc.SolcNotFound) as e:
                out = _Compiled("unavailable", reason=str(e))
        self.texts[digest] = out
        return out

    def _fingerprints(self, result) -> Dict[str, str]:
        """Per unit, what a run of it depends on: its own code, and the
        declarations when it is rewritten (the exact form uses none)."""
        ci = result._assembly
        lines = result.solidity.split("\n")
        declarations = _digest(json.dumps(ci.declarations, sort_keys=True))
        code: Dict[str, str] = {}
        routes = router_spans(result.solidity, ci)  # the lines of fallback() that route one function are its own
        routing = {n for first, last, _ in routes for n in range(first, last + 1)}
        for first, last, key in entry_spans(result.solidity, ci):
            code[key] = "\n".join(line for n, line in enumerate(lines[first - 1:last], first)
                                  if not line.lstrip().startswith("///") and n not in routing)
        for first, last, key in routes:
            code[key] = code.get(key, "") + "\n" + "\n".join(lines[first - 1:last])
        out = {}
        for unit in ci.units:
            if unit.folded:
                basis = f"folded into {unit.folded}\n{declarations}"
            elif unit.passes:
                basis = code.get(unit.key, "") + "\n" + declarations
            else:
                basis = code.get(unit.key, "")
            out[unit.key] = _digest(f"{unit.key}\n{basis}")
        return out

    def _state(self, result) -> Dict[str, Optional[_Evidence]]:
        """Unit key -> what was seen of the form it has in `result`."""
        prints = self._fingerprints(result)
        return {u.key: self.evidence.get((u.key, prints[u.key])) for u in result._assembly.units}

    # ------------------------------------------------------------ runs

    def _execute(self, result, keys: Optional[Sequence[str]] = None):
        """One run of scobelix.verify on `result`: of the whole contract,
        or of the entry points `keys` only.  Records what it showed of every
        unit it ran; None when it could not be made.

        A run its time limit cut short is evidence of what it saw, no more.
        scobelix.verify stops calling at the limit: the function under way
        keeps the calls made so far (EQUIVALENT after one call that did not
        differ), the later ones get none, and the sequences of calls, made
        last, are the first to go.  So when the time limit was reached (or
        an entry point has fewer calls than the run asks for, which only the
        limit does), a unit is recorded only when it differed or got all its
        calls, never as seen in a run of the whole contract, and the report
        is not the check of the whole text (`self.whole`)."""
        ci = result._assembly
        names = v2.report_keys(ci.units)
        options: Dict[str, object] = {}
        if keys is not None:
            options["selectors"] = sorted({name for key in keys for name in names[key]})
        limit = self._run_limit()
        budget = dataclasses.replace(self.budget, l3_time_limit=limit)
        self.rounds += 1
        start = time.monotonic()
        report, why = v2._check(result, self.g.bytecode, budget, self.g.allow_download, options)
        if report is None:
            self.problem = why
            return None
        self.last = report
        cut = limit is not None and time.monotonic() - start >= limit
        ran: Dict[str, Tuple[object, Dict[str, object], bool]] = {}  # unit key -> (shown, entries, all calls made)
        for unit in ci.units:
            if keys is not None and unit.key not in keys:
                continue
            entries = {name: report.functions[name] for name in names[unit.key] if name in report.functions}
            shown = v2.speaking(report, names[unit.key])
            if shown is None or (shown.verdict in ("SKIPPED", "ROUTED") and not shown.calls):
                continue  # not run
            made = {name: fr.calls >= _requested(self.budget, fr) for name, fr in entries.items()}  # type: ignore
            if any(fr.verdict in OK_VERDICTS and not made[name] for name, fr in entries.items()):  # type: ignore
                cut = True  # an agreement on fewer calls than asked: the time limit stopped the run
            ran[unit.key] = (shown, entries, all(made.values()))
        if cut:
            self.exhausted = self.exhausted or "time"
            own = self.budget.l3_time_limit
            if own is not None and limit is not None and own <= limit:
                self.cut_limit = own  # the limit of a run, not that of the loop
        elif keys is None:
            self.whole[_digest(result.solidity)] = report
        prints = self._fingerprints(result)
        for key, (shown, entries, full) in ran.items():
            if cut and shown.verdict in OK_VERDICTS and not full:  # type: ignore[attr-defined]
                continue  # cut short: nothing established
            old = self.evidence.get((key, prints[key]))
            if old is not None and old.verdict not in OK_VERDICTS and shown.verdict in OK_VERDICTS:  # type: ignore
                # a difference seen in exactly this form stays seen: a later run (of another text,
                # whose sequences ended earlier) that did not meet it does not undo it
                continue
            self.evidence[(key, prints[key])] = _Evidence(shown.verdict, entries,  # type: ignore[attr-defined]
                                                         keys is None and not cut)
        return report

    # ------------------------------------------------------------ L0

    def _l0_round(self, trial: Dict[str, Tuple[str, ...]]) -> Optional[Dict[str, Optional[bool]]]:
        left = self._remaining()
        if left is not None and left <= 0:
            return None
        result = self._candidate(trial)
        if result is None:
            return {key: False for key in trial}
        comp = self._compile(result)
        if comp.status == "unavailable":
            return None
        if comp.status == "ok":
            return {key: True for key in trial}
        where = locate_errors(result, comp.errors)
        return {key: key not in where.functions for key in trial}

    def _candidate(self, trial: Mapping[str, Sequence[str]]):
        """The text with the candidate sets of `trial` switched off too
        (None when it cannot be written: no candidate, then)."""
        try:
            return self._generate(self._with(trial))
        except Exception:  # noqa: BLE001
            logger.debug("generation of a candidate failed", exc_info=True)
            return None

    def _repair_l0(self) -> _Compiled:
        """The text of the current switches; when solc rejects it, with
        what it takes switched off to make it compile."""
        try:
            self.result = self._generate()
        except Exception as e:  # noqa: BLE001 - what a pass built cannot even be written out
            if set(self.disabled.get("*", ())) == set(pipeline.PASS_ORDER):
                raise
            logger.debug("generation failed", exc_info=True)
            self.l0_log.append({"function": "*", "passes": list(pipeline.PASS_ORDER),
                                "message": f"the text could not be written: {type(e).__name__}: {e}"})
            self.disabled = {"*": set(pipeline.PASS_ORDER)}
            self.excluded = set()
            self.result = self._generate()
        comp = self._compile(self.result)
        for _ in range(self.L0_ATTEMPTS):
            if comp.status != "error":
                return comp
            where = locate_errors(self.result, comp.errors)
            applied = {key: tuple(self.result.functions[key]["passes"]) for key in where.functions}
            targets = sorted(key for key in where.functions if applied[key])
            acted = False
            if targets:
                found = _minimise(targets, applied, self._l0_round)
                for key in targets:
                    off = found.get(key) or applied[key]
                    self.disabled.setdefault(key, set()).update(off)
                    self.l0_log.append({"function": key, "passes": list(off), "message": where.functions[key][0]})
                acted = True
            for name in sorted(where.passes):
                if name not in self.disabled.get("*", ()):
                    self.disabled.setdefault("*", set()).add(name)
                    self.l0_log.append({"function": "*", "passes": [name], "message": where.passes[name][0]})
                    acted = True
            if not acted:
                break
            self.result = self._generate()
            comp = self._compile(self.result)
        if comp.status == "error" and set(self.disabled.get("*", ())) != set(pipeline.PASS_ORDER):
            # last resort: the whole contract at the exact tier
            self.l0_log.append({"function": "*", "passes": list(pipeline.PASS_ORDER),
                                "message": _message(comp.errors[0]) if comp.errors else comp.reason})
            self.disabled = {"*": set(pipeline.PASS_ORDER)}
            self.excluded = set()
            self.result = self._generate()
            comp = self._compile(self.result)
        return comp

    # ------------------------------------------------------------ L2

    def _settle(self) -> _Compiled:
        """A text for the current switches that compiles (L0) and whose
        state variables are where they were inferred (L2); `self.result`."""
        comp = self._repair_l0()
        attempts = 0
        while comp.status == "ok":
            rows = layout_rows(self.result.storage_layout, comp.artifact.storage_layout)  # type: ignore[attr-defined]
            bad = [row for row in rows or [] if row["status"] != "match"]
            if not bad:
                break
            names = [row["name"] for row in bad]
            if attempts < self.L2_ATTEMPTS:
                self.excluded.update(str(row["id"]) for row in bad if row["id"])
                self.l2_log.append({"variables": names, "action": "by slot", "rows": bad})
            elif "storage" not in self.disabled.get("*", ()):
                self.disabled.setdefault("*", set()).add("storage")
                self.l2_log.append({"variables": names, "action": "storage pass off", "rows": bad})
            else:
                break  # nothing of the storage pass is left: reported as it is
            attempts += 1
            comp = self._repair_l0()
        return comp

    def _l2_level(self, comp: _Compiled):
        from scobelix.verify.report import LevelResult

        if comp.status != "ok":
            return LevelResult("skipped", "no compiler" if comp.status == "unavailable" else "L0 failed")
        by_slot = sorted({name for entry in self.l2_log for name in entry["variables"]})
        details: Dict[str, object] = {"repairs": self.l2_log} if self.l2_log else {}
        rows = layout_rows(self.result.storage_layout, comp.artifact.storage_layout)  # type: ignore[attr-defined]
        declared = [v for v in self.result.storage_layout if not v.get("namespace")]
        if not declared:
            why = "no state variable declared"
            return LevelResult("skipped", why + (f" (reached by slot: {', '.join(by_slot)})" if by_slot else ""),
                               details)
        if rows is None:
            return LevelResult("skipped", f"solc {self.result.target_solc} does not report a storage layout", details)
        bad = [row for row in rows if row["status"] != "match"]
        details["variables"] = len(rows)
        if bad:
            return LevelResult("fail", f"{len(bad)} state variable(s) are not where they were inferred: "
                               + v2._shown(row["name"] for row in bad), dict(details, rows=bad))
        return LevelResult("pass", "", details)

    # ------------------------------------------------------------ L3

    def _l3_round(self, trial: Dict[str, Tuple[str, ...]], whole: bool) -> Optional[Dict[str, Optional[bool]]]:
        result = self._candidate(trial)
        if result is None:
            return {key: False for key in trial}
        comp = self._compile(result)
        if comp.status == "unavailable":
            return None
        if comp.status == "error":  # a candidate that does not compile is no candidate
            where = locate_errors(result, comp.errors)
            hit = [key for key in trial if key in where.functions] or list(trial)
            return {key: False for key in hit}
        prints = self._fingerprints(result)

        def seen(key: str) -> Optional[_Evidence]:
            e = self.evidence.get((key, prints[key]))
            return e if e is not None and (e.whole or not whole) else None

        need = sorted(key for key in trial if seen(key) is None)
        if need:
            why = self._out_of(reserve=1)  # one run is kept for the final check
            if why:
                self.exhausted = self.exhausted or why
                return None
            if self._execute(result, None if whole else need) is None:
                return None
        out: Dict[str, Optional[bool]] = {}
        for key in trial:
            e = seen(key)
            out[key] = None if e is None else e.verdict in OK_VERDICTS
        return out

    def _search(self, keys: Sequence[str], state: Mapping[str, Optional[_Evidence]]) -> None:
        """Switch off, for each of `keys` (rewritten, not accepted), a
        smallest set of its passes with which it is accepted; all of them
        when there is none, or when the budget stops the search before one
        was found."""
        whole = any(_sequence_only(state[key]) for key in keys)
        applied = {key: tuple(self.result.functions[key]["passes"]) for key in keys}
        found = _minimise(keys, applied, lambda trial: self._l3_round(trial, whole))
        for key in keys:
            off = found.get(key)
            if off is None:
                self._exact(key)
            else:
                self.disabled.setdefault(key, set()).update(off)

    # ------------------------------------------------------------ the whole

    def _drop(self, keys: Sequence[str], rewritten: Sequence[str]) -> None:
        """Put the units `keys` back to the exact form (the whole contract
        to the exact tier when they are all the `rewritten` ones)."""
        if set(keys) >= set(rewritten):
            self.disabled = {"*": set(pipeline.PASS_ORDER)}
        else:
            for key in keys:
                self._exact(key)

    def run(self):
        comp = self._settle()
        try:
            self.reference = {key: list(passes) for key, passes in self.g.full_passes().items()}
        except Exception:  # noqa: BLE001 - the full tier cannot be written (the loop then left it: see l0)
            self.reference = {}
        whole = None  # the report of a run of the whole current text
        if comp.status == "ok" and self.g.bytecode:
            whole = self._execute(self.result)
            if whole is not None:
                keys = v2.report_keys(self.result._assembly.units)
                for unit in self.result._assembly.units:
                    shown = v2.speaking(whole, keys[unit.key])
                    if shown is not None and not (shown.verdict in ("SKIPPED", "ROUTED") and not shown.calls):
                        self.first[unit.key] = shown.verdict  # (a unit not run did not differ: it was not seen)
            while whole is not None:
                state = self._state(self.result)
                rewritten = sorted(u.key for u in self.result._assembly.units if u.passes)
                failing = [k for k in rewritten if state[k] is not None and state[k].verdict not in OK_VERDICTS]
                unseen = [k for k in rewritten if state[k] is None]
                if not failing and not unseen:
                    break  # settled: `whole` is the check of the final text
                if failing:
                    self._search(failing, state)
                if unseen:  # never run: not kept rewritten
                    self.unrun.extend(unseen)
                    self._drop(unseen, rewritten)
                comp = self._settle()
                whole = self.whole.get(_digest(self.result.solidity)) if comp.status == "ok" else None
                if comp.status != "ok" or whole is not None:
                    continue
                why = self._out_of()
                if why:
                    self.exhausted = self.exhausted or why
                    break
                whole = self._execute(self.result)
        if whole is not None and self.whole.get(_digest(self.result.solidity)) is not whole:
            whole = None  # the last run of the whole text was cut short by its time limit: no check of it
        return self._finish(comp, whole)

    def _demote(self, comp: _Compiled) -> _Compiled:
        """Without a run of the whole final text: every rewritten unit with
        no accepted run of exactly its form goes back to the exact form
        (again and again: a declaration that changes takes away what was
        seen of the units built on it)."""
        while True:
            state = self._state(self.result)
            rewritten = sorted(u.key for u in self.result._assembly.units if u.passes)
            drop = [k for k in rewritten if state[k] is None or state[k].verdict not in OK_VERDICTS]
            if not drop:
                return comp
            self.unrun.extend(k for k in drop if state[k] is None)
            self._drop(drop, rewritten)
            comp = self._settle()

    def _carried(self, comp: _Compiled):
        """The report of a final text that was not run as a whole: its
        static levels, and for each unit what an earlier run showed of
        exactly this form."""
        from scobelix.verify.report import LevelResult

        if comp.status != "ok" or not self.g.bytecode:
            report, why = v2._check(self.result, self.g.bytecode, self.budget, self.g.allow_download)
            self.problem = self.problem or why
            return report
        report, why = v2._check(self.result, self.g.bytecode, self.budget, self.g.allow_download,
                                {"levels": ("L0", "L1"), "backend": "none"})
        if report is None:
            self.problem = self.problem or why
            return None
        names = v2.report_keys(self.result._assembly.units)
        state = self._state(self.result)
        carried, missing = [], []
        for unit in self.result._assembly.units:
            e = state[unit.key]
            if e is not None:
                report.functions.update(e.entries)
                carried.append(unit.key)
                continue
            missing.append(unit.key)
            for name in names[unit.key]:
                fr = report.functions.get(name)
                if fr is not None and fr.verdict in ("SKIPPED", "ROUTED"):
                    report.functions[name] = dataclasses.replace(
                        fr, verdict="SKIPPED", reason="this form was not run in full: " + (self._why_not() or "no run"))
        if self.last is not None and self.last.levels["L3"].status in ("skipped", "error") and not carried:
            report.levels["L3"] = self.last.levels["L3"]  # no run was possible at all: the reason of the last try
        else:
            report.levels["L3"] = LevelResult(
                "inconclusive",
                f"{self._why_not() or 'no run of the final text'}: {len(carried)} entry point(s) carry the verdict "
                f"of an earlier run of the same code, {len(missing)} were not run in full in their final form",
                {"carried": carried, "not_run": missing})
        return report

    def _why_not(self) -> str:
        if self.exhausted == "time" and self.cut_limit is not None:
            return f"budget exhausted (time limit of {self.cut_limit:g} s per run)"
        if self.exhausted == "time":
            return f"budget exhausted (time limit of {self.limits.time_limit or 0:g} s)"
        if self.exhausted == "rounds":
            return f"budget exhausted ({self.limits.max_rounds} run(s))"
        return ""

    def _l4_level(self, comp: _Compiled):
        from scobelix.verify.report import LevelResult

        if comp.status != "ok":
            return LevelResult("skipped", "no compiler" if comp.status == "unavailable" else "L0 failed")
        code = self.g.bytecode
        if not code:
            return LevelResult("skipped", "no original bytecode")
        if self.limits.l4 is False:
            return LevelResult("skipped", "switched off")
        if self.limits.l4 is None and len(code) > self.limits.l4_max_size:
            return LevelResult("skipped", f"original of {len(code)} bytes: tried up to {self.limits.l4_max_size} "
                               f"bytes unless asked for")
        left = self._remaining()
        if left is not None and left <= 0:
            return LevelResult("skipped", self._why_not() or "budget exhausted")
        limits = [x for x in (self.budget.l4_time_limit, left) if x is not None]
        budget = dataclasses.replace(self.budget, l4_time_limit=min(limits) if limits else None)
        report, why = v2._check(self.result, code, budget, self.g.allow_download,
                                {"levels": ("L4",), "backend": "none"})
        if report is None:
            return LevelResult("skipped", why)
        return report.levels["L4"]

    def _finish(self, comp: _Compiled, whole):
        # the returned text was run as a whole (a run that executed nothing is no check)
        final_check = whole is not None and whole.levels["L3"].status not in ("skipped", "error")
        if whole is None:
            comp = self._demote(comp)
            report = self._carried(comp)
        else:
            report = whole
        result = self.result
        # a result verified again keeps the warnings of its last verification only
        result.warnings[:] = [w for w in result.warnings if not w.startswith("verification")]
        rewritten = [key for key, passes in self.reference.items() if passes]
        if report is None:
            result.warnings.append(self.problem or "verification unavailable")
            if comp.status == "error":  # (no run, e.g. no bytecode: the compiler still said it)
                result.warnings.append("verification L0 fail: the text does not compile ("
                                       + (_message(comp.errors[0]) if comp.errors else comp.reason) + ")")
            lost = sorted(k for k in rewritten if not result.functions[k]["passes"])
            if lost:
                result.warnings.append(_exact_warning(lost))
            return result
        report.levels["L2"] = self._l2_level(comp)
        report.levels["L4"] = self._l4_level(comp)
        result.warnings.extend(v2._level_warnings(report))
        v2.record(result, report)  # the verdicts of the units
        summary = self._summary(result, report, final_check)
        result.warnings.extend(self._warnings(result, report, summary))
        lines = v2.summary_lines(report, self._lines(summary, report))
        result.verification = Verification(report, summary, lines)
        v2.record(result, report, lines)
        return result

    # ------------------------------------------------------------ what was done

    def _summary(self, result, report, final_check: bool) -> dict:
        functions = result.functions
        tiers = {tier: sum(1 for f in functions.values() if f["tier"] == tier) for tier in TIERS}
        l4 = report.levels["L4"]
        matching = list(l4.details.get("matching") or [])
        return {
            "levels": {name: level.status for name, level in report.levels.items()},
            "verdicts": dict(report.summary),
            "tiers": tiers,
            "rounds": self.rounds,
            "max_rounds": self.limits.max_rounds,
            "compilations": sum(1 for comp in self.texts.values() if comp.status != "unavailable"),
            "elapsed": round(time.monotonic() - self.t0, 3),
            "time_limit": self.limits.time_limit,
            "budget_exhausted": bool(self.exhausted),
            "exhausted_by": self.exhausted or None,
            "final_check": final_check,
            "repaired": sorted(k for k, f in functions.items()
                               if self.first.get(k) not in (None,) + OK_VERDICTS and f["verdict"] in OK_VERDICTS),
            "divergent": sorted(k for k, f in functions.items() if f["verdict"] in DIFFERING),
            "unverified": sorted(k for k, f in functions.items() if f["verdict"] not in OK_VERDICTS + DIFFERING),
            "backed_off": {k: list(f["disabled_passes"]) for k, f in functions.items() if f["disabled_passes"]},
            "contract": [p for p in pipeline.PASS_ORDER if p in self.disabled.get("*", ())],
            "excluded_storage": sorted(self.excluded),
            "l0": self.l0_log,
            "l2": _level_json(report.levels["L2"]),
            "l4": dict(_level_json(l4), settings=matching),
        }

    def _lines(self, summary: dict, report) -> List[str]:
        """The summary lines of the loop (nothing that changes from one run
        to the next: no time)."""
        tiers = summary["tiers"]
        lines = ["tiers: " + ", ".join(f"{tiers[tier]} {tier}" for tier in TIERS)]
        runs = f"loop: {summary['rounds']} run(s) against the original, {summary['compilations']} text(s) compiled"
        lines.append(runs if summary["final_check"] else runs + "; the final text was not run as a whole")
        if self.l0_log:
            first = self.l0_log[0]
            lines.append(f"L0: the text first written did not compile ({first['message']}); switched off: "
                         + v2._shown(f"{e['function']} ({', '.join(e['passes'])})" for e in self.l0_log))
        l2 = report.levels["L2"]
        if self.l2_log or l2.status == "fail":
            lines.append("L2: " + (l2.reason or "state variables not where they were inferred are reached by slot: "
                                   + v2._shown(sorted({n for e in self.l2_log for n in e["variables"]}))))
        if summary["backed_off"]:
            lines.append("backed off: " + v2._shown(
                (f"{key} ({', '.join(passes)})" for key, passes in summary["backed_off"].items()), 6))
        l4 = report.levels["L4"]
        if l4.status == "pass":
            lines.append("L4: the original bytecode, apart from metadata and immutables, with the settings "
                         + ", ".join(summary["l4"]["settings"]))
        elif l4.reason:
            lines.append(f"L4: {l4.reason}")
        if self.exhausted:
            lines.append(self._why_not() + ": functions not accepted by a run are written in exact form")
        return lines

    def _warnings(self, result, report, summary: dict) -> List[str]:
        out = []
        for entry in self.l0_log:
            what = "every pass, for the whole contract" if entry["function"] == "*" and len(entry["passes"]) > 1 \
                else f"{', '.join(entry['passes'])} for {entry['function']}"
            out.append(f"verification L0: the text did not compile ({entry['message']}); switched off: {what}")
        l2 = report.levels["L2"]
        if l2.status == "fail":
            out.append(f"verification L2 fail: {l2.reason}")
        for entry in self.l2_log:
            out.append(f"verification L2: {len(entry['variables'])} state variable(s) were not where they were "
                       f"inferred ({v2._shown(entry['variables'])}): " + (
                           "reached by slot instead" if entry["action"] == "by slot"
                           else "the storage pass is switched off"))
        differed = sorted(k for k, verdict in self.first.items()
                          if verdict not in OK_VERDICTS and k in summary["backed_off"])
        if differed:
            out.append(f"verification L3: {len(differed)} function(s) did not behave like the original as first "
                       f"written and were backed off: " + v2._shown(
                           f"{k} ({', '.join(summary['backed_off'][k])}: now {result.functions[k]['verdict']})"
                           for k in differed))
        unrun = sorted(set(self.unrun) & set(summary["backed_off"]))
        if unrun:
            out.append(_exact_warning(unrun))
        if self.exhausted:
            out.append("verification: " + self._why_not() + (
                "" if summary["final_check"] else "; the final text was not run as a whole"))
        return out


def _level_json(level) -> dict:
    """A level result as JSON data."""
    return v2._jsonable(level.to_dict())

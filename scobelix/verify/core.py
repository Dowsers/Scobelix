"""
`verify()`: compiles a candidate Solidity source and checks it against the
original runtime bytecode, level by level.

    L0  the source compiles (solc chosen from the pragmas, preferring the
        version recorded in the original's metadata)
    L1  same external ABI: selector set (with routed selectors), payability,
        declared events / custom errors present in the original
    L2  same storage layout as the given reference (`layout`)
    L3  behavioural equivalence by differential execution, per function
    L4  bytecode identical modulo metadata / immutables / link placeholders,
        trying the usual optimizer settings when the compiler version matches

Every level degrades into "skipped" with a reason instead of raising: no
solc for the pragma, no EVM backend installed (L3: `pip install
'scobelix[verify]'`), no reference layout, ...  An unexpected failure inside
one level marks that level "error" and leaves the others intact.
"""

from __future__ import annotations

import dataclasses
import time
import traceback
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from scobelix.utils.metadata import Metadata, parse_metadata

from .abi import (
    EXTRA,
    MATCH,
    MISSING,
    ROUTED,
    FuncSpec,
    L1Result,
    compare_abi,
    dispatcher_selectors,
    parse_selector,
)
from .abi import specs_from_abi, specs_from_hint
from .bytecode import compare_runtime, patch_immutables, read_immutables, search_l4, to_bytes
from .equiv import Differ, FunctionStats, env_sensitivity
from .evm import BackendUnavailable, available_backends
from .layout import compare_layout, normalize_layout
from .oracle import probe_payable, probe_widths
from .report import (
    LEVELS,
    FunctionReport,
    LevelResult,
    VerificationReport,
    counterexample_to_dict,
    derive_verdict,
)
from .solc import (
    Artifact,
    Compilation,
    CompilationError,
    Settings,
    SolcNotFound,
    compile_standard_json,
    execution_evm_version,
    find_solc,
    normalize_version,
    optimizer_variants,
    solc_for_source,
    version_key,
)

__all__ = ["Budget", "verify"]

INSTALL_HINT = "no EVM backend installed: pip install 'scobelix[verify]'"
PROBES = ("fallback", "receive")


@dataclasses.dataclass
class Budget:
    """How much work `verify` does.  `Budget.quick()` suits tests and repeated checks."""

    calls_per_function: int = 300
    # per probe: unknown selector ("fallback") and empty calldata ("receive")
    probe_calls: int = 100
    sequences: int = 30
    sequence_length: int = 12
    coverage_calls: int = 64  # calls per function run instrumented (py-evm): coverage and cmp-log
    # stop fuzzing a function after this many confirmed divergences (differences only because the
    # original runs out of a block's gas do not count: they never end the search)
    max_divergences: int = 25
    l3_time_limit: Optional[float] = None  # seconds; functions not reached get calls = 0
    l4_search: bool = True  # also try the usual optimizer settings (same compiler version only)
    l4_time_limit: Optional[float] = 60.0
    oracle_widths: bool = False  # measure the checked parameter widths of every function (py-evm)
    via_ratio: float = 0.4
    mutate_ratio: float = 0.15
    seed: int = 1

    @classmethod
    def quick(cls) -> "Budget":
        return cls(
            calls_per_function=60,
            probe_calls=20,
            sequences=6,
            sequence_length=8,
            coverage_calls=16,
            max_divergences=3,
            l4_search=False,
        )


def _levels(levels: Iterable[str]) -> Tuple[str, ...]:
    out = tuple(str(x).upper() for x in levels)
    unknown = [x for x in out if x not in LEVELS]
    if unknown:
        raise ValueError(f"unknown levels {unknown} (expected some of {LEVELS})")
    return out


def _backends(backend: str) -> Tuple[Optional[str], Optional[str], str]:
    """(bulk backend, confirmation backend, reason when none) for the `backend` argument."""
    have = available_backends()
    if backend == "none":
        return None, None, "L3 disabled (backend='none')"
    if backend == "auto":
        if not have:
            return None, None, INSTALL_HINT
        primary = have[0]
        return primary, ("pyevm" if primary == "pyrevm" and "pyevm" in have else None), ""
    if backend not in ("pyrevm", "pyevm"):
        raise ValueError(f"unknown backend {backend!r} (auto, pyrevm, pyevm or none)")
    if backend not in have:
        return None, None, f"backend {backend} is not installed: pip install 'scobelix[verify]'"
    return backend, None, ""


def _compile(
    sources: Dict[str, str],
    contract_name: str,
    version: str,
    path: str,
    settings: Settings,
    warnings: List[str],
) -> Tuple[Compilation, Artifact]:
    """Compiles, retrying with viaIR (solc >= 0.8.13) when the legacy pipeline runs out of stack."""
    try:
        comp = compile_standard_json(sources, settings, version=version, solc_path=path)
    except CompilationError as e:
        if not (e.stack_too_deep and not settings.via_ir and version_key(version) >= (0, 8, 13)):
            raise
        settings = dataclasses.replace(settings, via_ir=True)
        warnings.append("stack too deep with the legacy pipeline: compiled with viaIR")
        comp = compile_standard_json(sources, settings, version=version, solc_path=path)
    return comp, comp.artifact(contract_name)


def _immutable_values(
    art: Artifact, original: bytes, immutables: Optional[Mapping[str, Any]], warnings: List[str]
) -> bytes:
    """The candidate runtime with its immutables filled (given by name, or read in the original)."""
    if not art.immutable_refs:
        return art.runtime
    by_name = {name: ast_id for ast_id, name in art.immutable_names.items()}
    values: Dict[str, Any] = {}
    for name, value in (immutables or {}).items():
        if isinstance(value, str):  # "0x..." addresses / numbers
            value = int(value, 16) if value.lower().startswith("0x") else int(value)
        if name in by_name:
            values[by_name[name]] = value
        else:
            warnings.append(f"immutable {name!r} is not declared by the candidate")
    missing = [ast_id for ast_id in art.immutable_refs if ast_id not in values]
    if (
        missing
        and compare_runtime(original, art.runtime, art.immutable_refs, art.link_refs).identical
    ):
        values.update(
            {k: v for k, v in read_immutables(original, art.immutable_refs).items() if k in missing}
        )
        missing = []
    if missing:
        names = ", ".join(art.immutable_names.get(m, m) for m in missing)
        warnings.append(f"no value for the candidate's immutables ({names}): they stay 0 during L3")
    return patch_immutables(art.runtime, art.immutable_refs, values)


def _error(e: BaseException) -> LevelResult:
    return LevelResult(
        "error",
        f"{type(e).__name__}: {e}",
        {"traceback": traceback.format_exc(limit=6).splitlines()[-6:]},
    )


def verify(
    original_runtime: Union[bytes, str],
    source: Union[str, Mapping[str, str]],
    *,
    contract_name: str,
    layout: Any = None,
    abi_hint: Any = None,
    solc_version: Optional[str] = None,
    levels: Sequence[str] = LEVELS,
    budget: Optional[Union[Budget, Mapping[str, Any]]] = None,
    backend: str = "auto",
    routed_selectors: Iterable[Union[int, str, bytes]] = (),
    selectors: Optional[Iterable[Union[int, str, bytes]]] = None,
    settings: Optional[Settings] = None,
    immutables: Optional[Mapping[str, Any]] = None,
    allow_download: Optional[bool] = None,
) -> VerificationReport:
    """
    Checks `source` (one Solidity text, or {file name: text}) against
    `original_runtime` (deployed bytecode, bytes or hex).

    contract_name     the candidate contract ("Name" or "file.sol:Name")
    layout            the ORIGINAL's storage layout (any form
                      `layout.normalize_layout` accepts): the L2 reference
                      and the type information L3 seeds storage with
    abi_hint          the original's functions (see `abi.specs_from_hint`),
                      authoritative even when it names none; without it
                      (None) they come from a dispatcher scan
    solc_version      compile with this version (default: from the pragmas,
                      preferring the original's metadata version)
    levels            any subset of L0..L4 (L0 always runs: it compiles)
    budget            a Budget (or its fields as a dict)
    backend           auto | pyrevm | pyevm | none (auto: pyrevm in bulk,
                      py-evm to confirm divergences and measure coverage)
    routed_selectors  selectors the candidate dispatches from fallback()
    selectors         restrict L3 to these functions (keys of other
                      functions are reported SKIPPED); "fallback" and
                      "receive" select the probes
    settings          compiler settings (default: optimizer on, 200 runs,
                      an EVM version the backends can run)
    immutables        {name: value} for the candidate's immutables
    allow_download    fetch a missing solc release (default:
                      $SCOBELIX_ALLOW_SOLC_DOWNLOAD)
    """
    t_start = time.monotonic()
    wanted = _levels(levels)
    if isinstance(budget, Mapping):
        budget = Budget(**budget)
    budget = budget or Budget()
    original = to_bytes(original_runtime)
    if isinstance(source, str):
        file_name, _, name = contract_name.rpartition(":")
        sources = {file_name or f"{name}.sol": source}
    else:
        sources = dict(source)
    md = parse_metadata(original)
    warnings: List[str] = []
    results: Dict[str, LevelResult] = {k: LevelResult("skipped", "not requested") for k in LEVELS}
    functions: Dict[str, FunctionReport] = {}
    original_info = {
        "size": len(original),
        "metadata": (
            None
            if md is None
            else {
                "compiler": md.compiler,
                "version": md.version,
                "version_range": md.version_range,
                "hash": md.hash_kind,
            }
        ),
    }
    candidate_info: dict = {"contract": contract_name}
    primary, confirm, no_backend = _backends(backend)
    backend_info = {"bulk": primary, "confirm": confirm, "available": available_backends()}

    def finish() -> VerificationReport:
        return VerificationReport(
            results,
            functions,
            original_info,
            candidate_info,
            backend_info,
            warnings,
            sequences,
            time.monotonic() - t_start,
        )

    sequences: dict = {}

    # ---------------------------------------------------------------- L0
    try:
        solc_version = normalize_version(solc_version) if solc_version else None
    except ValueError as e:
        results["L0"] = LevelResult("skipped", str(e))
        for k in LEVELS[1:]:
            if k in wanted:
                results[k] = LevelResult("skipped", "no compiler")
        return finish()
    preferred = solc_version or (md.version if md is not None and md.compiler == "solc" else None)
    try:
        if solc_version:
            version, path = solc_version, find_solc(solc_version, allow_download)
        else:
            version, path = solc_for_source(sources, preferred, allow_download)
    except SolcNotFound as e:
        results["L0"] = LevelResult("skipped", str(e))
        for k in LEVELS[1:]:
            if k in wanted:
                results[k] = LevelResult("skipped", "no compiler")
        return finish()
    settings = settings or Settings(evm_version=execution_evm_version(version))
    candidate_info.update(solc=version, settings=settings.label)
    try:
        comp, art = _compile(sources, contract_name, version, path, settings, warnings)
    except CompilationError as e:
        results["L0"] = LevelResult(
            "fail", f"{len(e.errors)} compilation error(s)", {"errors": e.messages[:10]}
        )
        for k in LEVELS[1:]:
            if k in wanted:
                results[k] = LevelResult("skipped", "L0 failed")
        return finish()
    except (KeyError, SolcNotFound) as e:
        results["L0"] = LevelResult("error", str(e))
        return finish()
    candidate_info.update(name=art.name, size=len(art.runtime), settings=comp.settings.label)
    results["L0"] = LevelResult(
        "pass",
        "",
        {"solc": version, "settings": comp.settings.label, "warnings": comp.warnings[:10]},
    )

    # ---------------------------------------------------------------- original functions
    scan = dispatcher_selectors(original)
    original_specs = specs_from_hint(abi_hint)
    spec_source = "hint"
    # a hint naming no function says the original has none (a fallback that tests msg.sig itself
    # has no entry point of its own): the scan, which sees every PUSH4 compared, is only reported
    if abi_hint is None:
        original_specs = {s.to_bytes(4, "big"): FuncSpec(s.to_bytes(4, "big")) for s in scan}
        spec_source = "dispatcher scan"
    routed = {parse_selector(s) for s in routed_selectors}
    candidate_specs = specs_from_abi(art.abi)
    l1: Optional[L1Result] = None
    if "L1" in wanted:
        try:
            l1 = compare_abi(
                original_specs,
                art.abi,
                original,
                routed=routed,
                source=spec_source,
                scan=scan,
                hint=abi_hint,
            )
        except Exception as e:  # noqa: BLE001 - one level failing must not lose the others
            results["L1"] = _error(e)

    # ---------------------------------------------------------------- L2
    if "L2" in wanted:
        if layout is None:
            results["L2"] = LevelResult("skipped", "no reference layout given")
        elif art.storage_layout is None:
            results["L2"] = LevelResult(
                "skipped", f"solc {version} does not report a storageLayout"
            )
        else:
            try:
                cmp = compare_layout(layout, art.storage_layout)
                results["L2"] = LevelResult(
                    "pass" if cmp.match else "fail",
                    "" if cmp.match else "layout differs",
                    cmp.to_dict(),
                )
            except Exception as e:  # noqa: BLE001
                results["L2"] = _error(e)

    # ---------------------------------------------------------------- L4
    if "L4" in wanted:
        try:
            results["L4"] = _level4(original, md, sources, art, comp, version, path, budget)
        except Exception as e:  # noqa: BLE001
            results["L4"] = _error(e)

    # ---------------------------------------------------------------- L3 (+ oracle for L1)
    keys = _function_table(original_specs, candidate_specs, routed, scan, l1)
    restrict = None
    if selectors is not None:
        restrict = {s if s in PROBES else "0x" + parse_selector(s).hex() for s in selectors}
    stats: Dict[str, FunctionStats] = {}
    oracle_payable: Dict[str, Optional[bool]] = {}
    checked: Dict[str, Optional[List[int]]] = {}
    coverage: Dict[str, Dict[str, int]] = {}
    env_reasons: List[str] = []
    l3_skip = ""
    run_l3 = "L3" in wanted
    need_backend = run_l3 or ("L1" in wanted and l1 is not None)
    if need_backend and primary is None:
        l3_skip = no_backend
        if run_l3:
            results["L3"] = LevelResult("skipped", no_backend)
    elif need_backend:
        try:
            runtime = _immutable_values(art, original, immutables, warnings)
            layout_vars = normalize_layout(layout) if layout is not None else []
            if not layout_vars:
                warnings.append("no reference layout: storage is seeded from observed SLOADs only")
            typed = [
                spec for spec, _, _ in keys.values() if spec is not None and spec.inputs is not None
            ]
            deadline = time.monotonic() + budget.l3_time_limit if budget.l3_time_limit else None
            differ = Differ(
                original,
                runtime,
                specs=typed,
                layout=layout_vars,
                backend=primary,
                confirm_backend=confirm,
                seed=budget.seed,
                via_ratio=budget.via_ratio,
                mutate_ratio=budget.mutate_ratio,
                max_divergences=budget.max_divergences,
                deadline=deadline,
            )
            t_l3 = time.monotonic()
            if run_l3:
                for key, (spec, origin, abi_status) in keys.items():
                    if restrict is not None and key not in restrict:
                        continue
                    n = budget.probe_calls if key in PROBES else budget.calls_per_function
                    if abi_status in (EXTRA, MISSING) or origin == "scan":
                        n = max(1, n // 4)  # the verdict is already decided by L1 / weak evidence
                    stats[key] = differ.fuzz_function(
                        key,
                        spec,
                        n,
                        probe=key if key in PROBES else None,
                        sample_size=budget.coverage_calls,
                    )
                if budget.sequences and restrict is None:
                    divs, made = differ.fuzz_sequences(budget.sequences, budget.sequence_length)
                    sequences = {
                        "run": budget.sequences,
                        "length": budget.sequence_length,
                        "calls": made,
                        "divergent": len(divs),
                    }
                    for (
                        d
                    ) in divs:  # sequences only call functions of the table: they all have stats
                        st = stats[d.key]
                        st.sequence_divergences += 1
                        for k in d.kinds:
                            st.kinds[k] += 1
                        if st.first is None:
                            st.first = differ.explain(d)
                    for d in differ.gas_sequences:  # the original out of a block's gas only
                        st = stats[d.key]
                        st.gas_divergences += 1
                        st.first_gas = st.first_gas or d
                known = [parse_selector(k) for k in keys if k not in PROBES]
                coverage = _coverage(differ, stats, known, primary, confirm)
            # oracle: payability of every function the original accepted a call of
            for key, (spec, origin, abi_status) in keys.items():
                if key in PROBES or spec is None:
                    continue
                base = stats[key].success_base if key in stats else None
                if base is None and not run_l3:
                    base = differ.find_success(key, spec, tries=min(100, budget.calls_per_function))
                oracle_payable[key] = probe_payable(differ, base)
                if budget.oracle_widths and "pyevm" in (primary, confirm):
                    checked[key] = probe_widths(differ, base)
            if run_l3:
                if primary == "pyrevm" and confirm is None:
                    env_reasons = env_sensitivity(original)
                results["L3"] = _level3(
                    stats, sequences, env_reasons, primary, confirm, time.monotonic() - t_l3
                )
        except BackendUnavailable as e:
            l3_skip = str(e)
            if run_l3:
                results["L3"] = LevelResult("skipped", str(e))
        except Exception as e:  # noqa: BLE001
            l3_skip = f"L3 failed: {type(e).__name__}"
            if run_l3:
                results["L3"] = _error(e)

    # ---------------------------------------------------------------- L1 verdict (with the oracle)
    if l1 is not None:
        l1.apply_oracle(oracle_payable)
        reason = "; ".join(
            f"{label}: {', '.join(items[:6])}" for label, items in l1.failures().items()
        )
        results["L1"] = LevelResult(l1.status, reason, l1.to_dict())

    # ---------------------------------------------------------------- per-function reports
    for key, (spec, origin, abi_status) in keys.items():
        st = stats.get(key)
        skipped_reason = l3_skip or (
            "not selected" if restrict is not None and key not in restrict else ""
        )
        if not run_l3 and not skipped_reason:
            skipped_reason = "L3 not requested"
        verdict, reason = derive_verdict(
            abi_status if l1 is not None else None,
            st,
            env_reasons=env_reasons,
            skipped_reason=skipped_reason,
        )
        payable = {}
        if l1 is not None and key in l1.functions:
            payable = dict(l1.functions[key]["payable"])
        elif key in oracle_payable:
            payable = {"oracle": oracle_payable[key]}
        functions[key] = FunctionReport(
            key=key,
            signature=spec.signature if spec is not None else f"<{key}>",
            origin=origin,
            abi=abi_status if l1 is not None else None,
            verdict=verdict,
            reason=reason,
            calls=st.calls if st else 0,
            original_success=st.original_success if st else 0,
            divergences=st.divergences if st else 0,
            sequence_divergences=st.sequence_divergences if st else 0,
            env_divergences=st.env_divergences if st else 0,
            gas_divergences=st.gas_divergences if st else 0,
            kinds=dict(st.kinds) if st else {},
            coverage=coverage.get(key),
            payable=payable,
            checked_bytes=checked.get(key),
            counterexample=(
                counterexample_to_dict(st.first or st.first_gas)
                if st and (st.first or st.first_gas)
                else None
            ),
            elapsed=st.elapsed if st else 0.0,
        )
    return finish()


def _function_table(
    original_specs: Dict[bytes, FuncSpec],
    candidate_specs: Dict[bytes, FuncSpec],
    routed: set,
    scan: Sequence[int],
    l1: Optional[L1Result],
) -> Dict[str, Tuple[Optional[FuncSpec], str, Optional[str]]]:
    """key -> (spec used to generate calls, origin, L1 status) for every function and probe."""
    table: Dict[str, Tuple[Optional[FuncSpec], str, Optional[str]]] = {}
    for sel in sorted(set(original_specs) | set(candidate_specs) | routed):
        o, c = original_specs.get(sel), candidate_specs.get(sel)
        if o is not None and c is not None:
            entry = (c, "both", MATCH)
        elif o is not None:
            entry = (
                o,
                "routed" if sel in routed else "original",
                ROUTED if sel in routed else MISSING,
            )
        elif c is not None:
            entry = (c, "candidate", EXTRA)
        else:
            entry = (FuncSpec(sel), "routed", EXTRA)
        table["0x" + sel.hex()] = entry
    for s in scan:
        key = f"0x{s:08x}"
        if key not in table:
            table[key] = (FuncSpec(s.to_bytes(4, "big")), "scan", None)
    for probe in PROBES:
        table[probe] = (None, "probe", None)
    if l1 is not None:  # keep the L1 classification authoritative
        for key, row in l1.functions.items():
            if key in table:
                spec, origin, _ = table[key]
                table[key] = (spec, origin, row["status"])
    return table


def _coverage(
    differ: Differ,
    stats: Dict[str, FunctionStats],
    selectors: Sequence[bytes],
    primary: str,
    confirm: Optional[str],
) -> Dict[str, Dict[str, int]]:
    """Branch coverage of the original per function, the dispatcher's JUMPIs excluded."""
    if "pyevm" not in (primary, confirm):
        return {}
    dispatcher = differ.dispatcher_pcs(selectors)
    out = {}
    for key, st in stats.items():
        if key in PROBES:
            continue
        own = {(pc, taken) for pc, taken in st.covered if pc not in dispatcher}
        out[key] = {"covered": len(own), "seen": 2 * len({pc for pc, _ in own})}
    return out


def _level3(
    stats: Dict[str, FunctionStats],
    sequences: dict,
    env_reasons: Sequence[str],
    primary: str,
    confirm: Optional[str],
    elapsed: float,
) -> LevelResult:
    calls = sum(st.calls for st in stats.values())
    divergent = sorted(k for k, st in stats.items() if st.divergences or st.sequence_divergences)
    starved = sorted(k for k, st in stats.items() if st.gas_divergences and k not in divergent)
    unreached = sorted(k for k, st in stats.items() if st.calls == 0 and k not in divergent)
    details = {
        "backend": primary,
        "confirm_backend": confirm,
        "calls": calls + sequences.get("calls", 0),
        "executions_per_second": (
            round(2 * (calls + sequences.get("calls", 0)) / elapsed) if elapsed > 0 else None
        ),
        "elapsed": round(elapsed, 3),
        "divergent": divergent,
        "env_divergences": sum(st.env_divergences for st in stats.values()),
        "gas_divergences": sum(st.gas_divergences for st in stats.values()),
        "sequences": sequences,
    }
    if divergent and env_reasons:
        return LevelResult(
            "inconclusive",
            "divergences the environment may explain: " + ", ".join(env_reasons),
            details,
        )
    if divergent:
        return LevelResult("fail", "divergent: " + ", ".join(divergent[:8]), details)
    if starved:
        return LevelResult(
            "inconclusive",
            "the original runs out of a block's gas where the candidate finishes: "
            + ", ".join(starved[:8]),
            details,
        )
    if unreached:
        return LevelResult(
            "inconclusive", "time budget exhausted before: " + ", ".join(unreached[:8]), details
        )
    return LevelResult("pass", "", details)


def _level4(
    original: bytes,
    md: Optional[Metadata],
    sources: Dict[str, str],
    art: Artifact,
    comp: Compilation,
    version: str,
    path: str,
    budget: Budget,
) -> LevelResult:
    """L4: the compiled runtime, then (same compiler version only) the usual optimizer settings."""
    cmp = compare_runtime(original, art.runtime, art.immutable_refs, art.link_refs)
    details = {"compiled": cmp.to_dict(), "settings": comp.settings.label}
    if cmp.identical:
        return LevelResult("pass", "", dict(details, matching=[comp.settings.label]))
    if budget.l4_search and md is not None and md.version == version:
        search = search_l4(
            original,
            sources,
            art.name,
            version,
            solc_path=path,
            variants=optimizer_variants(version),
            time_limit=budget.l4_time_limit,
        )
        details["search"] = search.to_dict()
        if search.identical:
            return LevelResult(
                "pass", "", dict(details, matching=[s.label for s in search.matching])
            )
        best = search.best.instr_similarity if search.best else cmp.instr_similarity
        return LevelResult(
            "fail",
            f"not identical under any tried settings (best instr_similarity {best})",
            details,
        )
    why = (
        ""
        if md is None or md.version == version
        else f" (original compiled by {md.compiler} {md.version})"
    )
    return LevelResult(
        "fail", f"not identical (instr_similarity {cmp.instr_similarity}){why}", details
    )

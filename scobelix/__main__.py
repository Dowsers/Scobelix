import cProfile
import json
import logging
import argparse
import os
import re
import sys
import threading

import coloredlogs
import timeout_decorator

from scobelix.decompiler import MAX_ALARM_SECONDS, TimeoutInterrupt, decompile_address, decompile_bytecode
from scobelix.loader import InvalidBytecode

logger = logging.getLogger(__name__)

# The global time budget of a decompilation, when --time-budget is absent:
# read at every invocation.
TIME_BUDGET_ENV = "SCOBELIX_TIME_BUDGET"
# Under a time budget, the Solidity generation and the validation get what
# is left of it less this many seconds for printing the output; the
# generation is not attempted with less than SOLGEN_MIN_SECONDS.
OUTPUT_RESERVE = 2.0
SOLGEN_MIN_SECONDS = 2.0
# Under a time budget, the share of the time of the generation its
# verification loop does not get (OUTPUT_RESERVE seconds at least): the
# loop stops by itself before the alarm of the generation, which then
# writes the functions it did not accept in exact form.
VERIFY_RESERVE = 0.25
SOLGEN_SKIPPED = "time budget exhausted before the Solidity generation"
SOLGEN_INTERRUPTED = "Solidity generation interrupted by the time budget"
VALIDATION_SKIPPED = "time budget exhausted before the Solidity validation"


class _BudgetExhausted(TimeoutInterrupt):
    """The time budget left no time for the Solidity generation, or
    interrupted it (`value` says which)."""


def parse_args(args):
    parser = argparse.ArgumentParser(description="EVM decompiler.")
    parser.add_argument(
        "-v",
        default=str(logging.INFO),
        help="log level (INFO, DEBUG...)",
        metavar="LOG_LEVEL",
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        default=False,
        help="Enable profiling of the application. "
        "Dumps the profile data to a 'scobelix.prof' file.",
    )
    parser.add_argument(
        "address_or_bytecode",
        help="An ethereum address, a comma-separated list of ethereum addresses, or `-` to read bytecode from stdin.",
    )
    parser.add_argument(
        "--function",
        default="",
        help="Function name to decompile only this one.",
        required=False,
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--explain", action="store_true")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the decompiled contract's structured AST as JSON instead "
        "of the pseudo-code text.",
    )
    parser.add_argument(
        "--solidity",
        action="store_true",
        help="Print a Solidity reconstruction (see scobelix.solgen) instead "
        "of the pseudo-code text. It keeps the behaviour of the bytecode "
        "(what is not ordinary Solidity is written with its exact EVM "
        "meaning) and is not verified unless --verify is passed - see the "
        "generated file's header comment.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="With --solidity, also compile the generated source and run it "
        "against the original bytecode, function by function: a function "
        "keeps its rewritten form only if it was seen to behave like the "
        "original (the rewriting passes are backed off until it does), any "
        "other is written in the form closest to the bytecode. The verdict "
        "of every function goes into the source's comments and a summary to "
        "stderr. Needs a solc release and an EVM backend (pip install "
        "'scobelix[verify]'); without them the source is printed unverified, "
        "in the form closest to the bytecode, with a warning.",
    )
    parser.add_argument(
        "--verify-timeout",
        type=_seconds,
        default=None,
        metavar="SECONDS",
        help="With --verify, the time the verification may take as a whole "
        "(default: 300; under --time-budget, at most three quarters of what "
        "is left for the Solidity generation, which keeps the rest to write "
        "the source). When it runs out, the functions not verified yet are "
        "written in the form closest to the bytecode and reported as not "
        "verified.",
    )
    parser.add_argument(
        "--target-solc",
        type=_solc_version,
        default=None,
        metavar="X.Y.Z",
        help="With --solidity, the compiler version to write the source for "
        "(default: the original's when it is an available 0.8 release, else "
        "the newest installed 0.8).",
    )
    parser.add_argument(
        "--allow-solc-download",
        action="store_true",
        help="Let --verify and --validate-solidity download the official "
        "solc release they need (default: only when the environment variable "
        "SCOBELIX_ALLOW_SOLC_DOWNLOAD is set).",
    )
    parser.add_argument(
        "--idiom-level",
        choices=("exact", "full"),
        default="full",
        help="With --solidity: 'full' (default) writes idiomatic Solidity "
        "wherever a rewriting applies, 'exact' keeps every function in the "
        "form closest to the bytecode.",
    )
    parser.add_argument(
        "--validate-solidity",
        action="store_true",
        help="With --solidity, also compile the generated source with solc "
        "and print a validity status line to stderr (skipped if no fitting "
        "solc is installed; solc is not a dependency of this package).",
    )
    parser.add_argument(
        "--combined-json",
        action="store_true",
        help="Print a single JSON object with the pseudo-code text, the "
        "structured AST, and (if --solidity is also passed) the Solidity "
        "reconstruction with its confidence/warnings and its per-function "
        "table (plus the verification report with --verify) - for callers "
        "that want everything from one decompilation pass instead of "
        "invoking this CLI multiple times. Takes precedence over "
        "--json/--solidity alone.",
    )
    parser.add_argument(
        "--time-budget",
        type=_seconds,
        default=None,
        metavar="SECONDS",
        help="The time the whole decompilation of one input may take "
        "(default: the SCOBELIX_TIME_BUDGET environment variable, else no "
        "limit besides the per-function budgets). The functions it leaves "
        "less than a second to are written as failures, every step keeps the "
        "smaller of its own budget and what is left, and the Solidity "
        "generation (with --solidity) is interrupted or skipped when it "
        "would outlive it. The output is then partial, never absent (except "
        "with --solidity alone, which has nothing to print without the "
        "generation: use --combined-json), but it is printed at the end: a "
        "caller that kills the process on a timeout must allow the budget "
        "plus a margin for what the budget does not bound (the start of the "
        "process, reading the input, a first build of the signature "
        "database, the steps after the functions when they outlive the "
        "share of the budget kept for them).",
    )

    parsed = parser.parse_args(args)
    if parsed.time_budget is None:
        parsed.time_budget = _time_budget_from_environment(parser)
    return parsed


def _time_budget_from_environment(parser):
    """The time budget of SCOBELIX_TIME_BUDGET, read now; None when the
    variable is absent or empty, a usage error (status 2) when its value
    is not a positive number of seconds."""
    value = os.environ.get(TIME_BUDGET_ENV, "").strip()
    if not value:
        return None
    try:
        return _seconds(value)
    except argparse.ArgumentTypeError as e:
        parser.error(f"{TIME_BUDGET_ENV}: {e}")


def _solc_version(value):
    if not re.fullmatch(r"\d+\.\d+\.\d+", value):
        raise argparse.ArgumentTypeError(f"not a compiler version (expected X.Y.Z): {value!r}")
    return value


def _seconds(value):
    try:
        seconds = float(value)
    except ValueError:
        seconds = 0.0
    if not 0 < seconds < float("inf"):
        raise argparse.ArgumentTypeError(f"not a positive number of seconds: {value!r}")
    return seconds


def _verification_limits(args, time_left):
    """The time limit of the verification loop under a time budget
    (`time_left`: the seconds the Solidity generation has), and its own one
    (--verify-timeout, else the default of the loop): the shorter of that
    and what is left less VERIFY_RESERVE of it."""
    from scobelix.solgen import SearchBudget

    own = SearchBudget().time_limit if args.verify_timeout is None else args.verify_timeout
    share = time_left - max(OUTPUT_RESERVE, VERIFY_RESERVE * time_left)
    return min(own, max(share, 1e-3)), own  # (a positive time: the loop then stops at its first check)


def _generate_solidity(decompilation, args, time_left=None):
    """generate_solidity() with the options of the command; `time_left`
    (seconds, under a time budget) caps the time limit of the verification
    loop (_verification_limits)."""
    from scobelix.solgen import generate_solidity

    limit = args.verify_timeout if time_left is None else _verification_limits(args, time_left)[0]
    return generate_solidity(
        decompilation,
        verify=args.verify,
        target_solc=args.target_solc,
        idiom_level=args.idiom_level,
        allow_solc_download=True if args.allow_solc_download else None,
        budget=None if limit is None else {"time_limit": limit},
    )


def _cut_by_the_budget(result, args, time_left):
    """Whether the verification loop of `result` stopped at the time limit
    the time budget gave it, shorter than its own."""
    limit, own = _verification_limits(args, time_left)
    search = getattr(getattr(result, "verification", None), "search", None) or {}
    return limit < own and search.get("exhausted_by") == "time"


def _validate(result, args, time_left=None):
    """validate() with the options of the command; `time_left` (seconds)
    caps the time of the compiler."""
    from scobelix.solgen import validate

    allow = True if args.allow_solc_download else None
    if time_left is None:
        return validate(result, allow_download=allow)
    return validate(result, allow_download=allow, timeout=time_left)


def _generate_under_budget(decompilation, args):
    """_generate_solidity(), bounded by what is left of the time budget of
    the decompilation (none: as it is): nothing is attempted when too
    little is left, and an alarm interrupts a generation that outlives it
    (_BudgetExhausted either way, the budget marked exhausted); a
    verification loop that stops at the time the budget left it marks the
    budget exhausted too. The alarm needs the main thread: elsewhere the
    generation runs unbounded."""
    budget = decompilation.time_budget
    if budget is None:
        return _generate_solidity(decompilation, args)
    time_left = min(budget.remaining() - OUTPUT_RESERVE, MAX_ALARM_SECONDS)
    if time_left < SOLGEN_MIN_SECONDS:
        budget.exhausted = True
        raise _BudgetExhausted(SOLGEN_SKIPPED)

    def generate():
        return _generate_solidity(decompilation, args, time_left)

    if threading.current_thread() is not threading.main_thread():
        logger.warning("the time budget cannot bound the Solidity generation outside the main thread")
        result = generate()
    else:
        bounded = timeout_decorator.timeout(
            time_left, timeout_exception=_BudgetExhausted, exception_message=SOLGEN_INTERRUPTED
        )(generate)
        try:
            result = bounded()
        except _BudgetExhausted:
            budget.exhausted = True
            raise
    if args.verify and _cut_by_the_budget(result, args, time_left):
        budget.exhausted = True
    return result


def _validate_under_budget(result, decompilation, args):
    """_validate(), the compiler's time capped by what is left of the time
    budget of the decompilation (none: as it is); a validation `skipped`
    when nothing is left. The budget is marked exhausted then, and when
    what was left of it cut the compiler short."""
    from scobelix.solgen import ValidationResult

    budget = decompilation.time_budget
    if budget is None:
        return _validate(result, args)
    time_left = budget.remaining() - OUTPUT_RESERVE
    if time_left <= 0:
        budget.exhausted = True
        return ValidationResult(status="skipped", errors=[], warnings=[VALIDATION_SKIPPED])
    validation = _validate(result, args, time_left)
    if getattr(validation, "out_of_time", False):
        budget.exhausted = True
    return validation


def _verification_warnings(result):
    return [w for w in result.warnings if w.startswith("verification")]


def _no_verification(warnings):
    """The top-level keys of a verification report, with nothing in them:
    the report of a verification that could not run at all."""
    return {"passed": False, "levels": {}, "summary": {}, "functions": {}, "warnings": warnings}


def _verification_json(result):
    """The verification report as JSON data; the same top-level keys with
    nothing in them when the verification could not run at all."""
    report = result.verification_json()
    if report is None:
        report = _no_verification(_verification_warnings(result))
    return report


def _failure(e):
    """What the combined JSON says of an exception of the generation."""
    if isinstance(e, _BudgetExhausted):
        return e.value
    return f"{type(e).__name__}: {e}"


def _solgen_payload(decompilation, args):
    """The keys --solidity adds to the combined JSON object.

    An exception of the generation (or of the verification it runs), or
    its interruption by the time budget, does not lose the text and the
    AST already decompiled: the keys are present with nothing in them,
    `solgen_warnings` and `solgen_error` carry the message, and the
    traceback goes to the log. The same goes for an exception of the
    validation, which then keeps the generated source.
    """
    payload = {}
    try:
        result = _generate_under_budget(decompilation, args)
        payload["solidity"] = result.solidity
        payload["solgen_confidence"] = result.confidence
        payload["solgen_warnings"] = result.warnings
        payload["solgen_functions"] = result.functions_json()

        if args.verify:
            payload["solgen_verification"] = _verification_json(result)
    except (Exception, TimeoutInterrupt) as e:
        message = _failure(e)
        if isinstance(e, _BudgetExhausted):
            logger.warning("%s: the text and the AST are printed without it", message)
        else:
            logger.exception("Solidity generation failed (%s): the text and the AST are printed without it", message)
        payload.update(solidity="", solgen_confidence={}, solgen_warnings=[message], solgen_functions={})
        if args.verify:
            payload["solgen_verification"] = _no_verification([message])
        if args.validate_solidity:
            payload["solgen_validation"] = {"status": "skipped", "errors": [], "warnings": [message]}
        payload["solgen_error"] = message
        return payload

    if args.validate_solidity:
        try:
            v = _validate_under_budget(result, decompilation, args)
            payload["solgen_validation"] = {
                "status": v.status,
                "errors": v.errors,
                "warnings": v.warnings,
            }
        except (Exception, TimeoutInterrupt) as e:
            message = _failure(e)
            logger.exception("Solidity validation failed (%s): the source is printed unvalidated", message)
            payload["solgen_validation"] = {"status": "skipped", "errors": [], "warnings": [message]}
            payload["solgen_error"] = message
    return payload


def _time_budget_json(budget):
    """The `time_budget` key of the combined JSON object."""
    return {"seconds": budget.seconds, "exhausted": budget.exhausted, "skipped": list(budget.skipped)}


def _print_verification(result):
    """The summary the header of the source carries (levels, verdicts,
    tiers, what the verification backed off), the time it took, then the
    warnings of the verification."""
    report = result.verification
    if report is None:
        print("# verification: unavailable", file=sys.stderr)
    else:
        lines = list(getattr(report, "lines", None) or ())
        if not lines:
            levels = "  ".join(f"{k}={v.status}" for k, v in report.levels.items() if v.reason != "not requested")
            verdicts = ", ".join(f"{k} {n}" for k, n in sorted(report.summary.items()))
            lines = [f"verification: {levels}"] + ([f"verdicts: {verdicts}"] if verdicts else [])
        print(f"# {lines[0]}", file=sys.stderr)
        for line in lines[1:]:
            print(f"#   {line}", file=sys.stderr)
        elapsed = (getattr(report, "search", None) or {}).get("elapsed")
        if elapsed is not None:
            print(f"#   time: {elapsed:.1f} s", file=sys.stderr)
    for w in _verification_warnings(result):
        print(f"#   {w}", file=sys.stderr)


def print_decompilation(this_addr, args):
    function_name = args.function or None

    if this_addr == "-":
        this_addr = sys.stdin.read().strip()

    if len(this_addr) == 42:
        decompilation = decompile_address(this_addr, function_name, time_budget=args.time_budget)
    else:
        decompilation = decompile_bytecode(this_addr, function_name, time_budget=args.time_budget)

    if args.combined_json:
        payload = {"text": decompilation.text, "json": decompilation.json}

        if args.solidity:
            payload.update(_solgen_payload(decompilation, args))

        if decompilation.time_budget is not None:
            payload["time_budget"] = _time_budget_json(decompilation.time_budget)

        print(json.dumps(payload))
    elif args.solidity:
        result = _generate_under_budget(decompilation, args)
        print(result.solidity)

        if args.verify:
            _print_verification(result)

        if args.validate_solidity:
            v = _validate_under_budget(result, decompilation, args)
            print(f"# solc validation: {v.status}", file=sys.stderr)
            if v.via_ir or VALIDATION_SKIPPED in v.warnings:
                print(f"#   {v.warnings[0]}", file=sys.stderr)
            for e in v.errors:
                print(f"#   {e}", file=sys.stderr)
    elif args.json:
        print(json.dumps(decompilation.json, indent=2))
    else:
        print(decompilation.text)


def main():
    args = parse_args(sys.argv[1:])

    if args.v.isnumeric():
        coloredlogs.install(level=int(args.v), milliseconds=True)
    elif hasattr(logging, args.v.upper()):
        coloredlogs.install(level=getattr(logging, args.v.upper()), milliseconds=True)
    else:
        raise ValueError("Logging should be DEBUG/INFO/WARNING/ERROR.")

    try:
        if "," in args.address_or_bytecode:
            for addr in args.address_or_bytecode.split(","):
                print_decompilation(addr, args)
        elif args.profile:
            with cProfile.Profile() as profile:
                try:
                    print_decompilation(args.address_or_bytecode, args)
                finally:
                    profile.dump_stats("scobelix.prof")

        else:
            print_decompilation(args.address_or_bytecode, args)
    except InvalidBytecode as e:
        # a usage error, like the ones of argparse: a message and status 2
        print(f"scobelix: error: invalid bytecode: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()

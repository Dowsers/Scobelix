import cProfile
import json
import logging
import argparse
import re
import sys

import coloredlogs

from scobelix.decompiler import decompile_address, decompile_bytecode
from scobelix.loader import InvalidBytecode

logger = logging.getLogger(__name__)


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
        "(default: 300). When it runs out, the functions not verified yet "
        "are written in the form closest to the bytecode and reported as "
        "not verified.",
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

    return parser.parse_args(args)


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


def _generate_solidity(decompilation, args):
    from scobelix.solgen import generate_solidity

    return generate_solidity(
        decompilation,
        verify=args.verify,
        target_solc=args.target_solc,
        idiom_level=args.idiom_level,
        allow_solc_download=True if args.allow_solc_download else None,
        budget=None if args.verify_timeout is None else {"time_limit": args.verify_timeout},
    )


def _validate(result, args):
    from scobelix.solgen import validate

    return validate(result, allow_download=True if args.allow_solc_download else None)


def _verification_warnings(result):
    return [w for w in result.warnings if w.startswith("verification")]


def _verification_json(result):
    """The verification report as JSON data; the same top-level keys with
    nothing in them when the verification could not run at all."""
    report = result.verification_json()
    if report is None:
        report = {
            "passed": False,
            "levels": {},
            "summary": {},
            "functions": {},
            "warnings": _verification_warnings(result),
        }
    return report


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
        decompilation = decompile_address(this_addr, function_name)
    else:
        decompilation = decompile_bytecode(this_addr, function_name)

    if args.combined_json:
        payload = {"text": decompilation.text, "json": decompilation.json}

        if args.solidity:
            result = _generate_solidity(decompilation, args)
            payload["solidity"] = result.solidity
            payload["solgen_confidence"] = result.confidence
            payload["solgen_warnings"] = result.warnings
            payload["solgen_functions"] = result.functions_json()

            if args.verify:
                payload["solgen_verification"] = _verification_json(result)

            if args.validate_solidity:
                v = _validate(result, args)
                payload["solgen_validation"] = {
                    "status": v.status,
                    "errors": v.errors,
                    "warnings": v.warnings,
                }

        print(json.dumps(payload))
    elif args.solidity:
        result = _generate_solidity(decompilation, args)
        print(result.solidity)

        if args.verify:
            _print_verification(result)

        if args.validate_solidity:
            v = _validate(result, args)
            print(f"# solc validation: {v.status}", file=sys.stderr)
            if v.via_ir:
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

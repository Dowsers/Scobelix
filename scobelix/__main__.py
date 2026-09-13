import cProfile
import json
import logging
import argparse
import sys

import coloredlogs

from scobelix.decompiler import decompile_address, decompile_bytecode

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
        help="Print a best-effort Solidity reconstruction (see scobelix.solgen) "
        "instead of the pseudo-code text. Approximation only - see the "
        "generated file's header comment.",
    )
    parser.add_argument(
        "--validate-solidity",
        action="store_true",
        help="With --solidity, also compile the generated source with solc "
        "and print a validity status line to stderr (skipped if solc isn't "
        "on PATH; solc is not a dependency of this package).",
    )
    parser.add_argument(
        "--combined-json",
        action="store_true",
        help="Print a single JSON object with the pseudo-code text, the "
        "structured AST, and (if --solidity is also passed) the Solidity "
        "reconstruction with its confidence/warnings - for callers that want "
        "everything from one decompilation pass instead of invoking this CLI "
        "multiple times. Takes precedence over --json/--solidity alone.",
    )

    return parser.parse_args(args)


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
            from scobelix.solgen import generate_solidity

            result = generate_solidity(decompilation)
            payload["solidity"] = result.solidity
            payload["solgen_confidence"] = result.confidence
            payload["solgen_warnings"] = result.warnings

            if args.validate_solidity:
                from scobelix.solgen import validate

                v = validate(result)
                payload["solgen_validation"] = {
                    "status": v.status,
                    "errors": v.errors,
                    "warnings": v.warnings,
                }

        print(json.dumps(payload))
    elif args.solidity:
        from scobelix.solgen import generate_solidity

        result = generate_solidity(decompilation)
        print(result.solidity)

        if args.validate_solidity:
            from scobelix.solgen import validate

            v = validate(result)
            print(f"# solc validation: {v.status}", file=sys.stderr)
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


if __name__ == "__main__":
    main()

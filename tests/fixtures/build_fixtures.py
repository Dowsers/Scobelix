#!/usr/bin/env python3
"""
(Re)builds the runtime bytecode fixtures from their Solidity sources.

    python tests/fixtures/build_fixtures.py            # rebuild bytecode/<Name>.hex
    python tests/fixtures/build_fixtures.py --check    # compare only, exit 1 on mismatch
    python tests/fixtures/build_fixtures.py Name ...   # only these fixtures

fixtures.json maps each fixture name to:

    source       file in sources/
    contract     contract name in that file
    solc         exact compiler version
    optimizer    true / false
    runs         optimizer runs
    via_ir       true / false
    evm_version  EVM version, null for the compiler's default

Sources are compiled with --standard-json under the source unit name
"sources/<file>", i.e. their path relative to this directory: the metadata
hash at the end of the runtime code depends on it, and this is what makes a
rebuild byte-identical. Relative imports ("./X.sol") are resolved in
sources/.

solc binaries are looked up by exact version through scobelix.verify.solc
when that module is available, otherwise in $SCOBELIX_SOLC_DIR, ~/.solcx,
~/.solc-select/artifacts, ~/.svm and PATH. Every candidate is identified with
`--version`; wrapper scripts (such as the solc-select shim) are skipped.
"""

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCES = HERE / "sources"
BYTECODE = HERE / "bytecode"
SPECS = HERE / "fixtures.json"

_VERSION_RE = re.compile(r"Version:\s*(\d+\.\d+\.\d+)")
_IMPORT_RE = re.compile(r"""^\s*import\s+(?:[^"']*\bfrom\s+)?["']\./([^"']+)["']""", re.M)


class SolcNotFound(RuntimeError):
    pass


def load_specs():
    return json.loads(SPECS.read_text())


def _binary_version(path):
    try:
        with open(path, "rb") as fh:
            if fh.read(2) == b"#!":
                return None
        out = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=30
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = _VERSION_RE.search(out)
    return m.group(1) if m else None


def _candidates(version):
    dirs = []
    if os.environ.get("SCOBELIX_SOLC_DIR"):
        dirs.append(os.environ["SCOBELIX_SOLC_DIR"])
    home = os.path.expanduser("~")
    yield from glob.glob(os.path.join(home, ".solcx", "solc-v" + version))
    yield from glob.glob(
        os.path.join(home, ".solc-select", "artifacts", "solc-" + version, "solc-" + version)
    )
    yield from glob.glob(os.path.join(home, ".svm", version, "solc-" + version))
    for d in dirs:
        yield from glob.glob(os.path.join(d, "*" + version + "*"))
    for name in ("solc-" + version, "solc"):
        found = shutil.which(name)
        if found:
            yield found


def find_solc(version):
    """Path of a solc binary of exactly `version`."""
    try:
        from scobelix.verify.solc import find_solc as resolver
    except ImportError:
        resolver = None
    if resolver is not None:
        try:
            return resolver(version)
        except Exception:
            pass
    for path in _candidates(version):
        if os.path.isfile(path) and _binary_version(path) == version:
            return path
    raise SolcNotFound("solc %s not found" % version)


def _sources(filename, seen=None):
    """{unit name: {"content": ...}} for `filename` and its relative imports."""
    seen = {} if seen is None else seen
    unit = "sources/" + filename
    if unit in seen:
        return seen
    content = (SOURCES / filename).read_text()
    seen[unit] = {"content": content}
    for dep in _IMPORT_RE.findall(content):
        _sources(dep, seen)
    return seen


def compile_fixture(spec):
    """Runtime bytecode (hex, no 0x) of one fixture spec."""
    settings = {
        "optimizer": {"enabled": bool(spec["optimizer"]), "runs": int(spec["runs"])},
        "outputSelection": {"*": {"*": ["evm.deployedBytecode.object"]}},
    }
    if spec.get("via_ir"):
        settings["viaIR"] = True
    if spec.get("evm_version"):
        settings["evmVersion"] = spec["evm_version"]
    request = {"language": "Solidity", "sources": _sources(spec["source"]), "settings": settings}

    solc = find_solc(spec["solc"])
    proc = subprocess.run(
        [solc, "--standard-json"], input=json.dumps(request), capture_output=True, text=True
    )
    if not proc.stdout.strip():
        raise RuntimeError("solc %s produced no output: %s" % (spec["solc"], proc.stderr[-500:]))
    out = json.loads(proc.stdout)
    errors = [e for e in out.get("errors", []) if e.get("severity") == "error"]
    if errors:
        raise RuntimeError(
            "\n".join(e.get("formattedMessage", e.get("message", "")) for e in errors)
        )
    contract = out["contracts"]["sources/" + spec["source"]][spec["contract"]]
    code = contract["evm"]["deployedBytecode"]["object"]
    if not code:
        raise RuntimeError("empty runtime code for %s" % spec["contract"])
    return code


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("names", nargs="*", help="fixtures to build (default: all)")
    ap.add_argument(
        "--check", action="store_true", help="compare with the committed bytecode, write nothing"
    )
    args = ap.parse_args(argv)

    specs = load_specs()
    names = args.names or sorted(specs)
    unknown = [n for n in names if n not in specs]
    if unknown:
        ap.error("unknown fixtures: %s" % ", ".join(unknown))

    failed = False
    for name in names:
        try:
            code = compile_fixture(specs[name])
        except SolcNotFound as e:
            print("%-32s SKIPPED (%s)" % (name, e))
            continue
        path = BYTECODE / (name + ".hex")
        old = path.read_text().strip() if path.is_file() else None
        if args.check:
            status = "ok" if old == code else "DIFFERS"
            failed |= old != code
        else:
            if old != code:
                path.write_text(code)
            status = "unchanged" if old == code else "written"
        print("%-32s %s" % (name, status))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

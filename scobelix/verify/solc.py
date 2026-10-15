"""
Locating, downloading and running solc for verification.

Every solc binary is identified by running it with `--version`, never by its
file name, and wrapper scripts are skipped: the solc-select shim installed on
PATH starts with a `#!` line, honours `SOLC_VERSION`, and exits 0 with an
EMPTY output when that version is not installed, which would make a broken
compilation look like a successful one.

Binaries are searched, in this order (first one found for a version wins):

    $SCOBELIX_SOLC_DIR/solc-*                    user override
    <user cache dir>/scobelix/solc/solc-*        download_solc() destination
    ~/.solcx/solc-v*                             py-solc-x
    ~/.solc-select/artifacts/solc-*/solc-*       solc-select
    ~/.svm/*/solc-*                              foundry
    hardhat's compiler cache                     hardhat
    PATH                                         anything named solc*

Downloads are opt-in (`allow_download=True`, or SCOBELIX_ALLOW_SOLC_DOWNLOAD=1):
the official static build is fetched from binaries.soliditylang.org, checked
against the sha256 of the release list, then against its own `--version`.

Compilation goes through `--standard-json` (`compile_standard_json`); the
version is either given or chosen from the sources' `pragma solidity` lines
(`select_version`).  Only release builds are used: a nightly binary does not
count as the release it is a prerelease of.  solc's output is cached per
(binary, exact input) for the life of the process (`COMPILE_CACHE_BYTES`):
recompiling an unchanged source with unchanged settings costs nothing.
"""

from __future__ import annotations

import collections
import dataclasses
import glob
import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from appdirs import user_cache_dir

__all__ = [
    "Artifact",
    "Compilation",
    "CompilationError",
    "Settings",
    "SolcNotFound",
    "available_releases",
    "binary_version",
    "clear_compile_cache",
    "compile_standard_json",
    "download_allowed",
    "download_solc",
    "execution_evm_version",
    "find_solc",
    "installed_solcs",
    "normalize_version",
    "optimizer_variants",
    "parse_version_output",
    "pragma_constraints",
    "select_version",
    "solc_for_source",
    "version_key",
    "version_satisfies",
    "versions_matching",
]

DIR_ENV = "SCOBELIX_SOLC_DIR"
DOWNLOAD_ENV = "SCOBELIX_ALLOW_SOLC_DOWNLOAD"
BINARIES_URL = "https://binaries.soliditylang.org"
# binaries.soliditylang.org answers HTTP 403 to urllib's default User-Agent
USER_AGENT = "scobelix-verify (+https://pypi.org/project/scobelix/)"

SEARCH_PATTERNS = (
    "~/.solcx/solc-v*",
    "~/.solc-select/artifacts/solc-*/solc-*",
    "~/.svm/*/solc-*",
    "~/.cache/hardhat-nodejs/compilers*/*/solc-*",
    "~/Library/Caches/hardhat-nodejs/compilers*/*/solc-*",
)

_VERSION_RE = re.compile(r"Version:\s*(\d+\.\d+\.\d+)(\S*)")


class SolcNotFound(RuntimeError):
    """No usable solc binary for the requested version (and no download allowed)."""


class CompilationError(RuntimeError):
    """solc reported at least one error (or produced no usable output)."""

    def __init__(self, errors: List[dict], version: Optional[str] = None):
        self.errors = errors
        self.version = version
        super().__init__("\n".join(_error_text(e) for e in errors) or "compilation failed")

    @property
    def messages(self) -> List[str]:
        return [_error_text(e) for e in self.errors]

    @property
    def stack_too_deep(self) -> bool:
        return any("stack too deep" in _error_text(e).lower() for e in self.errors)


def _error_text(e: dict) -> str:
    return (e.get("formattedMessage") or e.get("message") or "").strip()


def version_key(version: str) -> Tuple[int, int, int]:
    """'0.8.19' -> (0, 8, 19), for sorting and comparisons."""
    major, minor, patch = (int(x) for x in version.split("."))
    return major, minor, patch


def normalize_version(version: str) -> str:
    """'v0.8.19', '0.8.19+commit.7dd6d404' -> '0.8.19' (ValueError when there is no X.Y.Z)."""
    m = re.fullmatch(r"\s*v?(\d+\.\d+\.\d+)(\+commit\.[0-9a-f]+(\..*)?)?\s*", version)
    if not m:
        raise ValueError(f"not a solc release version: {version!r}")
    return m.group(1)


# ---------------------------------------------------------------- discovery

_version_cache: Dict[Tuple[str, int, int], Optional[str]] = {}


def parse_version_output(text: str) -> Optional[str]:
    """The release version in `solc --version` output; None for a prerelease or anything else."""
    m = _VERSION_RE.search(text)
    # "+commit.xxx" (or nothing) follows a release version, "-nightly..." a prerelease one
    return m.group(1) if m and not m.group(2).startswith("-") else None


def binary_version(path: str) -> Optional[str]:
    """
    The release version ('0.8.19') a solc binary reports, or None when `path`
    is not a working solc release build (script, shim, nightly, broken file).
    Results are cached per (path, mtime, size).
    """
    try:
        real = os.path.realpath(path)
        st = os.stat(real)
    except OSError:
        return None
    key = (real, st.st_mtime_ns, st.st_size)
    if key in _version_cache:
        return _version_cache[key]
    version = None
    try:
        with open(real, "rb") as fh:
            is_script = fh.read(2) == b"#!"
        if not is_script:
            out = subprocess.run(
                [real, "--version"], capture_output=True, text=True, timeout=30
            ).stdout
            version = parse_version_output(out)
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError):
        version = None
    _version_cache[key] = version
    return version


def _download_dir() -> Path:
    override = os.environ.get(DIR_ENV)
    if override:
        return Path(override).expanduser()
    return Path(user_cache_dir("scobelix", "scobelix")) / "solc"


def _candidate_paths(extra_dirs: Iterable[str]) -> List[str]:
    patterns = [os.path.join(os.path.expanduser(d), "solc*") for d in extra_dirs]
    override = os.environ.get(DIR_ENV)
    if override:
        patterns.append(os.path.join(os.path.expanduser(override), "solc*"))
    patterns.append(str(Path(user_cache_dir("scobelix", "scobelix")) / "solc" / "solc*"))
    patterns += [os.path.expanduser(p) for p in SEARCH_PATTERNS]
    patterns += [
        os.path.join(d, "solc*") for d in os.environ.get("PATH", "").split(os.pathsep) if d
    ]
    out: List[str] = []
    for pattern in patterns:
        out += sorted(glob.glob(pattern))
    return out


def installed_solcs(extra_dirs: Iterable[str] = ()) -> Dict[str, str]:
    """version -> absolute path of a verified release binary, sorted by version."""
    found: Dict[str, str] = {}
    for cand in _candidate_paths(extra_dirs):
        if not (os.path.isfile(cand) and os.access(cand, os.X_OK)):
            continue
        version = binary_version(cand)
        if version and version not in found:
            found[version] = os.path.realpath(cand)
    return dict(sorted(found.items(), key=lambda kv: version_key(kv[0])))


def download_allowed(allow_download: Optional[bool] = None) -> bool:
    """An explicit flag wins; else SCOBELIX_ALLOW_SOLC_DOWNLOAD=1/true/yes/on enables downloads."""
    if allow_download is not None:
        return bool(allow_download)
    return os.environ.get(DOWNLOAD_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def find_solc(version: str, allow_download: Optional[bool] = None) -> str:
    """
    Path of solc `version` ('0.8.19', 'v0.8.19+commit.7dd6d404'); downloads it
    when allowed and not installed.
    """
    try:
        version = normalize_version(version)
    except ValueError as e:
        raise SolcNotFound(str(e)) from e
    found = installed_solcs()
    if version in found:
        return found[version]
    if download_allowed(allow_download):
        return download_solc(version)
    have = ", ".join(found) or "none"
    raise SolcNotFound(
        f"solc {version} is not installed (installed: {have}); pass allow_download=True "
        f"or set {DOWNLOAD_ENV}=1 to fetch the official build"
    )


# ---------------------------------------------------------------- downloads


def _platform_dir() -> str:
    system, machine = platform.system(), platform.machine().lower()
    if system == "Linux" and machine in ("x86_64", "amd64"):
        return "linux-amd64"
    if system == "Darwin":
        return "macosx-amd64"  # also runs on arm64 (universal / Rosetta builds)
    if system == "Windows" and machine in ("x86_64", "amd64"):
        return "windows-amd64"
    raise SolcNotFound(f"no official solc build for {system}/{machine}")


def _http_get(url: str, timeout: float) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _release_list(timeout: float = 60) -> dict:
    url = f"{BINARIES_URL}/{_platform_dir()}/list.json"
    try:
        return json.loads(_http_get(url, timeout))
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise SolcNotFound(f"cannot fetch the solc release list {url}: {e}") from e


def available_releases(timeout: float = 60) -> List[str]:
    """Official release versions for this platform (network access), oldest first."""
    return sorted(_release_list(timeout).get("releases", {}), key=version_key)


def download_solc(
    version: str, dest: Optional[Union[str, Path]] = None, timeout: float = 300
) -> str:
    """
    Fetches the official solc `version` build into `dest` (default
    $SCOBELIX_SOLC_DIR, else the user cache dir) and returns its path.
    The file is written atomically, after its sha256 matched the release list
    and the binary reported the expected version.
    """
    listing = _release_list()
    fname = listing.get("releases", {}).get(version)
    if not fname:
        raise SolcNotFound(f"solc {version} is not an official release for {_platform_dir()}")
    build = next((b for b in listing.get("builds", []) if b.get("path") == fname), None)
    if build is None or not build.get("sha256"):
        raise SolcNotFound(f"no checksum published for {fname}")
    url = f"{BINARIES_URL}/{_platform_dir()}/{fname}"
    try:
        blob = _http_get(url, timeout)
    except (urllib.error.URLError, OSError) as e:
        raise SolcNotFound(f"download of {url} failed: {e}") from e
    expected = build["sha256"].lower()
    expected = expected[2:] if expected.startswith("0x") else expected
    if hashlib.sha256(blob).hexdigest() != expected:
        raise SolcNotFound(f"sha256 mismatch for {fname}")
    target_dir = Path(dest).expanduser() if dest else _download_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    suffix = ".exe" if fname.endswith(".exe") else ""
    final = target_dir / f"solc-{version}{suffix}"
    fd, tmp = tempfile.mkstemp(prefix=f".solc-{version}-", dir=str(target_dir))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        os.chmod(tmp, 0o755)
        got = binary_version(tmp)
        if got != version:
            raise SolcNotFound(f"downloaded {fname} reports version {got}, not {version}")
        os.replace(tmp, final)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return str(final)


# ---------------------------------------------------------------- pragmas

_PRAGMA_RE = re.compile(r"\bpragma\s+solidity\s+([^;]+);")
_COMPARATOR_RE = re.compile(
    r"(\^|~|>=|<=|>|<|=)?\s*v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?"
)
_HYPHEN_RE = re.compile(r"^\s*(\S+)\s+-\s+(\S+)\s*$")


def _strip_comments_and_strings(source: str) -> str:
    """Blanks out comments and string literals (so a pragma inside them is ignored)."""
    out, i, n = [], 0, len(source)
    while i < n:
        c = source[i]
        if source.startswith("//", i):
            j = source.find("\n", i)
            i = n if j < 0 else j
        elif source.startswith("/*", i):
            j = source.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        elif c in "\"'":
            j = i + 1
            while j < n and source[j] != c and source[j] != "\n":
                j += 2 if source[j] == "\\" else 1
            i = j + 1
            out.append('""')
        else:
            out.append(c)
            i += 1
    return "".join(out)


def pragma_constraints(source: Union[str, Mapping[str, str]]) -> List[str]:
    """The expressions of every `pragma solidity <expr>;` of a source or a {name: source} map."""
    texts = source.values() if isinstance(source, Mapping) else [source]
    out: List[str] = []
    for text in texts:
        out += [m.group(1).strip() for m in _PRAGMA_RE.finditer(_strip_comments_and_strings(text))]
    return out


def _partial(m: "re.Match") -> List[Optional[int]]:
    """[major, minor, patch] with None for a wildcard / missing component."""
    parts: List[Optional[int]] = []
    for g in m.groups()[1:]:
        if g is None or g in ("x", "X", "*") or (parts and parts[-1] is None):
            parts.append(None)
        else:
            parts.append(int(g))
    return parts


def _bounds(op: str, parts: List[Optional[int]]) -> List[Tuple[str, Tuple[int, int, int]]]:
    """One comparator (operator + possibly partial version) as elementary (op, version) tests."""
    major, minor, patch = parts
    if major is None:
        return []  # "*": anything
    lo = (major, minor or 0, patch or 0)
    if minor is None:
        hi = (major + 1, 0, 0)
    elif patch is None:
        hi = (major, minor + 1, 0)
    else:
        hi = (major, minor, patch + 1)
    if op in ("", "="):
        return [(">=", lo), ("<", hi)]
    if op == "^":
        if major > 0 or minor is None:
            return [(">=", lo), ("<", (major + 1, 0, 0))]
        if minor > 0 or patch is None:
            return [(">=", lo), ("<", (0, minor + 1, 0))]
        return [(">=", lo), ("<", (0, 0, patch + 1))]
    if op == "~":
        return [(">=", lo), ("<", (major + 1, 0, 0) if minor is None else (major, minor + 1, 0))]
    if op == ">":
        return [(">=", hi)]
    if op == ">=":
        return [(">=", lo)]
    if op == "<":
        return [("<", lo)]
    if op == "<=":
        return [("<", hi)]
    raise ValueError(f"unknown comparator {op!r}")


def _range_tests(expr: str) -> List[Tuple[str, Tuple[int, int, int]]]:
    hyphen = _HYPHEN_RE.match(expr)
    if hyphen:
        a, b = (_COMPARATOR_RE.fullmatch(x.strip()) for x in hyphen.groups())
        if not a or not b:
            raise ValueError(f"bad version range {expr!r}")
        return _bounds(">=", _partial(a)) + _bounds("<=", _partial(b))
    tests: List[Tuple[str, Tuple[int, int, int]]] = []
    pos, expr = 0, expr.strip()
    while pos < len(expr):
        if expr[pos].isspace():
            pos += 1
            continue
        m = _COMPARATOR_RE.match(expr, pos)
        if not m or m.end() == pos:
            raise ValueError(f"bad version constraint {expr!r}")
        tests += _bounds(m.group(1) or "", _partial(m))
        pos = m.end()
    return tests


def version_satisfies(version: str, constraint: str) -> bool:
    """npm-style semver match, as solc's `pragma solidity` does it (^ ~ >= <= > < = x || -)."""
    v = version_key(version)
    ops = {">=": v.__ge__, "<": v.__lt__}
    for alternative in constraint.split("||"):
        tests = _range_tests(alternative)
        if all(ops[op](bound) for op, bound in tests):
            return True
    return False


def versions_matching(constraints: Sequence[str], candidates: Iterable[str]) -> List[str]:
    """The candidate versions every constraint accepts, oldest first."""
    return sorted(
        (v for v in candidates if all(version_satisfies(v, c) for c in constraints)),
        key=version_key,
    )


def select_version(
    sources: Union[str, Mapping[str, str]],
    preferred: Optional[str] = None,
    candidates: Optional[Iterable[str]] = None,
) -> Optional[str]:
    """
    The solc version to compile `sources` with: `preferred` when every pragma
    accepts it and it is a candidate, else the newest candidate every pragma
    accepts (candidates default to the installed versions), else None.
    """
    pool = list(candidates) if candidates is not None else list(installed_solcs())
    ok = versions_matching(pragma_constraints(sources), pool)
    if preferred and preferred in ok:
        return preferred
    return ok[-1] if ok else None


def solc_for_source(
    sources: Union[str, Mapping[str, str]],
    preferred: Optional[str] = None,
    allow_download: Optional[bool] = None,
) -> Tuple[str, str]:
    """
    (version, path) of a solc able to compile `sources`: `preferred` if the
    pragmas accept it and it is installed (or downloadable), else the newest
    installed version they accept, else (downloads allowed) the newest
    official release they accept.
    """
    constraints = pragma_constraints(sources)
    installed = installed_solcs()
    ok = versions_matching(constraints, installed)
    download = download_allowed(allow_download)
    if preferred and all(version_satisfies(preferred, c) for c in constraints):
        if preferred in installed:
            return preferred, installed[preferred]
        if download:
            try:
                return preferred, download_solc(preferred)
            except SolcNotFound:
                pass  # not an official release / offline: fall back to what is installed
    if ok:
        return ok[-1], installed[ok[-1]]
    if download:
        releases = versions_matching(constraints, available_releases())
        if releases:
            return releases[-1], download_solc(releases[-1])
    raise SolcNotFound(
        f"no installed solc satisfies {' and '.join(constraints) or 'any version'} "
        f"(installed: {', '.join(installed) or 'none'})"
    )


# ---------------------------------------------------------------- settings


def execution_evm_version(version: str) -> Optional[str]:
    """
    EVM version to compile candidates with so that both execution backends
    (Cancun) can run them: solc >= 0.8.24 defaults to newer forks (0.8.31:
    osaka, whose CLZ opcode the backends lack), so Cancun is pinned there.
    Older compilers' defaults are all Cancun-compatible (None = solc default).
    """
    return "cancun" if version_key(version) >= (0, 8, 24) else None


@dataclasses.dataclass(frozen=True)
class Settings:
    """Compiler settings that change the bytecode (the subset an L4 search explores)."""

    optimize: bool = True
    runs: int = 200
    via_ir: bool = False
    evm_version: Optional[str] = None  # None: the compiler's default
    metadata_hash: Optional[str] = None  # "ipfs" | "bzzr1" | "none" (solc >= 0.6.0)
    append_cbor: bool = True  # False: no CBOR trailer at all (solc >= 0.8.18)

    @property
    def label(self) -> str:
        parts = ["viaIR"] if self.via_ir else []
        parts.append(f"opt{self.runs}" if self.optimize else "noopt")
        if self.evm_version:
            parts.append(self.evm_version)
        return "-".join(parts)

    def to_json(self, version: str, ast: bool = False) -> dict:
        """The standard-json `settings` object for solc `version`."""
        outputs = [
            "abi",
            "evm.bytecode.object",
            "evm.deployedBytecode.object",
            "evm.deployedBytecode.linkReferences",
            "evm.methodIdentifiers",
        ]
        if version_key(version) >= (0, 6, 5):
            outputs.append("evm.deployedBytecode.immutableReferences")
        if version_key(version) >= (0, 5, 13):
            outputs.append("storageLayout")
        selection: Dict[str, List[str]] = {"*": outputs}
        if ast:
            selection[""] = ["ast"]
        out: dict = {
            "optimizer": {"enabled": bool(self.optimize), "runs": int(self.runs)},
            "outputSelection": {"*": selection},
        }
        if self.via_ir:
            out["viaIR"] = True
        if self.evm_version:
            out["evmVersion"] = self.evm_version
        metadata: dict = {}
        if self.metadata_hash:
            metadata["bytecodeHash"] = self.metadata_hash
        if not self.append_cbor:
            metadata["appendCBOR"] = False
        if metadata:
            out["metadata"] = metadata
        return out

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def optimizer_variants(version: str, evm_version: Optional[str] = None) -> List[Settings]:
    """The settings an L4 search tries, most common first (viaIR from 0.8.13)."""
    out = [
        Settings(optimize=opt, runs=runs, evm_version=evm_version)
        for opt, runs in (
            (True, 200),
            (False, 200),
            (True, 1),
            (True, 1000),
            (True, 10000),
            (True, 1000000),
        )
    ]
    if version_key(version) >= (0, 8, 13):
        out += [Settings(True, runs, True, evm_version) for runs in (200, 1, 10000)]
    return out


# ---------------------------------------------------------------- compilation


@dataclasses.dataclass
class Artifact:
    """One compiled contract."""

    name: str  # "file.sol:Contract"
    abi: list
    creation: bytes  # bytecode.object, library placeholders zero-filled
    runtime: bytes  # deployedBytecode.object (immutables zero, placeholders zero-filled)
    immutable_refs: Dict[str, List[Dict[str, int]]]  # AST id -> [{start, length}]
    link_refs: Dict[str, Dict[str, List[Dict[str, int]]]]  # file -> library -> [{start, length}]
    method_ids: Dict[str, str]  # "transfer(address,uint256)" -> "a9059cbb"
    storage_layout: Optional[dict]  # solc storageLayout (>= 0.5.13), else None
    version: str
    settings: Settings
    immutable_names: Dict[str, str] = dataclasses.field(default_factory=dict)  # AST id -> name

    @property
    def contract_name(self) -> str:
        return self.name.rsplit(":", 1)[-1]

    @property
    def selectors(self) -> Dict[int, str]:
        """selector -> canonical signature."""
        return {int(sel, 16): sig for sig, sel in self.method_ids.items()}


@dataclasses.dataclass
class Compilation:
    """The artifacts of one `--standard-json` run plus its warnings."""

    version: str
    solc_path: str
    settings: Settings
    artifacts: Dict[str, Artifact]
    warnings: List[str]

    def artifact(self, name: Optional[str] = None) -> Artifact:
        """
        The artifact called `name` ("Contract" or "file.sol:Contract").
        Without a name: the only contract with runtime code, if there is one.
        """
        if name is None:
            deployable = [a for a in self.artifacts.values() if a.runtime]
            if len(deployable) == 1:
                return deployable[0]
            raise KeyError(f"several contracts compiled, pass a name: {sorted(self.artifacts)}")
        if name in self.artifacts:
            return self.artifacts[name]
        matches = [a for a in self.artifacts.values() if a.contract_name == name]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise KeyError(f"contract {name!r} not found in {sorted(self.artifacts)}")
        raise KeyError(f"contract name {name!r} is ambiguous: {sorted(a.name for a in matches)}")


_PLACEHOLDER_RE = re.compile(r"__.{36}__")  # 0.4: "__Lib____..__", >= 0.5: "__$<34 hex>$__"

# solc's stdout per (binary identity, sha256 of the standard-json input), least recently used
# first; bounded by the total size of the outputs kept
COMPILE_CACHE_BYTES = 64 << 20
_compile_cache: "collections.OrderedDict[tuple, str]" = collections.OrderedDict()
_compile_cache_size = 0
_compile_cache_lock = threading.Lock()


def clear_compile_cache() -> None:
    """Forgets every cached solc output."""
    global _compile_cache_size
    with _compile_cache_lock:
        _compile_cache.clear()
        _compile_cache_size = 0


def _standard_json_output(solc_path: str, std_json: str, version: str, timeout: float) -> str:
    """solc's stdout for `std_json`, from the cache when this binary already compiled it."""
    global _compile_cache_size
    try:
        real = os.path.realpath(solc_path)
        st = os.stat(real)
        key: Optional[tuple] = (
            real,
            st.st_mtime_ns,
            st.st_size,
            hashlib.sha256(std_json.encode()).digest(),
        )
    except OSError:
        key = None
    if key is not None:
        with _compile_cache_lock:
            cached = _compile_cache.get(key)
            if cached is not None:
                _compile_cache.move_to_end(key)
                return cached
    try:
        proc = subprocess.run(
            [solc_path, "--standard-json"],
            input=std_json,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise CompilationError(
            [{"message": f"solc {version} timed out after {timeout}s"}], version
        ) from e
    except OSError as e:
        raise SolcNotFound(f"cannot run {solc_path}: {e}") from e
    if not proc.stdout.strip():
        raise CompilationError(
            [
                {
                    "message": f"empty output from {solc_path} (rc={proc.returncode}): "
                    f"{proc.stderr[:500]}"
                }
            ],
            version,
        )
    if key is not None and len(proc.stdout) <= COMPILE_CACHE_BYTES:
        with _compile_cache_lock:
            if key not in _compile_cache:  # another thread may have compiled it meanwhile
                _compile_cache[key] = proc.stdout
                _compile_cache_size += len(proc.stdout)
            while _compile_cache_size > COMPILE_CACHE_BYTES and _compile_cache:
                _, old = _compile_cache.popitem(last=False)
                _compile_cache_size -= len(old)
    return proc.stdout


def _unhex(obj: Optional[str]) -> bytes:
    # hex digits never contain "_", so every "__...__" run is a 20-byte link placeholder
    return bytes.fromhex(_PLACEHOLDER_RE.sub("0" * 40, obj or ""))


def _immutable_names(sources_out: dict) -> Dict[str, str]:
    names: Dict[str, str] = {}

    def walk(node):
        if isinstance(node, dict):
            if (
                node.get("nodeType") == "VariableDeclaration"
                and node.get("mutability") == "immutable"
            ):
                names[str(node.get("id"))] = node.get("name", "")
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    for src in sources_out.values():
        walk(src.get("ast"))
    return names


def compile_standard_json(
    sources: Union[str, Mapping[str, str]],
    settings: Optional[Settings] = None,
    *,
    version: Optional[str] = None,
    solc_path: Optional[str] = None,
    allow_download: Optional[bool] = None,
    want_ast: bool = False,
    timeout: float = 300,
) -> Compilation:
    """
    Compiles `sources` (one source text, or {file name: text}) with
    `--standard-json`.  The compiler is `solc_path`, else solc `version`, else
    the version `select_version` picks from the pragmas.  Raises SolcNotFound
    or CompilationError (with solc's error objects); warnings are returned.
    """
    if isinstance(sources, str):
        sources = {"Contract.sol": sources}
    settings = settings or Settings()
    if version is not None:
        try:
            version = normalize_version(version)
        except ValueError as e:
            raise SolcNotFound(str(e)) from e
    if solc_path is None:
        if version is None:
            version, solc_path = solc_for_source(sources, allow_download=allow_download)
        else:
            solc_path = find_solc(version, allow_download)
    elif version is None:
        version = binary_version(solc_path)
        if version is None:
            raise SolcNotFound(f"{solc_path} is not a solc release binary")
    want_ast = want_ast or any("immutable" in text for text in sources.values())
    std_input = {
        "language": "Solidity",
        "sources": {name: {"content": text} for name, text in sources.items()},
        "settings": settings.to_json(version, ast=want_ast),
    }
    stdout = _standard_json_output(solc_path, json.dumps(std_input), version, timeout)
    try:
        out = json.loads(stdout)
    except ValueError as e:
        raise CompilationError(
            [{"message": f"unparsable solc output: {stdout[:300]}"}], version
        ) from e
    diagnostics = out.get("errors", []) or []
    errors = [e for e in diagnostics if e.get("severity") == "error"]
    if errors:
        raise CompilationError(errors, version)
    names = _immutable_names(out.get("sources", {}) or {}) if want_ast else {}
    artifacts: Dict[str, Artifact] = {}
    for fname, contracts in (out.get("contracts") or {}).items():
        for cname, c in contracts.items():
            evm = c.get("evm", {}) or {}
            dep = evm.get("deployedBytecode", {}) or {}
            refs = dep.get("immutableReferences", {}) or {}
            artifacts[f"{fname}:{cname}"] = Artifact(
                name=f"{fname}:{cname}",
                abi=c.get("abi", []) or [],
                creation=_unhex((evm.get("bytecode", {}) or {}).get("object")),
                runtime=_unhex(dep.get("object")),
                immutable_refs=refs,
                link_refs=dep.get("linkReferences", {}) or {},
                method_ids=evm.get("methodIdentifiers", {}) or {},
                storage_layout=c.get("storageLayout"),
                version=version,
                settings=settings,
                immutable_names={k: v for k, v in names.items() if k in refs},
            )
    if not artifacts:
        raise CompilationError([{"message": "solc produced no contract"}], version)
    warnings = [_error_text(e) for e in diagnostics if e.get("severity") != "error"]
    return Compilation(version, solc_path, settings, artifacts, warnings)

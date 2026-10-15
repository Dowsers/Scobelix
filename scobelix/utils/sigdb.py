"""
Signature database: names and types for function selectors, event topics
and custom-error selectors.

Three namespaces, each keyed the way the EVM sees the value:

- functions: 4-byte selector (calldata[0:4], CALL payload prefix),
- events:    full 32-byte topic0 (LOGn first topic),
- errors:    4-byte selector (first word of a REVERT payload).

Every entry is keccak-verified: the canonical signature `name(type,...)` must
hash to its key, so a lookup never returns a name whose selector differs from
the queried one. Placeholder rows of the bundled dump (`unknownXXXXXXXX`,
no name information) are dropped. A key may have several candidates (true
4-byte collisions, or the same signature with different outputs or indexed
flags, e.g. the ERC-20 and ERC-721 `Transfer` events); they are returned
best first.

The database is built once, from the files under `scobelix/data/` plus the
built-in `LOCAL_SIGS` table, into a read-only SQLite file in the user cache
directory named `sigdb-<schema>-<datahash>.sqlite`, so a change of any input
or of the format selects a new file. The build writes a temporary file and
renames it into place under an exclusive lock file, so concurrent processes
never see a partial database and build it only once. Readers open the file
with `mode=ro&immutable=1`: no lock, no journal, safe in parallel. The
environment variable SCOBELIX_SIGDB can point to a prebuilt (or to be built)
file instead; a file there that is not a SQLite database is never replaced
(the database is then unavailable). Lookups never touch the network.

Sources, in decreasing order of trust (used to rank colliding signatures and
to pick outputs and mutability):

1. builtin: `scobelix.utils.supplement.LOCAL_SIGS` (hand-written, functions),
2. curated: `data/extra_sigs.json` (ABIs of standard interfaces and of
   widely used libraries: functions with outputs and mutability, events
   with indexed flags, custom errors),
3. dump:    `data/abi_dump.xz` (one ABI per 4-byte key: functions, events
   keyed by topic0[:4], errors, and untyped signatures of text lists),
4. local:   `data/local_sigs.json` (functions, see tools/build_local_sigs.py).

Parameter names of one signature come from builtin, then dump, then curated,
then local (the historical lookup order), skipping empty or synthetic names.

Candidates are plain dicts shaped like ABI JSON entries ("type", "name",
"inputs" and, when known, "outputs"/"stateMutability"; "outputs" is None
when unknown) with extra keys: "signature", "selector" or "topic0" (hex),
"sources", "generic_names" (some parameter names are synthetic or empty),
"untyped" (the kind is unknown: an untyped source, or, in error and event
lookups, a signature of another kind with the same hash) and "library"
(non-ABI parameter types of library functions, such as `Lib.Data storage`).
Parameter types are canonical (`uint` is `uint256`); a tuple is `tuple`
with "components", or written out (`(address,bytes)[]`) when the source
gave it so.
"""

import contextlib
import errno
import hashlib
import json
import logging
import lzma
import os
import re
import sqlite3
import stat
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms build unlocked
    fcntl = None

logger = logging.getLogger(__name__)

# part of the file name: bump it whenever the tables or the build rules change
SCHEMA_VERSION = 2

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DUMP_PATH = DATA_DIR / "abi_dump.xz"
LOCAL_SIGS_PATH = DATA_DIR / "local_sigs.json"
EXTRA_SIGS_PATH = DATA_DIR / "extra_sigs.json"

ENV_PATH = "SCOBELIX_SIGDB"

SOURCE_BUILTIN = "builtin"
SOURCE_CURATED = "curated"
SOURCE_DUMP = "dump"
SOURCE_LOCAL = "local"
# trust order: ranks candidates and picks outputs/mutability
_SOURCE_PRIORITY = {SOURCE_BUILTIN: 0, SOURCE_CURATED: 1, SOURCE_DUMP: 2, SOURCE_LOCAL: 3}
# parameter names follow the historical lookup order, so the decompiler keeps
# printing the names it printed before; curated names fill generic ones
_NAMES_PRIORITY = {SOURCE_BUILTIN: 0, SOURCE_DUMP: 1, SOURCE_CURATED: 2, SOURCE_LOCAL: 3}

FLAG_GENERIC_NAMES = 1
FLAG_UNTYPED = 2
FLAG_LIBRARY = 4

FUNCTION = "function"
EVENT = "event"
ERROR = "error"
KINDS = (FUNCTION, EVENT, ERROR)

MUTABILITIES = ("pure", "view", "nonpayable", "payable")

_SCHEMA_SQL = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE functions (
    selector INTEGER NOT NULL,
    rank INTEGER NOT NULL,
    signature TEXT NOT NULL,
    inputs TEXT NOT NULL,
    outputs TEXT,
    mutability TEXT,
    sources TEXT NOT NULL,
    flags INTEGER NOT NULL,
    PRIMARY KEY (selector, rank)
) WITHOUT ROWID;
CREATE TABLE events (
    topic0 BLOB NOT NULL,
    rank INTEGER NOT NULL,
    signature TEXT NOT NULL,
    inputs TEXT NOT NULL,
    anonymous INTEGER NOT NULL,
    sources TEXT NOT NULL,
    flags INTEGER NOT NULL,
    PRIMARY KEY (topic0, rank)
) WITHOUT ROWID;
CREATE TABLE errors (
    selector INTEGER NOT NULL,
    rank INTEGER NOT NULL,
    signature TEXT NOT NULL,
    inputs TEXT NOT NULL,
    sources TEXT NOT NULL,
    flags INTEGER NOT NULL,
    PRIMARY KEY (selector, rank)
) WITHOUT ROWID;
"""

# ---------------------------------------------------------------------------
# hashing and canonical ABI types


_keccak = None


def keccak256(data: Union[bytes, str]) -> bytes:
    """Keccak-256 (the Ethereum variant, not NIST SHA3-256) of `data`."""
    global _keccak
    if _keccak is None:
        from eth_hash.auto import keccak

        _keccak = keccak
    if isinstance(data, str):
        data = data.encode("utf-8")
    return _keccak(data)


def function_selector(signature: str) -> int:
    """4-byte selector of a canonical signature, e.g. 'transfer(address,uint256)'."""
    return int.from_bytes(keccak256(signature)[:4], "big")


def event_topic(signature: str) -> int:
    """topic0 of a (non-anonymous) event with this canonical signature."""
    return int.from_bytes(keccak256(signature), "big")


_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_GENERIC_NAME = re.compile(r"_?(?:param|arg|p)?[0-9]*\Z")
_ARRAY_SUFFIX = re.compile(r"((?:\[[0-9]*\])*)\Z")
_INT_TYPE = re.compile(r"u?int([1-9][0-9]*)\Z")
_BYTES_TYPE = re.compile(r"bytes([1-9][0-9]*)\Z")
_FIXED_TYPE = re.compile(r"u?fixed([1-9][0-9]*)x([0-9]+)\Z")
_ELEMENTARY_ALIASES = {
    "uint": "uint256",
    "int": "int256",
    "byte": "bytes1",
    "fixed": "fixed128x18",
    "ufixed": "ufixed128x18",
}
_type_cache = {}  # type: Dict[str, Tuple[Optional[str], bool, str]]


def _canonical_elementary(t: str) -> Optional[str]:
    """Canonical spelling of an elementary ABI type, None if `t` is not one."""
    if t in ("address", "bool", "string", "bytes", "function"):
        return t
    if t in _ELEMENTARY_ALIASES:
        return _ELEMENTARY_ALIASES[t]
    m = _INT_TYPE.match(t)
    if m and int(m.group(1)) % 8 == 0 and int(m.group(1)) <= 256:
        return t
    m = _BYTES_TYPE.match(t)
    if m and int(m.group(1)) <= 32:
        return t
    m = _FIXED_TYPE.match(t)
    if m and int(m.group(1)) % 8 == 0 and int(m.group(1)) <= 256 and int(m.group(2)) <= 80:
        return t
    return None


def _split_types(inner: str) -> List[str]:
    """Split a comma-separated type list at the top level of parentheses."""
    types, depth, start = [], 0, 0
    for i, ch in enumerate(inner):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            types.append(inner[start:i])
            start = i + 1
    if inner:
        types.append(inner[start:])
    return types


def _type_info(t: str) -> Tuple[Optional[str], bool, str]:
    """(canonical type or None, is a `tuple` with components, array suffix)
    of a type string. Tuples may also be written out, `(address,uint256)[]`
    (untyped signature lists do so)."""
    info = _type_cache.get(t)
    if info is None:
        suffix = _ARRAY_SUFFIX.search(t).group(1)
        base = t[: len(t) - len(suffix)]
        if base == "tuple":
            info = (None, True, suffix)
        elif base.startswith("(") and base.endswith(")"):
            parts = [_type_info(x)[0] for x in _split_types(base[1:-1])]
            ok = None not in parts and base.count("(") == base.count(")")
            info = ("(" + ",".join(parts) + ")" + suffix if ok else None, False, suffix)
        else:
            elem = _canonical_elementary(base)
            info = (None if elem is None else elem + suffix, False, suffix)
        if len(_type_cache) < 65536:
            _type_cache[t] = info
    return info


class _Rejected(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _parse_params(params, with_indexed=False) -> Tuple[List[dict], Optional[List[str]], List[str]]:
    """Normalise ABI parameters in one pass.

    Returns (params reduced to name/type/components(/indexed), canonical types
    or None when some type is not an ABI type, types as written with tuples
    expanded). Raises _Rejected on malformed input.
    """
    if not isinstance(params, list):
        raise _Rejected("bad-params")
    out, canon, given = [], [], []
    for p in params:
        t = p.get("type") if isinstance(p, dict) else None
        if not isinstance(t, str):
            raise _Rejected("bad-params")
        ctype, is_tuple, suffix = _type_info(t)
        q = {"name": p.get("name") or "", "type": ctype or t}
        if is_tuple:
            comps, ccanon, cgiven = _parse_params(p.get("components"))
            q["components"] = comps
            ctype = None if ccanon is None else "(" + ",".join(ccanon) + ")" + suffix
            given.append("(" + ",".join(cgiven) + ")" + suffix)
        else:
            given.append(t)
        if with_indexed:
            q["indexed"] = bool(p.get("indexed"))
        out.append(q)
        if canon is not None:
            if ctype is None:
                canon = None
            else:
                canon.append(ctype)
    return out, canon, given


def canonical_type(param: dict) -> Optional[str]:
    """Canonical ABI type of an ABI parameter (tuples expanded), or None when
    the type is not a valid ABI type (e.g. `Lib.Data storage`)."""
    try:
        _, canon, _ = _parse_params([param])
    except _Rejected:
        return None
    return None if canon is None else canon[0]


def canonical_signature(name: str, inputs: Sequence[dict]) -> Optional[str]:
    """`name(type,...)` with canonical ABI types, None if a type is invalid."""
    try:
        _, canon, _ = _parse_params(list(inputs))
    except _Rejected:
        return None
    return None if canon is None else name + "(" + ",".join(canon) + ")"


def signature_types(signature: str) -> List[str]:
    """Top-level parameter types of a canonical signature."""
    return _split_types(signature[signature.index("(") + 1 : -1])


def _canonical_type_string(t: str) -> str:
    """Canonical spelling of a type given as a string ('uint' -> 'uint256')."""
    return canonical_type({"type": t}) or t


def _is_generic(params: Sequence[dict]) -> bool:
    """True when some parameter name is empty or synthetic (`_param1`...)."""
    return any(_GENERIC_NAME.match(p["name"]) for p in params)


# ---------------------------------------------------------------------------
# normalisation of source entries


class _Entry:
    """One verified signature from one source, before merging."""

    __slots__ = (
        "kind", "key", "signature", "inputs", "outputs", "mutability", "anonymous",
        "group", "source", "prio", "order", "generic", "untyped", "library",
    )


def _mutability(abi: dict) -> Optional[str]:
    """stateMutability when the ABI comes from a compiler (it has outputs);
    entries without outputs carry synthetic defaults and are not trusted."""
    if "outputs" not in abi:
        return None
    sm = abi.get("stateMutability")
    if sm in MUTABILITIES:
        return sm
    if "constant" in abi or "payable" in abi:  # pre-0.4.16 ABI flags
        if abi.get("payable"):
            return "payable"
        return "view" if abi.get("constant") else "nonpayable"
    return None


def _make_entry(abi: dict, kind: Optional[str], source: str, expected_key=None) -> _Entry:
    """Normalise and keccak-verify one ABI-like entry.

    `kind` None means an untyped signature (from a text signature list),
    stored as a function. `expected_key` is the 4-byte key the source filed it under
    (an int); entries whose signature does not hash to it are rejected.
    """
    name = abi.get("name")
    if not isinstance(name, str) or not _IDENTIFIER.match(name):
        raise _Rejected("bad-name")
    if (
        expected_key is not None
        and name.startswith("unknown")
        and name.lower() == "unknown%08x" % expected_key
    ):
        raise _Rejected("placeholder")  # name made up from the key, no information
    event = kind == EVENT
    params = abi.get("inputs", [])
    if kind is None and isinstance(params, list) and len(params) == 1:
        if isinstance(params[0], dict) and params[0].get("type") == "":
            params = []  # `f()` of a text signature list, read as one empty parameter
    inputs, canon, given = _parse_params(params, with_indexed=event)
    library = canon is None
    if library and kind not in (FUNCTION, None):
        raise _Rejected("bad-params")
    signature = name + "(" + ",".join(given if library else canon) + ")"
    digest = keccak256(signature)
    if expected_key is not None and int.from_bytes(digest[:4], "big") != expected_key:
        raise _Rejected("keccak-mismatch")

    e = _Entry()
    e.kind = kind or FUNCTION
    e.key = digest if event else int.from_bytes(digest[:4], "big")
    e.signature = signature
    e.inputs = inputs
    e.outputs = None
    e.mutability = None
    e.anonymous = bool(abi.get("anonymous")) if event else False
    e.group = ()
    if e.kind == FUNCTION:
        e.group = None  # outputs unknown
        if kind is not None and "outputs" in abi:
            outputs, ocanon, ogiven = _parse_params(abi["outputs"])
            # outside library ABIs, outputs that are not ABI types (contract
            # or enum names of hand-written ABIs) are unknown outputs
            if ocanon is not None or library:
                e.outputs = outputs
                e.group = tuple(ogiven if ocanon is None else ocanon)
            e.mutability = _mutability(abi)
    elif event:
        e.group = tuple(p["indexed"] for p in inputs)
    e.source = source
    e.prio = _SOURCE_PRIORITY[source]
    e.order = 0
    e.generic = _is_generic(inputs)
    e.untyped = kind is None
    e.library = library
    return e


def _key_int(value, width: int) -> int:
    if isinstance(value, (bytes, bytearray)):
        value = int.from_bytes(value, "big")
    elif isinstance(value, str):
        value = int(value, 16)
    if not isinstance(value, int) or value < 0 or value >= 1 << (8 * width):
        raise ValueError("not a %d-byte key: %r" % (width, value))
    return value


# Source readers: (items, decode) where decode(item) gives (abi, kind, key)
# or None to skip the item; decode errors count as malformed entries.


def _read_selector_table(table: Dict[str, dict]):
    """`{"0x12345678": {"name": ..., "inputs": [...]}}` tables (functions)."""
    return table.items(), lambda kv: (kv[1], FUNCTION, _key_int(kv[0], 4))


def _read_selector_json(path: Path):
    return _read_selector_table(json.loads(Path(path).read_text(encoding="utf-8")))


def _read_curated(path: Path):
    """`{"abi": [ABI entries]}`: entries are keyed by their own signature."""

    def decode(abi):
        kind = abi["type"]
        return (abi, kind, None) if kind in KINDS else None

    return json.loads(Path(path).read_text(encoding="utf-8"))["abi"], decode


def _read_dump(path: Path):
    """JSON lines `{"selector": "0x........", "abi": {...}}`; events are filed
    under the first 4 bytes of their topic0, untyped entries have no type."""

    def lines():
        with lzma.open(str(path), "rt", encoding="utf-8") as f:
            yield from f

    def decode(line):
        # a quarter of the dump is `"name": "unknown<selector>"` rows:
        # recognise them without parsing (_make_entry rejects them)
        if line.startswith('{"selector": "0x') and ('"name": "unknown%s"' % line[16:24]) in line:
            return {"name": "unknown" + line[16:24]}, FUNCTION, _key_int(line[16:24], 4)
        d = json.loads(line)
        abi = d["abi"]
        kind = abi.get("type")
        return abi, (kind if kind in KINDS else None), _key_int(d["selector"], 4)

    return lines(), decode


# ---------------------------------------------------------------------------
# merging


def _merge(entries: List[_Entry]) -> List[Tuple[_Entry, List[_Entry]]]:
    """Group the entries of one (namespace, key) into ranked candidates.

    A candidate is one signature with one outputs list (functions) or one
    indexed pattern (events). Function entries with unknown outputs join the
    only known-outputs candidate of their signature when there is exactly
    one; otherwise they form their own candidate. Returns
    [(representative, members)] best first.
    """
    entries = sorted(entries, key=lambda e: (e.prio, e.order))
    groups = {}  # type: Dict[tuple, List[_Entry]]
    for e in entries:
        groups.setdefault((e.signature, e.group), []).append(e)
    if entries[0].kind == FUNCTION:
        for sig in {e.signature for e in entries}:
            known = [g for (s, g) in groups if s == sig and g is not None]
            if len(known) == 1 and (sig, None) in groups:
                groups[(sig, known[0])].extend(groups.pop((sig, None)))
                groups[(sig, known[0])].sort(key=lambda e: (e.prio, e.order))

    # different signatures (4-byte collisions) are ranked by trust; variants
    # of one signature (outputs, indexed flags) by the names order, so the
    # first candidate keeps the historical names
    trust = {}
    for e in entries:
        trust[e.signature] = min(trust.get(e.signature, e.prio), e.prio)
    ranked = []
    for members in groups.values():
        untyped = all(m.untyped for m in members)
        names = min(_NAMES_PRIORITY[m.source] for m in members)
        ranked.append(((untyped, trust[members[0].signature], names, members[0].order), members))
    ranked.sort(key=lambda r: r[0])
    return [(_representative(members), members) for _, members in ranked]


def _representative(members: List[_Entry]) -> _Entry:
    named = sorted((m for m in members if not m.generic), key=lambda m: _NAMES_PRIORITY[m.source])
    src = named[0] if named else members[0]
    rep = _Entry()
    for attr in _Entry.__slots__:
        setattr(rep, attr, getattr(src, attr))
    for m in members:
        if m.outputs is not None:
            rep.outputs = m.outputs
            break
    for m in members:
        if m.mutability is not None:
            rep.mutability = m.mutability
            break
    rep.untyped = all(m.untyped for m in members)
    return rep


def _sources_csv(members: List[_Entry]) -> str:
    seen = []
    for m in members:
        if m.source not in seen:
            seen.append(m.source)
    return ",".join(seen)


_JSON = json.JSONEncoder(separators=(",", ":"))


def _encode_inputs(kind: str, inputs: List[dict]) -> str:
    """JSON of the inputs; for functions and errors without tuples, only the
    names (the types are those of the signature)."""
    if kind != EVENT and all(len(p) == 2 for p in inputs):
        return _JSON.encode([p["name"] for p in inputs])
    return _JSON.encode(inputs)


def _decode_inputs(text: str, signature: str) -> List[dict]:
    value = json.loads(text)
    if value and isinstance(value[0], str):
        return [{"name": n, "type": t} for n, t in zip(value, signature_types(signature))]
    return value


def _row(rep: _Entry, rank: int, sources: str) -> Tuple[str, tuple]:
    flags = (
        (FLAG_GENERIC_NAMES if rep.generic else 0)
        | (FLAG_UNTYPED if rep.untyped else 0)
        | (FLAG_LIBRARY if rep.library else 0)
    )
    inputs = _encode_inputs(rep.kind, rep.inputs)
    if rep.kind == FUNCTION:
        outputs = None if rep.outputs is None else _JSON.encode(rep.outputs)
        row = (rep.key, rank, rep.signature, inputs, outputs, rep.mutability, sources, flags)
        return "functions", row
    if rep.kind == EVENT:
        return "events", (rep.key, rank, rep.signature, inputs, int(rep.anonymous), sources, flags)
    return "errors", (rep.key, rank, rep.signature, inputs, sources, flags)


_INSERT = {
    "functions": "INSERT INTO functions VALUES (?,?,?,?,?,?,?,?)",
    "events": "INSERT INTO events VALUES (?,?,?,?,?,?,?)",
    "errors": "INSERT INTO errors VALUES (?,?,?,?,?,?)",
}


# ---------------------------------------------------------------------------
# building


def default_sources() -> dict:
    """The sources bundled with scobelix (missing files are skipped)."""
    from scobelix.utils.supplement import LOCAL_SIGS

    return {
        SOURCE_BUILTIN: LOCAL_SIGS,
        SOURCE_CURATED: EXTRA_SIGS_PATH,
        SOURCE_DUMP: DUMP_PATH,
        SOURCE_LOCAL: LOCAL_SIGS_PATH,
    }


def data_hash(sources: dict) -> str:
    """Content hash of the build inputs (and of the database format)."""
    h = hashlib.sha256(b"scobelix-sigdb-%d" % SCHEMA_VERSION)
    for name in sorted(sources):
        value = sources[name]
        h.update(b"\0" + name.encode() + b"\0")
        if value is None:
            h.update(b"<none>")
        elif isinstance(value, dict):
            h.update(json.dumps(value, sort_keys=True).encode())
        elif Path(value).is_file():
            with open(value, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
        else:
            h.update(b"<missing>")
    return h.hexdigest()[:16]


def build(dest: Union[str, Path], sources: Optional[dict] = None) -> dict:
    """Build a database at `dest` (atomically replacing it) and return stats.

    `sources` maps "builtin" to a `{selector: {"name", "inputs"}}` dict and
    "curated" / "dump" / "local" to file paths (see the module docstring for
    their formats); absent or None sources are skipped.
    """
    sources = default_sources() if sources is None else sources
    dest = Path(dest)
    t0 = time.time()
    stats = {"rejected": {}, "accepted": {}, "rows": {}}
    tmp = dest.with_name("%s.tmp-%d-%x" % (dest.name, os.getpid(), int(t0 * 1e6) & 0xFFFFFF))
    try:
        conn = sqlite3.connect(str(tmp), isolation_level=None)
        try:
            for pragma in (
                "journal_mode=OFF",
                "synchronous=OFF",
                "locking_mode=EXCLUSIVE",
                "temp_store=MEMORY",
                "cache_size=-65536",
            ):
                conn.execute("PRAGMA " + pragma)
            conn.executescript(_SCHEMA_SQL)
            conn.execute("BEGIN")
            _fill(conn, sources, stats)
            stats["build_seconds"] = round(time.time() - t0, 2)
            meta = {
                "schema": str(SCHEMA_VERSION),
                "data_hash": data_hash(sources),
                "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "stats": json.dumps(stats, sort_keys=True),
                "complete": "1",
            }
            conn.executemany("INSERT INTO meta VALUES (?,?)", sorted(meta.items()))
            conn.execute("COMMIT")
        finally:
            conn.close()
        with open(tmp, "rb") as f:
            os.fsync(f.fileno())
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            tmp.unlink()
    logger.info("signature database %s built in %.1fs", dest, time.time() - t0)
    return stats


def _fill(conn, sources: dict, stats: dict):
    """Verify every source entry and insert the merged rows.

    The small sources are held in memory; the dump is streamed and its
    entries are written directly unless a small source shares their key.
    """
    counter = [0]

    def entries(source, reader):
        rejected = stats["rejected"].setdefault(source, {})
        items, decode = reader
        for item in items:
            try:
                record = decode(item)
                if record is None:
                    continue
                e = _make_entry(record[0], record[1], source, record[2])
            except _Rejected as r:
                rejected[r.reason] = rejected.get(r.reason, 0) + 1
                continue
            except (KeyError, TypeError, ValueError, AttributeError):
                rejected["malformed"] = rejected.get("malformed", 0) + 1
                continue
            counter[0] += 1
            e.order = counter[0]
            stats["accepted"][source] = stats["accepted"].get(source, 0) + 1
            yield e

    readers = {
        SOURCE_BUILTIN: _read_selector_table,
        SOURCE_CURATED: _read_curated,
        SOURCE_LOCAL: _read_selector_json,
    }
    for source, value in sorted(sources.items()):
        if value is not None and not isinstance(value, dict) and not Path(value).is_file():
            # a partial installation: the database is built without it
            logger.warning("signature source %s not found: %s", source, value)

    small = {}  # type: Dict[tuple, List[_Entry]]
    for source in (SOURCE_BUILTIN, SOURCE_CURATED, SOURCE_LOCAL):
        value = sources.get(source)
        if value is None or (not isinstance(value, dict) and not Path(value).is_file()):
            continue
        for e in entries(source, readers[source](value)):
            small.setdefault((e.kind, e.key), []).append(e)

    batches = {"functions": [], "events": [], "errors": []}

    def put(table, row):
        batch = batches[table]
        batch.append(row)
        stats["rows"][table] = stats["rows"].get(table, 0) + 1
        if len(batch) >= 20000:
            conn.executemany(_INSERT[table], batch)
            batch.clear()

    dump = sources.get(SOURCE_DUMP)
    if dump is not None and Path(dump).is_file():
        for e in entries(SOURCE_DUMP, _read_dump(Path(dump))):
            pending = small.get((e.kind, e.key))
            if pending is not None:
                pending.append(e)
            else:
                put(*_row(e, 0, e.source))

    for key in sorted(small, key=lambda k: (k[0], k[1])):
        for rank, (rep, members) in enumerate(_merge(small[key])):
            put(*_row(rep, rank, _sources_csv(members)))

    for table, batch in batches.items():
        if batch:
            conn.executemany(_INSERT[table], batch)
    stats["rejected"] = {k: v for k, v in stats["rejected"].items() if v}


@contextlib.contextmanager
def _exclusive_lock(path: Path):
    """Exclusive advisory lock on `path` (no-op where fcntl is unavailable)."""
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o644)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def ensure_built(dest: Union[str, Path], sources: Optional[dict] = None) -> Path:
    """Return `dest`, building it first if it is missing or unusable.

    Only a signature database is ever replaced (an incomplete one, or one of
    another schema): any other file at `dest` - a path set by mistake, say a
    data file - raises FileExistsError and is left untouched, nothing is
    created next to it.  Safe to call from many processes at once: one
    builds, the others wait for the lock and then reuse the result.
    """
    dest = Path(dest)
    if _is_complete(dest):
        return dest
    _check_replaceable(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with _exclusive_lock(dest.with_name(dest.name + ".lock")):
        if not _is_complete(dest):
            _check_replaceable(dest)
            _remove_stale_temporaries(dest)
            build(dest, sources)
    return dest


_SQLITE_HEADER = b"SQLite format 3\x00"


def _check_replaceable(dest: Path) -> None:
    """Raise FileExistsError unless `dest` is absent, an empty file or a
    signature database (a SQLite database with this module's `meta` table:
    another program's SQLite database is not one)."""
    try:
        st = dest.stat()
    except FileNotFoundError:
        return
    if stat.S_ISREG(st.st_mode):
        if st.st_size == 0:
            return
        with open(dest, "rb") as f:
            sqlite = f.read(len(_SQLITE_HEADER)) == _SQLITE_HEADER
        if sqlite and _has_meta_table(dest):
            return
    raise FileExistsError(
        errno.EEXIST, "not a signature database: refusing to replace it", str(dest)
    )


def _has_meta_table(path: Path) -> bool:
    """`path` (a SQLite database) has the `meta` table every signature database has."""
    try:
        conn = _connect_ro(path)
        try:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'"
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return False  # unreadable: nothing tells it is one
    return row is not None


def _remove_stale_temporaries(dest: Path, max_age: float = 3600.0):
    """Delete temporary files left by interrupted builds of `dest`. Only old
    ones: without fcntl the lock is a no-op and another build may be running."""
    for p in dest.parent.glob(dest.name + ".tmp-*"):
        with contextlib.suppress(OSError):
            if time.time() - p.stat().st_mtime > max_age:
                p.unlink()


def _is_complete(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        conn = _connect_ro(path)
        try:
            rows = dict(conn.execute("SELECT key, value FROM meta"))
        finally:
            conn.close()
    except sqlite3.Error:
        return False
    return rows.get("schema") == str(SCHEMA_VERSION) and rows.get("complete") == "1"


def _connect_ro(path: Path) -> sqlite3.Connection:
    uri = Path(path).resolve().as_uri() + "?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True, check_same_thread=False)


# ---------------------------------------------------------------------------
# reading


def _hex(value: int, width: int) -> str:
    return "0x%0*x" % (2 * width, value)


class SigDB:
    """Read-only view of a built signature database."""

    def __init__(self, path: Union[str, Path]):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._conn = None
        self._pid = None
        self._cache = {}  # type: Dict[tuple, tuple]
        self.meta = dict(self._query("SELECT key, value FROM meta"))
        if self.meta.get("schema") != str(SCHEMA_VERSION):
            raise ValueError("%s: unsupported signature database schema" % self.path)

    def _query(self, sql: str, args: tuple = ()) -> list:
        with self._lock:
            if self._conn is None or self._pid != os.getpid():
                # a connection must not be shared with a forked child
                self._conn = _connect_ro(self.path)
                self._pid = os.getpid()
            return self._conn.execute(sql, args).fetchall()

    def close(self):
        with self._lock:
            if self._conn is not None and self._pid == os.getpid():
                self._conn.close()
            self._conn = None

    def stats(self) -> dict:
        return json.loads(self.meta.get("stats", "{}"))

    def _cached(self, ck: tuple, sql: str, args: tuple) -> tuple:
        rows = self._cache.get(ck)
        if rows is None:
            rows = tuple(self._query(sql, args))
            if len(self._cache) > 200000:
                self._cache.clear()
            self._cache[ck] = rows
        return rows

    def _rows(self, table: str, key) -> tuple:
        col = "topic0" if table == "events" else "selector"
        sql = "SELECT * FROM %s WHERE %s=? ORDER BY rank" % (table, col)
        return self._cached((table, key), sql, (key,))

    def _event_prefix_rows(self, prefix: int) -> tuple:
        """Event rows whose topic0 starts with the 4 bytes `prefix`."""
        head = prefix.to_bytes(4, "big")
        sql = "SELECT * FROM events WHERE topic0 BETWEEN ? AND ? ORDER BY topic0, rank"
        return self._cached(("events-prefix", prefix), sql, (head + bytes(28), head + b"\xff" * 28))

    @staticmethod
    def _candidate(kind: str, row: tuple) -> dict:
        if kind == FUNCTION:
            key, _, sig, inputs, outputs, mutability, sources, flags = row
        elif kind == EVENT:
            key, _, sig, inputs, anonymous, sources, flags = row
        else:
            key, _, sig, inputs, sources, flags = row
        c = {"type": kind, "name": sig[: sig.index("(")], "inputs": _decode_inputs(inputs, sig)}
        if kind == FUNCTION:
            c["outputs"] = None if outputs is None else json.loads(outputs)
            c["stateMutability"] = mutability
            c["selector"] = _hex(key, 4)
        elif kind == EVENT:
            c["anonymous"] = bool(anonymous)
            c["topic0"] = "0x" + bytes(key).hex()
        else:
            c["selector"] = _hex(key, 4)
        c["signature"] = sig
        c["sources"] = sources.split(",")
        c["generic_names"] = bool(flags & FLAG_GENERIC_NAMES)
        c["untyped"] = bool(flags & FLAG_UNTYPED)
        c["library"] = bool(flags & FLAG_LIBRARY)
        return c

    @staticmethod
    def _filter_types(cands: List[dict], types: Optional[Sequence[str]]) -> List[dict]:
        if types is None:
            return cands
        want = [_canonical_type_string(t) for t in types]
        return [c for c in cands if signature_types(c["signature"]) == want]

    def lookup_function(self, selector, types: Optional[Sequence[str]] = None) -> List[dict]:
        """Candidates for a 4-byte function selector (int or hex), best first.
        With `types`, only signatures with exactly these canonical types."""
        rows = self._rows("functions", _key_int(selector, 4))
        return self._filter_types([self._candidate(FUNCTION, r) for r in rows], types)

    def lookup_error(self, selector, types: Optional[Sequence[str]] = None) -> List[dict]:
        """Candidates for a 4-byte custom-error selector, best first.

        Error entries come first. An error selector is keccak(signature)[:4]
        like a function selector or a topic0 prefix, and custom errors are
        rare in the sources, so the other signatures hashing to `selector`
        (functions, untyped, events) follow, marked "untyped".
        """
        sel = _key_int(selector, 4)
        cands = [self._candidate(ERROR, r) for r in self._rows("errors", sel)]
        seen = {c["signature"] for c in cands}
        others = [self._candidate(FUNCTION, r) for r in self._rows("functions", sel)]
        others.sort(key=lambda c: not c["untyped"])  # untyped signatures first
        others += [self._candidate(EVENT, r) for r in self._event_prefix_rows(sel)]
        for c in others:
            if c["signature"] in seen or c["library"]:
                continue
            seen.add(c["signature"])
            cands.append({
                "type": ERROR, "name": c["name"],
                "inputs": [{k: v for k, v in p.items() if k != "indexed"} for p in c["inputs"]],
                "selector": _hex(sel, 4), "signature": c["signature"], "sources": c["sources"],
                "generic_names": c["generic_names"], "untyped": True, "library": False,
            })
        return self._filter_types(cands, types)

    def lookup_event(self, topic0, num_indexed: Optional[int] = None) -> List[dict]:
        """Candidates for a full 32-byte topic0 (int, bytes or hex), best first.

        Without an event entry, the other signatures (functions, untyped,
        errors) whose full keccak equals topic0 are returned, marked "untyped"
        (their inputs carry no "indexed" flags). With `num_indexed` (the number of
        topics after topic0), only candidates that can produce that many
        indexed topics are kept.
        """
        key = _key_int(topic0, 32).to_bytes(32, "big")
        cands = [self._candidate(EVENT, r) for r in self._rows("events", key)]
        if not cands:
            sel = int.from_bytes(key[:4], "big")
            seen = set()
            others = [self._candidate(FUNCTION, r) for r in self._rows("functions", sel)]
            others += [self._candidate(ERROR, r) for r in self._rows("errors", sel)]
            for c in others:
                if c["signature"] in seen or c["library"] or keccak256(c["signature"]) != key:
                    continue
                seen.add(c["signature"])
                cands.append({
                    "type": EVENT, "name": c["name"], "inputs": c["inputs"], "anonymous": False,
                    "topic0": "0x" + key.hex(), "signature": c["signature"],
                    "sources": c["sources"], "generic_names": c["generic_names"],
                    "untyped": True, "library": False,
                })
        if num_indexed is not None:
            cands = [
                c for c in cands
                if (sum(1 for p in c["inputs"] if p.get("indexed")) == num_indexed)
                or (c["untyped"] and len(c["inputs"]) >= num_indexed)
            ]
        return cands


# ---------------------------------------------------------------------------
# default database

_default = None  # type: Optional[SigDB]
_default_failed = False
_default_lock = threading.Lock()


def default_path(sources: Optional[dict] = None) -> Path:
    """Where the default database lives (SCOBELIX_SIGDB or the cache dir)."""
    env = os.environ.get(ENV_PATH)
    if env:
        return Path(env)
    from scobelix.utils.helpers import cache_dir

    sources = default_sources() if sources is None else sources
    return cache_dir() / _file_name(data_hash(sources))


def _file_name(digest: str) -> str:
    return "sigdb-%d-%s.sqlite" % (SCHEMA_VERSION, digest)


def get_default() -> Optional[SigDB]:
    """The process-wide database, built on first use; None if it cannot be
    built (lookups then find nothing and decompilation goes on unnamed)."""
    global _default, _default_failed
    if _default is not None or _default_failed:
        return _default
    with _default_lock:
        if _default is None and not _default_failed:
            _default = _open_default()
            _default_failed = _default is None
    return _default


def _open_default() -> Optional[SigDB]:
    """Open (building if needed) the default database; when the cache dir is
    not writable, fall back to a private directory under the temporary one."""
    sources = default_sources()
    for p in _default_locations(sources):
        try:
            if not _is_complete(p):
                logger.info("Building the signature database %s (once)...", p)
            return SigDB(ensure_built(p, sources))
        except (OSError, sqlite3.Error) as e:  # this location is unusable
            logger.warning("signature database unavailable at %s: %s", p, e)
        except Exception as e:  # noqa: BLE001 - e.g. damaged bundled data
            logger.warning("signature database unavailable: %s: %s", type(e).__name__, e)
            return None
    logger.warning("signature database unavailable: no writable location")
    return None


def _default_locations(sources: dict):
    """Paths for the default database, in order of preference (the later
    ones are only computed when the earlier ones are unusable)."""
    if os.environ.get(ENV_PATH):
        yield Path(os.environ[ENV_PATH])
        return
    from scobelix.utils.helpers import cache_dir

    name = _file_name(data_hash(sources))
    try:
        cache = cache_dir()
    except OSError as e:
        logger.warning("cache directory unavailable: %s", e)
    else:
        yield cache / name
    temp = _private_temp_dir()
    if temp is not None:
        yield temp / name


def _private_temp_dir() -> Optional[Path]:
    """This user's directory under the temporary directory, None when it
    cannot be made or is not private: a shared one could hold a database
    planted by another user."""
    uid = os.getuid() if hasattr(os, "getuid") else None
    path = Path(tempfile.gettempdir()) / ("scobelix" if uid is None else "scobelix-%d" % uid)
    try:
        path.mkdir(mode=0o700, exist_ok=True)
        st = path.lstat()
    except OSError as e:
        logger.warning("temporary directory unavailable: %s", e)
        return None
    if not stat.S_ISDIR(st.st_mode) or (
        uid is not None and (st.st_uid != uid or st.st_mode & 0o022)
    ):
        logger.warning("%s is not a private directory: not used", path)
        return None
    return path


def set_default(db: Optional[SigDB]):
    """Replace the process-wide database (None: reopen the default lazily)."""
    global _default, _default_failed
    with _default_lock:
        _default = db
        _default_failed = False


def lookup_function(selector, types: Optional[Sequence[str]] = None) -> List[dict]:
    """See SigDB.lookup_function (default database)."""
    db = get_default()
    return db.lookup_function(selector, types) if db is not None else []


def lookup_event(topic0, num_indexed: Optional[int] = None) -> List[dict]:
    """See SigDB.lookup_event (default database)."""
    db = get_default()
    return db.lookup_event(topic0, num_indexed) if db is not None else []


def lookup_error(selector, types: Optional[Sequence[str]] = None) -> List[dict]:
    """See SigDB.lookup_error (default database)."""
    db = get_default()
    return db.lookup_error(selector, types) if db is not None else []

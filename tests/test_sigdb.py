"""
Tests for the signature database (scobelix.utils.sigdb) and for the code
that reads it: fetch_sig/make_abi and the printer's selector lookups.

Most tests build a database from tiny synthetic sources written to a temp
dir (milliseconds, no dependency on the bundled 24 MB dump). The bundled
small sources are checked for consistency the same way; one test reads the
real database only when it is already built in the user cache.
"""

import json
import lzma
import os
import re
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scobelix.utils import sigdb
from scobelix.utils.supplement import LOCAL_SIGS, fetch_sig

REPO_ROOT = Path(__file__).resolve().parents[1]

# widely published constants, independent of this module's keccak
TRANSFER = 0xA9059CBB  # transfer(address,uint256)
APPROVE = 0x095EA7B3  # approve(address,uint256)
TRANSFER_TOPIC = 0xDDF252AD1BE2C89B69C2B068FC378DAA952BA7F163C4A11628F55A4DF523B3EF
ERROR_STRING = 0x08C379A0  # Error(string)
PANIC = 0x4E487B71  # Panic(uint256)
OWNABLE_UNAUTHORIZED = 0x118CDAA7  # OwnableUnauthorizedAccount(address)
GET_CHAIN_STORAGE = 0x027BA49D  # getChainStorage()
MULTICALL_AGGREGATE = 0x252DBA42  # aggregate((address,bytes)[])
MINT = 0x40C10F19  # mint(address,uint256)
NONCES = 0x7ECEBE00  # nonces(address)
BURN = 0x42966C68  # burn(uint256)
DIAMOND_CUT = 0x1F931C1C  # diamondCut((address,uint8,bytes4[])[],address,bytes)
# signatures whose selector has a leading zero byte (below 2**24)
SMALL_ERROR = "SmallError350()"  # 0x00483fb6
SMALL_FUNCTION = "smallSelector2()"  # 0x0044b368


def _p(name, type_, **extra):
    return dict({"name": name, "type": type_}, **extra)


def _dump_line(selector, abi):
    # same layout as data/abi_dump.xz
    return json.dumps({"selector": "0x%08x" % selector, "abi": abi}) + "\n"


def _synthetic_sources(tmp, n_padding=0):
    """Small builtin/curated/dump/local sources exercising every rule."""
    lib_sig = "get(Lib.Data storage,uint256)"
    lines = [
        # typed function: outputs/mutability, names overridden by builtin
        _dump_line(TRANSFER, {
            "name": "transfer", "type": "function",
            "inputs": [_p("recipient", "address"), _p("amount", "uint256")],
            "outputs": [_p("", "bool")], "stateMutability": "nonpayable",
        }),
        # real dump names are kept over curated ones; generic ones are not
        _dump_line(MINT, {
            "name": "mint", "type": "function",
            "inputs": [_p("_to", "address"), _p("_amount", "uint256")],
            "outputs": [], "stateMutability": "nonpayable",
        }),
        _dump_line(BURN, {
            "name": "burn", "type": "function", "inputs": [_p("_value", "uint256")],
            "outputs": [_p("success", "bool")], "stateMutability": "nonpayable",
        }),
        _dump_line(NONCES, {
            "name": "nonces", "type": "function", "inputs": [_p("", "address")],
            "outputs": [_p("", "uint256")], "stateMutability": "view",
        }),
        # placeholders: no information; one hides a local_sigs entry
        _dump_line(0x12345678, {"name": "unknown12345678", "type": "function",
                                "inputs": [], "stateMutability": "payable"}),
        _dump_line(GET_CHAIN_STORAGE, {"name": "unknown027ba49d", "type": "function",
                                       "inputs": [], "stateMutability": "payable"}),
        # filed under a selector it does not hash to
        _dump_line(0x00000001, {"name": "foo", "type": "function",
                                "inputs": [_p("x", "uint256")], "outputs": []}),
        # event filed under topic0[:4], merges with the curated ERC-20 shape
        _dump_line(TRANSFER_TOPIC >> 224, {
            "name": "Transfer", "type": "event", "anonymous": False,
            "inputs": [_p("from", "address", indexed=True), _p("to", "address", indexed=True),
                       _p("value", "uint256", indexed=False)],
        }),
        # an event whose signature is also used as a custom error
        _dump_line(sigdb.function_selector("Blacklisted(address)"), {
            "name": "Blacklisted", "type": "event", "anonymous": False,
            "inputs": [_p("account", "address", indexed=True)],
        }),
        # untyped signatures (text signature lists)
        _dump_line(PANIC, {"name": "Panic", "inputs": [_p("_param1", "uint256")]}),
        _dump_line(sigdb.function_selector("Ping(uint256)"),
                   {"name": "Ping", "inputs": [_p("_param1", "uint256")]}),
        # untyped lists write tuples out
        _dump_line(MULTICALL_AGGREGATE,
                   {"name": "aggregate", "inputs": [_p("_param1", "(address,bytes)[]")]}),
        # library function with a non-ABI parameter type
        _dump_line(sigdb.function_selector(lib_sig), {
            "name": "get", "type": "function",
            "inputs": [_p("self", "Lib.Data storage"), _p("i", "uint256")], "outputs": [],
        }),
        # a function with a small selector, like the vanity ones of real dumps
        _dump_line(sigdb.function_selector(SMALL_FUNCTION), {
            "name": "smallSelector2", "type": "function", "inputs": [], "outputs": [],
            "stateMutability": "nonpayable",
        }),
        # `f()` of a text signature list, read as one parameter without a type
        _dump_line(sigdb.function_selector("finishUpgrade()"),
                   {"name": "finishUpgrade", "inputs": [_p("_param1", "")]}),
        # outputs written with a contract type name: not ABI types
        _dump_line(sigdb.function_selector("registry()"), {
            "name": "registry", "type": "function", "inputs": [],
            "outputs": [_p("", "Registry")], "stateMutability": "view",
        }),
        "{not json\n",
    ]
    for i in range(n_padding):
        name = "pad%d" % i
        lines.append(_dump_line(sigdb.function_selector(name + "()"), {"name": name, "inputs": []}))
    dump = tmp / "dump.xz"
    with lzma.open(str(dump), "wt", encoding="utf-8") as f:
        f.writelines(lines)

    local = tmp / "local.json"
    local.write_text(
        json.dumps({"0x%08x" % GET_CHAIN_STORAGE: {"name": "getChainStorage", "inputs": []}})
    )

    erc20_transfer = {"type": "event", "name": "Transfer", "anonymous": False, "inputs": [
        _p("from", "address", indexed=True), _p("to", "address", indexed=True),
        _p("value", "uint256", indexed=False)]}
    erc721_transfer = {"type": "event", "name": "Transfer", "anonymous": False, "inputs": [
        _p("from", "address", indexed=True), _p("to", "address", indexed=True),
        _p("tokenId", "uint256", indexed=True)]}
    curated = tmp / "extra.json"
    curated.write_text(json.dumps({"format": 1, "abi": [
        erc20_transfer,
        {"type": "function", "name": "approve",
         "inputs": [_p("spender", "address"), _p("value", "uint256")],
         "outputs": [_p("", "bool")], "stateMutability": "nonpayable"},
        erc721_transfer,
        {"type": "function", "name": "approve",
         "inputs": [_p("to", "address"), _p("tokenId", "uint256")],
         "outputs": [], "stateMutability": "nonpayable"},
        {"type": "function", "name": "mint",
         "inputs": [_p("to", "address"), _p("amount", "uint256")],
         "outputs": [], "stateMutability": "nonpayable"},
        {"type": "function", "name": "burn", "inputs": [_p("value", "uint256")],
         "outputs": [], "stateMutability": "nonpayable"},
        {"type": "function", "name": "nonces", "inputs": [_p("owner", "address")],
         "outputs": [_p("", "uint256")], "stateMutability": "view"},
        {"type": "error", "name": "Error", "inputs": [_p("reason", "string")]},
        {"type": "error", "name": "Panic", "inputs": [_p("code", "uint256")]},
        {"type": "error", "name": "OwnableUnauthorizedAccount",
         "inputs": [_p("account", "address")]},
        {"type": "error", "name": "SmallError350", "inputs": []},
        {"type": "constructor", "inputs": []},
    ]}))

    builtin = {
        "0x%08x" % TRANSFER: {
            "name": "transfer", "inputs": [_p("to", "address"), _p("amount", "uint256")]},
        "0x%08x" % APPROVE: {
            "name": "approve", "inputs": [_p("spender", "address"), _p("amount", "uint256")]},
        "0x%08x" % DIAMOND_CUT: {"name": "diamondCut", "inputs": [
            _p("_cut", "tuple[]", components=[
                _p("facetAddress", "address"), _p("action", "uint8"),
                _p("functionSelectors", "bytes4[]")]),
            _p("_init", "address"), _p("_calldata", "bytes")]},
    }
    return {"builtin": builtin, "curated": str(curated), "dump": str(dump), "local": str(local)}


@pytest.fixture(scope="module")
def synthetic(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sigdb")
    sources = _synthetic_sources(tmp)
    path = tmp / "db.sqlite"
    stats = sigdb.build(path, sources)
    db = sigdb.SigDB(path)
    yield db, stats, sources
    db.close()


@pytest.fixture
def as_default(synthetic):
    sigdb.set_default(synthetic[0])
    yield synthetic[0]
    sigdb.set_default(None)


def test_selector_helpers_match_published_constants():
    assert sigdb.function_selector("transfer(address,uint256)") == TRANSFER
    assert sigdb.event_topic("Transfer(address,address,uint256)") == TRANSFER_TOPIC
    assert sigdb.function_selector("Error(string)") == ERROR_STRING
    assert sigdb.canonical_signature("f", [_p("a", "uint"), _p("b", "tuple[2]", components=[
        _p("x", "int"), _p("y", "bytes32")])]) == "f(uint256,(int256,bytes32)[2])"
    assert sigdb.canonical_type(_p("s", "Lib.Data storage")) is None
    written_out = _p("t", "(uint,(address,bool)[])[2]")
    assert sigdb.canonical_type(written_out) == "(uint256,(address,bool)[])[2]"
    assert sigdb.canonical_type(_p("t", "(uint256,bool256)")) is None
    assert sigdb.signature_types("f(uint256,(address,bool)[],bytes)") == [
        "uint256", "(address,bool)[]", "bytes"]


def test_build_verifies_every_entry(synthetic):
    _, stats, _ = synthetic
    rejected = stats["rejected"]["dump"]
    assert rejected == {"placeholder": 2, "keccak-mismatch": 1, "malformed": 1}
    assert "builtin" not in stats["rejected"] and "curated" not in stats["rejected"]
    assert stats["accepted"] == {"builtin": 3, "curated": 11, "dump": 13, "local": 1}


def test_function_candidate_merges_sources(synthetic):
    db = synthetic[0]
    (c,) = db.lookup_function(TRANSFER)
    assert c["signature"] == "transfer(address,uint256)"
    assert [p["name"] for p in c["inputs"]] == ["to", "amount"]  # builtin names win
    assert c["outputs"] == [{"name": "", "type": "bool"}]  # from the dump
    assert c["stateMutability"] == "nonpayable"
    assert c["sources"] == ["builtin", "dump"]
    assert c["selector"] == "0xa9059cbb" and not c["untyped"] and not c["generic_names"]
    assert db.lookup_function("0xa9059cbb") == db.lookup_function(TRANSFER)


def test_parameter_names_keep_the_historical_order(synthetic):
    db = synthetic[0]
    (mint,) = db.lookup_function(MINT)
    assert [p["name"] for p in mint["inputs"]] == ["_to", "_amount"]  # dump before curated
    assert mint["sources"] == ["curated", "dump"]  # trust order
    # variants of one signature: the one with the historical names first
    burn, burn_no_return = db.lookup_function(BURN)
    assert (burn["inputs"][0]["name"], burn["outputs"]) == ("_value", [_p("success", "bool")])
    assert (burn_no_return["inputs"][0]["name"], burn_no_return["outputs"]) == ("value", [])
    (nonces,) = db.lookup_function(NONCES)
    assert nonces["inputs"] == [{"name": "owner", "type": "address"}]  # generic dump name filled
    assert not nonces["generic_names"] and nonces["stateMutability"] == "view"


def test_ambiguous_outputs_give_separate_candidates(synthetic):
    db = synthetic[0]
    cands = db.lookup_function(APPROVE)
    assert [(c["outputs"], c["sources"]) for c in cands] == [
        (None, ["builtin"]),
        ([{"name": "", "type": "bool"}], ["curated"]),
        ([], ["curated"]),
    ]
    assert [p["name"] for p in cands[2]["inputs"]] == ["to", "tokenId"]
    assert db.lookup_function(APPROVE, types=["address", "uint"]) == cands
    assert db.lookup_function(APPROVE, types=["address"]) == []


def test_placeholders_never_match(synthetic):
    db = synthetic[0]
    assert db.lookup_function(0x12345678) == []
    # the placeholder no longer hides the real local_sigs entry
    (c,) = db.lookup_function(GET_CHAIN_STORAGE)
    assert c["signature"] == "getChainStorage()" and c["sources"] == ["local"]
    assert db.lookup_function(1) == []  # keccak mismatch dropped


def test_events_are_keyed_by_full_topic0(synthetic):
    db = synthetic[0]
    cands = db.lookup_event(TRANSFER_TOPIC)
    assert [[p["indexed"] for p in c["inputs"]] for c in cands] == [
        [True, True, False], [True, True, True]]
    assert cands[0]["sources"] == ["curated", "dump"]
    assert cands[0]["topic0"] == "0x%064x" % TRANSFER_TOPIC
    (erc721,) = db.lookup_event(TRANSFER_TOPIC, num_indexed=3)
    assert erc721["inputs"][2]["name"] == "tokenId"
    assert db.lookup_event(TRANSFER_TOPIC, num_indexed=0) == []
    # same first 4 bytes, different topic: no match
    assert db.lookup_event(TRANSFER_TOPIC ^ 1) == []
    assert db.lookup_event(TRANSFER_TOPIC >> 224) == []


def test_event_fallback_on_untyped_signature_with_full_hash(synthetic):
    db = synthetic[0]
    (c,) = db.lookup_event(sigdb.event_topic("Ping(uint256)"))
    assert c["type"] == "event" and c["signature"] == "Ping(uint256)" and c["untyped"]
    assert db.lookup_event(sigdb.event_topic("Ping(uint256)"), num_indexed=1) == [c]
    assert db.lookup_event(sigdb.event_topic("Ping(uint256)"), num_indexed=2) == []


def test_errors_have_their_own_namespace(synthetic):
    db = synthetic[0]
    assert [c["signature"] for c in db.lookup_error(ERROR_STRING)] == ["Error(string)"]
    assert db.lookup_function(ERROR_STRING) == []
    (account,) = db.lookup_error(OWNABLE_UNAUTHORIZED)
    assert account["inputs"] == [{"name": "account", "type": "address"}]
    (panic,) = db.lookup_error(PANIC)  # the untyped dump entry is the same signature
    assert (panic["inputs"][0]["name"], panic["untyped"]) == ("code", False)
    # other signatures hashing to the selector follow, marked untyped
    (ping,) = db.lookup_error(sigdb.function_selector("Ping(uint256)"))
    assert (ping["type"], ping["untyped"], ping["generic_names"]) == ("error", True, True)
    (blacklisted,) = db.lookup_error(sigdb.function_selector("Blacklisted(address)"))
    assert blacklisted["untyped"]
    assert blacklisted["inputs"] == [{"name": "account", "type": "address"}]


def test_library_signatures_are_flagged(synthetic):
    db = synthetic[0]
    (c,) = db.lookup_function(sigdb.function_selector("get(Lib.Data storage,uint256)"))
    assert c["library"] and c["inputs"][0] == {"name": "self", "type": "Lib.Data storage"}
    (agg,) = db.lookup_function(MULTICALL_AGGREGATE)  # a written-out tuple is an ABI type
    assert not agg["library"] and agg["inputs"][0]["type"] == "(address,bytes)[]"
    assert db.lookup_function(MULTICALL_AGGREGATE, types=["(address,bytes)[]"]) == [agg]


def test_malformed_parts_of_valid_entries(synthetic):
    db = synthetic[0]
    # `f()` read as one parameter of type "": no parameter, not a library ABI
    (finish,) = db.lookup_function(sigdb.function_selector("finishUpgrade()"))
    assert finish["signature"] == "finishUpgrade()" and finish["inputs"] == []
    assert not finish["library"] and finish["untyped"]
    # outputs that are not ABI types are unknown; the rest of the ABI is kept
    (registry,) = db.lookup_function(sigdb.function_selector("registry()"))
    assert registry["outputs"] is None and registry["stateMutability"] == "view"


def test_candidates_are_fresh_copies(synthetic):
    db = synthetic[0]
    db.lookup_function(TRANSFER)[0]["inputs"][0]["name"] = "changed"
    assert db.lookup_function(TRANSFER)[0]["inputs"][0]["name"] == "to"


def test_database_opens_read_only(synthetic, tmp_path):
    db_path = tmp_path / "ro" / "db.sqlite"
    db_path.parent.mkdir()
    db_path.write_bytes(synthetic[0].path.read_bytes())
    db_path.chmod(stat.S_IRUSR)
    db_path.parent.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        db = sigdb.SigDB(db_path)
        assert db.lookup_function(TRANSFER)
        assert sigdb.ensure_built(db_path) == db_path  # complete: no lock, no write
        db.close()
        assert sorted(p.name for p in db_path.parent.iterdir()) == ["db.sqlite"]
    finally:
        db_path.parent.chmod(stat.S_IRWXU)


def test_file_name_follows_the_data(synthetic, tmp_path, monkeypatch):
    """A change of any source or of the format selects another file, so a
    stale database is never reused (the new one is built on first use)."""
    sources = synthetic[2]
    digest = sigdb.data_hash(sources)
    builtin = dict(sources["builtin"], **{"0x%08x" % NONCES: {
        "name": "nonces", "inputs": [_p("owner", "address")]}})
    assert sigdb.data_hash(dict(sources, builtin=builtin)) != digest
    local = tmp_path / "local.json"
    local.write_text(Path(sources["local"]).read_text() + " ")
    assert sigdb.data_hash(dict(sources, local=str(local))) != digest
    assert sigdb.data_hash(dict(sources, local=str(tmp_path / "missing.json"))) != digest
    monkeypatch.setattr(sigdb, "SCHEMA_VERSION", sigdb.SCHEMA_VERSION + 1)
    assert sigdb.data_hash(sources) != digest


def test_missing_source_file_is_reported(synthetic, tmp_path, caplog):
    """A source file absent from the installation is skipped with a warning
    (the names it holds are silently missing otherwise)."""
    sources = dict(synthetic[2], dump=str(tmp_path / "absent.xz"))
    stats = sigdb.build(tmp_path / "db.sqlite", sources)
    assert "dump" not in stats["accepted"] and stats["accepted"]["curated"] == 11
    assert "signature source dump not found" in caplog.text


def test_incomplete_file_is_rebuilt(synthetic, tmp_path):
    dest = tmp_path / "db.sqlite"
    conn = sqlite3.connect(str(dest))  # a database without the "complete" mark
    conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.commit()
    conn.close()
    old = tmp_path / "db.sqlite.tmp-1-abc"  # left by a killed build
    old.write_bytes(b"")
    os.utime(old, (time.time() - 7200, time.time() - 7200))
    recent = tmp_path / "db.sqlite.tmp-2-abc"  # possibly another build running
    recent.write_bytes(b"")
    sigdb.ensure_built(dest, synthetic[2])
    assert sigdb.SigDB(dest).lookup_function(TRANSFER)
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "db.sqlite", "db.sqlite.lock", "db.sqlite.tmp-2-abc"]
    empty = tmp_path / "empty.sqlite"  # nothing to lose
    empty.write_bytes(b"")
    assert sigdb.SigDB(sigdb.ensure_built(empty, synthetic[2])).lookup_function(TRANSFER)


def test_a_file_that_is_no_database_is_never_replaced(synthetic, tmp_path, monkeypatch, caplog):
    """A database path set by mistake on another file (a data file of the
    project, say) must not cost that file: it is refused, left as it was,
    and nothing is created next to it."""
    data = tmp_path / "data" / "abi_dump.xz"
    data.parent.mkdir()
    data.write_bytes(b"\xfd7zXZ\x00 some compressed data")
    with pytest.raises(FileExistsError):
        sigdb.ensure_built(data, synthetic[2])
    assert data.read_bytes() == b"\xfd7zXZ\x00 some compressed data"
    assert sorted(p.name for p in data.parent.iterdir()) == ["abi_dump.xz"]
    with pytest.raises(FileExistsError):  # a directory neither
        sigdb.ensure_built(tmp_path / "data", synthetic[2])
    # nor is another program's SQLite database (no `meta` table of a signature database)
    other = tmp_path / "data" / "history.sqlite"
    conn = sqlite3.connect(str(other))
    conn.execute("CREATE TABLE visits (url TEXT, at INTEGER)")
    conn.execute("INSERT INTO visits VALUES ('page', 1)")
    conn.commit()
    conn.close()
    before = other.read_bytes()
    with pytest.raises(FileExistsError):
        sigdb.ensure_built(other, synthetic[2])
    assert other.read_bytes() == before
    assert sorted(p.name for p in data.parent.iterdir()) == ["abi_dump.xz", "history.sqlite"]
    # the default database at such a path: unavailable, with a warning, the file kept
    monkeypatch.setenv(sigdb.ENV_PATH, str(data))
    monkeypatch.setattr(sigdb, "default_sources", lambda: synthetic[2])
    assert sigdb._open_default() is None and "not a signature database" in caplog.text
    assert data.read_bytes() == b"\xfd7zXZ\x00 some compressed data"


def test_default_database_falls_back_to_the_temp_dir(synthetic, tmp_path, monkeypatch, caplog):
    import tempfile

    from scobelix.utils import helpers

    def unusable_cache_dir():
        raise PermissionError("read-only cache directory")

    monkeypatch.delenv(sigdb.ENV_PATH, raising=False)
    monkeypatch.setattr(sigdb, "default_sources", lambda: synthetic[2])
    monkeypatch.setattr(helpers, "cache_dir", unusable_cache_dir)
    (tmp_path / "tmp").mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "tmp"))
    sigdb.set_default(None)
    db = None
    try:
        db = sigdb.get_default()
        private = tmp_path / "tmp" / ("scobelix-%d" % os.getuid())  # one per user
        assert db.path.parent == private and stat.S_IMODE(private.stat().st_mode) == 0o700
        assert db.path.name == "sigdb-%d-%s.sqlite" % (
            sigdb.SCHEMA_VERSION, sigdb.data_hash(synthetic[2]))
        assert fetch_sig(TRANSFER)["name"] == "transfer"

        # nowhere to build it: lookups find nothing, callers go on unnamed
        (tmp_path / "file").write_text("")
        monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "file" / "tmp"))
        sigdb.set_default(None)
        assert sigdb.get_default() is None
        assert sigdb.lookup_function(TRANSFER) == [] and fetch_sig(TRANSFER) is None
        assert sigdb.lookup_event(TRANSFER_TOPIC) == [] and sigdb.lookup_error(ERROR_STRING) == []
        assert "signature database unavailable" in caplog.text
    finally:
        if db is not None:
            db.close()
        sigdb.set_default(None)


def test_temp_dir_fallback_is_private(tmp_path, monkeypatch):
    """A directory other users can write to may hold a planted database."""
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    path = tmp_path / ("scobelix-%d" % os.getuid())
    path.mkdir()
    path.chmod(0o777)
    assert sigdb._private_temp_dir() is None
    path.rmdir()
    (tmp_path / "elsewhere").mkdir()
    path.symlink_to(tmp_path / "elsewhere")
    assert sigdb._private_temp_dir() is None
    path.unlink()
    assert sigdb._private_temp_dir() == path
    assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_cache_dir_tolerates_concurrent_creation(tmp_path, monkeypatch):
    """Processes started together all find the cache directory missing;
    all but one then find it created by another when they make it."""
    from scobelix.utils import helpers

    monkeypatch.setattr(helpers, "user_cache_dir", lambda *args: str(tmp_path / "scobelix"))
    (tmp_path / "scobelix").mkdir()
    checks = []
    real_is_dir = Path.is_dir

    def is_dir(self):  # missing at the first check, created right after
        checks.append(self)
        return len(checks) > 1 and real_is_dir(self)

    monkeypatch.setattr(Path, "is_dir", is_dir)
    assert helpers.cache_dir() == tmp_path / "scobelix"


def test_damaged_bundled_data_leaves_lookups_empty(synthetic, tmp_path, monkeypatch, caplog):
    """A truncated dump fails the build: lookups find nothing, decompilation
    goes on unnamed, and the build is not retried at every lookup."""
    sources = dict(synthetic[2])
    dump = Path(sources["dump"]).read_bytes()
    sources["dump"] = str(tmp_path / "truncated.xz")
    Path(sources["dump"]).write_bytes(dump[: len(dump) // 2])
    builds = []
    real_build = sigdb.build

    def build(*args, **kwargs):
        builds.append(args[0])
        return real_build(*args, **kwargs)

    monkeypatch.setattr(sigdb, "build", build)
    monkeypatch.setattr(sigdb, "default_sources", lambda: sources)
    monkeypatch.setenv(sigdb.ENV_PATH, str(tmp_path / "db.sqlite"))
    sigdb.set_default(None)
    try:
        assert sigdb.lookup_function(TRANSFER) == [] and fetch_sig(TRANSFER) is None
        assert sigdb.lookup_event(TRANSFER_TOPIC) == [] and sigdb.lookup_error(ERROR_STRING) == []
        assert len(builds) == 1 and "signature database unavailable" in caplog.text
        assert not (tmp_path / "db.sqlite").exists()
    finally:
        sigdb.set_default(None)


_CHILD = r"""
import json, sys, time
sys.path.insert(0, sys.argv[3])
from scobelix.utils import sigdb
real_build = sigdb.build
def build(*args, **kwargs):
    print("BUILT", flush=True)
    return real_build(*args, **kwargs)
sigdb.build = build
time.sleep(max(0.0, float(sys.argv[4]) - time.time()))  # start together
db = sigdb.SigDB(sigdb.ensure_built(sys.argv[1], json.loads(sys.argv[2])))
print(len(db.lookup_function(0xa9059cbb)))
"""


def test_concurrent_processes_build_once(tmp_path):
    sources = _synthetic_sources(tmp_path, n_padding=10000)  # a build of ~0.2 s
    dest = tmp_path / "shared" / "db.sqlite"
    start = "%f" % (time.time() + 1.0)
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CHILD, str(dest), json.dumps(sources), str(REPO_ROOT), start],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for _ in range(4)
    ]
    outs = [p.communicate(timeout=120) for p in procs]
    assert all(p.returncode == 0 for p in procs), [err for _, err in outs]
    assert sum(out.count("BUILT") for out, _ in outs) == 1
    assert all(out.strip().endswith("1") for out, _ in outs)
    assert sorted(p.name for p in dest.parent.iterdir()) == ["db.sqlite", "db.sqlite.lock"]


def test_fetch_sig_is_namespace_aware(as_default):
    sig = fetch_sig(TRANSFER)
    assert sig["name"] == "transfer"
    assert [p["type"] for p in sig["inputs"]] == ["address", "uint256"]
    assert fetch_sig("0xa9059cbb") == sig
    assert fetch_sig(ERROR_STRING) is None  # an error, not a function
    assert fetch_sig(ERROR_STRING, kind="error")["name"] == "Error"
    assert fetch_sig(TRANSFER_TOPIC, kind="event")["name"] == "Transfer"
    assert fetch_sig(0x12345678) is None
    assert fetch_sig(TRANSFER_TOPIC) is None  # not a 4-byte selector


def test_make_abi_names_and_placeholders(as_default):
    from scobelix.utils import signatures

    signatures.make_abi({
        "0x%08x" % TRANSFER: (10, ()),
        "0x12345678": (20, ()),
        "0x%08x" % DIAMOND_CUT: (30, ()),
        "_fallback": (0, ()),
    })
    assert signatures.get_func_name("0x%08x" % TRANSFER) == "transfer(address to, uint256 amount)"
    assert signatures.get_abi_name("0x%08x" % TRANSFER) == "transfer(address,uint256)"
    # placeholder entries are not hits: the name stays unknown and the
    # parameters are left to the decompiler's inference
    assert signatures.get_func_name("0x12345678") == "unknown12345678(?)"
    assert signatures.get_func_params("0x12345678") is None
    assert signatures.get_func_name("_fallback") == "_fallback(?)"
    # the ABI name is the canonical signature: tuples written out
    abi_name = signatures.get_abi_name("0x%08x" % DIAMOND_CUT)
    assert abi_name == "diamondCut((address,uint8,bytes4[])[],address,bytes)"
    assert sigdb.function_selector(abi_name) == DIAMOND_CUT


def test_printer_resolves_selectors_only_in_selector_positions(as_default):
    from scobelix.prettify import pretty_line as _pretty_line, prettify

    def pretty_line(line, add_color=False):
        ansi = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
        return [ansi.sub("", text) for text in _pretty_line(line, add_color=add_color)]

    selector_exp = ("mask_shl", 32, 224, -224, ("cd", 0))
    name = "transfer(address to, uint256 amount)"

    # arbitrary constants are numbers, whatever their leading bytes
    assert prettify(TRANSFER) == str(TRANSFER)
    assert name not in prettify(TRANSFER << 16)
    assert name not in prettify(("eq", TRANSFER, ("var", 0)))
    assert name not in "\n".join(pretty_line(("return", TRANSFER), add_color=False))

    # dispatcher comparisons with the calldata selector, in every form
    assert name in prettify(("eq", TRANSFER, selector_exp))
    assert name in prettify(("iszero", ("eq", selector_exp, TRANSFER)))
    assert name in prettify(("gt", TRANSFER, ("div", ("cd", 0), 2**224)))
    assert name in prettify(("add", TRANSFER, ("mul", -1, selector_exp)))

    # head of an encoded call written to memory (abi.encodeWithSelector): a
    # 4-byte part, or a word holding the selector in its first 4 bytes
    assert name in prettify(("data", ("bytes", 4, TRANSFER), ("param", "to"), 5))
    assert name in prettify(("data", TRANSFER << 224, 5))
    assert prettify(("data", 32, 5)) == "32, 5"
    assert prettify(("setmem", ("range", 160, 4), TRANSFER)).endswith("= " + name)
    assert name not in prettify(("setmem", ("range", 160, 32), TRANSFER))

    # returned data decoded by try/catch: head of a word, or its first 4
    # bytes read as such, vs an error selector
    for head in (
        ("mask_shl", 32, 224, -224, ("mem", ("range", 4, 28))),
        ("mask_shl", 32, 0, 0, ("ext_call.return_data", 0, 4)),
        ("mask_shl", 32, 0, 0, ("mem", ("range", 0, 4))),
    ):
        assert "Error(string reason)" in prettify(("add", ERROR_STRING, ("mul", -1, head)))
        assert "Error(string reason)" in prettify(("eq", ERROR_STRING, head))
        assert "Panic(uint256 code)" in prettify(("iszero", ("eq", head, PANIC)))
        assert prettify(("eq", 5, head)).startswith("(5 == ")
    # a wider read is not a 4-byte head
    wide = ("mask_shl", 32, 0, 0, ("ext_call.return_data", 0, 32))
    assert "Error" not in prettify(("eq", ERROR_STRING, wide))

    # call targets
    call = ("call", "gas", ("param", "token"), 0, TRANSFER, ("data", ("param", "to"), 5))
    assert any(name in line for line in pretty_line(call, add_color=False))

    # revert payloads use the error namespace
    error_string = ("bytes", 4, ERROR_STRING)
    revert = "\n".join(pretty_line(("revert", ("data", error_string, 32, 5, "'hello'"))))
    assert "Error(string reason)" in revert
    assert "OwnableUnauthorizedAccount(address account)" in "\n".join(
        pretty_line(("revert", ("bytes", 4, OWNABLE_UNAUTHORIZED)), add_color=False))
    assert "OwnableUnauthorizedAccount(address account)" in "\n".join(
        pretty_line(("revert", OWNABLE_UNAUTHORIZED << 224), add_color=False))
    assert "revert with 0, 7" in "\n".join(  # 0: an empty or lost selector
        pretty_line(("revert", ("data", 0, 7)), add_color=False))

    # logs are resolved by their full topic0 and number of topics
    log = "\n".join(pretty_line(("log", ("param", "v"), TRANSFER_TOPIC, "caller", ("param", "to")),
                                add_color=False))
    assert "log Transfer(" in log and "uint256 value=" in log
    log721 = "\n".join(pretty_line(("log", None, TRANSFER_TOPIC, "caller", ("param", "to"), 7),
                                   add_color=False))
    assert "tokenId" in log721
    other = ("log", ("param", "v"), TRANSFER_TOPIC ^ 1, "caller")
    assert "Transfer" not in "\n".join(pretty_line(other))


def test_printer_leaves_raw_words_and_custom_dispatch_unnamed(as_default):
    """Values that only resemble selectors: other reads of cd[0] (custom
    dispatch on its first byte, the whole word, its low 4 bytes), plain
    words in byte strings (raw revert words, return values, log data: 32
    bytes, so a value below 2**224 starts with zero bytes), small packed
    integers. Small dumps' vanity selectors (0x00000001...) would otherwise
    name some of them."""
    from scobelix.prettify import pretty_line as _pretty_line, prettify

    ansi = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

    def text(line):
        return "\n".join(ansi.sub("", t) for t in _pretty_line(line, add_color=False))

    def revert_text(payload):
        return text(("revert", payload))

    small_function = sigdb.function_selector(SMALL_FUNCTION)
    small_error = sigdb.function_selector(SMALL_ERROR)
    assert small_function < 2**24 and small_error < 2**24
    ping = sigdb.function_selector("Ping(uint256)")
    assert ping >= 2**24
    selector_exp = ("mask_shl", 256, -224, -224, ("cd", 0))  # solc >= 0.5
    name = "transfer(address to, uint256 amount)"

    # the selector, in every form, possibly masked, in both test directions
    assert name in prettify(("eq", TRANSFER, selector_exp))
    assert name in prettify(("eq", TRANSFER, ("mask_shl", 32, 0, 0, selector_exp)))
    assert name in prettify(("eq", ("and", ("div", ("cd", 0), 2**224), 0xFFFFFFFF), TRANSFER))
    assert name in prettify(("add", -TRANSFER, selector_exp))  # selector - K
    assert "smallSelector2()" in prettify(("eq", small_function, selector_exp))
    assert name in prettify(("eq", TRANSFER, ("shr", 224, ("cd", 0))))
    # a selector without a known name shows its 4 bytes
    assert prettify(("eq", 0x11111111, selector_exp)).startswith("(0x11111111 == ")
    assert " - 0x00000001)" in prettify(("add", -1, selector_exp))
    head = ("mask_shl", 32, 0, 0, ("ext_call.return_data", 0, 4))
    assert prettify(("eq", 0x12345678, head)).startswith("(0x12345678 == ")
    # other reads of cd[0] are not the selector, its low 4 bytes included
    # (`and(calldataload(0), 0xffffffff)` of a custom dispatch)
    assert name not in prettify(("eq", TRANSFER, ("mask_shl", 8, 248, -248, ("cd", 0))))
    assert name not in prettify(("eq", TRANSFER, ("cd", 0)))
    assert name not in prettify(("eq", TRANSFER << 224, ("cd", 0)))
    assert name not in prettify(("eq", TRANSFER, ("and", 0xFF, ("div", ("cd", 0), 2**224))))
    assert name not in prettify(("eq", TRANSFER << 224, selector_exp))
    assert name not in prettify(("eq", TRANSFER, ("mask_shl", 32, 0, 0, ("cd", 0))))
    assert name not in prettify(("add", -TRANSFER, ("mask_shl", 32, 0, 0, ("cd", 0))))

    # plain words are numbers, whatever selector their value equals
    for word in (TRANSFER, ERROR_STRING, OWNABLE_UNAUTHORIZED, ping, small_error, 1):
        assert revert_text(word) == "revert with %d" % word
        assert "(" not in revert_text(("data", word, 7))
        assert "(" not in text(("return", ("data", word, 7)))
        assert "(" not in text(("log", ("data", word, 7), TRANSFER_TOPIC ^ 1))

    # 4-byte revert payloads: a small value only names a declared error
    assert "SmallError350()" in revert_text(("bytes", 4, small_error))
    assert "SmallError350()" in revert_text(("data", ("bytes", 4, small_error), 7))
    assert "smallSelector2" not in revert_text(("bytes", 4, small_function))
    assert "smallSelector2" not in revert_text(("data", ("bytes", 4, small_function), 7))
    # larger values still fall back to signatures of other kinds
    assert "Ping(uint256" in revert_text(("bytes", 4, ping))

    # a 4-byte part outside the selector positions shows its width, not a name
    assert prettify(("bytes", 4, TRANSFER)) == "0xa9059cbb"
    assert name not in prettify(("sha3", ("data", 7, ("bytes", 4, TRANSFER))))

    # 4-byte memory writes: small values are packed integers
    assert "smallSelector2" not in prettify(("setmem", ("range", 160, 4), small_function))
    assert prettify(("setmem", ("range", 160, 4), TRANSFER)).endswith("= " + name)


def test_printer_reads_explicit_width_selector_parts(as_default):
    """A memory blob part with an explicit width, ("bytes", 4, K) = the low
    4 bytes of K, holds a selector like a bare 4-byte constant, with the same
    rules (error namespace in revert payloads, no small packed integers)."""
    from scobelix.prettify import pretty_line, prettify

    def revert_text(payload):
        ansi = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
        return "\n".join(ansi.sub("", t) for t in pretty_line(("revert", payload)))

    def part(value):
        return ("bytes", 4, value)

    name = "transfer(address to, uint256 amount)"
    small_function = sigdb.function_selector(SMALL_FUNCTION)

    assert "Error(string reason)" in revert_text(("data", part(ERROR_STRING), 32, 5, "'hello'"))
    assert "OwnableUnauthorizedAccount(address account)" in revert_text(part(OWNABLE_UNAUTHORIZED))
    assert "Error(string reason)" in revert_text(part(ERROR_STRING + (7 << 32)))  # low 4 bytes
    assert "smallSelector2" not in revert_text(("data", part(small_function), 7))
    assert name in prettify(("data", part(TRANSFER), ("param", "to"), 5))
    assert "smallSelector2" not in "".join(prettify(("data", part(small_function), 5)))
    assert prettify(("setmem", ("range", 160, 4), part(TRANSFER))).endswith("= " + name)


def test_bundled_small_sources_are_consistent(tmp_path):
    """Every entry of LOCAL_SIGS, extra_sigs.json and local_sigs.json is a
    well-formed signature whose key matches its keccak hash."""
    sources = dict(sigdb.default_sources(), dump=None)
    stats = sigdb.build(tmp_path / "small.sqlite", sources)
    assert stats["rejected"] == {}
    curated = json.loads(sigdb.EXTRA_SIGS_PATH.read_text())["abi"]
    assert stats["accepted"]["builtin"] == len(LOCAL_SIGS)
    assert stats["accepted"]["curated"] == len(curated)
    assert stats["accepted"]["local"] == len(json.loads(sigdb.LOCAL_SIGS_PATH.read_text()))
    assert {e["type"] for e in curated} == {"function", "event", "error"}
    assert all(set(e) <= {"type", "name", "inputs", "outputs", "stateMutability", "anonymous"}
               for e in curated)


def _real_db():
    if os.environ.get(sigdb.ENV_PATH):
        pytest.skip("SCOBELIX_SIGDB points to a custom database")
    path = sigdb.default_path()
    if not path.is_file():
        pytest.skip("the signature database is not built in the user cache yet")
    return sigdb.SigDB(path)


def test_real_database_lookups():
    db = _real_db()
    sig = lambda cands: [c["signature"] for c in cands]  # noqa: E731
    assert sig(db.lookup_function(TRANSFER))[0] == "transfer(address,uint256)"
    assert db.lookup_function(TRANSFER)[0]["outputs"] == [{"name": "", "type": "bool"}]
    assert sig(db.lookup_function(GET_CHAIN_STORAGE)) == ["getChainStorage()"]
    assert db.lookup_function(0x00000003) == []  # placeholder in the dump
    assert db.lookup_function(ERROR_STRING) == []
    for error in ("ERC20InsufficientBalance(address,uint256,uint256)",
                  "OwnableUnauthorizedAccount(address)", "EnforcedPause()",
                  "ERC1967InvalidImplementation(address)", "FailedCall()"):
        assert error in sig(db.lookup_error(sigdb.function_selector(error))), error
    for event in ("Initialized(uint64)", "EIP712DomainChanged()", "Upgraded(address)"):
        assert event in sig(db.lookup_event(sigdb.event_topic(event))), event
    assert len(db.lookup_event(TRANSFER_TOPIC, num_indexed=3)) >= 1
    assert db.stats()["rejected"]["dump"]["placeholder"] > 300000
    db.close()

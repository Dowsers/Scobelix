"""
The signature adapter over the signature database: keccak-verified
candidates of the three namespaces (functions with their outputs and
mutability, events by full topic0 and indexed count, custom errors), and
what tells several candidates of one key apart.

The databases are built for the tests: the small tables shipped with the
package, and a synthetic one holding real 4-byte collisions.
"""

import json
import lzma

import pytest

from conftest import default_sigdb
from scobelix.solgen import abi, sigs
from scobelix.utils import sigdb

TRANSFER = "transfer(address,uint256)"
COLLIDING = "many_msg_babbage(bytes1)"  # the same 4 bytes as transfer(address,uint256)
BURN = "burn(uint256)"
BURN_COLLIDING = "collate_propagate_storage(bytes16)"


def _p(type_, name=""):
    return {"name": name, "type": type_}


def _line(signature, kind, inputs, **extra):
    name = signature.split("(")[0]
    entry = dict({"name": name, "inputs": inputs}, **extra)
    if kind is not None:
        entry["type"] = kind
    return json.dumps({"selector": "0x%08x" % sigs.function_selector(signature), "abi": entry}) + "\n"


@pytest.fixture
def collisions(tmp_path):
    """A database whose function and error namespaces both hold two
    signatures for one selector (a curated table and a dump: the dump has
    one line per selector and kind)."""
    transfer_inputs = [_p("address", "to"), _p("uint256", "amount")]
    curated = tmp_path / "curated.json"
    curated.write_text(json.dumps({"abi": [
        {"type": "function", "name": "transfer", "inputs": transfer_inputs, "outputs": [_p("bool")],
         "stateMutability": "nonpayable"},
        {"type": "error", "name": "transfer", "inputs": transfer_inputs},
        {"type": "error", "name": "burn", "inputs": [_p("uint256", "amount")]},
    ]}))
    lines = [
        _line(COLLIDING, "function", [_p("bytes1", "x")], outputs=[], stateMutability="nonpayable"),
        _line(COLLIDING, "error", [_p("bytes1", "x")]),
        _line(BURN_COLLIDING, None, [_p("bytes16", "id")]),  # no type: not declared as an error
    ]
    dump = tmp_path / "dump.xz"
    with lzma.open(str(dump), "wt", encoding="utf-8") as f:
        f.writelines(lines)
    path = tmp_path / "collisions.sqlite"
    stats = sigdb.build(path, {"curated": curated, "dump": dump})
    assert not any(stats["rejected"].values())
    with default_sigdb(path) as db:
        yield db


def test_colliding_signatures_are_real():
    assert sigs.function_selector(TRANSFER) == sigs.function_selector(COLLIDING) == 0xA9059CBB
    assert sigs.function_selector(BURN) == sigs.function_selector(BURN_COLLIDING)


def test_functions_carry_outputs_and_mutability(bundled_sigdb):
    cands = sigs.function_candidates(0xA9059CBB)
    assert [c.signature for c in cands] == [TRANSFER]
    (c,) = cands
    assert c.kind == "function" and c.outputs == (("bool", ""),) and c.mutability == "nonpayable" and c.trusted
    assert c.inputs[0][0] == "address" and c.inputs[1][0] == "uint256" and not c.generic_names
    (view,) = sigs.function_candidates(sigs.function_selector("balanceOf(address)"))
    assert view.outputs == (("uint256", ""),) and view.mutability == "view"
    # one signature, several output lists: every one is a candidate
    approve = sigs.function_candidates(sigs.function_selector("approve(address,uint256)"))
    assert {c.signature for c in approve} == {"approve(address,uint256)"}
    assert (("bool", ""),) in {c.outputs for c in approve}
    assert all(sigs.function_selector(c.signature) == 0x095EA7B3 for c in approve)


def test_events_are_found_by_full_topic_and_indexed_count(bundled_sigdb):
    topic = sigs.event_topic("Transfer(address,address,uint256)")
    both = sigs.event_candidates(topic)
    assert {sum(c.indexed) for c in both} == {2, 3}
    assert all(c.kind == "event" and c.signature == "Transfer(address,address,uint256)" for c in both)
    (two,) = sigs.event_candidates(topic, 2)
    assert two.indexed == (True, True, False) and [n for _, n in two.inputs] == ["from", "to", "value"]
    (three,) = sigs.event_candidates(topic, 3)
    assert three.indexed == (True, True, True)
    assert sigs.event_candidates(topic, 1) == ()
    # the first 4 bytes of a topic are not enough: the whole hash is the key
    assert sigs.event_candidates((topic >> 224 << 224) | 1) == ()


def test_errors_have_their_namespace(bundled_sigdb):
    sel = sigs.function_selector("OwnableUnauthorizedAccount(address)")
    (c,) = sigs.error_candidates(sel)
    assert c.kind == "error" and c.declared and c.signature == "OwnableUnauthorizedAccount(address)"
    assert c.inputs == (("address", "account"),)
    assert sigs.function_candidates(sel) == ()  # an error is no function
    three = sigs.error_candidates(sigs.function_selector("ERC20InsufficientBalance(address,uint256,uint256)"))
    assert [n for _, n in three[0].inputs] == ["sender", "balance", "needed"]
    assert [c.signature for c in sigs.error_candidates(0x08C379A0)] == ["Error(string)"]
    # a function signature with the selector is offered last, marked as not declared an error
    (other,) = sigs.error_candidates(0xA9059CBB)
    assert other.signature == TRANSFER and not other.declared


def test_colliding_functions_are_told_apart_by_the_decoder_checks(collisions):
    cands = sigs.function_candidates(0xA9059CBB)
    assert {c.signature for c in cands} == {TRANSFER, COLLIDING}
    assert all(sigs.function_selector(c.signature) == 0xA9059CBB for c in cands)
    # a two-word head with a validated address: transfer; one word validated as bytes1: the other
    assert abi._choose(cands, 2, {0: "address"}, frozenset(), strict=True).signature == TRANSFER
    assert abi._choose(cands, 1, {0: "bytes1"}, frozenset(), strict=True).signature == COLLIDING
    # the reverse order of the candidates changes nothing
    assert abi._choose(cands[::-1], 2, {0: "address"}, frozenset(), strict=True).signature == TRANSFER
    assert abi._choose(cands[::-1], 1, {0: "bytes1"}, frozenset(), strict=True).signature == COLLIDING
    # checks neither signature explains: no name
    assert abi._choose(cands, 3, {}, frozenset(), strict=True) is None
    assert abi._choose(cands, 1, {0: "address"}, frozenset(), strict=True) is None


def test_colliding_errors_and_the_type_filter(collisions):
    cands = sigs.error_candidates(0xA9059CBB)
    assert {c.signature for c in cands} == {TRANSFER, COLLIDING} and all(c.declared for c in cands)
    assert [c.signature for c in sigs.error_candidates(0xA9059CBB, ("bytes1",))] == [COLLIDING]
    assert [c.signature for c in sigs.error_candidates(0xA9059CBB, ("address", "uint256"))] == [TRANSFER]
    assert sigs.error_candidates(0xA9059CBB, ("uint256",)) == ()
    # declared errors first, then the signatures of unknown kind
    burn = sigs.error_candidates(sigs.function_selector(BURN))
    assert [(c.signature, c.declared) for c in burn] == [(BURN, True), (BURN_COLLIDING, False)]


def test_unknown_keys_have_no_candidate(bundled_sigdb):
    assert sigs.function_candidates(0x5EED0001) == ()
    assert sigs.error_candidates(0x5EED0001) == ()
    assert sigs.event_candidates(0x5EED0001 << 224) == ()


def test_only_keccak_verified_declarable_entries_are_returned(bundled_sigdb, monkeypatch):
    transfer = {"name": "transfer", "inputs": [_p("address"), _p("uint256")], "sources": ["curated"]}
    answers = [
        transfer,  # hashes to another selector than the one asked
        {"name": "unknown5eed0002", "inputs": [], "sources": ["dump"]},  # placeholder
        {"name": "get", "inputs": [_p("Lib.Data storage")], "sources": ["dump"]},  # not an ABI type
        dict(transfer, library=True),
    ]
    monkeypatch.setattr(sigdb, "lookup_function", lambda selector, types=None: answers)
    monkeypatch.setattr(sigdb, "lookup_error", lambda selector, types=None: answers)
    sigs.function_candidates.cache_clear()
    sigs.error_candidates.cache_clear()
    assert sigs.function_candidates(0x5EED0002) == ()
    assert sigs.error_candidates(0x5EED0002) == ()
    assert [c.signature for c in sigs.function_candidates(0xA9059CBB)] == [TRANSFER]  # the library entry is dropped


def test_a_failing_database_gives_no_candidate(bundled_sigdb, monkeypatch, caplog):
    def broken(*args, **kwargs):
        raise OSError("database is locked")

    for name in ("lookup_function", "lookup_event", "lookup_error"):
        monkeypatch.setattr(sigdb, name, broken)
    for f in (sigs.function_candidates, sigs.event_candidates, sigs.error_candidates):
        f.cache_clear()
    assert sigs.function_candidates(0xA9059CBB) == ()
    assert sigs.event_candidates(sigs.event_topic("Transfer(address,address,uint256)"), 2) == ()
    assert sigs.error_candidates(0x08C379A0) == ()
    assert "signature database lookup failed" in caplog.text


def test_without_a_database_nothing_is_named(monkeypatch):
    monkeypatch.setattr(sigdb, "get_default", lambda: None)
    for f in (sigs.function_candidates, sigs.event_candidates, sigs.error_candidates):
        f.cache_clear()
    try:
        assert sigs.function_candidates(0xA9059CBB) == ()
        assert sigs.error_candidates(0x08C379A0) == ()
    finally:
        for f in (sigs.function_candidates, sigs.event_candidates, sigs.error_candidates):
            f.cache_clear()

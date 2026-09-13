"""
Regression tests for the storage-postprocessing resilience fix
(scobelix/sparser.py::_sparser_resilient).

Before this fix, contract.py::postprocess() caught any exception from
sparser.rewrite_functions() and reset self.stor_defs to {} for the *entire*
contract - meaning a single unresolvable storage slot (e.g. a deeply embedded
struct expression tripping one of the "deep embedding unsupported" asserts in
simplify.py) would silently un-name and un-type every other slot too.

_sparser_resilient() now isolates the offending entry/entries instead, so the
rest of the contract's storage still resolves normally. These tests exercise
that isolation logic directly against a stubbed `_sparser`, independent of
the real (complex, heuristic) storage-parsing engine.
"""

import scobelix.sparser as sparser


def test_no_failures_returns_normal_result(monkeypatch):
    def fake_sparser(storages):
        return {s: f"resolved_{s}" for s in storages}

    monkeypatch.setattr(sparser, "_sparser", fake_sparser)

    result = sparser._sparser_resilient(["a", "b", "c"])
    assert result == {"a": "resolved_a", "b": "resolved_b", "c": "resolved_c"}


def test_single_bad_entry_is_excluded_others_still_resolve(monkeypatch):
    def fake_sparser(storages):
        if "bad" in storages:
            raise AssertionError("deep embedding unsupported")
        return {s: f"resolved_{s}" for s in storages}

    monkeypatch.setattr(sparser, "_sparser", fake_sparser)

    result = sparser._sparser_resilient(["a", "bad", "b", "c"])
    # every entry except the culprit is still named/typed
    assert result == {"a": "resolved_a", "b": "resolved_b", "c": "resolved_c"}


def test_multiple_bad_entries_are_excluded_one_at_a_time(monkeypatch):
    bad_entries = {"bad1", "bad2"}

    def fake_sparser(storages):
        if bad_entries & set(storages):
            raise AssertionError("deep embedding unsupported")
        return {s: f"resolved_{s}" for s in storages}

    monkeypatch.setattr(sparser, "_sparser", fake_sparser)

    result = sparser._sparser_resilient(["a", "bad1", "b", "bad2", "c"])
    assert result == {"a": "resolved_a", "b": "resolved_b", "c": "resolved_c"}


def test_unresolvable_as_a_whole_gives_up_instead_of_looping_forever(monkeypatch):
    def always_fails(storages):
        raise AssertionError("deep embedding unsupported")

    monkeypatch.setattr(sparser, "_sparser", always_fails)

    import pytest

    with pytest.raises(AssertionError):
        sparser._sparser_resilient(["a", "b"])


def test_find_unresolvable_storage_identifies_the_single_culprit(monkeypatch):
    def fake_sparser(storages):
        if "bad" in storages:
            raise AssertionError
        return True

    monkeypatch.setattr(sparser, "_sparser", fake_sparser)

    culprit = sparser._find_unresolvable_storage(["a", "bad", "b"])
    assert culprit == "bad"


def test_find_unresolvable_storage_returns_none_when_failure_is_interaction_only(
    monkeypatch,
):
    # Neither "a" nor "b" is broken in isolation - the failure only shows up
    # when 2+ entries are processed together, so no single entry can be
    # blamed for it.
    def fails_only_together(storages):
        if len(storages) >= 2:
            raise AssertionError
        return True

    monkeypatch.setattr(sparser, "_sparser", fails_only_together)

    assert sparser._find_unresolvable_storage(["a", "b"]) is None

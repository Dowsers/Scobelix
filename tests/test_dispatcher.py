"""
Function dispatcher recognition (scobelix/dispatcher.py, Loader.run): every
selector becomes a function of its own, the fallback and the receive
function are told apart from solc's built-in revert, and payability takes
into account the callvalue check solc hoists above the dispatcher when no
entry point is payable.

The Dispatch* fixtures (tests/fixtures/sources, built by
tests/fixtures/build_fixtures.py) write a distinct marker constant in every
body, so a function that holds another one's code - a merged or duplicated
body, a wrong target - shows a foreign marker.
"""

import json
import re
from pathlib import Path

import pytest

import scobelix.dispatcher as dispatcher
from scobelix.decompiler import decompile_bytecode

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"

A, B, S = "0x0dbe671f", "0x4df7e3d0", "0x86b714e2"  # a(), b(), s()

# expected functions {key: (payable, marker)}; s() is the getter of `s`
_SMALL = {A: (False, 0x5EED0001), B: (True, 0x5EED0002), S: (False, None)}
_ALL_NON_PAYABLE = {
    "0x5f57697c": (False, 0x5EED0001),  # c1()
    "0x23f4761a": (False, 0x5EED0002),  # c2(uint256)
    "0xf2c07be5": (False, 0x5EED0003),  # c3()
    "0x04c1bd57": (False, 0x5EED0004),  # c4(address)
    "0x95d099ae": (False, 0x5EED0005),  # c5()
    S: (False, None),
}
_BINARY_SEARCH = {
    "0x10c772cc": 0x01, "0xebbd40a9": 0x02, "0xd758c88e": 0x03, "0x3d492ec4": 0x04,
    "0xcba58af7": 0x05, "0x8a67ee70": 0x06, "0x4e580bc4": 0x07, "0x6d738a50": 0x08,
    "0x905f7d67": 0x09, "0x8dc714ba": 0x0A, "0x40bcff2a": 0x0B, "0x6d4975a2": 0x0C,
    "0x920f5c73": 0x0D, "0x5fb43592": 0x0E, "0x24a75cfd": 0x0F, "0x3b88f6c2": 0x10,
}

_BINARY_SEARCH_FUNCTIONS = {k: (v >= 0x0E, 0x5EED0000 + v) for k, v in _BINARY_SEARCH.items()}
_BINARY_SEARCH_FUNCTIONS[S] = (False, None)


def _case(functions, fallback=None, receive=None, hoisted=False):
    """fallback: (payable, marker), None for solc's default revert;
    receive: marker or None; hoisted: one callvalue check above the dispatch."""
    return dict(functions=functions, fallback=fallback, receive=receive, hoisted=hoisted)


CASES = {
    "DispatchNone": _case(_SMALL),
    "DispatchAllNonPayable": _case(_ALL_NON_PAYABLE, fallback=(False, 0x5EED0006), hoisted=True),
    # via-IR checks callvalue in every function instead
    "DispatchAllNonPayableViaIR": _case(_ALL_NON_PAYABLE, fallback=(False, 0x5EED0006)),
    "DispatchReceiveOnly": _case(_SMALL, receive=0x5EED0003),
    "DispatchFallbackOnly": _case(_SMALL, fallback=(True, 0x5EED0003)),
    "DispatchFallbackOnlyViaIRNoopt": _case(_SMALL, fallback=(True, 0x5EED0003)),
    "DispatchBoth": _case(_SMALL, fallback=(True, 0x5EED0004), receive=0x5EED0003),
    "DispatchBothViaIR": _case(_SMALL, fallback=(True, 0x5EED0004), receive=0x5EED0003),
    "DispatchFallbackOld": _case(_SMALL, fallback=(False, 0x5EED0003)),
    "DispatchLegacy04": _case(_SMALL, fallback=(True, 0x5EED0003)),
    # f14..f16 are payable
    "DispatchBinarySearch": _case(_BINARY_SEARCH_FUNCTIONS),
}

_MARKER_RE = re.compile(r"(?<![\w.])(\d{10})(?![\w.])")
_cache = {}


def _decompile(name):
    if name not in _cache:
        _cache[name] = decompile_bytecode((FIXTURES_DIR / f"{name}.hex").read_text().strip())
    return _cache[name]


def _markers(trace):
    text = json.dumps(trace, default=str)
    return {int(x) for x in _MARKER_RE.findall(text) if 0x5EED0000 <= int(x) <= 0x5EEDFFFF}


@pytest.mark.parametrize("name", sorted(CASES))
def test_every_selector_becomes_its_own_function(name):
    d = _decompile(name)
    case = CASES[name]

    assert d.json["problems"] == {}
    assert {s["selector"] for s in d.dispatcher["selectors"]} == set(case["functions"])

    expected = set(case["functions"]) | {dispatcher.FALLBACK}
    if case["receive"] is not None:
        expected.add(dispatcher.RECEIVE)
    assert set(d.functions) == expected
    assert {f["hash"] for f in d.json["functions"]} == expected


@pytest.mark.parametrize("name", sorted(CASES))
def test_bodies_are_neither_merged_nor_duplicated(name):
    d = _decompile(name)
    case = CASES[name]

    own = {key: {marker} if marker else set() for key, (_, marker) in case["functions"].items()}
    own[dispatcher.FALLBACK] = {case["fallback"][1]} if case["fallback"] else set()
    if case["receive"] is not None:
        own[dispatcher.RECEIVE] = {case["receive"]}

    for key, func in d.functions.items():
        assert _markers(func.orig_trace) == own[key], key


@pytest.mark.parametrize("name", sorted(CASES))
def test_payable_flags(name):
    d = _decompile(name)
    case = CASES[name]

    for key, (payable, _) in case["functions"].items():
        assert d.functions[key].payable is payable, key
    if case["fallback"] is not None:
        assert d.functions[dispatcher.FALLBACK].payable is case["fallback"][0]
    if case["receive"] is not None:
        assert d.functions[dispatcher.RECEIVE].payable is True
    assert d.dispatcher["callvalue_hoisted"] is case["hoisted"]


@pytest.mark.parametrize("name", sorted(CASES))
def test_fallback_and_receive_classification(name):
    d = _decompile(name)
    case = CASES[name]
    fallback = d.dispatcher["fallback"]

    assert fallback["function"] == dispatcher.FALLBACK
    assert fallback["present"] is (case["fallback"] is not None)
    assert fallback["default_revert"] is (case["fallback"] is None)
    assert fallback["consistent"] is True
    assert d.dispatcher["regular"] is True
    if case["receive"] is None:
        assert d.dispatcher["receive"] is None
    else:
        assert d.dispatcher["receive"]["function"] == dispatcher.RECEIVE
    # every default exit runs the code of one of the two default functions
    defaults = {dispatcher.FALLBACK, dispatcher.RECEIVE}
    assert {x["function"] for x in d.dispatcher["exits"]} <= defaults
    # the solc default is the plain revert
    if case["fallback"] is None:
        assert dispatcher.is_plain_revert(d.functions[dispatcher.FALLBACK].trace)


# Selector routing behind code that is not a dispatcher (DispatchGuarded.sol):
# {fixture: (selector functions, markers the whole-code fallback must hold)}
_NOT_DISPATCHERS = {
    "DispatchGuarded": ({A}, {0x5EED0002, 0x5EED0003, 0x5EED0004}),
    "DispatchGuardedProxy": (set(), set()),
    "DispatchValueFirst": (set(), {0x5EED0005, 0x5EED0006}),
}


@pytest.mark.parametrize("name", sorted(_NOT_DISPATCHERS))
def test_selectors_routed_behind_other_code_stay_in_the_fallback(name):
    # An access check or a value-dependent path above selector tests: those
    # selectors are not entry points (split out, they would look callable by
    # anyone, with any value), and no other path of the fallback may be lost.
    selectors, markers = _NOT_DISPATCHERS[name]
    d = _decompile(name)

    assert d.json["problems"] == {}
    assert {s["selector"] for s in d.dispatcher["selectors"]} == selectors
    assert set(d.functions) == selectors | {dispatcher.FALLBACK}
    assert d.dispatcher["regular"] is False
    fallback = d.dispatcher["fallback"]
    assert (fallback["kind"], fallback["target"], fallback["present"]) == ("whole_code", 0, True)
    trace = d.functions[dispatcher.FALLBACK].orig_trace
    assert markers <= _markers(trace)
    text = json.dumps(trace, default=str)
    if name == "DispatchGuardedProxy":
        assert '"delegatecall"' in text  # what everybody but the admin gets
    if name == "DispatchValueFirst":
        assert '"callvalue"' in text and '"caller"' in text  # the deposit


def test_hoisted_callvalue_check_makes_every_function_non_payable():
    # SimpleToken has no payable entry point: solc checks callvalue once,
    # before the dispatch, and the function bodies have no check at all.
    d = decompile_bytecode((FIXTURES_DIR / "SimpleToken.hex").read_text().strip())

    assert d.dispatcher["callvalue_hoisted"] is True
    assert all(s["callvalue_hoisted"] for s in d.dispatcher["selectors"])
    assert all(f["payable"] is False for f in d.json["functions"])
    text = re.sub(r"\x1b\[[0-9;]*m", "", d.text)
    assert "def transfer(address to, uint256 amount): # not payable" in text
    assert not re.search(r"\) payable:", text)


def test_dispatcher_and_metadata_are_in_the_json():
    d = _decompile("DispatchBoth")

    assert d.json["dispatcher"] == d.dispatcher
    assert d.json["metadata"] == d.metadata
    assert d.metadata["compiler"] == "solc" and d.metadata["version"] == "0.7.6"
    # the in-memory Function objects are not serialised
    json.dumps(d.json)
    assert "functions" not in json.dumps(d.dispatcher)
    assert d.bytecode == (FIXTURES_DIR / "DispatchBoth.hex").read_text().strip()


def test_selector_test_shapes():
    # shr(224, calldataload(0)) as the VM encodes it
    s_shr = ("mask_shl", 256, -224, -224, ("cd", 0))
    s_div = ("mask_shl", 32, 224, -224, ("cd", 0))  # div(calldataload(0), 2**224), solc 0.4
    k = 0x0DBE671F

    for s in (s_shr, s_div, ("mask_shl", 32, 0, 0, s_shr), ("div", ("cd", 0), 2**224)):
        assert dispatcher.selector_test(("eq", k, s)) == (k, True)
        assert dispatcher.selector_test(("eq", s, k)) == (k, True)
        assert dispatcher.selector_test(("iszero", ("eq", k, s))) == (k, False)
        # via-IR last switch case: K - S and S - K, function in the false branch
        assert dispatcher.selector_test(("add", k, ("mul", -1, s))) == (k, False)
        assert dispatcher.selector_test(("add", -k, s)) == (k, False)
        assert dispatcher.selector_test(("add", 2**256 - k, s)) == (k, False)
        assert dispatcher.selector_test(("xor", k, s)) == (k, False)
        assert dispatcher.selector_test(("iszero", ("add", k, ("mul", -1, s)))) == (k, True)

    # not selector comparisons
    assert dispatcher.selector_test(("eq", k, ("cd", 0))) is None  # whole calldata word
    assert dispatcher.selector_test(("eq", k << 224, ("mask_shl", 32, 224, 0, ("cd", 0)))) is None
    assert dispatcher.selector_test(("eq", 2**32, s_shr)) is None
    assert dispatcher.selector_test(("eq", k, ("mask_shl", 32, 224, -224, ("cd", 4)))) is None
    assert dispatcher.selector_test(("eq", k, ("mask_shl", 16, 0, 0, s_shr))) is None
    assert dispatcher.selector_test(("lt", k, s_shr)) is None
    assert dispatcher.selector_test(("eq", True, s_shr)) is None
    assert dispatcher.is_selector_range_test(("gt", k, s_shr))


_SEL = ("mask_shl", 256, -224, -224, ("cd", 0))


def _jd(pc):
    return ("jd", pc, ())


def _select(selector, target, rest):
    """A selector comparison as the VM leaves it: the match cut out as a funccall."""
    call = [_jd(target), ("funccall", selector, target, ())]
    return [_jd(target - 1), ("if", ("eq", selector, _SEL), call, rest)]


def test_analysis_of_synthetic_dispatchers():
    # the same selector twice: the first target is kept, the clash recorded
    trace = _select(1, 20, _select(1, 50, [_jd(60), ("revert", None)]))
    d = dispatcher.analyse(trace)
    assert [(e.selector, e.target) for e in d.entries] == [(1, 20)]
    assert d.duplicates == [(1, 20, 50)]
    assert d.regular is True and d.fallback_consistent is True
    assert d.fallback.start == 60 and d.fallback_is_default

    assert dispatcher.analyse([_jd(0), ("stop",)]) is None


def test_code_that_is_not_a_dispatcher_is_not_split():
    # Selector tests behind an access check only run for that caller: they
    # are not entry points, and the other caller's path (here the stop) must
    # not be lost. The whole code is the fallback.
    dispatch = _select(0xAABBCCDD, 20, [_jd(30), ("revert", None)])
    trace = [_jd(0), ("if", ("eq", "caller", 0x1234), dispatch, [_jd(40), ("stop",)])]
    assert dispatcher.analyse(trace) is None

    # a side effect before the selector tests: same thing
    trace = [_jd(0), ("store", 256, 0, 0, 1)] + dispatch
    assert dispatcher.analyse(trace) is None

    # a callvalue test whose other branch does something: not a hoisted check
    trace = [_jd(0), ("if", "callvalue", [_jd(3), ("store", 256, 0, 0, 1), ("stop",)], dispatch)]
    assert dispatcher.analyse(trace) is None

    # after a regular dispatch, a default branch that routes selectors behind
    # a condition of its own is default code: decompiled in one piece, from
    # the start of that branch
    guarded = [_jd(50), ("if", ("eq", "caller", 0x1234), _select(2, 70, [_jd(80), ("stop",)]),
                         [_jd(90), ("revert", None)])]
    d = dispatcher.analyse(_select(1, 20, guarded))
    assert [e.key for e in d.entries] == ["0x00000001"]
    assert d.fallback.start == 50 and d.fallback.irregular
    assert d.fallback_is_default is False and d.regular is False


def test_default_exits_running_different_code_make_the_whole_code_the_fallback():
    # short calldata stops, unknown selectors revert: no single default
    # function tells both, the whole code does
    dispatch = _select(1, 20, [_jd(30), ("revert", None)])
    trace = [_jd(0), ("if", ("lt", "calldatasize", 4), [_jd(5), ("stop",)], dispatch)]
    d = dispatcher.analyse(trace)
    assert [e.key for e in d.entries] == ["0x00000001"]
    assert d.fallback_consistent is False
    assert d.fallback is None and d.receive is None and not d.fallback_is_default
    summary = d.to_dict()
    assert summary["fallback"] == {
        "function": "_fallback",
        "target": 0,
        "kind": "whole_code",
        "present": True,
        "default_revert": False,
        "consistent": False,
    }
    # the whole code holds every exit
    assert [x["function"] for x in summary["exits"]] == ["_fallback", "_fallback"]

    # the same code reached with different memory is not the same behaviour
    written = [_jd(5), ("setmem", ("range", 0, 32), 1)] + _select(
        2, 40, [_jd(30), ("revert", None)]
    )
    trace = [_jd(0), ("if", ("lt", "calldatasize", 4), written, dispatch)]
    d = dispatcher.analyse(trace)
    assert [e.key for e in d.entries] == ["0x00000002", "0x00000001"]
    assert d.fallback is None and d.fallback_consistent is False


def test_payable_unless_every_path_checks_callvalue():
    revert = [_jd(9), ("revert", None)]
    guarded = [_jd(2), ("if", "callvalue", revert, _select(1, 20, [_jd(30), ("revert", None)]))]
    # the same function reached with and without the callvalue check
    trace = [_jd(0), ("if", ("lt", "calldatasize", 4), _select(1, 20, [_jd(30), ("revert", None)]),
                      guarded)]
    d = dispatcher.analyse(trace)
    assert [e.key for e in d.entries] == ["0x00000001"]
    assert d.entries[0].callvalue_guarded is False
    assert d.callvalue_hoisted is False
    assert dispatcher.FALLBACK not in d.callvalue_guarded_keys()

    d = dispatcher.analyse([_jd(0)] + guarded)
    assert d.callvalue_guarded_keys() == {"0x00000001", dispatcher.FALLBACK}


def test_entries_carry_the_memory_the_dispatcher_wrote():
    seed = [("setmem", ("range", 64, 32), 0), ("setmem", ("range", 96, 32), 0)]
    prologue = [("setmem", ("range", 64, 32), 0x80)]
    constant = [("setmem", ("range", 0xA0, 32), 7)]
    trace = [_jd(0)] + seed + prologue + [_jd(1)] + constant + _select(
        1, 20, [_jd(30), ("revert", None)]
    )
    d = dispatcher.analyse(trace)

    assert d.entries[0].memory == tuple(seed + prologue + constant)
    assert d.fallback.memory == tuple(seed + prologue + constant)
    # the write the prologue replaced is dropped, the rest sorted by address
    assert dispatcher.memory_seed(d.entries[0].memory) == [
        ("setmem", ("range", 64, 32), 0x80),
        ("setmem", ("range", 96, 32), 0),
        ("setmem", ("range", 0xA0, 32), 7),
    ]
    # writes that may overlap keep their order
    odd = (("setmem", ("range", 64, 32), 1), ("setmem", ("range", 70, 4), 2))
    assert dispatcher.memory_seed(odd) == list(odd)
    symbolic = (("setmem", ("range", ("cd", 4), 32), 1), ("setmem", ("range", 64, 32), 2))
    assert dispatcher.memory_seed(symbolic) == list(symbolic)


def test_calldatasize_and_callvalue_tests():
    cds = dispatcher.calldatasize_test

    assert cds(("lt", "calldatasize", 4)) == ([(0, 3)], [(4, None)])
    assert cds(("ge", "calldatasize", 4)) == ([(4, None)], [(0, 3)])
    assert cds(("gt", 4, "calldatasize")) == ([(0, 3)], [(4, None)])
    assert cds(("iszero", "calldatasize")) == ([(0, 0)], [(1, None)])
    assert cds("calldatasize") == ([(1, None)], [(0, 0)])
    assert cds(("lt", "calldatasize", ("cd", 4))) is None
    assert cds(("lt", ("add", -4, "calldatasize"), 32)) is None

    assert dispatcher.callvalue_test("callvalue") is True
    assert dispatcher.callvalue_test(("iszero", "callvalue")) is False
    assert dispatcher.callvalue_test(("iszero", ("iszero", "callvalue"))) is True
    assert dispatcher.callvalue_test(("lt", "callvalue", 5)) is None

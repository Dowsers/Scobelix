"""
The time limit of the simplification (PANORAMIX_WHILES_TIMEOUT) bounds the
whole simplification, not only the time between two of its passes.

The rewrites whose cost grows with the square of the trace (cleanup_mems,
replace_mem, cleanup_vars) used to run to their end once a pass had
started: on a large trace one pass took longer than the limit, and the
function timeout then threw the function away (a `problem`). Past the
limit they now leave the rest of the trace as it is. Every rewrite keeps the
semantics, so the function stays exact, only less simplified; it is marked
`time_limited` (JSON, and a comment in the text).
"""

import functools
import logging
from pathlib import Path

import pytest
from eth_hash.auto import keccak

import scobelix.decompiler as decompiler
from scobelix.decompiler import decompile_bytecode
from trace_machine import Machine, NotEvaluable

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"
M = 2**256
HOLDER = 0xCA11E4  # the trace machine's caller


def _decompile(name):
    logging.disable(logging.CRITICAL)
    try:
        return decompile_bytecode((FIXTURES_DIR / f"{name}.hex").read_text().strip())
    finally:
        logging.disable(logging.NOTSET)


@functools.lru_cache(maxsize=None)
def _full(name):
    return _decompile(name)


def _limited(name, monkeypatch):
    # a limit already over when the simplification starts
    monkeypatch.setattr(decompiler, "WHILES_TIMEOUT", 1e-9)
    return _decompile(name)


def _selector(signature):
    return "0x" + keccak(signature.encode()).hex()[:8]


def _word(x):
    return (x % M).to_bytes(32, "big")


def _outcome(trace, calldata, storage):
    machine = Machine(calldata, storage=storage)
    ok, out = machine.call(trace)
    return ok, out, machine.storage, machine.logs


CALLS = {
    "SimpleToken": [
        ("balanceOf(address)", [HOLDER]),
        ("balanceOf(address)", [0xBEEF]),
        ("transfer(address,uint256)", [0xBEEF, 5]),
        ("transfer(address,uint256)", [0xBEEF, 10**30]),
        ("approve(address,uint256)", [0xBEEF, 7]),
        ("allowance(address,address)", [HOLDER, 0xBEEF]),
        ("transferFrom(address,address,uint256)", [HOLDER, 0xBEEF, 1]),
        ("totalSupply()", []),
    ],
}


@pytest.mark.parametrize("name", ["SimpleToken"])
def test_time_limited_functions_stay_exact(monkeypatch, name):
    full = _full(name)
    limited = _limited(name, monkeypatch)
    assert set(limited.functions) == set(full.functions)  # none became a `problem`
    assert all(f.time_limited for f in limited.functions.values())
    assert not any(f.time_limited for f in full.functions.values())
    assert "time_limited" in str(limited.json)
    assert "simplification stopped at its time limit" in limited.text
    # less simplified: the limit really stopped the rewrites
    assert any(limited.functions[h].orig_trace != full.functions[h].orig_trace for h in full.functions)
    # some storage with balances and an allowance for the calls
    storage = {}
    for slot in range(8):
        storage[slot] = 10**6
    compared = 0
    for signature, args in CALLS[name]:
        sel = _selector(signature)
        if sel not in full.functions:
            continue
        calldata = bytes.fromhex(sel[2:]) + b"".join(_word(a) for a in args)
        try:
            expected = _outcome(full.functions[sel].orig_trace, calldata, storage)
            got = _outcome(limited.functions[sel].orig_trace, calldata, storage)
        except NotEvaluable:
            continue
        assert got == expected, signature
        compared += 1
    assert compared >= 3


@pytest.mark.parametrize("checks", [1, 3, 10, 40, 150])
def test_a_limit_reached_inside_a_pass_keeps_the_code_exact(monkeypatch, checks):
    # the limit is reached after `checks` tests of it: inside cleanup_mems,
    # replace_mem or cleanup_vars of some pass, with part of the trace
    # rewritten and the rest not
    import scobelix.simplify as simplify

    count = {"n": 0}

    def out_of_time():
        count["n"] += 1
        if count["n"] > checks:
            simplify.last_run_timed_out = True
            return True
        return False

    monkeypatch.setattr(simplify, "_out_of_time", out_of_time)
    name = "SimpleToken"
    full = _full(name)
    limited = _decompile(name)
    assert set(limited.functions) == set(full.functions)
    storage = {slot: 10**6 for slot in range(8)}
    for signature, args in CALLS[name]:
        sel = _selector(signature)
        if sel not in full.functions:
            continue
        calldata = bytes.fromhex(sel[2:]) + b"".join(_word(a) for a in args)
        try:
            expected = _outcome(full.functions[sel].orig_trace, calldata, storage)
            got = _outcome(limited.functions[sel].orig_trace, calldata, storage)
        except NotEvaluable:
            continue
        assert got == expected, (checks, signature)


def test_without_a_limit_nothing_is_marked():
    d = _full("SimpleToken")
    assert "simplification stopped" not in d.text
    assert "time_limited" not in str(d.json)


def test_the_simplification_ends_before_the_function_timeout(monkeypatch):
    # the function timeout throws the function away: the simplification
    # keeps a share of it for the work it does after its own limit
    monkeypatch.setattr(decompiler, "FUNCTION_TIMEOUT", 100)
    assert decompiler.simplification_deadline(10.0) == 10.0 + 100 * (1 - decompiler.SIMPLIFY_RESERVE)
    assert 0 < decompiler.SIMPLIFY_RESERVE < 1
    monkeypatch.setattr(decompiler, "FUNCTION_TIMEOUT", 0)  # no function timeout
    assert decompiler.simplification_deadline(10.0) is None


def test_a_function_past_its_deadline_stays_exact(monkeypatch):
    # the deadline from the function timeout reaches the simplification
    # (WHILES_TIMEOUT keeps its default): every function is still there,
    # marked, with the outcomes of the fully simplified one
    import time

    monkeypatch.setattr(decompiler, "simplification_deadline", lambda started: time.monotonic() - 1)
    name = "SimpleToken"
    full = _full(name)
    limited = _decompile(name)
    assert set(limited.functions) == set(full.functions)
    assert all(f.time_limited for f in limited.functions.values())
    storage = {slot: 10**6 for slot in range(8)}
    compared = 0
    for signature, args in CALLS[name]:
        sel = _selector(signature)
        if sel not in full.functions:
            continue
        calldata = bytes.fromhex(sel[2:]) + b"".join(_word(a) for a in args)
        try:
            expected = _outcome(full.functions[sel].orig_trace, calldata, storage)
            got = _outcome(limited.functions[sel].orig_trace, calldata, storage)
        except NotEvaluable:
            continue
        assert got == expected, signature
        compared += 1
    assert compared >= 3


def test_limits_combine():
    import time

    import scobelix.simplify as simplify

    trace = [("return", ("add", 1, 2))]
    simplify.simplify_trace(trace, timeout=600)
    assert not simplify.last_run_timed_out
    # the earliest limit wins: a deadline already past stops it at once
    simplify.simplify_trace(trace, timeout=600, deadline=time.monotonic() - 1)
    assert simplify.last_run_timed_out
    simplify.simplify_trace(trace, deadline=time.monotonic() + 600)
    assert not simplify.last_run_timed_out
    assert simplify._deadline is None  # restored after each run

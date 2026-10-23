"""
The global time budget of a decompilation: `decompile_bytecode(...,
time_budget=seconds)`, `--time-budget SECONDS` or SCOBELIX_TIME_BUDGET.

It is a deadline on the monotonic clock, consulted before the function
discovery and before every function. A share of it (10 %, at least 5 s) is
kept for what follows the functions (storage, JSON, text), which has no
time limit of its own, and grows by half the time of every function kept
less simplified. Every step keeps its own budget (LOADER_TIMEOUT,
FUNCTION_TIMEOUT, VM_RUN_TIMEOUT, the simplification deadline), capped by
what is left; a function reached with less than a second left is not
decompiled (a `problem`, listed in `time_budget.skipped`). Without a budget
nothing changes: every step gets exactly the limit it always had.

The clock is `decompiler._clock`: the tests replace it. The decompiler
reads it once when the budget starts, once before the discovery, once
before every function and once after every function kept less simplified.
"""

import logging
import math
import time
from pathlib import Path

import pytest
import timeout_decorator

import scobelix.decompiler as decompiler
import scobelix.loader as loader
from scobelix.__main__ import parse_args
from scobelix.decompiler import TimeBudget, decompile_bytecode
from scobelix.vm import VM

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"
SIMPLE_TOKEN = (FIXTURES_DIR / "SimpleToken.hex").read_text().strip()
# the entry points of SimpleToken, in the order they are decompiled
ORDER = ["0x18160ddd", "0x70a08231", "0xa9059cbb", "_fallback"]


def _decompile(code=SIMPLE_TOKEN, **kwargs):
    logging.disable(logging.CRITICAL)
    try:
        return decompile_bytecode(code, **kwargs)
    finally:
        logging.disable(logging.NOTSET)


def _clock_reading(monkeypatch, values):
    """decompiler._clock gives `values` one by one, then the last one."""
    values = list(values)

    def clock():
        return values.pop(0) if len(values) > 1 else values[0]

    monkeypatch.setattr(decompiler, "_clock", clock)


def _stepping_clock(monkeypatch, step):
    """decompiler._clock advances by `step` seconds at every reading."""
    now = [0.0]

    def clock():
        now[0] += step
        return now[0]

    monkeypatch.setattr(decompiler, "_clock", clock)


def _spies(monkeypatch):
    """What every step receives: the seconds of the per-function alarm, the
    `timeout` of every symbolic execution (the discovery first), and for
    every simplification its `deadline` next to the time it started."""
    seen = {"alarm": [], "vm": [], "whiles": []}
    real_timeout = timeout_decorator.timeout

    def timeout(seconds, *args, **kwargs):
        seen["alarm"].append(seconds)
        return real_timeout(seconds, *args, **kwargs)

    monkeypatch.setattr(timeout_decorator, "timeout", timeout)
    real_run = VM.run

    def run(self, start, *args, **kwargs):
        seen["vm"].append(kwargs.get("timeout"))
        return real_run(self, start, *args, **kwargs)

    monkeypatch.setattr(VM, "run", run)
    real_whiles = decompiler.make_whiles

    def make_whiles(trace, **kwargs):
        seen["whiles"].append((time.monotonic(), kwargs.get("deadline")))
        return real_whiles(trace, **kwargs)

    monkeypatch.setattr(decompiler, "make_whiles", make_whiles)
    return seen


# ---------------------------------------------------------------- the budget


def test_the_reserve_is_a_share_of_the_budget_with_a_floor(monkeypatch):
    _clock_reading(monkeypatch, [1000.0])
    budget = TimeBudget.start(100)
    assert (budget.seconds, budget.deadline, budget.reserve) == (100, 1100.0, 10.0)
    assert budget.remaining() == 100.0 and budget.left_for_functions() == 90.0
    assert TimeBudget.start(20).reserve == 5.0
    assert not budget.exhausted and budget.skipped == []


@pytest.mark.parametrize("seconds", [0, -1, math.inf, math.nan, True, False, "5"])
def test_a_budget_must_be_a_positive_number_of_seconds(seconds):
    with pytest.raises(ValueError):
        TimeBudget.start(seconds)
    with pytest.raises(ValueError):
        _decompile(time_budget=seconds)


@pytest.mark.parametrize("seconds", [1e10, 1e11, 1e300])
def test_a_budget_too_long_for_an_alarm_sets_no_limit(seconds, monkeypatch):
    # signal.setitimer refuses about 9.2e9 s and more: every alarm is capped
    # (31 years), even for a step without a limit of its own
    seen = _spies(monkeypatch)
    monkeypatch.setattr(decompiler, "FUNCTION_TIMEOUT", 0)
    d = _decompile(time_budget=seconds)
    assert set(d.functions) == set(ORDER) and d.json["problems"] == {}
    assert seen["alarm"] == [decompiler.MAX_ALARM_SECONDS] * 4
    assert not d.time_budget.exhausted and d.time_budget.skipped == []


# ---------------------------------------------------------------- what every step gets


def test_without_a_budget_every_step_keeps_its_own_limit(monkeypatch):
    seen = _spies(monkeypatch)
    d = _decompile()
    assert d.time_budget is None and set(d.functions) == set(ORDER)
    assert seen["alarm"] == [decompiler.FUNCTION_TIMEOUT] * 4
    assert seen["vm"] == [loader.LOADER_TIMEOUT] + [decompiler.VM_RUN_TIMEOUT] * 4
    share = decompiler.FUNCTION_TIMEOUT * (1 - decompiler.SIMPLIFY_RESERVE)
    for started, deadline in seen["whiles"]:
        assert 0 <= share - (deadline - started) < 1.0


def test_under_a_budget_every_step_is_capped_by_what_is_left(monkeypatch):
    seen = _spies(monkeypatch)
    _clock_reading(monkeypatch, [0.0])  # time does not pass: 90 s are left for every step
    d = _decompile(time_budget=100)
    assert set(d.functions) == set(ORDER) and d.json["problems"] == {}
    assert seen["alarm"] == [90.0] * 4
    # the symbolic execution keeps the share of the function's budget it has
    # without a global one (600 of 720 s): it ends before the alarm
    share = decompiler.VM_RUN_TIMEOUT / decompiler.FUNCTION_TIMEOUT
    assert seen["vm"] == [90.0] + [90.0 * share] * 4 and 90.0 * share < 90.0
    for started, deadline in seen["whiles"]:
        assert 0 <= 90.0 * (1 - decompiler.SIMPLIFY_RESERVE) - (deadline - started) < 1.0
    assert (d.time_budget.seconds, d.time_budget.exhausted, d.time_budget.skipped) == (100, False, [])


def test_a_step_without_a_limit_of_its_own_gets_what_is_left(monkeypatch):
    seen = _spies(monkeypatch)
    _clock_reading(monkeypatch, [0.0])
    monkeypatch.setattr(decompiler, "FUNCTION_TIMEOUT", 0)
    monkeypatch.setattr(decompiler, "VM_RUN_TIMEOUT", 0)
    monkeypatch.setattr(loader, "LOADER_TIMEOUT", 0)
    _decompile(time_budget=100)
    assert seen["alarm"] == [90.0] * 4
    assert seen["vm"] == [90.0] + [90.0 * (1 - decompiler.SIMPLIFY_RESERVE)] * 4
    assert all(deadline is not None for _, deadline in seen["whiles"])
    monkeypatch.setattr(decompiler, "FUNCTION_TIMEOUT", 720)  # a function budget, no limit of the execution
    seen["vm"].clear()
    _decompile(time_budget=100)
    assert seen["vm"] == [90.0] + [90.0 * (1 - decompiler.SIMPLIFY_RESERVE)] * 4
    # no function budget, a limit of the execution: that limit at most
    monkeypatch.setattr(decompiler, "FUNCTION_TIMEOUT", 0)
    monkeypatch.setattr(decompiler, "VM_RUN_TIMEOUT", 60)
    seen["vm"].clear()
    _decompile(time_budget=100)
    assert seen["vm"] == [90.0] + [60] * 4
    seen["vm"].clear()
    _decompile(time_budget=50)  # 45 s for a function: 75 % of it, under the limit
    assert seen["vm"] == [45.0] + [45.0 * (1 - decompiler.SIMPLIFY_RESERVE)] * 4


def test_the_simplification_deadline_follows_the_capped_function_budget(monkeypatch):
    monkeypatch.setattr(decompiler, "FUNCTION_TIMEOUT", 100)
    assert decompiler.simplification_deadline(10.0) == 10.0 + 100 * (1 - decompiler.SIMPLIFY_RESERVE)
    assert decompiler.simplification_deadline(10.0, budget=40) == 10.0 + 40 * (1 - decompiler.SIMPLIFY_RESERVE)
    monkeypatch.setattr(decompiler, "FUNCTION_TIMEOUT", 0)
    assert decompiler.simplification_deadline(10.0) is None
    assert decompiler.simplification_deadline(10.0, budget=40) == 10.0 + 40 * (1 - decompiler.SIMPLIFY_RESERVE)


# ---------------------------------------------------------------- when it runs out


def test_the_functions_reached_after_the_budget_are_problems(monkeypatch):
    # 100 s, 10 of them reserved; the clock advances by 20 s at every reading:
    # 20 when the budget starts, 40 before the discovery, then 60, 80, 100 and
    # 120 before the functions: the fourth one comes 10 s past the 110 s limit
    _stepping_clock(monkeypatch, 20)
    d = _decompile(time_budget=100)
    assert list(d.functions) == ORDER[:3]
    assert d.json["problems"] == {"_fallback": "_fallback(?)"}
    assert "I failed with these" in d.text and "_fallback(?)" in d.text
    assert [f["hash"] for f in d.json["functions"]] == ORDER[:3]  # the AST is intact
    assert d.time_budget.exhausted and d.time_budget.skipped == ["_fallback"]


def test_a_function_with_little_time_left_stays_exact_instead_of_failing(monkeypatch):
    # the second function has 2 s: its simplification stops at 75 % of them,
    # as it would at 75 % of FUNCTION_TIMEOUT, and the function is kept exact
    # and marked - not thrown away by the 2 s alarm (a problem)
    real_whiles = decompiler.make_whiles

    def slow_make_whiles(trace, **kwargs):
        deadline = kwargs.get("deadline")
        assert deadline is not None
        if deadline - time.monotonic() < 5:
            while time.monotonic() < deadline:  # a simplification that lasts until its deadline
                time.sleep(0.01)
        return real_whiles(trace, **kwargs)

    monkeypatch.setattr(decompiler, "make_whiles", slow_make_whiles)
    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 88.0, 1000.0])
    d = _decompile(time_budget=100)
    assert list(d.functions) == ORDER[:2]
    assert set(d.json["problems"]) == set(ORDER[2:]) == set(d.time_budget.skipped)
    assert not d.functions[ORDER[0]].time_limited
    assert d.functions[ORDER[1]].time_limited
    assert "simplification stopped at its time limit" in d.text


def test_a_function_is_not_attempted_with_less_than_a_second_left(monkeypatch, caplog):
    # 0.5 s left for the second function: it is left out like the next ones,
    # not started and cut short by its alarm (a failure with a traceback)
    seen = _spies(monkeypatch)
    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 100 - 10 - 0.5])
    with caplog.at_level(logging.WARNING, logger="scobelix.decompiler"):
        d = decompile_bytecode(SIMPLE_TOKEN, time_budget=100)
    assert seen["alarm"] == [90.0]
    assert list(d.functions) == ORDER[:1]
    assert set(d.json["problems"]) == set(ORDER[1:]) and d.time_budget.skipped == ORDER[1:]
    assert d.time_budget.exhausted
    assert len([r for r in caplog.records if "not decompiled, the time budget" in r.getMessage()]) == 3
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert decompiler.MIN_FUNCTION_SECONDS == 1.0


def _time_limited(monkeypatch, which):
    """The simplification of the functions numbered `which` (from 1, in the
    order they are decompiled) reports that it stopped at its time limit;
    the list returned counts the simplifications (clear it to count again)."""
    real_whiles, calls = decompiler.make_whiles, []

    def make_whiles(trace, **kwargs):
        out = real_whiles(trace, **kwargs)
        calls.append(1)
        if len(calls) in which:
            decompiler.simplify.last_run_timed_out = True
        return out

    monkeypatch.setattr(decompiler, "make_whiles", make_whiles)
    return calls


def test_a_function_kept_less_simplified_makes_the_reserve_larger(monkeypatch):
    # 100 s, 10 of them reserved. The first function is kept time_limited
    # after 40 s: half of that is added to the reserve, so the second one,
    # at 50 s, has 100 - 50 - 30 = 20 s instead of 40, the third one, at
    # 60 s, 10 s, and the fourth one, at 75 s, none
    seen = _spies(monkeypatch)
    _time_limited(monkeypatch, {1})
    _clock_reading(monkeypatch, [0.0, 0.0, 0.0, 40.0, 50.0, 60.0, 75.0])
    d = _decompile(time_budget=100)
    assert seen["alarm"] == [90.0, 20.0, 10.0]
    assert d.time_budget.reserve == 10.0 + decompiler.TIME_LIMITED_RESERVE * 40.0 == 30.0
    assert list(d.functions) == ORDER[:3] and d.functions[ORDER[0]].time_limited
    assert d.json["problems"] == {"_fallback": "_fallback(?)"} and d.time_budget.skipped == ["_fallback"]


def test_a_simplification_stopped_by_the_time_left_exhausts_the_budget(monkeypatch):
    # stopped at the deadline of a function budget the global budget capped
    # (90 s < FUNCTION_TIMEOUT): the budget cut the work short
    calls = _time_limited(monkeypatch, {2})
    _clock_reading(monkeypatch, [0.0])
    d = _decompile(time_budget=100)
    assert d.functions[ORDER[1]].time_limited and d.json["problems"] == {}
    assert d.time_budget.exhausted and d.time_budget.skipped == []
    # stopped at the function's own deadline (FUNCTION_TIMEOUT is shorter
    # than what is left): not the budget's doing
    monkeypatch.setattr(decompiler, "FUNCTION_TIMEOUT", 50)
    calls.clear()
    d = _decompile(time_budget=1000)
    assert d.functions[ORDER[1]].time_limited and not d.time_budget.exhausted


def test_a_bytecode_without_code_keeps_the_state_of_its_budget(monkeypatch, capsys):
    import json

    import scobelix.__main__ as cli

    for code in ("0x", ""):
        d = _decompile(code, time_budget=10)
        assert "No code found" in d.text and d.json == {}
        assert (d.time_budget.seconds, d.time_budget.exhausted, d.time_budget.skipped) == (10, False, [])
        assert _decompile(code).time_budget is None
    monkeypatch.delenv("SCOBELIX_TIME_BUDGET", raising=False)
    args = parse_args(["--combined-json", "--time-budget", "10", "0x"])
    cli.print_decompilation("0x", args)
    payload = json.loads(capsys.readouterr().out)
    assert payload["time_budget"] == {"seconds": 10.0, "exhausted": False, "skipped": []}


def test_a_tiny_budget_still_gives_a_result_quickly():
    started = time.monotonic()
    d = _decompile(time_budget=1e-3)
    assert time.monotonic() - started < 5
    assert d.text and "Palkeoramix decompiler" in d.text
    assert d.time_budget.exhausted and set(d.time_budget.skipped) == set(d.json["problems"])
    assert isinstance(d.json, dict) and d.json.get("functions") == []


# ---------------------------------------------------------------- the command line


def test_the_option_and_the_variable(monkeypatch):
    monkeypatch.delenv("SCOBELIX_TIME_BUDGET", raising=False)
    assert parse_args([SIMPLE_TOKEN]).time_budget is None
    assert parse_args(["--time-budget", "5", SIMPLE_TOKEN]).time_budget == 5.0
    assert parse_args(["--time-budget", "2.5", SIMPLE_TOKEN]).time_budget == 2.5
    monkeypatch.setenv("SCOBELIX_TIME_BUDGET", "7")
    assert parse_args([SIMPLE_TOKEN]).time_budget == 7.0  # read at every invocation
    assert parse_args(["--time-budget", "5", SIMPLE_TOKEN]).time_budget == 5.0  # the option wins
    monkeypatch.setenv("SCOBELIX_TIME_BUDGET", " ")
    assert parse_args([SIMPLE_TOKEN]).time_budget is None


@pytest.mark.parametrize("value", ["0", "-1", "inf", "soon"])
def test_an_unusable_budget_is_a_usage_error(value, monkeypatch, capsys):
    monkeypatch.delenv("SCOBELIX_TIME_BUDGET", raising=False)
    with pytest.raises(SystemExit) as e:
        parse_args(["--time-budget", value, SIMPLE_TOKEN])
    assert e.value.code == 2 and "usage:" in capsys.readouterr().err
    monkeypatch.setenv("SCOBELIX_TIME_BUDGET", value)
    with pytest.raises(SystemExit) as e:
        parse_args([SIMPLE_TOKEN])
    assert e.value.code == 2
    assert "SCOBELIX_TIME_BUDGET" in capsys.readouterr().err

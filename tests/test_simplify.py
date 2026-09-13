"""
Regression tests for scobelix/simplify.py.

These used to be bare `assert` statements executed as a side effect of
importing the module (a form of informal doctest). That meant: (1) they were
never run under pytest/CI, (2) they would be silently skipped entirely if the
interpreter were ever run with `-O`/`PYTHONOPTIMIZE` (which strips `assert`).
Moved here as real, always-executed tests.
"""

from scobelix.simplify import affects, canonise_max, find_mems, only_add_in_expr, sizeof


def test_canonise_max():
    assert canonise_max(("max", ("mul", 1, ("x", "y")), 4)) == ("max", 4, ("x", "y"))


def test_only_add_in_expr():
    assert only_add_in_expr(("setvar", 100, ("mul", ("var", 100), 1))) is False
    assert only_add_in_expr(("setvar", 100, ("add", ("var", 100), 1))) is True


def test_sizeof():
    assert sizeof(("mask_shl", 96, 160, 0, "x")) == 96
    assert sizeof(("mem", ("range", 64, 32))) == 32 * 8
    assert sizeof("x") is None


def test_find_mems():
    test_e = ("x", "sth", ("mem", 4), ("t", ("mem", 4), ("mem", 8), ("mem", ("mem", 64))))
    assert find_mems(test_e) == {
        ("mem", 64),
        ("mem", ("mem", 64)),
        ("mem", 4),
        ("mem", 8),
    }


def test_affects_overlapping_ranges():
    line_test = ("setmem", ("range", 65, 32), "x")

    exp_test = ("mul", 8, ("mem", ("range", 64, 32)))
    assert affects(line_test, exp_test) is True

    exp_test = ("mul", 8, ("mem", ("range", 100, 32)))
    assert affects(line_test, exp_test) is False


def test_affects_unknown_size_is_conservative():
    line_test = ("setmem", ("range", 65, "sth"), "x")

    exp_test = ("mul", 8, ("mem", ("range", 64, 32)))
    assert affects(line_test, exp_test) is True

    exp_test = ("mul", 8, ("mem", ("range", 100, 32)))
    assert affects(line_test, exp_test) is True


def test_affects_no_overlap_and_unknown_exp_size():
    line_test = ("setmem", ("range", 65, 32), "x")

    exp_test = ("mul", 8, ("mem", ("range", 64, 1)))
    assert affects(line_test, exp_test) is False

    exp_test = ("mul", 8, ("mem", ("range", 64, "sth")))
    assert affects(line_test, exp_test) is True

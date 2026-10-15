"""
Loop variables keep their own identity.

The VM names the variables of a loop after their stack position and the
depth where the loop was found. Two loops found at the same depth got the
same names: in BatchStrings.labelsOf the copy loop of a long string, on one
path, reused the name of the outer loop's index, so the code after it read
the copy pointer as the index (a variable read before any assignment on
one path, another loop's value on another).

Every function of the loop fixtures is checked: no loop assigns a variable
of a loop that encloses it, and no variable is read on a path where nothing
assigned it.
"""

import logging
from pathlib import Path

import pytest

from scobelix.decompiler import decompile_bytecode

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"
FIXTURES = ["BatchStrings", "BatchStringsNoopt", "LoopShapes", "LoopShapesNoopt", "SumLoop", "StorageMoves"]


def _reads(e):
    if type(e) == tuple and len(e) == 2 and e[0] == "var":
        yield e[1]
    elif type(e) in (tuple, list):
        for x in e:
            yield from _reads(x)


def loop_variable_problems(trace):
    problems = []

    def block(lines, assigned, enclosing):
        for line in lines:
            op = line[0] if type(line) == tuple and line else None
            if op == "while":
                _, cond, path, jd, setvars = line[:5]
                ids = {sv[1] for sv in setvars}
                for sv in setvars:
                    problems.extend(("unassigned", v, sv) for v in _reads(sv[2]) if v not in assigned)
                for outer_jd, outer_ids in enclosing:
                    if ids & outer_ids:
                        problems.append(("shared", sorted(ids & outer_ids, key=str), jd, outer_jd))
                inner = assigned | ids
                problems.extend(("unassigned", v, cond) for v in _reads(cond) if v not in inner)
                block(path, inner, enclosing + [(jd, ids)])
                assigned = inner
            elif op == "if":
                problems.extend(("unassigned", v, line[1]) for v in _reads(line[1]) if v not in assigned)
                block(line[2], assigned, enclosing)
                block(line[3], assigned, enclosing)
            elif op == "continue":
                for sv in line[2]:
                    problems.extend(("unassigned", v, sv) for v in _reads(sv[2]) if v not in assigned)
            elif op == "setvar":
                problems.extend(("unassigned", v, line) for v in _reads(line[2]) if v not in assigned)
                assigned = assigned | {line[1]}
            else:
                problems.extend(("unassigned", v, line) for v in _reads(line) if v not in assigned)

    block(trace, frozenset(), [])
    return problems


class _Decompiled(dict):
    def __missing__(self, name):
        logging.disable(logging.CRITICAL)
        try:
            d = decompile_bytecode((FIXTURES_DIR / (name + ".hex")).read_text().strip())
        finally:
            logging.disable(logging.NOTSET)
        self[name] = d
        return d


@pytest.fixture(scope="module")
def decompiled():
    return _Decompiled()


def _check(d, name):
    assert d.functions, name
    for func in d.functions.values():
        problems = loop_variable_problems(func.trace)
        assert not problems, (name, func.name, problems[:3])


def test_loops_keep_their_own_variables(decompiled):
    _check(decompiled["BatchStrings"], "BatchStrings")


@pytest.mark.slow
@pytest.mark.parametrize("name", FIXTURES[1:])
def test_loops_keep_their_own_variables_more_fixtures(decompiled, name):
    _check(decompiled[name], name)


def _nested_loops(lines, depth=0):
    best = depth
    for line in lines:
        op = line[0] if type(line) == tuple and line else None
        if op == "while":
            best = max(best, _nested_loops(line[2], depth + 1))
        elif op == "if":
            best = max(best, _nested_loops(line[2], depth), _nested_loops(line[3], depth))
    return best


def test_batch_strings_has_copy_loops_inside_the_outer_loop(decompiled):
    # the shape the check is about: the copy loops of labelsOf run inside
    # the loop over ids, whose index is read after them (bounds check of
    # out[i], increment)
    assert any(_nested_loops(f.trace) >= 2 for f in decompiled["BatchStrings"].functions.values())


class _Label:
    def __init__(self, ids):
        self.begin_vars = tuple(("var", i, 0, 0) for i in ids)


class _Node:
    def __init__(self, jd, labels):
        self.jd = jd
        self.label_history = labels


def test_loop_var_depth_skips_the_depths_of_the_labels_on_the_path():
    from scobelix.vm import loop_var_depth

    outer = _Label([38001, 38003])
    node = _Node("inner", {"outer": outer})
    assert loop_var_depth(node, 38) == 39
    assert loop_var_depth(node, 12) == 12
    # the loop's own label (a widening) does not count
    node = _Node("outer", {"outer": outer})
    assert loop_var_depth(node, 38) == 38
    # several labels on the path
    node = _Node("x", {"a": _Label([5001]), "b": _Label([6002])})
    assert loop_var_depth(node, 5) == 7

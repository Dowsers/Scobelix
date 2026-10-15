"""
The decompilation does not depend on Python's string hashing.

Sets of expressions iterate in an order that changes with PYTHONHASHSEED.
A decision taken while iterating one (which variables of an expression get
which test values when the engine compares memory offsets built from the
free memory pointer, which of two equal expressions is kept, the operand
order of a max) made the text differ from one run to the next. Each fixture
(tests/fixtures/sources/EncodingShapes.sol and others) is decompiled in
subprocesses under several hash seeds: the text and the JSON must be
byte-identical.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scobelix.core import variants as V
from scobelix.core.algebra import add_ge_zero

ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = ROOT / "tests" / "fixtures" / "bytecode"
FMP = ("mem", ("range", 64, 32))

_RUN = r"""
import json, logging, sys
logging.disable(logging.CRITICAL)
from scobelix.decompiler import decompile_bytecode
d = decompile_bytecode(open(sys.argv[1]).read().strip())
sys.stdout.write(json.dumps({"text": d.text, "json": d.json}, sort_keys=True, default=str))
"""


def _decompile(name, seed):
    env = dict(os.environ, PYTHONHASHSEED=str(seed))
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(ROOT), env.get("PYTHONPATH")) if p)
    proc = subprocess.run(
        [sys.executable, "-c", _RUN, str(FIXTURES_DIR / (name + ".hex"))],
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    return proc.stdout


def _differing_functions(a, b):
    def split(out):
        res, name = {}, "<head>"
        for line in json.loads(out)["text"].splitlines():
            if line.lstrip("\x1b[0123456789;m").startswith("def "):
                name = line
            res.setdefault(name, []).append(line)
        return res

    fa, fb = split(a), split(b)
    return sorted(k for k in set(fa) | set(fb) if fa.get(k) != fb.get(k))


def _check(name, seeds):
    outputs = {seed: _decompile(name, seed) for seed in seeds}
    first = seeds[0]
    for seed in seeds[1:]:
        assert outputs[seed] == outputs[first], (
            "%s: PYTHONHASHSEED=%s and %s give different decompilations (%s)"
            % (name, first, seed, _differing_functions(outputs[first], outputs[seed]) or "json")
        )


# seeds 0 and 1 gave different texts for these fixtures before the engine
# chose its candidates in a fixed order
@pytest.mark.parametrize("name", ["EncodingShapes", "EncodingShapesNoopt"])
def test_decompilation_does_not_depend_on_hash_seed(name):
    _check(name, (0, 1))


@pytest.mark.slow
@pytest.mark.parametrize(
    "name",
    ["EncodingShapes", "EncodingShapesNoopt", "EncodingShapesRecent", "StorageShapes", "LoopShapes", "Vault"],
)
def test_decompilation_does_not_depend_on_hash_seed_more_seeds(name):
    _check(name, (0, 1, 2, 3, 7))


def test_variables_in_order_of_first_occurrence():
    exp = ("add", ("var", "b"), ("mul", 2, FMP), ("var", "a"), ("var", "b"))
    assert V.extract_variables(exp) == [("var", "b"), FMP, ("var", "a")]


def test_every_variant_assigns_every_variable():
    # the free memory pointer used to get its own value (96) with the other
    # variables left symbolic when it was not the last variable found
    for order in ([FMP, "x"], ["x", FMP], [FMP, "calldatasize", "x"]):
        found = list(V.possibilities(order))
        assert all(set(p) == set(order) for p in found)
        values = {tuple(p[v] for v in sorted(order, key=repr)) for p in found}
        expected = 1
        for v in order:
            expected *= len(V.candidate_values(v))
        assert len(values) == expected


def test_variants_do_not_depend_on_the_order_of_the_variables():
    exp = ("add", FMP, ("var", "x"), -100)
    forward = {V.replace_dict(exp, p) for p in V.possibilities([FMP, ("var", "x")])}
    backward = {V.replace_dict(exp, p) for p in V.possibilities([("var", "x"), FMP])}
    assert forward == backward
    assert all(type(e[1]) == int and type(e[2]) == int for e in forward)


def test_nested_variable_goes_with_the_outer_one():
    # a variable inside another one (a var in the index of a mem read) does
    # not stop the outer one from being replaced, whatever the order
    inner = ("var", "i")
    outer = ("mem", ("range", inner, 32))
    exp = ("add", inner, outer)
    for order in ([inner, outer], [outer, inner]):
        dic = dict(zip(order, (1, 2)))
        res = V.replace_dict(exp, dic)
        assert res == ("add", dic[inner], dic[outer])


def test_free_memory_pointer_sum_is_decided():
    # mem[64] + x - 64 >= 0: the pointer is at least 96 in every variant
    assert add_ge_zero(("add", -64, ("var", "x"), FMP)) is True
    assert add_ge_zero(("add", -64, FMP, ("var", "x"))) is True

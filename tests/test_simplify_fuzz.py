"""
Property test of the expression simplifier: random expression trees are
evaluated concretely (EVM word semantics, modulo 2**256) before and after
`simplify_exp`, on several assignments of their symbols. Any difference is
an unsound rewrite.

The default run is small and seeded. Longer local runs:

    python tests/test_simplify_fuzz.py TREES SEED [DEPTH]
"""

import random
import sys

from scobelix.simplify import simplify_exp

M = 2**256
SYMS = [("cd", 4), ("cd", 36), ("var", 1)]
CONSTS = [
    0, 1, 2, 3, 7, 8, 31, 32, 33, 63, 64, 96, 255, 256, 2**160 - 1, 2**255, M - 1, M - 32, -1, -4,
]
SIZES = [1, 5, 8, 16, 32, 64, 128, 160, 224, 246, 248, 251, 253, 255, 256]
OFFSETS = [0, 0, 0, 3, 5, 8, 96, 160, 224, 248]


class NotEvaluable(Exception):
    pass


def signed(x):
    x %= M
    return x - M if x >> 255 else x


def mask_shl(size, off, shl, v):
    """(v & ((2**size - 1) << off)) << shl modulo 2**256, a negative offset
    or shl shifting right; written out here, independent of the engine."""
    v %= M
    if off < 0:
        size, off = size + off, 0
    if size <= 0 or off >= 256:
        return 0
    field = (v >> off) & ((1 << min(size, 256 - off)) - 1)
    shift = off + shl
    if shift < 0:
        return field >> -shift
    return (field << shift) % M if shift < 256 else 0


def evaluate(e, env):
    """Value of a trace expression, or NotEvaluable outside this subset."""
    if isinstance(e, bool):
        return int(e)
    if isinstance(e, int):
        return e % M
    if isinstance(e, tuple) and e in env:
        return env[e]
    if not isinstance(e, tuple) or not e:
        raise NotEvaluable(e)
    op, args = e[0], e[1:]
    if op == "mask_shl":
        # sizes, offsets and shifts computed at runtime are signed bit counts
        # (a size <= 0 selects nothing)
        size, off, shl = (t if isinstance(t, int) else signed(evaluate(t, env)) for t in args[:3])
        if max(abs(size), abs(off), abs(shl)) > 4096:
            raise NotEvaluable(e)
        return mask_shl(size, off, shl, evaluate(args[3], env))
    if op == "bytes":
        if not isinstance(args[0], int):
            raise NotEvaluable(e)
        return evaluate(args[1], env) % (1 << (8 * args[0]))
    v = [evaluate(x, env) for x in args]
    if op == "add":
        return sum(v) % M
    if op == "sub":
        return (v[0] - v[1]) % M
    if op == "smod":
        if v[1] == 0:
            return 0
        a, b = signed(v[0]), signed(v[1])
        return (abs(a) % abs(b) * (-1 if a < 0 else 1)) % M
    if op == "mul":
        r = 1
        for x in v:
            r = r * x % M
        return r
    if op == "div":
        return v[0] // v[1] if v[1] else 0
    if op == "mod":
        return v[0] % v[1] if v[1] else 0
    if op == "sdiv":
        if v[1] == 0:
            return 0
        a, b = signed(v[0]), signed(v[1])
        q = abs(a) // abs(b)
        return (q if (a < 0) == (b < 0) else -q) % M
    if op == "exp":
        return pow(v[0], v[1], M)
    if op == "addmod":
        return (v[0] + v[1]) % v[2] if v[2] else 0
    if op == "mulmod":
        return (v[0] * v[1]) % v[2] if v[2] else 0
    if op == "signextend":
        b, x = v
        if b >= 31:
            return x
        bit = 8 * b + 7
        return (x | (M - (1 << bit))) % M if (x >> bit) & 1 else x & ((1 << bit) - 1)
    if op == "iszero":
        return int(v[0] == 0)
    if op == "bool":
        return int(v[0] != 0)
    if op in ("lt", "gt", "le", "ge", "eq"):
        a, b = v
        return int({"lt": a < b, "gt": a > b, "le": a <= b, "ge": a >= b, "eq": a == b}[op])
    if op in ("slt", "sgt", "sle", "sge"):
        a, b = signed(v[0]), signed(v[1])
        return int({"slt": a < b, "sgt": a > b, "sle": a <= b, "sge": a >= b}[op])
    if op == "and":
        r = M - 1
        for x in v:
            r &= x
        return r
    if op == "or":
        r = 0
        for x in v:
            r |= x
        return r
    if op == "xor":
        r = 0
        for x in v:
            r ^= x
        return r
    if op == "not":
        return (M - 1) ^ v[0]
    if op == "byte":
        i, x = v
        return (x >> (8 * (31 - i))) & 0xFF if i < 32 else 0
    if op == "shl":
        k, x = v
        return (x << k) % M if k < 256 else 0
    if op == "shr":
        k, x = v
        return x >> k if k < 256 else 0
    if op == "sar":
        k, x = v
        if k >= 256:
            return M - 1 if x >> 255 else 0
        return (signed(x) >> k) % M
    raise NotEvaluable(e)


def random_tree(rng, depth):
    if depth == 0 or rng.random() < 0.2:
        return rng.choice(SYMS) if rng.random() < 0.6 else rng.choice(CONSTS)
    k = rng.random()
    sub = lambda: random_tree(rng, depth - 1)  # noqa: E731
    if k < 0.2:
        return ("add", sub(), sub())
    if k < 0.28:
        return ("mul", rng.choice([-1, 2, 3, 32, 256, 2**224]), sub())
    if k < 0.55:
        size = rng.choice(SIZES)
        off = rng.choice(OFFSETS)
        if size + off > 256:
            size = 256 - off
        shl = rng.choice([0, 0, -off, 5, 8, -3, -5, 96, -96])
        return ("mask_shl", size, off, shl, sub())
    if k < 0.62:
        return (rng.choice(["iszero", "bool", "not"]), sub())
    if k < 0.75:
        return (rng.choice(["lt", "gt", "eq", "slt", "sgt", "and", "or", "xor"]), sub(), sub())
    if k < 0.83:
        shift = rng.choice([0, 1, 3, 8, 31, 224, 255, 256])
        return (rng.choice(["shr", "shl", "sar", "byte"]), shift, sub())
    if k < 0.88:
        divisor = rng.choice([1, 2, 32, 2**128, M - 1])
        return (rng.choice(["div", "mod", "sdiv", "signextend"]), sub(), divisor)
    if k < 0.93:
        return (rng.choice(["addmod", "mulmod"]), sub(), sub(), rng.choice([0, 7, 2**200, M - 1]))
    if k < 0.97:
        # masks whose width is computed at runtime, as in memory-copy code:
        # 8 * (32 - x % 32) bits
        bits = ("mask_shl", 253, 0, 3, ("add", 32, ("mul", -1, ("mask_shl", 5, 0, 0, rng.choice(SYMS)))))
        return rng.choice([
            ("mask_shl", bits, 0, 0, sub()),
            ("mask_shl", ("add", 256, ("mul", -1, bits)), bits, 0, sub()),
            ("mask_shl", bits, 0, ("add", 256, ("mul", -1, bits)), sub()),
            ("mask_shl", 251, 5, 0, ("add", 31, sub())),
            (rng.choice(["sub", "smod"]), sub(), sub()),
        ])
    return ("bytes", rng.choice([1, 4, 20, 31]), sub())


def assignments(rng):
    for _ in range(5):
        values = [0, 1, 31, 32, 33, 2**64 + 5, M - 1, 2**255 + 9]
        yield {s: rng.choice(values + [rng.getrandbits(256), rng.getrandbits(20)]) for s in SYMS}


def unsound_rewrites(trees, seed, depth=4, unevaluable=None):
    """[(expression, simplified, assignment)] where simplify_exp changed the
    value; `unevaluable` (a list) collects the simplified forms this
    evaluator cannot compute (they are not checked)."""
    rng = random.Random(seed)
    bad = []
    for _ in range(trees):
        e = random_tree(rng, depth)
        s = simplify_exp(e)
        for env in assignments(rng):
            try:
                before = evaluate(e, env)
            except NotEvaluable:
                break
            try:
                after = evaluate(s, env)
            except NotEvaluable:
                if unevaluable is not None:
                    unevaluable.append(s)
                break  # simplified into a form outside the evaluated subset
            if before != after:
                bad.append((e, s, env))
                break
    return bad


def test_simplify_exp_keeps_values():
    for seed in (1, 2, 3):
        unevaluable = []
        bad = unsound_rewrites(400, seed, unevaluable=unevaluable)
        assert bad == [], bad[:3]
        # the check only means something if the simplified forms are evaluated
        assert len(unevaluable) <= 4, unevaluable[:3]


if __name__ == "__main__":
    trees, seed = int(sys.argv[1]), int(sys.argv[2])
    depth = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    found = unsound_rewrites(trees, seed, depth)
    print("unsound rewrites:", len(found))
    for e, s, env in sorted(found, key=lambda t: len(str(t[0])))[:20]:
        print("  ", e, "\n    ->", s, "\n    at", {str(k): hex(v) for k, v in env.items()})

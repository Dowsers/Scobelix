"""
The arith pass turns the compiler's Panic(0x11) / Panic(0x12) guards and the
wrapping operation they protect into one checked operation (and drops the
Panic(0x32) guards a storage access repeats); the EVM semantics must not
change: the same inputs give the same results, revert with the same data at
the same point, write the same storage.

Tests:
  * the catalogue of compiler checks (`expected_guards`) is exactly the
    overflow predicate of its operation and type: exhaustively on 8-bit
    types (slow), on bounds and random words for every width;
  * the normal form identifies the guard shapes the compilers produce;
  * the rewrite on hand-written IR: one use inlined, several uses or a use
    after a statement that may fail bound to a local at the guard, a use
    after a store of an operand left wrapping, operands not valid for a
    narrow type, dead guards, the int256 product and signed division
    pairs, Panic(0x32) duplicates, pre-0.8 originals, the pass disabled;
  * differential execution of probe contracts compiled by solc 0.8.19
    (optimised, not, via-IR) and 0.8.31 via-IR, on value grids at the type
    bounds and storage presets near the bounds (arithprobe), with every
    guard form x type, `unchecked` blocks next to checked code, user checks
    that look like guards, failure order between division and overflow,
    packed storage fields, mappings of structs, arrays; pre-0.8 originals
    (0.7.6, 0.5.17, SafeMath) where nothing may become checked.
"""

import itertools
import random

import pytest

import arithprobe
from probes import Build, compile_probe, function_text, generate_probe, patch_signatures
from scobelix.solgen import ir, pipeline
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.passes import arith
from scobelix.solgen.types import parse_type

W = 1 << 256


# ---------------------------------------------------------------- the catalogue


def _signed(v, bits):
    v %= 1 << bits
    return v - (1 << bits) if v >> (bits - 1) else v


def _value(word, t):
    """The integer a valid word of type t holds."""
    return _signed(word, 256) if t.kind == "int" else word


def _word(v):
    return v % W


def _overflows(op, t, x, y):
    lo, hi = (-(1 << (t.bits - 1)), (1 << (t.bits - 1)) - 1) if t.kind == "int" else (0, (1 << t.bits) - 1)
    a, b = _value(x, t), _value(y, t) if y is not None else None
    r = {"add": lambda: a + b, "sub": lambda: a - b, "mul": lambda: a * b, "neg": lambda: -a}[op]()
    return not lo <= r <= hi


def _valid_words(t, rng, n):
    if t.kind == "int":
        lo, hi = -(1 << (t.bits - 1)), (1 << (t.bits - 1)) - 1
        base = [0, 1, -1, 2, -2, hi, hi - 1, lo, lo + 1, hi // 2, lo // 2]
        return [_word(v) for v in base] + [_word(rng.randint(lo, hi)) for _ in range(n)]
    m = (1 << t.bits) - 1
    base = [0, 1, 2, 3, m, m - 1, m >> 1, (m >> 1) + 1, 1 << (t.bits // 2), (1 << (t.bits // 2)) - 1]
    return base + [rng.randint(0, m) for _ in range(n)]


def _check_forms(op, t, pairs):
    for x, y in pairs:
        cx, cy = ir.Const(x), (ir.Const(y) if y is not None else None)
        want = _overflows(op, t, x, y)
        for form, _, _ in arith.expected_guards(op, t, cx, cy):
            got = ir.evaluate(form)
            assert got is not None and bool(got) == want, (op, t.canonical, hex(x), y and hex(y), form)


TYPES = ["uint8", "uint16", "uint64", "uint128", "uint136", "uint192", "uint248", "uint256",
         "int8", "int16", "int64", "int128", "int136", "int192", "int248", "int256"]


@pytest.mark.parametrize("ty", TYPES)
@pytest.mark.parametrize("op", ["add", "sub", "mul", "neg"])
def test_every_catalogue_form_is_the_overflow_predicate(op, ty):
    t = parse_type(ty)
    if op == "neg" and t.kind == "uint":
        assert arith.expected_guards(op, t, ir.ONE, None) == []  # unary minus of unsigned values does not exist
        return
    rng = random.Random(f"{op}{ty}")
    words = _valid_words(t, rng, 40)
    pairs = [(x, None) for x in words] if op == "neg" else list(itertools.product(words, words))
    _check_forms(op, t, pairs)


@pytest.mark.slow
@pytest.mark.parametrize("ty", ["uint8", "int8"])
@pytest.mark.parametrize("op", ["add", "sub", "mul"])
def test_catalogue_exhaustively_on_8_bit_types(op, ty):
    t = parse_type(ty)
    words = [_word(v) for v in (range(-128, 128) if t.kind == "int" else range(256))]
    _check_forms(op, t, itertools.product(words, words))


def test_int256_product_pair_and_signed_division_overflow():
    """The two guards of an int256 product together, and `x == min && y ==
    -1` of a signed division, are exactly the overflow of the operation."""
    t = parse_type("int256")
    rng = random.Random(5)
    words = _valid_words(t, rng, 60)
    for x, y in itertools.product(words, words):
        special = ir.evaluate(arith._op("and", arith._op("slt", ir.Const(x), 0),
                                        arith._op("eq", ir.Const(y), 1 << 255)))
        m = arith._op("mul", ir.Const(x), ir.Const(y))
        generic = ir.evaluate(arith._op("and", arith._op("iszero", arith._op("iszero", ir.Const(x))),
                                        arith._op("iszero", arith._op("eq", ir.Const(y),
                                                                      arith._op("sdiv", m, ir.Const(x))))))
        assert bool(special or generic) == _overflows("mul", t, x, y), (hex(x), hex(y))
    for bits in (8, 64, 256):
        t = parse_type(f"int{bits}")
        lo = _word(-(1 << (bits - 1)))
        for x, y in itertools.product(_valid_words(t, rng, 10), _valid_words(t, rng, 10)):
            if y == 0:
                continue
            a, b = _value(x, t), _value(y, t)
            q = abs(a) // abs(b)
            q = -q if (a < 0) != (b < 0) else q  # truncated toward zero, like sdiv
            fires = ir.evaluate(arith._op("and", arith._op("eq", ir.Const(x), lo), arith._op("eq", ir.Const(y), W - 1)))
            assert bool(fires) == (q > (1 << (bits - 1)) - 1), (bits, hex(x), hex(y))


# ---------------------------------------------------------------- the normal form


def cd(i):
    return ir.CalldataWord(ir.Const(4 + 32 * i))


def m8(e):
    return ir.Mask(8, 0, 0, e)


def se(b, e):
    return ir.Op("signextend", (ir.Const(b), e))


def op(name, *args):
    return ir.Op(name, tuple(a if isinstance(a, ir.Node) else ir.const(a) for a in args))


def test_normal_form_of_the_observed_guard_shapes():
    """Guards as the decompiler writes them (legacy / via-IR, optimised or
    not) normalise like the catalogue's forms of the same check."""
    n = arith.Normaliser()
    a, b = cd(0), cd(1)
    t256 = parse_type("uint256")
    shapes = [
        # uint256 a + b: gt(x, sum) with either operand, sums in any order
        (op("gt", a, op("add", b, a)), "add", t256, a, b),
        (op("gt", b, op("add", a, b)), "add", t256, a, b),
        # a + 1: iszero(add(1, a)) / eq(a, -1)
        (op("iszero", op("add", 1, a)), "add", t256, a, ir.ONE),
        (op("eq", a, W - 1), "add", t256, a, ir.ONE),
        # a - b: gt(add(a, -b), a); a - 3: gt(add(-3, a), a)
        (op("gt", op("add", a, op("mul", W - 1, b)), a), "sub", t256, a, b),
        (op("gt", op("add", W - 3, a), a), "sub", t256, a, ir.Const(3)),
        # a * b: legacy optimised and IR forms
        (op("and", op("iszero", op("eq", b, op("div", op("mul", b, a), a))), op("iszero", op("iszero", a))),
         "mul", t256, a, b),
        (op("and", op("iszero", op("iszero", a)), op("iszero", op("eq", op("div", op("mul", a, b), a), b))),
         "mul", t256, a, b),
        # 3 * a with the constant folded away, a * 2 as a mask
        (op("iszero", op("eq", a, op("div", op("mul", 3, a), 3))), "mul", t256, ir.Const(3), a),
        (op("iszero", op("eq", a, ir.Mask(255, 0, 0, a))), "mul", t256, a, ir.Const(2)),
        # uint8: gt(sum, 255); products as eq / as a difference (via-IR)
        (op("gt", op("add", m8(b), m8(a)), 255), "add", parse_type("uint8"), m8(a), m8(b)),
        (op("iszero", op("eq", op("mul", m8(b), m8(a)), m8(op("mul", m8(b), m8(a))))), "mul",
         parse_type("uint8"), m8(a), m8(b)),
        (op("add", m8(op("mul", m8(a), m8(b))), op("mul", W - 1, m8(a), m8(b))), "mul",
         parse_type("uint8"), m8(a), m8(b)),
        # int8: or(slt(sum, -128), sgt(sum, 127)) in both orders; negation
        (op("or", op("sgt", op("add", se(0, a), se(0, b)), 127), op("slt", op("add", se(0, a), se(0, b)), W - 128)),
         "add", parse_type("int8"), se(0, a), se(0, b)),
        (op("iszero", op("add", 128, se(0, a))), "neg", parse_type("int8"), se(0, a), None),
        (op("eq", se(0, a), W - 128), "neg", parse_type("int8"), se(0, a), None),
        # int256 a + b
        (op("or", op("and", op("slt", a, 0), op("iszero", op("slt", op("add", b, a), b))),
            op("and", op("slt", op("add", b, a), b), op("iszero", op("slt", a, 0)))),
         "add", parse_type("int256"), a, b),
    ]
    for guard, o, t, x, y in shapes:
        p = n.cond(guard)
        forms = [n.cond(f) for f, _, _ in arith.expected_guards(o, t, n(x), n(y) if y is not None else None)]
        assert p in forms, (guard, o, t.canonical)


def test_normal_form_keeps_values():
    """Every rewrite of the normal form keeps the word's value (random
    words, the operators the guards use)."""
    n = arith.Normaliser()
    rng = random.Random(9)
    for _ in range(300):
        pool = [0, 1, 2, W - 1, W - 2, 1 << 255, rng.getrandbits(256), rng.getrandbits(8)]
        vals = [rng.choice(pool) for _ in range(3)]
        a, b, c = (ir.Const(v) for v in vals)
        exprs = [op("sub", a, op("add", b, c)), op("iszero", op("add", a, op("mul", W - 1, b))),
                 op("gt", a, op("add", a, b)), op("iszero", op("or", op("lt", a, b), op("iszero", c))),
                 op("eq", op("add", a, 5), 0), ir.Mask(255, 0, 1, a), op("mul", W - 1, op("add", a, b))]
        for e in exprs:
            # the operands are constants: compare the folded values through
            # symbolic placeholders instead
            ps = [ir.Param(i) for i in range(3)]
            sym = _substitute(e, dict(zip((a, b, c), ps)))
            back = _substitute(n(sym), dict(zip(ps, (a, b, c))))
            assert ir.evaluate(back) == ir.evaluate(e), e


def _substitute(e, table):
    return ir.transform(e, lambda x: table.get(x, x))


# ---------------------------------------------------------------- the rewrite on IR


def ctx_for(fns, specs=None, metadata=None, abi_v2=True, off=()):
    specs = specs or {k: EntrySpec(key=k, kind="function", selector=int(k, 16)) for k in fns}
    return pipeline.PassContext(specs=specs, metadata=metadata, dispatcher=None, target_solc="0.8.19",
                                abi_v2=abi_v2, idiom_level="full", functions=dict(fns),
                                disabled_passes={"*": set(off)})


def guard(cond, rest, code=0x11):
    return ir.If(cond, (ir.Revert(ir.Panic(code)),), tuple(rest))


def ret(*words):
    return ir.Return(ir.Blob(tuple(ir.WordBytes(w) for w in words)) if len(words) > 1 else ir.WordBytes(words[0]))


def run(body, **kw):
    fn = ir.Function("0x00000001", tuple(body))
    ctx = ctx_for({fn.key: fn}, **kw)
    out = arith.run(fn, ctx)
    return out, ctx.facts["arith"]["functions"].get(fn.key)


A, B, C = cd(0), cd(1), cd(2)
SUM = op("add", A, B)
CHECKED = ir.Typed("add", (A, B), "uint256", True)


def test_one_use_in_the_next_statement_becomes_the_checked_operation():
    out, facts = run([guard(op("gt", A, SUM), [ret(SUM)])])
    assert out.body == (ret(CHECKED),)
    assert facts["absorbed"] == {0x11: 1} and facts["bound"] == 0


def test_several_uses_bind_the_checked_result_at_the_guard():
    body = [guard(op("gt", A, SUM), [ir.Require(op("gt", SUM, 10), ir.ErrorString(b"small")), ret(SUM)])]
    out, facts = run(body)
    s = ir.Local("sum")
    assert out.body == (ir.Assign(s, CHECKED), ir.Require(op("gt", s, 10), ir.ErrorString(b"small")), ret(s))
    assert facts["bound"] == 1


def test_a_use_after_something_that_may_fail_in_another_way_is_bound():
    """`if (a + b overflows) Panic; if (c == 0) Panic(0x12)...; return (a + b) + c / x`:
    the overflow must still be raised first."""
    div = ir.Typed("div", (C, A), "uint256", False)  # may fail with Panic(0x12)
    body = [guard(op("gt", A, SUM), [ret(op("add", div, SUM))])]
    out, _ = run(body)
    s = ir.Local("sum")
    assert out.body[0] == ir.Assign(s, CHECKED)
    assert out.body[1] in (ret(op("add", div, s)), ret(op("add", s, div)))


def test_a_store_of_an_operand_ends_the_uses():
    """After `total = 5` the expression total + a is another value: the use
    there stays wrapping; the guard's result has no use before the store, so
    the checked sum is computed at the guard (an unused result)."""
    total = ir.StateRef("total", (), "uint256")
    s2 = op("add", A, total)
    body = [guard(op("gt", total, s2), [ir.Assign(total, ir.Const(5)), ret(s2)])]
    out, facts = run(body)
    s = ir.Local("sum")
    assert out.body == (ir.Assign(s, ir.Typed("add", (total, A), "uint256", True)), ir.Assign(total, ir.Const(5)),
                        ret(s2))
    assert facts["unused"] == 1 and not facts["kept"]


def test_an_unused_result_is_computed_at_the_guard():
    """`uint256 x = a * 2;` never used: the checked product at the guard's
    position raises the same Panic; also the x * 2 check written with an
    `and` mask."""
    body = [guard(op("iszero", op("eq", A, op("and", A, (1 << 255) - 1))), [ret(B)])]
    out, facts = run(body)
    assert out.body == (ir.Assign(ir.Local("product"), ir.Typed("mul", (A, ir.Const(2)), "uint256", True)), ret(B))
    assert facts["unused"] == 1
    # the same check with the mask read as a field of a state variable, the product used
    total = ir.StateRef("total", (), "uint256")
    body = [guard(op("iszero", op("eq", total, ir.Field(total, 0, 255))), [ret(ir.Mask(255, 0, 1, total))])]
    out, _ = run(body)
    assert out.body == (ret(ir.Typed("mul", (total, ir.Const(2)), "uint256", True)),)


def test_a_snapshot_local_holding_the_operand_carries_it_past_the_store():
    """The engine's snapshot t1 = total before the guard: the guard reads
    total, the use after the store reads t1 (the same value at the guard)."""
    total = ir.StateRef("total", (), "uint256")
    t1 = ir.Local("t1")
    body = [ir.Assign(t1, total),
            guard(op("gt", total, op("add", A, total)), [ir.Assign(total, ir.Const(5)), ret(op("add", t1, A))])]
    out, _ = run(body)
    s = ir.Local("sum")
    assert out.body == (ir.Assign(t1, total), ir.Assign(s, ir.Typed("add", (t1, A), "uint256", True)),
                        ir.Assign(total, ir.Const(5)), ret(s))


def test_narrow_operands_must_be_valid_values_of_the_type():
    clean = op("add", m8(A), m8(B))
    dirty = op("add", A, m8(B))  # A may have high bits: not a uint8 addition
    out, _ = run([guard(op("gt", clean, 255), [ret(m8(clean))])])
    assert out.body == (ret(ir.Typed("add", (m8(A), m8(B)), "uint8", True)),)
    body = [guard(op("gt", dirty, 255), [ret(m8(dirty))])]
    out, facts = run(body)
    assert out.body == tuple(body) and facts["kept"] == {0x11: 1}


def test_validated_parameters_are_valid_narrow_operands():
    spec = EntrySpec(key="0x00000001", kind="function", selector=1, signature="f(uint8,uint8)", name="f",
                     params=((parse_type("uint8"), "a"), (parse_type("uint8"), "b")))
    s = op("add", ir.Param(0), ir.Param(1))
    out, _ = run([guard(op("gt", s, 255), [ret(s)])], specs={"0x00000001": spec})
    assert out.body == (ret(ir.Typed("add", (ir.Param(0), ir.Param(1)), "uint8", True)),)
    out, _ = run([guard(op("gt", s, 255), [ret(s)])], specs={"0x00000001": spec}, abi_v2=False)
    assert isinstance(out.body[0], ir.If)  # ABI coder v1 validates nothing


def test_checks_of_expressions_the_decompiler_simplified():
    """Like terms combined ((a - f) - 2f written a - 3f), products of sums
    expanded ((a + 1) * (b - 1) as ab - a + b - 1), the check of x * 1 (never
    fires)."""
    f = B
    first = op("add", A, op("mul", W - 1, f))  # a - f
    second = op("add", A, op("mul", W - 3, f))  # (a - f) - 2f
    out, facts = run([guard(op("gt", second, first), [ret(second)])])
    assert facts["absorbed"] == {0x11: 1}
    t = out.body[0].data.value
    n = arith.Normaliser()
    assert isinstance(t, ir.Typed) and t.op == "sub" and n(t.args[0]) == n(first)
    assert ir.evaluate(_substitute(t.args[1], {f: ir.Const(5)})) == 10  # y = 2f
    a1, b1 = op("add", A, 1), op("add", B, W - 1)
    expanded = op("add", op("mul", A, B), op("mul", W - 1, A), B, W - 1)
    check = op("and", op("iszero", op("iszero", a1)), op("iszero", op("eq", b1, op("div", expanded, a1))))
    out, facts = run([guard(check, [ret(expanded)])])
    assert facts["absorbed"] == {0x11: 1}
    t = out.body[0].data.value
    assert isinstance(t, ir.Typed) and t.op == "mul" and {t.args[0], t.args[1]} == {a1, b1}
    out, facts = run([guard(op("and", op("iszero", op("eq", 1, op("div", A, A))), op("iszero", op("iszero", A))),
                            [ret(A)])])
    assert out.body == (ret(A),) and facts["dead"] == 1


def test_dead_guard_is_dropped():
    out, facts = run([guard(op("gt", A, A), [ret(A)])])
    assert out.body == (ret(A),) and facts["dead"] == 1


def test_the_condition_must_not_fail():
    body = [guard(op("gt", ir.MLoad(A), op("add", ir.MLoad(A), B)), [ret(op("add", ir.MLoad(A), B))])]
    out, facts = run(body)
    assert out.body == tuple(body) and facts["reasons"] == {"condition may halt": 1}


def test_int256_product_pair_and_signed_division_pair():
    prod = op("mul", B, A)
    body = [guard(op("and", op("eq", B, 1 << 255), op("slt", A, 0)),
                  [guard(op("and", op("iszero", op("iszero", A)), op("iszero", op("eq", B, op("sdiv", prod, A)))),
                         [ret(prod)])])]
    out, facts = run(body)
    assert out.body == (ret(ir.Typed("mul", (A, B), "int256", True)),)
    assert facts["absorbed"] == {0x11: 2} and not facts["kept"]
    body = [guard(op("iszero", B), [guard(op("and", op("eq", B, W - 1), op("eq", A, 1 << 255)),
                                          [ret(op("sdiv", A, B))])], code=0x12)]
    out, facts = run(body)
    assert out.body == (ret(ir.Typed("div", (A, B), "int256", True)),)
    assert facts["absorbed"] == {0x12: 1, 0x11: 1}


def test_division_and_modulo_guards():
    out, _ = run([guard(op("iszero", B), [ret(op("div", A, B), op("mod", A, B))], code=0x12)])
    # two uses of the divisor: the first division takes the guard, the modulo keeps the EVM helper (exact: B != 0)
    assert out.body == (ret(ir.Typed("div", (A, B), "uint256", False), op("mod", A, B)),)
    body = [guard(op("iszero", B), [ret(op("sdiv", A, B))], code=0x12)]
    out, _ = run(body)
    assert out.body == tuple(body)  # unchecked signed division: min / -1 wraps, kept exact


def test_storage_index_guard_repeated_by_the_access():
    arr = ir.StateRef("arr", (A,), "uint256")
    length = ir.StateRef("arr", ("length",), "uint256")
    out, facts = run([guard(op("iszero", op("lt", A, length)), [ret(arr)], code=0x32)])
    assert out.body == (ret(arr),) and facts["absorbed"] == {0x32: 1}
    other = ir.StateRef("arr", (B,), "uint256")
    body = [guard(op("iszero", op("lt", A, length)), [ret(other)], code=0x32)]
    out, facts = run(body)
    assert out.body == tuple(body) and facts["kept"] == {0x32: 1}


SCRATCH = ir.Mstore(ir.ZERO, ir.WordBytes(ir.Const(3)))


def test_scratch_writes_before_the_use_or_the_access():
    """The engine's `mstore(0, slot)` (hashing the slot) between the guard and
    the statement: the use / the access is still the first failure (the write
    cannot fail, and nothing observes it once the call reverts)."""
    arr = ir.StateRef("arr", (A,), "uint256")
    length = ir.StateRef("arr", ("length",), "uint256")
    out, facts = run([guard(op("iszero", op("lt", A, length)), [SCRATCH, ret(arr)], code=0x32)])
    assert out.body == (SCRATCH, ret(arr)) and facts["absorbed"] == {0x32: 1}
    out, facts = run([guard(op("gt", A, SUM), [SCRATCH, ret(SUM)])])
    assert out.body == (SCRATCH, ret(CHECKED)) and facts["bound"] == 0
    # a write elsewhere in memory is not skipped: the use is bound at the guard
    far = ir.Mstore(ir.Const(0x80), ir.WordBytes(ir.Const(3)))
    out, _ = run([guard(op("gt", A, SUM), [far, ret(SUM)])])
    assert out.body == (ir.Assign(ir.Local("sum"), CHECKED), far, ret(ir.Local("sum")))


def test_an_access_that_took_a_bounds_check_may_fail_first():
    """`if (a + b overflows) Panic(0x11); if (c >= arr.length) Panic(0x32);
    return arr[c] + (a + b)`: once the access checks c itself, the sum must
    not move into its statement (both may fail, the overflow comes first):
    bound at the guard.  When the operands read the access too (`arr[c] =
    arr[c] + a`: the guard's condition read arr[c], its check had passed),
    the operation moves."""
    arr = ir.StateRef("arr", (C,), "uint256")
    length = ir.StateRef("arr", ("length",), "uint256")
    body = [guard(op("gt", A, SUM), [guard(op("iszero", op("lt", C, length)), [ret(op("add", arr, A, B))],
                                           code=0x32)])]
    out, facts = run(body)
    s = ir.Local("sum")
    assert out.body == (ir.Assign(s, CHECKED), ret(op("add", s, arr)))
    assert facts["absorbed"] == {0x11: 1, 0x32: 1}
    total = op("add", arr, A)
    body = [guard(op("gt", arr, total), [guard(op("iszero", op("lt", C, length)), [ir.Assign(arr, total)],
                                               code=0x32)])]
    out, facts = run(body)
    assert len(out.body) == 1 and out.body[0].target == arr and facts["absorbed"] == {0x11: 1, 0x32: 1}
    t = out.body[0].value
    assert isinstance(t, ir.Typed) and t.checked and set(t.args) == {arr, A}


def test_pre_08_originals_and_the_disabled_pass():
    body = [guard(op("gt", A, SUM), [ret(SUM)])]
    fn = ir.Function("0x00000001", tuple(body))
    ctx = ctx_for({fn.key: fn}, metadata={"compiler": "solc", "version": "0.7.6"})
    assert arith.run(fn, ctx) is fn
    ctx = ctx_for({fn.key: fn}, off=("arith",))
    out, applied = pipeline.run_passes(fn, [("arith", arith)], ctx)
    assert out is fn and applied == ()


# ---------------------------------------------------------------- probes on real compilers

PROBE_OPS = """
contract Ops {
    function addU(uint256 a, uint256 b) external pure returns (uint256) { return a + b; }
    function subU(uint256 a, uint256 b) external pure returns (uint256) { return a - b; }
    function mulU(uint256 a, uint256 b) external pure returns (uint256) { return a * b; }
    function divU(uint256 a, uint256 b) external pure returns (uint256) { return a / b; }
    function modU(uint256 a, uint256 b) external pure returns (uint256) { return a % b; }
    function constOps(uint256 a) external pure returns (uint256, uint256, uint256) { return (a + 1, a - 3, a * 3); }
    function twice(uint256 a) external pure returns (uint256) { return a * 2; }
    function add8(uint8 a, uint8 b) external pure returns (uint8) { return a + b; }
    function sub8(uint8 a, uint8 b) external pure returns (uint8) { return a - b; }
    function mul8(uint8 a, uint8 b) external pure returns (uint8) { return a * b; }
    function add64(uint64 a, uint64 b) external pure returns (uint64) { return a + b; }
    function mul128(uint128 a, uint128 b) external pure returns (uint128) { return a * b; }
    function mul192(uint192 a, uint192 b) external pure returns (uint192) { return a * b; }
    function addI(int256 a, int256 b) external pure returns (int256) { return a + b; }
    function subI(int256 a, int256 b) external pure returns (int256) { return a - b; }
    function mulI(int256 a, int256 b) external pure returns (int256) { return a * b; }
    function divI(int256 a, int256 b) external pure returns (int256) { return a / b; }
    function modI(int256 a, int256 b) external pure returns (int256) { return a % b; }
    function negI(int256 a) external pure returns (int256) { return -a; }
    function addI8(int8 a, int8 b) external pure returns (int8) { return a + b; }
    function subI8(int8 a, int8 b) external pure returns (int8) { return a - b; }
    function mulI8(int8 a, int8 b) external pure returns (int8) { return a * b; }
    function divI8(int8 a, int8 b) external pure returns (int8) { return a / b; }
    function negI8(int8 a) external pure returns (int8) { return -a; }
    function addI128(int128 a, int128 b) external pure returns (int128) { return a + b; }
    function mulI128(int128 a, int128 b) external pure returns (int128) { return a * b; }
    function mulI192(int192 a, int192 b) external pure returns (int192) { return a * b; }
    function incs(uint256 a, int256 b) external pure returns (uint256, int256) { a++; b--; return (a, b); }
    function incs8(uint8 a, int8 b) external pure returns (uint8, int8) { a--; b++; return (a, b); }
    function chain(uint256 a, uint256 b, uint256 c) external pure returns (uint256) { return a * b + c - a; }
    function unc(uint256 a, uint256 b) external pure returns (uint256) { unchecked { return a * b + a; } }
}
"""

PROBE_STATE = """
contract State {
    struct Pos { uint64 a; uint128 b; int32 c; }
    mapping(address => Pos) public pos;
    mapping(address => uint256) public bal;
    uint256[] public arr;
    uint256[4] public fixedArr;
    uint256 public total;
    uint8 public small;
    int16 public sm16;
    function transfer(address to, uint256 v) external { bal[msg.sender] -= v; bal[to] += v; }
    function posAdd(uint64 v) external { pos[msg.sender].a += v; }
    function posSub(uint128 v) external { pos[msg.sender].b -= v; }
    function posMul(int32 v) external { pos[msg.sender].c *= v; }
    function arrAdd(uint256 i, uint256 v) external { arr[i] += v; }
    function arrAt(uint256 i) external view returns (uint256) { return arr[i]; }
    function fixedAdd(uint256 i, uint256 v) external { fixedArr[i] += v; }
    function smallInc() external { small++; }
    function smallDec() external { small--; }
    function sm16Neg() external { sm16 = -sm16; }
    function totalDiv(uint256 d) external { total /= d; }
    function totalMod(uint256 d) external { total = total % d; }
    function loopSum(uint256 n) external pure returns (uint256 s) { for (uint256 i = 0; i < n % 8; i++) { s += i; } }
}
"""

PROBE_ORDER = """
interface ISink { function ping() external returns (uint256); }
contract Order {
    uint256 public total;
    uint8 public counter8;
    function storeBetween(uint256 a) external returns (uint256) { uint256 s = total + a; total = 5; return s + total; }
    function callBetween(address to, uint256 a) external returns (uint256) {
        uint256 s = total + a; uint256 r = ISink(to).ping(); return s + r;
    }
    function userCheck(uint256 a, uint256 b) external pure returns (uint256) {
        require(a + b >= a, "overflow"); return a + b;
    }
    function mixed(uint256 a, uint256 b) external pure returns (uint256 x, uint256 y) {
        unchecked { x = a + b; } y = a * b;
    }
    function branch(uint256 a, uint256 b, bool f) external pure returns (uint256) {
        uint256 s = a + b; if (f) { return s; } return s * 2;
    }
    function divmod(uint256 a, uint256 b) external pure returns (uint256, uint256) { return (a / b, a % b); }
    function order(uint256 a, uint256 b, uint256 c) external pure returns (uint256) { return (a + b) / c; }
    function order2(uint256 a, uint256 b, uint256 c) external pure returns (uint256) { return a / c + b; }
    function signedMix(int256 a, int256 b) external pure returns (int256) { return a * b - a / b; }
    function pct(uint256 a) external pure returns (uint256) { return a - a * 3 / 100; }
    function counterLoop(uint8 n) external { for (uint8 i = 0; i < n % 5; i++) { counter8 += 2; } }
    function guardThenReq(uint256 a, uint256 b) external pure returns (uint256) {
        uint256 s = a + b; require(s > 10, "small"); return s;
    }
    uint256[] public items;
    function itemThenSum(uint256 a, uint256 b, uint256 c) external view returns (uint256) { return items[c] + (a + b); }
    function sumThenItem(uint256 a, uint256 b, uint256 c) external view returns (uint256) { return (a + b) + items[c]; }
}
"""

BUILDS = [Build("0.8.19"), Build("0.8.19", optimize=False), Build("0.8.19", via_ir=True), Build("0.8.31", via_ir=True)]
PROBES = {"Ops": PROBE_OPS, "State": PROBE_STATE, "Order": PROBE_ORDER}


def _probe(monkeypatch, name, build, off=(), limit=50, presets=4):
    try:
        art = compile_probe(PROBES[name], build, name)
    except pytest.fail.Exception as e:
        if build.via_ir and not build.optimize and "Stack too deep" in str(e):
            pytest.skip("the IR pipeline without the optimizer: the probe itself is stack too deep")
        raise
    patch_signatures(monkeypatch, art.abi)
    res = generate_probe(art.runtime, off=off)
    calls, skipped = arithprobe.all_calls(res, limit=limit)
    pre = arithprobe.storage_presets(art.storage_layout)
    pre = [pre[i] for i in (0, 1, 2, 4) if i < len(pre)][:presets] if presets else pre
    mism = arithprobe.differential(art.runtime, res.solidity, res.target_solc, calls, pre)
    return res, calls, skipped, mism


def _absorbed(res, code=0x11):
    return sum((f.get("arith") or {}).get("absorbed", {}).get(code, 0) for f in res.functions.values())


# both pipelines of one compiler by default; every build with `-m slow` (the full grids below)
@pytest.mark.parametrize("build", [b for b in BUILDS if b.version == "0.8.19" and b.optimize], ids=lambda b: b.label)
@pytest.mark.parametrize("name", sorted(PROBES))
def test_probe_same_behaviour(monkeypatch, name, build):
    res, calls, skipped, mism = _probe(monkeypatch, name, build)
    assert not skipped and calls
    assert mism == []
    assert _absorbed(res) >= {"Ops": 30, "State": 8, "Order": 8}[name]


def test_failure_order_holds_with_the_ir_pipeline(monkeypatch):
    """The generated code compiled by the IR pipeline (left operand first;
    the legacy pipeline evaluates the right operand of a binary operation
    first): `items[c] + (a + b)` with c out of range and a + b overflowing
    still raises the overflow first (the access took over a bounds check)."""
    art = compile_probe(PROBES["Order"], Build("0.8.19"), "Order")
    patch_signatures(monkeypatch, art.abi)
    res = generate_probe(art.runtime)
    assert _absorbed(res, 0x32) >= 1  # itemThenSum's check, taken over by the access
    calls = [c for sig in ("itemThenSum(uint256,uint256,uint256)", "sumThenItem(uint256,uint256,uint256)")
             for c in arithprobe.calls_for(sig, 600)]
    pre = arithprobe.storage_presets(art.storage_layout)[:4]
    assert arithprobe.differential(art.runtime, res.solidity, res.target_solc, calls, pre, via_ir=True) == []


def test_probe_reads_like_source(monkeypatch):
    res, _, _, mism = _probe(monkeypatch, "State", Build("0.8.19"))
    assert mism == []
    src = res.solidity
    assert "bal[msg.sender] -= v;" in src and "bal[to] += v;" in src
    assert "pos[msg.sender].m0_0 += v;" in function_text(src, "posAdd")
    assert "arr[i] += v;" in function_text(src, "arrAdd") and "_panic" not in function_text(src, "arrAdd")
    assert "small++;" in function_text(src, "smallInc") and "small--;" in function_text(src, "smallDec")
    assert "sm16 = -sm16;" in function_text(src, "sm16Neg")
    assert "unchecked" not in function_text(src, "transfer") and "_panic" not in function_text(src, "transfer")
    res, _, _, _ = _probe(monkeypatch, "Ops", Build("0.8.31", via_ir=True), limit=1)
    src = res.solidity
    assert "return a + b;" in function_text(src, "addU")
    assert "return a * b + c - a;" in function_text(src, "chain")
    assert "unchecked" in function_text(src, "unc")  # no guard: stays wrapping
    assert "_panic(17)" not in src and "_panic(18)" not in src


@pytest.mark.parametrize("build", [Build("0.7.6"), Build("0.7.6", optimize=False), Build("0.5.17")],
                         ids=lambda b: b.label)
def test_pre_08_originals_never_become_checked(monkeypatch, build):
    src = """
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b; require(c >= a, "SafeMath: addition overflow"); return c;
    }
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0; uint256 c = a * b; require(c / a == b, "SafeMath: multiplication overflow"); return c;
    }
}
contract Old {
    using SafeMath for uint256;
    uint256 public total;
    uint8 public small;
    function add(uint256 a, uint256 b) external pure returns (uint256) { return a + b; }
    function sub8(uint8 a, uint8 b) external pure returns (uint8) { return a - b; }
    function safeAdd(uint256 a, uint256 b) external pure returns (uint256) { return a.add(b); }
    function safeMul(uint256 a, uint256 b) external pure returns (uint256) { return a.mul(b); }
    function credit(uint256 v) external { total = total.add(v); small++; }
}
"""
    art = compile_probe(src, build, "Old")
    patch_signatures(monkeypatch, art.abi)
    res = generate_probe(art.runtime)
    assert '"SafeMath: addition overflow"' in res.solidity  # library code stays a require
    assert not any((f.get("arith") or {}).get("absorbed") for f in res.functions.values())
    calls, _ = arithprobe.all_calls(res, limit=50)
    pre = arithprobe.storage_presets(art.storage_layout)[:4]
    assert arithprobe.differential(art.runtime, res.solidity, res.target_solc, calls, pre) == []


@pytest.mark.slow
@pytest.mark.parametrize("build", BUILDS + [Build("0.8.19", optimize=False, via_ir=True), Build("0.8.31"),
                                            Build("0.8.31", optimize=False),
                                            Build("0.8.31", optimize=False, via_ir=True)],
                         ids=lambda b: b.label)
@pytest.mark.parametrize("name", sorted(PROBES))
def test_probe_same_behaviour_full_grids(monkeypatch, name, build):
    res, calls, skipped, mism = _probe(monkeypatch, name, build, limit=600, presets=0)
    assert mism == []

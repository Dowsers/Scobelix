"""
Exactness checks of the solgen core: inputs chosen to make the rendered
Solidity behave differently from the EVM semantics of the IR.

  * random word expressions (booleans used as words, words used as
    conditions, hostile constants, symbolic mask and field operands, shifts
    and byte indexes past the word, division by zero, signed overflow...)
    in three positions (returned word, `if` condition, `require`), each in
    a function without and with checked operations; the reference is
    `ir.evaluate` (itself checked against the raw opcodes by
    test_core_render_ops);
  * wrapping arithmetic next to checked operations (conditions, loop tests,
    loop updates, compound assignments, `for` steps), the idiomatic nodes
    (`Typed` of narrow types, `StateRef` of packed variables);
  * statements whose EVM meaning is easy to lose: empty memory ranges at
    huge offsets, operands that end the call behind `&&` or an `if` with
    two equal branches;
  * text that solc rejects: revert strings that are not UTF-8 or carry
    line separators and bidirectional controls, comments carrying such
    characters, database names that are keywords, builtins or names the
    generator declares itself;
  * hostile sizes that must not allocate (masks, constant lengths, static
    arrays of database signatures).
"""

import random
import subprocess
import sys
import textwrap

import pytest

from conftest import backend_or_skip, compile_or_fail
from scobelix.solgen import abi, ir, lift, sigs
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.contract import ContractInput, Unit, assemble
from scobelix.solgen.types import parse_type

A, B, C = (ir.CalldataWord(ir.Const(o)) for o in (4, 36, 68))
M = ir.WORD_MAX
EDGE = [0, 1, 2, 7, 8, 31, 32, 33, 160, 255, 256, 257, 300, 2**64, 2**160 - 1, 2**248, 2**255 - 1, 2**255,
        2**255 + 1, M - 255, M - 1, M]
CALLER = "0x" + "a1" * 20
CAND = "0x" + "c0" * 20
HUGE = 1 << 40  # a memory offset no gas could pay for

BIN = ("add", "sub", "mul", "div", "sdiv", "mod", "smod", "exp", "signextend", "lt", "gt", "slt", "sgt", "eq",
       "and", "or", "xor", "byte", "shl", "shr", "sar")

# a checked operation that never overflows: makes the function a checked one
_CHECKED = ir.Assign(ir.Local("chk"), ir.Typed("add", (ir.Const(1), ir.Const(2)), "uint256", checked=True))


def word(x):
    return (x % 2**256).to_bytes(32, "big")


def _deploy(units, version="0.8.19", **kw):
    backend = backend_or_skip()
    from scobelix.verify.evm import make_world

    source, _ = assemble(ContractInput(units=units, target=version, original="test", **kw))
    art = compile_or_fail(source, version)
    world = make_world(backend)
    world.set_balance(CALLER, 10**20)
    world.set_code(CAND, art.runtime)
    return world, source


def _unit(sel, body, mutability="nonpayable"):
    key = f"0x{sel:08x}"
    return Unit(key, ir.Function(key, tuple(body)), EntrySpec(key=key, kind="function", selector=sel,
                                                             mutability=mutability))


def _call(world, sel, *args, data=None):
    payload = sel.to_bytes(4, "big") + (data if data is not None else b"".join(word(a) for a in args))
    return world.call(CALLER, CAND, payload)


# ---------------------------------------------------------------- random expressions


def _const(rnd):
    r = rnd.random()
    if r < 0.6:
        return ir.Const(rnd.choice(EDGE))
    if r < 0.8:
        return ir.Const(rnd.getrandbits(rnd.choice((8, 64, 256))))
    return ir.const(-rnd.randrange(1, 300))


def _field(rnd, depth):
    """A bit-position field of Mask / Field: a small int, a hostile one, or a word."""
    r = rnd.random()
    if r < 0.45:
        return rnd.choice((0, 1, 4, 8, 96, 160, 224, 248, 255, 256))
    if r < 0.6:
        return rnd.choice((-1, -8, -96, -224, -255, -256, 257, 300, 512))
    if r < 0.8:
        return ir.Op("and", (_expr(rnd, depth), ir.Const(rnd.choice((255, 511)))))
    return _expr(rnd, depth)


def _expr(rnd, depth):
    if depth <= 0 or rnd.random() < 0.2:
        return rnd.choice((A, B, C, A, B, ir.Env("calldatasize"))) if rnd.random() < 0.75 else _const(rnd)
    r = rnd.random()
    d = depth - 1
    if r < 0.55:
        op = rnd.choice(BIN)
        if op in ("add", "mul", "and", "or", "xor") and rnd.random() < 0.3:
            return ir.Op(op, tuple(_expr(rnd, d) for _ in range(3)))
        return ir.Op(op, (_expr(rnd, d), _expr(rnd, d)))
    if r < 0.62:
        return ir.Op(rnd.choice(("iszero", "not")), (_expr(rnd, d),))
    if r < 0.67:
        return ir.Op(rnd.choice(("addmod", "mulmod")), (_expr(rnd, d), _expr(rnd, d), _expr(rnd, d)))
    if r < 0.78:
        return ir.Mask(_field(rnd, d), _field(rnd, d), _field(rnd, d), _expr(rnd, d))
    if r < 0.85:
        return ir.Field(_expr(rnd, d), _field(rnd, d), _field(rnd, d))
    if r < 0.92:
        return ir.Ternary(_expr(rnd, d), _expr(rnd, d), _expr(rnd, d))
    if r < 0.96:
        return ir.BytesWord(ir.WordBytes(_expr(rnd, d), rnd.choice((1, 4, 20, 31, 32))))
    return ir.Keccak(ir.Blob((ir.WordBytes(_expr(rnd, d), rnd.choice((1, 4, 32))), ir.WordBytes(_expr(rnd, d)))))


def _substitute(e, args):
    def f(n):
        if isinstance(n, ir.CalldataWord) and isinstance(n.offset, ir.Const):
            return ir.Const(args[(n.offset.value - 4) // 32])
        if n == ir.Env("calldatasize"):
            return ir.Const(4 + 32 * len(args))
        return n

    return ir.transform(e, f)


def _bodies(e, checked):
    pre = (_CHECKED,) if checked else ()
    yield "word", pre + (ir.Return(ir.WordBytes(e)),)
    yield "if", pre + (ir.If(e, (ir.Return(ir.WordBytes(ir.Const(1))),), (ir.Return(ir.WordBytes(ir.Const(2))),)),)
    yield "require", pre + (ir.Require(e), ir.Return(ir.WordBytes(ir.Const(3))))


def _expected(kind, e, args):
    v = ir.evaluate(_substitute(e, args))
    assert v is not None, f"ir.evaluate is partial on {e}"
    if kind == "word":
        return True, word(v)
    if kind == "if":
        return True, word(1 if v else 2)
    return (True, word(3)) if v else (False, b"")


def _cases(seed, n):
    rnd = random.Random(seed)
    out = []
    while len(out) < n:
        e = _expr(rnd, rnd.choice((2, 3, 4)))
        if ir.evaluate(e) is not None:
            continue  # constant: the renderer folds it, nothing to test
        checked = len(out) % 2 == 1
        for kind, body in _bodies(e, checked):
            out.append((kind, checked, e, body))
    return out


@pytest.mark.parametrize("seed", [11, 12])
def test_random_expressions_keep_evm_semantics(seed):
    cases = _cases(seed, 120)
    world, _ = _deploy([_unit(0x10000000 + i, body, "pure") for i, (_k, _c, _e, body) in enumerate(cases)])
    rnd = random.Random(seed)
    failures = []
    for i, (kind, checked, e, _body) in enumerate(cases):
        for _ in range(14):
            args = tuple(rnd.choice(EDGE) if rnd.random() < 0.6 else rnd.getrandbits(256) for _ in range(3))
            got = _call(world, 0x10000000 + i, *args)
            ok, out = _expected(kind, e, args)
            if got.success != ok or (ok and got.output != out):
                failures.append(f"{kind} checked={checked} {e} args={args}: got {got.success} {got.output.hex()} "
                                f"want {ok} {out.hex()}")
                break
    assert not failures, "\n".join(failures[:8])


def test_field_semantics_are_total_and_unsigned():
    """Field offsets / sizes are unsigned bit counts (what the _field helper
    computes): words of 2**255 or more, and negative Python ints, are huge."""
    x = ir.Const(0x1234)
    assert ir.evaluate(ir.Field(x, ir.Const(2**255), ir.Const(8))) == 0
    assert ir.evaluate(ir.Field(x, 4, ir.Const(M))) == 0x123
    assert ir.evaluate(ir.Field(x, -8, 8)) == 0  # offset 2**256 - 8
    assert ir.evaluate(ir.Field(x, 0, -1)) == 0x1234  # size 2**256 - 1: every bit
    from scobelix.solgen.types import is_boolean, max_bits

    assert max_bits(ir.Field(A, 0, -1)) == 256 and not is_boolean(ir.Field(A, 0, ir.Const(M)))


# ---------------------------------------------------------------- checked functions


def _while_add():
    # v0 = A; while (v0 + 1 != 0) { if (v0 > A + 5) return 99; v0 = v0 + 1 }  return v0
    loop = "Node((7, 1, ('x',)))"
    return (
        ir.While(ir.Op("add", (ir.Local("v0"), ir.ONE)),
                 (ir.If(ir.Op("gt", (ir.Local("v0"), ir.Op("add", (A, ir.Const(5))))),
                        (ir.Return(ir.WordBytes(ir.Const(99))),),
                        (ir.Continue(loop, (ir.Assign(ir.Local("v0"), ir.Op("add", (ir.Local("v0"), ir.ONE))),)),)),),
                 (ir.Assign(ir.Local("v0"), A),), loop),
        ir.Return(ir.WordBytes(ir.Local("v0"))))


def _for_step():
    # for (i = A; i != 0; i = i + 1) n = n + 1 (checked);  return n   (the step wraps)
    loop = "Node((8, 1, ('y',)))"
    i, n = ir.Local("i"), ir.Local("n")
    return (
        ir.For((ir.Assign(i, A), ir.Assign(n, ir.ZERO)), ir.Op("iszero", (ir.Op("eq", (i, ir.ZERO)),)),
               (ir.Assign(i, ir.Op("add", (i, ir.ONE))),),
               (ir.Assign(n, ir.Typed("add", (n, ir.ONE), "uint256", checked=True)),), loop),
        ir.Return(ir.WordBytes(n)))


SPLIT_CASES = {
    # wrapping arithmetic directly in a condition, in a require, under a
    # mask / field / cast that keeps the whole word, in a loop test, in a
    # compound assignment, in a `for` step, and around a checked operation
    "if_add": ((ir.If(ir.Op("add", (A, ir.ONE)), (ir.Return(ir.WordBytes(ir.ONE)),),
                      (ir.Return(ir.WordBytes(ir.Const(2))),)),),
               [((M, 0), (True, word(2))), ((5, 0), (True, word(1)))]),
    "require_sub": ((ir.Require(ir.Op("sub", (A, B))), ir.Return(ir.WordBytes(ir.Const(3)))),
                    [((5, 5), (False, b"")), ((4, 5), (True, word(3)))]),
    "iszero_mul": ((ir.Return(ir.WordBytes(ir.Op("iszero", (ir.Op("mul", (A, B)),)))),),
                   [((2**255, 2), (True, word(1)))]),
    "mask_passthrough": ((ir.Return(ir.WordBytes(ir.Mask(256, 0, 0, ir.Op("add", (A, B))))),),
                         [((M, 2), (True, word(1)))]),
    "field_passthrough": ((ir.Return(ir.WordBytes(ir.Field(ir.Op("sub", (A, B)), 0, 256))),),
                          [((0, 1), (True, word(M)))]),
    "cast_passthrough": ((ir.Return(ir.WordBytes(ir.Cast("uint256", ir.Op("add", (A, B))))),),
                         [((M, M), (True, word(M - 1)))]),
    "while_add": (_while_add(), [((M - 5, 0), (True, word(M))), ((M - 2, 0), (True, word(99))),
                                 ((3, 0), (True, word(99)))]),
    "compound_add": ((ir.Assign(ir.Local("x"), A), ir.Assign(ir.Local("x"), B, op="+"),
                      ir.Assign(ir.Local("x"), ir.Op("mul", (B, ir.Typed("add", (ir.ONE, ir.ONE), "uint256", True))),
                                op="*"),
                      ir.Return(ir.WordBytes(ir.Local("x")))),
                     [((M, 2), (True, word(((M + 2) * 4) % 2**256)))]),
    "compound_div_zero": ((ir.Assign(ir.Local("x"), A), ir.Assign(ir.Local("x"), B, op="/"),
                           ir.Assign(ir.Local("y"), A), ir.Assign(ir.Local("y"), B, op="%"),
                           ir.Return(ir.Blob((ir.WordBytes(ir.Local("x")), ir.WordBytes(ir.Local("y")))))),
                          [((7, 0), (True, word(0) + word(0))), ((7, 2), (True, word(3) + word(1)))]),
    "for_step": (_for_step(), [((M - 2, 0), (True, word(3))), ((M, 0), (True, word(1)))]),
    "wrap_around_checked": ((ir.Return(ir.WordBytes(ir.Op("add", (ir.Typed("add", (A, B), "uint256", True),
                                                                  ir.Op("mul", (A, ir.Const(M))))))),),
                            [((3, 4), (True, word(4))), ((M, 1), (False, None))]),
}


@pytest.mark.parametrize("checked", [False, True])
def test_wrapping_arithmetic_wraps_in_every_position(checked):
    """Each case run in a function without checked operations (one
    `unchecked` block) and in one with a checked operation (statement-level
    blocks and wrapping helpers): the same EVM results."""
    names = list(SPLIT_CASES)
    units = []
    for i, name in enumerate(names):
        body = SPLIT_CASES[name][0]
        units.append(_unit(0x20000000 + i, ((_CHECKED,) if checked else ()) + tuple(body), "pure"))
    world, _ = _deploy(units)
    for i, name in enumerate(names):
        for (a, b), (ok, out) in SPLIT_CASES[name][1]:
            r = _call(world, 0x20000000 + i, a, b)
            if out is None:  # a checked overflow: Panic(0x11)
                out = bytes.fromhex("4e487b71") + word(0x11)
            assert (r.success, r.output) == (ok, out), (name, checked, a, b, r.success, r.output.hex())


def test_dependent_parallel_updates_in_a_checked_function():
    """Loop updates that read each other, with wrapping arithmetic, in a
    function that also has a checked operation."""
    loop = "Node((9, 1, ('y',)))"
    L = ir.Local
    body = (
        _CHECKED,
        ir.While(ir.Op("lt", (L("v0"), ir.Op("and", (A, ir.Const(15))))),
                 (ir.Continue(loop, (ir.Assign(L("v0"), ir.Op("add", (L("v0"), ir.ONE))),
                                     ir.Assign(L("v1"), ir.Op("add", (L("v2"), L("v0")))),
                                     ir.Assign(L("v2"), ir.Op("sub", (L("v1"), L("v0")))),
                                     ir.Assign(L("v3"), ir.Typed("add", (L("v3"), ir.ONE), "uint256", True)))),),
                 (ir.Assign(L("v0"), ir.ZERO), ir.Assign(L("v1"), ir.Const(M)), ir.Assign(L("v2"), ir.ONE),
                  ir.Assign(L("v3"), ir.ZERO)), loop),
        ir.Return(ir.Blob((ir.WordBytes(L("v1")), ir.WordBytes(L("v2")), ir.WordBytes(L("v3"))))))
    world, _ = _deploy([_unit(0x30000000, body, "pure")])
    for n in (0, 1, 2, 5, 15):
        v0, v1, v2 = 0, M, 1
        while v0 < n:
            v0, v1, v2 = v0 + 1, (v2 + v0) % 2**256, (v1 - v0) % 2**256
        r = _call(world, 0x30000000, n)
        assert r.success and r.output == word(v1) + word(v2) + word(n), (n, r.output.hex())


# ---------------------------------------------------------------- idiomatic nodes


def _sx(v, bits):
    v %= 1 << bits
    return v - (1 << bits) if v >> (bits - 1) else v


TYPED = [
    # (type, op, checked, operands from (a, b), Solidity semantics)
    ("uint8", "add", True, lambda a, b: (a % 256, b % 256), lambda x, y: x + y if x + y < 256 else "panic"),
    ("uint8", "add", False, lambda a, b: (a % 256, b % 256), lambda x, y: (x + y) % 256),
    ("uint8", "mul", False, lambda a, b: (a % 256, b % 256), lambda x, y: (x * y) % 256),
    ("uint8", "sub", True, lambda a, b: (a % 256, b % 256), lambda x, y: x - y if x >= y else "panic"),
    ("int8", "add", True, lambda a, b: (_sx(a, 8), _sx(b, 8)),
     lambda x, y: x + y if -128 <= x + y < 128 else "panic"),
    ("int8", "sub", False, lambda a, b: (_sx(a, 8), _sx(b, 8)), lambda x, y: _sx(x - y, 8)),
    ("int8", "lt", False, lambda a, b: (_sx(a, 8), _sx(b, 8)), lambda x, y: int(x < y)),
    ("int256", "mul", True, lambda a, b: (_sx(a, 256), _sx(b, 256)),
     lambda x, y: x * y if -2**255 <= x * y < 2**255 else "panic"),
    ("uint16", "div", False, lambda a, b: (a % 65536, b % 65536), lambda x, y: x // y if y else "panic0"),
]


def _typed_operand(v, ty):
    """The IR word of a `ty` value v (a valid value: masked or sign-extended)."""
    bits = int(ty.lstrip("uint") or 256)
    if ty.startswith("int"):
        return ir.Op("signextend", (ir.Const(bits // 8 - 1), v)) if bits < 256 else v
    return ir.Mask(bits, 0, 0, v) if bits < 256 else v


@pytest.mark.parametrize("mode", ["unchecked function", "own statement", "next to a checked operation"])
def test_typed_operations_have_solidity_semantics_in_their_type(mode):
    """Typed operations in a function without checked operations, in a
    statement of their own of a checked function, and in the same
    statement as a checked operation (unchecked ones through the wrapping
    helpers there)."""
    three = ir.Typed("add", (ir.Const(1), ir.Const(2)), "uint256", checked=True)
    units, run = [], []
    for i, (ty, op, checked, _ops, _sem) in enumerate(TYPED):
        if checked and mode == "unchecked function":
            continue
        e = ir.Typed(op, (_typed_operand(A, ty), _typed_operand(B, ty)), ty, checked)
        if mode == "next to a checked operation":
            body = (ir.Return(ir.Blob((ir.WordBytes(e), ir.WordBytes(three)))),)
        else:
            body = ((_CHECKED,) if mode == "own statement" else ()) + (ir.Return(ir.WordBytes(e)),)
        units.append(_unit(0x40000000 + i, body, "pure"))
        run.append(i)
    world, _ = _deploy(units)
    tail = word(3) if mode == "next to a checked operation" else b""
    rnd = random.Random(5)
    for i in run:
        ty, op, checked, operands, sem = TYPED[i]
        for _ in range(40):
            a, b = (rnd.choice(EDGE + [127, 128, 129, 254, 65535]) if rnd.random() < 0.7 else rnd.getrandbits(256)
                    for _ in range(2))
            want = sem(*operands(a, b))
            r = _call(world, 0x40000000 + i, a, b)
            if want == "panic":
                assert (r.success, r.output) == (False, bytes.fromhex("4e487b71") + word(0x11)), (ty, op, a, b)
            elif want == "panic0":
                assert (r.success, r.output) == (False, bytes.fromhex("4e487b71") + word(0x12)), (ty, op, a, b)
            else:
                assert r.success and r.output == word(want) + tail, (ty, op, checked, a, b, r.output.hex(), want)


def test_state_refs_are_widened_and_assignments_narrowed():
    """Packed state variables of narrow types, read as words and assigned
    from words (the storage pass declares them)."""
    S = ir.StateRef
    body = (
        ir.Assign(S("v8", (), "uint8"), ir.Mask(8, 0, 0, A)),
        ir.Assign(S("owner", (), "address"), ir.Mask(160, 0, 0, B)),
        ir.Assign(S("flag", (), "bool"), ir.Op("iszero", (ir.Op("iszero", (C,)),))),
        ir.Assign(S("s16", (), "int16"), ir.Op("signextend", (ir.ONE, A))),
        ir.Assign(S("b4", (), "bytes4"), ir.Mask(32, 224, 0, B)),
        ir.Return(ir.Blob(tuple(ir.WordBytes(x) for x in (
            S("v8", (), "uint8"), S("owner", (), "address"), S("flag", (), "bool"), S("s16", (), "int16"),
            S("b4", (), "bytes4"), ir.Op("add", (S("v8", (), "uint8"), ir.Const(M))), ir.Sload(ir.ZERO))))),
    )
    decl = {"state": ["uint8 internal v8;", "address internal owner;", "bool internal flag;", "int16 internal s16;",
                      "bytes4 internal b4;"]}
    world, _ = _deploy([_unit(0x50000000, body)], declarations=decl)
    for a, b, c in ((0x1234_ff, 2**200 + 0xabc, 7), (M, M, 0), (0x8001, 0, 1)):
        r = _call(world, 0x50000000, a, b, c)
        s16 = _sx(a, 16) % 2**256
        slot = (a & 0xFF) | ((b % 2**160) << 8) | (int(c != 0) << 168) | ((a & 0xFFFF) << 176) | ((b >> 224) << 192)
        want = b"".join(word(x) for x in (a & 0xFF, b % 2**160, int(c != 0), s16, (b >> 224) << 224,
                                          (a & 0xFF) - 1, slot))
        assert r.success and r.output == want, (a, b, c, r.output.hex())


def test_typed_returns_and_events():
    """Return.values and Emit write typed values (a uint256 word where the
    declaration says address / bool / uint8 would not compile), with the
    same bytes as the words."""
    text = "get(uint256,uint256)"
    sel = sigs.function_selector(text)
    spec = EntrySpec(key=f"0x{sel:08x}", kind="function", selector=sel, name="get", signature=text,
                     params=((parse_type("uint256"), "a"), (parse_type("uint256"), "b")), mutability="nonpayable",
                     returns=(parse_type("address"), parse_type("bool"), parse_type("uint8")))
    vals = (ir.Mask(160, 0, 0, A), ir.Op("lt", (A, B)), ir.Mask(8, 0, 0, B))
    body = (ir.Emit("Seen", (ir.Mask(160, 0, 0, A), ir.Mask(8, 0, 0, B), ir.Op("iszero", (A,))),
                    ("address", "uint8", "bool")),
            ir.Return(values=vals))
    routed = _unit(0x90000000, (ir.Return(values=(A, ir.Op("add", (A, B)))),), "pure")
    world, _ = _deploy([Unit(spec.key, ir.Function(spec.key, body), spec), routed],
                       declarations={"event": ["event Seen(address indexed who, uint8 small, bool zero);"]})
    from eth_utils import keccak

    a, b = 2**200 + 0x1234, 0x1FF
    r = _call(world, sel, a, b)
    assert r.success and r.output == word(a % 2**160) + word(int(a < b)) + word(b % 256), r.output.hex()
    (_addr, topics, data), = r.logs
    assert topics == (int.from_bytes(keccak(text="Seen(address,uint8,bool)"), "big"), a % 2**160)
    assert data == word(b % 256) + word(0)
    r = _call(world, 0x90000000, 3, M)
    assert r.success and r.output == word(3) + word(2)


# ---------------------------------------------------------------- statements


def test_empty_memory_ranges_at_huge_offsets_touch_no_memory():
    """A zero-length range costs nothing in the EVM, at any offset."""
    huge = ir.Op("add", (ir.Const(HUGE), A))
    body = (ir.Mstore(huge, ir.Blob(())),
            ir.Log((), ir.MemSlice(huge, ir.ZERO)),
            ir.Return(ir.Blob((ir.WordBytes(ir.Keccak(ir.MemSlice(huge, ir.ZERO))),
                               ir.WordBytes(ir.MLoad(ir.Const(0x40)))))))
    world, _ = _deploy([_unit(0x60000000, body), _unit(0x60000001, (ir.Return(ir.MemSlice(huge, ir.ZERO)),))])
    r = _call(world, 0x60000000, 5)
    assert r.success and r.output == bytes.fromhex(
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470") + word(0), r.output.hex()
    r = _call(world, 0x60000001, 5)
    assert r.success and r.output == b""


def test_operands_that_end_the_call_are_evaluated():
    """`and` / `or` of booleans and an `if` whose branches are equal: the
    opcodes evaluate every operand, so a memory read no gas could pay for
    ends the call even when the result is already known."""
    far = ir.MLoad(ir.Op("add", (ir.Const(HUGE), B)))
    body_and = (ir.If(ir.Op("and", (ir.Op("iszero", (A,)), ir.Op("lt", (far, ir.Const(5))))),
                      (ir.Return(ir.WordBytes(ir.ONE)),), (ir.Return(ir.WordBytes(ir.Const(2))),)),)
    body_or = (ir.Return(ir.WordBytes(ir.Op("or", (ir.Op("iszero", (A,)), ir.Op("eq", (far, ir.ZERO)))))),)
    same = (ir.Return(ir.WordBytes(ir.ONE)),)
    body_if = (ir.If(ir.Op("lt", (far, ir.ONE)), same, same),)
    world, _ = _deploy([_unit(0x61000000 + i, b, "pure") for i, b in enumerate((body_and, body_or, body_if))])
    # and: the left operand is 0; or: it is 1 (a short-circuit skips the read)
    for i, a in enumerate((7, 0, 0)):
        r = _call(world, 0x61000000 + i, a, 0)
        assert not r.success and r.output == b"", (i, r.success, r.output.hex())
    # memory that the call can pay for: the plain results
    near = ir.MLoad(ir.Op("and", (B, ir.Const(0xFFFF))))
    body_and_near = (ir.Return(ir.WordBytes(ir.Op("and", (ir.Op("iszero", (A,)), ir.Op("lt", (near, ir.ONE)))))),)
    world, _ = _deploy([_unit(0x62000000, body_and_near, "pure")])
    assert _call(world, 0x62000000, 0, 77).output == word(1)
    assert _call(world, 0x62000000, 3, 77).output == word(0)


# ---------------------------------------------------------------- text solc rejects


MESSAGES = [
    b"plain",
    "café \U0001F600 ́  ".encode(),
    "line para next\u0085".encode(),
    "rtl‮override ⁦isolate ‏mark ﻿bom".encode(),
    b"\x00\x01\x1f\x7f quote\" back\\slash \n\r\t",
    b"\xff\xfe not utf-8 \x80",
    b"",
]


def _error_string(msg):
    pad = (-len(msg)) % 32
    return bytes.fromhex("08c379a0") + word(32) + word(len(msg)) + msg + bytes(pad)


def test_revert_strings_compile_and_keep_their_bytes():
    units = [_unit(0x70000000 + i, (ir.Revert(ir.ErrorString(m)),), "pure") for i, m in enumerate(MESSAGES)]
    world, _ = _deploy(units)
    for i, m in enumerate(MESSAGES):
        r = _call(world, 0x70000000 + i)
        assert not r.success and r.output == _error_string(m), (m, r.output.hex())


def test_comments_carry_only_safe_characters():
    """Untranslated code and the header are comments: a line separator
    there would end the comment, a bidirectional control is rejected."""
    nasty = "x y z\u0085w‮\nrevert();}contract Evil{"
    body = (ir.Unstructured(raw=nasty, reason=nasty),)
    source, _ = assemble(ContractInput(units=[_unit(0x71000000, body, "pure")], target="0.8.19", original=nasty))
    compile_or_fail(source, "0.8.19")
    for line in source.splitlines():
        text = line.strip()
        if "Evil" in text:
            assert text.startswith("//"), line
        if text.startswith("//"):
            assert all(" " <= ch <= "~" for ch in text), line


def _head_check(n_words):
    return ir.Op("slt", (ir.Op("add", (ir.const(-4), ir.Env("calldatasize"))), ir.Const(32 * n_words)))


def _sig(text, names):
    name, types = text.split("(", 1)
    types = [t for t in types[:-1].split(",") if t]
    return sigs.Signature("function", name, tuple(zip(types, names)), text, trusted=True)


def test_database_names_that_solc_rejects(monkeypatch):
    """Function names that are keywords, builtins or generated names are
    routed (same selector); parameter names are renamed; both compile."""
    table = {}
    entries = [
        ("apply(uint256)", ("x",)),
        ("default()", ()),
        ("_code(uint256)", ("x",)),
        ("S0()", ()),
        ("keccak256(uint256)", ("x",)),
        ("Decompiled()", ()),
        # parameters named like helpers, keywords, types, builtins and locals
        ("touch(uint256,uint256,uint256)", ("_code", "byte", "abi")),
        ("poke(uint256,uint256,uint256)", ("c1_ok", "_", "uint8")),
        ("prod(uint256,uint256)", ("hex", "this")),
    ]
    for text, names in entries:
        table[sigs.function_selector(text)] = (_sig(text, names),)
    monkeypatch.setattr(sigs, "function_candidates", lambda sel: table.get(sel, ()))

    def body_for(n):
        p = [ir.CalldataWord(ir.Const(4 + 32 * k)) for k in range(n)]
        if n == 3:  # code copy, byte, keccak of a blob, a call
            inner = (ir.ExtCall(1, "staticcall", None, ir.Const(0xDEAD), None, None, ir.WordBytes(p[1])),
                     ir.Return(ir.Blob((ir.WordBytes(ir.Op("byte", (p[1], p[2]))),
                                        ir.WordBytes(ir.Keccak(ir.Blob((ir.WordBytes(p[0]), ir.WordBytes(p[2]))))),
                                        ir.WordBytes(ir.CallOut(1, "success")),
                                        ir.CodeSlice(p[0], ir.Const(3))))))
        elif n == 2:
            inner = (ir.Return(ir.Blob((ir.WordBytes(ir.Op("add", (p[0], p[1]))),))),)
        else:
            inner = (ir.Return(ir.WordBytes(p[0] if p else ir.ONE)),)
        if not n:
            return inner
        return (ir.If(_head_check(n), (ir.Revert(),), inner),)

    units = []
    for text, names in entries:
        sel = sigs.function_selector(text)
        key = f"0x{sel:08x}"
        fn = ir.Function(key, body_for(len(names)))
        spec, fn = abi.analyse_entry(fn, key, selector=sel, payable=False, reserved=frozenset({"Decompiled"}))
        units.append(Unit(key, fn, spec))
    by_name = {u.spec.key: u.spec for u in units}
    for text, _names in entries[:6]:
        spec = by_name[f"0x{sigs.function_selector(text):08x}"]
        assert spec.routed and "signature_name_reserved" in spec.flags, text
    named = [u.spec for u in units if not u.spec.routed]
    assert sorted(s.name for s in named) == ["poke", "prod", "touch"]
    world, source = _deploy(units, original_code=bytes(range(40)))
    for s in named:
        for _t, n in s.params:
            assert not abi.reserved_name(n, parameter=True), n
    # the routed and the named functions behave like their bodies
    sel = sigs.function_selector("apply(uint256)")
    assert _call(world, sel, 41).output == word(41)
    sel = sigs.function_selector("prod(uint256,uint256)")
    assert _call(world, sel, 2, M).output == word(1)
    sel = sigs.function_selector("touch(uint256,uint256,uint256)")
    r = _call(world, sel, 5, 31, 0xAB)
    from eth_utils import keccak

    assert r.success and r.output == word(0xAB) + keccak(word(5) + word(0xAB)) + word(1) + bytes([5, 6, 7]), \
        r.output.hex()


def test_parameterless_bodies_take_no_database_parameters(monkeypatch):
    """Without a calldata size check (legacy code generator, no
    parameters), a candidate with parameters would add the decoder's size
    check: the parameterless candidate is the only one that fits."""
    sel = 0x12345678
    with_args = sigs.Signature("function", "f", (("uint256", "x"),), "f(uint256)", trusted=True)
    without = sigs.Signature("function", "g", (), "g()", trusted=False)
    fn = ir.Function("0x12345678", (ir.Return(ir.WordBytes(ir.Sload(ir.ZERO))),))
    monkeypatch.setattr(sigs, "function_candidates", lambda s: (with_args,))
    spec, _ = abi.analyse_entry(fn, "0x12345678", selector=sel, payable=False)
    assert spec.routed and "signature_rejected" in spec.flags
    monkeypatch.setattr(sigs, "function_candidates", lambda s: (with_args, without))
    spec, _ = abi.analyse_entry(fn, "0x12345678", selector=sel, payable=False)
    assert spec.signature == "g()"
    # a body that reads its arguments keeps the database's parameters
    reads = ir.Function("0x12345678", (ir.Return(ir.WordBytes(A)),))
    monkeypatch.setattr(sigs, "function_candidates", lambda s: (with_args,))
    spec, _ = abi.analyse_entry(reads, "0x12345678", selector=sel, payable=False)
    assert spec.signature == "f(uint256)"


def test_abi_coder_v1_originals_take_no_v2_only_parameter_types(monkeypatch):
    """Structs and arrays of dynamic types need ABI coder v2 (solc rejects
    them under `pragma abicoder v1`, and a v1 decoder never took them): for
    an ABI coder v1 original such a candidate is routed."""
    text = "f((uint256,address),string[])"
    sel = sigs.function_selector(text)
    cand = sigs.Signature("function", "f", (("(uint256,address)", "s"), ("string[]", "t")), text, trusted=True)
    monkeypatch.setattr(sigs, "function_candidates", lambda s: (cand,))

    def entry(bound, abi_v2):
        # the size check, then the decoder's offset check of the string[] (v1: 2**32, v2: 2**64 - 1)
        offset = ir.Op("gt", (ir.CalldataWord(ir.Const(4 + 64)), ir.Const(bound)))
        body = (ir.If(_head_check(3), (ir.Revert(),), (ir.If(offset, (ir.Revert(),), (ir.Return(ir.WordBytes(A)),)),)),)
        fn = ir.Function(f"0x{sel:08x}", body)
        return abi.analyse_entry(fn, fn.key, selector=sel, payable=False, abi_v2=abi_v2)[0]

    assert entry(1 << 32, abi_v2=False).routed
    assert entry((1 << 64) - 1, abi_v2=True).signature == text
    assert not abi._needs_abi_v2(parse_type("uint256[2][]")) and abi._needs_abi_v2(parse_type("bytes[]"))


# ---------------------------------------------------------------- hostile sizes


def _bounded(code):
    """Run `code` in a child process limited to 2 GB of address space."""
    prog = "import resource\nresource.setrlimit(resource.RLIMIT_AS, (1 << 31, 1 << 31))\n" + textwrap.dedent(code)
    r = subprocess.run([sys.executable, "-c", prog], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-2000:]
    return r.stdout


def test_hostile_constants_do_not_allocate():
    """Masks / fields with huge constant bit positions, constant lengths of
    2**40 bytes and static arrays of 10**12 words in database signatures
    are handled in bounded memory (clamped before building integers)."""
    out = _bounded("""
        from scobelix.solgen import abi, ir, lift, sigs
        from scobelix.solgen.abi import EntrySpec
        from scobelix.solgen.contract import ContractInput, Unit, assemble
        A = ir.CalldataWord(ir.Const(4))
        exprs = [ir.Mask(8, 1 << 40, 0, A), ir.Mask(1 << 40, 0, 0, A), ir.Mask(8, 0, 1 << 40, A),
                 ir.Mask(1 << 40, 8, -8, A), ir.Mask(8, -(1 << 40), 0, A), ir.Field(A, 1 << 40, 8),
                 ir.Field(A, 0, 1 << 40), ir.Mask(ir.Const(1 << 200), ir.Const(1 << 199), ir.Const(3), A),
                 ir.Mask(1 << 40, -(1 << 39), 4, A)]
        units = []
        for i, e in enumerate(exprs):
            key = "0x%08x" % (0x40000000 + i)
            units.append(Unit(key, ir.Function(key, (ir.Return(ir.WordBytes(e)),)),
                              EntrySpec(key=key, kind="function", selector=0x40000000 + i)))
        src, _ = assemble(ContractInput(units=units, target="0.8.19", original="test"))
        ctx = lift.LiftContext()
        trace = [("setmem", ("range", 0, 1 << 40), 5), ("setmem", ("range", 0, 1 << 40), 1 << 300),
                 ("return", ("data", ("bytes", 1 << 40, 1 << 300)))]
        fn = lift.lift_function("_fallback", trace, ctx)
        huge = sigs.Signature("function", "f", (("uint256[1000000000000]", "x"),), "f(uint256[1000000000000])")
        assert abi._choose([huge], None, {}, frozenset()) is None
        print(len(src), "unstructured" in fn.flags)
    """)
    assert out.split()[-1] == "True"


def test_mask_helper_matches_the_reference_on_symbolic_fields():
    """The _maskShl helper (symbolic size / offset / shift) against
    ir.mask_value, including sizes above 256 with negative offsets (the
    mask is shifted right before it is cut to the word)."""
    e = ir.Mask(A, B, C, ir.Const(M))
    world, source = _deploy([_unit(0x80000000, (ir.Return(ir.WordBytes(e)),), "pure")])
    assert "_maskShl(" in source
    rnd = random.Random(3)
    cases = [(300, -10, 0), (260, -4, 0), (511, -255, 1), (257, -1, -1), (8, -4, 0), (2**255, 0, 0),
             (M, 3, 0), (100, 2**255, 0), (100, 0, -(2**255) % 2**256), (9, 250, 3)]
    for _ in range(60):
        cases.append(tuple(rnd.choice([0, 1, 8, 255, 256, 257, 300, 511, M, M - 7, 2**255, rnd.getrandbits(9),
                                       (-rnd.randrange(1, 300)) % 2**256]) for _ in range(3)))
    for size, off, shl in cases:
        want = ir.mask_value(ir.to_signed(size % 2**256), ir.to_signed(off % 2**256), ir.to_signed(shl % 2**256), M)
        r = _call(world, 0x80000000, size % 2**256, off % 2**256, shl % 2**256)
        assert r.success and r.output == word(want), (size, off, shl, r.output.hex(), hex(want))


# ---------------------------------------------------------------- pass interface


def test_passes_declare_modifiers_and_internal_functions(monkeypatch):
    """Every declaration kind a pass may add is written out (none is
    dropped silently), an unknown kind is an error, and the result
    compiles and still behaves like the original."""
    import types

    from conftest import decompiled
    from scobelix.solgen import pipeline
    from scobelix.solgen.v2 import generate

    def finish(ctx):
        ctx.declare("modifier", "modifier onlyTest() {\n    _;\n}")
        ctx.declare("function", "function _testHelper(uint256 x) internal pure returns (uint256) {\n"
                                "    return x;\n}")
        ctx.declare("state", "uint256 internal testVar;")
        with pytest.raises(ValueError):
            ctx.declare("statement", "x = 1;")

    fake = types.ModuleType("scobelix.solgen.passes.modifiers")
    fake.run = lambda fn, ctx: fn
    fake.finish = finish
    monkeypatch.setitem(pipeline._LOADED, "modifiers", fake)
    r = generate(decompiled("SimpleToken"), idiom_level="full")
    assert "modifier onlyTest()" in r.solidity and "function _testHelper(" in r.solidity
    assert not any("finish failed" in w for w in r.warnings), r.warnings
    compile_or_fail(r.solidity, r.target_solc)

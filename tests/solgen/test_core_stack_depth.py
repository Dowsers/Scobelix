"""
Statements whose operands nest deeper than the 16 stack slots solc's legacy
code generator reaches: their operands are evaluated first into locals (on
the stack, each in a scope of its own; or, when that cannot fit either, in
memory arrays), the conditions of `if` and of loops through one bool, and
the text compiles with the legacy pipeline and behaves as the IR says.
Operands move only when no two that fail differently change order.
"""

import re

import pytest
from eth_utils import keccak

from conftest import backend_or_skip, compile_or_fail
from probes import CALLER as PROBE_CALLER
from probes import Build, compile_probe, differential, function_text, generate_probe, patch_signatures, probe_calls
from scobelix.solgen import ir, sigs, stack
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.contract import ContractInput, Unit, assemble
from scobelix.solgen.types import parse_type

CALLER = "0x" + "a1" * 20
CAND = "0x" + "c0" * 20
W = 1 << 256
A, B, C = (ir.CalldataWord(ir.Const(o)) for o in (4, 36, 68))


def word(x):
    return (x % W).to_bytes(32, "big")


def h(*parts):
    """keccak256 of the words, as a word (IR and reference)."""
    return ir.Keccak(ir.Blob(tuple(ir.WordBytes(p) for p in parts)))


def ref_h(*words):
    return int.from_bytes(keccak(b"".join(word(w) for w in words)), "big")


def deep(n, x, y):
    """h(x + n - 1, y, h(..., h(x, y, x + calldata word))) n levels deep: the
    nested operand is the last argument of each level (two slots a level)."""
    e = ir.Op("add", (x, ir.CalldataWord(ir.Op("add", (ir.Const(4), ir.Op("and", (y, ir.Const(64))))))))
    for k in range(n):
        e = h(ir.Op("add", (x, ir.Const(k))), y, e)
    return e


def ref_deep(n, x, y, cd):
    def cdload(off):
        return int.from_bytes((cd + bytes(64))[off:off + 32], "big")

    e = (x + cdload(4 + (y & 64))) % W
    for k in range(n):
        e = ref_h((x + k) % W, y, e)
    return e


def ret_words(*ws):
    return ir.Return(ir.Blob(tuple(ir.WordBytes(w) for w in ws)))


LOOP = "Node((77, 4, ('1',)))"
N = 9  # levels of the deep operands: far more than the window
LOCALS = tuple(ir.Assign(ir.Local(f"v{i}"), ir.Op("add", (A, ir.Const(i)))) for i in range(6))

CASES = {
    # a payload of several deep words
    "deep_return": (
        (ret_words(deep(N, A, B), deep(N, B, C), ir.Op("add", (deep(N, C, A), A))),),
        lambda a, b, c, cd: word(ref_deep(N, a, b, cd)) + word(ref_deep(N, b, c, cd))
        + word(ref_deep(N, c, a, cd) + a),
    ),
    # a deep condition, then branches that read the same operands
    "deep_if": (
        (ir.If(ir.Op("eq", (ir.Op("and", (deep(N, A, B), ir.Const(1))), ir.ZERO)),
               (ret_words(deep(N - 2, B, C)),), (ret_words(A),)),),
        lambda a, b, c, cd: word(ref_deep(N - 2, b, c, cd)) if ref_deep(N, a, b, cd) % 2 == 0 else word(a),
    ),
    # a loop whose condition is deep, evaluated again at every iteration
    "deep_loop": (
        (ir.While(ir.Op("lt", (ir.Op("and", (deep(N, ir.Local("i"), B), ir.Const(3))), ir.Const(3))),
                  (ir.Continue(LOOP, (ir.Assign(ir.Local("i"), ir.Op("add", (ir.Local("i"), ir.ONE))),)),),
                  (ir.Assign(ir.Local("i"), ir.Op("and", (A, ir.Const(7)))),), LOOP),
         ret_words(ir.Local("i"))),
        lambda a, b, c, cd: word(_loop_ref(a, b, cd)),
    ),
    # locals on the stack under a deep payload
    "crowded": (
        LOCALS + (ret_words(*(ir.Op("add", (ir.Local(f"v{i}"), deep(N - 3, A, ir.Local(f"v{5 - i}"))))
                              for i in range(3)), *(ir.Local(f"v{i}") for i in range(6))),),
        lambda a, b, c, cd: b"".join(word(a + i + ref_deep(N - 3, a, a + 5 - i, cd)) for i in range(3))
        + b"".join(word(a + i) for i in range(6)),
    ),
}


def _loop_ref(a, b, cd):
    i = a & 7
    for _ in range(1000):
        if not ref_deep(N, i, b, cd) & 3 < 3:
            return i
        i += 1
    raise AssertionError("no exit")


OPERANDS = [(0, 0, 0), (1, 2, 3), (2**256 - 1, 2**255, 64), (0x1234 << 100, 2**64 + 64, 7)]


@pytest.fixture(scope="module")
def deployed():
    backend = backend_or_skip()
    from scobelix.verify.evm import make_world

    units, keys = [], {}
    for i, (name, (body, _)) in enumerate(CASES.items()):
        sel = 0x30000000 + i
        key = f"0x{sel:08x}"
        units.append(Unit(key, ir.Function(key, body), EntrySpec(key=key, kind="function", selector=sel)))
        keys[name] = sel
    source, _ = assemble(ContractInput(units=units, target="0.8.19", original="test"))
    art = compile_or_fail(source, "0.8.19")  # the legacy pipeline: no "Stack too deep"
    return backend, make_world, art.runtime, keys, source


@pytest.mark.parametrize("name", list(CASES))
def test_deep_statements_compile_and_keep_their_values(deployed, name):
    backend, make_world, runtime, keys, source = deployed
    for a, b, c in OPERANDS:
        world = make_world(backend)
        world.set_balance(CALLER, 10**20)
        world.set_code(CAND, runtime)
        cd = keys[name].to_bytes(4, "big") + word(a) + word(b) + word(c)
        res = world.call(CALLER, CAND, cd)
        assert res.success, (name, (a, b, c), res.error)
        assert res.output == CASES[name][1](a, b, c, cd), (name, (a, b, c))


def test_the_forms(deployed):
    source = deployed[4]
    assert "uint256 _h" in source  # locals on the stack
    assert "memory _t" in source  # and in memory arrays, where the stack is full
    assert "if (!_c) break;" in source  # the loop condition at the top of the body
    assert "_c = " in source


def test_the_model_counts_calls_and_operators():
    model = stack.StackModel()
    # a call: its return label, then each argument over the ones before it
    e = ir.Mask(ir.Const(8), ir.Const(0), ir.Const(0), A)  # _maskShl(8, 0, 0, _calldataload(4))
    assert model.need(A, set(), {}) == 2  # the label and the argument
    assert model.need(e, set(), {}) == 4 + 2  # the 4th argument over the label and 3 values
    # a binary operator: the right operand first, then the left one over its value
    left_deep = ir.Op("add", (ir.Op("add", (A, ir.ONE)), ir.ONE))
    right_deep = ir.Op("add", (ir.ONE, ir.Op("add", (ir.ONE, A))))
    assert model.need(right_deep, set(), {}) < model.need(left_deep, set(), {})


WEIGHTS = """
contract Sums {
    mapping(address => uint256) public balance;
    uint256 public totalSupply;

    function total(address[] memory who) public view returns (uint256 result) {
        for (uint256 i = 0; i < who.length; i++) {
            result += balance[who[i]];
        }
    }

    function weighted(address[] memory who, uint256[] memory weights, uint256 a, uint256 b, uint256 c, uint256 d)
        public view returns (uint256 result, uint256 extra)
    {
        for (uint256 i = 0; i < who.length; i++) {
            result += balance[who[i]] * weights[i] + a;
            extra += balance[who[(i + b) % who.length]] + c * d;
        }
    }

    function spread(address[] memory who, uint256[] memory amounts) public {
        require(who.length == amounts.length, "lengths");
        for (uint256 i = 0; i < who.length; i++) {
            require(balance[msg.sender] >= amounts[i], "funds");
            balance[msg.sender] -= amounts[i];
            balance[who[i]] += amounts[i];
        }
    }
}
"""


def _unread_locals(text: str) -> list:
    """The hoisted locals of a function's text that are set and never read."""
    out = []
    for name in sorted(set(re.findall(r"\b(?:uint256|bytes memory) (_h(?:_\d+)?)\b", text))):
        uses = len(re.findall(rf"\b{name}\b", text))
        defs = len(re.findall(rf"\b{name}\s*=(?!=)", text)) + len(re.findall(rf"\b(?:uint256|bytes memory) {name};", text))
        if uses <= defs:
            out.append(name)
    return out


def test_no_hoisted_local_is_left_unread(monkeypatch):
    # a local the renderer never reads (the statement writes the operand from its parts: an
    # address key unwraps its mask) is another plan's job, and a local declared then set in a
    # scope of its own (two occurrences) is no read either
    art = compile_probe(WEIGHTS, Build("0.8.19"), "Sums")
    patch_signatures(monkeypatch, art.abi)
    res = generate_probe(art.runtime)
    assert "uint256 _h" in res.solidity  # the planner hoisted operands
    for name in ("total", "weighted", "spread"):
        text = function_text(res.solidity, name)
        assert text and not _unread_locals(text), (name, _unread_locals(text))
    calls, skipped = probe_calls(res)
    assert not skipped
    balances = {int.from_bytes(keccak(bytes(12) + bytes.fromhex(PROBE_CALLER[2:]) + bytes(32)), "big"): 10**30}
    assert not differential(art.runtime, res.solidity, res.target_solc, calls, balances)


def _typed(name: str, n: int, body) -> Unit:
    """`name(uint256 p0, ..., uint256 p<n-1>)` with this body."""
    text = f"{name}(" + ",".join(["uint256"] * n) + ")"
    sel = sigs.function_selector(text)
    spec = EntrySpec(key=f"0x{sel:08x}", kind="function", selector=sel, name=name, signature=text,
                     params=tuple((parse_type("uint256"), f"p{i}") for i in range(n)))
    return Unit(spec.key, ir.Function(spec.key, body), spec)


def test_a_statement_is_planned_over_the_variables_it_names():
    # five parameters (the most an external function keeps on its stack) under a deep payload:
    # one that reads only the last parameter never reaches the four below it (written as it is),
    # one that reads the first reaches them all (its operands go into locals); both compile with
    # the legacy pipeline and return the reference value
    backend = backend_or_skip()
    from scobelix.verify.evm import make_world

    n, k = 5, 6
    last = ir.CalldataWord(ir.Const(4 + 32 * (n - 1)))
    units = [_typed("shallow", n, (ret_words(deep(k, last, last)),)), _typed("deepest", n, (ret_words(deep(k, A, A)),))]
    source, _ = assemble(ContractInput(units=units, target="0.8.19", original="test"))
    planned = re.compile(r"\b_(?:h|t|tb)(?:_\d+)?\b")
    assert not planned.search(function_text(source, "shallow")), function_text(source, "shallow")
    assert planned.search(function_text(source, "deepest"))
    runtime = compile_or_fail(source, "0.8.19").runtime  # the legacy pipeline: no "Stack too deep"
    for unit, p in zip(units, (n - 1, 0)):
        for args in OPERANDS:
            ws = [(args[i % 3] + i) % W for i in range(n)]
            cd = unit.spec.selector.to_bytes(4, "big") + b"".join(word(w) for w in ws)
            world = make_world(backend)
            world.set_balance(CALLER, 10**20)
            world.set_code(CAND, runtime)
            res = world.call(CALLER, CAND, cd)
            assert res.success and res.output == word(ref_deep(k, ws[p], ws[p], cd)), (unit.spec.name, args)


def test_a_statement_is_planned_over_the_locals_in_scope():
    # two branches each declare five locals where they are set (ten: all on the stack); a deep
    # payload in the second branch sits over its own five only (the first branch's have left the
    # stack): written as it is when it fits over them (k = 2), through locals when it does not
    # (k = 5); the text compiles with the legacy pipeline and returns the reference values
    backend = backend_or_skip()
    from scobelix.verify.evm import make_world

    units = []
    for k in (2, 5):
        xs = tuple(ir.Assign(ir.Local(f"x{i}"), ir.Op("add", (A, ir.Const(i))), declare=True) for i in range(5))
        ys = tuple(ir.Assign(ir.Local(f"y{i}"), ir.Op("add", (B, ir.Const(i))), declare=True) for i in range(5))
        payload = ret_words(deep(k, ir.Local("y4"), ir.Local("y0")), ir.Local("y1"), ir.Local("y2"))
        body = (ir.If(ir.Op("iszero", (C,)), xs + (ret_words(*(ir.Local(f"x{i}") for i in range(5))),),
                      ys + (payload,)),)
        sel = 0x51000000 + k
        units.append(Unit(f"0x{sel:08x}", ir.Function(f"0x{sel:08x}", body),
                          EntrySpec(key=f"0x{sel:08x}", kind="function", selector=sel)))
    source, _ = assemble(ContractInput(units=units, target="0.8.19", original="test"))
    planned = re.compile(r"\buint256 _h\b|\bmemory _t\b")
    assert "uint256 y0 = " in source  # (declared where set: ten locals stay on the stack)
    assert not planned.search(function_text(source, "_fn_51000002"))
    assert planned.search(function_text(source, "_fn_51000005"))
    runtime = compile_or_fail(source, "0.8.19").runtime  # the legacy pipeline: no "Stack too deep"
    for k in (2, 5):
        for a, b, c in OPERANDS:
            world = make_world(backend)
            world.set_balance(CALLER, 10**20)
            world.set_code(CAND, runtime)
            cd = (0x51000000 + k).to_bytes(4, "big") + word(a) + word(b) + word(c)
            res = world.call(CALLER, CAND, cd)
            want = b"".join(word(a + i) for i in range(5)) if c == 0 else \
                word(ref_deep(k, b + 4, b, cd)) + word(b + 1) + word(b + 2)
            assert res.success and res.output == want, (k, (a, b, c))


def test_failures_that_differ_keep_their_order():
    slice_ = ir.MemSlice(A, B)  # halts for a huge size
    element = ir.StateRef("items", (C,), "uint256")  # an array element: Panic 0x32 out of bounds
    blob = ir.Blob((ir.WordBytes(element), slice_))  # the element is read first
    nodes = [blob]
    assert stack.order_safe(nodes, [(element, [])])  # the element first: the same order
    assert not stack.order_safe(nodes, [(slice_, [])])  # the halt would come first
    two_halts = ir.Blob((ir.MemSlice(B, C), slice_))
    assert stack.order_safe([two_halts], [(slice_, [])])  # two halts: which one comes first cannot be seen
    # a shift is written `value << amount` and solc evaluates the amount first; wrapping
    # arithmetic goes through helpers (left to right) outside `unchecked`: under such an
    # operator two operands that fail differently keep their places (no failing operand moves)
    amount = ir.Typed("add", (A, B), "uint256", checked=True)  # Panic 0x11
    shifted = ir.Op("shl", (amount, element))
    assert not stack.order_safe([shifted], [(element, [])])
    assert not stack.order_safe([shifted], [(amount, [])])
    summed = ir.Op("add", (element, ir.Typed("mul", (A, B), "uint256", checked=True)))
    assert not stack.order_safe([summed], [(element, [])])
    calm = ir.Op("xor", (A, ir.Const(7)))  # an operand that cannot fail still moves
    assert stack.order_safe([ir.Op("shl", (amount, ir.Op("add", (element, calm))))], [(calm, [])])

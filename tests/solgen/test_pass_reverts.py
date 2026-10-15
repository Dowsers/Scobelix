"""
The reverts pass turns `if (c) revert(payload)` + rest into `require` /
`assert` statements and names custom errors; the EVM semantics must not
change: the same inputs revert with the same data.

Tests: the rewrite on hand-written IR (shapes, nesting, what stays), the
rendering, naming with a stubbed signature database (clashes, arguments
that cannot be proven valid, the Error / Panic selectors), and differential
execution on probe contracts compiled by real compilers (require with
messages of every length, revert(), assert, custom errors with static,
string and dynamic arguments, compiler Panic guards that must stay).
"""

import re
import types

import pytest

from eth_utils import keccak

from probes import (CALLER, Build, all_cases, compile_probe, differential, function_text, generate_probe,
                    named_functions, patch_signatures, run_calls, selector)
from conftest import compile_or_fail
from scobelix.solgen import ir, pipeline, sigs
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.contract import ContractInput, Unit, assemble
from scobelix.solgen.types import parse_type


def cd(i):
    return ir.CalldataWord(ir.Const(4 + 32 * i))


def ret(*words):
    return ir.Return(ir.Blob(tuple(ir.WordBytes(w) for w in words)))


def word(v):
    return (v % 2**256).to_bytes(32, "big")


def error_sig(name, types, names=None, kind="error", declared=True):
    inputs = tuple((t, (names or [""] * len(types))[i]) for i, t in enumerate(types))
    return sigs.Signature(kind=kind, name=name, inputs=inputs, signature=f"{name}({','.join(types)})", trusted=True,
                          source="curated", declared=declared)


def stub_sigs(errors):
    """A signature module answering custom-error lookups from `errors`
    ({selector: [Signature]})."""
    mod = types.ModuleType("stub_sigs")
    mod.error_candidates = lambda sel, types=None: tuple(errors.get(sel, ()))
    mod.function_candidates = lambda sel: ()
    mod.function_selector = sigs.function_selector
    return mod


def build(entries, errors=None, level="full", off=(), abi_v2=True, facts=None):
    specs = {k: s for k, (_, s) in entries.items()}
    functions = {k: f for k, (f, _) in entries.items()}
    ctx = pipeline.PassContext(specs=specs, metadata=None, dispatcher=None, target_solc="0.8.19", abi_v2=abi_v2,
                               idiom_level=level, functions=dict(functions), disabled_passes={"*": set(off)},
                               sigs=stub_sigs(errors or {}), facts=dict(facts or {}))
    passes = pipeline.available_passes(level)
    pipeline.prepare(passes, ctx)
    units = []
    for key, fn in functions.items():
        fn2, applied = pipeline.run_passes(fn, passes, ctx)
        units.append(Unit(key, fn2, specs[key], passes=applied, flags=set(fn2.flags)))
    pipeline.finish(passes, ctx)
    src, _ = assemble(ContractInput(units=units, target="0.8.19", original="test", abi_v2=abi_v2, idiom_level=level,
                                    declarations=ctx.declarations))
    return src, ctx, {u.key: u for u in units}


def entry(sel, body, signature=None, params=(), mutability="pure", returns=None):
    key = f"0x{sel:08x}"
    spec = EntrySpec(key=key, kind="function", selector=sel, signature=signature,
                     name=signature.split("(")[0] if signature else None,
                     params=tuple((parse_type(t), f"p{i}") for i, t in enumerate(params)), mutability=mutability,
                     returns=None if returns is None else tuple(parse_type(t) for t in returns))
    return key, (ir.Function(key, tuple(body)), spec)


SEL_EMPTY = sigs.function_selector("Empty()")
SEL_INSUF = sigs.function_selector("Insufficient(uint256,uint256)")
SEL_BAD = sigs.function_selector("Bad(address,string)")
ERRORS = {
    SEL_EMPTY: [error_sig("Empty", [])],
    SEL_INSUF: [error_sig("Insufficient", ["uint256", "uint256"], ["available", "required"])],
    SEL_BAD: [error_sig("Bad", ["address", "string"], ["who", "why"])],
}


def custom(sel, *parts):
    return ir.Custom(sel, tuple(parts))


def string_tail(data: bytes, offset: int = 64):
    """The ABI tail of one string argument at `offset`."""
    padded = data.ljust((len(data) + 31) // 32 * 32, b"\0")
    parts = [ir.WordBytes(ir.Const(offset)), ir.WordBytes(ir.Const(len(data)))]
    parts.extend(ir.WordBytes(ir.Const(int.from_bytes(padded[i:i + 32], "big"))) for i in range(0, len(padded), 32))
    return parts


# ---------------------------------------------------------------- the rewrite on IR


def test_if_revert_becomes_require_in_both_branch_orders():
    c = ir.Op("gt", (cd(0), ir.Const(10)))
    key, e = entry(0x1, [ir.If(c, (ir.Revert(),), (ret(cd(0)),))])
    key2, e2 = entry(0x2, [ir.If(c, (ret(cd(0)),), (ir.Revert(ir.ErrorString(b"big")),))])
    src, ctx, units = build({key: e, key2: e2})
    b1, b2 = units[key].fn.body, units[key2].fn.body
    assert b1 == (ir.Require(ir.Op("iszero", (c,)), ir.Empty()), ret(cd(0)))
    assert b2 == (ir.Require(c, ir.ErrorString(b"big")), ret(cd(0)))
    assert "require(_calldataload(4) <= 10);" in function_text(src, "_fn_00000001")
    assert 'require(_calldataload(4) > 10, "big");' in function_text(src, "_fn_00000002")


def test_assert_and_untouched_payloads():
    c = ir.Op("eq", (cd(0), ir.Const(4)))
    overflow = ir.Op("gt", (cd(0), ir.Op("add", (cd(0), cd(1)))))
    body = [ir.If(c, (ir.Revert(ir.Panic(1)),), (
        ir.If(overflow, (ir.Revert(ir.Panic(0x11)),), (
            ir.If(ir.Op("iszero", (cd(1),)), (ir.Revert(ir.Panic(0x12)),), (
                ir.If(ir.Op("lt", (cd(0), cd(1))), (ir.Revert(ir.Raw(ir.WordBytes(cd(0), 4))),), (
                    ir.If(ir.Op("gt", (cd(0), cd(1))), (ir.Revert(ir.Bubble(1)),), (ret(ir.Op("add", (cd(0), cd(1)))),)),
                )),)),)),))]
    key, e = entry(0x3, body)
    src, ctx, units = build({key: e}, off=("arith", "compound"))  # the arith pass owns the Panic guards
    b = units[key].fn.body
    assert b[0] == ir.Assert(ir.Op("iszero", (c,)))
    assert isinstance(b[1], ir.If) and b[1].then[0].payload == ir.Panic(0x11)
    inner = b[1].orelse[0]
    assert isinstance(inner, ir.If) and inner.then[0].payload == ir.Panic(0x12)
    raw = inner.orelse[0]
    assert isinstance(raw, ir.If) and isinstance(raw.then[0].payload, ir.Raw)
    bubble = raw.orelse[0]
    assert isinstance(bubble, ir.If) and isinstance(bubble.then[0].payload, ir.Bubble)
    text = function_text(src, "_fn_00000003")
    assert "assert(_calldataload(4) != 4);" in text and "_panic(17)" in text and "_bubble()" in text


def test_structurer_require_with_panic_one_becomes_assert():
    key, e = entry(0x4, [ir.Require(cd(0), ir.Panic(1)), ir.Require(cd(1), ir.ErrorString(b"m")), ret(cd(0))])
    src, ctx, units = build({key: e})
    assert units[key].fn.body[0] == ir.Assert(cd(0))
    assert units[key].fn.body[1] == ir.Require(cd(1), ir.ErrorString(b"m"))


def test_nested_blocks_and_loops():
    c = ir.Op("gt", (cd(0), ir.Const(5)))
    inner = ir.If(ir.Op("lt", (cd(1), ir.Const(3))), (ret(cd(0)),), (ir.Revert(ir.ErrorString(b"y")),))
    loop = ir.While(ir.Op("lt", (ir.Local("i"), cd(0))), (
        ir.If(ir.Op("eq", (ir.Local("i"), ir.Const(7))), (ir.Revert(ir.ErrorString(b"seven")),), (
            ir.Continue("L", (ir.Assign(ir.Local("i"), ir.Op("add", (ir.Local("i"), ir.ONE))),)),)),),
        (ir.Assign(ir.Local("i"), ir.ZERO),), "L")
    body = [ir.If(c, (inner,), (loop, ret(ir.Local("i"))))]
    key, e = entry(0x5, body)
    src, ctx, units = build({key: e}, off=("loops",))  # (the loops pass would write the loop as a `for`)
    b = units[key].fn.body
    assert isinstance(b[0], ir.If) and isinstance(b[0].then[0], ir.Require)
    w = b[0].orelse[0]
    assert isinstance(w, ir.While) and isinstance(w.body[0], ir.Require) and isinstance(w.body[1], ir.Continue)
    text = function_text(src, "_fn_00000005")
    assert 'require(_calldataload(36) < 3, "y");' in text and 'require(i != 7, "seven");' in text


# ---------------------------------------------------------------- custom errors


def test_custom_errors_are_named_and_declared_once():
    c = ir.Op("gt", (cd(0), ir.Const(100)))
    body = [ir.If(ir.Op("eq", (cd(0), ir.Const(9))), (ir.Revert(custom(SEL_EMPTY)),), (
        ir.If(c, (ir.Revert(custom(SEL_INSUF, ir.WordBytes(cd(0)), ir.WordBytes(ir.Const(100)))),), (ret(cd(0)),)),))]
    key, e = entry(0x6, body)
    body2 = [ir.If(c, (ir.Revert(custom(SEL_INSUF, ir.WordBytes(cd(0)), ir.WordBytes(ir.Const(100)))),), (ret(cd(1)),))]
    key2, e2 = entry(0x7, body2)
    src, ctx, units = build({key: e, key2: e2}, ERRORS)
    text = function_text(src, "_fn_00000006")
    assert "revert Empty();" in text and "revert Insufficient(_calldataload(4), 100);" in text
    assert src.count("error Insufficient(uint256 available, uint256 required);") == 1
    assert src.count("error Empty();") == 1
    first = units[key].fn.body[0]
    assert isinstance(first, ir.If) and first.then[0].payload == ir.NamedError("Empty")
    p = first.orelse[0].then[0].payload
    assert isinstance(p, ir.NamedError) and p.types == ("uint256", "uint256") and p.args == (cd(0), ir.Const(100))
    assert ctx.declarations["error"] == ["error Empty();", "error Insufficient(uint256 available, uint256 required);"]


def test_arguments_must_be_valid_values_of_the_declared_types():
    addr = ir.Mask(160, 0, 0, cd(0))
    valid = custom(SEL_BAD, ir.WordBytes(addr), *string_tail(b"zero"))
    dirty = custom(SEL_BAD, ir.WordBytes(cd(0)), *string_tail(b"zero"))
    bad_pad = custom(SEL_BAD, ir.WordBytes(addr), ir.WordBytes(ir.Const(64)), ir.WordBytes(ir.Const(4)),
                     ir.WordBytes(ir.Const((int.from_bytes(b"zero".ljust(32, b"\0"), "big")) | 1)))
    bad_offset = custom(SEL_BAD, ir.WordBytes(addr), *string_tail(b"zero", offset=96))
    non_const = custom(SEL_BAD, ir.WordBytes(addr), ir.WordBytes(ir.Const(64)), ir.WordBytes(ir.Const(4)),
                       ir.WordBytes(cd(1)))
    keys = {}
    entries = {}
    for i, p in enumerate((valid, dirty, bad_pad, bad_offset, non_const), start=0x10):
        k, e = entry(i, [ir.If(ir.Op("iszero", (cd(0),)), (ir.Revert(p),), (ret(cd(0)),))])
        keys[i] = k
        entries[k] = e
    src, ctx, units = build(entries, ERRORS)
    assert 'revert Bad(address(uint160(_calldataload(4))), "zero");' in function_text(src, "_fn_00000010")
    for i in (0x11, 0x12, 0x13, 0x14):
        text = function_text(src, f"_fn_{i:08x}")
        assert "revert Bad(" not in text and "_revert(" in text, text
    # a validated parameter is a valid value of its type
    k, e = entry(0x20, [ir.If(ir.Op("iszero", (cd(0),)), (ir.Revert(dirty),), (ret(cd(0)),))], "f(address)", ["address"])
    src2, _, _ = build({k: e}, ERRORS)
    assert 'revert Bad(p0, "zero");' in function_text(src2, "f")
    # so is a local whose every assigned value is one (a cached address)
    who = ir.Local("_who")
    cached = custom(SEL_BAD, ir.WordBytes(who), *string_tail(b"zero"))
    for value, named in ((addr, True), (cd(0), False)):
        k, e = entry(0x21, [ir.Assign(who, value),
                            ir.If(ir.Op("iszero", (cd(0),)), (ir.Revert(cached),), (ret(cd(0)),))])
        src3, _, units3 = build({k: e}, ERRORS)
        assert ("revert Bad(" in function_text(src3, "_fn_00000021")) is named, src3


def test_a_local_a_call_also_binds_is_not_judged_by_its_assignments():
    # a precompile's output word or a send's success flag bound to the local too: its plain
    # assignments are not every value it holds
    from scobelix.solgen.passes.reverts import _valid_word, local_values, with_locals

    who, addr, t = ir.Local("_who"), ir.Mask(160, 0, 0, cd(0)), parse_type("address")
    assert _valid_word(who, t, with_locals({}, (ir.Assign(who, addr),)))
    for binder in (ir.Precompile(1, 2, "sha256hash", ir.ConstBytes(b"x"), output="_who"),
                   ir.Transfer(1, addr, ir.Const(0), send=True, ok="_who")):
        body = (ir.Assign(who, addr), binder)
        assert local_values(body)["_who"] is None, binder
        assert not _valid_word(who, t, with_locals({}, body)), binder


def test_names_that_clash_or_are_reserved_are_not_used():
    p = custom(SEL_EMPTY)
    k, e = entry(0x30, [ir.If(ir.Op("iszero", (cd(0),)), (ir.Revert(p),), (ret(cd(0)),))], "Empty(uint256)", ["uint256"])
    src, ctx, units = build({k: e}, ERRORS)
    assert "revert Empty();" not in src and "error Empty();" not in src
    k2, e2 = entry(0x31, [ir.If(ir.Op("iszero", (cd(0),)), (ir.Revert(p),), (ret(cd(0)),))])
    src2, _, _ = build({k2: e2}, {SEL_EMPTY: [error_sig("revert", [])]})
    assert "error revert" not in src2
    src3, _, _ = build({k2: e2}, {SEL_EMPTY: [error_sig("Empty", ["uint256[]"])]})
    assert "error Empty" not in src3  # array parameters are not decoded
    # the Error(string) / Panic(uint256) selectors belong to the lifter's decoding
    err = custom(0x08c379a0, ir.WordBytes(ir.Const(32)), ir.WordBytes(ir.ZERO), ir.WordBytes(ir.ZERO))
    k4, e4 = entry(0x32, [ir.If(ir.Op("iszero", (cd(0),)), (ir.Revert(err),), (ret(cd(0)),))])
    src4, _, _ = build({k4: e4}, {0x08c379a0: [error_sig("Error", ["string"])], 0x4e487b71: [error_sig("Panic", ["uint256"])]})
    assert "error Error" not in src4 and "revert Error(" not in src4


def test_declared_names_are_shared_with_other_passes():
    p = custom(SEL_EMPTY)
    k, e = entry(0x40, [ir.If(ir.Op("iszero", (cd(0),)), (ir.Revert(p),), (ret(cd(0)),))])
    src, ctx, _ = build({k: e}, ERRORS, facts={"declared_names": {"Empty"}})
    assert "error Empty" not in src
    src2, ctx2, _ = build({k: e}, ERRORS)
    assert "Empty" in ctx2.facts["declared_names"]


def _named_in(payload, candidates, sel=0x5EED0010, signature=None, params=()):
    """The source of one function reverting with `payload`, the database
    answering `candidates` for its selector."""
    k, e = entry(0x60, [ir.If(ir.Op("iszero", (cd(0),)), (ir.Revert(payload),), (ret(cd(0)),))], signature, params)
    src, _, _ = build({k: e}, {sel: list(candidates)})
    return src


def test_several_signatures_are_told_apart_by_the_argument_types():
    sel = 0x5EED0010
    by_account = error_sig("ByAccount", ["address", "uint256"], ["account", "amount"])
    by_tag = error_sig("ByTag", ["bytes1"], ["tag"])
    two = custom(sel, ir.WordBytes(ir.Mask(160, 0, 0, cd(0))), ir.WordBytes(cd(1)))
    one = custom(sel, ir.WordBytes(ir.Mask(8, 248, 0, cd(0))))
    for cands in ([by_tag, by_account], [by_account, by_tag]):  # the database's order decides nothing
        src = _named_in(two, cands)
        assert "revert ByAccount(" in src and "error ByAccount(address account, uint256 amount);" in src
        assert "ByTag" not in src
        src = _named_in(one, cands)
        assert "revert ByTag(" in src and "error ByTag(bytes1 tag);" in src and "ByAccount" not in src
        # three words: neither signature encodes them
        src = _named_in(custom(sel, ir.WordBytes(cd(0)), ir.WordBytes(cd(1)), ir.WordBytes(cd(2))), cands)
        assert "error " not in src and "_revert(" in src


def test_signatures_the_types_cannot_tell_apart_are_not_used():
    sel = 0x5EED0010
    as_uint = error_sig("AsUint", ["uint256"])
    as_word = error_sig("AsWord", ["bytes32"])
    small = error_sig("Small", ["uint8"])
    for cands in ([as_uint, as_word], [as_word, as_uint]):
        src = _named_in(custom(sel, ir.WordBytes(cd(0))), cands)
        assert "error " not in src and "_revert(" in src  # a word is a uint256 and a bytes32
    # an unvalidated word is no uint8: one signature is left; a small constant is both
    for cands in ([small, as_uint], [as_uint, small]):
        assert "revert AsUint(_calldataload(4));" in _named_in(custom(sel, ir.WordBytes(cd(0))), cands)
        src = _named_in(custom(sel, ir.WordBytes(ir.Const(5))), cands)
        assert "error " not in src and "_revert(" in src
        # the validated uint8 parameter of the function is a uint8 and a uint256
        src = _named_in(custom(sel, ir.WordBytes(cd(0))), cands, signature="f(uint8)", params=["uint8"])
        assert "error " not in src and "_revert(" in src
    # the same signature listed twice is one signature
    assert "revert AsUint(_calldataload(4));" in _named_in(custom(sel, ir.WordBytes(cd(0))), [as_uint, as_uint])


def test_declared_errors_come_before_signatures_of_other_namespaces():
    sel = 0x5EED0010
    declared = error_sig("Declared", ["uint8"], ["code"])
    other = error_sig("other", ["uint256"], ["value"], declared=False)
    word = custom(sel, ir.WordBytes(cd(0)))
    for cands in ([declared, other], [other, declared]):
        # the selector has a declared error: a payload it does not decode gets no other name
        src = _named_in(word, cands)
        assert "error " not in src and "_revert(" in src
        src = _named_in(custom(sel, ir.WordBytes(ir.Const(5))), cands)
        assert re.search(r"revert Declared\((uint8\(uint256\(5\)\)|uint8\(5\)|5)\);", src) \
            and "error Declared(uint8 code);" in src
    # without a declared error, the one signature with the selector names it
    src = _named_in(word, [other])
    assert "revert other(_calldataload(4));" in src and "error other(uint256 value);" in src
    # an event or a function entry is never an error candidate
    assert "error " not in _named_in(word, [error_sig("Evt", ["uint256"], kind="event")])


def test_the_first_decoded_payload_fixes_the_error_of_a_selector():
    sel = 0x5EED0010
    small = error_sig("Small", ["uint8"])
    as_uint = error_sig("AsUint", ["uint256"])
    k1, e1 = entry(0x61, [ir.If(ir.Op("iszero", (cd(0),)), (ir.Revert(custom(sel, ir.WordBytes(ir.Const(5)))),),
                          (ret(cd(0)),))])
    k2, e2 = entry(0x62, [ir.If(ir.Op("iszero", (cd(0),)), (ir.Revert(custom(sel, ir.WordBytes(cd(0)))),),
                          (ret(cd(0)),))])
    k3, e3 = entry(0x63, [ir.If(ir.Op("iszero", (cd(0),)), (ir.Revert(custom(sel, ir.WordBytes(ir.Const(7)))),),
                          (ret(cd(0)),))])
    src, ctx, _ = build({k1: e1, k2: e2, k3: e3}, {sel: [small, as_uint]})
    # 0x61: 5 is a uint8 and a uint256 (kept raw); 0x62 decides; 0x63 then uses the contract's error
    assert "_revert(" in function_text(src, "_fn_00000061") and "revert " not in function_text(src, "_fn_00000061")
    assert "revert AsUint(_calldataload(4));" in function_text(src, "_fn_00000062")
    assert "revert AsUint(7);" in function_text(src, "_fn_00000063")
    assert ctx.declarations["error"] == ["error AsUint(uint256);"]
    compile_or_fail(src, "0.8.19")


# ---------------------------------------------------------------- exactness on IR (exact vs full)


def _run_both(entries, calls, errors=None):
    exact_src, _, _ = build(entries, errors, level="exact")
    full_src, _, _ = build(entries, errors, level="full")
    a = compile_or_fail(exact_src, "0.8.19").runtime
    b = compile_or_fail(full_src, "0.8.19").runtime
    ra = run_calls(a, calls)
    rb = run_calls(b, calls)
    for (data, _), x, y in zip(calls, ra, rb):
        assert x == y, (data.hex(), x, y, full_src)
    return full_src


def test_requires_and_named_errors_are_exact():
    c = ir.Op("gt", (cd(0), ir.Const(100)))
    body = [ir.If(ir.Op("eq", (cd(0), ir.Const(9))), (ir.Revert(custom(SEL_EMPTY)),), (
        ir.If(ir.Op("eq", (cd(0), ir.Const(4))), (ir.Revert(ir.Panic(1)),), (
            ir.If(ir.Op("eq", (cd(0), ir.Const(5))), (ir.Revert(ir.ErrorString(b"")),), (
                ir.If(ir.Op("eq", (cd(0), ir.Const(6))), (ir.Revert(ir.ErrorString(b"x" * 85)),), (
                    ir.If(ir.Op("eq", (cd(0), ir.Const(7))), (ir.Revert(),), (
                        ir.If(ir.Op("iszero", (cd(1),)), (ir.Revert(custom(SEL_BAD, ir.WordBytes(ir.Mask(160, 0, 0, cd(1))),
                                                                              *string_tail("caf\xc3\xa9".encode("latin-1")))),), (
                            ir.If(c, (ir.Revert(custom(SEL_INSUF, ir.WordBytes(cd(0)), ir.WordBytes(ir.Const(100)))),), (
                                ret(cd(0)),)),)),)),)),)),)),))]
    key, e = entry(0x50, body)
    calls = [(bytes.fromhex("00000050") + word(x) + word(y), 0) for x in (0, 4, 5, 6, 7, 9, 50, 101, 2**256 - 1)
             for y in (0, 1, 2**200)]
    src = _run_both({key: e}, calls, ERRORS)
    text = function_text(src, "_fn_00000050")
    assert "revert Empty();" in text and "assert(" in text and 'require(_calldataload(4) != 5, "");' in text
    assert "revert Insufficient(" in text and "revert Bad(" in text


# ---------------------------------------------------------------- real compilers

R_SOURCE = """
contract R {
    uint256 v;
%(ERRORS)s
    function rReq(uint256 x) external pure { require(x != 1, "x is one"); require(x != 2); }
    function rLong(uint256 x) external pure {
        require(x != 3, "this revert message is definitely longer than thirty-two bytes, spanning three words!");
    }
    function rEmptyMsg(uint256 x) external pure { require(x != 5, ""); }
    function rAssert(uint256 x) external pure { assert(x != 6); }
    function rRevert(uint256 x) external pure { if (x == 7) revert(); if (x == 8) revert("eight"); }
    function rPanic(uint256 a, uint256 b) external pure returns (uint256) { return a + b; }
    function rDiv(uint256 a, uint256 b) external pure returns (uint256) { return a / b; }
    function rNested(uint256 x, uint256 y) external pure returns (uint256) {
        if (x > 5) { require(y < 3, "y"); return x; }
        require(x != y);
        return y;
    }
    function rLoop(uint256 n) external pure returns (uint256 s) {
        for (uint256 i = 0; i < n; i++) { require(i != 7, "seven"); s ^= i; }
    }
    function rStore(uint256 x) external { require(x != 0, "zero"); v = x; }
%(EXTRA)s
}
"""

R_ERRORS = """
    error Empty();
    error Insufficient(uint256 available, uint256 required);
    error Bad(address who, string why);
    error Dyn(bytes data);
    error Typed(uint8 a, bool b, address c, bytes4 d, int16 e);
"""

R_CUSTOM = """
    function rCustom(uint256 x) external pure { if (x == 9) revert Empty(); if (x > 100) revert Insufficient(x, 100); }
    function rCustomStr(address a) external pure { if (a == address(0)) revert Bad(a, "zero"); }
    function rCustomDyn(bytes calldata d) external pure { if (d.length > 2) revert Dyn(d); }
    function rUni(uint256 x) external pure { require(x != 4, unicode"caf\\u00e9 \\u2615"); }
    function rTyped(uint8 a, bool b, address c, bytes4 d, int16 e) external pure { if (a == 1) revert Typed(a, b, c, d, e); }
"""

R_SIGS = ["rReq(uint256)", "rLong(uint256)", "rEmptyMsg(uint256)", "rAssert(uint256)", "rRevert(uint256)",
          "rPanic(uint256,uint256)", "rDiv(uint256,uint256)", "rNested(uint256,uint256)", "rLoop(uint256)",
          "rStore(uint256)"]
R_CUSTOM_SIGS = ["rCustom(uint256)", "rCustomStr(address)", "rCustomDyn(bytes)", "rUni(uint256)",
                 "rTyped(uint8,bool,address,bytes4,int16)"]


def r_source(build):
    custom_ok = build.major >= (0, 8)
    return R_SOURCE % {"ERRORS": R_ERRORS if custom_ok else "", "EXTRA": R_CUSTOM if custom_ok else ""}


BUILDS = [
    Build("0.4.26"),
    Build("0.5.17"),
    Build("0.7.6", optimize=False),
    Build("0.8.19"),
    Build("0.8.19", optimize=False),
    Build("0.8.19", via_ir=True),
    Build("0.8.31", via_ir=True),
]


def _calls(signatures):
    calls = all_cases(signatures, short=False)
    # the values the probe tests for
    for s in signatures:
        n = s.count(",") + (0 if s.endswith("()") else 1)
        for x in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 50, 101, 2**256 - 1):
            calls.append((selector(s) + word(x) + word(2) * (n - 1), 0))
    return calls


@pytest.mark.parametrize("build", BUILDS, ids=lambda b: b.label)
def test_reverts_probe(build, monkeypatch):
    art = compile_probe(r_source(build), build, "R")
    patch_signatures(monkeypatch, art.abi)
    r = generate_probe(art.runtime)
    signatures = R_SIGS + (R_CUSTOM_SIGS if build.major >= (0, 8) else [])
    named = named_functions(r)
    assert set(f["signature"] for f in named.values()) == set(signatures)
    calls = _calls(signatures)
    assert not differential(art.runtime, r.solidity, r.target_solc, calls, storage={0: 5})
    src = r.solidity
    # (the compilers order the operands of a comparison both ways, and via-IR rewrites y < 3 as y <= 2)
    assert re.search(r'require\((x != 1|1 != x), "x is one"\);', function_text(src, "rReq"))
    assert re.search(r"require\((x != 2|2 != x)\);", function_text(src, "rReq"))
    # (0.5 / 0.7 copy a long message from the code through memory: the lifter keeps the exact bytes)
    assert "spanning three words!" in function_text(src, "rLong") \
        or b"spanning three words!".hex() in function_text(src, "rLong")
    assert "require(x != 5" in function_text(src, "rEmptyMsg") or "_revert(" in function_text(src, "rEmptyMsg")
    assert re.search(r'require\((y < 3|3 > y|y <= 2|2 >= y), "y"\);', function_text(src, "rNested"))
    assert re.search(r'require\((\w+ != 7|7 != \w+), "seven"\);', function_text(src, "rLoop"))  # (the counter's name: naming pass)
    if build.major >= (0, 8):
        # the compiler's Panic guards are the arith pass's: checked `+` and `/` again
        assert "_panic" not in function_text(src, "rPanic") and "_panic" not in function_text(src, "rDiv")
        assert "assert(x != 6);" in function_text(src, "rAssert")
        assert "revert Empty();" in function_text(src, "rCustom") and "revert Insufficient(x, 100);" in function_text(src, "rCustom")
        assert 'revert Bad(a, "zero");' in function_text(src, "rCustomStr")
        assert "error Insufficient(uint256 available, uint256 required);" in src
        assert "revert Dyn(" not in src  # a calldata argument: the exact bytes stay
        # validated parameters passed as they are read as the parameters
        assert "revert Typed(a, b, c, d, e);" in function_text(src, "rTyped")
    else:
        assert "_invalid()" in function_text(src, "rAssert")  # pre-0.8 assert halts with INVALID: kept exact


# ---------------------------------------------------------------- the signature database, end to end

LIB_SOURCE = """
contract Guarded {
    error OwnableUnauthorizedAccount(address account);
    error OwnableInvalidOwner(address owner);
    error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);
    error ERC20InvalidReceiver(address receiver);
    error EnforcedPause();
    error ReentrancyGuardReentrantCall();
    error SafeCastOverflowedUintDowncast(uint8 bits, uint256 value);
    error StringTooLong(string str);
    error ProbeOnlyError_q7(uint256 code);

    address owner;
    bool paused;
    uint256 status;
    mapping(address => uint256) balances;

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert OwnableUnauthorizedAccount(msg.sender);
        if (newOwner == address(0)) revert OwnableInvalidOwner(address(0));
        owner = newOwner;
    }
    function transfer(address to, uint256 value) external returns (bool) {
        if (paused) revert EnforcedPause();
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        uint256 b = balances[msg.sender];
        if (b < value) revert ERC20InsufficientBalance(msg.sender, b, value);
        unchecked { balances[msg.sender] = b - value; balances[to] += value; }
        return true;
    }
    function toUint64(uint256 v) external pure returns (uint64) {
        if (v > type(uint64).max) revert SafeCastOverflowedUintDowncast(64, v);
        return uint64(v);
    }
    function enter(uint256 x) external {
        if (status == 2) revert ReentrancyGuardReentrantCall();
        status = 2;
        if (x == 7) revert StringTooLong("this short string is far too long for a ShortString");
        if (x == 8) revert ProbeOnlyError_q7(x);
        status = 1;
    }
}
"""

LIB_SIGS = ["transferOwnership(address)", "transfer(address,uint256)", "toUint64(uint256)", "enter(uint256)"]
LIB_BUILDS = [Build("0.8.19"), Build("0.8.19", optimize=False), Build("0.8.31", via_ir=True)]
LIB_NAMED = {
    "OwnableUnauthorizedAccount": "error OwnableUnauthorizedAccount(address account);",
    "OwnableInvalidOwner": "error OwnableInvalidOwner(address owner);",
    "ERC20InsufficientBalance": "error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);",
    "ERC20InvalidReceiver": "error ERC20InvalidReceiver(address receiver);",
    "EnforcedPause": "error EnforcedPause();",
    "ReentrancyGuardReentrantCall": "error ReentrancyGuardReentrantCall();",
    "SafeCastOverflowedUintDowncast": "error SafeCastOverflowedUintDowncast(uint8 bits, uint256 value);",
    "StringTooLong": "error StringTooLong(string str);",
}


@pytest.mark.parametrize("build", LIB_BUILDS, ids=lambda b: b.label)
def test_library_style_errors_are_named_from_the_database(build, bundled_sigdb):
    """No stub: the names come from the signature database (the small
    tables shipped with the package)."""
    art = compile_probe(LIB_SOURCE, build, "Guarded")
    r = generate_probe(art.runtime)
    src = r.solidity
    for name, declaration in LIB_NAMED.items():
        assert src.count(declaration) == 1, (name, src)
        assert f"revert {name}(" in src, (name, src)
    assert "revert OwnableUnauthorizedAccount(msg.sender);" in src
    assert re.search(r"revert ERC20InsufficientBalance\(msg\.sender, \w+\[msg\.sender\], \w+\);", src)
    assert re.search(r"revert SafeCastOverflowedUintDowncast\((uint8\(uint256\(64\)\)|uint8\(64\)|64), ", src)
    assert 'revert StringTooLong("this short string is far too long for a ShortString");' in src
    # an error no table knows keeps its exact bytes
    assert "ProbeOnlyError_q7" not in src and "_revert(abi.encodePacked(bytes4(" in src
    assert src.count("\n    error ") == len(LIB_NAMED)
    # the same reverts, byte for byte, in every state
    caller = int(CALLER, 16)
    calls = all_cases(LIB_SIGS, short=False)
    for x in (0, 1, 7, 8, 2**64 - 1, 2**64, 2**256 - 1):
        calls.append((selector("enter(uint256)") + word(x), 0))
        calls.append((selector("toUint64(uint256)") + word(x), 0))
        calls.append((selector("transfer(address,uint256)") + word(0xB0B) + word(x), 0))
    balance_slot = int.from_bytes(keccak(word(caller) + word(2)), "big")
    states = [{}, {0: caller}, {0: caller | 1 << 160}, {0: caller, 1: 2}, {0: 5, 1: 1, balance_slot: 2**64}]
    reverted = set()
    for storage in states:
        assert not differential(art.runtime, src, r.target_solc, calls, storage=storage), storage
        reverted |= {out[:4] for ok, out, _ in run_calls(art.runtime, calls, storage) if not ok and len(out) >= 4}
    # the calls reach every error of the source
    assert {selector(f"{name}({','.join(t for t in types)})") for name, types in (
        ("OwnableUnauthorizedAccount", ["address"]), ("OwnableInvalidOwner", ["address"]),
        ("ERC20InsufficientBalance", ["address", "uint256", "uint256"]), ("ERC20InvalidReceiver", ["address"]),
        ("EnforcedPause", []), ("ReentrancyGuardReentrantCall", []),
        ("SafeCastOverflowedUintDowncast", ["uint8", "uint256"]), ("StringTooLong", ["string"]),
        ("ProbeOnlyError_q7", ["uint256"]))} <= reverted

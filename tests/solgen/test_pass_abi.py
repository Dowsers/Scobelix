"""
The abi pass removes the ABI decoder prologue of known-name functions and
types their parameters and return values.  Every removal must be exact: the
target compiler's decoder makes the same check before the body runs.

Three kinds of tests:
  * the classification of the decoder checks on synthetic IR (which forms
    are recognised, which are removable for which declared type);
  * rendering on hand-written IR (typed parameters, enum, return types);
  * differential execution on probe contracts compiled by real compilers
    (ABI coder v1 and v2, legacy and via-IR, optimised or not) on crafted
    calldata: dirty high bits, values out of range, short calldata, bad
    offsets and lengths of dynamic parameters.
"""

import pytest

from probes import (Build, calldata_cases, compile_probe, differential, function_text, generate_probe,
                    named_functions, patch_signatures, probe_calls)
from scobelix.solgen import ir, pipeline
from scobelix.solgen import abi as abi_mod
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.contract import ContractInput, Unit, assemble
from scobelix.solgen.passes import abi as abi_pass
from scobelix.solgen.types import parse_type

CDS = ir.Env("calldatasize")
B64 = ir.Const((1 << 64) - 1)
B32 = ir.Const(1 << 32)


def cd(i):
    return ir.CalldataWord(ir.Const(4 + 32 * i))


def head(n, signed=True):
    return ir.Op("slt" if signed else "lt", (ir.Op("add", (ir.const(-4), CDS)), ir.Const(32 * n)))


def legacy(i, cleanup):
    """iszero(eq(P, cleanup(P)))"""
    return ir.Op("iszero", (ir.Op("eq", (cd(i), cleanup(cd(i)))),))


def via_ir_dirty(i, size, off):
    return ir.Mask(size, off, 0, cd(i))


def enum_check(i, k):
    return ir.Op("iszero", (ir.Op("lt", (cd(i), ir.Const(k))),))


def length_word(i):
    return ir.CalldataWord(ir.Op("add", (ir.Const(4), cd(i))))


def spec_for(signature, params):
    return EntrySpec(key="0x00000001", kind="function", selector=1, name=signature.split("(")[0], signature=signature,
                     params=tuple((parse_type(t), f"p{i}") for i, t in enumerate(params)))


def classify(cond, payload=ir.Empty()):
    return abi_pass._classify(cond, payload)


def removable(cond, params, abi_v2=True, payload=ir.Empty(), enums=None):
    c = classify(cond, payload)
    if c is None:
        return None
    spec = spec_for("f(" + ",".join(params) + ")", params)
    return abi_pass._removable(c, abi_pass._layout(spec.params), abi_v2, enums if enums is not None else {})


# ---------------------------------------------------------------- classification


def test_head_size_check_is_removed_only_for_the_declared_head():
    assert classify(head(2)) == ("head", 64)
    assert classify(head(2, signed=False)) == ("head", 64)
    assert removable(head(2), ["address", "uint256"]) is True
    assert removable(head(1), ["address", "uint256"]) is False  # a user check of the size: kept
    assert removable(head(0), []) is True
    assert removable(head(2), ["uint256", "bytes"]) is True  # a dynamic parameter is one head word
    assert removable(head(3), ["uint256", "bytes"]) is False


@pytest.mark.parametrize("ty, cleanup", [
    ("address", lambda p: ir.Mask(160, 0, 0, p)),
    ("uint8", lambda p: ir.Mask(8, 0, 0, p)),
    ("uint40", lambda p: ir.Mask(40, 0, 0, p)),
    ("uint128", lambda p: ir.Mask(128, 0, 0, p)),
    ("bool", lambda p: ir.Op("iszero", (ir.Op("iszero", (p,)),))),
    ("int8", lambda p: ir.Op("signextend", (ir.Const(0), p))),
    ("int128", lambda p: ir.Op("signextend", (ir.Const(15), p))),
    ("bytes4", lambda p: ir.Mask(32, 224, 0, p)),
    ("bytes31", lambda p: ir.Mask(248, 8, 0, p)),
])
def test_legacy_validators_match_their_type_only(ty, cleanup):
    cond = legacy(0, cleanup)
    assert classify(cond) == ("value", 0, ty)
    assert removable(cond, [ty]) is True
    other = "uint16" if ty != "uint16" else "uint24"
    assert removable(cond, [other]) is False  # a narrower / wider type: the decoder's check differs
    assert removable(cond, [ty], abi_v2=False) is False  # ABI coder v1 validates nothing
    # the second head word
    cond1 = legacy(1, cleanup)
    assert removable(cond1, ["uint256", ty]) is True
    assert removable(cond1, [ty, "uint256"]) is False


def test_identity_validators_of_full_width_types():
    cond = legacy(0, lambda p: p)
    assert classify(cond) == ("value", 0, "identity")
    for ty in ("uint256", "int256", "bytes32"):
        assert removable(cond, [ty]) is True
    assert removable(cond, ["uint8"]) is False
    assert removable(cond, ["uint256"], abi_v2=False) is False


def test_via_ir_validators():
    assert removable(via_ir_dirty(0, 96, 160), ["address"]) is True
    assert removable(via_ir_dirty(0, 248, 8), ["uint8"]) is True
    assert removable(via_ir_dirty(0, 248, 8), ["uint16"]) is False
    neg = ir.Op("mul", (ir.const(-1), via_ir_dirty(0, 96, 160)))  # unoptimised via-IR negates the dirty bits
    assert removable(neg, ["address"]) is True
    p = cd(0)
    sub_bool = ir.Op("add", (p, ir.Op("mul", (ir.const(-1), ir.Op("iszero", (ir.Op("iszero", (p,)),))))))
    assert removable(sub_bool, ["bool"]) is True
    sub_int = ir.Op("add", (p, ir.Op("mul", (ir.const(-1), ir.Op("signextend", (ir.Const(3), p))))))
    assert removable(sub_int, ["int32"]) is True
    assert removable(sub_int, ["int64"]) is False


def test_enum_range_becomes_an_enum_once():
    enums = {}
    assert removable(enum_check(0, 3), ["uint8"], enums=enums) is True
    assert enums == {0: 3}
    reversed_form = ir.Op("iszero", (ir.Op("gt", (ir.Const(3), cd(0))),))  # unoptimised via-IR
    assert classify(reversed_form) == ("enum", 0, 3)
    assert removable(reversed_form, ["uint8"], enums={}) is True
    assert removable(enum_check(0, 5), ["uint8"], enums=enums) is False  # a second range check: user code
    assert removable(enum_check(0, 3), ["uint16"]) is False
    assert removable(enum_check(0, 3), ["uint8"], abi_v2=False) is False
    assert removable(enum_check(0, 256), ["uint8"], enums={}) is True  # the uint8 range itself


def test_dynamic_parameter_checks_v2():
    off = cd(1)
    assert removable(ir.Op("gt", (off, B64)), ["uint256", "bytes"]) is True
    assert removable(ir.Op("gt", (off, B64)), ["uint256", "uint256"]) is False
    assert removable(ir.Op("gt", (off, B32)), ["uint256", "bytes"]) is False  # the v1 bound on a v2 decoder
    end = ir.Op("iszero", (ir.Op("slt", (ir.Op("add", (ir.Const(35), off)), CDS)),))
    assert removable(end, ["uint256", "bytes"]) is True
    assert removable(end, ["uint256", "bytes"], abi_v2=False) is False
    length = ir.Op("gt", (length_word(1), B64))
    assert removable(length, ["uint256", "string"]) is True
    bounds = ir.Op("gt", (ir.Op("add", (ir.Const(36), off, length_word(1))), CDS))
    assert removable(bounds, ["uint256", "bytes"]) is True
    assert removable(bounds, ["uint256", "uint256[]"]) is False  # stride 1 on an array of words
    bounds32 = ir.Op("gt", (ir.Op("add", (ir.Const(36), off, ir.Mask(251, 0, 5, length_word(1)))), CDS))
    assert removable(bounds32, ["uint256", "uint256[]"]) is True
    assert removable(bounds32, ["uint256", "address[]"]) is True
    assert removable(bounds32, ["uint256", "bytes"]) is False
    shl = ir.Op("gt", (ir.Op("add", (ir.Const(36), off, ir.Op("shl", (ir.Const(5), length_word(1))))), CDS))
    assert removable(shl, ["uint256", "uint256[]"]) is True
    mul64 = ir.Op("gt", (ir.Op("add", (ir.Const(36), off, ir.Op("mul", (ir.Const(64), length_word(1))))), CDS))
    assert removable(mul64, ["uint256", "(uint256,uint256)[]"]) is True
    assert removable(mul64, ["uint256", "uint256[]"]) is False


def test_dynamic_parameter_checks_v1():
    off = cd(0)
    assert removable(ir.Op("gt", (off, B32)), ["bytes"], abi_v2=False) is True
    assert removable(ir.Op("gt", (off, B64)), ["bytes"], abi_v2=False) is False
    end = ir.Op("gt", (ir.Op("add", (ir.Const(36), off)), CDS))
    assert removable(end, ["bytes"], abi_v2=False) is True
    assert removable(end, ["bytes"], abi_v2=True) is False
    tail = ir.Op("or", (ir.Op("gt", (length_word(0), B32)),
                        ir.Op("gt", (ir.Op("add", (ir.Const(36), off, length_word(0))), CDS))))
    assert removable(tail, ["bytes"], abi_v2=False) is True
    assert removable(tail, ["uint256[]"], abi_v2=False) is False


def test_allocation_panics_of_memory_parameters():
    p41 = ir.Panic(0x41)
    length = ir.Op("gt", (length_word(0), B64))
    assert classify(length, p41) == ("p41_length", 0)
    assert removable(length, ["bytes"], payload=p41) is True
    assert removable(length, ["bytes"], payload=p41, abi_v2=False) is False
    size = ir.Op("add", (ir.Const(0xa0), ir.Mask(251, 5, 0, ir.Op("add", (ir.Const(31), length_word(0))))))
    alloc = ir.Op("or", (ir.Op("gt", (size, B64)), ir.Op("lt", (size, ir.Const(0x80)))))
    assert classify(alloc, p41) == ("p41_alloc", (0,))
    assert removable(alloc, ["bytes"], payload=p41) is True
    assert removable(alloc, ["uint256"], payload=p41) is False
    two = ir.Op("add", (ir.Const(0xc0), ir.Mask(251, 5, 0, ir.Op("add", (ir.Const(31), length_word(0)))),
                        ir.Mask(251, 0, 5, length_word(1))))
    alloc2 = ir.Op("or", (ir.Op("gt", (two, B64)), ir.Op("lt", (two, ir.Const(0x80)))))
    assert removable(alloc2, ["bytes", "uint256[]"], payload=p41) is True
    # an allocation check with an empty revert is not the decoder's
    assert classify(alloc, ir.Empty()) is None


def test_unknown_checks_are_kept():
    user = ir.Op("gt", (cd(0), ir.Const(100)))
    assert classify(user) is None
    assert classify(ir.Op("iszero", (cd(0),))) is None
    assert classify(ir.Op("iszero", (ir.Op("lt", (cd(0), cd(1))),))) is None  # not a constant range


def test_via_ir_bytes_validator_tests_the_low_bits():
    # the optimised via-IR validator of bytesN: and(P, 2**(256-8N) - 1) != 0 reverts
    assert abi_mod.validator(ir.Mask(128, 0, 0, cd(2))) == (2, "bytes16")
    assert abi_mod.validator(ir.Mask(224, 0, 0, cd(0))) == (0, "bytes4")
    assert abi_mod.validator(ir.Mask(8, 0, 0, cd(0))) == (0, "bytes31")
    assert abi_mod.validator(ir.Mask(256, 0, 0, cd(0))) is None
    assert classify(ir.Mask(128, 0, 0, cd(2))) == ("value", 2, "bytes16")
    assert removable(ir.Mask(128, 0, 0, cd(2)), ["uint256", "uint256", "bytes16"]) is True
    assert removable(ir.Mask(128, 0, 0, cd(2)), ["uint256", "uint256", "bytes32"]) is False
    assert removable(ir.Mask(128, 0, 0, cd(2)), ["uint256", "uint256", "uint128"]) is False


def test_array_strides_that_are_powers_of_two():
    off, ln = cd(0), length_word(0)
    bounds64 = ir.Op("gt", (ir.Op("add", (ir.Const(36), off, ir.Mask(256, 0, 6, ln))), CDS))
    assert classify(bounds64) == ("dyn_bounds", 0, 64)
    assert removable(bounds64, ["uint256[2][]"]) is True
    assert removable(bounds64, ["(uint256,uint256)[]"]) is True
    assert removable(bounds64, ["uint256[]"]) is False
    bounds128 = ir.Op("gt", (ir.Op("add", (ir.Const(36), ir.Op("shl", (ir.Const(7), ln)), off)), CDS))
    assert classify(bounds128) == ("dyn_bounds", 0, 128)
    assert removable(bounds128, ["bytes32[4][]"]) is True
    assert removable(bounds128, ["uint256[2][]"]) is False
    bounds250 = ir.Op("gt", (ir.Op("add", (ir.Const(36), off, ir.Mask(250, 0, 6, ln))), CDS))
    assert classify(bounds250) == ("dyn_bounds", 0, 64)  # the 250-bit mask of a shifted word


def test_head_checks_continue_through_the_memory_panics():
    # the uint8 validator after the Panic(0x41) checks of a memory parameter
    # is still the decoder's (signature matching needs it)
    body = (ir.If(head(2), (ir.Revert(),), (
        ir.If(ir.Op("gt", (length_word(0), B64)), (ir.Revert(ir.Panic(0x41)),), (
            ir.If(legacy(1, lambda p: ir.Mask(8, 0, 0, p)), (ir.Revert(),), (_ret(cd(1)),)),)),)),)
    checks = abi_mod.head_checks(body)
    assert len(checks) == 3 and abi_mod.validator(checks[2]) == (1, "uint8")
    # any other panic ends the chain
    body2 = (ir.If(head(2), (ir.Revert(),), (
        ir.If(ir.Op("gt", (length_word(0), B64)), (ir.Revert(ir.Panic(0x11)),), (
            ir.If(legacy(1, lambda p: ir.Mask(8, 0, 0, p)), (ir.Revert(),), (_ret(cd(1)),)),)),)),)
    assert len(abi_mod.head_checks(body2)) == 1


def test_member_words_of_composite_parameters_are_no_length_words():
    # the word at the head offset of a struct / fixed-size array is a member
    # (an element offset), not a length: `gt(cd[4 + OFF], 2**64-1)` there is
    # the memory decoder's check of a member offset, which the decoder of the
    # declared parameter does not make when it is declared calldata
    length = ir.Op("gt", (length_word(0), B64))
    assert removable(length, ["bytes"]) is True
    for t in ("(bytes,uint256)", "(uint256[],uint8)", "bytes[2]", "uint256[][2]"):
        assert removable(length, [t]) is False, t
        assert removable(length, [t], payload=ir.Panic(0x41)) is False, t
    size = ir.Op("add", (ir.Const(0xa0), ir.Mask(251, 5, 0, ir.Op("add", (ir.Const(31), length_word(0))))))
    alloc = ir.Op("or", (ir.Op("gt", (size, B64)), ir.Op("lt", (size, ir.Const(0x80)))))
    assert removable(alloc, ["(bytes,uint256)"], payload=ir.Panic(0x41)) is False
    # the offset and the end of the head word: any dynamic type's decoder
    # (the size check of a struct / fixed array implies the end check)
    off = ir.Op("gt", (cd(0), B64))
    end = ir.Op("iszero", (ir.Op("slt", (ir.Op("add", (ir.Const(35), cd(0))), CDS)),))
    for t in ("(bytes,uint256)", "bytes[2]", "(uint256,bytes)"):
        assert removable(off, [t]) is True, t
        assert removable(end, [t]) is True, t


def test_allocation_size_with_the_full_width_rounding_mask():
    # ceil32(32 len) written mask_shl(256, 5, 0, 31 + mask_shl(256, 0, 5, len))
    # by the optimiser: the same word as the 251-bit mask
    ln = length_word(0)
    size = ir.Op("add", (ir.Const(0xa0), ir.Mask(256, 5, 0, ir.Op("add", (ir.Const(31), ir.Mask(256, 0, 5, ln))))))
    alloc = ir.Op("or", (ir.Op("lt", (size, ir.Const(0x80))), ir.Op("gt", (size, B64))))
    assert classify(alloc, ir.Panic(0x41)) == ("p41_alloc", (0,))
    assert removable(alloc, ["uint256[]"], payload=ir.Panic(0x41)) is True
    assert classify(ir.Op("or", (ir.Op("lt", (size, ir.Const(0x80))), ir.Op("gt", (size, B64)))), ir.Empty()) is None


def _copy_loop(w, validate=True):
    """The decoder's copy of array parameter w to memory (32-byte elements,
    each validated as an address)."""
    v0, v1 = ir.Local("v0"), ir.Local("v1")
    elem = ir.CalldataWord(v0)
    store = (ir.Mstore(v1, ir.WordBytes(elem)),
             ir.Continue("L", (ir.Assign(v1, ir.Op("add", (ir.Const(32), v1))),
                               ir.Assign(v0, ir.Op("add", (ir.Const(32), v0))))))
    body = (ir.If(ir.Op("iszero", (ir.Op("eq", (elem, ir.Mask(160, 0, 0, elem))),)), (ir.Revert(),), store),) \
        if validate else store
    end = ir.Op("add", (ir.Const(36), cd(w), ir.Mask(256, 0, 5, length_word(w))))
    return ir.While(ir.Op("lt", (v0, end)), body,
                    (ir.Assign(v1, ir.Const(0xa0)), ir.Assign(v0, ir.Op("add", (ir.Const(36), cd(w))))), "L")


def _memory_array_checks(w, rest):
    off, ln = cd(w), length_word(w)
    size = ir.Op("add", (ir.Const(0xa0), ir.Mask(256, 5, 0, ir.Op("add", (ir.Const(31), ir.Mask(256, 0, 5, ln))))))
    return ir.If(ir.Op("gt", (off, B64)), (ir.Revert(),), (
        ir.If(ir.Op("iszero", (ir.Op("slt", (ir.Op("add", (ir.Const(35), off)), CDS)),)), (ir.Revert(),), (
            ir.If(ir.Op("gt", (ln, B64)), (ir.Revert(ir.Panic(0x41)),), (
                ir.If(ir.Op("or", (ir.Op("lt", (size, ir.Const(0x80))), ir.Op("gt", (size, B64)))),
                      (ir.Revert(ir.Panic(0x41)),), (
                    ir.If(ir.Op("gt", (ir.Op("add", (ir.Const(36), off, ir.Mask(256, 0, 5, ln))), CDS)),
                          (ir.Revert(),), tuple(rest)),)),)),)),))


def test_the_chain_continues_through_the_decoder_copy_loop():
    # f(address[] memory a, bytes memory b): the copy loop of `a` (element
    # validators inside) sits between the checks of `a` and those of `b`;
    # `b` is decoded to memory too (its length bound panics)
    rest = [_copy_loop(0), _memory_bytes_checks(1, (_ret(length_word(1)),))]
    body = [ir.If(head(2), (ir.Revert(),), (_memory_array_checks(0, rest),))]
    key, e = _entry("f(address[],bytes)", [("address[]", "a"), ("bytes", "b")], body, ["uint256"])
    src, ctx, units = _build({key: e}, off=("reverts",))
    text = function_text(src, "f")
    assert "function f(address[] memory a, bytes memory b) external pure returns (uint256)" in text
    facts = ctx.facts["abi"]["functions"][key]
    assert (facts["checks"], facts["removed"], facts["kept"], facts["unmatched"]) == (11, 11, 0, 0), facts
    assert "_panic(" not in text and "return b.length;" in text
    loops = [n for n in ir.walk_all(units[0].fn.body) if isinstance(n, (ir.While, ir.For))]
    assert len(loops) == 1 and ir.contains(loops[0].body, ir.Revert)  # the copy loop stays, as it is
    # the head checks see the validator of a value parameter after the loop
    body2 = [ir.If(head(2), (ir.Revert(),), (_memory_array_checks(0, [
        _copy_loop(0, validate=False),
        ir.If(legacy(1, lambda p: ir.Mask(160, 0, 0, p)), (ir.Revert(),), (_ret(cd(1)),))]),))]
    checks = abi_mod.head_checks(body2)
    assert abi_mod.validator(checks[-1]) == (1, "address")
    # a loop with an effect is not the decoder's: the chain ends before it
    effect = ir.While(ir.Op("lt", (ir.Local("v0"), cd(1))), (ir.Sstore(ir.Local("v0"), ir.ONE),), (), "M")
    body3 = [ir.If(head(2), (ir.Revert(),), (_memory_array_checks(0, [
        effect, ir.If(legacy(1, lambda p: ir.Mask(160, 0, 0, p)), (ir.Revert(),), (_ret(cd(1)),))]),))]
    assert len(abi_mod.head_checks(body3)) == 6


def _struct_member_checks(w, rest):
    """The memory decoder of `(bytes,uint256)` at head word w: its size,
    the offset of its `bytes` member, then that member's checks."""
    off = cd(w)
    member = ir.CalldataWord(ir.Op("add", (ir.Const(4), off)))
    mlen = ir.CalldataWord(ir.Op("add", (ir.Const(4), off, member)))
    size = ir.Op("slt", (ir.Op("add", (ir.const(-4), CDS, ir.Op("mul", (ir.const(-1), off)))), ir.Const(64)))
    return ir.If(ir.Op("gt", (off, B64)), (ir.Revert(),), (
        ir.If(size, (ir.Revert(),), (
            ir.If(ir.Op("gt", (member, B64)), (ir.Revert(),), (
                ir.If(ir.Op("gt", (mlen, B64)), (ir.Revert(ir.Panic(0x41)),), tuple(rest)),)),)),))


def test_struct_and_fixed_array_locations_follow_the_decoder():
    # f((bytes,uint256) s, bytes b): the members of `s` are read before the
    # checks of `b`: the original decoded `s` to memory, so must the target
    # (declared calldata, its Panic(0x41) and `b`'s empty reverts would run
    # in another order)
    rest = [_memory_bytes_checks(1, (_ret(length_word(1)),))]
    body = [ir.If(head(2), (ir.Revert(),), (_struct_member_checks(0, rest),))]
    key, e = _entry("f((bytes,uint256),bytes)", [("(bytes,uint256)", "s"), ("bytes", "b")], body, ["uint256"])
    src, ctx, _ = _build({key: e}, off=("reverts",))
    assert e[1].locations == {0: "memory", 1: "memory"}
    # the last parameter: a calldata struct read by the body looks the same,
    # and the calldata declaration is exact there (no later check to order)
    body2 = [ir.If(head(1), (ir.Revert(),), (_struct_member_checks(0, [_ret(cd(0))]),))]
    key2, e2 = _entry("g((bytes,uint256))", [("(bytes,uint256)", "s")], body2, ["uint256"])
    _build({key2: e2}, off=("reverts",))
    assert e2[1].locations.get(0, "calldata") == "calldata"
    # a static array copied by a loop (element validators) before the next
    # parameter's checks
    v0, v1 = ir.Local("v0"), ir.Local("v1")
    elem = ir.CalldataWord(v0)
    loop = ir.While(ir.Op("lt", (v0, ir.Const(68))), (
        ir.If(ir.Op("iszero", (ir.Op("eq", (elem, ir.Mask(8, 0, 0, elem))),)), (ir.Revert(),), (
            ir.Mstore(v1, ir.WordBytes(elem)),
            ir.Continue("L", (ir.Assign(v0, ir.Op("add", (ir.Const(32), v0))),
                              ir.Assign(v1, ir.Op("add", (ir.Const(32), v1)))))),),),
        (ir.Assign(v0, ir.Const(4)), ir.Assign(v1, ir.Const(0x80))), "L")
    body3 = [ir.If(head(3), (ir.Revert(),), (loop, _memory_bytes_checks(2, (_ret(length_word(2)),))))]
    key3, e3 = _entry("h(uint8[2],bytes)", [("uint8[2]", "x"), ("bytes", "b")], body3, ["uint256"])
    src3, _, _ = _build({key3: e3}, off=("reverts",))
    assert "function h(uint8[2] memory x, bytes memory b)" in function_text(src3, "h")
    # without a read of its elements before `b`'s checks: calldata
    body4 = [ir.If(head(3), (ir.Revert(),), (_memory_bytes_checks(2, (_ret(cd(0)),)),))]
    key4, e4 = _entry("k(uint256[2],bytes)", [("uint256[2]", "x"), ("bytes", "b")], body4, ["uint256"])
    src4, _, _ = _build({key4: e4}, off=("reverts",))
    assert "function k(uint256[2] calldata x, bytes memory b)" in function_text(src4, "k")


# ---------------------------------------------------------------- the pass on IR


def _build(entries, abi_v2=True, level="full", off=()):
    specs = {k: s for k, (_, s) in entries.items()}
    functions = {k: f for k, (f, _) in entries.items()}
    ctx = pipeline.PassContext(specs=specs, metadata=None, dispatcher=None, target_solc="0.8.19", abi_v2=abi_v2,
                               idiom_level=level, functions=dict(functions), disabled_passes={"*": set(off)})
    passes = pipeline.available_passes(level)
    pipeline.prepare(passes, ctx)
    units = []
    for key, fn in functions.items():
        fn2, applied = pipeline.run_passes(fn, passes, ctx)
        units.append(Unit(key, fn2, specs[key], passes=applied, flags=set(fn2.flags)))
    pipeline.finish(passes, ctx)
    src, _ = assemble(ContractInput(units=units, target="0.8.19", original="test", abi_v2=abi_v2, idiom_level=level,
                                    declarations=ctx.declarations))
    return src, ctx, units


def _entry(signature, params, body, returns=None):
    from scobelix.solgen import sigs

    sel = sigs.function_selector(signature)
    key = f"0x{sel:08x}"
    spec = EntrySpec(key=key, kind="function", selector=sel, name=signature.split("(")[0], signature=signature,
                     params=tuple((parse_type(t), n) for t, n in params), mutability="pure",
                     returns=None if returns is None else tuple(parse_type(t) for t in returns))
    return key, (ir.Function(key, tuple(body)), spec)


def _ret(*words):
    return ir.Return(ir.Blob(tuple(ir.WordBytes(w) for w in words)))


def test_prologue_removed_and_parameters_typed():
    body = [ir.If(head(2), (ir.Revert(),), (
        ir.If(legacy(0, lambda p: ir.Mask(160, 0, 0, p)), (ir.Revert(),), (
            ir.If(enum_check(1, 3), (ir.Revert(),), (
                _ret(ir.Op("add", (ir.Mask(160, 0, 0, cd(0)), cd(1)))),)),)),))]
    key, e = _entry("f(address,uint8)", [("address", "to"), ("uint8", "kind")], body, ["uint256"])
    src, ctx, units = _build({key: e})
    text = function_text(src, "f")
    assert "function f(address to, Enum3 kind) external pure returns (uint256)" in text
    assert "revert" not in text and "msg.data.length" not in text
    assert "enum Enum3 { V0, V1, V2 }" in src
    facts = ctx.facts["abi"]["functions"][key]
    assert facts == {"checks": 3, "removed": 3, "kept": 0, "unmatched": 0, "params": 2, "prologue_removed": True}
    assert isinstance(units[0].fn.body[0], ir.Return)
    assert ir.contains(units[0].fn.body, ir.Param)


def _memory_bytes_checks(w, rest):
    off, ln = cd(w), length_word(w)
    size = ir.Op("add", (ir.Const(0xa0), ir.Mask(251, 5, 0, ir.Op("add", (ir.Const(31), ln)))))
    return ir.If(ir.Op("gt", (off, B64)), (ir.Revert(),), (
        ir.If(ir.Op("iszero", (ir.Op("slt", (ir.Op("add", (ir.Const(35), off)), CDS)),)), (ir.Revert(),), (
            ir.If(ir.Op("gt", (ln, B64)), (ir.Revert(ir.Panic(0x41)),), (
                ir.If(ir.Op("or", (ir.Op("gt", (size, B64)), ir.Op("lt", (size, ir.Const(0x80))))),
                      (ir.Revert(ir.Panic(0x41)),), (
                    ir.If(ir.Op("gt", (ir.Op("add", (ir.Const(36), off, ln)), CDS)), (ir.Revert(),), rest),)),)),)),))


def test_enum_range_is_declared_only_in_the_decoder_position():
    # the body's own `require(x < 3)` on a uint8 after the checks of a
    # memory parameter: an enum would move the test before the Panic(0x41)
    body = [ir.If(head(2), (ir.Revert(),), (
        ir.If(legacy(0, lambda p: ir.Mask(8, 0, 0, p)), (ir.Revert(),), (
            _memory_bytes_checks(1, (ir.If(enum_check(0, 3), (ir.Revert(),), (_ret(cd(0)),)),)),)),))]
    key, e = _entry("f(uint8,bytes)", [("uint8", "x"), ("bytes", "d")], body, ["uint256"])
    src, ctx, _ = _build({key: e}, off=("reverts",))
    text = function_text(src, "f")
    assert "function f(uint8 x, bytes memory d) external pure returns (" in text
    assert "(uint256(x) >= 3)" in text and "revert();" in text and "Enum3" not in src
    assert ctx.facts["abi"]["functions"][key]["removed"] == 7
    # the decoder's own enum range sits before the next parameter's checks
    body2 = [ir.If(head(2), (ir.Revert(),), (
        ir.If(enum_check(0, 3), (ir.Revert(),), (_memory_bytes_checks(1, (_ret(cd(0)),)),)),))]
    key2, e2 = _entry("g(uint8,bytes)", [("uint8", "x"), ("bytes", "d")], body2, ["uint256"])
    src2, ctx2, _ = _build({key2: e2}, off=("reverts",))
    assert "function g(Enum3 x, bytes memory d) external pure returns (" in function_text(src2, "g")
    assert "revert" not in function_text(src2, "g")
    # a range check preceded by a validator of the same word is the body's
    # (the decoder of an enum validates the range only)
    body3 = [ir.If(head(1), (ir.Revert(),), (
        ir.If(legacy(0, lambda p: ir.Mask(8, 0, 0, p)), (ir.Revert(),), (
            ir.If(enum_check(0, 3), (ir.Revert(),), (_ret(cd(0)),)),)),))]
    key3, e3 = _entry("h(uint8)", [("uint8", "x")], body3, ["uint256"])
    src3, ctx3, _ = _build({key3: e3}, off=("reverts",))
    assert "function h(uint8 x)" in function_text(src3, "h") and "(uint256(x) >= 3)" in function_text(src3, "h")
    # a range check after a user check is the body's too
    body4 = [ir.If(head(1), (ir.Revert(),), (
        ir.If(ir.Op("eq", (cd(0), ir.Const(7))), (ir.Revert(),), (
            ir.If(enum_check(0, 3), (ir.Revert(),), (_ret(cd(0)),)),)),))]
    key4, e4 = _entry("k(uint8)", [("uint8", "x")], body4, ["uint256"])
    src4, ctx4, _ = _build({key4: e4}, off=("reverts",))
    assert "function k(uint8 x)" in function_text(src4, "k") and function_text(src4, "k").count("revert();") == 2


def test_user_checks_stay_and_the_chain_keeps_its_order():
    user = ir.Op("gt", (cd(0), ir.Const(100)))
    body = [ir.If(head(1), (ir.Revert(),), (
        ir.If(legacy(0, lambda p: ir.Mask(8, 0, 0, p)), (ir.Revert(),), (
            ir.If(user, (ir.Revert(ir.ErrorString(b"too big")),), (_ret(cd(0)),)),)),))]
    key, e = _entry("g(uint8)", [("uint8", "x")], body, ["uint256"])
    src, ctx, units = _build({key: e}, off=("reverts",))
    text = function_text(src, "g")
    assert text.count("revert") == 1 and "too big" in text
    assert ctx.facts["abi"]["functions"][key]["removed"] == 2
    # a decoder-shaped check after a user check is not the decoder's: kept
    body2 = [ir.If(head(1), (ir.Revert(),), (
        ir.If(user, (ir.Revert(ir.ErrorString(b"too big")),), (
            ir.If(legacy(0, lambda p: ir.Mask(8, 0, 0, p)), (ir.Revert(),), (_ret(cd(0)),)),)),))]
    key2, e2 = _entry("g2(uint8)", [("uint8", "x")], body2, ["uint256"])
    src2, ctx2, _ = _build({key2: e2}, off=("reverts",))
    assert function_text(src2, "g2").count("revert") == 2
    f2 = ctx2.facts["abi"]["functions"][key2]
    assert (f2["removed"], f2["kept"], f2["unmatched"], f2["prologue_removed"]) == (1, 0, 0, True)
    # (the chain of decoder checks ends at the user's revert with a message)
    body3 = [ir.If(head(1), (ir.Revert(),), (
        ir.If(ir.Op("eq", (cd(0), ir.Const(7))), (ir.Revert(),), (
            ir.If(legacy(0, lambda p: ir.Mask(8, 0, 0, p)), (ir.Revert(),), (_ret(cd(0)),)),)),))]
    key3, e3 = _entry("g3(uint8)", [("uint8", "x")], body3, ["uint256"])
    src3, ctx3, _ = _build({key3: e3}, off=("reverts",))
    f3 = ctx3.facts["abi"]["functions"][key3]
    # the validator after the user's empty revert is still the decoder's
    # (the target validates before the body runs): removed; the user's stays
    assert (f3["removed"], f3["kept"], f3["unmatched"], f3["prologue_removed"]) == (2, 0, 1, True)
    assert function_text(src3, "g3").count("revert();") == 1 and "== 7" in function_text(src3, "g3")
    # a validator of another type than the declared one is user code
    body2 = [ir.If(head(1), (ir.Revert(),), (
        ir.If(legacy(0, lambda p: ir.Mask(16, 0, 0, p)), (ir.Revert(),), (_ret(cd(0)),)),))]
    key2, e2 = _entry("h(uint8)", [("uint8", "x")], body2, ["uint256"])
    src2, ctx2, _ = _build({key2: e2}, off=("reverts",))
    assert "revert();" in function_text(src2, "h")
    assert ctx2.facts["abi"]["functions"][key2]["prologue_removed"] is False
    assert ctx2.facts["abi"]["functions"][key2]["kept"] == 1


def test_abi_v1_removes_only_the_size_check():
    body = [ir.If(head(1, signed=False), (ir.Revert(),), (_ret(ir.Mask(160, 0, 0, cd(0))),))]
    key, e = _entry("f(address)", [("address", "a")], body, ["uint256"])
    src, ctx, _ = _build({key: e}, abi_v2=False)
    text = function_text(src, "f")
    assert "revert" not in text
    assert "_calldataload(4)" in text  # ABI coder v1: the declared parameter does not carry the raw word


def test_routed_functions_are_typed_from_their_checks_or_left_alone():
    body = [ir.If(head(1), (ir.Revert(),), (_ret(cd(0)),))]
    key = "0x12345678"
    # typed: the router decodes the head word (its size check), the body reads the parameter
    spec = EntrySpec(key=key, kind="function", selector=0x12345678, head_words=1)
    src, ctx, _ = _build({key: (ir.Function(key, tuple(body)), spec)}, off=("reverts",))
    assert "function _fn_12345678(uint256 arg0) private returns (uint256)" in src
    assert "return arg0;" in function_text(src, "_fn_12345678")
    assert "return abi.encode(_fn_12345678(abi.decode(input[4:], (uint256))));" in src
    assert ctx.facts["abi"]["functions"][key]["route"] == "typed"
    # the abi pass off: the private body reads the calldata itself, behind its own checks
    spec = EntrySpec(key=key, kind="function", selector=0x12345678, head_words=1)
    src, ctx, _ = _build({key: (ir.Function(key, tuple(body)), spec)}, off=("reverts", "abi"))
    assert "revert();" in function_text(src, "_fn_12345678") and "fallback() external {" in src
    assert key not in ctx.facts.get("abi", {}).get("functions", {})


def test_memory_location_from_the_allocation_panic():
    off, ln = cd(0), length_word(0)
    size = ir.Op("add", (ir.Const(0xa0), ir.Mask(251, 5, 0, ir.Op("add", (ir.Const(31), ln)))))
    chain = [ir.If(head(1), (ir.Revert(),), (
        ir.If(ir.Op("gt", (off, B64)), (ir.Revert(),), (
            ir.If(ir.Op("iszero", (ir.Op("slt", (ir.Op("add", (ir.Const(35), off)), CDS)),)), (ir.Revert(),), (
                ir.If(ir.Op("gt", (ln, B64)), (ir.Revert(ir.Panic(0x41)),), (
                    ir.If(ir.Op("or", (ir.Op("gt", (size, B64)), ir.Op("lt", (size, ir.Const(0x80))))),
                          (ir.Revert(ir.Panic(0x41)),), (
                        ir.If(ir.Op("gt", (ir.Op("add", (ir.Const(36), off, ln)), CDS)), (ir.Revert(),), (
                            _ret(ln),)),)),)),)),)),))]
    key, e = _entry("f(bytes)", [("bytes", "d")], chain, ["uint256"])
    src, ctx, _ = _build({key: e})
    text = function_text(src, "f")
    assert "function f(bytes memory d) external pure returns (uint256)" in text
    assert "revert" not in text and "_panic" not in text
    assert "return d.length;" in text
    # the calldata decoder: the length bound reverts without data
    chain2 = [ir.If(head(1), (ir.Revert(),), (
        ir.If(ir.Op("gt", (off, B64)), (ir.Revert(),), (
            ir.If(ir.Op("iszero", (ir.Op("slt", (ir.Op("add", (ir.Const(35), off)), CDS)),)), (ir.Revert(),), (
                ir.If(ir.Op("gt", (ln, B64)), (ir.Revert(),), (
                    ir.If(ir.Op("gt", (ir.Op("add", (ir.Const(36), off, ln)), CDS)), (ir.Revert(),), (
                        ir.Return(ir.CalldataSlice(ir.Op("add", (ir.Const(36), off)), ln)),)),)),)),)),))]
    key2, e2 = _entry("g(bytes)", [("bytes", "d")], chain2)
    src2, ctx2, _ = _build({key2: e2})
    text2 = function_text(src2, "g")
    assert "function g(bytes calldata d) external pure" in text2
    assert "_return(d);" in text2


def test_return_types_are_refined_from_the_returned_words():
    a = ir.Mask(160, 0, 0, cd(0))
    body = [ir.If(head(1), (ir.Revert(),), (
        ir.If(legacy(0, lambda p: ir.Mask(160, 0, 0, p)), (ir.Revert(),), (
            ir.If(ir.Op("iszero", (cd(0),)), (_ret(ir.ZERO, ir.ZERO, ir.Const(0x12 << 248), ir.Const(7)),),
                  (_ret(ir.ONE, a, ir.Mask(8, 248, 0, ir.Op("add", (ir.ONE, cd(0)))), ir.Mask(8, 0, 0, cd(0))),)),)),))]
    key, e = _entry("f(address)", [("address", "a")], body, ["uint256", "uint256", "uint256", "uint256"])
    src, ctx, _ = _build({key: e})
    text = function_text(src, "f")
    assert "returns (bool, address, bytes1, uint8)" in text
    assert "return (true, a, " in text


def test_constant_string_return_is_declared_string_memory():
    msg = b"probe"
    data = ir.Blob((ir.WordBytes(ir.Const(32)), ir.WordBytes(ir.Const(5)), ir.WordBytes(ir.Const(int.from_bytes(msg.ljust(32, b"\0"), "big")))))
    key, e = _entry("name()", [], [ir.Return(data)])
    src, ctx, _ = _build({key: e})
    text = function_text(src, "name")
    assert "returns (string memory)" in text and 'return "probe";' in text
    # a padding byte that is not zero is not the standard encoding: raw return kept
    bad = ir.Blob((ir.WordBytes(ir.Const(32)), ir.WordBytes(ir.Const(5)), ir.WordBytes(ir.Const((int.from_bytes(msg.ljust(32, b"\0"), "big")) | 1))))
    key2, e2 = _entry("sym()", [], [ir.Return(bad)])
    src2, _, _ = _build({key2: e2})
    assert "returns (string memory)" not in function_text(src2, "sym")


# ---------------------------------------------------------------- real compilers

V_SOURCE = """
contract V {
    enum E { A, B, C }
    function vAddr(address a) external pure returns (uint256) { return uint256(%(ADDR)s); }
    function vU8(uint8 x) external pure returns (uint256) { return x; }
    function vU40(uint40 x) external pure returns (uint256) { return x; }
    function vU128(uint128 x) external pure returns (uint256) { return x; }
    function vBool(bool b) external pure returns (uint256) { return b ? 1 : 0; }
    function vI8(int8 x) external pure returns (int256) { return x; }
    function vI128(int128 x) external pure returns (int256) { return x; }
    function vB4(bytes4 x) external pure returns (uint256) { return uint256(uint32(x)); }
    function vB32(bytes32 x) external pure returns (bytes32) { return x; }
    function vEnum(E e) external pure returns (uint256) { return uint256(e); }
    function vMix(address a, bool b, uint16 c, int32 d, bytes8 e) external pure returns (uint256) {
        return uint256(%(ADDR)s) ^ (b ? 1 : 0) ^ c ^ uint256(%(I32)s) ^ uint256(uint64(e));
    }
    function vNone() external pure returns (uint256) { return 7; }
    function vRet(address a) external pure returns (bool, address, bytes4, uint8, int16) {
        return (a != address(0), a, bytes4(0x12345678), 200, -5);
    }
    function vWide(uint256 x, bytes32 y, int256 z) external pure returns (uint256) { return x ^ uint256(y) ^ uint256(z); }
    function vB16(uint64 x, uint32 y, bytes16 z) external pure returns (uint256) { return x ^ y ^ uint256(uint128(z)); }
}
"""

V_SIGS = ["vAddr(address)", "vU8(uint8)", "vU40(uint40)", "vU128(uint128)", "vBool(bool)", "vI8(int8)", "vI128(int128)",
          "vB4(bytes4)", "vB32(bytes32)", "vEnum(uint8)", "vMix(address,bool,uint16,int32,bytes8)", "vNone()",
          "vRet(address)", "vWide(uint256,bytes32,int256)", "vB16(uint64,uint32,bytes16)"]


def v_source(build):
    old = build.major < (0, 8)
    return V_SOURCE % {"ADDR": "a" if old else "uint160(a)", "I32": "d" if old else "int256(d)"}


D_SOURCE = """
contract D {
    function dBytes(bytes %(CD)s d) external pure returns (uint256) { return d.length; }
    function dStr(string %(CD)s s) external pure returns (bytes32) { return keccak256(%(SBYTES)s); }
    function dArr(uint256[] %(CD)s a) external pure returns (uint256) { return a.length; }
    function dAddrArr(address[] %(CD)s a) external pure returns (uint256) { return a.length; }
    function dMulti(address to, bytes %(CD)s d, uint256[] %(CD)s a, uint8 k) external pure returns (uint256) {
        return uint256(%(ADDR)s) ^ d.length ^ a.length ^ k;
    }
    function dSum(uint256[] %(CD)s a) external pure returns (uint256 s) {
        for (uint256 i = 0; i < a.length; i++) { s ^= a[i]; }
    }
    function dEcho(bytes %(CD)s d) external pure returns (bytes memory) { return d; }
    function dName() external pure returns (string memory) { return "probe"; }
%(MEM)s
}
"""

D_MEM = """
    function dBytesMem(bytes memory d) external pure returns (uint256) { return d.length; }
    function dArrMem(uint256[] memory a) external pure returns (uint256) { return a.length; }
    function dAddrMem(address[] memory a) external pure returns (uint256) { return a.length; }
    function dStrMem(string memory s) external pure returns (uint256) { return bytes(s).length; }
    function dMemThen(bytes memory d, uint8 k) external pure returns (uint256) { return d.length ^ k; }
"""

D_SIGS = ["dBytes(bytes)", "dStr(string)", "dArr(uint256[])", "dAddrArr(address[])", "dMulti(address,bytes,uint256[],uint8)",
          "dSum(uint256[])", "dEcho(bytes)", "dName()"]
D_MEM_SIGS = ["dBytesMem(bytes)", "dArrMem(uint256[])", "dAddrMem(address[])", "dStrMem(string)",
              "dMemThen(bytes,uint8)"]


def d_source(build):
    old = build.major < (0, 8)
    mem = build.major >= (0, 8)  # memory parameters of external functions: 0.6.9+, tested on 0.8
    return D_SOURCE % {"CD": "" if build.major < (0, 5) else "calldata", "SBYTES": "bytes(s)",
                       "ADDR": "to" if old else "uint160(to)", "MEM": D_MEM if mem else ""}


BUILDS = [
    Build("0.4.26"),
    Build("0.5.17", optimize=False),
    Build("0.7.6"),
    Build("0.7.6", optimize=False, abicoder="v2"),
    Build("0.8.19"),
    Build("0.8.19", optimize=False),
    Build("0.8.19", via_ir=True),
    Build("0.8.31", optimize=False, via_ir=True),
    Build("0.8.31"),
]
# the probes over every build run by default on one build of each decoder
# (0.4.26, ABI coder v1 and v2 before 0.8, 0.8.19 with both pipelines), on the
# other builds with `-m slow`
_PROBE_BUILDS = [b if i in (0, 1, 3, 4, 6) else pytest.param(b, marks=pytest.mark.slow) for i, b in enumerate(BUILDS)]


def _check_probe(build, source, contract, signatures, monkeypatch, outputs=True):
    art = compile_probe(source, build, contract)
    patch_signatures(monkeypatch, art.abi, outputs=outputs)
    r = generate_probe(art.runtime)
    named = named_functions(r)
    assert set(f["signature"] for f in named.values()) == set(signatures), sorted(f["signature"] for f in named.values())
    calls, skipped = probe_calls(r)
    assert set(skipped) <= {"dEcho(bytes)"}, skipped  # the memory round trip of a calldata slice: engine limitation
    assert not differential(art.runtime, r.solidity, r.target_solc, calls)
    return r, {k: f for k, f in named.items() if f["signature"] not in skipped}


@pytest.mark.parametrize("build", _PROBE_BUILDS, ids=lambda b: b.label)
def test_value_types_probe(build, monkeypatch):
    r, named = _check_probe(build, v_source(build), "V", V_SIGS, monkeypatch)
    for key, f in named.items():
        facts = f["abi"]
        assert facts is not None and facts["unmatched"] == 0, (f["signature"], facts)
        assert facts["prologue_removed"], (f["signature"], facts)
    # the database's output types are the declaration (the source said uint256)
    assert "function vAddr(address a) external pure returns (uint256)" in r.solidity
    assert "function vMix(address a, bool b, uint16 c, int32 d, bytes8 e) external pure returns (uint256)" in r.solidity
    assert "function vRet(address a) external pure returns (bool, address, bytes4, uint8, int16)" in r.solidity
    if build.v2:
        assert "function vEnum(Enum3 e) external pure returns (uint256)" in r.solidity
        for name in ("vAddr", "vU8", "vBool", "vI8", "vB4", "vEnum", "vMix", "vB16"):
            assert "_calldataload(" not in function_text(r.solidity, name), name


@pytest.mark.parametrize("build", [BUILDS[4], BUILDS[6], BUILDS[8]], ids=lambda b: b.label)
def test_return_types_are_inferred_without_database_outputs(build, monkeypatch):
    r, named = _check_probe(build, v_source(build), "V", V_SIGS, monkeypatch, outputs=False)
    # constants alone do not tell a type (200 may be a uint256): the shaped words do
    assert "function vRet(address a) external pure returns (bool, address, uint256, uint256, uint256)" in r.solidity
    assert "function vBool(bool b) external pure returns (bool)" in r.solidity
    assert "function vI8(int8 x) external pure returns (int8)" in r.solidity  # the sign-extended word
    assert "function vU40(uint40 x) external pure returns (uint40)" in r.solidity
    assert "function vAddr(address a) external pure returns (address)" in r.solidity
    assert "function vB32(bytes32 x) external pure returns (bytes32)" in r.solidity  # the parameter's own type
    assert "function vWide(uint256 x, bytes32 y, int256 z) external pure returns (uint256)" in r.solidity
    assert "function vEnum(Enum3 e) external pure returns (uint8)" in r.solidity


@pytest.mark.parametrize("build", _PROBE_BUILDS, ids=lambda b: b.label)
def test_dynamic_parameters_probe(build, monkeypatch):
    sigs_ = D_SIGS + (D_MEM_SIGS if build.major >= (0, 8) else [])
    r, named = _check_probe(build, d_source(build), "D", sigs_, monkeypatch)
    if build.v2:
        for key, f in named.items():
            assert f["abi"]["prologue_removed"], (f["signature"], f["abi"])
        assert "function dBytes(bytes calldata d) external pure returns (uint256)" in r.solidity
        assert "return d.length;" in function_text(r.solidity, "dBytes")
        assert "function dArr(uint256[] calldata a) external pure returns (uint256)" in r.solidity
        assert "function dStr(string calldata s) external pure returns (bytes32)" in r.solidity
        assert 'return "probe";' in function_text(r.solidity, "dName")
        if build.major >= (0, 8):
            assert "function dBytesMem(bytes memory d) external pure returns (uint256)" in r.solidity
            assert "function dStrMem(string memory s) external pure returns (uint256)" in r.solidity
            # the validator after the memory parameter's checks: the signature matched, the prologue removed
            assert "function dMemThen(bytes memory d, uint8 k) external pure returns (uint256)" in r.solidity
            assert "_calldataload(" not in function_text(r.solidity, "dMemThen")
    else:
        for key, f in named.items():  # v1 decoders: the size check (0.5+) and the v1 offset / bound forms
            assert f["abi"]["prologue_removed"] and f["abi"]["unmatched"] == 0, (f["signature"], f["abi"])
            assert f["abi"]["checks"] >= 1 or build.major < (0, 5) or not f["abi"]["params"], (f["signature"], f["abi"])


M_SOURCE = """
contract M {
    struct S { bytes b; uint256 x; }
    struct T { uint256 x; bytes b; }
    function sm(S memory s) external pure returns (uint256) { return s.x ^ s.b.length; }
    function tc(T calldata t) external pure returns (uint256) { return t.x; }
    function am(address[] memory a, bytes memory b) external pure returns (uint256) { return a.length ^ b.length; }
    function bm(uint256[] memory a, bytes memory b) external pure returns (uint256) { return a.length ^ b.length; }
    function cm(uint8[] memory a, string memory b) external pure returns (uint256) { return a.length ^ bytes(b).length; }
}
"""

M_CALLS = [
    ("sm((bytes,uint256))", ((b"abcd", 5),)),
    ("tc((uint256,bytes))", ((5, b"abcd"),)),
    ("am(address[],bytes)", (["0x" + "11" * 20, "0x" + "22" * 20], b"xyz")),
    ("bm(uint256[],bytes)", ([1, 2], b"xyz")),
    ("cm(uint8[],string)", ([1, 2], "xyz")),
]

EDGE_WORDS = (0, 1, 31, 32, 64, 96, (1 << 32) - 1, 1 << 32, (1 << 64) - 1, 1 << 64, (1 << 64) + 64, 1 << 255,
              (1 << 256) - 64, (1 << 256) - 32, (1 << 256) - 1)


def mismatch_summary(bad, n=6):
    """The first mismatches of a differential run, readable: selector, the
    calldata words, (success, output) of the original and the generated."""
    out = [f"{len(bad)} mismatches"]
    for data, _, x, y in bad[:n]:
        words = [data[i:i + 64].lstrip("0") or "0" for i in range(8, len(data), 64)]
        out.append(f"{data[:8]} {' '.join(words)[:300]}: original {x[0]} {x[1].hex()[:72]} / "
                   f"generated {y[0]} {y[1].hex()[:72]}")
    return "\n".join(out)


def mutated_calls(signature, values):
    """The encoding of `values`, every word of it set to each edge value in
    turn, and the encoding cut at every word boundary."""
    from eth_abi import encode as abi_encode
    from probes import selector
    from scobelix.solgen.types import split_types

    types = split_types(signature.split("(", 1)[1][:-1])
    data = abi_encode(types, list(values))
    out = [data]
    for i in range(len(data) // 32):
        for v in EDGE_WORDS:
            out.append(data[:32 * i] + v.to_bytes(32, "big") + data[32 * i + 32:])
    out.extend(data[:k] for k in range(0, len(data), 32))
    return [(selector(signature) + d, 0) for d in out]


@pytest.mark.parametrize("build", [Build("0.8.19"), Build("0.8.19", optimize=False), Build("0.8.31", via_ir=True),
                                   Build("0.8.31", optimize=False, via_ir=True)], ids=lambda b: b.label)
def test_struct_and_copied_memory_parameters_probe(build, monkeypatch):
    # a memory struct keeps the checks of its members (the word at its head
    # offset is no length word); a memory parameter after a memory array is
    # decoded to memory (its checks follow the copy loop of the array); a
    # struct's first member is read as a member, not as a length
    art = compile_probe(M_SOURCE, build, "M")
    patch_signatures(monkeypatch, art.abi)
    r = generate_probe(art.runtime)
    assert set(f["signature"] for f in named_functions(r).values()) == {s for s, _ in M_CALLS}
    calls = [c for s, v in M_CALLS for c in mutated_calls(s, v)]
    bad = differential(art.runtime, r.solidity, r.target_solc, calls)
    assert not bad, mismatch_summary(bad)
    for name in ("am", "bm"):
        assert f"function {name}(" in r.solidity and "bytes memory b)" in function_text(r.solidity, name)
    assert "string memory b)" in function_text(r.solidity, "cm")


O_SOURCE = """
contract O {
    struct S { bytes b; uint256 x; }
    function f1(S memory s, address a) external pure returns (uint256) { return s.x ^ uint160(a); }
    function f2(S memory s, bytes memory b) external pure returns (uint256) { return s.x ^ b.length; }
    function f5(uint8[2] memory x, bytes memory b) external pure returns (uint256) { return x[0] ^ b.length; }
    function f6(bytes memory a, S calldata s) external pure returns (uint256) { return a.length ^ s.x; }
    function f11(S calldata s) external pure returns (uint256) { bytes memory m = s.b; return m.length ^ s.x; }
}
"""

O_CALLS = [
    ("f1((bytes,uint256),address)", ((b"abcd", 5), "0x" + "11" * 20)),
    ("f2((bytes,uint256),bytes)", ((b"abcd", 5), b"xyz")),
    ("f5(uint8[2],bytes)", ([1, 2], b"xyz")),
    ("f6(bytes,(bytes,uint256))", (b"xyz", (b"abcd", 5))),
    ("f11((bytes,uint256))", ((b"abcd", 5),)),
]

PAIR_WORDS = (31, 1 << 64, (1 << 256) - 1)  # a misaligned offset, a length that panics, dirty bits


def pair_mutated_calls(signature, values):
    """Every two words of the encoding set to edge values together: a
    decoder making two checks with different revert data in another order
    differs only on calldata malformed twice."""
    from eth_abi import encode as abi_encode
    from probes import selector
    from scobelix.solgen.types import split_types

    data = abi_encode(split_types(signature.split("(", 1)[1][:-1]), list(values))
    n = len(data) // 32
    out = []
    for i in range(n):
        for j in range(i + 1, n):
            for a in PAIR_WORDS:
                for b in PAIR_WORDS:
                    d = bytearray(data)
                    d[32 * i:32 * i + 32] = a.to_bytes(32, "big")
                    d[32 * j:32 * j + 32] = b.to_bytes(32, "big")
                    out.append((selector(signature) + bytes(d), 0))
    return out


@pytest.mark.parametrize("build", [Build("0.8.19"), Build("0.8.31", via_ir=True)], ids=lambda b: b.label)
def test_decoder_order_with_struct_and_fixed_array_parameters_probe(build, monkeypatch):
    art = compile_probe(O_SOURCE, build, "O")
    patch_signatures(monkeypatch, art.abi)
    r = generate_probe(art.runtime)
    assert set(f["signature"] for f in named_functions(r).values()) == {s for s, _ in O_CALLS}
    calls = [c for s, v in O_CALLS for c in mutated_calls(s, v) + pair_mutated_calls(s, v)]
    bad = differential(art.runtime, r.solidity, r.target_solc, calls)
    assert not bad, mismatch_summary(bad)
    assert "uint8[2] memory x, bytes memory b)" in function_text(r.solidity, "f5")
    assert " calldata s)" in function_text(r.solidity, "f6") and " calldata s)" in function_text(r.solidity, "f11")


def test_crafted_calldata_covers_the_forms():
    cases = calldata_cases("f(address,bytes)")
    assert len(cases) > 40 and all(c[:4] == cases[0][:4] for c in cases if len(c) >= 4)
    assert any(len(c) == 3 for c in cases) and any(len(c) < 36 for c in cases)
    assert len(calldata_cases("g()")) >= 3


# ---------------------------------------------------------------- database signatures

COLLIDING = 0xBB05E3BB  # a166444(uint256) and b775(bytes)
BYTES_ENTRY = {"type": "function", "name": "b775", "inputs": [{"name": "d", "type": "bytes"}],
               "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "pure"}
UINT_ENTRY = {"type": "function", "name": "a166444", "inputs": [{"name": "x", "type": "uint256"}],
              "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "pure"}


def _only_candidate(monkeypatch, entry):
    """The database knows the colliding selector under `entry` only."""
    from scobelix.solgen import sigs

    sig = sigs._from_entry("function", dict(entry), "curated")
    assert sigs.function_selector(sig.signature) == COLLIDING
    monkeypatch.setattr(sigs, "function_candidates", lambda s: (sig,) if s == COLLIDING else ())
    monkeypatch.setattr(sigs, "error_candidates", lambda s, types=None: ())
    monkeypatch.setattr(sigs, "event_candidates", lambda t, n=None: ())


def test_dynamic_candidates_need_the_decoders_offset_check(monkeypatch):
    """A database that knows a selector under another signature than the
    code's: a dynamic type where the decoder reads a value word would add
    the offset / length checks of a dynamic parameter.  A decoder that
    checks the calldata (solc >= 0.5: a head size check) checks the head
    offset of every dynamic parameter (2**64 - 1, ABI coder v1: 2**32)."""

    def entry(*checks, abi_v2=True):
        body = (ir.Return(ir.WordBytes(cd(0))),)
        for c in reversed(checks):
            body = (ir.If(c, (ir.Revert(),), body),)
        fn = ir.Function("0xbb05e3bb", body)
        spec, _ = abi_mod.analyse_entry(fn, fn.key, selector=COLLIDING, payable=False, abi_v2=abi_v2)
        return spec

    _only_candidate(monkeypatch, BYTES_ENTRY)
    for v2 in (True, False):
        spec = entry(head(1, signed=v2), abi_v2=v2)
        assert spec.routed and "signature_rejected" in spec.flags, v2
    assert entry(head(1), ir.Op("gt", (cd(0), B64))).signature == "b775(bytes)"
    assert entry(head(1, signed=False), ir.Op("gt", (cd(0), B32)), abi_v2=False).signature == "b775(bytes)"
    assert entry(head(1), ir.Op("gt", (cd(0), B32))).routed  # under v2: a test of the code, not the decoder's
    # no size check (solc 0.4 decoders check nothing): the policy of the
    # legacy decoders (abi:short_calldata_check) is unchanged
    assert entry(abi_v2=False).signature == "b775(bytes)"
    # a value candidate where the decoder checks a head offset (v1 too)
    _only_candidate(monkeypatch, UINT_ENTRY)
    assert entry(head(1, signed=False), ir.Op("gt", (cd(0), B32)), abi_v2=False).routed
    assert entry(head(1), ir.Op("gt", (cd(0), B64))).routed
    assert entry(head(1)).signature == "a166444(uint256)"


X_SOURCE = """
contract X {
    function a166444(uint256 x) external pure returns (uint256) { return x + 7; }
}
"""


@pytest.mark.parametrize("build", [Build("0.5.17", optimize=False), Build("0.7.6"), Build("0.8.19"),
                                   Build("0.8.31", via_ir=True)], ids=lambda b: b.label)
def test_a_colliding_dynamic_database_signature_is_not_declared_probe(build, monkeypatch):
    art = compile_probe(X_SOURCE, build, "X")
    _only_candidate(monkeypatch, BYTES_ENTRY)
    r = generate_probe(art.runtime)
    f = next(f for f in r.functions.values() if f.get("selector") == "0xbb05e3bb")
    assert f["routed"] and "signature_rejected" in f["flags"], f
    calls = mutated_calls("a166444(uint256)", (5,)) + mutated_calls("b775(bytes)", (b"abc",))
    bad = differential(art.runtime, r.solidity, r.target_solc, calls)
    assert not bad, mismatch_summary(bad)


ARRAY_COLLIDING = 0xAD52B7B0  # a294937(bytes) and b6023(uint256[])
ARRAY_ENTRIES = {
    "bytes": {"type": "function", "name": "a294937", "inputs": [{"name": "d", "type": "bytes"}],
              "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "pure"},
    "array": {"type": "function", "name": "b6023", "inputs": [{"name": "x", "type": "uint256[]"}],
              "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "pure"},
    "struct": {"type": "function", "name": "a294937", "inputs": [{"name": "s", "type": "tuple", "components": [
        {"name": "x", "type": "uint256"}, {"name": "b", "type": "bytes"}]}], "outputs": [], "stateMutability": "pure"},
}


def test_dynamic_candidates_need_the_stride_of_the_decoders_bounds_check(monkeypatch):
    """The bounds check of a dynamic parameter's data multiplies its length
    by the element size (1 for bytes / string, 32 for uint256[] ...): a
    candidate of another dynamic type would check other bounds (a bytes
    parameter declared uint256[] rejects any length above calldatasize / 32)."""
    from scobelix.solgen import sigs

    def only(kind):
        sig = sigs._from_entry("function", dict(ARRAY_ENTRIES[kind]), "curated")
        monkeypatch.setattr(sigs, "function_candidates", lambda s: (sig,))
        return sig.signature

    def entry(scaled):
        off = cd(0)
        checks = [head(1), ir.Op("gt", (off, B64)),
                  ir.Op("iszero", (ir.Op("slt", (ir.Op("add", (ir.Const(35), off)), CDS)),)),
                  ir.Op("gt", (length_word(0), B64))]
        if scaled is not None:
            checks.append(ir.Op("gt", (ir.Op("add", (ir.Const(36), off, scaled)), CDS)))
        body = (ir.Return(ir.WordBytes(length_word(0))),)
        for c in reversed(checks):
            body = (ir.If(c, (ir.Revert(),), body),)
        fn = ir.Function("0xad52b7b0", body)
        return abi_mod.analyse_entry(fn, fn.key, selector=ARRAY_COLLIDING, payable=False, abi_v2=True)[0]

    by_bytes = length_word(0)
    by_words = ir.Op("shl", (ir.Const(5), length_word(0)))
    text = only("bytes")
    assert entry(by_bytes).signature == text and entry(by_words).routed
    text = only("array")
    assert entry(by_words).signature == text and entry(by_bytes).routed
    only("struct")  # no length word at the head offset of a struct
    assert entry(by_bytes).routed
    # without a recognised bounds check the stride is no evidence either way
    assert entry(None).signature is not None


A_SOURCE = """
contract A {
    function a294937(bytes calldata d) external pure returns (uint256) { return d.length; }
}
"""


@pytest.mark.parametrize("build", [Build("0.7.6"), Build("0.8.19"), Build("0.8.31", via_ir=True)],
                         ids=lambda b: b.label)
def test_a_colliding_database_signature_of_another_dynamic_type_is_not_declared_probe(build, monkeypatch):
    from scobelix.solgen import sigs

    art = compile_probe(A_SOURCE, build, "A")
    sig = sigs._from_entry("function", dict(ARRAY_ENTRIES["array"]), "curated")
    monkeypatch.setattr(sigs, "function_candidates", lambda s: (sig,) if s == ARRAY_COLLIDING else ())
    monkeypatch.setattr(sigs, "error_candidates", lambda s, types=None: ())
    monkeypatch.setattr(sigs, "event_candidates", lambda t, n=None: ())
    r = generate_probe(art.runtime)
    f = next(f for f in r.functions.values() if f.get("selector") == "0xad52b7b0")
    assert f["routed"] and "signature_rejected" in f["flags"], f
    calls = mutated_calls("a294937(bytes)", (b"abc",)) + mutated_calls("a294937(bytes)", (bytes(range(40)),))
    bad = differential(art.runtime, r.solidity, r.target_solc, calls)
    assert not bad, mismatch_summary(bad)


Q_SOURCE = """
pragma experimental ABIEncoderV2;
contract Q {
    struct S { bytes b; uint256 x; }
    struct T { uint256[] a; uint256 y; }
    function f1(S memory s, uint8 a) external pure returns (uint256) { return s.x ^ a; }
    function f2(T memory t, uint8 a) external pure returns (uint256) { return t.y ^ t.a.length ^ a; }
    function f3(S memory s, bytes memory b, uint8 a) external pure returns (uint256) { return s.x ^ b.length ^ a; }
}
"""

Q_CALLS = [
    ("f1((bytes,uint256),uint8)", ((b"abcd", 5), 7)),
    ("f2((uint256[],uint256),uint8)", (([1, 2], 5), 7)),
    ("f3((bytes,uint256),bytes,uint8)", ((b"abcd", 5), b"xyz", 7)),
]


@pytest.mark.parametrize("build", [Build("0.6.12"), Build("0.7.6", optimize=False)], ids=lambda b: b.label)
def test_memory_structs_of_pre_08_coder_v2_originals_probe(build, monkeypatch):
    # before 0.8 a decoder reverts without data where a 0.8 memory decoder
    # raises Panic(0x41) (the allocation of a struct's dynamic member): such
    # a struct is declared calldata (the target's checks are then a prefix,
    # all without data, of the original's)
    art = compile_probe(Q_SOURCE, build, "Q")
    patch_signatures(monkeypatch, art.abi)
    r = generate_probe(art.runtime)
    assert set(f["signature"] for f in named_functions(r).values()) == {s for s, _ in Q_CALLS}
    calls = [c for s, v in Q_CALLS for c in mutated_calls(s, v) + pair_mutated_calls(s, v)]
    bad = differential(art.runtime, r.solidity, r.target_solc, calls)
    assert not bad, mismatch_summary(bad)


def test_signed_size_checks_are_abi_coder_v2():
    """Before 0.8 `pragma abicoder v2` leaves no trace in the CBOR data: a
    v2 decoder is told by a validator or by its signed size check (v1
    compares unsigned)."""

    def fn(*checks):
        body = (ir.Return(ir.WordBytes(cd(0))),)
        for c in reversed(checks):
            body = (ir.If(c, (ir.Revert(),), body),)
        return ir.Function("0x00000001", body)

    assert abi_mod.uses_abi_v2([fn(head(1))])
    assert not abi_mod.uses_abi_v2([fn(head(1, signed=False)), fn()])
    assert abi_mod.uses_abi_v2([fn(head(1, signed=False), legacy(0, lambda p: ir.Mask(8, 0, 0, p)))])


C2V2_SOURCE = """
pragma abicoder v2;
contract C {
    struct S { bytes b; uint256 x; }
    struct T { uint256 x; bytes b; }
    function sm(S memory s) external pure returns (uint256) { return s.x ^ s.b.length; }
    function sc(S calldata s) external pure returns (uint256) { return s.x ^ s.b.length; }
    function tm(T memory s) external pure returns (uint256) { return s.x ^ s.b.length; }
    function dm(bytes[] memory a) external pure returns (uint256) { return a.length; }
    function am(address[] memory a, bytes memory b) external pure returns (uint256) { return a.length ^ b.length; }
}
"""

C2V2_CALLS = [
    ("sm((bytes,uint256))", ((b"abcd", 5),)),
    ("sc((bytes,uint256))", ((b"abcd", 5),)),
    ("tm((uint256,bytes))", ((5, b"abcd"),)),
    ("dm(bytes[])", ([b"ab", b"c"],)),
    ("am(address[],bytes)", (["0x" + "11" * 20, "0x" + "22" * 20], b"xyz")),
]


@pytest.mark.parametrize("build", [Build("0.7.6"), Build("0.7.6", optimize=False)], ids=lambda b: b.label)
def test_pre_08_coder_v2_without_narrow_parameters_probe(build, monkeypatch):
    # `pragma abicoder v2` (0.7.5+) is not in the CBOR data and no parameter
    # is narrow: the signed size checks tell the v2 decoders, so the structs
    # and arrays of dynamic types keep their names
    art = compile_probe(C2V2_SOURCE, build, "C")
    patch_signatures(monkeypatch, art.abi)
    r = generate_probe(art.runtime)
    assert set(f["signature"] for f in named_functions(r).values()) == {s for s, _ in C2V2_CALLS}
    assert "pragma abicoder v1" not in r.solidity
    calls = [c for s, v in C2V2_CALLS for c in mutated_calls(s, v) + pair_mutated_calls(s, v)]
    bad = differential(art.runtime, r.solidity, r.target_solc, calls)
    assert not bad, mismatch_summary(bad)


def test_validated_members_of_static_composites_match_their_leaf_types():
    """The memory decoder of a static struct (or the body's first member
    reads of a calldata one) validates its members in the leading chain:
    each head word is compared with the member's type, not the struct's."""
    from scobelix.solgen import sigs

    def cand(text):
        name, rest = text.split("(", 1)
        types = parse_type("(" + rest).components if rest != ")" else ()
        return sigs.Signature("function", name, tuple((t.canonical, f"p{i}") for i, t in enumerate(types)), text)

    s = cand("f((address,uint8))")
    assert abi_mod._choose([s], 2, {0: "address", 1: "uint8"}, frozenset(), strict=True) is s
    assert abi_mod._choose([s], 2, {0: "uint8"}, frozenset(), strict=True) is None  # a member of another type
    c = cand("c(uint8[2],uint8)")
    assert abi_mod._choose([c], 3, {0: "uint8", 1: "uint8", 2: "uint8"}, frozenset(), strict=True) is c
    assert abi_mod._choose([c], 3, {0: "uint8", 1: "uint8"}, frozenset(), strict=True) is None  # y unvalidated
    assert abi_mod._choose([c], 3, {0: "address"}, frozenset(), strict=True) is None
    n = cand("g((uint256,(bool,bytes4)[2]),int16)")
    inferred = {1: "bool", 2: "bytes4", 3: "bool", 4: "bytes4", 5: "int16"}
    assert abi_mod._choose([n], 6, inferred, frozenset(), strict=True) is n
    assert abi_mod._choose([n], 6, {**inferred, 2: "bool"}, frozenset(), strict=True) is None


S_SOURCE = """
contract SS {
    struct S { address a; uint8 b; }
    struct T { uint256 x; bool f; bytes4 g; }
    function f1(S calldata s) external view returns (bool) { return s.a == msg.sender; }
    function f2(S memory s) external pure returns (uint256) { return uint160(s.a) ^ s.b; }
    function f3(T calldata t, uint8 k) external pure returns (uint256) { return t.f ? t.x : k; }
    function f5(S calldata s, bytes calldata d) external pure returns (uint256) { return s.b ^ d.length; }
    function f6(T memory t) external pure returns (bytes4) { return t.g; }
    function f7(uint8 k, S memory s) external pure returns (uint256) { return k ^ s.b; }
    function f8(uint8[2] calldata x, uint8 y) external pure returns (uint256) { return uint256(x[0]) ^ x[1] ^ y; }
}
"""

S_CALLS = [
    ("f1((address,uint8))", (("0x" + "a1" * 20, 3),)),
    ("f2((address,uint8))", (("0x" + "11" * 20, 3),)),
    ("f3((uint256,bool,bytes4),uint8)", ((5, True, b"\x01\x02\x03\x04"), 7)),
    ("f5((address,uint8),bytes)", (("0x" + "11" * 20, 3), b"xyz")),
    ("f6((uint256,bool,bytes4))", ((5, False, b"\x01\x02\x03\x04"),)),
    ("f7(uint8,(address,uint8))", (4, ("0x" + "11" * 20, 3))),
    ("f8(uint8[2],uint8)", ([1, 2], 3)),
]


@pytest.mark.parametrize("build", [Build("0.8.19"), Build("0.8.19", optimize=False), Build("0.8.31", via_ir=True),
                                   Build("0.7.6", abicoder="v2")], ids=lambda b: b.label)
def test_static_struct_and_fixed_array_parameters_probe(build, monkeypatch):
    art = compile_probe(S_SOURCE, build, "SS")
    patch_signatures(monkeypatch, art.abi)
    r = generate_probe(art.runtime)
    assert set(f["signature"] for f in named_functions(r).values()) == {s for s, _ in S_CALLS}
    calls = [c for s, v in S_CALLS for c in mutated_calls(s, v) + pair_mutated_calls(s, v)]
    bad = differential(art.runtime, r.solidity, r.target_solc, calls)
    assert not bad, mismatch_summary(bad)


# ---------------------------------------------------------------- `pragma abicoder v1` under solc 0.8


def test_abi_coder_v1_decoders_are_recognised():
    """ABI coder v1 checks the head size unsigned (`lt`; v2 writes `slt`)
    and validates no parameter."""

    def fn(*checks):
        body = (ir.Return(ir.WordBytes(cd(0))),)
        for c in reversed(checks):
            body = (ir.If(c, (ir.Revert(),), body),)
        return ir.Function("0x00000001", body)

    assert abi_mod.uses_abi_v1([fn(head(1, signed=False)), fn()])
    assert not abi_mod.uses_abi_v1([fn(head(1, signed=False)), fn(head(2))])  # one v2 decoder
    assert not abi_mod.uses_abi_v1([fn(head(1, signed=False), legacy(0, lambda p: ir.Mask(8, 0, 0, p)))])
    assert not abi_mod.uses_abi_v1([fn()])  # no decoder: no evidence


V1_PRAGMA_SOURCE = """
pragma abicoder v1;
contract P {
    function a(bytes memory d) external pure returns (uint256) { return d.length; }
    function b(uint256[] memory d, uint8 k) external pure returns (uint256) { return d.length ^ k; }
    function c(uint8[2] memory x) external pure returns (uint256) { return uint256(x[0]) ^ x[1]; }
    function g(uint8 v, address w) external pure returns (uint256) { return v ^ uint160(w); }
}
"""

V1_PRAGMA_CALLS = [
    ("a(bytes)", (b"abcd",)),
    ("b(uint256[],uint8)", ([1, 2], 3)),
    ("c(uint8[2])", ([1, 2],)),
    ("g(uint8,address)", (5, "0x" + "11" * 20)),
]


@pytest.mark.parametrize("build", [Build("0.8.19"), Build("0.8.31", optimize=False)], ids=lambda b: b.label)
def test_abi_coder_v1_pragma_under_solc_08_probe(build, monkeypatch):
    # the CBOR says 0.8 (v2 by default) but the decoders are v1: the output
    # declares `pragma abicoder v1`, so the narrow parameters the v1 decoder
    # does not validate keep their names, and the v1 checks go
    art = compile_probe(V1_PRAGMA_SOURCE, build, "P")
    patch_signatures(monkeypatch, art.abi)
    r = generate_probe(art.runtime)
    named = named_functions(r)
    assert set(f["signature"] for f in named.values()) == {s for s, _ in V1_PRAGMA_CALLS}
    assert "pragma abicoder v1;" in r.solidity
    for f in named.values():
        assert f["abi"]["prologue_removed"], (f["signature"], f["abi"])
    calls = [c for s, v in V1_PRAGMA_CALLS for c in mutated_calls(s, v)]
    bad = differential(art.runtime, r.solidity, r.target_solc, calls)
    assert not bad, mismatch_summary(bad)


# ---------------------------------------------------------------- mutability of constant getters


CONSTANTS = """
contract Constants {
    uint256 public constant PRICE = 0.1 ether;
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    string public constant NAME = "Constants";
    uint256 public constant fee = 3;
    uint256 public total;

    function pureFee() external pure returns (uint256) { return 4; }
    function viewer(uint256 x) external view returns (uint256) { return x + total; }
    function plain(uint256 x) external pure returns (uint256) { return x * 2; }
    function buy() external payable { total += msg.value; }
}
"""

CONSTANTS_CALLS = ["PRICE()", "OPERATOR_ROLE()", "NAME()", "fee()", "total()", "pureFee()", "viewer(uint256)",
                   "plain(uint256)", "buy()"]


LEGACY = """
contract Legacy {
    address public admin;
    string public label;
    function setAdmin(address a) public { admin = a; }
    function labelLength(string s) public pure returns (uint256) { return bytes(s).length; }
}
"""


def test_legacy_decoder_differences_are_explained_in_the_text(monkeypatch):
    """A solc 0.4 original keeps its function names (selectors are sacred,
    the declared ABI with them), but its decoder reads missing arguments as
    zeros and copies reference parameters to memory unchecked: what the
    target's decoder cannot reproduce is said on each function concerned."""
    art = compile_probe(LEGACY, Build("0.4.26"), "Legacy")
    patch_signatures(monkeypatch, art.abi)
    r = generate_probe(art.runtime)
    short = "decoder (solc < 0.5) reads the arguments missing from short calldata as zeros"
    copy = "copies dynamic arguments to memory without bounds checks"
    admin = r.solidity[:r.solidity.index("function setAdmin(")]
    assert short in admin.rsplit("@notice", 1)[1], r.solidity
    label = r.solidity[:r.solidity.index("function labelLength(")].rsplit("@notice", 1)[1]
    assert short in label and copy in label, r.solidity
    getter = r.solidity[:r.solidity.index("function label(")].rsplit("@notice", 1)[1]  # (no parameter)
    assert short not in getter and copy not in getter


@pytest.mark.parametrize("build", [Build("0.8.19"), pytest.param(Build("0.8.19", optimize=False), marks=pytest.mark.slow)],
                         ids=lambda b: b.label)
def test_public_constants_are_view_when_the_contract_has_a_payable_function(build, monkeypatch):
    """With a payable function in the contract every other function checks
    the call value itself: a constant getter is judged once that check is
    stripped (UPPER_CASE public constants, a string constant among them, are
    `view` as in the original's ABI).  A lowercase constant cannot be told
    from a pure function returning a literal: `pure`."""
    from conftest import compile_or_fail

    art = compile_probe(CONSTANTS, build, "Constants")
    # (as most database rows: names and types, no mutability)
    patch_signatures(monkeypatch, [{k: v for k, v in x.items() if k != "stateMutability"} for x in art.abi])
    r = generate_probe(art.runtime)

    def mutabilities(abi):
        return {x["name"]: x["stateMutability"] for x in abi if x.get("type") == "function"}

    want, got = mutabilities(art.abi), mutabilities(compile_or_fail(r.solidity, r.target_solc).abi)
    for name in ("PRICE", "OPERATOR_ROLE", "NAME", "pureFee", "viewer", "plain", "buy", "total"):
        assert got.get(name) == want[name], (name, got.get(name), want[name], r.solidity)
    assert got.get("fee") == "pure"
    calls = [(c, 0) for s in CONSTANTS_CALLS for c in calldata_cases(s)]
    bad = differential(art.runtime, r.solidity, r.target_solc, calls)
    assert not bad, bad[:2]

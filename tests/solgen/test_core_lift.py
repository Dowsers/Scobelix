"""
The lifter: every node kind of the trace grammar, in the raw and the json
vocabularies, and robustness (unknown shapes become Unstructured nodes,
flagged; nothing raises).
"""

import pytest

from scobelix.solgen import ir, lift

CTX = lift.LiftContext()
A = ir.CalldataWord(ir.Const(4))
B = ir.CalldataWord(ir.Const(36))
HI = int.from_bytes(b"hi".ljust(32, b"\0"), "big")


def one(trace, ctx=CTX, params=None):
    fn = lift.lift_function("0x12345678", trace, ctx, params)
    return fn


def expr(e, ctx=CTX):
    """`e` lifted in a word context (an if condition)."""
    fn = one([("if", e, [("stop",)], [("stop",)])], ctx)
    (stmt,) = fn.body
    return stmt.cond, fn.flags


# ---------------------------------------------------------------- statements


def test_statement_kinds():
    trace = [
        ("setmem", ("range", 64, 32), 128),
        ("setvar", "_5", ("storage", 256, 0, 3)),
        ("store", 8, 264, 2, ("var", "_5")),
        ("tstore", ("cd", 4), 1),
        ("log", ("data", ("cd", 4), ("cd", 36)), 0xDDF2, "caller"),
        ("call", "gas", ("cd", 4), "callvalue", None, ("data", ("bytes", 4, 0xA9059CBB), ("cd", 36))),
        ("if", ("iszero", "ext_call.success"),
         [("revert", ("ext_call.return_data", 0, "returndatasize"))],
         [("selfdestruct", "caller")]),
    ]
    fn = one(trace)
    mstore, setvar, store, tstore, log, call, branch = fn.body
    assert mstore == ir.Mstore(ir.Const(64), ir.WordBytes(ir.Const(128)))
    assert setvar == ir.Assign(ir.Local("t5"), ir.Sload(ir.Const(3)))
    # offset 264 = slot + 1, bit 8
    assert store == ir.Sstore(ir.Op("add", (ir.Const(2), ir.Const(1))), ir.Local("t5"), 8, 8)
    assert tstore == ir.TStore(A, ir.ONE)
    assert log == ir.Log((ir.Const(0xDDF2), ir.Env("caller")), ir.Blob((ir.WordBytes(A), ir.WordBytes(B))))
    assert call.kind == "call" and call.selector is None and call.value == ir.Env("callvalue")
    assert call.gas is None and call.args == ir.Blob((ir.WordBytes(ir.Const(0xA9059CBB), 4), ir.WordBytes(B)))
    assert branch.cond == ir.Op("iszero", (ir.CallOut(call.call_id, "success"),))
    assert branch.then == (ir.Revert(ir.Bubble(call.call_id)),)
    assert branch.orelse == (ir.SelfDestruct(ir.Env("caller")),)
    assert not fn.flags


def test_terminators_and_markers():
    fn = one([("jd", 12, ()), "debug text", ("if", 1, [("stop",)], [("invalid",)])])
    assert fn.body == (ir.If(ir.ONE, (ir.Stop(),), (ir.Invalid(""),)),)
    assert one([("undefined", "decompilation didn't finish")]).flags >= {"unstructured"}
    assert one([("invalid", "jumpdest")]).body == (ir.Invalid("jumpdest"),)


def test_empty_data_and_zero_words():
    # empty data is None; `return 0` / `revert 0` are one zero word
    assert one([("return", None)]).body == (ir.Return(),)
    assert one([("revert", None)]).body == (ir.Revert(ir.Empty()),)
    fn = one([("return", 0)])
    assert fn.body == (ir.Return(ir.WordBytes(ir.ZERO)),) and not fn.flags
    assert one([("revert", 0)]).body == (ir.Revert(ir.Raw(ir.WordBytes(ir.ZERO))),)


def test_while_continue_parallel_setvars():
    jd = "Node((83, 6, ('60',)))"
    trace = [("while", ("lt", ("var", 0), ("cd", 4)),
              [("continue", jd, (("setvar", 0, ("add", 1, ("var", 0))), ("setvar", 1, ("var", 0))))],
              jd, [("setvar", 0, 0), ("setvar", 1, 0)]),
             ("return", ("var", 1))]
    fn = one(trace)
    loop, ret = fn.body
    assert loop.loop_id == jd and loop.init == (ir.Assign(ir.Local("v0"), ir.ZERO), ir.Assign(ir.Local("v1"), ir.ZERO))
    (cont,) = loop.body
    assert cont == ir.Continue(jd, (ir.Assign(ir.Local("v0"), ir.Op("add", (ir.ONE, ir.Local("v0")))),
                                    ir.Assign(ir.Local("v1"), ir.Local("v0"))))
    assert "loop_exit_unstructured" not in fn.flags and "engine:dangling_var" not in fn.flags


def test_label_with_back_edge_becomes_while_true():
    jd = "Node((452, 4, ('226',)))"
    trace = [("label", jd, [("setvar", 10001, 0)]),
             ("if", ("lt", ("var", 10001), 5),
              [("continue", jd, [("setvar", 10001, ("add", 2, ("var", 10001)))])],
              [("return", ("var", 10001))])]
    fn = one(trace)
    (loop,) = fn.body
    assert isinstance(loop, ir.While) and loop.cond == ir.ONE and loop.loop_id == jd
    assert "label_lowered" in fn.flags


def test_label_without_back_edge_is_a_marker():
    fn = one([("label", "Node((1, 1, ()))", []), ("stop",)])
    assert fn.body == (ir.Stop(),)


def test_calls_of_every_kind():
    fn = one([
        ("staticcall", "gas", ("cd", 4), 0, None, ("data", ("bytes", 4, 0x70A08231), ("cd", 36))),
        ("delegatecall", 5000, ("cd", 4), None, ("call.data", 0, "calldatasize")),
        ("callcode", "gas", ("cd", 4), 0, None, ("mem", ("range", 128, 4))),
        ("create2", "callvalue", ("bytes", 2, 0x6080), ("cd", 36)),
        ("precompiled", "signer", "erecover", ("data", 1, 2, 3, 4)),
        ("return", ("data", ("var", "signer"), "create2.new_address", ("var", "delegatecall_7.success"),
                    "callcode.return_code", "erecover.result")),
    ])
    st, dc, cc, cr, pc, ret = fn.body
    assert st.kind == "staticcall" and st.value is None
    assert st.args == ir.Blob((ir.WordBytes(ir.Const(0x70A08231), 4), ir.WordBytes(B)))
    # forwarded calldata: one slice for any calldata size
    assert dc.kind == "delegatecall" and dc.gas == ir.Const(5000)
    assert dc.args == ir.CalldataSlice(ir.ZERO, ir.Env("calldatasize"))
    assert cc.kind == "callcode" and cc.args == ir.MemSlice(ir.Const(128), ir.Const(4))
    assert isinstance(cr, ir.Create) and cr.salt == B and cr.code == ir.WordBytes(ir.Const(0x6080), 2)
    assert pc == ir.Precompile(pc.call_id, 1, "erecover", pc.args, "signer_" + str(pc.call_id))
    words = [p.value for p in ret.data.parts]
    assert words == [ir.Local(pc.output), ir.CallOut(cr.call_id, "address"), ir.CallOut(dc.call_id, "success"),
                     ir.CallOut(cc.call_id, "success"), ir.CallOut(pc.call_id, "success")]
    assert not fn.flags


def test_call_results_without_a_call_are_unstructured():
    value, flags = expr("ext_call.success")
    assert isinstance(value, ir.UnstructuredExpr) and "unstructured" in flags


# ---------------------------------------------------------------- expressions


@pytest.mark.parametrize("trace, expected", [
    (("add", 1, ("cd", 4), -1), ir.Op("add", (ir.ONE, A, ir.Const(ir.WORD_MAX)))),
    (("mul", -1, ("cd", 4)), ir.Op("mul", (ir.Const(ir.WORD_MAX), A))),
    (("le", ("cd", 4), 3), ir.Op("iszero", (ir.Op("gt", (A, ir.Const(3))),))),
    (("sge", ("cd", 4), 3), ir.Op("iszero", (ir.Op("slt", (A, ir.Const(3))),))),
    (("bool", ("cd", 4)), ir.Op("iszero", (ir.Op("iszero", (A,)),))),
    (("max", ("cd", 4), 64), ir.Ternary(ir.Op("gt", (ir.Const(64), A)), ir.Const(64), A)),
    (("sha3", ("data", ("cd", 4), 1)), ir.Keccak(ir.Blob((ir.WordBytes(A), ir.WordBytes(ir.ONE))))),
    (("sha3", 0), ir.Keccak(ir.WordBytes(ir.ZERO))),
    (("storage", 160, 8, 0), ir.Field(ir.Sload(ir.ZERO), 8, 160)),
    (("storage", 8, 424, ("sha3", ("data", ("cd", 4), 0))),
     ir.Field(ir.Sload(ir.Op("add", (ir.Keccak(ir.Blob((ir.WordBytes(A), ir.WordBytes(ir.ZERO)))), ir.ONE))), 168, 8)),
    (("mask_shl", 160, 0, 0, ("cd", 4)), ir.Mask(160, 0, 0, A)),
    (("mask_shl", 32, ("mul", -1, ("cd", 36)), 0, ("cd", 4)),
     ir.Mask(32, ir.Op("sub", (ir.ZERO, B)), 0, A)),
    (("balance", "address"), ir.Balance(ir.Env("address"))),
    (("extcodesize", ("cd", 4)), ir.ExtCodeSize(A)),
    (("extcodehash", ("cd", 4)), ir.ExtCodeHash(A)),
    (("blockhash", "number"), ir.BlockHash(ir.Env("number"))),
    (("blobhash", 0), ir.BlobHash(ir.ZERO)),
    (("tload", 7), ir.TLoad(ir.Const(7))),
    (("mem", ("range", 128, 32)), ir.MLoad(ir.Const(128))),
    (("mem", ("range", 132, 4)), ir.BytesWord(ir.MemSlice(ir.Const(132), ir.Const(4)))),
    (("call.data", 0, 4), ir.BytesWord(ir.CalldataSlice(ir.ZERO, ir.Const(4)))),
    (True, ir.ONE),
    (-1, ir.Const(ir.WORD_MAX)),
    ("prevrandao", ir.Env("prevrandao")),
    ("returndatasize", ir.CallOut(0, "returndatasize")),
    (("sar", 3, ("cd", 4)), ir.Op("sar", (ir.Const(3), A))),
    (("addmod", ("cd", 4), 1, 7), ir.Op("addmod", (A, ir.ONE, ir.Const(7)))),
    (("mulmod", ("cd", 4), 1, 7), ir.Op("mulmod", (A, ir.ONE, ir.Const(7)))),
    (("shr", 3, ("cd", 4)), ir.Op("shr", (ir.Const(3), A))),
    (("sub", ("cd", 4), 1), ir.Op("sub", (A, ir.ONE))),
    (("mask_shl", 253, 3, -3, ("cd", 4)), ir.Mask(253, 3, -3, A)),
])
def test_expressions(trace, expected):
    value, flags = expr(trace)
    assert value == expected and not flags


def test_shifts_are_exact_masks():
    value, flags = expr(("mask_shl", 252, 4, -4, ("cd", 4)))  # the engine's SHR by 4
    assert value == ir.Mask(252, 4, -4, A) and not flags
    x = 0xF123456789ABCDEF << 190
    assert ir.evaluate(ir.Mask(252, 4, -4, ir.Const(x))) == x >> 4
    # a negative offset is unexpected: kept exact, flagged
    value, flags = expr(("mask_shl", 256, -4, -4, ("cd", 4)))
    assert value == ir.Mask(256, -4, -4, A) and "engine:negative_mask_offset" in flags


def test_dangling_variable_is_flagged():
    _, flags = expr(("var", "_9"))
    assert "engine:dangling_var" in flags


# ---------------------------------------------------------------- bytes and payloads


def test_blob_widths():
    fn = one([("return", ("data", ("mask_shl", 32, 224, -224, ("cd", 0)), ("call.data", 4, 7),
                          ("mem", ("range", 128, ("cd", 4))), 2**300))])
    (ret,) = fn.body
    sel, cd, mem, wide = ret.data.parts
    assert sel == ir.WordBytes(ir.Mask(32, 224, -224, ir.CalldataWord(ir.ZERO)))  # any word: 32 bytes
    assert cd == ir.CalldataSlice(ir.Const(4), ir.Const(7))
    assert mem == ir.MemSlice(ir.Const(128), A)
    assert wide == ir.ConstBytes((2**300).to_bytes(38, "big")) and "codecopy_blob" in fn.flags


def test_arr_expands_to_the_abi_tail():
    trace = [("return", ("data", ("arr", ("cd", ("add", 4, ("cd", 4))),
                                  ("call.data", ("add", 36, ("cd", 4)), ("cd", ("add", 4, ("cd", 4)))))))]
    fn = one(trace)
    (ret,) = fn.body
    offset, length, payload, padding = ret.data.parts
    assert offset == ir.WordBytes(ir.Const(32)) and isinstance(payload, ir.CalldataSlice)
    assert isinstance(padding, ir.ZeroBytes) and "arr_expanded" in fn.flags


@pytest.mark.parametrize("count, size, padding", [
    (5, 5, 27),  # bytes: 5 of them, padded to a word
    (32, 32, 0),
    (3, 96, 0),  # a word array: 3 elements are 96 bytes, which the ABI does not pad
    (1, 32, 0),
    (0, 0, 0),
])
def test_arr_pads_the_bytes_of_its_payload(count, size, padding):
    fn = one([("return", ("data", ("arr", count, ("mem", ("range", 160, size)))))])
    (ret,) = fn.body
    offset, length, payload, pad = ret.data.parts
    assert length == ir.WordBytes(ir.Const(count)) and payload == ir.MemSlice(ir.Const(160), ir.Const(size))
    assert isinstance(pad, ir.ZeroBytes) and ir.evaluate(pad.length) == padding


def test_arr_padding_follows_the_length_of_the_slice():
    # L elements read from calldata, copied as a slice of 32 L bytes
    count = ("cd", ("add", 4, ("cd", 4)))
    fn = one([("return", ("data", ("arr", count, ("mem", ("range", 160, ("mul", 32, count))))))])
    (ret,) = fn.body
    _, length, payload, pad = ret.data.parts
    assert isinstance(payload, ir.MemSlice) and payload.length != length.value
    assert pad == ir.ZeroBytes(ir.Op("and", (ir.Op("sub", (ir.ZERO, payload.length)), ir.Const(31))))


@pytest.mark.parametrize("payload, expected", [
    (("data", ("bytes", 4, 0x4E487B71), 17), ir.Panic(17)),
    (("data", ("bytes", 4, 0x08C379A0), 32, 2, HI), ir.ErrorString(b"hi")),
    (("bytes", 4, 0xDEADBEEF), ir.Custom(0xDEADBEEF)),
    (("data", ("bytes", 4, 0xDA472023), "caller", ("cd", 4)),
     ir.Custom(0xDA472023, (ir.WordBytes(ir.Env("caller")), ir.WordBytes(A)))),
    # without a `bytes 4` part the first element is a whole word
    (("data", 0x4E487B71, 17), ir.Raw(ir.Blob((ir.WordBytes(ir.Const(0x4E487B71)), ir.WordBytes(ir.Const(17)))))),
    (17, ir.Raw(ir.WordBytes(ir.Const(17)))),
    (0, ir.Raw(ir.WordBytes(ir.ZERO))),
    (None, ir.Empty()),
    (("ext_call.return_data", 0, "returndatasize"), ir.Bubble(0)),
])
def test_revert_payloads(payload, expected):
    fn = one([("revert", payload)])
    assert fn.body == (ir.Revert(expected),) and "unstructured" not in fn.flags


def test_long_error_strings():
    msg = b"a revert reason longer than thirty-two bytes"
    n = len(msg)
    payload = ("data", ("bytes", 4, 0x08C379A0), 32, n, ("bytes", n, int.from_bytes(msg, "big")), ("bytes", 64 - n, 0))
    fn = one([("revert", payload)])
    assert fn.body == (ir.Revert(ir.ErrorString(msg)),) and not fn.flags
    # a padding byte read from memory: not a constant message, kept as exact bytes, nothing untranslated
    payload = ("data", ("bytes", 4, 0x08C379A0), 32, 63, ("bytes", 63, 2**300 + 1), ("mem", ("range", 259, 1)))
    fn = one([("revert", payload)])
    assert isinstance(fn.body[0].payload, ir.Custom) and "unstructured" not in fn.flags


def test_explicit_width_parts():
    packed = ("return", ("sha3", ("data", ("bytes", 20, ("mask_shl", 160, 0, 0, ("cd", 4))), ("cd", 36))))
    keccak = one([packed]).body[0].data.value
    assert keccak.data == ir.Blob((ir.WordBytes(ir.Mask(160, 0, 0, A), 20), ir.WordBytes(B)))
    fn = one([("return", ("data", ("bytes", 1, ("mask_shl", 8, 0, 0, ("cd", 4))), ("mem", ("range", 1, 31)),
                          ("bytes", 7, 0), ("bytes", ("cd", 4), 0), ("bytes", 32, ("mem", ("range", 0, 4))),
                          ("bytes", 36, ("cd", 36)), ("bytes", 3, 2**300 + 5)))])
    assert fn.body[0].data.parts == (
        ir.WordBytes(ir.Mask(8, 0, 0, A), 1), ir.MemSlice(ir.ONE, ir.Const(31)), ir.ZeroBytes(ir.Const(7)),
        ir.ZeroBytes(A), ir.ZeroBytes(ir.Const(28)), ir.MemSlice(ir.ZERO, ir.Const(4)),
        ir.ZeroBytes(ir.Const(4)), ir.WordBytes(B), ir.ConstBytes(b"\0\0\x05"))
    assert not fn.flags
    fn = one([("return", ("data", ("bytes", ("cd", 36), ("cd", 4)), ("bytes", ("cd", 36), ("mem", ("range", 0, 9)))))])
    # a byte string cut to a symbolic width: its last W bytes (zero bytes on the left past it)
    assert fn.body[0].data.parts == (ir.WordSlice(A, B), ir.MaskBytes(None, 0, 0, ir.MemSlice(ir.ZERO, ir.Const(9)), B))
    assert "unstructured" not in fn.flags
    assert ir.const_bytes(ir.WordSlice(ir.Const(0x0102), ir.Const(3))) == b"\0\1\2"
    assert ir.const_bytes(ir.WordSlice(ir.Const(7), ir.Const(34))) == bytes(33) + b"\7"
    # as a word: the value of the low W bytes
    value, _ = expr(("eq", ("bytes", 4, ("cd", 4)), ("bytes", 32, ("cd", 36))))
    assert value == ir.Op("eq", (ir.Mask(32, 0, 0, A), B))


def test_setmem_widths():
    fn = one([("setmem", ("range", 128, 8), ("cd", 4)), ("setmem", ("range", 0, 1), 65),
              ("setmem", ("range", 0, ("cd", 4)), 0), ("setmem", ("range", 64, 40), 2**300), ("stop",)])
    m8, m1, z, wide, _ = fn.body
    assert m8.data == ir.WordBytes(A, 8)
    assert m1.data == ir.WordBytes(ir.Const(65), 1)
    assert z.data == ir.ZeroBytes(A)
    assert wide.data == ir.ConstBytes((2**300 % 2**320).to_bytes(40, "big"))


def test_code_copies_read_the_original_code():
    code = bytes.fromhex("6080604052") + b"scobelix" + b"\xfe"
    fn = one([("return", ("code.data", 5, 8))], lift.make_context(code))
    assert fn.body[0].data == ir.ConstBytes(b"scobelix") and not fn.flags
    fn = one([("return", ("code.data", 5, 8))])  # no code known: zeros, flagged
    assert fn.body[0].data == ir.ConstBytes(bytes(8)) and "code_unknown" in fn.flags


def test_make_context_keeps_the_code_and_narrow_push32_values():
    narrow = 0x1234
    code = bytes.fromhex("7f") + narrow.to_bytes(32, "big") + bytes.fromhex("600080fd")
    ctx = lift.make_context("0x" + code.hex())
    assert ctx.code == code and ctx.push32_narrow == frozenset({narrow}) and ctx.vocabulary == "raw"


# ---------------------------------------------------------------- json vocabulary


def test_json_vocabulary():
    ctx = lift.LiftContext(vocabulary="json", array_bases=frozenset({0}))
    trace = [["if", ["gt", ["param", "amount"], ["stor", 256, 0, ["map", "caller", ["name", "balanceOf", 1]]]],
              [["revert", None]],
              [["store", 256, 0, ["array", ["param", "i"], ["loc", 0]], ["param", "amount"]],
               ["return", ["stor", 256, 0, ["length", ["loc", 0]]]]]]]
    fn = one(trace, ctx, params={"amount": 4, "i": 36})
    (branch,) = fn.body
    assert branch.cond.args[0] == A and branch.then == (ir.Revert(ir.Empty()),)
    assert branch.cond.args[1] == ir.Sload(ir.Keccak(ir.Blob((ir.WordBytes(ir.Env("caller")), ir.WordBytes(ir.ONE)))))
    store, ret = branch.orelse
    assert store.slot == ir.Op("add", (ir.Keccak(ir.WordBytes(ir.ZERO)), B))
    assert ret.data == ir.WordBytes(ir.Sload(ir.ZERO))
    assert {"json_trace", "json_storage_ambiguous"} <= fn.flags


# ---------------------------------------------------------------- robustness


@pytest.mark.parametrize("trace", [
    [("frobnicate", 1)],
    [("return", ("frobnicate", 1))],
    [("return", [["mask_shl", 256, 0, -3, ("cd", 4)], 0])],  # a list inside an expression
    [("return", "'abc'")],  # an atom of no known kind
    [("if", ("lt", 1))],
    [("store", 256, 0)],
    [("return", None, None, None)],
    [("log", ("data", 1), 1, 2, 3, 4, 5)],
    [("setmem", 5, 5)],
    [("require", ("cd", 4)), ("stop",)],  # a require without its revert line
    [("call", "gas", ("cd", 4), 0, 0xA9059CBB, 0)],  # a payload split in two
    [None],
    [],
    [("while", 1, [("continue", "X", [])], "Y", [])],
])
def test_unknown_or_malformed_shapes_never_raise(trace):
    fn = one(trace)
    assert fn.body and ("unstructured" in fn.flags or "loop_exit_unstructured" in fn.flags
                        or all(not isinstance(s, ir.Unstructured) for s in fn.body))


# ---------------------------------------------------------------- snapshots, requires, min, loops


def test_require_keeps_its_revert_line():
    cond = ("lt", ("add", 1, ("var", 0)), 50)
    fn = one([("setvar", 0, 0), ("require", cond, ("revert", None)), ("stop",)])
    assert fn.body[1] == ir.Require(ir.Op("lt", (ir.Op("add", (ir.ONE, ir.Local("v0"))), ir.Const(50))), ir.Empty())
    assert not fn.flags
    fn = one([("require", ("cd", 4), ("revert", ("bytes", 4, 0x3DB2A12A))), ("stop",)])
    assert fn.body[0] == ir.Require(A, ir.Custom(0x3DB2A12A)) and not fn.flags
    fn = one([("require", ("cd", 4), ("revert", ("data", ("bytes", 4, 0x4E487B71), 0x11))), ("stop",)])
    assert fn.body[0] == ir.Require(A, ir.Panic(0x11)) and not fn.flags
    fn = one([("require", ("cd", 4), ("revert", ("data", ("bytes", 4, 0x08C379A0), 32, 2, HI))), ("stop",)])
    assert fn.body[0] == ir.Require(A, ir.ErrorString(b"hi")) and not fn.flags


def test_require_with_an_invalid_line_is_the_branch_it_came_from():
    fn = one([("require", ("lt", ("cd", 4), 50), ("invalid",)), ("setvar", 0, 1), ("return", ("var", 0))])
    (branch,) = fn.body
    assert branch == ir.If(ir.Op("lt", (A, ir.Const(50))),
                           (ir.Assign(ir.Local("v0"), ir.ONE), ir.Return(ir.WordBytes(ir.Local("v0")))),
                           (ir.Invalid(""),))
    assert not fn.flags
    # inside a loop body too, with the continue after it
    jd = "Node((92, 4, ('71',)))"
    loop = ("while", ("lt", ("var", 0), ("cd", 4)),
            [("require", ("lt", ("add", 1, ("var", 0)), 50), ("invalid",)),
             ("continue", jd, (("setvar", 0, ("add", 1, ("var", 0))),))],
            jd, [("setvar", 0, 0)])
    fn = one([loop, ("return", ("cd", 4))])
    (branch,) = fn.body[0].body
    assert isinstance(branch, ir.If) and isinstance(branch.then[0], ir.Continue) and branch.orelse == (ir.Invalid(""),)
    assert not fn.flags


def test_min_is_the_unsigned_minimum():
    rds = ir.CallOut(0, "returndatasize")
    value, flags = expr(("min", 64, "returndatasize"))
    assert value == ir.Ternary(ir.Op("lt", (rds, ir.Const(64))), rds, ir.Const(64)) and not flags
    value, _ = expr(("min", ("cd", 4), ("cd", 36), 7))
    inner = ir.Ternary(ir.Op("lt", (B, A)), B, A)
    assert value == ir.Ternary(ir.Op("lt", (ir.Const(7), inner)), ir.Const(7), inner)
    value, _ = expr(("min", 64, 3))
    assert ir.evaluate(value) == 3
    assert ir.evaluate(ir.Ternary(ir.Op("lt", (ir.Const(2**255), ir.ONE)), ir.Const(2**255), ir.ONE)) == 1  # unsigned


def test_call_output_copy_is_a_memory_write_of_the_return_data():
    n = ("min", 64, "returndatasize")
    fn = one([("setmem", ("range", 128, 32), 0xAAAA), ("call", "gas", ("cd", 4), 0, None, ("bytes", 4, 0x33333333)),
              ("setmem", ("range", 128, n), ("ext_call.return_data", 0, n)),
              ("return", ("mem", ("range", 128, 64)))])
    pre, call, copy, ret = fn.body
    assert pre == ir.Mstore(ir.Const(128), ir.WordBytes(ir.Const(0xAAAA)))
    assert call.selector is None and call.args == ir.WordBytes(ir.Const(0x33333333), 4)
    rds = ir.CallOut(call.call_id, "returndatasize")
    length = ir.Ternary(ir.Op("lt", (rds, ir.Const(64))), rds, ir.Const(64))
    assert copy == ir.Mstore(ir.Const(128), ir.ReturnData(call.call_id, ir.ZERO, length))
    assert ret == ir.Return(ir.MemSlice(ir.Const(128), ir.Const(64)))
    assert not fn.flags
    # the whole-buffer shape of checked calls is unchanged
    fn = one([("staticcall", "gas", ("cd", 4), 0, None, None),
              ("setmem", ("range", 128, 32), ("ext_call.return_data", 0, 32)), ("return", ("mem", ("range", 128, 32)))])
    assert fn.body[1] == ir.Mstore(ir.Const(128), ir.ReturnData(fn.body[0].call_id, ir.ZERO, ir.Const(32)))


def test_read_snapshots_are_locals_bound_at_their_line():
    trace = [
        ("setvar", "_1", ("storage", 256, 0, 0)),
        ("store", 256, 0, 0, ("cd", 4)),
        ("setvar", "_2", ("tload", 5)),
        ("tstore", 5, ("cd", 4)),
        ("setvar", "_3", ("balance", "address")),
        ("call", 0, ("cd", 36), 1, None, None),
        ("setvar", "_4", "ext_call.success"),
        ("setvar", "_5", "returndatasize"),
        ("setvar", "_6", ("ext_call.return_data", 0, 32)),
        ("create", 0, ("bytes", 3, 0x6000FD)),
        ("setvar", "_7", "create.new_address"),
        ("precompiled", "signer", "erecover", ("data", ("cd", 4), ("cd", 36), ("cd", 68), ("cd", 100))),
        ("setvar", "_8", ("var", "signer")),
        ("delegatecall", "gas", ("cd", 36), None, ("call.data", 0, "calldatasize")),
        ("setvar", "_9", ("var", "delegatecall_9.success")),
        ("setvar", "_10", ("extcodesize", ("cd", 36))),
        ("call", 0, ("cd", 36), 2, None, None),
        ("return", ("data", ("var", "_1"), ("storage", 256, 0, 0), ("var", "_2"), ("tload", 5), ("var", "_3"),
                    ("balance", "address"), ("var", "_4"), "ext_call.success", ("var", "_5"), "returndatasize",
                    ("var", "_6"), ("var", "_7"), ("var", "_8"), ("var", "_9"), ("var", "_10"))),
    ]
    fn = one(trace)
    call1, create, pre, dc, call2 = [s for s in fn.body if isinstance(s, (ir.ExtCall, ir.Create, ir.Precompile))]
    assigns = {s.target.name: s.value for s in fn.body if isinstance(s, ir.Assign)}
    assert assigns == {
        "t1": ir.Sload(ir.ZERO), "t2": ir.TLoad(ir.Const(5)), "t3": ir.Balance(ir.Env("address")),
        "t4": ir.CallOut(call1.call_id, "success"), "t5": ir.CallOut(call1.call_id, "returndatasize"),
        "t6": ir.BytesWord(ir.ReturnData(call1.call_id, ir.ZERO, ir.Const(32))),
        "t7": ir.CallOut(create.call_id, "address"), "t8": ir.Local(pre.output),
        "t9": ir.CallOut(dc.call_id, "success"), "t10": ir.ExtCodeSize(B),
    }
    # the uses read the locals; the inlined reads mean their value at the return
    words = [p.value for p in fn.body[-1].data.parts]
    assert words == [ir.Local("t1"), ir.Sload(ir.ZERO), ir.Local("t2"), ir.TLoad(ir.Const(5)), ir.Local("t3"),
                     ir.Balance(ir.Env("address")), ir.Local("t4"), ir.CallOut(call2.call_id, "success"),
                     ir.Local("t5"), ir.CallOut(call2.call_id, "returndatasize"), ir.Local("t6"), ir.Local("t7"),
                     ir.Local("t8"), ir.Local("t9"), ir.Local("t10")]
    assert not fn.flags


def test_split_field_snapshots_get_distinct_local_names():
    fn = one([("setvar", "_1_160_96", ("storage", 96, 160, 0)), ("setvar", "_1_0_160", ("storage", 160, 0, 0)),
              ("call", "gas", ("cd", 4), 0, None, None),
              ("return", ("data", ("var", "_1_0_160"), ("var", "_1_160_96")))])
    a, b, _, ret = fn.body
    assert a == ir.Assign(ir.Local("t1_160_96"), ir.Field(ir.Sload(ir.ZERO), 160, 96))
    assert b == ir.Assign(ir.Local("t1_0_160"), ir.Field(ir.Sload(ir.ZERO), 0, 160))
    assert [p.value for p in ret.data.parts] == [ir.Local("t1_0_160"), ir.Local("t1_160_96")]
    assert not fn.flags


def test_loop_variables_keep_their_exit_values_after_the_loop():
    jd = "Node((1274, 5, ('257',)))"
    v0, v1 = ir.Local("v0"), ir.Local("v1")
    updates = (("setvar", 0, ("add", 1, ("var", 0))), ("setvar", 1, ("mask_shl", 255, 0, 1, ("var", 1))))
    trace = [("while", ("lt", ("var", 0), ("cd", 4)), [("continue", jd, updates)], jd,
              [("setvar", 0, 0), ("setvar", 1, 1)]),
             ("return", ("data", ("var", 1), ("var", 0)))]
    fn = one(trace)
    loop, ret = fn.body
    assert loop.init == (ir.Assign(v0, ir.ZERO), ir.Assign(v1, ir.ONE))
    (cont,) = loop.body
    assert cont.updates == (ir.Assign(v0, ir.Op("add", (ir.ONE, v0))), ir.Assign(v1, ir.Mask(255, 0, 1, v1)))
    assert [p.value for p in ret.data.parts] == [v1, v0]
    assert not fn.flags


def test_whole_payloads():
    # fname None and fargs the whole payload (a zero word stays one)
    fn = one([("callcode", "gas", ("cd", 4), 0, None, 0),
              ("call", "gas", ("cd", 4), 0, None, ("data", ("bytes", 4, 0xA9059CBB), ("cd", 36)))])
    cc, c = fn.body
    assert cc.selector is None and cc.args == ir.WordBytes(ir.ZERO)
    assert c.selector is None and c.args == ir.Blob((ir.WordBytes(ir.Const(0xA9059CBB), 4), ir.WordBytes(B)))
    assert not fn.flags

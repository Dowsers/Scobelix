"""
The symbolic VM on small hand-assembled programs: every opcode gives a trace
node with the EVM's exact meaning, and a path the VM cannot follow ends with
an explicit ("undefined", reason) node instead of going on silently.

The programs have no selector dispatch: the whole code is `_fallback`, run
from pc 0. They return or revert the value under test.
"""

import logging

import pytest

import scobelix.utils.opcode_dict as opcode_dict
import scobelix.vm as vm_module
from scobelix.decompiler import decompile_bytecode
from scobelix.loader import Loader
from scobelix.stack import Stack
from scobelix.vm import VM

RETURN_WORD = "600052" "60206000f3"  # mstore(0, top); return(0, 32)


def trace_of(code):
    return decompile_bytecode(code).functions["_fallback"].orig_trace


def raw_trace(code):
    loader = Loader()
    loader.load_binary(code)
    return VM(loader).run(0)


def returned(code):
    trace = trace_of(code)
    assert len(trace) == 1 and trace[0][0] == "return", trace
    return trace[0][1]


def test_shr_by_a_constant_keeps_the_top_bits():
    # x >> 8: bits [8, 256) moved down (the shape of div(x, 2**8))
    assert returned("600435" "60081c" + RETURN_WORD) == ("mask_shl", 248, 8, -8, ("cd", 4))
    assert returned("600435" "6101001c" + RETURN_WORD) == 0  # shift >= 256
    assert returned("600435" "6024351c" + RETURN_WORD) == ("shr", ("cd", 36), ("cd", 4))


def test_sar_is_an_arithmetic_shift():
    assert returned("600435" "60031d" + RETURN_WORD) == ("sar", 3, ("cd", 4))
    # -16 >> 2 == -4 (sign bits shifted in), and a shift of 256 or more
    assert returned("7f" + "ff" * 31 + "f0" "60021d" + RETURN_WORD) == -4
    assert returned("7f" + "ff" * 31 + "f0" "6101001d" + RETURN_WORD) == -1


def test_byte_takes_the_index_from_the_top_of_the_stack():
    # byte(5, x): bits [208, 216) of x
    assert returned("600435" "60051a" + RETURN_WORD) == ("mask_shl", 8, 208, -208, ("cd", 4))
    assert returned("600435" "6024351a" + RETURN_WORD) == ("byte", ("cd", 36), ("cd", 4))
    assert returned("614142" "601e1a" + RETURN_WORD) == 0x41  # byte 30 of 0x4142
    assert returned("614142" "60201a" + RETURN_WORD) == 0  # index >= 32


def test_addmod_is_not_mulmod():
    assert returned("600d" "6007" "600435" "08" + RETURN_WORD) == ("addmod", ("cd", 4), 7, 13)
    assert returned("600d" "6007" "600a" "08" + RETURN_WORD) == (10 + 7) % 13
    assert returned("600d" "6007" "600435" "09" + RETURN_WORD) == ("mulmod", ("cd", 4), 7, 13)


def test_mstore8_writes_one_byte():
    # mstore(0, 0); mstore8(0, 0x4142); mstore8(1, 0x43): the word is 0x4243 << 240
    code = "6000600052" "614142600053" "6043600153" "60206000f3"
    assert returned(code) == 0x4243 << 240
    assert ("setmem", ("range", 0, 1), 0x42) in raw_trace(code)


def test_codecopy_copies_the_right_bytes_zero_padded():
    # codecopy(0, codesize - 4, 32) of a code ending with deadbeef
    code = "6020600c600039" "60206000f3" "deadbeef"
    assert returned(code) == 0xDEADBEEF << 224
    # the first bytes of the code, from offset 0
    code = "6000600052" "6004600060003960206000f3"
    assert returned(code) == int(code[:8], 16) << 224


def test_call_payload_is_kept_whole():
    # mstore8(0, 0x61); call(0xffff, 0x1234, 0, 0, 1, 0, 0): one byte of calldata
    code = "6061600053" "6000600060016000600061123461ffff" "f1" + RETURN_WORD
    call = trace_of(code)[0]
    assert call == ("call", 0xFFFF, 0x1234, 0, None, ("bytes", 1, 0x61))


def test_identity_precompile_copies_the_shorter_length():
    # staticcall(gas, 4, args 0..32, ret 0x40..0x44): 4 bytes written at 0x40
    code = "6011600052" "6004604060206000600460ff" "fa" "50" "60206040f3"
    setmems = [line for line in raw_trace(code) if line[0] == "setmem"]
    assert ("setmem", ("range", 0x40, 4), ("mem", ("range", 0, 4))) in setmems


def test_balance_of_a_constant_address():
    assert returned("611234" "31" + RETURN_WORD) == ("balance", 0x1234)


def test_empty_return_and_revert_are_none():
    assert trace_of("60006000f3") == [("return", None)]
    assert trace_of("60006000fd") == [("revert", None)]
    # one zero word is 0, not an empty payload
    assert trace_of("6000600052" "60206000f3") == [("return", 0)]


def test_stack_underflow_is_reported():
    assert trace_of("01") == [("undefined", "stack underflow", 0)]


def test_wrong_stack_effect_ends_the_path(monkeypatch):
    monkeypatch.setitem(opcode_dict.stack_diffs, "add", 0)
    trace = raw_trace("6001600201" "600052" "60206000f3")
    assert trace[-1] == ("undefined", "stack effect of add not modelled", 4)


def test_unsupported_opcode_ends_the_path():
    loader = Loader()
    loader.load_binary("600160025b00")
    loader.lines[4] = (4, "frobnicate", None)
    trace = VM(loader).run(0)
    assert ("undefined", "unsupported opcode frobnicate", 4) in trace


def test_pruned_branches_are_reported_not_stopped(monkeypatch):
    # past 60% of the node budget the VM stops exploring the false branch of
    # a symbolic jumpi: that branch is ("undefined", "branch pruned"), not a
    # successful ("stop",). Here: if cd[4]: stop, else revert.
    code = "600435600a57" "600080fd" "5b00"
    loader = Loader()
    loader.load_binary(code)
    assert VM(loader).run(0)[-1] == ("if", ("cd", 4), [("stop",)], [("revert", None)])

    monkeypatch.setattr(vm_module, "MAX_NODE_COUNT", 6)
    loader = Loader()
    loader.load_binary(code)
    assert VM(loader).run(0)[-1] == (
        "if", ("cd", 4), [("stop",)], [("undefined", "branch pruned")]
    )


def test_huge_values_are_not_formatted_for_the_logs():
    # a 90 kB value (copied code) has more digits than str() allows: debug
    # messages must not format it eagerly (it was a ValueError)
    from scobelix.core.memloc import fill_mem
    from scobelix.simplify import simplify_exp

    big = (1 << (8 * 90000)) - 1
    res = fill_mem(("mem", ("range", 0, 32)), ("range", 0, 90000), big)
    assert simplify_exp(res) == 2**256 - 1  # its first 32 bytes


def test_masks_of_runtime_width_do_not_break_parameter_guessing():
    # cd[4] & (256 ** cd[36] - 1): a mask whose width is only known at run
    # time (it was a TypeError in the parameter type guessing)
    code = "6001" "602435" "610100" "0a" "03" "600435" "16" + RETURN_WORD
    assert returned(code) == ("mask_shl", ("mask_shl", 253, 0, 3, ("cd", 36)), 0, 0, ("cd", 4))


def test_stack_copies_its_initial_list():
    items = [1, 2]
    stack = Stack(items)
    stack.append(3)
    stack.pop()
    stack.pop()
    assert items == [1, 2]


@pytest.fixture(autouse=True)
def _quiet():
    logging.disable(logging.WARNING)
    yield
    logging.disable(logging.NOTSET)


def test_reads_past_a_head_offset_mark_a_dynamic_parameter():
    # selector 0x8badf00d: return uint8(bytes(data)[0]), i.e. the word at
    # 36 + calldata[4] (the first bytes of the dynamic parameter) >> 248
    code = (
        "600035" "60e01c" "80" "638badf00d" "14" "6011" "57" "00" "5b"
        "600435" "6024" "01" "35" "60f8" "1c" + RETURN_WORD
    )
    f = decompile_bytecode(code).functions["0x8badf00d"]
    assert f.orig_trace == [("return", ("mask_shl", 8, 248, -248, ("cd", ("add", 36, ("cd", 4)))))]
    assert f.name == "unknown8badf00d(array _param1)"

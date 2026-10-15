"""
Unit tests of core/effects.py (which lines change which time-dependent
values) and call_output.py (the output buffer of a call).
"""

from scobelix.call_output import output_write, resolve_call_outputs
from scobelix.core.effects import clobbers, disjoint_slots, kinds
from scobelix.simplify import simplify_trace

MAP_A = ("sha3", ("data", ("cd", 4), 1))
MAP_B = ("sha3", ("data", ("cd", 36), 0))
NESTED = ("sha3", ("data", "caller", MAP_A))
CALL = ("call", "gas", 0x1234, 0, None, None)
STATIC = ("staticcall", "gas", 0x1234, 0, None, None)


def test_kinds_of_reads():
    assert kinds(("add", 1, ("storage", 256, 0, 3))) == {"storage"}
    assert kinds("returndatasize") == {"result"}
    assert kinds(("ext_call.return_data", 0, 32)) == {"result"}
    assert kinds(("var", "signer")) == {"result"}
    assert kinds(("var", "delegatecall_7.success")) == {"result"}
    assert kinds(("balance", "address")) == {"balance"}
    assert kinds(("tload", 5)) == {"transient"}
    assert kinds(("extcodesize", ("cd", 4))) == {"code"}
    assert not kinds(("add", ("cd", 4), "caller", ("var", "_3")))


def test_what_lines_change():
    read = ("storage", 256, 0, 3)
    assert clobbers(("store", 256, 0, 3, 1), read)
    assert clobbers(CALL, read)  # the callee may call back and write it
    assert not clobbers(STATIC, read)
    assert clobbers(STATIC, "ext_call.success")
    assert clobbers(("precompiled", "hash", "sha256hash", 0), ("var", "hash"))
    assert clobbers(("create", 0, 0), ("balance", "address"))
    assert clobbers(("tstore", 5, 1), ("tload", 5))
    assert not clobbers(("tstore", 5, 1), read)
    assert not clobbers(("log", 0, 1), read)
    # a loop changes what its body changes, ifs included
    loop = ("while", 1, [("if", ("cd", 4), [("store", 256, 0, 3, 1)], [])], "jd", [])
    assert clobbers(loop, read)
    # an if itself changes nothing: callers look into its branches
    assert not clobbers(("if", 1, [("store", 256, 0, 3, 1)], []), read)


def test_stores_to_other_slots_and_fields():
    assert not clobbers(("store", 256, 0, MAP_B, 1), ("storage", 256, 0, NESTED))
    assert not clobbers(("store", 256, 0, 4, 1), ("storage", 256, 0, 3))
    assert not clobbers(("store", 128, 128, 3, 1), ("storage", 128, 0, 3))
    assert clobbers(("store", 128, 64, 3, 1), ("storage", 128, 0, 3))
    assert not clobbers(("store", 256, 256, 3, 1), ("storage", 256, 0, 3))  # slot 4
    assert clobbers(("store", 8, ("cd", 4), 3, 1), ("storage", 256, 0, 3))  # unknown bits
    assert clobbers(("store", 256, 0, ("sha3", ("data", ("cd", 68), 1)), 1), ("storage", 256, 0, MAP_A))


def test_disjoint_slots():
    assert disjoint_slots(0, 1) and not disjoint_slots(1, 1)
    assert disjoint_slots(MAP_A, MAP_B)  # different mapping slots
    assert disjoint_slots(3, MAP_A)  # a hash is not a small slot
    assert disjoint_slots(("add", 1, MAP_A), MAP_A)
    assert not disjoint_slots(MAP_A, ("sha3", ("data", ("cd", 68), 1)))  # same mapping, keys may be equal
    assert not disjoint_slots(("add", ("cd", 4), MAP_A), MAP_A)  # unknown index


def test_call_output_under_a_returndatasize_check():
    write = output_write(0x80, 32)
    revert = [("revert", None)]
    use = [("return", ("mem", ("range", 0x80, 32)))]
    guarded = [CALL, write, ("if", ("lt", "returndatasize", 32), revert, use)]
    res = resolve_call_outputs(guarded)
    full = ("setmem", ("range", 0x80, 32), ("ext_call.return_data", 0, 32))
    assert res[1][3][0] == full  # the checked branch reads the whole buffer
    assert simplify_trace(guarded)[-1][3] == [("return", ("ext_call.return_data", 0, 32))]
    # unchecked: the exact copy stays
    unguarded = [CALL, write] + use
    assert resolve_call_outputs(unguarded) == unguarded
    # a check that is not enough for the buffer
    short = [CALL, write, ("if", ("lt", "returndatasize", 31), revert, use)]
    assert resolve_call_outputs(short)[1][3][0] == write


def test_delegatecall_output_under_a_returndatasize_check():
    """The output buffer of a delegatecall (and a callcode) is copied the
    same way, with its own return data node."""
    callee = ("cd", 4)
    delegate = ("delegatecall", "gas", callee, None, None)
    write = output_write(0x80, 32, "delegate.return_data", callee)
    assert write[2] == ("delegate.return_data", callee, ("min", 32, "returndatasize"))
    use = [("return", ("mem", ("range", 0x80, 32)))]
    guarded = [delegate, write, ("if", ("lt", "returndatasize", 32), [("revert", None)], use)]
    full = ("setmem", ("range", 0x80, 32), ("delegate.return_data", callee, 32))
    assert resolve_call_outputs(guarded)[1][3][0] == full
    assert resolve_call_outputs([delegate, write] + use) == [delegate, write] + use


def test_call_output_does_not_move_past_a_write_its_address_reads():
    """The buffer address is read from memory (the free memory pointer): the
    copy cannot move below a write to that memory."""
    fmp = ("mem", ("range", 64, 32))
    write = output_write(fmp, 32)
    bump = ("setmem", ("range", 64, 32), ("add", 32, fmp))
    use = [("return", ("mem", ("range", 0x80, 32)))]
    trace = [CALL, write, bump, ("if", ("lt", "returndatasize", 32), [("revert", None)], use)]
    res = resolve_call_outputs(trace)
    assert res[1] == write and res[2] == bump


def test_a_zero_word_return_is_not_a_revert():
    """("return", 0) returns one zero word: the loop structurer must not turn
    the if before it into a require; ("revert", ...) keeps its line."""
    from scobelix.core.arithmetic import is_zero
    from scobelix.whiles import to_while

    jd = "J"
    loop = [("setvar", 1, ("add", 1, ("var", 1))), ("goto", jd, (("setvar", 1, ("add", 1, ("var", 1))),))]
    trace = [("if", ("lt", ("var", 1), 10), [("return", 0)], loop)]
    before, inside, after, cond = to_while(trace, jd)
    assert not [l for l in before if l[0] == "require"]
    assert after == [("return", 0)]

    # an if whose branch reverts with a payload: a require keeping that line
    fail = ("revert", ("bytes", 4, 0x12345678))
    trace = [("if", ("lt", ("var", 1), 10), [fail], [("if", ("lt", ("var", 1), 5), loop, [("stop",)])])]
    before, inside, after, cond = to_while(trace, jd)
    assert before == [("require", is_zero(("lt", ("var", 1), 10)), fail)]


def test_loop_header_read_is_bound_again_before_each_test():
    """`x = n; while (i < x) { x -= 1; i++; }`: the loop header reads x into
    a variable before the loop and again before each continue. The
    simplifier keeps the second binding (the condition reads it), does not
    inline the first one into the condition, and gives no closed form for
    i after the loop."""
    from trace_machine import Machine

    x = ("storage", 256, 0, 0)
    trace = [
        ("store", 256, 0, 0, ("cd", 4)),
        ("setvar", "_6", x),
        ("while", ("lt", ("var", 1), ("var", "_6")),
         [("store", 256, 0, 0, ("add", -1, x)), ("setvar", "_6", x),
          ("continue", "jd", [("setvar", 1, ("add", 1, ("var", 1)))])],
         "jd", [("setvar", 1, 0)]),
        ("return", ("data", ("var", 1), x)),
    ]
    simplified = simplify_trace(trace)
    for n in (0, 1, 4, 5):
        m = Machine(bytes(4) + n.to_bytes(32, "big"))
        ok, out = m.call(simplified)
        assert ok and out == ((n + 1) // 2).to_bytes(32, "big") + (n // 2).to_bytes(32, "big"), n

    # the same with a byte of the word (`uint8 x` packed in slot 0): the
    # two bindings of the variable stay alike (no narrowing of one of them)
    word = ("storage", 256, 0, 0)
    byte = ("mask_shl", 8, 0, 0, ("var", "_6"))
    trace = [
        ("store", 8, 0, 0, ("cd", 4)),
        ("setvar", "_6", word),
        ("while", ("lt", ("var", 1), byte),
         [("store", 8, 0, 0, ("add", -1, ("storage", 8, 0, 0))), ("setvar", "_6", word),
          ("continue", "jd", [("setvar", 1, ("add", 1, ("var", 1)))])],
         "jd", [("setvar", 1, 0)]),
        ("return", ("data", ("var", 1), ("storage", 8, 0, 0))),
    ]
    simplified = simplify_trace(trace)
    for n in (0, 1, 4, 5):
        m = Machine(bytes(4) + n.to_bytes(32, "big"), storage={0: 0xAB00})
        ok, out = m.call(simplified)
        assert ok and out == ((n + 1) // 2).to_bytes(32, "big") + (n // 2).to_bytes(32, "big"), n


def test_call_output_inside_the_checked_branch():
    """A copy already below the size check (a former pass moved it there):
    the check above it still proves the size; a call in between does not."""
    write = output_write(0x80, 32)
    use = [("return", ("mem", ("range", 0x80, 32)))]
    full = ("setmem", ("range", 0x80, 32), ("ext_call.return_data", 0, 32))
    checked = [CALL, ("if", ("slt", "returndatasize", 32), [("revert", None)], [write] + use)]
    assert resolve_call_outputs(checked)[1][3][0] == full
    other = [CALL, ("if", ("slt", "returndatasize", 32), [("revert", None)], [STATIC, write] + use)]
    assert resolve_call_outputs(other)[1][3][1] == write

"""
Exact EVM semantics in the decompiled traces of compiled code (fixtures
EngineSemantics, EngineSemanticsNoopt and EngineSemanticsLegacy, see
tests/fixtures/sources/): shifts, BYTE, ADDMOD, constants, revert and return
payloads with their selectors and widths, packed encodings, copied code,
short call payloads; and their text form.

Byte strings (payloads, data blobs) have explicit widths: a plain word is 32
bytes, a slice its own length, ("bytes", n, x) the low n bytes of x.
"""

import functools
import logging
import re
from pathlib import Path

from scobelix.decompiler import decompile_bytecode

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"

ERROR_STRING = 0x08C379A0  # Error(string)
PANIC = 0x4E487B71  # Panic(uint256)

CD4, CD36, CD68 = ("cd", 4), ("cd", 36), ("cd", 68)

# keccak selectors of the fixture's functions (solc methodIdentifiers)
SEL = {
    "am": "0xc1013215", "belowMax": "0xde178e1e", "byte5": "0xeb84f3a2",
    "byteAt": "0xaee24bcc", "call1": "0xf1b9b841", "callData": "0x42e86d27",
    "codeTail": "0xd44e7f14", "constBalance": "0x71d968a9", "hashPacked": "0x8be8e5d9",
    "hashPrefix": "0x022863ea", "hi8": "0xd7d89a27", "magic": "0x0d854646",
    "packAdd": "0xe113dce4", "packed": "0xdac067ea", "retEmpty": "0xc0c956a4",
    "retZero": "0x1db909f4", "revertArg": "0x0a6c13bf", "revertEmpty": "0x4926c4c6",
    "revertPanic": "0x0c780a0c", "revertString": "0x6a8ed30f", "sar3": "0xc5683161",
    "setX": "0x4018d9aa", "shr248": "0x12a6514c", "shrVar": "0xe317208b",
    "sig": "0x00a7029b", "store8": "0xbb717bb1", "x": "0x0c55699c",
}

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


@functools.lru_cache(maxsize=None)
def _decompile(name):
    logging.disable(logging.WARNING)
    try:
        return decompile_bytecode((FIXTURES_DIR / f"{name}.hex").read_text().strip())
    finally:
        logging.disable(logging.NOTSET)


def trace(fn, fixture="EngineSemantics"):
    return _decompile(fixture).functions[SEL.get(fn, fn)].orig_trace


def body(fn, fixture="EngineSemantics"):
    """The trace past the ABI decoder checks (leading `if c: revert`)."""
    lines = trace(fn, fixture)
    while len(lines) == 1 and lines[0][0] == "if" and lines[0][2] == [("revert", None)]:
        lines = lines[0][3]
    return lines


def text(fixture="EngineSemantics"):
    return _ANSI_RE.sub("", _decompile(fixture).text)


def test_no_function_is_lost():
    for name in ("EngineSemantics", "EngineSemanticsNoopt", "EngineSemanticsLegacy"):
        assert _decompile(name).json["problems"] == {}


def test_shifts_and_bytes():
    assert body("shr248") == [("return", ("mask_shl", 8, 248, -248, CD4))]
    assert body("hi8") == [("return", ("mask_shl", 8, 8, -8, CD4))]
    assert body("sar3") == [("return", ("sar", 3, CD4))]
    assert body("shrVar") == [("return", ("shr", CD36, CD4))]
    assert body("byte5") == [("return", ("mask_shl", 8, 208, -208, CD4))]
    # bytes32 b; b[i] (bytes1, left-aligned), after the index check
    check, oob, ok = body("byteAt")[0][1:]
    assert check == ("ge", CD36, 32)
    assert oob == [("revert", ("data", ("bytes", 4, PANIC), 0x32))]
    assert ok == [("return", ("mask_shl", 8, 0, 248, ("byte", CD36, CD4)))]


def test_msg_sig_keeps_the_selector():
    # uint32(msg.sig): the top 4 bytes of calldata, in optimized and plain builds
    for fixture in ("EngineSemantics", "EngineSemanticsNoopt"):
        assert body("sig", fixture) == [("return", ("mask_shl", 32, 224, -224, ("cd", 0)))]


def test_selector_test_in_the_fallback_survives_without_optimizer():
    # fallback: if (uint32(msg.sig) == 0x33333333) {x = 1; return;} x = 2
    for fixture in ("EngineSemantics", "EngineSemanticsNoopt"):
        d = _decompile(fixture)
        assert d.functions["0x33333333"].orig_trace == [("store", 256, 0, 0, 1), ("stop",)]
        assert d.functions["_fallback"].orig_trace == [("store", 256, 0, 0, 2), ("stop",)]


def test_addmod_and_arithmetic():
    check, panic, ok = body("am")[0][1:]
    assert panic == [("revert", ("data", ("bytes", 4, PANIC), 0x12))]
    assert ok == [("return", ("addmod", CD4, CD36, CD68))]
    assert body("packAdd") == [("return", ("mul", 257, CD4))]  # x * 256 + x
    # type(uint256).max - 1, as a two's complement word
    assert body("belowMax") == [("return", ("lt", CD4, -2))]


def test_constants_stay_ints():
    assert body("magic") == [("return", 0x4142434445464748)]
    assert body("constBalance") == [("return", ("balance", 0x1234))]


def test_revert_payloads_carry_their_selector():
    assert body("revertEmpty") == [("revert", ("bytes", 4, 0x3DB2A12A))]  # Empty()
    assert body("revertArg") == [("revert", ("data", ("bytes", 4, 0xE386E5D3), CD4))]
    cond, panic, ok = body("revertPanic")[0][1:]
    assert panic == [("revert", ("data", ("bytes", 4, PANIC), 0x12))]
    cond, fail, ok = body("revertString")[0][1:]
    reason = int.from_bytes(b"short reason".ljust(32, b"\0"), "big")
    assert fail == [("revert", ("data", ("bytes", 4, ERROR_STRING), 32, 12, reason))]


def test_packed_encodings_have_exact_widths():
    assert body("hashPacked") == [
        ("return", ("sha3", ("data", ("bytes", 20, ("mask_shl", 160, 0, 0, CD4)), CD36)))
    ]
    # "\x19\x01" (2 bytes) then the word
    assert body("hashPrefix") == [("return", ("sha3", ("data", ("bytes", 2, 0x1901), CD4)))]


def test_returns():
    assert body("retZero") == [("return", 0)]  # one zero word
    assert trace("retEmpty", "EngineSemanticsNoopt") == [("return", None)]  # return(0, 0)
    assert body("store8") == [("return", 0x4243 << 240)]  # two mstore8


def test_codecopy_reads_the_code():
    code = bytes.fromhex((FIXTURES_DIR / "EngineSemantics.hex").read_text().strip())
    assert body("codeTail") == [("return", int.from_bytes(code[-4:].ljust(32, b"\0"), "big"))]


def test_long_strings_copied_from_the_code():
    msg = b"a revert reason that is definitely longer than thirty-two bytes"
    check, fail, ok = body("0x53fec806", "EngineSemanticsLegacy")[0][1:]
    payload = fail[0][1]
    assert payload[:4] == ("data", ("bytes", 4, ERROR_STRING), 32, len(msg))
    assert payload[4] == ("bytes", 63, int.from_bytes(msg, "big"))


def test_call_payloads():
    # t.call(hex"61"): one byte, the payload is kept whole
    call = body("call1")[0]
    assert call[0] == "call" and call[4:] == (None, ("bytes", 1, 0x61))


def test_text_output():
    out = text()
    # the selector is printed (by its name when the signature database has
    # it), no longer a 0 in its place
    assert re.search(r"revert with (Error\(string reason\)|147028384), 'short reason'", out)
    assert "revert with 0," not in out
    assert "revert with Panic(18)" in out
    assert "return addmod(" in out
    assert "_param1 >>′ 3" in out
    assert " = 'ABCDEFGH'" in out  # magic(): a constant shown as its text
    assert "a revert reason that is definitely longer than thirty-two bytes" in text(
        "EngineSemanticsLegacy"
    )


def test_shifted_fields_do_not_type_the_parameter():
    # x >> 248, uint8(x >> 8) and byte(5, x) read a field out of a uint256:
    # the mask of that field says nothing of the parameter's own type
    for fn in ("shr248", "hi8", "byte5"):
        assert _decompile("EngineSemantics").functions[SEL[fn]].name.endswith("(uint256 _param1)")


def test_narrow_constant_bytes_show_their_width():
    out = text()
    assert "sha3(0x1901, _param1)" in out  # abi.encodePacked("\x19\x01", d)
    assert "revert with 0xe386e5d3, _param1" in out  # WithArg(a): not a function name
    assert "args 0x61" in out  # t.call(hex"61")

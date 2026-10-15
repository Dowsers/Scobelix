"""
Compiler metadata trailer (scobelix/utils/metadata.py) and how the loader
uses it: the trailer is parsed (compiler, exact version or version range)
and kept out of the disassembly, while CODECOPY / CODESIZE still see the
whole code.
"""

import random
from pathlib import Path

from scobelix.decompiler import decompile_bytecode
from scobelix.loader import Loader
from scobelix.utils.metadata import find_all_metadata, parse_metadata, strip_metadata

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"

CODE = bytes.fromhex("6080604052600080fd")  # mstore(0x40, 0x80) revert(0, 0)
HASH = bytes(range(32))


def _text(s):
    """CBOR text string (< 24 bytes)."""
    return bytes([0x60 + len(s)]) + s.encode()


def _trailer(cbor, counts_itself=False):
    """CBOR followed by its big-endian 2-byte length."""
    n = len(cbor) + (2 if counts_itself else 0)
    return cbor + n.to_bytes(2, "big")


IPFS = bytes.fromhex("a2") + _text("ipfs") + bytes.fromhex("58221220") + HASH  # 2-entry map
SOLC_0819 = _text("solc") + bytes.fromhex("43000813")


def test_solc_ipfs_trailer():
    md = parse_metadata(CODE + _trailer(IPFS + SOLC_0819))

    assert (md.compiler, md.version, md.hash_kind) == ("solc", "0.8.19", "ipfs")
    assert md.hash_hex == "1220" + HASH.hex()
    assert (md.start, md.length) == (len(CODE), 53)
    assert md.to_dict()["raw"] == {"ipfs": "1220" + HASH.hex(), "solc": "000813"}


def test_solc_bzzr1_and_metadata_hash_none():
    bzzr1 = bytes.fromhex("a2") + _text("bzzr1") + bytes.fromhex("5820") + HASH
    md = parse_metadata(CODE + _trailer(bzzr1 + _text("solc") + bytes.fromhex("43000511")))
    assert (md.version, md.hash_kind, md.length) == ("0.5.17", "bzzr1", 52)

    md = parse_metadata(CODE + _trailer(bytes.fromhex("a1") + SOLC_0819))
    assert (md.version, md.hash_kind, md.length) == ("0.8.19", None, 12)


def test_bzzr0_gives_a_version_range():
    bzzr0 = bytes.fromhex("a1") + _text("bzzr0") + bytes.fromhex("5820") + HASH
    # the byte before the trailer is STOP for solc 0.4.x, INVALID for 0.5.x
    md = parse_metadata(bytes.fromhex("600080fd00") + _trailer(bzzr0))
    assert (md.version, md.version_range, md.length) == (None, ("0.4.7", "0.4.26"), 43)
    md = parse_metadata(bytes.fromhex("600080fdfe") + _trailer(bzzr0))
    assert md.version_range == ("0.5.0", "0.5.8")

    experimental = bytes.fromhex("a2") + _text("bzzr0") + bytes.fromhex("5820") + HASH
    experimental += bytes.fromhex("6c") + b"experimental" + bytes.fromhex("f5")
    md = parse_metadata(CODE + _trailer(experimental))
    assert md.experimental is True and md.length == 57


def test_prerelease_version_text():
    nightly = "0.8.20-nightly.2023.1.1+commit.0123abcd"
    cbor = IPFS + _text("solc") + bytes([0x78, len(nightly)]) + nightly.encode()
    md = parse_metadata(CODE + _trailer(cbor))
    assert (md.version, md.prerelease) == ("0.8.20", nightly)


def test_vyper_trailers():
    vyper = bytes.fromhex("a1") + _text("vyper")
    assert parse_metadata(CODE + _trailer(vyper + bytes.fromhex("83000307"))).version == "0.3.7"
    # 0.3.4: no length suffix
    assert parse_metadata(CODE + vyper + bytes.fromhex("83000304")).version == "0.3.4"
    # >= 0.3.10 initcode: [runtime size, [data sizes], immutables size,
    # {"vyper": [0, 3, 10]}], and the length suffix counts itself
    initcode_meta = bytes.fromhex("84" "190100" "8104" "00") + vyper + bytes.fromhex("8300030a")
    md = parse_metadata(CODE + _trailer(initcode_meta, counts_itself=True))
    assert (md.compiler, md.version) == ("vyper", "0.3.10")


def test_code_without_trailer_and_random_bytes_are_not_metadata():
    assert parse_metadata(CODE) is None
    assert parse_metadata(b"") is None
    # unknown keys: not a compiler trailer
    assert parse_metadata(CODE + _trailer(bytes.fromhex("a1") + _text("foo") + b"\x01")) is None
    # crafted deep nesting is rejected, not a RecursionError
    assert parse_metadata(CODE + _trailer(b"\x81" * 3000 + b"\x00")) is None

    rng = random.Random(1234)
    for _ in range(2000):
        blob = bytes(rng.getrandbits(8) for _ in range(rng.randint(2, 400)))
        assert parse_metadata(blob) is None


def test_strip_and_find_all_metadata():
    outer = _trailer(IPFS + SOLC_0819)
    code, md = strip_metadata(CODE + outer)
    assert code == CODE and md.length == 53
    assert strip_metadata("0x" + CODE.hex()) == (CODE, None)

    # a factory carries its child's initcode, trailer included
    child = CODE + outer
    start = 2 * len(CODE)
    spans = find_all_metadata(CODE + child + outer)
    assert spans == [(start, start + 53), (start + 53, start + 106)]


def test_fixture_versions():
    expected = {
        "SimpleToken": ("0.8.19", None),
        "DispatchBoth": ("0.7.6", None),
        "DispatchFallbackOld": ("0.5.17", None),
        "DispatchLegacy04": (None, ("0.4.7", "0.4.26")),
        "DispatchFallbackOnlyViaIRNoopt": ("0.8.31", None),
    }
    for name, (version, version_range) in expected.items():
        md = parse_metadata((FIXTURES_DIR / f"{name}.hex").read_text().strip())
        assert md.compiler == "solc"
        assert (md.version, md.version_range) == (version, version_range), name


def test_loader_does_not_disassemble_the_trailer():
    # every hash byte is 0x5b: disassembled, the trailer would hold JUMPDESTs
    trailer = bytes.fromhex("a2") + _text("ipfs") + bytes.fromhex("58221220") + b"\x5b" * 32
    code = CODE + _trailer(trailer + SOLC_0819)
    loader = Loader()
    loader.load_binary(code.hex())

    assert loader.metadata.start == len(CODE)
    assert loader.last_line == len(CODE)
    assert max(pc for pc, _, _ in loader.parsed_lines) < len(CODE)
    assert loader.jump_dests == []
    assert len(loader.binary) == len(code)  # CODECOPY / CODESIZE see everything
    assert loader.bytecode == code.hex()


def test_execution_reaching_the_trailer_is_reported_not_followed():
    # The EVM takes a JUMPDEST byte of the trailer as a jump target: here the
    # hash hides JUMPDEST CALLER SELFDESTRUCT and the code jumps there. The
    # trailer is not disassembled, so the decompiler must say it cannot
    # follow the jump instead of calling it invalid (a revert).
    jump = bytes.fromhex("61000f56fe")  # PUSH2 15, JUMP, INVALID
    hidden = bytes.fromhex("5b33ff") + b"\x00" * 29
    cbor = bytes.fromhex("a2") + _text("ipfs") + bytes.fromhex("58221220") + hidden + SOLC_0819
    code = jump + _trailer(cbor)
    loader = Loader()
    loader.load_binary(code.hex())
    assert loader.metadata.start == len(jump)
    assert loader.trailer_jump_dests == {15}

    text = decompile_bytecode(code.hex()).text
    assert "jump into the metadata trailer" in text

    # code that falls through into its trailer
    code = bytes.fromhex("6001") + _trailer(bytes.fromhex("a1") + SOLC_0819)
    assert "runs into the metadata trailer" in decompile_bytecode(code.hex()).text


def test_push_data_past_the_end_of_the_code_reads_zeros():
    loader = Loader()
    loader.load_binary("61ab")  # PUSH2 with a single byte left
    assert loader.parsed_lines == [(0, "push2", 0xAB00)]


def test_decompilation_exposes_bytecode_and_metadata():
    hex_code = (FIXTURES_DIR / "SimpleToken.hex").read_text().strip()
    d = decompile_bytecode("0x" + hex_code)

    assert d.bytecode == hex_code
    assert d.metadata["version"] == "0.8.19"
    assert d.metadata["offset"] + d.metadata["length"] == len(hex_code) // 2
    assert all(int(line.split(",")[0], 16) < d.metadata["offset"] for line in d.asm)

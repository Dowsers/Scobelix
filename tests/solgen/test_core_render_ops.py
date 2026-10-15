"""
Render exactness of every word operation: the Solidity solgen v2 renders
for an IR expression, compiled and executed, must return the same word as
the raw EVM opcode (executed on the same backend) and as the IR's
reference semantics (ir.evaluate), on edge and random operands.
"""

import random

import pytest

from conftest import backend_or_skip, compile_or_fail, installed
from scobelix.solgen import ir
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.contract import ContractInput, Unit, assemble

A, B, C = (ir.CalldataWord(ir.Const(o)) for o in (4, 36, 68))
M = ir.WORD_MAX
EDGE = [0, 1, 2, 7, 31, 32, 255, 256, 2**64 - 1, 2**160 - 1, 2**255 - 1, 2**255, 2**255 + 1, M - 31, M - 1, M]

# opcode bytes of the binary / unary / ternary operations
BINARY = {"add": 0x01, "mul": 0x02, "sub": 0x03, "div": 0x04, "sdiv": 0x05, "mod": 0x06, "smod": 0x07,
          "exp": 0x0A, "signextend": 0x0B, "lt": 0x10, "gt": 0x11, "slt": 0x12, "sgt": 0x13, "eq": 0x14,
          "and": 0x16, "or": 0x17, "xor": 0x18, "byte": 0x1A, "shl": 0x1B, "shr": 0x1C, "sar": 0x1D}
UNARY = {"iszero": 0x15, "not": 0x19}
TERNARY = {"addmod": 0x08, "mulmod": 0x09}

_TAIL = bytes([0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3])  # mstore(0, top) return(0, 32)


def _load(off):
    return bytes([0x60, off, 0x35])  # calldataload(off)


def evm_code(op: str) -> bytes:
    """Runtime code computing op(cd[4], cd[36], cd[68]) and returning it."""
    if op in UNARY:
        return _load(4) + bytes([UNARY[op]]) + _TAIL
    if op in TERNARY:
        return _load(68) + _load(36) + _load(4) + bytes([TERNARY[op]]) + _TAIL
    return _load(36) + _load(4) + bytes([BINARY[op]]) + _TAIL


def op_expr(op: str) -> ir.Expr:
    if op in UNARY:
        return ir.Op(op, (A,))
    if op in TERNARY:
        return ir.Op(op, (A, B, C))
    return ir.Op(op, (A, B))


# expressions with no single opcode: checked against ir.evaluate only
EXTRA = {
    "mask_low160": ir.Mask(160, 0, 0, A),
    "mask_low8": ir.Mask(8, 0, 0, A),
    "mask_low5": ir.Mask(5, 0, 0, A),
    "mask_shr_vm": ir.Mask(32, 224, -224, A),
    "mask_top_bytes4": ir.Mask(32, 224, 0, A),
    "mask_shl_artifact": ir.Mask(160, 0, 96, A),
    "mask_round32": ir.Mask(251, 5, 0, ir.Op("add", (A, ir.Const(31)))),
    "mask_shl_into_top": ir.Mask(255, 0, 1, A),
    "mask_half_right": ir.Mask(255, 1, -1, A),
    "mask_neg_offset": ir.Mask(256, -8, -8, A),
    "mask_wide": ir.Mask(300, 0, 0, A),
    "mask_symbolic": ir.Mask(ir.Op("and", (B, ir.Const(511))), ir.Op("sub", (ir.Const(128), ir.Op("and", (C, ir.Const(255))))),
                             ir.Op("sub", (ir.Op("and", (C, ir.Const(255))), ir.Const(128))), A),
    "field_const": ir.Field(A, 8, 16),
    "field_top": ir.Field(A, 200, 56),
    "field_symbolic": ir.Field(A, ir.Op("and", (B, ir.Const(255))), ir.Op("and", (C, ir.Const(511)))),
    "ternary": ir.Ternary(ir.Op("lt", (A, B)), C, ir.Op("not", (C,))),
    "bool_word": ir.Op("add", (ir.Op("lt", (A, B)), ir.Op("lt", (A, B)))),
    "bool_sub": ir.Op("sub", (ir.Op("eq", (A, B)), ir.Const(1))),
    "bool_not": ir.Op("not", (ir.Op("gt", (A, B)),)),
    "bool_shl": ir.Op("shl", (ir.Const(200), ir.Op("iszero", (A,)))),
    "and_bools": ir.Op("and", (ir.Op("lt", (A, B)), ir.Op("gt", (A, C)))),
    "or_bools": ir.Op("or", (ir.Op("lt", (A, B)), ir.Op("eq", (A, C)))),
    "xor_bools": ir.Op("xor", (ir.Op("lt", (A, B)), ir.Op("eq", (A, C)))),
    "add3_neg": ir.Op("add", (A, ir.Op("mul", (ir.const(-1), B)), ir.const(-4))),
    "div_const": ir.Op("div", (A, ir.Const(7))),
    "mod_const": ir.Op("mod", (A, ir.Const(2**128 + 3))),
    "addmod_const": ir.Op("addmod", (A, B, ir.Const(97))),
    "exp_small": ir.Op("exp", (ir.Op("and", (A, ir.Const(15))), ir.Op("and", (B, ir.Const(511))))),
    "shift_const_left": ir.Op("shl", (ir.Op("and", (A, ir.Const(511))), ir.Const(5))),
    "bytesword_word": ir.BytesWord(ir.WordBytes(A, 4)),
    "keccak_mixed": ir.Keccak(ir.Blob((ir.WordBytes(A, 4), ir.WordBytes(B), ir.WordBytes(C, 1)))),
    "keccak_single": ir.Keccak(ir.WordBytes(A)),
    # constant operands: every conversion needs a uint256-typed operand
    "slt_negative_const": ir.Op("slt", (A, ir.const(-5))),
    "sgt_negative_const_left": ir.Op("sgt", (ir.const(-5), A)),
    "sge_big_const": ir.Op("iszero", (ir.Op("slt", (A, ir.Const(2**255))),)),
    "signextend_const_index": ir.Op("signextend", (ir.Const(1), A)),
    "shl_const_base": ir.Op("shl", (ir.Op("and", (A, ir.Const(511))), ir.const(-3))),
    "not_of_bool": ir.Op("not", (ir.Op("lt", (A, B)),)),
    "ternary_consts": ir.Ternary(ir.Op("lt", (A, B)), ir.const(-1), ir.Const(2)),
    "packed_wide_const_narrow": ir.Keccak(ir.Blob((ir.WordBytes(ir.Const(0x1234), 1), ir.WordBytes(A, 3)))),
    "bytesword_const_selector": ir.Op("add", (ir.BytesWord(ir.WordBytes(ir.Const(0xDEADBEEF), 4)), A)),
}


def _substitute(e, args):
    def f(n):
        if isinstance(n, ir.CalldataWord) and isinstance(n.offset, ir.Const):
            k = (n.offset.value - 4) // 32
            return ir.Const(args[k])
        return n

    return ir.transform(e, f)


def _contract(cases):
    """A contract routing selector 0x10000000 + i to case i."""
    units = []
    for i, (name, e) in enumerate(cases):
        sel = 0x10000000 + i
        key = f"0x{sel:08x}"
        fn = ir.Function(key, (ir.Return(ir.Blob((ir.WordBytes(e),))),))
        spec = EntrySpec(key=key, kind="function", selector=sel, mutability="pure")
        units.append(Unit(key, fn, spec))
    return units


def _operands(op, rnd, n_random=24):
    out = []
    for a in EDGE:
        for b in (EDGE if op not in UNARY else [0]):
            out.append((a, b, rnd.choice(EDGE)))
    for _ in range(n_random):
        out.append(tuple(rnd.getrandbits(rnd.choice((8, 64, 256))) for _ in range(3)))
    if op in ("shl", "shr", "sar", "byte", "signextend"):
        for _ in range(40):
            out.append((rnd.randrange(0, 300), rnd.getrandbits(256), 0))
    return out


@pytest.fixture(scope="module")
def world_and_cases():
    backend = backend_or_skip()
    from scobelix.verify.evm import make_world

    cases = [(op, op_expr(op)) for op in list(BINARY) + list(UNARY) + list(TERNARY)] + list(EXTRA.items())
    units = _contract(cases)
    ci = ContractInput(units=units, target="0.8.19", original="test")
    source, _ = assemble(ci)
    return backend, make_world, cases, source


def _check(world_and_cases, version):
    if version not in installed():
        pytest.skip(f"solc {version} is not installed")
    backend, make_world, cases, source = world_and_cases
    art = compile_or_fail(source, version)
    caller, cand, ref_addr = "0x" + "a1" * 20, "0x" + "c0" * 20, "0x" + "e0" * 20
    rnd = random.Random(1234)
    failures = []
    for i, (op, e) in enumerate(cases):
        world = make_world(backend)  # fresh: a long-lived world slows down
        world.set_balance(caller, 10**20)
        world.set_code(cand, art.runtime)
        refs = {}
        if op in BINARY or op in UNARY or op in TERNARY:
            world.set_code(ref_addr, evm_code(op))
            refs[op] = ref_addr
        for a, b, c in _operands(op, rnd):
            args = (a, b, c)
            data = b"".join(x.to_bytes(32, "big") for x in args)
            got = world.call(caller, cand, (0x10000000 + i).to_bytes(4, "big") + data)
            expected = ir.evaluate(_substitute(e, args))
            if op in refs:
                ref = world.call(caller, refs[op], b"\0\0\0\0" + data)
                assert ref.success
                assert int.from_bytes(ref.output, "big") == expected, f"ir.evaluate wrong for {op}{args}"
            if not got.success or int.from_bytes(got.output, "big") != expected:
                failures.append((op, args, got.success, got.output.hex(), hex(expected)))
                if len(failures) > 10:
                    break
    assert not failures, failures[:10]


def test_rendered_ops_match_the_evm(world_and_cases):
    _check(world_and_cases, "0.8.19")


@pytest.mark.slow
def test_rendered_ops_match_the_evm_latest_solc(world_and_cases):
    _check(world_and_cases, "0.8.31")


def test_reference_semantics_of_masks():
    """ir.Mask is the decompiler's mask_shl (algebra.apply_mask), with the
    word reduced modulo 2**256."""
    from scobelix.core.algebra import apply_mask

    rnd = random.Random(7)
    for _ in range(500):
        size = rnd.choice([1, 5, 8, 32, 160, 251, 255, 256])
        off = rnd.choice([0, 1, 5, 8, 96, 224])
        shl = rnd.choice([0, 1, 4, 96, -1, -5, -224])
        v = rnd.getrandbits(256)
        assert ir.mask_value(size, off, shl, v) == apply_mask(v, size, off, shl) % ir.WORD_MOD

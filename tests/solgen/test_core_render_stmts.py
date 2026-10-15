"""
Render exactness of statements: each case is an IR function routed from
fallback(), executed on an EVM backend, and compared with what the EVM
semantics of the IR give (computed here by hand).
"""

import hashlib

import pytest
from eth_utils import keccak

from conftest import backend_or_skip, compile_or_fail
from scobelix.solgen import ir
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.contract import ContractInput, Unit, assemble

A, B, C = (ir.CalldataWord(ir.Const(o)) for o in (4, 36, 68))
CALLER = "0x" + "a1" * 20
CAND = "0x" + "c0" * 20
ECHO = "0x" + "e1" * 20  # returns its calldata
REVERTER = "0x" + "e2" * 20  # reverts with its calldata

# runtime code: calldatacopy(0, 0, calldatasize) return / revert (0, calldatasize)
ECHO_CODE = bytes.fromhex("366000600037366000f3")
REVERT_CODE = bytes.fromhex("366000600037366000fd")


def word(x):
    return x.to_bytes(32, "big")


def L(n):
    return ir.Local(n)


def assign(n, v):
    return ir.Assign(ir.Local(n), v)


def ret_words(*ws):
    return ir.Return(ir.Blob(tuple(ir.WordBytes(w) for w in ws)))


def _addr(a):
    return ir.Const(int(a, 16))


LOOP = "Node((99, 4, ('1',)))"

CASES = {
    "sstore_field": (
        (ir.Sstore(ir.Const(5), A, 8, 16), ret_words(ir.Sload(ir.Const(5)))),
        lambda a, b, c, pre: (True, word((pre & ~(0xFFFF << 8)) | ((a & 0xFFFF) << 8))),
    ),
    "sstore_field_symbolic": (
        (ir.Sstore(ir.Const(5), A, ir.Op("and", (B, ir.Const(127))), ir.Op("add", (ir.Op("and", (C, ir.Const(63))), ir.ONE))),
         ret_words(ir.Sload(ir.Const(5)))),
        lambda a, b, c, pre: (True, word((pre & ~((((1 << ((c & 63) + 1)) - 1) << (b & 127)) % 2**256))
                                         | ((a << (b & 127)) & ((((1 << ((c & 63) + 1)) - 1) << (b & 127)) % 2**256)))),
    ),
    "sstore_full": (
        (ir.Sstore(ir.Op("add", (ir.Const(5), B)), A), ret_words(ir.Sload(ir.Op("add", (ir.Const(5), B))))),
        lambda a, b, c, pre: (True, word(a)),
    ),
    "memory_words_and_bytes": (
        (ir.Mstore(ir.Const(0x80), ir.WordBytes(A)), ir.Mstore(ir.Const(0x82), ir.WordBytes(B, 1)),
         ir.Return(ir.MemSlice(ir.Const(0x7F), ir.Const(40)))),
        lambda a, b, c, pre: (True, (b"\0" + word(a)[:2] + bytes([b & 0xFF]) + word(a)[3:] + bytes(7))[:40]),
    ),
    "memory_unaligned_load": (
        (ir.Mstore(ir.Const(0x80), ir.WordBytes(A)), ir.Mstore(ir.Const(0xA0), ir.WordBytes(B)),
         ret_words(ir.MLoad(ir.Const(0x8F)))),
        lambda a, b, c, pre: (True, (word(a) + word(b))[0xF:0xF + 32]),
    ),
    "memory_never_written": (
        (ret_words(ir.MLoad(ir.Op("and", (C, ir.Const(0xFFFF))))),),
        lambda a, b, c, pre: (True, word(0)),
    ),
    "memory_unaligned_copies": (
        (ir.Mstore(ir.Const(0x83), ir.CalldataSlice(ir.Const(4), ir.Const(96))),
         ir.Mstore(ir.Const(0x90), ir.WordBytes(C, 5)),
         ir.Mstore(ir.Const(0x101), ir.MemSlice(ir.Const(0x85), ir.Const(45))),
         ir.Return(ir.MemSlice(ir.Const(0x81), ir.Const(0xB7)))),
        lambda a, b, c, pre: (True, _memory_unaligned(a, b, c)),
    ),
    "memory_long_copy": (
        (ir.Mstore(ir.Const(0x101), ir.CalldataSlice(ir.Const(4), ir.Const(5000))),
         ret_words(ir.Keccak(ir.MemSlice(ir.Const(0xF0), ir.Const(4000))), ir.MLoad(ir.Const(0x101 + 90)))),
        lambda a, b, c, pre: (True, _memory_long(a, b, c)),
    ),
    "word_slice_symbolic": (
        (ir.Return(ir.Blob((ir.WordSlice(A, ir.Op("and", (B, ir.Const(63)))), ir.WordBytes(C, 2)))),),
        lambda a, b, c, pre: (True, _word_slice(a, b & 63) + word(c)[-2:]),
    ),
    "code_copy_past_end": (
        (ir.Return(ir.CodeSlice(ir.Op("and", (A, ir.Const(0x3FF))), ir.Const(70))),),
        lambda a, b, c, pre: (True, ORIGINAL_CODE[a & 0x3FF:][:70].ljust(70, b"\0")),
    ),
    "calldata_past_end": (
        (ir.Return(ir.CalldataSlice(ir.Const(90), ir.Const(64))),),
        lambda a, b, c, pre: (True, (word(a) + word(b) + word(c))[86:] .ljust(64, b"\0")),
    ),
    "log2_mixed_data": (
        (ir.Log((ir.Const(0xABCD), A), ir.Blob((ir.WordBytes(B), ir.WordBytes(C, 4)))), ir.Stop()),
        lambda a, b, c, pre: (True, b""),
    ),
    "revert_error_string": (
        (ir.Revert(ir.ErrorString(b'say "hi"\n')),),
        lambda a, b, c, pre: (False, bytes.fromhex("08c379a0") + word(32) + word(9) + b'say "hi"\n'.ljust(32, b"\0")),
    ),
    "revert_panic": (
        (ir.Revert(ir.Panic(0x11)),),
        lambda a, b, c, pre: (False, bytes.fromhex("4e487b71") + word(0x11)),
    ),
    "revert_custom": (
        (ir.Revert(ir.Custom(0xDEADBEEF, (ir.WordBytes(A), ir.WordBytes(B, 2)))),),
        lambda a, b, c, pre: (False, bytes.fromhex("deadbeef") + word(a) + word(b)[-2:]),
    ),
    "revert_empty": (
        (ir.Revert(ir.Empty()),),
        lambda a, b, c, pre: (False, b""),
    ),
    "fib_parallel_updates": (
        (ir.While(ir.Op("lt", (L("v0"), ir.Op("and", (A, ir.Const(63))))),
                  (ir.Continue(LOOP, (assign("v0", ir.Op("add", (L("v0"), ir.ONE))), assign("v1", L("v2")),
                                      assign("v2", ir.Op("add", (L("v1"), L("v2")))))),),
                  (assign("v0", ir.ZERO), assign("v1", ir.ZERO), assign("v2", ir.ONE)), LOOP),
         ret_words(L("v1"))),
        lambda a, b, c, pre: (True, word(_fib(a & 63))),
    ),
    "while_true_label_style": (
        (ir.While(ir.ONE,
                  (ir.If(ir.Op("gt", (L("v0"), ir.Op("and", (A, ir.Const(15))))),
                         (ret_words(L("v0")),),
                         (ir.Continue(LOOP, (assign("v0", ir.Op("add", (L("v0"), ir.Const(3)))),)),)),),
                  (assign("v0", ir.ZERO),), LOOP),),
        lambda a, b, c, pre: (True, word(next(x for x in range(0, 100, 3) if x > (a & 15)))),
    ),
    "staticcall_echo": (
        (ir.ExtCall(1, "staticcall", None, _addr(ECHO), None, ir.Const(0x11223344), ir.WordBytes(A)),
         ir.Return(ir.Blob((ir.WordBytes(ir.CallOut(1, "success")), ir.WordBytes(ir.CallOut(1, "returndatasize")),
                            ir.ReturnData(1, ir.Const(2), ir.Const(40)))))),
        lambda a, b, c, pre: (True, word(1) + word(36) + (bytes.fromhex("11223344") + word(a))[2:].ljust(40, b"\0")),
    ),
    "call_bubble": (
        (ir.ExtCall(1, "call", None, _addr(REVERTER), ir.ZERO, None, ir.WordBytes(A, 5)),
         ir.If(ir.Op("iszero", (ir.CallOut(1, "success"),)), (ir.Revert(ir.Bubble(1)),), (ir.Stop(),))),
        lambda a, b, c, pre: (False, word(a)[-5:]),
    ),
    "sha256_precompile": (
        (ir.Precompile(1, 2, "sha256hash", ir.Blob((ir.WordBytes(A), ir.WordBytes(B, 3))), "hash_1"),
         ret_words(L("hash_1"), ir.CallOut(1, "success"))),
        lambda a, b, c, pre: (True, hashlib.sha256(word(a) + word(b)[-3:]).digest() + word(1)),
    ),
    "keccak_blob": (
        (ret_words(ir.Keccak(ir.Blob((ir.WordBytes(A, 20), ir.ConstBytes(b"\x01\x02"), ir.ZeroBytes(ir.Const(3)))))),),
        lambda a, b, c, pre: (True, keccak(word(a)[-20:] + b"\x01\x02" + bytes(3))),
    ),
    "return_raw_bytes": (
        (ir.Return(ir.Blob((ir.WordBytes(A, 1), ir.WordBytes(B, 31), ir.WordBytes(C, 2)))),),
        lambda a, b, c, pre: (True, word(a)[-1:] + word(b)[-31:] + word(c)[-2:]),
    ),
    "invalid_halts": (
        (ir.Invalid(),),
        lambda a, b, c, pre: (False, b""),
    ),
    "unstructured_reverts": (
        (ir.Unstructured("('weird', 1)", "test"),),
        lambda a, b, c, pre: (False, None),
    ),
}


def _fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a % 2**256


def _calldata(a, b, c):
    return b"\0\0\0\0" + word(a) + word(b) + word(c)  # the 4 selector bytes do not matter


def _memory_unaligned(a, b, c):
    mem = bytearray(0x200)
    cd = _calldata(a, b, c)
    mem[0x83:0x83 + 96] = cd[4:100]
    mem[0x90:0x95] = word(c)[-5:]
    mem[0x101:0x101 + 45] = mem[0x85:0x85 + 45]
    return bytes(mem[0x81:0x81 + 0xB7])


def _memory_long(a, b, c):
    mem = bytearray(0x101 + 5000 + 32)
    mem[0x101:0x101 + 96] = _calldata(a, b, c)[4:]  # calldata[4:5004], zero past its end
    return keccak(bytes(mem[0xF0:0xF0 + 4000])) + bytes(mem[0x101 + 90:0x101 + 90 + 32])


def _word_slice(v, n):
    return (v % (1 << (8 * n))).to_bytes(n, "big") if n <= 32 else bytes(n - 32) + word(v)


ORIGINAL_CODE = bytes(range(256)) * 2 + b"\x7f"  # what CodeSlice copies (the "original" runtime code)


@pytest.fixture(scope="module")
def deployed():
    backend = backend_or_skip()
    from scobelix.verify.evm import make_world

    units = []
    keys = {}
    for i, (name, (body, _)) in enumerate(CASES.items()):
        sel = 0x20000000 + i
        key = f"0x{sel:08x}"
        units.append(Unit(key, ir.Function(key, body), EntrySpec(key=key, kind="function", selector=sel)))
        keys[name] = sel
    source, _ = assemble(ContractInput(units=units, target="0.8.19", original="test", original_code=ORIGINAL_CODE))
    art = compile_or_fail(source, "0.8.19")
    return backend, make_world, art.runtime, keys, source


OPERANDS = [(0, 0, 0), (1, 2, 3), (2**256 - 1, 2**255, 7), (0x1234567890ABCDEF << 100, 2**160 + 5, 2**64),
            (37, 0xFFFF, 2**255 - 1)]


@pytest.mark.parametrize("name", list(CASES))
def test_statement_is_exact(deployed, name):
    backend, make_world, runtime, keys, source = deployed
    _, expected = CASES[name]
    for a, b, c in OPERANDS:
        world = make_world(backend)
        world.set_balance(CALLER, 10**20)
        world.set_code(CAND, runtime)
        world.set_code(ECHO, ECHO_CODE)
        world.set_code(REVERTER, REVERT_CODE)
        pre = 0x0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
        world.set_storage(CAND, 5, pre)
        res = world.call(CALLER, CAND, keys[name].to_bytes(4, "big") + word(a) + word(b) + word(c))
        ok, out = expected(a, b, c, pre)
        assert res.success == ok, (name, (a, b, c), res.error, res.output.hex())
        if out is not None:
            assert res.output == out, (name, (a, b, c), res.output.hex(), out.hex())
        if name == "log2_mixed_data":
            assert [(t, d) for _, t, d in res.logs] == [((0xABCD, a), word(b) + word(c)[-4:])]
        if name == "invalid_halts":
            assert res.halted

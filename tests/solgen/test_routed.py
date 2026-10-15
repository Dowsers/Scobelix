"""
Routed functions with typed parameters (selectors the signature database
does not name): the abi pass declares their parameters from the decoder
checks of the original (passes/abi._route) and fallback() decodes them with
abi.decode (contract.py).

The differential tests compile a probe with a given solc build, decompile
it with every signature lookup answering NOTHING (so every function of the
probe is routed), generate it again, and run both runtimes on crafted
calldata: short and long encodings, dirty high bits of every value
parameter, enum values out of range, bad offsets and lengths of dynamic
parameters (lengths of 2**64 and more included), trailing bytes, empty and
1-3 byte calldata, unknown selectors, with and without value.  Success,
return data, revert data, logs, storage and balances must be the same.
"""

from __future__ import annotations

import logging
import random
from typing import Dict, List, Optional, Sequence, Tuple

import pytest
from eth_abi import encode as abi_encode

from conftest import backend_or_skip, compile_or_fail
from probes import Build, calldata_cases, compile_probe, patch_signatures, selector
from scobelix.solgen import ir
from scobelix.solgen.abi import EntrySpec, _leaves
from scobelix.solgen.types import parse_type, split_types

TARGET = "0x" + "0e" * 20
CALLER = "0x" + "a1" * 20
W = 1 << 256

# ---------------------------------------------------------------- probes

R_SOURCE = """
contract R {
    enum E { A, B, C }
    uint256 public stored;
    event Set(uint256 indexed k, uint256 v);
    function u8(uint8 x) external pure returns (uint256) { return x; }
    function u40(uint40 x) external pure returns (uint40) { return x; }
    function u128(uint128 a, uint128 b) external pure returns (uint256) { return uint256(a) + b; }
    function i8(int8 x) external pure returns (int256) { return x; }
    function i128(int128 x) external pure returns (int128) { return x; }
    function i256(int256 x) external pure returns (int256) { return x / 3; }
    function flag(bool b) external pure returns (bool) { return !b; }
    function who(address a) external view returns (bool, address) { return (a == msg.sender, a); }
    function b4(bytes4 x) external pure returns (bytes4) { return x; }
    function b32(bytes32 x, bytes16 y) external pure returns (bytes32) { return x ^ bytes32(y); }
    function en(E e) external pure returns (uint256) { return uint256(e); }
    function none() external pure returns (uint256) { return 7; }
    function set(uint256 k, uint256 v) external { stored = k + v; emit Set(k, v); }
    function pay(uint256 v) external payable returns (uint256) { return v ^ msg.value; }
    function loop(uint256 n) external pure returns (uint256) {
        for (uint256 i = 0; i < 10; i++) { if (i == n) return i * 3; }
        return 99;
    }
    function name() external pure returns (string memory) { return "routed"; }
    function raw(uint256 x) external pure returns (uint256) { assembly { mstore(0, x) return(0, 31) } }
    function halt(uint256 x) external { if (x == 1) { stored = 1; return; } stored = 2; }
    function many(uint8 a, uint16 b, uint32 c, uint64 d, address e) external pure returns (uint256) {
        return uint256(a) ^ b ^ c ^ d ^ uint256(uint160(e));
    }
}
"""

F_SOURCE = """
contract F {
    uint256 public last;
    event Got(uint256 n);
    function f1(uint256 x) external returns (uint256) { last = x; return x * 2; }
    function f2(address a) external view returns (bool) { return a == msg.sender; }
    function f3(int16 a) external payable { last = uint256(int256(a)) + msg.value; }
    receive() external payable { emit Got(msg.value); }
    fallback() external payable { last = msg.data.length; }
}
"""

F_SOURCE_05 = """
contract F {
    uint256 public last;
    function f1(uint256 x) external returns (uint256) { last = x; return x * 2; }
    function f3(int16 a) external payable { last = uint256(int256(a)) + msg.value; }
    function() external payable { last = msg.data.length; }
}
"""

# a fallback of the original that returns the calldata (solc >= 0.7.6)
G_SOURCE = """
contract G {
    function g1(uint8 x) external pure returns (uint256) { return x; }
    function g2(uint256 x) external pure { require(x != 3, "three"); }
    fallback(bytes calldata d) external returns (bytes memory) { return d; }
}
"""

# a receive() without fallback: unknown selectors revert
H_SOURCE = """
contract H {
    uint256 public last;
    function h1(uint256 x) external { last = x; }
    receive() external payable { last = msg.value; }
}
"""

D_SOURCE = """
contract D {
    struct S { uint8 a; address b; }
    function dBytes(bytes calldata d) external pure returns (uint256) { return d.length; }
    function dArr(uint256[] calldata a, uint8 k) external pure returns (uint256) { return a.length + k; }
    function dStr(string calldata s, uint256 x) external pure returns (uint256) { return bytes(s).length ^ x; }
    function dMem(bytes memory d) external pure returns (uint256) { return d.length; }
    function dAddrs(address[] calldata a) external pure returns (uint256) { return a.length; }
    function nested(uint256[][] calldata a) external pure returns (uint256) { return a.length; }
    function nestedMem(bytes[] memory b) external pure returns (uint256) { return b.length; }
    function sArr(uint8[3] calldata a) external pure returns (uint256) { return uint256(a[0]) + a[2]; }
    function sArrMem(uint16[2] memory a) external pure returns (uint256) { return a[1]; }
    function sStruct(S calldata s) external pure returns (uint256) { return s.a; }
    function sStructMem(S memory s) external pure returns (address) { return s.b; }
}
"""

# ABI coder v1 (no struct, no nested dynamic type)
D_SOURCE_V1 = """
contract D {
    function dBytes(bytes calldata d) external pure returns (uint256) { return d.length; }
    function dArr(uint256[] calldata a, uint8 k) external pure returns (uint256) { return a.length + k; }
    function dStr(string calldata s, uint256 x) external pure returns (uint256) { return bytes(s).length ^ x; }
    function dMem(bytes memory d) public pure returns (uint256) { return d.length; }
    function sArr(uint8[3] calldata a) external pure returns (uint256) { return uint256(a[0]) + a[2]; }
    function sArrMem(uint16[2] memory a) public pure returns (uint256) { return a[1]; }
}
"""

# byte strings decoded to memory (public functions), with a calldata one and an array beside
M_SOURCE = """
contract M {
    string public label;
    function setLabel(string memory s) public { label = s; }
    function lenOf(bytes memory b, uint8 k) public pure returns (uint256) { return b.length + k; }
    function two(string memory a, string memory b) public pure returns (uint256) {
        return bytes(a).length * 100 + bytes(b).length;
    }
    function mixed(bytes memory a, bytes calldata b) external pure returns (uint256) { return a.length ^ b.length; }
    function arr(uint256[] memory a) public pure returns (uint256) { return a.length; }
    function first(bytes memory b) public pure returns (bytes1) { return b.length > 0 ? b[0] : bytes1(0); }
}
"""

# checks made after a byte string is decoded to memory, on a word before it: the body's own range
# test (no message), the validator of a calldata array member the body reads; and a range test of
# the last word, which the decoder order allows to type
O_SOURCE = """
contract O {
    function a(uint256 x, bytes memory b) public pure returns (uint256) { require(x < 10); return b.length + x; }
    function n(uint256 x, uint8 k, string memory s) public pure returns (uint256) {
        if (x >= 3) revert();
        return bytes(s).length + k + x;
    }
    function m(uint8[2] calldata p, bytes memory b) external pure returns (uint256) { return p[1] + b.length; }
    function q(bytes memory b, uint256 x) public pure returns (uint256) { require(x < 10); return b.length + x; }
}
"""

# a body close to the renderer's stack budget (emulated memory, a low-level call in a loop): a
# typed parameter would sit below its locals, out of reach of its deepest expressions
K_SOURCE = """
contract K {
    address[] public members;
    function ping(bytes calldata data) external {
        for (uint256 i = 0; i < members.length; i++) {
            (bool ok,) = members[i].call(data);
            require(ok);
        }
    }
}
"""

# locals the compiler moved to memory (via-IR, optimiser): the free memory pointer of the original
# starts above 0x80, so its decoder panics on lengths the decoder of the generated text accepts
L_SOURCE = "contract L {\n" + "".join(f"    uint256 s{i} = {i};\n" for i in range(1, 15)) + """    uint256 public total;
    function many(bytes memory b) public returns (uint256 r) {
""" + "".join(f"        uint256 a{i} = s{i};\n" for i in range(1, 15)) + """        for (uint256 i = 0; i < b.length; i++) {
            total += a1 * i + a2;
            r ^= a3 * i + a4;
            total += a5 * r + a6;
            r += a7 * i ^ a8;
            total ^= a9 + a10 * i;
            r += a11 * a12 + i;
            total += a13 ^ (a14 + r);
        }
    }
}
"""

# sample values of the types calldata_cases does not craft (nested dynamic types, structs)
SAMPLES = {
    "nested(uint256[][])": [[[1, 2], [3]]],
    "nestedMem(bytes[])": [[b"\x01\x02", b"", bytes(40)]],
    "sStruct((uint8,address))": [(7, "0x" + "a1" * 20)],
    "sStructMem((uint8,address))": [(7, "0x" + "a1" * 20)],
}

EDGE_WORDS = (0, 1, 31, 32, 33, 64, (1 << 32) - 1, 1 << 32, (1 << 64) - 1, 1 << 64, (1 << 64) + 64, 1 << 255,
              W - 32, W - 1)


# ---------------------------------------------------------------- the harness

def _canonical(item: dict) -> str:
    if item["type"].startswith("tuple"):
        return "(" + ",".join(_canonical(c) for c in item["components"]) + ")" + item["type"][5:]
    return item["type"]


def signatures(abi: list) -> List[str]:
    return [f"{i['name']}({','.join(_canonical(x) for x in i['inputs'])})" for i in abi if i.get("type") == "function"]


def word_mutations(signature: str, values: Sequence[object]) -> List[bytes]:
    """The encoding of `values`, every word of it set to each edge value in
    turn, and the encoding cut at every word boundary."""
    types = split_types(signature.split("(", 1)[1][:-1])
    data = abi_encode(types, list(values))
    out = [data]
    for i in range(len(data) // 32):
        for v in EDGE_WORDS:
            out.append(data[:32 * i] + v.to_bytes(32, "big") + data[32 * i + 32:])
    out.extend(data[:k] for k in range(0, len(data), 32))
    out.append(data + b"\xff" * 5)
    return [selector(signature) + d for d in out]


def cases(signature: str) -> List[bytes]:
    """Crafted calldata of one function: probes.calldata_cases, with the
    members of a static struct / array as words of their own, or the word
    mutations of sample values."""
    if signature in SAMPLES:
        return word_mutations(signature, SAMPLES[signature])
    name, rest = signature.split("(", 1)
    flat = []
    for t in (parse_type(x) for x in split_types(rest[:-1]) if x):
        static_composite = (t.kind == "tuple" or (t.kind == "array" and t.length is not None)) and not t.is_dynamic
        flat.extend(x.canonical for x in _leaves(t)) if static_composite else flat.append(t.canonical)
    sel = selector(signature)
    return [sel + c[4:] for c in calldata_cases(f"{name}({','.join(flat)})") if len(c) >= 4]


def special_calls() -> List[bytes]:
    """Calldata matching no selector: empty, 1 to 3 bytes, unknown selectors."""
    return [b"", b"\x01", b"\xaa\xbb", b"\x00\x00\x00", b"\x12\x34\x56\x78", b"\xff" * 4 + bytes(32)]


def outcome(runtime: bytes, data: bytes, value: int, storage: Optional[Dict[int, int]] = None):
    from scobelix.verify.evm import make_world

    world = make_world(backend_or_skip())
    world.set_code(TARGET, runtime)
    if storage:
        world.set_storage_many(TARGET, storage)
    world.set_balance(CALLER, 10**20)
    r = world.call(CALLER, TARGET, data, value=value)
    logs = tuple((a.lower(), tuple(t), bytes(d)) for a, t, d in r.logs)
    diff = tuple(sorted((a.lower(), k, v[1]) for (a, k), v in r.storage_diff.items()))
    balances = tuple(sorted((a.lower(), b) for a, b in r.balances.items()))
    return r.success, bytes(r.output), logs, diff, balances


def differential(original: bytes, source: str, target: str, calls: Sequence[Tuple[bytes, int]]) -> List[tuple]:
    art = compile_or_fail(source, target)
    out = []
    for data, value in calls:
        a, b = outcome(original, data, value), outcome(art.runtime, data, value)
        if a != b:
            out.append((data.hex(), value, a[:2], b[:2]))
    return out


def generate(runtime: bytes, disabled: Optional[dict] = None, **kw):
    from scobelix.decompiler import decompile_bytecode
    from scobelix.solgen.v2 import generate as v2_generate

    logging.disable(logging.CRITICAL)
    try:
        d = decompile_bytecode(runtime.hex())
    finally:
        logging.disable(logging.NOTSET)
    return v2_generate(d, idiom_level="full", disabled_passes=disabled, **kw)


def routed_probe(source: str, build: Build, contract: str, monkeypatch, values=(0, 1)):
    """Compile, hide every signature, generate, run the differential on the
    crafted calls of every function (the untranslated ones aside: they
    revert by design) and on calldata matching no selector."""
    art = compile_probe(source, build, contract)
    patch_signatures(monkeypatch, [])
    r = generate(art.runtime)
    by_sel = {"0x" + selector(s).hex(): s for s in signatures(art.abi)}
    assert {k for k, f in r.functions.items() if f["routed"]} == set(by_sel), sorted(r.functions)
    calls: List[Tuple[bytes, int]] = []
    for key, sig in sorted(by_sel.items()):
        if "unstructured" in r.functions[key]["flags"]:
            continue
        for v in values:
            calls.extend((c, v) for c in cases(sig))
    for v in values:
        calls.extend((c, v) for c in special_calls())
    bad = differential(art.runtime, r.solidity, r.target_solc, calls)
    assert not bad, f"{len(bad)} differences of {len(calls)} calls, e.g. {bad[:3]}"
    names = {by_sel[k].split("(")[0]: f for k, f in r.functions.items() if k in by_sel}
    return r, names, art


def route(f: dict) -> Optional[str]:
    return (f.get("abi") or {}).get("route")


# ---------------------------------------------------------------- default run (solc 0.8.19)

def test_value_parameters_and_returns_are_typed_0819(monkeypatch):
    r, f, _ = routed_probe(R_SOURCE, Build("0.8.19"), "R", monkeypatch)
    src = r.solidity
    assert "fallback(bytes calldata input) external payable returns (bytes memory) {" in src
    assert "if (input.length >= 4) {" in src
    for name, typ in (("u8", "uint8"), ("u40", "uint40"), ("i8", "int8"), ("i128", "int128"), ("i256", "uint256"),
                      ("flag", "bool"), ("b4", "bytes4"), ("en", "Enum3"), ("pay", "uint256"), ("loop", "uint256")):
        assert route(f[name]) == "typed", (name, f[name]["abi"])
        assert "abi" in f[name]["passes"], name
        assert f"abi.decode(input[4:], ({typ}))" in src, (name, typ)
    sel = {n: x["selector"][2:] for n, x in f.items()}
    # the value of a return is the private function's, encoded by the router
    assert f"function _fn_{sel['u8']}(uint8 arg0) private pure returns (uint8)" in src
    assert f"if (msg.sig == 0x{sel['u8']}) {{" in src
    assert f"return abi.encode(_fn_{sel['u8']}(abi.decode(input[4:], (uint8))));" in src
    assert f"(bool r0, address r1) = _fn_{sel['who']}(abi.decode(input[4:], (address)));" in src
    assert "return abi.encode(r0, r1);" in src
    # (the router's locals take the private function's parameter names)
    assert f"(uint128 arg0, uint128 arg1) = abi.decode(input[4:], (uint128, uint128));" in src
    assert f"_fn_{sel['set']}(arg0, arg1);\n                return \"\";" in src  # STOP: an empty success
    assert f"function _fn_{sel['name']}() private pure returns (string memory)" in src
    # payable: no callvalue check in its route, the others reject value before decoding
    pay = src[src.index(f"if (msg.sig == 0x{sel['pay']})"):]
    assert pay.split("\n")[0].endswith(f"return abi.encode(_fn_{sel['pay']}(abi.decode(input[4:], (uint256))));")
    # raw returns and halts keep their exact helpers in the typed body
    assert route(f["raw"]) == "typed" and "_return(" in src
    # five parameters and a return value: over the stack slots of a typed body
    assert route(f["many"]) == "untyped" and f["many"]["abi"]["why"] == "too many parameters for the stack"
    assert f"_fn_{sel['many']}();" in src
    assert "routed (" in src.split("entry points")[1].split("\n")[0]


def test_own_fallback_and_receive_0819(monkeypatch):
    r, f, _ = routed_probe(F_SOURCE, Build("0.8.19"), "F", monkeypatch, values=(0, 3))
    src = r.solidity
    assert all(route(x) == "typed" for x in f.values()), {n: x["abi"] for n, x in f.items()}
    assert "receive() external payable {" in src
    body = src[src.index("fallback(bytes calldata input) external payable returns (bytes memory)"):]
    body = body[:body.index("\n    }\n")]
    assert "msg.data.length" in body and 'return "";' in body  # the original's fallback, its STOP


def test_byte_strings_decoded_to_memory_0819(monkeypatch):
    r, f, _ = routed_probe(M_SOURCE, Build("0.8.19"), "M", monkeypatch)
    src = r.solidity
    for name in ("setLabel", "lenOf", "two", "first"):
        assert route(f[name]) == "typed" and f[name]["abi"]["memory_bytes"] >= 1, (name, f[name]["abi"])
        assert f[name]["abi"]["prologue_removed"], (name, f[name]["abi"])
    assert "(bytes memory arg0, uint8 arg1) = abi.decode(input[4:], (bytes, uint8));" in src
    sel = f["lenOf"]["selector"][2:]
    assert f"function _fn_{sel}(bytes memory arg0, uint8 arg1) private pure returns (uint256)" in src
    # a calldata byte string beside (abi.decode would copy it and panic where the original reverts
    # without data), an array decoded to memory (its elements are checked in the copy loop): untyped
    for name in ("mixed", "arr"):
        assert route(f[name]) == "untyped" and f[name]["abi"]["why"] == "memory parameter", (name, f[name]["abi"])


def _words(*values: int) -> bytes:
    return b"".join(v.to_bytes(32, "big") for v in values)


def _order_probe(build: Build, monkeypatch):
    """O_SOURCE: a check of the chain made after the byte string's checks (a Panic(0x41) on its
    length) is no decoder check of an earlier word, and abi.decode must not make it first (the
    word stays a uint256, the check stays in the body): huge lengths with words out of range."""
    art = compile_probe(O_SOURCE, build, "O")
    patch_signatures(monkeypatch, [])
    r = generate(art.runtime)
    data = _words(2) + b"\xaa\xbb" + bytes(30)
    calls = []
    for x in (5, 300, 1 << 255):
        for tail in (_words(1 << 64), data):
            calls += [selector("a(uint256,bytes)") + _words(x, 64) + tail,
                      selector("n(uint256,uint8,string)") + _words(x, 3, 96) + tail,
                      selector("m(uint8[2],bytes)") + _words(0, x, 96) + tail,
                      selector("q(bytes,uint256)") + _words(64, x) + tail]
    calls += [c for s in ("a(uint256,bytes)", "m(uint8[2],bytes)", "q(bytes,uint256)") for c in cases(s)]
    assert not differential(art.runtime, r.solidity, r.target_solc, [(c, 0) for c in calls])
    by_sel = {"0x" + selector(s).hex(): s.split("(")[0] for s in signatures(art.abi)}
    f = {by_sel[k]: x for k, x in r.functions.items() if k in by_sel}
    assert all(route(x) == "typed" for x in f.values()), {n: x["abi"] for n, x in f.items()}
    return r


def test_a_body_close_to_the_stack_budget_keeps_its_locals_in_memory_0819(monkeypatch):
    # with its parameter on the stack and its locals too, the text did not compile with the
    # default pipeline of solc ("Stack too deep") where the untyped body did
    art = compile_probe(K_SOURCE, Build("0.8.19"), "K")
    patch_signatures(monkeypatch, [x for x in art.abi if x.get("name") == "members"])  # ping: no known name
    r = generate(art.runtime)
    calls = [(c, v) for c in cases("ping(bytes)") + special_calls() for v in (0, 1)]
    assert not differential(art.runtime, r.solidity, r.target_solc, calls)
    key = "0x" + selector("ping(bytes)").hex()
    assert route(r.functions[key]) == "typed", r.functions[key]["abi"]
    body = r.solidity[r.solidity.index(f"function _fn_{key[2:]}(uint256 arg0) private {{"):]
    assert "memory _l; // locals (in memory: too many for the stack)" in body[:body.index("\n    }\n")], \
        "the body of the probe is no longer close to the stack budget: give it more locals"


def test_checks_after_a_byte_string_in_memory_keep_their_place_0819(monkeypatch):
    src = _order_probe(Build("0.8.19"), monkeypatch).solidity
    assert "abi.decode(input[4:], (uint256, bytes))" in src
    assert "abi.decode(input[4:], (uint256, uint8, bytes))" in src
    assert "abi.decode(input[4:], (uint256, uint256, bytes))" in src
    assert "abi.decode(input[4:], (bytes, Enum10))" in src  # (the last word: the decoder's order)


def _pointer_probe(build: Build, monkeypatch):
    """L_SOURCE: abi.decode in the router allocates from 0x80, the original's decoder from
    above (0xa0 here): for lengths of 2**64 - 0xdf to 2**64 - 0xc0 it raises Panic(0x41) where
    abi.decode reverts without data, so the byte string is not declared `bytes memory`."""
    art = compile_probe(L_SOURCE, build, "L")
    sel = selector("many(bytes)")
    calls = [(sel + _words(32, (1 << 64) - d + e), 0) for d in range(0x60, 0x140, 0x20) for e in (-1, 0, 1)]
    calls += [(c, v) for c in cases("many(bytes)") for v in (0, 1)]
    high = outcome(art.runtime, sel + _words(32, (1 << 64) - 0xc0), 0)
    assert not high[0] and high[1][:4] == selector("Panic(uint256)"), "the probe's pointer starts at 0x80"
    patch_signatures(monkeypatch, [])
    r = generate(art.runtime)
    assert not differential(art.runtime, r.solidity, r.target_solc, calls)
    f = r.functions["0x" + sel.hex()]
    assert route(f) == "untyped" and f["abi"]["why"] == "memory parameter", f["abi"]


def test_a_decoder_allocating_above_the_free_memory_pointer_of_the_target_0819_ir(monkeypatch):
    _pointer_probe(Build("0.8.19", via_ir=True), monkeypatch)


def test_a_named_decoder_allocating_above_the_target_pointer_is_said_0819_ir(monkeypatch):
    """The same function under its name: the selector needs the `bytes`
    parameter and the target's decoder runs first, from 0x80, so no
    declaration panics where the original's does on lengths near 2**64.
    The function says so; the other calls agree."""
    art = compile_probe(L_SOURCE, Build("0.8.19", via_ir=True), "L")
    sel = selector("many(bytes)")
    patch_signatures(monkeypatch, art.abi)
    r = generate(art.runtime)
    f = r.functions["0x" + sel.hex()]
    assert "abi:memory_start_above_0x80" in f["flags"], f["flags"]
    natspec = r.solidity[:r.solidity.index("function many(")].rsplit("@notice", 1)[1]
    assert "Panic(0x41)" in natspec and "near 2**64" in natspec, natspec
    calls = [(c, v) for c in cases("many(bytes)") for v in (0, 1)]
    assert not differential(art.runtime, r.solidity, r.target_solc, calls)
    # (a decoder from 0x80, the usual case, is not flagged)
    art = compile_probe("contract M { function many(bytes memory b) public pure returns (uint256) { return b.length; } }",
                        Build("0.8.19"), "M")
    patch_signatures(monkeypatch, art.abi)
    assert "abi:memory_start_above_0x80" not in generate(art.runtime).functions["0x" + sel.hex()]["flags"]


def test_the_untyped_route_is_the_abi_switch_of_the_function(monkeypatch):
    art = compile_probe(R_SOURCE, Build("0.8.19"), "R")
    patch_signatures(monkeypatch, [])
    from scobelix.decompiler import decompile_bytecode
    from scobelix.solgen.v2 import Generator

    logging.disable(logging.CRITICAL)
    try:
        g = Generator(decompile_bytecode(art.runtime.hex()), idiom_level="full")
    finally:
        logging.disable(logging.NOTSET)
    key = "0x" + selector("u128(uint128,uint128)").hex()
    r = g.regenerate({key: {"abi"}})
    assert r.functions[key]["tier"] in ("exact", "partial") and "abi" not in r.functions[key]["passes"]
    assert "abi" in r.functions[key]["disabled_passes"]
    assert f"_fn_{key[2:]}();" in r.solidity and f"function _fn_{key[2:]}() private pure {{" in r.solidity
    other = "0x" + selector("u8(uint8)").hex()
    assert r.functions[other]["abi"]["route"] == "typed"
    calls = [(c, 0) for s in ("u128(uint128,uint128)", "u8(uint8)") for c in cases(s)]
    assert not differential(art.runtime, r.solidity, r.target_solc, calls)
    # every pass off: the router of the exact tier (no input, no typed route)
    r0 = g.regenerate({"*": {"abi", "storage", "reverts", "arith", "calls", "events", "compound"}})
    assert "fallback() external payable {" in r0.solidity and "abi.decode(" not in r0.solidity


# ---------------------------------------------------------------- without a compiler

def _spec(key, head, inferred=None, dynamic=()):
    return EntrySpec(key=key, kind="function", selector=int(key, 16), head_words=head,
                     inferred=dict(inferred or {}), dynamic_words=frozenset(dynamic))


def _run(fn, spec, abi_v2=True):
    from scobelix.solgen import pipeline
    from scobelix.solgen.passes import abi as abi_pass

    ctx = pipeline.PassContext(specs={fn.key: spec}, metadata=None, dispatcher=None, target_solc="0.8.19",
                               abi_v2=abi_v2, idiom_level="full")
    out = abi_pass.run(fn, ctx)
    return out, ctx.facts["abi"]["functions"][fn.key]


CDS = ir.Env("calldatasize")


def _size_check(h):
    return ir.If(ir.Op("slt", (ir.Op("add", (ir.const(-4), CDS)), ir.Const(32 * h))), (ir.Revert(ir.Empty()),), ())


def _ret(*words):
    return ir.Return(ir.Blob(tuple(ir.WordBytes(w) for w in words)))


def test_route_decisions():
    cd = lambda i: ir.CalldataWord(ir.Const(4 + 32 * i))  # noqa: E731
    # two value words, the first an address: typed, the checks gone, the words read as parameters
    validator = ir.Op("iszero", (ir.Op("eq", (cd(0), ir.Mask(160, 0, 0, cd(0)))),))
    body = (_size_check(2),)
    body = (ir.If(body[0].cond, body[0].then, (ir.If(validator, (ir.Revert(ir.Empty()),), (_ret(cd(1)),)),)),)
    fn = ir.Function("0x00000001", body)
    spec = _spec("0x00000001", 2, {0: "address"})
    out, facts = _run(fn, spec)
    assert facts["route"] == "typed" and facts["prologue_removed"] and spec.typed_route
    assert [(t.canonical, n) for t, n in spec.params] == [("address", "arg0"), ("uint256", "arg1")]
    assert out.body == (ir.Return(ir.Blob((ir.WordBytes(ir.Param(1)),))),)
    assert [t.canonical for t in spec.returns] == ["uint256"]
    # a Panic(0x41) in the chain (a memory parameter): untyped, untouched
    panic = ir.If(ir.Op("gt", (cd(0), ir.Const((1 << 64) - 1))), (ir.Revert(ir.Panic(0x41)),), (_ret(cd(0)),))
    fn = ir.Function("0x00000002", (ir.If(_size_check(1).cond, (ir.Revert(ir.Empty()),), (panic,)),))
    out, facts = _run(fn, _spec("0x00000002", 1))
    assert out is fn and facts == {"route": "untyped", "why": "memory parameter"}
    # no size check, but arguments read: untyped; none read: no parameter
    fn = ir.Function("0x00000003", (_ret(cd(0)),))
    assert _run(fn, _spec("0x00000003", None))[1]["why"] == "no calldata size check"
    fn = ir.Function("0x00000004", (_ret(ir.Const(5)),))
    spec = _spec("0x00000004", None)
    assert _run(fn, spec)[1]["route"] == "typed" and spec.params == ()
    # a dynamic parameter: its head offset is a raw word, the offset check stays in the body
    offset = ir.If(ir.Op("gt", (cd(0), ir.Const((1 << 64) - 1))), (ir.Revert(ir.Empty()),), (_ret(cd(0)),))
    fn = ir.Function("0x00000005", (ir.If(_size_check(1).cond, (ir.Revert(ir.Empty()),), (offset,)),))
    spec = _spec("0x00000005", 1, {0: "dynamic"}, dynamic=(0,))
    out, facts = _run(fn, spec)
    assert facts["route"] == "typed" and facts["raw_words"] == 1 and facts["kept"] == 1
    assert [t.canonical for t, _ in spec.params] == ["uint256"]
    assert isinstance(out.body[0], ir.If) and ir.contains(out.body[0], ir.Param)
    # ABI coder v1: every word a uint256 (no validator to rely on)
    fn = ir.Function("0x00000006", (ir.If(_size_check(1).cond, (ir.Revert(ir.Empty()),), (_ret(cd(0)),)),))
    spec = _spec("0x00000006", 1, {0: "uint8"})
    _run(fn, spec, abi_v2=False)
    assert [t.canonical for t, _ in spec.params] == ["uint256"]


def test_a_byte_string_in_memory_is_typed_from_the_free_memory_pointer_of_the_target_only():
    from scobelix.solgen.passes import abi as abi_pass

    off = ir.CalldataWord(ir.Const(4))
    ln = ir.CalldataWord(ir.Op("add", (ir.Const(4), off)))
    bound, p41 = ir.Const((1 << 64) - 1), ir.Panic(0x41)

    def strings(base, wrapped=False):
        # the checks of `bytes memory` at head word 0: offset, length (Panic), allocation from
        # the free memory pointer `base` - 32 (Panic; none when `base` is None), data bounds
        checks = [(ir.Op("gt", (off, bound)), ir.Empty()), (ir.Op("gt", (ln, bound)), p41),
                  (ir.Op("gt", (ir.Op("add", (ir.Const(36), off, ln)), CDS)), ir.Empty())]
        kinds = ["dyn_offset", "p41_length", "dyn_bounds"]
        if base is not None:
            size = ir.Op("add", (ir.Const(base), ir.Mask(251, 5, 0, ir.Op("add", (ir.Const(31), ln)))))
            alloc = ir.Op("or", (ir.Op("gt", (size, bound)), ir.Op("lt", (size, ir.Const(base - 32)))))
            if wrapped:
                alloc = ir.Op("mul", (ir.const(-1), alloc))  # (via-IR without the optimiser)
            checks.insert(2, (alloc, p41))
            kinds.insert(2, "p41_alloc")
        classes = [abi_pass._classify(c, p) for c, p in checks]
        assert [c[0] for c in classes] == kinds, classes
        return abi_pass._memory_strings(_spec("0x00000007", 1, {0: "dynamic"}, dynamic=(0,)), classes, True, checks)

    assert strings(0xa0) == {0} and strings(0xa0, wrapped=True) == {0}  # 0x80, and the length word
    # a pointer that starts above (locals in memory): Panic(0x41) on lengths abi.decode accepts
    assert strings(0xc0) == set() and strings(0xc0, wrapped=True) == set()
    assert strings(0x80) == set()
    assert strings(None) == set()  # no allocation check: where the original's memory starts is unknown


def test_router_lines_belong_to_their_function():
    from scobelix.solgen.contract import ContractInput, Unit, router_spans

    units = [Unit(k, ir.Function(k, ()), _spec(k, 0)) for k in ("0x0000000a", "0x0000000b")]
    ci = ContractInput(units=units, target="0.8.19", original="solc 0.8.19")
    source = "\n".join([
        "    fallback(bytes calldata input) external returns (bytes memory) {",
        "        if (input.length >= 4) {",
        "            if (msg.sig == 0x0000000a) return abi.encode(_fn_0000000a());",
        "            if (msg.sig == 0x0000000b) {",
        "                _fn_0000000b();",
        "                return \"\";",
        "            }",
        "            if (msg.sig == 0x0000000c) {",
        "        }",
        "        revert();",
        "    }",
    ])
    assert router_spans(source, ci) == [(3, 3, "0x0000000a"), (4, 7, "0x0000000b")]


# ---------------------------------------------------------------- the other builds (slow)

V1_BUILDS = [Build("0.7.6"), Build("0.5.17", optimize=False)]
V2_BUILDS = [Build("0.8.19", optimize=False), Build("0.8.19", via_ir=True), Build("0.8.31", via_ir=True),
             Build("0.7.6", optimize=False, abicoder="v2")]


@pytest.mark.slow
@pytest.mark.parametrize("build", V2_BUILDS + V1_BUILDS + [Build("0.5.17", optimize=True)], ids=lambda b: b.label)
def test_value_parameters_probe(build, monkeypatch):
    source = R_SOURCE
    if build.label == "0.5.17-opt":
        source = "pragma experimental ABIEncoderV2;\n" + source  # ABI coder v2 of 0.5
    r, f, _ = routed_probe(source, build, "R", monkeypatch)
    typed = {n for n, x in f.items() if route(x) == "typed"}
    assert typed >= {"u8", "u40", "i8", "flag", "b4", "en", "set", "pay", "loop", "name", "none"}, typed
    v2 = build.v2 or build.label == "0.5.17-opt"
    assert ("abi.decode(input[4:], (uint8))" in r.solidity) == v2  # v1 decodes the raw word: uint256


@pytest.mark.slow
@pytest.mark.parametrize("build", V2_BUILDS[:3], ids=lambda b: b.label)
def test_checks_after_a_byte_string_in_memory_probe(build, monkeypatch):
    _order_probe(build, monkeypatch)


@pytest.mark.slow
def test_a_decoder_allocating_above_the_free_memory_pointer_of_the_target_probe(monkeypatch):
    _pointer_probe(Build("0.8.31", via_ir=True), monkeypatch)


@pytest.mark.slow
@pytest.mark.parametrize("build", V2_BUILDS[1:] + [Build("0.8.19")], ids=lambda b: b.label)
def test_dynamic_and_composite_parameters_probe(build, monkeypatch):
    r, f, _ = routed_probe(D_SOURCE, build, "D", monkeypatch)
    # calldata dynamic parameters: the head offset is a raw word, its checks in the body
    for name in ("dBytes", "dArr", "dStr", "dAddrs", "nested"):
        assert route(f[name]) == "typed" and f[name]["abi"]["raw_words"] == 1, (name, f[name]["abi"])
    # members of static structs and arrays: one word each
    assert route(f["sArr"]) == "typed" and route(f["sStruct"]) == "typed"
    if build.major >= (0, 8):
        # a byte string decoded to memory: abi.decode is the original's decoder; an array of byte
        # strings decoded to memory (a copy loop and its Panic checks): untyped
        assert route(f["dMem"]) == "typed" and f["dMem"]["abi"]["memory_bytes"] == 1, f["dMem"]["abi"]
        assert route(f["nestedMem"]) == "untyped" and f["nestedMem"]["abi"]["why"] == "memory parameter"


@pytest.mark.slow
@pytest.mark.parametrize("build", V2_BUILDS + [Build("0.7.6")], ids=lambda b: b.label)
def test_byte_strings_in_memory_probe(build, monkeypatch):
    r, f, _ = routed_probe(M_SOURCE, build, "M", monkeypatch)
    typed = {n for n, x in f.items() if route(x) == "typed"}
    assert typed >= {"setLabel", "lenOf", "two", "first"}, {n: x["abi"] for n, x in f.items()}
    if build.major >= (0, 8):
        assert "abi.decode(input[4:], (bytes, bytes))" in r.solidity
    else:  # no Panic(0x41) before 0.8: every check reverts without data, the offsets are raw words
        assert typed >= {"mixed", "arr"} and "abi.decode(input[4:], (bytes" not in r.solidity


@pytest.mark.slow
@pytest.mark.parametrize("build", V1_BUILDS, ids=lambda b: b.label)
def test_dynamic_parameters_abi_coder_v1_probe(build, monkeypatch):
    r, f, _ = routed_probe(D_SOURCE_V1, build, "D", monkeypatch)
    assert "pragma abicoder v1;" in r.solidity
    assert all(route(x) == "typed" for x in f.values()), {n: x["abi"] for n, x in f.items()}


@pytest.mark.slow
@pytest.mark.parametrize("build, source, contract", [
    (Build("0.8.19", optimize=False), F_SOURCE, "F"),
    (Build("0.8.31", via_ir=True), F_SOURCE, "F"),
    (Build("0.7.6"), F_SOURCE, "F"),
    (Build("0.5.17", optimize=False), F_SOURCE_05, "F"),
    (Build("0.8.19"), G_SOURCE, "G"),
    (Build("0.8.31", via_ir=True), G_SOURCE, "G"),
    (Build("0.8.19"), H_SOURCE, "H"),
], ids=lambda x: x.label if isinstance(x, Build) else (x if isinstance(x, str) and len(x) == 1 else ""))
def test_fallback_and_receive_probe(build, source, contract, monkeypatch):
    r, f, _ = routed_probe(source, build, contract, monkeypatch, values=(0, 3))
    assert all(route(x) == "typed" for x in f.values()), {n: x["abi"] for n, x in f.items()}


# ---------------------------------------------------------------- the verification loop (slow)

def _break_route(monkeypatch, sel: str, line: str) -> None:
    """Make the router of one selector write `line` (a wrong route)."""
    from scobelix.solgen import contract

    real = contract._route_call

    def broken(unit, inp, structs, declared):
        return [line] if unit.spec.selector == int(sel, 16) else real(unit, inp, structs, declared)

    monkeypatch.setattr(contract, "_route_call", broken)


@pytest.mark.slow
@pytest.mark.parametrize("line, step", [
    ("return abi.encode(uint256(12345));", "L3"),  # a route that answers wrong: seen by the runs
    ("return abi.encode(undeclared_name);", "L0"),  # a route that does not compile: located on its lines
])
def test_the_loop_backs_off_a_broken_typed_route(line, step, monkeypatch):
    from scobelix.verify import Budget

    art = compile_probe(R_SOURCE, Build("0.8.19"), "R")
    patch_signatures(monkeypatch, [])
    key = "0x" + selector("u40(uint40)").hex()
    _break_route(monkeypatch, key[2:], line)
    r = generate(art.runtime, verify=True, budget=Budget.quick())
    fn = r.functions[key]
    assert "abi" in fn["disabled_passes"] and fn["abi"] is None, fn  # (the pass did not run on it)
    assert fn["verdict"] in ("EQUIVALENT", "EQUIVALENT_REVERTS_ONLY"), fn
    other = r.functions["0x" + selector("u8(uint8)").hex()]
    assert other["abi"]["route"] == "typed" and other["tier"] == "idiomatic", other
    if step == "L0":
        assert any(e["function"] == key for e in r.verification.search["l0"]), r.verification.search["l0"]
    assert f"_fn_{key[2:]}();" in r.solidity

"""
The storage and getters passes keep the EVM semantics: hand-written IR
contracts rendered at the exact level and at the full level (storage +
getters) are executed on the same storage and calldata (dirty bits, values
out of range, out-of-bounds indices included), and every outcome (success,
return / revert data, storage writes) must be identical.  The tests also
check that the idiomatic form is used where it is exact and the raw form
where it is not.
"""

import random

from eth_utils import keccak

from conftest import backend_or_skip, compile_or_fail
from scobelix.solgen import ir, pipeline, sigs
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.contract import ContractInput, Unit, assemble
from scobelix.solgen.types import parse_type

CALLER, CAND = "0x" + "a1" * 20, "0x" + "c0" * 20


def cd(i):
    return ir.CalldataWord(ir.Const(4 + 32 * i))


def field(slot, off, size):
    return ir.Field(ir.Sload(slot if isinstance(slot, ir.Expr) else ir.Const(slot)), off, size)


def mapkey(key, slot):
    return ir.Keccak(ir.Blob((ir.WordBytes(key), ir.WordBytes(ir.Const(slot)))))


def ret(*words):
    return ir.Return(ir.Blob(tuple(ir.WordBytes(w) for w in words)) if len(words) > 1 else ir.WordBytes(words[0]))


def size_check(n):
    """The decoder's calldata size check of n head words, as solc emits it."""
    return ir.Op("slt", (ir.Op("add", (ir.const(-4), ir.Env("calldatasize"))), ir.Const(32 * n)))


def checked(n, body, validators=()):
    """body behind the decoder's checks: size, then `iszero(eq(p, cleanup(p)))`."""
    out = list(body)
    for v in reversed(validators):
        out = [ir.If(v, (ir.Revert(),), tuple(out))]
    return [ir.If(size_check(n), (ir.Revert(),), tuple(out))] if n else out


def address_validator(i):
    p = cd(i)
    return ir.Op("iszero", (ir.Op("eq", (p, ir.Mask(160, 0, 0, p))),))


class Case:
    def __init__(self):
        self.entries = {}

    def fn(self, sel, body, signature=None, params=(), mutability="nonpayable", inferred=None):
        key = f"0x{sel:08x}"
        spec = EntrySpec(key=key, kind="function", selector=sel, signature=signature,
                         name=signature.split("(")[0] if signature else None,
                         params=tuple((parse_type(t), f"p{i}") for i, t in enumerate(params)),
                         mutability=mutability, inferred=dict(inferred or {}))
        self.entries[key] = (ir.Function(key, tuple(body)), spec)
        return key

    def named(self, signature, body, params=(), mutability="nonpayable"):
        return self.fn(sigs.function_selector(signature), body, signature, params, mutability)

    def build(self, level):
        specs = {k: s for k, (_, s) in self.entries.items()}
        functions = {k: f for k, (f, _) in self.entries.items()}
        ctx = pipeline.PassContext(specs=specs, metadata=None, dispatcher=None, target_solc="0.8.19", abi_v2=True,
                                   idiom_level=level, functions=dict(functions))
        passes = pipeline.available_passes(level)
        pipeline.prepare(passes, ctx)
        units = []
        for key, fn in functions.items():
            fn2, applied = pipeline.run_passes(fn, passes, ctx)
            units.append(Unit(key, fn2, specs[key], passes=applied, flags=set(fn2.flags)))
        pipeline.finish(passes, ctx)
        for u in units:
            u.folded = ctx.folded.get(u.key)
        src, _ = assemble(ContractInput(units=units, target="0.8.19", original="test", idiom_level=level,
                                        declarations=ctx.declarations))
        return src, ctx


def _run_both(case, calls, storages):
    """Execute the exact and the full rendering on every (storage, call)."""
    backend = backend_or_skip()
    from scobelix.verify.evm import make_world

    exact_src, _ = case.build("exact")
    full_src, ctx = case.build("full")
    codes = {lvl: compile_or_fail(src, "0.8.19").runtime for lvl, src in (("exact", exact_src), ("full", full_src))}
    for store in storages:
        for data in calls:
            out = {}
            for lvl, code in codes.items():
                world = make_world(backend)
                world.set_code(CAND, code)
                world.set_storage_many(CAND, store)
                r = world.call(CALLER, CAND, data)
                out[lvl] = (r.success, r.output, sorted((k[1], v) for k, v in r.storage_diff.items()))
            assert out["exact"] == out["full"], (data.hex(), store, out, full_src)
    return full_src, ctx


def word(v):
    return (v % 2**256).to_bytes(32, "big")


def mslot(key, slot):
    """keccak256(key . slot): the slot of mapping value m[key]."""
    return int.from_bytes(keccak(word(key) + word(slot)), "big")


def calldata(sel, *args):
    return sel.to_bytes(4, "big") + b"".join(word(a) for a in args)


RNG = random.Random(7)


def dirty_words(n=6):
    return [RNG.randrange(2**256) for _ in range(n)] + [0, 2**256 - 1, 1 << 160, (1 << 168) - 1]


# ---------------------------------------------------------------- packed value variables


def _packed_case():
    c = Case()
    sel = {}
    # slot 0: address @0, bool @20, uint8 @21, int16 @22, bytes4 @24
    sel["owner"] = c.named("owner()", [ret(field(0, 0, 160))], mutability="view")
    sel["flag"] = c.named("flag()", [ret(ir.Op("iszero", (ir.Op("iszero", (field(0, 160, 8),)),)))], mutability="view")
    sel["small"] = c.named("small()", [ret(field(0, 168, 8))], mutability="view")
    sel["delta"] = c.named("delta()", [ret(ir.Op("signextend", (ir.Const(1), field(0, 176, 80))))], mutability="view")
    sel["tag"] = c.named("tag()", [ret(ir.Mask(32, 0, 224, field(0, 192, 64)))], mutability="view")
    sel["setOwner"] = c.named("setOwner(address)", checked(1, [ir.Sstore(ir.Const(0), ir.Mask(160, 0, 0, cd(0)), 0, 160),
                                                                 ir.Stop()], [address_validator(0)]), ("address",))
    sel["setFlag"] = c.fn(0x11110001, [ir.Sstore(ir.Const(0), ir.Mask(8, 0, 0, ir.Op("iszero", (ir.Op("iszero", (cd(0),)),))),
                                                 160, 8), ir.Stop()])
    sel["setFlagRaw"] = c.fn(0x11110002, [ir.Sstore(ir.Const(0), cd(0), 160, 8), ir.Stop()])  # any byte
    sel["setDelta"] = c.fn(0x11110003, [ir.Sstore(ir.Const(0), cd(0), 176, 16), ir.Stop()])
    sel["setTag"] = c.fn(0x11110004, [ir.Sstore(ir.Const(0), ir.Mask(32, 224, -224, cd(0)), 192, 32), ir.Stop()])
    sel["setTagLow"] = c.fn(0x11110005, [ir.Sstore(ir.Const(0), cd(0), 192, 32), ir.Stop()])
    sel["bump"] = c.fn(0x11110006, [ir.Sstore(ir.Const(0), ir.Mask(8, 0, 0, ir.Op("add", (ir.ONE, field(0, 168, 8)))),
                                              168, 8), ir.Stop()])
    sel["useFlag"] = c.fn(0x11110007, [ir.If(field(0, 160, 8), (ret(ir.Const(7)),), (ret(field(0, 160, 8)),))])
    return c, sel


def test_packed_values_are_exact_and_idiomatic():
    c, sel = _packed_case()
    calls = [calldata(s, a) for s in [int(k, 16) for k in sel.values()] for a in (0, 1, 2, 2**200 + 3, 2**256 - 1)]
    storages = [{0: w} for w in dirty_words()]
    src, ctx = _run_both(c, calls, storages)
    assert "address public owner;" in src and "int16 public delta;" in src and "bytes4 public tag;" in src
    assert "function owner()" not in src  # folded into the public variable
    assert "flag = (" in src or "flag = " in src  # the boolean store
    body = src[src.index("function _fn_11110002"):]
    assert "_sstoreField(0, 160, 8" in body.split("\n    }\n")[0]  # a byte that may be neither 0 nor 1: raw


# ---------------------------------------------------------------- mappings, arrays, structs


def _composite_case():
    c = Case()
    sel = {}
    # slot 1: mapping(address => uint256); slot 2: mapping(uint256 => struct {uint128 a; uint128 b; address c})
    # slot 3: uint256[] (dynamic); slot 4..6: uint256[3]
    sel["balanceOf"] = c.named("balanceOf(address)", checked(1, [ret(ir.Sload(mapkey(cd(0), 1)))], [address_validator(0)]),
                               ("address",), "view")
    sel["setBalance"] = c.named("setBalance(address,uint256)", checked(2, [
        ir.Sstore(mapkey(ir.Mask(160, 0, 0, cd(0)), 1), cd(1)), ir.Stop()], [address_validator(0)]),
        ("address", "uint256"), "nonpayable")
    sel["rawBalance"] = c.fn(0x22220001, [ret(ir.Sload(mapkey(cd(0), 1)))])  # unvalidated key: raw
    item = mapkey(cd(0), 2)
    sel["items"] = c.named("items(uint256)", checked(1, [ret(field(item, 0, 128), field(item, 128, 128),
                                                             field(ir.Op("add", (ir.ONE, item)), 0, 160))]),
                           ("uint256",), "view")
    sel["setItemB"] = c.fn(0x22220002, [ir.Sstore(item, cd(1), 128, 128), ir.Stop()])
    sel["setItemC"] = c.fn(0x22220003, [ir.Sstore(ir.Op("add", (ir.ONE, item)), ir.Env("caller"), 0, 160), ir.Stop()])
    data = ir.Keccak(ir.WordBytes(ir.Const(3)))
    bound = ir.Op("iszero", (ir.Op("lt", (cd(0), ir.Sload(ir.Const(3)))),))
    sel["nums"] = c.named("nums(uint256)", checked(1, [ir.If(bound, (ir.Revert(),),
                                                             (ret(ir.Sload(ir.Op("add", (data, cd(0))))),))]),
                          ("uint256",), "view")
    sel["numAt"] = c.named("numAt(uint256)", checked(1, [ir.If(bound, (ir.Revert(ir.Panic(0x32)),),
                                                               (ret(ir.Sload(ir.Op("add", (data, cd(0))))),))]),
                           ("uint256",), "view")
    sel["numsLength"] = c.named("numsLength()", [ret(ir.Sload(ir.Const(3)))], mutability="view")
    fixed_bound = ir.Op("iszero", (ir.Op("lt", (cd(0), ir.Const(3))),))
    sel["setFixed"] = c.fn(0x22220004, [ir.If(fixed_bound, (ir.Revert(ir.Panic(0x32)),),
                                              (ir.Sstore(ir.Op("add", (ir.Const(4), cd(0))), cd(1)), ir.Stop()))])
    sel["fixedLast"] = c.fn(0x22220005, [ret(ir.Sload(ir.Const(6)))])
    # unguarded element read, and a guard invalidated by a store to the length
    sel["rawElem"] = c.fn(0x22220006, [ret(ir.Sload(ir.Op("add", (data, cd(0)))))])
    sel["stale"] = c.fn(0x22220007, [ir.If(bound, (ir.Revert(ir.Panic(0x32)),),
                                           (ir.Sstore(ir.Const(3), ir.ZERO),
                                            ret(ir.Sload(ir.Op("add", (data, cd(0)))))))])
    return c, sel


def test_composites_are_exact_and_idiomatic():
    c, sel = _composite_case()
    keys = (0, 5, 2**160 - 1, 2**200 + 5)
    calls = [calldata(int(k, 16), a, b) for k in sel.values() for a in keys for b in (0, 1, 2**255)]
    storages = [{1: 0}, {3: 2, 4: 9, 6: 11}, {3: 5, 6: 2**256 - 1}]
    for k, a in ((1, 5), (2, 0), (2, 5)):
        storages[0][mslot(a, k)] = 2**256 - 3
        storages[0][mslot(a, k) + 1] = RNG.randrange(2**256)
    src, ctx = _run_both(c, calls, storages)
    assert "mapping(address => uint256) public balanceOf;" in src
    assert "function balanceOf(" not in src and "function nums(" not in src  # auto-getters
    assert "function numAt(" in src  # Panic(0x32) on the bound: an explicit function, not a getter
    assert "balanceOf[p0] = p1;" in src  # validated key: the parameter itself
    raw = src[src.index("function _fn_22220001"):].split("\n    }\n")[0]
    assert "_sload(" in raw  # unvalidated key: the hash of the raw word
    assert "nums.length" in src and ".m0_16 = uint128(" in src and "[2]" in src
    num_at = src[src.index("function numAt("):].split("\n    }\n")[0]
    assert "nums[p0]" in num_at  # bounded by the dominating test
    fixed = src[src.index("function _fn_22220004"):].split("\n    }\n")[0]
    assert "[uint256(" in fixed or "[_calldataload(36)]" in fixed or "] = " in fixed
    for raw in ("_fn_22220006", "_fn_22220007"):
        body = src[src.index(f"function {raw}"):].split("\n    }\n")[0]
        assert "nums[" not in body, body  # not proven in bounds there


def test_getters_with_another_selector_are_not_folded():
    c = Case()
    # the body is balances(address)'s, the selector is another name's
    key = c.fn(sigs.function_selector("total()"), [ret(ir.Sload(ir.Const(0)))], "total()", (), "view")
    c.named("setTotal(uint256)", checked(1, [ir.Sstore(ir.Const(0), cd(0)), ir.Stop()]), ("uint256",))
    src, ctx = c.build("full")
    assert ctx.folded == {key: "total"}
    c2 = Case()
    k2 = c2.fn(0x12345678, [ret(ir.Sload(ir.Const(0)))], "total()", (), "view")  # keccak(total()) != 0x12345678
    src2, ctx2 = c2.build("full")
    assert k2 not in ctx2.folded and "function total()" in src2


def test_constants_fold_only_when_nothing_is_read():
    c = Case()
    k1 = c.named("FEE()", [ret(ir.Const(30))], mutability="view")
    k2 = c.named("LIMIT()", [ir.If(ir.Sload(ir.Const(0)), (ir.Revert(),), (ret(ir.Const(5)),))], mutability="view")
    k3 = c.named("paused()", [ret(ir.Op("iszero", (ir.Op("iszero", (field(0, 0, 8),)),)))], mutability="view")
    src, ctx = c.build("full")
    assert ctx.folded.get(k1) == "FEE" and "uint256 public constant FEE = 30;" in src
    assert k2 not in ctx.folded and ctx.folded.get(k3) == "paused" and "bool public paused;" in src
    compile_or_fail(src, "0.8.19")


def _body(src, name):
    return src[src.index(f"function {name}"):].split("\n    }\n")[0]


def test_split_stores_of_one_variable_are_one_write():
    """The engine writes one SSTORE as one store per run of changed bits: a
    narrow value zero-extended into a wider variable is a value row and a
    zero row right above it (in either order, maybe with stores of other
    bits in between), a constant store may clear several variables."""
    c = Case()
    s0, s1 = ir.Const(0), ir.Const(1)
    # slot 0: bytes4 tag [0, 32), uint64 count [32, 96); slot 1: bool flag [0, 8), address addr [8, 168)
    c.named("tag()", [ret(ir.Mask(32, 0, 224, field(0, 0, 32)))], mutability="view")
    c.named("count()", [ret(field(0, 32, 64))], mutability="view")
    c.named("flag()", [ret(ir.Op("iszero", (ir.Op("iszero", (field(1, 0, 8),)),)))], mutability="view")
    c.named("addr()", [ret(field(1, 8, 160))], mutability="view")
    # count = uint64(uint32(tag)); tag = 0 (the engine puts the reader first)
    c.fn(0x33330001, [ir.Sstore(s0, field(0, 0, 32), 32, 32), ir.Sstore(s0, ir.ZERO, 0, 32),
                      ir.Sstore(s0, ir.ZERO, 64, 32), ir.Stop()])
    # count = uint8(x), the zero row first
    c.fn(0x33330002, [ir.Sstore(s0, ir.ZERO, 40, 56), ir.Sstore(s0, ir.Mask(8, 0, 0, cd(0)), 32, 8), ir.Stop()])
    # a dirty value: only its low 32 bits are stored
    c.fn(0x33330003, [ir.Sstore(s0, cd(0), 32, 32), ir.Sstore(s0, ir.ZERO, 64, 32), ir.Stop()])
    # a store in between reads storage (it could read the bits the zero row clears): kept as it is
    c.fn(0x33330004, [ir.Sstore(s0, cd(0), 32, 32), ir.Sstore(s0, ir.Sload(ir.Const(5)), 0, 32),
                      ir.Sstore(s0, ir.ZERO, 64, 32), ir.Stop()])
    # delete s (flag and addr at once), a constant over both, one over a gap too
    c.fn(0x33330005, [ir.Sstore(s1, ir.ZERO, 0, 168), ir.Stop()])
    c.fn(0x33330006, [ir.Sstore(s1, ir.Const(1 | 0xABC << 8), 0, 168), ir.Stop()])
    c.fn(0x33330007, [ir.Sstore(s1, ir.ZERO, 0, 176), ir.Stop()])
    # part of a variable (the low byte of addr): raw, and nothing to report
    c.fn(0x33330008, [ir.Sstore(s1, ir.Const(0x55), 8, 8), ir.Stop()])
    calls = [calldata(0x33330000 + i, a) for i in range(1, 9) for a in (0, 7, 2**40 + 5, 2**256 - 1)]
    storages = [{0: w, 1: v, 5: w ^ v} for w, v in zip(dirty_words(), reversed(dirty_words()))]
    src, _ = _run_both(c, calls, storages)
    assert "packed_store_suspect" not in src  # every store is (part of) one variable, or whole variables
    for k in (1, 2, 3):
        body = _body(src, f"_fn_3333000{k}")
        assert "count = " in body and "_sstoreField(0, 64" not in body and "_sstoreField(0, 40" not in body, body
    assert "tag = " in _body(src, "_fn_33330001")
    assert "_sstoreField(0, 64, 32, 0)" in _body(src, "_fn_33330004")
    for k in (5, 6):
        body = _body(src, f"_fn_3333000{k}")
        assert "flag = " in body and "addr = " in body and "_sstoreField" not in body, body
    assert "_sstoreField(1, 0, 176, 0)" in _body(src, "_fn_33330007")
    body = _body(src, "_fn_33330008")
    assert "_sstoreField(1, 8, 8, " in body, body


def test_a_store_cutting_a_variable_is_flagged():
    """A packed store over one whole variable and part of the next one
    cannot be attributed to the recovered variables: it stays raw (exact)
    and its function is flagged."""
    c = Case()
    s1 = ir.Const(1)
    # slot 1: bool flag [0, 8), address addr [8, 168)
    c.named("flag()", [ret(ir.Op("iszero", (ir.Op("iszero", (field(1, 0, 8),)),)))], mutability="view")
    c.named("addr()", [ret(field(1, 8, 160))], mutability="view")
    c.fn(0x33340001, [ir.Sstore(s1, ir.Env("caller"), 8, 160), ir.Stop()])
    c.fn(0x33340002, [ir.Sstore(s1, ir.Const(0x0100), 0, 16), ir.Stop()])  # flag and the low byte of addr
    # the high byte of addr and the byte above it, in a branch
    c.fn(0x33340003, [ir.If(ir.Op("iszero", (cd(0),)), (ir.Sstore(s1, ir.Const(0x0101), 160, 16),), ()), ir.Stop()])
    calls = [calldata(0x33340000 + i, a) for i in range(1, 4) for a in (0, 7, 2**40 + 5, 2**256 - 1)]
    storages = [{1: v} for v in dirty_words()]
    src, _ = _run_both(c, calls, storages)
    tags = {k: src[:src.index(f"function _fn_3334000{k}")].rsplit("@custom:scobelix", 1)[1].split("\n")[0]
            for k in (1, 2, 3)}
    assert "packed_store_suspect" not in tags[1] and "addr = msg.sender;" in _body(src, "_fn_33340001")
    assert "flags=engine:packed_store_suspect" in tags[2] and "_sstoreField(1, 0, 16, " in _body(src, "_fn_33340002")
    assert "flags=engine:packed_store_suspect" in tags[3] and "_sstoreField(1, 160, 16, " in _body(src, "_fn_33340003")
    assert "address " in src and "bool " in src  # the variables are still declared where the getters read them


def test_custom_slot_namespaces():
    """ERC-7201 / EIP-1967 slots: members of a struct at the namespace base,
    reached through an assembly accessor."""
    base = 0x183A6125C38840424C4A85FA12BAB2AB606C4B6D0E7CC73C0C06BA5300EAB500
    impl = 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
    c = Case()
    k1 = c.fn(0x44440001, [ret(ir.Sload(ir.Const(base)))])
    c.fn(0x44440002, [ir.Sstore(ir.Const(base + 1), ir.Env("caller"), 0, 160), ir.Stop()])
    c.fn(0x44440003, [ret(ir.Sload(mapkey_const(cd(0), base + 2)))])
    c.fn(0x44440004, [ir.Sstore(mapkey_const(ir.Mask(160, 0, 0, cd(0)), base + 2), cd(1)), ir.Stop()])
    c.fn(0x44440005, [ret(field(impl, 0, 160))])
    c.fn(0x44440006, [ir.Sstore(ir.Const(impl), cd(0)), ir.Stop()])  # the whole word: raw
    calls = [calldata(0x44440000 + i, a, b) for i in range(1, 7) for a in (0, 7, 2**200 + 9) for b in (1, 2**256 - 1)]
    storages = [{base: 5, base + 1: 2**256 - 1, impl: 2**200 + 77}, {mslot(7, base + 2): 3}]
    src, ctx = _run_both(c, calls, storages)
    assert "function _namespace183a6125() private pure returns (" in src
    assert "_namespace183a6125().m2_0[" in src and "_namespace360894a1().m0_0" in src
    assert k1 not in ctx.folded  # no state variable to fold into


def mapkey_const(key, slot_word):
    return ir.Keccak(ir.Blob((ir.WordBytes(key), ir.WordBytes(ir.Const(slot_word)))))


def test_reads_masked_from_an_offset_are_exact_and_idiomatic():
    """mask_shl reads taking a value's bits straight from the slot word: a
    uint64 at byte 1 moved down, a bytes4 at byte 11 moved to the top or
    down, a bytes2 at byte 30 in place; other placements stay raw."""
    w = ir.Sload(ir.Const(0))
    c = Case()
    c.fn(0x66660001, [ret(ir.Mask(64, 8, -8, w))])
    c.fn(0x66660002, [ret(ir.Mask(32, 88, 136, w), ir.Mask(32, 88, -88, w))])
    c.fn(0x66660003, [ret(ir.Mask(16, 240, 0, w), ir.Mask(16, 240, -232, w))])  # the last: moved elsewhere
    c.fn(0x66660004, [ir.Sstore(ir.Const(0), ir.Mask(64, 0, 0, cd(0)), 8, 64),
                      ir.Sstore(ir.Const(0), ir.Mask(32, 224, -224, cd(1)), 88, 32),
                      ir.Sstore(ir.Const(0), ir.Mask(16, 240, -240, cd(2)), 240, 16), ir.Stop()])
    calls = [calldata(0x66660000 + i, a, a, a) for i in range(1, 5) for a in (0, 5, 2**255 + 3, 2**256 - 1)]
    storages = [{0: x} for x in dirty_words()]
    src, ctx = _run_both(c, calls, storages)
    body = src[src.index("function _fn_66660002"):].split("\n    }\n")[0]
    assert "bytes4" in src and "_sload(0)" not in body
    raw = src[src.index("function _fn_66660003"):].split("\n    }\n")[0]
    assert "_sload(0)" in raw  # the bits moved elsewhere are read raw

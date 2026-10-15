"""
Storage layout inference (scobelix.solgen.storage) on hand-written IR:
slot expressions -> paths, keccak decomposition, field partition, key and
value typing, composite types, fillers (compiled: every variable lands at
its recovered position), the variable lookups the passes use, and the
detection of packed stores the engine may have misplaced.
"""

from eth_utils import keccak

from conftest import compile_or_fail, solc_or_skip
from scobelix.solgen import ir, lift, storage
from scobelix.solgen.abi import EntrySpec
from scobelix.solgen.types import parse_type


def cd(i):
    return ir.CalldataWord(ir.Const(4 + 32 * i))


def kc(*words):
    return ir.Keccak(ir.Blob(tuple(ir.WordBytes(w) for w in words)) if len(words) > 1 else ir.WordBytes(words[0]))


def hashed(i):
    return int.from_bytes(keccak(i.to_bytes(32, "big")), "big")


def field(slot, off, size):
    return ir.Field(ir.Sload(slot if isinstance(slot, ir.Expr) else ir.Const(slot)), off, size)


def ret(*words):
    return ir.Return(ir.Blob(tuple(ir.WordBytes(w) for w in words)))


def layout_of(*bodies, params=None, outputs=None, check=None):
    functions, specs = {}, {}
    for i, body in enumerate(bodies):
        key = f"0x{0x10000000 + i:08x}"
        functions[key] = ir.Function(key, tuple(body))
        specs[key] = EntrySpec(key=key, kind="function", selector=0x10000000 + i,
                               params=tuple((parse_type(t), f"p{j}") for j, t in enumerate((params or {}).get(i, ()))),
                               signature="x()" if (params or {}).get(i) is not None else None)
    return storage.infer_layout(functions, specs, outputs or {}, check)


def types(lay):
    return {(v.slot, v.offset): storage.type_text(v.type, lay) for v in lay.vars}


# ---------------------------------------------------------------- paths


def test_slot_expressions_become_paths():
    p = storage.parse_slot
    assert p(ir.Const(3)) == ("slot", 3)
    assert p(kc(cd(0), ir.Const(1))) == ("map", ("slot", 1), cd(0))
    assert p(kc(cd(1), kc(cd(0), ir.Const(1)))) == ("map", ("map", ("slot", 1), cd(0)), cd(1))
    assert p(ir.Op("add", (kc(ir.Const(0)), cd(0)))) == ("elem", ("data", ("slot", 0)), cd(0), 1, 1)
    # a struct member of a dynamic array of 3-slot elements, the hash folded by the optimizer
    e = ir.Op("add", (ir.const(hashed(1) + 2), ir.Op("mul", (ir.Const(3), cd(0)))))
    assert p(e) == ("off", ("elem", ("data", ("slot", 1)), cd(0), 3, 1), 2)
    # pop: keccak(0) - 1 + length moves the -1 into the index
    pop = p(ir.Op("add", (ir.const(-1), kc(ir.Const(0)), ir.Sload(ir.Const(0)))))
    assert pop[0] == "elem" and pop[3:] == (1, 1) and pop[2] == ir.Op("add", (ir.Sload(ir.Const(0)), ir.const(-1)))
    # packed uint8[]: 32 elements per slot
    assert p(ir.Op("add", (ir.Mask(251, 5, -5, cd(0)), kc(ir.Const(1)))))[3:] == (1, 32)
    # fixed uint64[5] at slot 6: 4 per slot
    assert p(ir.Op("add", (ir.Const(6), ir.Mask(254, 2, -2, cd(0)))))[3:] == (1, 4)
    # a string key, a custom slot, an unknown base
    assert p(ir.Keccak(ir.Blob((ir.CalldataSlice(ir.Const(68), cd(1)), ir.WordBytes(ir.Const(7))))))[0] == "map"
    assert p(ir.const(0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC))[0] == "cslot"
    assert p(ir.Op("add", (cd(0), cd(1)))) == ("unk",)


def test_keccak_decomposition():
    assert storage.decompose_keccak(hashed(5)) == (5, 0)
    assert storage.decompose_keccak(hashed(4095) + 7) == (4095, 7)
    assert storage.decompose_keccak((hashed(11) - 3) % 2**256) == (11, -3)
    assert storage.decompose_keccak(hashed(4096)) is None  # beyond the table
    assert storage.decompose_keccak(hashed(3) + 2**30) is None  # too far from any hash


# ---------------------------------------------------------------- fields and types


def test_packed_fields_and_value_types():
    lay = layout_of(
        [ret(field(0, 0, 160))],
        [ret(ir.Op("iszero", (ir.Op("iszero", (field(0, 160, 8),)),)))],
        [ret(ir.Op("signextend", (ir.Const(1), field(0, 168, 88))))],
        [ret(ir.Mask(32, 0, 224, field(0, 184, 72)))],
        [ir.Sstore(ir.Const(0), ir.Mask(16, 0, 0, ir.Env("timestamp")), 216, 16), ir.Stop()],
        [ir.Sstore(ir.Const(1), ir.Env("caller"), 0, 160), ir.Stop()],
    )
    assert types(lay) == {(0, 0): "address", (0, 20): "bool", (0, 21): "int16", (0, 23): "bytes4",
                          (0, 27): "uint16", (1, 0): "address"}


def test_read_modify_write_and_widened_constants_do_not_make_fields():
    lay = layout_of(
        [ret(field(0, 0, 8)), ret(field(0, 8, 8))],
        # a whole-word store (read-modify-write) and a boolean widened to the end of the slot
        [ir.Sstore(ir.Const(0), ir.Op("or", (cd(0), ir.Sload(ir.Const(0))))), ir.Stop()],
        [ir.Sstore(ir.Const(0), ir.ONE, 16, 240), ir.Stop()],
    )
    assert sorted(types(lay)) == [(0, 0), (0, 1), (0, 2)]
    assert types(lay)[(0, 2)] == "uint240"  # the widened store's start is the only evidence


def test_keys_values_and_composites():
    validated = {0: ("address", "uint256")}
    lay = layout_of(
        [ir.Sstore(kc(cd(1), kc(ir.Env("caller"), ir.Const(1))), cd(2)), ir.Stop()],
        [ret(ir.Sload(kc(ir.Mask(32, 224, 0, cd(0)), ir.Const(2))))],
        [ret(ir.Sload(ir.Op("add", (kc(ir.Const(3)), cd(0)))))],
        [ret(ir.Sload(ir.Const(3)))],
        [ir.If(ir.Op("iszero", (ir.Op("lt", (cd(0), ir.Const(4))),)), (ir.Revert(ir.Panic(0x32)),),
               (ret(ir.Sload(ir.Op("add", (ir.Const(4), cd(0))))),))],
        # 0.8 length decoding: Panic(0x22) when bit 0 disagrees with length < 32
        [ir.If(ir.Op("eq", (field(kc(cd(0), ir.Const(9)), 0, 1),
                            ir.Op("lt", (field(kc(cd(0), ir.Const(9)), 1, 7), ir.Const(32))))),
               (ir.Revert(ir.Panic(0x22)),), (ret(field(kc(cd(0), ir.Const(9)), 1, 7)),))],
        params=validated,
    )
    t = types(lay)
    assert t[(1, 0)] == "mapping(address => mapping(uint256 => uint256))"
    assert t[(2, 0)] == "mapping(bytes4 => uint256)"
    assert t[(3, 0)] == "uint256[]"
    assert t[(4, 0)] == "uint256[4]"
    assert t[(9, 0)] == "mapping(uint256 => string)"


def test_enum_from_panic_21_and_struct_members():
    getter = ir.If(ir.Op("iszero", (ir.Op("lt", (field(0, 0, 8), ir.Const(3))),)), (ir.Revert(ir.Panic(0x21)),),
                   (ret(field(0, 0, 8)),))
    base = kc(cd(0), ir.Const(5))
    lay = layout_of([getter], [ret(field(base, 0, 64), field(ir.Op("add", (ir.Const(2), base)), 8, 8))])
    assert storage.type_text(lay.vars[0].type, lay) == "Enum3"
    s = lay.vars[1].type[2]
    assert s[0] == "struct" and s[1] == ((0, 0, ("v", "uint64")), (2, 1, ("v", "uint8"))) and s[2] == 3


def test_fillers_put_every_variable_at_its_position():
    solc_or_skip("0.8.19")
    lay = layout_of(
        [ret(field(0, 8, 16))],  # a uint16 after an unknown byte
        [ret(field(2, 0, 160))],  # an address after an unknown slot
        [ret(field(2, 200, 8))],
        [ret(ir.Sload(kc(cd(0), ir.Const(7))))],
        [ret(ir.Sload(ir.Const(9)))],
        check="0.8.19",
    )
    assert lay.checked is True and not lay.dropped
    src = ("pragma solidity ^0.8.0;\ncontract L {\n" + "\n".join(storage.type_declarations(lay))
           + "\n".join(storage.state_declarations(lay)) + "\n}\n")
    sl = compile_or_fail(src, "0.8.19", "L").storage_layout
    got = {(int(e["slot"]), e["offset"]) for e in sl["storage"] if not e["label"].startswith("__gap")}
    assert got == {(0, 1), (2, 0), (2, 25), (7, 0), (9, 0)}


def test_elements_read_at_constant_positions_stay_in_their_array():
    bound = ir.Op("iszero", (ir.Op("lt", (cd(0), ir.Const(3))),))
    lay = layout_of([ir.If(bound, (ir.Revert(ir.Panic(0x32)),), (ret(ir.Sload(ir.Op("add", (ir.Const(4), cd(0))))),))],
                    [ret(ir.Sload(ir.Const(6)))])
    assert types(lay) == {(4, 0): "uint256[3]"}
    ref = lay.resolve(ir.Const(6), 0, 256)
    assert ref is not None and ref.steps == (("index", ir.Const(2), 3, False),)


def test_resolve_follows_keys_members_and_lengths():
    base = kc(cd(0), ir.Const(1))
    lay = layout_of([ret(field(ir.Op("add", (ir.ONE, base)), 0, 160), field(base, 0, 128))],
                    [ret(ir.Sload(ir.Op("add", (kc(ir.Const(2)), cd(0)))))], [ret(ir.Sload(ir.Const(2)))])
    r = lay.resolve(ir.Op("add", (ir.ONE, kc(cd(3), ir.Const(1)))), 0, 160)
    assert r.steps[0][:2] == ("key", cd(3)) and r.steps[1] == ("member", "m1_0") and r.ty == ("v", "address")
    assert lay.resolve(base, 0, 256) is None  # the slot holds a 128-bit member
    assert lay.length_ref(ir.Const(2)).steps == (("length",),)
    assert lay.resolve(ir.Op("add", (kc(ir.Const(2)), cd(5))), 0, 256).steps[0][3] is True  # a dynamic index


def test_stores_of_another_width_are_no_field_evidence():
    lay = layout_of(
        [ret(ir.Op("iszero", (ir.Op("iszero", (field(0, 160, 8),)),)))],
        [ret(field(0, 168, 8))],
        [ir.Sstore(ir.Const(0), ir.Op("iszero", (ir.Op("iszero", (cd(0),)),)), 160, 96), ir.Stop()],  # a bool widened
        [ir.Sstore(ir.Const(0), ir.Env("caller"), 0, 192), ir.Stop()],  # an address written 192 bits wide
        [ir.Sstore(ir.Const(0), cd(0), 168, 8), ir.Stop()],
    )
    assert types(lay) == {(0, 20): "bool", (0, 21): "uint8"}


def test_string_length_of_legacy_code_is_decoded():
    ctx = lift.make_context(b"", "raw")
    fn = lift.lift_function("0x10000000", [("return", ("data", ("storage", 256, 0, ("length", ("loc", 3)))))], ctx)
    ret_stmt = fn.body[0]
    word = ret_stmt.data.parts[0].value if isinstance(ret_stmt.data, ir.Blob) else ret_stmt.data.value
    for raw, length in ((0x2A, 0x15), (2 * 70 + 1, 70), (0xFF00, 0)):
        assert ir.evaluate(ir.transform(word, lambda n: ir.Const(raw) if isinstance(n, ir.Sload) else n)) == length


def test_bit_arithmetic_is_no_string_and_no_field():
    # x % 2, x / 2 and (x / 2) % 128 of a uint256, x / 2 of a packed uint8, a
    # bytes3 after an int8 read by a shift: none of them is a string length
    half = ir.Op("shr", (ir.ONE, ir.Sload(ir.Const(0))))
    lay = layout_of(
        [ir.Sstore(ir.Const(0), cd(0)), ir.Sstore(ir.Const(1), cd(1), 0, 8), ir.Sstore(ir.Const(1), cd(2), 8, 16),
         ir.Stop()],
        [ret(field(0, 0, 1), field(0, 1, 255), field(0, 1, 7), half)],
        [ret(field(1, 1, 7), field(1, 0, 1))],
        [ret(ir.Op("signextend", (ir.Const(0), ir.Sload(ir.Const(2)))), ir.Mask(24, 0, 232, field(2, 8, 248)))],
    )
    assert types(lay) == {(0, 0): "uint256", (1, 0): "uint8", (1, 1): "uint16", (2, 0): "int8", (2, 1): "bytes3"}


def test_legacy_string_length_decoding_makes_a_string():
    word = ir.Sload(ir.Const(3))
    keep = ir.Op("add", (ir.Op("shl", (ir.Const(8), ir.Op("iszero", (ir.Field(word, 0, 1),)))), ir.Const(ir.WORD_MAX)))
    lay = layout_of([ret(ir.Op("shr", (ir.ONE, ir.Op("and", (word, keep)))))])
    assert types(lay) == {(3, 0): "string"}


def test_struct_member_only_set_to_zero_is_a_member():
    base = kc(cd(0), ir.Const(0))
    flag = ir.Op("iszero", (ir.Op("iszero", (cd(1),)),))
    lay = layout_of(
        # a bool member in its own byte and a bytes4 member: nothing above them
        [ir.Sstore(base, flag, 0, 8), ir.Sstore(base, ir.Mask(32, 224, -224, cd(2)), 8, 32), ir.Stop()],
        [ret(ir.Op("iszero", (ir.Op("iszero", (field(base, 0, 8),)),)))],
        # a member only ever set to zero when the struct is built stays a member
        [ir.Sstore(ir.Op("add", (ir.ONE, base)), cd(1), 0, 8), ir.Sstore(ir.Op("add", (ir.ONE, base)), ir.ZERO, 8, 64),
         ir.Stop()],
    )
    assert types(lay) == {(0, 0): "mapping(uint256 => Struct0)"}
    members = lay.vars[0].type[2][1]
    assert [(s, b, t) for s, b, t in members] == [(0, 0, ("v", "bool")), (0, 1, ("v", "bytes4")),
                                                   (1, 0, ("v", "uint8")), (1, 1, ("v", "uint64"))]


def test_reads_masked_from_an_offset_are_fields():
    w = ir.Sload(ir.Const(0))
    lay = layout_of(
        [ret(field(0, 0, 8))],
        [ret(ir.Mask(64, 8, -8, w))],  # a uint64 at byte 1, moved down
        [ret(ir.Mask(32, 88, 136, w))],  # a bytes4 at byte 11, moved to the top
        [ret(ir.Mask(16, 240, 0, w))],  # a bytes2 at byte 30, in place
        # the kept part of a word stored back is no field
        [ir.Sstore(ir.Const(1), ir.Op("or", (ir.Mask(248, 8, 0, ir.Sload(ir.Const(1))), ir.Mask(8, 0, 0, cd(0))))),
         ir.Sstore(ir.Const(2), ir.Mask(248, 8, 0, ir.Sload(ir.Const(2)))), ir.Stop()],
        [ret(field(1, 0, 8))],
        [ret(field(2, 0, 8))],
    )
    assert types(lay) == {(0, 0): "uint8", (0, 1): "uint64", (0, 11): "bytes4", (0, 30): "bytes2",
                          (1, 0): "uint8", (2, 0): "uint8"}


def test_bits_stored_back_where_they_were_are_no_field():
    # a read-modify-write split in parts: t = sload(0); two fields written;
    # the bits above them stored back from t
    t = ir.Local("t4")
    lay = layout_of(
        [ir.Assign(t, ir.Sload(ir.Const(0))), ir.Sstore(ir.Const(0), ir.Mask(8, 0, 0, cd(0)), 0, 8),
         ir.Sstore(ir.Const(0), ir.Mask(128, 0, 0, cd(1)), 8, 128), ir.Sstore(ir.Const(0), ir.Mask(120, 136, -136, t),
                                                                             136, 120), ir.Stop()],
        [ret(field(0, 0, 8), field(0, 8, 128))],
    )
    assert types(lay) == {(0, 0): "uint8", (0, 1): "uint128"}


def test_untrusted_outputs_never_contradict_the_reads():
    # h() returns its uint128 zero-extended: a database output int128 is
    # contradicted (an int128 getter sign-extends); bytes32 / uint outputs
    # are not (no cleanup tells them)
    reads = {"h": field(0, 0, 128), "w": ir.Sload(ir.Const(1)), "v": field(2, 0, 64)}
    functions, specs = {}, {}
    for i, (name, word) in enumerate(reads.items()):
        key = f"0x{0x20000000 + i:08x}"
        functions[key] = ir.Function(key, (ret(word),))
        specs[key] = EntrySpec(key=key, kind="function", selector=0x20000000 + i, signature=f"{name}()", name=name)
    outputs = dict(zip(functions, (("int128",), ("bytes32",), ("uint64",))))
    assert types(storage.infer_layout(functions, specs, outputs)) == {(0, 0): "uint128", (1, 0): "bytes32",
                                                                      (2, 0): "uint64"}
    trusted = storage.infer_layout(functions, specs, outputs, trusted={next(iter(functions))})
    assert types(trusted)[(0, 0)] == "int128"


def test_a_zero_extended_narrow_write_is_one_field():
    # acc = uint8(v) on a uint256 variable: the engine writes the value's bits
    # and the zero bits above them apart; another function writes the word
    narrow = [ir.Sstore(ir.Const(0), ir.Mask(8, 0, 0, cd(0)), 0, 8), ir.Sstore(ir.Const(0), ir.ZERO, 8, 248),
              ir.Stop()]
    lay = layout_of(narrow, [ir.Sstore(ir.Const(0), cd(0)), ir.Stop()], [ret(ir.Sload(ir.Const(0)))])
    assert types(lay) == {(0, 0): "uint256"}
    # alone, with a whole-word read: the start is the only reliable bound
    address = [ir.Sstore(ir.Const(0), ir.Mask(160, 0, 0, cd(0)), 0, 160),
               ir.Sstore(ir.Const(0), ir.ZERO, 160, 96), ir.Stop()]
    assert types(layout_of(address, [ret(ir.Sload(ir.Const(0)))])) == {(0, 0): "uint256"}
    # a packed value whose upper bits are kept is its own field
    kept = [ir.Sstore(ir.Const(0), ir.Mask(160, 0, 0, cd(0)), 0, 160), ir.Stop()]
    assert types(layout_of(kept, [ret(ir.Sload(ir.Const(0)))])) == {(0, 0): "address"}


def test_a_zero_extension_split_around_another_field_write():
    # [bytes4 tag | uint64 count]: count = uint64(uint32(tag)); tag = 0 is one
    # SSTORE the engine splits into count's low half (read before tag is
    # cleared), tag's zero and count's high half
    tag_to_count = [ir.Sstore(ir.Const(1), field(1, 0, 32), 32, 32), ir.Sstore(ir.Const(1), ir.ZERO, 0, 32),
                    ir.Sstore(ir.Const(1), ir.ZERO, 64, 32), ir.Stop()]
    lay = layout_of(tag_to_count, [ret(field(1, 32, 64))], [ret(ir.Mask(32, 0, 224, field(1, 0, 32)))])
    assert types(lay) == {(1, 0): "bytes4", (1, 4): "uint64"}


def test_a_byte_read_of_a_written_field_does_not_split_it():
    set_tag = [ir.Sstore(ir.Const(1), ir.Mask(32, 224, -224, cd(0)), 0, 32), ir.Stop()]
    first_byte = [ret(ir.Mask(8, 24, 224, ir.Sload(ir.Const(1))))]  # tag[0]
    lay = layout_of(set_tag, first_byte, [ret(ir.Mask(32, 0, 224, field(1, 0, 32)))])
    assert types(lay) == {(1, 0): "bytes4"}
    # without the write the byte read is the only evidence: a bytes1 field
    assert types(layout_of(first_byte)) == {(1, 3): "bytes1"}
    # a whole-word value written once and read in parts (manual packing) is one word
    lay = layout_of([ir.Sstore(ir.Const(2), cd(0)), ir.Stop()], [ret(field(2, 64, 64))], [ret(field(2, 0, 64))])
    assert types(lay) == {(2, 0): "uint256"}


def test_an_enum_range_check_types_only_a_one_byte_field():
    # a validated enum parameter stored into a uint256 variable is no enum field
    check = ir.If(ir.Op("gt", (cd(0), ir.Const(2))), (ir.Revert(ir.Panic(0x21)),))
    lay = layout_of([check, ir.Sstore(ir.Const(0), cd(0)), ir.Stop()], [ret(ir.Sload(ir.Const(0)))])
    assert types(lay) == {(0, 0): "uint256"}
    lay = layout_of([check, ir.Sstore(ir.Const(0), cd(0), 0, 8), ir.Stop()], [ret(field(0, 0, 8))])
    assert types(lay) == {(0, 0): "Enum3"}


def test_a_getter_of_every_field_of_one_slot_is_a_struct_of_a_known_shape():
    # `Pair public pair` (slot 0) next to `mapping(address => Pair) pairs` (slot 2)
    base = kc(cd(0), ir.Const(2))
    pair = [ret(field(0, 0, 8), field(0, 8, 8), field(0, 16, 16))]
    pairs = [ret(field(base, 0, 8), field(base, 8, 8), field(base, 16, 16))]
    lay = layout_of(pair, pairs, params={1: ("address",)})
    assert types(lay) == {(0, 0): "Struct0", (2, 0): "mapping(address => Struct0)"}
    # the same getter without that struct elsewhere: packed values (a getter
    # returning several variables of one slot reads the same)
    assert types(layout_of(pair)) == {(0, 0): "uint8", (0, 1): "uint8", (0, 2): "uint16"}


def test_a_narrower_value_stored_as_a_whole_word_is_read_as_its_field():
    # `sstore(0, who)` in assembly next to the ordinary accesses of
    # `address owner`: the 160-bit reads cover every bit the value can have
    setter = [ir.Sstore(ir.Const(0), cd(0)), ir.Stop()]
    renounce = [ir.Sstore(ir.Const(0), ir.ZERO, 0, 160), ir.Stop()]
    lay = layout_of(setter, renounce, [ret(field(0, 0, 160))], params={0: ("address",)})
    assert types(lay) == {(0, 0): "address"}
    # the same with a value bounded by a mask instead of a parameter type
    masked = [ir.Sstore(ir.Const(1), ir.Mask(64, 0, 0, cd(0))), ir.Stop()]
    assert types(layout_of(masked, [ret(field(1, 0, 64))])) == {(1, 0): "uint64"}
    # a read of fewer bits than the value has is still a part of it
    assert types(layout_of(masked, [ret(field(1, 0, 32))])) == {(1, 0): "uint256"}


# ---------------------------------------------------------------- usage of the values read


def test_a_byte_only_tested_against_zero_is_a_bool():
    # `require(allowed[msg.sender])` on a mapping only the constructor writes,
    # and a flag only read as a condition
    allowed = field(kc(ir.Env("caller"), ir.Const(1)), 0, 8)
    lay = layout_of([ir.If(ir.Op("iszero", (allowed,)), (ir.Revert(ir.ErrorString(b"no")),)), ir.Stop()],
                    [ir.Require(field(0, 0, 8)), ir.Stop()])
    assert types(lay) == {(0, 0): "bool", (1, 0): "mapping(address => bool)"}
    # a byte also compared with 5, or written with 2, is a number
    lay = layout_of([ir.Require(field(0, 0, 8)), ir.Stop()],
                    [ir.Require(ir.Op("eq", (field(0, 0, 8), ir.Const(5)))), ir.Stop()],
                    [ir.Require(field(1, 0, 8)), ir.Sstore(ir.Const(1), ir.Const(2), 0, 8), ir.Stop()])
    assert types(lay) == {(0, 0): "uint8", (1, 0): "uint8"}


def test_a_byte_written_with_one_but_compared_as_a_number_is_no_bool():
    # `require(_initialized < 1); _initialized = 1;` (a version counter)
    init = [ir.Require(ir.Op("lt", (field(0, 0, 8), ir.ONE))), ir.Sstore(ir.Const(0), ir.ONE, 0, 8), ir.Stop()]
    assert types(layout_of(init)) == {(0, 0): "uint8"}
    # the same flag tested against zero only stays a bool
    flag = [ir.Require(ir.Op("iszero", (field(0, 0, 8),))), ir.Sstore(ir.Const(0), ir.ONE, 0, 8), ir.Stop()]
    assert types(layout_of(flag)) == {(0, 0): "bool"}


def test_a_word_hashed_or_compared_with_a_hash_is_bytes32():
    hashed_param = kc(cd(0))
    lay = layout_of([ir.Sstore(ir.Const(0), hashed_param), ir.Stop()],
                    [ir.Require(ir.Op("eq", (hashed_param, ir.Sload(ir.Const(1))))), ir.Stop()])
    assert types(lay) == {(0, 0): "bytes32", (1, 0): "bytes32"}
    # a hash used as a number (a random seed) is a uint256
    seed = [ir.Sstore(ir.Const(0), kc(ir.Env("timestamp"))), ir.Stop()]
    draw = [ret(ir.Op("mod", (ir.Sload(ir.Const(0)), ir.Const(10))))]
    assert types(layout_of(seed, draw)) == {(0, 0): "uint256"}


def test_signed_comparisons_and_arithmetic_make_an_int256():
    lay = layout_of([ret(ir.Op("slt", (ir.Sload(ir.Const(0)), ir.ZERO)))],
                    [ret(ir.Op("sdiv", (ir.Sload(ir.Const(1)), ir.Const(2))))],
                    [ret(ir.Op("lt", (ir.Sload(ir.Const(2)), ir.Const(7))))])
    assert types(lay) == {(0, 0): "int256", (1, 0): "int256", (2, 0): "uint256"}


def test_the_uses_of_a_local_holding_the_value_count():
    # `uint256 seed = _seed; return seed % 10;` where _seed = keccak256(...):
    # a number; `bool ok = flags[msg.sender]; require(ok);`: a bool
    seed, ok = ir.Local("seed"), ir.Local("ok")
    write = [ir.Sstore(ir.Const(0), kc(ir.Env("timestamp"))), ir.Stop()]
    draw = [ir.Assign(seed, ir.Sload(ir.Const(0))), ret(ir.Op("mod", (seed, ir.Const(10))))]
    check = [ir.Assign(ok, field(kc(ir.Env("caller"), ir.Const(1)), 0, 8)), ir.Require(ok), ir.Stop()]
    assert types(layout_of(write, draw, check)) == {(0, 0): "uint256", (1, 0): "mapping(address => bool)"}


def test_hashes_used_as_keys_make_bytes32_keys():
    # roles[MINTER_ROLE][msg.sender] (a role id is a keccak256 constant),
    # queued[keccak256(id)]; a small constant or a mask stays a uint256 key
    role = int.from_bytes(keccak(b"MINTER_ROLE"), "big")
    member = kc(ir.Env("caller"), kc(ir.Const(role), ir.Const(0)))
    lay = layout_of([ir.Require(field(member, 0, 8)), ir.Stop()],
                    [ret(ir.Sload(kc(kc(cd(0)), ir.Const(1))))],
                    [ret(ir.Sload(kc(ir.Const(7), ir.Const(2)))), ret(ir.Sload(kc(ir.Const(2**256 - 1), ir.Const(2))))])
    assert types(lay) == {(0, 0): "mapping(bytes32 => mapping(address => bool))", (1, 0): "mapping(bytes32 => uint256)",
                          (2, 0): "mapping(uint256 => uint256)"}


def test_a_value_only_written_zero_extended_takes_the_cleared_bits_above():
    # `uint256 v = p` for a uint128 p, `uint64 s = q` for a uint32 q: the SSTORE
    # clears the bits above the value (a narrower variable would keep them)
    wide = [ir.Sstore(ir.Const(0), ir.Mask(128, 0, 0, cd(0)), 0, 128), ir.Sstore(ir.Const(0), ir.ZERO, 128, 128),
            ir.Stop()]
    small = [ir.Sstore(ir.Const(1), ir.Mask(32, 0, 0, cd(0)), 0, 32), ir.Sstore(ir.Const(1), ir.ZERO, 32, 32),
             ir.Stop()]
    assert types(layout_of(wide, small)) == {(0, 0): "uint256", (1, 0): "uint64"}
    # read at the value's width, the value is the variable and the bits above are unused
    assert types(layout_of(wide, [ret(field(0, 0, 128))])) == {(0, 0): "uint128"}


def test_untrusted_outputs_do_not_type_the_elements_of_a_getter():
    # `uint256[] public data` whose getter some other contract declared with a
    # bytes32 output; a curated output still decides
    data = int.from_bytes(keccak((0).to_bytes(32, "big")), "big")
    body = [ir.Require(ir.Op("lt", (cd(0), ir.Sload(ir.Const(0))))),
            ret(ir.Sload(ir.Op("add", (ir.Const(data), cd(0)))))]
    key = "0x30000000"
    functions = {key: ir.Function(key, tuple(body))}
    specs = {key: EntrySpec(key=key, kind="function", selector=0x30000000, signature="data(uint256)", name="data",
                            params=((parse_type("uint256"), "p0"),))}
    outputs = {key: ("bytes32",)}
    assert types(storage.infer_layout(functions, specs, outputs)) == {(0, 0): "uint256[]"}
    assert types(storage.infer_layout(functions, specs, outputs, trusted={key})) == {(0, 0): "bytes32[]"}

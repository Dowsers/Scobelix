"""
Parameter types of functions whose selector is not in the signature
database (fixture ParamTypes: solc 0.8.19 legacy and via IR, 0.5.17 with
ABI coder v1), inferred from the decoder's validators or from the uses of
the head words.
"""

import functools
import logging
from pathlib import Path

import pytest
from eth_hash.auto import keccak

from scobelix.decompiler import decompile_bytecode
from scobelix.function import has_validators, infer_params

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "bytecode"


@functools.lru_cache(maxsize=None)
def _decompile(name):
    logging.disable(logging.WARNING)
    try:
        return decompile_bytecode((FIXTURES_DIR / f"{name}.hex").read_text().strip())
    finally:
        logging.disable(logging.NOTSET)


def selector(signature):
    return "0x" + keccak(signature.encode()).hex()[:8]


def types(fixture, signature):
    f = _decompile(fixture).functions[selector(signature)]
    assert f.name.startswith("unknown"), f.name  # not in the signature database
    return [kind for kind, _ in f.inferred_params.values()]


V2_BUILDS = ("ParamTypes", "ParamTypesViaIR")


@pytest.mark.parametrize("fx", V2_BUILDS)
def test_validators_give_the_types(fx):
    assert types(fx, "qpAddr(address)") == ["address"]
    assert types(fx, "qpBool(bool)") == ["bool"]
    assert types(fx, "qpSmall(uint8,uint40)") == ["uint8", "uint40"]
    assert types(fx, "qpSigned(int16)") == ["int16"]
    assert types(fx, "qpBytes(bytes4)") == ["bytes4"]
    assert types(fx, "qpEnum(uint8)") == ["uint8"]
    assert types(fx, "qpWide(uint256,uint128)") == ["uint256", "uint128"]


@pytest.mark.parametrize("fx", V2_BUILDS)
def test_dynamic_parameters(fx):
    assert types(fx, "qpData(bytes)") == ["bytes"]
    assert types(fx, "qpWords(uint256[])") == ["array"]


@pytest.mark.parametrize("fx", V2_BUILDS + ("ParamTypesLegacy",))
def test_an_unused_head_word_keeps_its_place(fx):
    assert types(fx, "qpSkip(uint256,uint8)") == ["uint256", "uint8"]


def test_coder_v1_types_come_from_the_uses():
    fx = "ParamTypesLegacy"
    assert types(fx, "qpAddr(address)") == ["address"]
    assert types(fx, "qpBool(bool)") == ["bool"]
    assert types(fx, "qpSmall(uint8,uint40)") == ["uint8", "uint40"]
    assert types(fx, "qpSigned(int16)") == ["int16"]
    assert types(fx, "qpEnum(uint8)") == ["uint8"]
    assert types(fx, "qpWide(uint256,uint128)") == ["uint256", "uint128"]
    assert types(fx, "qpData(bytes)") == ["array"]  # copied word by word, like an array


# ------------------------------------------------------------- unit level

CD4 = ("cd", 4)
REVERT = [("revert", None)]


def with_validator(cond, body):
    return [("if", ("slt", ("add", -4, "calldatasize"), 32), REVERT, [("if", cond, REVERT, body)])]


def test_narrowest_use_site_mask_wins():
    # the first mask seen used to win (a comparison instead of an assignment)
    trace = [
        ("store", 256, 0, 0, ("mask_shl", 32, 0, 0, CD4)),
        ("store", 256, 0, 1, ("mask_shl", 8, 0, 0, CD4)),
        ("stop",),
    ]
    assert infer_params(trace) == {4: ("uint8", "_param1")}


def test_legacy_v2_validator_forms():
    body = [("store", 256, 0, 0, CD4), ("stop",)]
    for exp, kind in (
        (("mask_shl", 160, 0, 0, CD4), "address"),
        (("mask_shl", 24, 0, 0, CD4), "uint24"),
        (("bool", CD4), "bool"),
        (("signextend", 1, CD4), "int16"),
        (("mask_shl", 32, 224, 0, CD4), "bytes4"),
    ):
        trace = with_validator(("iszero", ("eq", CD4, exp)), body)
        assert infer_params(trace) == {4: (kind, "_param1")}, kind
    trace = with_validator(("ge", CD4, 3), body)
    assert infer_params(trace) == {4: ("uint8", "_param1")}


def test_via_ir_validator_forms():
    body = [("store", 256, 0, 0, CD4), ("stop",)]
    for cond, kind in (
        (("mask_shl", 96, 160, 0, CD4), "address"),
        (("mul", -1, ("mask_shl", 96, 160, 0, CD4)), "address"),
        (("add", CD4, ("mul", -1, ("bool", CD4))), "bool"),
        (("add", ("bool", CD4), ("mul", -1, CD4)), "bool"),
        (("add", CD4, ("mul", -1, ("signextend", 0, CD4))), "int8"),
        (("le", 3, CD4), "uint8"),
    ):
        assert infer_params(with_validator(cond, body)) == {4: (kind, "_param1")}, kind


def test_a_validated_function_keeps_wide_words_wide():
    # ABI coder v2 checks every narrow type: a word without a check is a
    # 256-bit one even when the code masks it later
    body = [("store", 256, 0, 0, ("mask_shl", 8, 0, 0, ("cd", 36))), ("stop",)]
    trace = [
        ("if", ("slt", ("add", -4, "calldatasize"), 64), REVERT,
         [("if", ("iszero", ("eq", CD4, ("bool", CD4))), REVERT, body)]),
    ]
    assert infer_params(trace) == {4: ("bool", "_param1"), 36: ("uint256", "_param2")}


def test_a_shifted_field_is_not_a_type():
    trace = [("return", ("mask_shl", 8, 248, -248, CD4))]
    assert infer_params(trace) == {4: ("uint256", "_param1")}


def test_a_read_at_a_computed_offset_does_not_stop_the_inference():
    trace = [
        ("store", 256, 0, 0, ("mask_shl", 8, 0, 0, CD4)),
        ("store", 256, 0, 1, ("cd", ("add", 36, ("cd", 36), ("var", 0)))),
        ("store", 256, 0, 2, ("cd", ("var", 0))),
        ("stop",),
    ]
    assert infer_params(trace) == {4: ("uint8", "_param1"), 36: ("array", "_param2")}


def test_a_pointer_read_through_a_computed_offset_is_not_a_parameter():
    # cd[4 + cd[4 + cd[4]]]: the outer read's offset is computed, only the
    # head word at 4 is a (dynamic) parameter
    inner = ("cd", ("add", 4, CD4))
    trace = [("return", ("add", CD4, ("cd", ("add", 4, inner))))]
    assert infer_params(trace) == {4: ("array", "_param1")}
    # a pointer that is not a head word (here the selector word): no guess
    assert infer_params([("return", ("cd", ("add", 36, ("cd", 0))))]) == {}
    assert infer_params([("return", ("cd", ("add", 4, ("cd", 5))))]) == {}


def test_the_head_size_comes_from_the_code_and_is_bounded():
    def sized(k):
        return [("if", ("lt", ("add", -4, "calldatasize"), k), REVERT, [("return", CD4)])]

    assert len(infer_params(sized(32 * 64))) == 64  # a static array of 64 words
    # a bound no argument list has gives no slot to the words it would cover
    assert infer_params(sized(2**40)) == {4: ("uint256", "_param1")}
    assert infer_params(sized(-32)) == {4: ("uint256", "_param1")}


def test_unoptimized_code_validates_256_bit_words_against_themselves():
    # hi << 128 | uint128(lo) with two uint256 parameters: the decoder's
    # iszero(eq(P, P)) is the mark of ABI coder v2, the masks are uses
    body = [("return", ("or", ("mask_shl", 256, 0, 128, CD4), ("mask_shl", 128, 0, 0, ("cd", 36))))]
    trace = [
        ("if", ("slt", ("add", -4, "calldatasize"), 64), REVERT,
         [("if", ("iszero", ("eq", CD4, CD4)), REVERT,
           [("if", ("iszero", ("eq", ("cd", 36), ("cd", 36))), REVERT, body)])]),
    ]
    assert has_validators(trace)
    assert infer_params(trace) == {4: ("uint256", "_param1"), 36: ("uint256", "_param2")}
    # without the checks (optimized code, or ABI coder v1) the mask is all there is
    assert not has_validators(body)
    assert infer_params(body) == {4: ("uint256", "_param1"), 36: ("uint128", "_param2")}


def test_the_256_bit_validator_of_a_fixture():
    trace = _decompile("StorageShapesNoopt").functions[selector("close(uint256)")].orig_trace
    assert has_validators(trace)
    assert infer_params(trace) == {4: ("uint256", "_param1")}


def test_a_left_shift_is_not_a_cleanup():
    # x << k and x * 2**k keep the low 256 - k bits: no narrower type
    for shl in (8, 96, 128):
        trace = [("return", ("mask_shl", 256 - shl, 0, shl, CD4))]
        assert infer_params(trace) == {4: ("uint256", "_param1")}, shl
    # a mask narrower than the shift leaves room for is a cleanup
    trace = [("return", ("mask_shl", 160, 0, 64, CD4))]
    assert infer_params(trace) == {4: ("address", "_param1")}

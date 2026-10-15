"""scobelix.verify.bytecode: masking, runtime comparison (L4), immutables, settings search."""

import pytest
from verify_helpers import SOLC, compile_fixture, fixture_source, original_runtime, requires_solc

from scobelix.utils.metadata import find_all_metadata
from scobelix.verify import bytecode, solc


def test_disasm_and_hex_input():
    code = bytecode.to_bytes(" 0x6001600201610102 ")
    assert bytecode.disasm(code) == [(0, 0x60, 1), (2, 0x60, 2), (4, 0x01, None), (5, 0x61, 0x0102)]
    assert bytecode.disasm(b"\x62\x01") == [(0, 0x62, 0x010000)]  # a PUSH3 cut short is zero-padded
    assert bytecode.to_bytes(b"\x01") == b"\x01" and bytecode.to_bytes("ab") == b"\xab"


def test_mask_clips_and_zeroes():
    assert bytecode.mask(b"\x01\x02\x03\x04", [(1, 3), (3, 10)]) == b"\x01\x00\x00\x00"


def test_outer_metadata_is_dropped():
    code = original_runtime("SimpleToken")
    stripped = bytecode.strip_all_metadata(code)
    assert len(stripped) == len(code) - 53  # solc 0.8.19 ipfs trailer
    assert bytecode.push_values(code) == bytecode.push_values(stripped)


@requires_solc
def test_embedded_trailers_are_masked_and_child_code_cut():
    art = compile_fixture("misc/Factory.sol", "Factory")
    spans = find_all_metadata(art.runtime)
    assert len(spans) == 2 and spans[-1][1] == len(art.runtime)
    stripped = bytecode.strip_all_metadata(art.runtime)
    start, end = spans[0]
    assert stripped[start:end] == bytes(end - start)
    own = bytecode.own_code(art.runtime)
    child = compile_fixture("misc/Factory.sol", "Child")
    assert len(own) < start and child.creation[:5] == art.runtime[len(own) : len(own) + 5]


@requires_solc
def test_recompiled_fixture_is_identical():
    cmp = bytecode.compare_runtime(
        original_runtime("SimpleToken"), compile_fixture("token/Recon.sol", "Recon").runtime
    )
    assert cmp.identical and cmp.same_length and cmp.first_diff is None
    assert cmp.instr_similarity == cmp.opcode_similarity == 1.0


@requires_solc
def test_another_metadata_format_is_still_identical():
    art = compile_fixture("token/Recon.sol", "Recon", solc.Settings(metadata_hash="none"))
    assert len(art.runtime) != len(original_runtime("SimpleToken"))
    assert bytecode.compare_runtime(original_runtime("SimpleToken"), art.runtime).identical


@requires_solc
@pytest.mark.parametrize(
    "rel, name", [("token/Restyled.sol", "Restyled"), ("token/UncheckedAdd.sol", "UncheckedAdd")]
)
def test_different_code_reports_similarity(rel, name):
    cmp = bytecode.compare_runtime(
        original_runtime("SimpleToken"), compile_fixture(rel, name).runtime
    )
    assert not cmp.identical and cmp.first_diff is not None
    assert 0.5 < cmp.instr_similarity < 1.0 and cmp.opcode_similarity >= cmp.instr_similarity
    assert bytecode.instr_sim(
        original_runtime("SimpleToken"), compile_fixture(rel, name).runtime
    ) == (cmp.instr_similarity)
    assert cmp.to_dict()["len_original"] == 512


@requires_solc
def test_immutables_are_masked_read_and_patched():
    art = compile_fixture("misc/Immutables.sol", "Imm")
    ids = {name: ast_id for ast_id, name in art.immutable_names.items()}
    owner = int("a1" * 20, 16)
    deployed = bytecode.patch_immutables(
        art.runtime, art.immutable_refs, {ids["owner"]: owner, ids["cap"]: 1000}
    )
    assert deployed != art.runtime
    assert not bytecode.compare_runtime(deployed, art.runtime).identical
    assert bytecode.compare_runtime(deployed, art.runtime, art.immutable_refs).identical
    values = bytecode.read_immutables(deployed, art.immutable_refs)
    assert (
        int.from_bytes(values[ids["owner"]], "big") == owner
        and int.from_bytes(values[ids["cap"]], "big") == 1000
    )
    assert bytecode.patch_immutables(art.runtime, art.immutable_refs, values) == deployed
    spans = bytecode.immutable_spans(art.immutable_refs)
    assert len(spans) >= 2 and all(e - s == 32 for s, e in spans)


@requires_solc
def test_library_self_address_is_masked():
    lib = compile_fixture("misc/Immutables.sol", "Lib")
    assert lib.runtime[0] == 0x73 and lib.runtime[1:21] == bytes(20)
    # what the deployer patches in
    deployed = lib.runtime[:1] + bytes.fromhex("12" * 20) + lib.runtime[21:]
    assert bytecode.library_self_address_span(lib.runtime) == [(1, 21)]
    assert bytecode.compare_runtime(deployed, lib.runtime).identical


def test_link_spans():
    refs = {"L.sol": {"L": [{"start": 10, "length": 20}, {"start": 40, "length": 20}]}}
    assert bytecode.link_spans(refs) == [(10, 30), (40, 60)]


@requires_solc
def test_settings_search_lists_every_identical_variant():
    source = (
        bytecode.to_bytes(original_runtime("SimpleToken")),
        {"Recon.sol": fixture_source("token/Recon.sol")},
    )
    search = bytecode.search_l4(source[0], source[1], "Recon", SOLC)
    assert search.identical and search.complete
    assert {s.label for s in search.matching} == {"opt200", "opt1"}
    assert len(search.variants) == 9 and search.best_settings.label == "opt200"
    assert search.to_dict()["matching"] == ["opt200", "opt1"]


@requires_solc
def test_settings_search_respects_its_time_limit():
    search = bytecode.search_l4(
        original_runtime("SimpleToken"),
        fixture_source("token/UncheckedAdd.sol"),
        "UncheckedAdd",
        SOLC,
        time_limit=0,
    )
    assert not search.complete and len(search.variants) == 1 and not search.identical
    assert search.best is not None and search.best.instr_similarity < 1


@requires_solc
def test_settings_search_reports_compile_errors_per_variant():
    search = bytecode.search_l4(
        original_runtime("SimpleToken"), "contract", "X", SOLC, variants=[solc.Settings()]
    )
    assert search.best is None and "error" in search.variants[0]

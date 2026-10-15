"""scobelix.verify.guides: guard-directed inputs, and what they let a small budget reach."""

import random

import pytest
from eth_abi import encode
from verify_helpers import compile_fixture, requires_pyevm, requires_pyrevm, requires_solc

from scobelix.verify.abi import specs_from_abi
from scobelix.verify.equiv import CONTRACT, Call, Differ, Learned, PreState
from scobelix.verify.evm import CallResult
from scobelix.verify.guides import (
    Context,
    Guide,
    Loc,
    Ref,
    apply_call,
    apply_storage,
    learn,
    shape_slots,
)
from scobelix.verify.layout import normalize_layout
from scobelix.verify.seeds import SeedPlan, mapping_slot

SENDER = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
STUB = 0x57AB57AB57AB57AB57AB57AB57AB57AB57AB57AB
OWNER = 0x1234567890ABCDEF1234567890ABCDEF12345678
LT, GT, EQ, ISZERO, CALL, EXTCODESIZE = 0x10, 0x11, 0x14, 0x15, 0xF1, 0x3B


def _result(trace, reads=(), hashes=()):
    return CallResult(
        success=False,
        output=b"",
        error="revert",
        logs=[],
        storage_diff={},
        storage_reads={(CONTRACT, s) for s in reads},
        balances={},
        created=[],
        trace=list(trace),
        hashes=list(hashes),
    )


def _ctx(*args, sender=SENDER):
    data = bytes.fromhex("aabbccdd") + b"".join(a.to_bytes(32, "big") for a in args)
    return Context.of(data, sender, STUB)


def _learn(trace, storage, ctx, reads=None, hashes=(), failed=False, env=None, value=0):
    result = _result(trace, storage if reads is None else reads, hashes)
    return learn(result, storage, env or {}, value, ctx, CONTRACT, failed)


def test_an_owner_packed_with_a_flag_is_located_through_its_mask():
    word = (1 << 160) | OWNER  # `paused` set above the owner
    lesson = _learn([(EQ, OWNER, SENDER)], {0: word}, _ctx())
    assert lesson.guides == [Guide(Loc("storage", 0, bits=160), Ref("sender"))]


def test_a_repetitive_word_locates_its_mask_once():
    ones = (1 << 256) - 1
    lesson = _learn([(EQ, (1 << 160) - 1, SENDER)], {0: ones}, _ctx())
    assert [g.loc for g in lesson.guides] == [Loc("storage", 0, bits=160)]


def test_mapping_entries_are_keyed_by_the_call_s_own_context():
    tid = 77777777
    entry = mapping_slot(tid, 2)
    holder = 0xBEEF0000000000000000000000000000000000BE
    lesson = _learn(
        [(EQ, holder, SENDER)], {entry: holder}, _ctx(tid), hashes=[(entry, (tid, 2))]
    )
    loc = Loc("storage", 2, keys=(Ref("arg", 0),))
    assert lesson.guides == [Guide(loc, Ref("sender"))] and lesson.shapes == [loc]
    # placed in another call: the entry of that call's own argument, for that call's sender
    other = _ctx(5, sender=0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2)
    storage = {}
    apply_storage(random.Random(1), [Guide(loc, Ref("sender"))], storage, {}, other)
    assert storage == {mapping_slot(5, 2): other.sender}
    assert shape_slots([loc], other) == [mapping_slot(5, 2)]


def test_nested_mappings_and_struct_members():
    inner = mapping_slot(SENDER, 7)
    member = mapping_slot(SENDER >> 8, inner) + 3
    words = [(inner, (SENDER, 7)), (member - 3, (SENDER >> 8, inner))]
    ctx = _ctx(SENDER >> 8)
    lesson = _learn([(ISZERO, 123456789, 0)], {member: 123456789}, ctx, hashes=words)
    assert lesson.shapes == [Loc("storage", 7, keys=(Ref("sender"), Ref("arg", 0)), offset=3)]


def test_decisive_guides_flip_the_guard_that_rejected_the_call():
    amount, balance = 10**20, 10**18
    entry = mapping_slot(SENDER, 1)
    loc = Loc("storage", 1, keys=(Ref("sender"),))
    hashes = [(entry, (SENDER, 1))]
    # require(balanceOf[msg.sender] >= amount): lt(balance, amount) reverts
    lesson = _learn(
        [(LT, balance, amount), (LT, 0, 7)],  # then the revert path's own small comparison
        {entry: balance},
        _ctx(amount),
        hashes=hashes,
        failed=True,
    )
    assert lesson.decisive == [Guide(loc, Ref("arg", 0), True)]  # balance := amount
    # the other side of the boundary: a balance above the amount that the guard rejects
    lesson = _learn([(GT, balance, amount)], {entry: balance}, _ctx(amount), hashes=hashes,
                    failed=True)
    assert lesson.decisive == [Guide(loc, Ref("arg", 0, 1), True)]  # balance := amount + 1
    # a call between the guard and the revert: the call may have failed, nothing is decided
    lesson = _learn(
        [(LT, balance, amount), (CALL, STUB, 1), (ISZERO, 0, 0)],
        {entry: balance},
        _ctx(amount),
        hashes=hashes,
        failed=True,
    )
    assert lesson.decisive == [] and lesson.guides
    # an owner check that held, then a small unlocated comparison failing: nothing to flip
    lesson = _learn([(EQ, OWNER, OWNER), (LT, 3, 2)], {0: OWNER}, _ctx(sender=OWNER), failed=True)
    assert lesson.decisive == [] and lesson.guides == [Guide(Loc("storage", 0), Ref("sender"))]
    # a flag tested for zero: the opposite of its value
    flag = mapping_slot(SENDER, 5)
    lesson = _learn(
        [(ISZERO, 99999999, 0)], {flag: 99999999}, _ctx(), hashes=[(flag, (SENDER, 5))], failed=True
    )
    listed = Loc("storage", 5, keys=(Ref("sender"),))
    assert lesson.decisive == [Guide(listed, Ref("const", 0), True)]


def test_a_target_without_code_gets_the_generic_contract():
    oracle = 0xD00D000000000000000000000000000000000D00
    lesson = _learn([(EXTCODESIZE, oracle, 0)], {3: oracle}, _ctx(), failed=True)
    assert lesson.guides == [Guide(Loc("storage", 3), Ref("contract"))]
    assert lesson.decisive == [Guide(Loc("storage", 3), Ref("contract"), True)]


def test_small_values_locate_only_an_input_holding_them_alone():
    # 7 in two places: ambiguous; 9 in one: located
    lesson = _learn([(EQ, 7, 1000), (EQ, 9, 1000)], {1: 7, 2: 7, 3: 9}, _ctx())
    assert lesson.guides == [Guide(Loc("storage", 3), Ref("const", 1000))]
    # the calldata size is the decoder's, never an argument
    ctx = _ctx(36)
    assert _learn([(LT, 36, 100)], {}, ctx).guides == []


def test_placing_guides_in_a_call():
    ctx = _ctx(1, 2)
    data, value = apply_call(
        random.Random(1),
        [Guide(Loc("arg", n=1), Ref("sender")), Guide(Loc("value"), Ref("const", 5), True)],
        bytes.fromhex("aabbccdd") + encode(["uint256", "uint256"], [1, 2]),
        0,
        ctx,
        10**18,
    )
    assert data[36:] == SENDER.to_bytes(32, "big") and value == 5
    storage, env = {0: (1 << 200) | 0xFF}, {"0x" + "57ab" * 10: {0: 3, 1: 0}}
    apply_storage(
        random.Random(1),
        [
            Guide(Loc("storage", 0, bits=160), Ref("sender")),
            Guide(Loc("env", 1, account="0x" + "57ab" * 10), Ref("const", 42), True),
        ],
        storage,
        env,
        ctx,
    )
    assert storage[0] == (1 << 200) | SENDER  # the bits above the field are kept
    assert env["0x" + "57ab" * 10] == {0: 0, 1: 42}  # the stub now answers the word


def test_guides_keep_off_the_decoder_s_words():
    # a typed function's offsets, lengths and dynamic data are the ABI decoder's: a guide there
    # breaks the encoding of the calls that place the guides that matter
    d = Differ(b"\x00", b"\x00")
    learned = Learned(words=frozenset({0}))  # f(uint64, string): word 1 is the string's offset
    data = bytes.fromhex("aabbccdd") + encode(["uint64", "string"], [5, "hi"])
    trace = [(GT, 0x40, (1 << 64) - 1), (EQ, 5, 77777)]  # the decoder's bound, then a guard
    d._guide(learned, PreState({}, {}), Call("0x" + "a1" * 20, 0, data), _result(trace))
    assert list(learned.guides) == [Guide(Loc("arg", n=0), Ref("const", 77777))]


@requires_solc
def test_guided_writes_keep_the_layout_s_invariants():
    # an array length or a string word takes no guided value: viaIR and legacy code of one source
    # differ on lengths no contract reaches; a typed slot only takes values inside its fields
    guarded = compile_fixture("misc/Guarded.sol", "Guarded")
    plan = SeedPlan(normalize_layout(guarded.storage_layout), [])
    assert plan.admits(0, 0, 160) and plan.admits(0, 160, 8)  # owner, paused
    assert not plan.admits(0, 0, 256)  # across both fields
    assert plan.admits(mapping_slot(SENDER, 1), 0, 256)  # an entry: no layout slot
    ledger = compile_fixture("misc/Ledger.sol", "Ledger")
    plan = SeedPlan(normalize_layout(ledger.storage_layout), [])
    assert not plan.admits(1, 0, 256) and not plan.admits(1, 0, 64)  # entries.length
    assert SeedPlan([], []).admits(1, 0, 256)  # without a layout, any word


# ------------------------------------------------------------------ end to end


def _quick_differ(name, seed):
    art = compile_fixture("misc/Guarded.sol", name)
    specs = specs_from_abi(art.abi)
    # as in a generator's verification: no storage layout, pyrevm in bulk, py-evm instrumented
    return (
        Differ(
            art.runtime,
            art.runtime,
            specs=[s for s in specs.values() if s.inputs is not None],
            backend="pyrevm",
            confirm_backend="pyevm",
            seed=seed,
            max_divergences=3,
        ),
        art,
        specs,
    )


@requires_solc
@requires_pyrevm
@requires_pyevm
@pytest.mark.parametrize("seed", [1, 2, 3])
def test_a_quick_budget_reaches_the_accepting_paths(seed):
    """Budget.quick()'s 60 calls per function (16 instrumented) pass every guard: the caller
    compared with an owner packed with a flag, flags and balances under the caller, an entry
    under an argument, an oracle and a beacon held in storage, a facet keyed by msg.sig."""
    accepted = {}
    d, art, specs = _quick_differ("Guarded", seed)
    for sig in (
        "setTotal(uint256)",
        "withdraw(uint256)",
        "burn(uint256)",
        "price()",
        "label(uint64,string)",
    ):
        sel = bytes.fromhex(art.method_ids[sig])
        accepted[sig] = d.fuzz_function("0x" + sel.hex(), specs[sel], 60, sample_size=16)
    for name in ("BeaconProxy", "Facets"):
        d, _, _ = _quick_differ(name, seed)
        accepted[name] = d.fuzz_function("fallback", None, 20, probe="fallback", sample_size=16)
    assert {k: st.original_success > 0 for k, st in accepted.items()} == dict.fromkeys(
        accepted, True
    )

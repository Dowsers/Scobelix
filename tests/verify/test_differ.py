"""scobelix.verify.equiv: result comparison, environment scan, and the Differ's machinery."""

import dataclasses
import time

import pytest
from verify_helpers import (
    compile_fixture,
    original_artifact,
    original_runtime,
    requires_backend,
    requires_solc,
)

from scobelix.verify import solc
from scobelix.verify.abi import specs_from_abi
from scobelix.verify.equiv import (
    BLOCKS,
    CONTRACT,
    WEIGHT_CAP,
    Call,
    Differ,
    Divergence,
    FunctionStats,
    Learned,
    PreState,
    compare_results,
    contract_success,
    env_sensitivity,
    hardcoded_addresses,
    slot_constants,
)
from scobelix.verify.evm import DEFAULT_GAS, CallResult, available_backends
from scobelix.verify.layout import normalize_layout
from scobelix.verify.mocks import ACCEPTING_CALLER, REENTRANT_CALLER, RETURN_STUB

A = "0x" + "a1" * 20
PRE = {A: 100}  # balances before the call


def _r(**kw):
    base = dict(
        success=True,
        output=b"",
        error="",
        logs=[],
        storage_diff={},
        storage_reads=set(),
        balances={},
        created=[],
    )
    base.update(kw)
    return CallResult(**base)


def test_identical_results_do_not_diverge():
    r = _r(output=b"\x01", logs=[(CONTRACT, (1,), b"x")], storage_diff={(CONTRACT, 0): (0, 1)})
    assert compare_results(r, dataclasses.replace(r), PRE, True) == []


@pytest.mark.parametrize(
    "a, b, kinds",
    [
        (_r(), _r(success=False, error="revert"), ["success"]),
        (
            _r(success=False, error="revert"),
            _r(success=False, error="halt:InvalidFEOpcode"),
            ["halt"],
        ),
        (_r(output=b"\x01"), _r(output=b"\x02"), ["returndata"]),
        (
            _r(success=False, error="revert", output=b"\x01"),
            _r(success=False, error="revert"),
            ["revert_data"],
        ),
        (_r(logs=[(CONTRACT, (1,), b"")]), _r(logs=[(CONTRACT, (2,), b"")]), ["logs"]),
        (
            _r(storage_diff={(CONTRACT, 0): (0, 1)}),
            _r(storage_diff={(CONTRACT, 0): (0, 2)}),
            ["storage"],
        ),
        (_r(balances={A: 100}), _r(balances={A: 99}), ["balance"]),
        # an untouched account keeps its pre-state balance
        (
            _r(balances={A: 99}),
            _r(),
            ["balance"],
        ),
        (_r(calls=[(1, "call", A, 0, b"")]), _r(), ["calls"]),
        (_r(created=[(A, b"\x00")]), _r(), ["created"]),
    ],
)
def test_divergence_kinds(a, b, kinds):
    assert compare_results(a, b, PRE, compare_calls=True) == kinds


def test_same_final_storage_is_no_divergence_and_calls_need_hooks():
    a = _r(storage_diff={(CONTRACT, 0): (5, 7)}, calls=[(1, "call", A, 0, b"")])
    b = _r(storage_diff={(CONTRACT, 0): (6, 7)})
    assert compare_results(a, b, PRE, compare_calls=False) == []
    assert compare_results(a, b, PRE, compare_calls=True) == ["calls"]


def test_created_addresses_are_mapped_by_creation_order():
    orig, cand = "0x" + "11" * 20, "0x" + "22" * 20

    def word(addr):
        return bytes(12) + bytes.fromhex(addr[2:])

    a = _r(
        output=word(orig),
        logs=[(CONTRACT, (int(orig, 16),), word(orig))],
        created=[(orig, b"\x01")],
        storage_diff={(CONTRACT, 0): (0, int(orig, 16)), (orig, 0): (0, 5)},
        balances={orig: 0},
    )
    b = _r(
        output=word(cand),
        logs=[(CONTRACT, (int(cand, 16),), word(cand))],
        created=[(cand, b"\x02")],
        storage_diff={(CONTRACT, 0): (0, int(cand, 16)), (cand, 0): (0, 5)},
        balances={cand: 0},
    )
    assert compare_results(a, b, PRE, True) == []  # other child code: not compared
    b2 = dataclasses.replace(b, storage_diff={(CONTRACT, 0): (0, int(cand, 16)), (cand, 0): (0, 6)})
    assert compare_results(a, b2, PRE, True) == ["storage"]


@requires_solc
@pytest.mark.parametrize("backend", available_backends())
def test_created_addresses_stay_mapped_along_a_sequence(backend):
    from eth_abi import encode

    orig = compile_fixture("misc/PayingFactory.sol", "PayingFactory")
    cand = compile_fixture("misc/PayingFactory.sol", "PayingFactory", solc.Settings(optimize=False))
    d = Differ(orig.runtime, cand.runtime, backend=backend)
    make2 = bytes.fromhex(orig.method_ids["make2(uint256,bytes32)"]) + encode(
        ["uint256", "bytes32"], [7, b"\x01" * 32]
    )
    calls = [Call(A, 5, make2), Call(A, 0, bytes.fromhex(orig.method_ids["lastBalance()"]))]
    pre = PreState({}, {A: 10**20})
    created = (
        d.execute("o", pre, calls[0]).created[0][0],
        d.execute("c", pre, calls[0]).created[0][0],
    )
    assert created[0] != created[1]  # CREATE2 hashes the (metadata-bearing) child initcode
    index, kinds, ro, _ = d.replay_sequence(pre, calls)
    assert (index, kinds) == (2, []) and int.from_bytes(ro.output, "big") == 5


def test_contract_success_through_a_caller_mock():
    direct = Call(A, 0, b"")
    relayed = Call(A, 0, b"", via=ACCEPTING_CALLER)
    ok = _r(output=(1).to_bytes(32, "big") + bytes(64))
    nok = _r(output=bytes(96))
    assert contract_success(direct, nok) and not contract_success(direct, _r(success=False))
    assert contract_success(relayed, ok) and not contract_success(relayed, nok)


def test_environment_scan():
    gas_forwarded = bytes.fromhex("6000600060006000600073" + "11" * 20 + "5af1")  # ... GAS CALL
    assert env_sensitivity(gas_forwarded) == []
    assert env_sensitivity(bytes.fromhex("5a600052")) == ["gasleft()"]
    assert env_sensitivity(bytes.fromhex("38303b3f1e")) == [
        "CLZ (post-Cancun opcode)",
        "codesize",
        "extcode* (possibly of itself)",
    ]


def test_slot_constants():
    slot = 0xB53127684A568B3173AE13B9F8A6016E243E63B6E8EE1178D6A717850B5D6103
    code = bytes.fromhex(
        "7f" + f"{slot:064x}" + "54"  # PUSH32 <hashed slot> SLOAD
        "6005" "80" "54"  # PUSH1 5 DUP1 SLOAD
        "7f" + "ff" * 32 + "7f" + "ff" * 16 + "00" * 16 + "6009" "50"  # two masks, PUSH1 9 POP
    )
    assert slot_constants(code) == [slot, 5]


def test_the_two_blocks_differ_in_every_value_a_candidate_could_hard_code():
    first, second = BLOCKS
    for name in ("number", "timestamp", "coinbase", "prevrandao", "gas_limit", "chain_id"):
        assert getattr(first, name) != getattr(second, name), name
    assert first.basefee == second.basefee == 0  # gas price 0 stays valid: no fee moves ETH
    assert min(first.gas_limit, second.gas_limit) >= 3 * DEFAULT_GAS  # room for gas re-checks


def test_learned_values_count_once_per_call_and_weigh_by_recurrence():
    d = Differ(b"\x00", b"\x00")
    learned = Learned()
    call = Call(A, 0, b"\x00\x00\x00\x01" + (7).to_bytes(32, "big"))
    for _ in range(3):  # 7 is the call's argument: 1000 its partner, (8, 9) other operands
        d._learn(learned, [7, 1000, 7, 1000, 8, 9], PreState({}, {}), call)
    assert learned.partners == {1000: 3} and learned.others == {8: 3, 9: 3}
    weighted = Learned.weighted({1000: 30, 5: 1})
    assert weighted.count(1000) == WEIGHT_CAP and weighted.count(5) == 1


@requires_solc
@requires_backend
def test_running_out_of_gas_on_one_side_only_is_no_divergence():
    from eth_abi import encode

    orig = compile_fixture("misc/Loop.sol", "Loop")
    cand = compile_fixture("misc/Loop.sol", "Loop", solc.Settings(optimize=False))
    d = Differ(orig.runtime, cand.runtime, backend=available_backends()[0], gas=300_000)
    spin = bytes.fromhex(orig.method_ids["spin(uint256)"])
    pre = PreState({}, {A: 10**20})

    def call(n):
        return Call(A, 0, spin + encode(["uint256"], [n]))

    lo, hi = 1, 1 << 16  # the first bound the unoptimised loop does not finish within the gas
    while hi - lo > 1:
        mid = (lo + hi) // 2
        lo, hi = (mid, hi) if d.execute("c", pre, call(mid)).success else (lo, mid)
    kinds, ro, rc = d.check(pre, call(hi))
    assert ro.success and rc.halted and "success" in kinds
    stats = FunctionStats("0x" + spin.hex(), "spin")
    d._record(stats, Divergence(stats.key, kinds, call(hi), pre, ro, rc, d.backend))
    assert (stats.divergences, stats.env_divergences, stats.gas_checks) == (0, 1, 1)


@requires_solc
@requires_backend
@pytest.mark.parametrize("mock", [RETURN_STUB, ACCEPTING_CALLER, REENTRANT_CALLER])
def test_a_delegatecalled_mock_never_calls_the_contract_back(mock):
    orig = compile_fixture("misc/Proxy.sol", "Proxy")
    cand = compile_fixture("misc/Proxy.sol", "Proxy", solc.Settings(optimize=False))
    d = Differ(orig.runtime, cand.runtime, backend=available_backends()[0])
    for work in range(0, 64, 3):  # the fallback's gas varies with `work`: no budget may split
        pre = PreState({0: int(mock, 16), 2: work}, {A: 10**20})
        kinds, ro, _ = d.check(pre, Call(A, 0, bytes.fromhex("fc571204") + bytes(32)))
        assert kinds == [] and ro.success, work
        assert ro.storage_diff[(CONTRACT, 1)] == (0, 1)  # hits: the fallback ran once


def test_hardcoded_addresses():
    parts = [
        "73" + "ff" * 20,  # the 160-bit mask
        "73" + "00" * 16 + "12345678",  # small
        "73" + b"insufficient balance".hex(),  # a 20-character string
        "73" + "de" * 20,  # an address...
        "73" + "de" * 20,  # ... twice
    ]
    code = bytes.fromhex("".join(parts))
    assert hardcoded_addresses(code) == ["0x" + "de" * 20]


@pytest.fixture(scope="module")
def token_differ():
    if not available_backends():
        pytest.skip("pip install 'scobelix[verify]'")
    ref = original_artifact("SimpleToken")
    mutant = compile_fixture("token/OffByOne.sol", "OffByOne")
    return lambda **kw: Differ(
        original_runtime("SimpleToken"),
        mutant.runtime,
        specs=list(specs_from_abi(ref.abi).values()),
        layout=normalize_layout(ref.storage_layout),
        backend=available_backends()[0],
        **kw,
    )


@requires_solc
@requires_backend
def test_per_key_streams_are_reproducible(token_differ):
    spec = next(s for s in token_differ().specs if s.key == "0x70a08231")
    a = token_differ().fuzz_function(spec.key, spec, 50)
    b = token_differ()
    # another key first does not change this one
    b.fuzz_function("other", None, 20, probe="fallback")
    b = b.fuzz_function(spec.key, spec, 50)
    assert (a.calls, a.original_success, a.covered) == (b.calls, b.original_success, b.covered)
    assert [c for _, c in a.sample] == [c for _, c in b.sample]


@requires_solc
@requires_backend
def test_divergence_budget_deadline_and_shrinking(token_differ):
    d = token_differ(max_divergences=2)
    spec = next(s for s in d.specs if s.key == "0xa9059cbb")
    st = d.fuzz_function(spec.key, spec, 2000)
    assert st.divergences == 2 and st.calls < 2000
    first = st.first
    assert first.kinds and len(first.pre.storage) <= 2
    # the shrunk counterexample still diverges
    assert d.check(first.pre, first.call, first.backend)[0]
    late = token_differ(deadline=time.monotonic() - 1)
    assert late.fuzz_function(spec.key, spec, 100).calls == 0


@requires_solc
@requires_backend
def test_find_success_and_sequences(token_differ):
    d = token_differ()
    spec = next(s for s in d.specs if s.key == "0xa9059cbb")
    pre, call = d.find_success(spec.key, spec)
    assert call.value == 0 and call.via is None and d.execute("o", pre, call).success
    divs, made = d.fuzz_sequences(10, 8)
    assert made > 0 and divs and all(x.label == "sequence" for x in divs)
    small = d.explain(divs[0])
    index, kinds, _, _ = d.replay_sequence(small.pre, small.sequence + [small.call], small.backend)
    assert kinds and index == len(small.sequence) and len(small.sequence) <= len(divs[0].sequence)

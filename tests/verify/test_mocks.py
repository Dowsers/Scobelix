"""scobelix.verify.mocks: the environment contracts of differential execution."""

import pytest
from eth_abi import decode, encode
from eth_utils import keccak
from verify_helpers import BACKENDS, compile_fixture, original_runtime, requires_solc, solc_path

from scobelix.verify import mocks, solc
from scobelix.verify.evm import make_world

TARGET = "0x" + "c0de" * 10
EOA = "0x" + "a1" * 20


@pytest.mark.skipif(solc_path(mocks.MOCKS_SOLC_VERSION) is None, reason="solc 0.8.19 not installed")
def test_embedded_runtimes_are_the_compiled_source():
    comp = solc.compile_standard_json(
        {"Mocks.sol": mocks.MOCKS_SOLIDITY}, solc.Settings(), version=mocks.MOCKS_SOLC_VERSION
    )
    for name, mock in mocks.MOCKS.items():
        assert comp.artifact(name).runtime == mock.runtime, name


def _world(backend, target_code):
    w = make_world(backend)
    for m in mocks.MOCKS.values():
        w.set_code(m.address, m.runtime)
    w.set_code(TARGET, target_code)
    w.set_balance(EOA, 10**20)
    return w


def _fwd(w, caller, data, reentry=b"", value=0):
    r = w.call(EOA, caller, mocks.encode_fwd(TARGET, data, reentry), value)
    assert r.success
    ok, ret = decode(["bool", "bytes"], r.output)
    return r, ok, ret


@requires_solc
@pytest.mark.parametrize("backend", BACKENDS)
def test_callers_forward_and_react_to_eth(backend):
    w = _world(backend, original_runtime("Vault"))
    deposit, withdraw = bytes.fromhex("d0e30db0"), bytes.fromhex("2e1a7d4d") + encode(
        ["uint256"], [10]
    )
    for caller in mocks.CALLERS:
        _, ok, _ = _fwd(w, caller, deposit, value=100)
        assert ok, caller
    _, ok, _ = _fwd(w, mocks.ACCEPTING_CALLER, withdraw)
    assert ok
    _, ok, ret = _fwd(w, mocks.REJECTING_CALLER, withdraw)
    assert not ok and b"transfer failed" in ret
    r, ok, _ = _fwd(w, mocks.REENTRANT_CALLER, withdraw, reentry=withdraw)
    assert ok
    topic = int.from_bytes(keccak(text="Reentered(bool,bytes)"), "big")
    reentered = [lg for lg in r.logs if lg[0] == mocks.REENTRANT_CALLER and lg[1] == (topic,)]
    # called back exactly once
    assert len(reentered) == 1 and decode(["bool", "bytes"], reentered[0][2])[0] is True
    assert w.get_balance(mocks.REENTRANT_CALLER) == 20


@pytest.mark.parametrize("backend", BACKENDS)
def test_callbacks_get_their_selector_back(backend):
    w = _world(backend, b"")
    # onERC721Received(...)
    r = w.call(EOA, mocks.ACCEPTING_CALLER, bytes.fromhex("150b7a02") + bytes(96))
    assert r.success and r.output == bytes.fromhex("150b7a02") + bytes(28)
    assert not w.call(EOA, mocks.REJECTING_CALLER, bytes.fromhex("150b7a02")).success


STUB_CALL = bytes.fromhex("a9059cbb") + bytes(64)


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize(
    "mode, success, output",
    [
        (0, True, (7).to_bytes(32, "big")),
        (1, True, bytes(32)),
        (2, True, b""),
        (3, False, b""),
        (4, True, (int.from_bytes(keccak(STUB_CALL), "big") & 7).to_bytes(32, "big")),
        (5, False, (7).to_bytes(32, "big")),
    ],
)
def test_return_stub_modes(backend, mode, success, output):
    w = _world(backend, b"")
    w.set_storage(mocks.RETURN_STUB, 0, mode)
    w.set_storage(mocks.RETURN_STUB, 1, 7)
    r = w.call(EOA, mocks.RETURN_STUB, STUB_CALL, value=1)
    assert (r.success, r.output) == (success, output)


def _records(r):
    """(log address, `at`, (from, value, data)) of every Received record of a call."""
    out = []
    for address, topics, data in r.logs:
        if topics and topics[0] == mocks.RECEIVED_TOPIC:
            sender, value, inner = decode(["address", "uint256", "bytes"], data)
            out.append((address, topics[1], (sender.lower(), value, inner)))
    return out


@requires_solc
@pytest.mark.parametrize("backend", BACKENDS)
def test_calls_reaching_a_mock_are_recorded(backend):
    caller = compile_fixture("misc/Caller.sol", "Caller")
    w = _world(backend, caller.runtime)
    w.set_storage(mocks.RETURN_STUB, 1, 1)
    inner = bytes.fromhex("a9059cbb") + encode(["address", "uint256"], [EOA, 5])

    def run(kind, mock):
        sel = bytes.fromhex(caller.method_ids[f"{kind}(address,bytes)"])
        r = w.call(EOA, TARGET, sel + encode(["address", "bytes"], [mock, inner]))
        ok, _ = decode(["bool", "bytes"], r.output)
        assert r.success and ok
        return _records(r)

    for mock in (mocks.RETURN_STUB, mocks.ACCEPTING_CALLER, mocks.REENTRANT_CALLER):
        # a call: the recorder logs it, `at` the mock, from the calling contract
        assert run("c", mock) == [(mocks.RECORDER, int(mock, 16), (TARGET, 0, inner))]
        # a static call: nothing can be recorded (the answer is what the caller observes)
        assert run("s", mock) == []
        # a delegatecall: the mock's code records from the caller's own account, without
        # calling it back (its gas-hungry code would make equivalent builds differ)
        assert run("dc", mock) == [(mocks.RECORDER, int(TARGET, 16), (EOA, 0, inner))]
    assert w.get_storage(TARGET, 0) == 0  # Caller.hits: its fallback never ran

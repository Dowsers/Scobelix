"""scobelix.verify.evm: the pyrevm and py-evm worlds."""

import pytest
from eth_abi import encode
from eth_utils import keccak
from verify_helpers import (
    BACKENDS,
    compile_fixture,
    original_runtime,
    requires_pyevm,
    requires_pyrevm,
    requires_solc,
)

from scobelix.verify.bytecode import patch_immutables
from scobelix.verify.equiv import BLOCKS
from scobelix.verify.evm import BackendUnavailable, HarnessError, available_backends, make_world
from scobelix.verify.seeds import mapping_slot

TOKEN = "0x" + "c0de" * 10
ALICE, BOB = "0x" + "a1" * 20, "0x" + "b0" * 20
TRANSFER = bytes.fromhex("a9059cbb")


def _bal_slot(addr):
    return mapping_slot(int(addr, 16), 0)


def _token(backend, **hooks):
    w = make_world(backend, **hooks)
    w.set_code(TOKEN, original_runtime("SimpleToken"))
    w.set_storage(TOKEN, _bal_slot(ALICE), 100)
    w.set_storage(TOKEN, 1, 100)
    w.set_balance(ALICE, 10**18)
    return w


def test_available_backends_and_factory_errors():
    assert set(available_backends()) <= {"pyrevm", "pyevm"}
    with pytest.raises(ValueError):
        make_world("nope")
    if "pyrevm" in available_backends():
        with pytest.raises(ValueError, match="no hooks"):
            make_world("pyrevm", gas_cap=1)
        with pytest.raises(ValueError, match="unsupported fork"):
            make_world("pyrevm", fork="SHANGHAI")  # pyrevm would silently run LATEST


@pytest.mark.parametrize("backend", BACKENDS)
def test_success_storage_diff_and_return(backend):
    w = _token(backend)
    r = w.call(ALICE, TOKEN, TRANSFER + encode(["address", "uint256"], [BOB, 30]))
    assert r.success and r.error == "" and r.output == (1).to_bytes(32, "big")
    assert r.storage_diff == {
        (TOKEN, _bal_slot(ALICE)): (100, 70),
        (TOKEN, _bal_slot(BOB)): (0, 30),
    }
    assert (TOKEN, _bal_slot(ALICE)) in r.storage_reads
    assert w.get_storage(TOKEN, _bal_slot(BOB)) == 30  # the world keeps the new state


@pytest.mark.parametrize("backend", BACKENDS)
def test_revert_data_and_value_rejection(backend):
    w = _token(backend)
    r = w.call(ALICE, TOKEN, TRANSFER + encode(["address", "uint256"], [BOB, 1000]))
    assert not r.success and r.error == "revert" and r.output[:4] == bytes.fromhex("08c379a0")
    assert b"insufficient balance" in r.output and r.storage_diff == {}
    r = w.call(ALICE, TOKEN, TRANSFER + encode(["address", "uint256"], [BOB, 1]), value=7)
    assert not r.success and r.output == b"" and r.balances.get(ALICE, 10**18) == 10**18


@pytest.mark.parametrize("backend", BACKENDS)
def test_halt_is_not_a_revert(backend):
    w = make_world(backend)
    w.set_code(TOKEN, b"\xfe")  # INVALID
    r = w.call(ALICE, TOKEN, b"")
    assert not r.success and r.halted and r.error.startswith("halt:")


@pytest.mark.parametrize("backend", BACKENDS)
def test_unfunded_value_is_a_harness_error(backend):
    w = make_world(backend)
    w.set_code(TOKEN, b"\x00")
    with pytest.raises(HarnessError):
        w.call(ALICE, TOKEN, b"", value=5)


@requires_solc
@pytest.mark.parametrize("backend", BACKENDS)
def test_eth_transfer_and_call_tree(backend):
    vault = "0x" + "fa17" * 10
    w = make_world(backend)
    w.set_code(vault, original_runtime("Vault"))
    w.set_balance(ALICE, 10**18)
    r = w.call(ALICE, vault, bytes.fromhex("d0e30db0"), value=10**17)  # deposit()
    assert r.success and r.balances[ALICE] == 9 * 10**17 and r.balances[vault] == 10**17
    # withdraw()
    r = w.call(ALICE, vault, bytes.fromhex("2e1a7d4d") + encode(["uint256"], [4 * 10**16]))
    assert r.success and r.balances[ALICE] == 94 * 10**16
    if backend == "pyevm":
        assert r.calls == [(1, "call", ALICE, 4 * 10**16, b"")]


@requires_solc
@pytest.mark.parametrize("backend", BACKENDS)
def test_created_contracts_logs_and_order(backend):
    factory = "0x" + "fac7" * 10
    art = compile_fixture("misc/Factory.sol", "Factory")
    child = compile_fixture("misc/Factory.sol", "Child")
    w = make_world(backend)
    w.set_code(factory, art.runtime)
    made = []
    for x in (5, 6):
        r = w.call(
            ALICE,
            factory,
            bytes.fromhex(art.method_ids["make(uint256)"]) + encode(["uint256"], [x]),
        )
        assert r.success and len(r.created) == 1 and r.created[0][1] == child.runtime
        addr = r.created[0][0]
        assert r.output[-20:].hex() == addr[2:]
        assert r.logs == [
            (factory, (int.from_bytes(keccak(text="Made(address)"), "big"),), r.output)
        ]
        assert r.storage_diff[(addr, 0)] == (0, x)
        made.append(addr)
    assert made[0] != made[1]


@requires_solc
@pytest.mark.parametrize("backend", BACKENDS)
def test_snapshot_and_revert(backend):
    w = _token(backend)
    tok = w.snapshot()
    w.call(ALICE, TOKEN, TRANSFER + encode(["address", "uint256"], [BOB, 30]))
    w.revert(tok)
    assert w.get_storage(TOKEN, _bal_slot(BOB)) == 0


@requires_pyrevm
@requires_pyevm
def test_backends_agree():
    calls = [
        (ALICE, TRANSFER + encode(["address", "uint256"], [BOB, n]), v)
        for n in (0, 1, 70, 100, 101)
        for v in (0, 1)
    ] + [(BOB, bytes.fromhex("70a08231") + encode(["address"], [ALICE]), 0), (ALICE, b"\x12", 0)]
    worlds = [_token("pyrevm"), _token("pyevm")]
    for caller, data, value in calls:
        a, b = (w.call(caller, TOKEN, data, value) for w in worlds)
        assert (a.success, a.output, a.error, a.logs, a.storage_diff) == (
            b.success,
            b.output,
            b.error,
            b.logs,
            b.storage_diff,
        )


@requires_solc
@requires_pyrevm
@requires_pyevm
def test_backends_see_the_same_block_environment():
    art = compile_fixture("misc/Block.sol", "Block")
    for block in BLOCKS:
        seen = []
        for backend in ("pyrevm", "pyevm"):
            w = make_world(backend, block)
            w.set_code(TOKEN, art.runtime)
            seen.append(
                {
                    sig: w.call(ALICE, TOKEN, bytes.fromhex(sel)).output
                    for sig, sel in art.method_ids.items()
                }
            )
        assert seen[0] == seen[1]
        assert int.from_bytes(seen[0]["limit()"], "big") == block.gas_limit
        assert int.from_bytes(seen[0]["chain()"], "big") == block.chain_id
        assert seen[0]["previous()"] == keccak(text=str(block.number - 1))


# tload(7) is returned after tstore(7, tload(7) + 1)
TRANSIENT = bytes.fromhex("60075c8060010160075d60005260206000f3")


@pytest.mark.parametrize("backend", BACKENDS)
def test_every_call_starts_with_empty_transient_storage(backend):
    w = make_world(backend)
    w.set_code(TOKEN, TRANSIENT)
    assert [int.from_bytes(w.call(ALICE, TOKEN, b"").output, "big") for _ in range(3)] == [0, 0, 0]


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_revert_returns_its_gas_and_a_halt_burns_it(backend):
    w = make_world(backend)
    w.set_code(TOKEN, bytes.fromhex("60006000fd"))  # revert(0, 0)
    assert w.call(ALICE, TOKEN, b"", gas=1_000_000).gas_used < 50_000
    w.set_code(TOKEN, b"\xfe")
    assert w.call(ALICE, TOKEN, b"", gas=1_000_000).gas_used == 1_000_000


@requires_pyevm
def test_pyevm_reads_are_exact_and_coverage_is_recorded():
    w = _token("pyevm", covered=TOKEN, cmplog=True)
    w.set_storage(TOKEN, 12345, 1)  # seeded, never read
    r = w.call(ALICE, TOKEN, TRANSFER + encode(["address", "uint256"], [BOB, 30]))
    assert (TOKEN, 12345) not in r.storage_reads
    assert r.jumpis and all(isinstance(pc, int) and isinstance(t, bool) for pc, t in r.jumpis)
    # the balance check compares the amount with the balance
    assert 30 in r.compared and 100 in r.compared
    # SUB and XOR operands too (solc's `x != c` is often `jumpi(.., sub(x, c))`), in pairs
    w.set_code(TOKEN, bytes.fromhex("6005600903600760091800"))  # sub(9, 5) xor(9, 7) stop
    assert w.call(ALICE, TOKEN, b"").compared == [9, 5, 9, 7]


@requires_pyrevm
def test_pyrevm_reads_include_seeded_slots():
    w = _token("pyrevm")
    w.set_storage(TOKEN, 12345, 1)
    r = w.call(ALICE, TOKEN, TRANSFER + encode(["address", "uint256"], [BOB, 30]))
    assert (TOKEN, 12345) in r.storage_reads


GAS = bytes.fromhex("5a60005260206000f3")  # return gasleft()
CODESIZE = bytes.fromhex("3860005260206000f3")  # return codesize()


@requires_pyevm
def test_gas_cap_scales_with_call_depth():
    w = make_world("pyevm", covered=TOKEN, gas_cap=4_000_000)
    w.set_code(TOKEN, GAS)
    r = w.call(ALICE, TOKEN, b"")
    assert int.from_bytes(r.output, "big") == 4_000_000
    proxy = "0x" + "99" * 20  # forwards gas() to TOKEN, returns its returndata
    w.set_code(proxy, bytes.fromhex("6020600060006000600073" + TOKEN[2:] + "5af160206000f3"))
    r = w.call(ALICE, proxy, b"")
    assert r.success and int.from_bytes(r.output, "big") == 1_000_000


@requires_pyevm
def test_self_code_is_virtualised_for_the_covered_contract_only():
    w = make_world("pyevm", covered=TOKEN, self_code=(1234, b"\x11" * 32))
    w.set_code(TOKEN, CODESIZE)
    other = "0x" + "99" * 20
    w.set_code(other, CODESIZE)
    assert int.from_bytes(w.call(ALICE, TOKEN, b"").output, "big") == 1234
    assert int.from_bytes(w.call(ALICE, other, b"").output, "big") == len(CODESIZE)


@requires_pyrevm
@requires_solc
def test_patched_immutables_equal_a_real_deployment():
    import pyrevm

    art = compile_fixture("misc/Immutables.sol", "Imm")
    evm = pyrevm.EVM(spec_id="Cancun")
    evm.set_balance(ALICE, 10**20)
    addr = evm.deploy(ALICE, art.creation + encode(["uint256"], [1000]))
    onchain = bytes(evm.get_code(addr))[: len(art.runtime)]  # pyrevm pads analysed code
    ids = {name: ast_id for ast_id, name in art.immutable_names.items()}
    assert (
        patch_immutables(
            art.runtime, art.immutable_refs, {ids["owner"]: int(ALICE, 16), ids["cap"]: 1000}
        )
        == onchain
    )


def test_missing_backend_is_reported(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_pyrevm(name, *a, **k):
        if name == "pyrevm":
            raise ImportError("no pyrevm")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_pyrevm)
    with pytest.raises(BackendUnavailable, match="scobelix\\[verify\\]"):
        make_world("pyrevm")

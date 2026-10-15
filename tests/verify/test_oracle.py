"""scobelix.verify.oracle: payability and parameter widths measured on the original."""

from verify_helpers import (
    original_artifact,
    original_runtime,
    requires_pyevm,
    requires_pyrevm,
    requires_solc,
)

from scobelix.verify.abi import specs_from_abi
from scobelix.verify.layout import normalize_layout
from scobelix.verify.oracle import probe_original

pytestmark = requires_solc


def _probe(name, **kw):
    ref = original_artifact(name)
    specs = list(specs_from_abi(ref.abi).values())
    return probe_original(
        original_runtime(name), specs, layout=normalize_layout(ref.storage_layout), **kw
    )


@requires_pyevm
def test_token_is_non_payable_with_exact_widths():
    res = _probe("SimpleToken")
    assert {k: r.payable for k, r in res.items()} == {
        "0x18160ddd": False,
        "0x70a08231": False,
        "0xa9059cbb": False,
    }
    assert res["0xa9059cbb"].checked_bytes == [12, 0]  # address, uint256
    assert res["0x70a08231"].to_dict()["widths"] == ["160-bit (address)"]
    assert res["0x18160ddd"].checked_bytes == []


@requires_pyevm
def test_vault_payability_and_bool_width():
    res = _probe("Vault")
    assert res["0xd0e30db0"].payable is True  # deposit()
    assert all(r.payable is False for k, r in res.items() if k != "0xd0e30db0")
    assert res["0x16c38b3c"].checked_bytes == [31]  # setPaused(bool): only the low byte may be set
    assert res["0xf2fde38b"].checked_bytes == [12]


@requires_pyrevm
def test_pyrevm_measures_payability_only():
    res = _probe("Vault", backend="pyrevm")
    assert res["0xd0e30db0"].payable is True and res["0x2e1a7d4d"].payable is False
    assert all(r.checked_bytes is None for r in res.values())


@requires_pyevm
def test_unreachable_functions_are_reported():
    res = _probe("Vault", tries=1)
    assert any(r.payable is None and "no accepted call" in r.note for r in res.values())

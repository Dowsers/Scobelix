from panoramix.tools.build_local_sigs import compute_selector


def test_compute_selector_matches_well_known_transfer():
    # keccak256("transfer(address,uint256)")[:4] - a widely published constant,
    # used here as a ground truth independent of any solc/subprocess call.
    assert compute_selector("transfer(address,uint256)") == "0xa9059cbb"


def test_compute_selector_matches_well_known_balanceof():
    assert compute_selector("balanceOf(address)") == "0x70a08231"


def test_compute_selector_no_args():
    assert compute_selector("totalSupply()") == "0x18160ddd"

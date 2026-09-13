from scobelix.solgen.event_signatures import KNOWN_EVENT_SIGNATURES


def test_transfer_topic0_matches_well_known_value():
    # 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef is
    # the widely-published ERC20 Transfer event topic0, used here as ground
    # truth independent of the table's own keccak256 computation.
    topic0 = int(
        "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", 16
    )
    assert topic0 in KNOWN_EVENT_SIGNATURES
    name, types, indexed, names = KNOWN_EVENT_SIGNATURES[topic0]
    assert name == "Transfer"
    assert types == ["address", "address", "uint256"]
    assert indexed == [True, True, False]


def test_no_array_typed_events_in_table():
    # solgen deliberately doesn't attempt multi-value ABI decoding of the log
    # data blob, so no entry should need it.
    for name, types, _indexed, _names in KNOWN_EVENT_SIGNATURES.values():
        assert not any(t.endswith("[]") for t in types), name

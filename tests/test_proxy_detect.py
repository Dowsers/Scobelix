from scobelix.utils.proxy_detect import detect_proxy_slots


def test_no_hints_on_empty_input():
    assert detect_proxy_slots([]) == []


def test_no_hints_when_no_known_slot_present():
    parsed_lines = [
        (0, "push1", 0x2A),
        (2, "push1", 0x00),
        (4, "mstore", None),
    ]
    assert detect_proxy_slots(parsed_lines) == []


def test_detects_eip1967_implementation_slot():
    slot = 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
    parsed_lines = [(0, "push32", slot), (33, "sload", None)]

    hints = detect_proxy_slots(parsed_lines)

    assert len(hints) == 1
    assert hints[0]["name"] == "eip1967.proxy.implementation"
    assert hints[0]["slot"] == hex(slot)
    assert hints[0]["line"] == 0


def test_detects_all_known_slots_and_deduplicates():
    impl = 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
    admin = 0xB53127684A568B3173AE13B9F8A6016E243E63B6E8EE1178D6A717850B5D6103
    beacon = 0xA3F0AD74E5423AEBFD80D3EF4346578335A9A72AEAEE59FF6CB3582B35133D50
    uups = 0xC5F16F0FCC639FA48A6947836D9850F504798523BF8C9A3A87D5876CF622BCF7

    parsed_lines = [
        (0, "push32", impl),
        (33, "push32", impl),  # duplicate, should not appear twice
        (66, "push32", admin),
        (99, "push32", beacon),
        (132, "push32", uups),
    ]

    hints = detect_proxy_slots(parsed_lines)
    names = {h["name"] for h in hints}

    assert names == {
        "eip1967.proxy.implementation",
        "eip1967.proxy.admin",
        "eip1967.proxy.beacon",
        "PROXIABLE",
    }
    assert len(hints) == 4


def test_ignores_non_push_ops_and_non_int_params():
    parsed_lines = [
        (0, "sload", None),
        (1, "push32", "not-an-int"),
    ]
    assert detect_proxy_slots(parsed_lines) == []

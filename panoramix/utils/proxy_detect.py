"""
Best-effort detection of well-known upgradeable-proxy storage slot patterns
(EIP-1967, EIP-1822/UUPS) in decompiled bytecode.

This does NOT resolve the proxy's actual implementation address (that would
require an on-chain read) or rewrite the symbolic trace - it only flags, from
the raw PUSH32 constants present in the bytecode, that a given storage slot
is very likely used for one of these known proxy patterns, so callers (CLI
output, solgen, reports) can surface a human-readable hint instead of an
opaque 32-byte constant such as
0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc.

Values below are `bytes32(uint256(keccak256(<name>)) - 1)`, except PROXIABLE
(EIP-1822) which is the raw hash with no "-1" offset, per each EIP's spec -
derived directly from those formulas rather than retyped from memory.
"""

KNOWN_PROXY_SLOTS = {
    0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC: (
        "eip1967.proxy.implementation",
        "EIP-1967 implementation slot",
    ),
    0xB53127684A568B3173AE13B9F8A6016E243E63B6E8EE1178D6A717850B5D6103: (
        "eip1967.proxy.admin",
        "EIP-1967 admin slot",
    ),
    0xA3F0AD74E5423AEBFD80D3EF4346578335A9A72AEAEE59FF6CB3582B35133D50: (
        "eip1967.proxy.beacon",
        "EIP-1967 beacon slot",
    ),
    0xC5F16F0FCC639FA48A6947836D9850F504798523BF8C9A3A87D5876CF622BCF7: (
        "PROXIABLE",
        "EIP-1822 (UUPS) proxiable UUID slot",
    ),
}


def detect_proxy_slots(parsed_lines):
    """
    parsed_lines: iterable of (line_no, op, param) as produced by
    Loader.load_binary() (panoramix/loader.py, self.parsed_lines). Scans for
    pushN immediates matching a known proxy slot constant and returns a list
    of {"line", "slot", "name", "description"} hints, deduplicated by slot.

    Best-effort only: a contract can be a proxy without using one of these
    standardized slots (custom storage layout), and a match here only means
    this exact 32-byte constant appears in the bytecode - it is not a proof
    the contract behaves as a proxy at runtime.
    """
    seen = set()
    hints = []
    for line_no, op, param in parsed_lines:
        if not isinstance(op, str) or not op.startswith("push"):
            continue
        if not isinstance(param, int) or param in seen:
            continue
        match = KNOWN_PROXY_SLOTS.get(param)
        if match is None:
            continue
        seen.add(param)
        name, description = match
        hints.append(
            {
                "line": line_no,
                "slot": hex(param),
                "name": name,
                "description": description,
            }
        )
    return hints

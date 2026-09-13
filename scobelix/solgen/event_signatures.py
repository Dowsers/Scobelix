"""
A small table of well-known event signatures (topic0 -> name/types), used by
solgen to reconstruct real `emit EventName(...)` statements instead of a
generic placeholder, for the handful of events common enough across real
contracts to be worth hardcoding (mirrors the same idea as
scobelix.utils.supplement.LOCAL_SIGS for function selectors - except
fetch_sig() there is hardcoded to format hashes as 4-byte selectors
(`"{:#010x}".format(...)`), so it cannot resolve a full 32-byte event topic;
this is a separate, dedicated table rather than a misuse of that one).

Panoramix's own TODO.md already flags event/log ABI resolution as an
unaddressed gap ("re-add support for log ABI") - this covers the common
cases without attempting a general solution (arbitrary custom events still
fall back to solgen's generic placeholder).

Each entry: topic0 (int, keccak256(signature)) -> (name, types, indexed,
param_names). `indexed` and `types`/`param_names` are parallel lists in
event-declaration order. Only scalar types are included on purpose - array
types (e.g. ERC1155's TransferBatch) need multi-value ABI decoding of the
log data blob that solgen does not attempt, so they're left out rather than
resolved incorrectly.
"""

from web3 import Web3


def _topic0(signature: str) -> int:
    return int.from_bytes(Web3.keccak(text=signature), "big")


_EVENTS = [
    ("Transfer", ["address", "address", "uint256"], [True, True, False], ["from", "to", "value"]),
    (
        "Approval",
        ["address", "address", "uint256"],
        [True, True, False],
        ["owner", "spender", "value"],
    ),
    (
        "ApprovalForAll",
        ["address", "address", "bool"],
        [True, True, False],
        ["owner", "operator", "approved"],
    ),
    (
        "OwnershipTransferred",
        ["address", "address"],
        [True, True],
        ["previousOwner", "newOwner"],
    ),
    ("Upgraded", ["address"], [True], ["implementation"]),
    ("AdminChanged", ["address", "address"], [False, False], ["previousAdmin", "newAdmin"]),
    ("BeaconUpgraded", ["address"], [True], ["beacon"]),
    ("Paused", ["address"], [False], ["account"]),
    ("Unpaused", ["address"], [False], ["account"]),
    ("Deposit", ["address", "uint256"], [True, False], ["dst", "wad"]),
    ("Withdrawal", ["address", "uint256"], [True, False], ["src", "wad"]),
]

KNOWN_EVENT_SIGNATURES = {}
for _name, _types, _indexed, _param_names in _EVENTS:
    _sig = f"{_name}({','.join(_types)})"
    KNOWN_EVENT_SIGNATURES[_topic0(_sig)] = (_name, _types, _indexed, _param_names)

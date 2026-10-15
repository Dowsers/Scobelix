"""
Environment mocks for differential execution, with their Solidity source.

EIP-3607 forbids transactions from accounts with code, so a contract caller
is modelled as EOA -> caller.fwd(target, data, reentry) -> target.  The
callers differ in how they react to ETH and callbacks from the target:

  AcceptingCaller   accepts ETH; answers any callback with its selector (the
                    ERC-721 / ERC-1155 receiver convention)
  RejectingCaller   reverts (empty data) on ETH and on every callback
  ReentrantCaller   on the first ETH transfer or callback from the target,
                    calls it back once with `reentry` and logs the outcome

ReturnStub is a generic external contract (ERC20-like): plain ETH transfers
are accepted, and every call with calldata is answered according to its
slot 0 - 0: the word in slot 1 (1 = true), 1: 0 (false), 2: no returndata,
3: revert, 4: keccak256(calldata) & slot 1 (an answer that depends on the
arguments), 5: revert with the word in slot 1 as its data.

Every call carrying calldata that reaches a mock is recorded by the Recorder
(RECORDER, never called by the contract under test) as the log
`Received(address indexed at, address from, uint256 value, bytes data)`
(RECEIVED_TOPIC): `at` is the mock, `from` / `value` / `data` the call it
received.  The arguments, targets and order of the external calls a contract
makes are then part of the compared logs on every backend, not only of
py-evm's call tree.  The record is a gas-capped call: in a static context its
log fails and nothing is recorded (there, the arguments of a view call reach
the comparison through mode 4's answer).  When the contract under test
delegatecalls a mock, the mock's code records from the contract's own account
(`at` is the contract) and never calls the contract back.  Recording does
not depend on the gas left (that would make two builds of a contract differ),
so a mock given less than about 12k gas for a call with calldata fails - the
record is a cold call - on both sides alike.

The runtimes below are `MOCKS_SOLIDITY` compiled with solc 0.8.19 (optimizer
on, 200 runs); a test recompiles the source and checks they still match.
"""

from __future__ import annotations

import dataclasses
from typing import Dict

__all__ = [
    "ACCEPTING_CALLER",
    "CALLERS",
    "FWD_SELECTOR",
    "MOCKS",
    "MOCKS_SOLC_VERSION",
    "MOCKS_SOLIDITY",
    "RECEIVED_TOPIC",
    "RECORDER",
    "REENTRANT_CALLER",
    "REJECTING_CALLER",
    "RETURN_STUB",
    "Mock",
    "encode_fwd",
]

MOCKS_SOLC_VERSION = "0.8.19"

MOCKS_SOLIDITY = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Environment of the contract under test during differential execution.
// EIP-3607 forbids transactions from accounts with code, so a contract caller
// is modelled as EOA -> caller.fwd(target, data, reentry) -> target.
//
// Every call carrying calldata that reaches a mock (a callback, a token call)
// is recorded by the Recorder as a log, so that the arguments, the target and
// the order of external calls are observable even without a call tracer.  The
// record is a gas-capped call to the Recorder, never to the target: in a
// static context its log fails and nothing is recorded (there, the answer,
// which may depend on the calldata, is what the caller observes), and when
// the target delegatecalls a mock, the mock's code records from the target's
// own account without calling the target back.

address constant RECORDER = 0x7eC07ec07Ec07ec07EC07EC07eC07EC07ec07Ec0;

function record(bytes calldata data) {
    (bool recorded, ) = RECORDER.call{gas: 6000 + 16 * data.length}(
        abi.encode(msg.sender, msg.value, data)
    );
    recorded;
}

// Logs every call it receives: Received(the calling account, then the call's data,
// which the mocks encode as (from, value, data)).
contract Recorder {
    event Received(address indexed at, address from, uint256 value, bytes data);

    fallback() external {
        bytes32 topic = Received.selector;
        assembly {
            calldatacopy(0, 0, calldatasize())
            log2(0, calldatasize(), topic, caller())
        }
    }
}

// Accepts ETH and answers any call with its own selector (ERC-721/1155 receiver convention).
contract AcceptingCaller {
    function fwd(address target, bytes calldata data, bytes calldata)
        external
        payable
        returns (bool ok, bytes memory ret)
    {
        (ok, ret) = target.call{value: msg.value}(data);
    }

    receive() external payable {}

    fallback(bytes calldata data) external payable returns (bytes memory) {
        record(data);
        return abi.encode(msg.sig);
    }
}

// Rejects ETH and every callback (no receive / fallback: empty revert).
contract RejectingCaller {
    function fwd(address target, bytes calldata data, bytes calldata)
        external
        payable
        returns (bool ok, bytes memory ret)
    {
        (ok, ret) = target.call{value: msg.value}(data);
    }
}

// On the first ETH transfer or callback from the target during fwd, calls the
// target back once with `reentry`, and logs the outcome.
contract ReentrantCaller {
    address private target;
    bool private armed;
    bytes private reentry;

    event Reentered(bool ok, bytes ret);

    function fwd(address to, bytes calldata data, bytes calldata again)
        external
        payable
        returns (bool ok, bytes memory ret)
    {
        target = to;
        armed = true;
        reentry = again;
        (ok, ret) = to.call{value: msg.value}(data);
        armed = false;
    }

    receive() external payable {
        _reenter();
    }

    fallback(bytes calldata data) external payable returns (bytes memory) {
        record(data);
        _reenter();
        return abi.encode(msg.sig);
    }

    function _reenter() private {
        if (armed && msg.sender == target) {
            armed = false;
            (bool ok, bytes memory ret) = target.call(reentry);
            emit Reentered(ok, ret);
        }
    }
}

// Generic external contract (ERC20-like).  Plain ETH transfers are accepted (no
// storage access: a 2300-gas stipend suffices); a call with calldata is
// recorded, then answered according to slot 0:
//   0 -> the word in slot 1 (1 = true)   1 -> 0 (false)   2 -> no returndata
//   3 -> revert (no data)                4 -> keccak256(calldata) & slot 1
//   5 -> revert with the word in slot 1 as its data
// Mode 4 makes the answer to a static call depend on its arguments; mode 5
// tells a caller that bubbles revert data up from one that does not.
contract ReturnStub {
    uint256 private mode;
    uint256 private value;

    receive() external payable {}

    fallback(bytes calldata data) external payable returns (bytes memory) {
        record(data);
        uint256 m = mode;
        if (m == 3) revert();
        if (m == 5) {
            uint256 word = value;
            assembly {
                mstore(0, word)
                revert(0, 32)
            }
        }
        if (m == 2) return "";
        if (m == 4) return abi.encode(uint256(keccak256(data)) & value);
        return abi.encode(m == 1 ? 0 : value);
    }
}
"""


@dataclasses.dataclass(frozen=True)
class Mock:
    name: str
    address: str
    runtime: bytes


ACCEPTING_CALLER = "0x" + "7e1a" * 10
REJECTING_CALLER = "0x" + "7e1b" * 10
REENTRANT_CALLER = "0x" + "7e1c" * 10
RETURN_STUB = "0x" + "57ab" * 10
RECORDER = "0x" + "7ec0" * 10
CALLERS = (ACCEPTING_CALLER, REJECTING_CALLER, REENTRANT_CALLER)

FWD_SELECTOR = bytes.fromhex("457fa049")  # fwd(address,bytes,bytes)
# topic0 of Received(address,address,uint256,bytes): one log per recorded call
RECEIVED_TOPIC = 0x00D9411AE77B2BACABE5CBE62A2ABDBEB78992A0182C6F3C83E0029C7615D6B6

MOCKS: Dict[str, Mock] = {
    "Recorder": Mock(
        "Recorder",
        RECORDER,
        bytes.fromhex(
            "6080604052348015600f57600080fd5b507ed9411ae77b2bacabe5cbe62a2abdbeb78992a0182c6f"
            "3c83e0029c7615d6b636600080373381366000a200fea2646970667358221220b86cde71a9633a88"
            "c3726a926be42b684fa59b4c39746dc4ef6174e55ec51fc464736f6c63430008130033"
        ),
    ),
    "AcceptingCaller": Mock(
        "AcceptingCaller",
        ACCEPTING_CALLER,
        bytes.fromhex(
            "6080604052600436106100225760003560e01c8063457fa0491461006b57610029565b3661002957"
            "005b60003660606100388383610095565b604080516001600160e01b031960003516602082015201"
            "6040516020818303038152906040529050915050805190602001f35b61007e6100793660046101f8"
            "565b61013f565b60405161008c9291906102ab565b60405180910390f35b6000737ec07ec07ec07e"
            "c07ec07ec07ec07ec07ec07ec06100b78360106102fd565b6100c39061177061031a565b33348686"
            "6040516020016100da949392919061032d565b60408051601f19818403018152908290526100f491"
            "610375565b60006040518083038160008787f1925050503d8060008114610132576040519150601f"
            "19603f3d011682016040523d82523d6000602084013e610137565b606091505b505050505050565b"
            "60006060866001600160a01b031634878760405161015e929190610391565b600060405180830381"
            "85875af1925050503d806000811461019b576040519150601f19603f3d011682016040523d82523d"
            "6000602084013e6101a0565b606091505b50909890975095505050505050565b60008083601f8401"
            "126101c157600080fd5b50813567ffffffffffffffff8111156101d957600080fd5b602083019150"
            "8360208285010111156101f157600080fd5b9250929050565b600080600080600060608688031215"
            "61021057600080fd5b85356001600160a01b038116811461022757600080fd5b9450602086013567"
            "ffffffffffffffff8082111561024457600080fd5b61025089838a016101af565b90965094506040"
            "88013591508082111561026957600080fd5b50610276888289016101af565b969995985093965092"
            "949392505050565b60005b838110156102a257818101518382015260200161028a565b5050600091"
            "0152565b821515815260406020820152600082518060408401526102d28160608501602087016102"
            "87565b601f01601f1916919091016060019392505050565b634e487b7160e01b6000526011600452"
            "60246000fd5b8082028115828204841417610314576103146102e7565b92915050565b8082018082"
            "1115610314576103146102e7565b6001600160a01b03851681526020810184905260606040820181"
            "90528101829052818360808301376000818301608090810191909152601f909201601f1916010193"
            "92505050565b60008251610387818460208701610287565b9190910192915050565b818382376000"
            "910190815291905056fea264697066735822122017dce0b30d3a24cbad3570683a126019b85612be"
            "3ab83e0ce3f16e1ba2a6b95164736f6c63430008130033"
        ),
    ),
    "RejectingCaller": Mock(
        "RejectingCaller",
        REJECTING_CALLER,
        bytes.fromhex(
            "60806040526004361061001e5760003560e01c8063457fa04914610023575b600080fd5b61003661"
            "0031366004610106565b61004d565b604051610044929190610195565b60405180910390f35b6000"
            "6060866001600160a01b031634878760405161006c9291906101ed565b6000604051808303818587"
            "5af1925050503d80600081146100a9576040519150601f19603f3d011682016040523d82523d6000"
            "602084013e6100ae565b606091505b50909890975095505050505050565b60008083601f84011261"
            "00cf57600080fd5b50813567ffffffffffffffff8111156100e757600080fd5b6020830191508360"
            "208285010111156100ff57600080fd5b9250929050565b6000806000806000606086880312156101"
            "1e57600080fd5b85356001600160a01b038116811461013557600080fd5b9450602086013567ffff"
            "ffffffffffff8082111561015257600080fd5b61015e89838a016100bd565b909650945060408801"
            "3591508082111561017757600080fd5b50610184888289016100bd565b9699959850939650929493"
            "92505050565b821515815260006020604081840152835180604085015260005b818110156101cb57"
            "8581018301518582016060015282016101af565b506000606082860101526060601f19601f830116"
            "850101925050509392505050565b818382376000910190815291905056fea2646970667358221220"
            "cc0a7de532bc27c7e6928a0f67d06ad5c1272df10b15fe781678336a7cffb1f364736f6c63430008"
            "130033"
        ),
    ),
    "ReentrantCaller": Mock(
        "ReentrantCaller",
        REENTRANT_CALLER,
        bytes.fromhex(
            "6080604052600436106100225760003560e01c8063457fa0491461007b57610031565b3661003157"
            "61002f6100a5565b005b6000366060610040838361017b565b6100486100a5565b60408051600160"
            "0160e01b031960003516602082015201604051602081830303815290604052905091505080519060"
            "2001f35b61008e610089366004610318565b610225565b60405161009c9291906103cb565b604051"
            "80910390f35b600054600160a01b900460ff1680156100c857506000546001600160a01b03163314"
            "5b15610179576000805460ff60a01b198116825560405182916001600160a01b0316906100f69060"
            "0190610441565b6000604051808303816000865af19150503d806000811461013357604051915060"
            "1f19603f3d011682016040523d82523d6000602084013e610138565b606091505b50915091507fde"
            "a04a62bcd851e860379bb6a89860dbf3f534ef70263ff5d4942d029160581a828260405161016e92"
            "91906103cb565b60405180910390a150505b565b6000737ec07ec07ec07ec07ec07ec07ec07ec07e"
            "c07ec061019d8360106104cd565b6101a9906117706104ea565b333486866040516020016101c094"
            "939291906104fd565b60408051601f19818403018152908290526101da91610545565b6000604051"
            "8083038160008787f1925050503d8060008114610218576040519150601f19603f3d011682016040"
            "523d82523d6000602084013e61021d565b606091505b505050505050565b600080546001600160a8"
            "1b0319166001600160a01b03871617600160a01b178155606060016102558486836105c2565b5086"
            "6001600160a01b0316348787604051610271929190610683565b60006040518083038185875af192"
            "5050503d80600081146102ae576040519150601f19603f3d011682016040523d82523d6000602084"
            "013e6102b3565b606091505b506000805460ff60a01b19169055909890975095505050505050565b"
            "60008083601f8401126102e157600080fd5b50813567ffffffffffffffff8111156102f957600080"
            "fd5b60208301915083602082850101111561031157600080fd5b9250929050565b60008060008060"
            "006060868803121561033057600080fd5b85356001600160a01b038116811461034757600080fd5b"
            "9450602086013567ffffffffffffffff8082111561036457600080fd5b61037089838a016102cf56"
            "5b9096509450604088013591508082111561038957600080fd5b50610396888289016102cf565b96"
            "9995985093965092949392505050565b60005b838110156103c25781810151838201526020016103"
            "aa565b50506000910152565b821515815260406020820152600082518060408401526103f2816060"
            "8501602087016103a7565b601f01601f1916919091016060019392505050565b600181811c908216"
            "8061041b57607f821691505b60208210810361043b57634e487b7160e01b60005260226004526024"
            "6000fd5b50919050565b600080835461044f81610407565b60018281168015610467576001811461"
            "047c576104ab565b60ff19841687528215158302870194506104ab565b8760005260208060002060"
            "005b858110156104a25781548a820152908401908201610489565b50505082870194505b50929695"
            "505050505050565b634e487b7160e01b600052601160045260246000fd5b80820281158282048414"
            "176104e4576104e46104b7565b92915050565b808201808211156104e4576104e46104b7565b6001"
            "600160a01b0385168152602081018490526060604082018190528101829052818360808301376000"
            "818301608090810191909152601f909201601f191601019392505050565b60008251610557818460"
            "2087016103a7565b9190910192915050565b634e487b7160e01b600052604160045260246000fd5b"
            "601f8211156105bd57600081815260208120601f850160051c8101602086101561059e5750805b60"
            "1f850160051c820191505b8181101561021d578281556001016105aa565b505050565b67ffffffff"
            "ffffffff8311156105da576105da610561565b6105ee836105e88354610407565b83610577565b60"
            "00601f841160018114610622576000851561060a5750838201355b600019600387901b1c19166001"
            "86901b17835561067c565b600083815260209020601f19861690835b828110156106535786850135"
            "825560209485019460019092019101610633565b50868210156106705760001960f88860031b161c"
            "19848701351681555b505060018560011b0183555b5050505050565b818382376000910190815291"
            "905056fea2646970667358221220a17519594947c46277fcc8e16d3dd4c5ebeb8931c3397c080c7d"
            "d3391cd9bbb364736f6c63430008130033"
        ),
    ),
    "ReturnStub": Mock(
        "ReturnStub",
        RETURN_STUB,
        bytes.fromhex(
            "60806040523661000b57005b600036606061001a83836100e7565b600054600381900361002b5760"
            "0080fd5b80600503610040576001546000818152602090fd5b8060020361005e5750506040805160"
            "208101909152600081526100dc565b806004036100a4576001548484604051610079929190610191"
            "565b6040805191829003822092909216602082015201604051602081830303815290604052915050"
            "6100dc565b806001146100b4576001546100b7565b60005b6040516020016100c991815260200190"
            "565b6040516020818303038152906040529150505b915050805190602001f35b6000737ec07ec07e"
            "c07ec07ec07ec07ec07ec07ec07ec06101098360106101b7565b610115906117706101d4565b3334"
            "868660405160200161012c94939291906101e7565b60408051601f19818403018152908290526101"
            "469161022f565b60006040518083038160008787f1925050503d8060008114610184576040519150"
            "601f19603f3d011682016040523d82523d6000602084013e610189565b606091505b505050505050"
            "565b8183823760009101908152919050565b634e487b7160e01b600052601160045260246000fd5b"
            "80820281158282048414176101ce576101ce6101a1565b92915050565b808201808211156101ce57"
            "6101ce6101a1565b6001600160a01b03851681526020810184905260606040820181905281018290"
            "52818360808301376000818301608090810191909152601f909201601f191601019392505050565b"
            "6000825160005b818110156102505760208186018101518583015201610236565b50600092019182"
            "525091905056fea2646970667358221220b2cd1d6bd75c7a1e6df7107a56e484ce1d095a766a848a"
            "4e5656f1e3cf06a6e564736f6c63430008130033"
        ),
    ),
}


def _padded(blob: bytes) -> bytes:
    return len(blob).to_bytes(32, "big") + blob + bytes(-len(blob) % 32)


def encode_fwd(target: str, data: bytes, reentry: bytes = b"") -> bytes:
    """Calldata of caller.fwd(target, data, reentry) (the ABI encoding, written out: it is hot)."""
    second = 96 + 32 + len(data) + (-len(data) % 32)
    return (
        FWD_SELECTOR
        + bytes(12)
        + bytes.fromhex(target[2:])
        + (96).to_bytes(32, "big")
        + second.to_bytes(32, "big")
        + _padded(data)
        + _padded(reentry)
    )

// SPDX-License-Identifier: MIT
// Functions behind the usual guards, and fallbacks that reach code through storage: what a small
// fuzzing budget only passes when the guards direct the inputs.
pragma solidity 0.8.19;

interface IOracle {
    function latestAnswer() external view returns (int256);
}

interface IBeacon {
    function implementation() external view returns (address);
}

contract Guarded {
    address public owner; // slot 0, packed with `paused`
    bool public paused;
    mapping(address => uint256) public balanceOf; // slot 1
    mapping(uint256 => address) public ownerOf; // slot 2
    IOracle public oracle; // slot 3
    uint256 public total; // slot 4
    mapping(address => bool) public listed; // slot 5

    function setTotal(uint256 v) external {
        require(msg.sender == owner, "owner");
        require(!paused, "paused");
        total = v;
    }

    function withdraw(uint256 amount) external {
        require(listed[msg.sender], "not listed");
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
    }

    function burn(uint256 id) external {
        require(ownerOf[id] == msg.sender, "not the owner");
        delete ownerOf[id];
    }

    function price() external view returns (uint256) {
        int256 answer = oracle.latestAnswer();
        require(answer > 0, "no price");
        return uint256(answer);
    }

    // decoded before the owner check: a guide in the string's offset word would break the call
    function label(uint64 id, string calldata text) external returns (uint256) {
        require(msg.sender == owner, "owner");
        return bytes(text).length + id;
    }
}

// The implementation comes from a beacon held in the ERC-1967 beacon slot.
contract BeaconProxy {
    bytes32 private constant BEACON =
        0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    fallback() external payable {
        address beacon;
        assembly {
            beacon := sload(BEACON)
        }
        address impl = IBeacon(beacon).implementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}

// The implementation of each selector comes from a mapping keyed by msg.sig.
contract Facets {
    mapping(bytes4 => address) public facetOf;

    fallback() external payable {
        address facet = facetOf[msg.sig];
        require(facet != address(0), "no facet");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}

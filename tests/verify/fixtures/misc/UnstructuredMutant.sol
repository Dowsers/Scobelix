// SPDX-License-Identifier: MIT
// Unstructured mutant: the owner-only setter stores another value.
pragma solidity 0.8.19;

contract Unstructured {
    bytes32 private constant OWNER_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    uint256 public value;

    function set(uint256 v) external {
        address o;
        bytes32 s = OWNER_SLOT;
        assembly {
            o := sload(s)
        }
        require(msg.sender == o, "owner");
        value = v + 2;
    }
}

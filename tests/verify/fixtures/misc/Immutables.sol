// SPDX-License-Identifier: MIT
// Immutables: the deployed code holds their values where the compiled code has zeros.
pragma solidity 0.8.19;

contract Imm {
    address public immutable owner;
    uint256 public immutable cap;

    constructor(uint256 c) {
        owner = msg.sender;
        cap = c;
    }

    function clamp(uint256 x) external view returns (uint256) {
        require(msg.sender == owner, "not owner");
        return x < cap ? x : cap;
    }
}

library Lib {
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }
}

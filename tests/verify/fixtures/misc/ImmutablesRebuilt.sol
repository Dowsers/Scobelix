// SPDX-License-Identifier: MIT
// Imm rebuilt with the clamp written another way: the code no longer lines up with the original's.
pragma solidity 0.8.19;

contract Imm {
    address public immutable owner;
    uint256 public immutable cap;

    constructor(uint256 c) {
        owner = msg.sender;
        cap = c;
    }

    function clamp(uint256 x) external view returns (uint256) {
        if (msg.sender != owner) revert("not owner");
        if (x >= cap) return cap;
        return x;
    }
}

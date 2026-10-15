// SPDX-License-Identifier: MIT
// A contract whose function names the rebuilt source cannot know.
pragma solidity 0.8.19;

contract Routed {
    uint256 public total;

    function accumulate(uint256 x) external returns (uint256) {
        total += x;
        return total;
    }
}

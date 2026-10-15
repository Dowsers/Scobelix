// SPDX-License-Identifier: MIT
// SimpleToken mutant: the amount is a uint128 (another selector).
pragma solidity 0.8.19;

contract NarrowParam {
    mapping(address => uint256) public balanceOf; // slot 0
    uint256 public totalSupply; // slot 1

    function transfer(address arg0, uint128 arg1) external returns (bool) {
        if (balanceOf[msg.sender] < arg1) revert("insufficient balance");
        balanceOf[msg.sender] -= arg1;
        balanceOf[arg0] += arg1;
        return true;
    }
}

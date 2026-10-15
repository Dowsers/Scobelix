// SPDX-License-Identifier: MIT
// SimpleToken mutant: a custom error instead of Error(string).
pragma solidity 0.8.19;

contract CustomError {
    error InsufficientBalance();

    mapping(address => uint256) public balanceOf; // slot 0
    uint256 public totalSupply; // slot 1

    function transfer(address arg0, uint256 arg1) external returns (bool) {
        if (balanceOf[msg.sender] < arg1) revert InsufficientBalance();
        balanceOf[msg.sender] -= arg1;
        balanceOf[arg0] += arg1;
        return true;
    }
}

// SPDX-License-Identifier: MIT
// SimpleToken mutant: <= instead of < in the balance check.
pragma solidity 0.8.19;

contract OffByOne {
    mapping(address => uint256) public balanceOf; // slot 0
    uint256 public totalSupply; // slot 1

    function transfer(address arg0, uint256 arg1) external returns (bool) {
        if (balanceOf[msg.sender] <= arg1) revert("insufficient balance");
        balanceOf[msg.sender] -= arg1;
        balanceOf[arg0] += arg1;
        return true;
    }
}

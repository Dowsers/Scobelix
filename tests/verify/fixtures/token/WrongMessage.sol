// SPDX-License-Identifier: MIT
// SimpleToken mutant: another revert string.
pragma solidity 0.8.19;

contract WrongMessage {
    mapping(address => uint256) public balanceOf; // slot 0
    uint256 public totalSupply; // slot 1

    function transfer(address arg0, uint256 arg1) external returns (bool) {
        if (balanceOf[msg.sender] < arg1) revert("insufficient funds");
        balanceOf[msg.sender] -= arg1;
        balanceOf[arg0] += arg1;
        return true;
    }
}

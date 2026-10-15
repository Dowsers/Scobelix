// SPDX-License-Identifier: MIT
// SimpleToken mutant: transfer accepts ETH.
pragma solidity 0.8.19;

contract PayableTransfer {
    mapping(address => uint256) public balanceOf; // slot 0
    uint256 public totalSupply; // slot 1

    function transfer(address arg0, uint256 arg1) external payable returns (bool) {
        if (balanceOf[msg.sender] < arg1) revert("insufficient balance");
        balanceOf[msg.sender] -= arg1;
        balanceOf[arg0] += arg1;
        return true;
    }
}

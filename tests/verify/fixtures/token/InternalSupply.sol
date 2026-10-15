// SPDX-License-Identifier: MIT
// SimpleToken mutant: totalSupply has no getter.
pragma solidity 0.8.19;

contract InternalSupply {
    mapping(address => uint256) public balanceOf; // slot 0
    uint256 internal totalSupply; // slot 1

    function transfer(address arg0, uint256 arg1) external returns (bool) {
        if (balanceOf[msg.sender] < arg1) revert("insufficient balance");
        balanceOf[msg.sender] -= arg1;
        balanceOf[arg0] += arg1;
        return true;
    }
}

// SPDX-License-Identifier: MIT
// SimpleToken mutant: the credit of the receiver wraps around instead of reverting on overflow.
pragma solidity 0.8.19;

contract UncheckedAdd {
    mapping(address => uint256) public balanceOf; // slot 0
    uint256 public totalSupply; // slot 1

    function transfer(address arg0, uint256 arg1) external returns (bool) {
        if (balanceOf[msg.sender] < arg1) revert("insufficient balance");
        balanceOf[msg.sender] -= arg1;
        unchecked {
            balanceOf[arg0] += arg1;
        }
        return true;
    }
}

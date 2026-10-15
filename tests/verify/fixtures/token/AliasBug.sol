// SPDX-License-Identifier: MIT
// SimpleToken mutant: the receiver balance is read before the debit (wrong when arg0 == msg.sender).
pragma solidity 0.8.19;

contract AliasBug {
    mapping(address => uint256) public balanceOf; // slot 0
    uint256 public totalSupply; // slot 1

    function transfer(address arg0, uint256 arg1) external returns (bool) {
        uint256 fromBal = balanceOf[msg.sender];
        uint256 toBal = balanceOf[arg0];
        if (fromBal < arg1) revert("insufficient balance");
        balanceOf[msg.sender] = fromBal - arg1;
        balanceOf[arg0] = toBal + arg1;
        return true;
    }
}

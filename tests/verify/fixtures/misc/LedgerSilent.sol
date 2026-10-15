// SPDX-License-Identifier: MIT
// Ledger mutant: debit() never emits Large.
pragma solidity 0.8.19;

contract Ledger {
    mapping(address => uint256) public balance;
    address[] public entries;

    event Credit(address indexed who, uint256 amount);
    event Large(address indexed who, uint256 amount);

    function credit(address who, uint256 amount) external {
        balance[who] += amount;
        entries.push(who);
        emit Credit(who, amount);
    }

    function debit(uint256 amount) external {
        balance[msg.sender] -= amount;

    }
}

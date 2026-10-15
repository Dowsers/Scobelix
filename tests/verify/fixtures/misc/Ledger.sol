// SPDX-License-Identifier: MIT
// Events, a constant threshold and a dynamic array of entries.
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
        if (amount > 1000) emit Large(msg.sender, amount);
    }
}

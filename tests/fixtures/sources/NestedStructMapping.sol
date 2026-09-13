// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract NestedStructMapping {
    struct Account {
        uint128 balance;
        uint64 lastUpdate;
        bool frozen;
    }

    mapping(address => Account) public accounts;
    mapping(address => mapping(address => uint256)) public allowances;

    function deposit(uint128 amount) external {
        Account storage acc = accounts[msg.sender];
        require(!acc.frozen, "frozen");
        acc.balance += amount;
        acc.lastUpdate = uint64(block.timestamp);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowances[from][msg.sender];
        require(allowed >= amount, "not allowed");
        Account storage fromAcc = accounts[from];
        Account storage toAcc = accounts[to];
        require(fromAcc.balance >= amount, "insufficient");
        fromAcc.balance -= uint128(amount);
        toAcc.balance += uint128(amount);
        allowances[from][msg.sender] = allowed - amount;
        return true;
    }
}

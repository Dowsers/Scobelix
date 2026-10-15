// SPDX-License-Identifier: MIT
// Same behaviour as SimpleToken, written differently: explicit getters, a cached local, a named return.
pragma solidity ^0.8.0;

contract Restyled {
    mapping(address => uint256) internal _balances; // slot 0
    uint256 internal _supply; // slot 1

    function totalSupply() external view returns (uint256) {
        return _supply;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 amount) external returns (bool ok) {
        uint256 bal = _balances[msg.sender];
        require(bal >= amount, "insufficient balance");
        _balances[msg.sender] = bal - amount;
        _balances[to] = _balances[to] + amount; // re-read: correct when to == msg.sender
        ok = true;
    }
}

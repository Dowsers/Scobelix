// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract EventsEmitter {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Ping(uint256 value);

    function transfer(address to, uint256 amount) external returns (bool) {
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function ping(uint256 value) external {
        emit Ping(value);
    }
}

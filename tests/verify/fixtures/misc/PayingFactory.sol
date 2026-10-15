// SPDX-License-Identifier: MIT
// A funded CREATE2 child that later calls look at: recompiled children get other addresses.
pragma solidity 0.8.19;

contract Child {
    uint256 public v;

    constructor(uint256 x) payable {
        v = x;
    }
}

contract PayingFactory {
    address public last;

    function make2(uint256 x, bytes32 salt) external payable returns (address c) {
        c = address(new Child{salt: salt, value: msg.value}(x));
        last = c;
    }

    function lastBalance() external view returns (uint256) {
        return last.balance;
    }
}

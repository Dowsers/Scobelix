// SPDX-License-Identifier: MIT
// Factory mutant: the child stores x + 1.
pragma solidity ^0.8.19;

contract Child {
    uint256 public v;

    constructor(uint256 x) {
        v = x + 1;
    }
}

contract Factory {
    event Made(address c);

    function make(uint256 x) external returns (address c) {
        c = address(new Child(x));
        emit Made(c);
    }

    function make2(uint256 x, bytes32 salt) external returns (address c) {
        c = address(new Child{salt: salt}(x));
        emit Made(c);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;
contract R1Combined {
    uint32 public a;
    uint32 public b;
    address public who;
    function f(uint32 x) external { a = x; who = msg.sender; }
    function g(uint32 x, uint32 y) external { a = x; b = y; }
}

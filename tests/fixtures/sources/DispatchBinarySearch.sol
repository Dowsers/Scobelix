// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Dispatcher fixture: enough functions for the optimizer to split the
// selector comparisons into a binary search. Every body writes its own
// marker constant.
contract DispatchBinarySearch {
    uint256 public s;

    function f01() external { s = 0x5eed0001; }
    function f02() external { s = 0x5eed0002; }
    function f03() external { s = 0x5eed0003; }
    function f04() external { s = 0x5eed0004; }
    function f05() external { s = 0x5eed0005; }
    function f06() external { s = 0x5eed0006; }
    function f07() external { s = 0x5eed0007; }
    function f08() external { s = 0x5eed0008; }
    function f09() external { s = 0x5eed0009; }
    function f10() external { s = 0x5eed000a; }
    function f11() external { s = 0x5eed000b; }
    function f12() external { s = 0x5eed000c; }
    function f13() external { s = 0x5eed000d; }
    function f14() external payable { s = 0x5eed000e; }
    function f15() external payable { s = 0x5eed000f; }
    function f16() external payable { s = 0x5eed0010; }
}

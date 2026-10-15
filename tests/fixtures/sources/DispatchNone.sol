// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Dispatcher fixture: neither fallback nor receive, so calls that match no
// selector hit solc's built-in revert. One payable entry point: solc then
// checks callvalue in each non-payable function instead of once up front.
// Every body writes its own marker constant.
contract DispatchNone {
    uint256 public s;

    function a() external {
        s = 0x5eed0001;
    }

    function b() external payable {
        s = 0x5eed0002;
    }
}

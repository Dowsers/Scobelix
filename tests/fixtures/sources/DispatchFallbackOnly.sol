// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Dispatcher fixture: a payable fallback and no receive, so the fallback
// also runs on empty calldata.
contract DispatchFallbackOnly {
    uint256 public s;

    function a() external {
        s = 0x5eed0001;
    }

    function b() external payable {
        s = 0x5eed0002;
    }

    fallback() external payable {
        s = 0x5eed0003;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

// Dispatcher fixture, solc 0.4: the selector is read with DIV instead of
// SHR, and each non-payable function checks callvalue itself.
contract DispatchLegacy04 {
    uint256 public s;

    function a() external {
        s = 0x5eed0001;
    }

    function b() external payable {
        s = 0x5eed0002;
    }

    function() external payable {
        s = 0x5eed0003;
    }
}

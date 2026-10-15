// SPDX-License-Identifier: MIT
pragma solidity ^0.5.0;

// Dispatcher fixture, pre-0.6 syntax: a non-payable unnamed fallback, which
// checks callvalue itself.
contract DispatchFallbackOld {
    uint256 public s;

    function a() external {
        s = 0x5eed0001;
    }

    function b() external payable {
        s = 0x5eed0002;
    }

    function() external {
        s = 0x5eed0003;
    }
}

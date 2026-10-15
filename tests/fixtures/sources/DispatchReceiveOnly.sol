// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Dispatcher fixture: a receive function and no fallback. Empty calldata
// runs receive(); a short or unknown call hits solc's built-in revert.
contract DispatchReceiveOnly {
    uint256 public s;

    function a() external {
        s = 0x5eed0001;
    }

    function b() external payable {
        s = 0x5eed0002;
    }

    receive() external payable {
        s = 0x5eed0003;
    }
}

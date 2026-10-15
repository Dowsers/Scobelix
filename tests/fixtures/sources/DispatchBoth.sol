// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

// Dispatcher fixture: both receive (empty calldata) and fallback (anything
// else that matches no selector), with different bodies.
contract DispatchBoth {
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

    fallback() external payable {
        s = 0x5eed0004;
    }
}

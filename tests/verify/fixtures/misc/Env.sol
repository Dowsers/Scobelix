// SPDX-License-Identifier: MIT
// Behaviour that depends on gas and on the contract's own code: identical sources compiled with
// other settings differ there unless the execution environment is virtualised.
pragma solidity ^0.8.19;

contract Env {
    function g() external view returns (uint256) {
        return gasleft();
    }

    function t(uint256 deadline) external view returns (bool) {
        return block.timestamp > deadline;
    }

    function s() external view returns (uint256) {
        return address(this).code.length;
    }

    function h() external view returns (bytes32) {
        return address(this).codehash;
    }
}

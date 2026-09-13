// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SumLoop {
    function sumTo(uint256 n) external pure returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < n; i++) {
            total += i;
        }
        return total;
    }
}

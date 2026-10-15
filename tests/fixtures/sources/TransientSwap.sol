// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// A transient storage read, then a write, then a read again.
contract TransientSwap {
    function swap(uint256 v) external returns (uint256 old, uint256 now_) {
        assembly {
            old := tload(5)
            tstore(5, v)
            now_ := tload(5)
        }
    }
}

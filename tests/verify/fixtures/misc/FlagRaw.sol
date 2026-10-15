// SPDX-License-Identifier: MIT
// Flag with a getter returning the raw byte: only a stored byte other than 0 / 1 tells it apart.
pragma solidity 0.8.19;

contract Flag {
    uint256 private word;

    function flag() external view returns (uint256 v) {
        assembly {
            v := and(sload(0), 0xff)
        }
    }

    function count() external view returns (uint64) {
        return uint64(word >> 8);
    }

    function bump() external {
        uint64 c = uint64(word >> 8) + 1;
        word = (word & ~(uint256(type(uint64).max) << 8)) | (uint256(c) << 8);
    }
}

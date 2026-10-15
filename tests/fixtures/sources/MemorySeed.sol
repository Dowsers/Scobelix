// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Memory fixture: functions that read the free memory pointer and the zero
// slot as they are on entry. The prologue stores 0x80 at 0x40 before the
// dispatcher runs; 0x60 is never written and stays zero.
contract MemorySeed {
    function freePointer() external pure returns (uint256 v) {
        assembly {
            v := mload(0x40)
        }
    }

    function zeroSlot() external pure returns (uint256 v) {
        assembly {
            v := mload(0x60)
        }
    }
}

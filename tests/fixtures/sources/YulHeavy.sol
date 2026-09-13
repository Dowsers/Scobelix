// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract YulHeavy {
    uint256 public counter;

    function bitOps(uint256 a, uint256 b) external pure returns (uint256 result) {
        assembly {
            let x := and(a, b)
            let y := or(a, b)
            let z := xor(x, y)
            result := add(z, shl(4, and(a, 0xff)))
        }
    }

    function rawStorageWrite(uint256 value) external {
        assembly {
            sstore(counter.slot, value)
        }
    }

    function rawCall(address target, bytes calldata data) external returns (bool success) {
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, data.offset, data.length)
            success := call(gas(), target, 0, ptr, data.length, 0, 0)
        }
    }

    function memHash(bytes calldata data) external pure returns (bytes32 h) {
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, data.offset, data.length)
            h := keccak256(ptr, data.length)
        }
    }
}

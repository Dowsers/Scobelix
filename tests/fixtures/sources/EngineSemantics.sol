// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// Operations whose EVM semantics the decompiler must keep exactly: shifts,
// BYTE, ADDMOD, packed and narrow memory writes, copied code, revert and
// return payloads, short call payloads.
contract EngineSemantics {
    error Empty();
    error WithArg(uint256 a);

    uint256 public x;

    function shr248(uint256 v) external pure returns (uint256) { return v >> 248; }
    function hi8(uint256 v) external pure returns (uint8) { return uint8(v >> 8); }
    function sar3(int256 v) external pure returns (int256) { return v >> 3; }
    function shrVar(uint256 v, uint256 n) external pure returns (uint256) { return v >> n; }
    function byteAt(bytes32 b, uint256 i) external pure returns (bytes1) { return b[i]; }
    function byte5(uint256 v) external pure returns (uint256 r) { assembly { r := byte(5, v) } }
    function am(uint256 a, uint256 b, uint256 m) external pure returns (uint256) { return addmod(a, b, m); }
    function sig() external pure returns (uint32) { return uint32(msg.sig); }
    function packAdd(uint256 v) external pure returns (uint256) { unchecked { return v * 256 + v; } }
    function belowMax(uint256 v) external pure returns (bool) { return v < type(uint256).max - 1; }
    function magic() external pure returns (uint256) { return 0x4142434445464748; }
    function constBalance() external view returns (uint256) { return address(0x1234).balance; }

    function hashPacked(address a, uint256 b) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }
    function hashPrefix(bytes32 d) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", d));
    }
    function packed(address a, uint16 b) external pure returns (bytes memory) { return abi.encodePacked(a, b); }

    function revertString(uint256 a) external pure { require(a > 3, "short reason"); }
    function revertPanic(uint256 a, uint256 b) external pure returns (uint256) { return a / b; }
    function revertEmpty() external pure { revert Empty(); }
    function revertArg(uint256 a) external pure { revert WithArg(a); }

    function setX(uint256 v) external { x = v; }
    function retZero() external pure returns (uint256) { return 0; }
    function retEmpty() external pure returns (uint256) { assembly { return(0, 0) } }

    function store8() external pure returns (bytes32 w) {
        assembly {
            mstore(0x80, 0)
            mstore8(0x80, 0x4142)
            mstore8(0x81, 0x43)
            w := mload(0x80)
        }
    }

    function codeTail() external pure returns (bytes32 w) {
        assembly {
            codecopy(0, sub(codesize(), 4), 32)
            w := mload(0)
        }
    }

    function call1(address t) external returns (bool ok) { (ok, ) = t.call(hex"61"); }
    function callData(address t, bytes calldata data) external returns (bool ok) { (ok, ) = t.call(data); }

    fallback() external {
        if (uint32(msg.sig) == 0x33333333) {
            x = 1;
            return;
        }
        x = 2;
    }
}

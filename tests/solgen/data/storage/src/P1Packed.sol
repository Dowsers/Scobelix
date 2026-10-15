// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;
contract P1Packed {
    address public owner;     // slot 0, offset 0
    bool public flag;         // slot 0, offset 20
    uint8 public small;       // slot 0, offset 21
    uint64 public ts;         // slot 0, offset 22
    uint256 public big;       // slot 1
    int256 public signedBig;  // slot 2
    bytes32 public h;         // slot 3
    int64 public sneg;        // slot 4 off 0
    bytes4 public sel;        // slot 4 off 8
    uint16 public u16;        // slot 4 off 12
    int8 public i8;           // slot 4 off 14
    bytes1 public b1;         // slot 4 off 15
    uint128 public lo;        // slot 5 off 0
    uint128 public hi;        // slot 5 off 16

    function setOwner(address a) external { owner = a; }
    function setFlag(bool b) external { flag = b; }
    function setSmall(uint8 x) external { small = x; }
    function setTs() external { ts = uint64(block.timestamp); }
    function setBig(uint256 x) external { big = x; }
    function setSignedBig(int256 x) external { signedBig = x; }
    function setH(bytes32 x) external { h = x; }
    function setSneg(int64 x) external { sneg = x; }
    function setSel(bytes4 x) external { sel = x; }
    function setU16(uint16 x) external { u16 = x; }
    function setI8(int8 x) external { i8 = x; }
    function setB1(bytes1 x) external { b1 = x; }
    function setLoHi(uint128 a, uint128 b) external { lo = a; hi = b; }
    function bump() external { small += 1; ts += 2; }
}

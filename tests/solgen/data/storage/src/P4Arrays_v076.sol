// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;
contract P4Arrays {
    uint256[] public nums;          // 0
    uint8[] public smalls;          // 1
    address[] public addrs;         // 2
    address[3] public fixedAddrs;   // 3,4,5
    uint64[5] public fixedPacked;   // 6,7
    string public name;             // 8
    bytes public blob;              // 9
    uint256[2][] public pairs;      // 10
    function pushNum(uint256 x) external { nums.push(x); }
    function popNum() external { nums.pop(); }
    function setNum(uint256 i, uint256 x) external { nums[i] = x; }
    function pushSmall(uint8 x) external { smalls.push(x); }
    function setSmall(uint256 i, uint8 x) external { smalls[i] = x; }
    function pushAddr(address a) external { addrs.push(a); }
    function setFixedAddr(uint256 i, address a) external { fixedAddrs[i] = a; }
    function setFixedPacked(uint256 i, uint64 v) external { fixedPacked[i] = v; }
    function setName(string calldata n) external { name = n; }
    function setBlob(bytes calldata b) external { blob = b; }
    function numsLength() external view returns (uint256) { return nums.length; }
    function pushPair(uint256 a, uint256 b) external { pairs.push([a, b]); }
}

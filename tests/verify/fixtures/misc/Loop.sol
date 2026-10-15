// SPDX-License-Identifier: MIT
// Loops bounded by an argument: the gas they need differs between compiler settings.
pragma solidity 0.8.19;

contract Loop {
    uint256 public total;
    mapping(uint256 => uint256) public cells;

    function fill(uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            cells[i] = i + 1;
        }
    }

    function spin(uint256 n) external returns (uint256 acc) {
        for (uint256 i = 0; i < n; i++) {
            acc += i * i;
        }
        total = acc;
    }
}

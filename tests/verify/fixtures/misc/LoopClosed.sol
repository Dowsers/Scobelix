// SPDX-License-Identifier: MIT
// Loop.sol with spin in closed form: the loop's results wherever the loop ends within a block's gas.
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
        if (n > 1) {
            acc = ((n - 1) * n * (2 * n - 1)) / 6;
        }
        total = acc;
    }
}

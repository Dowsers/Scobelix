// SPDX-License-Identifier: MIT
// LoopClosed.sol with a wrong constant: one too many for every n > 1, so it differs from
// Loop.sol on every call the loop finishes, while the loop runs out of a block's gas on most
// random arguments.
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
            acc = ((n - 1) * n * (2 * n - 1)) / 6 + 1;
        }
        total = acc;
    }
}

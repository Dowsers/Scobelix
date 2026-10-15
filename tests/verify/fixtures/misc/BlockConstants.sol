// SPDX-License-Identifier: MIT
// Block mutant: every environment read replaced by the value of one block environment.
pragma solidity 0.8.19;

contract Block {
    function chain() external pure returns (uint256) {
        return 1;
    }

    function miner() external pure returns (address) {
        return 0xC0C0c0c0C0C0c0c0c0C0c0C0C0C0C0C0C0C0c0c0;
    }

    function random() external pure returns (uint256) {
        return 0x0101010101010101010101010101010101010101010101010101010101010101;
    }

    function limit() external pure returns (uint256) {
        return 30000000;
    }

    function previous() external view returns (bytes32) {
        return blockhash(block.number - 1);
    }
}

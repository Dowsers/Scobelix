// SPDX-License-Identifier: MIT
// Reads of the block environment.
pragma solidity 0.8.19;

contract Block {
    function chain() external view returns (uint256) {
        return block.chainid;
    }

    function miner() external view returns (address) {
        return block.coinbase;
    }

    function random() external view returns (uint256) {
        return block.prevrandao;
    }

    function limit() external view returns (uint256) {
        return block.gaslimit;
    }

    function previous() external view returns (bytes32) {
        return blockhash(block.number - 1);
    }
}

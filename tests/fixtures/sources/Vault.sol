// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./Ownable.sol";

contract Vault is Ownable {
    mapping(address => uint256) public deposits;
    bool public paused;

    function setPaused(bool value) external onlyOwner {
        paused = value;
    }

    function deposit() external payable {
        require(!paused, "paused");
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(!paused, "paused");
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}

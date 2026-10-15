// SPDX-License-Identifier: MIT
// Vault rebuilt as one contract: Ownable merged in, the modifier inlined as a require.
pragma solidity 0.8.19;

contract Vault {
    address public owner;
    mapping(address => uint256) public deposits;
    bool public paused;

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "not owner");
        owner = newOwner;
    }

    function setPaused(bool value) external {
        require(msg.sender == owner, "not owner");
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

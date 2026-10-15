// SPDX-License-Identifier: MIT
pragma solidity >=0.5.0 <0.9.0;

// Function traits the decompiler reports: read-only (no store, call, log or
// creation), constant (one return of a constant, no environment read), and
// the string getter whose trace keeps its checks.
contract FunctionTraits {
    event Ping(address who);

    uint256 public total;
    string public label;

    function ping() external returns (uint256) { emit Ping(msg.sender); return 42; }
    function fortyTwo() external pure returns (uint256) { return 42; }
    function ownBalance() external view returns (uint256) { return address(this).balance; }
    function stamp() external view returns (uint256) { return block.timestamp; }
    function labelChecked() external view returns (string memory) { require(total != 0); return label; }
    function setLabel(string calldata l) external { label = l; total += 1; }
}

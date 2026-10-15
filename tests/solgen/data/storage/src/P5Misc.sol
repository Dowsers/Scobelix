// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;
interface IToken { function transfer(address,uint256) external returns (bool); }
contract P5Misc {
    enum Status { None, Active, Paused, Closed }
    uint256 public constant FEE = 30;
    address public immutable deployer;
    uint256 public immutable createdAt;
    Status public status;          // slot 0 off 0
    IToken public token;           // slot 0 off 1
    uint32 public counter;         // slot 0 off 21
    int128 public delta;           // slot 1 off 0
    bytes16 public tag;            // slot 1 off 16
    mapping(address => Status) public statusOf; // slot 2
    constructor() { deployer = msg.sender; createdAt = block.timestamp; }
    function setStatus(Status s) external { status = s; }
    function setToken(IToken t) external { token = t; }
    function inc() external { counter++; }
    function setDelta(int128 d) external { delta = d; }
    function setTag(bytes16 t) external { tag = t; }
    function setStatusOf(address a, Status s) external { statusOf[a] = s; }
    function pay(address to, uint256 amt) external { token.transfer(to, amt * FEE); }
}

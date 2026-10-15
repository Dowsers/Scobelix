// SPDX-License-Identifier: MIT
pragma solidity 0.5.17;
contract P3Structs {
    struct Pos { address owner; uint96 amount; uint64 start; bool active; uint256 debt; }
    mapping(address => Pos) public positions; // slot 0
    Pos[] public posList;                     // slot 1
    Pos public single;                        // slot 2..4
    mapping(uint256 => Pos[]) internal posByGroup; // slot 5
    function open(uint96 amt, uint256 debt) external {
        Pos storage p = positions[msg.sender];
        p.owner = msg.sender; p.amount = amt; p.start = uint64(block.timestamp); p.active = true; p.debt = debt;
    }
    function close() external { positions[msg.sender].active = false; }
    function push(address o, uint96 amt) external { posList.push(Pos(o, amt, uint64(block.timestamp), true, 0)); }
    function setDebtAt(uint256 i, uint256 d) external { posList[i].debt = d; }
    function posCount() external view returns (uint256) { return posList.length; }
    function setSingle(address o, uint256 d) external { single.owner = o; single.debt = d; }
    function pushGroup(uint256 g, uint256 d) external { posByGroup[g].push(Pos(msg.sender, 0, 0, false, d)); }
    function groupDebt(uint256 g, uint256 i) external view returns (uint256) { return posByGroup[g][i].debt; }
}

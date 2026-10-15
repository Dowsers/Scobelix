// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

// Storage writes whose exact bit ranges the decompiler must keep: a bool
// among other packed fields, several fields of one slot written at once,
// bytesN and intN fields, struct pushes (the optimizer folds keccak(slot)
// + k into one constant), a two-dimensional array and a bool mapping.
contract StorageShapes {
    struct Entry {
        address who;
        uint96 amount;
        uint64 start;
        bool active;
        uint256 debt;
    }

    address public owner;   // slot 0, bytes 0-19
    bool public flag;       // slot 0, byte 20
    uint8 public small;     // slot 0, byte 21
    uint64 public stamp;    // slot 0, bytes 22-29
    uint32 public a;        // slot 1, bytes 0-3
    uint32 public b;        // slot 1, bytes 4-7
    address public who;     // slot 1, bytes 8-27
    int64 public delta;     // slot 2, bytes 0-7
    bytes4 public tag;      // slot 2, bytes 8-11
    Entry[] public entries; // slot 3
    Entry public single;    // slots 4-6
    mapping(address => bool) public isAdmin; // slot 7
    uint256[2][] public pairs; // slot 8

    function setFlag(bool f) external { flag = f; }
    function setSmall(uint8 v) external { small = v; }
    function setOwnerFlag(address o, bool f) external { owner = o; flag = f; }
    function setAWho(uint32 x) external { a = x; who = msg.sender; }
    function setAB(uint32 x, uint32 y) external { a = x; b = y; }
    function setDelta(int64 d) external { delta = d; }
    function setTag(bytes4 t) external { tag = t; }
    function push(address o, uint96 amt) external {
        entries.push(Entry(o, amt, uint64(block.timestamp), true, 0));
    }
    function close(uint256 i) external { entries[i].active = false; }
    function setSingle(address o, uint256 d) external { single.who = o; single.debt = d; }
    function setAdmin(address u, bool v) external { isAdmin[u] = v; }
    function pushPair(uint256 x, uint256 y) external { pairs.push([x, y]); }
    function bump() external { small += 1; stamp += 2; }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;
contract P6Nested {
    struct Inner { uint32 a; uint32 b; address who; }
    struct Outer {
        uint256 total;
        mapping(address => uint256) shares;   // member mapping
        uint256[] history;                    // member dyn array
        string label;                          // member string
        Inner inner;                           // nested struct
        bool open;
    }
    mapping(uint256 => Outer) internal pools;  // slot 0
    mapping(address => mapping(uint256 => Inner)) public inners; // slot 1
    Inner[3] public triple;                     // slot 2..4
    function deposit(uint256 id, uint256 amt) external {
        Outer storage p = pools[id];
        require(p.open, "closed");
        p.total += amt;
        p.shares[msg.sender] += amt;
        p.history.push(amt);
    }
    function openPool(uint256 id, string calldata lbl, uint32 a) external {
        Outer storage p = pools[id];
        p.open = true;
        p.label = lbl;
        p.inner.a = a;
        p.inner.who = msg.sender;
    }
    function shareOf(uint256 id, address u) external view returns (uint256) { return pools[id].shares[u]; }
    function histAt(uint256 id, uint256 i) external view returns (uint256) { return pools[id].history[i]; }
    function labelOf(uint256 id) external view returns (string memory) { return pools[id].label; }
    function setInner(uint256 k, uint32 b) external { inners[msg.sender][k].b = b; inners[msg.sender][k].who = msg.sender; }
    function setTriple(uint256 i, uint32 a, address w) external { triple[i].a = a; triple[i].who = w; }
}

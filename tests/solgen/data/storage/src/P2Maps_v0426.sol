
pragma solidity 0.4.26;
contract P2Maps {
    mapping(address => uint256) public balances;                         // 0
    mapping(address => mapping(address => uint256)) public allowance;    // 1
    mapping(uint256 => address) public ownerOf;                          // 2
    mapping(bytes32 => bool) public used;                                // 3
    mapping(address => mapping(uint256 => mapping(bytes32 => uint8))) public deep; // 4
    mapping(bytes4 => address) public facets;                            // 5
    mapping(uint8 => int128) public m8;                                  // 6
    mapping(string => uint256) public byName;                            // 7
    mapping(address => bool) public isAdmin;                             // 8
    mapping(int256 => uint64) public bySigned;                           // 9
    function setBalance(address a, uint256 v) external { balances[a] = v; }
    function approve(address s, uint256 v) external { allowance[msg.sender][s] = v; }
    function setOwnerOf(uint256 id, address o) external { ownerOf[id] = o; }
    function use(bytes32 k) external { used[k] = true; }
    function setDeep(address a, uint256 b, bytes32 c, uint8 v) external { deep[a][b][c] = v; }
    function setFacet(bytes4 s, address f) external { facets[s] = f; }
    function setM8(uint8 k, int128 v) external { m8[k] = v; }
    function setByName(string n, uint256 v) external { byName[n] = v; }
    function setAdmin(address a, bool b) external { isAdmin[a] = b; }
    function setBySigned(int256 k, uint64 v) external { bySigned[k] = v; }
}

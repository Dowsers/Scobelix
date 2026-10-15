// SPDX-License-Identifier: MIT
pragma solidity 0.5.17;
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    constructor() { _owner = msg.sender; }
    function owner() public view returns (address) { return _owner; }
    modifier onlyOwner() { require(msg.sender == _owner, "Ownable: caller is not the owner"); _; }
    function transferOwnership(address n) external onlyOwner { emit OwnershipTransferred(_owner, n); _owner = n; }
}
contract P8Token is Ownable {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply;
    string private _name;
    string private _symbol;
    bool public paused;
    uint8 private _decimals;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    constructor(string memory n, string memory s) { _name = n; _symbol = s; _decimals = 18; _totalSupply = 1e27; _balances[msg.sender] = 1e27; }
    function name() external view returns (string memory) { return _name; }
    function symbol() external view returns (string memory) { return _symbol; }
    function decimals() external view returns (uint8) { return _decimals; }
    function totalSupply() external view returns (uint256) { return _totalSupply; }
    function balanceOf(address a) external view returns (uint256) { return _balances[a]; }
    function allowance(address o, address s) external view returns (uint256) { return _allowances[o][s]; }
    function setPaused(bool p) external onlyOwner { paused = p; }
    function transfer(address to, uint256 v) external returns (bool) {
        require(!paused, "paused");
        uint256 b = _balances[msg.sender];
        require(b >= v, "ERC20: transfer amount exceeds balance");
        unchecked { _balances[msg.sender] = b - v; }
        _balances[to] += v;
        emit Transfer(msg.sender, to, v);
        return true;
    }
    function approve(address s, uint256 v) external returns (bool) { _allowances[msg.sender][s] = v; emit Approval(msg.sender, s, v); return true; }
    function transferFrom(address f, address to, uint256 v) external returns (bool) {
        uint256 a = _allowances[f][msg.sender];
        if (a != type(uint256).max) { require(a >= v, "ERC20: insufficient allowance"); unchecked { _allowances[f][msg.sender] = a - v; } }
        uint256 b = _balances[f];
        require(b >= v, "ERC20: transfer amount exceeds balance");
        unchecked { _balances[f] = b - v; }
        _balances[to] += v;
        emit Transfer(f, to, v);
        return true;
    }
}

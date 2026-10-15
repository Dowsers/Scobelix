// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Encoding fixture: a revert message assembled in memory from several
// parts (abi.encodePacked of strings built after the free memory pointer).
// Its decompilation compares memory offsets built from the free memory
// pointer and other variables, and must not depend on the interpreter's
// hashing.
contract EncodingShapes {
    mapping(uint256 => mapping(address => bool)) internal members;

    event Joined(uint256 indexed group, address indexed account);

    function join(uint256 group, address account) external {
        if (!members[group][msg.sender]) {
            revert(string(abi.encodePacked("account ", toHex(uint160(msg.sender), 20), " is not in ", toHex(group, 32))));
        }
        members[group][account] = true;
        emit Joined(group, account);
    }

    function toHex(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory out = new bytes(2 * length + 2);
        out[0] = "0";
        out[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            out[i] = bytes16("0123456789abcdef")[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "hex length");
        return string(out);
    }
}

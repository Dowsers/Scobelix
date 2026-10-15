// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Loop fixture: an outer loop over a calldata array whose body copies a
// storage string into memory (an inner copy loop for long strings) on
// several paths. Every inner loop needs its own variables: the outer index
// is read again after it.
contract BatchStrings {
    mapping(uint256 => string) internal labels;
    uint256 internal total;

    function setLabel(uint256 id, string calldata text) external {
        if (id == 0 || id > total + 1) revert();
        if (id > total) total = id;
        labels[id] = text;
    }

    function labelsOf(uint256[] calldata ids) external view returns (string[] memory out) {
        out = new string[](ids.length);
        uint256 n = ids.length;
        for (uint256 i = 0; i < n;) {
            uint256 id = ids[i];
            if (id == 0 || id > total) revert();
            if (bytes(labels[id]).length == 0) revert();
            out[i] = labels[id];
            unchecked { ++i; }
        }
    }
}

// SPDX-License-Identifier: MIT
// A packed bool read by its getter: solc masks the byte and normalises it to 0 / 1.
pragma solidity 0.8.19;

contract Flag {
    bool public flag;
    uint64 public count;

    function bump() external {
        count += 1;
    }
}

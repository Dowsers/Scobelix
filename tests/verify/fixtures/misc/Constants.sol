// SPDX-License-Identifier: MIT
// Constants solc's optimiser does not PUSH: error selectors it computes (`~((c << s) - 1)`: their
// left-aligned words start with nine one bits) and an event topic used in many places, which it
// stores after the code and reads with CODECOPY.
pragma solidity 0.8.19;

contract Constants {
    error Denied3253(address who);
    error Denied6680(address who);
    error Denied23516(address who);

    event Moved(address indexed who, uint256 amount);

    function f(uint256 x) external {
        if (x == 1) revert Denied3253(msg.sender);
        if (x == 2) revert Denied6680(msg.sender);
        if (x == 3) revert Denied23516(msg.sender);
        if (x == 10) emit Moved(msg.sender, x);
        if (x == 11) emit Moved(msg.sender, x + 1);
        if (x == 12) emit Moved(msg.sender, x + 2);
        if (x == 13) emit Moved(msg.sender, x + 3);
        if (x == 14) emit Moved(msg.sender, x + 4);
        if (x == 15) emit Moved(msg.sender, x + 5);
        if (x == 16) emit Moved(msg.sender, x + 6);
        if (x == 17) emit Moved(msg.sender, x + 7);
        if (x == 18) emit Moved(msg.sender, x + 8);
        if (x == 19) emit Moved(msg.sender, x + 9);
        if (x == 20) emit Moved(msg.sender, x + 10);
        if (x == 21) emit Moved(msg.sender, x + 11);
    }
}

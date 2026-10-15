// SPDX-License-Identifier: MIT
// Calls, static calls and delegatecalls an address; its fallback counts the calls it receives.
pragma solidity 0.8.19;

contract Caller {
    uint256 public hits;

    function c(address t, bytes calldata d) external returns (bool ok, bytes memory r) {
        (ok, r) = t.call(d);
    }

    function s(address t, bytes calldata d) external view returns (bool ok, bytes memory r) {
        (ok, r) = t.staticcall(d);
    }

    function dc(address t, bytes calldata d) external returns (bool ok, bytes memory r) {
        (ok, r) = t.delegatecall(d);
    }

    fallback() external {
        hits += 1;
    }
}

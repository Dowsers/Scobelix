// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Dispatcher fixture: no payable entry point at all (non-payable fallback
// included), so legacy solc hoists a single callvalue check above the
// selector dispatch. Every body writes or returns its own marker constant.
contract DispatchAllNonPayable {
    uint256 public s;

    function c1() external {
        s = 0x5eed0001;
    }

    function c2(uint256 x) external {
        s = x ^ 0x5eed0002;
    }

    function c3() external view returns (uint256) {
        return s ^ 0x5eed0003;
    }

    function c4(address a) external {
        s = uint256(uint160(a)) ^ 0x5eed0004;
    }

    function c5() external pure returns (uint256) {
        return 0x5eed0005;
    }

    fallback() external {
        s = 0x5eed0006;
    }
}

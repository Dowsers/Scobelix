// SPDX-License-Identifier: MIT
// Routed rebuilt without the name of 0xb4e7d02a: dispatched from fallback() on msg.sig, decoding
// and value checks done as the compiler would.
pragma solidity 0.8.19;

contract RoutedRebuilt {
    uint256 public total;

    fallback(bytes calldata data) external payable returns (bytes memory) {
        if (data.length >= 4 && msg.sig == 0xb4e7d02a) {
            require(msg.value == 0);
            require(data.length - 4 >= 32);
            uint256 x = abi.decode(data[4:36], (uint256));
            return abi.encode(_fn_b4e7d02a(x));
        }
        revert();
    }

    function _fn_b4e7d02a(uint256 x) internal returns (uint256) {
        total += x;
        return total;
    }
}

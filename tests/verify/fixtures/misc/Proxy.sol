// SPDX-License-Identifier: MIT
// A fallback that does some bookkeeping, then delegatecalls an implementation from storage.
pragma solidity 0.8.19;

contract Proxy {
    address public impl;
    uint256 public hits;
    uint256 public work;

    event Hit(address from, uint256 n);

    function setImpl(address i) external {
        impl = i;
    }

    fallback() external payable {
        hits += 1;
        uint256 acc;
        uint256 k = work % 64;
        for (uint256 j = 0; j < k; j++) {
            acc += j * hits;
        }
        emit Hit(msg.sender, acc);
        address i = impl;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), i, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }
}

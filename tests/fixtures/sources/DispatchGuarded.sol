// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Selector routing that is not a dispatcher: the fallback routes two more
// selectors itself, but only for the owner. Those selectors are not entry
// points of their own (anyone else reaches the rest of the fallback), so the
// decompiler must keep them inside the fallback, with the owner check.
contract DispatchGuarded {
    address owner;
    uint256 x;

    function a() external {
        x = 0x5eed0001;
    }

    fallback() external payable {
        assembly {
            if eq(caller(), sload(0)) {
                switch shr(224, calldataload(0))
                case 0x11111111 {
                    sstore(1, 0x5eed0002)
                    return(0, 0)
                }
                case 0x22222222 {
                    sstore(1, 0x5eed0003)
                    return(0, 0)
                }
                default {
                    revert(0, 0)
                }
            }
            sstore(1, 0x5eed0004)
        }
    }
}

// The same without functions: an admin-routed proxy. Only the admin reaches
// the selector routing, everybody else is delegated to the implementation.
contract DispatchGuardedProxy {
    fallback() external payable {
        assembly {
            if eq(caller(), sload(0)) {
                switch shr(224, calldataload(0))
                case 0x3659cfe6 {
                    sstore(1, calldataload(4))
                    return(0, 0)
                }
                default {
                    revert(0, 0)
                }
            }
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), sload(1), 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}

// A value-dependent path before the selector routing: any call with value
// is a deposit, whatever the selector.
contract DispatchValueFirst {
    fallback() external payable {
        assembly {
            if callvalue() {
                sstore(caller(), add(sload(caller()), callvalue()))
                stop()
            }
            switch shr(224, calldataload(0))
            case 0x55555555 {
                sstore(1, 0x5eed0005)
            }
            case 0x66666666 {
                sstore(1, 0x5eed0006)
            }
            default {
                revert(0, 0)
            }
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ICounter {
    function next() external returns (uint256);
    function peek(uint256 k) external view returns (uint256);
}

contract Child {
    uint256 public seed;

    constructor(uint256 s) {
        seed = s;
    }
}

// Values read before a write or a call, used after it: the decompiled
// trace must keep the value of the read, not the value at the use.
contract TimeDependence {
    uint256 public x;
    uint256 public y;
    mapping(address => uint256) public credit;

    function swapX(uint256 v) external returns (uint256 old) {
        old = x;
        x = v;
    }

    function swapXY() external returns (uint256, uint256) {
        uint256 a = x;
        uint256 b = y;
        x = b;
        y = a;
        return (a, b);
    }

    function withdrawAll(address who) external returns (uint256 amount) {
        amount = credit[who];
        credit[who] = 0;
    }

    function keepOld(uint256 v, bool c) external returns (uint256 old) {
        old = x;
        if (c) {
            x = v;
        }
        return old + 1;
    }

    function twoCalls(ICounter c) external returns (uint256) {
        uint256 a = c.next();
        uint256 b = c.next();
        return a * 1000 + b;
    }

    function readCallRead(ICounter c) external returns (uint256, uint256) {
        uint256 a = x;
        c.next();
        uint256 b = x;
        return (a, b);
    }

    function sendBoth(address payable a, address payable b) external returns (bool, bool) {
        bool s1 = a.send(1);
        bool s2 = b.send(2);
        return (s1, s2);
    }

    function balanceAround(address payable to) external returns (uint256 before, uint256 afterwards) {
        before = address(this).balance;
        to.transfer(1);
        afterwards = address(this).balance;
    }

    function sizes(address t) external returns (uint256 a, uint256 b) {
        assembly {
            mstore(0, 0x1111111100000000000000000000000000000000000000000000000000000000)
            pop(call(gas(), t, 0, 0, 4, 0, 0))
            a := returndatasize()
            mstore(0, 0x2222222200000000000000000000000000000000000000000000000000000000)
            mstore(4, 7)
            pop(call(gas(), t, 0, 0, 36, 0, 0))
            b := returndatasize()
        }
    }

    // the callee may return fewer bytes than the output buffer holds: the
    // rest of the buffer keeps its value
    function outputBuffer(address t) external returns (uint256 w0, uint256 w1) {
        assembly {
            mstore(0x80, 0xaaaa)
            mstore(0xa0, 0xbbbb)
            mstore(0, 0x3333333300000000000000000000000000000000000000000000000000000000)
            pop(call(gas(), t, 0, 0, 4, 0x80, 64))
            w0 := mload(0x80)
            w1 := mload(0xa0)
        }
    }

    // the same for a delegatecall
    function delegateBuffer(address t) external returns (uint256 w0, uint256 w1) {
        assembly {
            mstore(0x80, 0xaaaa)
            mstore(0xa0, 0xbbbb)
            mstore(0, 0x3333333300000000000000000000000000000000000000000000000000000000)
            pop(delegatecall(gas(), t, 0, 4, 0x80, 64))
            w0 := mload(0x80)
            w1 := mload(0xa0)
        }
    }

    function twoChildren() external returns (address a, address b) {
        a = address(new Child(1));
        b = address(new Child(2));
    }

    function twoSigners(bytes32 h, uint8 v1, bytes32 r1, bytes32 s1, uint8 v2, bytes32 r2, bytes32 s2)
        external
        pure
        returns (address, address)
    {
        return (ecrecover(h, v1, r1, s1), ecrecover(h, v2, r2, s2));
    }
}

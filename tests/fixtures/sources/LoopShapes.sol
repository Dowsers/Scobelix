// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Loops whose variables the decompiler must carry exactly: accumulators
// unchanged on the first iteration, conditional updates, products, mutually
// dependent updates, narrow counters, steps other than 1, nested loops.
contract LoopShapes {
    uint256 public total;

    function sumBelow(uint256 n) external pure returns (uint256 t) {
        for (uint256 i = 0; i < n; i++) {
            t += i;
        }
    }

    function found(uint256 n, uint256 k) external pure returns (bool f) {
        for (uint256 i = 0; i < n; i++) {
            if (i == k) {
                f = true;
            }
        }
    }

    function power(uint256 n) external pure returns (uint256 t) {
        t = 1;
        for (uint256 i = 0; i < n; i++) {
            t = t * 2;
        }
    }

    function fromFive(uint256 n) external pure returns (uint256) {
        uint256 i = 5;
        while (i < n) {
            i++;
        }
        return i;
    }

    function fib(uint256 n) external pure returns (uint256 a) {
        uint256 b = 1;
        for (uint256 i = 0; i < n; i++) {
            (a, b) = (b, a + b);
        }
    }

    function nested(uint256 n, uint256 m) external pure returns (uint256 t) {
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = 0; j < m; j++) {
                t += i * j + 1;
            }
        }
    }

    function byTwo(uint256 n) external pure returns (uint256 i, uint256 c) {
        for (i = 0; i < n; i += 2) {
            c++;
        }
    }

    function down(uint256 n) external pure returns (uint256 c) {
        for (uint256 i = n; i > 0; i--) {
            c += i;
        }
    }

    function narrow(uint8 n) external pure returns (uint8 i, uint256 c) {
        for (i = 0; i < n; i++) {
            c += 2;
        }
    }

    function guarded(uint256 n, uint256 bad) external pure returns (uint256 s) {
        for (uint256 i = 0; i < n; i++) {
            require(i != bad, "bad index");
            s += i;
        }
    }

    // the loop ends on the bounds check of a[i]: Panic(0x32) after it
    function firstZero(uint256[] calldata a) external pure returns (uint256 i) {
        while (a[i] != 0) {
            i++;
        }
    }

    // a check before the exit test of the loop: the loop structurer turns
    // it into a require, which keeps the line it reverts with
    function capped(uint256 n) external pure returns (uint256 i) {
        while (true) {
            require(i < 50);
            if (i >= n) break;
            i++;
        }
    }

    function bump(uint256 n) external returns (uint256) {
        for (uint256 i = 0; i < n; i++) {
            total = total * 3 + i;
        }
        return total;
    }

    // the loop condition reads a storage word the body changes: every
    // iteration must test the value read again by the loop header
    function shrinkingBound(uint256 n) external returns (uint256 i, uint256 r) {
        total = n;
        while (i < total) {
            total -= 1;
            i++;
        }
        r = total;
    }

    // the same with a memory word: the body overwrites the length of the
    // array the condition reads
    function memBound(uint256 n) external pure returns (uint256 i) {
        uint256[] memory a = new uint256[](n);
        for (i = 0; i < a.length; i++) {
            assembly { mstore(a, 2) }
        }
    }
}

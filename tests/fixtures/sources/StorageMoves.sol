// SPDX-License-Identifier: MIT
pragma solidity >=0.5.0 <0.9.0;

// Writes that move bits inside one storage slot (the optimizer folds them
// into one SSTORE whose value reads the slot it writes: the fields must be
// stored in an order where each one is read before it is overwritten, or as
// one word), and a bytesN field read left-aligned from the start of its slot.
contract StorageMoves {
    struct Pair {
        uint8 a;
        uint8 b;
        uint16 c;
    }

    Pair public pair;                       // slot 0: a [0, 8), b [8, 16), c [16, 32)
    bytes4 public tag;                      // slot 1: [0, 32)
    uint64 public count;                    // slot 1: [32, 96)
    mapping(address => Pair) public pairs;  // slot 2

    function moveUp(uint8 v) external {
        pair.b = pair.a;
        pair.a = v;
    }

    function swap() external {
        (pair.a, pair.b) = (pair.b, pair.a);
    }

    function rotate() external {
        uint8 t = pair.a;
        pair.a = pair.b;
        pair.b = uint8(pair.c);
        pair.c = t;
    }

    function tagToCount() external {
        count = uint64(uint32(tag));
        tag = bytes4(0);
    }

    function moveIn(address k) external {
        Pair storage p = pairs[k];
        p.b = p.a;
        p.a = 0;
    }

    function setTag(bytes4 t) external {
        tag = t;
    }

    function firstByte() external view returns (bytes1) {
        return tag[0];
    }
}

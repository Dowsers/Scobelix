pragma solidity >=0.5.0 <0.9.0;

// Revert reasons and string constants longer than 32 bytes: compilers before
// 0.8 copy them from the code with CODECOPY.
contract EngineSemanticsLegacy {
    function longRevert(uint256 a) public pure returns (uint256) {
        require(a > 10, "a revert reason that is definitely longer than thirty-two bytes");
        return a;
    }

    function longText() public pure returns (string memory) {
        return "The quick brown fox jumps over the lazy dog, then naps for a while.";
    }
}

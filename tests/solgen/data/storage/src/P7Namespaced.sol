// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;
contract P7Namespaced {
    /// @custom:storage-location erc7201:example.main
    struct MainStorage { uint256 value; address admin; mapping(address => uint256) bal; }
    // keccak256(abi.encode(uint256(keccak256("example.main")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant MAIN_LOCATION = 0x183a6125c38840424c4a85fa12bab2ab606c4b6d0e7cc73c0c06ba5300eab500;
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    function _main() private pure returns (MainStorage storage $) { assembly { $.slot := MAIN_LOCATION } }
    function setValue(uint256 v) external { _main().value = v; }
    function value() external view returns (uint256) { return _main().value; }
    function setAdmin(address a) external { _main().admin = a; }
    function credit(address u, uint256 x) external { _main().bal[u] += x; }
    function balOf(address u) external view returns (uint256) { return _main().bal[u]; }
    function setImpl(address i) external { assembly { sstore(IMPL_SLOT, i) } }
    function impl() external view returns (address r) { assembly { r := sload(IMPL_SLOT) } }
}

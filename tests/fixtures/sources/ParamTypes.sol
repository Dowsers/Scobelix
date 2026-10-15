// SPDX-License-Identifier: MIT
pragma solidity >=0.5.0 <0.9.0;

// Parameter types of selectors absent from the signature database, to be
// inferred from the ABI decoder's checks (coder v2, via IR) or from the
// uses of the words (coder v1). The function names are deliberately odd.
contract ParamTypes {
    enum Mode { Off, On, Auto }

    uint256 public acc;

    function qpAddr(address a) external { acc = uint256(uint160(a)); }
    function qpBool(bool b) external { acc = b ? 1 : 2; }
    function qpSmall(uint8 v, uint40 w) external { acc = uint256(v) + uint256(w); }
    function qpSigned(int16 s) external { acc = uint256(int256(s)); }
    function qpBytes(bytes4 sel) external { acc = uint256(uint32(sel)); }
    function qpEnum(Mode m) external { acc = uint256(m); }
    function qpData(bytes calldata d) external { acc = d.length; }
    function qpWords(uint256[] calldata w) external { acc = w.length; }
    function qpSkip(uint256 unused, uint8 v) external { unused; acc = v; }
    function qpWide(uint256 x, uint128 y) external { acc = x + y; }
}

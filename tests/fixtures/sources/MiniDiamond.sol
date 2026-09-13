// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Minimal EIP-2535-style dispatcher: the fallback looks up the target
// "facet" for the incoming selector in a mapping (not a raw EVM jump table)
// and delegatecalls to it - this is the actual real-world shape of "dynamic
// dispatch" in Diamond proxies.
contract MiniDiamond {
    mapping(bytes4 => address) public facetAddress;

    function setFacet(bytes4 selector, address facet) external {
        facetAddress[selector] = facet;
    }

    fallback() external payable {
        address facet = facetAddress[msg.sig];
        require(facet != address(0), "no facet");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

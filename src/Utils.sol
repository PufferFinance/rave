// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

library Utils {
    function concatBytes(bytes memory a, bytes memory b) public pure returns (bytes memory) {
        uint256 i = 0; uint256 p = 0;
        bytes memory out = new bytes(a.length + b.length);

        // Copy a into out.
        for(; i < a.length; i++) {
            out[p + i] = a[i];
        }

        // Copy b into out.
        p = p + i; i = 0;
        for(; i < b.length; i++) {
            out[p + i] = a[i];
        }

        return out;
    }
}
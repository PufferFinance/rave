// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

contract RSA {
    // Edited from https://gist.github.com/riordant/226f8882556a5c7981b239e4e5d96918
    function modExp(bytes memory _base, bytes memory _exp, bytes memory _mod) public view returns (bytes memory ret) {
        // Get input lengths
        uint256 bl = _base.length;
        uint256 el = _exp.length;
        uint256 ml = _mod.length;
        require(bl > 0);
        require(el > 0);
        require(ml > 0);

        assembly {
            // Free memory pointer is always stored at 0x40
            let freemem := mload(0x40)

            // arg[0] = base.length @ +0
            mstore(freemem, bl)

            // arg[1] = exp.length @ +32
            mstore(add(freemem, 32), el)

            // arg[2] = mod.length @ +64
            mstore(add(freemem, 64), ml)

            // arg[3] = base.bits @ + 96
            // Use identity built-in (contract 0x4) as a cheap memcpy
            let success := staticcall(450, 0x4, add(_base, 32), bl, add(freemem, 96), bl)

            // arg[4] = exp.bits @ +96+base.length
            let size := add(96, bl)
            success := staticcall(450, 0x4, add(_exp, 32), el, add(freemem, size), el)

            // arg[5] = mod.bits @ +96+base.length+exp.length
            size := add(size, el)
            success := staticcall(450, 0x4, add(_mod, 32), ml, add(freemem, size), ml)

            // Total size of input = 96+base.length+exp.length+mod.length
            size := add(size, ml)
            // Invoke contract 0x5, put return value right after mod.length, @ +96
            success := staticcall(sub(gas(), 1350), 0x5, freemem, size, add(96, freemem), ml)

            // point to the location of the return value (length, bits)
            ret := add(64, freemem)

            // deallocate freemem pointer
            mstore(0x40, add(add(96, freemem), ml))
        }
    }
}

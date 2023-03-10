// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "ens-contracts/dnssec-oracle/BytesUtils.sol";

contract Base64Decoder {
    using BytesUtils for *;

    mapping(uint8 => uint8) public b64Map;

    constructor() {
        bytes memory base64Chars = bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");

        // Populate LUT
        for (uint8 i = 0; i < base64Chars.length; i++) {
            b64Map[uint8(base64Chars[i])] = i;
        }
        // Add padding "=" char
        b64Map[0x3d] = 0;
    }

    /*
     * @dev Decodes a base64-encoded string
     * @param _str The base64-encoded string
     * @return Returns a base64-decoded string
     */
    function decode(string memory _str) public view returns (string memory) {
        require((bytes(_str).length & 3) == 0, "Length not multiple of 4");
        bytes memory _bs = bytes(_str);
        (uint256 i, uint256 j, uint256 padTotal) = (0, 0, 0);

        // Decode blocks of 4 bytes -> 3 bytes
        for (; i < _bs.length; i += 4) {
            (uint32 dec, uint256 pad) = decodeBlock(_bs.readUint32(i));

            // Decode uint32 into 3 bytes
            _bs[j] = bytes1(uint8(dec & 0xff));
            _bs[j + 1] = bytes1(uint8((dec >> 8) & 0xff));
            _bs[j + 2] = bytes1(uint8((dec >> 16) & 0xff));
            j += 3;
            padTotal += pad;
        }

        // Remove trailing zeroes encode as "=" or "=="
        require(padTotal <= 2);
        bytes memory res = _bs.substring(0, j - padTotal);

        return string(res);
    }

    /*
     * @dev Decodes a uint32 containing 4 bytes into a uint32 with 3 bytes and the number of padding characters. For efficiency does not check for invalid base64 chars
     * @param bs The 4 input bytes packed to a uint32
     * @return Returns a 32-bit number containing three decoded bytes and the number of padding characters. 
     */
    function decodeBlock(uint32 bs) public view returns (uint32 out, uint256 pad) {
        (pad, out) = (0, 0);
        uint8 b0 = uint8((bs >> 24) & 0xff);
        uint8 b1 = uint8((bs >> 16) & 0xff);
        uint8 b2 = uint8((bs >> 8) & 0xff);
        uint8 b3 = uint8((bs >> 0) & 0xff);

        // Convert octets to sextets using lookup table
        uint8 sext0 = b64Map[b0];
        uint8 sext1 = b64Map[b1];
        uint8 sext2 = b64Map[b2];
        uint8 sext3 = b64Map[b3];

        // If last two chars are "=" it is padding
        if (b2 == 0x3d) {
            pad += 1;
        }

        if (b3 == 0x3d) {
            pad += 1;
        }

        // Convert the 4-byte block to a 3-byte block
        out |= uint32(sext0 << 2 | sext1 >> 4);
        out |= uint32(((sext1 & 15) << 4 | sext2 >> 2)) << 8;
        out |= uint32(((sext2 & 3) << 6 | sext3)) << 16;
    }

    /*
     * @dev Decodes a uint32 containing 4 bytes into a uint32 with 3 bytes and the number of padding characters. This function will revert if an invalid base64 character is inputed.
     * @param bs The 4 input bytes packed to a uint32
     * @return Returns a 32-bit number containing three decoded bytes and the number of padding characters. 
     */
    function decodeBlockSafe(uint32 bs) public view returns (uint32 out, uint256 pad) {
        (pad, out) = (0, 0);
        uint8 b0 = uint8((bs >> 24) & 0xff);
        uint8 b1 = uint8((bs >> 16) & 0xff);
        uint8 b2 = uint8((bs >> 8) & 0xff);
        uint8 b3 = uint8((bs >> 0) & 0xff);

        // Convert octets to sextets using lookup table
        uint8 sext0 = b64Map[b0];
        uint8 sext1 = b64Map[b1];
        uint8 sext2 = b64Map[b2];
        uint8 sext3 = b64Map[b3];

        // Revert if a non-valid base64 char (should be "=" or "A")
        if (sext0 == 0) {
            assert(b0 == 0x3d || b0 == 0x41);
        }
        if (sext1 == 0) {
            assert(b1 == 0x3d || b1 == 0x41);
        }
        if (sext2 == 0) {
            assert(b2 == 0x3d || b2 == 0x41);
            if (b2 == 0x3d) {
                pad += 1;
            }
        }
        if (sext3 == 0) {
            assert(b3 == 0x3d || b3 == 0x41);
            if (b3 == 0x3d) {
                pad += 1;
            }
        }

        // Convert the 4-byte block to a 3-byte block
        out |= uint32(sext0 << 2 | sext1 >> 4);
        out |= uint32(((sext1 & 15) << 4 | sext2 >> 2)) << 8;
        out |= uint32(((sext2 & 3) << 6 | sext3)) << 16;
    }
}

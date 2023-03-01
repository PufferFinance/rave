// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

contract Base64Decoder {
    mapping(bytes1 => uint8) public b64Map;

    constructor() {
        bytes memory base64Chars = bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");

        // Populate LUT
        for (uint8 i = 0; i < base64Chars.length; i++) {
            b64Map[base64Chars[i]] = i;
        }
        // Add padding "=" char
        b64Map["="] = 0;
    }

    function decode(string memory _str) public view returns (string memory) {
        // require((bytes(_str).length % 4) == 0, "Length not multiple of 4");
        require((bytes(_str).length & 3) == 0, "Length not multiple of 4");
        bytes memory _bs = bytes(_str);

        uint256 i = 0;
        uint256 j = 0;
        // uint256 dec_length = (_bs.length / 4) * 3;
        uint256 dec_length = (_bs.length >> 2) * 3;
        bytes memory dec = new bytes(dec_length);

        uint256 padTotal = 0;
        uint256 pad;
        // Decode blocks of 4 bytes -> 3 bytes
        for (; i < _bs.length; i += 4) {
            (dec[j], dec[j + 1], dec[j + 2], pad) = decodeBlock(_bs[i], _bs[i + 1], _bs[i + 2], _bs[i + 3]);
            j += 3;
            padTotal += pad;
        }

        // Remove trailing zeroes encode as "=" or "=="
        uint256 outLen = j - padTotal;
        bytes memory res = new bytes(outLen);
        for (i = 0; i < outLen; i++) {
            res[i] = dec[i];
        }

        return string(res);
    }

    function decodeBlock(bytes1 b0, bytes1 b1, bytes1 b2, bytes1 b3)
        public
        view
        returns (bytes1 a0, bytes1 a1, bytes1 a2, uint256 pad)
    {
        pad = 0;
        // Convert octets to sextets using lookup table
        uint8 sext0 = b64Map[b0];
        uint8 sext1 = b64Map[b1];
        uint8 sext2 = b64Map[b2];
        uint8 sext3 = b64Map[b3];

        // Revert if a non-valid base64 char
        if (sext0 == 0) {
            assert(b0 == "=" || b0 == "A");
        }
        if (sext1 == 0) {
            assert(b1 == "=" || b1 == "A");
        }
        if (sext2 == 0) {
            assert(b2 == "=" || b2 == "A");
            if (b2 == "=") {
                pad += 1;
            }
        }
        if (sext3 == 0) {
            assert(b3 == "=" || b3 == "A");
            if (b3 == "=") {
                pad += 1;
            }
        }

        // Convert the 4-byte block to a 3-byte block
        a0 = bytes1(uint8((sext0 << 2 | sext1 >> 4)));
        a1 = bytes1(uint8(((sext1 & 15) << 4 | sext2 >> 2)));
        a2 = bytes1(uint8(((sext2 & 3) << 6 | sext3)));
    }
}

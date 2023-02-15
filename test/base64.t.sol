// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "src/base64.sol";

contract TestBase64 is Test {
    mapping(bytes1 => uint8) public b64Map;

    function setUp() public {
        bytes memory base64Chars = bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");

        for (uint8 i = 0; i < base64Chars.length; i++) {
            b64Map[base64Chars[i]] = i;
            // console.log("map[%s] = %s", uint8(base64Chars[i]), i);
        }
        // Add padding "=" char
        b64Map["="] = 0;
    }

    function testDecodeMan() public {
        string memory enc = "TWFu";
        string memory dec = decode(enc);
        console.log("decode '%s' -> '%s'", enc, dec);
        assertEq(dec, "Man");
    }

    function testDecodeHelloWorld() public {
        string memory enc = "SGVsbG8sIHdvcmxkIQ==";
        string memory dec = decode(enc);
        console.log("decode '%s' -> '%s'", enc, dec);
        assertEq(dec, "Hello, world!");
    }

    function decode(string memory _str) public view returns (string memory) {
        require((bytes(_str).length % 4) == 0, "Length not multiple of 4");
        bytes memory _bs = bytes(_str);
        console.logBytes(_bs);
        console.log("%s", _bs.length);

        uint256 i = 0;
        uint256 j = 0;
        uint256 dec_length = (_bs.length / 4) * 3;
        bytes memory dec = new bytes(dec_length);

        console.log("%s", dec_length);

        uint256 padTotal = 0;
        for (; i < _bs.length; i += 4) {
            console.log("i: %s, j: %s", i, j);
            uint256 pad;
            (dec[j], dec[j + 1], dec[j + 2], pad) = decodeBlock(_bs[i], _bs[i + 1], _bs[i + 2], _bs[i + 3]);
            j += 3;
            padTotal += pad;
            console.log("%s", string(dec));
            console.log("%s", vm.toString(dec));
        }

        console.log("j: %s", j);
        // expensive way to remove trailing zeroes
        // while (dec[--j] == 0) {}

        // bytes memory res = new bytes(j+1);
        // for (i = 0; i <= j; i++) {
        //     res[i] = dec[i];
        // }

        // return string(res);
        // return string(dec);
        console.log("Total pad: %s", padTotal);
        bytes memory res = new bytes(j-padTotal+1);
        for (i = 0; i <= j; i++) {
            res[i] = dec[i];
        }

        return string(res);
    }

    function decodeBlock(bytes1 b0, bytes1 b1, bytes1 b2, bytes1 b3)
        private
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
            pad += 1;
        }
        if (sext1 == 0) {
            assert(b1 == "=" || b1 == "A");
            pad += 1;
        }
        if (sext2 == 0) {
            assert(b2 == "=" || b2 == "A");
            pad += 1;
        }
        if (sext3 == 0) {
            assert(b3 == "=" || b3 == "A");
            pad += 1;
        }

        console.log("%s, %s", vm.toString(sext0), vm.toString(sext1));
        console.log("%s, %s", vm.toString(sext2), vm.toString(sext3));

        // Convert the 4-byte block to a 3-byte block
        a0 = bytes1(uint8((sext0 << 2 | sext1 >> 4)));
        a1 = bytes1(uint8(((sext1 & 15) << 4 | sext2 >> 2)));
        a2 = bytes1(uint8(((sext2 & 3) << 6 | sext3)));
    }

    function testDecodeIsvEnclaveQuoteBody() public {
        string memory enc =
            "AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAfAAAAAAAAANCud0d0wgZKYN2SVB/MfLizrN6g15PzsnonpE2/cedfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACk8eLeQq3kKFam57ApQyJ412rRw+hs7M1vL0ZTKGHCDAYVo7T4o+KD0jwJJV5RNg4AAAAAAAAAAAAAAAAAAAAA";

        string memory dec = decode(enc);
        // console.log("decode '%s' -> '%s'", enc, dec);
        // console.logBytes(bytes(dec));

        bytes memory expDec =
            hex"02000100800c00000d000d000000000042616c98d53c9712639447c9b0e7003f0000000000000000000000000000000014140b07ff800e000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000001f00000000000000d0ae774774c2064a60dd92541fcc7cb8b3acdea0d793f3b27a27a44dbf71e75f000000000000000000000000000000000000000000000000000000000000000083d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a4f1e2de42ade42856a6e7b029432278d76ad1c3e86ceccd6f2f46532861c20c0615a3b4f8a3e283d23c09255e51360e00000000000000000000000000000000";

        // assertEq(dec, vm.toString(expDec));
        // assertEq(vm.toString(bytes(dec)), string(expDec));
        assertEq(vm.toString(bytes(dec)), vm.toString(expDec));

        // assert(false);
        // assertEq(dec, vm.toString(expDec));

        // bytes(dec)[112:144]
        // string memory expMre = "d0ae774774c2064a60dd92541fcc7cb8b3acdea0d793f3b27a27a44dbf71e75f";

        // bytes(dec)[368:432]
        // string memory expPk = "0xa4f1e2de42ade42856a6e7b029432278d76ad1c3e86ceccd6f2f46532861c20c0615a3b4f8a3e283d23c09255e51360e";
    }
}

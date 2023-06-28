// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test, console } from "forge-std/Test.sol";
import { Base64Decoder } from "rave/Base64Decode.sol";
import { BytesFFIFuzzer, BytesHelper } from "test/utils/helper.sol";
import { Base64 } from "openzeppelin/utils/Base64.sol";

contract TestBase64 is Base64Decoder, Test, BytesFFIFuzzer {
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

    function testEncodeHelloWorld() public {
        bytes memory input = "Hello, world!";
        string memory enc = Base64.encode(input);
        assertEq(enc, "SGVsbG8sIHdvcmxkIQ==");
    }

    function testDecodeSentence() public {
        string memory enc = "UkFWZSBpcyB1c2VkIHRvIHZlcmlmeSBTR1ggcmVtb3RlIGF0dGVzdGF0aW9uJ3Mgb24gY2hhaW4=";
        string memory dec = decode(enc);
        console.log("decode '%s' -> '%s'", enc, dec);
        assertEq(dec, "RAVe is used to verify SGX remote attestation's on chain");
    }

    function testEncodeSentence() public {
        bytes memory input = "RAVe is used to verify SGX remote attestation's on chain";
        string memory enc = Base64.encode(input);
        assertEq(enc, "UkFWZSBpcyB1c2VkIHRvIHZlcmlmeSBTR1ggcmVtb3RlIGF0dGVzdGF0aW9uJ3Mgb24gY2hhaW4=");
    }

    function testDecodeIsvEnclaveQuoteBody() public {
        string memory enc =
            "AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAfAAAAAAAAANCud0d0wgZKYN2SVB/MfLizrN6g15PzsnonpE2/cedfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACk8eLeQq3kKFam57ApQyJ412rRw+hs7M1vL0ZTKGHCDAYVo7T4o+KD0jwJJV5RNg4AAAAAAAAAAAAAAAAAAAAA";

        string memory dec = decode(enc);

        bytes memory expDec =
            hex"02000100800c00000d000d000000000042616c98d53c9712639447c9b0e7003f0000000000000000000000000000000014140b07ff800e000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000001f00000000000000d0ae774774c2064a60dd92541fcc7cb8b3acdea0d793f3b27a27a44dbf71e75f000000000000000000000000000000000000000000000000000000000000000083d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a4f1e2de42ade42856a6e7b029432278d76ad1c3e86ceccd6f2f46532861c20c0615a3b4f8a3e283d23c09255e51360e00000000000000000000000000000000";
        assertEq(vm.toString(bytes(dec)), vm.toString(expDec));
    }

    function testEncodeIsvEnclaveQuoteBody() public {
        bytes memory input =
            hex"02000100800c00000d000d000000000042616c98d53c9712639447c9b0e7003f0000000000000000000000000000000014140b07ff800e000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000001f00000000000000d0ae774774c2064a60dd92541fcc7cb8b3acdea0d793f3b27a27a44dbf71e75f000000000000000000000000000000000000000000000000000000000000000083d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a4f1e2de42ade42856a6e7b029432278d76ad1c3e86ceccd6f2f46532861c20c0615a3b4f8a3e283d23c09255e51360e00000000000000000000000000000000";
        string memory enc = Base64.encode(input);
        assertEq(
            enc,
            "AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAfAAAAAAAAANCud0d0wgZKYN2SVB/MfLizrN6g15PzsnonpE2/cedfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACk8eLeQq3kKFam57ApQyJ412rRw+hs7M1vL0ZTKGHCDAYVo7T4o+KD0jwJJV5RNg4AAAAAAAAAAAAAAAAAAAAA"
        );
    }

    function testFuzzBase64Decode(bytes memory _m) public {
        // Verify not empty bytes for FFI compatibility
        vm.assume(_m.length > 1);
        vm.assume(BytesHelper.notAllZeroes(_m));

        // Convert the random bytes into valid utf-8 bytes
        bytes memory _msg = getFriendlyBytes(_m);

        // The msg will be a valid utf-8 hex string as input to bash FFI
        console.log("input string: %s", string(_msg));
        console.logBytes(_msg);

        // Run base64 encoding in python via ffi
        string[] memory cmds = new string[](3);
        cmds[0] = "python3";
        cmds[1] = "test/scripts/runBase64Encode.py";
        cmds[2] = string(_msg);
        bytes memory _encoded = vm.ffi(cmds);
        string memory _enc = string(_encoded);
        console.log(_enc);
        console.logBytes(_encoded);

        // base64 decode to recover the initial msg
        string memory _dec = decode(_enc);
        console.log("decode '%s' -> '%s'", _enc, _dec);
        assertEq(_dec, string(_msg));
    }
}

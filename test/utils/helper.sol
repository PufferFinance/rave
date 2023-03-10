// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

library BytesHelper {
    function notAllZeroes(bytes memory data) public pure returns (bool) {
        for (uint256 i = 0; i < data.length; i++) {
            if (data[i] != 0) {
                return true;
            }
        }
        return false;
    }
}

contract BytesFFIFuzzer is Test {
    // convert random fuzzed bytes -> hex string -> valid utf-8 bytes
    function getFriendlyBytes(bytes memory _fuzzedBytes) public pure returns (bytes memory) {
        return bytes(vm.toString(_fuzzedBytes));
    }
}

contract KeyGenHelper is Test {
    bytes PUBKEY;

    function newRsaKeypair() public {
        // Generate a new 4096b RSA private key
        string[] memory cmds = new string[](3);
        cmds[0] = "bash";
        cmds[1] = "test/scripts/runRSAKeygen.sh";
        cmds[2] = "4096";
        vm.ffi(cmds);
    }

    function readRsaPubKey() public {
        // Extract public key using openssl
        string[] memory cmds = new string[](2);
        cmds[0] = "bash";
        cmds[1] = "test/scripts/runPubKeyExtraction.sh";
        PUBKEY = vm.ffi(cmds);
    }

    function newX509Cert() public {
        // Generate a new 4096b RSA private key and x509 cert
        string[] memory cmds = new string[](3);
        cmds[0] = "bash";
        cmds[1] = "test/scripts/runX509Gen.sh";
        cmds[2] = "4096";
        vm.ffi(cmds);
    }

    function readX509PubKey() public {
        // Extract public key using openssl
        string[] memory cmds = new string[](2);
        cmds[0] = "bash";
        cmds[1] = "test/scripts/runX509PubKeyExtraction.sh";
        PUBKEY = vm.ffi(cmds);
    }
}

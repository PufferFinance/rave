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
}

// Helper functions to generate self-signed x509 and methods to extract relevant info
contract X509GenHelper is Test {
    bytes CERT_BYTES;
    bytes CERT_SIG;
    bytes MODULUS;

    string KEY_BITS = "512";
    string X509_NAME = "SelfSignedx509.pem";

    function newSelfSignedX509() public {
        // Generate a new KEY_BITS length RSA private key and self-sign an x509 certificate
        string[] memory cmds = new string[](4);
        cmds[0] = "bash";
        cmds[1] = "test/scripts/runX509Gen.sh";
        cmds[2] = KEY_BITS;
        cmds[3] = X509_NAME;
        vm.ffi(cmds);
    }

    function readX509Signature() public {
        // Extract signature from self-signed x509 cert
        string[] memory cmds = new string[](3);
        cmds[0] = "bash";
        cmds[1] = "test/scripts/runX509SigExtraction.sh";
        cmds[2] = X509_NAME;
        CERT_SIG = vm.ffi(cmds);
    }

    function readX509Modulus() public {
        // Extract modulus from self-signed x509
        string[] memory cmds = new string[](3);
        cmds[0] = "bash";
        cmds[1] = "test/scripts/runX509ModulusExtraction.sh";
        cmds[2] = X509_NAME;
        MODULUS = vm.ffi(cmds);
    }

    function readX509Body() public {
        // Extract self-signed x509 body
        string[] memory cmds = new string[](3);
        cmds[0] = "bash";
        cmds[1] = "test/scripts/runX509BodyExtraction.sh";
        cmds[2] = X509_NAME;
        CERT_BYTES = vm.ffi(cmds);
    }
}

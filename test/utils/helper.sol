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

    // convert random fuzzed bytes -> hex string -> valid utf-8 bytes
    function getFriendlyBytes32(bytes32 _fuzzedBytes) public pure returns (bytes memory) {
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
    bytes public CERT_BYTES;
    bytes public CERT_BODY_BYTES;
    bytes public CERT_SIG;
    bytes public MODULUS;
    bytes public EXPONENT = hex"010001";

    string KEY_BITS;
    string X509_NAME = "/tmp/SelfSignedx509.pem";
    string X509_PRIV_KEY_NAME = "/tmp/x509SigningKey.pem";

    constructor(string memory keyBits) {
        KEY_BITS = keyBits;
    }

    function newSelfSignedX509() public {
        // Generate a new KEY_BITS length RSA private key and self-sign an x509 certificate
        string[] memory cmds = new string[](5);
        cmds[0] = "bash";
        cmds[1] = "test/scripts/runX509Gen.sh";
        cmds[2] = KEY_BITS;
        cmds[3] = X509_NAME;
        cmds[4] = X509_PRIV_KEY_NAME;
        vm.ffi(cmds);
    }

    function readX509Cert() public {
        // Get DER-encoded self-signed x509 as hex string
        string[] memory cmds = new string[](3);
        cmds[0] = "bash";
        cmds[1] = "test/scripts/runX509GetDer.sh";
        cmds[2] = X509_NAME;
        CERT_BYTES = vm.ffi(cmds);
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
        CERT_BODY_BYTES = vm.ffi(cmds);
    }
}

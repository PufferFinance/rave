// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "src/RAVE.sol";
import "src/X509.sol";
import "ens-contracts/dnssec-oracle/BytesUtils.sol";
import "test/mocks/MockEvidence.sol";
import "test/utils/helper.sol";

abstract contract RAVETester is Test {
    using BytesUtils for *;

    MockEvidence m;
    RAVEBase c;

    function setUp() public virtual {}

    function test_VerifyRA() public view {
        bytes memory report = m.report();
        bytes memory sig = m.sig();
        bytes memory signingMod = m.signingMod();
        bytes memory signingExp = m.signingExp();
        bytes32 mrenclave = m.mrenclave();
        bytes32 mrsigner = m.mrsigner();
        bytes memory payload = m.payload();
        run_verifyRemoteAttestation(report, sig, signingMod, signingExp, mrenclave, mrsigner);
        // bytes memory gotPayload = c.verifyRemoteAttestation(report, sig, signingMod, signingExp, mrenclave, mrsigner);
        // assert(keccak256(gotPayload.substring(0, payload.length)) == keccak256(payload));
    }

    // Test gas
    function run_verifyRemoteAttestation(
        bytes memory report,
        bytes memory sig,
        bytes memory signingMod,
        bytes memory signingExp,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) {
        bytes memory gotPayload = c.verifyRemoteAttestation(report, sig, signingMod, signingExp, mrenclave, mrsigner);
        assert(keccak256(gotPayload.substring(0, payload.length)) == keccak256(payload));
    }

    function test_VerifyRave() public view {
        bytes memory report = m.report();
        bytes memory sig = m.sig();
        bytes memory signingCert = m.signingCert();
        bytes32 mrenclave = m.mrenclave();
        bytes32 mrsigner = m.mrsigner();
        bytes memory payload = m.payload();
        // Intel's root CA modulus
        bytes memory intelRootModulus =
            hex"9F3C647EB5773CBB512D2732C0D7415EBB55A0FA9EDE2E649199E6821DB910D53177370977466A6A5E4786CCD2DDEBD4149D6A2F6325529DD10CC98737B0779C1A07E29C47A1AE004948476C489F45A5A15D7AC8ECC6ACC645ADB43D87679DF59C093BC5A2E9696C5478541B979E754B573914BE55D32FF4C09DDF27219934CD990527B3F92ED78FBF29246ABECB71240EF39C2D7107B447545A7FFB10EB060A68A98580219E36910952683892D6A5E2A80803193E407531404E36B315623799AA825074409754A2DFE8F5AFD5FE631E1FC2AF3808906F28A790D9DD9FE060939B125790C5805D037DF56A99531B96DE69DE33ED226CC1207D1042B5C9AB7F404FC711C0FE4769FB9578B1DC0EC469EA1A25E0FF9914886EF2699B235BB4847DD6FF40B606E6170793C2FB98B314587F9CFD257362DFEAB10B3BD2D97673A1A4BD44C453AAF47FC1F2D3D0F384F74A06F89C089F0DA6CDB7FCEEE8C9821A8E54F25C0416D18C46839A5F8012FBDD3DC74D256279ADC2C0D55AFF6F0622425D1B";

        bytes memory intelRootExponent = hex"010001";

        run_rave(report, sig, signingCert, intelRootModulus, intelRootModulus, mrenclave, mrsigner);

        // Run rave to extract its payload
        // bytes memory gotPayload =
        //     c.rave(bytes(report), sig, signingCert, intelRootModulus, intelRootExponent, mrenclave, mrsigner);

        // // Verify it matches the expected payload
        // assert(keccak256(gotPayload.substring(0, payload.length)) == keccak256(payload));
    }

    // Test gas
    function run_rave(
        bytes memory report,
        bytes memory sig,
        bytes memory signingCert,
        bytes memory intelRootModulus,
        bytes memory intelRootModulus,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) {
        // Run rave to extract its payload
        bytes memory gotPayload =
            c.rave(bytes(report), sig, signingCert, intelRootModulus, intelRootExponent, mrenclave, mrsigner);

        // Verify it matches the expected payload
        assert(keccak256(gotPayload.substring(0, payload.length)) == keccak256(payload));
    }
}

contract TestHappyRAVE is RAVETester {
    function setUp() public override {
        m = new ValidBLSEvidenceJSONDecodedAndBase64Decoded();
        c = new RAVE();
    }
}

contract TestHappyRAVE_Base64Decode is RAVETester {
    function setUp() public override {
        m = new ValidBLSEvidenceJSONDecodedAndBase64Encoded();
        c = new RAVEWithBase64Decode();
    }
}

contract TestHappyRAVE_JSONDecodeAndBase64Decode is RAVETester {
    function setUp() public override {
        m = new ValidBLSEvidenceJSONEncodedAndBase64Encoded();
        c = new RAVEWithJSONDecodeAndBase64Decode();
    }
}

contract RaveFuzzer is Test, X509GenHelper, BytesFFIFuzzer {
    using BytesUtils for *;

    RAVEBase c;
    bool useJSONDecode;
    bool encodeQuote;

    constructor(bool _useJSONDecode, string memory _keyBits, bool _useCachedX509s, bool _encodeQuote)
        X509GenHelper(_keyBits)
    {
        // Save global
        useJSONDecode = _useJSONDecode;
        encodeQuote = _encodeQuote;

        if (_useCachedX509s) {
            console.log("Reading cached x509 values for numBits:", _keyBits);
            readCached();
        } else {
            console.log("Generated new X509 values for numBits:", _keyBits);
            setupFreshX509();
        }

        if (useJSONDecode) {
            c = new RAVEWithJSONDecodeAndBase64Decode();
        } else {
            c = new RAVEWithBase64Decode();
        }

        if (_encodeQuote) {
            c = new RAVE();
        }
    }

    function genNewEvidence(string memory mrenclave, string memory mrsigner, string memory payload)
        public
        returns (bytes memory, bytes memory)
    {
        assertEq(bytes(mrenclave).length, 66, "bad mre len");
        assertEq(bytes(mrsigner).length, 66, "bad mrs len");
        assertEq(bytes(payload).length, 130, "bad payload len");
        string[] memory cmds = new string[](8);
        cmds[0] = "python3";
        cmds[1] = "test/scripts/runSignRandomEvidence.py";
        cmds[2] = mrenclave;
        cmds[3] = mrsigner;
        cmds[4] = payload;
        cmds[5] = X509_PRIV_KEY_NAME;
        cmds[6] = "False";
        cmds[7] = "True";

        // Tell script to return entire report JSON as bytes to decode on-chain
        if (useJSONDecode) {
            cmds[6] = "True";
        }

        // Tell script to not to base64 decode quote in response
        if (encodeQuote) {
            cmds[7] = "False";
        }

        // Request .py sript to generate and sign mock RA evidence
        bytes memory resp = vm.ffi(cmds);

        // Script expected to return an x509 signature and the RA report (with an encoding depenent on useJSONDecode)
        (bytes memory signature, bytes memory values) = abi.decode(resp, (bytes, bytes));

        return (signature, values);
    }

    function runRAVE(bytes32 mrenclave, bytes32 mrsigner, bytes memory p) public {
        vm.assume(p.length >= 64);

        // Convert the random bytes into valid utf-8 bytes
        bytes memory payload = getFriendlyBytes(p).substring(0, 130);
        console.logBytes(payload);

        // Request new RA evidence
        (bytes memory signature, bytes memory reportValues) =
            genNewEvidence(vm.toString(mrenclave), vm.toString(mrsigner), string(payload));

        // Run rave to extract its payload
        bytes memory gotPayload = c.rave(reportValues, signature, CERT_BYTES, MODULUS, EXPONENT, mrenclave, mrsigner);

        // Verify it matches the expected payload
        assertEq(keccak256(gotPayload.substring(0, 64)), keccak256(p.substring(0, 64)));

        console.log("Passed test");
    }
}

// Test a single FuzzTest instance on one known input
contract RaveInstanceTest is RaveFuzzer {
    // Manually adjust the parameters
    bool constant _useJSONDecode = false;
    string constant keyBits = "1024";
    bool constant useCachedX509s = true;
    bool constant _encodeQuote = false;

    constructor() RaveFuzzer(_useJSONDecode, keyBits, useCachedX509s, _encodeQuote) {}

    function test() public {
        bytes32 mrenclave = hex"d0ae774774c2064a60dd92541fcc7cb8b3acdea0d793f3b27a27a44dbf71e75f";
        bytes32 mrsigner = hex"83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e";
        bytes memory p =
            hex"83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e";

        // Pass hardcoded values for sanity check
        runRAVE(mrenclave, mrsigner, p);
    }
}

// Test every FuzzTest parameterization on the same known input
contract RaveSanityTester is Test {
    bool useCachedX509s = false;

    function testOnSanityCheckedValues() public {
        bytes32 mrenclave = hex"d0ae774774c2064a60dd92541fcc7cb8b3acdea0d793f3b27a27a44dbf71e75f";
        bytes32 mrsigner = hex"83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e";
        bytes memory p =
            hex"83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e";

        bool[2] memory raveUsesJSONDecode = [true, false];
        string[5] memory rsaKeySize = ["512", "1024", "2048", "3072", "4096"];

        for (uint256 i = 0; i < raveUsesJSONDecode.length; i++) {
            for (uint256 j = 0; j < rsaKeySize.length; j++) {
                bool _useJSONDecode = raveUsesJSONDecode[i];
                bool _encodeQuote = _useJSONDecode;
                string memory _rsaKeySize = rsaKeySize[j];

                console.log(
                    "Testing against: (_rsaKeySize, _useJSONDecode, _encodeQuote) = ({}, {}, {})",
                    _rsaKeySize,
                    _useJSONDecode,
                    _encodeQuote
                );

                // Setup fuzzer by running openSSL via FFI or read from cache
                RaveFuzzer c = new RaveFuzzer(_useJSONDecode, _rsaKeySize, useCachedX509s, _encodeQuote);

                // Stall to prevent race conditions when testing against openSSL via FFI
                for (uint256 s = 0; s < 30 ** 7; s++) {}

                // Pass hardcoded values for sanity check
                c.runRAVE(mrenclave, mrsigner, p);
            }
        }
    }
}

// Fuzz test every FuzzTest parameterization
contract RaveFuzzTester is Test {
    RaveFuzzer[] c;
    // Warning, if true this will fail if all x509s do not already exist
    bool useCachedX509s = true;
    bool[2] raveUsesJSONDecode = [true, false];
    string[5] rsaKeySize = ["512", "1024", "2048", "3072", "4096"];
    uint256 numFuzzers = raveUsesJSONDecode.length * rsaKeySize.length;

    // Create all possible RAVEFuzzer (expensive so run only once)
    constructor() {
        for (uint256 i = 0; i < raveUsesJSONDecode.length; i++) {
            for (uint256 j = 0; j < rsaKeySize.length; j++) {
                bool _useJSONDecode = raveUsesJSONDecode[i];
                bool _encodeQuote = _useJSONDecode;
                string memory _rsaKeySize = rsaKeySize[j];

                // Setup fuzzer by running openSSL via FFI or read from cache
                c.push(new RaveFuzzer(_useJSONDecode, _rsaKeySize, useCachedX509s, _encodeQuote));

                // Stall to prevent race conditions when testing against openSSL via FFI
                for (uint256 s = 0; s < 30 ** 7; s++) {}
            }
        }
    }

    // Run a fuzz test sequentially on each RAVe parameterization
    function testRaveFuzz(bytes32 mrenclave, bytes32 mrsigner, bytes memory p) public {
        vm.assume(p.length >= 64);
        for (uint256 i = 0; i < numFuzzers; i++) {
            c[i].runRAVE(mrenclave, mrsigner, p);
        }
    }
}

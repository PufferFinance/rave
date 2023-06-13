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

    function testVerifyRA() public view {
        bytes memory report = m.report();
        bytes memory sig = m.sig();
        bytes memory signingMod = m.signingMod();
        bytes memory signingExp = m.signingExp();
        bytes32 mrenclave = m.mrenclave();
        bytes32 mrsigner = m.mrsigner();
        bytes memory payload = m.payload();
        bytes memory gotPayload = c.verifyRemoteAttestation(report, sig, signingMod, signingExp, mrenclave, mrsigner);
        assert(keccak256(gotPayload.substring(0, payload.length)) == keccak256(payload));
    }

    function testVerifyRave() public view {
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

        // Run rave to extract its payload
        bytes memory gotPayload =
            c.rave(bytes(report), sig, signingCert, intelRootModulus, intelRootExponent, mrenclave, mrsigner);

        // Verify it matches the expected payload
        assert(keccak256(gotPayload.substring(0, payload.length)) == keccak256(payload));
    }
}

contract TestHappyRAVE is RAVETester {
    function setUp() public override {
        m = new ValidBLSEvidenceJSONDecoded();
        c = new RAVE();
    }
}

contract TestHappyRAVEJSONDecode is RAVETester {
    function setUp() public override {
        m = new ValidBLSEvidenceJSONEncoded();
        c = new RAVEWithJSONDecode();
    }
}

abstract contract RaveFuzzTester is Test, X509GenHelper, BytesFFIFuzzer {
    using BytesUtils for *;

    RAVEBase c;
    bool useJSONDecode;

    constructor(bool _useJSONDecode) {
        useJSONDecode = _useJSONDecode;
    }

    function setUp() public virtual {
        // Generate new self-signed x509 cert
        newSelfSignedX509();

        // Read self-signed DER-encoded cert
        readX509Cert();
        console.log("Cert:");
        console.logBytes(CERT_BYTES);

        // Read self-signed cert's body (what was used as input to RSA-SHA256)
        readX509Body();
        console.log("CertBody:");
        console.logBytes(CERT_BODY_BYTES);

        // Read the self-signed cert's signature
        readX509Signature();
        console.log("Signature:");
        console.logBytes(CERT_SIG);

        // Read the public key's modulus
        readX509Modulus();
        console.log("Modulus:");
        console.logBytes(MODULUS);

        if (useJSONDecode) {
            c = new RAVEWithJSONDecode();
        } else {
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
        string[] memory cmds = new string[](7);
        cmds[0] = "python3";
        cmds[1] = "test/scripts/runSignRandomEvidence2.py";
        cmds[2] = mrenclave;
        cmds[3] = mrsigner;
        cmds[4] = payload;
        cmds[5] = X509_PRIV_KEY_NAME;
        cmds[6] = "False";
        if (useJSONDecode) {
            cmds[6] = "True";
        }
        bytes memory resp = vm.ffi(cmds);

        (bytes memory signature, bytes memory values) = abi.decode(resp, (bytes, bytes));

        return (signature, values);
    }

    function testGenMockEvidence(bytes32 mrenclave, bytes32 mrsigner, bytes memory p) public {
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
    }
}

contract Rave512BitFuzzTester is RaveFuzzTester {
    constructor() RaveFuzzTester(false) X509GenHelper("512") {}
}

contract Rave512BitFuzzTesterUsesJSONDecode is RaveFuzzTester {
    constructor() RaveFuzzTester(true) X509GenHelper("512") {}
}

contract Rave1024BitFuzzTester is RaveFuzzTester {
    constructor() RaveFuzzTester(false) X509GenHelper("1024") {}
}

contract Rave1024BitFuzzTesterUsesJSONDecode is RaveFuzzTester {
    constructor() RaveFuzzTester(true) X509GenHelper("1024") {}
}

contract Rave2048BitFuzzTester is RaveFuzzTester {
    constructor() RaveFuzzTester(false) X509GenHelper("2048") {}
}

contract Rave2048BitFuzzTesterUsesJSONDecode is RaveFuzzTester {
    constructor() RaveFuzzTester(true) X509GenHelper("2048") {}
}

contract Rave3076BitFuzzTester is RaveFuzzTester {
    constructor() RaveFuzzTester(false) X509GenHelper("3076") {}
}

contract Rave3076BitFuzzTesterUsesJSONDecode is RaveFuzzTester {
    constructor() RaveFuzzTester(true) X509GenHelper("3076") {}
}

contract Rave4096BitFuzzTester is RaveFuzzTester {
    constructor() RaveFuzzTester(false) X509GenHelper("4096") {}
}

contract Rave4096BitFuzzTesterUsesJSONDecode is RaveFuzzTester {
    constructor() RaveFuzzTester(true) X509GenHelper("4096") {}
}

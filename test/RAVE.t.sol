// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { RAVEBase } from "rave/RAVEBase.sol";
import { RAVE } from "rave/RAVE.sol";
import { BytesUtils } from "ens-contracts/dnssec-oracle/BytesUtils.sol";
import { MockEvidence, ValidBLSEvidence } from "test/mocks/MockEvidence.sol";
import { X509GenHelper, BytesFFIFuzzer } from "test/utils/helper.sol";
import { Test, console } from "forge-std/Test.sol";

abstract contract RAVETester is Test {
    using BytesUtils for *;

    MockEvidence m;
    RAVEBase c;

    function setUp() public virtual { }

    function test_VerifyRA() public view {
        bytes memory report = m.report();
        bytes memory sig = m.sig();
        bytes memory signingMod = m.signingMod();
        bytes memory signingExp = m.signingExp();
        bytes32 mrenclave = m.mrenclave();
        bytes32 mrsigner = m.mrsigner();
        bytes memory payload = m.payload();
        run_verifyRemoteAttestation(report, sig, signingMod, signingExp, mrenclave, mrsigner, payload);
    }

    // Test gas
    function run_verifyRemoteAttestation(
        bytes memory report,
        bytes memory sig,
        bytes memory signingMod,
        bytes memory signingExp,
        bytes32 mrenclave,
        bytes32 mrsigner,
        bytes memory expPayload
    ) public view {
        bytes memory gotPayload = c.verifyRemoteAttestation(report, sig, signingMod, signingExp, mrenclave, mrsigner);
        assert(keccak256(gotPayload.substring(0, expPayload.length)) == keccak256(expPayload));
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

        run_rave(report, sig, signingCert, intelRootModulus, intelRootExponent, mrenclave, mrsigner, payload);
    }

    // Test gas
    function run_rave(
        bytes memory report,
        bytes memory sig,
        bytes memory signingCert,
        bytes memory intelRootModulus,
        bytes memory intelRootExponent,
        bytes32 mrenclave,
        bytes32 mrsigner,
        bytes memory expPayload
    ) public view {
        // Run rave to extract its payload
        bytes memory gotPayload =
            c.rave(bytes(report), sig, signingCert, intelRootModulus, intelRootExponent, mrenclave, mrsigner);

        // Verify it matches the expected payload
        assert(keccak256(gotPayload.substring(0, expPayload.length)) == keccak256(expPayload));
    }
}

contract TestHappyRAVE is RAVETester {
    function setUp() public override {
        m = new ValidBLSEvidence();
        c = new RAVE();
    }
}

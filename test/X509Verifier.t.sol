// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test, console } from "forge-std/Test.sol";
import { X509GenHelper } from "test/utils/helper.sol";
import { Asn1Decode } from "rave/ASN1Decode.sol";
import { X509Verifier } from "rave/X509Verifier.sol";
import { RAVE } from "rave/RAVE.sol";
import { BytesUtils } from "ens-contracts/dnssec-oracle/BytesUtils.sol";
import { Base64 } from "openzeppelin/utils/Base64.sol";

contract TestIntelCert is Test {

    X509Verifier Certs = new X509Verifier();

    function testIntelCertChainFromSignedX509ExtractedBody() public {
        // DER encoded bytes of the Intel Leaf Signing x509 Certificate (excluding the header and signature)
        bytes memory certBytes =
            hex"30820309a003020102020900d107765d32a3b096300d06092a864886f70d01010b0500307e310b3009060355040613025553310b300906035504080c0243413114301206035504070c0b53616e746120436c617261311a3018060355040a0c11496e74656c20436f72706f726174696f6e3130302e06035504030c27496e74656c20534758204174746573746174696f6e205265706f7274205369676e696e67204341301e170d3136313132323039333635385a170d3236313132303039333635385a307b310b3009060355040613025553310b300906035504080c0243413114301206035504070c0b53616e746120436c617261311a3018060355040a0c11496e74656c20436f72706f726174696f6e312d302b06035504030c24496e74656c20534758204174746573746174696f6e205265706f7274205369676e696e6730820122300d06092a864886f70d01010105000382010f003082010a0282010100a97a2de0e66ea6147c9ee745ac0162686c7192099afc4b3f040fad6de093511d74e802f510d716038157dcaf84f4104bd3fed7e6b8f99c8817fd1ff5b9b864296c3d81fa8f1b729e02d21d72ffee4ced725efe74bea68fbc4d4244286fcdd4bf64406a439a15bcb4cf67754489c423972b4a80df5c2e7c5bc2dbaf2d42bb7b244f7c95bf92c75d3b33fc5410678a89589d1083da3acc459f2704cd99598c275e7c1878e00757e5bdb4e840226c11c0a17ff79c80b15c1ddb5af21cc2417061fbd2a2da819ed3b72b7efaa3bfebe2805c9b8ac19aa346512d484cfc81941e15f55881cc127e8f7aa12300cd5afb5742fa1d20cb467a5beb1c666cf76a368978b50203010001a381a43081a1301f0603551d2304183016801478437b76a67ebcd0af7e4237eb357c3b8701513c300e0603551d0f0101ff0404030206c0300c0603551d130101ff0402300030600603551d1f045930573055a053a051864f687474703a2f2f7472757374656473657276696365732e696e74656c2e636f6d2f636f6e74656e742f43524c2f5347582f4174746573746174696f6e5265706f72745369676e696e6743412e63726c";

        // SHA256 of the certificate bytes
        bytes32 _msgHash = sha256(certBytes);

        // sha256WithRSAEncryption signature from Intel's Root CA
        bytes memory certSig =
            hex"6708b61b5c2bd215473e2b46af99284fbb939d3f3b152c996f1a6af3b329bd220b1d3b610f6bce2e6753bded304db21912f385256216cfcba456bd96940be892f5690c260d1ef84f1606040222e5fe08e5326808212a447cfdd64a46e94bf29f6b4b9a721d25b3c4e2f62f58baed5d77c505248f0f801f9fbfb7fd752080095cee80938b339f6dbb4e165600e20e4a718812d49d9901e310a9b51d66c79909c6996599fae6d76a79ef145d9943bf1d3e35d3b42d1fb9a45cbe8ee334c166eee7d32fcdc9935db8ec8bb1d8eb3779dd8ab92b6e387f0147450f1e381d08581fb83df33b15e000a59be57ea94a3a52dc64bdaec959b3464c91e725bbdaea3d99e857e380a23c9d9fb1ef58e9e42d71f12130f9261d7234d6c37e2b03dba40dfdfb13ac4ad8e13fd3756356b6b50015a3ec9580b815d87c2cef715cd28df00bbf2a3c403ebf6691b3f05edd9143803ca085cff57e053eec2f8fea46ea778a68c9be885bc28225bc5f309be4a2b74d3a03945319dd3c7122fed6ff53bb8b8cb3a03c";

        // Intel's root CA modulus
        bytes memory intelRootModulus =
            hex"9F3C647EB5773CBB512D2732C0D7415EBB55A0FA9EDE2E649199E6821DB910D53177370977466A6A5E4786CCD2DDEBD4149D6A2F6325529DD10CC98737B0779C1A07E29C47A1AE004948476C489F45A5A15D7AC8ECC6ACC645ADB43D87679DF59C093BC5A2E9696C5478541B979E754B573914BE55D32FF4C09DDF27219934CD990527B3F92ED78FBF29246ABECB71240EF39C2D7107B447545A7FFB10EB060A68A98580219E36910952683892D6A5E2A80803193E407531404E36B315623799AA825074409754A2DFE8F5AFD5FE631E1FC2AF3808906F28A790D9DD9FE060939B125790C5805D037DF56A99531B96DE69DE33ED226CC1207D1042B5C9AB7F404FC711C0FE4769FB9578B1DC0EC469EA1A25E0FF9914886EF2699B235BB4847DD6FF40B606E6170793C2FB98B314587F9CFD257362DFEAB10B3BD2D97673A1A4BD44C453AAF47FC1F2D3D0F384F74A06F89C089F0DA6CDB7FCEEE8C9821A8E54F25C0416D18C46839A5F8012FBDD3DC74D256279ADC2C0D55AFF6F0622425D1B";

        bytes memory intelRootExponent = hex"010001";

        // The expected msg hash
        bytes32 expectedHash = hex"13472863bcbe2462fb4312ddda9d77ca41575d79760881eb1d2d6c9be2c40094";
        assertEq(expectedHash, _msgHash);

        require(Certs.verifyChildCert(certBytes, certSig, intelRootModulus, intelRootExponent));

        //require(Certs.verifyRSA(certBytes, certSig, intelRootModulus, intelRootExponent));
    }

    function testIntelCertChainFromSignedX509() public {
        // DER encoded bytes of the signed Intel Leaf Signing x509 Certificate (including the header and signature)
        bytes memory certBytes =
            hex"308204a130820309a003020102020900d107765d32a3b096300d06092a864886f70d01010b0500307e310b3009060355040613025553310b300906035504080c0243413114301206035504070c0b53616e746120436c617261311a3018060355040a0c11496e74656c20436f72706f726174696f6e3130302e06035504030c27496e74656c20534758204174746573746174696f6e205265706f7274205369676e696e67204341301e170d3136313132323039333635385a170d3236313132303039333635385a307b310b3009060355040613025553310b300906035504080c0243413114301206035504070c0b53616e746120436c617261311a3018060355040a0c11496e74656c20436f72706f726174696f6e312d302b06035504030c24496e74656c20534758204174746573746174696f6e205265706f7274205369676e696e6730820122300d06092a864886f70d01010105000382010f003082010a0282010100a97a2de0e66ea6147c9ee745ac0162686c7192099afc4b3f040fad6de093511d74e802f510d716038157dcaf84f4104bd3fed7e6b8f99c8817fd1ff5b9b864296c3d81fa8f1b729e02d21d72ffee4ced725efe74bea68fbc4d4244286fcdd4bf64406a439a15bcb4cf67754489c423972b4a80df5c2e7c5bc2dbaf2d42bb7b244f7c95bf92c75d3b33fc5410678a89589d1083da3acc459f2704cd99598c275e7c1878e00757e5bdb4e840226c11c0a17ff79c80b15c1ddb5af21cc2417061fbd2a2da819ed3b72b7efaa3bfebe2805c9b8ac19aa346512d484cfc81941e15f55881cc127e8f7aa12300cd5afb5742fa1d20cb467a5beb1c666cf76a368978b50203010001a381a43081a1301f0603551d2304183016801478437b76a67ebcd0af7e4237eb357c3b8701513c300e0603551d0f0101ff0404030206c0300c0603551d130101ff0402300030600603551d1f045930573055a053a051864f687474703a2f2f7472757374656473657276696365732e696e74656c2e636f6d2f636f6e74656e742f43524c2f5347582f4174746573746174696f6e5265706f72745369676e696e6743412e63726c300d06092a864886f70d01010b050003820181006708b61b5c2bd215473e2b46af99284fbb939d3f3b152c996f1a6af3b329bd220b1d3b610f6bce2e6753bded304db21912f385256216cfcba456bd96940be892f5690c260d1ef84f1606040222e5fe08e5326808212a447cfdd64a46e94bf29f6b4b9a721d25b3c4e2f62f58baed5d77c505248f0f801f9fbfb7fd752080095cee80938b339f6dbb4e165600e20e4a718812d49d9901e310a9b51d66c79909c6996599fae6d76a79ef145d9943bf1d3e35d3b42d1fb9a45cbe8ee334c166eee7d32fcdc9935db8ec8bb1d8eb3779dd8ab92b6e387f0147450f1e381d08581fb83df33b15e000a59be57ea94a3a52dc64bdaec959b3464c91e725bbdaea3d99e857e380a23c9d9fb1ef58e9e42d71f12130f9261d7234d6c37e2b03dba40dfdfb13ac4ad8e13fd3756356b6b50015a3ec9580b815d87c2cef715cd28df00bbf2a3c403ebf6691b3f05edd9143803ca085cff57e053eec2f8fea46ea778a68c9be885bc28225bc5f309be4a2b74d3a03945319dd3c7122fed6ff53bb8b8cb3a03c";

        // SHA256 of the certificate bytes
        bytes32 _msgHash = sha256(certBytes);

        // sha256WithRSAEncryption signature from Intel's Root CA
        bytes memory certSig =
            hex"6708b61b5c2bd215473e2b46af99284fbb939d3f3b152c996f1a6af3b329bd220b1d3b610f6bce2e6753bded304db21912f385256216cfcba456bd96940be892f5690c260d1ef84f1606040222e5fe08e5326808212a447cfdd64a46e94bf29f6b4b9a721d25b3c4e2f62f58baed5d77c505248f0f801f9fbfb7fd752080095cee80938b339f6dbb4e165600e20e4a718812d49d9901e310a9b51d66c79909c6996599fae6d76a79ef145d9943bf1d3e35d3b42d1fb9a45cbe8ee334c166eee7d32fcdc9935db8ec8bb1d8eb3779dd8ab92b6e387f0147450f1e381d08581fb83df33b15e000a59be57ea94a3a52dc64bdaec959b3464c91e725bbdaea3d99e857e380a23c9d9fb1ef58e9e42d71f12130f9261d7234d6c37e2b03dba40dfdfb13ac4ad8e13fd3756356b6b50015a3ec9580b815d87c2cef715cd28df00bbf2a3c403ebf6691b3f05edd9143803ca085cff57e053eec2f8fea46ea778a68c9be885bc28225bc5f309be4a2b74d3a03945319dd3c7122fed6ff53bb8b8cb3a03c";

        // Intel's root CA modulus
        bytes memory intelRootModulus =
            hex"9F3C647EB5773CBB512D2732C0D7415EBB55A0FA9EDE2E649199E6821DB910D53177370977466A6A5E4786CCD2DDEBD4149D6A2F6325529DD10CC98737B0779C1A07E29C47A1AE004948476C489F45A5A15D7AC8ECC6ACC645ADB43D87679DF59C093BC5A2E9696C5478541B979E754B573914BE55D32FF4C09DDF27219934CD990527B3F92ED78FBF29246ABECB71240EF39C2D7107B447545A7FFB10EB060A68A98580219E36910952683892D6A5E2A80803193E407531404E36B315623799AA825074409754A2DFE8F5AFD5FE631E1FC2AF3808906F28A790D9DD9FE060939B125790C5805D037DF56A99531B96DE69DE33ED226CC1207D1042B5C9AB7F404FC711C0FE4769FB9578B1DC0EC469EA1A25E0FF9914886EF2699B235BB4847DD6FF40B606E6170793C2FB98B314587F9CFD257362DFEAB10B3BD2D97673A1A4BD44C453AAF47FC1F2D3D0F384F74A06F89C089F0DA6CDB7FCEEE8C9821A8E54F25C0416D18C46839A5F8012FBDD3DC74D256279ADC2C0D55AFF6F0622425D1B";

        bytes memory intelRootExponent = hex"010001";

        bytes memory expectedLeafModulus =
            hex"A97A2DE0E66EA6147C9EE745AC0162686C7192099AFC4B3F040FAD6DE093511D74E802F510D716038157DCAF84F4104BD3FED7E6B8F99C8817FD1FF5B9B864296C3D81FA8F1B729E02D21D72FFEE4CED725EFE74BEA68FBC4D4244286FCDD4BF64406A439A15BCB4CF67754489C423972B4A80DF5C2E7C5BC2DBAF2D42BB7B244F7C95BF92C75D3B33FC5410678A89589D1083DA3ACC459F2704CD99598C275E7C1878E00757E5BDB4E840226C11C0A17FF79C80B15C1DDB5AF21CC2417061FBD2A2DA819ED3B72B7EFAA3BFEBE2805C9B8AC19AA346512D484CFC81941E15F55881CC127E8F7AA12300CD5AFB5742FA1D20CB467A5BEB1C666CF76A368978B5";
        bytes memory expectedLeafExponent = hex"010001";

        (bytes memory modulus, bytes memory exponent) =
            Certs.verifySignedX509(certBytes, intelRootModulus, intelRootExponent);

        // Correct the lengths since parsing may prepend an empty "0x00"
        uint256 lenGot = modulus.length;
        uint256 lenExpected = expectedLeafModulus.length;
        if (lenGot < lenExpected) {
            modulus = abi.encodePacked(new bytes(lenExpected - lenGot), modulus);
        } else if (lenExpected < lenGot) {
            expectedLeafModulus = abi.encodePacked(new bytes(lenGot - lenExpected), expectedLeafModulus);
        }

        assertEq(keccak256(modulus), keccak256(expectedLeafModulus));
    }
}

abstract contract TestCertChainVerification is Test, X509GenHelper {
    using BytesUtils for *;

    X509Verifier Certs = new X509Verifier();

    function setUp() public {
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

        // Read the private key pem.
        readX509PrivPEM();
        console.log("priv pem:");
        console.logBytes(CERT_PRIV_PEM);
    }

    function testSelfSignedCertIsValid() public view {
        // Verify the pre-extracted cert body was signed with MODULUS
        assert(Certs.verifyChildCert(CERT_BODY_BYTES, CERT_SIG, MODULUS, EXPONENT));
    }

    function testCertModulusExtracted() public {
        (bytes memory modulus,) = Certs.verifySignedX509(CERT_BYTES, MODULUS, EXPONENT);

        console.logBytes(modulus);
        return;

        // Correct the lengths since parsing may prepend an empty "0x00"
        uint256 lenGot = modulus.length;
        uint256 lenExpected = MODULUS.length;
        if (lenGot < lenExpected) {
            modulus = abi.encodePacked(new bytes(lenExpected - lenGot), modulus);
        } else if (lenExpected < lenGot) {
            MODULUS = abi.encodePacked(new bytes(lenGot - lenExpected), MODULUS);
        }

        assertEq(keccak256(modulus), keccak256(MODULUS));
    }

    function _helperPKCS1Padding(bool incNULL) private {
        // Calculate padded message.
        bytes32 digest = sha256(CERT_BYTES);
        bytes memory em = Certs.rsaPad(MODULUS, digest, incNULL);

        // Get DER-encoded self-signed x509 as hex string
        string[] memory cmds = new string[](8);
        cmds[0] = "python";
        cmds[1] = "test/scripts/rsa_pkcs1.py";
        cmds[2] = "-msg";
        cmds[3] = Base64.encode(CERT_BYTES);
        cmds[4] = "-pem_priv";
        cmds[5] = Base64.encode(CERT_PRIV_PEM);
        cmds[6] = "-inc_null";
        if(incNULL) {
            cmds[7] = "True";
        }
        if(!incNULL) {
            cmds[7] = "False";
        }

        bytes memory out = vm.ffi(cmds);

        // Expected padded msg.
        bytes memory expected = abi.decode(
            out, 
            (bytes)
        );

        assertEq(keccak256(em), keccak256(expected));
    }

    function testPKCS1Padding() public {
        if(MODULUS.length != 4096) return;
        _helperPKCS1Padding(true);
        _helperPKCS1Padding(false);
    }

    function testVerifyRSA() public {
        if(MODULUS.length != 4096) return;
        bool is_valid = Certs.verifyRSA(
            CERT_BODY_BYTES,
            CERT_SIG,
            MODULUS,
            EXPONENT
        );

        assertTrue(is_valid);
    }
}


contract Test512BitCertChain is TestCertChainVerification {
    constructor() X509GenHelper("512") { }
}

contract Test1024BitCertChain is TestCertChainVerification {
    constructor() X509GenHelper("1024") { }
}

contract Test2048BitCertChain is TestCertChainVerification {
    constructor() X509GenHelper("2048") { }
}

contract Test3072BitCertChain is TestCertChainVerification {
    constructor() X509GenHelper("3072") { }
}

contract Test4096BitCertChain is TestCertChainVerification {
    constructor() X509GenHelper("4096") { }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Asn1Decode, NodePtr } from "./ASN1Decode.sol";
import { RSAVerify } from "ens-contracts/dnssec-oracle/algorithms/RSAVerify.sol";
import { BytesUtils } from "ens-contracts/dnssec-oracle/BytesUtils.sol";
import { SafeMath } from "openzeppelin-contracts/contracts/utils/math/SafeMath.sol";
import { Math } from "openzeppelin-contracts/contracts/utils/math/Math.sol";
import { Utils } from "./Utils.sol";
import "./DateTime.sol";
import { Test, console } from "forge-std/Test.sol";

contract X509Verifier is Test, DateTime {
    using Asn1Decode for bytes;
    using BytesUtils for bytes;
    using Utils for bytes;


    bytes constant _SHA256_PAD_ID_WITH_NULL = hex"3031300d060960864801650304020105000420";
    bytes constant _SHA256_PAD_ID_WITHOUT_NULL = hex"302f300b06096086480165030402010420";
    bytes constant _CERT_PUB_ALG = hex"2A864886F70D010101";
    bytes constant _CERT_SIG_ALG = hex"2a864886f70d01010b";

    bytes constant _INTEL_ROOT_MOD = hex"9F3C647EB5773CBB512D2732C0D7415EBB55A0FA9EDE2E649199E6821DB910D53177370977466A6A5E4786CCD2DDEBD4149D6A2F6325529DD10CC98737B0779C1A07E29C47A1AE004948476C489F45A5A15D7AC8ECC6ACC645ADB43D87679DF59C093BC5A2E9696C5478541B979E754B573914BE55D32FF4C09DDF27219934CD990527B3F92ED78FBF29246ABECB71240EF39C2D7107B447545A7FFB10EB060A68A98580219E36910952683892D6A5E2A80803193E407531404E36B315623799AA825074409754A2DFE8F5AFD5FE631E1FC2AF3808906F28A790D9DD9FE060939B125790C5805D037DF56A99531B96DE69DE33ED226CC1207D1042B5C9AB7F404FC711C0FE4769FB9578B1DC0EC469EA1A25E0FF9914886EF2699B235BB4847DD6FF40B606E6170793C2FB98B314587F9CFD257362DFEAB10B3BD2D97673A1A4BD44C453AAF47FC1F2D3D0F384F74A06F89C089F0DA6CDB7FCEEE8C9821A8E54F25C0416D18C46839A5F8012FBDD3DC74D256279ADC2C0D55AFF6F0622425D1B";
    bytes constant _INTEL_ROOT_EXP = hex"010001";

    // Intel SGX Attestation Report Signing [subject] (issuer blank)
    bytes constant _SGX_REPORT_SIGNING_SUBJECT = hex"310b3009060355040613025553310b300906035504080c0243413114301206035504070c0b53616e746120436c617261311a3018060355040a0c11496e74656c20436f72706f726174696f6e3130302e06035504030c27496e74656c20534758204174746573746174696f6e205265706f7274205369676e696e67204341";

    bytes constant _SGX_REPORT_SIGNING_ISSUER = hex"310b3009060355040613025553310b300906035504080c0243413114301206035504070c0b53616e746120436c617261311a3018060355040a0c11496e74656c20436f72706f726174696f6e312d302b06035504030c24496e74656c20534758204174746573746174696f6e205265706f7274205369676e696e67";

    // Intel SGX Attestation Report Root CA Signing [subject and issuer]
    bytes constant _SGX_ROOT_SA_SUBJECT = hex"310b3009060355040613025553310b300906035504080c0243413114301206035504070c0b53616e746120436c617261311a3018060355040a0c11496e74656c20436f72706f726174696f6e3130302e06035504030c27496e74656c20534758204174746573746174696f6e205265706f7274205369676e696e67204341";

    // 06092a864886f70d01010b0500

    constructor() { }

    /*
     * @dev Verifies an x509 certificate was signed (RSASHA256) by the supplied public key. 
     * @param childCertBody The DER-encoded body (preimage) of the x509   child certificate
     * @param certSig The RSASHA256 signature of the childCertBody
     * @param parentMod The modulus of the parent certificate's public RSA key
     * @param parentExp The exponent of the parent certificate's public RSA key
     * @return Returns true if this childCertBody was signed by the parent's RSA private key
     */
    function verifyChildCert(
        bytes memory childCertBody,
        bytes memory certSig,
        bytes memory parentMod,
        bytes memory parentExp
    ) public view returns (bool) {
        // Recover the digest using parent's public key
        (bool success, bytes memory res) = RSAVerify.rsarecover(parentMod, parentExp, certSig);
        // Digest is last 32 bytes of res
        bytes32 recovered = res.readBytes32(res.length - 32);
        return success && recovered == sha256(childCertBody);
    }

    // withNULL seems true by default.
    function rsaPad(bytes memory mod, bytes32 digest, bool withNULL) public pure returns (bytes memory) {
        // RSA pub key 'size' / bit length.
        uint256 modBits = SafeMath.mul(mod.length, 8);
        uint256 emBits = SafeMath.sub(modBits, 1);
        uint256 emLen = Math.ceilDiv(emBits, 8);

        // Select digest OID portion based on bool flag.
        bytes memory digestOID;
        if(withNULL) {
            digestOID = _SHA256_PAD_ID_WITH_NULL;
        } else {
            digestOID = _SHA256_PAD_ID_WITHOUT_NULL;
        }

        // Is message long enough?
        uint256 tLen = SafeMath.add(digestOID.length, digest.length);
        if(emLen < SafeMath.add(tLen, 11)) {
            revert();
        }

        //        (1)       (2)      (3)   (4)         (5)
        // out = 00 01 (FF * ps_len) 00 SHA256ID... MSG_DIGEST
        uint256 psLen = SafeMath.sub(SafeMath.sub(emLen, tLen), 3);
        uint256 outLen = SafeMath.add(SafeMath.add(3, psLen), tLen);
        bytes memory out = new bytes(outLen);

        // (1): Leading 00 FF bytes.
        out[0] = hex"00";
        out[1] = hex"01";

        // (2): Add FF section to padding.
        uint256 p = 2; uint256 i = 0;
        for(i = 0; i < psLen; i++) {
            out[p++] = hex"ff";
        }

        // (3): Followed by 00.
        out[p++] = hex"00";

        // (4): Digest algorithm ID.
        for(i = 0; i < digestOID.length; i++) {
            out[p++] = digestOID[i];
        }

        // (5): Digest of the message to be padded.
        for(i = 0; i < digest.length; i++) {
            out[p++] = digest[i];
        }

        return out;
    }

    /*
        Verifies an RSA 'signature' (encryption over a message)
        matches what is specified in PKCS#1. Note: that the
        format of this encoding allows for the digest algorithm
        to include an optional 'NULL parameter.' It is assumed
        this is included and hence we don't test for a valid
        sig for a message where this parameter isn't include.
        But regular implementations of RSA verification do this.
    */
    function verifyRSA(
        bytes memory message,
        bytes memory sig,
        bytes memory mod,
        bytes memory exp
    ) public view returns (bool) {
        // The signature len must match the modulus length.
        if(sig.length != mod.length) {
            console.log(sig.length);
            console.log(mod.length);
            console.log("sig len error");
            return false;
        }

        // Invalid msg length.
        // ((2 ** 64) - 1).
        // There's a practical limit to the msg size for sha256.
        if(message.length > 18446744073709551615) {
            console.log("msg error");
            return false;
        }

        // Recover the PKCS#1 encoded message from the signature.
        // Message gets encoded according to rfc8017#section-9.2.
        // That becomes the value input to sha256.
        (bool success, bytes memory res) = RSAVerify.rsarecover(
            mod,
            exp,
            sig
        );

        /*
        The message to encrypt is padded such that the length
        matches the modulus. To 'compress' the message sha256 is
        used yielding a 32 byte digest. The digest is then
        prefixed according to the PKCS#1 padding scheme.
        Encryption of the result becomes the full signature.
        */
        bytes32 digest = sha256(message);
        bytes memory encodedMsg = rsaPad(mod, digest, true);
        bytes memory encodedMsg2 = rsaPad(mod, digest, false);

        console.logBytes(res);
        console.logBytes(encodedMsg);
        console.logBytes(encodedMsg2);

        // Compare recovered digest to encoded input digest.
        return success && (keccak256(res) == keccak256(encodedMsg));
    }

    function toX509Time(bytes memory x509Time) public pure returns (uint) {
        uint16 yrs;  uint8 mnths;
        uint8  dys;  uint8 hrs;
        uint8  mins; uint8 secs;
        uint8  offset;

        if (x509Time.length == 13) {
        if (uint8(x509Time[0])-48 < 5) yrs += 2000;
        else yrs += 1900;
        }
        else {
        yrs += (uint8(x509Time[0])-48) * 1000 + (uint8(x509Time[1])-48) * 100;
        offset = 2;
        }
        yrs +=  (uint8(x509Time[offset+0])-48)*10 + uint8(x509Time[offset+1])-48;
        mnths = (uint8(x509Time[offset+2])-48)*10 + uint8(x509Time[offset+3])-48;
        dys +=  (uint8(x509Time[offset+4])-48)*10 + uint8(x509Time[offset+5])-48;
        hrs +=  (uint8(x509Time[offset+6])-48)*10 + uint8(x509Time[offset+7])-48;
        mins += (uint8(x509Time[offset+8])-48)*10 + uint8(x509Time[offset+9])-48;
        secs += (uint8(x509Time[offset+10])-48)*10 + uint8(x509Time[offset+11])-48;

        return toTimestamp(yrs, mnths, dys, hrs, mins, secs);
    }

    /*
     * @dev specs: https://www.ietf.org/rfc/rfc5280.txt
     * @dev     Certificate  ::=  SEQUENCE  {
     * @dev         tbsCertificate       TBSCertificate,
     * @dev         signatureAlgorithm   AlgorithmIdentifier,
     * @dev         signatureValue       BIT STRING  }
     * @dev
     * @dev     TBSCertificate  ::=  SEQUENCE  {
     * @dev         version         [0]  EXPLICIT Version DEFAULT v1,
     * @dev         serialNumber         CertificateSerialNumber,
     * @dev         signature            AlgorithmIdentifier,
     * @dev         issuer               Name,
     * @dev         validity             Validity,
     * @dev         subject              Name,
     * @dev         subjectPublicKeyInfo SubjectPublicKeyInfo,
     * @dev         issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     * @dev                              -- If present, version MUST be v2 or v3
     * @dev         subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     * @dev                              -- If present, version MUST be v2 or v3
     * @dev         extensions      [3]  EXPLICIT Extensions OPTIONAL
     * @dev                              -- If present, version MUST be v3
     * @dev         }
     * @dev Verifies an x509 certificate was signed (RSASHA256) by the parent's
     * @dev supplied modulus and exponent, then returns the child x509's modulus and exponent.
     * @param cert The DER-encoded signed x509 certificate.
     * @param parentMod The parent RSA modulus.
     * @param parentExp The parent RSA exponent.
     * @return Returns the RSA modulus and exponent of the signed x509 certificate iff it was signed by the parent.
     */
    function verifySignedX509(bytes memory cert, bytes memory parentMod, bytes memory parentExp)
        public
        view
        returns (bytes memory, bytes memory)
    {
        /*
        Test code calls this function directly
        using self-signed certs. Consequently, they
        will have different mods and exps to Intel.
        Extended checks for issuer and subject will
        be disabled in this case.
        */
        bool extended_checks = false;
        if(
            (parentMod.compare(_INTEL_ROOT_MOD) == 0)
                &&
            (parentExp.compare(_INTEL_ROOT_EXP) == 0)
        ) {
            extended_checks = true;
        }
        console.log(extended_checks);

        // Traverse to first in sequence (the tbsCertificate)
        uint256 tbsPtr = cert.firstChildOf(cert.root());

        // Extracts the TBSCerificate (what is used as input to RSA-SHA256)
        //bytes memory certBody = cert.allBytesAt(tbsPtr);

        // Top level traverse to signatureAlgorithm
        uint256 sigAlgPtr = cert.nextSiblingOf(tbsPtr);
        require(
            _CERT_SIG_ALG.compare(
                cert.bytesAt(
                    cert.firstChildOf(sigAlgPtr)
                )
            ) == 0
        );

        // Top level traverse to signatureValue
        uint256 sigPtr = cert.nextSiblingOf(sigAlgPtr);

        // Extracts the signed certificate body
        bytes memory signature = cert.bytesAt(sigPtr);

        // Verify the parent signed the certBody
        require(verifyChildCert(cert.allBytesAt(tbsPtr), signature, parentMod, parentExp), "verifyChildCert fail");
        //require(verifyRSA(certBody, signature, parentMod, parentExp), "verifyChildCert fail");

        //  ----------------
        // Begin traversing the tbsCertificate
        //  ----------------

        // Traverse to first child of tbsCertificate
        uint256 ptr = cert.firstChildOf(tbsPtr);

        // Account for v1 vs v3
        if (cert[NodePtr.type_index(ptr)] == 0xa0) {
            ptr = cert.nextSiblingOf(ptr);
        }

        // Extract serialNumber (CertificateSerialNumber)
        // uint256 serialNumber = uint160(cert.uintAt(ptr));

        // Skip the next 3 fields (signature, issuer, validity, subject)
        ptr = cert.nextSiblingOf(ptr); // point to signature
        ptr = cert.nextSiblingOf(ptr); // point to issuer
        console.log("issuer...");
        if(extended_checks) {
            require(
                _SGX_REPORT_SIGNING_SUBJECT.compare(
                    cert.bytesAt(ptr)
                ) == 0
            );
        }
        

        ptr = cert.nextSiblingOf(ptr); // point to validity
        //ptr = cert.firstChildOf(ptr);

        // Arrive at the validity field
        // todo verifiy validity timestamps
        console.log("Valid before unix = ");

        console.logBytes(cert.bytesAt(ptr));
        console.logBytes(cert.bytesAt(cert.firstChildOf(ptr)));

        // Valid before.
        ptr = cert.firstChildOf(ptr);
        uint x = toX509Time(cert.bytesAt(ptr));
        console.log(x);

        // Valid after.
        ptr = cert.nextSiblingOf(ptr);
        x = toX509Time(cert.bytesAt(ptr));
        console.log(x);

        //ptr = cert.firstChildOf(ptr); 
        //x = toX509Time(cert.bytesAt(cert.firstChildOf(ptr)));
        //console.log(x);


        // Arrive at the validity field
        // todo verifiy validity timestamps
        // uint256 validityPtr = ptr;
        // bytes memory validNotBefore = cert.bytesAt(validityPtr);
        // console.logBytes(validNotBefore);
        // uint40 validNotBefore = uint40(toTimestamp(cert.bytesAt(validityPtr)));
        // console.log("validNotBefore: %s", validNotBefore);
        // validityPtr = cert.nextSiblingOf(validityPtr);
        // bytes memory validNotAfter = cert.bytesAt(validityPtr);
        // console.logBytes(validNotAfter);
        // uint40 validNotAfter = uint40(toTimestamp(cert.bytesAt(validityPtr)));
        // console.log("validNotAfter: %s", validNotAfter);
        // Traverse until the subjectPublicKeyInfo field


        ptr = cert.nextSiblingOf(ptr); // point to subject
        console.log("subject");
        console.logBytes(cert.bytesAt(ptr));
        if(extended_checks) {
            require(
                _SGX_REPORT_SIGNING_ISSUER.compare(
                    cert.bytesAt(ptr)
                ) == 0
            );
        }


        ptr = cert.nextSiblingOf(ptr); // point to subjectPublicKeyInfo

        // Enter subjectPublicKeyInfo
        ptr = cert.firstChildOf(ptr); // point to subjectPublicKeyInfo.algorithm

        // Require the pubkey algorithm to be RSA.
        require(
            _CERT_PUB_ALG.compare(
                cert.bytesAt(
                    cert.firstChildOf(ptr)
                )
            ) == 0
        );

        ptr = cert.nextSiblingOf(ptr); // point to subjectPublicKeyInfo.subjectPublicKey

        // Extract DER-encoded RSA public key
        bytes memory pubKey = cert.bitstringAt(ptr);

        // Extract RSA modulus
        uint256 pkPtr = pubKey.root();
        pkPtr = pubKey.firstChildOf(pkPtr);
        bytes memory modulus = pubKey.bytesAt(pkPtr);
        //modulus = abi.encodePacked(modulus.readBytesN(1, modulus.length));

        // Extract RSA exponent
        pkPtr = pubKey.nextSiblingOf(pkPtr);
        bytes memory exponent = pubKey.bytesAt(pkPtr);

        return (modulus, exponent);
    }

    /*
     * @dev Verifies the x509 certificate hasn't expired
     * @param certBody The DER-encoded body (preimage) of the x509 
     * @return Returns ...
     */
    function notExpired(bytes calldata certBody) public view returns (bool) {
        // TODO
        return true;
    }
}

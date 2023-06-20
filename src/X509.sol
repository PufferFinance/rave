// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "src/ASN1Decode.sol";
import "ens-contracts/dnssec-oracle/algorithms/RSAVerify.sol";
import "ens-contracts/dnssec-oracle/BytesUtils.sol";

library X509Verifier {
    using Asn1Decode for bytes;
    using BytesUtils for bytes;

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
        // Pointer to top level asn1 object: Sequence{tbsCertificate, signatureAlgorithm, signatureValue}
        uint256 root = cert.root();

        // Traverse to first in sequence (the tbsCertificate)
        uint256 tbsPtr = cert.firstChildOf(root);

        // Extracts the TBSCerificate (what is used as input to RSA-SHA256)
        bytes memory certBody = cert.allBytesAt(tbsPtr);

        // Top level traverse to signatureAlgorithm
        uint256 sigAlgPtr = cert.nextSiblingOf(tbsPtr);

        // Top level traverse to signatureValue
        uint256 sigPtr = cert.nextSiblingOf(sigAlgPtr);

        // Extracts the signed certificate body
        bytes memory signature = cert.bytesAt(sigPtr);

        // Verify the parent signed the certBody
        require(verifyChildCert(certBody, signature, parentMod, parentExp), "verifyChildCert fail");

        //  ----------------
        // Begin traversing the tbsCertificate
        //  ----------------

        // Traverse to first child of tbsCertificate
        uint256 ptr = cert.firstChildOf(tbsPtr);

        // Account for v1 vs v3
        if (cert[NodePtr.ixs(ptr)] == 0xa0) {
            ptr = cert.nextSiblingOf(ptr);
        }

        // Extract serialNumber (CertificateSerialNumber)
        // uint256 serialNumber = uint160(cert.uintAt(ptr));

        // Skip the next 3 fields (signature, issuer, validity, subject)
        ptr = cert.nextSiblingOf(ptr); // point to signature
        ptr = cert.nextSiblingOf(ptr); // point to issuer
        ptr = cert.nextSiblingOf(ptr); // point to validity

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
        ptr = cert.nextSiblingOf(ptr); // point to subjectPublicKeyInfo

        // Enter subjectPublicKeyInfo
        ptr = cert.firstChildOf(ptr); // point to subjectPublicKeyInfo.algorithm
        ptr = cert.nextSiblingOf(ptr); // point to subjectPublicKeyInfo.subjectPublicKey

        // Extract DER-encoded RSA public key
        bytes memory pubKey = cert.bitstringAt(ptr);

        // Extract RSA modulus
        uint256 pkPtr = pubKey.root();
        pkPtr = pubKey.firstChildOf(pkPtr);
        bytes memory modulus = pubKey.bytesAt(pkPtr);

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

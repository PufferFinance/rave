pragma solidity ^0.8.13;

import "src/ASN1Decode.sol";
import "ens-contracts/dnssec-oracle/algorithms/RSAVerify.sol";
import "ens-contracts/dnssec-oracle/BytesUtils.sol";

library X509Verifier {
    using BytesUtils for *;

    /*
     * @dev Verifies an x509 certificate was signed (RSASHA256) by the supplied public key. 
     * @param childCertBody The DER-encoded body (preimage) of the x509   child certificate
     * @param certSig The RSASHA256 signature of the childCertBody
     * @param parentMod The modulus of the parent certificate's public RSA key
     * @param parentExp The exponent of the parent certificate's public RSA key
     * @return Returns true if this childCertBody was signed by the parent's RSA private key
     */
    function verifyChildCert(
        bytes calldata childCertBody,
        bytes calldata certSig,
        bytes calldata parentMod,
        bytes calldata parentExp
    ) public view returns (bool) {
        // Recover the digest using parent's public key
        (bool success, bytes memory res) = RSAVerify.rsarecover(parentMod, parentExp, certSig);
        // Digest is last 32 bytes of res
        bytes32 recovered = res.readBytes32(res.length - 32);
        return success && recovered == sha256(childCertBody);
    }

    /*
     * @dev Verifies an x509 certificate was signed (RSASHA256) by the supplied public key. 
     * @param certBody The DER-encoded body (preimage) of the x509 
     * @return Returns ...
     */
    function getCertPubKey(bytes calldata certBody) public view {
        // Recover the digest using parent's public key
        // TODO
    }

    /*
     * @dev Verifies the x509 certificate hasn't expired
     * @param certBody The DER-encoded body (preimage) of the x509 
     * @return Returns ...
     */
    function notExpired(bytes calldata certBody) public view returns (bool) {
        // Recover the digest using parent's public key
        // TODO
        return true;
    }
}

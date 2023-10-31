// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title IRave interface
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 * @notice IRave interface
 */
interface IRave {
    /**
     * Bad report signature
     */
    error BadReportSignature();

    /*
    * @dev Verifies that the leafX509Cert was signed by the expected signer (signingMod, signingExp). 
        Then uses leafX509Cert RSA public key to verify the signature over the report, sig. 
        The trusted report is verified for correct fields and then the enclave' 64 byte commitment is extracted. 
    * @param report The attestation evidence report from IAS.
    * @param sig The RSA-SHA256 signature over the report.
    * @param leafX509Cert The signed leaf x509 certificate.
    * @param signingMod The expected signer's RSA modulus
    * @param signingExp The expected signer's RSA exponent
    * @param mrenclave The expected enclave measurement.
    * @param mrsigner The expected enclave signer.
    * @return The 64 byte payload from the report.
    */
    function rave(
        bytes calldata report,
        bytes memory sig,
        bytes memory leafX509Cert,
        bytes memory signingMod,
        bytes memory signingExp,
        bytes memory mrenclave,
        bytes memory mrsigner
    ) external view returns (bytes memory payload);

    /*
    * @dev Verifies that this report was signed by the expected signer, then extracts out the report's 64 byte payload.
    * @param report The attestation evidence report from IAS.
    * @param sig The RSA-SHA256 signature over the report.
    * @param signingMod The expected signer's RSA modulus
    * @param signingExp The expected signer's RSA exponent
    * @param mrenclave The expected enclave measurement.
    * @param mrsigner The expected enclave signer.
    * @return The 64 byte payload from the report.
    */
    function verifyRemoteAttestation(
        bytes calldata report,
        bytes memory sig,
        bytes memory signingMod,
        bytes memory signingExp,
        bytes memory mrenclave,
        bytes memory mrsigner
    ) external view returns (bytes memory payload);
}

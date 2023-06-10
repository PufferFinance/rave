// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "src/X509.sol";
import "src/Base64Decode.sol";
import "src/JSONBuilder.sol";
import "ens-contracts/dnssec-oracle/algorithms/RSAVerify.sol";
import "ens-contracts/dnssec-oracle/BytesUtils.sol";

import "forge-std/Test.sol";

contract RAVE2 is Base64Decoder, JSONBuilder, Test {
    using BytesUtils for *;

    uint256 constant MAX_JSON_ELEMENTS = 19;
    uint256 constant QUOTE_BODY_LENGTH = 432;
    uint256 constant MRENCLAVE_OFFSET = 112;
    uint256 constant MRSIGNER_OFFSET = 176;
    uint256 constant PAYLOAD_OFFSET = 368;
    uint256 constant PAYLOAD_SIZE = 64;

    bytes32 constant OK_STATUS = keccak256("OK");
    bytes32 constant HARDENING_STATUS = keccak256("SW_HARDENING_NEEDED");

    constructor() {}

    /*
    * @dev Verifies the RSA-SHA256 signature of the attestation report.
    * @param _report The attestation evidence report from IAS.
    * @param _sig The RSA-SHA256 signature over the report.
    * @param _signingMod The expected signer's RSA modulus
    * @param _signingExp The expected signer's RSA exponent
    * @return True if the signature is valid
    */
    function verifyReportSignature(
        bytes memory _report,
        bytes memory _sig,
        bytes memory _signingMod,
        bytes memory _signingExp
    ) public view returns (bool) {
        // Use _signingPK to verify _sig is the RSA signature over sha256(_report)
        (bool _success, bytes memory _got) = RSAVerify.rsarecover(_signingMod, _signingExp, _sig);
        // Last 32 bytes is recovered signed digest
        bytes32 _recovered = _got.readBytes32(_got.length - 32);
        return _success && _recovered == sha256(_report);
    }

    /*
    * @dev Parses a report, verifies the fields are correctly set, and extracts the enclave' 64 byte commitment.
    * @param _report The attestation evidence report from IAS.
    * @param _mrenclave The expected enclave measurement.
    * @param _mrsigner The expected enclave signer.
    * @return The 64 byte payload if the mrenclave and mrsigner values were correctly set.
    */
    function verifyReportContents(Values memory _reportValues, bytes32 _mrenclave, bytes32 _mrsigner)
        public
        view
        returns (bytes memory _payload)
    {
        // check enclave status
        bytes32 status = keccak256(_reportValues.isvEnclaveQuoteStatus);
        require(status == OK_STATUS || status == HARDENING_STATUS, "bad isvEnclaveQuoteStatus");

        // base64 decode quote body
        bytes memory _quoteBody = bytes(decode(string(_reportValues.isvEnclaveQuoteBody)));
        assert(_quoteBody.length == QUOTE_BODY_LENGTH);

        // Verify report's MRENCLAVE matches the expected
        bytes32 _mre = _quoteBody.readBytes32(MRENCLAVE_OFFSET);
        require(_mre == _mrenclave);

        // Verify report's MRSIGNER matches the expected
        bytes32 _mrs = _quoteBody.readBytes32(MRSIGNER_OFFSET);
        require(_mrs == _mrsigner);

        // Verify report's <= 64B payload matches the expected
        _payload = _quoteBody.substring(PAYLOAD_OFFSET, PAYLOAD_SIZE);
    }

    /*
    * @dev Verifies that this report was signed by the expected signer, then extracts out the report's 64 byte payload.
    * @param _report The attestation evidence report from IAS.
    * @param _sig The RSA-SHA256 signature over the report.
    * @param _signingMod The expected signer's RSA modulus
    * @param _signingExp The expected signer's RSA exponent
    * @param _mrenclave The expected enclave measurement.
    * @param _mrsigner The expected enclave signer.
    * @return The 64 byte payload from the report.
    */
    function verifyRemoteAttestation(
        Values memory _reportValues,
        bytes memory _sig,
        bytes memory _signingMod,
        bytes memory _signingExp,
        bytes32 _mrenclave,
        bytes32 _mrsigner
    ) public view returns (bytes memory _payload) {
        // Reconstruct the JSON report that was signed
        bytes memory _report = bytes(buildJSON(_reportValues));

        console.logBytes(_report);

        // Verify the report was signed by the _SigningPK
        require(verifyReportSignature(_report, _sig, _signingMod, _signingExp), "bad signature");

        // Verify the report's contents match the expected
        _payload = verifyReportContents(_reportValues, _mrenclave, _mrsigner);
    }

    /*
    * @dev Verifies that the _leafX509Cert was signed by the expected signer (_signingMod, _signingExp). Then uses _leafX509Cert RSA public key to verify the signature over the _report, _sig. The trusted _report is verified for correct fields and then the enclave' 64 byte commitment is extracted. 
    * @param _report The attestation evidence report from IAS.
    * @param _sig The RSA-SHA256 signature over the report.
    * @param _leafX509Cert The signed leaf x509 certificate.
    * @param _signingMod The expected signer's RSA modulus
    * @param _signingExp The expected signer's RSA exponent
    * @param _mrenclave The expected enclave measurement.
    * @param _mrsigner The expected enclave signer.
    * @return The 64 byte payload from the report.
    */
    function rave(
        Values memory _reportValues,
        bytes memory _sig,
        bytes memory _leafX509Cert,
        bytes memory _signingMod,
        bytes memory _signingExp,
        bytes32 _mrenclave,
        bytes32 _mrsigner
    ) public view returns (bytes memory _payload) {
        // Verify the _leafX509Cert was signed with _signingMod and _signingExp
        (bytes memory _leafCertModulus, bytes memory _leafCertExponent) =
            X509Verifier.verifySignedX509(_leafX509Cert, _signingMod, _signingExp);

        // Verify report has expected fields then extract its payload
        _payload =
            verifyRemoteAttestation(_reportValues, _sig, _leafCertModulus, _leafCertExponent, _mrenclave, _mrsigner);
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { X509Verifier } from "rave/X509Verifier.sol";
import { JSONBuilder } from "rave/JSONBuilder.sol";
import { BytesUtils } from "ens-contracts/dnssec-oracle/BytesUtils.sol";
import { Base64 } from "openzeppelin/utils/Base64.sol";
import { RAVEBase } from "rave/RAVEBase.sol";

/**
 * @title RAVE
 * @author PufferFinance
 * @custom:security-contact security@puffer.fi
 * @notice RAVe is a smart contract for verifying Remote Attestation evidence.
 */
contract RAVE is RAVEBase, JSONBuilder {
    using BytesUtils for *;

    constructor() { }

    /**
     * @inheritdoc RAVEBase
     */
    function verifyRemoteAttestation(
        bytes calldata report,
        bytes calldata sig,
        bytes memory signingMod,
        bytes memory signingExp,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) public view override returns (bytes memory payload) {
        // Decode the encoded report JSON values to a Values struct and reconstruct the original JSON string
        (Values memory reportValues, bytes memory reportBytes) = _buildReportBytes(report);

        // Verify the report was signed by the SigningPK
        if (!verifyReportSignature(reportBytes, sig, signingMod, signingExp)) {
            revert BadReportSignature();
        }

        // Verify the report's contents match the expected
        payload = _verifyReportContents(reportValues, mrenclave, mrsigner);
    }

    /**
     * @inheritdoc RAVEBase
     */
    function rave(
        bytes calldata report,
        bytes calldata sig,
        bytes memory leafX509Cert,
        bytes memory signingMod,
        bytes memory signingExp,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) public view override returns (bytes memory payload) {
        // Verify the leafX509Cert was signed with signingMod and signingExp
        (bytes memory leafCertModulus, bytes memory leafCertExponent) =
            X509Verifier.verifySignedX509(leafX509Cert, signingMod, signingExp);

        // Verify report has expected fields then extract its payload
        payload = verifyRemoteAttestation(report, sig, leafCertModulus, leafCertExponent, mrenclave, mrsigner);
    }

    /*
    * @dev Builds the JSON report string from the abi-encoded `encodedReportValues`. The assumption is that `isvEnclaveQuoteBody` value was previously base64 decoded off-chain and needs to be base64 encoded to produce the message-to-be-signed.
    * @param encodedReportValues The values from the attestation evidence report JSON from IAS.
    * @return reportValues The JSON values as a Values struct for easier processing downstream
    * @return reportBytes The exact message-to-be-signed
    */
    function _buildReportBytes(bytes memory encodedReportValues)
        internal
        view
        returns (Values memory reportValues, bytes memory reportBytes)
    {
        // Decode the report JSON values
        (
            bytes memory id,
            bytes memory timestamp,
            bytes memory version,
            bytes memory epidPseudonym,
            bytes memory advisoryURL,
            bytes memory advisoryIDs,
            bytes memory isvEnclaveQuoteStatus,
            bytes memory isvEnclaveQuoteBody
        ) = abi.decode(encodedReportValues, (bytes, bytes, bytes, bytes, bytes, bytes, bytes, bytes));

        // Assumes the quote body was already decoded off-chain
        bytes memory encBody = bytes(Base64.encode(isvEnclaveQuoteBody));

        // Pack values to struct
        reportValues = JSONBuilder.Values(
            id, timestamp, version, epidPseudonym, advisoryURL, advisoryIDs, isvEnclaveQuoteStatus, encBody
        );

        // Reconstruct the JSON report that was signed
        reportBytes = bytes(buildJSON(reportValues));

        // Pass on the decoded value for later processing
        reportValues.isvEnclaveQuoteBody = isvEnclaveQuoteBody;
    }

    /*
    * @dev Parses a report, verifies the fields are correctly set, and extracts the enclave' 64 byte commitment.
    * @param reportValues The values from the attestation evidence report JSON from IAS.
    * @param mrenclave The expected enclave measurement.
    * @param mrsigner The expected enclave signer.
    * @return The 64 byte payload if the mrenclave and mrsigner values were correctly set.
    */
    function _verifyReportContents(Values memory reportValues, bytes32 mrenclave, bytes32 mrsigner)
        internal
        pure
        returns (bytes memory payload)
    {
        // check enclave status
        bytes32 status = keccak256(reportValues.isvEnclaveQuoteStatus);
        require(status == OK_STATUS || status == HARDENING_STATUS, "bad isvEnclaveQuoteStatus");

        // quote body is already base64 decoded
        bytes memory quoteBody = reportValues.isvEnclaveQuoteBody;
        assert(quoteBody.length == QUOTE_BODY_LENGTH);

        // Verify report's MRENCLAVE matches the expected
        bytes32 mre = quoteBody.readBytes32(MRENCLAVE_OFFSET);
        require(mre == mrenclave);

        // Verify report's MRSIGNER matches the expected
        bytes32 mrs = quoteBody.readBytes32(MRSIGNER_OFFSET);
        require(mrs == mrsigner);

        // Verify report's <= 64B payload matches the expected
        payload = quoteBody.substring(PAYLOAD_OFFSET, PAYLOAD_SIZE);
    }
}

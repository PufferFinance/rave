// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Base64Decoder } from "rave/Base64Decode.sol";
import { RAVEBase } from "rave/RAVEBase.sol";
import { BytesUtils } from "ens-contracts/dnssec-oracle/BytesUtils.sol";
import { X509Verifier } from "rave/X509Verifier.sol";
import { JSONBuilder } from "rave/JSONBuilder.sol";

/**
 * @title RAVEWithBase64Decode
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 * @notice RAVEWithBase64Decode is a smart contract for verifying Remote Attestation evidence.
 */
contract RAVEWithBase64Decode is RAVEBase, Base64Decoder, JSONBuilder {
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
        // Decode the encoded _report JSON values to a Values struct and reconstruct the original JSON string
        (Values memory reportValues, bytes memory reportBytes) = buildReportBytes(report);

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
        bytes calldata leafX509Cert,
        bytes calldata signingMod,
        bytes calldata signingExp,
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
    * @dev Parses a report, verifies the fields are correctly set, and extracts the enclave' 64 byte commitment.
    * @param reportValues The values from the attestation evidence report JSON from IAS.
    * @param mrenclave The expected enclave measurement.
    * @param mrsigner The expected enclave signer.
    * @return The 64 byte payload if the mrenclave and mrsigner values were correctly set.
    */
    function _verifyReportContents(Values memory reportValues, bytes32 mrenclave, bytes32 mrsigner)
        internal
        view
        returns (bytes memory payload)
    {
        // check enclave status
        bytes32 status = keccak256(reportValues.isvEnclaveQuoteStatus);
        require(status == OK_STATUS || status == HARDENING_STATUS, "bad isvEnclaveQuoteStatus");

        // base64 decode quote body
        bytes memory quoteBody = bytes(decode(string(reportValues.isvEnclaveQuoteBody)));
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

    function buildReportBytes(bytes memory encodedReportValues)
        internal
        pure
        returns (Values memory reportValues, bytes memory reportBytes)
    {
        // Decode the report JSON values
        (
            bytes memory v0,
            bytes memory v1,
            bytes memory v2,
            bytes memory v3,
            bytes memory v4,
            bytes memory v5,
            bytes memory v6,
            bytes memory v7
        ) = abi.decode(encodedReportValues, (bytes, bytes, bytes, bytes, bytes, bytes, bytes, bytes));

        // Pack values
        reportValues = JSONBuilder.Values(v0, v1, v2, v3, v4, v5, v6, v7);

        // Reconstruct the JSON report that was signed
        reportBytes = bytes(buildJSON(reportValues));
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Base64Decoder } from "rave/Base64Decode.sol";
import { RAVEBase } from "rave/RAVEBase.sol";
import { BytesUtils } from "ens-contracts/dnssec-oracle/BytesUtils.sol";
import { JSONParser } from "rave/JSONDecode.sol";
import { X509Verifier } from "rave/X509Verifier.sol";

/**
 * @title RAVEWithJSONDecodeAndBase64Decode
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 * @notice RAVEWithJSONDecodeAndBase64Decode is a smart contract for verifying Remote Attestation evidence.
 */
contract RAVEWithJSONDecodeAndBase64Decode is Base64Decoder, RAVEBase {
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
        // Verify the report was signed by the _SigningPK
        if (!verifyReportSignature(report, sig, signingMod, signingExp)) {
            revert BadReportSignature();
        }

        // Verify the report's contents match the expected
        payload = _verifyAndExtractReportContents(report, mrenclave, mrsigner);
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
        // Verify the _leafX509Cert was signed with _signingMod and _signingExp
        (bytes memory leafCertModulus, bytes memory leafCertExponent) =
            X509Verifier.verifySignedX509(leafX509Cert, signingMod, signingExp);

        // Verify report has expected fields then extract its payload
        payload = verifyRemoteAttestation(report, sig, leafCertModulus, leafCertExponent, mrenclave, mrsigner);
    }

    /*
    * @dev Parses a report, verifies the fields are correctly set, and extracts the enclave' 64 byte commitment.
    * @param report The attestation evidence report from IAS.
    * @param mrenclave The expected enclave measurement.
    * @param mrsigner The expected enclave signer.
    * @return The 64 byte payload if the mrenclave and mrsigner values were correctly set.
    */
    function _verifyAndExtractReportContents(bytes calldata report, bytes32 mrenclave, bytes32 mrsigner)
        public
        view
        returns (bytes memory payload)
    {
        // Extract the quote body
        bytes memory quoteBody = _extractQuoteBody(string(report));

        // Verify report's MRENCLAVE matches the expected
        bytes32 mre = quoteBody.readBytes32(MRENCLAVE_OFFSET);
        require(mre == mrenclave);

        // Verify report's MRSIGNER matches the expected
        bytes32 mrs = quoteBody.readBytes32(MRSIGNER_OFFSET);
        require(mrs == mrsigner);

        // Verify report's <= 64B payload matches the expected
        payload = quoteBody.substring(PAYLOAD_OFFSET, PAYLOAD_SIZE);
    }

    /*
    * @dev Parses attestation report JSON, extracts quote body, then base64 decodes. Assumes the quote body is the last key-pair in the JSON.
    * @param report The utf-8 encoded JSON string containing the attestation report.
    * @return The extracted and base64 decoded quote body or fail parsing.
    */
    function _extractQuoteBody(string calldata report) internal view returns (bytes memory) {
        // Parse the report json
        (uint256 ret, JSONParser.Token[] memory tokens, uint256 numTokens) = JSONParser.parse(report, MAX_JSON_ELEMENTS);
        assert(ret == JSONParser.RETURN_SUCCESS);
        assert(numTokens == MAX_JSON_ELEMENTS);

        // Verify report's isvEnclaveQuoteStatus
        JSONParser.Token memory statusToken = tokens[numTokens - 3];
        string memory encQuoteStatus = JSONParser.getBytes(report, statusToken.start, statusToken.end);
        bytes32 status = keccak256(bytes(encQuoteStatus));
        require(status == OK_STATUS || status == HARDENING_STATUS, "bad isvEnclaveQuoteStatus");

        // Extract quote body (positioned at end of report)
        JSONParser.Token memory lastToken = tokens[numTokens - 1];
        string memory encQuoteBody = JSONParser.getBytes(report, lastToken.start, lastToken.end);

        // base64 decode body
        bytes memory quoteBody = bytes(decode(encQuoteBody));
        assert(quoteBody.length == QUOTE_BODY_LENGTH);
        return quoteBody;
    }
}

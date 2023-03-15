// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "src/X509.sol";
import "src/Base64Decode.sol";
import "src/JSONDecode.sol";
import "ens-contracts/dnssec-oracle/algorithms/RSAVerify.sol";
import "ens-contracts/dnssec-oracle/BytesUtils.sol";
import "forge-std/Test.sol";

contract RAVE is Base64Decoder {
    using BytesUtils for *;

    uint256 constant MAX_JSON_ELEMENTS = 19;
    uint256 constant QUOTE_BODY_LENGTH = 432;
    uint256 constant MRENCLAVE_OFFSET = 112;
    uint256 constant MRSIGNER_OFFSET = 176;
    uint256 constant PAYLOAD_OFFSET = 368;
    uint256 constant PAYLOAD_SIZE = 64;

    constructor() {}

    function extractQuoteBody(string memory _report) public view returns (bytes memory) {
        // Parse the report json
        (uint256 _ret, JSONParser.Token[] memory _tokens, uint256 _numTokens) =
            JSONParser.parse(_report, MAX_JSON_ELEMENTS);
        assert(_ret == JSONParser.RETURN_SUCCESS);
        assert(_numTokens == MAX_JSON_ELEMENTS);

        // Extract quote body (positioned at end of report)
        JSONParser.Token memory _lastToken = _tokens[_numTokens - 1];
        string memory _encQuoteBody = JSONParser.getBytes(_report, _lastToken.start, _lastToken.end);

        // base64 decode body
        bytes memory _quoteBody = bytes(decode(_encQuoteBody));
        assert(_quoteBody.length == QUOTE_BODY_LENGTH);
        return _quoteBody;
    }

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

    function verifyAndExtractReportContents(string memory _report, bytes32 _mrenclave, bytes32 _mrsigner)
        public
        view
        returns (bytes memory _payload)
    {
        // Extract the quote body
        bytes memory _quoteBody = extractQuoteBody(_report);

        // Verify report's MRENCLAVE matches the expected
        bytes32 _mre = _quoteBody.readBytes32(MRENCLAVE_OFFSET);
        require(_mre == _mrenclave);

        // Verify report's MRSIGNER matches the expected
        bytes32 _mrs = _quoteBody.readBytes32(MRSIGNER_OFFSET);
        require(_mrs == _mrsigner);

        // Verify report's <= 64B payload matches the expected
        _payload = _quoteBody.substring(PAYLOAD_OFFSET, PAYLOAD_SIZE);
    }

    function verifyRemoteAttestation(
        string memory _report,
        bytes memory _sig,
        bytes memory _signingMod,
        bytes memory _signingExp,
        bytes32 _mrenclave,
        bytes32 _mrsigner
    ) public view returns (bytes memory _payload) {
        // Verify the report was signed by the _SigningPK
        require(verifyReportSignature(bytes(_report), _sig, _signingMod, _signingExp));

        // Verify the report's contents match the expected
        _payload = verifyAndExtractReportContents(_report, _mrenclave, _mrsigner);
    }

    function rave(
        bytes memory _report,
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
            verifyRemoteAttestation(string(_report), _sig, _leafCertModulus, _leafCertExponent, _mrenclave, _mrsigner);
    }
}

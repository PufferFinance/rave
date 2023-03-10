// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "src/base64.sol";
import "src/JSON.sol";
import "ens-contracts/dnssec-oracle/algorithms/RSAVerify.sol";
import "ens-contracts/dnssec-oracle/BytesUtils.sol";

contract RAVE is Base64Decoder {
    using BytesUtils for *;

    uint256 constant MAX_JSON_ELEMENTS = 19;
    uint256 constant QUOTE_BODY_LENGTH = 432;
    uint256 constant MRENCLAVE_OFFSET = 112;
    uint256 constant MRSIGNER_OFFSET = 176;
    uint256 constant PAYLOAD_OFFSET = 368;
    bytes exp = hex"0000000000000000000000000000000000000000000000000000000000010001";

    constructor() {}

    function extractQuoteBody(string calldata _report) public view returns (bytes memory) {
        // Parse the report json
        (uint256 ret, JSONParser.Token[] memory tokens, uint256 numTokens) =
            JSONParser.parse(_report, MAX_JSON_ELEMENTS);
        assert(ret == JSONParser.RETURN_SUCCESS);
        assert(numTokens == MAX_JSON_ELEMENTS);

        // Extract quote body
        JSONParser.Token memory lastToken = tokens[numTokens - 1];
        string memory _encQuoteBody = JSONParser.getBytes(_report, lastToken.start, lastToken.end);

        // base64 decode body
        bytes memory _quoteBody = bytes(decode(_encQuoteBody));
        assert(_quoteBody.length == QUOTE_BODY_LENGTH);
        return _quoteBody;
    }

    function verifyReportSignature(bytes calldata _report, bytes calldata _sig, bytes calldata _signingPK)
        public
        view
        returns (bool)
    {
        // Use _signingPK to verify _sig is the RSA signature over sha256(_report)
        (bool success, bytes memory got) = RSAVerify.rsarecover(_signingPK, exp, _sig);
        // Last 32 bytes is recovered signed digest
        bytes32 recovered = got.readBytes32(got.length - 32);

        return success && recovered == sha256(_report);
    }

    function verifyReportContents(
        string calldata _report,
        bytes32 _mrenclave,
        bytes32 _mrsigner,
        bytes calldata _payload
    ) public view returns (bool) {
        require(_payload.length <= 64);
        require(_mrenclave.length == 32);
        require(_mrsigner.length == 32);

        // Extract the quote body
        bytes memory _quoteBody = extractQuoteBody(_report);

        // Verify report's MRENCLAVE matches the expected
        bytes32 mre = _quoteBody.readBytes32(MRENCLAVE_OFFSET);
        require(mre == _mrenclave);

        // Verify report's MRSIGNER matches the expected
        bytes32 mrs = _quoteBody.readBytes32(MRSIGNER_OFFSET);
        require(mrs == _mrsigner);

        // Verify report's <= 64B payload matches the expected
        bytes memory p = _quoteBody.substring(PAYLOAD_OFFSET, _payload.length);
        assert(keccak256(p) == keccak256(_payload));

        return true;
    }

    function verifyRemoteAttestation(
        string calldata _report,
        bytes calldata _sig,
        bytes calldata _signingPK,
        bytes32 _mrenclave,
        bytes32 _mrsigner,
        bytes calldata _payload
    ) public view returns (bool) {
        require(_payload.length <= 64);
        require(_mrenclave.length == 32);
        require(_mrsigner.length == 32);

        // Verify the report was signed by the _SigningPK
        require(verifyReportSignature(bytes(_report), _sig, _signingPK));

        // Verify the report's contents match the expected
        require(verifyReportContents(_report, _mrenclave, _mrsigner, _payload));

        return true;
    }
}

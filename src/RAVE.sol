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

    function verifyReport(bytes calldata _report, bytes calldata _sig, bytes calldata _signingPK)
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

    function verifyRA(
        string calldata _report,
        bytes calldata _sig,
        bytes calldata _signingPK,
        bytes calldata _mrenclave,
        bytes calldata _mrsigner,
        bytes calldata _payload
    ) public view returns (bool) {
        require(_payload.length <= 64);
        require(_mrenclave.length == 32);
        require(_mrsigner.length == 32);

        require(verifyReport(bytes(_report), _sig, _signingPK));

        // Extract the quote body
        bytes memory _quoteBody = extractQuoteBody(_report);

        // Verify report's MRENCLAVE matches the expected
        uint256 i;
        uint256 j;
        bytes memory mre = new bytes(32);
        for ((i, j) = (112, 0); i < 144; i++) {
            mre[j] = _quoteBody[i];
            j += 1;
        }
        assert(keccak256(mre) == keccak256(_mrenclave));

        // Verify report's MRSIGNER matches the expected
        bytes memory mrs = new bytes(32);
        for ((i, j) = (176, 0); i < 208; i++) {
            mrs[j] = _quoteBody[i];
            j += 1;
        }
        assert(keccak256(mrs) == keccak256(_mrsigner));

        // Verify report's <= 64B payload matches the expected
        bytes memory p = new bytes(_payload.length);
        for ((i, j) = (368, 0); i < 368 + _payload.length; i++) {
            p[j] = _quoteBody[i];
            j += 1;
        }
        assert(keccak256(_payload) == keccak256(p));

        return true;
    }
}

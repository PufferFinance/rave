// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

contract JSONBuilder {
    struct Values {
        bytes id;
        bytes timestamp;
        bytes version;
        bytes epidPseudonym;
        bytes advisoryURL;
        bytes advisoryIDs;
        bytes isvEnclaveQuoteStatus;
        bytes isvEnclaveQuoteBody;
    }

    function buildJSON(Values memory values) public pure returns (string memory json) {
        json = string(
            abi.encodePacked(
                '{"id":"',
                values.id,
                '","timestamp":"',
                values.timestamp,
                '","version":',
                values.version,
                ',"epidPseudonym":"',
                values.epidPseudonym
            )
        );
        json = string(
            abi.encodePacked(
                json,
                '","advisoryURL":"',
                values.advisoryURL,
                '","advisoryIDs":',
                values.advisoryIDs,
                ',"isvEnclaveQuoteStatus":"',
                values.isvEnclaveQuoteStatus,
                '","isvEnclaveQuoteBody":"',
                values.isvEnclaveQuoteBody,
                '"}'
            )
        );
    }
}

contract CustomJSONBuilder {
    string[] public keys;

    constructor(string[] memory _keys) {
        keys = _keys;
    }

    function buildJSON(string[] memory values) public view returns (string memory) {
        require(values.length == keys.length);
        string memory json = "";
        for (uint256 i = 0; i < keys.length; i++) {
            json = string(abi.encodePacked(json, keys[i], values[i]));
        }
        return string(abi.encodePacked("{", json, '"}'));
    }
}

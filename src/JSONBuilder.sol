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

    function buildJSON(string[] calldata values) public view returns (string memory) {
        // require(values.length == keys.length);
        if (values.length != keys.length) {
            revert();
        }
        string memory json = "";
        uint256 length = keys.length;
        for (uint256 i = 0; i < length; ) {
            json = string(abi.encodePacked(json, keys[i], values[i]));
            unchecked {
                i++; 
            }
        }
        return string(abi.encodePacked("{", json, '"}'));
    }
}

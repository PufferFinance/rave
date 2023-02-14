// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "src/JSON.sol";
import "test/utils/helper.sol";
import "test/mocks/JSON.sol";

abstract contract TestHappyJSON is Test, BytesFFIFuzzer {
    MockableJson c;

    function setUp() public virtual {}

    function testVmParseJson() public {
        string memory json = c.JSON();
        string[] memory keys = c.keys();
        string[] memory values = c.values();

        for (uint256 i = 0; i < keys.length; i++) {
            string memory key = keys[i];
            string memory value = values[i];
            console.log("expected: json['%s'] = %s", key, value);

            bytes memory parsed = abi.decode(vm.parseJson(json, key), (bytes));
            console.log("got: %s", string(parsed));

            assertEq(bytes(value).length, parsed.length);
            assertEq(bytes(value), parsed);
            assertEq(value, string(parsed));
        }
    }

    function testLibParseJson() public {
        string memory json = c.JSON();
        string[] memory keys = c.keys();
        string[] memory values = c.values();

        // Parse JSON into tokens
        (uint256 code, JSONParser.Token[] memory tokens, uint256 numTokens) = JSONParser.parse(json, c.maxElements());

        // Successful parsing
        assertEq(code, JSONParser.RETURN_SUCCESS);
        assertEq(numTokens, c.maxElements());

        // The 0th token references the whole JSON
        assert(tokens[0].jsmnType == JSONParser.JsmnType.OBJECT);
        assertEq(tokens.length, values.length + keys.length + 1);
        assertEq(tokens[0].start, 0);
        assertEq(tokens[0].end, bytes(json).length);

        for ((uint256 i, uint256 j) = (1, 0); i < numTokens; i += 2) {
            string memory k = JSONParser.getBytes(json, tokens[i].start, tokens[i].end);
            string memory v = JSONParser.getBytes(json, tokens[i + 1].start, tokens[i + 1].end);
            console.log("got: json['%s']: %s", k, v);
            console.log("expected: json['%s']: %s", keys[j], values[j]);
            assertEq(k, keys[j]);
            assertEq(v, values[j]);
            j += 1;
        }
    }
}

contract TestBasicJson is TestHappyJSON {
    function setUp() public override {
        c = new MockBasicJson();
    }
}

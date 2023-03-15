// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "src/JSONDecode.sol";
import "test/utils/helper.sol";
import "test/mocks/JSONDecode.sol";

abstract contract TestHappyJSON is Test, MockableJsonTypes {
    MockableJson c;

    function setUp() public virtual {}

    function testVmParseJson() public {
        string memory json = c.JSON();
        string[] memory keys = c.keys();
        Value[] memory values = c.values();

        for (uint256 i = 0; i < keys.length; i++) {
            string memory key = keys[i];
            Value memory value = values[i];

            if (value.vType == JSONParser.JsmnType.STRING) {
                // Parse a string
                console.log("expected: json['%s'] = %s", key, value.v);
                bytes memory parsed = abi.decode(vm.parseJson(json, key), (bytes));
                console.log("got: %s", string(parsed));
                assertEq(parsed.length, bytes(value.v).length);
                assertEq(parsed, bytes(value.v));
                assertEq(string(parsed), value.v);
            } else if (value.vType == JSONParser.JsmnType.PRIMITIVE) {
                // Parse an integer
                console.log("expected: json['%s'] = %s", key, value.v);
                uint256 parsed = abi.decode(vm.parseJson(json, key), (uint256));
                console.log("got: %s", vm.toString(parsed));
                assertEq(vm.toString(parsed), value.v);
            } else if (value.vType == JSONParser.JsmnType.ARRAY) {
                // Parse an array of strings
                string[] memory parsed = vm.parseJsonStringArray(json, key);
                assertEq(parsed.length, value.array.length);
                for (uint256 j = 0; j < parsed.length; j++) {
                    console.log("expected: json['%s'][%s] = %s", key, j, value.array[j]);
                    console.log("got json['%s'][%s] = %s", key, j, parsed[j]); // bytes memory parsed = abi.decode(vm.parseJson(json, key), (obytes));
                    assertEq(parsed[j], value.array[j]);
                }
            } else if (value.vType == JSONParser.JsmnType.OBJECT) {
                // Parse a nested JSON object
                //todo unimplemented (unnecessary for RAVE)
                console.log("unimplemented");
                assert(false);
            } else {
                // Not a valid JsmnType
                console.log("Bad parsing");
                assert(false);
            }
        }
    }

    function testLibParseJson() public {
        string memory json = c.JSON();
        string[] memory keys = c.keys();
        Value[] memory values = c.values();

        // Parse JSON into tokens
        (uint256 code, JSONParser.Token[] memory tokens, uint256 numTokens) = JSONParser.parse(json, c.maxElements());

        // Successful parsing
        assertEq(code, JSONParser.RETURN_SUCCESS);
        assertEq(numTokens, c.maxElements());

        // The 0th token references the whole JSON
        assert(tokens[0].jsmnType == JSONParser.JsmnType.OBJECT);
        assertEq(tokens[0].start, 0);
        assertEq(tokens[0].end, bytes(json).length);

        for ((uint256 i, uint256 j) = (1, 0); i < numTokens; i += 2) {
            string memory k = JSONParser.getBytes(json, tokens[i].start, tokens[i].end);
            string memory v = JSONParser.getBytes(json, tokens[i + 1].start, tokens[i + 1].end);
            Value memory value = values[j];
            console.log("i: %s, j: %s", i, j);
            console.log("got: json['%s']: %s", k, v);
            if (value.vType == JSONParser.JsmnType.ARRAY) {
                assertEq(k, keys[j]);
                // next l tokens will be the array contents
                for (uint256 l = 0; l < value.array.length; l++) {
                    v = JSONParser.getBytes(json, tokens[i + l + 2].start, tokens[i + l + 2].end);
                    console.log("ARRAY TYPE, expected: %s", value.array[l]);
                    console.log("ARRAY TYPE, got: %s", v);
                    assertEq(v, value.array[l]);
                }
                // advance tokens
                i += value.array.length;
            } else {
                console.log("expected: json['%s']: %s", keys[j], value.v);
                assertEq(k, keys[j]);
                assertEq(v, value.v);
            }
            j += 1;
        }
    }
}

contract TestBasicJson is TestHappyJSON {
    function setUp() public override {
        c = new MockBasicJson();
    }
}

contract TestRemoteAttestationEvidenceJson is TestHappyJSON {
    function setUp() public override {
        c = new MockRemoteAttestationEvidence();
    }
}

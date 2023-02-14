// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "src/JSON.sol";
import "test/helper.sol";

contract TestJSON is Test, BytesFFIFuzzer {
    // JSONDecoderc;

    function setUp() public {
        // c = new JSONDecoder();
    }

    function testVmParseJson() public {
        string memory json = "{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}";
        string memory key = "name";
        bytes memory expected = abi.decode(vm.parseJson(json, key), (bytes));
        console.log("json['%s'] = %s", key, string(expected));
        console.logBytes(expected);
        assertEq(bytes("John"), expected);
    }

    function testParseValidJson() public {
        string memory json = "{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}";
        console.log("%s", json);
        string memory key = "city";
        bytes memory expected = abi.decode(vm.parseJson(json, key), (bytes));
        console.log("expected: json['%s']: %s", key, string(expected));

        uint256 maxElements = 7;
        (uint256 code, JsmnSolLib.Token[] memory tokens, uint256 numTokens) = JsmnSolLib.parse(json, maxElements);

        console.log("code: %s", code);
        assertEq(code, 0);
        assertEq(numTokens, maxElements);

        for (uint256 i = 1; i < tokens.length; i += 2) {
            string memory k = JsmnSolLib.getBytes(json, tokens[i].start, tokens[i].end);
            string memory v = JsmnSolLib.getBytes(json, tokens[i + 1].start, tokens[i + 1].end);
            console.log("json['%s']: %s", k, v);
        }
    }
}

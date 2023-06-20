// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "src/JSONBuilder.sol";
import "test/utils/helper.sol";
import "test/mocks/JSONDecode.sol";

contract TestJSONBuilder is Test, JSONBuilder {
    string expected;
    bytes32 expectedHash;
    CustomJSONBuilder customBuilder;

    function setUp() public virtual {
        string[] memory _keys = new string[](8);
        _keys[0] = '"id":"';
        _keys[1] = '","timestamp":"';
        _keys[2] = '","version":';
        _keys[3] = ',"epidPseudonym":"';
        _keys[4] = '","advisoryURL":"';
        _keys[5] = '","advisoryIDs":';
        _keys[6] = ',"isvEnclaveQuoteStatus":"';
        _keys[7] = '","isvEnclaveQuoteBody":"';
        customBuilder = new CustomJSONBuilder(_keys);
        expected = expectedJSON();
        expectedHash = keccak256(abi.encodePacked(expected));
    }

    function expectedJSON() public pure returns (string memory) {
        return
        "{\"id\":\"219966280568893600543427580608194089763\",\"timestamp\":\"2023-01-20T19:47:28.465440\",\"version\":4,\"epidPseudonym\":\"EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhLO4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/tepdezMsSB8Go=\",\"advisoryURL\":\"https://security-center.intel.com\",\"advisoryIDs\":[\"INTEL-SA-00334\",\"INTEL-SA-00615\"],\"isvEnclaveQuoteStatus\":\"SW_HARDENING_NEEDED\",\"isvEnclaveQuoteBody\":\"AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAfAAAAAAAAAE2yt+DKX+yq83lz+hnlXoyXOtEe0PZj7lECfkmRha1yAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACOKnQegP7jJKCRW0CuwocB1b9Ilk3LxdQfcm8RgfwktN7LzgWkmU1t7GzZf3P8g2cAAAAAAAAAAAAAAAAAAAAA\"}";
    }

    function testBuildJSON() public {
        Values memory v = Values(
            "219966280568893600543427580608194089763",
            "2023-01-20T19:47:28.465440",
            "4",
            "EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhLO4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/tepdezMsSB8Go=",
            "https://security-center.intel.com",
            "[\"INTEL-SA-00334\",\"INTEL-SA-00615\"]",
            "SW_HARDENING_NEEDED",
            "AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAfAAAAAAAAAE2yt+DKX+yq83lz+hnlXoyXOtEe0PZj7lECfkmRha1yAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACOKnQegP7jJKCRW0CuwocB1b9Ilk3LxdQfcm8RgfwktN7LzgWkmU1t7GzZf3P8g2cAAAAAAAAAAAAAAAAAAAAA"
        );
        string memory built = buildJSON(v);
        bytes32 builtHash = keccak256(abi.encodePacked(built));
        assertEq(builtHash, expectedHash, "built does not match expected");
    }

    function testBuildCustomJSON() public {
        string[] memory values = new string[](8);
        values[0] = "219966280568893600543427580608194089763";
        values[1] = "2023-01-20T19:47:28.465440";
        values[2] = "4";
        values[3] =
            "EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhLO4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/tepdezMsSB8Go=";
        values[4] = "https://security-center.intel.com";
        values[5] = "[\"INTEL-SA-00334\",\"INTEL-SA-00615\"]";
        values[6] = "SW_HARDENING_NEEDED";
        values[7] =
            "AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAfAAAAAAAAAE2yt+DKX+yq83lz+hnlXoyXOtEe0PZj7lECfkmRha1yAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACOKnQegP7jJKCRW0CuwocB1b9Ilk3LxdQfcm8RgfwktN7LzgWkmU1t7GzZf3P8g2cAAAAAAAAAAAAAAAAAAAAA";

        string memory built = customBuilder.buildJSON(values);
        bytes32 builtHash = keccak256(abi.encodePacked(built));
        assertEq(builtHash, expectedHash, "built does not match expected");
    }
}

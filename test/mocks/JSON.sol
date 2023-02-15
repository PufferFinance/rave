// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "src/JSON.sol";

contract MockableJsonTypes {
    struct Value {
        JSONParser.JsmnType vType;
        string v;
        string[] array;
    }
}

abstract contract MockableJson is MockableJsonTypes {
    function keys() public pure virtual returns (string[] memory);
    function values() public pure virtual returns (Value[] memory);
    function JSON() public pure virtual returns (string memory j);
    function maxElements() public pure virtual returns (uint256);
}

contract MockBasicJson is MockableJson {
    function maxElements() public pure override returns (uint256) {
        return 7;
    }

    function JSON() public pure override returns (string memory) {
        return "{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}";
    }

    function keys() public pure override returns (string[] memory) {
        string[] memory s = new string[](3);
        s[0] = "name";
        s[1] = "age";
        s[2] = "city";
        return s;
    }

    function values() public pure override returns (Value[] memory) {
        Value[] memory s = new Value[](3);
        s[0] = Value({vType: JSONParser.JsmnType.STRING, v: "John", array: new string[](0)});
        s[1] = Value({vType: JSONParser.JsmnType.PRIMITIVE, v: "30", array: new string[](0)});
        s[2] = Value({vType: JSONParser.JsmnType.STRING, v: "New York", array: new string[](0)});
        return s;
    }
}

contract MockRemoteAttestationEvidence is MockableJson {
    function maxElements() public pure override returns (uint256) {
        return 19;
    }

    function JSON() public pure override returns (string memory) {
        return
        "{\"id\":\"219966280568893600543427580608194089763\",\"timestamp\":\"2023-01-20T19:47:28.465440\",\"version\":4,\"epidPseudonym\":\"EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhLO4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/tepdezMsSB8Go=\",\"advisoryURL\":\"https://security-center.intel.com\",\"advisoryIDs\":[\"INTEL-SA-00334\",\"INTEL-SA-00615\"],\"isvEnclaveQuoteStatus\":\"SW_HARDENING_NEEDED\",\"isvEnclaveQuoteBody\":\"AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAfAAAAAAAAAE2yt+DKX+yq83lz+hnlXoyXOtEe0PZj7lECfkmRha1yAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACOKnQegP7jJKCRW0CuwocB1b9Ilk3LxdQfcm8RgfwktN7LzgWkmU1t7GzZf3P8g2cAAAAAAAAAAAAAAAAAAAAA\"}";
    }

    function keys() public pure override returns (string[] memory) {
        string[] memory s = new string[](8);
        s[0] = "id";
        s[1] = "timestamp";
        s[2] = "version";
        s[3] = "epidPseudonym";
        s[4] = "advisoryURL";
        s[5] = "advisoryIDs";
        s[6] = "isvEnclaveQuoteStatus";
        s[7] = "isvEnclaveQuoteBody";
        return s;
    }

    function values() public pure override returns (Value[] memory) {
        Value[] memory s = new Value[](8);
        s[0] = Value({
            vType: JSONParser.JsmnType.STRING,
            v: "219966280568893600543427580608194089763",
            array: new string[](0)
        });

        s[1] = Value({vType: JSONParser.JsmnType.STRING, v: "2023-01-20T19:47:28.465440", array: new string[](0)});

        s[2] = Value({vType: JSONParser.JsmnType.PRIMITIVE, v: "4", array: new string[](0)});

        s[3] = Value({
            vType: JSONParser.JsmnType.STRING,
            v: "EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhLO4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/tepdezMsSB8Go=",
            array: new string[](0)
        });

        s[4] =
            Value({vType: JSONParser.JsmnType.STRING, v: "https://security-center.intel.com", array: new string[](0)});
        string[] memory arr = new string[](2);

        arr[0] = "INTEL-SA-00334";
        arr[1] = "INTEL-SA-00615";
        s[5] = Value({vType: JSONParser.JsmnType.ARRAY, v: "", array: arr});

        s[6] = Value({vType: JSONParser.JsmnType.STRING, v: "SW_HARDENING_NEEDED", array: new string[](0)});

        s[7] = Value({
            vType: JSONParser.JsmnType.STRING,
            v: "AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAfAAAAAAAAAE2yt+DKX+yq83lz+hnlXoyXOtEe0PZj7lECfkmRha1yAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACOKnQegP7jJKCRW0CuwocB1b9Ilk3LxdQfcm8RgfwktN7LzgWkmU1t7GzZf3P8g2cAAAAAAAAAAAAAAAAAAAAA",
            array: new string[](0)
        });
        return s;
    }
}

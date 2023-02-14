// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

abstract contract MockableJson {
    function keys() public pure virtual returns (string[] memory);
    function values() public pure virtual returns (string[] memory);
    function JSON() public pure virtual returns (string memory j);
    function maxElements() public pure virtual returns (uint256);
}

contract MockBasicJson is MockableJson {
    function maxElements() public pure override returns (uint256) {
        return 7;
    }

    function JSON() public pure override returns (string memory) {
        return "{\"name\":\"John\",\"age\":\"30\",\"city\":\"New York\"}";
    }

    function keys() public pure override returns (string[] memory) {
        string[] memory s = new string[](3);
        s[0] = "name";
        s[1] = "age";
        s[2] = "city";
        return s;
    }

    function values() public pure override returns (string[] memory) {
        string[] memory s = new string[](3);
        s[0] = "John";
        s[1] = "30";
        s[2] = "New York";
        return s;
    }
}

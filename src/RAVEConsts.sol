// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

abstract contract RAVEConsts {
    uint256 constant MAX_JSON_ELEMENTS = 19;
    uint256 constant QUOTE_BODY_LENGTH = 432;
    uint256 constant MRENCLAVE_OFFSET = 112;
    uint256 constant MRSIGNER_OFFSET = 176;
    uint256 constant PAYLOAD_OFFSET = 368;
    uint256 constant PAYLOAD_SIZE = 64;

    bytes32 constant OK_STATUS = keccak256("OK");
    bytes32 constant HARDENING_STATUS = keccak256("SW_HARDENING_NEEDED");
}

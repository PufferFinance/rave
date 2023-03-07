// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "src/RAVE.sol";
import "src/JSON.sol";
import "src/RSA.sol";
import "test/utils/helper.sol";
import "test/mocks/MockEvidence.sol";

abstract contract RAVETester is Test {
    MockEvidence m;
    RAVE c;

    function setUp() public virtual {}

    function testVerifyRA() public {
        string memory _report = m.report();
        bytes memory _sig = m.sig();
        bytes memory _signingPK = m.signingPK();
        bytes memory _mrenclave = m.mrenclave();
        bytes memory _mrsigner = m.mrsigner();
        bytes memory _payload = m.payload();
        assert(c.verifyRA(_report, _sig, _signingPK, _mrenclave, _mrsigner, _payload));
    }
}

contract TestHappyRAVE is RAVETester {
    function setUp() public override {
        m = new ValidBLSEvidence();
        c = new RAVE();
    }
}

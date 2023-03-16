// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "src/RAVE.sol";
import "src/X509.sol";
import "ens-contracts/dnssec-oracle/BytesUtils.sol";
import "test/mocks/MockEvidence.sol";
import "test/utils/helper.sol";

abstract contract RAVETester is Test {
    using BytesUtils for *;

    MockEvidence m;
    RAVE c;

    function setUp() public virtual {}

    function testVerifyRA() public {
        string memory report = m.report();
        bytes memory sig = m.sig();
        bytes memory signingMod = m.signingMod();
        bytes memory signingExp = m.signingExp();
        bytes32 mrenclave = m.mrenclave();
        bytes32 mrsigner = m.mrsigner();
        bytes memory payload = m.payload();
        bytes memory gotPayload = c.verifyRemoteAttestation(report, sig, signingMod, signingExp, mrenclave, mrsigner);
        assert(keccak256(gotPayload.substring(0, payload.length)) == keccak256(payload));
    }
}

contract TestHappyRAVE is RAVETester {
    function setUp() public override {
        m = new ValidBLSEvidence();
        c = new RAVE();
    }
}

abstract contract RaveFuzzTester is Test, X509GenHelper, BytesFFIFuzzer {
    using BytesUtils for *;

    RAVE c;

    function setUp() public virtual {
        // Generate new self-signed x509 cert
        newSelfSignedX509();

        // Read self-signed DER-encoded cert
        readX509Cert();
        console.log("Cert:");
        console.logBytes(CERT_BYTES);

        // Read self-signed cert's body (what was used as input to RSA-SHA256)
        readX509Body();
        console.log("CertBody:");
        console.logBytes(CERT_BODY_BYTES);

        // Read the self-signed cert's signature
        readX509Signature();
        console.log("Signature:");
        console.logBytes(CERT_SIG);

        // Read the public key's modulus
        readX509Modulus();
        console.log("Modulus:");
        console.logBytes(MODULUS);

        c = new RAVE();
    }

    function genNewEvidence(string memory mrenclave, string memory mrsigner, string memory payload)
        public
        returns (bytes memory)
    {
        assertEq(bytes(mrenclave).length, 66, "bad mre len");
        assertEq(bytes(mrsigner).length, 66, "bad mrs len");
        assertEq(bytes(payload).length, 130, "bad payload len");
        string[] memory cmds = new string[](5);
        cmds[0] = "python3";
        cmds[1] = "test/scripts/runSignRandomEvidence.py";
        cmds[2] = mrenclave;
        cmds[3] = mrsigner;
        cmds[4] = payload;
        bytes memory resp = vm.ffi(cmds);
        return resp;
    }

    function testGenMockEvidence(bytes32 mrenclave, bytes32 mrsigner, bytes memory p) public {
        vm.assume(p.length >= 64);

        // Convert the random bytes into valid utf-8 bytes
        bytes memory payload = getFriendlyBytes(p).substring(0, 130);
        console.logBytes(payload);

        // Request new RA evidence
        bytes memory evidence = genNewEvidence(vm.toString(mrenclave), vm.toString(mrsigner), string(payload));

        // Split response into a report and signature
        (bytes memory report, bytes memory signature) = abi.decode(evidence, (bytes, bytes));

        // Run rave to extract its payload
        bytes memory gotPayload = c.rave(report, signature, CERT_BYTES, MODULUS, EXPONENT, mrenclave, mrsigner);

        // Verify it matches the expected payload
        assert(keccak256(gotPayload.substring(0, 64)) == keccak256(p.substring(0, 64)));
    }
}

contract Rave512BitFuzzTester is RaveFuzzTester {
    constructor() X509GenHelper("512") {}
}

contract Rave1024BitFuzzTester is RaveFuzzTester {
    constructor() X509GenHelper("1024") {}
}

contract Rave2048BitFuzzTester is RaveFuzzTester {
    constructor() X509GenHelper("2048") {}
}

contract Rave3072BitFuzzTester is RaveFuzzTester {
    constructor() X509GenHelper("3072") {}
}

contract Rave4096BitFuzzTester is RaveFuzzTester {
    constructor() X509GenHelper("4096") {}
}

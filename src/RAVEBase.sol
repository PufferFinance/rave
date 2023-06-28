// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { BytesUtils } from "ens-contracts/dnssec-oracle/BytesUtils.sol";
import { RSAVerify } from "ens-contracts/dnssec-oracle/algorithms/RSAVerify.sol";

abstract contract RAVEBase {
    using BytesUtils for *;

    uint256 constant MAX_JSON_ELEMENTS = 19;
    uint256 constant QUOTE_BODY_LENGTH = 432;
    uint256 constant MRENCLAVE_OFFSET = 112;
    uint256 constant MRSIGNER_OFFSET = 176;
    uint256 constant PAYLOAD_OFFSET = 368;
    uint256 constant PAYLOAD_SIZE = 64;

    bytes32 constant OK_STATUS = keccak256("OK");
    bytes32 constant HARDENING_STATUS = keccak256("SW_HARDENING_NEEDED");

    constructor() { }

    /*
    * @dev Verifies the RSA-SHA256 signature of the attestation report.
    * @param _report The attestation evidence report from IAS.
    * @param _sig The RSA-SHA256 signature over the report.
    * @param _signingMod The expected signer's RSA modulus
    * @param _signingExp The expected signer's RSA exponent
    * @return True if the signature is valid
    */
    function verifyReportSignature(
        bytes memory _report,
        bytes memory _sig,
        bytes memory _signingMod,
        bytes memory _signingExp
    ) public view returns (bool) {
        // Use _signingPK to verify _sig is the RSA signature over sha256(_report)
        (bool _success, bytes memory _got) = RSAVerify.rsarecover(_signingMod, _signingExp, _sig);
        // Last 32 bytes is recovered signed digest
        bytes32 _recovered = _got.readBytes32(_got.length - 32);
        return _success && _recovered == sha256(_report);
    }

    /*
    * @dev Verifies that this report was signed by the expected signer, then extracts out the report's 64 byte payload.
    * @param _report The attestation evidence report from IAS.
    * @param _sig The RSA-SHA256 signature over the report.
    * @param _signingMod The expected signer's RSA modulus
    * @param _signingExp The expected signer's RSA exponent
    * @param _mrenclave The expected enclave measurement.
    * @param _mrsigner The expected enclave signer.
    * @return The 64 byte payload from the report.
    */
    function verifyRemoteAttestation(
        bytes memory _report,
        bytes memory _sig,
        bytes memory _signingMod,
        bytes memory _signingExp,
        bytes32 _mrenclave,
        bytes32 _mrsigner
    ) public view virtual returns (bytes memory _payload) { }

    /*
    * @dev Verifies that the _leafX509Cert was signed by the expected signer (_signingMod, _signingExp). Then uses _leafX509Cert RSA public key to verify the signature over the _report, _sig. The trusted _report is verified for correct fields and then the enclave' 64 byte commitment is extracted. 
    * @param _report The attestation evidence report from IAS.
    * @param _sig The RSA-SHA256 signature over the report.
    * @param _leafX509Cert The signed leaf x509 certificate.
    * @param _signingMod The expected signer's RSA modulus
    * @param _signingExp The expected signer's RSA exponent
    * @param _mrenclave The expected enclave measurement.
    * @param _mrsigner The expected enclave signer.
    * @return The 64 byte payload from the report.
    */
    function rave(
        bytes memory _report,
        bytes memory _sig,
        bytes memory _leafX509Cert,
        bytes memory _signingMod,
        bytes memory _signingExp,
        bytes32 _mrenclave,
        bytes32 _mrsigner
    ) public view virtual returns (bytes memory _payload) { }
}

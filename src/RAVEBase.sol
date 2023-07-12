// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { BytesUtils } from "ens-contracts/dnssec-oracle/BytesUtils.sol";
import { RSAVerify } from "ens-contracts/dnssec-oracle/algorithms/RSAVerify.sol";
import { IRave } from "rave/IRave.sol";

abstract contract RAVEBase is IRave {
    using BytesUtils for *;

    constructor() { }

    /**
     * @inheritdoc IRave
     */
    function verifyReportSignature(
        bytes memory report,
        bytes calldata sig,
        bytes memory signingMod,
        bytes memory signingExp
    ) public view returns (bool) {
        // Use signingPK to verify sig is the RSA signature over sha256(report)
        (bool success, bytes memory got) = RSAVerify.rsarecover(signingMod, signingExp, sig);
        // Last 32 bytes is recovered signed digest
        bytes32 recovered = got.readBytes32(got.length - 32);
        return success && recovered == sha256(report);
    }

    /**
     * @inheritdoc IRave
     */
    function verifyRemoteAttestation(
        bytes calldata report,
        bytes calldata sig,
        bytes memory signingMod,
        bytes memory signingExp,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) public view virtual returns (bytes memory payload) { }

    /**
     * @inheritdoc IRave
     */
    function rave(
        bytes calldata report,
        bytes calldata sig,
        bytes memory leafX509Cert,
        bytes memory signingMod,
        bytes memory signingExp,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) external view virtual returns (bytes memory payload) { }
}

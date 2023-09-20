/*
The most significant function in this module is rave().
The purpose of RAVE is to validate the integrity of an
'attestation report' vouched for by Intel and return the
reports payload body on success.

The process involves:
    (1) Re-constructing a JSON attestation report that
    byte-for-byte matches the original report returned by
    the appropriate Intel attestation APIs.
    (2) Confirming that the report was signed by an X509
    'leaf' certificate issued by a CA.
    (3) Confirming that this CA was in fact Intel
    (also known as the 'report attestation signer CA -- this
    cert can be found in the certs directory in both
    DER form and PEM form for convienence.)

The result is an API that can verify attestation reports
on-chain issued by Intel. Unfortunately, the process to
call the rave() function is quite involved. One has to:
    (1) Pack a special list of report fields as bytes.
    (2) Extract the right enclave hash values.
    (3) And pass in the right leaf certificate values.

All of this is easier said than done. But I've created some
scripts to make this a little easier.
    (1) There is a script that takes the output of the
    secure signer binary (ss_out) and converts it into a
    list of hex data for calling rave(). It can be found in
    /test/scripts/bin/ss_to_abi. The bin directory also
    contains other useful commands for working with certs
    and doing operations needed for RAVE. You will need to cd
    to this dir to use them though.
    (2) There is also a script demonstrating full deployment
    of the RAVE contract and calling rave() from scratch
    using the above function. It can be found in my fork
    here: https://github.com/matthew-puffer-finance-forks/rave-foundry/blob/master/deploy.sh
*/


// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { RAVEConsts } from "./RAVEConsts.sol";
import { X509Verifier } from "./X509Verifier.sol";
import { JSONBuilder } from "./JSONBuilder.sol";
import { BytesUtils } from "ens-contracts/dnssec-oracle/BytesUtils.sol";
import { Base64 } from "openzeppelin-contracts/contracts/utils/Base64.sol";
import { RAVEBase } from "./RAVEBase.sol";
import { Test, console } from "forge-std/Test.sol";

/**
 * @title RAVE
 * @author PufferFinance
 * @custom:security-contact security@puffer.fi
 * @notice RAVe is a smart contract for verifying Remote Attestation evidence.
 */
contract RAVE is Test, RAVEBase, JSONBuilder, X509Verifier {
    using BytesUtils for *;

    constructor() { }

    /**
     * @inheritdoc RAVEBase
     */
    function verifyRemoteAttestation(
        // ABI encoded list of report fields as bytes.
        bytes calldata reportFieldsABI,
        bytes memory sig,
        bytes memory signingMod,
        bytes memory signingExp,
        bytes memory mrenclave,
        bytes memory mrsigner
    ) public view override returns (bytes memory payload) {
        // Decode the encoded report JSON values to a Values struct and reconstruct the original JSON string
        (Values memory reportValues, bytes memory reportBytes) = _buildReportBytes(reportFieldsABI);
        console.log(string(reportBytes));

        // Verify the report's contents match the expected
        payload = _verifyReportContents(reportValues, mrenclave, mrsigner);
        

        // Verify the report was signed by the SigningPK
        if (!verifyRSA(reportBytes, sig, signingMod, signingExp)) {
            console.logBytes(sig); 
            revert BadReportSignature();
        }


        return payload;
    }



    /**
     * @inheritdoc RAVEBase
     */
    function rave(
        // ABI encoded list of report fields as bytes.
        bytes calldata report,

        /*
        RSA encryption of the report from the leaf cert.
        The exact algorithm is: sha256WithRSA (PKCS#1 padding.)
        The signature can be verified with the signing
        public key found inside the leaf X509 cert.
        */
        bytes memory sig,

        /*
        This can be a leaf certificate issued by Intel's
        'report signing CA' or it can be a self-signed cert.
        Refer to the field bellow for more details.
        */
        bytes memory leafX509Cert,

        /*
        The fields here allow passing in the parameters
        for the CA who issued the leaf certificate.
        Set the bytes to empty for both to force it to use
        the Intel root CA. Otherwise, you can pass in your
        own values to test the function with self-signed certs.
        */
        bytes memory signingMod,
        bytes memory signingExp,

        /*
        These are special values that belong to the enclave binary
        and hardware that did the attestation report.
        You can gather them using:
            occlum print mrenclave
            occlum print mrsigner
        In the enclave directory.
        */
        bytes memory mrenclave,
        bytes memory mrsigner
    ) public view override returns (bytes memory payload) {
        /*
        The root CA params are hard-coded in the contract.
        If blank data is passed to the function use these values.
        Otherwise use the passed values so self-signed certs
        can be used as input test data.
        */
        if(
            (signingMod.compare(NULL) == 0)
                &&
            (signingExp.compare(NULL) == 0)
        ) {
            signingMod = _INTEL_ROOT_MOD;
            signingExp = _INTEL_ROOT_EXP;
        }

        // Verify the leafX509Cert was signed with signingMod and signingExp
        (bytes memory leafCertModulus, bytes memory leafCertExponent) =
           verifySignedX509(leafX509Cert, signingMod, signingExp);

        // Verify report has expected fields then extract its payload
        console.logBytes(leafCertModulus);
        console.logBytes(leafCertExponent);

        // TODO: remove this patch for mod extraction.
        bytes memory truncMod = abi.encodePacked(leafCertModulus.substring(1, leafCertModulus.length - 1));
        console.logBytes(truncMod);
        console.log(truncMod.length);

        console.log("leaf cert modulus");
        console.log(leafCertModulus.length);
        payload = verifyRemoteAttestation(report, sig, truncMod, leafCertExponent, mrenclave, mrsigner);
        return payload;
    }

    /*
    * @dev Builds the JSON report string from the abi-encoded `encodedReportValues`. The assumption is that `isvEnclaveQuoteBody` value was previously base64 decoded off-chain and needs to be base64 encoded to produce the message-to-be-signed.

    Ref: https://www.intel.com/content/dam/develop/public/us/en/documents/sgx-attestation-api-spec.pdf p24

    * @param encodedReportValues The values from the attestation evidence report JSON from IAS.
    * @return reportValues The JSON values as a Values struct for easier processing downstream
    * @return reportBytes The exact message-to-be-signed
    */
    function _buildReportBytes(bytes memory encodedReportValues)
        internal
        view
        returns (Values memory reportValues, bytes memory reportBytes)
    {
        // Decode the report JSON values
        (
            // string of numbers = 123213124
            bytes memory id,

            // string of data:time = 2023-02-15T01:24:57.989456
            bytes memory timestamp,

            // string of numbers = 4
            bytes memory version,

            /*
                (opt) b64 EPID B (64 bytes) & EPID K (64 bytes)
                components of EPID signature. 
            */
            bytes memory epidPseudonym,

            // (opt) string with advisory url
            bytes memory advisoryURL,

            // (opt) string with a python-like list = ['test']
            bytes memory advisoryIDs,

            // string for the status = OK
            bytes memory isvEnclaveQuoteStatus,

            /*
                raw bytes of the quote body
                normally this field in the verification report is
                base64 encoded but having to decode this on-chain =
                horrible waste of gas.
            */
            bytes memory isvEnclaveQuoteBody
        ) = abi.decode(encodedReportValues, (bytes, bytes, bytes, bytes, bytes, bytes, bytes, bytes));

        // Assumes the quote body was already decoded off-chain
        bytes memory encBody = bytes(Base64.encode(isvEnclaveQuoteBody));

        // Pack values to struct
        reportValues = JSONBuilder.Values(
            id, timestamp, version, epidPseudonym, advisoryURL, advisoryIDs, isvEnclaveQuoteStatus, encBody
        );

        // Reconstruct the JSON report that was signed
        reportBytes = bytes(buildJSON(reportValues));

        // Pass on the decoded value for later processing
        reportValues.isvEnclaveQuoteBody = isvEnclaveQuoteBody;
    }

    /*
    * @dev Parses a report, verifies the fields are correctly set, and extracts the enclave' 64 byte commitment.
    * @param reportValues The values from the attestation evidence report JSON from IAS.
    * @param mrenclave The expected enclave measurement.
    * @param mrsigner The expected enclave signer.
    * @return The 64 byte payload if the mrenclave and mrsigner values were correctly set.
    */
    function _verifyReportContents(Values memory reportValues, bytes memory mrenclave, bytes memory mrsigner)
        internal
        pure
        returns (bytes memory payload)
    {
        // check enclave status
        bytes32 status = keccak256(reportValues.isvEnclaveQuoteStatus);
        require(status == OK_STATUS || status == HARDENING_STATUS, "bad isvEnclaveQuoteStatus");

        // quote body is already base64 decoded
        bytes memory quoteBody = reportValues.isvEnclaveQuoteBody;
        assert(quoteBody.length == QUOTE_BODY_LENGTH);

        // Verify report's MRENCLAVE matches the expected
        bytes32 mre = quoteBody.readBytes32(MRENCLAVE_OFFSET);
        bytes32 mre2 = mrenclave.readBytes32(0);
        require(mre2 == mre);

        // Verify report's MRSIGNER matches the expected
        bytes32 mrs = quoteBody.readBytes32(MRSIGNER_OFFSET);
        bytes32 mrs2 = mrsigner.readBytes32(0);
        require(mrs == mrs2);

        // Verify report's <= 64B payload matches the expected
        payload = quoteBody.substring(PAYLOAD_OFFSET, PAYLOAD_SIZE);
    }
}

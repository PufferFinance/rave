#!/bin/python3

import base64
import sys
import json
import hashlib

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from eth_utils import to_bytes, encode_hex, to_hex
import eth_abi

mrenclave_offset = 112
mrsigner_offset = 176
payload_offset = 368
quote_body_length = 432

def build_quote_body(mre, mrs, payload) -> bytes:
    assert len(mre) == 32
    assert len(mrs) == 32
    assert len(payload) <= 64
    assert len(payload) <= 64
    body_bytes = bytes(mrenclave_offset) + mre
    body_bytes += bytes(mrsigner_offset - len(body_bytes)) + mrs
    body_bytes += bytes(payload_offset - len(body_bytes)) + payload
    body_bytes += bytes(64 - len(payload)) # pad extra bytes with 0s
    assert len(body_bytes) == quote_body_length 
    return body_bytes

def mock_evidence(mrenclave, mrsigner, payload):
    quote_body = build_quote_body(mrenclave, mrsigner, payload)
    assert mrenclave == bytes(quote_body[mrenclave_offset:mrenclave_offset+32])
    assert mrsigner == bytes(quote_body[mrsigner_offset:mrsigner_offset+32])
    assert payload == bytes(quote_body[payload_offset:payload_offset+64])

    quote_body = base64.b64encode(quote_body).decode('utf-8')

    evidence = {
        "id":"142090828149453720542199954221331392599",
        "timestamp":"2023-02-15T01:24:57.989456",
        "version":4,
        "epidPseudonym":"EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhLO4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/tepdezMsSB8Go=",
        "advisoryURL":"https://security-center.intel.com",
        "advisoryIDs":["INTEL-SA-00334","INTEL-SA-00615"],
        "isvEnclaveQuoteStatus":"OK",
        "isvEnclaveQuoteBody": quote_body
    }
    return evidence 

def sign(fname, message) -> bytes:
    # Load the private key from a file
    with open(fname, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    hash_func = hashlib.sha256()
    hash_func.update(message)
    digest = hash_func.digest()
    signature = private_key.sign(digest, padding.PKCS1v15(), hashes.SHA256())
    return signature


def main():
    # mrenclave = bytes.from_hex(sys.argv[1])
    # mrsigner = bytes.from_hex(sys.argv[2])
    # payload = bytes.from_hex(sys.argv[3])

    exp_mre = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    exp_mrs = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    exp_payload = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
    mrenclave = bytes.fromhex(exp_mre)
    mrsigner = bytes.fromhex(exp_mrs)
    payload = bytes.fromhex(exp_payload)

    evidence = mock_evidence(mrenclave, mrsigner, payload)
    evidence_bytes = json.dumps(evidence).encode('utf-8')
    # print(evidence_bytes)

    fname = 'x509SigningKey.pem'
    signature = sign(fname, evidence_bytes)

    # abi encode bytes
    ffi_payload = eth_abi.encode(['bytes', 'bytes'], [evidence_bytes, signature])
    print(ffi_payload.hex())

if __name__ == "__main__":
    main()
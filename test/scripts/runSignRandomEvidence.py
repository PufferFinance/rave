#!/bin/python3

from collections import OrderedDict
import base64
import sys
import json

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import eth_abi

MRENCLAVE_OFFSET = 112
MRSIGNER_OFFSET = 176
PAYLOAD_OFFSET = 368
QUOTE_BODY_LENGTH = 432

def build_quote_body(mre, mrs, payload) -> bytes:
    assert len(mre) == 32
    assert len(mrs) == 32
    assert len(payload) <= 64
    body_bytes = bytes(MRENCLAVE_OFFSET) + mre
    body_bytes += bytes(MRSIGNER_OFFSET - len(body_bytes)) + mrs
    body_bytes += bytes(PAYLOAD_OFFSET - len(body_bytes)) + payload
    body_bytes += bytes(64 - len(payload)) # pad extra bytes with 0s
    assert len(body_bytes) == QUOTE_BODY_LENGTH 
    return body_bytes

def mock_evidence(mrenclave, mrsigner, payload):
    quote_body = build_quote_body(mrenclave, mrsigner, payload)
    assert mrenclave == bytes(quote_body[MRENCLAVE_OFFSET:MRENCLAVE_OFFSET+32])
    assert mrsigner == bytes(quote_body[MRSIGNER_OFFSET:MRSIGNER_OFFSET+32])
    assert payload == bytes(quote_body[PAYLOAD_OFFSET:PAYLOAD_OFFSET+len(payload)])

    enc_quote_body = base64.b64encode(quote_body).decode('utf-8')
    evidence = OrderedDict([
        ('id', '142090828149453720542199954221331392599'),
        ('timestamp', "2023-02-15T01:24:57.989456"),
        ('version', 4),
        ('epidPseudonym', "EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhLO4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/tepdezMsSB8Go="),
        ("advisoryURL", "https://security-center.intel.com"),
        ("advisoryIDs", ["INTEL-SA-00334","INTEL-SA-00615"]),
        ("isvEnclaveQuoteStatus", "OK"),
        ("isvEnclaveQuoteBody", f"{enc_quote_body}"),
        
    ])
    
    return evidence, quote_body

def prepare_values(e: dict, dec_quote_body: bytes) -> bytes:
        vs = []
        for k, v in e.items():
            # insert base64 decoded quote
            if k == 'isvEnclaveQuoteBody':
                vs.append(dec_quote_body)
            else:
                if type(v) != str:
                    # handle lists and integers
                    vs.append(json.dumps(v).replace(" ", "").encode('utf-8'))
                else:
                    vs.append(v.encode('utf-8'))

        values_payload = eth_abi.encode(['bytes'] * len(vs), vs)
        return values_payload


def sign(fname, message) -> bytes:
    # Load the private key from a file
    with open(fname, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return signature


def main():
    # Prepare inputs
    stripped_mre = sys.argv[1].lstrip('0x')
    stripped_mrs = sys.argv[2].lstrip('0x')
    stripped_payload = sys.argv[3].lstrip('0x')
    mrenclave = '0' * (64 - len(stripped_mre)) + stripped_mre
    mrsigner = '0' * (64 - len(stripped_mrs)) + stripped_mrs
    payload = '0' * (128 - len(stripped_payload)) + stripped_payload
    mrenclave = bytes.fromhex(mrenclave)
    mrsigner = bytes.fromhex(mrsigner)
    payload = bytes.fromhex(payload)

    # mock json report
    evidence, dec_quote_body = mock_evidence(mrenclave, mrsigner, payload)

    # json -> bytes to sign (ignoring whitespace)
    evidence_bytes = json.dumps(evidence).replace(" ", "").encode('utf-8')
    with open('/tmp/evidence_b.json', 'wb') as f:
        f.write(evidence_bytes)

    # sign json bytes (send as base64 decoded)
    fname = sys.argv[4]
    signature = sign(fname, evidence_bytes)

    # convert JSON values to abi-encoded bytes to send to contract 
    values_payload = prepare_values(evidence, dec_quote_body)

    # Send only the report's JSON values 
    ffi_payload = eth_abi.encode(['bytes', 'bytes'], [signature, values_payload])

    # save payload for debug
    with open('/tmp/evidence.json', 'w') as f:
        d = dict(evidence=evidence, quote_body=dec_quote_body.hex())
        f.write(json.dumps(d))
    
    # print for ffi interface
    print(ffi_payload.hex())

if __name__ == "__main__":
    main()
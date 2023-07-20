"""
Generate RSA PKCS#1 encoded messages so they can be used
to compare to the implementation in X509Verifier.sol.
"""

from utils import *
import os, eth_abi, argparse, sys
from Crypto.Signature import pkcs1_15
from Crypto.Signature.pkcs1_15 import _EMSA_PKCS1_V1_5_ENCODE
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util import number
from Crypto.Util.number import ceil_div, bytes_to_long, long_to_bytes


def get_rsa_pkcs1_padding(msg, pem_priv, include_null=True):
    # Load RSA key params from PEM private key.
    key = RSA.import_key(pem_priv)

    # Hash the message with SHA256.
    h = SHA256.new(to_b(msg))

    # Create a padding object. 
    pad = pkcs1_15.new(key)

    # See 8.2.1 in RFC 3447.
    modBits = number.size(pad._key.n)

    # Convert from bits to bytes.
    k = ceil_div(modBits, 8)

    # Return the padded message with null params for der(HID, h).
    # DerObject.__init__(self, 0x05, b'', None, False)
    # b'\x05\x00'
    em = _EMSA_PKCS1_V1_5_ENCODE(h, k, include_null)

    # NOTE: Very important: may need to test both of these in our script.
    # WITH and WITHOUT the algorithm id!
    return em

if __name__ == "__main__":
    # Command-line args.
    parser = argparse.ArgumentParser()
    parser.add_argument('-msg', '--msg')
    parser.add_argument('-pem_priv', '--pem_priv')
    parser.add_argument('-inc_null', '--inc_null')
    args = vars(parser.parse_args(sys.argv[1:]))

    # Details to pad.
    msg = "hello world!"
    rsa_key = pem_priv = None
    pem_path = os.path.join('test', 'mocks', 'test_rsa_priv.pem.hex')
    with open(pem_path) as f:
        pem_priv = from_hex(f.read())

    # Process any command-line args.
    inc_null = True
    for opt in args:
        # Not set.
        arg = args[opt]
        if arg is None:
            continue

        if opt in ("msg"):
            msg = base64.b64decode(to_b(arg))

        if opt in ("pem_priv"):
            pem_priv = base64.b64decode(to_b(arg))

        if opt in ("inc_null"):
            inc_null = True if arg == "True" else False
        
    # Get padded msg.
    em = get_rsa_pkcs1_padding(msg, pem_priv, inc_null)
    ffi_payload = eth_abi.encode(
        ['bytes'], 
        [em]
    )

    # Return results.
    print(ffi_payload.hex(),)
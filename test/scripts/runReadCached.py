#!/bin/python3

import sys
import json

import eth_abi


def main():
    key_bits = str(sys.argv[1])

    # * data expected to be decoded in this order *
    files = ["cert-hex.txt", "cert-body-hex.txt", "modulus.txt", "cert-signature.txt"]

    # data expected to follow naming convention
    paths = [f"/tmp/{key_bits}BitSelfSignedx509.pem.{name}" for name in files]

    cached_data = []

    for p in paths:
        with open(p) as f:
            hex_data = f.read().strip('0x')
            bytes_data = bytes.fromhex(hex_data)
            cached_data.append(bytes_data)
        
    
    # abi encode all of the cached data
    ffi_payload = eth_abi.encode(['bytes'] * len(cached_data), cached_data).hex()

    # print for ffi interface
    print(ffi_payload)
    

if __name__ == "__main__":
    main()


# read cert from f"/tmp/{key_bits}BitSelfSignedx509.pem.cert-hex.txt"
# read body from f"/tmp/{key_bits}BitSelfSignedx509.pem.cert-body-hex.txt"
# read modulus from f"/tmp/{key_bits}BitSelfSignedx509.pem.modulus.txt"
# read signature from f"/tmp/{key_bits}BitSelfSignedx509.pem.cert-signature.txt"
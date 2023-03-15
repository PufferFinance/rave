#!/bin/bash

# get DER-encoded x509 certificate as hex string
CERT=$(openssl asn1parse -in $1 -out /tmp/cert-body.bin -noout && xxd -p /tmp/cert-body.bin | tr -d '\n')

# print to stdout for FFI
echo "0x${CERT}"
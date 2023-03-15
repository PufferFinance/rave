#!/bin/bash

# extract x509 certificate body as hex string
BODY=$(openssl asn1parse -in $1 -strparse 4 -out /tmp/cert-body.bin -noout && xxd -p /tmp/cert-body.bin | tr -d '\n')

# print to stdout for FFI
echo "0x${BODY}"
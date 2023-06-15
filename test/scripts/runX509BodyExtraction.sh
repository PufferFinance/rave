#!/bin/bash

in_file_name=$1
out_file_name="$1.cert-body-hex.txt"

# extract x509 certificate body as hex string
BODY=$(openssl asn1parse -in $in_file_name -strparse 4 -out /tmp/cert-body.bin -noout && xxd -p /tmp/cert-body.bin | tr -d '\n')

# print to stdout for FFI
echo "0x${BODY}"

# Save the output to file
echo "0x${BODY}" > $out_file_name
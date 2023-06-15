#!/bin/bash

in_file_name=$1
out_file_name="$1.cert-hex.txt"

# get DER-encoded x509 certificate as hex string
CERT=$(openssl asn1parse -in $in_file_name -out /tmp/cert-body.bin -noout && xxd -p /tmp/cert-body.bin | tr -d '\n')

# print to stdout for FFI
echo "0x${CERT}"

# Save the output to file
echo "0x${CERT}" > $out_file_name


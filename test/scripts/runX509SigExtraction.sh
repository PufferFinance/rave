#!/bin/bash

CERT=$1
in_file_name=$1
out_file_name="$1.cert-signature.txt"

# extract signature as hex string
SIGNATURE_HEX=$(openssl x509 -in $in_file_name -text -noout -certopt ca_default -certopt no_validity -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame | grep -v 'Signature Algorithm' | tr -d '[:space:]:')

# print to stdout for FFI
echo "0x${SIGNATURE_HEX}"

# Save the output to file
echo "0x${SIGNATURE_HEX}" > $out_file_name
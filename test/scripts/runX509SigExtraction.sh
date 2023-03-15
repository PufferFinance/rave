#!/bin/bash

CERT=$1

# extract signature as hex string
SIGNATURE_HEX=$(openssl x509 -in $CERT -text -noout -certopt ca_default -certopt no_validity -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame | grep -v 'Signature Algorithm' | tr -d '[:space:]:')

# print to stdout for FFI
echo "0x${SIGNATURE_HEX}"
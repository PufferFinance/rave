#!/bin/bash

BITS=$1
CERT_NAME=$2
KEY_NAME=$3

# Create a private key named $KEY_NAME and then self-sign an x509 certificate
# US\nCA\nSan Francisco\nMy Organization\nMy PARENT Name\n\n\n
out=$(echo -e "US\nCA\nSanta Clara\nIntel Corporation\nIntel SGX Attestation Report Signing\n\n\n" | openssl req -x509 -newkey rsa:$BITS -keyout $KEY_NAME -out $CERT_NAME -sha256 -days 365 -nodes 2>/dev/null)
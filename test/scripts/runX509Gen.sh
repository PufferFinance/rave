#!/bin/bash

BITS=$1
CERT_NAME=$2
KEY_NAME="SelfSigningPrivateKey.pem"

# Create a private key named $KEY_NAME and then self-sign an x509 certificate
echo -e "US\nCA\nSan Francisco\nMy Organization\nMy PARENT Name\n\n\n" | openssl req -x509 -newkey rsa:$BITS -keyout $KEY_NAME -out $CERT_NAME -sha256 -days 365 -nodes 
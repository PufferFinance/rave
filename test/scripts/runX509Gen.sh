#!/bin/bash

# Generates two new RSA private key with number of bits passed as command line arg
openssl genrsa -out parent_key.pem "$1"
openssl genrsa -out child_key.pem "$1"

# Create a parent x509 certificate with default args
echo -e "US\nCA\nSan Francisco\nMy Organization\nMy PARENT Name\n\n\n" | openssl req -new -x509 -key parent_key.pem -out parent.cer -days 365

# Create a child x509 certificate with default args
echo -e "US\nCA\nSan Francisco\nMy Organization\nMy CHILD Name\n\n\n" | openssl req -new -x509 -key child_key.pem -out child.cer -days 365

# Sign the child x509 certificate with the parent's key
openssl x509 -in child.cer -signkey parent_key.pem > signed_child.cer 
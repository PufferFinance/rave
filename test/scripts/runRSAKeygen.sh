#!/bin/bash

# Generates new RSA private key with number of bits passed as command line arg
openssl genrsa -out /tmp/private.pem "$1" 2>/dev/null

# Write the public key to file
openssl rsa -in /tmp/private.pem -outform der -pubout -out /tmp/public.der 2>/dev/null
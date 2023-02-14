#!/bin/bash

# Generates new RSA private key with number of bits passed as command line arg
openssl genrsa -out private.pem "$1"

# Write the public key to file
openssl rsa -in private.pem -outform der -pubout -out public.pem
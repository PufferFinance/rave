#!/bin/bash

# new key with $1 bits
openssl genrsa -out private.pem "$1"
# write public key to file
openssl rsa -in private.pem -outform der -pubout -out public.pem
#!/bin/bash

# Display all RSA public key metadata
keydata=$(openssl rsa -pubin -inform DER -text -noout < public.pem)

# Filter for the modulus (public key)
modulus=$(echo $keydata | sed -n 's/.*Modulus: \(.*\) Exponent.*/\1/p' | tr -d ' ')

# Extract out colons separating the bytes
no_colons=${modulus//:/}

# Prepend 0x
output="0x$no_colons"

# Print public key to stdout for FFI
echo $output
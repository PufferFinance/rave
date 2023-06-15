#!/bin/bash

der_file_name="/tmp/public.der"
out_file_name="/tmp/public.txt"

# Display all RSA public key metadata
keydata=$(openssl rsa -pubin -inform DER -text -noout < $der_file_name)

# Filter for the modulus (public key)
modulus=$(echo $keydata | sed -n 's/.*Modulus: \(.*\) Exponent.*/\1/p' | tr -d ' ')

# Extract out colons separating the bytes
no_colons=${modulus//:/}

# Prepend 0x
output="0x$no_colons"

# Print public key to stdout for FFI
echo $output

# Save the output to file
echo "$output" > $out_file_name

# openssl x509 -modulus -noout < public.cer | sed s/Modulus=/0x/
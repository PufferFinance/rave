#!/bin/bash

in_file_name=$1
out_file_name="$1.modulus.txt"

# get the modulus of the x509 cert, where input filename is passed as clarg
modulus=$(openssl x509 -modulus -noout < $in_file_name | sed s/Modulus=/0x/)

# Print modulus to stdout for FFI
echo $modulus

# Save the output to file
echo $modulus > $out_file_name
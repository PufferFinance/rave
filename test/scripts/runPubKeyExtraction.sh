#!/bin/bash

keydata=$(openssl rsa -pubin -inform DER -text -noout < public.pem)
modulus=$(echo $keydata | sed -n 's/.*Modulus: \(.*\) Exponent.*/\1/p' | tr -d ' ')
no_colons=${modulus//:/}
output="0x$no_colons"
echo $output
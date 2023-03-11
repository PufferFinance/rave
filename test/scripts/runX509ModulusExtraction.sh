#!/bin/bash

# Prints out the modulus of the x509 cert, where fname is passed as clarg
openssl x509 -modulus -noout < $1 | sed s/Modulus=/0x/
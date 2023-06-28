#!/bin/bash

# Sign the data passed in from the command line and print the hex-encoded signature to stdout
echo -n "$1" | openssl dgst -sha256 -sign /tmp/private.pem | xxd -p | tr -d \\n
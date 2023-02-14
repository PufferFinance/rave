#!/bin/bash

echo -n "$1" | openssl dgst -sha256 -sign private.pem -out | xxd -p | tr -d \\n
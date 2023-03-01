#!/bin/python3

import sys
import base64
from eth_utils import encode_hex, to_bytes

# expect valid utf-8 string as input
data = bytes(sys.argv[1], 'utf-8')

# base64 encrypt using std lib
enc = base64.b64encode(data)

# convert to proper hex value to send over ffi
bs = encode_hex(to_bytes(enc)).lstrip("0x")
print(bs)
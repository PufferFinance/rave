#!/bin/python3

from eth_utils import to_bytes, encode_hex, to_hex
import sys


def convert_to_int(input_value):
    if isinstance(input_value, bytes):
        # If the input is raw bytes, try to decode it as utf-8 first
        try:
            input_value = input_value.decode("utf-8")
        except:
            # If it fails, assume it's a hex-encoded string
            return int(input_value.hex(), 16)
    elif isinstance(input_value, str):
        # If the input is a string, check if it's hex-encoded
        if input_value.startswith("0x"):
            return int(input_value, 16)
        # If it's not hex-encoded, check if it's a decimal string
        try:
            return int(input_value)
        except:
            # If it's not a decimal string, assume it's utf-8 encoded
            return int(input_value.encode().hex(), 16)
    else:
        # If the input is not a string or bytes, return error
        raise ValueError("Invalid input type")


base = convert_to_int(sys.argv[1])
exp = convert_to_int(sys.argv[2])
mod = convert_to_int(sys.argv[3])

# compute modular exponentiation
res = pow(base, exp, mod)

# encode as hex string
bs = encode_hex(to_bytes(res)).lstrip("0x")

# figure out padding
num_bytes = max((mod.bit_length() + 7) // 8, 32)  # modulus width or at least 32B
num_hex_digits = num_bytes * 2
pad_zeroes = num_hex_digits - len(bs)
out = "0x" + pad_zeroes * "0" + bs

# stdout -> ffi
print(out)

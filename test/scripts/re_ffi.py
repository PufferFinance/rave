from utils import *
import re, eth_abi, argparse, sys

"""
usage:
pattern (as hex) hey (as hex)

"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--p')
    parser.add_argument('-s', '--s')
    args = vars(parser.parse_args(sys.argv[1:]))
    p = s = None
    for opt in args:
        arg = args[opt]
        if opt in ('p'):
            p = b64_decode(arg)

        if opt in ('s'):
            s = b64_decode(arg)

    out = [to_b(to_hex(x)) for x in re.findall(p, s)]
    out_len = len(out)
    if out_len:
        ffi_payload = eth_abi.encode(
            ['bytes'] * out_len, 
            out
        )
    else:
        ffi_payload = eth_abi.encode(
            ['bytes'],
            [b'']
        )

    print(ffi_payload.hex(),)



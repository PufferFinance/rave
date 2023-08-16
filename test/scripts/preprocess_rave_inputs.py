from utils import *
import re, eth_abi, argparse, sys


"""
        bytes calldata report,
        bytes calldata sig,
        bytes memory leafX509Cert,
        bytes memory signingMod,
        bytes memory signingExp,
        bytes32 mrenclave,
        bytes32 mrsigner

tthew@matthew-secure-signer-dev:~/projects/rave-foundry$ cp -R ../rave lib/rave
matthew@matthew-secure-signer-dev:~/projects/rave-foundry$ forge create --rpc-url "http://127.0.0.1:8545" --private-key "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6" src/Main.sol:Main

"""

def cert_wrap(x):
    x = x.strip()
    return f"""-----BEGIN CERTIFICATE-----
{x}
-----END CERTIFICATE-----"""

# Process command line arguments.
parser = argparse.ArgumentParser()

# Output options.
parser.add_argument('-abi_encode', '--abi_encode')

# Always required.
parser.add_argument('-cert', '--cert')

# Used by abi encode.
parser.add_argument('-report', '--report')
parser.add_argument('-sig', '--sig')
parser.add_argument('-sig_mod', '--sig_mod')
parser.add_argument('-sig_exp', '--sig_exp')
parser.add_argument('-mrenclave', '--mrenclave')
parser.add_argument('-mrsigner', '--mrsigner')

# Args to dict.
args = vars(parser.parse_args(sys.argv[1:]))



if args["abi_encode"] is not None:
    # Trucate 0x prefix from args.
    rm_0x(args)


    # 
    unhex_list = [
        args["report"],
        args["sig"],
        args["cert"],
        args["sig_mod"],
        args["sig_exp"],
        args["mrenclave"],
        args["mrsigner"]
    ]

    # Convert hex strings to bytes.
    bytes_list = list_to_b([
        binascii.unhexlify(to_b(x)) for x in 
        unhex_list
    ])

    #bytes_list[0] = bytes_list[0].strip()
    bytes_list[1] = bytes_list[1].strip()
    ffi_payload = eth_abi.encode(
        [
            "bytes", # Report
            "bytes", # Sig
            "bytes", # Leaf cert
            "bytes", # Sig modulus
            "bytes", # Sig exponent
            "bytes32", # Mrenclave digest
            "bytes32", # Mrsigner digest
        ],
        bytes_list
    )

    # Add function name to out.
    out = sha3_hex(b"rave(bytes,bytes,bytes,bytes,bytes,bytes32,bytes32)")[:8]
    out = to_s(out) + ffi_payload.hex()
    #out = ffi_payload.hex()

    # Then dump everything as hex.
    print(out, end="")

    
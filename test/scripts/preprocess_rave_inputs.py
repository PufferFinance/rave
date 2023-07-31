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

cert_p = "([-]{2,}BEGIN[ ]+CERTIFICATE[-]{2,}(?:[^-]+)[-]{2,}END[ ]+CERTIFICATE[-]{2,})+"


parser = argparse.ArgumentParser()
parser.add_argument('-certs', '--certs')
parser.add_argument('-get_root', '--get_root')
parser.add_argument('-get_leaf', '--get_leaf')
args = vars(parser.parse_args(sys.argv[1:]))

# Unpack certs.
certs = from_hex(args["certs"])
certs = re.findall(cert_p, certs)
intel_root_cert, leaf_cert = certs


if args["get_root"] is not None:
    print(repr(intel_root_cert))

if args["get_leaf"] is not None:
    print(repr(leaf_cert))
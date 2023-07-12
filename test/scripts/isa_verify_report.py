from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import time
import datetime
import sys
import getopt
import binascii
import argparse
import os
import random
import eth_abi
import json

def get_timezome():
    now = datetime.datetime.now()
    return now.astimezone().tzinfo

def gen_rsa_keys():
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_key = priv_key.public_key()
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return priv_key, priv_pem, pub_key, pub_pem

to_b = lambda x: x if type(x) == bytes else x.encode("ascii")
to_s = lambda x: x if type(x) == str else x.decode("utf-8")

def from_hex(x):
    return to_s(binascii.unhexlify(to_b(x)))

def to_hex(x):
    return to_s(binascii.hexlify(to_b(x)))

def load_rsa_priv(pem):
    return serialization.load_pem_private_key(
        to_b(pem),
        password=None,
        backend=default_backend()
    )

def load_rsa_pub(pem):
    return serialization.load_pem_public_key(to_b(pem))

def gen_rand_id(id_len=39):
    buf = ""
    for _ in range(id_len):
        buf += f'{random.choice(range(1, 10))}'

    return int(buf)

def gen_epid_pseudo():
    buf  = "EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh"
    buf += "+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGo"
    buf += "MU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhL"
    buf += "O4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/"
    buf += "tepdezMsSB8Go="

    return buf

def gen_quote_body():
    return """AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAfAAAAAAAAANCud0d0wgZKYN2SVB/MfLizrN6g15PzsnonpE2/cedfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACk8eLeQq3kKFam57ApQyJ412rRw+hs7M1vL0ZTKGHCDAYVo7T4o+KD0jwJJV5RNg4AAAAAAAAAAAAAAAAAAAAA"""

def abi_dict_to_bytes(e: dict) -> bytes:
        vs = []
        for k, v in e.items():
            if type(v) != str:
                # handle lists and integers
                vs.append(json.dumps(v).replace(" ", "").encode('utf-8'))
            else:
                vs.append(v.encode('utf-8'))

        values_payload = eth_abi.encode(['bytes'] * len(vs), vs)
        return values_payload

class ISAVerifyReport():
    def __init__(self):
        self.id = gen_rand_id()
        self.timestamp = time.time()
        self.version = 4
        self.epid_pseudo = gen_epid_pseudo()
        self.advisory_url = "https://security-center.intel.com"
        self.advisory_ids = [
            "INTEL-SA-00334",
            "INTEL-SA-00615"
        ]
        self.quote_status = "SW_HARDENING_NEEDED"
        self.quote_body = gen_quote_body()

    def set_rsa_keys(self):
        # Setup key pairs used for signing.
        self.priv_key, self.priv_pem, \
        self.pub_key, self.pub_pem = \
        gen_rsa_keys()

    def use_rsa_test_keys(self):
        def load_hex(file_name):
            path = os.path.join("test", "mocks", file_name)
            with open(path, 'r') as f:
                return f.read()

        self.priv_pem = from_hex(load_hex('test_rsa_priv.pem.hex'))
        self.priv_key = load_rsa_priv(self.priv_pem)
        self.pub_pem = from_hex(load_hex('test_rsa_pub.pem.hex'))
        self.pub_key = load_rsa_pub(self.pub_pem)

    def toJson(self):
        # Random report ID.
        out  = f'"id":"{self.id}",'

        # Build timestamp portion from unix timestamp.
        tz = get_timezome()
        dt = datetime.datetime.fromtimestamp(self.timestamp, tz)
        dt_str = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
        out += f'"timestamp":"{dt_str}",'

        # Meta data for the report.
        out += f'"version":{self.version},'
        out += f'"epidPseudonym":"{self.epid_pseudo}",'

        # Optionally added based on isv_quote_status.   
        if self.quote_status == "SW_HARDENING_NEEDED":
            out += f'"advisoryURL":"{self.advisory_url}",'

            # Generate advisory id string.
            advisory_ids = [f'"{x}"' for x in self.advisory_ids]
            advisory_str = ",".join(advisory_ids)
            out += f'"advisoryIDs":[{advisory_str}],'

        # Last fields about the quote.
        out += f'"isvEnclaveQuoteStatus":"{self.quote_status}",'
        out += f'"isvEnclaveQuoteBody":"{self.quote_body}"'

        # Wrap everything in braces.
        return '{' + out + '}'

    def sign(self):
        report = self.toJson()
        sig = self.priv_key.sign(
            report.encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return to_hex(sig)

    def __str__(self):
        # Serialize this object as a JSON str.
        report = self.toJson()

        # Build the output keys as hex.
        sig = self.sign()
        pub_key = to_hex(self.pub_pem)
        priv_key = to_hex(self.priv_pem)

        # Spaces break up arguments.
        # Be sure that the report doesn't have spaces.
        for v in [report, sig, pub_key, priv_key]:
            assert(' ' not in v)

        # Return a signed verification report.
        return f'{report} {sig} {pub_key} {priv_key}'

    def ffi(self):
        return [
            #abi_dict_to_bytes(self.toJson()),
            to_b(self.toJson()),
            to_b(self.sign()),
            to_b(to_hex(self.pub_pem)),
            to_b(to_hex(self.priv_pem))
        ]

    def to_dict(self):
        return json.loads(self.toJson())

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-abi_out', '--abi_out')
    parser.add_argument('-id', '--id')
    parser.add_argument('-timestamp', '--timestamp')
    parser.add_argument('-version', '--version')
    parser.add_argument('-epid_pseudo', '--epid_pseudo')
    parser.add_argument('-advisory_url', '--advisory_url')
    parser.add_argument('-advisory_ids', '--advisory_ids')
    parser.add_argument('-quote_status', '--quote_status')
    parser.add_argument('-quote_body', '--quote_body')
    parser.add_argument('-pem_priv', '--pem_priv')
    parser.add_argument('-pem_pub', '--pem_pub')
    parser.add_argument('-use_test_key', '--use_test_key')
    args = vars(parser.parse_args(sys.argv[1:]))

    abi_out = False
    do_gen_rsa_keys = True
    report = ISAVerifyReport()
    for opt in args:
        # Not set.
        arg = args[opt]
        if arg is None:
            continue

        # Exec is used later on.
        # Only accept values that don't contain Python.
        try:
            compile(arg, '<stdin>', 'eval')
        except SyntaxError:
            continue

        if opt in ("abi_out"):
            abi_out = True
            continue

        if opt in ("pem_priv"):
            report.priv_pem = arg
            report.priv_key = load_rsa_priv(arg)
            do_gen_rsa_keys = False

        if opt in ("pem_pub"):
            report.pub_pem = arg
            report.pub_key = load_rsa_pub(arg)
            do_gen_rsa_keys = False

        if opt in ("use_test_key"):
            report.use_rsa_test_keys()
            do_gen_rsa_keys = False

        # Overwrite report fields.
        exec(f'report.{opt} = "{arg}"')

    # Generate new RSA key pairs.
    if do_gen_rsa_keys:
        report.set_rsa_keys()

    # Generate output for foundary.
    if abi_out:
        ffi_payload = eth_abi.encode(
            ['bytes'] * 4, 
            report.ffi()
        )
    
        print(ffi_payload.hex())
    else:
        # sig report
        print(report)
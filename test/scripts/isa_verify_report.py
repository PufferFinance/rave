from utils import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import time, datetime, sys, getopt, binascii, argparse
import os, random, eth_abi, json, base64, re


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

def verify_json(s):
    d = json.loads(s)
    req_fields = [
        'id',
        'timestamp',
        'version',
        'epidPseudonym',
        'isvEnclaveQuoteStatus',
        'isvEnclaveQuoteBody'
    ]

    # Check required fields are present.
    for field in req_fields:
        assert(field in d)
        d[field] = str(d[field])

    # ID is numeric.
    assert(re.match('^[0-9]+$', d['id']))

    # Timestamp matches date + time format.
    p = '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]+$'
    assert(re.match(p, d['timestamp']))

    # Version is numeric.
    assert(re.match('^[0-9]+$', d['version']))

    # EPID is b64.
    b64_p = '^[0-9a-zA-Z\/=+]+$'
    assert(re.match(b64_p, d['epidPseudonym']))

    # Advisory URL is correct.
    if 'advisoryURL' in d:
        assert(d['advisoryURL'] == 'https://security-center.intel.com')
        assert('advisoryIDs' in d)

    # Advisory IDs in Intel's format.
    if 'advisoryIDs' in d:
        p = '\[(,?"INTEL[-]SA[-][0-9]{5}")+\]'
        assert(re.match(p, d['advisoryIDs']))
        assert('advisoryURL' in d)

    # Quote status is correct.
    assert(d['isvEnclaveQuoteStatus'] in ('OK', 'SW_HARDENING_NEEDED'))

    # Quote body is b64.
    assert(re.match(b64_p, d['isvEnclaveQuoteBody']))


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

    def get_timestamp(self):
        tz = get_timezome()
        dt = datetime.datetime.fromtimestamp(self.timestamp, tz)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")

    def get_advisory_ids(self):
        advisory_ids = [f'"{x}"' for x in self.advisory_ids]
        advisory_ids = ",".join(advisory_ids)
        return f'[{advisory_ids}]'

    def get_quote_body(self):
        qb = base64.b64decode(self.quote_body)
        return to_b(qb)

    def toJson(self):
        # Random report ID.
        out  = f'"id":"{self.id}",'

        # Build timestamp portion from unix timestamp.
        timestamp = self.get_timestamp()
        out += f'"timestamp":"{timestamp}",'

        # Meta data for the report.
        out += f'"version":{self.version},'
        out += f'"epidPseudonym":"{self.epid_pseudo}",'

        # Optionally added based on isv_quote_status.   
        if self.quote_status == "SW_HARDENING_NEEDED":
            out += f'"advisoryURL":"{self.advisory_url}",'

            # Generate advisory id string.
            advisory_str = self.get_advisory_ids()
            out += f'"advisoryIDs":{advisory_str},'

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

    def to_dict(self):
        return json.loads(self.toJson())

    def out_program_args(self):
        return list_to_b(str(self).split(' '))

    def out_report_list(self):
        return eth_abi.encode(
            ['bytes'] * 8, 
            list_to_b(
                [
                    f'{self.id}',
                    f'{self.get_timestamp()}',
                    f'{self.version}',
                    f'{self.epid_pseudo}',
                    f'{self.advisory_url}',
                    f'{self.get_advisory_ids()}',
                    f'{self.quote_status}',
                    self.get_quote_body()
                ]
            )
        )

    def out_values_struct(self):
        return eth_abi.encode(
            ['(' + (',bytes' * 8)[1:] + ')'],
            [(
                to_b(f'{self.id}'),
                to_b(f'{self.get_timestamp()}'),
                to_b(f'{self.version}'),
                to_b(f'{self.epid_pseudo}'),
                to_b(f'{self.advisory_url}'),
                to_b(f'{self.get_advisory_ids()}'),
                to_b(f'{self.quote_status}'),
                to_b(gen_quote_body()),
            )]
        )

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-out', '--out')
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
    parser.add_argument('-verify_json', '--verify_json')
    args = vars(parser.parse_args(sys.argv[1:]))

    out = ''
    do_gen_rsa_keys = True
    report = ISAVerifyReport()
    ffi_payload = None
    json_in = None
    for opt in args:
        # Not set.
        arg = args[opt]
        if arg is None:
            continue

        if opt in ("out"):
            out = arg
            continue

        if opt in ("verify_json"):
            out = "verify_json"
            json_in = arg
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
    if out == 'program_args':
        ffi_payload = eth_abi.encode(
            ['bytes'] * 4, 
            report.out_program_args()
        )
        
    elif out == 'report_list':
        print(report.out_report_list())

    elif out == 'values_struct':
        ffi_payload = report.out_values_struct()

    elif out == "verify_json":
        json_in = to_s(base64.b64decode(to_b(json_in)))
        verify_json(json_in)
        print("success")

    else:
        print(report)

    if ffi_payload is not None:
        print(ffi_payload.hex(),)
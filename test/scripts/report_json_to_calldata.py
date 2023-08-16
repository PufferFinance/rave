import sys
import json
import eth_abi
import base64
from utils import *

report = """{\"id\":\"110476064596730008034271421949666627812\",\"timestamp\":\"2023-08-02T01:14:44.710374\",\"version\":4,\"epidPseudonym\":\"EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsg3vJ/jYtxE7QKoJypEq0wf9UVdBV8ObzwbdyJnrSlaupBDoXTtMHZ22Pn/Ek2IVpq1LnrV3fzjRjf8+DK3lq70=\",\"advisoryURL\":\"https://security-center.intel.com\",\"advisoryIDs\":[\"INTEL-SA-00334\",\"INTEL-SA-00615\"],\"isvEnclaveQuoteStatus\":\"SW_HARDENING_NEEDED\",\"isvEnclaveQuoteBody\":\"AgABAKwMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFRULB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAfAAAAAAAAAHtuArxn6fp52elmtugVqAvx8yQDiSsb6ypFoJLoP8HlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACkGRraXOtBJeTRWO09P94OCQ1y1xbNo8G1t2D+3K/PiLpWcyzRHc4ZRCaUNwpkw44AAAAAAAAAAAAAAAAAAAAA\"}"""

def prepare_values(e: dict) -> bytes:
    param_names = [
        "id",
        "timestamp",
        "version",
        "epidPseudonym",
        "advisoryURL",
        "advisoryIDs",
        "isvEnclaveQuoteStatus",

        # Decode this
        "isvEnclaveQuoteBody"
    ]

    vs = []
    for k in param_names:
        # insert base64 decoded quote
        v = e[k]
        if k == 'isvEnclaveQuoteBody':
            quote_body = base64.b64decode(to_b(v))
            vs.append(quote_body)
        else:
            if type(v) != str:
                # handle lists and integers
                vs.append(
                    to_b(json.dumps(v).replace(" ", ""))
                )
            else:
                vs.append(to_b(v))

    values_payload = eth_abi.encode(['bytes'] * len(vs), vs)
    return values_payload.hex()

report_hex = sys.stdin.read().strip()
report = from_hex(report_hex)
as_dict = json.loads(report)
out = prepare_values(as_dict)
print(out,)
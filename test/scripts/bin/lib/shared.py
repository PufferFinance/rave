import sha3

REPORT_FIELDS = [
    "id",
    "timestamp",
    "version",
    "epidPseudonym",
    "advisoryURL",
    "advisoryIDs",
    "isvEnclaveQuoteStatus",
    "isvEnclaveQuoteBody"
]

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {
            "type": "string",
            "pattern": "^[0-9]+$"
        },
        "timestamp": {
            "type": "string",
            "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]+$",
            "format": "date-time"
        },
        "version": {
            "type": "integer",
            "minimum": 1
        },
        "epidPseudonym": {
            "type": "string",
            "pattern": "^[0-9a-zA-Z\\/=+]+$"
        },
        "isvEnclaveQuoteStatus": {
            "type": "string",
            "pattern": "^OK|SW_HARDENING_NEEDED$"
        },
        "isvEnclaveQuoteBody": {
            "type": "string",
            "pattern": "^[0-9a-zA-Z\\/=+]+$"
        },
        "advisoryIDs": {
            "type": "array",
            "items": {
                "type": "string",
                "pattern": 'INTEL[-]SA[-][0-9]{5}',
            }
        },
        "advisoryURL": {
            "type": "string",
            "pattern": "https://security[-]center[.]intel[.]com"
        }
    },
    "required": [
        "id",
        "timestamp",
        "version",
        "epidPseudonym",
        "isvEnclaveQuoteStatus",
        "isvEnclaveQuoteBody"
    ]
}

def log(m):
    # Writing to file
    with open("error.log", "a") as fp:
        # Writing data to a file
        fp.write(m)

def sha3_hex(x):
    k = sha3.keccak_256()
    k.update(x)
    return k.hexdigest()
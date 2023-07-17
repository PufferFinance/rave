import base64, binascii

to_b = lambda x: x if type(x) == bytes else x.encode("ascii")
to_s = lambda x: x if type(x) == str else x.decode("utf-8")
list_to_b = lambda l: [to_b(x) for x in l]
b64_encode = lambda x: to_s(base64.b64encode(to_b(x)))
b64_decode = lambda x: to_s(base64.b64decode(to_b(x)))

def from_hex(x):
    return to_s(binascii.unhexlify(to_b(x)))

def to_hex(x):
    return to_s(binascii.hexlify(to_b(x)))
from eth_utils import keccak
import math
import random


# Function for extended Euclidean Algorithm
# Source: https://www.geeksforgeeks.org/python-program-for-basic-and-extended-euclidean-algorithms-2/
def gcd_extended(a, b):
    # Base Case
    if a == 0:
        return b, 0, 1

    gcd, x1, y1 = gcd_extended(b % a, a)

    # Update x and y using results of recursive call
    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y


def mod_inverse(a, m):
    gcd, x, y = gcd_extended(a, m)

    if gcd != 1:
        print("Not coprime!")
        raise ValueError

    return x % m


def get_large_prime(min_bit_width):
    min_p = pow(2, min_bit_width - 1)
    max_p = pow(2, min_bit_width) - 1

    # 2^-security level chance that the number is composite
    security_level = 100

    while True:
        # Not the most secure way to get rand number...
        prime_candidate = random.randint(min_p, max_p)
        tested = 0

        for _ in range(security_level):
            random_choice = random.randint(2, prime_candidate - 1)

            # Test primality using Fermat's Little Theorem
            if pow(random_choice, prime_candidate - 1, prime_candidate) != 1:
                prime_candidate = random.randint(min_p, max_p)
                break

            tested += 1

        if tested == security_level:
            break

    return prime_candidate


class RSA(object):
    modulus: int
    e: int
    private_key: int
    p: int
    q: int

    def __init__(self, p: int = None, q: int = None, mod_width: int = 4096):
        has_correct_values = False

        while not has_correct_values:
            if not p or not q:
                self.p = get_large_prime(math.floor(mod_width / 2.0))
                self.q = get_large_prime(math.ceil(mod_width / 2.0))

            else:
                self.p = p
                self.q = q

            # This is the "PublicKey"
            self.modulus = self.p * self.q

            # Hardcoded prime for efficiency
            self.e = 65537
            self.private_key = mod_inverse(self.e, (self.p - 1) * (self.q - 1))

            has_correct_values = True

    # Sign a hashed int value using your private key
    def sign_payload(self, hashed_payload_as_int):
        assert hashed_payload_as_int < self.modulus
        return pow(hashed_payload_as_int, self.private_key, self.modulus)

    # Decrypt a payload that was encrypted with your public key
    def decrypt_payload(self, payload_as_int):
        assert payload_as_int < self.modulus
        return pow(payload_as_int, self.private_key, self.modulus)

    # Encrypt a payload using someone else's public key
    @staticmethod
    def encrypt_payload(payload_as_int, other_public_key, other_modulus):
        assert payload_as_int < other_modulus
        return pow(payload_as_int, other_public_key, other_modulus)

    @staticmethod
    def is_valid_signature(signature, public_key, modulus, message):
        return pow(signature, public_key, modulus) == message


if __name__ == "__main__":
    max_width = 2048
    mod_width = random.randint(256, max_width)
    mod_width = 4096
    a = RSA(mod_width=mod_width)
    print(f"{mod_width}-bit modulus (pub key): {hex(a.modulus)}")
    print(f"{mod_width}-bit modulus (priv key): {hex(a.private_key)}")

    n = 4
    msg = random.randint(2, pow(2, n * mod_width))

    print(f"msg: {hex(msg)}")

    msg_digest = int(keccak(msg).hex(), 16)
    print(f"msg digest: {hex(msg_digest)}")

    sig = a.sign_payload(msg_digest)
    print(f"signature: {hex(sig)}")

    assert RSA.is_valid_signature(sig, a.e, a.modulus, msg_digest)
    print("Was valid")

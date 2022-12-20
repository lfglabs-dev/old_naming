#!/usr/bin/env python3
import sys

from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash
from starkware.crypto.signature.signature import private_to_stark_key, sign

# params
argv = sys.argv
if len(argv) < 5:
    print("[ERROR] Invalid amount of parameters")
    print("Usage: ./whitelist.py priv_key domain expiry receiver_address")
    quit()
priv_key = argv[1]
domain = argv[2]
expiry = argv[3]
receiver_address = argv[4]


# domain encoding
basicAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"
bigAlphabet = "这来"
small_size_plus = len(basicAlphabet) + 1
big_size_plus = len(bigAlphabet) + 1


def encode(decoded):
    encoded = 0
    multiplier = 1
    for i in range(len(decoded)):
        char = decoded[i]
        try:
            index = basicAlphabet.index(char)
            if i == len(decoded) - 1 and decoded[i] == basicAlphabet[0]:
                encoded += multiplier * len(basicAlphabet)
                multiplier *= small_size_plus**2  # like adding 0
            else:
                encoded += multiplier * index
                multiplier *= small_size_plus
        except ValueError:
            encoded += multiplier * len(basicAlphabet)
            multiplier *= small_size_plus
            newid = int(i == len(decoded) - 1) + bigAlphabet.index(char)
            encoded += multiplier * newid
            multiplier *= len(bigAlphabet)
    return encoded


# compute signature
encoded_domain = encode(domain)
print("encoded:", encoded_domain)
hashed = pedersen_hash(
    pedersen_hash(encoded_domain, int(expiry)),
    int(receiver_address),
)
signed = sign(hashed, int(priv_key))
print("signature:", signed)

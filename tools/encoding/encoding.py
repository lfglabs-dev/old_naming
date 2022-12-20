# pylint: disable=redefined-builtin
#!/usr/bin/env python3
import sys

# params
argv = sys.argv
if len(argv) < 2:
    print("[ERROR] Invalid amount of parameters")
    print("Usage: ./encoding/encoding.py to_encode")
    sys.exit()

to_encode = argv[1]

basicAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"
bigAlphabet = "这来"
small_size_plus = len(basicAlphabet) + 1
big_size_plus = len(bigAlphabet) + 1

def extract_stars(str):
    k = 0
    while str.endswith(bigAlphabet[-1]):
        str = str[:-1]
        k += 1
    return (str, k)

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

#encoded domain
encoded_domain = encode(to_encode)
print("encoded:", encoded_domain)
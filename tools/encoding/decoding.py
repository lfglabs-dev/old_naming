# pylint: disable=redefined-builtin
#!/usr/bin/env python3
import sys

# params
argv = sys.argv
if len(argv) < 2:
    print("[ERROR] Invalid amount of parameters")
    print("Usage: ./encoding/encoding.py to_encode")
    sys.exit()

to_decode = argv[1]


basicAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"
bigAlphabet = "这来"

def extract_stars(str):
    k = 0
    while str.endswith(bigAlphabet[-1]):
        str = str[:-1]
        k += 1
    return (str, k)

def decode(felt):
    decoded = ""
    while felt != 0:
        code = felt % (len(basicAlphabet) + 1)
        felt = felt // (len(basicAlphabet) + 1)
        if code == len(basicAlphabet):
            next_felt = felt // (len(bigAlphabet) + 1)
            if next_felt == 0:
                code2 = felt % (len(bigAlphabet) + 1)
                felt = next_felt
                decoded += basicAlphabet[0] if code2 == 0 else bigAlphabet[code2 - 1]
            else:
                decoded += bigAlphabet[felt % len(bigAlphabet)]
                felt = felt // len(bigAlphabet)
        else:
            decoded += basicAlphabet[code]

    decoded, k = extract_stars(decoded)
    if k:
        decoded += (
            ((bigAlphabet[-1] * (k // 2 - 1)) + bigAlphabet[0] + basicAlphabet[1])
            if k % 2 == 0
            else bigAlphabet[-1] * (k // 2 + 1)
        )

    return decoded

#encoded domain
encoded_domain = decode(int(to_decode))
print("encoded:", encoded_domain)
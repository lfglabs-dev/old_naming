#!/usr/bin/env python3
import sys
import json
from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash
from starkware.crypto.signature.signature import sign

# params
argv = sys.argv
if len(argv) < 2:
    print("[ERROR] Invalid amount of parameters")
    print("Usage: ./whitelist.py priv_key domain expiry receiver_address")
    quit()
priv_key = argv[1]
expiry = argv[2]


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


whitelists_data = dict()

with open('./tools/whitelists.json') as json_file:
    whitelistedDomains = json.loads(json_file.read())

for i in range(len(whitelistedDomains)):
    whitelists_data[whitelistedDomains[i]["receiver_address"]] = []


for i in range(len(whitelistedDomains)):
    # compute signature
    domain = whitelistedDomains[i]["domain"]
    encoded_domain = encode(domain)
    hashed = pedersen_hash(
        pedersen_hash(encoded_domain, int(expiry)),
        int(whitelistedDomains[i]["receiver_address"]),
    )
    signed = sign(hashed, int(priv_key))
    whitelist_info = {
        "domain": whitelistedDomains[i]["domain"],
        "signature": signed,
        "expiry": expiry,
    }
    whitelists_data[whitelistedDomains[i]["receiver_address"]].append(whitelist_info)
 
        
    with open('./tools/whitelistsdata.json', 'w') as json_file:
        json_object = json.dumps(whitelists_data)
        json_file.write(json_object)
        
        


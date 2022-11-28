
import json

def returnDomain(index):
    digits = len(str(index))
                 
    if (digits == 1):
        return "000" + str(index)
    if (digits == 2):
        return "00" + str(index)
    if (digits == 3):
        return "0" + str(index)   
    if (digits == 4):
        return str(index)
    else:
        return ("Ein problem")


whitelists_data_early_starkers = []

with open('./tools/snapshots/snapshotEarlyStarkers.json') as json_file:
    whitelistedDomains = json.loads(json_file.read())
    
for i in range(len(whitelistedDomains)):
    # compute signature
    receiver_address = whitelistedDomains[i]
    whitelist_info = {
        "domain": returnDomain(i+1),
        "receiver_address": int(receiver_address[2::], 16),
    }
    whitelists_data_early_starkers.append(whitelist_info)
    
    with open('./tools/partnersEarlyStarkers.json', 'w') as json_file:
        json_object = json.dumps(whitelists_data_early_starkers)
        json_file.write(json_object)

whitelists_data_manual = []

with open('./tools/snapshots/snapshotManual.json') as json_file:
    whitelistedDomainsManual = json.loads(json_file.read())
    
for i in range(len(whitelistedDomainsManual)):
    # compute signature
    receiver_address = whitelistedDomainsManual[i]["receiver_address"]
    domain = whitelistedDomainsManual[i]["domain"]
    whitelist_info = {
        "domain": domain,
        "receiver_address": int(receiver_address[2::], 16),
    }
    whitelists_data_manual.append(whitelist_info)
    
    with open('./tools/partnersManual.json', 'w') as json_file:
        json_object = json.dumps(whitelists_data_manual)
        json_file.write(json_object)
        
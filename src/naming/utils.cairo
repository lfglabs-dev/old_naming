%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math_cmp import is_le

struct DomainData {
    owner: felt,  // a starknet.id
    resolver: felt,
    address: felt,  // a wallet address
    expiry: felt,  // expiration dates
    key: felt,  // a uniq id, updated on transfer
    parent_key: felt,  // key of parent domain
}

// @event
// func name_update(name : felt, address : felt):
// end

@storage_var
func _address_to_domain(address: felt, index: felt) -> (subdomain: felt) {
}

@storage_var
func _domain_data(hashed_domain: felt) -> (data: DomainData) {
}

@storage_var
func _admin_address() -> (admin_address: felt) {
}

@storage_var
func _whitelisting_key() -> (whitelisting_key: felt) {
}

@storage_var
func _pricing_contract() -> (pricing_contract: felt) {
}

@storage_var
func _l1_contract() -> (l1_contract: felt) {
}

@storage_var
func blacklisted_point(r) -> (blacklisted: felt) {
}

func hash_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*
) -> (hashed_domain: felt) {
    alloc_locals;
    if (domain_len == 0) {
        return (FALSE,);
    }
    tempvar new_len = domain_len - 1;
    let x = domain[new_len];
    let (y) = hash_domain(new_len, domain);
    let (hashed_domain) = hash2{hash_ptr=pedersen_ptr}(x, y);
    return (hashed_domain,);
}

func write_domain_data{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*, data: DomainData
) {
    let (hashed_domain) = hash_domain(domain_len, domain);
    _domain_data.write(hashed_domain, data);
    return ();
}

// can be used for writing only, overwriting needs next felt to be zero
func _write_address_to_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*, address: felt
) {
    if (domain_len == 0) {
        return ();
    }

    tempvar new_len = domain_len - 1;
    _address_to_domain.write(address, new_len, domain[new_len]);
    return _write_address_to_domain(new_len, domain, address);
}

func _address_to_domain_util{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    address: felt, domain: felt*, index: felt
) -> (domain_len: felt) {
    let (subdomain) = _address_to_domain.read(address, index);
    if (subdomain == 0) {
        return (index,);
    } else {
        assert domain[index] = subdomain;
        return _address_to_domain_util(address, domain, index + 1);
    }
}

// begin_index should be 1 since you first want to start with the first elt
func domain_to_resolver{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*, begin_elts
) -> (resolver: felt, rest_len: felt, rest: felt*) {
    if (domain_len == begin_elts) {
        return (0, 0, new ());
    }
    let (hashed_domain) = hash_domain(begin_elts, domain);
    let (domain_data) = _domain_data.read(hashed_domain);
    if (domain_data.resolver != 0) {
        return (domain_data.resolver, domain_len - begin_elts, domain + begin_elts);
    } else {
        return domain_to_resolver(domain_len - 1, domain, begin_elts);
    }
}

// adds days to current_timestamp if the domain is expired, otherwise to current_expiry
func compute_new_expiry{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    current_expiry: felt, current_timestamp: felt, days: felt
) -> felt {
    let expired = is_le(current_expiry, current_timestamp);
    if (expired == TRUE) {
        return current_timestamp + 86400 * days;
    } else {
        return current_expiry + 86400 * days;  // 1 day = 86400s
    }
}

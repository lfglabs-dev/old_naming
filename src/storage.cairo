%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.uint256 import Uint256

struct DomainData {
    owner: Uint256,  // a starknet.id
    address: felt,  // a wallet address
    expiry: felt,  // expiration date
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
func _pricing_contract() -> (pricing_contract: felt) {
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

func write_address_to_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*, address: felt
) {
    if (domain_len == 0) {
        return ();
    }

    tempvar new_len = domain_len - 1;
    _address_to_domain.write(address, new_len, domain[new_len]);
    return write_address_to_domain(new_len, domain, address);
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

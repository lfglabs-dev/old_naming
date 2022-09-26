%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.storage import (
    _domain_data,
    hash_domain,
    _address_to_domain_util,
    _address_to_domain,
    write_domain_data,
    write_address_to_domain,
    DomainData,
    _admin_address,
    _pricing_contract,
)

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

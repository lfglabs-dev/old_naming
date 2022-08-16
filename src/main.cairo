%lang starknet
from starkware.cairo.common.math import assert_nn
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.alloc import alloc

from src.storage import _domain_data, hash_domain, write_domain, _address_to_domain_util

@view
func domain_to_address{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*
) -> (address : felt):
    let (hashed_domain) = hash_domain(domain_len, domain)
    let (domain_data) = _domain_data.read(hashed_domain)
    if domain_data.address == FALSE:
        let (owner : felt) = domain_to_tokenid(domain_len, domain)
        return (owner)
    else:
        return (domain_data.address)
    end
end

@view
func address_to_domain{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    address : felt
) -> (domain_len : felt, domain : felt*):
    alloc_locals
    let (arr : felt*) = alloc()
    let (arr_len : felt) = _address_to_domain_util(address, arr, 0)
    return (arr_len, arr)
end

@view
func domain_to_tokenid{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*
) -> (owner : felt):
    let (hashed_domain) = hash_domain(domain_len, domain)
    let (domain_data) = _domain_data.read(hashed_domain)
    let owner = domain_data.owner

    if owner == 0:
        if domain_len == 0:
            return (FALSE)
        end
        return domain_to_tokenid(domain_len - 1, domain + 1)
    end
    return (owner)
end

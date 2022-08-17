%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.hash import hash2

struct DomainData:
    member owner : felt  # a starknet.id
    member address : felt  # a contract address
    member expiry : felt  # expiration date
end

# @event
# func name_update(name : felt, address : felt):
# end

@storage_var
func _address_to_domain(address : felt, index : felt) -> (subdomain : felt):
end

@storage_var
func _domain_data(hashed_domain : felt) -> (data : DomainData):
end

func hash_domain{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*
) -> (hashed_domain : felt):
    alloc_locals
    if domain_len == 0:
        return (FALSE)
    end
    tempvar new_len = domain_len - 1
    let x = domain[new_len]
    let (y) = hash_domain(new_len, domain)
    let (hashed_domain) = hash2{hash_ptr=pedersen_ptr}(x, y)
    return (hashed_domain)
end

func write_domain_data{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*, data : DomainData
):
    let (hashed_domain) = hash_domain(domain_len, domain)
    _domain_data.write(hashed_domain, data)
    return ()
end

func write_address_to_domain{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*, address : felt
):
    if domain_len == 0:
        return ()
    end

    tempvar new_len = domain_len - 1
    _address_to_domain.write(address, new_len, domain[new_len])
    return write_address_to_domain(new_len, domain, address)
end

func _address_to_domain_util{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    address : felt, domain : felt*, index : felt
) -> (domain_len : felt):
    let (subdomain) = _address_to_domain.read(address, index)
    if subdomain == 0:
        return (index)
    else:
        assert domain[index] = subdomain
        return _address_to_domain_util(address, domain, index + 1)
    end
end

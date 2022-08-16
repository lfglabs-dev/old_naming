%lang starknet
from starkware.cairo.common.math import assert_nn
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.alloc import alloc

struct DomainData:
    member owner : felt  # a starknet.id
    member address : felt  # a contract address
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

func write_domain{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*, data : DomainData
):
    _write_domain_util(domain_len, domain, data.address)
    let (hashed_domain) = hash_domain(domain_len, domain)
    _domain_data.write(hashed_domain, data)
end

func _write_domain_util(domain_len : felt, domain : felt*, address : felt):
    if domain_len == 0:
        return ()
    end

    tempvar new_len = domain_len - 1
    _address_to_domain.write(address, new_len, domain[new_len])
    return _write_domain_util(new_len, domain, address)
end

@view
func owner_of{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*
) -> (owner : felt):
    let (hashed_domain) = hash_domain(domain_len, domain)
    let (domain_data) = _domain_data.read(hashed_domain)
    let owner = domain_data.owner

    if owner == 0:
        if domain_len == 0:
            return (FALSE)
        end
        return owner_of(domain_len - 1, domain + 1)
    end
    return (owner)
end

@view
func lookup{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*
) -> (address : felt):
    let (hashed_domain) = hash_domain(domain_len, domain)
    let (domain_data) = _domain_data.read(hashed_domain)

    return (domain_data.address)
end

@view
func reverse_lookup{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    address : felt
) -> (domain_len : felt, domain : felt*):
    alloc_locals
    let (arr : felt*) = alloc()
    let (arr_len : felt) = _reverse_lookup_util(address, arr, 0)
    return (arr_len, arr)
end

func _reverse_lookup_util{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    address : felt, domain : felt*, index : felt
) -> (domain_len : felt):
    let (subdomain) = _address_to_domain.read(address, index)
    if subdomain == 0:
        return (index)
    else:
        assert domain[index] = subdomain
        return _reverse_lookup_util(address, domain, index + 1)
    end
end

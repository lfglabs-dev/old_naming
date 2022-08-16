%lang starknet
from src.main import hash_domain, reverse_lookup, _address_to_domain, DomainData, _domain_data, owner_of, lookup, write_domain
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc

@external
func test_hash_domain{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
    let (test0) = hash_domain(0, new ())
    assert test0 = 0

    let (test1) = hash_domain(1, new ('starkware'))
    assert test1 = 2140142446875703710710518347945668701142580220800197817593363984239628985951

    let (test2) = hash_domain(2, new ('guthl', 'starkware'))
    assert test2 = 1395499529913953935276270903350646799347103589599528505201612686379860101034

    return ()
end

@external
func test_reverse_lookup{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    arguments
):
    _address_to_domain.write(123, 0, 'guthl')
    _address_to_domain.write(123, 1, 'starkware')
    _address_to_domain.write(123, 2, 'com')
    let (domain_len, domain) = reverse_lookup(123)
    assert domain_len = 3
    assert 'guthl' = domain[0]
    assert 'starkware' = domain[1]
    assert 'com' = domain[2]
    return ()
end

@external
func test_owner_of{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    arguments
):
    alloc_locals

    let (domain1 : felt*) = alloc()
    let domainData_instance = DomainData(
    owner='starkware starknet.id', address='0x..')  
    _domain_data.write(2140142446875703710710518347945668701142580220800197817593363984239628985951, domainData_instance)
    assert domain1[0] = 'starkware'

    ## Should return domain data owner
    let (owner) = owner_of(1, domain1) 
    assert owner = 'starkware starknet.id'
    

    let (domain2 : felt*) = alloc()
    let domainData_instance = DomainData(
    owner='starkware starknet.id', address='0x..')   
    assert domain2[0] = 'guthl'
    assert domain2[1] = 'starkware'


    ## Should return domain data owner
    let (owner) = owner_of(2, domain2) 
    assert owner = 'starkware starknet.id'

    return ()
end

@external
func test_lookup{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    arguments
):
    alloc_locals

    let (domain1 : felt*) = alloc()
    let domainData_instance = DomainData(
    owner='starkware starknet.id', address='0x..')  
    _domain_data.write(2140142446875703710710518347945668701142580220800197817593363984239628985951, domainData_instance)
    assert domain1[0] = 'starkware'

    ## Should return domain data owner
    let (address) = lookup(1, domain1) 
    assert address = '0x..'

    return ()
end

# @external
# func write_domain{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
#     arguments
# ):
#     alloc_locals

#     let (domain1 : felt*) = alloc()
#     assert domain1[0] = 'guthl'
#     assert domain1[1] = 'starkware'
#     let domainData_instance = DomainData(
#     owner='starkware starknet.id', address='0x..')

    



#     let (domain) = _domain_data.read(1395499529913953935276270903350646799347103589599528505201612686379860101034)
#     assert domain.address = '0x..'
#     assert domain.address = '0x..'


#     return ()
# end
%lang starknet
from src.main import hash_domain, reverse_lookup, _address_to_domain
from starkware.cairo.common.cairo_builtins import HashBuiltin

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

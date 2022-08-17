%lang starknet
from src.main import domain_to_address, address_to_domain
from src.storage import DomainData, hash_domain, write_domain_data, write_address_to_domain
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256

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
func test_write_domain_data{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    arguments
):
    # todo: write domain data on naming_contract and starknetid
    let tokenid = Uint256(123, 0)
    let data = DomainData(tokenid, 456, 1)
    write_domain_data(4, new ('this', 'is', 'a', 'domain'), data)

    let (address) = domain_to_address(4, new ('this', 'is', 'a', 'domain'))
    assert address = 456

    return ()
end

@external
func test_write_address_to_domain{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr
}(arguments):
    write_address_to_domain(4, new ('this', 'is', 'a', 'domain'), 456)

    let (domain_len, domain) = address_to_domain(456)
    assert domain_len = 4
    assert domain[0] = 'this'
    assert domain[1] = 'is'
    assert domain[2] = 'a'
    assert domain[3] = 'domain'

    return ()
end

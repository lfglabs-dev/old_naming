%lang starknet
from src.naming.main import domain_to_address, address_to_domain, domain_to_token_id
from src.naming.utils import DomainData, _address_to_domain, _domain_data, hash_domain
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc

@external
func test_address_to_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    arguments
) {
    let (hashed_domain) = hash_domain(3, new ('guthl', 'starkware', 'com'));
    _domain_data.write(hashed_domain, DomainData(0, 0, 123, 0, 0, 0));
    _address_to_domain.write(123, 0, 'guthl');
    _address_to_domain.write(123, 1, 'starkware');
    _address_to_domain.write(123, 2, 'com');
    let (domain_len, domain) = address_to_domain(123);
    assert domain_len = 3;
    assert 'guthl' = domain[0];
    assert 'starkware' = domain[1];
    assert 'com' = domain[2];
    return ();
}

@external
func test_domain_to_address{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    arguments
) {
    alloc_locals;

    let (domain1: felt*) = alloc();
    let tokenid = 'starkware starknet.id';
    let domainData_instance = DomainData(owner=tokenid, 0, address='0x..', 1, 1, 0);
    _domain_data.write(
        2140142446875703710710518347945668701142580220800197817593363984239628985951,
        domainData_instance,
    );
    assert domain1[0] = 'starkware';

    // # Should return domain data owner
    let (address) = domain_to_address(1, domain1);
    assert address = '0x..';

    return ();
}

@external
func test_domain_to_token_id{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    arguments
) {
    alloc_locals;
    let tokenid = 123;
    let domainData_instance = DomainData(owner=tokenid, 0, address='0x..', 1, 1, 0);
    _domain_data.write(
        2140142446875703710710518347945668701142580220800197817593363984239628985951,
        domainData_instance,
    );

    let (domain1: felt*) = alloc();
    assert domain1[0] = 'starkware';

    // Should return domain data owner
    let (owner) = domain_to_token_id(1, domain1);
    assert owner = tokenid;

    let (domain2: felt*) = alloc();
    let domainData_instance = DomainData(owner=tokenid, 0, address='0x..', 1, 1, 0);
    assert domain2[0] = 'guthl';
    assert domain2[1] = 'starkware';

    // Should return domain data owner
    let (owner) = domain_to_token_id(2, domain2);
    assert owner = tokenid;

    return ();
}

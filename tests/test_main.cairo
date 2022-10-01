%lang starknet
from src.main import (
    domain_to_address,
    domain_to_expiry,
    address_to_domain,
    set_admin,
    set_pricing_contract,
    set_domain_owner,
    set_domain_to_resolver,
)
from src.storage import (
    DomainData,
    hash_domain,
    write_domain_data,
    write_address_to_domain,
    _admin_address,
    _pricing_contract,
    _domain_data,
)
from src.registration import starknetid_contract
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc

@external
func test_hash_domain{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let (test0) = hash_domain(0, new ());
    assert test0 = 0;

    let (test1) = hash_domain(1, new ('starkware'));
    assert test1 = 2140142446875703710710518347945668701142580220800197817593363984239628985951;

    let (test2) = hash_domain(2, new ('guthl', 'starkware'));
    assert test2 = 1395499529913953935276270903350646799347103589599528505201612686379860101034;

    return ();
}

@external
func test_write_domain_data{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    arguments
) {
    // todo: write domain data on naming_contract and starknetid
    let tokenid = 123;
    let data = DomainData(tokenid, 0, 456, 1, 1, 0);
    write_domain_data(4, new ('this', 'is', 'a', 'domain'), data);

    let (address) = domain_to_address(4, new ('this', 'is', 'a', 'domain'));
    assert address = 456;

    let (expiry) = domain_to_expiry(4, new ('this', 'is', 'a', 'domain'));
    assert expiry = 1;

    return ();
}

@external
func test_write_address_to_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    arguments
) {
    write_address_to_domain(4, new ('this', 'is', 'a', 'domain'), 456);

    let (domain_len, domain) = address_to_domain(456);
    assert domain_len = 4;
    assert domain[0] = 'this';
    assert domain[1] = 'is';
    assert domain[2] = 'a';
    assert domain[3] = 'domain';

    return ();
}

@external
func test_buy{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(arguments) {
    // Mock starknetID.owner_of

    // Test with a not registered domain

    // Test with a registered and expired domain

    // Test with a registered and not expired domain

    return ();
}

@external
func test_set_admin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(arguments) {
    %{ stop_prank_callable = start_prank(123) %}

    _admin_address.write(123);
    set_admin(1234);
    let (changed_address) = _admin_address.read();
    assert changed_address = 1234;
    %{ stop_prank_callable() %}
    return ();
}

@external
func test_set_pricing_contract{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    arguments
) {
    %{ stop_prank_callable = start_prank(123) %}

    // test case : admin is caller
    _admin_address.write(123);
    set_pricing_contract(1234);
    let (changed_address) = _pricing_contract.read();
    assert changed_address = 1234;

    %{ stop_prank_callable() %}

    return ();
}

@external
func test_set_domain_owner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    arguments
) {
    tempvar starknet_id_contract;
    %{
        stop_prank_callable = start_prank(123)
        ids.starknet_id_contract = deploy_contract("./lib/starknetid/src/StarknetId.cairo").contract_address
    %}

    starknetid_contract.write(starknet_id_contract);

    // test case : admin is caller
    _admin_address.write(123);
    set_domain_owner(1, new (123456789), 8);
    let (hashed) = hash_domain(1, new (123456789));
    let (domain_data) = _domain_data.read(hashed);
    assert domain_data.owner = 8;
    %{ stop_prank_callable() %}

    return ();
}

@external
func test_set_domain_to_resolver{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    arguments
) {
    %{ stop_prank_callable = start_prank(123) %}

    let owner = 123;
    let expiry = 3;
    let domain_data = DomainData(owner, 0, 0, expiry, 0, 0);
    write_domain_data(1, new ('aloha'), domain_data);
    let starknetid_address = 0x0123456;
    starknetid_contract.write(starknetid_address);
 
    %{ stop_mock = mock_call(ids.starknetid_address, "owner_of", [123]) %}

    set_domain_to_resolver(1, new ('aloha'), 456);
    let (hashed) = hash_domain(1, new ('aloha'));
    let (domain_data) = _domain_data.read(hashed);
    assert domain_data.resolver = 456;

    return ();
}

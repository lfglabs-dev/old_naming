%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.naming.registration import assert_is_owner, assert_control_domain, starknetid_contract
from src.naming.utils import write_domain_data, write_address_to_domain, DomainData

@external
func test_assert_is_owner{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let owner = 123;
    let domain_data = DomainData(owner, 0, 0, 456, 0, 0);
    write_domain_data(1, new ('aloha'), domain_data);

    let starknetid_address = 0x0123456;

    %{ stop_mock = mock_call(ids.starknetid_address, "owner_of", [789]) %}

    assert_is_owner(1, new ('aloha'), starknetid_address, 789);

    %{
        expect_revert(error_message="You do not have rights on this domain") 
        stop_mock()
        stop_mock = mock_call(ids.starknetid_address, "owner_of", [123456789])
    %}

    assert_is_owner(1, new ('aloha'), starknetid_address, 789);

    return ();
}

@external
func test_assert_control_domain{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let owner = 123;
    let expiry = 3;
    let domain_data = DomainData(owner, 0, 0, expiry, 0, 0);
    write_domain_data(1, new ('aloha'), domain_data);
    let starknetid_address = 0x0123456;

    starknetid_contract.write(starknetid_address);

    %{ 
        stop_mock = mock_call(ids.starknetid_address, "owner_of", [789])
        warp(2)
    %}

    // # Should pass because expiry > current_timestamp
    assert_control_domain(1, new ('aloha'), 789);

    let expiry2 = 1;
    let domain_data2 = DomainData(owner, 0, 0, expiry2, 0, 0);
    write_domain_data(1, new ('ntm'), domain_data2);

    // # Should not pass because expiry < current_timestamp
    %{ expect_revert(error_message="This domain is expired") %}
    assert_control_domain(1, new ('ntm'), 789);

    return ();
}

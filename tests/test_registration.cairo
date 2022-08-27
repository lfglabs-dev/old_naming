%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from src.registration import assert_is_owner, assert_control_domain, starknetid_contract
from src.storage import write_domain_data, write_address_to_domain, DomainData

@external
func test_assert_is_owner{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
    let owner = Uint256(123, 0)
    let domain_data = DomainData(owner, 0, 456, 0, 0)
    write_domain_data(1, new ('aloha'), domain_data)

    let starknetid_address = 0x0123456

    %{ stop_mock = mock_call(ids.starknetid_address, "ownerOf", [789]) %}

    assert_is_owner(1, new ('aloha'), starknetid_address, 789)

    %{
        expect_revert(error_message="you do not have rights on this domain") 
        stop_mock()
        stop_mock = mock_call(ids.starknetid_address, "ownerOf", [123456789])
    %}

    assert_is_owner(1, new ('aloha'), starknetid_address, 789)

    return ()
end

@external
func test_assert_control_domain{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
    let owner = Uint256(123, 0)
    let domain_data = DomainData(owner, 0, 32524303730, 0, 0)
    write_domain_data(1, new ('aloha'), domain_data)
    let starknetid_address = 0x0123456

    starknetid_contract.write(0x0123456)

    %{ stop_mock = mock_call(ids.starknetid_address, "ownerOf", [789]) %}

    ## Should pass because expiry > current_timestamp
    assert_control_domain(1, new ('aloha'), 789)

    ## Should not pass because expiry < current_timestamp
    let domain_data2 = DomainData(owner, 0, 1661618930, 0, 0)

    %{
        expect_revert() 
    %}

    return ()
end



%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from src.interface.starknetid import StarknetID
from src.interface.naming import Naming

@external
func __setup__():
    %{
        context.starknet_id_contract = deploy_contract("./lib/starknet_id/src/StarknetId.cairo").contract_address
        context.pricing_contract = deploy_contract("./src/pricing/main.cairo", [123]).contract_address
        context.naming_contract = deploy_contract("./src/main.cairo", [context.starknet_id_contract, context.pricing_contract, 456]).contract_address
    %}
    return ()
end

@external
func test_simple_buy{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
    tempvar starknet_id_contract
    tempvar naming_contract
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable = start_prank(456)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1)
    %}

    let token_id = Uint256(1, 0)
    StarknetID.mint(starknet_id_contract, token_id)
    # th0rgal encoded
    let th0rgal_string = 28235132438

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 456)
    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string))
    assert addr = 456
    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ()
end

@external
func test_set_domain_to_address{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}(
    ):
    tempvar starknet_id_contract
    tempvar naming_contract
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable = start_prank(456)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1)
    %}

    let token_id = Uint256(1, 0)
    StarknetID.mint(starknet_id_contract, token_id)
    # th0rgal encoded
    let th0rgal_string = 28235132438

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 456)
    Naming.set_domain_to_address(naming_contract, 1, new (th0rgal_string), 789)

    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ()
end

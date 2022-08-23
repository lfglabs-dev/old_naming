%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.interface.naming import Naming

@external
func __setup__():
    %{
        context.starknet_id_contract  = deploy_contract("./lib/starknet_id/src/StarknetId.cairo").contract_address
        context.pricing_contract = deploy_contract("./src/pricing/main.cairo", [123]).contract_address
        context.naming_contract = deploy_contract("./src/main.cairo", [context.starknet_id_contract, context.pricing_contract, 456]).contract_address
    %}
    return ()
end

@external
func test_simple_buy{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
    tempvar naming_contract
    %{ ids.naming_contract = context.naming_contract %}

    # Naming.buy()

    return ()
end

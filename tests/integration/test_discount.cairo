%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.interface.starknetid import StarknetId
from src.interface.naming import Naming
from src.naming.discounts import Discount

@external
func __setup__() {
    %{
        from starkware.starknet.compiler.compile import get_selector_from_name
        context.starknet_id_contract = deploy_contract("./lib/starknetid/src/StarknetId.cairo").contract_address
        context.pricing_contract = deploy_contract("./src/pricing/main.cairo", [123]).contract_address
        logic_contract_class_hash = declare("./src/naming/main.cairo").class_hash
        context.naming_contract = deploy_contract("./lib/cairo_contracts/src/openzeppelin/upgrades/presets/Proxy.cairo", [logic_contract_class_hash,
            get_selector_from_name("initializer"), 4, 
            context.starknet_id_contract, context.pricing_contract, 456, 0]).contract_address
    %}
    return ();
}

@external
func test_discounted_buy{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable = start_prank(456, context.naming_contract)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);
    // th0rgal encoded
    let th0rgal_string = 28235132438;
    // 10% discount for max 1 year if your domain is between 4 and 25 characters
    let discount = Discount((4, 25), (0, 365), (0, 99999999999999999), 2);

    // should create a discount
    Naming.write_discount(naming_contract, 1, discount);

    // should buy a discounted domain
    Naming.buy_discounted(naming_contract, token_id, th0rgal_string, 250, 0, 456, 1);
    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string));
    assert addr = 456;
    %{ expect_revert(error_message="Invalid discount. Days amount is out of range") %}
    // should fail because 700 days is out of range
    let token_id2 = 2;
    StarknetId.mint(starknet_id_contract, token_id2);
    Naming.buy_discounted(naming_contract, token_id2, 282351324389, 700, 0, 456, 1);

    return ();
}

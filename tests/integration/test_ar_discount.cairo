%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.interface.starknetid import StarknetId
from src.interface.naming import Naming
from src.naming.discounts import Discount
from src.naming.utils import DomainData

@external
func __setup__() {
    %{
        from starkware.starknet.compiler.compile import get_selector_from_name
        context.starknet_id_contract = deploy_contract("./lib/old_identity/src/StarknetId.cairo").contract_address
        context.pricing_contract = deploy_contract("./src/pricing/main.cairo", [123]).contract_address
        logic_contract_class_hash = declare("./src/naming/main.cairo").class_hash
        context.naming_contract = deploy_contract("./lib/cairo_contracts/src/openzeppelin/upgrades/presets/Proxy.cairo", [logic_contract_class_hash,
            get_selector_from_name("initializer"), 4, 
            context.starknet_id_contract, context.pricing_contract, 456, 0]).contract_address
    %}
    return ();
}


@external
func test_simple_ar{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable = start_prank(456, ids.naming_contract)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);
    // th0rgal encoded
    let th0rgal_string = 28235132438;
    Naming.set_auto_renew_contract(naming_contract, 789);
    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456, 0, 0);
    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string));

    %{
        stop_mock()
        stop_mock = mock_call(789, "get_renewing_allowance", [1, 0])
    %}
    Naming.renew_ar_discount(naming_contract, th0rgal_string);
    let (data : DomainData) = Naming.domain_to_data(naming_contract, 1, new (th0rgal_string));
    assert data.expiry = 1 + (365 + 90) * 86400;

    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}
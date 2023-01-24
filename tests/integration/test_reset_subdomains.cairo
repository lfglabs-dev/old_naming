%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.interface.starknetid import StarknetId
from src.interface.naming import Naming

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
func test_reset_subdomains{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable = start_prank(456)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);

    let token_id2 = 2;
    StarknetId.mint(starknet_id_contract, token_id2);

    // should mint a domain and create a subdomain
    Naming.buy(naming_contract, token_id, 'alpha', 365, 0, 456);
    Naming.transfer_domain(naming_contract, 2, new ('bravo', 'alpha'), token_id2);

    // should return the subdomain owner
    let (owner) = Naming.domain_to_token_id(naming_contract, 2, new ('bravo', 'alpha'));
    assert owner = token_id2;

    // should reset the subdomain owner
    Naming.reset_subdomains(naming_contract, 1, new ('alpha'));
    let (owner) = Naming.domain_to_token_id(naming_contract, 2, new ('bravo', 'alpha'));
    assert owner = 0;

    let token_id3 = 3;
    StarknetId.mint(starknet_id_contract, token_id3);
    Naming.transfer_domain(naming_contract, 2, new ('charlie', 'alpha'), token_id3);
    let (owner) = Naming.domain_to_token_id(naming_contract, 2, new ('charlie', 'alpha'));
    assert owner = token_id3;

    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

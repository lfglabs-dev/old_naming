%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.interface.starknetid import StarknetId
from src.interface.naming import Naming
from tests.simple_resolver import ISimpleResolver

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
        context.basic_resolver = deploy_contract("./tests/example_resolver.cairo", []).contract_address
        context.simple_resolver = deploy_contract("./tests/simple_resolver.cairo", []).contract_address
    %}
    return ();
}

@external
func test_basic_resolver{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    local basic_resolver;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        ids.basic_resolver = context.basic_resolver
        stop_prank_callable = start_prank(456)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);

    // th0rgal encoded
    let th0rgal_string = 28235132438;

    Naming.buy(
        naming_contract, token_id, th0rgal_string, days=365, resolver=basic_resolver, address=456, sponsor=0
    );
    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string));
    assert addr = 456;

    let (addr) = Naming.domain_to_address(naming_contract, 2, new ('anything', th0rgal_string));
    assert addr = 789;

    let (found_token_id) = Naming.domain_to_token_id(
        naming_contract, 2, new ('subdomain', th0rgal_string)
    );
    // owner is owner of th0rgal.stark
    assert found_token_id = 1;

    // should reset the resolver
    Naming.set_domain_to_resolver(naming_contract, 1, new (th0rgal_string), 0);

    let (addr) = Naming.domain_to_address(naming_contract, 2, new ('anything', th0rgal_string));
    assert addr = 0;

    let token_id2 = 2;
    StarknetId.mint(starknet_id_contract, token_id2);
    Naming.transfer_domain(naming_contract, 2, new ('subdomain', th0rgal_string), token_id2);
    let (found_token_id) = Naming.domain_to_token_id(
        naming_contract, 2, new ('subdomain', th0rgal_string)
    );
    assert found_token_id = token_id2;

    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_simple_resolver{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    local simple_resolver;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        ids.simple_resolver = context.simple_resolver
        stop_prank_callable = start_prank(456)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);

    Naming.buy(naming_contract, token_id, 'alpha', days=365, resolver=simple_resolver, address=456, sponsor=0);
    let (addr) = Naming.domain_to_address(naming_contract, 1, new ('alpha'));
    assert addr = 456;

    %{
        stop_prank_callable = start_prank(123, context.simple_resolver) 
        stop_mock = mock_call(123, "get_implementation", [0x12345])
    %}
    ISimpleResolver.claim_name(simple_resolver, 'bravo');

    // should return the subdomain target directly
    let (owner) = ISimpleResolver.domain_to_address(simple_resolver, 1, new ('bravo'));
    assert owner = 123;

    // should return the subdomain target via naming contract
    let (addr) = Naming.domain_to_address(naming_contract, 2, new ('bravo', 'alpha'));
    assert addr = 123;

    // should not return anything
    let (addr) = Naming.domain_to_address(naming_contract, 2, new ('charlie', 'alpha'));
    assert addr = 0;

    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

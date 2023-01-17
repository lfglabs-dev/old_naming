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
func test_set_domain_to_address{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
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
    // th0rgal encoded
    let th0rgal_string = 28235132438;

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456);
    Naming.set_domain_to_address(naming_contract, 1, new (th0rgal_string), 789);

    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string));
    assert addr = 789;

    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_set_domain_to_address_fail{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable1 = start_prank(456, context.starknet_id_contract)
        stop_prank_callable2 = start_prank(456, context.naming_contract)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);
    // th0rgal encoded
    let th0rgal_string = 28235132438;

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456);
    %{
        stop_prank_callable1()
        stop_prank_callable2()
        stop_prank_callable = start_prank(789, context.starknet_id_contract)
        expect_revert(error_message="You do not have rights on this domain")
    %}

    Naming.set_domain_to_address(naming_contract, 1, new (th0rgal_string), 789);

    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_set_address_to_domain{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable = start_prank(456, context.starknet_id_contract)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);
    // th0rgal encoded
    let th0rgal_string = 28235132438;
    %{
        stop_prank_callable()
        stop_prank_callable = start_prank(456, context.naming_contract)
    %}
    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456);
    Naming.set_address_to_domain(naming_contract, 1, new (th0rgal_string));
    let (domain_len, domain: felt*) = Naming.address_to_domain(naming_contract, 456);
    assert domain_len = 1;
    assert domain[0] = th0rgal_string;
    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_set_address_to_domain_fail{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable1 = start_prank(456, context.starknet_id_contract)
        stop_prank_callable2 = start_prank(456, context.naming_contract)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);
    // th0rgal encoded
    let th0rgal_string = 28235132438;
    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456);
    %{
        stop_prank_callable1()
        stop_prank_callable2()
        stop_prank_callable = start_prank(789, context.naming_contract)
        expect_revert(error_message="You can only point your address to a domain pointing back")
    %}
    Naming.set_address_to_domain(naming_contract, 1, new (th0rgal_string));
    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_main_domain{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable_starknetid = start_prank(456, context.starknet_id_contract)
        stop_prank_callable_naming = start_prank(456, context.naming_contract)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);

    let token_id2 = 2;
    StarknetId.mint(starknet_id_contract, token_id2);

    local root_domain1 = 12345;
    local subdomain1 = 6789;
    Naming.buy(naming_contract, token_id, root_domain1, 365, 0, 456);
    Naming.transfer_domain(naming_contract, 2, new (subdomain1, root_domain1), token_id2);

    Naming.set_domain_to_address(naming_contract, 2, new (subdomain1, root_domain1), 456);
    Naming.set_address_to_domain(naming_contract, 2, new (subdomain1, root_domain1));
    let (domain_len, domain: felt*) = Naming.address_to_domain(naming_contract, 456);
    assert domain_len = 2;
    assert domain[0] = subdomain1;
    assert domain[1] = root_domain1;

    Naming.set_domain_to_address(naming_contract, 1, new (root_domain1), 456);
    Naming.set_address_to_domain(naming_contract, 1, new (root_domain1));
    let (domain_len, domain: felt*) = Naming.address_to_domain(naming_contract, 456);
    assert domain_len = 1;
    assert domain[0] = root_domain1;

    let token_id3 = 3;
    Naming.transfer_domain(naming_contract, 1, new (root_domain1), token_id3);

    %{
        stop_prank_callable_starknetid()
        stop_prank_callable_naming()
        stop_prank_callable_starknetid = start_prank(789, context.starknet_id_contract)
        stop_prank_callable_naming = start_prank(789, context.naming_contract)
        stop_mock()
    %}

    StarknetId.mint(starknet_id_contract, token_id3);
    Naming.set_domain_to_address(naming_contract, 1, new (root_domain1), 789);
    let (domain_len, domain: felt*) = Naming.address_to_domain(naming_contract, 456);
    assert domain_len = 0;

    %{
        stop_prank_callable_starknetid()
        stop_prank_callable_naming()
    %}

    return ();
}

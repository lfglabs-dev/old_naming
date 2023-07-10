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
func test_transfer_domain{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
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

    // th0rgal encoded
    let th0rgal_string = 28235132438;

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456, 0);
    Naming.transfer_domain(naming_contract, 1, new (th0rgal_string), token_id2);

    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_transfer_domain_fail{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
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

    let token_id2 = 2;
    StarknetId.mint(starknet_id_contract, token_id2);

    // th0rgal encoded
    let th0rgal_string = 28235132438;

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456, 0);
    %{
        stop_prank_callable1()
        stop_prank_callable2()
        stop_prank_callable = start_prank(789, context.naming_contract)
        expect_revert(error_message="You do not have rights on this domain")
    %}
    Naming.transfer_domain(naming_contract, 1, new (th0rgal_string), token_id2);

    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_transfer_subdomain{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
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
    // th0rgal encoded
    let th0rgal_string = 28235132438;
    // buying th0rgal.stark and creating th0rgal.th0rgal.stark
    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456, 0);
    Naming.transfer_domain(naming_contract, 2, new (th0rgal_string, th0rgal_string), token_id2);

    // should return the starknet_id to which subdomain was transfered
    let (starknet_id) = Naming.domain_to_token_id(
        naming_contract, 2, new (th0rgal_string, th0rgal_string)
    );
    assert starknet_id = token_id2;

    // trying to transfer th0rgal.stark to starknet_id containg th0rgal.th0rgal.stark
    %{ expect_revert(error_message="This starknet_id already has a domain") %}
    Naming.transfer_domain(naming_contract, 1, new (th0rgal_string), token_id2);

    %{
        stop_prank_callable()
        stop_mock()
    %}
    return ();
}

@external
func test_transfer_subdomain_fail{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}(
    ) {
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

    let token_id2 = 2;
    StarknetId.mint(starknet_id_contract, token_id2);

    // th0rgal encoded
    let th0rgal_string = 28235132438;

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456, 0);
    %{
        stop_prank_callable1()
        stop_prank_callable2()
        stop_prank_callable = start_prank(789, context.naming_contract)
        expect_revert(error_message="You do not have rights on this domain")
    %}
    Naming.transfer_domain(naming_contract, 2, new (th0rgal_string, th0rgal_string), token_id2);
    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

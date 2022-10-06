%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.interface.starknetid import StarknetID
from src.interface.naming import Naming

@external
func __setup__() {
    %{
        context.starknet_id_contract = deploy_contract("./lib/starknetid/src/StarknetId.cairo").contract_address
        context.pricing_contract = deploy_contract("./src/pricing/main.cairo", [123]).contract_address
        context.naming_contract = deploy_contract("./src/naming/main.cairo", [context.starknet_id_contract, context.pricing_contract, 456]).contract_address
        context.resolver_contract = deploy_contract("./tests/example_resolver.cairo", []).contract_address
    %}
    return ();
}

@external
func test_simple_buy{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    tempvar starknet_id_contract;
    tempvar naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable = start_prank(456)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetID.mint(starknet_id_contract, token_id);
    // th0rgal encoded
    let th0rgal_string = 28235132438;

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456);
    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string));
    assert addr = 456;
    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_booked_buy{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    tempvar starknet_id_contract;
    tempvar naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable = start_prank(456)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetID.mint(starknet_id_contract, token_id);
    // th0rgal encoded
    let th0rgal_string = 28235132438;
    tempvar hashed_th0rgal_string;
    %{
        from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash
        ids.hashed_th0rgal_string = pedersen_hash(ids.th0rgal_string, 0)
    %}

    Naming.book_domain(naming_contract, hashed_th0rgal_string);
    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456);
    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string));
    assert addr = 456;
    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_booked_buy_fails{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    tempvar starknet_id_contract;
    tempvar naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    // th0rgal encoded
    let th0rgal_string = 28235132438;
    tempvar hashed_th0rgal_string;
    %{
        from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash
        ids.hashed_th0rgal_string = pedersen_hash(ids.th0rgal_string, 0)
        stop_prank_callable = start_prank(456, context.naming_contract)
    %}

    Naming.book_domain(naming_contract, hashed_th0rgal_string);

    %{
        stop_prank_callable()
        stop_prank_callable1 = start_prank(789, context.starknet_id_contract)
        stop_prank_callable2 = start_prank(789, context.naming_contract)
        expect_revert(error_message="Someone else booked this domain")
    %}

    let token_id = 1;
    StarknetID.mint(starknet_id_contract, token_id);
    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 789);
    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string));
    assert addr = 789;
    %{
        stop_prank_callable1()
        stop_prank_callable2()
        stop_mock()
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
    StarknetID.mint(starknet_id_contract, token_id);
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
    StarknetID.mint(starknet_id_contract, token_id);
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
    StarknetID.mint(starknet_id_contract, token_id);

    let token_id2 = 2;
    StarknetID.mint(starknet_id_contract, token_id2);

    // th0rgal encoded
    let th0rgal_string = 28235132438;

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456);
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
    StarknetID.mint(starknet_id_contract, token_id);

    let token_id2 = 2;
    StarknetID.mint(starknet_id_contract, token_id2);

    // th0rgal encoded
    let th0rgal_string = 28235132438;

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456);
    Naming.transfer_domain(naming_contract, 2, new (th0rgal_string, th0rgal_string), token_id2);

    %{ expect_revert(error_message="Target token_id already has a domain") %}
    Naming.transfer_domain(naming_contract, 1, new (th0rgal_string), token_id2);

    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_resolver{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    local resolver_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        ids.resolver_contract = context.resolver_contract
        stop_prank_callable = start_prank(456)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetID.mint(starknet_id_contract, token_id);

    // th0rgal encoded
    let th0rgal_string = 28235132438;

    Naming.buy(
        naming_contract, token_id, th0rgal_string, days=365, resolver=resolver_contract, address=456
    );
    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string));
    assert addr = 456;

    let (addr) = Naming.domain_to_address(naming_contract, 2, new (th0rgal_string, 'anything'));
    assert addr = 789;

    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

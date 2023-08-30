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
func test_simple_buy{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
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

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456, 0, 0);
    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string));
    assert addr = 456;
    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_simple_buy_fails_too_long{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable = start_prank(456)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
        expect_revert(error_message="A domain can't be purchased for more than 25 years")
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);
    // th0rgal encoded
    let th0rgal_string = 28235132438;

    Naming.buy(naming_contract, token_id, th0rgal_string, 36500, 0, 456, 0, 0);
    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_simple_buy_fails_too_short{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable = start_prank(456)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
        expect_revert(error_message="A domain can't be purchased for less than 2 months")
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);
    // th0rgal encoded
    let th0rgal_string = 28235132438;

    Naming.buy(naming_contract, token_id, th0rgal_string, 10, 0, 456, 0, 0);
    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_simple_buy_fails_non_empty_starknet_id{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable = start_prank(456)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
        expect_revert(error_message="This starknet_id already has a domain")
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);
    // th0rgal encoded
    let th0rgal_string = 28235132438;

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456, 0, 0);
    Naming.buy(naming_contract, token_id, 12345, 365, 0, 456, 0, 0);

    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

@external
func test_expired_buy{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable_1 = start_prank(456, context.starknet_id_contract)
        stop_prank_callable_2 = start_prank(456, context.naming_contract)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);
    // th0rgal encoded
    tempvar th0rgal_string = 28235132438;

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456, 0, 0);
    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string));
    assert addr = 456;
    %{
        stop_prank_callable_1()
        stop_prank_callable_2()
        # let's get this domain to expire
        warp(1 + 86400 * 366, context.naming_contract)
        stop_prank_callable_1 = start_prank(789, context.starknet_id_contract)
        stop_prank_callable_2 = start_prank(789, context.naming_contract)
    %}

    let token_id = 2;
    StarknetId.mint(starknet_id_contract, token_id);
    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 789, 0, 0);
    %{
        stop_prank_callable_1()
        stop_prank_callable_2()
        stop_mock()
    %}
    return ();
}

@external
func test_expired_renew{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable_1 = start_prank(456, context.starknet_id_contract)
        stop_prank_callable_2 = start_prank(456, context.naming_contract)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);
    // th0rgal encoded
    tempvar th0rgal_string = 28235132438;

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456, 0, 0);
    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string));
    assert addr = 456;
    Naming.renew(naming_contract, th0rgal_string, 365, 0, 0, 0);
    %{
        stop_prank_callable_1()
        stop_prank_callable_2()
        stop_mock()
    %}
    return ();
}

@external
func test_booked_buy{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
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
    tempvar hashed_th0rgal_string;
    %{
        from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash
        ids.hashed_th0rgal_string = pedersen_hash(ids.th0rgal_string, 0)
    %}

    Naming.book_domain(naming_contract, hashed_th0rgal_string);
    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456, 0, 0);
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
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
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
    StarknetId.mint(starknet_id_contract, token_id);
    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 789, 0, 0);
    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string));
    assert addr = 789;
    %{
        stop_prank_callable1()
        stop_prank_callable2()
        stop_mock()
    %}

    return ();
}

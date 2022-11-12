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
            get_selector_from_name("initializer"), 5, 
            context.starknet_id_contract, context.pricing_contract, 456, 1576987121283045618657875225183003300580199140020787494777499595331436496159, 0]).contract_address
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
    StarknetId.mint(starknet_id_contract, token_id);
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
func test_simple_buy_fails{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    tempvar starknet_id_contract;
    tempvar naming_contract;
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

    Naming.buy(naming_contract, token_id, th0rgal_string, 36500, 0, 456);
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
    StarknetId.mint(starknet_id_contract, token_id);
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
    StarknetId.mint(starknet_id_contract, token_id);
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
        expect_revert(error_message="You do not have rights on this domain")
    %}
    Naming.set_address_to_domain(naming_contract, 1, new (th0rgal_string));
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
    StarknetId.mint(starknet_id_contract, token_id);

    let token_id2 = 2;
    StarknetId.mint(starknet_id_contract, token_id2);

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

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456);
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

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456);
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
    StarknetId.mint(starknet_id_contract, token_id);

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

@external
func test_whitelist{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    tempvar starknet_id_contract;
    tempvar naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable1 = start_prank(456)
        stop_prank_callable2 = start_prank(456, context.naming_contract)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);

    // th0rgal encoded
    let th0rgal_string = 33133781693;

    Naming.whitelisted_mint(
        naming_contract,
        th0rgal_string,
        5065683439,
        1,
        456,
        (2796114368656848424401471571964226838027845300256693162318739706208869605847, 2616729108859312328977191098964106910423506378607747406940981178386941952093),
    );

    %{ expect_revert("TRANSACTION_FAILED") %}
    // Signature (1, 1), is invalid, with respect to the public key 1576987121283045618657875225183003300580199140020787494777499595331436496159, and the message hash 535384430805153015377328413841468779397008938018306822607442420255283071.
    Naming.whitelisted_mint(naming_contract, th0rgal_string, 5065683439, 1, 456, (1, 1));
    %{
        stop_prank_callable1()
        stop_prank_callable2()
    %}

    return ();
}

@external
func test_end_whitelist{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    tempvar starknet_id_contract;
    tempvar naming_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        stop_prank_callable1 = start_prank(456)
        stop_prank_callable2 = start_prank(456, context.naming_contract)
        stop_mock = mock_call(123, "transferFrom", [1])
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);

    // th0rgal encoded
    let th0rgal_string = 33133781693;

    Naming.end_whitelist(naming_contract);
    %{ expect_revert("TRANSACTION_FAILED") %}
    Naming.whitelisted_mint(
        naming_contract,
        th0rgal_string,
        5065683439,
        1,
        456,
        (2796114368656848424401471571964226838027845300256693162318739706208869605847, 2616729108859312328977191098964106910423506378607747406940981178386941952093),
    );

    return ();
}

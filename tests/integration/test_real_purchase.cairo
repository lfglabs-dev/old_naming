%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.interface.starknetid import StarknetId
from src.interface.naming import Naming
from starkware.cairo.common.uint256 import Uint256
from cairo_contracts.src.openzeppelin.token.erc20.IERC20 import IERC20

@external
func __setup__() {
    %{
        from starkware.starknet.compiler.compile import get_selector_from_name
        context.starknet_id_contract = deploy_contract("./lib/starknetid/src/StarknetId.cairo").contract_address
        context.eth_contract = deploy_contract("./lib/cairo_contracts/src/openzeppelin/token/erc20/presets/ERC20.cairo", [123, 123, 20, 2**127, 2**127, 456]).contract_address
        context.pricing_contract = deploy_contract("./src/pricing/main.cairo", [context.eth_contract]).contract_address
        logic_contract_class_hash = declare("./src/naming/main.cairo").class_hash
        context.naming_contract = deploy_contract("./lib/cairo_contracts/src/openzeppelin/upgrades/presets/Proxy.cairo", [logic_contract_class_hash,
            get_selector_from_name("initializer"), 4, 
            context.starknet_id_contract, context.pricing_contract, 456, 0]).contract_address
        context.resolver_contract = deploy_contract("./tests/example_resolver.cairo", []).contract_address
    %}
    return ();
}

@external
func test_simple_buy{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;
    local starknet_id_contract;
    local naming_contract;
    local eth_contract;
    %{
        ids.starknet_id_contract = context.starknet_id_contract
        ids.naming_contract = context.naming_contract
        ids.eth_contract = context.eth_contract
        stop_prank_callable1 = start_prank(456, context.starknet_id_contract)
        stop_prank_callable2 = start_prank(456, context.naming_contract)
        stop_prank_callable3 = start_prank(456, context.eth_contract)
        warp(1, context.naming_contract)
    %}

    let token_id = 1;
    StarknetId.mint(starknet_id_contract, token_id);
    // th0rgal encoded
    let th0rgal_string = 28235132438;

    IERC20.approve(eth_contract, naming_contract, Uint256(2 ** 127, 2 ** 127));
    %{ stop_prank_callable3() %}
    let (remaining: Uint256) = IERC20.allowance(eth_contract, 456, naming_contract);

    Naming.buy(naming_contract, token_id, th0rgal_string, 365, 0, 456, 0, 0);
    let (addr) = Naming.domain_to_address(naming_contract, 1, new (th0rgal_string));
    assert addr = 456;
    %{
        stop_prank_callable1()
        stop_prank_callable2()
    %}

    return ();
}

%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.interface.pricing import Pricing

@external
func __setup__() {
    %{
        #context.eth_contract = deploy_contract("./lib/cairo_contracts/src/openzeppelin/token/erc20/presets/ERC20.cairo", [298305742194, 4543560, 18, 0, 0]).contract_address
        context.pricing_contract = deploy_contract("./src/pricing/main.cairo", [123]).contract_address
    %}
    return ();
}

@external
func test_buy_price{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    tempvar pricing_contract;
    %{ ids.pricing_contract = context.pricing_contract %}
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, 'thomas', 365);
    assert erc20 = 123;
    assert price.low = 36500;
    assert price.high = 0;
    return ();
}

@external
func test_renew_price{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    tempvar pricing_contract;
    %{ ids.pricing_contract = context.pricing_contract %}
    let (erc20, price) = Pricing.compute_renew_price(pricing_contract, 'thomas', 365);
    assert erc20 = 123;
    assert price.low = 36500;
    assert price.high = 0;
    return ();
}

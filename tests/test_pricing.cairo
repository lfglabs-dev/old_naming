%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.interface.pricing import Pricing
from src.pricing.main import get_amount_of_chars

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

    // Test with "ben" / 3 letters and one year
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, 18925, 365);
    assert erc20 = 123;
    assert price.low = 390000000115000000;
    assert price.high = 0;

    // Test with "chocolate" / 9 letters and one year
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, 19565965532212, 365);
    assert price.low = 6999999999350000;
    assert price.high = 0;

    // Test with "chocolate" / 9 letters and 5 years
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, 19565965532212, 1825);
    assert price.low = 20999999998050000;
    assert price.high = 0;
    
    // Test with "chocolate" / 9 letters and 3 years
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, 19565965532212, 1095);
    assert price.low = 13999999998700000;
    assert price.high = 0;
    
    return ();
}

@external
func test_get_amount_of_chars{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    // ""
    let chars_amount = get_amount_of_chars(0);
    assert chars_amount = 0;

    // "toto"
    let chars_amount = get_amount_of_chars(796195);
    assert chars_amount = 4;

    // "aloha"
    let chars_amount = get_amount_of_chars(77554770);
    assert chars_amount = 5;

    // "chocolate"
    let chars_amount = get_amount_of_chars(19565965532212);
    assert chars_amount = 9;
    return ();
}

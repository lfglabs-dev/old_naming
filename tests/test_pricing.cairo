%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.interface.pricing import Pricing
from src.pricing.main import get_amount_of_chars
from starkware.cairo.common.math import split_felt
from starkware.cairo.common.uint256 import Uint256

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


    // Test with "b" / 1 letter and one year
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, 1, 365);
    assert erc20 = 123;
    assert price.low = 390000000000000180;
    assert price.high = 0;

    // Test with "be" / 2 letters and one year
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, 153, 365);
    assert erc20 = 123;
    assert price.low = 373999999999999875;
    assert price.high = 0;

    // Test with "ben" / 3 letters and one year
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, 18925, 365);
    assert erc20 = 123;
    assert price.low = 339999999999999820;
    assert price.high = 0;

    // Test with "benj" / 4 letters and one year
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, 512773, 365);
    assert erc20 = 123;
    assert price.low = 84999999999999955;
    assert price.high = 0;

    // Test with "chocolate" / 9 letters and one year
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, 19565965532212, 365);
    assert price.low = 8999999999999875;
    assert price.high = 0;

    // Test with "chocolate" / 9 letters and 5 years
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, 19565965532212, 1825);
    assert price.low = 26999999999999625;
    assert price.high = 0;

    // Test with "chocolate" / 9 letters and 3 years
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, 19565965532212, 1095);
    assert price.low = 17999999999999750;
    assert price.high = 0;

    // Test with "chocolate" / 9 letters and 20 years
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, 19565965532212, 7300);
    assert price.low = 161999999999997750;
    assert price.high = 0;

    return ();
}

@external
func test_get_amount_of_chars{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    // ""
    let chars_amount = get_amount_of_chars(Uint256(0, 0));
    assert chars_amount = 0;

    // "toto"
    let chars_amount = get_amount_of_chars(Uint256(796195, 0));
    assert chars_amount = 4;

    // "aloha"
    let chars_amount = get_amount_of_chars(Uint256(77554770, 0));
    assert chars_amount = 5;

    // "chocolate"
    let chars_amount = get_amount_of_chars(Uint256(19565965532212, 0));
    assert chars_amount = 9;

    // "这来abcdefghijklmopqrstuvwyq1234"
    let (high, low) = split_felt(801855144733576077820330221438165587969903898313);
    let chars_amount = get_amount_of_chars(Uint256(low, high));
    assert chars_amount = 30;
    return ();
}

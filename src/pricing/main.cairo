%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.math import assert_le
from starkware.cairo.common.math import unsigned_div_rem
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.math_cmp import is_le

@storage_var
func erc20() -> (erc20_address: felt) {
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    erc20_address: felt
) {
    erc20.write(erc20_address);
    return (); 
}  

@view
func compute_buy_price{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain, days
) -> (erc20_address: felt, price: Uint256) {
    alloc_locals;

    // Calculate price depending on number of characters
    let number_of_character = get_amount_of_chars(domain);
    let price_per_day_eth = get_price_per_day_eth(number_of_character);
    let days_to_pay = get_days_to_pay(days);
    let price = Uint256(days_to_pay * price_per_day_eth, 0);
    let (erc20_address) = erc20.read();
    
    return (erc20_address, price);
}

@view
func compute_renew_price{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain, days
) -> (erc20_address: felt, price: Uint256) {
    alloc_locals;

    // Calculate price depending on number of characters
    let number_of_character = get_amount_of_chars(domain);
    let price_per_day_eth = get_price_per_day_eth(number_of_character);
    let days_to_pay = get_days_to_pay(days);
    let price = Uint256(days_to_pay * price_per_day_eth, 0);
    let (erc20_address) = erc20.read();

    return (erc20_address, price);
}

const simple_alphabet_size = 38;
const complex_alphabet_size = 2;

func get_amount_of_chars{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain
) -> felt {
    if (domain == 0) {
        return (0);
    }
    let (p, q) = unsigned_div_rem(domain, simple_alphabet_size);
    if (p == 37) {
        let (shifted_p, _) = unsigned_div_rem(p, complex_alphabet_size);
        let next = get_amount_of_chars(shifted_p);
        return 1 + next;
    } else {
        let next = get_amount_of_chars(p);
        return 1 + next;
    }
}

func get_price_per_day_eth{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    number_of_character
) -> felt {

    if (number_of_character == 1) {
        return (1068493150684932);
    }

    if (number_of_character == 2) {
        return (1024657534246575);
    }

    if (number_of_character == 3) {
        return (931506849315068);
    }

    if (number_of_character == 4) {
        return (232876712328767);
    }

    return (24657534246575);
}

func get_days_to_pay{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    days
) -> felt {

    let is_longer_five_years = is_le(1824, days);

    if (is_longer_five_years  == TRUE) {
        return (days - 730);
    }

    let is_longer_three_years = is_le(1094, days);

    if (is_longer_three_years == TRUE) {
        return (days - 365);
    }

    return (days);
}

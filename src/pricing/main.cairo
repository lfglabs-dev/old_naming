%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256, uint256_unsigned_div_rem
from starkware.cairo.common.math import assert_le, split_felt
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
    let (high, low) = split_felt(domain);
    let number_of_character = get_amount_of_chars(Uint256(low, high));
    let price_per_day_eth = get_price_per_day_eth(number_of_character);
    let price = Uint256(days * price_per_day_eth, 0);
    let (erc20_address) = erc20.read();

    return (erc20_address, price);
}

@view
func compute_renew_price{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain, days
) -> (erc20_address: felt, price: Uint256) {
    alloc_locals;

    // Calculate price depending on number of characters
    let (high, low) = split_felt(domain);
    let number_of_character = get_amount_of_chars(Uint256(low, high));
    let price_per_day_eth = get_price_per_day_eth(number_of_character);
    let price = Uint256(days * price_per_day_eth, 0);
    let (erc20_address) = erc20.read();

    return (erc20_address, price);
}

func get_amount_of_chars{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain: Uint256
) -> felt {
    alloc_locals;
    if (domain.low == 0 and domain.high == 0) {
        return (0);
    }
    // 38 = simple_alphabet_size
    let (local p, q) = uint256_unsigned_div_rem(domain, Uint256(38, 0));
    if (q.high == 0 and q.low == 37) {
        // 3 = complex_alphabet_size
        let (shifted_p, _) = uint256_unsigned_div_rem(p, Uint256(2, 0));
        let next = get_amount_of_chars(shifted_p);
        return 1 + next;
    }
    let next = get_amount_of_chars(p);
    return 1 + next;
}

func get_price_per_day_eth{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    number_of_character
) -> felt {
    if (number_of_character == 1) {
        return (465753424657535);
    }

    if (number_of_character == 2) {
        return (465753424657535);
    }

    if (number_of_character == 3) {
        return (465753424657535);
    }

    if (number_of_character == 4) {
        return (232876712328767);
    }

    return (24657534246575);
}

// func get_days_to_pay{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
//     days
// ) -> felt {
//     PROMOTION FOR RENEWAL FEATURE
//     let is_longer_five_years = is_le(1824, days);

//     if (is_longer_five_years == TRUE) {
//         return (days - 730);
//     }

//     let is_longer_three_years = is_le(1094, days);

//     if (is_longer_three_years == TRUE) {
//         return (days - 365);
//     }

//     return (days);
// }

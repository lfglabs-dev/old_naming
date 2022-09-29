%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.math import assert_le
from starkware.cairo.common.math import unsigned_div_rem

@storage_var
func erc20() -> (erc20_address: felt) {
}

@storage_var
func _price_per_day(numberOfCharacter: felt) -> (price: felt) {
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    erc20_address: felt
) {
    erc20.write(erc20_address);
    _price_per_day.write(1, 490000000000000000);
    _price_per_day.write(2, 440000000000000000);
    _price_per_day.write(3, 390000000000000000);
    _price_per_day.write(4, 90000000000000000);
    _price_per_day.write(5, 7000000000000000);
    return ();
}

@view
func compute_buy_price{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain, days
) -> (erc20_address: felt, price: Uint256) {
    // you can't purchase a domain for longer than 25 years
    assert_le(days, 9125);
    // Calculate price depending on number of characters
    let number_of_character = get_amount_of_chars(domain);
    let (price_per_day_eth) = _price_per_day.read(number_of_character);
    let price = Uint256(days * price_per_day_eth, 0);
    let (erc20_address) = erc20.read();
    return (erc20_address, price);
}

@view
func compute_renew_price{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain, days
) -> (erc20_address: felt, price: Uint256) {
    // you can't renew ase a domain for longer than 25 years
    assert_le(days, 9125);

    // Calculate price depending on number of characters
    let number_of_character = get_amount_of_chars(domain);
    let (price_per_day_eth) = _price_per_day.read(number_of_character);
    let price = Uint256(days * price_per_day_eth, 0);
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

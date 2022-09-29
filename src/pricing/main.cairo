%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.math import assert_le

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
    let (erc20_address) = erc20.read();
    
    // Calculate price depending on number of characters
    let (number_of_character) = getNumberOfCharacter(domain);
    let (price_per_day_eth) = _price_per_day.read(number_of_character);
    let price = Uint256(days * price_per_day_eth, 0);

    return (erc20_address, price);
}

@view
func compute_renew_price{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain, days
) -> (erc20_address: felt, price: Uint256) {
    // you can't renew ase a domain for longer than 25 years
    assert_le(days, 9125);
    let (erc20_address) = erc20.read();
    
    // Calculate price depending on number of characters
    let (number_of_character) = getNumberOfCharacter(domain);
    let (price_per_day_eth) = _price_per_day.read(number_of_character);
    let price = Uint256(days * price_per_day_eth, 0);
    
    return (erc20_address, price);
}

func getNumberOfCharacter{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain
) -> (number_of_character: felt) {

    
    return ();
}

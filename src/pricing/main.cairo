%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.math import assert_le

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
    // you can't purchase a domain for longer than 25 years
    assert_le(days, 9125);
    let (erc20_address) = erc20.read();
    // one day = 100 wei
    let price = Uint256(days * 100, 0);
    return (erc20_address, price);
}

@view
func compute_renew_price{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain, days
) -> (erc20_address: felt, price: Uint256) {
    // you can't renew ase a domain for longer than 25 years
    assert_le(days, 9125);
    let (erc20_address) = erc20.read();
    // one day = 100 wei
    let price = Uint256(days * 100, 0);
    return (erc20_address, price);
}

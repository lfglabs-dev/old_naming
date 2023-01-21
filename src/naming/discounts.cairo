%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_unsigned_div_rem,
    uint256_sub,
    uint256_mul,
)

struct Discount {
    domain_len_range: (felt, felt),
    days_range: (felt, felt),
    timestamp_range: (felt, felt),
    amount: felt,
}

@storage_var
func discounts(discount_id) -> (discount: Discount) {
}

func compute_discount{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    price: Uint256, discount_amount: felt
) -> (discounted_price: Uint256) {
    // divide the price by 20
    let (q, r) = uint256_unsigned_div_rem(price, Uint256(20, 0));

    // substract q discount times
    let (to_substract, overflow) = uint256_mul(q, Uint256(discount_amount, 0));

    // this should never happen
    with_attr error_message(
            "Strange behavior has been detected, please contact a starknet.id developer") {
        assert overflow = Uint256(0, 0);
    }
    let (output) = uint256_sub(price, to_substract);
    return (output,);
}

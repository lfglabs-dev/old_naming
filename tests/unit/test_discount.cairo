%lang starknet
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256
from src.naming.discounts import compute_discount

@external
func test_assert_compute_discount{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ) {
    let price1 = Uint256(1000, 0);

    // trying -5% discount
    let (discount1) = compute_discount(price1, 1);
    assert discount1 = Uint256(950, 0);

    // trying -15% discount
    let (discount1) = compute_discount(price1, 3);
    assert discount1 = Uint256(850, 0);

    // trying -50% discount
    let (discount1) = compute_discount(price1, 10);
    assert discount1 = Uint256(500, 0);

    let price2 = Uint256(327898, 0);

    // trying -10% discount
    let (discount1) = compute_discount(price2, 2);
    // exact value would be 295108, this is a valid approximation
    assert discount1 = Uint256(295110, 0);

    // trying -15% discount
    let (discount1) = compute_discount(price2, 3);
    // exact value would be 278713, this is a valid approximation
    assert discount1 = Uint256(278716, 0);

    // trying -45% discount
    let (discount1) = compute_discount(price2, 9);
    // exact value would be 180343, this is a valid approximation
    assert discount1 = Uint256(180352, 0);

    return ();
}

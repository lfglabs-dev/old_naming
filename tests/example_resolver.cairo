%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin

@external
func domain_to_address{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*
) -> (address: felt) {
    return (address=789);
}

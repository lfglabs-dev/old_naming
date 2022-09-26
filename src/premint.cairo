%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_block_timestamp
from starkware.cairo.common.uint256 import Uint256

from src.registration import mint_domain

func distribute_domains{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    alloc_locals;
    let (current_timestamp) = get_block_timestamp();
    local expiry = current_timestamp + 3600 * 24 * 365 * 10;

    mint_domain(
        1978008092,
        0,
        2062164617078856708726359385275913687867681308215048325959467098459703644820,
        707480809674220547290526774807730021928734718267773781627142188130542240341,
        Uint256(1, 0),
        33133781693,
    );

    return ();
}

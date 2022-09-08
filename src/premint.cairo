%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_block_timestamp
from starkware.cairo.common.uint256 import Uint256

from src.registration import mint_domain

func distribute_domains{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    alloc_locals
    let (current_timestamp) = get_block_timestamp()
    local expiry = current_timestamp + 3600 * 24 * 365 * 10

    mint_domain(expiry, 0x123, 'hashed_domain', Uint256(123, 0), 'domain')
    mint_domain(expiry, 0x123, 'hashed_domain', Uint256(123, 0), 'domain')
    mint_domain(expiry, 0x123, 'hashed_domain', Uint256(123, 0), 'domain')
    mint_domain(expiry, 0x123, 'hashed_domain', Uint256(123, 0), 'domain')
    mint_domain(expiry, 0x123, 'hashed_domain', Uint256(123, 0), 'domain')
    mint_domain(expiry, 0x123, 'hashed_domain', Uint256(123, 0), 'domain')
    mint_domain(expiry, 0x123, 'hashed_domain', Uint256(123, 0), 'domain')
    mint_domain(expiry, 0x123, 'hashed_domain', Uint256(123, 0), 'domain')

    return ()
end

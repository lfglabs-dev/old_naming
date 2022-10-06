%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_block_timestamp, get_contract_address
from starkware.cairo.common.uint256 import Uint256
from src.naming.registration import mint_domain
from src.interface.starknetid import StarknetID

const starknet_id = 0x03ddb550162d2e85d4dce0cea558fe17dcf30a04147b6f5a7e7496aa3fac0efa;

func distribute_domains{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    alloc_locals;
    let (naming_contract) = get_contract_address();
    let (current_timestamp) = get_block_timestamp();
    local expiry = current_timestamp + 3600 * 24 * 365 * 10;

    StarknetID.mint(naming_contract, 1);
    mint_domain(
        1980423047,
        0,
        2062164617078856708726359385275913687867681308215048325959467098459703644820,
        707480809674220547290526774807730021928734718267773781627142188130542240341,
        1,
        33133781693,
    );
    StarknetID.transferFrom(
        starknet_id,
        naming_contract,
        2062164617078856708726359385275913687867681308215048325959467098459703644820,
        Uint256(1, 0),
    );

    return ();
}

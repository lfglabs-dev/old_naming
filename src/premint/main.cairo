%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.interface.naming import Naming

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(naming_contract) {
    //Naming.premint(
    //    naming_contract,
    //    1980447720,
    //    1,
    //    2062164617078856708726359385275913687867681308215048325959467098459703644820,
    //    707480809674220547290526774807730021928734718267773781627142188130542240341,
    //    33133781693,
    //);
    return ();
}

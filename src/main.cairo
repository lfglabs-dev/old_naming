%lang starknet
from starkware.cairo.common.math import assert_nn
from starkware.cairo.common.cairo_builtins import HashBuiltin

@storage_var
func _address_to_name(address : felt) -> (name : felt):
end

@storage_var
func _name_to_address(name : felt) -> (address : felt):
end

@view
func lookup{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(name : felt) -> (
    address : felt
):
    let (address) = _name_to_address.read(name)
    return (name)
end

@view
func reverse_lookup{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    address : felt
) -> (name : felt):
    let (name) = _address_to_name.read(address)
    return (name)
end

%lang starknet
from starkware.cairo.common.math import assert_nn
from starkware.cairo.common.cairo_builtins import HashBuiltin

@storage_var
func _name_to_address(name : felt) -> (address : felt):
end

@storage_var
func _address_to_name(addess : felt) -> (name : felt):
end

@view
func name_to_address(name : felt) -> (address : felt):
    return _name_to_address.read(name)
end

@view
func address_to_name(name : felt) -> (address : felt):
    return _address_to_name.read(name)
end
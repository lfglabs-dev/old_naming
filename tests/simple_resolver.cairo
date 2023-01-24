%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_caller_address

@contract_interface
namespace ISimpleResolver {
    func claim_name(name: felt) {
    }

    func domain_to_address(domain_len: felt, domain: felt*) -> (address: felt) {
    }
}

@storage_var
func name_owners(name) -> (owner: felt) {
}

@view
func domain_to_address{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*
) -> (address: felt) {
    assert domain_len = 1;
    let (owner) = name_owners.read([domain]);
    return (owner,);
}

@external
func claim_name{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(name: felt) -> () {
    let (owner) = name_owners.read(name);
    assert owner = 0;
    let (caller) = get_caller_address();
    name_owners.write(name, caller);
    return ();
}

@external
func transfer_name{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    name: felt, new_owner: felt
) -> () {
    let (owner) = name_owners.read(name);
    let (caller) = get_caller_address();
    assert owner = caller;
    name_owners.write(name, new_owner);
    return ();
}

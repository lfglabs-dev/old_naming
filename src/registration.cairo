%lang starknet
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_contract_address
from src.storage import (
    DomainData,
    write_domain_data,
    write_address_to_domain,
    hash_domain,
    _domain_data,
)
from starkware.starknet.common.syscalls import get_caller_address, get_block_timestamp
from starkware.cairo.common.math import assert_nn, assert_le
from src.interface.starknetid import StarknetID
from cairo_contracts.src.openzeppelin.token.erc20.IERC20 import IERC20

@event
func domain_to_addr_update(domain_len : felt, domain : felt*, address : felt):
end

@event
func addr_to_domain_update(address : felt, domain_len : felt, domain : felt*):
end

@event
func starknet_id_update(domain_len : felt, domain : felt*, owner : Uint256, expiry : felt):
end

@event
func reset_subdomains_update(domain_len : felt, domain : felt*):
end

@storage_var
func starknetid_contract() -> (address : felt):
end

func _register_domain{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    token_id : Uint256,
    domain : felt,
    erc20 : felt,
    price : Uint256,
    data : DomainData,
    caller : felt,
):
    let (contract) = get_contract_address()

    # Make the user pay
    IERC20.transferFrom(erc20, caller, contract, price)

    # Write info on starknet.id and write info on storage data
    write_domain_data(1, new (domain), data)

    let (contract_contract_addr) = starknetid_contract.read()
    StarknetID.set_verifier_data(contract_contract_addr, token_id, 'name', domain)

    return ()
end

func assert_control_domain{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*, caller : felt
) -> (hashed_root_domain, domain_data : DomainData):
    alloc_locals

    # fetch domain_data
    let (hashed_root_domain) = hash_domain(domain_len, domain)
    let (domain_data) = _domain_data.read(hashed_root_domain)

    # check ownership
    let (contract_addr) = starknetid_contract.read()
    assert_is_owner(domain_len, domain, contract_addr, caller)

    let (hashed_root_domain) = hash_domain(1, domain + domain_len - 1)
    let (root_domain_data) = _domain_data.read(hashed_root_domain)

    # check expiry of root domain
    let (current_timestamp) = get_block_timestamp()
    assert_le(root_domain_data.expiry, current_timestamp)

    return (hashed_root_domain, domain_data)
end

func assert_is_owner{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*, contract_addr : felt, caller : felt
) -> (key : felt):
    alloc_locals
    let (hashed_domain) = hash_domain(domain_len, domain)
    let (domain_data) = _domain_data.read(hashed_domain)
    let starknet_id = domain_data.owner
    let (starknet_id_owner) = StarknetID.ownerOf(contract_addr, starknet_id)

    if starknet_id_owner == caller:
        return (domain_data.key)
    end

    # if domain_len <= 2

    if domain_len == 1:
        with_attr error_message("you do not have rights on this domain"):
            assert 1 = 0
        end
        return (-1)
    end

    if domain_len == 0:
        with_attr error_message("you do not have rights on this domain"):
            assert 1 = 0
        end
        return (-1)
    end

    # else
    let (parent_key) = assert_is_owner(domain_len - 1, domain + 1, contract_addr, caller)
    assert parent_key = domain_data.parent_key

    return (domain_data.key)
end

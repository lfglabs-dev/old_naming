%lang starknet
from starkware.cairo.common.math import assert_nn, assert_le
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256
from starkware.starknet.common.syscalls import get_caller_address, get_block_timestamp
from starkware.cairo.common.math_cmp import is_le, is_not_zero
from starkware.starknet.common.syscalls import get_contract_address

from src.storage import (
    _domain_data,
    hash_domain,
    _address_to_domain_util,
    _address_to_domain,
    write_domain_data,
    write_address_to_domain,
    DomainData,
    _admin_address,
    _pricing_contract,
)
from src.interface.starknetid import StarknetID
from src.interface.pricing import Pricing
from src.registration import _register_domain, starknetid_contract

from cairo_contracts.src.openzeppelin.token.erc20.IERC20 import IERC20

@constructor
func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    starknetid_contract_addr : felt
):
    starknetid_contract.write(starknetid_contract_addr)
    return ()
end

# USER VIEW FUNCTIONS

@view
func domain_to_address{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*
) -> (address : felt):
    let (hashed_domain) = hash_domain(domain_len, domain)
    let (domain_data) = _domain_data.read(hashed_domain)
    if domain_data.address == FALSE:
        let (token_id : Uint256) = domain_to_token_id(domain_len, domain)
        return (0)
    else:
        return (domain_data.address)
    end
end

@view
func address_to_domain{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    address : felt
) -> (domain_len : felt, domain : felt*):
    alloc_locals
    let (arr : felt*) = alloc()
    let (arr_len : felt) = _address_to_domain_util(address, arr, 0)
    return (arr_len, arr)
end

@view
func domain_to_token_id{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*
) -> (owner : Uint256):
    let (hashed_domain) = hash_domain(domain_len, domain)
    let (domain_data) = _domain_data.read(hashed_domain)
    let owner = domain_data.owner

    if owner.low == 0 and owner.high == 0:
        if domain_len == 0:
            let false = Uint256(0, 0)
            return (false)
        end
        return domain_to_token_id(domain_len - 1, domain + 1)
    end
    return (owner)
end

# USER EXTERNAL FUNCTIONS

@external
func set_domain_to_address{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*, address : felt
):
    # fetch domain_data
    let (hashed_domain) = hash_domain(domain_len, domain)
    let (domain_data) = _domain_data.read(hashed_root_domain)

    # find starknet_id
    tempvar starknet_id = domain_data.owner
    if owner.low == 0 and owner.high == 0:
        # no owner
        if domain_len == 0:
            assert 1 = 0
        end
        tempvar starknet_id = domain_to_token_id(domain_len - 1, domain + 1)
    end

    # check ownership
    let (contract_addr) = starknetid_contract.read()
    let (starknet_id_owner) = StarknetID.ownerOf(contract_addr, starknet_id)
    let (caller) = get_caller_address()
    assert starknet_id_owner = caller

    let (hashed_root_domain) = hash_domain(1, domain + domain_len - 1)
    let (root_domain_data) = _domain_data.read(hashed_root_domain)

    # check expiry of root domain
    let (current_timestamp) = get_block_timestamp()
    assert_le(root_domain_data.expiry, current_timestamp)

    # if subdomain, check key
    if domain_len != 1:
    end
end

@external
func set_address_to_domain{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    address : felt, domain_len : felt, domain : felt*
):
    ret
end

@external
func buy{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    token_id : Uint256, domain_len : felt, domain : felt*, days : felt
):
    alloc_locals
    # # TODO : let time to stop front running

    # Verify that the starknet.id is owned by the caller
    let (caller) = get_caller_address()
    let (contract_addr) = starknetid_contract.read()
    let (starknet_id_owner) = StarknetID.ownerOf(contract_addr, token_id)
    assert caller = starknet_id_owner

    # Verify that the domain is not registered already or expired
    let (current_timestamp) = get_block_timestamp()
    let (hashed_domain) = hash_domain(domain_len, domain)
    let (domain_data) = _domain_data.read(hashed_domain)
    let (is_expired) = is_le(domain_data.expiry, current_timestamp)

    if domain_data.owner.low != 0:
        assert is_expired = TRUE
    end

    if domain_data.owner.high != 0:
        assert is_expired = TRUE
    end

    # Get expiry and price
    let expiry = current_timestamp + 86400 * days  # # 1 day = 86400s
    let (pricing_contract) = _pricing_contract.read()
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, domain[domain_len - 1], days)
    let data = DomainData(token_id, caller, expiry)

    # Register
    _register_domain(token_id, domain_len, domain, erc20, price, data, caller)

    ret
end

@external
func renew{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    token_id : Uint256, domain_len : felt, domain : felt*, days : felt
):
    alloc_locals

    # Verify that the domain is owned by the caller
    let (caller) = get_caller_address()
    let (contract_addr) = starknetid_contract.read()
    let (starknetIdOwner) = StarknetID.ownerOf(contract_addr, token_id)
    assert caller = starknetIdOwner

    # Verify that the domain is not expired
    let (current_timestamp) = get_block_timestamp()
    let (hashed_domain) = hash_domain(domain_len, domain)
    let (domain_data) = _domain_data.read(hashed_domain)
    let (is_expired) = is_le(domain_data.expiry, current_timestamp)
    assert is_expired = FALSE

    # Get expiry and price
    let expiry = domain_data.expiry + 86400 * days  # # 1 day = 86400s
    let (pricing_contract) = _pricing_contract.read()
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, domain[domain_len - 1], days)
    let data = DomainData(token_id, caller, expiry)

    # Register
    _register_domain(token_id, domain_len, domain, erc20, price, data, caller)

    ret
end

func _token_id_to_owner{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    token_id : Uint256
) -> (owner_address : felt):
    let (contract_addr) = starknetid_contract.read()
    let (owner_address) = StarknetID.ownerOf(contract_addr, token_id)
    return (owner_address)
end

# ADMIN EXTERNAL FUNCTIONS

@external
func set_admin{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(address : felt):
    # Verify that caller is admin
    let (caller) = get_caller_address()
    let (admin_address) = _admin_address.read()
    assert caller = admin_address

    # Write new admin
    _admin_address.write(address)

    return ()
end

@external
func set_domain_owner{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    domain_len : felt, domain : felt*, token_id : Uint256
):
    # Verify that caller is admin
    let (caller) = get_caller_address()
    let (admin_address) = _admin_address.read()
    assert caller = admin_address

    # Write domain owner
    let (hashed_domain) = hash_domain(domain_len, domain)
    let (current_domain_data) = _domain_data.read(hashed_domain)
    let new_domain_data = DomainData(
        token_id, current_domain_data.address, current_domain_data.expiry
    )
    _domain_data.write(hashed_domain, new_domain_data)

    return ()
end

@external
func set_pricing_contract{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    address : felt
):
    # Verify that caller is admin
    let (caller) = get_caller_address()
    let (admin_address) = _admin_address.read()
    assert caller = admin_address

    # Write domain owner
    _pricing_contract.write(address)

    return ()
end

@external
func transfer_balance{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    erc20 : felt, amount : Uint256
):
    # Verify that caller is admin
    let (caller) = get_caller_address()
    let (admin_address) = _admin_address.read()
    assert caller = admin_address
    let (contract) = get_contract_address()

    # Redeem funds
    IERC20.transferFrom(erc20, contract, caller, amount)

    return ()
end

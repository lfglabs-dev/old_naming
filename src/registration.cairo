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
    _pricing_contract,
)
from src.interface.pricing import Pricing
from starkware.starknet.common.syscalls import get_caller_address, get_block_timestamp
from starkware.cairo.common.math import assert_nn, assert_le
from src.interface.starknetid import StarknetID
from cairo_contracts.src.openzeppelin.token.erc20.IERC20 import IERC20

@event
func domain_to_addr_update(domain_len: felt, domain: felt*, address: felt) {
}

@event
func domain_to_resolver_update(domain_len: felt, domain: felt*, resolver: felt) {
}

@event
func addr_to_domain_update(address: felt, domain_len: felt, domain: felt*) {
}

@event
func starknet_id_update(domain_len: felt, domain: felt*, owner: Uint256, expiry: felt) {
}

@event
func reset_subdomains_update(domain_len: felt, domain: felt*) {
}

@storage_var
func starknetid_contract() -> (address: felt) {
}

@storage_var
func booked_domain(hashed_domain: felt) -> (booking_data: (owner: felt, expiry: felt)) {
}

func pay_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    current_timestamp, days, caller, domain
) -> (expiry: felt) {
    let expiry = current_timestamp + 86400 * days;  // 1 day = 86400s
    let (pricing_contract) = _pricing_contract.read();
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, domain, days);
    let (naming_contract) = get_contract_address();
    IERC20.transferFrom(erc20, caller, naming_contract, price);

    return (expiry,);
}

func mint_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    expiry, resolver, target_address, hashed_domain, token_id: Uint256, domain
) {
    alloc_locals;
    let data = DomainData(token_id, resolver, target_address, expiry, 1, 0);
    write_domain_data(1, new (domain), data);
    starknet_id_update.emit(1, new (domain), token_id, expiry);
    domain_to_addr_update.emit(1, new (domain), target_address);
    let (contract) = starknetid_contract.read();
    StarknetID.set_verifier_data(contract, token_id, 'name', hashed_domain);

    return ();
}

func assert_control_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*, caller: felt
) {
    alloc_locals;

    // check ownership
    let (contract_addr) = starknetid_contract.read();
    assert_is_owner(domain_len, domain, contract_addr, caller);

    let (hashed_root_domain) = hash_domain(1, domain + domain_len - 1);
    let (root_domain_data) = _domain_data.read(hashed_root_domain);

    // check expiry of root domain
    let (current_timestamp) = get_block_timestamp();

    with_attr error_message("This domain is expired") {
        assert_le(current_timestamp, root_domain_data.expiry);
    }

    return ();
}

func fetch_owner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    contract_addr, starknet_id: Uint256
) -> (owner: felt) {
    if (starknet_id.low == 0 and starknet_id.high == 0) {
        return (0,);
    }
    let (starknet_id_owner) = StarknetID.ownerOf(contract_addr, starknet_id);
    return (starknet_id_owner,);
}

func assert_is_owner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*, contract_addr: felt, caller: felt
) -> (key: felt) {
    alloc_locals;
    let (hashed_domain) = hash_domain(domain_len, domain);
    let (domain_data) = _domain_data.read(hashed_domain);
    let starknet_id = domain_data.owner;
    // shitty crashing function
    let (starknet_id_owner) = fetch_owner(contract_addr, starknet_id);

    if (starknet_id_owner == caller) {
        return (domain_data.key,);
    }

    // if domain_len <= 2

    if (domain_len == 1) {
        with_attr error_message("you do not have rights on this domain") {
            assert 1 = 0;
        }
        return (-1,);
    }

    if (domain_len == 0) {
        with_attr error_message("you do not have rights on this domain") {
            assert 1 = 0;
        }
        return (-1,);
    }

    // else
    let (parent_key) = assert_is_owner(domain_len - 1, domain + 1, contract_addr, caller);
    if (domain_data.parent_key != 0) {
        assert parent_key = domain_data.parent_key;
    }
    return (domain_data.key,);
}

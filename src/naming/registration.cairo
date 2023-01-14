%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_contract_address
from starkware.cairo.common.math import assert_le_felt
from src.naming.utils import (
    DomainData,
    write_domain_data,
    _write_address_to_domain,
    hash_domain,
    _domain_data,
    _pricing_contract,
)
from src.interface.pricing import Pricing
from starkware.starknet.common.syscalls import get_caller_address, get_block_timestamp
from starkware.cairo.common.math import assert_nn, assert_le
from src.interface.starknetid import StarknetId
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
func domain_transfer(domain_len: felt, domain: felt*, prev_owner: felt, new_owner: felt) {
}

@event
func starknet_id_update(domain_len: felt, domain: felt*, owner: felt, expiry: felt) {
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

func pay_buy_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    current_timestamp, days, caller, domain
) -> () {
    let (pricing_contract) = _pricing_contract.read();
    let (erc20, price) = Pricing.compute_buy_price(pricing_contract, domain, days);
    let (naming_contract) = get_contract_address();
    IERC20.transferFrom(erc20, caller, naming_contract, price);
    return ();
}

func pay_renew_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    current_timestamp, days, caller, domain
) -> () {
    let (pricing_contract) = _pricing_contract.read();
    let (erc20, price) = Pricing.compute_renew_price(pricing_contract, domain, days);
    let (naming_contract) = get_contract_address();
    IERC20.transferFrom(erc20, caller, naming_contract, price);
    return ();
}

func mint_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    expiry, resolver, target_address, hashed_domain, token_id, domain
) {
    alloc_locals;
    let data = DomainData(token_id, resolver, target_address, expiry, 1, 0);
    write_domain_data(1, new (domain), data);
    starknet_id_update.emit(1, new (domain), token_id, expiry);
    domain_to_addr_update.emit(1, new (domain), target_address);
    let (contract) = starknetid_contract.read();
    StarknetId.set_verifier_data(contract, token_id, 'name', hashed_domain);

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

    with_attr error_message("This domain has expired") {
        assert_le(current_timestamp, root_domain_data.expiry);
    }

    return ();
}

// We might remove it in the future and keep a clientisde check
func assert_empty_starknet_id{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    starknet_id, current_timestamp, naming_contract
) {
    let (contract_addr) = starknetid_contract.read();
    let (sid_hashed_domain) = StarknetId.get_verifier_data(
        contract_addr, starknet_id, 'name', naming_contract
    );

    with_attr error_message("This starknet_id already has a domain") {
        // if a domain was written, check if it expired
        if (sid_hashed_domain != 0) {
            let (data) = _domain_data.read(sid_hashed_domain);
            if (data.expiry != 0) {
                assert_le_felt(data.expiry, current_timestamp);
                // because cairo is hell
                tempvar syscall_ptr = syscall_ptr;
                tempvar pedersen_ptr = pedersen_ptr;
                tempvar range_check_ptr = range_check_ptr;
            } else {
                assert 1 = 0;
                tempvar syscall_ptr = syscall_ptr;
                tempvar pedersen_ptr = pedersen_ptr;
                tempvar range_check_ptr = range_check_ptr;
            }
        } else {
            tempvar syscall_ptr = syscall_ptr;
            tempvar pedersen_ptr = pedersen_ptr;
            tempvar range_check_ptr = range_check_ptr;
        }
    }
    return ();
}

func fetch_owner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    contract_addr, starknet_id
) -> (owner: felt) {
    if (starknet_id == 0) {
        return (0,);
    }
    let (starknet_id_owner) = StarknetId.owner_of(contract_addr, starknet_id);
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

    // if caller owns the starknet id, he owns the domain, we return the key
    if (starknet_id_owner == caller) {
        return (domain_data.key,);
    }

    // otherwise, if it is a root domain, he doesn't own it
    if (domain_len == 1) {
        with_attr error_message("You do not have rights on this domain") {
            assert 1 = 0;
        }
        return (-1,);
    }

    if (domain_len == 0) {
        with_attr error_message("You do not have rights on this domain") {
            assert 1 = 0;
        }
        return (-1,);
    }

    // if he doesn't own the starknet id, and doesn't own the domain, he might own the parent domain
    let (parent_key) = assert_is_owner(domain_len - 1, domain + 1, contract_addr, caller);
    // we ensure that the key is the same as the parent key
    // this is to allow to revoke all subdomains in o(1) writes, by juste updating the key of the parent
    if (domain_data.parent_key != 0) {
        assert parent_key = domain_data.parent_key;
    }
    return (domain_data.key,);
}

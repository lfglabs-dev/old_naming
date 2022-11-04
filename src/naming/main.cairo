%lang starknet
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.math import assert_nn, assert_le_felt
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.alloc import alloc
from starkware.starknet.common.syscalls import get_caller_address, get_block_timestamp
from starkware.cairo.common.math_cmp import is_le, is_not_zero
from starkware.starknet.common.syscalls import get_contract_address
from cairo_contracts.src.openzeppelin.upgrades.library import Proxy

from src.naming.utils import (
    _domain_data,
    hash_domain,
    _address_to_domain_util,
    _address_to_domain,
    write_domain_data,
    write_address_to_domain,
    DomainData,
    _admin_address,
    _pricing_contract,
    _whitelisting_key,
    _l1_contract,
    blacklisted_point,
)
from src.interface.starknetid import StarknetID
from src.interface.pricing import Pricing
from src.interface.resolver import Resolver
from src.naming.registration import (
    starknetid_contract,
    assert_control_domain,
    domain_to_addr_update,
    domain_to_resolver_update,
    addr_to_domain_update,
    starknet_id_update,
    reset_subdomains_update,
    booked_domain,
    pay_buy_domain,
    pay_renew_domain,
    mint_domain,
)
from src.naming.utils import domain_to_resolver
from cairo_contracts.src.openzeppelin.token.erc20.IERC20 import IERC20

@external
func initializer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    starknetid_contract_addr, pricing_contract_addr, admin, whitelisting_key, l1_contract
) {
    starknetid_contract.write(starknetid_contract_addr);
    _pricing_contract.write(pricing_contract_addr);
    _admin_address.write(admin);
    _whitelisting_key.write(whitelisting_key);
    _l1_contract.write(l1_contract);
    return ();
}

// USER VIEW FUNCTIONS

@view
func domain_to_address{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*
) -> (address: felt) {
    alloc_locals;
    let (resolver: felt, rest_len: felt, rest: felt*) = domain_to_resolver(domain_len, domain, 1);

    if (resolver == 0) {
        let (hashed_domain) = hash_domain(domain_len, domain);
        let (domain_data) = _domain_data.read(hashed_domain);
        if (domain_data.address == FALSE) {
            return (address=0,);
        } else {
            return (domain_data.address,);
        }
    } else {
        let (address) = Resolver.domain_to_address(resolver, rest_len, rest);
        return (address=address);
    }
}

@view
func domain_to_expiry{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*
) -> (expiry: felt) {
    let (hashed_domain) = hash_domain(domain_len, domain);
    let (domain_data) = _domain_data.read(hashed_domain);
    if (domain_data.expiry == FALSE) {
        return (0,);
    } else {
        return (domain_data.expiry,);
    }
}

@view
func address_to_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    address: felt
) -> (domain_len: felt, domain: felt*) {
    alloc_locals;
    let (arr: felt*) = alloc();
    let (arr_len: felt) = _address_to_domain_util(address, arr, 0);
    return (arr_len, arr);
}

@view
func domain_to_token_id{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*
) -> (owner: felt) {
    let (hashed_domain) = hash_domain(domain_len, domain);
    let (domain_data) = _domain_data.read(hashed_domain);
    let owner = domain_data.owner;

    if (owner == 0) {
        if (domain_len == 0) {
            return (FALSE,);
        }
        return domain_to_token_id(domain_len - 1, domain + 1);
    }
    return (owner,);
}

// USER EXTERNAL FUNCTIONS

@external
func set_domain_to_address{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*, address: felt
) {
    alloc_locals;
    let (caller) = get_caller_address();
    assert_control_domain(domain_len, domain, caller);
    let (hashed_domain) = hash_domain(domain_len, domain);
    let (domain_data) = _domain_data.read(hashed_domain);
    let new_data: DomainData = DomainData(
        domain_data.owner,
        domain_data.resolver,
        address,
        domain_data.expiry,
        domain_data.key,
        domain_data.parent_key,
    );
    write_domain_data(domain_len, domain, new_data);
    domain_to_addr_update.emit(domain_len, domain, address);
    return ();
}

@external
func set_domain_to_resolver{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*, resolver: felt
) {
    alloc_locals;
    let (caller) = get_caller_address();
    assert_control_domain(domain_len, domain, caller);
    let (hashed_domain) = hash_domain(domain_len, domain);
    let (domain_data) = _domain_data.read(hashed_domain);
    let new_data: DomainData = DomainData(
        domain_data.owner,
        resolver,
        domain_data.address,
        domain_data.expiry,
        domain_data.key,
        domain_data.parent_key,
    );
    write_domain_data(domain_len, domain, new_data);
    domain_to_resolver_update.emit(domain_len, domain, resolver);
    return ();
}

@external
func set_address_to_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*
) {
    alloc_locals;
    let (caller) = get_caller_address();
    assert_control_domain(domain_len, domain, caller);
    write_address_to_domain(domain_len, domain, caller);
    addr_to_domain_update.emit(caller, domain_len, domain);
    return ();
}

@external
func book_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_hash: felt
) {
    let (current_timestamp) = get_block_timestamp();
    let (booking_data) = booked_domain.read(domain_hash);
    assert_le_felt(booking_data.expiry, current_timestamp);
    let (caller) = get_caller_address();
    booked_domain.write(domain_hash, (caller, current_timestamp + 3600));
    return ();
}

@external
func buy{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    token_id: felt, domain: felt, days: felt, resolver: felt, address: felt
) {
    alloc_locals;

    // Verify that the starknet.id doesn't already manage a domain
    let (contract_addr) = starknetid_contract.read();
    let (naming_contract) = get_contract_address();
    let (data) = StarknetID.get_verifier_data(contract_addr, token_id, 'name', naming_contract);
    with_attr error_message("This StarknetID already has a domain") {
        assert data = 0;
    }

    // Verify that the domain is not registered already or expired
    let (current_timestamp) = get_block_timestamp();
    let (hashed_domain) = hash_domain(1, new (domain));

    // stop front running/mev
    let (booking_data: (owner: felt, expiry: felt)) = booked_domain.read(hashed_domain);
    let booked = is_le(current_timestamp, booking_data.expiry);

    let (caller) = get_caller_address();
    if (booked == TRUE) {
        with_attr error_message("Someone else booked this domain") {
            assert booking_data.owner = caller;
        }
    }

    let (domain_data) = _domain_data.read(hashed_domain);
    let is_expired = is_le(domain_data.expiry, current_timestamp);

    if (domain_data.owner != 0) {
        assert is_expired = TRUE;
    }

    pay_buy_domain(current_timestamp, days, caller, domain);
    let expiry = current_timestamp + 86400 * days;
    with_attr error_message("A domain can't be purchased for more than 25 years") {
        assert_le_felt(expiry, current_timestamp + 86400 * 9125);  // 25*365
    }
    mint_domain(expiry, resolver, address, hashed_domain, token_id, domain);
    return ();
}

@l1_handler
func buy_from_eth{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    from_address: felt, token_id: felt, domain: felt, days: felt, resolver: felt, address: felt
) {
    alloc_locals;
    // Ensure the caller is the right L1 contract
    let (l1_contract) = _l1_contract.read();
    assert from_address = l1_contract;

    // Verify that the starknet.id doesn't already manage a domain
    let (contract_addr) = starknetid_contract.read();
    let (naming_contract) = get_contract_address();
    let (data) = StarknetID.get_verifier_data(contract_addr, token_id, 'name', naming_contract);
    with_attr error_message("This StarknetID already has a domain") {
        assert data = 0;
    }

    // Verify that the domain is not registered already or expired
    let (current_timestamp) = get_block_timestamp();
    let (hashed_domain) = hash_domain(1, new (domain));

    // stop front running/mev on L2
    let (booking_data: (owner: felt, expiry: felt)) = booked_domain.read(hashed_domain);
    with_attr error_message("Someone else booked this domain on L2") {
        assert_le_felt(booking_data.expiry, current_timestamp);
    }

    let (domain_data) = _domain_data.read(hashed_domain);
    let is_expired = is_le(domain_data.expiry, current_timestamp);

    if (domain_data.owner != 0) {
        assert is_expired = TRUE;
    }

    // no need to pay on l2, already paid on l1
    // pay_buy_domain(current_timestamp, days, caller, domain);
    let expiry = current_timestamp + 86400 * days;
    with_attr error_message("A domain can't be purchased for more than 25 years") {
        assert_le_felt(expiry, current_timestamp + 86400 * 9125);  // 25*365
    }
    mint_domain(expiry, resolver, address, hashed_domain, token_id, domain);
    return ();
}

@external
func renew{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain: felt, days: felt
) {
    alloc_locals;

    // Verify that the domain is not expired
    let (current_timestamp) = get_block_timestamp();
    let (hashed_domain) = hash_domain(1, new (domain));
    let (domain_data: DomainData) = _domain_data.read(hashed_domain);
    let is_expired = is_le(domain_data.expiry, current_timestamp);
    assert is_expired = FALSE;

    // Get expiry and price
    let expiry = domain_data.expiry + 86400 * days;  // 1 day = 86400s
    with_attr error_message("A domain can't be purchased for more than 25 years") {
        assert_le_felt(expiry, current_timestamp + 86400 * 9125);  // 25*365
    }
    let data = DomainData(
        domain_data.owner, domain_data.resolver, domain_data.address, expiry, domain_data.key, 0
    );

    // Register
    let (caller) = get_caller_address();

    // Make the user pay
    pay_renew_domain(current_timestamp, days, caller, domain);

    // Write info on starknet.id and write info on storage data
    write_domain_data(1, new (domain), data);

    starknet_id_update.emit(1, new (domain), domain_data.owner, expiry);
    return ();
}

@external
func transfer_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*, target_token_id: felt
) {
    alloc_locals;
    let (caller) = get_caller_address();
    assert_control_domain(domain_len, domain, caller);

    // Write domain owner
    let (hashed_domain) = hash_domain(domain_len, domain);
    let (current_domain_data) = _domain_data.read(hashed_domain);
    let (contract) = starknetid_contract.read();
    let (naming_contract) = get_contract_address();
    let (data: felt) = StarknetID.get_verifier_data(
        contract, target_token_id, 'name', naming_contract
    );
    // ensure target doesn't already have a domain
    with_attr error_message("Target token_id already has a domain") {
        assert data = 0;
    }
    if (current_domain_data.parent_key == 0) {
        let (hashed_parent_domain) = hash_domain(domain_len - 1, domain + 1);
        let (next_domain_data) = _domain_data.read(hashed_parent_domain);
        let new_domain_data = DomainData(
            target_token_id,
            current_domain_data.resolver,
            current_domain_data.address,
            current_domain_data.expiry,
            current_domain_data.key,
            next_domain_data.key,
        );
        _domain_data.write(hashed_domain, new_domain_data);
        starknet_id_update.emit(0, new (), current_domain_data.owner, 0);
        starknet_id_update.emit(domain_len, domain, target_token_id, current_domain_data.expiry);
        StarknetID.set_verifier_data(contract, current_domain_data.owner, 'name', 0);
        StarknetID.set_verifier_data(contract, target_token_id, 'name', hashed_domain);
        return ();
    } else {
        let new_domain_data = DomainData(
            target_token_id,
            current_domain_data.resolver,
            current_domain_data.address,
            current_domain_data.expiry,
            current_domain_data.key,
            current_domain_data.parent_key,
        );
        _domain_data.write(hashed_domain, new_domain_data);
        starknet_id_update.emit(0, new (), current_domain_data.owner, 0);
        starknet_id_update.emit(domain_len, domain, target_token_id, current_domain_data.expiry);
        StarknetID.set_verifier_data(contract, current_domain_data.owner, 'name', 0);
        StarknetID.set_verifier_data(contract, target_token_id, 'name', hashed_domain);
        return ();
    }
}

@external
func reset_subdomains{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*
) {
    alloc_locals;
    let (caller) = get_caller_address();
    assert_control_domain(domain_len, domain, caller);

    // Write domain owner
    let (hashed_domain) = hash_domain(domain_len, domain);
    let (current_domain_data) = _domain_data.read(hashed_domain);
    let new_domain_data = DomainData(
        current_domain_data.owner,
        current_domain_data.resolver,
        current_domain_data.address,
        current_domain_data.expiry,
        current_domain_data.key + 1,
        current_domain_data.parent_key,
    );
    _domain_data.write(hashed_domain, new_domain_data);
    reset_subdomains_update.emit(domain_len, domain);

    return ();
}

// ADMIN EXTERNAL FUNCTIONS

@external
func set_admin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(address: felt) {
    // Verify that caller is admin
    let (caller) = get_caller_address();
    let (admin_address) = _admin_address.read();
    assert caller = admin_address;

    // Write new admin
    _admin_address.write(address);

    return ();
}

@external
func set_domain_owner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*, token_id: felt
) {
    alloc_locals;
    // Verify that caller is admin
    let (caller) = get_caller_address();
    let (admin_address) = _admin_address.read();
    assert caller = admin_address;

    // Write domain owner
    let (hashed_domain) = hash_domain(domain_len, domain);
    let (current_domain_data) = _domain_data.read(hashed_domain);
    let new_domain_data = DomainData(
        token_id,
        current_domain_data.resolver,
        current_domain_data.address,
        current_domain_data.expiry,
        current_domain_data.key,
        current_domain_data.parent_key,
    );
    _domain_data.write(hashed_domain, new_domain_data);
    starknet_id_update.emit(0, new (), current_domain_data.owner, 0);
    starknet_id_update.emit(domain_len, domain, token_id, current_domain_data.expiry);
    let (contract) = starknetid_contract.read();
    StarknetID.set_verifier_data(contract, current_domain_data.owner, 'name', 0);
    StarknetID.set_verifier_data(contract, token_id, 'name', hashed_domain);

    return ();
}

@external
func set_pricing_contract{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    address: felt
) {
    // Verify that caller is admin
    let (caller) = get_caller_address();
    let (admin_address) = _admin_address.read();
    assert caller = admin_address;

    // Write domain owner
    _pricing_contract.write(address);

    return ();
}

@external
func transfer_balance{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    erc20: felt, amount: Uint256
) {
    // Verify that caller is admin
    let (caller) = get_caller_address();
    let (admin_address) = _admin_address.read();
    assert caller = admin_address;

    // Redeem funds
    IERC20.transfer(erc20, caller, amount);

    return ();
}

@external
func whitelisted_mint{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, ecdsa_ptr: SignatureBuiltin*
}(domain, expiry, starknet_id, receiver_address, sig: (felt, felt)) {
    alloc_locals;

    let (caller) = get_caller_address();
    let (params_hash) = hash2{hash_ptr=pedersen_ptr}(domain, expiry);
    let (params_hash) = hash2{hash_ptr=pedersen_ptr}(params_hash, receiver_address);

    let (whitelisting_key) = _whitelisting_key.read();
    verify_ecdsa_signature(params_hash, whitelisting_key, sig[0], sig[1]);

    let (hashed_domain) = hash_domain(1, new (domain));
    let (is_blacklisted) = blacklisted_point.read(sig[0]);
    with_attr error_message("This signature has already been used") {
        assert is_blacklisted = 0;
    }

    // blacklisting r should be enough since it depends on the "secure random point" it should never be used again
    // to anyone willing to improve this check in the future, please be careful with s, as (r, -s) is also a valid signature
    blacklisted_point.write(sig[0], 1);

    with_attr error_message("Only the receiver can mint this") {
        assert caller = receiver_address;
    }

    mint_domain(expiry, 0, receiver_address, hashed_domain, starknet_id, domain);

    return ();
}

@external
func end_whitelist{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    // Verify that caller is admin
    let (caller) = get_caller_address();
    let (admin_address) = _admin_address.read();
    assert caller = admin_address;

    // Set whitelist key to 0
    _whitelisting_key.write(0);
    return ();
}

@external
func set_l1_contract{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(l1_contract) {
    // Verify that caller is admin
    let (caller) = get_caller_address();
    let (admin_address) = _admin_address.read();
    assert caller = admin_address;

    // Set l1_contract address
    _l1_contract.write(l1_contract);
    return ();
}

//
// UPGRADABILITY
//
@external
func upgrade{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    new_implementation: felt
) {
    // Verify that caller is admin
    let (caller) = get_caller_address();
    let (admin_address) = _admin_address.read();
    assert caller = admin_address;

    // Set contract implementation
    Proxy._set_implementation_hash(new_implementation);
    return ();
}

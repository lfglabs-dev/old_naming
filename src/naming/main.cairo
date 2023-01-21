%lang starknet
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.math import assert_nn, assert_le, assert_le_felt, split_felt
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.alloc import alloc
from starkware.starknet.common.syscalls import get_caller_address, get_block_timestamp
from starkware.cairo.common.math_cmp import is_le, is_not_zero
from starkware.starknet.common.syscalls import get_contract_address
from cairo_contracts.src.openzeppelin.upgrades.library import Proxy
from src.interface.starknetid import StarknetId
from src.interface.pricing import Pricing
from src.interface.resolver import Resolver
from src.naming.discounts import Discount, discounts
from src.naming.registration import (
    domain_to_addr_update,
    domain_to_resolver_update,
    addr_to_domain_update,
    starknet_id_update,
    reset_subdomains_update,
    domain_transfer,
    starknetid_contract,
    booked_domain,
    pay_buy_domain,
    pay_buy_domain_discount,
    pay_renew_domain,
    mint_domain,
    assert_control_domain,
    assert_purchase_is_possible,
    assert_empty_starknet_id,
)
from src.naming.utils import (
    _domain_data,
    domain_to_resolver,
    hash_domain,
    _address_to_domain_util,
    _address_to_domain,
    write_domain_data,
    _write_address_to_domain,
    DomainData,
    _admin_address,
    _pricing_contract,
    _l1_contract,
    compute_new_expiry,
    get_amount_of_chars,
)
from cairo_contracts.src.openzeppelin.token.erc20.IERC20 import IERC20

@external
func initializer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    starknetid_contract_addr, pricing_contract_addr, admin, l1_contract
) {
    // can only be called if there is no admin
    let (current_admin) = _admin_address.read();
    assert current_admin = 0;
    // then if there is no admin, the proxy can initialize the contract
    starknetid_contract.write(starknetid_contract_addr);
    _pricing_contract.write(pricing_contract_addr);
    _admin_address.write(admin);
    _l1_contract.write(l1_contract);
    return ();
}

// USER VIEW FUNCTIONS

@view
func domain_to_address{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*
) -> (address: felt) {
    alloc_locals;
    if (domain_len == 0) {
        return (address=0);
    }
    let (resolver: felt, rest_len: felt, rest: felt*) = domain_to_resolver(domain_len, domain, 1);
    if (resolver == 0) {
        let (hashed_domain) = hash_domain(domain_len, domain);
        let (domain_data) = _domain_data.read(hashed_domain);
        // if it is a root domain
        if (domain_len == 1) {
            return (domain_data.address,);
            // else, check that the parent_key equals parent.key
        } else {
            let (hashed_parent_domain) = hash_domain(domain_len - 1, domain + 1);
            let (parent_domain_data) = _domain_data.read(hashed_parent_domain);
            if (parent_domain_data.key == domain_data.parent_key) {
                return (domain_data.address,);
            } else {
                return (FALSE,);
            }
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
    return (domain_data.expiry,);
}

@view
func address_to_domain{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    address: felt
) -> (domain_len: felt, domain: felt*) {
    alloc_locals;
    let (arr: felt*) = alloc();
    let (arr_len: felt) = _address_to_domain_util(address, arr, 0);
    let (found_addr) = domain_to_address(arr_len, arr);
    if (found_addr == address) {
        return (arr_len, arr);
    } else {
        return (0, arr);
    }
}

@view
func domain_to_token_id{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain_len: felt, domain: felt*
) -> (owner: felt) {
    alloc_locals;
    let (hashed_domain) = hash_domain(domain_len, domain);
    let (domain_data) = _domain_data.read(hashed_domain);
    let owner = domain_data.owner;

    // recursive calls
    if (owner == 0) {
        if (domain_len == 0) {
            return (FALSE,);
        }
        return domain_to_token_id(domain_len - 1, domain + 1);
    }

    // if it is a root domain, return the owner
    if (domain_len == 1) {
        return (owner,);
    }

    // else, first check parent_key
    let (hashed_parent_domain) = hash_domain(domain_len - 1, domain + 1);
    let (parent_domain_data) = _domain_data.read(hashed_parent_domain);
    if (parent_domain_data.key == domain_data.parent_key) {
        return (owner,);
    } else {
        return (FALSE,);
    }
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
    let (target) = domain_to_address(domain_len, domain);
    with_attr error_message("You can only point your address to a domain pointing back") {
        assert target = caller;
    }
    _write_address_to_domain(domain_len, domain, caller);
    // in case of overwriting
    _address_to_domain.write(caller, domain_len, 0);
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
    let (hashed_domain, current_timestamp, expiry) = assert_purchase_is_possible(
        token_id, domain, days
    );

    // stop front running/mev
    let (booking_data: (owner: felt, expiry: felt)) = booked_domain.read(hashed_domain);
    let booked = is_le(current_timestamp, booking_data.expiry);
    let (caller) = get_caller_address();
    if (booked == TRUE) {
        with_attr error_message("Someone else booked this domain") {
            assert booking_data.owner = caller;
        }
    }

    pay_buy_domain(current_timestamp, days, caller, domain);
    mint_domain(expiry, resolver, address, hashed_domain, token_id, domain);
    return ();
}

@external
func buy_discounted{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    token_id: felt, domain: felt, days: felt, resolver: felt, address: felt, discount_id: felt
) {
    alloc_locals;
    let (hashed_domain, current_timestamp, expiry) = assert_purchase_is_possible(
        token_id, domain, days
    );

    // stop front running/mev
    let (booking_data: (owner: felt, expiry: felt)) = booked_domain.read(hashed_domain);
    let booked = is_le(current_timestamp, booking_data.expiry);
    let (caller) = get_caller_address();
    if (booked == TRUE) {
        with_attr error_message("Someone else booked this domain") {
            assert booking_data.owner = caller;
        }
    }

    // handle discount verification
    let (discount) = discounts.read(discount_id);

    with_attr error_message("Invalid discount. Domain length is out of range") {
        // assert domain_len_min <= domain length <= domain_len_max
        let (high, low) = split_felt(domain);
        let number_of_character = get_amount_of_chars(Uint256(low, high));
        assert_le(discount.domain_len_range[0], number_of_character);
        assert_le(number_of_character, discount.domain_len_range[1]);
    }

    with_attr error_message("Invalid discount. Days amount is out of range") {
        // assert days_min <= days <= days_max
        assert_le(discount.days_range[0], days);
        assert_le(days, discount.days_range[1]);
    }

    with_attr error_message("Invalid discount. Timestamp is out of range") {
        // assert timestamp_min <= current_timestamp <= timestamp_max
        assert_le(discount.timestamp_range[0], current_timestamp);
        assert_le(current_timestamp, discount.timestamp_range[1]);
    }

    pay_buy_domain_discount(current_timestamp, days, caller, domain, discount.amount);
    mint_domain(expiry, resolver, address, hashed_domain, token_id, domain);
    return ();
}

@l1_handler
func buy_from_eth{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    from_address: felt, token_id: felt, domain: felt, days: felt, resolver: felt, address: felt
) {
    let (hashed_domain, current_timestamp, expiry) = assert_purchase_is_possible(
        token_id, domain, days
    );

    // stop front running/mev on L2
    let (booking_data: (owner: felt, expiry: felt)) = booked_domain.read(hashed_domain);
    with_attr error_message("Someone else booked this domain on L2") {
        assert_le_felt(booking_data.expiry, current_timestamp);
    }

    // Ensure the caller is the right L1 contract
    let (l1_contract) = _l1_contract.read();
    assert from_address = l1_contract;

    // no need to pay on l2, already paid on l1
    // pay_buy_domain(current_timestamp, days, caller, domain);
    mint_domain(expiry, resolver, address, hashed_domain, token_id, domain);
    return ();
}

@external
func renew{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    domain: felt, days: felt
) {
    alloc_locals;

    let (current_timestamp) = get_block_timestamp();
    let (hashed_domain) = hash_domain(1, new (domain));
    let (domain_data: DomainData) = _domain_data.read(hashed_domain);
    // no need to verify the domain is expired
    // assert_le(domain_data.expiry, current_timestamp);

    // Get expiry and price
    let expiry = compute_new_expiry(domain_data.expiry, current_timestamp, days);

    with_attr error_message("A domain can't be purchased for more than 25 years") {
        assert_le_felt(expiry, current_timestamp + 86400 * 9125);  // 25*365
    }
    with_attr error_message("A domain can't be purchased for less than 6 months") {
        assert_le_felt(6 * 30, days);
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
    // ensure target doesn't already have a domain
    let (current_timestamp) = get_block_timestamp();
    assert_empty_starknet_id(target_token_id, current_timestamp, naming_contract);

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
        domain_transfer.emit(domain_len, domain, current_domain_data.owner, target_token_id);
        StarknetId.set_verifier_data(contract, current_domain_data.owner, 'name', 0);
        StarknetId.set_verifier_data(contract, target_token_id, 'name', hashed_domain);
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
        domain_transfer.emit(domain_len, domain, current_domain_data.owner, target_token_id);
        StarknetId.set_verifier_data(contract, current_domain_data.owner, 'name', 0);
        StarknetId.set_verifier_data(contract, target_token_id, 'name', hashed_domain);
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
    domain_transfer.emit(domain_len, domain, current_domain_data.owner, token_id);
    let (contract) = starknetid_contract.read();
    StarknetId.set_verifier_data(contract, current_domain_data.owner, 'name', 0);
    StarknetId.set_verifier_data(contract, token_id, 'name', hashed_domain);

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
func write_discount{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    discount_id: felt, discount: Discount
) {
    // Verify that caller is admin
    let (caller) = get_caller_address();
    let (admin_address) = _admin_address.read();
    assert caller = admin_address;

    // Even though admin should be trusted, mistakes happen
    // make sure ranges are valid
    assert_le(discount.domain_len_range[0], discount.domain_len_range[1]);
    assert_le(discount.days_range[0], discount.days_range[1]);
    assert_le(discount.timestamp_range[0], discount.timestamp_range[1]);
    // discount is in multiple of 5%, can't exceed 50%
    assert_le(discount.amount, 10);

    // Write discount (can be used to update a discount by reusing the same id)
    discounts.write(discount_id, discount);
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

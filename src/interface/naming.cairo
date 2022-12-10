%lang starknet
from starkware.cairo.common.uint256 import Uint256

@contract_interface
namespace Naming {
    // View functions

    func domain_to_address(domain_len: felt, domain: felt*) -> (address: felt) {
    }

    func domain_to_expiry(domain_len: felt, domain: felt*) -> (address: felt) {
    }

    func address_to_domain(address: felt) -> (domain_len: felt, domain: felt*) {
    }

    func domain_to_token_id(domain_len: felt, domain: felt*) -> (owner: felt) {
    }

    // Setters

    func set_domain_to_address(domain_len: felt, domain: felt*, address: felt) {
    }

    func set_address_to_domain(domain_len: felt, domain: felt*) {
    }

    func book_domain(domain_hash: felt) {
    }

    func buy(token_id: felt, domain: felt, days: felt, resolver: felt, address: felt) {
    }

    func renew(domain: felt, days: felt) {
    }

    func transfer_domain(domain_len: felt, domain: felt*, target_token_id: felt) {
    }

    func reset_subdomains(domain_len: felt, domain: felt*) {
    }

    // Admin setters

    func set_admin(address: felt) {
    }

    func set_domain_owner(domain_len: felt, domain: felt*, token_id: felt) {
    }

    func set_pricing_contract(address: felt) {
    }

    func transfer_balance(erc20: felt, amount: Uint256) {
    }

    func whitelisted_mint(domain, expiry, starknet_id, receiver_address, sig: (felt, felt)) {
    }

    func end_whitelist() {
    }

    func set_l1_contract(l1_contract) {
    }

    func upgrade(new_implementation: felt) {
    }
}

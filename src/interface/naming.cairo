%lang starknet
from starkware.cairo.common.uint256 import Uint256

@contract_interface
namespace Naming:
    # View functions

    func domain_to_address(domain_len : felt, domain : felt*) -> (address : felt):
    end

    func domain_to_expiry(domain_len : felt, domain : felt*) -> (address : felt):
    end

    func address_to_domain(address : felt) -> (domain_len : felt, domain : felt*):
    end

    func domain_to_token_id(domain_len : felt, domain : felt*) -> (owner : Uint256):
    end

    # Setters

    func set_domain_to_address(domain_len : felt, domain : felt*, address : felt):
    end

    func set_address_to_domain(domain_len : felt, domain : felt*):
    end

    func book_domain(domain_hash : felt):
    end

    func buy(token_id : Uint256, domain : felt, days : felt, address : felt):
    end

    func renew(token_id : Uint256, domain : felt, days : felt):
    end

    func transfer_domain(domain_len : felt, domain : felt*, target_token_id : Uint256):
    end

    func reset_subdomains(domain_len : felt, domain : felt*):
    end

    # Admin setters

    func set_admin(address : felt):
    end

    func set_domain_owner(domain_len : felt, domain : felt*, token_id : Uint256):
    end

    func set_pricing_contract(address : felt):
    end

    func transfer_balance(erc20 : felt, amount : Uint256):
    end
end

%lang starknet
from starkware.cairo.common.uint256 import Uint256

@contract_interface
namespace Resolver {
    func domain_to_address(domain_len: felt, domain: felt*) -> (address: felt) {
    }
}

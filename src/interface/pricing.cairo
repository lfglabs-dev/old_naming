%lang starknet
from starkware.cairo.common.uint256 import Uint256

@contract_interface
namespace Pricing {
    func compute_buy_price(domain: felt, days: felt) -> (erc20: felt, price: Uint256) {
    }

    func compute_renew_price(domain: felt, days: felt) -> (erc20: felt, price: Uint256) {
    }
}

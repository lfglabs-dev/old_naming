%lang starknet
from starkware.cairo.common.uint256 import Uint256

@contract_interface
namespace Referral {
    // View functions
    func add_commission(amount: Uint256, sponsor_addr: felt) {
    }
}
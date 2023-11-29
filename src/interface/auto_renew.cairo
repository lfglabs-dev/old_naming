%lang starknet
from starkware.cairo.common.uint256 import Uint256

@contract_interface
namespace AutoRenew {
    func get_renewing_allowance(domain: felt, renewer: felt) -> (allowance : Uint256) {
    }
}

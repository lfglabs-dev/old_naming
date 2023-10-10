%lang starknet

from starkware.cairo.common.uint256 import Uint256

@contract_interface
namespace StarknetId {
    func mint(token_id) {
    }

    func owner_of(token_id) -> (owner: felt) {
    }

    func get_verifier_data(token_id, field, verifier, domain) -> (data: felt) {
    }

    func set_verifier_data(token_id, field, data, domain) {
    }

}

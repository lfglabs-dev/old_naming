%lang starknet

from starkware.cairo.common.uint256 import Uint256

@contract_interface
namespace StarknetID {
    func mint(token_id: Uint256) {
    }

    func ownerOf(token_id: Uint256) -> (owner: felt) {
    }

    func get_verifier_data(token_id: Uint256, field: felt, verifier: felt) -> (data: felt) {
    }

    func set_verifier_data(token_id: Uint256, field: felt, data: felt) {
    }
}

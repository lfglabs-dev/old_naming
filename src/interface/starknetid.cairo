%lang starknet

from starkware.cairo.common.uint256 import Uint256

@contract_interface
namespace StarknetID:
    func ownerOf(token_id : Uint256) -> (owner : felt):
    end

    func get_verifier_data(token_id : Uint256, field : felt, verifier : felt) -> (data : felt):
    end

    func set_verifier_data(token_id : Uint256, field : felt, data : felt):
    end
end

%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from src.naming.main import buy_from_eth, domain_to_address
from src.naming.registration import starknetid_contract
from src.naming.utils import _l1_contract

@external
func __setup__() {
    %{ context.starknet_id_contract = deploy_contract("./lib/starknetid/src/StarknetId.cairo").contract_address %}
    return ();
}

@external
func test_simple_buy{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    tempvar starknet_id_contract_;

    %{
        ids.starknet_id_contract_ = context.starknet_id_contract
        stop_prank_callable = start_prank(456)
        stop_mock = mock_call(123, "transferFrom", [1])
    %}

    starknetid_contract.write(starknet_id_contract_);

    let l1_contract = 0xAAAAA;
    _l1_contract.write(l1_contract);
    let token_id = 1;
    let th0rgal_string = 28235132438;

    buy_from_eth(l1_contract, token_id, th0rgal_string, 365, 0, 456);

    let (addr) = domain_to_address(1, new (th0rgal_string));
    assert addr = 456;
    %{
        stop_prank_callable()
        stop_mock()
    %}

    return ();
}

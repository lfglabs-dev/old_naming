%lang starknet

@contract_interface
namespace Pricing:
    func compute_buy_price(domain : felt, days : felt) -> (erc20 : felt, price : felt):
    end

    func compute_renew_price(domain : felt, days : felt) -> (erc20 : felt, price : felt):
    end
end

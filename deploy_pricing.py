from starkware.starknet.compiler.compile import get_selector_from_name
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.net import AccountClient, KeyPair
from starknet_py.net.gateway_client import GatewayClient
from starknet_py.net.networks import Network
from starknet_py.transactions.deploy import make_deploy_tx
from starknet_py.compile.compiler import create_contract_class

import asyncio
import sys

argv = sys.argv

deployer_account_addr = (
    0x048F24D0D0618FA31813DB91A45D8BE6C50749E5E19EC699092CE29ABE809294
)
deployer_account_private_key = int(argv[1])
admin = 0x048F24D0D0618FA31813DB91A45D8BE6C50749E5E19EC699092CE29ABE809294
network: Network = "testnet"
chain: StarknetChainId = StarknetChainId.TESTNET
max_fee = int(1e16)
# ethereum contract
erc20 = 0x049D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7


async def main():
    client = GatewayClient(net=network)
    account = AccountClient(
        client=client,
        address=deployer_account_addr,
        key_pair=KeyPair.from_private_key(deployer_account_private_key),
        chain=chain,
        supported_tx_version=1,
    )

    pricing_file = open("./build/pricing.json", "r")
    deploy_pricing_tx = make_deploy_tx(
        compiled_contract=create_contract_class(pricing_file.read()),
        constructor_calldata=[erc20],
        version=1,
    )
    pricing_file.close()
    deployment_pricing = await account.deploy(deploy_pricing_tx)
    print("deployment txhash:", hex(deployment_pricing.transaction_hash))
    print("pricing contract address:", hex(deployment_pricing.contract_address))


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

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
token = argv[2] if len(argv) > 2 else None
admin = 0x048F24D0D0618FA31813DB91A45D8BE6C50749E5E19EC699092CE29ABE809294
# MAINNET: https://alpha-mainnet.starknet.io
# TESTNET: https://alpha4.starknet.io
# TESTNET2: https://alpha4-2.starknet.io
network_base_url = "https://alpha-mainnet.starknet.io/"
chainid: StarknetChainId = StarknetChainId.MAINNET
max_fee = int(1e16)

pricing = 0  # 0x6F670AAF8279931E6DE21F831530CB990DA81F51717D7E80E442AA010BC6EF5
l1_contract = 0  # 0xDF8C42FABB2A3E170603CBCB7AC3FA03F125CE6C
whitelisting_key = (
    1576987121283045618657875225183003300580199140020787494777499595331436496159
)
starknet_id = 0x030A9C7F261D34F4209E0B2466BC1FDD4AEAF87187DB7897FEBED83645905BBD


async def main():
    client = GatewayClient(
        net={
            "feeder_gateway_url": network_base_url + "feeder_gateway",
            "gateway_url": network_base_url + "gateway",
        }
    )
    account = AccountClient(
        client=client,
        address=deployer_account_addr,
        key_pair=KeyPair.from_private_key(deployer_account_private_key),
        chain=chainid,
        supported_tx_version=1,
    )

    logic_file = open("./build/naming.json", "r")
    declare_contract_tx = await account.sign_declare_transaction(
        compiled_contract=logic_file.read(), max_fee=max_fee
    )
    logic_file.close()
    logic_declaration = await client.declare(
        transaction=declare_contract_tx, token=token
    )
    logic_contract_class_hash = logic_declaration.class_hash
    print("implementation class hash:", hex(logic_contract_class_hash))

    proxy_file = open("./build/proxy.json", "r")
    deploy_contract_tx = make_deploy_tx(
        compiled_contract=create_contract_class(proxy_file.read()),
        constructor_calldata=[
            logic_contract_class_hash,
            get_selector_from_name("initializer"),
            5,
            starknet_id,
            pricing,
            admin,
            whitelisting_key,
            l1_contract,
        ],
        version=1,
    )
    proxy_file.close()
    deployment_resp = await client.deploy(transaction=deploy_contract_tx, token=token)
    print("deployment txhash:", hex(deployment_resp.transaction_hash))
    print("proxied naming contract address:", hex(deployment_resp.contract_address))


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

from starknet_py.net.models.chains import StarknetChainId
from starknet_py.net.gateway_client import GatewayClient
from starknet_py.net.udc_deployer.deployer import Deployer
from starknet_py.compile.compiler import create_contract_class
from starknet_py.net import AccountClient, KeyPair
import asyncio
import json
import sys

argv = sys.argv

deployer_account_addr = (
    0x048F24D0D0618FA31813DB91A45D8BE6C50749E5E19EC699092CE29ABE809294
)
deployer_account_private_key = int(argv[1])
# MAINNET: https://alpha-mainnet.starknet.io/
# TESTNET: https://alpha4.starknet.io/
# TESTNET2: https://alpha4-2.starknet.io/
network_base_url = "https://alpha4.starknet.io/"
chainid: StarknetChainId = StarknetChainId.TESTNET
max_fee = int(1e16)
# ethereum contract
erc20 = 0x049D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7
deployer = Deployer()


async def main():
    client = GatewayClient(
        net={
            "feeder_gateway_url": network_base_url + "feeder_gateway",
            "gateway_url": network_base_url + "gateway",
        }
    )
    account: AccountClient = AccountClient(
        client=client,
        address=deployer_account_addr,
        key_pair=KeyPair.from_private_key(deployer_account_private_key),
        chain=chainid,
        supported_tx_version=1,
    )

    pricing_file = open("./build/pricing.json", "r")
    pricing_content = pricing_file.read()
    pricing_file.close()
    declare_contract_tx = await account.sign_declare_transaction(
        compiled_contract=pricing_content, max_fee=max_fee
    )
    pricing_declaration = await client.declare(transaction=declare_contract_tx)
    pricing_json = json.loads(pricing_content)
    abi = pricing_json["abi"]
    print("pricing class hash:", hex(pricing_declaration.class_hash))
    deploy_call, address = deployer.create_deployment_call(
        class_hash=pricing_declaration.class_hash,
        abi=abi,
        calldata={"erc20_address": erc20},
    )

    resp = await account.execute(deploy_call, max_fee=int(1e16))
    print("deployment txhash:", hex(resp.transaction_hash))
    print("pricing contract address:", hex(address))


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

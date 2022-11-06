%lang starknet

@external
func up() {
    %{
        from starkware.starknet.compiler.compile import get_selector_from_name
        admin = 0x048F24D0D0618fa31813DB91a45d8be6c50749e5E19ec699092CE29aBe809294
        starknet_id = 0x0543b132a5adf5fe52788abe127d93d76d1fa25345456e3e4cd1a44610d07677
        eth = 0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7
        pricing = 0x06b018f6ec9191973da2f6c511819cc3ba29a6b02408c9e80a074ecd7c4c6ada #deploy_contract("./build/pricing.json", [eth]).contract_address
        whitelisting_key = 0
        l1_contract = 0

        logic_contract_class_hash = declare("./build/naming.json").class_hash
        storage_contract_address = deploy_contract("./build/proxy.json", [logic_contract_class_hash,
            get_selector_from_name("initializer"), 5, starknet_id, pricing, admin, whitelisting_key, l1_contract]).contract_address
    %}
    return ();
}

@external
func down() {
    %{ assert False, "Not implemented" %}
    return ();
}

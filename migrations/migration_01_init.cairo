%lang starknet

@external
func up() {
    %{
        from starkware.starknet.compiler.compile import get_selector_from_name
        admin = 0x048F24D0D0618fa31813DB91a45d8be6c50749e5E19ec699092CE29aBe809294
        starknet_id = 0x02450a4c45651d31d1a144a760ca19a5ca9bf72caeed9d5c8330c07adfd86604
        eth = 0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7
        pricing = deploy_contract("./build/pricing.json", [eth]).contract_address
        whitelisting_key = 1576987121283045618657875225183003300580199140020787494777499595331436496159
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

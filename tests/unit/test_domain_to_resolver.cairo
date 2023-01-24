%lang starknet
from src.naming.utils import domain_to_resolver, write_domain_data, DomainData
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc

@external
func test_domain_to_resolver{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    write_domain_data(2, new ('charlie', 'delta'), DomainData(1, 'resolver', 123, -1, 0, 0));

    // should return the resolver and the start index of the parent domain containing the resolver
    let (resolver: felt, id: felt) = domain_to_resolver(
        4, new ('alpha', 'bravo', 'charlie', 'delta'), 1
    );
    assert resolver = 'resolver';
    assert id = 2;

    let (resolver: felt, id: felt) = domain_to_resolver(
        5, new ('echo', 'alpha', 'bravo', 'charlie', 'delta'), 1
    );
    assert resolver = 'resolver';
    assert id = 3;

    // should not return a resolver
    let (resolver: felt, _) = domain_to_resolver(4, new ('delta', 'charlie', 'bravo', 'alpha'), 1);
    assert resolver = 0;

    write_domain_data(1, new ('alpha'), DomainData(1, 'resolver2', 123, -1, 0, 0));

    // same for root domain
    // should return the resolver and the start index of the parent domain containing the resolver
    let (resolver: felt, id: felt) = domain_to_resolver(
        4, new ('delta', 'charlie', 'bravo', 'alpha'), 1
    );
    assert resolver = 'resolver2';
    assert id = 3;

    let (resolver: felt, id: felt) = domain_to_resolver(2, new ('bravo', 'alpha'), 1);
    assert resolver = 'resolver2';
    assert id = 1;
    // should not return a resolver
    let (resolver: felt, _) = domain_to_resolver(1, new ('alpha'), 1);
    assert resolver = 0;

    return ();
}

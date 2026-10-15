"""
Getter folding (passes/getters.py): a function becomes `T public name` only
when solc's generated getter behaves exactly like it (and the exact and full
renderings are executed against each other where a fold happens).
"""

from eth_utils import keccak

from scobelix.solgen import ir, sigs

from test_storage_passes import Case, _run_both, calldata, cd, checked, field, mapkey, ret


def iszero(x):
    return ir.Op("iszero", (x,))


def test_enum_and_struct_getters_fold():
    c = Case()
    status = ir.If(iszero(ir.Op("lt", (field(0, 0, 8), ir.Const(4)))), (ir.Revert(ir.Panic(0x21)),),
                   (ret(field(0, 0, 8)),))
    k1 = c.named("status()", [status], mutability="view")
    pos = mapkey(cd(0), 1)
    k2 = c.named("positions(uint256)", checked(1, [ret(field(pos, 0, 160), field(pos, 160, 96),
                                                       iszero(iszero(field(ir.Op("add", (ir.ONE, pos)), 0, 8))))]),
                 ("uint256",), "view")
    c.fn(0x55550001, [ir.Sstore(ir.Const(0), cd(0), 0, 8), ir.Stop()])  # an enum written raw (any byte)
    calls = [calldata(int(k, 16), a) for k in (k1, k2, "0x55550001") for a in (0, 3, 4, 255, 2**200)]
    storages = [{0: w, 1: w} for w in (0, 3, 4, 2**256 - 1)]
    src, ctx = _run_both(c, calls, storages)
    assert ctx.folded.get(k1) == "status" and "Enum4 public status;" in src
    # (the struct is named after its only variable by the naming pass)
    assert ctx.folded.get(k2) == "positions" and "mapping(uint256 => Position) public positions;" in src


def test_a_getter_returning_the_raw_byte_of_a_bool_is_not_folded():
    """solc's bool getter returns 0 / 1; a function returning the byte as it
    is stored differs on a dirty byte."""
    c = Case()
    k_bool = c.named("flag()", [ret(iszero(iszero(field(0, 0, 8))))], mutability="view")
    k_raw = c.named("rawFlag()", [ret(field(0, 0, 8))], mutability="view")
    src, ctx = c.build("full")
    assert ctx.folded.get(k_bool) == "flag" and k_raw not in ctx.folded


def test_folded_names_never_shadow_a_parameter():
    from scobelix.solgen.types import parse_type

    c = Case()
    k = c.named("owner()", [ret(field(0, 0, 160))], mutability="view")
    # a function kept as such has a parameter named `owner`: the variable
    # cannot take that name (the parameter would shadow it in that function)
    k2 = c.named("allowed(address,address)", [ret(ir.Sload(mapkey(cd(1), 1)))], ("address", "address"), "view")
    c.entries[k2][1].params = ((parse_type("address"), "owner"), (parse_type("address"), "spender"))
    src, ctx = c.build("full")
    assert k not in ctx.folded and "address internal _owner;" in src


def test_disabled_getters_keep_the_function():
    c = Case()
    k = c.named("total()", [ret(ir.Sload(ir.Const(0)))], mutability="view")
    c.named("setTotal(uint256)", checked(1, [ir.Sstore(ir.Const(0), cd(0)), ir.Stop()]), ("uint256",))
    c.build("full")
    off = Case()
    off.entries = dict(c.entries)
    specs = {key: s for key, (_, s) in off.entries.items()}
    from scobelix.solgen import pipeline

    ctx = pipeline.PassContext(specs=specs, metadata=None, dispatcher=None, target_solc="0.8.19", abi_v2=True,
                               idiom_level="full", functions={key: f for key, (f, _) in off.entries.items()},
                               disabled_passes={k: {"getters"}})
    passes = pipeline.available_passes("full")
    pipeline.prepare(passes, ctx)
    for key, fn in ctx.functions.items():
        pipeline.run_passes(fn, passes, ctx)
    pipeline.finish(passes, ctx)
    assert k not in ctx.folded and any("uint256 internal _total;" in d for d in ctx.declarations["state"])


def _unless(cond, body):
    """`if (cond) revert(); body`, as the lifter nests it."""
    return [ir.If(cond, (ir.Revert(),), tuple(body))]


def test_getter_signatures_with_extra_checks_are_not_folded():
    """Functions with a getter's signature and body plus one more check (a
    constant, another parameter, another variable): random samples rarely
    hit the check, the values the conditions compare with and equal words
    do, and a branch no sample flips keeps the function."""
    from test_storage_passes import address_validator

    def eq(a, b):
        return ir.Op("eq", (a, b))

    minus = ir.Const(ir.WORD_MAX)
    c = Case()
    # require(_cap != 1000), in the engine's `x + (-1) * c` form
    is_1000 = iszero(ir.Op("add", (ir.Const(1000), ir.Op("mul", (minus, ir.Sload(ir.Const(0)))))))
    k_cap = c.named("cap()", _unless(is_1000, [ret(ir.Sload(ir.Const(0)))]), mutability="view")
    # require(a != 0xdead)
    k_bal = c.named("balances(address)", checked(
        1, _unless(eq(cd(0), ir.Const(0xDEAD)), [ret(ir.Sload(mapkey(cd(0), 1)))]), (address_validator(0),)),
        ("address",), "view")
    # require(a != b)
    k_allow = c.named("allowance(address,address)", checked(2, _unless(
        eq(cd(0), cd(1)), [ret(ir.Sload(ir.Keccak(ir.Blob((ir.WordBytes(cd(1)), ir.WordBytes(mapkey(cd(0), 2)))))))]),
        (address_validator(0), address_validator(1))), ("address", "address"), "view")
    # require(a != owner)
    k_dep = c.named("deposits(address)", checked(
        1, _unless(eq(cd(0), field(3, 0, 160)), [ret(ir.Sload(mapkey(cd(0), 4)))]), (address_validator(0),)),
        ("address",), "view")
    # require(_floor != _cap)
    k_floor = c.named("floor()", _unless(eq(ir.Sload(ir.Const(5)), ir.Sload(ir.Const(0))),
                                         [ret(ir.Sload(ir.Const(5)))]), mutability="view")
    # if (_rate == 77) revert(), _rate a uint64 after another uint64
    k_rate = c.named("rate()", _unless(eq(field(7, 64, 64), ir.Const(77)), [ret(field(7, 64, 64))]), mutability="view")
    c.named("other()", [ret(field(7, 0, 64))], mutability="view")
    k_price = c.named("price()", [ret(ir.Sload(ir.Const(8)))], mutability="view")
    src, ctx = c.build("full")
    for k in (k_cap, k_bal, k_allow, k_dep, k_floor, k_rate):
        assert k not in ctx.folded, (k, src)
    assert ctx.folded.get(k_price) == "price"


def test_accessors_with_a_check_of_their_own_are_not_folded():
    """ERC-721's `balanceOf(owner)` checks `owner != address(0)` before the
    mapping read: a one-sided test of the calldata is exempt only as the
    decoder's own check (an empty revert, not an Error(string)), and a test
    against zero (`iszero`, no constant in it) is sampled with zero."""
    from test_storage_passes import address_validator

    c = Case()
    owner_is_zero = iszero(cd(0))
    k_msg = c.named("balanceOf(address)", checked(1, [ir.If(owner_is_zero, (ir.Revert(ir.ErrorString(b"zero address")),),
                                                            (ret(ir.Sload(mapkey(cd(0), 1))),))],
                                                  (address_validator(0),)), ("address",), "view")
    k_empty = c.named("credits(address)", checked(1, _unless(owner_is_zero, [ret(ir.Sload(mapkey(cd(0), 2)))]),
                                                  (address_validator(0),)), ("address",), "view")
    k_plain = c.named("debts(address)", checked(1, [ret(ir.Sload(mapkey(cd(0), 3)))], (address_validator(0),)),
                      ("address",), "view")
    src, ctx = c.build("full")
    assert k_msg not in ctx.folded and k_empty not in ctx.folded, src
    assert ctx.folded.get(k_plain) == "debts"


GUARDED = """
contract Guarded {
    mapping(address => uint256) private _balances;
    mapping(address => uint256) private _plain;

    function balanceOf(address owner) external view returns (uint256) {
        require(owner != address(0), "zero address");
        return _balances[owner];
    }
    function plain(address a) external view returns (uint256) { return _plain[a]; }
    function set(address a, uint256 v) external { _balances[a] = v; _plain[a] = v; }
}
"""


def test_a_guarded_accessor_compiled_stays_a_function(monkeypatch):
    from probes import Build, calldata_cases, compile_probe, differential, generate_probe, patch_signatures

    art = compile_probe(GUARDED, Build("0.8.19"), "Guarded")
    patch_signatures(monkeypatch, art.abi)
    r = generate_probe(art.runtime)
    assert "function balanceOf(address owner) external view" in r.solidity, r.solidity
    assert "mapping(address => uint256) public plain;" in r.solidity
    calls = [(c, 0) for s in ("balanceOf(address)", "plain(address)") for c in calldata_cases(s)]
    assert not differential(art.runtime, r.solidity, r.target_solc, calls)


def test_array_getters_with_their_bound_check_still_fold():
    """The bounds check of a generated array getter is flipped by small
    lengths: covered, folded."""
    data = int.from_bytes(keccak((0).to_bytes(32, "big")), "big")
    bound = iszero(ir.Op("lt", (cd(0), ir.Sload(ir.Const(0)))))
    c = Case()
    elem = ir.Sload(ir.Op("add", (ir.Const(data), cd(0))))
    k = c.named("values(uint256)", checked(1, _unless(bound, [ret(elem)])), ("uint256",), "view")
    c.named("push(uint256)", checked(1, [ir.Sstore(ir.Const(0), ir.Op("add", (ir.ONE, ir.Sload(ir.Const(0))))),
                                         ir.Sstore(ir.Op("add", (ir.Const(data), ir.Sload(ir.Const(0)))), cd(0)),
                                         ir.Stop()]), ("uint256",))
    src, ctx = c.build("full")
    assert ctx.folded.get(k) == "values" and "uint256[] public values;" in src

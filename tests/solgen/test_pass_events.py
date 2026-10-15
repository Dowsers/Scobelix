"""
The events pass: differential tests on real compiler builds.  Probes emit
every shape of log (no data, one word, indexed and not, small and signed
types, constant and calldata strings, an indexed string, anonymous events,
LOG0, an ERC-20 and an ERC-721 `Transfer` with the same topic0, an event
the signature database does not know); the original and the generated text
must log the same topics and data in the same order on every crafted input,
and every other observable must agree.
"""

from __future__ import annotations

import pytest

import callprobe as cp
from probes import Build, calldata_cases, function_text
from scobelix.solgen import ir
from scobelix.solgen.pipeline import PASS_ORDER

PROBE = """
contract EventProbe {
    event E0();
    event E1(uint256 a);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Three(address indexed a, uint256 indexed b, bytes32 indexed c, uint256 d, address e);
    event Small(uint8 a, int16 b, bool c, address d, bytes4 e);
    event Str(string s);
    event IdxStr(string indexed s, uint256 v);
    event Anon(uint256 indexed a, uint256 indexed b, uint256 indexed c, uint256 d) anonymous;
    event AnonData(uint256 x) anonymous;
    event Hidden(uint256 a, address indexed b, uint256 c);

    uint256 public total;

    function e0() external { emit E0(); }
    function e1(uint256 a) external { emit E1(a); }
    function tr(address to, uint256 v) external { emit Transfer(msg.sender, to, v); }
    function trStored(uint256 v) external { total += v; emit Transfer(address(this), msg.sender, total); }
    function three(uint256 b, bytes32 c, uint256 d) external { emit Three(msg.sender, b, c, d, address(this)); }
    function small(uint8 a, int16 b, bool c, bytes4 e) external { emit Small(a, b, c, msg.sender, e); }
    function str(string calldata s) external { emit Str(s); }
    function strConst() external { emit Str("hello world, this is a long string literal over 32 bytes"); }
    function idxStr(string calldata s, uint256 v) external { emit IdxStr(s, v); }
    function anon(uint256 a, uint256 b, uint256 c, uint256 d) external { emit Anon(a, b, c, d); }
    function anonData(uint256 x) external { emit AnonData(x); }
    function hidden(uint256 a, address b) external { emit Hidden(a, b, a + 1); emit E1(a); }
    function twice(address to, uint256 v) external { emit E1(v); emit Transfer(to, msg.sender, v); emit E0(); }
}

contract NftProbe {
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    function move(address to, uint256 id) external { emit Transfer(msg.sender, to, id); }
}
"""

SIGNATURES = ["e0()", "e1(uint256)", "tr(address,uint256)", "trStored(uint256)", "three(uint256,bytes32,uint256)",
              "small(uint8,int16,bool,bytes4)", "str(string)", "strConst()", "idxStr(string,uint256)",
              "anon(uint256,uint256,uint256,uint256)", "anonData(uint256)", "hidden(uint256,address)",
              "twice(address,uint256)"]


def source(build: Build) -> str:
    return PROBE


def known_abis(comp):
    """The ABIs the signature lookups answer with: every event but Hidden."""
    out = []
    for a in comp.artifacts.values():
        out.append([x for x in a.abi if not (x.get("type") == "event" and x.get("name") == "Hidden")])
    return out


def run_probe(build: Build, monkeypatch, off=()):
    comp = cp.compile_all(source(build), build)
    cp.patch_lookups(monkeypatch, known_abis(comp))
    results, diffs = {}, []
    for contract, sigs in (("EventProbe", SIGNATURES), ("NftProbe", ["move(address,uint256)"])):
        art = comp.artifact(contract)
        result = cp.generate(art.runtime, off)
        results[contract] = result
        calls = [(c, 0) for s in sigs for c in calldata_cases(s)]
        diffs += cp.differential(art.runtime, result.solidity, result.target_solc, calls, ("true",))
    return results, diffs


def _show(diffs):
    return "\n".join(f"{d[0][:72]}\n  original {str(d[3])[:300]}\n  text     {str(d[4])[:300]}" for d in diffs[:4])


def test_events_0819_opt(monkeypatch):
    results, diffs = run_probe(Build("0.8.19"), monkeypatch)
    assert not diffs, _show(diffs)
    text = results["EventProbe"].solidity
    for snippet in ("event Transfer(address indexed from, address indexed to, uint256 value);",
                    "emit Transfer(msg.sender, to, v);", "emit E0();", "emit E1(a);",
                    "emit Three(msg.sender, b, c, d, address(this));", "emit Small(a, b, c, msg.sender, e);",
                    'emit Str("hello world, this is a long string literal over 32 bytes");',
                    "emit IdxStr(s, v);", "event Log3(uint256 indexed topic0, uint256 indexed topic1, "
                    "uint256 indexed topic2, uint256 data0) anonymous;", "emit Log3(a, b, c, d);", "emit Log0(x);"):
        assert snippet in text, snippet
    # an event the database does not name: the anonymous form, flagged
    hidden = function_text(text, "hidden")
    assert "emit Log_" in hidden and "emit E1(a);" in hidden
    entry = next(f for f in results["EventProbe"].functions.values() if f.get("signature") == "hidden(uint256,address)")
    assert "anonymous_event_form" in entry["flags"]
    # a calldata string: its tail has a symbolic length, solc's zero padding is read back from memory
    assert "emit Str(s);" in function_text(text, "str")
    nft = results["NftProbe"].solidity
    assert "event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);" in nft
    assert "emit Transfer(msg.sender, to, id);" in nft


@pytest.mark.slow
def test_events_pass_alone_and_switched_off(monkeypatch):
    others = [p for p in PASS_ORDER if p != "events"]
    results, diffs = run_probe(Build("0.8.19"), monkeypatch, off=others)
    assert not diffs, _show(diffs)
    assert "emit Transfer(" in results["EventProbe"].solidity
    results, diffs = run_probe(Build("0.8.19"), monkeypatch, off=["events"])
    assert not diffs, _show(diffs)
    assert "emit " not in results["EventProbe"].solidity


@pytest.mark.slow
@pytest.mark.parametrize("build", [Build("0.8.19", optimize=False), Build("0.8.19", via_ir=True),
                                   Build("0.8.31", via_ir=True), Build("0.7.6"), Build("0.5.17")],
                         ids=lambda b: b.label)
def test_events_other_builds(build, monkeypatch):
    results, diffs = run_probe(build, monkeypatch)
    assert not diffs, _show(diffs)
    assert "emit Transfer(" in results["EventProbe"].solidity


# ---------------------------------------------------------------- candidates without a build


class _Sig:
    def __init__(self, name, inputs, indexed=(), declared=True):
        self.name = name
        self.inputs = inputs
        self.types = tuple(t for t, _ in inputs)
        self.signature = f"{name}({','.join(self.types)})"
        self.indexed = indexed
        self.declared = declared
        self.anonymous = False


def _run(log: ir.Log, candidates, abi_v2=True):
    from scobelix.solgen import pipeline
    from scobelix.solgen.passes import events

    class _Sigs:
        @staticmethod
        def event_candidates(topic0, n=None):
            # (as the database: with n, the events indexing n parameters, and
            # the signatures without flags that have enough of them)
            return tuple(c for c in candidates if n is None or (sum(c.indexed) == n if c.declared
                                                                 else len(c.inputs) >= n))

    ctx = pipeline.PassContext(specs={}, metadata=None, dispatcher=None, target_solc="0.8.19", abi_v2=abi_v2,
                               idiom_level="full", sigs=_Sigs)
    fn = events.run(ir.Function("0x12345678", (log, ir.Stop())), ctx)
    events.finish(ctx)
    return fn, ctx.declarations.get("event", [])


T0 = 0xDDF252AD1BE2C89B69C2B068FC378DAA952BA7F163C4A11628F55A4DF523B3EF
CALLER, ADDR = ir.Env("caller"), ir.Env("address")


def test_ties_between_candidates_stay_exact():
    """Two readings of the same log (the indexed flags of two candidates
    put different values in the topics, both valid): none is taken."""
    log = ir.Log((ir.Const(T0), CALLER, ADDR), ir.WordBytes(ir.Const(5)))
    a = _Sig("Transfer", (("address", "from"), ("address", "to"), ("uint256", "value")), (True, True, False))
    b = _Sig("Transfer", (("address", "from"), ("uint256", "value"), ("address", "to")), (True, False, True))
    fn, decls = _run(log, [a, b])
    assert fn.body[0] == log and decls == []  # the exact helper call stays
    fn, decls = _run(log, [a])
    assert fn.body[0] == ir.Emit("Transfer", (CALLER, ADDR, ir.Const(5)), ("address", "address", "uint256"))


def test_a_candidate_without_indexed_flags_needs_one_placement():
    """A signature of another namespace that hashes to the topic: the
    placement of the indexed parameters that decodes the log, when it is
    the only one."""
    log = ir.Log((ir.Const(T0), CALLER, ADDR), ir.WordBytes(ir.Const(1 << 200)))
    untyped = _Sig("Transfer", (("address", ""), ("address", ""), ("uint256", "")), declared=False)
    fn, decls = _run(log, [untyped])
    assert fn.body[0] == ir.Emit("Transfer", (CALLER, ADDR, ir.Const(1 << 200)), ("address", "address", "uint256"))
    assert decls == ["event Transfer(address indexed, address indexed, uint256);"]
    # a word that is not a valid address cannot be the indexed address
    log = ir.Log((ir.Const(T0), ir.Const(1 << 200), ADDR), ir.WordBytes(CALLER))
    fn, decls = _run(log, [untyped])
    assert not isinstance(fn.body[0], ir.Emit) or fn.body[0].event.startswith("Log_")


def test_the_log_decides_the_indexed_flags_the_database_does_not_have():
    """The database knows the event with other indexed flags only: topic0
    hashes the types, so the flags are the one placement that decodes the
    log (the amount, a raw word, cannot be the indexed address)."""
    t0 = 0xD27F8A4F74D44C579D31D4BE927B4594935F2EC5FD875F9BE0B20350A3DBCC29
    action = _Sig("Action", (("address", "user"), ("uint256", "amount")), (False, False))
    log = ir.Log((ir.Const(t0), CALLER), ir.WordBytes(ir.CalldataWord(ir.Const(4))))
    fn, decls = _run(log, [action])
    assert fn.body[0] == ir.Emit("Action", (CALLER, ir.CalldataWord(ir.Const(4))), ("address", "uint256"))
    assert decls == ["event Action(address indexed user, uint256 amount);"]
    # both placements decode a log of two addresses: never a guess
    log = ir.Log((ir.Const(t0), CALLER), ir.WordBytes(ADDR))
    fn, decls = _run(log, [action])
    assert fn.body[0] == log and decls == []


def test_words_that_do_not_fit_the_types_stay_exact():
    log = ir.Log((ir.Const(T0), ir.Param(0), ADDR), ir.WordBytes(ir.Const(5)))  # a raw word as an address
    a = _Sig("Transfer", (("address", "from"), ("address", "to"), ("uint256", "value")), (True, True, False))
    fn, decls = _run(log, [a], abi_v2=False)
    assert fn.body[0].event.startswith("Log_")  # (no candidate decodes it: the anonymous form)
    # the comment of the declaration names the signature the log does not fit
    # (it does not say the database does not know the topic)
    assert len(decls) == 1 and "Transfer(address,address,uint256)" in decls[0], decls
    assert "does not name" not in decls[0]
    fn, decls = _run(log, [])
    assert "does not name" in decls[0] and "Transfer(" not in decls[0]


# ---------------------------------------------------------------- locals that cache a value


OWNED = """
contract Owned {
    address public owner;
    address public pending;
    address public treasury;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event TreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);
    event Moved(address from, uint256 amount);

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "not owner");
        address old = owner;
        owner = newOwner;
        emit OwnershipTransferred(old, newOwner);
    }
    function setTreasury(address t) external {
        address prev = treasury;
        treasury = t;
        emit TreasuryUpdated(prev, t);
    }
    function acceptOwnership() external {
        require(msg.sender == pending);
        address old = owner;
        owner = pending;
        pending = address(0);
        emit OwnershipTransferred(old, owner);
    }
    function move(uint256 amount) external {
        address prev = treasury;
        treasury = msg.sender;
        emit Moved(prev, amount);
    }
}
"""

OWNED_SIGNATURES = ["transferOwnership(address)", "setTreasury(address)", "acceptOwnership()", "move(uint256)"]


@pytest.mark.parametrize("build", [Build("0.8.19"), pytest.param(Build("0.8.19", optimize=False), marks=pytest.mark.slow)],
                         ids=lambda b: b.label)
def test_events_of_values_cached_in_locals(build, monkeypatch):
    """An address read into a local before the variable is written (the
    previous owner) is the topic: the local holds a cleaned address on every
    assignment, so the log is the named event."""
    comp = cp.compile_all(OWNED, build)
    cp.patch_lookups(monkeypatch, [a.abi for a in comp.artifacts.values()])
    art = comp.artifact("Owned")
    result = cp.generate(art.runtime)
    who = int(cp.CALLER, 16)
    calls = [(c, 0) for s in OWNED_SIGNATURES for c in calldata_cases(s)]
    for storage in (None, {0: who, 1: who, 2: 0xBEEF}):
        diffs = cp.differential(art.runtime, result.solidity, result.target_solc, calls, ("true",), storage)
        assert not diffs, _show(diffs)
    text = result.solidity
    assert "Log_" not in text, text
    assert "emit OwnershipTransferred(" in function_text(text, "transferOwnership")
    assert "emit OwnershipTransferred(" in function_text(text, "acceptOwnership")
    assert "emit TreasuryUpdated(" in function_text(text, "setTreasury")
    assert "emit Moved(" in function_text(text, "move")
    assert not any("anonymous_event_form" in f["flags"] for f in result.functions.values())


# ---------------------------------------------------------------- dynamic data


DYNAMIC = """
contract DynamicEvents {
    event Str(string s);
    event ActionProposed(bytes32 indexed id, string description);
    event Both(uint256 a, bytes b, address c);
    event Two(string a, string b);
    event Note(address indexed who, string text);
    event Secret(string text, uint256 v);
    string constant MSG = "a constant message longer than thirty-two bytes";
    string public stored;

    function str(string calldata s) external { emit Str(s); }
    function strMem(string memory s) external { emit Str(s); }
    function set(string calldata s) external { stored = s; }
    function storeRead() external { emit Str(stored); }
    function propose(bytes32 id, string calldata d) external { emit ActionProposed(id, d); }
    function both(uint256 a, bytes calldata b) external { emit Both(a, b, msg.sender); }
    function two(string calldata a, string calldata b) external { emit Two(a, b); }
    function announce() external { emit Str(MSG); }
    function note(string calldata t) external { emit Note(msg.sender, t); }
    function secret(string calldata t, uint256 v) external { emit Secret(t, v); }
}
"""

DYNAMIC_SIGNATURES = ["str(string)", "strMem(string)", "set(string)", "storeRead()", "propose(bytes32,string)",
                      "both(uint256,bytes)", "two(string,string)", "announce()", "note(string)",
                      "secret(string,uint256)"]


def run_dynamic(build: Build, monkeypatch):
    comp = cp.compile_all(DYNAMIC, build)
    abis = [[x for x in a.abi if not (x.get("type") == "event" and x.get("name") == "Secret")]
            for a in comp.artifacts.values()]
    cp.patch_lookups(monkeypatch, abis)
    art = comp.artifact("DynamicEvents")
    result = cp.generate(art.runtime)
    calls = [(c, 0) for s in DYNAMIC_SIGNATURES for c in calldata_cases(s)]
    diffs = cp.differential(art.runtime, result.solidity, result.target_solc, calls, ("true",))
    return result, diffs


@pytest.mark.parametrize("build", [Build("0.8.19"),
                                   pytest.param(Build("0.8.19", optimize=False), marks=pytest.mark.slow),
                                   pytest.param(Build("0.8.31", optimize=False), marks=pytest.mark.slow),
                                   pytest.param(Build("0.8.19", via_ir=True), marks=pytest.mark.slow)],
                         ids=lambda b: b.label)
def test_events_with_dynamic_data(build, monkeypatch):
    """Strings and byte strings in the data: the zero padding solc writes
    after the bytes (read back from memory) and the tails of symbolic
    length decode as the event's arguments; an event the database does
    not name gets the anonymous form with a `bytes` parameter."""
    result, diffs = run_dynamic(build, monkeypatch)
    assert not diffs, _show(diffs)
    text = result.solidity
    for name, snippet in (("str", "emit Str(s);"), ("propose", "emit ActionProposed("),
                          ("note", "emit Note(msg.sender, ")):
        body = function_text(text, name)
        assert snippet in body and "_log" not in body, body
    secret = function_text(text, "secret")
    assert "emit Log_" in secret and "_log" not in secret.replace("emit Log_", ""), secret


STR_TOPIC = 0xECC6E546C902CB34B0AC849D3311A9758A2D7C29E8CDBCCF71FD8E66E047F98B  # Str(string)


def _string_log(start_const=192, pad=None):
    """The log of `emit Str(s)` for a calldata string s (head word 0), as
    solc 0.8 writes it: the bytes, then its padding read back from memory
    where the cleanup word was stored."""
    n = ir.CalldataWord(ir.Op("add", (ir.Const(4), ir.Param(0))))
    payload = ir.CalldataSlice(ir.Op("add", (ir.Const(36), ir.Param(0))), n)
    at = ir.Op("add", (ir.Const(start_const), n))
    if pad is None:
        pad = ir.Op("add", (ir.Mask(251, 5, 0, ir.Op("add", (ir.Const(31), n))), ir.Op("mul", (ir.Const(ir.WORD_MOD - 1), n))))
    data = ir.Blob((ir.WordBytes(ir.Const(32)), ir.WordBytes(n), payload, ir.MemSlice(at, pad)))
    return ir.Log((ir.Const(STR_TOPIC),), data), payload, at


def test_zero_padding_read_back_from_memory():
    """The padding is zero when the last memory write before the log is a
    zero word at its start (statements that do not write memory between)."""
    sig = _Sig("Str", (("string", "s"),), (False,))
    log, payload, at = _string_log()
    zero = ir.Mstore(at, ir.WordBytes(ir.ZERO))
    emit = ir.Emit("Str", (payload,), ("string",))
    assert _run_body([zero, log], [sig]).body[1] == emit
    assert _run_body([zero, ir.Sstore(ir.Const(1), ir.Const(2)), log], [sig]).body[2] == emit
    # in a branch, the statements before the `if` count too
    fn = _run_body([zero, ir.If(ir.Env("callvalue"), (log,))], [sig])
    assert fn.body[1].then[0] == emit
    # another memory write after it, a zero word elsewhere, no write, a loop: the exact log stays
    other = ir.Mstore(ir.Const(64), ir.WordBytes(ir.Const(7)))
    assert _run_body([zero, other, log], [sig]).body[2] == log
    elsewhere = ir.Mstore(ir.Op("add", (ir.Const(224), payload.length)), ir.WordBytes(ir.ZERO))
    assert _run_body([elsewhere, log], [sig]).body[1] == log
    assert _run_body([log], [sig]).body[0] == log
    loop = ir.While(ir.Env("callvalue"), (log, ir.Continue("L")), (), "L")
    assert _run_body([zero, loop], [sig]).body[1].body[0] == log
    # a slice that may be longer than a word is not padding
    log32, _, at32 = _string_log(pad=ir.Op("add", (ir.Const(32), ir.Mask(251, 5, 0, ir.Op("add", (ir.Const(31), payload.length))))))
    assert _run_body([ir.Mstore(at32, ir.WordBytes(ir.ZERO)), log32], [sig]).body[1] == log32


def test_a_slice_that_ends_in_the_zero_word():
    """A memory string copied word by word (no optimiser): the slice runs to
    the length rounded up to words, the cleanup word stored after the copy
    zeroes its last bytes, and a padding of provably zero length follows."""
    sig = _Sig("Str", (("string", "s"),), (False,))
    n = ir.MLoad(ir.Const(128))
    start = ir.Op("add", (ir.Const(288), n))
    ceil = ir.Mask(251, 5, 0, ir.Op("add", (ir.Const(31), n)))
    data = ir.Blob((ir.WordBytes(ir.Const(32)), ir.WordBytes(n), ir.MemSlice(start, ceil),
                    ir.ZeroBytes(ir.Op("and", (ir.Op("sub", (ir.ZERO, ceil)), ir.Const(31))))))
    log = ir.Log((ir.Const(STR_TOPIC),), data)
    zero = ir.Mstore(ir.Op("add", (ir.Const(288), ir.Op("shl", (ir.Const(1), n)))), ir.WordBytes(ir.ZERO))
    fn = _run_body([zero, log], [sig])
    assert fn.body[1] == ir.Emit("Str", (ir.MemSlice(start, n),), ("string",))
    # the zero word elsewhere in the slice (more than 31 bytes before its end): no
    early = ir.Mstore(ir.Op("add", (ir.Const(256), ir.Op("shl", (ir.Const(1), n)))), ir.WordBytes(ir.ZERO))
    assert _run_body([early, log], [sig]).body[1] == log


def test_tails_of_symbolic_length_decode():
    """Two strings: the second offset word is the head plus the first tail
    (32 + L + padding), whatever form the padding's length has."""
    from scobelix.solgen.passes.reverts import decode_arguments
    from scobelix.solgen.types import parse_type

    s = parse_type("string")
    n0 = ir.CalldataWord(ir.Op("add", (ir.Const(4), ir.Param(0))))
    n1 = ir.CalldataWord(ir.Op("add", (ir.Const(4), ir.Param(1))))
    a = ir.CalldataSlice(ir.Op("add", (ir.Const(36), ir.Param(0))), n0)
    b = ir.CalldataSlice(ir.Op("add", (ir.Const(36), ir.Param(1))), n1)
    ceil0 = ir.Mask(251, 5, 0, ir.Op("add", (ir.Const(31), n0)))
    lifter_pad = ir.ZeroBytes(ir.Op("and", (ir.Op("sub", (ir.ZERO, n0)), ir.Const(31))))
    solc_pad = ir.ZeroBytes(ir.Op("add", (ceil0, ir.Op("mul", (ir.Const(ir.WORD_MOD - 1), n0)))))
    pad1 = ir.ZeroBytes(ir.Op("and", (ir.Op("sub", (ir.ZERO, n1)), ir.Const(31))))
    for pad0 in (lifter_pad, solc_pad):
        parts = (ir.WordBytes(ir.Const(64)), ir.WordBytes(ir.Op("add", (ir.Const(96), ceil0))),
                 ir.WordBytes(n0), a, pad0, ir.WordBytes(n1), b, pad1)
        assert decode_arguments([s, s], parts, {}) == [a, b]
        # a wrong second offset, a missing padding, bytes after the last tail: no
        bad = (ir.WordBytes(ir.Const(64)), ir.WordBytes(ir.Op("add", (ir.Const(64), ceil0)))) + parts[2:]
        assert decode_arguments([s, s], bad, {}) is None
        assert decode_arguments([s, s], parts[:4] + parts[5:], {}) is None
        assert decode_arguments([s, s], parts + (ir.WordBytes(ir.ZERO),), {}) is None


def test_dynamic_data_of_an_unknown_event_is_the_anonymous_form():
    log, payload, at = _string_log()
    fn = _run_body([ir.Mstore(at, ir.WordBytes(ir.ZERO)), log], [])
    emit = fn.body[1]
    assert emit.event == f"Log_{STR_TOPIC >> 224:08x}" and emit.args == (ir.Const(STR_TOPIC), payload)
    assert emit.types == ("bytes32", "bytes") and "anonymous_event_form" in fn.flags


def _run_body(stmts, candidates):
    from scobelix.solgen import pipeline
    from scobelix.solgen.passes import events

    class _Sigs:
        @staticmethod
        def event_candidates(topic0, n=None):
            return tuple(c for c in candidates if n is None or sum(c.indexed) == n)

    ctx = pipeline.PassContext(specs={}, metadata=None, dispatcher=None, target_solc="0.8.19", abi_v2=True,
                               idiom_level="full", sigs=_Sigs)
    return events.run(ir.Function("0x12345678", tuple(stmts) + (ir.Stop(),)), ctx)


OWNERSHIP = 0x8BE0079C531659141344CD1FD0A4F28419497F9722A3DAAFE3B4186F6B6457E0


def test_a_local_is_a_valid_word_when_every_assignment_is():
    sig = _Sig("OwnershipTransferred", (("address", "previousOwner"), ("address", "newOwner")), (True, True))
    old, other = ir.Local("_owner"), ir.Local("_other")
    clean = ir.Op("and", (ir.Sload(ir.Const(0)), ir.Const((1 << 160) - 1)))
    log = ir.Log((ir.Const(OWNERSHIP), old, CALLER))
    # one assignment of a cleaned address
    fn = _run_body([ir.Assign(old, clean), log], [sig])
    assert fn.body[1] == ir.Emit("OwnershipTransferred", (old, CALLER), ("address", "address"))
    # every assignment (in a loop init, a branch, a back edge) is a valid address
    loop = ir.While(ir.Const(1), (ir.Continue("L", (ir.Assign(old, ADDR),)),), (ir.Assign(old, clean),), "L")
    fn = _run_body([loop, ir.If(ir.Env("callvalue"), (ir.Assign(old, CALLER),)), log], [sig])
    assert isinstance(fn.body[2], ir.Emit) and fn.body[2].event == "OwnershipTransferred"
    # through another local that holds valid values only
    fn = _run_body([ir.Assign(other, clean), ir.Assign(old, other), log], [sig])
    assert fn.body[2].event == "OwnershipTransferred"
    # one assignment that is not provably an address: no
    fn = _run_body([ir.Assign(old, clean), ir.Assign(old, ir.Sload(ir.Const(1))), log], [sig])
    assert fn.body[2].event.startswith("Log_")
    # a compound assignment, a cycle of locals, a local never assigned: no
    fn = _run_body([ir.Assign(old, clean), ir.Assign(old, ir.Const(1), op="+"), log], [sig])
    assert fn.body[2].event.startswith("Log_")
    fn = _run_body([ir.Assign(other, old), ir.Assign(old, other), log], [sig])
    assert fn.body[2].event.startswith("Log_")
    fn = _run_body([log], [sig])
    assert fn.body[0].event.startswith("Log_")

"""
getters pass: entry points that behave exactly like a getter solc generates
become declarations, and are not written out.

  * `T public name`: a named function (keccak-
    verified signature, view, not payable) is folded into the state
    variable it reads when
      - the getter of that variable has the same signature: keccak of
        name(K1, ..., Kn) with the variable's key types and uint256 for the
        array indices equals the selector (key types of the layout may be
        refined to the signature's parameter types: the check below
        decides);
      - executing the function and solc's getter on the same valid
        calldata and storage gives the same outcome for every sample:
        the cleaned value of the variable's type (an enum out of range:
        Panic 0x21; a struct: its value members in order), a plain revert
        past the end of an array (the generated getter's bounds check; an
        explicit function's Panic 0x32 differs).  Samples combine random
        and small storage words (so that array bounds are crossed) with
        random valid parameters, parameters equal to each other and to the
        stored words, and the values the body's conditions compare with
        (in the parameters, and in storage at the bit offsets the
        conditions read);
      - every branch of the body is taken both ways by some sample, except
        a test of the calldata alone whose other way only reverts with
        empty data (the decoder's own checks, the same on both sides: the
        signature agrees with the validators of the body; a `require` with
        a message is the function's own check).  A condition no sample
        flips is an extra check a getter does not have, or one the samples
        cannot tell: either way the function is kept.  Zero is always one
        of the values sampled (a test `iszero(x)` holds no constant).
    The variable takes the getter's name, unless a parameter or a local of
    a function kept as such has that name.
  * `T public constant NAME = value`: a parameterless view function whose
    every run returns the same constant (public constants, and immutables,
    whose deployed value is in the runtime code).

Folding is decided in prepare (the storage pass names the variables before
any function is rewritten); run() records the fold of each enabled entry
point (`ctx.fold`), finish() declares the constants.  Strings, bytes and
structs with composite members are not folded (their getters copy memory).
"""

from __future__ import annotations

import dataclasses
import random
import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from eth_utils import keccak

from scobelix.solgen import ir, storage
from scobelix.solgen.render import literal, reserved_name
from scobelix.solgen.sigs import function_selector
from scobelix.solgen.types import parse_type

LEVELS = ("full",)

_SLOT = 256
_SAMPLES = 24  # half with random storage words, half with small ones (array bounds crossed)
_EQUAL_SAMPLES = 4  # parameters equal to each other (and storage words equal to them)
_MAX_CONSTANTS = 16  # constants in the conditions (more: no getter)
_MAX_OFFSETS = 8  # bit offsets of the storage reads in conditions (more: no getter)
_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


# ---------------------------------------------------------------- executing a body


class _Unsupported(Exception):
    pass


@dataclasses.dataclass
class _Env:
    calldata: bytes
    storage_word: object  # slot (int) -> word (int)
    locals: Dict[str, int] = dataclasses.field(default_factory=dict)


def _value(e: ir.Expr, env: _Env) -> int:
    """The word e evaluates to (straight-line reads of calldata, storage and
    locals; anything else is unsupported)."""

    def leaf(n):
        if isinstance(n, ir.Sload):
            slot = ir.evaluate(n.slot)
            if slot is None:
                raise _Unsupported("slot")
            return ir.Const(env.storage_word(slot))
        if isinstance(n, ir.Param):
            n = ir.CalldataWord(ir.Const(4 + 32 * n.index))  # (the abi pass names the head words)
        if isinstance(n, ir.CalldataWord):
            off = ir.evaluate(n.offset)
            if off is None:
                raise _Unsupported("calldata offset")
            word = env.calldata[off:off + 32] if off < len(env.calldata) else b""
            return ir.Const(int.from_bytes(word.ljust(32, b"\0"), "big"))
        if isinstance(n, ir.Env):
            if n.name == "calldatasize":
                return ir.Const(len(env.calldata))
            if n.name == "callvalue":
                return ir.ZERO
            raise _Unsupported(n.name)
        if isinstance(n, ir.Local):
            if n.name not in env.locals:
                raise _Unsupported("local")
            return ir.Const(env.locals[n.name])
        if isinstance(n, (ir.MLoad, ir.MemSlice, ir.StateRef, ir.Typed, ir.CallOut, ir.UnstructuredExpr,
                          ir.UnstructuredBytes, ir.ReturnData, ir.Balance, ir.ExtCodeSize, ir.ExtCodeHash,
                          ir.ExtCodeSlice, ir.CodeSlice, ir.TLoad, ir.BlockHash, ir.BlobHash, ir.CalldataSlice)):
            raise _Unsupported(type(n).__name__)
        return n

    v = ir.evaluate(ir.transform(e, leaf))
    if v is None:
        raise _Unsupported("not a closed word")
    return v


def _execute(body: Sequence[ir.Stmt], env: _Env, seen: Optional[Dict[tuple, Set[bool]]] = None,
             at: tuple = ()) -> tuple:
    """The outcome of a body: ("return", words) | ("revert",) | ("panic",
    code) | ("invalid",); _Unsupported for anything else (calls, memory,
    loops, writes...).  `seen` collects the way each branch went, by
    position (`at`: the path of statement indices and branch sides)."""
    for i, s in enumerate(body):
        if isinstance(s, ir.If):
            taken = bool(_value(s.cond, env))
            if seen is not None:
                seen.setdefault(at + (i,), set()).add(taken)
            return _execute(s.then if taken else s.orelse, env, seen, at + (i, taken))
        if isinstance(s, ir.Mstore):
            continue  # memory is never read back (checked by the caller)
        if isinstance(s, ir.Assign) and isinstance(s.target, ir.Local) and s.op is None:
            env.locals[s.target.name] = _value(s.value, env)
            continue
        if isinstance(s, ir.Return):
            words = storage._return_words(s) if s.data is not None or s.values is not None else []
            if words is None:
                raise _Unsupported("return data")
            return ("return", tuple(_value(w, env) for w in words))
        if isinstance(s, ir.Stop):
            return ("return", ())
        if isinstance(s, ir.Revert):
            if isinstance(s.payload, ir.Empty):
                return ("revert",)
            if isinstance(s.payload, ir.Panic):
                return ("panic", s.payload.code)
            raise _Unsupported("revert payload")
        if isinstance(s, ir.Invalid):
            return ("invalid",)
        raise _Unsupported(type(s).__name__)
    raise _Unsupported("falls through")


# ---------------------------------------------------------------- solc's getters


def getter_params(t: tuple) -> Optional[List[str]]:
    """Parameter types of the getter of a variable of type t (None: no
    getter this pass folds)."""
    out: List[str] = []
    while True:
        if t[0] == "map":
            out.append(t[1])
            t = t[2]
        elif t[0] in ("dyn", "fix"):
            out.append("uint256")
            t = t[1]
        elif storage.is_value(t):
            return out
        elif t[0] == "struct":
            return out if all(storage.is_value(m) for _, _, m in t[1]) else None
        else:
            return None


def _clean(t: tuple, raw: int) -> tuple:
    """The getter's return word of a value of type t stored as `raw` (its
    bits, right-aligned): ("ok", word) or a revert outcome."""
    if t[0] == "enum":
        return ("ok", raw) if raw < t[1] else ("panic", 0x21)
    name = "address" if t[0] == "contract" else t[1]
    nb = storage.val_nbytes(t)
    if name == "bool":
        return ("ok", 1 if raw else 0)
    if name.startswith("int"):
        bits = 8 * nb
        return ("ok", (raw - (1 << bits) if raw >> (bits - 1) else raw) % ir.WORD_MOD)
    if name.startswith("bytes"):
        return ("ok", raw << (_SLOT - 8 * nb))
    return ("ok", raw)


def _read(env: _Env, slot: int, byte: int, t: tuple) -> int:
    word = env.storage_word(slot % ir.WORD_MOD)
    return (word >> (8 * byte)) & ((1 << (8 * storage.val_nbytes(t))) - 1)


def _keccak_words(*words: int) -> int:
    return int.from_bytes(keccak(b"".join((w % ir.WORD_MOD).to_bytes(32, "big") for w in words)), "big")


def solc_getter(t: tuple, slot: int, env: _Env, byte: int = 0) -> tuple:
    """What solc's generated getter of a variable of type t at (`slot`,
    `byte`) returns for the calldata of env (valid parameters)."""
    i = 0

    def param() -> int:
        nonlocal i
        off = 4 + 32 * i
        i += 1
        return int.from_bytes(env.calldata[off:off + 32].ljust(32, b"\0"), "big")

    while True:
        if t[0] == "map":
            slot = _keccak_words(param(), slot)
            t = t[2]
        elif t[0] in ("dyn", "fix"):
            idx = param()
            elem = t[1]
            if t[0] == "dyn":
                length, base = env.storage_word(slot % ir.WORD_MOD), _keccak_words(slot)
            else:
                length, base = max(1, t[2] or 1), slot
            if idx >= length:
                return ("revert",)
            if storage.is_value(elem):
                per = 32 // storage.val_nbytes(elem)
                slot, byte = base + idx // per, (idx % per) * storage.val_nbytes(elem)
            else:
                slot = base + idx * storage.nslots(elem)
            t = elem
        elif storage.is_value(t):
            c = _clean(t, _read(env, slot, byte, t))
            return ("return", (c[1],)) if c[0] == "ok" else c
        else:  # struct of value members
            words = []
            for ms, mo, mt in t[1]:
                c = _clean(mt, _read(env, slot + ms, mo, mt))
                if c[0] != "ok":
                    return c
                words.append(c[1])
            return ("return", tuple(words))


# ---------------------------------------------------------------- sampling


def _param_word(rng: random.Random, ty: str, index: bool) -> int:
    if index:
        return rng.choice((0, 1, 2, 3, 5, rng.randrange(1 << 64), ir.WORD_MAX))
    t = parse_type(ty)
    if t.kind == "address":
        return rng.randrange(1 << 160)
    if t.kind == "bool":
        return rng.randrange(2)
    if t.kind == "uint":
        return rng.randrange(1 << t.bits)
    if t.kind == "int":
        return rng.randrange(-(1 << (t.bits - 1)), 1 << (t.bits - 1)) % ir.WORD_MOD
    if t.kind == "bytes":
        return rng.randrange(1 << t.bits) << (_SLOT - t.bits)
    return rng.randrange(ir.WORD_MOD)


def _fit(v: int, ty: str, index: bool) -> int:
    """The valid parameter word of type ty closest to the word v."""
    v %= ir.WORD_MOD
    if index:
        return v
    t = parse_type(ty)
    if t.kind == "address":
        return v & ((1 << 160) - 1)
    if t.kind == "bool":
        return 1 if v else 0
    if t.kind == "uint":
        return v & ((1 << t.bits) - 1)
    if t.kind == "int":
        low = v & ((1 << t.bits) - 1)
        return (low - (1 << t.bits) if low >> (t.bits - 1) else low) % ir.WORD_MOD
    if t.kind == "bytes" and t.bits < _SLOT:
        low_bits = _SLOT - t.bits
        return v if v & ((1 << low_bits) - 1) == 0 else (v & ((1 << t.bits) - 1)) << low_bits
    return v


def _triggers(fn: ir.Function) -> Optional[Tuple[List[int], List[int]]]:
    """(values, bit offsets) that may flip a test of the body (a branch
    condition, a ternary's, a comparison): the constants it compares with,
    negated (`x + (-c) == 0` tests x == c) and with their neighbours
    (x < c, x <= c); the bit offsets of the storage reads in it.  Constants
    of slot expressions are locations, not compared values.  None when
    there are too many (no getter has them)."""
    consts: Set[int] = set()
    offsets: Set[int] = {0}
    tests = [n.cond for n in ir.walk_all(fn.body) if isinstance(n, (ir.If, ir.Ternary))]
    tests += [n for n in ir.walk_all(fn.body) if isinstance(n, ir.Op) and n.op in ir.COMPARISONS]
    stack = list(tests)
    while stack:
        n = stack.pop()
        if isinstance(n, ir.Const):
            consts.add(n.value)
        if isinstance(n, (ir.Field, ir.Mask)) and isinstance(n.value, ir.Sload):
            off = ir.field_bits(n.offset) if isinstance(n, ir.Field) else storage._int_field(n.offset)
            if off is not None and 0 <= off < _SLOT:
                offsets.add(off)
        if not isinstance(n, (ir.Sload, ir.Keccak)):
            stack.extend(ir.children(n))
    if len(consts) > _MAX_CONSTANTS or len(offsets) > _MAX_OFFSETS:
        return None
    consts.add(0)  # (`iszero(x)` tests x == 0 with no constant in it: `require(owner != address(0))`)
    values = {(v + d) % ir.WORD_MOD for c in consts for v in (c, -c) for d in (-1, 0, 1)}
    return sorted(values), sorted(offsets)


def _samples(params: Sequence[str], indices: Sequence[bool], seed: str,
             triggers: Sequence[int] = (), offsets: Sequence[int] = (0,)) -> List[_Env]:
    rng = random.Random(seed)
    out = []

    def env(words, word):
        return _Env(bytes(4) + b"".join(w.to_bytes(32, "big") for w in words), word)

    def random_storage(small):
        salt = rng.randrange(1 << 64)

        def word(slot, salt=salt, small=small):
            h = int.from_bytes(keccak(salt.to_bytes(8, "big") + slot.to_bytes(32, "big")), "big")
            return h % 6 if small else h

        return word

    def fixed_storage(w):
        return lambda slot: w

    def fitted(v):
        return [_fit(v, ty, ix) for ty, ix in zip(params, indices)]

    for k in range(_SAMPLES):
        words = [_param_word(rng, ty, ix) for ty, ix in zip(params, indices)]
        out.append(env(words, random_storage(k % 2 == 1)))  # small words: array lengths the indices cross
    # parameters equal to each other; every stored word equal to one of
    # them, or to the same word (stored values compared with each other)
    for k in range(_EQUAL_SAMPLES):
        r = rng.randrange(ir.WORD_MOD)
        words = fitted(r)
        out.append(env(words, random_storage(k % 2 == 1)))
        for w in sorted(set(words) | {r, r % 6}):
            out.append(env(words, fixed_storage(w)))
    # the values the conditions compare with: in every parameter, and in
    # every stored word at each bit offset the conditions read
    for t in triggers:
        words = fitted(t)
        draws = [_param_word(rng, ty, ix) for ty, ix in zip(params, indices)]
        out.append(env(words, random_storage(False)))
        out.append(env(words, random_storage(True)))
        for off in offsets:
            planted = fixed_storage((t << off) % ir.WORD_MOD)
            out.append(env(draws, planted))
            out.append(env(words, planted))
    return out


def _decoder_failure(stmts: Sequence[ir.Stmt]) -> bool:
    """`stmts` only revert with empty data, as the decoder's checks do (a
    `require` with a message, a custom error or a panic is the function's
    own check: the generated getter does not have it)."""
    return bool(stmts) and isinstance(stmts[-1], ir.Revert) and isinstance(stmts[-1].payload, ir.Empty) \
        and all(isinstance(s, ir.Mstore) for s in stmts[:-1])


def _covered(body: Sequence[ir.Stmt], seen: Dict[tuple, Set[bool]], at: tuple = ()) -> bool:
    """Every branch reached went both ways, except a test of the calldata
    alone whose other way only reverts with empty data (a decoder check)."""
    for i, s in enumerate(body):
        if not isinstance(s, ir.If):
            continue
        ways = seen.get(at + (i,))
        if not ways:
            continue  # never reached (behind a branch checked above)
        if len(ways) == 1:
            other = s.orelse if True in ways else s.then
            if ir.contains(s.cond, (ir.Sload, ir.Local)) or not _decoder_failure(other):
                return False
        if not all(_covered(b, seen, at + (i, way)) for way, b in ((True, s.then), (False, s.orelse))):
            return False
    return True


def _same_behaviour(fn: ir.Function, expected, params: Sequence[str], indices: Sequence[bool]) -> bool:
    if any(isinstance(n, (ir.MLoad, ir.MemSlice)) for n in ir.walk_all(fn.body)):
        return False
    trig = _triggers(fn)
    if trig is None:
        return False
    seen: Dict[tuple, Set[bool]] = {}
    for env in _samples(params, indices, fn.key, *trig):
        try:
            got = _execute(fn.body, env, seen)
        except (_Unsupported, RecursionError):
            return False
        env.locals.clear()
        if got != expected(env):
            return False
    return _covered(fn.body, seen)


# ---------------------------------------------------------------- decisions


def _foldable_spec(spec) -> bool:
    return (spec is not None and spec.kind == "function" and spec.signature is not None and not spec.payable
            and spec.mutability == "view" and not ({"unstructured", "problem"} & set(spec.flags)))


def _index_flags(t: tuple) -> List[bool]:
    out = []
    while True:
        if t[0] == "map":
            out.append(False)
            t = t[2]
        elif t[0] in ("dyn", "fix"):
            out.append(True)
            t = t[1]
        else:
            return out


def _with_keys(t: tuple, keys: Sequence[str]) -> tuple:
    """t with its mapping key types replaced by `keys` (in getter order)."""
    if t[0] == "map":
        return ("map", keys[0], _with_keys(t[2], keys[1:]))
    if t[0] in ("dyn",):
        return ("dyn", _with_keys(t[1], keys[1:]))
    if t[0] == "fix":
        return ("fix", _with_keys(t[1], keys[1:]), t[2])
    return t


def _key_compatible(a: str, b: str) -> bool:
    """Replacing key type a by b keeps the slots of every key the code
    hashes (32-byte value types hash their word)."""
    if a == b:
        return True
    wide = ("uint256", "int256", "bytes32", "address")
    return a in wide and b in wide


def _var_fold(key: str, fn: ir.Function, spec, v: storage.StateVar) -> Optional[tuple]:
    """The (possibly key-refined) type of v when fn is its generated getter."""
    params = getter_params(v.type)
    if params is None:
        return None
    sig_types = [t.canonical for t, _ in spec.params]
    if len(sig_types) != len(params):
        return None
    t = v.type
    if sig_types != params:
        if not all(_key_compatible(a, b) for a, b in zip(params, sig_types)):
            return None
        t = _with_keys(t, sig_types)
    sig = f"{spec.name}({','.join(sig_types)})"
    if sig != spec.signature or function_selector(sig) != spec.selector:
        return None
    if not _same_behaviour(fn, lambda env: solc_getter(t, v.slot, env, v.offset), sig_types, _index_flags(t)):
        return None
    return t


_CONSTANT_ENV = frozenset({"calldatasize", "callvalue"})


def _reads_nothing(fn: ir.Function) -> bool:
    """The body reads nothing but the calldata size (the decoder's check):
    no storage, calldata words, memory, environment or call results."""
    for n in ir.walk_all(fn.body):
        if isinstance(n, ir.Env) and n.name not in _CONSTANT_ENV:
            return False
        if isinstance(n, (ir.Sload, ir.TLoad, ir.CalldataWord, ir.CalldataSlice, ir.Param, ir.MLoad, ir.MemSlice,
                          ir.CallOut, ir.ReturnData, ir.Balance, ir.ExtCodeSize, ir.ExtCodeHash, ir.ExtCodeSlice,
                          ir.BlockHash, ir.BlobHash, ir.CodeSlice, ir.StateRef)):
            return False
    return True


def _constant_fold(fn: ir.Function, spec) -> Optional[Tuple[str, int]]:
    """(type, value) when the parameterless fn reads nothing and every run
    returns one constant."""
    if spec.params or (spec.returns is not None and len(spec.returns) != 1) or not _reads_nothing(fn):
        return None
    value = None
    for env in _samples([], [], fn.key)[:4]:
        try:
            got = _execute(fn.body, env)
        except (_Unsupported, RecursionError):
            return None
        if got[0] != "return" or len(got[1]) != 1 or (value is not None and got[1][0] != value):
            return None
        value = got[1][0]
    ty = spec.returns[0] if spec.returns else parse_type("uint256")
    if not ty.is_value or ty.kind not in ("uint", "int", "bytes", "bool", "address") \
            or _fit(value, ty.canonical, False) != value:
        return None  # the getter of a constant of that type would not return this word
    return ty.canonical, value


def constant_literal(ty: str, value: int) -> str:
    t = parse_type(ty)
    if t.kind == "bool":
        return "true" if value else "false"
    if t.kind == "address":
        return f"address(uint160({literal(value)}))"
    if t.kind == "bytes":
        nb = t.bits // 8
        return "0x" + (value >> (_SLOT - t.bits)).to_bytes(nb, "big").hex()
    if t.kind == "int":
        s = value - ir.WORD_MOD if value >> 255 else value
        return f"{ty}({s})" if s < 0 else f"{ty}({literal(s)})"
    return f"{ty}({literal(value)})" if t.bits < _SLOT else literal(value)


def _prefer(name: str) -> int:
    return 1 if re.match(r"(get|is)[A-Z_]", name) else 0


def prepare(ctx) -> None:
    lay = storage.analyse(ctx)
    var_folds: Dict[str, Tuple[str, str]] = {}  # vid -> (function key, name)
    const_folds: Dict[str, Tuple[str, str]] = {}  # function key -> (name, declaration)
    refined: Dict[str, tuple] = {}
    cands: List[Tuple[int, str, str, storage.StateVar, tuple]] = []
    for key, spec in sorted(ctx.specs.items()):
        fn = ctx.functions.get(key)
        if fn is None or not ctx.enabled(key, "getters") or not _foldable_spec(spec):
            continue
        c = _constant_fold(fn, spec)
        if c is not None:
            ty, value = c
            const_folds[key] = (spec.name, f"{ty} public constant {spec.name} = {constant_literal(ty, value)};")
            continue
        if lay is None:
            continue
        for v in lay.vars:
            if any(k == key for k, _ in v.accessors):
                t = _var_fold(key, fn, spec, v)
                if t is not None:
                    cands.append((_prefer(spec.name), key, spec.name, v, t))
                break
    for _, key, name, v, t in sorted(cands, key=lambda c: (c[0], c[1])):
        if v.vid not in var_folds:
            var_folds[v.vid] = (key, name)
            refined[v.vid] = t
    # names: a folded name must not be a parameter or a local of a function
    # kept as such (it would shadow the variable there), nor taken twice
    while True:
        folded_keys = {k for k, _ in var_folds.values()} | set(const_folds)
        taken: Set[str] = set()
        for key, spec in ctx.specs.items():
            if key not in folded_keys:
                taken.update(n for _, n in getattr(spec, "params", ()) or ())
                if getattr(spec, "name", None):
                    taken.add(spec.name)
        for fn in ctx.functions.values():
            taken.update(n.name for n in ir.walk_all(fn.body) if isinstance(n, ir.Local))
        names = [n for _, n in var_folds.values()] + [n for n, _ in const_folds.values()]
        types = set(lay.structs.values()) | set(lay.enums.values()) if lay is not None else set()
        bad = {n for n in names if n in taken or names.count(n) > 1 or reserved_name(n)
               or not _IDENT_RE.fullmatch(n) or n in types}
        if not bad:
            break
        var_folds = {vid: kn for vid, kn in var_folds.items() if kn[1] not in bad}
        const_folds = {k: nd for k, nd in const_folds.items() if nd[0] not in bad}
    if lay is not None:
        for v in lay.vars:
            if v.vid in var_folds:
                v.type = refined[v.vid]
    ctx.facts["getters"] = {"vars": var_folds, "constants": const_folds}


def run(fn: ir.Function, ctx) -> ir.Function:
    facts = ctx.facts.get("getters") or {}
    for vid, (key, name) in (facts.get("vars") or {}).items():
        if key == fn.key:
            ctx.fold(key, name)
    if fn.key in (facts.get("constants") or {}):
        ctx.fold(fn.key, facts["constants"][fn.key][0])
    return fn


def finish(ctx) -> None:
    facts = ctx.facts.get("getters") or {}
    for key, (name, decl) in sorted((facts.get("constants") or {}).items()):
        if key in ctx.folded:
            ctx.declare("constant", decl)

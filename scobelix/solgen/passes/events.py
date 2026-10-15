"""
events pass: the LOGn of the original become `emit` statements.

  run     in one function, every `Log`:
            * topic0 a constant that the signature database names (the
              keccak256 of the candidate's signature is the FULL topic0, and
              it indexes as many parameters as there are other topics) and
              whose parameters decode the log exactly -> `emit Name(args)`
              (ir.Emit), the event declared once with the database's
              parameter names and `indexed` flags.  Decoding: every indexed
              value parameter is its topic, a word that is a valid value of
              the type (a cleaned word, a validated parameter, a constant,
              a local whose every assigned value is one: the previous owner
              read into a local before the variable is written);
              an indexed `string` / `bytes` is a topic that is the keccak256
              of a byte string (that byte string is the argument); the data
              is the standard ABI encoding of the other parameters (value
              types as such words, `string` / `bytes` as tails: constant,
              or of a symbolic length L with every offset word provably the
              head plus the tails before it, the decoding of the reverts
              pass).  The zero bytes solc pads a byte string with are
              often read back from memory: a slice of at most 31 bytes
              starting where the last memory write before the log stored a
              zero word is zeros.  A candidate without `indexed`
              flags (a signature of another namespace that hashes to the
              topic) is used when exactly one placement of the indexed
              parameters decodes the log; so are the database's events of
              the topic when none of them indexes as many parameters as the
              log has topics (topic0 hashes the types, not the flags: the
              log tells which parameters it indexes).  When several candidates (or
              placements) decode the log, none is taken: the log stays
              exact.  A signature is declared with one placement per
              contract (solc rejects two events of the same name and types).
            * otherwise, when the data is static words (or empty), or the
              standard encoding of words and byte strings: the
              assembly-free exact form, an anonymous event whose indexed
              parameters are the topics (topic0 first, `bytes32` when it is
              a constant) and whose other parameters are the data words
              (`bytes` for the tails),
              `event Log_<first 4 bytes of topic0>(...) anonymous` (`Log<n>`
              for a log without a constant topic0, n topics).  The log is
              the same (topics and data), the ABI entry is not the
              original's: the declaration says so in a comment and the
              function gets the flag `anonymous_event_form`.
            * anything else (dynamic data the decoder cannot read, more
              arguments than an emit keeps on the stack) stays the exact
              `_logN` helper call.
  finish  declares the events the rewritten functions emit.

The rewrite is exact by construction: the same topics in the same order and
the same data bytes, from the same words.  The pass does not depend on the
others (it reads the words as they are: lifted, or typed by the abi /
storage / arith passes).
"""

from __future__ import annotations

import itertools
import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from scobelix.solgen import ir
from scobelix.solgen.passes.reverts import (_taken_names, _valid_word, _validated, at_most_31, decode_arguments,
                                            flat_parts, read_tail, read_word, with_locals)
from scobelix.solgen.render import _may_halt, reserved_name
from scobelix.solgen.types import SolType, parse_type

LEVELS = ("full",)

FLAG_ANONYMOUS = "anonymous_event_form"

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_VALUE_KINDS = ("uint", "int", "address", "bool", "bytes")
_DYNAMIC_KINDS = ("dynbytes", "string")
_MAX_ARGS = 10  # arguments of one emit (the legacy code generator keeps them on the stack)
_MAX_PLACEMENTS = 64  # placements of the indexed parameters tried for an unflagged candidate
_TIE = ir.Stop()  # (marker: several candidates decode the log)


# ---------------------------------------------------------------- data shapes


def _parts(data: Optional[ir.Bytes]) -> Tuple[ir.Bytes, ...]:
    if data is None:
        return ()
    return tuple(data.parts) if isinstance(data, ir.Blob) else (data,)


def static_words(data: Optional[ir.Bytes]) -> Optional[List[ir.Expr]]:
    """The words of a log's data made only of whole words (32-byte word
    parts, constant bytes of whole words), [] for no data, else None."""
    out: List[ir.Expr] = []
    for p in _parts(data):
        if isinstance(p, ir.Blob):
            inner = static_words(p)
            if inner is None:
                return None
            out.extend(inner)
        elif isinstance(p, ir.WordBytes) and p.width == 32:
            out.append(p.value)
        else:
            raw = ir.const_bytes(p)
            if raw is None or len(raw) % 32:
                return None
            out.extend(ir.Const(int.from_bytes(raw[i:i + 32], "big")) for i in range(0, len(raw), 32))
    return out


def _flat(parts: Sequence[ir.Bytes]) -> Tuple[ir.Bytes, ...]:
    out: List[ir.Bytes] = []
    for p in parts:
        if isinstance(p, ir.Blob):
            out.extend(_flat(p.parts))
        else:
            out.append(p)
    return tuple(out)


def data_arguments(data: Optional[ir.Bytes]) -> Optional[Tuple[List[str], List[ir.Node]]]:
    """(types, arguments) of parameters whose ABI encoding is a log's data:
    its words as `uint256` values when the data is static words; else, for
    data with byte strings, the head words that are the offsets of the
    tails that follow as `bytes` parameters and the others as `uint256`
    (the smallest head that reads the whole data)."""
    words = static_words(data)
    if words is not None:
        return ["uint256"] * len(words), list(words)
    parts = flat_parts(_parts(data))
    for k in range(1, _MAX_ARGS + 1):
        rest, head = parts, []
        for _ in range(k):
            w, rest = read_word(rest)
            if w is None:
                return None
            head.append(w)
        expect: ir.Expr = ir.Const(32 * k)
        types: List[str] = []
        args: List[ir.Node] = []
        for w in head:
            if ir.same_value(w, expect):
                tail, after = read_tail(rest)
                if tail is not None:
                    types.append("bytes")
                    args.append(tail[0])
                    rest, expect = after, ir.Op("add", (expect, tail[1]))
                    continue
            types.append("uint256")
            args.append(w)
        if not rest and "bytes" in types:
            return types, args
    return None


# ---------------------------------------------------------------- zero padding read back from memory


_MEMORY_NEUTRAL = (ir.Assign, ir.Sstore, ir.TStore, ir.Log, ir.Emit, ir.Require, ir.Assert)


def _offset(a: ir.Expr, b: ir.Expr) -> Optional[ir.Expr]:
    """d with b + d = a provably: a constant, or one word of the linear form."""
    terms, const = ir.linear(ir.Op("sub", (a, b)))
    if not terms:
        return ir.Const(const)
    if len(terms) == 1 and terms[0][1] == 1 and const == 0:
        return terms[0][0]
    return None


def _zero_padded(log: ir.Log, before: Sequence[ir.Stmt]) -> ir.Log:
    """`log` with the bytes of memory its data reads that provably hold
    zeros as ZeroBytes: the last bytes of a slice, at most 31 (the padding
    of a byte string to whole words), that start where the last memory
    write before the log stored at least 31 zero bytes (solc's cleanup word
    after the bytes it copies).  Equal values: the write executed, so these
    bytes lie in memory already expanded and the read costs and fails
    nothing; the bytes before them are the same slice of memory."""
    last = None
    for s in reversed(before):
        if isinstance(s, ir.Mstore):
            last = s
            break
        if not isinstance(s, _MEMORY_NEUTRAL):
            return log
    zeros = ir.const_bytes(last.data) if last is not None else None
    if zeros is None or len(zeros) < 31 or any(zeros):
        return log

    def fx(n):
        if not isinstance(n, ir.MemSlice):
            return n
        if ir.same_value(n.start, last.addr):
            return ir.ZeroBytes(n.length) if at_most_31(n.length) else n
        d = _offset(last.addr, n.start)  # (the zero word starts d bytes into the slice)
        if d is None or (isinstance(d, ir.Const) and d.value >= 1 << 64):
            return n
        rest = ir.Op("sub", (n.length, d))
        if not at_most_31(rest):
            return n
        return ir.Blob((ir.MemSlice(n.start, d), ir.ZeroBytes(rest)))

    data = ir.transform(log.data, fx)
    return log if data == log.data else ir.Log(log.topics, data)


def _resolved_logs(body: Sequence[ir.Stmt]) -> Dict[int, ir.Log]:
    """id(log) -> the log with its zero padding resolved (`_zero_padded`),
    for the logs of `body` where it changes something: the statements
    before a log are those of its block and, in a branch, the ones before
    the `if` (a loop body starts afresh: other iterations come before)."""
    out: Dict[int, Optional[ir.Log]] = {}
    logs: Dict[int, ir.Log] = {}

    def block(stmts: Sequence[ir.Stmt], before: Tuple[ir.Stmt, ...]) -> None:
        for i, s in enumerate(stmts):
            if isinstance(s, ir.Log) and s.data is not None:
                new = _zero_padded(s, before + tuple(stmts[:i]))
                if id(s) in out and out[id(s)] != new:
                    out[id(s)] = None  # (one node in two places: no single answer)
                else:
                    out[id(s)], logs[id(s)] = new, s
            if isinstance(s, ir.If):
                block(s.then, before + tuple(stmts[:i]))
                block(s.orelse, before + tuple(stmts[:i]))
            elif isinstance(s, (ir.While, ir.For)):
                block(s.body, ())

    block(tuple(body), ())
    return {k: v for k, v in out.items() if v is not None and v is not logs[k]}


# ---------------------------------------------------------------- the events of a contract


class _Candidate:
    def __init__(self, sig, types: List[SolType], placements: List[Tuple[bool, ...]]):
        self.sig = sig
        self.types = types
        self.placements = placements


class _Events:
    """The events named or declared in this contract (shared by the functions)."""

    def __init__(self, ctx):
        self.ctx = ctx
        facts = ctx.facts.setdefault("events", {})
        self.cands: Dict[Tuple[int, int], List[_Candidate]] = facts.setdefault("candidates", {})
        self.placement: Dict[str, Tuple[bool, ...]] = facts.setdefault("placement", {})  # signature -> indexed flags
        self.decls: Dict[str, str] = facts.setdefault("decls", {})  # declaration text -> event name
        self.shapes: Dict[str, Dict[Tuple[str, ...], str]] = facts.setdefault("shapes", {})  # name -> types -> text
        self.counts: Dict[str, int] = facts.setdefault("counts", {"named": 0, "anonymous": 0, "raw": 0})
        if "taken" not in facts:
            facts["taken"] = set(_taken_names(ctx))
        self.taken: Set[str] = facts["taken"]

    # ------------------------------------------------------------ database

    def candidates(self, topic0: int, n: int) -> List[_Candidate]:
        key = (topic0, n)
        if key in self.cands:
            return self.cands[key]
        lookup = getattr(self.ctx.sigs, "event_candidates", None)
        out: List[_Candidate] = []
        found = tuple(lookup(topic0, n)) if lookup is not None else ()
        free = False
        if not found and lookup is not None:
            # the database knows the event with other indexed flags only: the
            # flags are the ones that place the log's topics, when only one
            # placement decodes it (topic0 hashes the types, not the flags)
            found, free = tuple(lookup(topic0)), True
        for c in found:
            if getattr(c, "anonymous", False) or not _IDENT_RE.fullmatch(c.name or "") or reserved_name(c.name):
                continue
            try:
                types = [parse_type(t) for t in c.types]
            except ValueError:
                continue
            if not all(t.kind in _VALUE_KINDS + _DYNAMIC_KINDS for t in types) or len(types) > _MAX_ARGS \
                    or n > len(types):
                continue
            flags = tuple(bool(x) for x in (getattr(c, "indexed", ()) or ()))
            if getattr(c, "declared", True) and len(flags) == len(types) and not free:
                placements = [flags] if sum(flags) == n else []
            elif free or not getattr(c, "declared", True):
                placements = []
                for chosen in itertools.islice(itertools.combinations(range(len(types)), n), _MAX_PLACEMENTS):
                    placements.append(tuple(i in chosen for i in range(len(types))))
            else:
                placements = []
            if placements:
                out.append(_Candidate(c, types, placements))
        self.cands[key] = out
        return out

    # ------------------------------------------------------------ one log

    @staticmethod
    def decode(types: List[SolType], placement: Tuple[bool, ...], topics: Sequence[ir.Expr],
               data: Optional[ir.Bytes], valid) -> Optional[List[ir.Node]]:
        """The arguments of `emit E(...)` that log exactly `topics` (after
        topic0) and `data`, else None."""
        indexed = [t for t, p in zip(types, placement) if p]
        rest = [t for t, p in zip(types, placement) if not p]
        if len(indexed) != len(topics):
            return None
        from_topics: List[ir.Node] = []
        for t, topic in zip(indexed, topics):
            if t.is_value:
                if not _valid_word(topic, t, valid):
                    return None
                from_topics.append(topic)
            elif t.kind in _DYNAMIC_KINDS and isinstance(topic, ir.Keccak):
                from_topics.append(topic.data)  # solc hashes the bytes of an indexed string / bytes
            else:
                return None
        from_data = decode_arguments(rest, _flat(_parts(data)), valid)
        if from_data is None:
            return None
        out: List[ir.Node] = []
        it_t, it_d = iter(from_topics), iter(from_data)
        for p in placement:
            out.append(next(it_t) if p else next(it_d))
        return out

    def named(self, log: ir.Log, valid):
        """The Emit of the one database event that decodes the log, `_TIE`
        when several do, None when none does."""
        topic0 = log.topics[0] if log.topics else None
        if not isinstance(topic0, ir.Const):
            return None
        fitting: Dict[Tuple[str, Tuple[bool, ...]], Tuple[_Candidate, Tuple[bool, ...], List[ir.Node]]] = {}
        for cand in self.candidates(topic0.value, len(log.topics) - 1):
            name = cand.sig.name
            if name in self.taken:
                continue
            for placement in cand.placements:
                fixed = self.placement.get(cand.sig.signature)
                if fixed is not None and fixed != placement:
                    continue
                args = self.decode(cand.types, placement, log.topics[1:], log.data, valid)
                if args is not None:
                    fitting.setdefault((cand.sig.signature, placement), (cand, placement, args))
        if len(fitting) > 1:
            return _TIE  # several readings the log cannot tell apart: never a guess
        if not fitting:
            return None  # nothing decodes the log
        (cand, placement, args), = fitting.values()
        text = self.declaration(cand, placement)
        if text is None:
            return None
        self.placement[cand.sig.signature] = placement
        self.decls[text] = cand.sig.name
        self.ctx.facts.setdefault("declared_names", set()).add(cand.sig.name)
        return ir.Emit(cand.sig.name, tuple(args), tuple(t.canonical for t in cand.types))

    def declaration(self, cand: _Candidate, placement: Tuple[bool, ...]) -> Optional[str]:
        names: List[str] = []
        seen: Set[str] = set()
        for _, n in cand.sig.inputs:
            # (`from` names the first parameter of every Transfer event: solc takes it)
            ok = bool(_IDENT_RE.fullmatch(n or "")) and (n == "from" or not reserved_name(n, parameter=True)) \
                and n not in seen and n != cand.sig.name
            names.append(n if ok else "")
            if ok:
                seen.add(n)
        params = []
        for t, p, n in zip(cand.types, placement, names):
            params.append(t.canonical + (" indexed" if p else "") + (f" {n}" if n else ""))
        text = f"event {cand.sig.name}({', '.join(params)});"
        types = tuple(t.canonical for t in cand.types)
        known = self.shapes.setdefault(cand.sig.name, {})
        if types in known and known[types] != text:
            return None  # the same event declared with other indexed flags (cannot happen: placement is fixed)
        known[types] = text
        return text

    def anonymous(self, log: ir.Log) -> Optional[Tuple[ir.Emit, str]]:
        """The anonymous-event form of a log whose data is static words or
        the standard encoding of words and byte strings."""
        got = data_arguments(log.data)
        if got is None or len(log.topics) + len(got[0]) > _MAX_ARGS:
            return None
        data_types, words = got
        topics = log.topics
        constant0 = bool(topics) and isinstance(topics[0], ir.Const)
        types: List[str] = []
        params: List[str] = []
        for i in range(len(topics)):
            ty = "bytes32" if i == 0 and constant0 else "uint256"
            types.append(ty)
            params.append(f"{ty} indexed topic{i}")
        for j, ty in enumerate(data_types):
            types.append(ty)
            params.append(f"{ty} data{j}")
        base = f"Log_{topics[0].value >> 224:08x}" if constant0 else f"Log{len(topics)}"
        known = sorted({c.sig.signature for c in self.candidates(topics[0].value, len(topics) - 1)}) \
            if constant0 else []
        if known:
            # (the database names the topic, but this log does not fit that
            # event's declaration here: its words, its indexed parameters)
            note = (f"/// topic0 0x{topics[0].value:064x}: {', '.join(known)} in the signature database,\n"
                    f"/// which does not fit this log here: declared anonymous with its topic0 as first indexed "
                    f"parameter,\n/// the same log, another ABI entry")
        elif constant0:
            note = (f"/// topic0 0x{topics[0].value:064x}: an event the signature database does not name, "
                    f"declared\n/// anonymous with its topic0 as first indexed parameter: the same log, another "
                    f"ABI entry")
        else:
            note = (f"/// a log of the original with {len(topics)} topic(s) and no constant topic0, declared "
                    f"anonymous:\n/// the same log, another ABI entry")
        body = f"({', '.join(params)}) anonymous;"
        name = base
        k = 1
        while True:
            known = self.shapes.get(name, {})
            text = f"{note}\nevent {name}{body}"
            clash = name in self.taken or reserved_name(name) or (tuple(types) in known and known[tuple(types)] != text)
            if not clash:
                break
            k += 1
            name = f"{base}_{k}"
        self.shapes.setdefault(name, {})[tuple(types)] = text
        self.decls[text] = name
        self.ctx.facts.setdefault("declared_names", set()).add(name)
        return ir.Emit(name, tuple(topics) + tuple(words), tuple(types)), text


def _halting_args(log: ir.Log) -> int:
    nodes = list(log.topics) + ([log.data] if log.data is not None else [])
    return sum(1 for n in nodes if _may_halt(n))


# ---------------------------------------------------------------- the pass


def run(fn: ir.Function, ctx) -> ir.Function:
    if not ir.contains(fn.body, ir.Log):
        return fn
    events = _Events(ctx)
    # (locals included: a value cached in a local before the state variable
    # is written, the previous owner, is a valid address when every value
    # the local is assigned is one)
    valid = with_locals(_validated(ctx.specs.get(fn.key), ctx.abi_v2), fn.body)
    resolved = _resolved_logs(fn.body)
    flags: Set[str] = set()

    def fx(n):
        if not isinstance(n, ir.Log):
            return n
        log = resolved.get(id(n), n)  # (the same log: zero padding read back from memory as zeros)
        if _halting_args(log) > 1:
            events.counts["raw"] += 1
            return n  # the order the arguments are evaluated in could tell the forms apart
        emit = events.named(log, valid)
        if emit is _TIE:
            events.counts["raw"] += 1
            return n
        if emit is not None:
            events.counts["named"] += 1
            return emit
        got = events.anonymous(log)
        if got is not None:
            events.counts["anonymous"] += 1
            flags.add(FLAG_ANONYMOUS)
            return got[0]
        events.counts["raw"] += 1
        return n

    body = ir.transform(fn.body, fx)
    if body == fn.body:
        return fn
    return fn.with_body(body, flags)


def finish(ctx) -> None:
    facts = ctx.facts.get("events") or {}
    decls = facts.get("decls") or {}
    for text in sorted(decls, key=lambda t: (decls[t], t)):
        ctx.declare("event", text)

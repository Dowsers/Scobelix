"""
calls pass: the external calls of the original in their Solidity forms.

  run     in one function, every `ExtCall`, in the order of the trace:
            * a high-level call: a CALL / STATICCALL whose payload is a
              constant selector the signature database names, followed by
              static words that are valid values of the signature's
              parameter types, wrapped in exactly the scaffolding the TARGET
              compiler generates for `I(to).f{value: v, gas: g}(args)`:
                - the check that the callee has code (`extcodesize`), which
                  solc writes for a function that returns nothing (from
                  0.8.10; before, for every call): it must be the statement
                  right before the call when the target writes it; the
                  original's own check is kept, as a statement, when the
                  target does not write it (0.7 originals check before every
                  call);
                - the bubbling of the callee's revert data when the call
                  fails;
                - when the function returns k static words, the check that
                  the return data holds them (`slt(returndatasize, 32k)` with
                  ABI coder v2, `lt` with v1) and, with v2, the validator of
                  every word whose type has one (address, uintN, intN,
                  bytesN, bool): those give the return types (a word without
                  one is uint256, int256 or bytes32: the database's type when
                  it is one of them).
              -> `ir.HighCall` (`view` for a STATICCALL, `payable` with a
              value), the returned words read after it -> `ir.Result`.  Every
              check the target regenerates is removed; nothing else is.  The
              function goes into one interface per standard (IERC20, IERC721)
              or per callee name (`I<Name>` from the parameter or state
              variable holding the address), declared once per contract.
            * `payable(a).transfer(v)` / `payable(a).send(v)`: a CALL without
              payload whose gas is the stipend (`mul(2300, iszero(v))`, or its
              value for a constant v); transfer when the failure bubbles the
              callee's revert data -> `ir.Transfer`.
            * the standard proxy forwarder (DELEGATECALL of the whole
              calldata with all the gas, revert data bubbled, return data
              returned) -> `ir.Forward`, one commented assembly block.
            * precompiles 1, 2, 3 called the way solc calls them for
              `ecrecover`, `sha256`, `ripemd160` (failure bubbled; for sha256
              the check that 32 bytes came back, which never fails) ->
              `ir.Builtin`.
            * any other call stays the exact low-level call, its success
              flag (and its whole return data, when used) declared as locals
              where it is made (`ExtCall.ok`, `.ret`), a payload of a
              constant selector and whole words written
              `abi.encodeWithSelector`.
  finish  declares the interfaces of the calls rewritten.

Not handled (exact forms stay): calls whose selector the database does not
name, dynamic arguments or return values, the scaffolding of the IR
pipeline around a call that returns values (its return data size check
goes through the allocation of the decoded values), other delegatecalls
and callcode, try/catch, contract creation, the other precompiles.  Exact
by construction: a rewrite only drops the checks the target compiler
writes again for the same line, with the same payloads, in the same place;
of the operands of a call (address, value, gas, arguments) at most one may
end the call when evaluated (render._may_halt), so their order cannot
matter.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from scobelix.solgen import ir
from scobelix.solgen import abi as _abi
from scobelix.solgen.passes.reverts import _taken_names, _valid_word, _validated
from scobelix.solgen.render import _may_halt, reserved_name
from scobelix.solgen.types import SolType, fits, max_bits, parse_type, sign_extended

LEVELS = ("full",)

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_CODE_CHECK_ONLY_WITHOUT_RETURNS = (0, 8, 10)  # solc skips the code check when it decodes return data
_STIPEND = 2300
_MAX_WORDS = 12  # arguments / return values of one high-level call (stack window of the legacy generator)
_FULL_WIDTH = ("uint256", "int256", "bytes32")  # return types without a validator

# selectors of the standard interfaces the calls are filed under
_ERC20 = frozenset({0x18160DDD, 0x70A08231, 0xA9059CBB, 0x23B872DD, 0x095EA7B3, 0xDD62ED3E, 0x313CE567,
                    0x06FDDE03, 0x95D89B41})
_ERC721 = frozenset({0x6352211E, 0x42842E0E, 0xA22CB465, 0x081812FC, 0xE985E9C5})


def _version(v: str) -> Tuple[int, int, int]:
    try:
        a, b, c = (int(x) for x in str(v).split(".")[:3])
        return a, b, c
    except ValueError:
        return 0, 8, 19


# ---------------------------------------------------------------- conditions


def _core(e: ir.Expr) -> Tuple[ir.Expr, bool]:
    """(x, positive): `e` is non-zero exactly when x is non-zero (positive)
    or zero (not positive)."""
    positive = True
    while True:
        if isinstance(e, ir.Op) and e.op == "iszero" and len(e.args) == 1:
            e, positive = e.args[0], not positive
        elif isinstance(e, ir.Not):
            e, positive = e.value, not positive
        elif isinstance(e, ir.Bool):
            e = e.value
        elif isinstance(e, ir.Op) and e.op == "eq" and len(e.args) == 2 and ir.ZERO in e.args:
            e, positive = (e.args[1] if e.args[0] == ir.ZERO else e.args[0]), not positive
        elif isinstance(e, ir.Op) and e.op == "gt" and len(e.args) == 2 and e.args[1] == ir.ZERO:
            e = e.args[0]
        elif isinstance(e, ir.Op) and e.op == "lt" and len(e.args) == 2 and e.args[0] == ir.ZERO:
            e = e.args[1]
        else:
            return e, positive


def _check(s: ir.Stmt) -> Optional[Tuple[ir.Expr, bool, ir.Payload, Tuple[ir.Stmt, ...]]]:
    """(x, when_nonzero, payload, rest) when statement `s` reverts with
    `payload` exactly when x is non-zero (when_nonzero) / zero, and runs
    `rest` otherwise (then the statements after it)."""
    if isinstance(s, ir.Require):
        x, positive = _core(s.cond)
        return x, not positive, s.payload, ()
    if isinstance(s, ir.If):
        for branch, other, on_true in ((s.then, s.orelse, True), (s.orelse, s.then, False)):
            if len(branch) == 1 and isinstance(branch[0], ir.Revert):
                x, positive = _core(s.cond)
                return x, positive if on_true else not positive, branch[0].payload, tuple(other)
    return None


def _address(e: ir.Expr) -> ir.Expr:
    """The word an address operand stands for (its low 160 bits matter)."""
    while isinstance(e, ir.Mask) and (e.size, e.offset, e.shl) == (160, 0, 0):
        e = e.value
    return e


def _word_index(w: ir.Expr, cid: int) -> Optional[int]:
    """i when w is the i-th word of call cid's return data."""
    if isinstance(w, ir.BytesWord) and isinstance(w.data, ir.ReturnData) and w.data.call_id == cid:
        start, length = ir.evaluate(w.data.start), ir.evaluate(w.data.length)
        if start is not None and length == 32 and start % 32 == 0:
            return start // 32
    return None


def _cleanup_type(c: ir.Expr, w: ir.Expr) -> Optional[str]:
    """The type whose ABI v2 validator compares w with c (c the cleanup of w)."""
    if isinstance(c, ir.Mask) and c.value == w and all(isinstance(x, int) for x in (c.size, c.offset, c.shl)) \
            and c.shl == 0 and c.size % 8 == 0 and 8 <= c.size < 256:
        if c.offset == 0:
            return "address" if c.size == 160 else f"uint{c.size}"
        if c.offset == 256 - c.size:
            return f"bytes{c.size // 8}"
        return None
    if isinstance(c, ir.Op) and c.op == "iszero" and isinstance(c.args[0], ir.Op) and c.args[0].op == "iszero" \
            and c.args[0].args[0] == w:
        return "bool"
    if isinstance(c, ir.Op) and c.op == "signextend" and c.args[1] == w:
        b = sign_extended(c)
        return f"int{8 * (b + 1)}" if b is not None else None
    return None


def _validator(x: ir.Expr, when_nonzero: bool, cid: int) -> Optional[Tuple[int, str]]:
    """(i, type) when the check fails exactly when the i-th returned word is
    not a valid value of the type (the ABI v2 decoder's validator); type ""
    for the validator of a full-width type, which never fails (`w == w`,
    left by the unoptimised code generator)."""
    if when_nonzero or not (isinstance(x, ir.Op) and x.op == "eq" and len(x.args) == 2):
        return None
    for w, c in ((x.args[0], x.args[1]), (x.args[1], x.args[0])):
        i = _word_index(w, cid)
        if i is not None:
            ty = "" if c == w else _cleanup_type(c, w)
            if ty is not None:
                return i, ty
    return None


def _size_words(x: ir.Expr, when_nonzero: bool, cid: int, abi_v2: bool) -> Optional[int]:
    """k when the check fails exactly when the return data is shorter than
    k words (the decoder's check: signed with ABI coder v2)."""
    if not when_nonzero or not isinstance(x, ir.Op) or len(x.args) != 2:
        return None
    rds = ir.CallOut(cid, "returndatasize")
    less, more = ("slt", "sgt") if abi_v2 else ("lt", "gt")
    n = None
    if x.op == less and x.args[0] == rds:
        n = ir.evaluate(x.args[1])
    elif x.op == more and x.args[1] == rds:
        n = ir.evaluate(x.args[0])
    if n is None or n % 32 or not 0 < n <= 32 * _MAX_WORDS:
        return None
    return n // 32


# ---------------------------------------------------------------- payloads


def _payload(args: Optional[ir.Bytes]) -> Optional[Tuple[int, List[ir.Expr]]]:
    """(selector, argument words) of a payload made of a constant selector
    and whole words."""
    if args is None:
        return None
    parts: List[ir.Bytes] = []

    def flat(b):
        if isinstance(b, ir.Blob):
            for p in b.parts:
                flat(p)
        else:
            parts.append(b)

    flat(args)
    if not parts:
        return None
    head = parts[0]
    words: List[ir.Expr] = []
    if isinstance(head, ir.WordBytes) and head.width == 4 and isinstance(head.value, ir.Const):
        selector = head.value.value & 0xFFFFFFFF
        rest = parts[1:]
    else:
        raw = ir.const_bytes(head)
        if raw is None or len(raw) < 4 or (len(raw) - 4) % 32:
            return None
        selector = int.from_bytes(raw[:4], "big")
        words.extend(ir.Const(int.from_bytes(raw[i:i + 32], "big")) for i in range(4, len(raw), 32))
        rest = parts[1:]
    for p in rest:
        if isinstance(p, ir.WordBytes) and p.width == 32:
            words.append(p.value)
            continue
        raw = ir.const_bytes(p)
        if raw is None or len(raw) % 32:
            return None
        words.extend(ir.Const(int.from_bytes(raw[i:i + 32], "big")) for i in range(0, len(raw), 32))
    return selector, words


_BUILTINS = {1: "ecrecover", 2: "sha256", 3: "ripemd160"}


def _words_of(data: Optional[ir.Bytes]) -> Optional[List[ir.Expr]]:
    """The words of a byte string made of whole words."""
    parts = data.parts if isinstance(data, ir.Blob) else (data,) if data is not None else ()
    out = []
    for p in parts:
        if not (isinstance(p, ir.WordBytes) and p.width == 32):
            return None
        out.append(p.value)
    return out


def _is_stipend(gas: Optional[ir.Expr], value: Optional[ir.Expr]) -> bool:
    """The gas of a CALL is what solc passes for send / transfer."""
    if gas is None or value is None:
        return False
    v = ir.evaluate(value)
    if v is not None:
        return ir.evaluate(gas) == (_STIPEND if v == 0 else 0)
    if isinstance(gas, ir.Op) and gas.op == "mul" and len(gas.args) == 2:
        for a, b in (gas.args, tuple(reversed(gas.args))):
            if a == ir.Const(_STIPEND) and b == ir.Op("iszero", (value,)):
                return True
    return False


# ---------------------------------------------------------------- uses


def _replace_results(nodes: Tuple[ir.Stmt, ...], cid: int, types: Sequence[str]) -> Tuple[ir.Stmt, ...]:
    """The statements after a high-level call, with its returned words read
    as its values and its success flag as 1 (they run only when it
    succeeded)."""
    k = len(types)

    def result_words(start: int, length: int) -> Optional[ir.Bytes]:
        if start % 32 or length % 32 or length == 0 or start + length > 32 * k:
            return None
        ws = [ir.WordBytes(ir.Result(cid, i, types[i])) for i in range(start // 32, (start + length) // 32)]
        return ws[0] if len(ws) == 1 else ir.Blob(tuple(ws))

    def fx(n):
        if isinstance(n, ir.CallOut) and n.call_id == cid and n.what == "success":
            return ir.ONE
        if isinstance(n, ir.BytesWord):
            if isinstance(n.data, ir.WordBytes) and n.data.width == 32 and isinstance(n.data.value, ir.Result):
                return n.data.value  # (the return data word, already read as the value)
            i = _word_index(n, cid)
            if i is not None and i < k:
                return ir.Result(cid, i, types[i])
        if isinstance(n, ir.ReturnData) and n.call_id == cid:
            start, length = ir.evaluate(n.start), ir.evaluate(n.length)
            if start is not None and length is not None:
                got = result_words(start, length)
                if got is not None:
                    return got
        return _plain(n)

    return ir.transform(nodes, fx)


def _plain(n):
    """A cleanup applied to a returned value that is already of the type: the value."""
    if isinstance(n, ir.Mask) and isinstance(n.value, ir.Result) and (n.offset, n.shl) == (0, 0) \
            and isinstance(n.size, int) and max_bits(n.value) <= n.size:
        return n.value
    if isinstance(n, ir.Op) and n.op == "iszero" and isinstance(n.args[0], ir.Op) and n.args[0].op == "iszero" \
            and isinstance(n.args[0].args[0], ir.Result) and max_bits(n.args[0].args[0]) <= 1:
        return n.args[0].args[0]
    if isinstance(n, ir.Op) and n.op == "signextend" and isinstance(n.args[1], ir.Result):
        b = sign_extended(n)
        if b is not None and fits(n.args[1], parse_type(f"int{8 * (b + 1)}")):
            return n.args[1]
    if isinstance(n, ir.Mask) and isinstance(n.value, ir.Result) and n.value.ty.startswith("bytes") \
            and isinstance(n.size, int) and n.shl == 0 and n.offset == 256 - n.size:
        if fits(n.value, parse_type(f"bytes{n.size // 8}")) if n.size % 8 == 0 and 8 <= n.size <= 256 else False:
            return n.value
    return n


def _halting(operands) -> int:
    """How many operands of a call may end the call when evaluated (see
    render._may_halt): with two, the order of evaluation could tell the
    forms apart; with one, the outcome is the same in any order."""
    return sum(1 for x in operands if x is not None and _may_halt(x))


def _uses(nodes, pred) -> bool:
    return any(pred(n) for n in ir.walk_all(nodes))


# ---------------------------------------------------------------- the interfaces of a contract


class _Interfaces:
    def __init__(self, ctx):
        self.ctx = ctx
        facts = ctx.facts.setdefault("calls", {})
        self.ifaces: Dict[str, Dict[int, str]] = facts.setdefault("interfaces", {})  # name -> selector -> decl
        if "taken" not in facts:
            facts["taken"] = set(_taken_names(ctx))
        self.taken: Set[str] = facts["taken"]

    def name(self, selector: int, decl: str, hint: str) -> str:
        if selector in _ERC20:
            base = "IERC20"
        elif selector in _ERC721:
            base = "IERC721"
        else:
            h = hint.lstrip("_")
            if re.fullmatch(r"(?:slot|var_|map_|arr_|arg)\d+(_\d+)*", h) or len(h) < 3:
                h = ""  # (a name given to a variable nobody named, or too short to tell: `IT`)
            base = "I" + h[:1].upper() + h[1:] if h and _IDENT_RE.fullmatch(h) else "IExternal"
        name, k = base, 1
        declared = self.ctx.facts.get("declared_names") or set()
        while (name in self.taken or (name in declared and name not in self.ifaces) or reserved_name(name)
               or self.ifaces.get(name, {}).get(selector, decl) != decl):
            k += 1
            name = f"{base}_{k}"
        self.ifaces.setdefault(name, {})[selector] = decl
        self.ctx.facts.setdefault("declared_names", set()).add(name)
        return name


def _param_name(spec, head: int) -> str:
    word = 0
    for t, n in getattr(spec, "params", ()) or ():
        if word == head:
            return n if t.kind == "address" else ""
        word += t.head_words
    return ""


def _hint(to: ir.Expr, spec) -> str:
    """A name for the callee: the parameter or state variable holding it."""
    x = _address(to)
    if isinstance(x, ir.Field) and isinstance(x.value, ir.StateRef):
        x = x.value
    if isinstance(x, ir.StateRef) and not x.path:
        return x.var
    w = None
    if isinstance(x, ir.Param):
        w = x.index
    elif isinstance(x, ir.CalldataWord) and isinstance(x.offset, ir.Const) and x.offset.value >= 4 \
            and (x.offset.value - 4) % 32 == 0:
        w = (x.offset.value - 4) // 32
    return _param_name(spec, w) if w is not None and spec is not None else ""


def _names(params, avoid: Set[str]) -> List[str]:
    out = []
    seen: Set[str] = set()
    for _, n in params:
        ok = bool(_IDENT_RE.fullmatch(n or "")) and (n == "from" or not reserved_name(n, parameter=True)) \
            and n not in seen and n not in avoid
        out.append(n if ok else "")
        if ok:
            seen.add(n)
    return out


# ---------------------------------------------------------------- the rewriter


class _Plan:
    """The function a call site calls: its signature, parameter types and
    argument words."""

    def __init__(self, sig, types: List[SolType], args: List[ir.Expr]):
        self.sig = sig
        self.types = types
        self.args = args


class _Rewriter:
    def __init__(self, fn: ir.Function, ctx):
        self.fn = fn
        self.ctx = ctx
        self.spec = ctx.specs.get(fn.key)
        self.valid = _validated(self.spec, ctx.abi_v2)
        self.target = _version(ctx.target_solc)
        self.ifaces = _Interfaces(ctx)
        self.changed = False
        self.counts = ctx.facts.setdefault("calls", {}).setdefault(
            "counts", {"interface": 0, "transfer": 0, "send": 0, "low-level": 0})

    # ------------------------------------------------------------ blocks

    def block(self, stmts: Sequence[ir.Stmt]) -> Tuple[ir.Stmt, ...]:
        out: List[ir.Stmt] = []
        stmts = tuple(stmts)
        for i, s in enumerate(stmts):
            rest = stmts[i + 1:]
            if isinstance(s, ir.ExtCall):
                guard = None
                if out:
                    c = _check(out[-1])
                    if c is not None and not c[3] and self._is_code_check(c, s.to):
                        guard = out[-1]
                got = self.call(s, rest, guard, nested=False)
                if got is not None:
                    drop, new = got
                    if drop:
                        out.pop()
                    out.extend(new)
                    return tuple(out)
                out.append(self.low_level(s, rest))
                continue
            if isinstance(s, ir.Precompile):
                got = self.builtin(s, rest)
                if got is not None:
                    out.extend(got)
                    return tuple(out)
            if isinstance(s, ir.If):
                c = _check(s)
                if c is not None and c[3] and isinstance(c[3][0], ir.ExtCall) and self._is_code_check(c, c[3][0].to):
                    got = self.call(c[3][0], c[3][1:] + rest, s, nested=True)
                    if got is not None:
                        out.extend(got[1])
                        return tuple(out)
            out.append(self.inner(s))
        return tuple(out)

    def inner(self, s: ir.Stmt) -> ir.Stmt:
        if isinstance(s, ir.If):
            then, orelse = self.block(s.then), self.block(s.orelse)
            if then == s.then and orelse == s.orelse:
                return s
            return ir.If(s.cond, then, orelse)
        if isinstance(s, ir.While):
            body = self.block(s.body)
            return s if body == s.body else ir.While(s.cond, body, s.init, s.loop_id)
        if isinstance(s, ir.For):
            body = self.block(s.body)
            return s if body == s.body else ir.For(s.init, s.cond, s.step, body, s.loop_id)
        return s

    @staticmethod
    def _is_code_check(c, to: ir.Expr) -> bool:
        x, when_nonzero, _, _ = c
        return not when_nonzero and isinstance(x, ir.ExtCodeSize) and _address(x.addr) == _address(to)

    # ------------------------------------------------------------ one call

    def call(self, s: ir.ExtCall, rest: Tuple[ir.Stmt, ...], guard: Optional[ir.Stmt], nested: bool) \
            -> Optional[Tuple[bool, List[ir.Stmt]]]:
        """(drop the guard before the call, the statements that replace the
        call and the rest of its block), or None: not a high-level call /
        transfer / send.  `guard`: the code check before the call (a
        Require before it in the block, or, `nested`, the If whose branch
        the call starts)."""
        if s.kind == "delegatecall":
            return self.forward(s, rest, guard, nested)
        if s.kind not in ("call", "staticcall"):
            return None
        if s.args is None and s.kind == "call":
            return self.transfer(s, rest, guard, nested)
        return self.high_level(s, rest, guard, nested)

    def _guarded(self, guard: Optional[ir.Stmt], nested: bool, absorb: bool,
                 new: List[ir.Stmt]) -> Tuple[bool, List[ir.Stmt]]:
        """`new` (the call and what follows it) with the code check before
        the call dropped (absorb) or kept."""
        if guard is None or not nested:
            return absorb and guard is not None, new
        if absorb:
            return False, new
        # keep the original's check around the rewritten call
        c = _check(guard)
        x, when_nonzero, payload, _ = c
        then_fails = len(guard.then) == 1 and isinstance(guard.then[0], ir.Revert)
        if then_fails:
            return False, [ir.If(guard.cond, guard.then, tuple(new))]
        return False, [ir.If(guard.cond, tuple(new), guard.orelse)]

    def builtin(self, s: ir.Precompile, rest) -> Optional[List[ir.Stmt]]:
        """ecrecover / sha256 / ripemd160: the precompile call solc writes for
        the builtin, its failure bubbling the revert data (and, for sha256,
        the check that 32 bytes came back, which never fails: the
        precompile always returns them)."""
        name = _BUILTINS.get(s.address)
        cid = s.call_id
        if name is None or not rest or s.output is None:
            return None
        c = _check(rest[0])
        if c is None or c[1] or c[0] != ir.CallOut(cid, "success") or c[2] != ir.Bubble(cid):
            return None
        cont = list(c[3]) + list(rest[1:])
        if name == "sha256" and cont:
            c2 = _check(cont[0])
            if c2 is not None and c2[2] == ir.Empty() and _size_words(c2[0], c2[1], cid, True) == 1:
                cont = list(c2[3]) + cont[1:]
        if name == "ecrecover":
            words = _words_of(s.args)
            if words is None or len(words) != 4 or not _valid_word(words[1], parse_type("uint8"), self.valid):
                return None
            args, types, ty = tuple(words), ("bytes32", "uint8", "bytes32", "bytes32"), "address"
        else:
            args, types, ty = (s.args,), ("bytes",), "bytes32" if name == "sha256" else "bytes20"
        if _halting(args) > 1:
            return None
        out, result = ir.Local(s.output), ir.Result(cid, 0, ty)

        def fx(n):
            if n == ir.CallOut(cid, "success"):
                return ir.ONE
            if name == "ripemd160":  # the 20 bytes of the hash, right-aligned in the word: bytes20 is its shift
                return result if isinstance(n, ir.Mask) and n.value == out and (n.size, n.offset, n.shl) == (
                    160, 0, 96) else n
            return result if n == out else _plain(n)

        cont_t = ir.transform(tuple(cont), fx)
        if _uses(cont_t, lambda n: n == out):
            return None
        used = _uses(cont_t, lambda n: n == result)
        self.changed = True
        self.counts["builtin"] = self.counts.get("builtin", 0) + 1
        local = ("signer" if name == "ecrecover" else "hash") if used else None
        return [ir.Builtin(cid, name, args, types, ty, local)] + list(self.block(cont_t))

    def forward(self, s: ir.ExtCall, rest, guard, nested):
        """The standard proxy forwarder: the whole calldata delegated with all
        the gas, the revert data bubbled, the return data returned."""
        cid = s.call_id
        if s.gas is not None or s.args != ir.CalldataSlice(ir.ZERO, ir.Env("calldatasize")) or not rest:
            return None
        c = _check(rest[0])
        if c is None or c[1] or c[0] != ir.CallOut(cid, "success") or c[2] != ir.Bubble(cid):
            return None
        ret = ir.Return(ir.ReturnData(cid, ir.ZERO, ir.CallOut(cid, "returndatasize")))
        if tuple(c[3]) + tuple(rest[1:]) != (ret,):
            return None
        self.changed = True
        self.counts["forward"] = self.counts.get("forward", 0) + 1
        return self._guarded(guard, nested, False, [ir.Forward(cid, s.to)])

    def transfer(self, s: ir.ExtCall, rest, guard, nested):
        if not _is_stipend(s.gas, s.value) or _halting((s.to, s.value)) > 1:
            return None
        cid = s.call_id
        success = ir.CallOut(cid, "success")
        if rest:
            c = _check(rest[0])
            if c is not None and not c[1] and c[0] == success and c[2] == ir.Bubble(cid):
                cont = _replace_results(c[3] + rest[1:], cid, ())
                if not self._still_reads(cont, cid):
                    self.changed = True
                    self.counts["transfer"] += 1
                    return self._guarded(guard, nested, False,
                                         [ir.Transfer(cid, s.to, s.value)] + list(self.block(cont)))
        if self._still_reads(rest, cid, success=False):
            return None
        used = _uses(rest, lambda n: n == success)
        self.changed = True
        self.counts["send"] += 1
        return self._guarded(guard, nested, False,
                             [ir.Transfer(cid, s.to, s.value, True, "sent" if used else None)] + list(self.block(rest)))

    @staticmethod
    def _still_reads(nodes, cid: int, success: bool = True) -> bool:
        """The statements read the return data of call cid (or its success
        flag, `success`)."""
        def pred(n):
            if isinstance(n, ir.CallOut) and n.call_id == cid:
                return success or n.what != "success"
            return isinstance(n, ir.ReturnData) and n.call_id == cid
        return _uses(nodes, pred)

    def plan(self, s: ir.ExtCall) -> Optional[Tuple[int, _Plan]]:
        got = _payload(s.args)
        if got is None:
            return None
        selector, words = got
        if len(words) > _MAX_WORDS:
            return None
        lookup = getattr(self.ctx.sigs, "function_candidates", None)
        for sig in (lookup(selector) if lookup is not None else ()):
            if not _IDENT_RE.fullmatch(sig.name or "") or reserved_name(sig.name):
                continue
            try:
                types = [parse_type(t) for t in sig.types]
            except ValueError:
                continue
            if len(types) != len(words) or not all(t.is_value for t in types):
                continue
            if all(_valid_word(w, t, self.valid) for w, t in zip(words, types)):
                return selector, _Plan(sig, types, words)
        return None

    def high_level(self, s: ir.ExtCall, rest, guard, nested):
        cid = s.call_id
        planned = self.plan(s)
        if planned is None or not rest:
            return None
        selector, plan = planned
        halting = _halting([s.to] + plan.args + [v for v in (s.gas, s.value) if v is not None])
        if halting > 1:
            return None
        # the failure bubbles the callee's revert data
        c = _check(rest[0])
        if c is None or c[1] or c[0] != ir.CallOut(cid, "success") or c[2] != ir.Bubble(cid):
            return None
        cont = list(c[3]) + list(rest[1:])
        # the decoder's checks: the size of the return data, then the validators
        k = 0
        validated: Dict[int, str] = {}
        while cont:
            c = _check(cont[0])
            if c is None or c[2] != ir.Empty():
                break
            x, when_nonzero, _, nxt = c
            if not k:
                n = _size_words(x, when_nonzero, cid, self.ctx.abi_v2)
                if n is None:
                    break
                k = n
            else:
                v = _validator(x, when_nonzero, cid) if self.ctx.abi_v2 else None
                if v is None or v[0] >= k or v[0] in validated:
                    break
                validated[v[0]] = v[1]
            cont = list(nxt) + cont[1:]
        if k > _MAX_WORDS:
            return None
        outputs = list(getattr(plan.sig, "outputs", None) or ())
        try:
            if any(not parse_type(t).is_value for t, _ in outputs[:k]):
                return None  # the database returns a dynamic value there: decoded by hand, not as words
        except ValueError:
            return None
        returns = []
        for i in range(k):
            if validated.get(i):
                ty = validated[i]
                if ty == "address" and i < len(outputs) and outputs[i][0] == "uint160":
                    ty = "uint160"
            else:
                ty = outputs[i][0] if i < len(outputs) and outputs[i][0] in _FULL_WIDTH else "uint256"
                if not self.ctx.abi_v2 and ty not in _FULL_WIDTH:
                    ty = "uint256"
            returns.append(ty)
        # the code check: the target writes it for a function without return
        # values, after evaluating the operands; the original's check, made
        # before them, is that one only when no operand may end the call
        # (else it stays, and the target's own check never fails after it)
        target_checks = k == 0 or self.target < _CODE_CHECK_ONLY_WITHOUT_RETURNS
        if target_checks and guard is None:
            return None
        absorb = target_checks and guard is not None and _check(guard)[2] == ir.Empty() and not halting
        # (what still reads the return data after the call reads the same
        # buffer: the call is the last one made)
        cont_t = _replace_results(tuple(cont), cid, returns)
        used = {n.index for n in ir.walk_all(cont_t) if isinstance(n, ir.Result) and n.call_id == cid}
        out_names = _names(outputs, set()) if outputs and len(outputs) == k else [""] * k
        outs: List[Optional[str]] = []
        for i in range(k):
            if i not in used:
                outs.append(None)
            elif out_names[i]:
                outs.append(out_names[i])
            else:
                outs.append("result" if k == 1 else f"result{i}")
        value = None
        if s.kind == "call" and s.value is not None and s.value != ir.ZERO:
            value = s.value
        mutability = " view" if s.kind == "staticcall" else " payable" if value is not None else ""
        pnames = _names(plan.sig.inputs, set())
        params = ", ".join(t.canonical + (f" {n}" if n else "") for t, n in zip(plan.types, pnames))
        rets = f" returns ({', '.join(returns)})" if returns else ""
        decl = f"function {plan.sig.name}({params}) external{mutability}{rets};"
        iface = self.ifaces.name(selector, decl, _hint(s.to, self.spec))
        call = ir.HighCall(cid, s.kind, iface, plan.sig.name, s.to, value, s.gas, tuple(plan.args),
                           tuple(t.canonical for t in plan.types), tuple(returns), tuple(outs))
        self.changed = True
        self.counts["interface"] += 1
        return self._guarded(guard, nested, absorb, [call] + list(self.block(cont_t)))

    def low_level(self, s: ir.ExtCall, rest) -> ir.Stmt:
        if s.kind == "callcode" or s.ok is not None:
            return s
        cid = s.call_id
        whole = ir.ReturnData(cid, ir.ZERO, ir.CallOut(cid, "returndatasize"))
        ret = "ret" if _uses(rest, lambda n: n == whole) else None
        self.changed = True
        self.counts["low-level"] += 1
        return ir.ExtCall(s.call_id, s.kind, s.gas, s.to, s.value, s.selector, s.args, s.ret_words, "ok", ret)


# ---------------------------------------------------------------- the pass


def run(fn: ir.Function, ctx) -> ir.Function:
    if not ir.contains(fn.body, (ir.ExtCall, ir.Precompile)):
        return fn
    rw = _Rewriter(fn, ctx)
    body = rw.block(fn.body)
    if not rw.changed or body == fn.body:
        return fn
    new = fn.with_body(body)
    spec = rw.spec
    if spec is not None and spec.kind == "function" and spec.returns is None and ir.contains(body, ir.Result):
        # the function returns what a call returned: declare the return types
        returns = _abi.declared_returns(new, spec.db_returns)
        if returns is not None:
            spec.returns = returns
    return new


def finish(ctx) -> None:
    ifaces = (ctx.facts.get("calls") or {}).get("interfaces") or {}
    for name in sorted(ifaces):
        fns = ifaces[name]
        lines = [f"interface {name} {{"] + ["    " + fns[sel] for sel in sorted(fns)] + ["}"]
        ctx.declare("interface", "\n".join(lines))

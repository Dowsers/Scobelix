"""
Lifting: decompiler trace -> solgen IR (`ir.Function`).

Input vocabularies:

  raw   `Function.orig_trace`: after the VM, the loop structurer and the
        simplifier, before `cleanup_masks` and the storage sparser
        (`storage` / `store` with raw slot expressions, `cd` calldata).
  json  `Decompilation.json["functions"][i]["trace"]`: after the sparser
        (`stor` / `store` with `loc`/`name`/`map`/`array`/`length` paths,
        `param` names) and after `cleanup_masks` removed the masks of typed
        parameters.  Degraded: storage paths are mapped back to slots on a
        best-effort basis and the function is flagged `json_trace`.

Both are accepted with lists or tuples for nodes.  Every node kind of the
trace grammar has a handler (tables `_STATEMENTS` and `_EXPRESSIONS`); an
unknown shape becomes `Unstructured` / `UnstructuredExpr` / `UnstructuredBytes`
and flags the function: the lifter never raises and never drops a node.

ASSUMPTIONS ABOUT THE TRACE (update this list when the engine changes)
------------------------------------------------------------------------
Statements
  if/while/continue/label/setvar/store/setmem/tstore/log/call/staticcall/
  delegatecall/callcode/precompiled/create/create2/selfdestruct/return/
  revert/stop/invalid/undefined/require, plus bare strings (debug output,
  skipped) and `jd` markers (skipped).
  * `while C body JD init`: init setvars and continue setvars are PARALLEL
    assignments; the body never falls through; the statements after a
    while are its exit path.  Every loop variable, accumulators included,
    keeps its value after the loop: `var idx` after the `while` is its exit
    value (the engine replaces it by a closed form only where that is
    exact).
  * `label JD setvars` (a loop the structurer could not turn into a while)
    is followed by the loop body; its back-edges are `continue JD`.  It is
    lowered to `init; while (true) body` when some continue targets it.
  * `store size off slot val`: bits [off, off+size) of slot := val; an
    offset >= 256 (or negative) moves to slot + off // 256.
  * `setmem (range P L) V`: memory [P, P+L) := V; a word V gives its low L
    bytes (MSTORE: L = 32, MSTORE8: L = 1).
  * calls: `call gas to value None fargs`, `staticcall gas to 0 None
    fargs`, `delegatecall gas to None fargs`, `callcode gas to value None
    fargs`: fargs is the WHOLE payload (a byte string whose first 4 bytes
    are the selector; None when empty).  `gas` atom: all gas.
  * the output buffer of a `call` / `staticcall` is written right after it
    by `setmem (range P (min L returndatasize)) (ext_call.return_data 0
    (min L returndatasize))`: min(L, returndatasize) bytes, the rest of the
    buffer unchanged; where the code checks the size first the engine
    makes it the whole buffer, `setmem (range P L) (ext_call.return_data 0
    L)` (the shape every compiled high-level call has).  Both are plain
    memory writes of a return data slice.
  * `precompiled VAR FNAME ARGS` (addresses 1-3, 5-8), followed by uses of
    `("var", VAR)` (first output word) and the atom "<FNAME>.result".
  * empty return / revert data is `return None` / `revert None`; `return
    0` / `revert 0` are one zero word.
  * `require C LINE` (loop structurer): LINE runs when C is 0; it is the
    one line of the reverting branch, `revert PAYLOAD`, `revert None` or
    `invalid`.  A revert line gives Require(C, payload); any other line
    gives back the branch it came from, `if C: rest else LINE`.
  * read snapshots: the engine binds every read of mutable state whose
    value is used after a line that may change it with `setvar _N READ`
    at the place of the read, used as `var _N`
    (`_N` names are SSA; a storage word read for several fields gives one
    snapshot per field, `_N_<off>_<size>`).  READ is a storage word or
    field, `tload`, `balance` (`address` for SELFBALANCE), `extcodesize`,
    `extcodehash`, `returndatasize`, a call success (`ext_call.success`,
    `callcode.return_code`, `var delegatecall_K.success`), a created
    address, a precompile output (`var signer`, `<name>.result`) or an
    expression of them; every other read is inlined where it is used and
    means its value at that line.  Snapshots are lifted as locals assigned
    where the trace reads them (`t<N>`, `t<N>_<off>_<size>`) and never
    re-evaluated at their uses.
Expressions
  * ints are words modulo 2**256 (negative: two's complement); ints wider
    than a word only occur as copied code (`codecopy`) in byte contexts.
    PUSH arguments stay ints (the text printer alone shows printable ones
    as strings).
  * le/ge/sle/sge/bool are negations made by the simplifier; max comes
    from msize handling and `min a b` (the unsigned minimum) from the call
    output copy: both are lowered to a `Ternary`.  `sar k x`, `addmod a b
    m`, `mulmod a b m`, `shl`, `shr`, `sub`, `byte` are plain EVM ops (a
    symbolic BYTE index gives `byte i x`, a constant one a mask).
    `undefined REASON` ends a path (a pruned branch, an unsupported opcode,
    a stack underflow...) and is lifted as an Unstructured statement /
    expression.
  * `mask_shl size off shl x` as `ir.Mask` (the engine's SHR, mask_shl(256
    - k, k, -k, x), is exact as it is); a negative offset is unexpected
    (flag `engine:negative_mask_offset`, kept exact as a Mask).
  * `storage 256 0 (length K)` (raw traces of legacy string / bytes code):
    the simplifier's name for the decoded length, (W & (W & 1 ? 2**256 - 1
    : 0xff)) >> 1 with W = sload(K) (it replaced solc's
    `and(W, mul(256, iszero(and(W, 1))) - 1) / 2`); lifted as that
    expression.
  * `storage size off slot`: (sload(slot') >> off') & (2**size - 1), off
    folded into slot' = slot + off // 256 like stores.
  * call results: `ext_call.success`, `ext_call.return_data`,
    `create(2).new_address`, `callcode.return_code`, `<precompile>.result`,
    `("var", "delegatecall_N.success")` are bound to the most recent such
    statement on the path (which is what they mean: the engine snapshots
    them when a later call could be confused with it);
    `returndatasize` and return data slices read the current return data
    buffer (exact as long as the generated code makes the same calls in
    the same order, which it does).
  * `("delegate.return_data", ADDR, LEN)`: the 2nd field is the target, the
    offset is 0.
  * `data e1 ... en` is a concatenation of elements of explicit widths:
    every element is a 32-byte word, a slice (its length) or `bytes W V`
    (the low W bytes of V, a word or a byte string, zero padded on the left
    when W is larger); a 4-byte selector is `bytes 4 SEL`.  A `mask_shl`
    of a byte string longer than a word or of symbolic length (memory a
    copy wrote, read back across its ends) keeps all the bits of the string
    (`ir.MaskBytes`, never cut to 256 bits).  `arr L
    payload` (rewriter) replaced the head offset of one dynamic value and
    moved its tail: it expands to the offset word, L, the payload and its
    zero padding (flag `arr_expanded`).

Flags the lifter sets (ir.Function.flags; the generator adds signature_rejected,
signature_name_reserved, problem, dispatcher_inconsistent, dispatcher_duplicate,
abi:short_calldata_check, abi:legacy_memory_copy, abi:callvalue_check_invalid,
time_limited - the decompiler stopped simplifying the trace at its time limit:
exact, not fully simplified;
the storage pass adds engine:packed_store_suspect, a packed store that cuts
the recovered variables):
  unstructured                  a node had no translation (rendered as a revert)
  loop_exit_unstructured        a continue to a loop that does not enclose it
  label_lowered                 an unstructured loop head became while (true)
  engine:negative_mask_offset   a mask_shl with a negative offset
  engine:dangling_var           a variable read before any assignment on its path
  arr_expanded                  an ABI dynamic value rebuilt from an `arr` node
  codecopy_blob                 a constant wider than a word (copied code)
  code_unknown                  a copy of the original code without that code (read as zeros)
  wide_int                     an int wider than a word in a word position
  json_trace, json_storage_ambiguous  lifted from the JSON trace (degraded)
"""

from __future__ import annotations

import dataclasses
import logging
import re
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from scobelix.solgen import ir

logger = logging.getLogger(__name__)

__all__ = ["LiftContext", "lift_function", "make_context"]

ERROR_SELECTOR = 0x08C379A0
PANIC_SELECTOR = 0x4E487B71

_PRECOMPILE_VARS = frozenset({"signer", "hash", "mod_exp", "bn_add", "bn_scalar_mul", "bn_pairing"})
_BYTE_SLICES = ("call.data", "ext_call.return_data", "delegate.return_data", "callcode.return_data",
                "code.data", "mem", "extcodecopy", "data", "arr", "bytes")
# constant byte strings longer than this are not built (hostile lengths)
_MAX_CONST_BYTES = 1 << 20


# ---------------------------------------------------------------- context


@dataclasses.dataclass(frozen=True)
class LiftContext:
    """Contract-level facts the lifter needs (see make_context)."""

    code: bytes = b""  # original runtime code, metadata included
    push32_narrow: FrozenSet[int] = frozenset()  # values < 2**248 pushed by PUSH32 (immutables)
    vocabulary: str = "raw"  # raw | json
    array_bases: FrozenSet[int] = frozenset()  # json: slots used as dynamic array bases


def _disassemble(code: bytes):
    """(pc, opcode, push argument or None) of the code before its metadata."""
    from scobelix.utils.metadata import parse_metadata

    md = parse_metadata(code)
    end = md.start if md is not None else len(code)
    pc, out = 0, []
    while pc < end:
        op = code[pc]
        if 0x60 <= op <= 0x7F:
            n = op - 0x5F
            out.append((pc, op, int.from_bytes(code[pc + 1 : pc + 1 + n].ljust(n, b"\0"), "big")))
            pc += 1 + n
        else:
            out.append((pc, op, 0 if op == 0x5F else None))
            pc += 1
    return out


def make_context(bytecode, vocabulary: str = "raw", array_bases: Iterable[int] = ()) -> LiftContext:
    """LiftContext for the runtime `bytecode` (hex string or bytes)."""
    if isinstance(bytecode, str):
        h = bytecode[2:] if bytecode.startswith("0x") else bytecode
        code = bytes.fromhex(h)
    else:
        code = bytes(bytecode or b"")
    narrow = {arg for _pc, op, arg in (_disassemble(code) if code else []) if op == 0x7F and arg < 1 << 248}
    return LiftContext(code=code, push32_narrow=frozenset(narrow), vocabulary=vocabulary,
                       array_bases=frozenset(array_bases))


# ---------------------------------------------------------------- helpers


def _is_seq(x) -> bool:
    return isinstance(x, (list, tuple))


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _head(x) -> Optional[str]:
    return x[0] if _is_seq(x) and x and isinstance(x[0], str) else None


def _short(x, limit=160) -> str:
    s = repr(x)
    return s if len(s) <= limit else s[: limit - 3] + "..."


def loop_id(jd) -> str:
    """Stable id of a loop head (`Node((pc, ...))` text, or anything else)."""
    return str(jd)


def _neg_of(x):
    """s when x is the trace's negation mul(-1, s), else None."""
    if _head(x) == "mul" and len(x) == 3 and _is_int(x[1]) and x[1] in (-1, ir.WORD_MAX):
        return x[2]
    return None


@dataclasses.dataclass(frozen=True)
class _Path:
    """What the lifter knows on the current path."""

    last: Dict[str, int] = dataclasses.field(default_factory=dict)  # kind -> call_id
    precompile_out: Dict[str, str] = dataclasses.field(default_factory=dict)  # var -> local
    assigned: FrozenSet[str] = frozenset()  # locals assigned on this path
    loops: Tuple[str, ...] = ()

    def but(self, **kw) -> "_Path":
        return dataclasses.replace(self, **kw)

    def with_call(self, kinds: Sequence[str], call_id: int) -> "_Path":
        last = dict(self.last)
        for k in kinds:
            last[k] = call_id
        return self.but(last=last)


# ---------------------------------------------------------------- the lifter


class _Lifter:
    def __init__(self, ctx: LiftContext, params: Optional[Dict[str, object]] = None):
        self.ctx = ctx
        # json vocabulary: parameter name -> calldata offset, or (offset, ABI type)
        self.params: Dict[str, Tuple[int, str]] = {}
        for name, v in (params or {}).items():
            self.params[name] = tuple(v) if isinstance(v, (list, tuple)) else (v, "uint256")
        self.flags = set()
        self.next_call = 0

    # ------------------------------------------------------------ blocks

    def block(self, lines, path: _Path) -> Tuple[ir.Stmt, ...]:
        lines = list(lines) if _is_seq(lines) else [lines]
        out: List[ir.Stmt] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            head = _head(line)
            if isinstance(line, str) or head == "jd":
                i += 1
                continue
            if head == "label":
                stmts, path = self.label(line, lines[i + 1 :], path)
                out.extend(stmts)
                return tuple(out)
            if head == "require" and len(line) > 2 and _head(line[2]) != "revert":
                out.extend(self.require_branch(line, lines[i + 1 :], path))
                return tuple(out)
            handler = _STATEMENTS.get(head)
            if handler is None:
                out.append(self.unstructured(line, f"unknown statement {head!r}"))
                i += 1
                continue
            try:
                stmts, path = handler(self, line, path)
            except Exception as e:  # noqa: BLE001 - malformed node: keep it, flagged
                logger.debug("lift failed on %s", _short(line), exc_info=True)
                stmts = [self.unstructured(line, f"{type(e).__name__}: {e}")]
            out.extend(stmts)
            i += 1
        return tuple(out)

    def unstructured(self, raw, reason: str) -> ir.Unstructured:
        self.flags.add("unstructured")
        return ir.Unstructured(_short(raw), reason)

    # ------------------------------------------------------------ statements

    def st_if(self, line, path):
        _, cond, then, orelse = line
        return [ir.If(self.cond(cond, path), self.block(then, path), self.block(orelse, path))], path

    def st_while(self, line, path):
        _, cond, body, jd, init = line[:5]
        lid = loop_id(jd)
        assigns = self.setvars(init, path)
        inner = path.but(loops=path.loops + (lid,), assigned=path.assigned | {a.target.name for a in assigns})
        stmt = ir.While(self.cond(cond, inner), self.block(body, inner), assigns, lid)
        return [stmt], inner.but(loops=path.loops)

    def st_continue(self, line, path):
        _, jd, setvars = line[:3]
        lid = loop_id(jd)
        if lid not in path.loops:
            self.flags.add("loop_exit_unstructured")  # (a loop that encloses it: the renderer leaves the inner ones)
        return [ir.Continue(lid, self.setvars(setvars, path))], path

    def label(self, line, rest, path):
        """`label JD setvars` + the rest of the block (the loop body)."""
        jd, setvars = line[1], line[2] if len(line) > 2 else ()
        lid = loop_id(jd)
        assigns = self.setvars(setvars, path)
        if not _targets(rest, lid):  # a plain marker: no back-edge to it
            path = path.but(assigned=path.assigned | {a.target.name for a in assigns})
            return list(assigns) + list(self.block(rest, path)), path
        self.flags.add("label_lowered")
        inner = path.but(loops=path.loops + (lid,), assigned=path.assigned | {a.target.name for a in assigns})
        return [ir.While(ir.ONE, self.block(rest, inner), assigns, lid)], path

    def setvars(self, setvars, path) -> Tuple[ir.Assign, ...]:
        out = []
        for sv in setvars or ():
            if _head(sv) == "setvar" and len(sv) == 3:
                out.append(ir.Assign(ir.Local(self.local_name(sv[1])), self.expr(sv[2], path)))
            else:
                self.flags.add("unstructured")
                out.append(ir.Assign(ir.Local("_unstructured"), ir.UnstructuredExpr(_short(sv), "bad setvar")))
        return tuple(out)

    def st_setvar(self, line, path):
        _, var, value = line[:3]
        name = self.local_name(var)
        stmt = ir.Assign(ir.Local(name), self.expr(value, path))
        return [stmt], path.but(assigned=path.assigned | {name})

    def st_store(self, line, path):
        _, size, off, slot, value = line[:5]
        slot_e = self.slot(slot, path)
        size_e = size if _is_int(size) else self.expr(size, path)
        if _is_int(off):
            k, o = divmod(off, 256)
            if k:
                slot_e = ir.Op("add", (slot_e, ir.const(k)))
            off_e = o
        else:
            off_e = self.expr(off, path)
        return [ir.Sstore(slot_e, self.expr(value, path), off_e, size_e)], path

    def st_setmem(self, line, path):
        _, rng, value = line[:3]
        if _head(rng) != "range":
            return [self.unstructured(line, "setmem without range")], path
        _, start, length = rng[:3]
        data = self.mem_value(value, length, path)
        return [ir.Mstore(self.expr(start, path), data)], path

    def st_tstore(self, line, path):
        _, slot, value = line[:3]
        return [ir.TStore(self.expr(slot, path), self.expr(value, path))], path

    def st_log(self, line, path):
        data = line[1] if len(line) > 1 else None
        topics = tuple(self.expr(t, path) for t in line[2:])
        if len(topics) > 4:
            return [self.unstructured(line, "more than 4 topics")], path
        return [ir.Log(topics, self.bytes_(data, path, "log") if data is not None else None)], path

    def st_call(self, line, path):
        kind = line[0]
        if kind == "delegatecall":
            _, gas, to, fname, fargs = line[:5]
            value = None
        else:
            _, gas, to, value, fname, fargs = line[:6]
        if fname is not None:
            return [self.unstructured(line, "call payload split in two")], path
        cid = self.new_call()
        stmt = ir.ExtCall(
            call_id=cid,
            kind=kind,
            gas=None if gas == "gas" else self.expr(gas, path),
            to=self.expr(to, path),
            value=None if kind in ("staticcall", "delegatecall") else self.expr(value, path),
            args=self.bytes_(fargs, path, "call_args") if fargs is not None else None,
        )
        keys = ("buffer", kind) + (("ext",) if kind in ("call", "staticcall") else ())
        return [stmt], path.with_call(keys, cid)

    def st_precompiled(self, line, path):
        _, var, fname, args = line[:4]
        if fname not in ir.PRECOMPILES:
            return [self.unstructured(line, f"unknown precompile {fname!r}")], path
        cid = self.new_call()
        out = f"{self.local_name(var)}_{cid}"
        stmt = ir.Precompile(cid, ir.PRECOMPILES[fname], fname, self.bytes_(args, path, "precompile"), out)
        outs = dict(path.precompile_out)
        outs[str(var)] = out
        path = path.with_call(("buffer", "precompile:" + fname), cid).but(precompile_out=outs)
        return [stmt], path

    def st_create(self, line, path):
        kind = line[0]
        value, code = line[1], line[2]
        salt = line[3] if kind == "create2" and len(line) > 3 else None
        cid = self.new_call()
        stmt = ir.Create(cid, self.expr(value, path), self.bytes_(code, path, "create_code"),
                         self.expr(salt, path) if salt is not None else None)
        return [stmt], path.with_call(("buffer", kind), cid)

    def st_selfdestruct(self, line, path):
        return [ir.SelfDestruct(self.expr(line[1], path))], path

    def st_return(self, line, path):
        data = line[1] if len(line) > 1 else None
        if data is None:
            return [ir.Return()], path
        return [ir.Return(self.bytes_(data, path, "return"))], path

    def st_revert(self, line, path):
        data = line[1] if len(line) > 1 else None
        return [ir.Revert(self.revert_payload(data, path))], path

    def st_stop(self, line, path):
        return [ir.Stop()], path

    def st_invalid(self, line, path):
        return [ir.Invalid(str(line[1]) if len(line) > 1 else "")], path

    def st_undefined(self, line, path):
        return [self.unstructured(line, str(line[1]) if len(line) > 1 else "undefined")], path

    def st_require(self, line, path):
        """`require C LINE`: LINE, a revert, runs when C is 0 (the other
        kinds of LINE go through require_branch)."""
        if len(line) < 3:
            return [self.unstructured(line, "require without its revert line")], path
        cond = self.cond(line[1], path)
        on_fail = line[2]
        return [ir.Require(cond, self.revert_payload(on_fail[1] if len(on_fail) > 1 else None, path))], path

    def require_branch(self, line, rest, path) -> List[ir.Stmt]:
        """`require C LINE` + the rest of the block, when LINE is not a
        revert (`invalid`): the branch the structurer folded, `if C: rest
        else LINE`."""
        cond = self.cond(line[1], path)
        return [ir.If(cond, self.block(rest, path), self.block([line[2]], path))]

    # ------------------------------------------------------------ words

    def new_call(self) -> int:
        self.next_call += 1
        return self.next_call

    def local_name(self, var) -> str:
        if _is_int(var):
            return f"v{var}" if var >= 0 else f"vm{-var}"
        s = str(var)
        if re.fullmatch(r"_\d+(_\d+)*", s):
            return "t" + s[1:]  # the engine's temporaries _N (snapshots split by field: _N_<off>_<size>)
        s = re.sub(r"[^A-Za-z0-9_]", "_", s)
        return s if re.match(r"[A-Za-z_]", s) else "v_" + s

    def cond(self, e, path) -> ir.Expr:
        return self.expr(e, path)

    def expr(self, e, path) -> ir.Expr:
        if isinstance(e, bool):
            return ir.ONE if e else ir.ZERO
        if _is_int(e):
            if e >= ir.WORD_MOD or e < -ir.WORD_MOD:
                self.flags.add("wide_int")
            return ir.const(e)
        if isinstance(e, str):
            return self.atom(e, path)
        head = _head(e)
        if head is None:
            self.flags.add("unstructured")
            return ir.UnstructuredExpr(_short(e), "not an expression")
        handler = _EXPRESSIONS.get(head)
        if handler is None:
            self.flags.add("unstructured")
            return ir.UnstructuredExpr(_short(e), f"unknown expression {head!r}")
        try:
            return handler(self, e, path)
        except Exception as exc:  # noqa: BLE001 - malformed node: keep it, flagged
            logger.debug("lift failed on %s", _short(e), exc_info=True)
            self.flags.add("unstructured")
            return ir.UnstructuredExpr(_short(e), f"{type(exc).__name__}: {exc}")

    def atom(self, name: str, path) -> ir.Expr:
        if name in ir.ENV_NAMES:
            return ir.Env(name)
        if name == "returndatasize":
            return ir.CallOut(path.last.get("buffer", 0), "returndatasize")
        if name == "ext_call.success":
            return self.call_out(path, "ext", "success", name)
        if name in ("create.new_address", "create2.new_address"):
            return self.call_out(path, name.split(".")[0], "address", name)
        if name == "callcode.return_code":
            return self.call_out(path, "callcode", "success", name)
        if name.endswith(".result") and name[: -len(".result")] in ir.PRECOMPILES:
            return self.call_out(path, "precompile:" + name[: -len(".result")], "success", name)
        if name == "memcopy.success":
            return ir.ONE
        self.flags.add("unstructured")
        return ir.UnstructuredExpr(name, "unknown atom")

    def call_out(self, path, kind, what, raw) -> ir.Expr:
        cid = path.last.get(kind)
        if cid is None:
            self.flags.add("unstructured")
            return ir.UnstructuredExpr(raw, "call result without a call on the path")
        return ir.CallOut(cid, what)

    def e_var(self, e, path):
        var = e[1]
        if isinstance(var, str):
            if var.startswith("delegatecall_") and var.endswith(".success"):
                return self.call_out(path, "delegatecall", "success", var)
            if var in _PRECOMPILE_VARS:
                local = path.precompile_out.get(var)
                if local is None:
                    self.flags.add("unstructured")
                    return ir.UnstructuredExpr(_short(e), "precompile output without a call")
                return ir.Local(local)
        name = self.local_name(var)
        if name not in path.assigned:
            self.flags.add("engine:dangling_var")
        return ir.Local(name)

    def e_cd(self, e, path):
        return ir.CalldataWord(self.expr(e[1], path))

    def e_param(self, e, path):
        """json: the decompiler's cleanup_masks dropped the cleanup of typed
        parameters (mask_shl(N, 0, 0, cd) / bool(cd) -> cd): put it back."""
        p = self.params.get(e[1])
        if p is None:
            self.flags.add("unstructured")
            return ir.UnstructuredExpr(_short(e), "unknown parameter")
        word = ir.CalldataWord(ir.const(p[0]))
        return _cleanup(word, p[1]) or word

    def json_validator(self, e) -> Optional[ir.Expr]:
        """json: `iszero(eq(p, p))` is what cleanup_masks left of the ABI
        decoder's validator iszero(eq(cd, cleanup(cd))): rebuild it."""
        if _head(e) == "iszero" and len(e) == 2 and _head(e[1]) == "eq" and len(e[1]) == 3:
            a, b = e[1][1], e[1][2]
            if a == b and _head(a) == "param" and a[1] in self.params:
                off, ty = self.params[a[1]]
                word = ir.CalldataWord(ir.const(off))
                clean = _cleanup(word, ty)
                if clean is not None:
                    return ir.Op("iszero", (ir.Op("eq", (word, clean)),))
        return None

    def e_storage(self, e, path):
        _, size, off, slot = e[:4]
        if self.ctx.vocabulary == "raw" and _head(slot) == "length" and len(slot) == 2:
            return self.string_length(slot[1], size, off, path)
        slot_e = self.slot(slot, path)
        return self.field_read(slot_e, size, off, path)

    def string_length(self, key, size, off, path) -> ir.Expr:
        """`storage size off (length K)`: the simplifier's name for the
        length the legacy code decodes from the bytes / string slot K,
        (W & (W & 1 ? 2**256 - 1 : 0xff)) >> 1 with W = sload(K) (bits
        [off, off + size) of it)."""
        if _head(key) in ("loc", "name") and _is_int(key[-1]):
            slot_e = ir.const(key[-1])  # the slot itself (as `length` does below)
        else:
            slot_e = self.json_slot(key, path)
        word = self.field_read(slot_e, 256, 0, path)
        low = ir.Field(word, 0, 1)
        keep = ir.Op("add", (ir.Op("shl", (ir.const(8), ir.Op("iszero", (low,)))), ir.const(ir.WORD_MAX)))
        length = ir.Op("shr", (ir.ONE, ir.Op("and", (word, keep))))
        if not (_is_int(size) and _is_int(off)):
            return ir.Field(length, off if _is_int(off) else self.expr(off, path),
                            size if _is_int(size) else self.expr(size, path))
        if (size, off) == (256, 0):
            return length
        return ir.Field(length, off, size)

    def field_read(self, slot_e, size, off, path):
        if _is_int(off):
            k, o = divmod(off, 256)
            if k:
                slot_e = ir.Op("add", (slot_e, ir.const(k)))
            off_e = o
        else:
            off_e = self.expr(off, path)
        value = ir.Sload(slot_e)
        size_e = size if _is_int(size) else self.expr(size, path)
        if size_e == 256 and off_e == 0:
            return value
        return ir.Field(value, off_e, size_e)

    def slot(self, s, path) -> ir.Expr:
        """A storage slot from the raw or json vocabulary."""
        head = _head(s)
        if self.ctx.vocabulary == "json" or head in ("loc", "name", "map", "array", "length"):
            return self.json_slot(s, path)
        return self.expr(s, path)

    def json_slot(self, s, path) -> ir.Expr:
        head = _head(s)
        if head in ("loc", "name"):
            n = s[-1]
            if _is_int(n):
                if n in self.ctx.array_bases:
                    return ir.Keccak(ir.WordBytes(ir.const(n)))
                return ir.const(n)
            return self.expr(n, path)
        if head == "length":
            base = s[1]
            if _head(base) in ("loc", "name") and _is_int(base[-1]):
                return ir.const(base[-1])
            return self.json_slot(base, path)
        if head == "map":
            key, base = s[1], s[2]
            if _head(key) == "data" and len(key) == 2:
                key_e = ir.Keccak(self.bytes_(key[1], path, "keccak"))
            else:
                key_e = self.expr(key, path)
            return ir.Keccak(ir.Blob((ir.WordBytes(key_e), ir.WordBytes(self.json_slot(base, path)))))
        if head == "array":
            idx, base = s[1], s[2]
            self.flags.add("json_storage_ambiguous")
            b = base
            if _head(b) in ("loc", "name") and _is_int(b[-1]):
                start = ir.Keccak(ir.WordBytes(ir.const(b[-1])))
            else:
                start = ir.Keccak(ir.WordBytes(self.json_slot(b, path)))
            return ir.Op("add", (start, self.expr(idx, path)))
        return self.expr(s, path)

    def e_stor(self, e, path):
        self.flags.add("json_trace")
        _, size, off, p = e[:4]
        return self.field_read(self.json_slot(p, path), size, off, path)

    def mask_fields(self, e, path) -> List[object]:
        """size, offset and shl of `mask_shl size off shl x`."""
        _, size, off, shl = e[:4]
        if _is_int(off) and off < 0:
            self.flags.add("engine:negative_mask_offset")
        fields = []
        for f in (size, off, shl):
            if _is_int(f):
                fields.append(f)
            elif _neg_of(f) is not None:
                fields.append(ir.Op("sub", (ir.ZERO, self.expr(_neg_of(f), path))))
            else:
                fields.append(self.expr(f, path))
        return fields

    def e_mask(self, e, path):
        masked = self.masked_bytes(e, path, ir.Const(32))
        if masked is not None:
            return ir.BytesWord(masked)  # a word: the low 32 bytes of the masked byte string
        fields = self.mask_fields(e, path)
        return ir.Mask(fields[0], fields[1], fields[2], self.expr(e[4], path))

    def byte_string(self, x, path, context: str) -> Optional[ir.Bytes]:
        """`x` as a byte string when it is a slice or a concatenation whose
        length is symbolic or more than 32 bytes, else None (a shorter one
        is a word: BytesWord)."""
        if _head(x) not in _BYTE_SLICES:
            return None
        b = self.bytes_(x, path, context)
        n = ir.byte_length(b)
        v = ir.evaluate(n) if n is not None else None
        return None if v is not None and v <= 32 else b

    def masked_bytes(self, e, path, length: ir.Expr) -> Optional[ir.Bytes]:
        """`mask_shl size off shl X` of a byte string X (byte_string) as
        `length` bytes: the bits of all of X, never cut to a word (the
        engine reads memory written by a copy of a symbolic length that
        way); None for any other node."""
        if _head(e) != "mask_shl" or len(e) < 5:
            return None
        data = self.byte_string(e[4], path, "mask")
        if data is None:
            return None
        size, off, shl = self.mask_fields(e, path)
        return ir.mask_bytes(size, off, shl, data, length)

    def e_op(self, e, path):
        if self.ctx.vocabulary == "json":
            v = self.json_validator(e)
            if v is not None:
                return v
        op = e[0]
        args = tuple(self.expr(a, path) for a in e[1:])
        if op in ("add", "mul", "and", "or", "xor") and len(args) == 1:
            return args[0]
        return ir.Op(op, args)

    def e_synthetic(self, e, path):
        op = e[0]
        a, b = self.expr(e[1], path), self.expr(e[2], path)
        base = {"le": "gt", "ge": "lt", "sle": "sgt", "sge": "slt"}[op]
        return ir.Op("iszero", (ir.Op(base, (a, b)),))

    def e_bool(self, e, path):
        return ir.Op("iszero", (ir.Op("iszero", (self.expr(e[1], path),)),))

    def e_max(self, e, path):
        args = [self.expr(a, path) for a in e[1:]]
        res = args[0]
        for a in args[1:]:
            res = ir.Ternary(ir.Op("gt", (a, res)), a, res)
        return res

    def e_min(self, e, path):
        """`min a b`: the unsigned minimum (the call output copy's length)."""
        args = [self.expr(a, path) for a in e[1:]]
        res = args[0]
        for a in args[1:]:
            res = ir.Ternary(ir.Op("lt", (a, res)), a, res)
        return res

    def e_sha3(self, e, path):
        return ir.Keccak(self.bytes_(e[1], path, "keccak"))

    def e_query(self, e, path):
        cls = {"balance": ir.Balance, "extcodesize": ir.ExtCodeSize, "extcodehash": ir.ExtCodeHash,
               "blockhash": ir.BlockHash, "blobhash": ir.BlobHash, "tload": ir.TLoad}[e[0]]
        return cls(self.expr(e[1], path))

    def e_bytes_word(self, e, path):
        """A byte string used as a word (a 4-byte selector, a 32-byte read)."""
        if _head(e) == "mem" and _head(e[1]) == "range" and e[1][2] == 32:
            return ir.MLoad(self.expr(e[1][1], path))
        if _head(e) == "bytes" and len(e) == 3 and _is_int(e[1]) and 0 < e[1] <= 32 \
                and _head(e[2]) not in _BYTE_SLICES:
            # the low W bytes of a word, as a number
            word = self.expr(e[2], path)
            return word if e[1] == 32 else ir.Mask(8 * e[1], 0, 0, word)
        b = self.bytes_(e, path, "word")
        n = ir.evaluate(ir.byte_length(b)) if ir.byte_length(b) is not None else None
        if n is None or n > 32:
            self.flags.add("unstructured")
            return ir.UnstructuredExpr(_short(e), "byte string of unknown or > 32 length used as a word")
        return ir.BytesWord(b)

    def e_undefined(self, e, path):
        self.flags.add("unstructured")
        return ir.UnstructuredExpr(_short(e), str(e[1]) if len(e) > 1 else "undefined")

    # ------------------------------------------------------------ bytes

    def mem_value(self, value, length, path) -> ir.Bytes:
        """What `setmem (range P length) value` writes."""
        if _head(value) in _BYTE_SLICES:
            return self.bytes_(value, path, "mem")
        if _head(value) == "mask_shl":
            # the low `length` bytes of a masked byte string
            n = ir.const(length) if _is_int(length) else self.expr(length, path)
            masked = self.masked_bytes(value, path, n)
            if masked is not None:
                return masked
        if _is_int(length):
            if length > _MAX_CONST_BYTES:  # (no integer of that many bits is built)
                self.flags.add("unstructured")
                return ir.UnstructuredBytes(_short(value), "memory write of a huge constant length")
            if _is_int(value) and (value >= ir.WORD_MOD or length > 32):
                self.flags.add("codecopy_blob")
                v = value % (1 << (8 * length)) if length else 0
                return ir.ConstBytes(v.to_bytes(length, "big"))
            if 1 <= length <= 32:
                return ir.WordBytes(self.expr(value, path), length)
            if length == 0:
                return ir.Blob(())
        if value == 0:
            return ir.ZeroBytes(self.expr(length, path))
        self.flags.add("unstructured")
        return ir.UnstructuredBytes(_short(value), "word written over a symbolic length")

    def bytes_(self, e, path, context: str) -> ir.Bytes:
        """A byte string from a payload / memory / slice node."""
        head = _head(e)
        if head == "data":
            return self.blob(e[1:], path, context)
        if head == "arr":
            return self.blob((e,), path, context)
        if head == "bytes":
            return self.sized(e, path, context)
        if head == "call.data":
            _, start, length = e[:3]
            if start == "calldatasize":
                return ir.ZeroBytes(self.expr(length, path))
            return ir.CalldataSlice(self.expr(start, path), self.expr(length, path))
        if head == "mem":
            rng = e[1]
            if _head(rng) == "range":
                return ir.MemSlice(self.expr(rng[1], path), self.expr(rng[2], path))
        if head == "ext_call.return_data":
            return ir.ReturnData(path.last.get("buffer", 0), self.expr(e[1], path), self.expr(e[2], path))
        if head == "delegate.return_data":
            return ir.ReturnData(path.last.get("delegatecall", 0), ir.ZERO, self.expr(e[2], path))
        if head == "callcode.return_data":
            return ir.ReturnData(path.last.get("callcode", 0), self.expr(e[1], path), self.expr(e[2], path))
        if head == "code.data":
            start, length = self.expr(e[1], path), self.expr(e[2], path)
            s, n = ir.evaluate(start), ir.evaluate(length)
            if not self.ctx.code:
                self.flags.add("code_unknown")
            if s is not None and n is not None and n <= 1 << 16:
                return ir.ConstBytes(self.ctx.code[s : s + n].ljust(n, b"\0"))
            return ir.CodeSlice(start, length)
        if head == "extcodecopy":
            rng = e[2]
            return ir.ExtCodeSlice(self.expr(e[1], path), self.expr(rng[1], path), self.expr(rng[2], path))
        if _is_int(e) and (e >= ir.WORD_MOD):
            self.flags.add("codecopy_blob")
            return ir.ConstBytes(e.to_bytes((e.bit_length() + 7) // 8, "big"))
        # one word read back whole: no slicing, so no shift artifact either
        return ir.WordBytes(self.expr(e, path))

    def sized(self, e, path, context) -> ir.Bytes:
        """`bytes W V` (explicit widths): the low W bytes of V, a word or a
        byte string, zero padded on the left when W is larger."""
        if len(e) != 3:
            self.flags.add("unstructured")
            return ir.UnstructuredBytes(_short(e), "malformed bytes node")
        width, value = e[1], e[2]
        if not _is_int(width):
            if value == 0 or value is None:
                return ir.ZeroBytes(self.expr(width, path))
            w = self.expr(width, path)
            masked = self.masked_bytes(value, path, w)
            if masked is not None:
                return masked
            if _head(value) not in _BYTE_SLICES:
                return ir.WordSlice(self.expr(value, path), w)
            # the last W bytes of a byte string (zero bytes on the left past it)
            return ir.mask_bytes(None, 0, 0, self.bytes_(value, path, context), w)
        if width <= 0:
            return ir.Blob(())
        if value == 0 or value is None:
            return ir.ZeroBytes(ir.const(width))
        if _head(value) in _BYTE_SLICES:
            inner = self.bytes_(value, path, context)
            n = ir.evaluate(ir.byte_length(inner)) if ir.byte_length(inner) is not None else None
            if n == width:
                return inner
            if n is not None and n < width:
                rest = inner.parts if isinstance(inner, ir.Blob) else (inner,)
                return ir.Blob((ir.ZeroBytes(ir.const(width - n)),) + tuple(rest))
            if n is not None and n <= 32:
                return ir.WordBytes(ir.BytesWord(inner), width)
            if ir.byte_length(inner) is None:
                self.flags.add("unstructured")
                return ir.UnstructuredBytes(_short(e), "last bytes of a byte string of unknown length")
            return ir.mask_bytes(None, 0, 0, inner, ir.const(width))
        masked = self.masked_bytes(value, path, ir.const(width))
        if masked is not None:
            return masked
        if _is_int(value) and value >= ir.WORD_MOD:
            if width > _MAX_CONST_BYTES:
                self.flags.add("unstructured")
                return ir.UnstructuredBytes(_short(e), "constant of a huge width")
            return ir.ConstBytes((value % (1 << (8 * width))).to_bytes(width, "big"))
        word = self.expr(value, path)
        if width <= 32:
            return ir.WordBytes(word, width)
        return ir.Blob((ir.ZeroBytes(ir.const(width - 32)), ir.WordBytes(word)))

    def blob(self, items, path, context: str) -> ir.Bytes:
        parts: List[ir.Bytes] = []
        head_words = len(items)  # the rewriter counted every element as a head word
        tails: List[ir.Bytes] = []
        for x in items:
            if _head(x) == "data":
                inner = self.blob(x[1:], path, context)
                parts.extend(inner.parts if isinstance(inner, ir.Blob) else (inner,))
                continue
            if _head(x) == "arr":
                self.flags.add("arr_expanded")
                parts.append(ir.WordBytes(ir.const(32 * head_words)))
                tails.extend(self.arr_tail(x, path, context))
                continue
            p = self.part(x, path, context)
            parts.extend(p.parts if isinstance(p, ir.Blob) else (p,))
        return ir.Blob(tuple(parts + tails))

    def arr_tail(self, x, path, context) -> List[ir.Bytes]:
        """`arr L payload...`: L, the payload, zero padding to 32 bytes."""
        length = self.expr(x[1], path)
        out: List[ir.Bytes] = [ir.WordBytes(length)]
        payload = [self.part(p, path, context) for p in x[2:]]
        out.extend(payload)
        if len(payload) == 1 and isinstance(payload[0], (ir.CalldataSlice, ir.MemSlice, ir.ReturnData,
                                                          ir.CodeSlice, ir.ExtCodeSlice)):
            # an unpadded slice: the ABI pads its bytes to a multiple of 32.  Its
            # own length counts, not L: L elements of a word array are 32 L
            # bytes, which take no padding
            size = payload[0].length
            out.append(ir.ZeroBytes(ir.Op("and", (ir.Op("sub", (ir.ZERO, size)), ir.Const(31)))))
        return out

    def part(self, x, path, context) -> ir.Bytes:
        head = _head(x)
        if head in _BYTE_SLICES:
            return self.bytes_(x, path, context)
        masked = self.masked_bytes(x, path, ir.Const(32))
        if masked is not None:
            return masked  # a word part: the low 32 bytes
        if _is_int(x) and x >= ir.WORD_MOD:
            self.flags.add("codecopy_blob")
            return ir.ConstBytes(x.to_bytes((x.bit_length() + 7) // 8, "big"))
        return ir.WordBytes(self.expr(x, path))

    # ------------------------------------------------------------ reverts

    def revert_payload(self, data, path) -> ir.Payload:
        if data is None:
            return ir.Empty()
        if _head(data) == "bytes" and len(data) == 3 and data[1] == 4:
            sel = ir.evaluate(self.expr(data[2], path))
            if sel is not None:
                return ir.Custom(sel % (1 << 32))
        head = _head(data)
        if head in ("ext_call.return_data", "delegate.return_data") and _is_full_returndata(data):
            kind = "buffer" if head == "ext_call.return_data" else "delegatecall"
            return ir.Bubble(path.last.get(kind, 0))
        if head == "data" and len(data) >= 2:
            payload = self.abi_revert(data[1:], path)
            if payload is not None:
                return payload
        return ir.Raw(self.bytes_(data, path, "revert"))

    def abi_revert(self, items, path) -> Optional[ir.Payload]:
        """Error(string) / Panic(uint256) / custom error payloads: a `bytes
        4 SEL` part followed by the arguments."""
        e0 = items[0]
        if not (_head(e0) == "bytes" and len(e0) == 3 and e0[1] == 4):
            return None  # any other first element is a whole word
        sel = ir.evaluate(self.expr(e0[2], _Path()))
        if sel is None:
            return None
        sel %= 1 << 32
        rest = list(items[1:])
        if sel == ERROR_SELECTOR and len(rest) >= 2 and rest[0] == 32 and _is_int(rest[1]):
            msg = self.string_words(rest[1], rest[2:], path)
            if msg is not None:
                return ir.ErrorString(msg)
        if sel == PANIC_SELECTOR and len(rest) == 1 and _is_int(rest[0]):
            return ir.Panic(rest[0] % ir.WORD_MOD)
        args = self.blob(rest, path, "revert")
        return ir.Custom(sel, args.parts if isinstance(args, ir.Blob) else (args,))

    def string_words(self, length: int, words, path) -> Optional[bytes]:
        """The message of an Error(string) payload whose words are constants
        (32-byte words, or parts of explicit width)."""
        chunks = []
        for w in words:
            if _head(w) == "bytes":
                data = ir.const_bytes(self.sized(w, path, "revert"))
            else:
                v = ir.evaluate(self.expr(w, path))
                data = None if v is None else v.to_bytes(32, "big")
            if data is None:
                return None
            chunks.append(data)
        data = b"".join(chunks)
        if len(data) != 32 * ((length + 31) // 32) or any(data[length:]):
            return None
        return data[:length]


def _cleanup(word: ir.Expr, ty: str) -> Optional[ir.Expr]:
    """The ABI decoder's cleanup of a word of type `ty` (None: none)."""
    m = re.fullmatch(r"(uint|int|bytes)(\d+)|address|bool", ty or "")
    if not m:
        return None
    if ty == "address":
        return ir.Mask(160, 0, 0, word)
    if ty == "bool":
        return ir.Op("iszero", (ir.Op("iszero", (word,)),))
    n = int(m.group(2))
    if m.group(1) == "uint" and n < 256:
        return ir.Mask(n, 0, 0, word)
    if m.group(1) == "int" and n < 256:
        return ir.Op("signextend", (ir.const(n // 8 - 1), word))
    if m.group(1) == "bytes" and n < 32:
        return ir.Mask(8 * n, 256 - 8 * n, 0, word)
    return None


def _is_full_returndata(e) -> bool:
    """`*.return_data 0 returndatasize` (the whole buffer)."""
    return len(e) >= 3 and e[2] == "returndatasize" and (e[0] == "delegate.return_data" or e[1] == 0)


def _targets(lines, lid: str) -> bool:
    """True if a `continue` to loop `lid` occurs in `lines` (recursively)."""
    stack = list(lines) if _is_seq(lines) else []
    while stack:
        x = stack.pop()
        if _head(x) == "continue" and len(x) > 1 and loop_id(x[1]) == lid:
            return True
        if _is_seq(x):
            stack.extend(y for y in x if _is_seq(y))
    return False


_STATEMENTS = {
    "if": _Lifter.st_if,
    "while": _Lifter.st_while,
    "continue": _Lifter.st_continue,
    "setvar": _Lifter.st_setvar,
    "store": _Lifter.st_store,
    "setmem": _Lifter.st_setmem,
    "tstore": _Lifter.st_tstore,
    "log": _Lifter.st_log,
    "call": _Lifter.st_call,
    "staticcall": _Lifter.st_call,
    "delegatecall": _Lifter.st_call,
    "callcode": _Lifter.st_call,
    "precompiled": _Lifter.st_precompiled,
    "create": _Lifter.st_create,
    "create2": _Lifter.st_create,
    "selfdestruct": _Lifter.st_selfdestruct,
    "return": _Lifter.st_return,
    "revert": _Lifter.st_revert,
    "stop": _Lifter.st_stop,
    "invalid": _Lifter.st_invalid,
    "assert_fail": _Lifter.st_invalid,
    "undefined": _Lifter.st_undefined,
    "require": _Lifter.st_require,
}

_EXPRESSIONS = {
    "var": _Lifter.e_var,
    "cd": _Lifter.e_cd,
    "param": _Lifter.e_param,
    "storage": _Lifter.e_storage,
    "stor": _Lifter.e_stor,
    "mask_shl": _Lifter.e_mask,
    "le": _Lifter.e_synthetic,
    "ge": _Lifter.e_synthetic,
    "sle": _Lifter.e_synthetic,
    "sge": _Lifter.e_synthetic,
    "bool": _Lifter.e_bool,
    "max": _Lifter.e_max,
    "min": _Lifter.e_min,
    "sha3": _Lifter.e_sha3,
    "balance": _Lifter.e_query,
    "extcodesize": _Lifter.e_query,
    "extcodehash": _Lifter.e_query,
    "blockhash": _Lifter.e_query,
    "blobhash": _Lifter.e_query,
    "tload": _Lifter.e_query,
    "mem": _Lifter.e_bytes_word,
    "call.data": _Lifter.e_bytes_word,
    "ext_call.return_data": _Lifter.e_bytes_word,
    "delegate.return_data": _Lifter.e_bytes_word,
    "callcode.return_data": _Lifter.e_bytes_word,
    "code.data": _Lifter.e_bytes_word,
    "extcodecopy": _Lifter.e_bytes_word,
    "data": _Lifter.e_bytes_word,
    "bytes": _Lifter.e_bytes_word,
    "undefined": _Lifter.e_undefined,
}
for _op in ir.OP_ARITY:
    _EXPRESSIONS.setdefault(_op, _Lifter.e_op)


# ---------------------------------------------------------------- entry point


def lift_function(key: str, trace, ctx: LiftContext, params: Optional[Dict[str, int]] = None) -> ir.Function:
    """Lift one function trace.  `params` (json vocabulary): parameter name
    -> calldata offset."""
    lifter = _Lifter(ctx, params)
    if ctx.vocabulary == "json":
        lifter.flags.add("json_trace")
    body = lifter.block(trace if trace is not None else [], _Path())
    if not body:
        body = (lifter.unstructured(trace, "empty trace"),)
    return ir.Function(key, body, frozenset(lifter.flags))

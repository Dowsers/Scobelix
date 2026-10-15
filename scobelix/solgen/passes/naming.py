"""
Pass `naming`: names, never semantics.

The other passes and the lifter leave placeholder names: `v0` / `t3` for
the locals of the decompiled code, `result` for the value a call returns,
`ok` / `ret` for a low-level call, `arg0` for the parameters of a function
whose signature is unknown.  This pass gives them names derived from what
they hold, by rules stated here, and changes nothing else: a rename is a
bijection on the names of one function (two locals never get one name), so
the body computes exactly what it computed before.

Locals (placeholders only: `v<N>`, `vm<N>`, `t<N>` of the lifter; the
names of the calls pass; `<x>_next` follows x):

  * the counter of a `for` header (an init and a step of the same local):
    `i`, `j`, `k`, in the order the loops are written;
  * the local a single-value `return` returns: `result`;
  * a local assigned once, from a state variable: the variable's name made
    a local (`balance = balanceOf[a]`, `balance = balances[a]`,
    `_totalSupply = totalSupply`, a struct member's own name);
  * the value of a high-level call without a database name: the function's
    name as a value (`decimals`, `balance` for `balanceOf`, `price` for
    `getPrice`); a low-level call's flag and return data: `success`,
    `data`; `send`: `sent`; `ecrecover`: `signer`; hashes: `hash`.

Every name avoids the contract's declarations (functions, state variables,
events, errors, interfaces, types), the function's parameters, the other
locals and `render.reserved_name`; the next candidate, then `<name>_<k>`.

Parameters without a database name (`arg<N>`), from evidence only:

  * passed as an argument of a high-level call, an event or a named error
    whose declaration names that parameter: that name (`to`, `amount`);
  * stored as it is into a state variable with a name: `_<name>`
    (`function setFee(uint256 _fee)`), else `new<Name>`.

A parameter compared with msg.sender or used any other way keeps its name.
`finish` takes back a parameter name that a declaration made after the
function (an event, an error, an interface) took.

Facts: ctx.facts["naming"]["functions"][key] counts the names given per
rule (counter, result, cached, call, temporary, params) and the
placeholders left (kept).
"""

from __future__ import annotations

import dataclasses
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from scobelix.solgen import ir
from scobelix.solgen.render import reserved_name

LEVELS = ("full",)

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_PLACEHOLDER_RE = re.compile(r"(?:v|vm|t)\d+(?:_\d+)*")  # lift.local_name
_ARG_RE = re.compile(r"arg\d+")  # abi._param_name without a database name
# the passes' own parameter names (events.py: the raw form of an unknown event)
_NOT_EVIDENCE_RE = re.compile(r"(?:arg|topic|data|param|a|r|p)\d+|_")
_NEXT_RE = re.compile(r"(\w+?)_next(\d*)")  # the loops pass's temporaries
_SYNTHETIC_RE = re.compile(r"(?:slot|var|map|arr)_?\d+(?:_\d+)*|m\d+_\d+|field\d+")  # storage's own names
_COUNTERS = ("i", "j", "k", "i2", "j2", "k2")
_DECLARED_RE = re.compile(r"\b(?:struct|enum|event|error|modifier|function|interface|contract)\s+"
                          r"([A-Za-z_$][\w$]*)")
_CONSTANT_RE = re.compile(r"\b(?:constant|immutable)\s+([A-Za-z_$][\w$]*)")
_STATE_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*;\s*$")


# ---------------------------------------------------------------- names of the contract


def contract_names(ctx) -> Set[str]:
    """The names the contract declares (or will declare) at its top level,
    as far as the passes know them when a function is rewritten."""
    out: Set[str] = set()
    for spec in ctx.specs.values():
        if getattr(spec, "name", None):
            out.add(spec.name)
    out |= set(ctx.facts.get("declared_names") or ())
    lay = ctx.facts.get("storage")
    if lay is not None and not ctx.off_everywhere("storage"):
        out |= {v.vid for v in getattr(lay, "vars", ())} | set(getattr(lay, "names", {}).values())
        out |= set(getattr(lay, "structs", {}).values()) | set(getattr(lay, "enums", {}).values())
    getters = ctx.facts.get("getters") or {}
    for entry in (getters.get("vars") or {}).values():
        out.add(entry[1])
    for entry in (getters.get("constants") or {}).values():
        out.add(entry[0])
    out |= set(((ctx.facts.get("calls") or {}).get("interfaces") or {}))
    out |= declared_in(ctx.declarations)
    return out


def declared_in(declarations: Dict[str, List[str]]) -> Set[str]:
    """Top-level names in declaration texts (PassContext.declarations)."""
    out: Set[str] = set()
    for kind, texts in declarations.items():
        for text in texts:
            if kind == "interface":
                out.update(_DECLARED_RE.findall(text)[:1])  # (not the members of the interface)
                continue
            out.update(_DECLARED_RE.findall(text))
            out.update(_CONSTANT_RE.findall(text))
            if kind == "state":
                for line in text.split("\n"):
                    line = line.strip()
                    m = _STATE_RE.search(line) if line and not line.startswith(("/", "*")) else None
                    if m is not None:
                        out.add(m.group(1))
    return out


def _free(name: str, taken: Set[str]) -> bool:
    return bool(_IDENT_RE.fullmatch(name)) and name not in taken and not reserved_name(name, parameter=True)


def _pick(cands: Iterable[str], taken: Set[str]) -> Optional[str]:
    """The first free candidate, else the first one with a `_<k>` suffix."""
    cands = [c for c in cands if c and _IDENT_RE.fullmatch(c)]
    for c in cands:
        if _free(c, taken):
            return c
    if not cands:
        return None
    k = 2
    while not _free(f"{cands[0]}_{k}", taken):
        k += 1
    return f"{cands[0]}_{k}"


def _cap(s: str) -> str:
    return s[:1].upper() + s[1:]


# ---------------------------------------------------------------- what a name is derived from


def value_name(function: str) -> str:
    """A function's name as the name of the value it returns: `balanceOf`
    -> `balance`, `getPrice` -> `price`, `decimals` -> `decimals`."""
    n = function
    if len(n) > 3 and n.startswith("get") and n[3].isupper():
        n = n[3].lower() + n[4:]
    elif len(n) > 2 and n.endswith("Of"):
        n = n[:-2]
    return n


def cached_names(var: str, element: bool, member: Optional[str] = None) -> List[str]:
    """Names for a local holding a state variable's value (`element`: an
    entry of a mapping or array; `member`: a struct member's name)."""
    if member and not _SYNTHETIC_RE.fullmatch(member):
        base = member.lstrip("_")
        return [base, "_" + base, "current" + _cap(base)] if base else []
    base = var.lstrip("_")
    if not base or _SYNTHETIC_RE.fullmatch(base):
        return []
    if element:
        base = base[:-2] if len(base) > 2 and base.endswith("Of") else singular(base)
    out = [base] if base != var else []
    return out + ["_" + base, "current" + _cap(base)]


def _unwrap(e: ir.Expr) -> ir.Expr:
    while isinstance(e, ir.Cast):
        e = e.value
    return e


def _param_index(e: ir.Node) -> Optional[int]:
    """The head word of the parameter `e` is (as it is, or converted)."""
    while isinstance(e, ir.Cast) or (isinstance(e, ir.Mask) and e.offset == 0 and e.shl == 0):
        e = e.value
    return e.index if isinstance(e, ir.Param) else None


def _declared_params(text: str) -> List[str]:
    """Parameter names of `function f(T a, ...)` / `event E(T indexed a)` /
    `error E(T a)` ("" where none)."""
    m = re.search(r"\(([^()]*)\)", text)
    if m is None or not m.group(1).strip():
        return []
    out = []
    for part in m.group(1).split(","):
        words = [w for w in part.split() if w not in ("indexed", "calldata", "memory", "storage")]
        out.append(words[-1] if len(words) >= 2 else "")
    return out


# ---------------------------------------------------------------- the pass


class _Namer:
    def __init__(self, fn: ir.Function, ctx):
        self.fn = fn
        self.ctx = ctx
        self.spec = ctx.specs.get(fn.key)
        self.counts: Dict[str, int] = {}
        self.contract = contract_names(ctx)

    def count(self, what: str, n: int = 1) -> None:
        if n:
            self.counts[what] = self.counts.get(what, 0) + n

    # ------------------------------------------------------------ parameters

    def _heads(self) -> Dict[int, int]:
        """head word -> parameter index."""
        out, word = {}, 0
        for i, (t, _) in enumerate(self.spec.params):
            out[word] = i
            word += t.head_words
        return out

    def _evidence(self) -> List[Tuple[int, List[str]]]:
        """(head word, candidate names) in the order the body gives them."""
        facts = self.ctx.facts
        ifaces = (facts.get("calls") or {}).get("interfaces") or {}
        events = {name: text for text, name in ((facts.get("events") or {}).get("decls") or {}).items()}
        errors: Dict[str, List[str]] = {}  # (reverts: selector -> (name, types, names))
        for _, entry in sorted(((facts.get("reverts") or {}).get("errors") or {}).items()):
            if entry and len(entry) == 3:
                errors.setdefault(entry[0], list(entry[2]))
        out: List[Tuple[int, List[str]]] = []

        def args(values, names):
            for v, n in zip(values, names):
                w = _param_index(v)
                if w is not None and n and not _NOT_EVIDENCE_RE.fullmatch(n):
                    out.append((w, [n]))

        for n in ir.walk_all(self.fn.body):
            if isinstance(n, ir.HighCall):
                decl = next((d for d in (ifaces.get(n.iface) or {}).values()
                             if re.match(rf"function {re.escape(n.name)}\(", d)), None)
                if decl is not None:
                    args(n.args, _declared_params(decl))
            elif isinstance(n, ir.Emit) and n.event in events:
                args(n.args, _declared_params(events[n.event]))
            elif isinstance(n, ir.NamedError) and n.name in errors:
                args(n.args, errors[n.name])
            elif isinstance(n, ir.Assign) and n.op is None and isinstance(n.target, ir.StateRef) \
                    and not n.target.path:
                w = _param_index(n.value)
                base = n.target.var.lstrip("_")
                if w is not None and base and not _SYNTHETIC_RE.fullmatch(base):
                    out.append((w, ["_" + base, "new" + _cap(base)]))
        return out

    def parameters(self, locals_: Set[str]) -> Dict[int, Tuple[str, str]]:
        """Rename the `arg<N>` parameters with evidence; index -> (old, new)."""
        spec = self.spec
        if spec is None or not getattr(spec, "typed", False) or not spec.params:
            return {}
        if not any(_ARG_RE.fullmatch(n) for _, n in spec.params):
            return {}
        heads = self._heads()
        names = [n for _, n in spec.params]
        taken = set(self.contract) | set(names) | locals_
        done: Dict[int, Tuple[str, str]] = {}
        for word, cands in self._evidence():
            i = heads.get(word)
            if i is None or i in done or not _ARG_RE.fullmatch(names[i]):
                continue
            new = next((c for c in cands if _free(c, taken)), None)
            if new is None:
                continue
            taken.add(new)
            done[i] = (names[i], new)
            names[i] = new
        if done:
            spec.params = tuple((t, n) for (t, _), n in zip(spec.params, names))
            self.count("params", len(done))
        return done

    # ------------------------------------------------------------ locals

    def locals(self) -> Tuple[Dict[str, str], Dict[tuple, str]]:
        """(IR local -> new name, (kind, call id, index) -> new name of a
        call's output) for the placeholders."""
        body = self.fn.body
        order: List[str] = []
        seen: Set[str] = set()
        assigns: Dict[str, int] = {}
        outputs: List[Tuple[tuple, List[str], str]] = []  # (key, candidates, rule)
        out_names: Set[str] = set()
        counters: List[str] = []
        returned: List[str] = []
        cached: Dict[str, List[str]] = {}
        for n in ir.walk_all(body):
            if isinstance(n, ir.Local) and n.name not in seen:
                seen.add(n.name)
                order.append(n.name)
            if isinstance(n, ir.Assign) and isinstance(n.target, ir.Local):
                assigns[n.target.name] = assigns.get(n.target.name, 0) + 1
                v = _unwrap(n.value)
                if isinstance(v, ir.StateRef) and n.op is None:
                    member = v.path[-1] if v.path and isinstance(v.path[-1], str) else None
                    element = any(isinstance(p, ir.Node) for p in v.path)
                    cached.setdefault(n.target.name, cached_names(v.var, element, member))
                else:
                    cached.setdefault(n.target.name, [])
            if isinstance(n, ir.For) and len(n.init) == 1 and len(n.step) == 1:
                a, s = n.init[0], n.step[0]
                if isinstance(a, ir.Assign) and isinstance(a.target, ir.Local) and isinstance(s, ir.Assign) \
                        and s.target == a.target and a.target.name not in counters:
                    counters.append(a.target.name)
            if isinstance(n, ir.Return):
                v = None
                if n.values is not None and len(n.values) == 1:
                    v = _unwrap(n.values[0])
                elif isinstance(n.data, ir.WordBytes) and n.data.width == 32:  # (one word of return data)
                    v = n.data.value
                if isinstance(v, ir.Local) and v.name not in returned:
                    returned.append(v.name)
            if isinstance(n, ir.HighCall):
                for i, o in enumerate(n.outs):
                    if o is None:
                        continue
                    out_names.add(o)
                    if o == "result" and len(n.outs) == 1:
                        outputs.append((("out", n.call_id, i), [value_name(n.name), "result"], "call"))
            elif isinstance(n, ir.ExtCall):
                for attr, old, cands in (("ok", "ok", ["success", "ok"]), ("ret", "ret", ["data", "returnData", "ret"])):
                    o = getattr(n, attr)
                    if o is not None:
                        out_names.add(o)
                        if o == old:
                            outputs.append(((attr, n.call_id, 0), cands, "call"))
            elif isinstance(n, ir.Transfer) and n.ok is not None:
                out_names.add(n.ok)
                if n.ok == "sent":
                    outputs.append((("ok", n.call_id, 0), ["sent", "success"], "call"))
            elif isinstance(n, ir.Builtin) and n.out is not None:
                out_names.add(n.out)
                if n.out in ("signer", "hash"):
                    cands = ["signer", "recovered"] if n.out == "signer" else ["hash", "digest"]
                    outputs.append((("out", n.call_id, 0), cands, "call"))
        placeholders = [x for x in order if _PLACEHOLDER_RE.fullmatch(x)]
        nexts = [x for x in order if _NEXT_RE.fullmatch(x) and not _PLACEHOLDER_RE.fullmatch(x)]
        # every local name of the body, placeholders and temporaries included:
        # a new name is never one of them, so two locals never end with one
        # name whatever the rules give (the outputs renamed below all have
        # one of the names left out)
        taken = set(self.contract) | {n for _, n in getattr(self.spec, "params", ()) or ()} | set(order) \
            | (out_names - {"result", "ok", "ret", "sent", "signer", "hash"})
        lmap: Dict[str, str] = {}

        def give(x: str, cands: List[str], rule: str) -> None:
            name = _pick(cands, taken)
            if name is not None:
                taken.add(name)
                if name != x:
                    lmap[x] = name
                    self.count(rule)

        letters = iter(_COUNTERS)
        for x in counters:
            if x in placeholders and x not in lmap:
                letter = next((c for c in letters if _free(c, taken)), None)
                if letter is not None:
                    give(x, [letter], "counter")
        for x in returned:
            if x in placeholders and x not in lmap and x not in counters:
                give(x, ["result"], "result")
                break
        for x in placeholders:
            if x not in lmap and assigns.get(x) == 1 and cached.get(x):
                give(x, cached[x], "cached")
        for x in placeholders:
            if x not in lmap:
                taken.add(x)  # (kept)
        self.count("kept", sum(1 for x in placeholders if x not in lmap))
        for x in nexts:
            m = _NEXT_RE.fullmatch(x)
            base = lmap.get(m.group(1))
            if base is not None:
                give(x, [f"{base}_next{m.group(2)}"], "temporary")
            else:
                taken.add(x)
        omap: Dict[tuple, str] = {}
        for key, cands, rule in outputs:
            name = _pick(cands, taken)
            if name is not None:
                taken.add(name)
                omap[key] = name
                self.count(rule)
        return lmap, omap


def _apply(body, lmap: Dict[str, str], omap: Dict[tuple, str]):
    def rename(n):
        if isinstance(n, ir.Local) and n.name in lmap:
            return ir.Local(lmap[n.name])
        if isinstance(n, ir.HighCall) and any(("out", n.call_id, i) in omap for i in range(len(n.outs))):
            return dataclasses.replace(n, outs=tuple(omap.get(("out", n.call_id, i), o) for i, o in enumerate(n.outs)))
        if isinstance(n, ir.ExtCall) and (("ok", n.call_id, 0) in omap or ("ret", n.call_id, 0) in omap):
            return dataclasses.replace(n, ok=omap.get(("ok", n.call_id, 0), n.ok), ret=omap.get(("ret", n.call_id, 0), n.ret))
        if isinstance(n, ir.Transfer) and ("ok", n.call_id, 0) in omap:
            return dataclasses.replace(n, ok=omap[("ok", n.call_id, 0)])
        if isinstance(n, ir.Builtin) and ("out", n.call_id, 0) in omap:
            return dataclasses.replace(n, out=omap[("out", n.call_id, 0)])
        if isinstance(n, ir.Precompile) and n.output in lmap:
            return dataclasses.replace(n, output=lmap[n.output])
        return n

    return ir.transform(tuple(body), rename)


# ---------------------------------------------------------------- state variables and structs


def _slot_of(e: ir.Expr) -> Optional[Tuple[int, int]]:
    """(slot, byte) of an address read from a constant slot in lifted code."""
    if isinstance(e, ir.Field) and isinstance(e.value, ir.Sload) and isinstance(e.value.slot, ir.Const) \
            and isinstance(e.offset, int) and e.size == 160 and e.offset % 8 == 0:
        return e.value.slot.value, e.offset // 8
    if isinstance(e, ir.Mask) and isinstance(e.value, ir.Sload) and isinstance(e.value.slot, ir.Const) \
            and e.size == 160 and isinstance(e.offset, int) and e.offset % 8 == 0 and e.shl == -e.offset:
        return e.value.slot.value, e.offset // 8
    if isinstance(e, ir.Sload) and isinstance(e.slot, ir.Const):
        return e.slot.value, 0
    return None


def _owners(ctx, lay) -> List[str]:
    """Ids of the address variables a function's first check (lifted form,
    after the decoder's checks) compares with msg.sender."""
    from scobelix.solgen.passes.modifiers import lifted_check

    out: List[str] = []
    for key in sorted(ctx.functions):
        got = lifted_check(ctx.functions[key].body)
        if got is None:
            continue
        for n in ir.walk(got[0]):
            if not (isinstance(n, ir.Op) and n.op == "eq" and len(n.args) == 2):
                continue
            for x, y in (n.args, n.args[::-1]):
                where = _slot_of(y) if isinstance(x, ir.Env) and x.name == "caller" else None
                v = lay.var_at(*where) if where is not None else None
                if v is not None and (v.type == ("v", "address") or v.type[0] == "contract") \
                        and v.offset == where[1] and v.vid not in out:
                    out.append(v.vid)
    return out


def _database_names(ctx) -> Set[str]:
    """The names the events and reverts passes may declare later: those the
    database gives the topic0 of the lifted logs and the selectors of the
    custom errors (an event or an error cannot take another name: its
    topic or selector hashes it)."""
    topics: Set[int] = set()
    selectors: Set[int] = set()
    for fn in ctx.functions.values():
        for n in ir.walk_all(fn.body):
            if isinstance(n, ir.Log) and n.topics and isinstance(n.topics[0], ir.Const):
                topics.add(n.topics[0].value)
            elif isinstance(n, ir.Custom):
                selectors.add(n.selector)
    out: Set[str] = set()
    for lookup, keys in ((getattr(ctx.sigs, "event_candidates", None), topics),
                         (getattr(ctx.sigs, "error_candidates", None), selectors)):
        for k in sorted(keys):
            try:
                out.update(c.name for c in (lookup(k) if lookup is not None else ()) if getattr(c, "name", None))
            except Exception:  # noqa: BLE001 - no database: nothing to leave free
                continue
    return out


def _uses_struct(t: tuple, key: tuple) -> bool:
    if t[0] == "struct":
        return (t[1], t[2]) == key or any(_uses_struct(m[2], key) for m in t[1])
    return any(isinstance(x, tuple) and x and isinstance(x[0], str) and _uses_struct(x, key) for x in t[1:])


def singular(name: str) -> str:
    """`accounts` -> `account`, `entries` -> `entry`; a final s that is not
    a plural mark stays (`status`, `bonus`, `basis`, `address`)."""
    if len(name) > 4 and name.endswith("ies"):
        return name[:-3] + "y"
    if len(name) > 3 and name.endswith("s") and not name.endswith(("ss", "us", "is")):
        return name[:-1]
    return name


def state_names(ctx) -> Dict[str, str]:
    """Names for the state variables the storage pass could not name (ids
    `slot<N>[_<byte>]`): `owner` when it is the only address variable that
    first checks compare with msg.sender (no other one, named or not: the
    pending owner of a two-step transfer, a pool its callbacks check), else
    `var_<N>` / `map_<N>` / `arr_<N>` (`_<byte>` for a packed one); and a
    struct type used by one named variable only takes that variable's name
    in the singular (`accounts`: `Account`), unless an event or an error of
    the contract has that name.  Done once, before the functions are
    rewritten."""
    if ctx.off_everywhere("storage"):
        return {}
    lay = ctx.facts.get("storage")
    if lay is None or not getattr(lay, "vars", None):
        return {}
    from scobelix.solgen.passes.storage import _taken_names, assign_names

    assign_names(ctx, lay)
    taken = set(_taken_names(ctx)) | set(lay.names.values()) | set(lay.structs.values()) | set(lay.enums.values()) \
        | set(ctx.facts.get("declared_names") or ())
    renamed: Dict[str, str] = {}
    compared = _owners(ctx, lay)
    owner = compared[0] if len(compared) == 1 and lay.names.get(compared[0], compared[0]) == compared[0] else None
    for v in sorted(lay.vars, key=lambda v: (v.slot, v.offset)):
        if lay.names.get(v.vid, v.vid) != v.vid:
            continue  # a getter's or an accessor's name
        prefix = "map" if v.type[0] == "map" else "arr" if v.type[0] == "dyn" else "var"
        cands = (["owner"] if v.vid == owner else []) + [f"{prefix}_{v.slot}" + (f"_{v.offset}" if v.offset else "")]
        name = next((c for c in cands if _free(c, taken)), None)
        if name is not None:
            taken.add(name)
            lay.names[v.vid] = name
            renamed[v.vid] = name
    if lay.structs:
        taken |= _database_names(ctx)
    for key, sname in list(lay.structs.items()):
        users = [v for v in lay.vars if _uses_struct(v.type, key)]
        if len(users) != 1:
            continue
        base = lay.names.get(users[0].vid, users[0].vid).lstrip("_")
        if not base or _SYNTHETIC_RE.fullmatch(base):
            continue
        name = _cap(singular(base))
        if _free(name, taken):
            taken.discard(sname)
            taken.add(name)
            lay.structs[key] = name
            renamed[sname] = name
    return renamed


def prepare(ctx) -> None:
    facts = ctx.facts.setdefault("naming", {"functions": {}, "params": {}})
    facts["state"] = state_names(ctx)


def run(fn: ir.Function, ctx) -> ir.Function:
    facts = ctx.facts.setdefault("naming", {"functions": {}, "params": {}})
    namer = _Namer(fn, ctx)
    locals_ = {n.name for n in ir.walk_all(fn.body) if isinstance(n, ir.Local)}
    params = namer.parameters(locals_)
    if params:
        facts["params"][fn.key] = params
    lmap, omap = namer.locals()
    if namer.counts:
        facts["functions"][fn.key] = dict(namer.counts)
    if not lmap and not omap:
        return fn
    return fn.with_body(_apply(fn.body, lmap, omap))


def finish(ctx) -> None:
    """Take back a parameter name a later declaration took (an event, an
    error or an interface declared after the function was rewritten)."""
    facts = ctx.facts.get("naming") or {}
    final = declared_in(ctx.declarations) | {s.name for s in ctx.specs.values() if getattr(s, "name", None)}
    for key, renamed in sorted((facts.get("params") or {}).items()):
        spec = ctx.specs.get(key)
        if spec is None:
            continue
        names = [n for _, n in spec.params]
        undo = [i for i, (old, new) in sorted(renamed.items()) if i < len(names) and names[i] == new and new in final]
        for i in undo:
            names[i] = renamed[i][0]
        if undo:
            spec.params = tuple((t, n) for (t, _), n in zip(spec.params, names))

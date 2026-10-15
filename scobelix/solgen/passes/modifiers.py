"""
Pass `modifiers`: a check that several functions start with becomes a
modifier (`modifier onlyOwner() { require(msg.sender == owner, "..."); _; }`)
applied to them.

Exactness.  solc writes the function body where the modifier's `_;`
stands, so a modifier made of one check followed by `_;` runs that check
as the first statement of the function, after the parameters are decoded
(as the original body did), and the function's `return` statements leave
the body for the rest of the modifier, which is empty.  The pass moves a
check only when:

  * it is the first statement of the final body (`require(c, ...)` or
    `if (c) revert ...;`): the function's first observable action;
  * its condition and revert data read nothing but msg.sender, tx.origin,
    the block, constants and state variables (no parameter, local,
    calldata, memory or call output), with no arithmetic;
  * it renders without a helper of the generated code (the modifier is
    written once for every function that uses it);
  * the function is a function (not the fallback or receive), and the
    same check, as the lifter sees it (the first check that reads neither
    the calldata nor the call value), starts at least two functions.

Two functions share a modifier when their checks are the same IR.  Names
come from the check: `onlyOwner` (msg.sender == owner), `only<Name>`
(msg.sender == <name>, or a mapping of msg.sender to a bool: isAdmin ->
onlyAdmin), `whenNotPaused` / `when<Name>` (a bool state variable, false
or true), else `check<k>`; a name the contract declares gets `_<k>`.

Facts: ctx.facts["modifiers"]["functions"][key] = [modifier names].
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from scobelix.solgen import ir
from scobelix.solgen.render import (EntryRender, RenderContext, _is_checked, _is_wrapping, render_function_body,
                                    reserved_name)

LEVELS = ("full",)

_ENV = frozenset({"caller", "origin", "address", "timestamp", "number", "chainid"})
_LOGIC = frozenset({"eq", "lt", "gt", "slt", "sgt", "iszero", "and", "or", "xor", "not", "shl", "shr"})
_TYPED = frozenset({"eq", "lt", "gt", "and", "or", "xor"})
_INPUT_ENV = frozenset({"calldatasize", "callvalue"})
_SYNTHETIC_RE = re.compile(r"(?:slot|var|map|arr)_?\d+(?:_\d+)*|m\d+_\d+|field\d+")


# ---------------------------------------------------------------- the checks


def _plain(node: ir.Node) -> bool:
    """`node` reads only msg.sender / tx.origin / the block, constants and
    state variables, with no arithmetic."""
    for n in ir.walk(node):
        if isinstance(n, (ir.Const, ir.StateRef, ir.Cast, ir.Bool, ir.Not, ir.And, ir.Or)):
            continue
        if isinstance(n, ir.Env) and n.name in _ENV:
            continue
        if isinstance(n, ir.Op) and n.op in _LOGIC:
            continue
        if isinstance(n, ir.Typed) and n.op in _TYPED and not n.checked:
            continue
        if isinstance(n, (ir.Mask, ir.Field)) and all(isinstance(getattr(n, f), int) for f in
                                                     (("size", "offset", "shl") if isinstance(n, ir.Mask)
                                                      else ("offset", "size"))):
            continue
        return False
    return True


def _payload_ok(p: ir.Payload) -> bool:
    if isinstance(p, (ir.Empty, ir.ErrorString)):
        return True
    if isinstance(p, ir.NamedError):
        return all(isinstance(a, ir.Expr) and _plain(a) for a in p.args)
    return False


def first_check(body: Tuple[ir.Stmt, ...]) -> Optional[Tuple[ir.Stmt, Tuple[ir.Stmt, ...]]]:
    """(the check that starts `body`, the statements after it)."""
    if not body:
        return None
    s = body[0]
    if isinstance(s, ir.Require):
        return s, tuple(body[1:])
    if isinstance(s, ir.If) and len(s.then) == 1 and isinstance(s.then[0], ir.Revert):
        return ir.If(s.cond, s.then, ()), tuple(s.orelse) + tuple(body[1:])
    return None


def _reads_input(e: ir.Node) -> bool:
    return any(isinstance(n, (ir.CalldataWord, ir.CalldataSlice, ir.Param))
               or (isinstance(n, ir.Env) and n.name in _INPUT_ENV) for n in ir.walk(e))


def lifted_check(body: Tuple[ir.Stmt, ...]):
    """(condition, payload) of the first check of a lifted body that reads
    neither the calldata nor the call value (the decoder's checks and the
    non-payable test come first)."""
    stmts = tuple(body)
    for _ in range(64):
        got = first_check(stmts)
        if got is None:
            return None
        check, rest = got
        cond = check.cond
        payload = check.payload if isinstance(check, ir.Require) else check.then[0].payload
        if not _reads_input(cond):
            return cond, payload, isinstance(check, ir.Require)
        stmts = rest
    return None


# ---------------------------------------------------------------- names


def _truth(e: ir.Expr) -> Tuple[bool, ir.Expr]:
    """(positive, core): e is core (positive) or !core."""
    pos = True
    while True:
        if isinstance(e, ir.Not):
            pos, e = not pos, e.value
        elif isinstance(e, ir.Op) and e.op == "iszero":
            pos, e = not pos, e.args[0]
        elif isinstance(e, (ir.Bool, ir.Cast)):
            e = e.value
        else:
            return pos, e


def _sender(e: ir.Expr) -> bool:
    while isinstance(e, (ir.Cast, ir.Mask, ir.Field)):
        e = e.value
    return isinstance(e, ir.Env) and e.name == "caller"


def _state(e: ir.Expr) -> Optional[ir.StateRef]:
    while isinstance(e, (ir.Cast, ir.Mask, ir.Field)):
        e = e.value
    return e if isinstance(e, ir.StateRef) else None


def _base(var: str) -> Optional[str]:
    base = var.lstrip("_")
    if not base or _SYNTHETIC_RE.fullmatch(base):
        return None
    return base[:1].upper() + base[1:]


def check_name(check: ir.Stmt) -> Optional[str]:
    """The modifier name the check's condition gives, or None."""
    cond = check.cond if isinstance(check, ir.Require) else ir.Not(check.cond)
    pos, core = _truth(cond)
    if pos and ((isinstance(core, ir.Op) and core.op == "eq" and len(core.args) == 2)
                or (isinstance(core, ir.Typed) and core.op == "eq")):
        a, b = core.args
        for x, y in ((a, b), (b, a)):
            ref = _state(y)
            if _sender(x) and ref is not None and not ref.path and _base(ref.var):
                return "only" + _base(ref.var)
        return None
    ref = _state(core)
    if ref is None or ref.ty != "bool":
        return None
    if not ref.path and _base(ref.var):
        return ("when" if pos else "whenNot") + _base(ref.var)
    if pos and len(ref.path) == 1 and isinstance(ref.path[0], ir.Node) and _sender(ref.path[0]):
        base = _base(ref.var)
        if base is None:
            return None
        if len(base) > 2 and base.startswith("Is") and base[2].isupper():
            base = base[2:]
        from scobelix.solgen.passes.naming import singular

        return "only" + singular(base)
    return None


# ---------------------------------------------------------------- the pass


def _target(ctx) -> Tuple[int, int, int]:
    try:
        return tuple(int(x) for x in str(ctx.target_solc).split("."))  # type: ignore[return-value]
    except ValueError:
        return (0, 8, 19)


def _rendered(check: ir.Stmt, ctx) -> Optional[List[str]]:
    """The check's lines (indent 1) when it renders on its own, without a
    helper, a flag or arithmetic."""
    if any(_is_checked(n) or _is_wrapping(n) for n in ir.walk(check)):
        return None
    rctx = RenderContext(target=_target(ctx), abi_v2=ctx.abi_v2)
    try:
        lines, flags = render_function_body(ir.Function("_modifier", (check,)), EntryRender("internal"), rctx, indent=1)
    except Exception:  # noqa: BLE001 - not renderable on its own: keep it in the body
        return None
    if flags or rctx.helpers.used or not lines:
        return None
    return lines


def prepare(ctx) -> None:
    facts = ctx.facts.setdefault("modifiers", {"functions": {}, "checks": {}, "lines": {}})
    raw: Dict[str, object] = {}
    seen: Dict[object, int] = {}
    for key, fn in ctx.functions.items():
        spec = ctx.specs.get(key)
        if spec is None or spec.kind != "function":
            continue
        got = lifted_check(fn.body)
        if got is not None:
            raw[key] = got
            seen[got] = seen.get(got, 0) + 1
    facts["repeated"] = {key for key, got in raw.items() if seen[got] >= 2}


def _taken(ctx) -> Set[str]:
    from scobelix.solgen.passes.naming import contract_names

    return contract_names(ctx)


def run(fn: ir.Function, ctx) -> ir.Function:
    facts = ctx.facts.setdefault("modifiers", {"functions": {}, "checks": {}, "lines": {}})
    spec = ctx.specs.get(fn.key)
    if spec is None or spec.kind != "function" or fn.key not in (facts.get("repeated") or ()):
        return fn
    got = first_check(fn.body)
    if got is None:
        return fn
    check, rest = got
    payload = check.payload if isinstance(check, ir.Require) else check.then[0].payload
    if not _plain(check.cond) or not _payload_ok(payload):
        return fn
    checks: Dict[ir.Stmt, str] = facts["checks"]
    name = checks.get(check)
    if name is None:
        lines = _rendered(check, ctx)
        if lines is None:
            return fn
        taken = _taken(ctx) | set(checks.values()) | {n for s in ctx.specs.values() for _, n in s.params}
        base = check_name(check) or f"check{1 + sum(1 for n in checks.values() if n.startswith('check'))}"
        name, k = base, 1
        while name in taken or reserved_name(name):
            k += 1
            name = f"{base}_{k}"
        checks[check] = name
        facts["lines"][name] = lines
    spec.modifiers = tuple(spec.modifiers) + (name,)
    facts["functions"][fn.key] = list(spec.modifiers)
    return fn.with_body(rest)


def finish(ctx) -> None:
    facts = ctx.facts.get("modifiers") or {}
    used = {m for key, ms in (facts.get("functions") or {}).items() for m in ms}
    for check, name in (facts.get("checks") or {}).items():
        if name in used:
            text = "\n".join([f"modifier {name}() {{"] + facts["lines"][name] + ["    _;", "}"])
            ctx.declare("modifier", "\n" + text)

"""
Contract assembly: one Solidity source from the rendered entry points.

  * pragma: `^0.8.M`, M the newest feature the text needs (NatSpec custom
    tags 0.8.2, block.basefee 0.8.7, block.prevrandao 0.8.18, cancun
    builtins 0.8.25); the target compiler is recorded in the header.
    `pragma abicoder v1` when the original's decoder did not validate
    parameters (ABI coder v1).
  * known names (keccak-verified signatures) become external functions
    with their canonical parameter types; tuple types get structs;
  * selectors without a known name are routed: fallback() dispatches them
    on msg.sig, when the calldata holds a selector, to private functions
    whose bodies read the calldata exactly like the original (same
    selector, same bytes, same behaviour).  A routed function the abi pass
    typed (spec.typed_route: value parameters from the decoder checks, see
    passes/abi._route) takes typed parameters: the fallback, then declared
    `fallback(bytes calldata input) external returns (bytes memory)`,
    decodes them with abi.decode and returns the standard encoding of the
    values the function returns (or an empty success: `return "";`);
    the untyped ones keep their call `_fn_<selector>();`, which halts;
  * receive() / fallback() from the dispatcher analysis; solc's default
    (plain revert) is not written out;
  * an entry point a pass folded into a declaration (a public state
    variable or constant, see passes/getters.py) is not written out: solc
    generates its getter;
  * the header names the original and target compilers and explains the
    tiers, verdicts and flags of the per-function NatSpec;
  * the locals of a body never take a name the contract declares (state
    variables, constants, types, events, errors, functions): they would
    shadow it there.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from scobelix.solgen import ir
from scobelix.solgen.abi import WRAP_SLOTS, EntrySpec
from scobelix.solgen.render import (EntryRender, RenderContext, comment_text, exact_machinery, render_function_body,
                                    reserved_name)
from scobelix.solgen.types import SolType

__all__ = ["Unit", "ContractInput", "assemble", "entry_spans", "router_spans"]

# the verdicts of a differential execution that found a difference
DIFFERING = ("DIVERGENT", "MISSING", "EXTRA")


@dataclasses.dataclass
class Unit:
    """One entry point ready to render."""

    key: str
    fn: ir.Function
    spec: EntrySpec
    tier: str = "exact"  # "exact", "idiomatic" or "partial" (rewritten, some passes switched off)
    verdict: str = "unverified"
    passes: Tuple[str, ...] = ()
    flags: Set[str] = dataclasses.field(default_factory=set)
    folded: Optional[str] = None  # the declaration whose generated getter replaces the function
    guards: Tuple[str, ...] = ()  # the risk flags for which no pass ran on the function
    disabled: Tuple[str, ...] = ()  # the passes switched off for the function
    counterexample: str = ""  # one line: the call on which the function differed from the original
    reason: str = ""  # why the verification was INCONCLUSIVE ("env: ...")


@dataclasses.dataclass
class ContractInput:
    units: List[Unit]
    target: str  # target solc version
    original: str  # "solc 0.8.19", "unknown compiler", ...
    abi_v2: bool = True
    idiom_level: str = "exact"
    contract_name: str = "Decompiled"
    original_code: bytes = b""
    fallback_payable: bool = False  # the original's fallback accepts value
    fallback_present: bool = False  # the original has a fallback of its own (not solc's default revert)
    receive_present: bool = False
    declarations: Dict[str, List[str]] = dataclasses.field(default_factory=dict)  # from passes
    verification_summary: Optional[List[str]] = None
    left_out: Tuple[str, ...] = ()  # entry points of the original that were not decompiled (not in `units`)


_WRAP_SLOTS = WRAP_SLOTS  # stack slots of parameters + return values above which the body runs in a private function


def _reads_calldata(fn: ir.Function) -> bool:
    return any(isinstance(n, (ir.CalldataWord, ir.CalldataSlice, ir.Param))
               or (isinstance(n, ir.Env) and n.name == "calldatasize") for n in ir.walk_all(fn.body))


_DECLARED_RE = re.compile(r"^\s*(?:struct|enum|event|error|modifier|function|interface|contract|library)\s+"
                          r"([A-Za-z_$][\w$]*)", re.M)
_CONSTANT_RE = re.compile(r"\b(?:constant|immutable)\s+([A-Za-z_$][\w$]*)")
_VARIABLE_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*;\s*$")


def _declared_names(ci: ContractInput) -> Set[str]:
    """The names the contract declares at its top level (state variables,
    constants, types, events, errors, modifiers, functions): a local
    variable of a body must not take one of them, it would shadow it there
    (`sum = s;` would write the local instead of the state variable)."""
    out: Set[str] = {ci.contract_name}
    for kind, texts in ci.declarations.items():
        for text in texts:
            if kind == "interface":
                # (its functions are members of the interface, not names of the contract)
                out.update(_DECLARED_RE.findall(text)[:1])
                continue
            out.update(_DECLARED_RE.findall(text))
            out.update(_CONSTANT_RE.findall(text))
            if kind != "state":
                continue
            for line in text.split("\n"):
                line = line.strip()
                m = _VARIABLE_RE.search(line) if line and not line.startswith(("/", "*")) else None
                if m is not None:
                    out.add(m.group(1))
    out.update(u.spec.name for u in ci.units if u.spec.name)
    return out


def _version(v: str) -> Tuple[int, int, int]:
    parts = [int(x) for x in v.split(".")[:3]]
    return tuple(parts + [0] * (3 - len(parts)))  # type: ignore[return-value]


# what an old original's decoder does that the declaration's cannot (the
# function keeps its name and selector: the difference is said where it is)
_DECODER_NOTES = (
    ("abi:short_calldata_check", "the original's decoder (solc < 0.5) reads the arguments missing from short "
                                 "calldata as zeros; the decoder of this declaration reverts on such calldata"),
    ("abi:legacy_memory_copy", "the original's decoder (ABI coder v1) copies dynamic arguments to memory without "
                               "bounds checks, so a huge length runs out of gas there; this code reads them in place"),
    ("abi:memory_start_above_0x80", "the original's decoder allocates from a free memory pointer above 0x80 (its "
                                    "compiler moved locals to memory): it raises Panic(0x41) on a few lengths near "
                                    "2**64 where the decoder of this declaration, allocating from 0x80, reverts "
                                    "without data"),
)
# the decompiler stopped simplifying the function's trace at its time limit: the code is exact
# but not fully simplified (no risk flag: the static guards ignore it; the tier stays exact)
FLAG_TIME_LIMITED = "time_limited"
_FLAG_NOTES = _DECODER_NOTES + (
    (FLAG_TIME_LIMITED, "the decompiler stopped simplifying this function at its time limit: the code is exact "
                        "but not fully simplified"),
)


def _natspec(unit: Unit, ind: str) -> List[str]:
    spec = unit.spec
    lines = []
    if spec.selector is not None:
        sig = comment_text(spec.signature or "unknown name", 200)
        lines.append(f"{ind}/// @notice selector 0x{spec.selector:08x} ({sig})")
    elif spec.kind == "receive":
        lines.append(f"{ind}/// @notice receive: calls without calldata")
    else:
        lines.append(f"{ind}/// @notice fallback: calls matching no selector")
    if unit.verdict in DIFFERING:
        lines.append(f"{ind}/// @dev NOT EQUIVALENT: executed against the original, this code behaved differently "
                     f"(verdict {unit.verdict})")
        if unit.counterexample:
            lines.append(f"{ind}/// @dev counterexample: {comment_text(unit.counterexample, 400)}")
    elif unit.verdict == "INCONCLUSIVE" and unit.reason:
        lines.append(f"{ind}/// @dev INCONCLUSIVE: {comment_text(unit.reason, 300)}")
        if unit.counterexample:
            lines.append(f"{ind}/// @dev counterexample: {comment_text(unit.counterexample, 400)}")
    for flag, note in _FLAG_NOTES:
        if flag in unit.flags:
            lines.append(f"{ind}/// @dev {note}")
    flags = sorted(unit.flags)
    tag = f"tier={unit.tier} verdict={unit.verdict}"
    if unit.passes:
        tag += " passes=" + ",".join(unit.passes)
    if unit.disabled:
        tag += " off=" + ",".join(unit.disabled)
    if flags:
        tag += " flags=" + ",".join(flags)
    if unit.guards:
        tag += " guards=" + ",".join(unit.guards)
    lines.append(f"{ind}/// @custom:scobelix {tag}")
    return lines


_NOTICE_RE = re.compile(r"^    /// @notice (?:selector 0x([0-9a-f]{8}) \(|(receive): |(fallback): )")
_HELPERS = "// ---- EVM-exact helpers"


def entry_spans(source: str, ci: ContractInput) -> List[Tuple[int, int, str]]:
    """Where `assemble` wrote the entry points of `ci` in `source`: (first
    line, last line, unit key), lines counted from 1.  A span runs from the
    NatSpec of the function to the line before the next entry point (or
    before the internal functions of the declarations, the helpers, the end
    of the contract).  The lines outside every span belong to the contract
    as a whole: header, declarations, the routing fallback, helpers.  An
    entry point folded into a declaration has no span."""
    by_selector = {u.spec.selector: u.key for u in ci.units if u.spec.selector is not None}
    by_kind = {u.spec.kind: u.key for u in ci.units if u.spec.kind in ("receive", "fallback")}
    stops = {"    " + decl.split("\n")[0] for decl in ci.declarations.get("function", [])}
    lines = source.split("\n")
    spans: List[Tuple[int, int, str]] = []
    start, key = 0, None
    for number, line in enumerate(lines + ["}"], 1):
        m = _NOTICE_RE.match(line)
        if not (m or line == "}" or line in stops or line.strip().startswith(_HELPERS)):
            continue
        if key is not None:
            spans.append((start, number - 1, key))
        start, key = number, None
        if m:
            key = by_selector.get(int(m.group(1), 16)) if m.group(1) else by_kind.get(m.group(2) or m.group(3))
    return spans


_ROUTE_RE = re.compile(r"^            if \(msg\.sig == 0x([0-9a-f]{8})\)(.*)$")


def router_spans(source: str, ci: ContractInput) -> List[Tuple[int, int, str]]:
    """(first line, last line, unit key) of the statements of fallback()
    that route one selector (its test and the block that decodes, calls,
    returns): they belong to that routed function, not to the fallback."""
    by_selector = {u.spec.selector: u.key for u in ci.units if u.spec.routed}
    lines = source.split("\n")
    out: List[Tuple[int, int, str]] = []
    number = 0
    while number < len(lines):
        m = _ROUTE_RE.match(lines[number])
        number += 1
        key = by_selector.get(int(m.group(1), 16)) if m else None
        if key is None:
            continue
        first = number
        if m.group(2).endswith("{"):
            while number < len(lines) and lines[number] != "            }":
                number += 1
            number += 1
        out.append((first, min(number, len(lines)), key))
    return out


class _Structs:
    """Struct declarations for tuple parameter types."""

    def __init__(self):
        self.names: Dict[str, str] = {}
        self.decls: List[str] = []

    def name(self, t: SolType) -> str:
        key = t.canonical
        if key not in self.names:
            members = [f"{c.solidity('', self.name)} m{i};" for i, c in enumerate(t.components)]
            name = f"S{len(self.names)}"
            self.names[key] = name
            self.decls.append(f"struct {name} {{ " + " ".join(members) + " }")
        return self.names[key]


def _word_views(params: Sequence[Tuple[SolType, str]], abi_v2: bool) -> Dict[int, str]:
    """Head word -> uint256 expression equal to that calldata word, for the
    declared value parameters (under ABI coder v2 the decoder validated
    them; under v1 only full-width types carry the raw word)."""
    views, word = {}, 0
    for t, name in params:
        if t.is_value:
            text = None
            if t.kind == "uint":
                text = name if t.bits == 256 else f"uint256({name})"
            elif t.kind == "int":
                text = f"uint256({name})" if t.bits == 256 else f"uint256(int256({name}))"
            elif t.kind == "bytes":
                text = f"uint256({name})" if t.bits == 256 else f"uint256(bytes32({name}))"
            elif t.kind == "address":
                text = f"uint256(uint160({name}))"
            elif t.kind == "bool":
                text = f"uint256({name} ? 1 : 0)"
            full = (t.kind in ("uint", "int", "bytes") and t.bits == 256)
            if text is not None and (abi_v2 or full):
                views[word] = text
        word += t.head_words
    return views


def _word_bits(params: Sequence[Tuple[SolType, str]], abi_v2: bool) -> Dict[int, int]:
    """Head word -> bit width of the validated value parameters' views."""
    out, word = {}, 0
    for t, _ in params:
        if abi_v2 and t.is_value:
            if t.kind == "uint":
                out[word] = t.bits
            elif t.kind == "address":
                out[word] = 160
            elif t.kind == "bool":
                out[word] = 1
        word += t.head_words
    return out


def _word_params(spec, abi_v2: bool) -> Dict[int, Tuple[str, SolType]]:
    """Head word -> (name, type) of the declared value parameters whose
    name is a value of their ABI type carrying the head word (the words
    _word_views covers, except a parameter declared as an enum)."""
    out, word = {}, 0
    for i, (t, name) in enumerate(spec.params):
        full = t.kind in ("uint", "int", "bytes") and t.bits == 256
        if t.is_value and (abi_v2 or full) and not spec.type_names.get(i):
            out[word] = (name, t)
        word += t.head_words
    return out


def _dynamic_views(params: Sequence[Tuple[SolType, str]]) -> Dict[int, Tuple[str, SolType]]:
    """Head word -> (name, type) of the declared `bytes` / `string` / `T[]`
    parameters (the renderer reads their length and bytes through them).
    The other dynamic types have no length word: what their head offset
    points to is the first member of a struct, the first element of a
    fixed-size array."""
    views, word = {}, 0
    for t, name in params:
        if t.kind in ("dynbytes", "string") or (t.kind == "array" and t.length is None):
            views[word] = (name, t)
        word += t.head_words
    return views


def _modifiers(spec: EntrySpec) -> str:
    """The modifiers of the function's header (modifiers pass)."""
    return "".join(f" {m}" for m in getattr(spec, "modifiers", ()) or ())


def _signature(unit: Unit, structs: _Structs, mutability: str) -> str:
    spec = unit.spec
    params = []
    for i, (t, name) in enumerate(spec.params):
        loc = spec.locations.get(i, "calldata") if t.needs_location else ""
        text = spec.type_names.get(i) or t.solidity(loc, structs.name)
        params.append(f"{text} {name}")
    head = f"function {spec.name}({', '.join(params)}) external"
    if mutability in ("payable", "view", "pure"):
        head += f" {mutability}"
    head += _modifiers(spec)
    if spec.returns:
        head += " returns (" + ", ".join(t.solidity("memory" if t.needs_location else "", structs.name)
                                          for t in spec.returns) + ")"
    return head


def _render(unit: Unit, entry: EntryRender, ctx: RenderContext, ind: int = 2) -> List[str]:
    lines, flags = render_function_body(unit.fn, entry, ctx, ind)
    unit.flags |= flags
    if ctx.trivial_idiomatic and unit.tier == "exact" and not unit.passes and not unit.guards \
            and not unit.disabled and FLAG_TIME_LIMITED not in unit.flags and not exact_machinery("\n".join(lines)):
        unit.tier = "idiomatic"  # no pass had anything to rewrite: the exact form is the usual one
    return lines


# ---------------------------------------------------------------- typed routes


# The private function of a typed route holds its parameters and return
# values at the bottom of the frame of a body that read the calldata before
# (the untyped route): the slots its deepest expressions reach last.  The
# renderer counts them this many slots more against its stack budget, so a
# body close to that budget keeps its locals in memory arrays rather than
# failing with "Stack too deep" where the untyped body compiled.
_ROUTE_MARGIN = 3


def _fresh(base: str, taken: Set[str]) -> str:
    """A local name of the router that no contract-level name shadows."""
    while base in taken or reserved_name(base, parameter=True):
        base += "_"
    return base


def _param_types(spec: EntrySpec, structs: _Structs, located: bool = True) -> List[str]:
    """The parameter types of a typed route: as declared (a reference type
    in memory, where abi.decode puts it), or as abi.decode lists them."""
    return [spec.type_names.get(i) or t.solidity("memory" if located and t.needs_location else "", structs.name)
            for i, (t, _) in enumerate(spec.params)]


def _return_types(spec: EntrySpec, structs: _Structs) -> List[str]:
    return [t.solidity("memory" if t.needs_location else "", structs.name) for t in spec.returns or ()]


def _routed_signature(unit: Unit, structs: _Structs, mutability: str) -> str:
    """The private function of a typed route: the parameters the router
    decodes, the return values it encodes."""
    spec = unit.spec
    params = ", ".join(f"{t} {name}" for t, (_, name) in zip(_param_types(spec, structs), spec.params))
    head = f"function _fn_{spec.selector:08x}({params}) private" + (f" {mutability}" if mutability else "")
    head += _modifiers(spec)
    if spec.returns:
        head += " returns (" + ", ".join(_return_types(spec, structs)) + ")"
    return head


def _routed_entry(unit: Unit, abi_v2: bool, declared: Set[str]) -> EntryRender:
    """The body of a typed route reads its parameters like an external
    function's (the router's abi.decode validated them the same way) and
    returns its values to the router (`return (...)`, or `return;` to the
    router's `return "";` without declared returns: an empty success, as
    the original's STOP).  Raw returns and stops with declared returns
    halt there (helpers); msg.value is read by a helper (private).
    Parameters and return values take _ROUTE_MARGIN more stack slots in
    the renderer's count (see there)."""
    spec = unit.spec
    slots = len(spec.params) + len(spec.returns or ())
    # (a dynamic calldata parameter takes two slots: offset and length)
    wide = sum(1 for t, _ in spec.params if t.is_dynamic or (t.kind == "array" and t.length is None))
    return EntryRender("external", payable=False, returns=spec.returns,
                       word_views=_word_views(spec.params, abi_v2), reserved={n for _, n in spec.params} | declared,
                       stack_slots=slots + (_ROUTE_MARGIN if slots else 0),
                       stack_margin=(_ROUTE_MARGIN - wide) if slots else 0,
                       word_bits=_word_bits(spec.params, abi_v2), dynamic_views=_dynamic_views(spec.params),
                       word_params=_word_params(spec, abi_v2))


def _route_call(unit: Unit, inp: str, structs: _Structs, declared: Set[str]) -> List[str]:
    """The router's statements for a typed route: decode the calldata after
    the selector (the original decoder's checks, see passes/abi._route),
    call the private function, return the standard encoding of its values
    (the original's return data: abi.pass declared only returns that
    encode the words it returned), or an empty success."""
    spec = unit.spec
    types, listed = _param_types(spec, structs), _param_types(spec, structs, located=False)
    lines: List[str] = []
    if not types:
        args = ""
    elif len(types) == 1:
        args = f"abi.decode({inp}[4:], ({listed[0]}))"
    else:
        # the private function's parameter names (each `if` of the router
        # is a scope of its own)
        names: List[str] = []
        for i, (_, n) in enumerate(spec.params):
            names.append(_fresh(n or f"a{i}", set(declared) | {inp} | set(names)))
        lines.append("(" + ", ".join(f"{t} {n}" for t, n in zip(types, names))
                     + f") = abi.decode({inp}[4:], ({', '.join(listed)}));")
        args = ", ".join(names)
    call = f"_fn_{spec.selector:08x}({args})"
    rets = _return_types(spec, structs)
    if not rets:
        return lines + [f"{call};", 'return "";']
    if len(rets) == 1:
        return lines + [f"return abi.encode({call});"]
    names = [_fresh(f"r{i}", declared) for i in range(len(rets))]
    lines.append("(" + ", ".join(f"{t} {n}" for t, n in zip(rets, names)) + f") = {call};")
    lines.append(f"return abi.encode({', '.join(names)});")
    return lines


def assemble(ci: ContractInput, ctx: Optional[RenderContext] = None) -> Tuple[str, RenderContext]:
    """The Solidity source of the contract, and the render context (helpers
    used, features needed)."""
    ctx = ctx or RenderContext(target=_version(ci.target), abi_v2=ci.abi_v2,
                               trivial_idiomatic=ci.idiom_level != "exact")
    if ci.declarations.get("error"):
        # (a declared error needs them, even when only a modifier, written
        # once outside the bodies rendered here, reverts with it)
        ctx.need("custom errors", (0, 8, 4))
    declared = _declared_names(ci)  # the locals of every body avoid them
    structs = _Structs()
    I1, I2 = "    ", "        "
    externals: List[str] = []
    routed: List[Unit] = []
    fallback_unit: Optional[Unit] = None
    receive_unit: Optional[Unit] = None

    for unit in sorted(ci.units, key=lambda u: (u.spec.selector is None, u.spec.selector or 0, u.key)):
        spec = unit.spec
        if unit.folded and spec.kind == "function" and not spec.routed:
            continue  # solc generates it from the declaration
        if spec.kind == "fallback":
            fallback_unit = unit
            continue
        if spec.kind == "receive":
            receive_unit = unit
            continue
        if spec.routed:
            routed.append(unit)
            continue
        taken = {n for _, n in spec.params}
        # (a dynamic calldata parameter takes two slots: offset and length)
        param_slots = tuple((n, 2 if t.is_dynamic or (t.kind == "array" and t.length is None) else 1)
                            for t, n in spec.params)
        slots = sum(k for _, k in param_slots) + len(spec.returns or ())
        at = len(externals)  # (its NatSpec goes here once the body is written: the tier depends on it)
        externals.append(I1 + _signature(unit, structs, spec.mutability) + " {")
        if slots > _WRAP_SLOTS:
            # the parameters would fill the stack window: the body runs in a
            # private function of its own, reading the calldata directly
            body_name = f"_{spec.name}_{spec.selector:08x}"
            entry = EntryRender("internal", payable=spec.payable, reserved=set(declared))
            body = _render(unit, entry, ctx)
            externals.append(I2 + f"{body_name}();")
            externals.append(I1 + "}")
            externals.append("")
            mut = spec.mutability if spec.mutability in ("pure", "view") else ""
            externals.append(I1 + f"function {body_name}() private" + (f" {mut}" if mut else "") + " {")
            externals.extend(body)
        else:
            entry = EntryRender("external", payable=spec.payable, returns=spec.returns,
                                word_views=_word_views(spec.params, ci.abi_v2), reserved=taken | declared,
                                stack_slots=slots, param_slots=param_slots,
                                word_bits=_word_bits(spec.params, ci.abi_v2),
                                dynamic_views=_dynamic_views(spec.params), word_params=_word_params(spec, ci.abi_v2))
            externals.extend(_render(unit, entry, ctx))
        externals[at:at] = _natspec(unit, I1)
        externals.append(I1 + "}")
        externals.append("")

    # ---- fallback(): routing + the original fallback body
    routed_payable = any(u.spec.payable for u in routed)
    fb_needed = bool(routed) or (fallback_unit is not None and ci.fallback_present)
    fb_payable = ci.fallback_payable or routed_payable
    typed = any(u.spec.typed_route for u in routed)
    # with a typed route the fallback takes the calldata and returns the
    # raw bytes of the encoded return values (solc >= 0.7.6)
    inp = _fresh("input", declared) if typed else ""
    fallback_lines: List[str] = []
    private_lines: List[str] = []
    if fb_needed:
        if fallback_unit is None:
            fallback_lines.append(f"{I1}/// @notice fallback: routes the selectors without a known name")
        if typed:
            fallback_lines.append(I1 + f"fallback(bytes calldata {inp}) external" + (" payable" if fb_payable else "")
                                  + " returns (bytes memory) {")
        else:
            fallback_lines.append(I1 + "fallback() external" + (" payable" if fb_payable else "") + " {")
        if routed:
            fallback_lines.append(I2 + (f"if ({inp}.length >= 4) {{" if typed else "if (msg.data.length >= 4) {"))
            for u in routed:
                check = ["if (msg.value != 0) revert();"] if fb_payable and not u.spec.payable else []
                block = check + (_route_call(u, inp, structs, declared) if u.spec.typed_route
                                 else [f"_fn_{u.spec.selector:08x}();"])
                test = f"if (msg.sig == 0x{u.spec.selector:08x})"
                if len(block) == 1 and u.spec.typed_route:
                    fallback_lines.append(I2 + I1 + f"{test} {block[0]}")
                    continue
                fallback_lines.append(I2 + I1 + test + " {")
                fallback_lines.extend(I2 + I2 + line for line in block)
                fallback_lines.append(I2 + I1 + "}")
            fallback_lines.append(I2 + "}")
        if fallback_unit is not None and ci.fallback_present:
            # (under the typed form, `return;` is not allowed: an empty return
            # or a stop of the original's fallback is `return "";`)
            entry = EntryRender("fallback", payable=fb_payable, reserved=set(declared) | ({inp} if inp else set()),
                                returns=() if typed else None)
            fallback_lines.extend(_render(fallback_unit, entry, ctx))
        else:
            fallback_lines.append(I2 + "revert();")
        if fallback_unit is not None:
            fallback_lines[0:0] = _natspec(fallback_unit, I1)  # (once the body is written)
        fallback_lines.append(I1 + "}")
        fallback_lines.append("")
        for u in routed:
            mut = u.spec.mutability if u.spec.mutability in ("pure", "view") else ""
            at = len(private_lines)  # (its NatSpec, once the body is written)
            if u.spec.typed_route:
                private_lines.append(I1 + _routed_signature(u, structs, mut) + " {")
                private_lines.extend(_render(u, _routed_entry(u, ci.abi_v2, declared), ctx))
            else:
                entry = EntryRender("internal", payable=u.spec.payable, reserved=set(declared))
                body = _render(u, entry, ctx)
                private_lines.append(I1 + f"function _fn_{u.spec.selector:08x}() private" + (f" {mut}" if mut else "")
                                     + _modifiers(u.spec) + " {")
                private_lines.extend(body)
            private_lines[at:at] = _natspec(u, I1)
            private_lines.append(I1 + "}")
            private_lines.append("")

    receive_lines: List[str] = []
    if receive_unit is not None and ci.receive_present:
        receive_lines.append(I1 + "receive() external payable {")
        if _reads_calldata(receive_unit.fn):
            # solc rejects msg.data inside receive() (where it is empty): the
            # body runs in a private function
            body = _render(receive_unit, EntryRender("internal", payable=True, reserved=set(declared)), ctx)
            receive_lines.append(I2 + "_receive_body();")
            receive_lines.append(I1 + "}")
            receive_lines.append("")
            receive_lines.append(I1 + "function _receive_body() private {")
        else:
            body = _render(receive_unit, EntryRender("receive", payable=True, reserved=set(declared)), ctx)
        receive_lines.extend(body)
        receive_lines[0:0] = _natspec(receive_unit, I1)  # (once the body is written)
        receive_lines.append(I1 + "}")
        receive_lines.append("")

    # ---- the contract
    out: List[str] = []
    min_version = max([(0, 8, 2)] + list(ctx.features.values()))
    out.append("// SPDX-License-Identifier: UNLICENSED")
    out.extend(_header(ci, ctx, routed, receive_lines != [], fb_needed))
    out.append(f"pragma solidity ^{min_version[0]}.{min_version[1]}.{min_version[2]};")
    if not ci.abi_v2:
        out.append("pragma abicoder v1;")
    out.append("")
    for decl in ci.declarations.get("interface", []):
        out.append(decl)
        out.append("")
    out.append(f"/// @custom:scobelix reconstructed tier={ci.idiom_level}")
    out.append(f"contract {ci.contract_name} {{")
    pre: List[str] = []
    for kind in ("struct", "event", "error", "constant", "state", "modifier"):
        for decl in ci.declarations.get(kind, []):
            pre.extend(I1 + line if line.strip() else "" for line in decl.split("\n"))
    for decl in structs.decls:
        pre.append(I1 + decl)
    if ctx.uses_code_constant:
        pre.append(I1 + "// the original runtime code (read by codecopy)")
        pre.append(I1 + f'bytes private constant _ORIGINAL_CODE = hex"{ci.original_code.hex()}";')
    if pre:
        out.extend(pre)
        out.append("")
    out.extend(externals)
    out.extend(receive_lines)
    out.extend(fallback_lines)
    out.extend(private_lines)
    for decl in ci.declarations.get("function", []):  # internal functions of the passes
        out.extend(I1 + line if line.strip() else "" for line in decl.split("\n"))
        out.append("")
    helpers = ctx.helpers.sources()
    if helpers:
        out.append(I1 + "// ---- EVM-exact helpers (inline assembly where Solidity's semantics differ)")
        for src in helpers:
            out.extend(I1 + line if line.strip() else "" for line in src.split("\n"))
    while out and out[-1] == "":
        out.pop()
    out.append("}")
    return "\n".join(out) + "\n", ctx


# what the tags of a verified text mean (scobelix.verify.report names the verdicts)
_VERIFIED_LEGEND = [
    "//   tier=partial   as idiomatic, without the passes listed in off=...: the",
    "//                  verification switched them off for this function (with them",
    "//                  the text did not compile, or did not behave like the original).",
    "//   verdict=...    what running this text and the original on the same calls",
    "//                  showed.  The verification loop (a 'loop:' line above) keeps",
    "//                  a rewritten function only with one of the first two",
    "//                  verdicts; otherwise it writes it at tier=exact.",
    "//     EQUIVALENT               no difference on any call, and the original",
    "//                              accepted some of them: the same behaviour was",
    "//                              observed (on the calls tried, not proven).",
    "//     EQUIVALENT_REVERTS_ONLY  no difference, but the original rejected every",
    "//                              call: only the rejecting paths were observed.",
    "//     DIVERGENT                a call behaved differently (the function's @dev",
    "//                              lines give it): this function is not the",
    "//                              original's.",
    "//     MISSING, EXTRA           an entry point of the original that this text",
    "//                              does not have; one the original does not have.",
    "//     ROUTED                   dispatched by fallback(); behaviour not run.",
    "//     INCONCLUSIVE             differences the execution environment may",
    "//                              explain (gas, own code): nothing established.",
    "//     SKIPPED                  not run (budget, no EVM backend): unverified.",
    "//   levels         L0 the text compiles; L1 same selectors, payability, events",
    "//                  and errors; L2 every declared state variable sits at the",
    "//                  slot and offset inferred from the bytecode; L3 the runs",
    "//                  above; L4 the compiled text is the original bytecode apart",
    "//                  from metadata and immutables (fail is the usual outcome",
    "//                  and says nothing against the behaviour).",
]


def _header(ci: ContractInput, ctx: RenderContext, routed: List[Unit], has_receive: bool,
            has_fallback: bool) -> List[str]:
    named = sum(1 for u in ci.units if u.spec.kind == "function" and not u.spec.routed)
    typed = sum(1 for u in routed if u.spec.typed_route)
    lines = [
        "//",
        "// Reconstructed from runtime bytecode by Scobelix (solgen v2).",
        f"//   original compiler : {comment_text(ci.original, 120)}",
        f"//   target compiler   : solc {comment_text(ci.target, 40)}",
        f"//   idiom level       : {ci.idiom_level}",
        f"//   entry points      : {named} named, {len(routed)} routed"
        + (f" ({typed} typed)" if typed else "")
        + (", receive" if has_receive else "") + (", fallback" if has_fallback else ""),
    ]
    if ci.left_out:
        shown = ", ".join(ci.left_out[:6]) + (", ..." if len(ci.left_out) > 6 else "")
        lines.append(f"//   not decompiled    : {len(ci.left_out)} entry point(s) of the original are absent from "
                     f"this text ({comment_text(shown, 120)})")
    if ci.verification_summary:
        lines.append("//")
        lines.extend("//   " + comment_text(s, 200) for s in ci.verification_summary)
    else:
        lines.append("//   verification      : not run (nothing in this text was executed against the original)")
    lines += [
        "//",
        "// Legend (per-function @custom:scobelix tags)",
        "//   tier=exact     every operation keeps its EVM meaning: wrapping arithmetic in",
        "//                  unchecked blocks, helpers with inline assembly where Solidity",
        "//                  differs (division by zero, signed ops, masks...), storage by slot.",
        "//   tier=idiomatic the passes listed (passes=...) rewrote the function into the",
        "//                  usual Solidity form of the same behaviour (no passes: its",
        "//                  exact form needs no helper and already is that form).",
    ]
    if ci.verification_summary:
        lines += _VERIFIED_LEGEND
    else:
        lines += [
            "//   verdict=...    differential execution against the original: EQUIVALENT,",
            "//                  DIVERGENT, ... (unverified: not checked).",
        ]
    if routed:
        lines += [
            "//   routed         no known name for the selector: fallback() dispatches it on",
            "//                  msg.sig to a private function _fn_<selector>, so the same",
            "//                  calldata behaves the same.",
        ]
    if typed:
        lines[-1] = "//                  calldata behaves the same.  Typed when the original's decoder"
        lines += [
            "//                  checks give the parameter types: fallback() decodes them with",
            "//                  abi.decode (the same checks) and returns the encoded values;",
            "//                  untyped, the private function reads the calldata itself.",
        ]
    lines += [
        "//   flags          what the decompiled code may not reproduce exactly (engine:*",
        "//                  name decompiler limitations; unstructured marks code that",
        "//                  could not be translated and reverts instead).",
        "//   guards         the flags for which the function was kept at tier=exact: no",
        "//                  rewriting on top of code marked as doubtful.",
        "//",
    ]
    return lines

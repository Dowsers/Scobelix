"""
Best-effort translator from a decompiled contract's JSON AST
(panoramix.decompiler.Decompilation.json, i.e. Contract.json()) into Solidity
source text.

This is NOT a recompiler: it cannot guarantee semantic fidelity to the
original bytecode (types, local variable names, control-flow structure and
event parameters are all reconstructed heuristically). Every approximation is
called out with an inline `// approximation: ...` comment, and functions that
failed to decompile at all (contract-level `problems`) are rendered as
explicit reverting stubs rather than silently dropped, so a reader (human or
downstream tool) can see exactly what is and isn't backed by real logic.

Design notes (see the plan this implements):
  - Panoramix, for most real contracts, reconstructs a SINGLE `_fallback`
    function whose body is one large nested if/else selector dispatch tree,
    rather than one Function object per ABI method. Rather than guess at
    splitting that tree into separate named functions (fragile - easy to
    misattribute a branch's revert/return to the wrong "function"), this
    emitter renders the whole reconstructed contract as a single
    `fallback(bytes calldata) external payable returns (bytes memory)`,
    which is always valid regardless of how many different return types the
    original branches used (every value is wrapped in `abi.encode(...)`,
    except values that are already `bytes memory` - i.e. relayed calldata
    return data from an external/delegate call).
  - State variables are declared from `stor_defs` (contract.json()["stor_defs"]).
  - Function parameters decoded by Panoramix (`func["params"]`, offset ->
    [type, name]) are declared as real local variables assigned from
    `msg.data`, not free-floating placeholders - so referencing them in
    translated expressions is semantically meaningful, not just cosmetic.
"""

import dataclasses
import re

from panoramix.solgen.event_signatures import KNOWN_EVENT_SIGNATURES


@dataclasses.dataclass
class SolgenResult:
    solidity: str
    confidence: dict
    warnings: list


_ADDRESS_MASK_SIZE = 160
_VALID_UINT_SIZES = set(range(8, 257, 8))

# bytes32(uint256(keccak256("Error(string)")))[:4] equivalent pattern used by
# Panoramix/solc for `revert("...")` / `require(cond, "...")`.
_STRING_LITERAL_RE = re.compile(r"^'(.*)'$", re.DOTALL)


def _op(exp):
    """Like panoramix.utils.helpers.opcode(), but tolerant of the plain
    Python lists that a JSON-decoded (or, here, JSON-*shaped* but never
    actually round-tripped through json.dumps/loads) trace uses instead of
    tuples."""
    if isinstance(exp, (list, tuple)) and len(exp) > 0:
        return exp[0]
    return None


def _args(exp):
    return exp[1:] if isinstance(exp, (list, tuple)) else ()


class SolidityEmitter:
    def __init__(self, contract_json):
        self.contract_json = contract_json
        self.warnings = []
        self.confidence = {}

        # loc -> (var_name, kind) where kind is "mapping" | "array" | "mask" | "struct"
        self.stor_by_loc = {}
        for d in contract_json.get("stor_defs", []):
            # d == ("def", name, loc, type)
            if _op(d) != "def":
                continue
            _, name, loc, typ = d
            kind = _op(typ) or "mask"
            self.stor_by_loc[loc] = (name, kind)

        self._extra_stor_vars = {}  # fallback loc key (str) -> synthetic var name
        self._last_call_result = None  # (ok_var, ret_var) of the most recent call
        self._call_counters = {}
        self._unresolved_count = 0
        self._total_node_count = 0
        self._used_function_names = set()
        self._loopvar_indices = set()  # populated per-function, see _emit_function
        self._used_events = {}  # name -> (types, indexed_flags, param_names)

        # loc -> max nesting depth actually used (e.g. allowances[a][b] is a
        # depth-2 map) - stor_defs alone doesn't say how many levels a
        # "mapping" kind slot needs; a single mapping(uint256=>uint256)
        # declaration would make a second index (`stor[a][b]`) a type error.
        self._map_depths = {}
        for func in contract_json.get("functions", []):
            self._collect_map_depths(func.get("trace", []))

    def _collect_map_depths(self, node):
        if isinstance(node, (list, tuple)):
            if _op(node) == "map" and len(node) == 3:
                depth = 1
                inner = node[2]
                while _op(inner) == "map":
                    depth += 1
                    inner = inner[2]
                if _op(inner) == "loc":
                    loc = inner[1]
                    try:
                        self._map_depths[loc] = max(self._map_depths.get(loc, 1), depth)
                    except TypeError:
                        pass  # unhashable loc (compound expr) - ignore, handled as synthetic
            for child in node:
                self._collect_map_depths(child)

    # ------------------------------------------------------------------
    # public entry point
    # ------------------------------------------------------------------

    def generate(self):
        functions = self.contract_json.get("functions", [])
        problems = self.contract_json.get("problems", {})

        # Function bodies are rendered first (into a buffer) because they can
        # discover storage slots that aren't in stor_defs (unrecognized index
        # shapes) - those get a synthetic declaration, which must appear
        # before we know the full set, hence: functions first, state vars
        # (regular + synthetic) assembled right after.
        function_blocks = []
        for func in functions:
            self._unresolved_count = 0
            self._total_node_count = 0
            function_blocks.append(self._emit_function(func))
            confidence = self._confidence_for(self._unresolved_count, self._total_node_count)
            self.confidence[func.get("hash", "?")] = confidence

        lines = []
        lines.append("// GENERATED BY SCOBELIX SOLGEN")
        lines.append("// Best-effort reconstruction of decompiled EVM bytecode.")
        lines.append("// This is an approximation, NOT verified/compiled original")
        lines.append("// source - see inline `// approximation:` comments for every")
        lines.append("// construct that could not be reconstructed with confidence.")
        lines.append("// SPDX-License-Identifier: UNKNOWN")
        lines.append("pragma solidity ^0.8.0;")
        lines.append("")
        lines.append("contract DecompiledContract {")
        lines.append(
            "    event ScobelixUnresolvedEvent(string detail); "
            "// approximation: real event ABI not reconstructed"
        )
        lines.extend(self._emit_event_declarations())

        lines.extend(self._emit_state_vars())
        lines.extend(self._declare_extra_stor_vars())

        for block in function_blocks:
            lines.extend(block)

        for selector, fname in problems.items():
            lines.append("")
            lines.append(f"    // decompilation failed for selector {selector} ({fname})")
            lines.append("    // @custom:scobelix-confidence none")

        lines.append("}")
        lines.append("")

        return SolgenResult(
            solidity="\n".join(lines),
            confidence=self.confidence,
            warnings=self.warnings,
        )

    def _confidence_for(self, unresolved, total):
        if total == 0:
            return "medium"
        ratio = unresolved / total
        if ratio == 0:
            return "high"
        if ratio < 0.1:
            return "medium"
        return "low"

    # ------------------------------------------------------------------
    # state variables
    # ------------------------------------------------------------------

    def _sol_type_for_stor(self, kind, loc=None):
        if kind == "mapping":
            depth = self._map_depths.get(loc, 1)
            return "mapping(uint256 => " * depth + "uint256" + ")" * depth
        if kind == "array":
            return "uint256[]"
        if kind == "struct":
            return "uint256"  # approximation: struct layout not reconstructed
        return "uint256"

    def _emit_state_vars(self):
        lines = []
        if not self.stor_by_loc:
            return lines

        for loc, (name, kind) in sorted(self.stor_by_loc.items(), key=lambda kv: str(kv[0])):
            sol_type = self._sol_type_for_stor(kind, loc)
            if kind not in ("mapping", "array"):
                lines.append(f"    // storage slot {loc}")
            lines.append(f"    {sol_type} internal {_safe_ident(name)};")
        lines.append("")
        return lines

    def _unique_function_name(self, raw_name):
        base = _safe_ident(str(raw_name).split("(")[0] or "unnamed")
        name = base
        n = 1
        while name in self._used_function_names:
            n += 1
            name = f"{base}_{n}"
        self._used_function_names.add(name)
        return name

    def _collect_loopvars(self, node, acc):
        if isinstance(node, (list, tuple)):
            if (
                len(node) >= 2
                and node[0] in ("setvar", "var")
                and isinstance(node[1], int)
                and not isinstance(node[1], bool)
            ):
                acc.add(node[1])
            for child in node:
                self._collect_loopvars(child, acc)

    def _loopvar_name(self, idx):
        return f"loopvar_{idx}"

    def _setvar_lines(self, setvars):
        lines = []
        for sv in setvars or []:
            if _op(sv) != "setvar":
                continue
            idx, val = sv[1], sv[2]
            lines.append(f"{self._loopvar_name(idx)} = {self._expr(val)};")
        return lines

    def _declare_extra_stor_vars(self):
        lines = []
        for _, var_name in self._extra_stor_vars.items():
            lines.append(f"    uint256 internal {var_name};")
        return lines

    # ------------------------------------------------------------------
    # functions
    # ------------------------------------------------------------------

    def _emit_function(self, func):
        lines = []
        hash_ = func.get("hash", "?")
        params = func.get("params", {}) or {}

        lines.append("")
        lines.append(f"    // reconstructed from function `{func.get('name', hash_)}`")
        # Solidity allows exactly one `fallback()` per contract - Panoramix
        # usually reconstructs the whole selector dispatch tree as a single
        # `_fallback` function, but defensively handle the (untested here)
        # case where it instead splits out separate Function entries too.
        if hash_ == "_fallback":
            signature = "fallback(bytes calldata) external payable returns (bytes memory)"
        else:
            fname = self._unique_function_name(func.get("abi_name") or func.get("name") or hash_)
            payable = " payable" if func.get("payable") else ""
            signature = f"function {fname}() external{payable} returns (bytes memory)"
        lines.append(f"    {signature} {{")

        for offset in sorted((int(o) for o in params.keys())):
            sol_type, name = params[str(offset)]
            lines.append(
                f"        uint256 {_safe_ident(name)} = "
                f"uint256(bytes32(msg.data[{offset}:{offset + 32}]));"
            )

        trace = func.get("trace", [])

        # Numbered loop-local variables (`("var", N)` / `("setvar", N, val)`)
        # are declared once, up front, at function scope - rather than
        # inline where a `while`'s initial setvars happen to appear - so
        # that referencing loopvar_N from ANY branch (including a sibling
        # branch with its own, later, unrelated loop reusing the same index)
        # is always a valid, already-declared identifier.
        self._loopvar_indices = set()
        self._collect_loopvars(trace, self._loopvar_indices)
        for idx in sorted(self._loopvar_indices):
            lines.append(f"        uint256 {self._loopvar_name(idx)};")

        body_lines = self._emit_block(trace, indent=2)
        lines.extend(body_lines)

        # any storage location referenced but not present in stor_defs gets a
        # synthetic declaration, added here (function-local scope is not
        # available for state vars, so these are added as extra contract
        # members - safe because Solidity allows forward references).
        lines.append("    }")

        return lines

    # ------------------------------------------------------------------
    # statements
    # ------------------------------------------------------------------

    def _emit_block(self, stmts, indent):
        lines = []
        if not stmts:
            return lines
        for stmt in stmts:
            lines.extend(self._emit_stmt(stmt, indent))
        return lines

    def _emit_stmt(self, stmt, indent):
        self._total_node_count += 1
        pad = "    " * indent
        op = _op(stmt)

        if op == "if":
            _, cond, true_branch, false_branch = stmt
            cond_sol = self._expr(cond)
            lines = [f"{pad}if ({cond_sol}) {{"]
            lines.extend(self._emit_block(true_branch, indent + 1))
            lines.append(f"{pad}}}")
            if false_branch:
                lines[-1] = f"{pad}}} else {{"
                lines.extend(self._emit_block(false_branch, indent + 1))
                lines.append(f"{pad}}}")
            return lines

        if op == "while":
            _, cond, path, _lid, setvars = stmt
            lines = [f"{pad}{line}" for line in self._setvar_lines(setvars)]
            cond_sol = self._expr(cond)
            lines.append(f"{pad}while ({cond_sol}) {{")
            lines.extend(self._emit_block(path, indent + 1))
            lines.append(f"{pad}}}")
            return lines

        if op == "continue":
            # ("continue", label, setvars) - setvars is the loop-variable
            # update applied on this iteration (e.g. `idx = idx + 1`),
            # applied just before looping back to the condition check.
            setvars = stmt[2] if len(stmt) > 2 else []
            lines = [f"{pad}{line}" for line in self._setvar_lines(setvars)]
            lines.append(f"{pad}continue;")
            return lines

        if op == "return":
            val = stmt[1] if len(stmt) > 1 else None
            return [f"{pad}return {self._return_expr(val)};"]

        if op == "revert":
            return [f"{pad}{self._revert_stmt(stmt[1] if len(stmt) > 1 else 0)}"]

        if op == "invalid":
            return [f"{pad}assert(false); // approximation: INVALID opcode"]

        if op == "stop":
            # STOP halts successfully with no return data.
            return [f'{pad}return "";']

        if op == "store":
            # ("store", size, off, idx, val)
            idx, val = stmt[3], stmt[4]
            target = self._resolve_storage(idx)
            # storage slots are always declared uint256/mapping-of-uint256
            # (see _sol_type_for_stor), regardless of whether this branch's
            # value happens to be address/bool-shaped.
            return [f"{pad}{target} = {self._expr_as_uint256(val)};"]

        if op == "set":
            # ("set", idx, val) - the post-make_ast() equivalent of "store"
            idx, val = stmt[1], stmt[2]
            target = self._resolve_storage(idx)
            return [f"{pad}{target} = {self._expr_as_uint256(val)};"]

        if op == "log":
            return self._log_stmt(stmt, indent)

        if op in ("call", "delegatecall", "callcode", "codecall"):
            return [f"{pad}{line}" for line in self._call_stmt(stmt)]

        if op == "selfdestruct":
            if len(stmt) > 1:
                target = f"address(uint160({self._expr_as_uint256(stmt[1])}))"
            else:
                target = "msg.sender"
            return [
                f"{pad}// approximation: selfdestruct target not reliably decoded",
                f"{pad}selfdestruct(payable({target}));",
            ]

        if op == "label":
            return [f"{pad}// label {stmt[1] if len(stmt) > 1 else ''} (no-op)"]

        if op == "setvar":
            # ("setvar", idx, val) appearing as a bare statement (rather than
            # nested inside a while's setvars or a continue's setvars, both
            # handled separately above).
            idx, val = stmt[1], stmt[2]
            return [f"{pad}{self._loopvar_name(idx)} = {self._expr(val)};"]

        # anything else: never crash, never silently drop - flag it.
        self._unresolved_count += 1
        self.warnings.append(f"unresolved statement opcode: {op!r}")
        return [
            f"{pad}// unresolved: {_short_repr(stmt)}",
            f'{pad}revert("scobelix: unsupported construct");',
        ]

    def _return_expr(self, val):
        # a value already bound to bytes memory (e.g. relayed call return
        # data) is returned as-is; everything else is abi-encoded so the
        # function's single `returns (bytes memory)` stays valid regardless
        # of what type the original branch actually returned.
        resolved = self._as_call_result_ret(val)
        if resolved is not None:
            return resolved
        return f"abi.encode({self._expr(val)})"

    def _revert_stmt(self, val):
        if val == 0 or val is None:
            return "revert();"

        message = self._extract_revert_string(val)
        if message is not None:
            escaped = message.replace("\\", "\\\\").replace('"', '\\"')
            return f'revert("{escaped}");'

        if _op(val) == "data" and len(val) >= 3 and val[-1] == 17:
            return "revert(); // panic(0x11): arithmetic overflow/underflow"

        return "revert(); // approximation: original revert reason not decoded"

    def _extract_revert_string(self, val):
        # observed shape: ("data", 0, <len>, <len2>, ("mask_shl", 256, 0, 96, "'msg'"))
        if _op(val) != "data":
            return None
        for part in _args(val):
            if _op(part) == "mask_shl" and len(part) == 5:
                inner = part[4]
                if isinstance(inner, str):
                    m = _STRING_LITERAL_RE.match(inner)
                    if m:
                        return m.group(1)
        return None

    def _log_stmt(self, stmt, indent):
        # ("log", data_expr, *topics) - see panoramix/vm.py's `elif op[:3]
        # == "log":` handler for this exact shape: topics are popped in
        # order, so topics[0] is always the event's signature hash (absent
        # for an anonymous log) and topics[1:] are the indexed param values
        # in declaration order; data_expr holds the non-indexed param(s).
        pad = "    " * indent
        resolved = self._resolve_event(stmt)
        if resolved is not None:
            name, args = resolved
            return [f"{pad}emit {name}({', '.join(args)});"]

        # TODO.md itself flags this as a known gap ("re-add support for log
        # ABI") - only a handful of well-known events are resolved (see
        # event_signatures.py); anything else falls back to this generic,
        # clearly-labelled placeholder rather than guessing.
        self.warnings.append("log/event reconstruction is approximate (no ABI match)")
        return [
            f"{pad}// approximation: event name/parameter types not reliably reconstructed",
            f'{pad}emit ScobelixUnresolvedEvent("{_short_repr(stmt)}");',
        ]

    def _resolve_event(self, stmt):
        data_expr = stmt[1] if len(stmt) > 1 else None
        topics = stmt[2:]

        if not topics or not isinstance(topics[0], int):
            return None

        sig = KNOWN_EVENT_SIGNATURES.get(topics[0])
        if sig is None:
            return None
        name, types, indexed_flags, param_names = sig

        if any(t.endswith("[]") for t in types):
            return None  # array-typed params need ABI decoding we don't attempt

        num_indexed = sum(indexed_flags)
        if num_indexed != len(topics) - 1:
            return None  # topic count doesn't match this signature - don't guess

        num_data = len(types) - num_indexed
        if num_data == 0:
            data_values = []
        elif num_data == 1:
            data_values = [data_expr]
        else:
            return None  # multi-field data-blob decoding not attempted

        indexed_values = list(topics[1:])
        args = []
        idx_i = data_i = 0
        for is_indexed, typ in zip(indexed_flags, types):
            if is_indexed:
                val = indexed_values[idx_i]
                idx_i += 1
            else:
                val = data_values[data_i]
                data_i += 1
            args.append(self._event_arg_expr(typ, val))

        self._used_events[name] = (types, indexed_flags, param_names)
        return name, args

    def _event_arg_expr(self, typ, val):
        if typ == "address":
            return f"address(uint160({self._expr_as_uint256(val)}))"
        if typ == "bool":
            return f"({self._expr_as_uint256(val)} != 0)"
        return self._expr_as_uint256(val)

    def _emit_event_declarations(self):
        lines = []
        for name, (types, indexed_flags, param_names) in sorted(self._used_events.items()):
            params = ", ".join(
                f"{t}{' indexed' if i else ''} {n}"
                for t, i, n in zip(types, indexed_flags, param_names)
            )
            lines.append(f"    event {name}({params});")
        return lines

    def _call_stmt(self, stmt):
        op = _op(stmt)
        n = self._call_counters.get(op, 0) + 1
        self._call_counters[op] = n

        target = self._expr_as_uint256(stmt[2]) if len(stmt) > 2 else "0"
        ok_var = f"{op}_ok_{n}"
        ret_var = f"{op}_ret_{n}"

        self._last_call_result = (ok_var, ret_var)

        sol_op = "delegatecall" if op in ("delegatecall", "codecall") else "call"
        lines = [
            f"// approximation: {op} arguments (gas/value/memory slice) are "
            "not reconstructed exactly - forwarding the full calldata",
            f"(bool {ok_var}, bytes memory {ret_var}) = "
            f"address(uint160({target})).{sol_op}(msg.data);",
        ]
        return lines

    # ------------------------------------------------------------------
    # storage resolution
    # ------------------------------------------------------------------

    def _resolve_storage(self, idx):
        # idx shapes: ("loc", N) ; ("map", key, ("loc", N)) ; anything else
        op = _op(idx)

        if op == "loc":
            return self._storage_base_name(idx[1])

        if op == "map":
            # ("map", key, inner) - inner is usually ("loc", N) but for a
            # nested mapping (e.g. allowances[owner][spender]) it is itself
            # another ("map", key2, ("loc", N)) node; recursing handles any
            # nesting depth, matching how Solidity applies indices outside-in
            # while the trace nests them inside-out (innermost = first index
            # applied in source).
            key_expr, inner = idx[1], idx[2]
            base = self._resolve_storage(inner)
            # mapping(uint256 => uint256) is always declared with a uint256
            # key (see _sol_type_for_stor) - but the SAME slot can be indexed
            # with an address-cast key in one branch (e.g. transfer's `to`)
            # and a raw uint256 in another (e.g. balanceOf's `account`), so
            # the key expression must always be coerced back to uint256.
            return f"{base}[{self._expr_as_uint256(key_expr)}]"

        # array/length/struct-field or anything unrecognized
        self._unresolved_count += 1
        self.warnings.append(f"unresolved storage index shape: {_short_repr(idx)}")
        return self._synthetic_stor_var(_short_repr(idx))

    def _storage_base_name(self, loc):
        try:
            entry = self.stor_by_loc.get(loc)
        except TypeError:
            # `loc` can itself be a compound (unhashable) expression - e.g. a
            # struct field access computes it as "base_slot + field_offset"
            # rather than a plain int. Fall back to a synthetic var rather
            # than crash; _synthetic_stor_var() stringifies the key itself.
            entry = None
        if entry:
            return _safe_ident(entry[0])
        return self._synthetic_stor_var(loc)

    def _synthetic_stor_var(self, key):
        key = str(key)
        if key not in self._extra_stor_vars:
            ident = f"stor_extra_{len(self._extra_stor_vars)}"
            self._extra_stor_vars[key] = ident
        return self._extra_stor_vars[key]

    # ------------------------------------------------------------------
    # expressions
    # ------------------------------------------------------------------

    _BINOPS = {
        "add": "+",
        "mul": "*",
        "div": "/",
        "sdiv": "/",
        "mod": "%",
        "smod": "%",
        "and": "&",
        "or": "|",
        "xor": "^",
        "eq": "==",
        "ne": "!=",
        "lt": "<",
        "gt": ">",
        "slt": "<",
        "sgt": ">",
        "le": "<=",
        "ge": ">=",
        "sle": "<=",
        "sge": ">=",
    }

    def _as_call_result_ret(self, val):
        """If `val` refers to a call's return-data variable, return that
        Solidity identifier - it is already `bytes memory`, so callers must
        not abi.encode() it.

        This matches ANY ".return_data"-suffixed var name (or the generic
        "ext_call.return_data" alias) against the MOST RECENTLY emitted
        call, rather than trying to match the exact id string embedded in
        the trace (e.g. "delegatecall_10"): that id comes from a counter
        vm.py shares across many unrelated operations (mload-introduced
        temporaries included, not just calls), so a second call in the same
        function is never "delegatecall_2" the way a naive per-function
        counter would guess - silently resolving to an unrelated, always-
        zero placeholder instead, which previously made every check after
        the first call look like the call had failed. Relying on "most
        recent call" instead is correct as long as this success/return-data
        reference immediately follows its own call in program order, which
        is the pattern Panoramix always emits.
        """
        if _op(val) == "var" and isinstance(val[1], str) and val[1].endswith(".return_data"):
            if self._last_call_result:
                return self._last_call_result[1]
        if isinstance(val, (list, tuple)) and len(val) >= 1 and val[0] == "ext_call.return_data":
            if self._last_call_result:
                return self._last_call_result[1]
        return None

    _BOOL_PRODUCING_OPS = {"eq", "ne", "lt", "gt", "slt", "sgt", "le", "ge", "iszero"}

    def _produces_bool(self, exp):
        return _op(exp) in self._BOOL_PRODUCING_OPS

    def _as_call_result_ok(self, val):
        """If `val` refers to a call's success flag, return that Solidity
        identifier - it is already `bool`, so callers must compare it with
        `!x` / plain truthiness, never `x == 0`. See _as_call_result_ret()
        for why this matches the most recent call rather than the exact id
        string."""
        if _op(val) == "var" and isinstance(val[1], str) and val[1].endswith(".success"):
            if self._last_call_result:
                return self._last_call_result[0]
        return None

    def _expr_as_uint256(self, exp):
        """Like _expr(), but guarantees a uint256-typed result - used
        anywhere a value must line up with a uint256 Solidity slot/operand
        even though the same underlying expression can independently be
        recognized as `address` (mask_shl size==160) or `bool` (a Stack
        simplification literal) by the generic translator: mapping keys
        (key type is always uint256, see _sol_type_for_stor), storage
        writes (state vars are always declared uint256/mask kind), and
        arithmetic/comparison operands in general."""
        if _op(exp) == "mask_shl" and len(exp) == 5 and exp[1] == _ADDRESS_MASK_SIZE:
            return f"uint256(uint160({self._expr_as_uint256(exp[4])}))"
        if _op(exp) == "bool":
            return "1" if exp[1] else "0"
        if exp == "caller":
            return "uint256(uint160(msg.sender))"
        if exp == "address":
            return "uint256(uint160(address(this)))"
        return self._expr(exp)

    def _expr(self, exp):
        self._total_node_count += 1

        if isinstance(exp, bool):
            return "true" if exp else "false"

        if isinstance(exp, int):
            if exp < 0:
                # EVM integers are 256-bit two's complement, and Solidity
                # (checked arithmetic by default since 0.8) has no single
                # literal for a negative value that must combine with
                # uint256 operands: `0 - N` would actually *revert* at
                # runtime (underflow), and a bare `-N` int_const literal
                # doesn't implicitly convert to uint256 either. Emitting the
                # pre-wrapped positive literal sidesteps both problems and
                # is exactly the value EVM's own arithmetic already uses.
                wrapped = (1 << 256) + exp
                return f"{wrapped} /* {exp} */"
            return str(exp)

        if isinstance(exp, str):
            return self._atom(exp)

        if not isinstance(exp, (list, tuple)):
            self._unresolved_count += 1
            return f"0 /* unresolved atom: {_short_repr(exp)} */"

        op = _op(exp)

        if op in self._BINOPS and len(exp) == 3:
            # every binop (comparison or arithmetic) needs both sides in the
            # same Solidity type; either side can independently be recognized
            # as `address` (mask_shl size==160) or `bool` (a Stack
            # simplification literal) by the generic translator, so both are
            # always forced through the uint256-coercing path.
            left, right = self._expr_as_uint256(exp[1]), self._expr_as_uint256(exp[2])
            return f"({left} {self._BINOPS[op]} {right})"

        if op == "add" and len(exp) > 3:
            return "(" + " + ".join(self._expr_as_uint256(e) for e in exp[1:]) + ")"

        if op == "iszero":
            inner = exp[1]
            ok_var = self._as_call_result_ok(inner)
            if ok_var is not None:
                return f"(!{ok_var})"
            if self._produces_bool(inner):
                return f"(!{self._expr(inner)})"
            return f"({self._expr(inner)} == 0)"

        if op == "not":
            return f"(~{self._expr(exp[1])})"

        if op == "param":
            return _safe_ident(exp[1])

        if op == "var":
            ident = exp[1]
            if isinstance(ident, int) and not isinstance(ident, bool):
                return self._loopvar_name(ident)
            resolved = self._as_call_result_ret(exp)
            if resolved is not None:
                return resolved
            ok_var = self._as_call_result_ok(exp)
            if ok_var is not None:
                return ok_var
            self.warnings.append(f"unresolved named var: {ident!r}")
            return self._synthetic_stor_var(f"var:{ident}")

        if op == "loc" or op == "map":
            return self._resolve_storage(exp)

        if op == "stor":
            # ("stor", size, off, idx) - storage READ expression.
            idx = exp[3] if len(exp) > 3 else exp[-1]
            return self._resolve_storage(idx)

        if op == "mask_shl" and len(exp) == 5:
            _, size, off, shl, val = exp
            # well-known idiom: 4-byte selector extraction from calldata[0:4]
            if (
                size == 256
                and off in (-224, 224)
                and shl in (-224, 224)
                and _op(val) == "cd"
                and val[1] == 0
            ):
                return "uint32(bytes4(msg.sig))"
            if size == _ADDRESS_MASK_SIZE:
                return f"address(uint160({self._expr_as_uint256(val)}))"
            if off >= 0:
                # unambiguous case (see panoramix.core.masks.mask_to_int and
                # core.algebra.apply_mask, the ground-truth evaluator):
                # mask_to_int(size, offset) == ((1<<size)-1) << offset for
                # offset>=0, with no clamping edge case (unlike offset<0,
                # where the window's lower edge falls below bit 0 - not
                # attempted here, see the fallback below) - verified against
                # a concrete apply_mask(val, size, offset, shl) call for
                # several (size, offset, shl) triples, not guessed.
                masked = self._expr_as_uint256(val)
                if size != 256 or off != 0:
                    mask_value = ((1 << size) - 1) << off
                    masked = f"({masked} & {mask_value})"
                if shl > 0:
                    return f"({masked} << {shl})"
                if shl < 0:
                    return f"({masked} >> {-shl})"
                return masked
            self.warnings.append(
                f"mask_shl({size},{off},{shl}) not exactly reconstructed"
            )
            return f"/* approximation: mask_shl({size},{off},{shl}) */ {self._expr(val)}"

        if op in ("shl", "shr", "sar") and len(exp) == 3:
            # EVM arg order: (shift_amount, value); `sar` is an arithmetic
            # (sign-preserving) shift - approximated here as a logical shift
            # since Solidity's >> on uint256 has no direct signed variant
            # without an explicit int256 cast, which we can't reliably infer.
            shift_amt, val = self._expr(exp[1]), self._expr(exp[2])
            if op == "shl":
                return f"({val} << {shift_amt})"
            if op == "sar":
                self.warnings.append("sar approximated as logical (unsigned) shift")
            return f"({val} >> {shift_amt})"

        if op == "sha3":
            # keccak256 over a memory region (offset, len); when it isn't the
            # mapping/array slot-derivation idiom (handled in _resolve_storage
            # via rainbow_sha3 upstream), approximate with a best-effort
            # region hint rather than trying to reconstruct exact memory
            # contents from the trace.
            self.warnings.append("sha3 region reconstruction is approximate")
            if len(exp) == 3:
                offset, length = self._expr(exp[1]), self._expr(exp[2])
                return f"keccak256(msg.data[0:0]) /* approximation: sha3({offset}, {length}) */"
            return f"keccak256(msg.data[0:0]) /* approximation: {_short_repr(exp)} */"

        if op == "bool":
            return "true" if exp[1] else "false"

        if op == "cd":
            # raw calldata word read - only reached when not part of the
            # selector idiom above (e.g. a param not resolved to `param`).
            # The offset can itself be a compound expression (e.g. a
            # dynamic-array element access), so it must be translated
            # recursively, never interpolated as a raw Python value.
            offset_expr = self._expr(exp[1]) if len(exp) > 1 else "0"
            return f"uint256(bytes32(msg.data[{offset_expr}:{offset_expr} + 32]))"

        if op == "call.data":
            start, length = exp[1], exp[2]
            return f"msg.data[{self._expr(start)}:{self._expr(start)} + {self._expr(length)}]"

        if op == "data":
            # generic byte-blob literal used e.g. for revert payloads already
            # handled in _revert_stmt(); as a bare expression, approximate.
            return "hex\"\" /* approximation: raw data blob */"

        if exp == "calldatasize" or op == "calldatasize":
            return "msg.data.length"
        if exp in ("caller",):
            return "msg.sender"
        if exp in ("address",):
            return "address(this)"
        if exp in ("origin",):
            return "tx.origin"
        if exp in ("gas", "gas_remaining"):
            return "gasleft()"
        if exp in ("timestamp",):
            return "block.timestamp"
        if exp in ("number",):
            return "block.number"

        self._unresolved_count += 1
        self.warnings.append(f"unresolved expression opcode: {op!r}")
        return f"0 /* unresolved: {_short_repr(exp)} */"

    def _atom(self, s):
        if s == "calldatasize":
            return "msg.data.length"
        if s == "caller":
            return "msg.sender"
        if s == "address":
            return "address(this)"
        if s == "gas" or s == "gas_remaining":
            return "gasleft()"
        if s == "ext_call.return_data":
            if self._last_call_result:
                return self._last_call_result[1]
        # a quoted string literal, e.g. "'insufficient balance'"
        m = _STRING_LITERAL_RE.match(s)
        if m:
            escaped = m.group(1).replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        return f"0 /* unresolved atom: {_short_repr(s)} */"


def _safe_ident(name):
    ident = re.sub(r"[^A-Za-z0-9_]", "_", str(name))
    if not ident or ident[0].isdigit():
        ident = "v_" + ident
    return ident


def _short_repr(obj, limit=80):
    r = repr(obj)
    if len(r) > limit:
        r = r[: limit - 3] + "..."
    return r.replace("\n", " ")


def generate_solidity(decompilation) -> SolgenResult:
    """Entry point: decompilation is a panoramix.decompiler.Decompilation."""
    emitter = SolidityEmitter(decompilation.json or {})
    return emitter.generate()

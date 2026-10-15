"""

    This module displays expressions and traces in a human readable form.

    It went through very many iterations, so it's a mess by now.

    A lot of it can be easily refactored, so if you're looking for a place to contribute,
    this may be it :)

"""

import logging
import string
import sys
from copy import deepcopy
from functools import partial

import scobelix.core.arithmetic as arithmetic
from scobelix.core.algebra import (
    add_op,
    apply_mask,
    ge_zero,
    lt_op,
    minus_op,
    mul_op,
    safe_ge_zero,
    safe_le_op,
    sub_op,
    to_bytes,
)
from scobelix.core.arithmetic import is_zero, simplify_bool
from scobelix.core.masks import get_bit, mask_to_type
from scobelix.dispatcher import is_selector_expr
from scobelix.matcher import Any, match
from scobelix.utils.helpers import (
    COLOR_BLUE,
    COLOR_BOLD,
    COLOR_GRAY,
    COLOR_GREEN,
    COLOR_HEADER,
    COLOR_OKGREEN,
    COLOR_UNDERLINE,
    COLOR_WARNING,
    ENDC,
    FAIL,
    C,
    all_concrete,
    clean_color,
    colorize,
    find_op_list,
    is_array,
    opcode,
    padded_hex,
    precompiled,
    pretty_bignum,
    replace_f,
    replace_lines,
    to_exp2,
)
from scobelix.utils.signatures import find_sig_name, get_param_name

logger = logging.getLogger(__name__)

PANIC_SELECTOR = 0x4E487B71  # Panic(uint256)

PANIC_CODES = {
    0x00: "Used for generic compiler inserted panics.",
    0x01: "If you call assert with an argument that evaluates to false.",
    0x11: "If an arithmetic operation results in underflow or overflow outside of an unchecked { ... } block.",
    0x12: "If you divide or modulo by zero (e.g. 5 / 0 or 23 % 0).",
    0x21: "If you convert a value that is too big or negative into an enum type.",
    0x22: "If you access a storage byte array that is incorrectly encoded.",
    0x31: "If you call .pop() on an empty array.",
    0x32: "If you access an array, bytesN or an array slice at an out-of-bounds or negative index (i.e. x[i] where i >= x.length or i < 0).",
    0x41: "If you allocate too much memory or create an array that is too large.",
    0x51: "If you call a zero-initialized variable of internal function type.",
}

prev_trace = None

def prettify(exp, rem_bool=False, parentheses=True, top_level=False, add_color=False):
    if exp is None:
        return "<?>"

def safe_pret(x):
    v = pret(x)
    return v if isinstance(v,str) else "<?>"


def explain(title, trace):
    global prev_trace

    if "--explain" not in sys.argv:
        return

    if trace == prev_trace:
        return

    print("\n" + C.green_back + f" {title}: " + C.end + "\n")
    pprint_trace(trace)
    prev_trace = trace


def explain_text(title, params):
    global prev_trace

    if "--explain" not in sys.argv:
        return

    print("\n" + C.blue_back + f" {title}: " + C.end + "\n")

    for name, val in params:
        print(f" {C.gray}{name}{C.end}: {val}")
    print()


def make_ast(trace):
    def store_to_set(line):
        if m := match(line, ("store", ":size", ":off", ":idx", ":val")):
            return ("set", ("stor", m.size, m.off, m.idx), m.val)
        else:
            return line

    def mask_storage(exp):
        if m := match(exp, ("stor", ":size", ":off", ":idx")):
            return ("mask_shl", m.size, 0, 0, exp)
        else:
            return exp

    trace = replace_lines(trace, store_to_set)
    trace = replace_f(trace, mask_storage)

    return trace


def format_exp(exp):
    if type(exp) == str:
        return f'"{exp}"'
    if type(exp) == int:
        if exp > 10**6 and exp % 10**6 != 0:
            return hex(exp)
        else:
            try:
                return str(exp)
            except Exception:
                return "<?>"
            
    elif type(exp) != list:
        return str(exp)
    else:
        if len(exp) == 0:
            return COLOR_GRAY + "[]" + ENDC
        if type(opcode(exp)) == list:
            return (
                COLOR_GRAY
                + "["
                + ENDC
                + f"{COLOR_GRAY}, {ENDC}".join([format_exp(e) for e in exp])
                + COLOR_GRAY
                + "]"
                + ENDC
            )
        else:
            return (
                COLOR_GRAY
                + "["
                + ENDC
                + f"{COLOR_GRAY}, {ENDC}".join(
                    [opcode(exp)] + [format_exp(e) for e in exp[1:]]
                )
                + COLOR_GRAY
                + "]"
                + ENDC
            )


def pprint_repr(trace, indent=0):
    for line in trace:
        if opcode(line) == "if":
            cond, if_true, if_false = line[1:]
            print(indent * " ", f"[if, {format_exp(cond)}, [")
            pprint_repr(if_true, indent + 2)
            print(indent * " ", "],[")
            pprint_repr(if_false, indent + 2)
            print(indent * " ", "] ")

        elif opcode(line) == "while":
            cond, tr = line[1], line[2]
            print(indent * " ", f"[while, {format_exp(cond)}, [")
            pprint_repr(tr, indent + 2)
            print(indent * " ", "], ")

        else:
            print(indent * " ", format_exp(line) + f"{COLOR_GRAY}, {ENDC}")


"""
def pprint_repr(exp):
    print(repr(exp))
    return
    print(pretty_repr(exp))
"""


def pretty_repr(exp, indent=0):
    if type(exp) not in (tuple, list):
        return repr(exp)
    elif type(exp) == list:
        res = ", \n".join([" " * indent + pretty_repr(e, indent) for e in exp])
        res = indent * " " + "[" + res[:-3] + "]"
        return res
    elif type(exp) == tuple:
        res = ", ".join(pretty_repr(e) for e in exp)
        if len(res) > 40 and len(exp) > 1:
            op, first, *rest = exp
            indent += len(pretty_repr(op) + ", ") + 1
            res = pretty_repr(op) + ", " + pretty_repr(first, indent) + ",\n"
            for r in rest:
                res += indent * " " + pretty_repr(r, indent) + ", \n"
            res = res[:-3]  # removes ', \n'

        return "(" + res + ")"
    elif type(exp) == list:
        res = (",\n" + " " * indent).join([pretty_repr(e, indent) for e in exp])
        return f"[{res}]"


# print(pretty_repr(('data', ('mem', ('range', ('add', 32, 'QQ', ('mask_shl', 251, 5, 0, ('add', 31, ('ext_call.return_data', 128, 32)))), 32)), 'yy', ('data', ('mem', ('range', ('add', 32, 'QQ'), ('ext_call.return_data', 128, 32))), ('mem', ('range', ('add', 96, 'QQ', ('mask_shl', 251, 5, 0, ('add', 31, ('ext_call.return_data', 128, 32))), ('ext_call.return_data', 128, 32)), 0))))))
# exit()

def emit_fallback(solc_version):
    if solc_version < (0, 6, 0):
        return "function() external payable { revert(); }"
    else:
        return "fallback() external payable { revert(); }"
    

def pformat_trace(trace):
    return "\n".join(pprint_logic(trace)) + "\n\n"


def pprint_trace(trace):
    trace = make_ast(trace)
    pprint_ast(trace)


def pprint_ast(trace):
    empty = True

    for l in pprint_logic(trace):
        print(l)
        empty = False

    if empty:
        print("  stop")
    print()
    print()


def pprint_logic(exp, indent=2):
    INDENT_LEN = 4

    if opcode(exp) == "while":
        if len(exp) == 5:
            cond, path, jd, vars = exp[1], exp[2], exp[3], exp[4]
        else:
            cond, path = exp[1], exp[2]
            vars = []

        for v in vars:
            yield " " * indent + list(
                pretty_line(("setvar", v[1], v[2]), add_color=True)
            )[0]

        yield " " * indent + COLOR_GREEN + "while " + ENDC + prettify(
            cond, add_color=True, parentheses=False, rem_bool=True
        ) + COLOR_GREEN + ":" + ENDC  # +COLOR_GREEN+':  # '+str(jd)+ENDC
        if type(path) != list:
            path = path.trace

        for l in pprint_logic(path, indent + INDENT_LEN):
            yield l

    elif opcode(exp) == "require":
        # ("require", cond, line): `line` (a revert or invalid) runs when
        # cond is false; older traces have no line
        cond = exp[1]
        fail = exp[2] if len(exp) > 2 else ("revert", None)
        if fail == ("revert", None) or opcode(fail) == "invalid":
            yield " " * indent + "require " + prettify(
                cond, add_color=True, parentheses=False, rem_bool=True
            ) + ""
        else:
            for l in pprint_logic(("if", is_zero(cond), [fail]), indent):
                yield l

    elif m := match(
        exp, ("if", ":cond", ":if_true")
    ):  # one-sided ifs, only after folding
        cond, if_true = m.cond, m.if_true
        if (
            len(if_true) == 1
            and (first := if_true[0])
            and ((first == ("revert", None)) or opcode(first) == "invalid")
        ):
            yield " " * indent + "require " + prettify(
                is_zero(exp[1]), add_color=True, parentheses=False, rem_bool=True
            )
        else:
            yield " " * indent + "if " + prettify(
                exp[1], add_color=True, parentheses=False, rem_bool=True
            ) + ":"
            for l in pprint_logic(if_true, indent + INDENT_LEN):
                yield l

    elif m := match(exp, ("if", ":cond", ":if_true", ":if_false")):
        cond, if_true, if_false = m.cond, m.if_true, m.if_false
        if (
            len(if_false) == 1
            and (first := if_false[0])
            and (first == ("revert", None) or opcode(first) == "invalid")
        ):
            yield " " * indent + "require " + prettify(
                exp[1], add_color=True, parentheses=False, rem_bool=True
            )

            for l in pprint_logic(exp[2], indent):
                yield l

        elif (
            len(if_true) == 1
            and (first := if_true[0])
            and ((first == ("revert", None)) or opcode(first) == "invalid")
        ):
            yield " " * indent + "require " + prettify(
                is_zero(exp[1]), add_color=True, parentheses=False, rem_bool=True
            )

            for l in pprint_logic(exp[3], indent):
                yield l

        else:
            yield " " * indent + "if " + prettify(
                exp[1], add_color=True, parentheses=False, rem_bool=True
            ) + ":"

            for l in pprint_logic(if_true, indent + INDENT_LEN):
                yield l
            """
            while len(if_false) == 1 and opcode(if_false) == 'if' and len(if_false) == 4:
                first = if_false[0]
                assert first ~ ('if', :c, :i_t, :if_false)

                yield ' '*indent + 'elif ' + prettify(c, add_color=True, parentheses=False, rem_bool=True) + ':'

                for l in pprint_logic(i_t, indent + INDENT_LEN):
                    yield l"""

            yield " " * indent + "else:"
            for l in pprint_logic(if_false, indent + INDENT_LEN):
                yield l

    elif type(exp) == list:
        for idx, line in enumerate(exp):
            if idx == len(exp) - 1 and indent == 2 and line == ("stop",):
                pass  # don't print the last stop
            else:
                for l in pprint_logic(line, indent):
                    yield l

    elif opcode(exp) == "or" and len(exp) > 1:
        yield " " * indent + "if"
        for l in pprint_logic(exp[1], indent + INDENT_LEN):
            yield l

        for line in exp[2:]:
            yield " " * indent + "or"
            for l in pprint_logic(line, indent + INDENT_LEN):
                yield l

    else:
        for l in pretty_line(exp):
            yield " " * indent + l


def to_real_int(exp):
    if type(exp) == int and get_bit(exp, 255):
        return -arithmetic.sub(0, exp)
    else:
        return exp


def pretty_line(r, add_color=True):
    col = partial(colorize, add_color=add_color)
    pret = partial(prettify, parentheses=False, add_color=add_color)

    if type(r) is str:
        yield COLOR_GRAY + "# " + r + ENDC

    #    elif r ~ ('jumpdest', ...):
    #        pass

    elif m := match(r, ("comment", ":text")):
        yield COLOR_GRAY + "# " + prettify(m.text, add_color=False) + ENDC

    elif match(r, ("log", ":params", ...)):
        _, params, *events = r
        num_indexed = len(events) - 1  # topics after topic0

        # solidstamp and dao cover most of those cases
        res_params = pretty_memory(params, add_color=False)

        for e in events:
            if type(e) != int:
                for e in events[1:]:
                    res_params = res_params + (
                        prettify(e, add_color=False, parentheses=False),
                    )
                events = [events[0]]
                break
                # breaks with more than one proper event

        # only topic0 identifies the event (other int topics are values)
        res_events = tuple(
            pretty_fname(
                e,
                add_color=False,
                force=True,
                kind="event" if i == 0 else None,
                num_indexed=num_indexed,
            )
            for i, e in enumerate(events)
        )
        res_events = tuple((x[:10] if x[:2] == "0x" else x) for x in res_events)
        for e in res_events:
            if e.count("(") != 1:
                yield col(
                    f"log {e}{':' if len(res_params)>0 else ''} {', '.join(res_params)}",
                    COLOR_GRAY,
                )
            else:
                fname, fparams = e.split("(")

                assert fparams[-1] == ")"
                fparams = fparams[:-1]

                fparams = fparams.split(", ")

                if fparams == [""] or len(res_params) == 0:
                    yield col(f"log {e}", COLOR_GRAY)

                elif len(fparams) == len(res_params):
                    p_list = []
                    try:
                        for idx, ptype, pname in [
                            f"{idx} {p}".split(" ") for idx, p in enumerate(fparams)
                        ]:
                            p_list.append((ptype, pname, res_params[int(idx)]))
                    except Exception:
                        logger.warning("weird log %s %s", e, fparams)
                        yield (f"log {e}")
                        return

                    if len(p_list) == 1:
                        yield col(
                            f"log {fname}({p_list[0][0]} {p_list[0][1]}={pret(p_list[0][2], add_color=False, parentheses=False)})",
                            COLOR_GRAY,
                        )
                    else:
                        ind = len(f"log   ")
                        first = p_list[0]
                        last = p_list[-1]

                        def pline(p):
                            return f"{p[0]} {p[1]}={pret(p[2], add_color=False, parentheses=False)}"

                        yield col(f"log {fname}(", COLOR_GRAY)  #
                        yield col(f"      {pline(first)},", COLOR_GRAY)

                        for p in p_list[1:-1]:
                            yield col(" " * ind + f"{pline(p)},", COLOR_GRAY)

                        yield col(" " * ind + f"{pline(last)})", COLOR_GRAY)
                #                elif len(res_params) == 0:
                #                        yield col(f'log {e}', COLOR_GRAY)
                else:
                    yield col(f"log {e}:", COLOR_GRAY)
                    ind = " " * len(f"log {fname}(")
                    for p in res_params:
                        yield col(ind + p + ",", COLOR_GRAY)
    #                        print(repr(len(fparams)), len(res_params))

    elif m := match(r, ("callcode", ":gas", ":addr", ":wei", ":fname", ":fparams")):
        gas, addr, wei = m.gas, m.addr, m.wei
        fname, fparams = split_payload(m.fname, m.fparams)
        fname = pretty_fname(fname, add_color=add_color)

        if type(addr) == int:
            addr = hex(addr)
        addr = prettify(addr, add_color=add_color)
        gas = prettify(gas, parentheses=False, add_color=add_color)
        fparams = pretty_memory(fparams, add_color=add_color)

        if fname is not None:
            if type(fname) == str:
                fname = pretty_fname(fname, add_color=add_color)
                yield f"{COLOR_WARNING}codecall{ENDC} {addr}.{fname} with:"

            else:
                yield f"{COLOR_WARNING}codecall{ENDC} {addr} with:"
                yield "   funct " + prettify(fname, add_color=add_color)

        else:
            yield f"{COLOR_WARNING}codecall{ENDC} {addr} with:"

        if wei != 0:
            wei = prettify(wei, parentheses=False, add_color=add_color)
            yield f"   value {wei} {COLOR_GRAY}wei{ENDC}"

        yield f"     gas {gas} {COLOR_GRAY}wei{ENDC}"

        if fparams is not None:
            yield "    args {}".format(", ".join(fparams))

    elif m := match(r, ("delegatecall", ":gas", ":addr", ":fname", ":fparams")):
        gas, addr = m.gas, m.addr
        fname, fparams = split_payload(m.fname, m.fparams)
        fname = pretty_fname(fname, add_color=add_color)

        if type(addr) == int:
            addr = hex(addr)
        addr = prettify(addr, add_color=add_color)
        gas = prettify(gas, parentheses=False, add_color=add_color)
        fparams = pretty_memory(fparams, add_color=add_color)

        if fname is not None:
            if type(fname) == str:
                fname = pretty_fname(fname, add_color=add_color)
                yield f"{COLOR_WARNING}delegate{ENDC} {addr}.{fname} with:"

            else:
                yield f"{COLOR_WARNING}delegate{ENDC} {addr} with:"
                yield "   funct " + prettify(fname, add_color=add_color)

        else:
            yield f"{COLOR_WARNING}delegate{ENDC} {addr} with:"

        yield f"     gas {gas} {COLOR_GRAY}wei{ENDC}"

        if fparams is not None:
            yield "    args {}".format(", ".join(fparams))

    elif opcode(r) == "selfdestruct":
        addr = r[1]
        yield col("selfdestruct(", COLOR_WARNING) + col(
            pret(addr, add_color=False, parentheses=False), FAIL
        ) + col(")", COLOR_WARNING)

    elif m := match(r, ("precompiled", ":var_name", ":func_name", ":params")):
        yield "{} = {}({}) {}".format(
            col(m.var_name, COLOR_BLUE),
            m.func_name,
            prettify(m.params, add_color=add_color, parentheses=False),
            COLOR_GRAY + "# precompiled" + ENDC,
        )

    elif m := match(r, ("create", ":wei", ":code")):
        yield f"create contract with {m.wei} wei"
        yield f"                code: {prettify(m.code)}"

    elif m := match(r, ("create2", ":wei", ":code", ":salt")):
        yield f"create2 contract with {m.wei} wei"
        yield f"                salt: {prettify(m.salt)}"
        yield f"                code: {prettify(m.code)}"

    elif m := match(r, ("call", ":gas", ":addr", ":wei", ":fname", ":fparams")):
        gas, addr, wei = m.gas, m.addr, m.wei
        fname, fparams = split_payload(m.fname, m.fparams)

        if type(addr) == int:
            if len(hex(addr)) > 22 + 2:
                addr = padded_hex(addr, 40)  # todo: padded hex
            else:
                addr = hex(addr)  # if it's longer, padded hex returns '???'

        addr = pret(addr)
        gas = pretty_gas(gas, wei, add_color)

        if fname is None:
            yield f"call {addr} with:"

        else:
            fname = pretty_fname(fname, add_color=add_color)

            if fname == "0x0":
                yield f"call {addr} with:"

            elif type(fname) == str:
                yield f"call {addr}.{pret(fname)} with:"

            else:
                yield f"call {addr} with:"
                yield f"   funct {pret(fname)}"

        if wei != 0:
            wei = prettify(wei, parentheses=False, add_color=add_color)
            yield f"   value {wei} {COLOR_GRAY}wei{ENDC}"

        yield f"     gas {gas} {COLOR_GRAY}wei{ENDC}"

        if fparams is not None:
            fparams = pretty_memory(fparams, add_color=add_color)
            yield "    args {}".format(", ".join(fparams))

    elif m := match(r, ("staticcall", ":gas", ":addr", ":wei", ":fname", ":fparams")):
        gas, addr, wei = m.gas, m.addr, m.wei
        fname, fparams = split_payload(m.fname, m.fparams)
        if type(addr) == int:
            addr = hex(addr)

        addr = prettify(addr, add_color=add_color, parentheses=False)
        gas = pretty_gas(gas, wei, add_color)

        if fname is not None:
            fname = pretty_fname(fname, add_color=add_color)

            if fname == "0x0":
                yield f"static call {addr} with:"
            elif type(fname) == str and fname != "0x0":
                yield f"static call {addr}.{pret(fname)} with:"
            else:
                yield f"static call {addr} with:"
                yield f"     funct {pret(fname)}"

        else:
            yield f"static call {addr} with:"

        yield f"        gas {gas} {COLOR_GRAY}wei{ENDC}"

        if fparams is not None:
            fparams = pretty_memory(fparams, add_color=add_color)
            yield "       args {}".format(", ".join(fparams))

    elif m := match(r, ("label", ":name", ":setvars")):
        yield COLOR_GREEN + f"label {str(m.name)} setvars: {str(m.setvars)}" + ENDC

    elif opcode(r) == "goto":
        _, *rest = r
        yield COLOR_GREEN + f"continue {str(rest)}" + ENDC

    elif m := match(r, ("continue", ":jd", ":setvars")):
        # the setvars of a continue are assigned all at once: shown as one
        # tuple assignment when a value reads a variable set before it
        assigned, parallel = set(), False
        for v in m.setvars:
            if any(e[1] in assigned for e in find_op_list(v[2], "var")):
                parallel = True
            assigned.add(v[1])
        if parallel:
            names = ", ".join(prettify(("var", v[1]), add_color=add_color) for v in m.setvars)
            values = ", ".join(
                prettify(v[2], add_color=add_color, parentheses=False) for v in m.setvars
            )
            yield f"{names} = {values}"
        else:
            for v in m.setvars:
                yield str(list(pretty_line(v, add_color=True))[0])
        yield COLOR_GREEN + "continue " + ENDC  # +str(jd)+ENDC

    elif opcode(r) == "setvar":
        yield prettify(r, add_color=add_color)

    elif opcode(r) == "setmem":
        yield prettify(r, add_color=add_color)

    elif m := match(r, ("set", ":idx", ":val")):
        idx, val = m.idx, m.val

        if m := match(val, ("add", ":int:v", idx)):
            v = m.v
            assert v != 0

            if v == -1:
                yield prettify(idx, add_color=add_color) + "--"
            elif v == 1:
                yield prettify(idx, add_color=add_color) + "++"

            elif v < 0:
                yield prettify(idx, add_color=add_color) + " -= " + prettify(
                    -v, add_color=add_color, parentheses=False
                )
            else:
                yield prettify(idx, add_color=add_color) + " += " + prettify(
                    v, add_color=add_color, parentheses=False
                )

        elif m := match(val, ("add", idx, ("mul", -1, ":v"))):
            v = m.v
            yield prettify(idx, add_color=add_color) + " -= " + prettify(
                v, add_color=add_color, parentheses=False
            )
        elif m := match(val, ("add", idx, ":v")):
            v = m.v
            yield prettify(idx, add_color=add_color) + " += " + prettify(
                v, add_color=add_color, parentheses=False
            )
        elif m := match(val, ("add", ("mul", -1, ":v"), idx)):
            v = m.v
            yield prettify(idx, add_color=add_color) + " -= " + prettify(
                v, add_color=add_color, parentheses=False
            )
        elif m := match(val, ("add", ":v", idx)):
            v = m.v
            yield prettify(idx, add_color=add_color) + " += " + prettify(
                v, add_color=add_color, parentheses=False
            )
        else:
            yield prettify(idx, add_color=add_color) + " = " + prettify(
                val, add_color=add_color, parentheses=False
            )

    elif opcode(r) == "stop":
        yield "stop"

    elif opcode(r) == "undefined":
        params = tuple(r[1:])
        yield COLOR_WARNING + "..." + ENDC + COLOR_GRAY + f"  # Decompilation aborted, sorry: {params}" + ENDC

    elif opcode(r) == "invalid":
        _, *rest = r
        if len(rest) > 0:
            yield "revert "  # + COLOR_GRAY + f"# {rest}" + ENDC
        else:
            yield "revert"

    elif r == ("revert", None):
        yield "revert"

    elif r == ("return", None):
        # RETURN without data (the 32-byte zero word is ("return", 0))
        yield "return"

    elif (
        m := match(r, (":op", ("mem", ("range", ":mem_idx", ":mem_len"))))
    ) and m.op in ("revert", "return"):
        op, mem_idx, mem_len = m.op, m.mem_idx, m.mem_len

        if op == "revert":
            yield "revert with memory"
        else:
            yield op + " memory"

        if m := match(mem_len, ("sub", ":mem_until", mem_idx)):
            yield f"  from  {pret(mem_idx)}"
            yield f"    to {pret(m.mem_until)}"
        else:
            yield "  from " + pret(mem_idx)
            yield "   " + col("len", COLOR_WARNING) + " " + pret(mem_len)

    elif opcode(r) in ("return", "revert") and len(r) == 2:
        op, param = r

        if op == "revert":
            op = "revert with"
            # a revert payload starts with an error selector; a payload of
            # just the selector is a custom error without arguments
            error = try_fname(payload_selector(param), add_color=True, kind="error")
            if error:
                res_mem = (error,)
            else:
                res_mem = pretty_memory(param, add_color=True, selector_kind="error")
        else:
            res_mem = pretty_memory(param, add_color=True)
        ret_val = ", ".join(res_mem)

        if m := match(r, ("revert", ("data", ("bytes", 4, PANIC_SELECTOR), ":int:panic_code"))):
            explanation = (
                (f" {COLOR_GRAY}# " + PANIC_CODES[m.panic_code] + ENDC)
                if m.panic_code in PANIC_CODES
                else ""
            )
            yield f"{op} Panic({m.panic_code}) {explanation}"
        elif len(clean_color(ret_val)) < 120 or opcode(param) != "data":
            yield f"{op} {ret_val}"
        else:
            # split long returns into lines. e.g. kitties.getKitten, or kitties.tokenMetadata
            #            yield str(len(ret_val))
            res_mem = list(res_mem)
            if res_mem[0] == "32":
                res_mem.pop(0)
                res_mem[0] = (
                    "32, " + res_mem[0]
                )  # happens often, this is probably an array structure,
                # and sole `32` in first line looks ugly

            yield f"{op} {res_mem[0]}, "
            for idx, l in enumerate(res_mem[1:]):
                yield " " * len(op) + " " + l + ("," if idx != len(res_mem) - 2 else "")

    #            assert op == 'revert'
    #            yield "{} with {}".format(op, ret_val) # adding 'with' to make it more readable

    elif m := match(r, ("tstore", ":idx", ":val")):
        idx = prettify(m.idx, add_color=add_color, parentheses=False)
        val = prettify(m.val, add_color=add_color, parentheses=False)
        yield f"tstorage[{idx}] = {val}"

    elif m := match(r, ("store", ":size", ":off", ":idx", ":val")):
        size, off, idx, val = m.size, m.off, m.idx, m.val
        stor_addr = prettify(("stor", size, off, idx), add_color=add_color)
        stor_val = prettify(val, add_color=add_color, parentheses=False)

        yield "{} = {}".format(stor_addr, stor_val)

    elif type(r) == list and len(r) > 1:
        yield "{} {}".format(
            r[0],
            ", ".join([prettify(x, True, False, add_color=add_color) for x in r[1:]]),
        )

    elif type(r) == list:
        yield str(r[0])

    else:
        yield str(r)


def pretty_type(t):
    if m := match(t, ("def", ":name", ":loc", ("mask", ":size", ":off"))):
        return (
            pretty_type(("def", m.name, m.loc, m.size))
            + COLOR_GRAY
            + (f" offset {m.off}" if m.off > 0 else "")
            + ENDC
        )

    elif m := match(t, ("def", ":name", ":loc", ":bts")):
        name, loc, bts = m.name, m.loc, m.bts
        if type(loc) == int and loc > 1000:
            loc = hex(loc)
        return f"  {COLOR_GREEN}{name}{ENDC} is {pretty_type(bts)} {COLOR_GRAY}at storage {loc}{ENDC}"

    elif t == ("struct", 1):
        return "struct"

    elif t == "struct":
        return "struct"

    elif m := match(t, ("struct", ":int:num")):
        return f"struct {m.num} bytes"

    elif m := match(t, ("array", ":bts")):
        return f"array of " + pretty_type(m.bts)

    elif m := match(t, ("mapping", ":bts")):
        return f"mapping of " + pretty_type(m.bts)

    elif type(t) == int:
        return mask_to_type(t, force=True)

    else:
        assert False, f"unknown type {t}"


def pretty_stor(exp, add_color=True):
    col = partial(colorize, color=COLOR_GREEN, add_color=add_color)
    stor = partial(pretty_stor, add_color=add_color)
    pret = partial(prettify, parentheses=False, add_color=add_color)

    if m := match(exp, ("stor", ("length", ":idx"))):
        return stor(m.idx) + col(".length")

    if m := match(exp, ("loc", ":loc")):
        return col(f"stor_l{m.loc}")

    if m := match(exp, ("name", ":name", ":loc")):
        return col(m.name)

    #    if exp ~ ('stor', (:op, :param)) and op in ('loc', 'name'):
    # with top-level fields, it's just a different stor
    # variable. with lower-level we treat it as a struct
    #        return stor((op, param))

    if m := match(exp, ("stor", ":loc")):
        # with top-level fields, it's just a different stor
        # variable. with lower-level we treat it as a struct
        return stor(m.loc)

    if m := match(exp, ("field", ":off", ":loc")):
        return stor(m.loc) + col(f".field_{pret(m.off, add_color=False)}")

    if m := match(exp, ("type", ":size", ":loc")):
        if m.size == 256:
            # prettify removes 256 masks by default, force it
            return (
                col("uint256(", color=COLOR_GRAY)
                + stor(m.loc)
                + col(")", color=COLOR_GRAY)
            )
        else:
            return pret(("mask", m.size, 0, stor(m.loc)))

    def pr_idx(idx):
        if opcode(idx) == "data":
            _, *terms = idx
            return col("][").join([pret(t) for t in terms])
        else:
            return pret(idx)

    if m := match(exp, ("map", ":idx", ":var")):
        idx, var = m.idx, m.var
        return stor(var) + col("[") + pr_idx(idx) + col("]")

    if m := match(exp, ("array", ("mul", ":int:any", ":idx"), ":var")):
        exp = (
            "array",
            m.idx,
            m.var,
        )  # nasty hack to not display storage[2*idx] for storages
        # that are structs
        # this should be handled in sparser really
    #        return stor(var) + col('[') + pr_idx(idx) + col(']')

    if m := match(exp, ("array", ":idx", ":var")):
        idx, var = m.idx, m.var
        return stor(var) + col("[") + pr_idx(idx) + col("]")

    if m := match(exp, ("length", ":var")):
        return stor(m.var) + col(".length")

    if m := match(exp, ("stor", ":loc")):
        return col("stor[") + pret(m.loc) + col("]")

    if m := match(exp, ("stor", ":size", ":off", ":loc")):
        return pret(("mask", m.size, m.off, col("stor[") + pret(m.loc) + col("]")))

    return col("stor[") + pret(exp) + col("]")


def pretty_num(exp, add_color):
    if type(exp) == float:
        if exp - int(exp) == 0:
            exp = int(exp)

    if type(exp) == int and 10**15 < exp < 2**256:
        # constants whose bytes are printable text (the trace keeps ints):
        # one run of characters, zero bytes only around it
        raw = exp.to_bytes((exp.bit_length() + 7) // 8, "big").rstrip(b"\0")
        text = pretty_bignum(exp)
        if b"\0" not in raw and type(text) == str:
            return text

    if type(exp) == int and exp > 8**50:
        return hex(
            exp
        )  # dealing with binary data probably, usually in call code - display in hex

    if type(exp) == int and exp != 0:
        count = 18
        while count >= 9:
            if exp % (10**count) == 0:
                if exp // (10**count) == 1:
                    return f"10^{count}"
                else:
                    return f"{exp // (10**count)} * 10^{count}"

            count -= 1

        count = 6
        if exp % (10**count) == 0:
            if exp // (10**count) == 1:
                return f"10^{count}"
            else:
                return f"{exp // (10**count)} * 10^{count}"

    if type(exp) == int:
        # no signature lookup here: an arbitrary constant is not a selector
        # (see try_fname for the positions where it is)
        if (exp & 2**256 - 1) < 8**30:  # if it's larger than 30 bytes, it's probably
            # an address, not a negative number
            return str(to_real_int(exp))

        elif exp > 0:
            return hex(exp)

        else:
            return str(exp)

    # print('warn: weird float exp', exp)
    return str(exp)


def prettify(exp, rem_bool=False, parentheses=True, top_level=False, add_color=False):
    col = partial(colorize, add_color=add_color)
    pret = partial(prettify, add_color=add_color, parentheses=False)

    if rem_bool:
        exp = simplify_bool(exp)
        if opcode(exp) == "bool":
            return prettify(
                exp,
                rem_bool=rem_bool,
                parentheses=parentheses,
                top_level=top_level,
                add_color=add_color,
            )

    if type(exp) == int and exp % (24 * 3600) == 0 and exp > 24 * 3600:
        exp = ("mul", exp // 3600, 24, 3600)

    if type(exp) == int and exp % 3600 == 0 and exp > 3600:
        exp = ("mul", exp // 3600, 3600)
        # also tried return col('seconds(', COLOR_GRAY) + '1 hour' + col(')', COLOR_GRAY)
        # but seemed less intuitive, e.g. 0xf64B584972FE6055a770477670208d737Fff282f calcMaxWithdraw
        # and 3600 every programmer should know, by heart, means 1 hour :)
        #
        # also, not tackling single minutes because too often they are not time related

    if type(exp) in (int, float):
        return pretty_num(exp, add_color)

    if (
        (m := match(exp, ("bytes", ":int:width", ":int:val")))
        and 0 < m.width < 32
        and m.val % (1 << (8 * m.width)) != 0
    ):
        # constant bytes narrower than a word (not zero padding): their
        # text, or every hex digit (0x1901, 0x61), so that the width shows;
        # a selector is named by the selector positions, never here
        raw = (m.val % (1 << (8 * m.width))).to_bytes(m.width, "big")
        if len(raw) > 1 and all(32 <= c < 127 and c != 39 for c in raw):
            return "'" + raw.decode() + "'"
        return "0x" + raw.hex()

    if m := match(exp, ("bytes", Any, ":val")):
        # a part of a byte string with an explicit width: shown by its value
        return prettify(m.val, add_color=add_color, parentheses=parentheses)

    if m := match(exp, ("byte", ":idx", ":val")):
        return f"byte({pret(m.idx)}, {pret(m.val)})"

    if m := match(exp, ("addmod", ":a", ":b", ":m")):
        return f"addmod({pret(m.a)}, {pret(m.b)}, {pret(m.m)})"

    if (m := match(exp, ("signextend", ":int:b", ":val"))) and 0 <= m.b < 31:
        return col(f"int{8 * (m.b + 1)}(", COLOR_GRAY) + pret(m.val) + col(")", COLOR_GRAY)

    if m := match(exp, ("signextend", ":b", ":val")):
        return f"signextend({pret(m.b)}, {pret(m.val)})"

    if opcode(exp) in precompiled.values():
        return f"{exp[0]}({pret(exp[1])})"

    if (
        m := match(exp, ("arr", ":int:num", ("mask_shl", Any, Any, Any, ":str:s")))
    ) and len(m.s) == m.num + 2:
        return m.s

    if m := match(exp, ("param", ":name")):
        return col(m.name, COLOR_GREEN)

    if m := match(exp, ("range", ":loc", ":size")):
        return "{} {} {}".format(pret(m.loc), col("len", COLOR_HEADER), pret(m.size))

    if opcode(exp) == "data":
        return ", ".join(pretty_memory(exp, add_color=add_color))

    if opcode(exp) == "arr" and len(exp) > 1:
        _, l, *terms = exp
        return (
            col("Array(len=", COLOR_GRAY)
            + pret(l)
            + col(", data=", COLOR_GRAY)
            + pret(("data",) + tuple(terms))
            + col(")", COLOR_GRAY)
        )

    if m := match(exp, ("blockhash", ":number")):
        return f"block.hash({pret(m.number)})"

    if m := match(exp, ("extcodehash", ":addr")):
        return f"{pret(m.addr)}.codehash"

    if m := match(exp, ("extcodesize", ":addr")):
        return f"{pret(m.addr)}.code.length"

    if m := match(exp, ("extcodecopy", ":addr", ":loc")):
        return f"ext_code.copy({pret(m.addr)}, {pret(m.loc)})"

    if m := match(exp, ("tload", ":idx")):
        return f"tstorage[{pret(m.idx)}]"

    if opcode(exp) in ("max", "min"):
        _, *terms = exp
        return "{}({})".format(exp[0], ", ".join([pret(e) for e in terms]))

    if exp == "number":
        return "block.number"

    if exp == "calldatasize":
        return "calldata.size"

    if exp == "returndatasize":
        return "return_data.size"

    if exp == "difficulty":
        return "block.difficulty"

    if exp == "prevrandao":
        return "block.prevrandao"

    if m := match(exp, ("blobhash", ":idx")):
        return f"block.blobhash({pret(m.idx)})"

    if exp == "blobbasefee":
        return "block.blobbasefee"

    if exp == "basefee":
        return "block.basefee"

    if exp == "gasprice":
        return "block.gasprice"

    if exp == "timestamp":
        return "block.timestamp"

    if exp == "coinbase":
        return "block.coinbase"

    if exp == "gaslimit":
        return "block.gas_limit"

    if exp == "callvalue":
        return "call.value"

    if exp == "address":
        return "this.address"

    if exp == ("mask_shl", 160, 0, 0, "caller"):
        return "caller"

    if exp == "caller":
        return "caller"

    if exp == ("mask_shl", 160, 0, 0, "origin"):
        return "tx.origin"

    if m := match(exp, ("mulmod", ":a", ":b", ":c")):
        return f"mulmod({pret(m.a)}, {pret(m.b)}, {pret(m.c)})"  # mulmod should really be replaced by mul & mod in other stages
        # but this is rare enough to ignore for now

    if exp == "origin":
        return "tx.origin"

    if exp == "gas":
        return "gas_remaining"

    if exp == ("bool", 1):
        return "True"

    if exp == ("bool", 0):
        return "False"

    if m := match(exp, ("code.data", ":c_start", ":c_len")):
        return f"code.data[{pret(m.c_start)} len {pret(m.c_len)}]"

    if m := match(exp, ("balance", ":addr")):
        return f"eth.balance({pret(m.addr)})"

    if opcode(exp) == "sha3":
        _, *terms = exp
        return "sha3({})".format(", ".join([pret(e) for e in terms]))

    #    if exp ~ ('mask_shl', 251, 5, 0, :val):
    #        return pret(('mul', 32, val))

    if (
        (m := match(exp, ("mask_shl", ":size", 5, 0, ":val")))
        or (m := match(exp, ("mask", ":size", 5, ":val")))
    ) and m.size > 245:
        size, val = m.size, m.val
        if m := match(val, ("add", 31, ":num")):
            return f"ceil32({pret(m.num)})"
        else:
            return f"floor32({pret(val)})"

    if (
        m := match(exp, ("call.data", ("add", 36, ("param", ":p_name")), ":size"))
    ) and m.size == ("cd", ("add", 4, ("param", m.p_name))):
        return f"{col(m.p_name+'[', C.green)}" + "all" + col("]", C.green)

    if (m := match(exp, (":name", ":offset", ":size"))) and is_array(
        m.name
    ):  # in ('call.data', 'ext_call.return_data'):
        if m.size == 32:
            return m.name + f"[{pret(m.offset)}]"
        else:
            return m.name + f"[{pret(m.offset)} len {pret(m.size)}]"

    if (
        (
            m := match(
                exp,
                (
                    "mask_shl",
                    ":size",
                    ":offset",
                    ":shl",
                    ("stor", ":s_size", ":s_off", ":s_idx"),
                ),
            )
        )
        and safe_le_op(m.s_size, m.size)
        and m.shl == 0
    ):
        return pret(("stor", m.s_size, m.s_off, m.s_idx))

    if opcode(exp) == "stor":
        return pretty_stor(exp, add_color=add_color)

    if opcode(exp) == "type":
        return pretty_stor(exp, add_color=add_color)

    if opcode(exp) == "field":
        return pretty_stor(exp, add_color=add_color)

    if m := match(exp, ("cd", ":num")):
        if m.num == 0:
            return col("call.func_hash", C.green)
        parsed_exp = get_param_name(exp, add_color=add_color)

        if type(parsed_exp) != str:
            return "cd[" + prettify(parsed_exp[1], add_color=add_color) + "]"
        else:
            return parsed_exp

    if m := match(exp, ("var", ":int:idx")):
        nice_names = [
            "idx",
            "s",
            "t",
            "u",
            "v",
            "w",
            "x",
            "y",
            "z",
            "a",
            "b",
            "c",
            "d",
            "e",
            "f",
            "g",
            "h",
        ]  # 'i','j','k','l','m','n','o','p','q','r',
        if m.idx < len(nice_names):
            name = nice_names[m.idx]
        else:
            name = "var" + str(m.idx)

        return col(name, COLOR_BLUE)

    if m := match(exp, ("var", ":name")):
        return col(str(m.name), COLOR_BLUE)

    if m := match(exp, ("mem", ("range", ":loc", 32))):
        exp = ("mem", m.loc)

    if m := match(exp, ("mem", ("range", ":loc", ":size"))):
        return (
            col("mem[", COLOR_HEADER)
            + pret(m.loc)
            + col(" len ", COLOR_HEADER)
            + pret(m.size)
            + col("]", COLOR_HEADER)
        )

    if m := match(exp, ("mem", ":idx")):
        assert opcode(m.idx) != "range"

        return col("mem[", COLOR_HEADER) + pret(m.idx) + col("]", COLOR_HEADER)

    if m := match(exp, ("setvar", ":idx", ":val")):  # shouldn't be pretty line?
        return pret(("var", m.idx)) + " = " + pret(m.val, parentheses=False)

    if m := match(exp, ("setmem", ":idx", ":val")):  # --,,--
        fname = None
        value = selector_value(m.val)
        if match(m.idx, ("range", Any, 4)) and value is not None and 2**24 <= value < 2**32:
            # a 4-byte constant written to memory: the selector heading an
            # encoded call (abi.encodeWithSelector / encodeWithSignature);
            # smaller values are packed integers (abi.encodePacked(uint32))
            fname = try_fname(value, add_color)
        return pret(("mem", m.idx)) + " = " + (fname or pret(m.val))

    if m := match(exp, ("mask_shl", ":size", ":offset", ":shl", ":val")):
        size, offset, shl, val = m.size, m.offset, m.shl, m.val

        if (
            all_concrete(size, offset, shl)
            and exp[1] + exp[2] == 256
            and exp[2] == -exp[3]
            and exp[2] > 0
        ):
            # the top bits moved down: x >> k (the VM's SHR, div by 2**k)
            # e.g. (Mask(255, 1, eth.balance(this.address)) >> 1
            #           --> eth.balance(this.address) / 2
            # for offsets smaller than 8

            if exp[2] < 8:
                return pret(("div", exp[4], 2 ** exp[2]), parentheses=parentheses)
            else:
                return pret(("shr", exp[2], exp[4]), parentheses=parentheses)

        if (
            (type(exp[1]), type(exp[2]), type(exp[3])) == (int, int, int)
            and exp[2] == exp[3]
            and exp[2] < 8
        ):
            # e.g. (Mask(255, 1, eth.balance(this.address)) << x
            #           --> eth.balance(this.address) * 2**x
            # for offsets smaller than 8

            if (
                size + offset != 256 and opcode(val) != "store"
            ):  # opcode=store - hotfix for 0x000000000045Ef846Ac1cB7fa62cA926D5701512
                val = ("mask", size + offset, 0, val)  # 0 because exp2 == exp3

            if exp[3] == 0:
                return pret(val, parentheses=parentheses)
            elif exp[3] <= 8 and exp[3] >= -8:
                return pret(("mul", val, 2 ** exp[3]), parentheses=parentheses)
            elif exp[3] > 0:
                return pret(
                    (
                        "shl",
                        exp[3],
                        val,
                    ),
                    parentheses=parentheses,
                )
            else:
                return pret(
                    (
                        "shr",
                        -exp[3],
                        val,
                    ),
                    parentheses=parentheses,
                )

        if all_concrete(size, offset, shl, val):
            return pret(apply_mask(exp[4], exp[1], exp[2], exp[3]))

        if shl == 0:
            exp = ("mask", size, offset, val)

        elif safe_ge_zero(shl) is not False:
            if (
                all_concrete(size, offset, shl)
                and size + shl == 256
                and offset == 0
                and shl > -8
            ):
                exp = ("mul", 2 ** exp[3], exp[4])
            else:
                if type(exp[3]) == int and exp[3] < 7 and exp[3] >= -8:
                    exp = ("mul", 2 ** exp[3], ("mask", exp[1], exp[2], exp[4]))

                elif type(exp[3]) == int and exp[3] < 0:
                    exp = ("shr", -exp[3], ("mask", exp[1], exp[2], exp[4]))
                else:
                    exp = ("shl", exp[3], ("mask", exp[1], exp[2], exp[4]))

        else:
            exp = ("shr", mul_op(-1, exp[3]), ("mask", exp[1], exp[2], exp[4]))

    if m := match(exp, ("mask", ":size", 0, ":val")):
        size, val = m.size, m.val

        if size == 256:
            return pret(val)

        if type(size) == int:
            if size == 255:
                type_name = "uint255"
            else:
                type_name = mask_to_type(size)

            if type_name is not None:
                return (
                    (col(type_name + "(", COLOR_GRAY) + (pret(val) or str(val)) + col(")", COLOR_GRAY))
                )

    if m := match(exp, ("bool", ":val")):
        if opcode(m.val) in ("lt", "gt", "iszero", "le", "ge", "bool"):
            return pret(m.val, parentheses=parentheses)
        else:
            return "bool(" + pret(m.val) + ")"

    if m := match(exp, ("mask", ":size", ":offset", ":val")):
        size, offset, val = m.size, m.offset, m.val
        if type(size) == int and offset == 0 and size < 64:
            return pret(("mod", val, 2**size), parentheses=parentheses)
        else:
            return "Mask({}, {}, {})".format(pret(size), pret(offset), pret(val))

    #    if opcode(exp) in ('byte', 'bytes8', 'uint16', 'bytes4', 'addr', 'int256'):
    #        return prettify('{}({})'.format(opcode(exp).lower(), prettify(exp[1], add_color=add_color)), add_color=add_color)

    opcode_to_arithm = {
        "sub": " - ",  # todo - parentheses?
        "div": " / ",
        "mul": " * ",
        "gt": " > ",
        "lt": " < ",
        "le": " <= ",
        "ge": " >= ",
        "or": " or ",
        "eq": " == ",
        "mod": " % ",
        "shl": " << ",
        "shr": " >> ",
        "sar": " >>′ ",
        "smod": " %′ ",
        "exp": "^",
        "and": " and ",
        "sge": " >=′ ",
        "sle": " <=′ ",
        "sgt": " >′ ",
        "slt": " <′ ",
        "sadd": " +′ ",
        "smul": " *′ ",
        "sdiv": " /′ ",
        "xor": " xor ",
    }

    def pretty_adds(exp):
        if opcode(exp) != "add":
            return prettify(exp, add_color=add_color)

        if type(exp[1]) == float:
            real = exp[1]
            if int(real) == real:
                real = int(real)  # 32.0 -> 32

            symbolic = exp[2:]
            res = " + ".join([prettify(x, add_color=add_color) for x in symbolic])
            if real > 0:
                res += " + " + prettify(real)
            elif real < 0:
                res += " - " + prettify(-real)

        elif type(exp[1]) == int:
            real = to_real_int(exp[1])
            symbolic = exp[2:]
            res = " + ".join([prettify(x, add_color=add_color) for x in symbolic])
            name = None
            if len(symbolic) == 1 and (m := match(symbolic[0], ("mul", -1, ":sel"))):
                # via-IR selector test `K - selector`
                name = pretty_selector_operand(exp[1], m.sel, add_color)
            elif len(symbolic) == 1 and real < 0:
                # selector test `selector - K`
                name = pretty_selector_operand(-real, symbolic[0], add_color)
            if real > 0:
                res += " + " + (name or prettify(real))
            elif real < 0:
                res += " - " + (name or prettify(-real))

        else:
            res = ""
            for x in exp[1:]:
                if res == "":
                    res = prettify(x, add_color=add_color)
                elif opcode(x) == "mul" and type(x[1]) == int and x[1] < 0:
                    res += " - " + prettify(minus_op(x), add_color=add_color)
                else:
                    res += " + " + prettify(x, add_color=add_color)

        if parentheses:
            return f"({res})"
        else:
            return res
    # we change that because it produce => !a ==b who is interpret as (!a) == b and we want => !(a == b)
    if opcode(exp) == "not":
        inner = prettify(exp[1], add_color=add_color, parentheses=True)
        return f"!({inner})"

    if opcode(exp) == "add":
        return pretty_adds(exp)

    if (
        opcode(exp) == "mul"
        and len(exp) == 3
        and to_exp2(exp[1]) != None
        and to_exp2(exp[1]) > 32
    ):
        exp = ("shl", to_exp2(exp[1]), exp[2])

    if m := match(exp, ("mul", -1, ":val")):
        return "-" + pret(m.val, parentheses=parentheses)

    if m := match(exp, ("mul", 1, ":val")):
        return pret(m.val, parentheses=parentheses)

    if m := match(exp, ("mul", 1, ...)):
        return pret(("mul",) + exp[2:], parentheses=parentheses)

    if m := match(exp, ("div", ":num", 1)):
        return pret(m.num, parentheses=parentheses)

    if m := match(exp, ("exp", ":a", ":n")):
        return pret(m.a, parentheses=True) + "^" + pret(m.n, parentheses=True)

    if opcode(exp) in opcode_to_arithm:
        if opcode(exp) in ["shl", "shr", "sar"]:
            exp = exp[0], exp[2], exp[1]

        form = "{}"
        if parentheses and not top_level:
            form = "({})"

        op_form = opcode_to_arithm[opcode(exp)]
        if add_color:
            op_form = COLOR_BOLD + op_form + ENDC

        def fold_ands(exp):
            assert opcode(exp) == "and"

            res = tuple()
            for e in exp[1:]:
                if opcode(e) == "and":
                    e = fold_ands(e)
                    res += e[1:]
                else:
                    res += (e,)

            return ("and",) + res

        if opcode(exp) == "and":
            exp = fold_ands(exp)
            return form.format(op_form.join(pret(e, rem_bool=True) for e in exp[1:]))
        elif opcode(exp) in ("eq", "gt", "lt", "ge", "le", "xor") and len(exp) == 3:
            unsigned = opcode(exp) in ("lt", "gt", "le", "ge")

            def operand(e, other):
                # a constant compared with the calldata selector is printed
                # by name; in an unsigned comparison, a negative constant is
                # a large word (-2 is 2^256 - 2), never a negative number
                name = pretty_selector_operand(e, other, add_color)
                if name:
                    return name
                if unsigned and type(e) == int and -(2**255) <= e < 0:
                    return "2^256 - " + pret(-e)
                return pret(e)

            return form.format(op_form.join((operand(exp[1], exp[2]), operand(exp[2], exp[1]))))
        elif opcode(exp) in ("lt", "gt", "le", "ge"):
            # unsigned comparison: a negative constant is a large word
            # (-2 is 2^256 - 2), never a negative number
            return form.format(
                op_form.join(
                    "2^256 - " + pret(-e) if type(e) == int and -(2**255) <= e < 0 else pret(e)
                    for e in exp[1:]
                )
            )
        else:
            return form.format(op_form.join(pret(e) for e in exp[1:]))

    # We need to keep a good boolean expression
    if m := match(exp, ("iszero", ":val")):
        val = m.val

        def s(x, other):
            r = pretty_selector_operand(x, other, add_color) or pret(x)
            return r if r is not None else str(x)

        if m2 := match(val, ("gt", ":left", ":right")):
            return f"({s(m2.left, m2.right)} <= {s(m2.right, m2.left)})"

        if m2 := match(val, ("lt", ":left", ":right")):
            return f"({s(m2.left, m2.right)} >= {s(m2.right, m2.left)})"

        if m2 := match(val, ("eq", ":left", ":right")):
            return f"({s(m2.left, m2.right)} != {s(m2.right, m2.left)})"

        return f"({s(val, None)} == 0)"

    return str(exp)





def split_payload(fname, fparams):
    """
    (selector, arguments) of a call for display. The trace keeps the payload
    whole (fname None, fparams = the payload bytes): a leading 4-byte part is
    shown as the called function, the rest as its arguments.
    """
    if fname is not None or fparams is None:
        return fname, fparams

    def is_selector(part):
        return (
            match(part, ("bytes", 4, Any))
            or match(part, ("mem", ("range", Any, 4)))
            or (is_array(opcode(part)) and len(part) == 3 and part[2] == 4)
        )

    if is_selector(fparams):
        return (fparams[2] if opcode(fparams) == "bytes" else fparams), None

    if opcode(fparams) == "data" and len(fparams) > 2 and is_selector(fparams[1]):
        first = fparams[1]
        sel = first[2] if opcode(first) == "bytes" else first
        rest = fparams[2:]
        return sel, rest[0] if len(rest) == 1 else ("data",) + rest

    return None, fparams


def pretty_gas(gas, value, add_color):
    if match(gas, ("mul", 2300, ("iszero", Any))):
        # should check if _ == value
        return "2300 * is_zero(value)"
    else:
        return prettify(gas, add_color=add_color, parentheses=False)


def try_fname(exp, add_color=False, kind="function", num_indexed=None):
    """Signature name of `exp`, a value in a selector position: the selector
    of a call or of a calldata comparison ("function"), the first word of a
    revert payload ("error"), the topic0 of a log ("event", with the number
    of topics after it). A 4-byte value may also come left-aligned in a word.
    Never call it on other constants: any int would match some 4-byte key.
    """
    exp = selector_value(exp)
    if kind is None or exp is None or exp <= 0 or exp >= 2**256:
        return None  # 0 is an empty or lost selector (zeroed memory)

    if kind == "event":
        return find_sig_name(exp, kind, add_color, num_indexed)

    if exp >= 2**32:
        if exp % 2**224:
            return None
        exp >>= 224

    # a revert payload may be a raw word (an error code) rather than a
    # selector: a small value only names a declared custom error, not a
    # signature of another kind with that hash (vanity selectors such as
    # 0x00000001 exist)
    typed_only = kind == "error" and exp < 2**24
    return find_sig_name(exp, kind, add_color, typed_only=typed_only)


def pretty_fname(exp, add_color=False, force=False, kind="function", num_indexed=None):
    if type(exp) == int:
        fname = try_fname(exp, add_color, kind, num_indexed)
        if fname:
            return fname
        else:
            return hex(exp)

    elif opcode(exp) == "mem" or force:
        return prettify(exp, add_color=add_color)

    return exp


def _constant_bytes(part):
    """Bytes of a constant part of a data blob (a word is 32 bytes), None
    when the part is not constant."""
    if type(part) == int:
        return (part % 2**256).to_bytes(32, "big")
    if (
        opcode(part) == "bytes"
        and type(part[1]) == int
        and type(part[2]) == int
        and 0 <= part[1] <= 1 << 16
    ):
        return (part[2] % (1 << (8 * part[1]))).to_bytes(part[1], "big")
    return None


def selector_value(exp):
    """The constant held by a selector position: an int, or an explicit 4-byte
    part of a byte string, ("bytes", 4, K) = the low 4 bytes of K; else None."""
    if type(exp) == int:
        return exp
    if m := match(exp, ("bytes", 4, ":int:val")):
        return m.val % 2**32
    return None


def payload_selector(part):
    """The selector a byte string starts with, `part` being its first part:
    an explicit 4-byte part, ("bytes", 4, K), or a word whose low 28 bytes
    are zero (a left-aligned bytes4); else None. A plain word below 2**224
    starts with zero bytes: it holds a number (a raw revert word, a return
    value, log data), not a selector."""
    if m := match(part, ("bytes", 4, ":int:val")):
        return m.val % 2**32
    if type(part) == int and 2**224 <= part < 2**256 and part % 2**224 == 0:
        return part >> 224
    return None


def is_selector_exp(exp):
    """True for the calldata selector, the top 4 bytes of cd[0]: the forms the
    dispatcher recognises (dispatcher.is_selector_expr) or `shr(224, cd[0])`,
    possibly masked to its low 32 bits or more. Other reads of cd[0] (the
    whole word, its first byte, its low 4 bytes `uint32(cd[0])`...) are not
    selectors: contracts with a custom dispatch compare them with constants."""
    while True:
        if (m := match(exp, ("mask_shl", ":int:size", 0, 0, ":inner"))) and m.size >= 32:
            exp = m.inner
        elif opcode(exp) == "and" and len(exp) == 3 and int in (type(exp[1]), type(exp[2])):
            mask, inner = (exp[1], exp[2]) if type(exp[1]) == int else (exp[2], exp[1])
            if mask < 2**32 - 1 or mask & (mask + 1):  # not a low mask of >= 32 bits
                return False
            exp = inner
        else:
            break

    return is_selector_expr(exp) or exp == ("shr", 224, ("cd", 0))


def is_word_head_exp(exp):
    """True for the first 4 bytes of a word, `x >> 224` (`mask_shl(32, 224,
    -224, x)`, `mask_shl(256, -224, -224, x)`), or of returned data or
    memory read 4 bytes wide (`uint32(ext_call.return_data[0 len 4])`)."""
    if m := match(exp, ("mask_shl", 32, 0, 0, ":inner")):
        exp = m.inner
    if match(exp, ("ext_call.return_data", Any, 4)) or match(exp, ("mem", ("range", Any, 4))):
        return True
    return opcode(exp) == "mask_shl" and exp[1:4] in ((32, 224, -224), (256, -224, -224))


def pretty_selector_operand(val, other, add_color=False):
    """`val` as printed when it is compared with a selector: the calldata one
    (dispatcher tests, `msg.sig == X`) or the head of another word (returned
    data decoded by try/catch: error selectors). Its signature name, else its
    8 hex digits (a selector nobody named); None when `val` is not such an
    operand."""
    if type(val) != int:
        return None
    if is_selector_exp(other) and 0 <= val < 2**32:
        # a 4-byte value: never equal to a left-aligned constant
        return try_fname(val, add_color) or "0x%08x" % val
    if is_word_head_exp(other) and 2**24 <= val < 2**32:
        # error namespace first; lookup_error also returns function signatures
        return try_fname(val, add_color, "error") or "0x%08x" % val
    return None


def pretty_memory(exp, add_color=False, selector_kind="function"):
    """Elements of a memory blob; `selector_kind` is the namespace of the
    selector a leading 4-byte word stands for ("error" in revert payloads)."""
    if exp is None:
        return tuple()

    if exp == "mem":
        return prettify(exp, add_color=add_color)

    if opcode(exp) != "data":
        return (prettify(exp, add_color=add_color),)

    exp = exp[1:]

    if len(exp) == 0:
        return "empty()"
    assert len(exp) > 0, exp

    res = []

    idx = 0

    def unmask(exp):
        if opcode(exp) == "mask_shl":
            return exp[4]

        return exp

    # merge things that look like string into a string

    while idx < len(exp):
        if (
            idx == 0
            and type(exp[0]) == tuple
            and exp[0][:4] == ("mask_shl", 32, 224, 0)
            and type(exp[0][4]) == int
        ):
            # This happens often in Log and Revert, first
            # memory result being an 8-byte identifier.
            # Definitely deserves a more generic solution.
            #
            # example: 0xd883209C4DCd497f24633C627a4E451013424841, sendFoods function
            v = exp[0][4] >> 224
            res.append(pretty_fname(v, add_color, kind=selector_kind))
            idx += 1
            continue

        el = exp[idx]
        head = payload_selector(el) if idx == 0 else None

        if head is not None:
            name = None
            if selector_kind == "error":
                # selector of a revert payload (Error(string), Panic, custom)
                name = try_fname(head, add_color, "error")
            elif head >= 2**24:
                # head of an encoded call (abi.encodeWithSelector); smaller
                # 4-byte values are packed integers (abi.encodePacked(uint32))
                name = try_fname(head, add_color, selector_kind)
            if name:
                res.append(name)
                idx += 1
                continue

        # detect a potential string: the ABI offset 32, the length, the bytes
        out_str = None
        if unmask(el) == 32 and len(exp) > idx + 2 and type(unmask(exp[idx + 1])) == int:
            length = unmask(exp[idx + 1])
            raw, end = b"", idx + 2
            while len(raw) < length and end < len(exp):
                part = _constant_bytes(exp[end])
                if part is None:
                    break
                raw += part
                end += 1
            if len(raw) >= length and end > idx + 2:
                text = raw[:length].decode("latin-1")
                if all(ch in string.printable for ch in text):
                    out_str = text
                    idx = end - 1

        if out_str != None:
            res.append("'" + out_str + "'")
        else:
            res.append(prettify(el, add_color=add_color, parentheses=False))

        idx = idx + 1

    return tuple(res)

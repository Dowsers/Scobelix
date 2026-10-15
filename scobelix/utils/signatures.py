import hashlib
import json
import logging
import os
import os.path
import sys
from typing import Optional, List

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
    cleanup_mul_1,
    colorize,
    opcode,
    cache_dir,
)
from scobelix.utils import sigdb
from scobelix.utils.supplement import fetch_sig

logger = logging.getLogger(__name__)

_abi = None
_func = None


def set_func_params_if_none(params):
    logger.debug("set_func_params_if_none %s - %s", params, _func)
    if "inputs" not in _func:
        res = []
        for t, n in params.values():
            res.append({"type": t, "name": n})

        _func["inputs"] = res


def set_func(hash):
    global _func
    global _abi

    assert _abi is not None
    _func = _abi[hash]


def get_param_name(cd, add_color=False, func=None):
    global _func
    loc = match(cd, ("cd", ":loc")).loc

    if _abi is None:
        return cd

    if _func is None:
        return cd

    if "inputs" not in _func:
        return cd

    if type(loc) != int:
        cd = cleanup_mul_1(cd)

        if m := match(loc, ("add", 4, ("param", ":point_loc"))):
            return colorize(m.point_loc + ".length", COLOR_GREEN, add_color)

        if m := match(loc, ("add", 4, ("cd", ":point_loc"))):
            return colorize(
                str(get_param_name(("cd", m.point_loc), func=func)) + ".length",
                COLOR_GREEN,
                add_color,
            )

        if m := match(loc, ("add", ":int:offset", ("cd", ":point_loc"))):
            return colorize(
                str(get_param_name(("cd", m.point_loc), func=func))
                + f"[{(m.offset - 36)//32}]",
                COLOR_GREEN,
                add_color,
            )

        return cd

    if (loc - 4) % 32 != 0:  # unusual parameter
        return cd

    num = (cd[1] - 4) // 32
    if num >= len(_func["inputs"]):
        return cd

    assert num < len(_func["inputs"]), str(cd) + " // " + str(func["inputs"])

    return colorize(_func["inputs"][num]["name"], COLOR_GREEN, add_color)


def get_abi_name(hash):
    a = _abi[hash]
    if "inputs" in a:
        # canonical types, as hashed into the selector: tuples written out
        types = [sigdb.canonical_type(x) or x["type"] for x in a["inputs"]]
        return "{}({})".format(a["name"], ",".join(types))
    else:
        return "{}(?)".format(a["name"])


def get_func_params(hash) -> Optional[List]:
    a = _abi[hash]
    logger.debug("get_func_params for %s is %s", hash, a.get("inputs"))
    return a.get("inputs")


def get_func_name(hash, add_color=False):
    a = _abi[hash]
    logger.debug("get_func_name for abi %s", a)
    if "inputs" in a:
        return "{}({})".format(
            a["name"],
            ", ".join(
                [
                    x["type"]
                    + " "
                    + colorize(
                        x["name"],
                        COLOR_GREEN,
                        add_color,
                    )
                    for x in a["inputs"]
                ]
            ),
        )
    else:
        return "{}(?)".format(a["name"])


def fix_input_names(inputs: List[dict]):
    for i, input in enumerate(inputs):
        if not input["name"]:
            input["name"] = f"_param{i+1}"

    return inputs


def make_abi(hash_targets):
    global _abi

    result = {}

    for h, target in hash_targets.items():
        res = {
            "name": "unknown" + h[2:],
        }

        if h.startswith("0x"):
            sig = fetch_sig(h)
            if sig:
                res = {
                    "name": sig["name"],
                    "inputs": fix_input_names(sig["inputs"]),
                }
        else:  # assuming index is a name - e.g. for _fallback()
            res = {
                "name": h,
            }

        res["target"] = target

        result[h] = res

    _abi = result


def find_sig_name(key, kind=sigdb.FUNCTION, add_color=False, num_indexed=None, typed_only=False):
    """`name(type param, ...)` of a selector (function or error, 4 bytes) or
    of an event topic0 (32 bytes), None when the database has no candidate.

    Only meant for values in selector positions; for events, `num_indexed`
    (topics after topic0) prefers the candidate with that many indexed
    parameters. `typed_only` skips the candidates flagged "untyped" (for
    errors and events: signatures of another kind with the same hash).
    """
    try:
        if kind == sigdb.EVENT:
            cands = sigdb.lookup_event(key, num_indexed) or sigdb.lookup_event(key)
        elif kind == sigdb.ERROR:
            cands = sigdb.lookup_error(key)
        else:
            cands = sigdb.lookup_function(key)
    except ValueError:  # not a key of that width
        return None
    if typed_only:
        cands = [c for c in cands if not c["untyped"]]
    if not cands:
        return None
    return "{}({})".format(
        cands[0]["name"],
        ", ".join(
            colorize(x["type"], COLOR_GRAY, add_color) + " " + x["name"]
            for x in cands[0]["inputs"]
        ),
    )

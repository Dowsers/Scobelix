import dataclasses
import io
import json
import logging
import os
import sys
import time
from contextlib import redirect_stdout
from typing import Optional

import timeout_decorator

import scobelix.folder as folder
import scobelix.simplify as simplify
from scobelix.contract import Contract
from scobelix.function import Function, has_validators
from scobelix.loader import Loader
from scobelix.prettify import explain, pprint_repr, pprint_trace, pretty_type
from scobelix.vm import VM
from scobelix.whiles import make_whiles
from scobelix.utils.helpers import C, rewrite_trace
from scobelix.utils.proxy_detect import detect_proxy_slots

logger = logging.getLogger(__name__)

# Per-function decompilation budget: a function that doesn't finish in time is
# added to `problems` and skipped, the rest of the contract still decompiles.
FUNCTION_TIMEOUT = int(os.environ.get("PANORAMIX_FUNCTION_TIMEOUT", str(60 * 12)))
# Budgets passed down to the symbolic VM run and to the goto->while structuring
# pass for a single function.
VM_RUN_TIMEOUT = int(os.environ.get("PANORAMIX_VM_RUN_TIMEOUT", "600"))
WHILES_TIMEOUT = int(os.environ.get("PANORAMIX_WHILES_TIMEOUT", "600"))
# Share of FUNCTION_TIMEOUT kept for what the simplification of a function
# still does once its time limit is reached (it ends the rewrite in progress,
# then the final cleanup and the text form): the function timeout throws the
# function away (a `problem`), the simplification limit only leaves it less
# simplified (exact, Function.time_limited).
SIMPLIFY_RESERVE = 0.25

# The global time budget of a decompilation (decompile_bytecode(...,
# time_budget=seconds)) is a deadline on this clock; an indirection, so
# that the tests can move the clock.
_clock = time.monotonic
# Share of the time budget, at least BUDGET_RESERVE_MIN seconds, kept for
# what follows the functions (the storage reconstruction, the JSON and the
# text), which has no time limit of its own. Every function kept less
# simplified (time_limited) adds TIME_LIMITED_RESERVE of the time it took:
# what follows the functions takes that much longer on its larger trace.
BUDGET_RESERVE = 0.1
BUDGET_RESERVE_MIN = 5.0
TIME_LIMITED_RESERVE = 0.5
# A function is not attempted with less time than this left (seconds): the
# alarm would only cut it short.
MIN_FUNCTION_SECONDS = 1.0
# What the function discovery gets when the budget is already exhausted: it
# cannot be left out, so it runs until its first check of the time.
MIN_SLICE = 1e-3
# The longest alarm a step gets under a time budget (about 31 years):
# signal.setitimer refuses much longer ones, and a budget that long sets
# no limit anyway.
MAX_ALARM_SECONDS = 1e9


def simplification_deadline(started, budget=None):
    """
    The time (time.monotonic()) at which the simplification of a function
    whose decompilation started at `started` stops, besides WHILES_TIMEOUT;
    None without a function timeout. `budget` is the time the function has
    (seconds) when a global time budget caps it: FUNCTION_TIMEOUT otherwise.
    """
    limit = FUNCTION_TIMEOUT if budget is None else budget
    if limit <= 0:
        return None
    return started + limit * (1 - SIMPLIFY_RESERVE)


def _capped(limit, cap):
    """`limit` (seconds; 0 or less: no limit) or `cap` when that is smaller:
    what a step of the decompilation gets under a global time budget."""
    return cap if limit <= 0 else min(limit, cap)


def _vm_share(ft):
    """The time limit of the symbolic execution of a function that has `ft`
    seconds under a global time budget: the share of the function's budget
    it has without one (VM_RUN_TIMEOUT / FUNCTION_TIMEOUT, all of it at
    most), 1 - SIMPLIFY_RESERVE of it when either has no limit (and
    VM_RUN_TIMEOUT at most). It ends before the alarm of the function, so
    that an execution stopped by it keeps its partial trace instead of
    making the function a failure."""
    if FUNCTION_TIMEOUT > 0 and VM_RUN_TIMEOUT > 0:
        return ft * min(1.0, VM_RUN_TIMEOUT / FUNCTION_TIMEOUT)
    return _capped(VM_RUN_TIMEOUT, ft * (1 - SIMPLIFY_RESERVE))


@dataclasses.dataclass
class TimeBudget:
    """
    The global time budget of one decompilation, as a deadline on `_clock`.

    The functions are decompiled until `reserve` seconds before the
    deadline, each under the smaller of its own budgets (FUNCTION_TIMEOUT,
    VM_RUN_TIMEOUT, the simplification deadline) and what is left; one
    reached with less than MIN_FUNCTION_SECONDS left is not decompiled: a
    `problem`, listed in `skipped`. Every function kept less simplified
    (time_limited) makes the reserve larger. `exhausted` tells whether the
    budget ran out before the end of the work or cut a step of it short (a
    function left out or interrupted, or whose simplification stopped at
    the time the budget left it; the command also sets it when the Solidity
    generation, its verification loop or its validation is).
    """

    seconds: float
    deadline: float  # the `_clock()` value at which the budget ends
    reserve: float  # seconds kept for what follows the functions
    exhausted: bool = False
    skipped: list = dataclasses.field(default_factory=list)  # keys of the functions left out

    @classmethod
    def start(cls, seconds):
        """A budget of `seconds` starting now."""
        if isinstance(seconds, bool) or not (isinstance(seconds, (int, float)) and 0 < seconds < float("inf")):
            raise ValueError(f"time_budget: not a positive number of seconds: {seconds!r}")
        reserve = max(BUDGET_RESERVE_MIN, seconds * BUDGET_RESERVE)
        return cls(seconds=seconds, deadline=_clock() + seconds, reserve=reserve)

    def remaining(self):
        """Seconds to the end of the budget (negative past it)."""
        return self.deadline - _clock()

    def left_for_functions(self, now=None):
        """Seconds the functions still have (at `now`, a `_clock()` value;
        by default now): the remaining less the reserve."""
        return self.deadline - (_clock() if now is None else now) - self.reserve


@dataclasses.dataclass
class Decompilation:
    text: str = ""
    asm: list = dataclasses.field(default_factory=list)
    json: dict = dataclasses.field(default_factory=dict)
    proxy_hints: list = dataclasses.field(default_factory=list)
    # Hex (no 0x prefix) of the whole runtime code, metadata trailer included.
    bytecode: str = ""
    # Compiler metadata trailer (utils.metadata.Metadata.to_dict()), or None.
    metadata: Optional[dict] = None
    # Dispatcher analysis (JSON-safe, see scobelix.dispatcher): selectors with
    # their targets, fallback/receive and their function keys, whether solc
    # hoisted the callvalue check above the dispatch.
    dispatcher: Optional[dict] = None
    # Function key (selector hex, "_fallback", "_receive") -> Function, for
    # in-memory consumers; not part of `json`.
    functions: dict = dataclasses.field(default_factory=dict)
    # The time budget the decompilation ran under (TimeBudget: what it was,
    # whether it ran out, the functions it left out); None without one.
    time_budget: Optional[TimeBudget] = None


# Derives from BaseException so it bypasses all the "except Exception" that are
# all around Panoramix code.
class TimeoutInterrupt(BaseException):
    """Thrown when a timeout occurs in the `timeout` context manager."""

    def __init__(self, value="Timed Out"):
        self.value = value

    def __str__(self):
        return repr(self.value)


def decompile_bytecode(code: str, only_func_name=None, *, time_budget=None) -> Decompilation:
    """The decompilation of the runtime bytecode `code` (hex, 0x optional).

    only_func_name: decompile only the functions whose name starts with it.
    time_budget: seconds the whole decompilation may take (see TimeBudget);
    None for the per-function budgets alone.
    """
    loader = Loader()
    loader.load_binary(code)  # Code is actually hex.
    return _decompile_with_loader(loader, only_func_name, time_budget=time_budget)


def decompile_address(address: str, only_func_name=None, *, time_budget=None) -> Decompilation:
    """The decompilation of the code deployed at `address` (read from the
    node of web3's automatic provider); parameters as decompile_bytecode."""
    loader = Loader()
    loader.load_addr(address)
    return _decompile_with_loader(loader, only_func_name, time_budget=time_budget)


def _decompile_with_loader(loader, only_func_name=None, *, time_budget=None) -> Decompilation:
    """

    But the main decompilation process looks like this:

        loader = Loader()
        loader.load(this_addr)

    loader.lines contains disassembled lines now

        loader.run(VM(loader, just_fdests=True))

    After this, loader.func_list contains a list of functions and their locations in the contract.
    Passing VM here is a pretty ugly hack, sorry about it.

        trace = VM(loader).run(target)

    Trace now contains the decompiled code, starting from target location.
    you can do pprint_repr or pprint_logic to see how it looks

        trace = make_whiles(trace)

    This turns gotos into whiles
    then it simplifies the code.
    (should be two functions really)

        functions[hash] = Function(hash, trace)

    Turns trace into a Function class.
    Function class constructor figures out it's kind (e.g. read-only, getter, etc),
    and some other things.

        contract = Contract(addr=this_addr,
                            ver=VER,
                            problems=problems,
                            functions=functions)

    Contract is a class containing all the contract decompiled functions and some other data.

        contract.postprocess()

    Figures out storage structure (you have to do it for the whole contract at once, not function by function)
    And folds the trace (that is, changes series of ifs into simpler forms)

    Finally...

        loader.disasm() -- contains disassembled version
        contract.json() -- contains json version of the contract

    Decompiled, human-readable version of the contract is done within this .py file,
    starting from `with redirect_stdout...`


    To anyone going into this code:
        - yes, it is chaotic
        - yes, there are way too many interdependencies between some modules
        - this is the first decompiler I've written in my life :)

    """

    """
        Fetch code from Web3, and disassemble it.

        Loader holds the disassembled line by line code,
        and the list of functions within the contract.
    """

    budget = None if time_budget is None else TimeBudget.start(time_budget)

    logger.info("Running light execution to find functions.")

    if budget is None:
        loader.run(VM(loader, just_fdests=True))
    else:
        loader.run(VM(loader, just_fdests=True), budget=max(budget.left_for_functions(), MIN_SLICE))

    metadata = loader.metadata.to_dict() if loader.metadata else None

    if len(loader.lines) == 0:
        # No code.
        return Decompilation(
            text=C.gray + "# No code found for this contract." + C.end,
            bytecode=loader.bytecode,
            metadata=metadata,
            time_budget=budget,
        )

    callvalue_guarded = loader.callvalue_guarded_functions()

    """

        Main decompilation loop

    """

    problems = {}
    functions = {}
    traces = {}
    names = {}
    time_limited = set()  # functions whose simplification stopped at its time limit

    for hash, fname, target, stack in loader.func_list:
        """
        hash contains function hash
        fname contains function name
        target contains line# for the given function
        """

        if only_func_name is not None and not fname.startswith(only_func_name):
            # if user provided a function_name in command line,
            # skip all the functions that are not it
            continue

        logger.info("Decompiling %s...", fname)
        logger.debug("stack %s", stack)
        names[hash] = fname

        # The time this function has: its own budgets, capped by what is
        # left of the global time budget. Too little left: it is not
        # decompiled (a problem), the next ones neither.
        ft, vm_timeout = FUNCTION_TIMEOUT, VM_RUN_TIMEOUT
        if budget is not None:
            began = _clock()
            left = budget.left_for_functions(began)
            if left < MIN_FUNCTION_SECONDS:
                problems[hash] = fname
                budget.skipped.append(hash)
                budget.exhausted = True
                logger.warning("%s: not decompiled, the time budget (%s s) is exhausted", fname, budget.seconds)
                continue
            ft = min(_capped(FUNCTION_TIMEOUT, left), MAX_ALARM_SECONDS)
            vm_timeout = _vm_share(ft)

        try:
            if target > 1 and loader.lines[target][1] == "jumpdest":
                target += 1

            # the memory the dispatcher leaves on the way to this function
            memory = loader.entry_memory.get(hash)

            @timeout_decorator.timeout(ft, timeout_exception=TimeoutInterrupt)
            def dec():
                started = time.monotonic()
                logger.info(" -> Interpreting EVM on function...")
                trace = VM(loader).run(
                    target, stack=stack, timeout=vm_timeout, memory=memory
                )
                explain("Initial decompiled trace", trace[1:])

                if "--explain" in sys.argv:
                    trace = rewrite_trace(
                        trace, lambda line: [] if type(line) == str else [line]
                    )
                    explain("Without assembly", trace)

                logger.info(" -> Cleaning up AST, identifying loops...")
                # the exact trace, and the one the text output shows
                trace, display = make_whiles(
                    trace,
                    timeout=WHILES_TIMEOUT,
                    display=True,
                    deadline=simplification_deadline(started)
                    if budget is None
                    else simplification_deadline(started, budget=ft),
                )
                if simplify.last_run_timed_out:
                    # exact, but the simplification stopped at its time limit
                    time_limited.add(hash)
                explain("final", display)

                if "--explain" in sys.argv:
                    explain("folded", folder.fold(display))

                return trace, display

            traces[hash] = dec()
            if budget is not None and hash in time_limited:
                # its trace, less simplified, makes what follows the
                # functions longer: the next functions get that much less
                budget.reserve += TIME_LIMITED_RESERVE * (_clock() - began)
                if FUNCTION_TIMEOUT <= 0 or ft < FUNCTION_TIMEOUT:
                    # the simplification stopped at the time the budget left it
                    budget.exhausted = True
        except (Exception, TimeoutInterrupt) as e:
            problems[hash] = fname
            if budget is not None and isinstance(e, TimeoutInterrupt) and (FUNCTION_TIMEOUT <= 0 or ft < FUNCTION_TIMEOUT):
                # the alarm was the budget's, not the function's own
                budget.exhausted = True
            logger.exception("Problem with %s%s", fname, C.end)

    # a contract whose decoder validates a parameter anywhere uses ABI coder
    # v2 for every function (its unchecked parameters are 256-bit types)
    abi_coder_v2 = any(has_validators(trace) for trace, _ in traces.values()) or None

    for hash, (trace, display) in traces.items():
        try:
            functions[hash] = Function(
                hash,
                trace,
                callvalue_guarded=hash in callvalue_guarded,
                abi_coder_v2=abi_coder_v2,
                display_trace=display,
            )
            if hash in time_limited:
                functions[hash].time_limited = True
                logger.warning(
                    "%s: simplification stopped at its time limit (PANORAMIX_WHILES_TIMEOUT, "
                    "PANORAMIX_FUNCTION_TIMEOUT%s): the code is exact but not fully simplified",
                    names[hash],
                    ", time budget" if budget is not None else "",
                )
        except Exception:
            problems[hash] = names[hash]
            logger.exception("Problem with %s%s", names[hash], C.end)

    logger.info("Functions decompilation finished, now doing post-processing.")

    """

        Store decompiled contract into .json

    """

    contract = Contract(
        problems=problems,
        functions=functions,
    )

    contract.postprocess()

    decompilation = Decompilation(
        bytecode=loader.bytecode,
        metadata=metadata,
        dispatcher=loader.dispatcher_summary,
        functions=functions,
        time_budget=budget,
    )

    for l in loader.disasm():
        decompilation.asm.append(l)

    decompilation.proxy_hints = detect_proxy_slots(loader.parsed_lines)

    try:
        decompilation.json = contract.json()
        decompilation.json["proxy_hints"] = decompilation.proxy_hints
        decompilation.json["metadata"] = decompilation.metadata
        decompilation.json["dispatcher"] = decompilation.dispatcher
        # This would raise a TypeError if it's not serializable, which is an
        # important assumption people can make.
        with open(os.devnull, "w") as f:
            json.dump(decompilation.json, f)
    except Exception:
        logger.exception("Failed json serialization.")
        decompilation.json = {}

    text_output = io.StringIO()
    with redirect_stdout(text_output):
        """
        Print out decompilation header
        """

        print(C.gray + "# Palkeoramix decompiler. " + C.end)

        if decompilation.proxy_hints:
            print(C.gray + "#")
            print("#  Detected known proxy storage slot(s):")
            for hint in decompilation.proxy_hints:
                print(f"{C.end}{C.gray}#  - {C.end}{hint['slot']} ({hint['description']}){C.gray}")
            print("#" + C.end)
            print()

        if len(problems) > 0:
            print(C.gray + "#")
            print("#  I failed with these: ")
            for p in problems.values():
                print(f"{C.end}{C.gray}#  - {C.end}{C.fail}{p}{C.end}{C.gray}")
            print("#  All the rest is below.")
            print("#" + C.end)

        print()

        """
            Print out constants & storage
        """

        shown_already = set()

        for func in contract.consts:
            shown_already.add(func.hash)
            print(func.print())

        if shown_already:
            print()

        if len(contract.stor_defs) > 0:
            print(f"{C.green}def {C.end}storage:")

            for s in contract.stor_defs:
                print(pretty_type(s))

            print()

        """
            Print out getters
        """

        for hash, func in functions.items():
            if func.getter is not None:
                shown_already.add(hash)
                print(func.print())

                if "--repr" in sys.argv:
                    print()
                    pprint_repr(func.trace)

                print()

        """
            Print out regular functions
        """

        func_list = list(contract.functions)
        func_list.sort(
            key=lambda f: f.priority()
        )  # sort func list by length, with some caveats

        if shown_already and any(1 for f in func_list if f.hash not in shown_already):
            # otherwise no irregular functions, so this is not needed :)
            print(C.gray + "#\n#  Regular functions\n#" + C.end + "\n")

        for func in func_list:
            hash = func.hash

            if hash not in shown_already:
                shown_already.add(hash)

                if func.time_limited:
                    print(C.gray + "# (simplification stopped at its time limit: exact, not fully simplified)" + C.end)
                print(func.print())

                if "--returns" in sys.argv:
                    for r in func.returns:
                        print(r)

                if "--repr" in sys.argv:
                    pprint_repr(func.orig_trace)

                print()

    """
        Wrap up
    """

    decompilation.text = text_output.getvalue()
    text_output.close()

    return decompilation

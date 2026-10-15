import json
import logging
import os
import os.path
import traceback

import scobelix.dispatcher as dispatcher
from scobelix.utils.helpers import (
    ENDC,
    EasyCopy,
    padded_hex,
)
from scobelix.utils.metadata import parse_metadata
from scobelix.utils.opcode_dict import opcode_dict
from scobelix.utils.signatures import get_func_name, make_abi

logger = logging.getLogger(__name__)

LOADER_TIMEOUT = int(os.environ.get("PANORAMIX_LOADER_TIMEOUT", "120"))

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class InvalidBytecode(ValueError):
    """The code to decompile is not a hexadecimal byte string."""


def parse_hex_code(source):
    """
    The bytes of `source`: hexadecimal digits, two per byte, with an
    optional 0x prefix (surrounding whitespace is ignored). Raises
    InvalidBytecode, with the reason, for anything else: a character that
    is not a hex digit, or an odd number of digits (an incomplete byte,
    usually a truncated copy).
    """
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if not isinstance(source, str):
        raise InvalidBytecode("expected a hex string, got %s" % type(source).__name__)

    text = source.strip()
    prefix = 2 if text[:2] in ("0x", "0X") else 0
    for pos in range(prefix, len(text)):
        if text[pos] not in _HEX_DIGITS:
            raise InvalidBytecode(
                "not hexadecimal: %r at position %d" % (text[pos], pos)
            )
    digits = len(text) - prefix
    if digits % 2:
        raise InvalidBytecode(
            "odd number of hex digits (%d): the last byte is incomplete" % digits
        )
    return bytes.fromhex(text[prefix:])

# Instructions (pops, pushes) the prologue scan steps over besides stack
# shuffling: the `PUSH20 <address> ADDRESS EQ` guard of solc library code.
_PROLOGUE_OPAQUE = {"address": (0, 1), "eq": (2, 1)}


def _prologue_free_memory_pointer(parsed_lines, limit=16):
    """
    Value stored at 0x40 by the first memory write of the straight-line code
    at pc 0: solc's `mstore(0x40, 0x80)` (0x60 before 0.4.22, other values
    when via-IR moves the memory guard), in any of the stack orders the
    compilers use. None when the code does not start that way.
    """
    stack = []
    for _, op, param in parsed_lines[:limit]:
        if op.startswith("push"):
            stack.append(param if isinstance(param, int) else None)
        elif op.startswith("dup") and op[3:].isdigit():
            n = int(op[3:])
            if len(stack) < n:
                return None
            stack.append(stack[-n])
        elif op.startswith("swap") and op[4:].isdigit():
            n = int(op[4:])
            if len(stack) < n + 1:
                return None
            stack[-1], stack[-1 - n] = stack[-1 - n], stack[-1]
        elif op == "pop":
            if not stack:
                return None
            stack.pop()
        elif op in _PROLOGUE_OPAQUE:
            pops, pushes = _PROLOGUE_OPAQUE[op]
            if len(stack) < pops:
                return None
            del stack[len(stack) - pops :]
            stack.extend([None] * pushes)
        elif op == "mstore" and len(stack) >= 2:
            offset, value = stack.pop(), stack.pop()
            if offset == 0x40 and isinstance(value, int):
                return value
            return None
        else:
            return None
    return None


class Loader(EasyCopy):
    signatures = {}

    lines = {}  # global, let's assume one loader for now
    binary = []  # array of ints, each int represents a byte in the source file

    def __init__(self):
        self.last_line = None
        self.jump_dests = []
        self.func_dests = {}  # func_name -> jumpdest
        self.hash_targets = {}  # hash -> (jumpdest, stack)
        # hash -> setmem lines recreating the memory the dispatcher leaves at
        # that entry (see dispatcher.memory_seed); Loader.memory_seed otherwise
        self.entry_memory = {}
        self.func_list = []

        # The whole runtime code, metadata trailer included: CODECOPY and
        # CODESIZE see all of it. Only the part before the trailer is
        # disassembled into `lines`.
        self.binary = None
        self.metadata = None  # utils.metadata.Metadata of the outer trailer
        self.code_end = 0  # end of the disassembled code (start of the trailer)
        self.trailer_jump_dests = set()  # JUMPDEST bytes the EVM sees in the trailer
        self.free_memory_pointer = None  # value the prologue stores at 0x40

        # dispatcher.Dispatcher of the last run(), None when the code has no
        # selector dispatch; `dispatcher_summary` is its JSON-safe form.
        self.dispatcher = None
        self.dispatcher_summary = None

    def load_addr(self, address):
        assert address.isalnum()
        address = address.lower()

        logger.info("Fetching code for %s...", address)
        from web3 import Web3
        from web3.auto import w3

        code = w3.eth.get_code(Web3.to_checksum_address(address)).hex().removeprefix("0x")
        logger.debug("Code: %s", code)

        self.load_binary(code)

    def run(self, vm):
        assert self.binary is not None, "Did you run load_*() first?"

        self.dispatcher = None
        self.dispatcher_summary = None

        try:
            # decompiles the code, starting from location 0
            # and running VM in a special mode that returns 'funccall'
            # in places where it looks like there is a func call

            trace = vm.run(0, timeout=LOADER_TIMEOUT)
            analysis = dispatcher.analyse(trace)

        except Exception:
            logger.exception("Loader issue.")
            analysis = None
            trace = None

        if analysis is None:
            # no selector dispatch: the whole code is the fallback
            self.add_func(0, name=dispatcher.FALLBACK)
            self.dispatcher_summary = dispatcher.no_dispatch_summary(
                whole_code_is_revert=trace is not None
                and dispatcher.is_plain_revert(trace),
                regular=trace is None or not dispatcher.routes_selectors(trace),
            )
        else:
            self.dispatcher = analysis
            for entry in analysis.entries:
                self.add_func(
                    target=entry.target,
                    hash=entry.selector,
                    stack=entry.stack,
                    memory=entry.memory,
                )

            fallback = analysis.fallback
            if fallback is not None:
                self.add_func(
                    fallback.start,
                    name=dispatcher.FALLBACK,
                    stack=fallback.stack,
                    memory=fallback.memory,
                )
            else:
                # no single default exit (none found, or exits running
                # different code): the whole code is the fallback
                self.add_func(0, name=dispatcher.FALLBACK)

            receive = analysis.receive
            if receive is not None:
                self.add_func(
                    receive.start,
                    name=dispatcher.RECEIVE,
                    stack=receive.stack,
                    memory=receive.memory,
                )

            self.dispatcher_summary = analysis.to_dict()

        make_abi(self.hash_targets)
        for hash, (target, stack) in self.hash_targets.items():
            fname = get_func_name(hash)
            self.func_list.append((hash, fname, target, stack))

    def next_line(self, i):
        i += 1
        while i not in self.lines and self.last_line > i:
            i += 1

        if i <= self.last_line:
            return i
        else:
            return None

    def add_func(self, target, hash=None, name=None, stack=(), memory=None):
        """memory: the dispatcher's memory writes before `target` (setmem
        lines in execution order), None when unknown."""
        assert hash is not None or name is not None  # we need at least one
        assert not (hash is not None and name is not None)  # we don't want both

        if hash is not None:
            padded = padded_hex(hash, 8)  # lines[i-12][2]
            if padded in self.signatures:
                name = self.signatures[padded]
            else:
                name = "unknown_{}".format(padded)
                self.signatures[padded] = name

        key = name if hash is None else padded_hex(hash, 8)
        self.hash_targets[key] = target, stack
        if memory is not None and target != 0:
            self.entry_memory[key] = dispatcher.memory_seed(memory)
        else:
            self.entry_memory.pop(key, None)

        self.func_dests[name] = target

    def callvalue_guarded_functions(self):
        """Keys of the functions that the dispatcher only reaches after a
        hoisted `callvalue == 0` check (solc does that when no entry point
        is payable): they are not payable whatever their body says."""
        if self.dispatcher is None:
            return set()
        return self.dispatcher.callvalue_guarded_keys()

    def memory_seed(self, start):
        """
        `setmem` lines describing memory when execution reaches `start`, for
        the runs the dispatcher analysis gives no memory for (`entry_memory`
        holds the exact writes of the dispatcher path to each function).

        At pc 0 memory is all zero. A function entry is reached after the
        prologue that stores the initial free memory pointer at 0x40; solc
        >= 0.4.22 starts allocating at 0x80 and keeps 0x60 as the zero slot.
        """
        if start == 0:
            return [
                ("setmem", ("range", 0x40, 32), 0),
                ("setmem", ("range", 0x60, 32), 0),
            ]

        fmp = self.free_memory_pointer
        if fmp is None:
            fmp = self._default_free_memory_pointer()
        if fmp is None:
            # no prologue and not solc: nothing was written before the entry
            return [
                ("setmem", ("range", 0x40, 32), 0),
                ("setmem", ("range", 0x60, 32), 0),
            ]

        seed = [("setmem", ("range", 0x40, 32), fmp)]
        if fmp >= 0x80:
            seed.append(("setmem", ("range", 0x60, 32), 0))
        return seed

    def _default_free_memory_pointer(self):
        md = self.metadata
        if md is None or md.compiler != "solc":
            return None
        version = md.version or (md.version_range[0] if md.version_range else None)
        if version is None:
            return None
        try:
            parsed = tuple(int(x) for x in version.split("."))
        except ValueError:
            return None
        return 0x80 if parsed >= (0, 4, 22) else 0x60

    def disasm(self):
        for line_no, op, param in self.parsed_lines:
            yield f"{hex(line_no)}, {op}, {hex(param) if param is not None else ''}"

    @property
    def bytecode(self):
        """Hex (no 0x prefix) of the whole runtime code, metadata included."""
        return bytes(self.binary or []).hex()

    def runs_into_trailer(self, pc):
        """True when `pc` lies in the metadata trailer left out of the
        disassembly: the EVM would execute those bytes as code."""
        return type(pc) == int and self.code_end <= pc < len(self.binary)

    def load_binary(self, source):
        self.binary = list(parse_hex_code(source))

        # The compiler metadata trailer is data: disassembling it would
        # produce instructions (and possibly JUMPDESTs) that do not exist.
        self.metadata = parse_metadata(self.binary)
        code_len = self.metadata.start if self.metadata else len(self.binary)

        code = self.binary
        pos = 0
        line = 0

        parsed_lines = []

        while pos < code_len:
            popped = code[pos]
            pos += 1

            orig_line = line

            if popped not in opcode_dict:
                op = "UNKNOWN"
                param = popped

            else:
                param = None
                op = opcode_dict[popped]

                if op == "jumpdest":
                    self.jump_dests.append(line)

                if op.startswith("push"):
                    num_words = int(op[4:])

                    # push data is read from the real code (a trailer
                    # included), zero-padded past its end as the EVM does
                    data = bytes(code[pos : pos + num_words])
                    param = int.from_bytes(data.ljust(num_words, b"\0"), "big")
                    pos += num_words
                    line += num_words

            parsed_lines.append((orig_line, op, param))
            line += 1

        # Compiled code never runs into its trailer, crafted code may: the
        # EVM takes any JUMPDEST byte outside push data as a jump target,
        # trailer included. The VM reports such paths instead of following
        # them (Loader.runs_into_trailer).
        self.code_end = pos
        self.trailer_jump_dests = set()
        while pos < len(code):
            if code[pos] == 0x5B:
                self.trailer_jump_dests.add(pos)
            pos += 1 + (code[pos] - 0x5F if 0x60 <= code[pos] <= 0x7F else 0)

        self.parsed_lines = parsed_lines
        self.last_line = line
        self.free_memory_pointer = _prologue_free_memory_pointer(parsed_lines)
        self.lines = {}

        # PUSH arguments stay ints: the text printer shows the printable ones
        # as strings (prettify.pretty_num)
        for line_no, op, param in parsed_lines:
            if op[:3] == "dup":
                param = int(op[3:])
                op = "dup"

            if op[:4] == "swap":
                param = int(op[4:])
                op = "swap"

            self.lines[line_no] = (line_no, op, param)

        return self.lines

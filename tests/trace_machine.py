"""
A small concrete evaluator of decompiled traces, for tests: it runs the
`orig_trace` of a function on given calldata and storage and returns what
the function does (success, output bytes, storage, logs, calls).

It is written out here, independent of the engine, from the trace
semantics: words are taken modulo 2**256; a time-dependent atom means its
value at the line where it appears (storage now, the result of the most
recent call); the setvars of a `continue` are parallel assignments;
("require", C, LINE) runs LINE when C is false. Byte strings: ("bytes", n,
x) is the low n bytes of x, ("data", ...) the concatenation of its parts, a
plain word part 32 bytes, a slice its length. An ABI dynamic value ("arr",
LEN, PARTS...) among the parts of a "data" is the offset word of its tail,
which follows the head parts: the word LEN, then PARTS, zero padded to whole
words. ("storage", SIZE, OFF, ("length", KEY)) is the length of the legacy
bytes / string slot KEY.

Calls are modelled by `on_call(kind, address, value, payload) -> (success,
return data)`, called in trace order (default: success, echo the payload).
Shapes outside this subset raise NotEvaluable.
"""

from eth_hash.auto import keccak

M = 2**256
RETURN_DATA = ("ext_call.return_data", "delegate.return_data", "callcode.return_data")


class NotEvaluable(Exception):
    pass


class Done(Exception):
    def __init__(self, success, output):
        self.success, self.output = success, output


class _Continue(Exception):
    def __init__(self, target, setvars):
        self.target, self.setvars = target, setvars


def signed(x):
    x %= M
    return x - M if x >> 255 else x


def mask_shl(size, off, shl, v):
    if off < 0:
        size, off = size + off, 0
    if size <= 0 or off >= 256:
        return 0
    field = (v >> off) & ((1 << min(size, 256 - off)) - 1)
    shift = off + shl
    if shift < 0:
        return field >> min(-shift, 256)
    return (field << shift) % M if shift < 256 else 0


def _echo(kind, address, value, payload):
    return 1, payload


class Machine:
    ENV = {"caller": 0xCA11E4, "origin": 0xCA11E4, "address": 0xC0DE, "callvalue": 0,
           "timestamp": 1700000000, "number": 100, "chainid": 1, "gasprice": 0}

    def __init__(self, calldata, storage=None, on_call=_echo, balance=10**18, max_steps=100000):
        self.cd = calldata
        self.storage = dict(storage or {})
        self.tstorage = {}
        self.mem = bytearray()
        self.vars = {}
        self.logs = []
        self.calls = []
        self.on_call = on_call
        self.balance = balance
        self.success = 1
        self.ret = b""
        self.steps = max_steps

    # ------------------------------------------------------------ running

    def call(self, trace):
        """(success, output) of running `trace`."""
        try:
            self.run(trace)
        except Done as d:
            return d.success, d.output
        return True, b""

    def run(self, trace):
        for idx, line in enumerate(trace):
            self.steps -= 1
            if self.steps < 0:
                raise NotEvaluable("too many steps")
            op = line[0]
            if op == "label":
                # a loop the structurer left as label + continue: the rest
                # of the block is its body
                self.parallel(line[2])
                while True:
                    try:
                        self.run(trace[idx + 1 :])
                    except _Continue as c:
                        if c.target != str(line[1]):
                            raise
                        self.parallel(c.setvars)
                        self.steps -= 1
                        if self.steps < 0:
                            raise NotEvaluable("too many steps")
                        continue
                    return
            if op == "if":
                self.run(line[2] if self.word(line[1]) else line[3])
                return
            if op == "setvar":
                self.vars[line[1]] = self.word(line[2])
            elif op == "setmem":
                p, n = self.word(line[1][1]), self.word(line[1][2])
                data = self.stored(line[2], n)
                self.read(p, n)
                self.mem[p : p + n] = data
            elif op == "store":
                size, off, slot, v = (self.word(x) for x in line[1:5])
                off = signed(off)
                slot = (slot + off // 256) % M
                off %= 256
                mask = ((1 << min(size, 256)) - 1) << off
                old = self.storage.get(slot, 0)
                self.storage[slot] = ((old & ~mask) | ((v << off) & mask)) % M
            elif op == "require":
                if not self.word(line[1]):
                    self.run([line[2] if len(line) > 2 else ("revert", None)])
            elif op == "while":
                _, cond, body, jd, init = line[:5]
                self.parallel(init)
                while self.word(cond):
                    self.steps -= 1
                    if self.steps < 0:
                        raise NotEvaluable("too many steps")
                    try:
                        self.run(body)
                    except _Continue as c:
                        if c.target != str(jd):
                            raise
                        self.parallel(c.setvars)
                        continue
                    return  # the body ended the function
            elif op == "continue":
                raise _Continue(str(line[1]), line[2])
            elif op == "tstore":
                self.tstorage[self.word(line[1])] = self.word(line[2])
            elif op == "log":
                self.logs.append((tuple(self.word(t) for t in line[2:]), self.bytes_of(line[1])))
            elif op in ("call", "staticcall", "delegatecall"):
                if op == "delegatecall":
                    _, _gas, addr, fname, payload = line[:5]
                    value = 0
                else:
                    _, _gas, addr, value, fname, payload = line[:6]
                head = self.bytes_of(fname) if fname is not None else b""
                body = self.bytes_of(payload) if payload is not None else b""
                kind, a, v = op, self.word(addr) % 2**160, self.word(value)
                self.calls.append((kind, a, v, head + body))
                ok, self.ret = self.on_call(kind, a, v, head + body)
                self.success = int(ok)
                if ok:
                    self.balance -= v
            elif op == "return":
                raise Done(True, self.bytes_of(line[1]))
            elif op == "revert":
                raise Done(False, self.bytes_of(line[1]))
            elif op == "stop":
                raise Done(True, b"")
            elif op == "invalid":
                raise Done(False, b"")
            else:
                raise NotEvaluable(op)

    def parallel(self, setvars):
        values = [(sv[1], self.word(sv[2])) for sv in setvars]
        self.vars.update(values)

    # ------------------------------------------------------------ memory

    def read(self, p, n):
        if p > 1 << 20 or n > 1 << 16:
            raise NotEvaluable("far memory")
        if p + n > len(self.mem):
            self.mem.extend(b"\0" * (p + n - len(self.mem)))
        return bytes(self.mem[p : p + n])

    def stored(self, v, n):
        if isinstance(v, tuple) and v and v[0] in ("data", "bytes", "mem", "call.data") + RETURN_DATA:
            raw = self.bytes_of(v)
            if len(raw) == n:
                return raw
            x = int.from_bytes(raw, "big")
        else:
            x = self.word(v)
        return (x % (1 << (8 * n))).to_bytes(n, "big") if n else b""

    def bytes_of(self, e):
        if e is None:
            return b""
        if isinstance(e, tuple) and e:
            op = e[0]
            if op == "data":
                tails = [p for p in e[1:] if isinstance(p, tuple) and p and p[0] == "arr"]
                if len(tails) > 1:
                    raise NotEvaluable("several dynamic tails")
                if tails:
                    _, length, *parts = tails[0]
                    tail = b"".join(self.bytes_of(p) for p in parts)
                    tail = self.word(length).to_bytes(32, "big") + tail + b"\0" * (-len(tail) % 32)
                    offset = (32 * (len(e) - 1)).to_bytes(32, "big")
                    head = b"".join(offset if p is tails[0] else self.bytes_of(p) for p in e[1:])
                    return head + tail
                return b"".join(self.bytes_of(p) for p in e[1:])
            if op == "bytes":
                n = self.word(e[1])
                return (self.word(e[2]) % (1 << (8 * n))).to_bytes(n, "big") if n else b""
            if op == "mem":
                return self.read(self.word(e[1][1]), self.word(e[1][2]))
            if op == "call.data" or op in RETURN_DATA:
                src = self.cd if op == "call.data" else self.ret
                # ("delegate.return_data", ADDR, n): from the start
                o = 0 if op == "delegate.return_data" else self.word(e[1])
                n = self.word(e[2])
                if n > 1 << 16:
                    raise NotEvaluable("huge slice")
                return src[o : o + n].ljust(n, b"\0") if o < len(src) else b"\0" * n
        return self.word(e).to_bytes(32, "big")

    # ------------------------------------------------------------ words

    def word(self, e):
        if isinstance(e, bool):
            return int(e)
        if isinstance(e, int):
            return e % M
        if isinstance(e, str):
            if e in self.ENV:
                return self.ENV[e]
            if e == "calldatasize":
                return len(self.cd)
            if e == "ext_call.success":
                return self.success
            if e == "returndatasize":
                return len(self.ret)
            raise NotEvaluable(e)
        if not isinstance(e, tuple) or not e:
            raise NotEvaluable(e)
        op = e[0]
        if op == "var":
            if e[1] not in self.vars:
                raise NotEvaluable("unbound variable %r" % (e[1],))
            return self.vars[e[1]]
        if op == "cd":
            off = self.word(e[1])
            return int.from_bytes(self.cd[off : off + 32].ljust(32, b"\0"), "big") if off < len(self.cd) else 0
        if op == "storage" and isinstance(e[3], tuple) and e[3][0] == "length":
            # the simplifier's (length KEY): the length the legacy code decodes
            # from a bytes / string slot W, (W & (W & 1 ? 2**256 - 1 : 0xff)) >> 1
            key = e[3][1]
            slot = key[1] if isinstance(key, tuple) and key[0] == "loc" else self.word(key)
            w = self.storage.get(slot, 0)
            off = signed(self.word(e[2]))
            return mask_shl(min(self.word(e[1]), 256), off, -off, (w if w & 1 else w & 0xFF) >> 1)
        if op == "storage":
            size, off, slot = self.word(e[1]), signed(self.word(e[2])), self.word(e[3])
            slot = (slot + off // 256) % M
            return mask_shl(min(size, 256), off % 256, -(off % 256), self.storage.get(slot, 0))
        if op == "balance":
            return self.balance if e[1] == "address" else 0
        if op == "tload":
            return self.tstorage.get(self.word(e[1]), 0)
        if op in ("mem", "data", "bytes", "call.data") + RETURN_DATA:
            raw = self.bytes_of(e)
            if len(raw) > 32:
                raise NotEvaluable("byte string wider than a word")
            return int.from_bytes(raw, "big")
        if op == "sha3":
            return int.from_bytes(keccak(self.bytes_of(e[1])), "big")
        a = [self.word(x) for x in e[1:]]
        if op == "mask_shl":
            return mask_shl(signed(a[0]), signed(a[1]), signed(a[2]), a[3])
        if op == "add":
            return sum(a) % M
        if op == "mul":
            r = 1
            for x in a:
                r = r * x % M
            return r
        if op == "sub":
            return (a[0] - a[1]) % M
        if op == "div":
            return a[0] // a[1] if a[1] else 0
        if op == "mod":
            return a[0] % a[1] if a[1] else 0
        if op == "exp":
            return pow(a[0], a[1], M)
        if op in ("lt", "gt", "le", "ge", "eq"):
            x, y = a
            return int({"lt": x < y, "gt": x > y, "le": x <= y, "ge": x >= y, "eq": x == y}[op])
        if op in ("slt", "sgt", "sle", "sge"):
            x, y = signed(a[0]), signed(a[1])
            return int({"slt": x < y, "sgt": x > y, "sle": x <= y, "sge": x >= y}[op])
        if op == "iszero":
            return int(a[0] == 0)
        if op == "bool":
            return int(a[0] != 0)
        if op == "and":
            r = M - 1
            for x in a:
                r &= x
            return r
        if op == "or":
            r = 0
            for x in a:
                r |= x
            return r
        if op == "xor":
            r = 0
            for x in a:
                r ^= x
            return r
        if op == "not":
            return (M - 1) ^ a[0]
        if op == "min":
            return min(a)
        if op == "signextend":
            b, x = a
            if b >= 31:
                return x
            bit = 8 * b + 7
            low = x & ((1 << (bit + 1)) - 1)
            return (low | (M - (1 << (bit + 1)))) % M if (x >> bit) & 1 else low
        raise NotEvaluable(op)

"""
Property test of the memory model: random straight-line traces of memory
writes and reads (concrete and runtime-computed addresses and lengths,
partial overlaps, one-byte writes, copies, words written over a computed
number of bytes) are evaluated on a byte-addressed memory before and after
`simplify_trace`, for several calldatas. Any difference is an unsound
memory rewrite (a value forwarded past a write that changed it, a split that
claims bytes it does not hold...).

The evaluator below is written out here, independent of the engine:
- a word expression stored in n bytes keeps its low n bytes (zero-extended
  when n > 32), so does a byte string of another length than its range;
- ("bytes", n, x) is the low n bytes of x, ("data", ...) the concatenation of
  its parts, a plain word part 32 bytes;
- mask sizes, offsets and shifts are signed (a size <= 0 selects nothing).

The default run is small and seeded. Longer local runs:

    python tests/test_memory_fuzz.py TRACES SEED [LINES]
"""

import random
import sys

from scobelix.simplify import simplify_trace

M = 2**256
CD = [("cd", 4), ("cd", 36), ("cd", 68)]
OFF6 = ("mask_shl", 6, 0, 0, ("cd", 100))  # 0..63, known at runtime only
OFF5 = ("mask_shl", 5, 0, 0, ("cd", 132))  # 0..31
TAIL = ("mask_shl", 253, 0, 3, ("add", 32, ("mul", -1, OFF5)))  # 8 * (32 - off5) bits
EDGE = [0, 1, 31, 32, 33, 0xFF, 2**64, 2**160 - 1, 2**255, M - 1, M - 2, 0x4142434445464748]


class NotEvaluable(Exception):
    pass


class Done(Exception):
    def __init__(self, data):
        self.data = data


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
        return field >> -shift
    return (field << shift) % M if shift < 256 else 0


class Machine:
    def __init__(self, calldata):
        self.cd = calldata
        self.mem = bytearray()
        self.vars = {}

    def read(self, p, n):
        if p > 1 << 16 or n > 1 << 12:
            raise NotEvaluable("far memory")
        if p + n > len(self.mem):
            self.mem.extend(b"\0" * (p + n - len(self.mem)))
        return bytes(self.mem[p : p + n])

    def word(self, e):
        if isinstance(e, bool):
            return int(e)
        if isinstance(e, int):
            if e >= M:
                raise NotEvaluable("wide int")
            return e % M
        if not isinstance(e, tuple) or not e:
            raise NotEvaluable(e)
        op = e[0]
        if op == "var":
            return self.vars[e[1]]
        if op == "cd":
            off = self.word(e[1])
            return int.from_bytes(self.cd[off : off + 32].ljust(32, b"\0"), "big")
        if op in ("mem", "data", "call.data", "bytes"):
            raw = self.bytes_of(e)
            if len(raw) > 32:
                raise NotEvaluable("byte string wider than a word")
            return int.from_bytes(raw, "big")
        args = [self.word(a) for a in e[1:]]
        if op == "mask_shl":
            return mask_shl(signed(args[0]), signed(args[1]), signed(args[2]), args[3])
        if op == "add":
            return sum(args) % M
        if op == "mul":
            r = 1
            for a in args:
                r = r * a % M
            return r
        if op == "or":
            r = 0
            for a in args:
                r |= a
            return r
        if op == "and":
            r = M - 1
            for a in args:
                r &= a
            return r
        if op == "iszero":
            return int(args[0] == 0)
        raise NotEvaluable(op)

    def bytes_of(self, e):
        """The byte string of a payload / blob part."""
        if e is None:
            return b""
        if isinstance(e, tuple) and e:
            op = e[0]
            if op == "data":
                return b"".join(self.bytes_of(p) for p in e[1:])
            if op == "bytes":
                n = self.word(e[1])
                if n > 1 << 12:
                    raise NotEvaluable("huge part")
                return (self.word(e[2]) % (1 << (8 * n))).to_bytes(n, "big") if n else b""
            if op == "mem":
                if e[1][0] != "range":
                    raise NotEvaluable(e)
                return self.read(self.word(e[1][1]), self.word(e[1][2]))
            if op == "call.data":
                o, n = self.word(e[1]), self.word(e[2])
                if n > 1 << 12:
                    raise NotEvaluable("huge slice")
                return self.cd[o : o + n].ljust(n, b"\0") if o < len(self.cd) else b"\0" * n
        return self.word(e).to_bytes(32, "big")

    def stored(self, v, n):
        """The n bytes a write of v to a range of n bytes puts in memory."""
        if isinstance(v, tuple) and v and v[0] in ("data", "bytes", "mem", "call.data"):
            raw = self.bytes_of(v)
            if len(raw) == n:
                return raw
            x = int.from_bytes(raw, "big")
        else:
            x = self.word(v)
        return (x % (1 << (8 * n))).to_bytes(n, "big") if n else b""

    def run(self, trace):
        for line in trace:
            op = line[0]
            if op == "setvar":
                self.vars[line[1]] = self.word(line[2])
            elif op == "setmem":
                p, n = self.word(line[1][1]), self.word(line[1][2])
                data = self.stored(line[2], n)
                self.read(p, n)  # grows the memory
                self.mem[p : p + n] = data
            elif op == "return":
                raise Done(self.bytes_of(line[1]))
            else:
                raise NotEvaluable(op)
        raise Done(b"")


def address(rng):
    k = rng.random()
    if k < 0.08:
        return ("add", rng.choice([0, 1, 4, 32]), ("mem", ("range", 64, 32)))
    if k < 0.6:
        return 0x80 + rng.choice([0, 0, 1, 4, 12, 20, 31, 32, 32, 33, 64, 96])
    if k < 0.8:
        return ("add", 0x80, OFF6)
    return ("add", 0x80 + rng.choice([0, 32]), OFF5)


def value(rng, reads, n):
    k = rng.random()
    if k < 0.25:
        return rng.choice(CD)
    if k < 0.4:
        return rng.choice([0, 1, 0xFF, 0x08C379A0 << 224, M - 1, 2**160 - 1, 0x4142 << 240])
    if k < 0.55:
        x = rng.choice(CD)
        return rng.choice([
            ("mask_shl", 160, 0, 0, x), ("mask_shl", 8, 248, -248, x), ("mask_shl", 32, 224, 0, x),
            ("mask_shl", 16, 0, 240, x), ("mask_shl", 248, 0, 8, x), ("mask_shl", 224, 32, -32, x),
        ])
    if k < 0.65 and reads:
        return ("var", rng.choice(reads))
    if k < 0.72 and type(n) == int and n <= 64:
        return ("call.data", rng.choice([4, 5, 36]), n)
    if k < 0.8:
        # the last word of a memory copy: high bytes from one value, low ones
        # from another, split at a position known at runtime
        a, b = rng.choice(CD), rng.choice(CD)
        return ("or", ("mask_shl", ("add", 256, ("mul", -1, TAIL)), TAIL, 0, a), ("mask_shl", TAIL, 0, 0, b))
    if k < 0.84 and reads:
        return ("add", ("var", rng.choice(reads)), rng.choice([1, 32, M - 1]))
    if k < 0.88 and type(n) == int:
        return ("mem", ("range", address(rng), n))  # a memory-to-memory copy
    if k < 0.9 and n == 32:
        return ("data", ("bytes", 4, 0x08C379A0), ("bytes", 28, rng.choice(CD)))
    return ("or", ("mask_shl", 128, 128, 0, rng.choice(CD)), ("mask_shl", 64, 0, 0, rng.choice(CD)))


def random_trace(rng, lines):
    trace, reads = [], []
    for i in range(lines):
        if rng.random() < 0.6:
            k = rng.random()
            if k < 0.6:
                n = 32
            elif k < 0.7:
                n = 1
            elif k < 0.85:
                n = rng.choice([1, 4, 20, 31, 64])
            else:
                n = ("add", 1, OFF5)  # 1..32
            v = value(rng, reads, n)
            if n == 1 and rng.random() < 0.5:
                v = ("mask_shl", 8, 0, 0, rng.choice(CD))
            if rng.random() < 0.05:
                trace.append(("setmem", ("range", 64, 32), rng.choice([0x80, 0xA0, ("add", 0xA0, OFF5)])))
            if type(n) != int and not (isinstance(v, tuple) and v[0] == "call.data"):
                v = ("call.data", 4, n) if rng.random() < 0.5 else 0
            trace.append(("setmem", ("range", address(rng), n), v))
        else:
            name = "_%d" % (i + 1)
            trace.append(("setvar", name, ("mem", ("range", address(rng), 32))))
            reads.append(name)
    last = rng.choice([32, 64, 4, 36, ("add", 1, OFF5)])
    out = tuple(("var", r) for r in reads) + (("mem", ("range", address(rng), last)),)
    trace.append(("return", ("data",) + out))
    return trace


def output(trace, calldata):
    try:
        Machine(calldata).run(trace)
    except Done as d:
        return d.data
    raise AssertionError("no return")  # pragma: no cover


def check(trace, rng, runs=6):
    """None, or (calldata, before, after) of a difference."""
    simplified = simplify_trace([tuple(line) for line in trace])
    for _ in range(runs):
        words = [rng.choice(EDGE + [rng.getrandbits(256)]) for _ in range(5)]
        calldata = bytes.fromhex("12345678") + b"".join(w.to_bytes(32, "big") for w in words)
        before = output(trace, calldata)
        try:
            after = output(simplified, calldata)
        except NotEvaluable:
            return "unevaluable"
        if before != after:
            return (calldata.hex(), before.hex(), after.hex(), simplified)
    return None


def unsound_rewrites(traces, seed, lines=8):
    rng = random.Random(seed)
    bad, unevaluable = [], 0
    for _ in range(traces):
        trace = random_trace(rng, rng.randint(2, lines))
        res = check(trace, rng)
        if res == "unevaluable":
            unevaluable += 1
        elif res is not None:
            bad.append((trace, res))
    return bad, unevaluable


def test_memory_rewrites_keep_values():
    for seed in (1, 2, 3):
        bad, unevaluable = unsound_rewrites(80, seed)
        assert bad == [], bad[:2]
        assert unevaluable <= 8  # the simplified traces stay in the evaluated subset


# Cases a random run found, kept as fixed regressions.
REGRESSIONS = [
    # a write that may end before the read range begins (off5 > 12): the
    # bytes before it must not be taken from it
    [("setmem", ("range", ("add", 128, OFF5), 31), ("cd", 36)),
     ("setmem", ("range", ("add", 160, OFF5), 32), ("cd", 36)),
     ("setmem", ("range", 140, 32), ("cd", 68)),
     ("return", ("mem", ("range", 172, 20)))],
    # a copy of bytes that a later write overwrites: its value is the bytes
    # read at the time of the copy
    [("setvar", "_1", ("mem", ("range", 161, 32))),
     ("setmem", ("range", 128, 32), ("var", "_1")),
     ("setmem", ("range", 159, 32), ("cd", 68)),
     ("return", ("data", ("mem", ("range", 128, 32)), ("mem", ("range", 129, 32))))],
]


def test_memory_regressions():
    rng = random.Random(0)
    for trace in REGRESSIONS:
        assert check(trace, rng, runs=12) is None, trace


if __name__ == "__main__":
    traces, seed = int(sys.argv[1]), int(sys.argv[2])
    lines = int(sys.argv[3]) if len(sys.argv) > 3 else 8
    bad, unevaluable = unsound_rewrites(traces, seed, lines)
    print("unsound rewrites:", len(bad), " unevaluable after simplification:", unevaluable)
    for trace, res in bad[:5]:
        print("  ", trace, "\n    ->", res)

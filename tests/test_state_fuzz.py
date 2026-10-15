"""
Property test of the time-dependent values: random traces that read
storage, balances and call results into variables (as the VM does), write
storage and memory, make calls that change storage and the return data, and
end with a branch, are run (tests/trace_machine.py) before and after
`simplify_trace`. Any difference is a read moved past a change of what it
read.

The default run is small and seeded. Longer local runs:

    python tests/test_state_fuzz.py TRACES SEED
"""

import random
import sys

from scobelix.simplify import simplify_trace

from trace_machine import Machine, NotEvaluable

SLOTS = [0, 1, ("sha3", ("data", ("cd", 4), 2)), ("sha3", ("data", ("cd", 36), 2))]
MEM = [0x80, 0xA0, 0xC0]


class Gen:
    def __init__(self, rng):
        self.rng = rng
        self.n = 0
        self.vars = []

    def fresh(self):
        self.n += 1
        return "_%d" % self.n

    def read(self):
        r = self.rng.random()
        if r < 0.5:
            return ("storage", 256, 0, self.rng.choice(SLOTS))
        if r < 0.65:
            return "returndatasize"
        if r < 0.8:
            return "ext_call.success"
        if r < 0.9:
            return ("balance", "address")
        return ("mem", ("range", self.rng.choice(MEM), 32))

    def value(self):
        r = self.rng.random()
        if self.vars and r < 0.6:
            v = ("var", self.rng.choice(self.vars))
            if self.rng.random() < 0.4:
                return ("add", self.rng.randrange(1, 9), v)
            return v
        if r < 0.8:
            return ("cd", self.rng.choice([4, 36, 68]))
        return self.rng.randrange(0, 31)  # 32 first in a return: an ABI head

    def line(self):
        r = self.rng.random()
        if r < 0.35:
            name = self.fresh()
            self.vars.append(name)
            return ("setvar", name, self.read())
        if r < 0.55:
            return ("store", 256, 0, self.rng.choice(SLOTS), self.value())
        if r < 0.75:
            return ("setmem", ("range", self.rng.choice(MEM), 32), self.value())
        value = self.rng.choice([0, 0, 1])
        return ("call", "gas", 0x1234, value, None, ("data", ("bytes", 4, 0x11223344), self.value()))

    def branch(self):
        known = list(self.vars)
        lines = [self.line(), ("return", ("data",) + tuple(self.value() for _ in range(3)))]
        self.vars = known  # a variable of one branch is not bound in the other
        return lines

    def trace(self, n):
        body = [self.line() for _ in range(n)]
        return body + [("if", ("lt", self.value(), 25), self.branch(), self.branch())]


def outcome(trace, calldata, storage):
    holder = {}

    def on_call(kind, address, value, payload):
        m = holder["m"]
        m.storage[0] = (m.storage.get(0, 0) + 1000) % 2**256  # the callee writes slot 0
        n = len(m.calls)
        return n % 3 != 0, bytes(range(n % 5 * 7))

    m = holder["m"] = Machine(calldata, storage=storage, on_call=on_call)
    try:
        ok, out = m.call(trace)
    except (NotEvaluable, KeyError):
        return None
    return ok, out, sorted(kv for kv in m.storage.items() if kv[1]), m.calls


def unsound_rewrites(traces, seed, lines=10):
    rng = random.Random(seed)
    bad = []
    for _ in range(traces):
        trace = Gen(rng).trace(lines)
        simplified = simplify_trace(trace)
        if "'arr'" in str(simplified):
            continue  # the rewriter's display form of an ABI head (32, len, ...): not evaluated here
        for _ in range(4):
            calldata = bytes.fromhex("aabbccdd") + b"".join(
                rng.randrange(0, 40).to_bytes(32, "big") for _ in range(3)
            )
            storage = {0: rng.randrange(0, 40), 1: rng.randrange(0, 40)}
            before = outcome(trace, calldata, dict(storage))
            if before is None:
                continue
            after = outcome(simplified, calldata, dict(storage))
            if before != after:
                bad.append((trace, simplified, calldata, storage, before, after))
                break
    return bad


def test_time_dependent_reads_keep_their_values():
    for seed in range(5):
        bad = unsound_rewrites(40, seed)
        assert not bad, bad[0]


if __name__ == "__main__":
    n, seed = int(sys.argv[1]), int(sys.argv[2])
    found = unsound_rewrites(n, seed)
    for t, s, cd, st, b, a in found[:3]:
        print("TRACE", t, "\nSIMPLIFIED", s, "\nCD", cd.hex(), st, "\n", b, "\n", a, "\n")
    print(len(found), "unsound of", n)

"""
Where the locals of a function body can be declared.

Solidity scopes a local from its declaration to the end of the enclosing
block.  `sites(body)` gives, for each local that can be declared where it is
first assigned, the assignments that then become declarations
(`uint256 x = value;`): every mention of the local lies after one of them,
in the same block or in a block nested in it, and the declarations of one
local stand in disjoint blocks (the two branches of an `if`: the code a
branch duplicates declares its own).

A site is found block by block.  In a block, the first statement that
mentions the local must be a plain assignment of it whose value does not
read it: it is the site, and it covers the rest of the block.  When one
single statement of the block mentions the local and that statement is an
`if` (not in its condition), a loop (not in its header) or a `for` whose
header initialises it, the search goes on inside.  Anything else (a local
first set in a branch and read after it, first mentioned by a loop header,
by a compound assignment or by the output of a precompile call) has no
site: the local is declared at the top of the function.

The loops pass marks the sites (`ir.Assign.declare`); the renderer runs the
same analysis on the body it writes and declares a local in place only when
its marked assignments are exactly its sites, so a pass that later moves or
copies statements cannot produce a text whose scopes are wrong.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, List, Optional, Sequence, Set

from scobelix.solgen import ir

__all__ = ["sites"]


class _Scopes:
    def __init__(self) -> None:
        self.memo: Dict[int, FrozenSet[str]] = {}
        self.foreign: Set[str] = set()  # locals something other than an assignment sets

    def names(self, n: ir.Node) -> FrozenSet[str]:
        """The locals node `n` mentions."""
        got = self.memo.get(id(n))
        if got is None:
            out: Set[str] = set()
            if isinstance(n, ir.Local):
                out.add(n.name)
            elif isinstance(n, ir.Precompile) and n.output:
                self.foreign.add(n.output)
                out.add(n.output)
            for c in ir.children(n):
                out |= self.names(c)
            got = self.memo[id(n)] = frozenset(out)
        return got

    def within(self, nodes: Sequence[ir.Node], x: str) -> bool:
        return any(x in self.names(n) for n in nodes)

    def plain(self, s: ir.Stmt, x: str) -> bool:
        return isinstance(s, ir.Assign) and isinstance(s.target, ir.Local) and s.target.name == x \
            and s.op is None and x not in self.names(s.value)

    def solve(self, block: Sequence[ir.Stmt], x: str) -> Optional[List[ir.Assign]]:
        """The declaration sites of `x` in `block` ([]: not mentioned; None:
        it cannot be declared inside)."""
        at = [k for k, s in enumerate(block) if x in self.names(s)]
        if not at:
            return []
        s = block[at[0]]
        if self.plain(s, x):
            return [s]
        if len(at) > 1:
            return None
        if isinstance(s, ir.If) and x not in self.names(s.cond):
            a, b = self.solve(s.then, x), self.solve(s.orelse, x)
            return None if a is None or b is None else a + b
        if isinstance(s, ir.For):
            if self.within(s.init, x):
                return [s.init[0]] if len(s.init) == 1 and self.plain(s.init[0], x) else None
            if x in self.names(s.cond) or self.within(s.step, x):
                return None
            return self.solve(s.body, x)
        if isinstance(s, ir.While) and x not in self.names(s.cond) and not self.within(s.init, x):
            return self.solve(s.body, x)
        return None


def sites(body: Sequence[ir.Stmt]) -> Dict[str, List[ir.Assign]]:
    """Local name -> the assignments that can declare it (see the module
    text); the locals left out are declared at the top of the function."""
    sc = _Scopes()
    names: Set[str] = set()
    for s in body:
        names |= sc.names(s)
    out: Dict[str, List[ir.Assign]] = {}
    for x in sorted(names - sc.foreign):
        got = sc.solve(body, x)
        if got:
            out[x] = got
    return out

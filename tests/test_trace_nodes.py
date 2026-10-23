"""
An execution node (vm.Node) left in a trace is an identity marker, printed
as `Node(jd)`: the graph behind it (the `prev` chain back to the root, the
VM, the loader) is not part of the trace and must never be copied with
it. Copying it recursed once per node of the chain, and a long chain
(hundreds of nodes) took the function down with a RecursionError in
Function.__init__, where the trace is deep-copied.
"""

import copy
import sys

from scobelix.function import Function
from scobelix.utils.signatures import make_abi
from scobelix.vm import Node

CHAIN = 3000  # nodes in the prev chain: more than the recursion limit below


def _node_with_a_long_chain(length=CHAIN):
    """A Node whose `prev` chain has `length` nodes, built without a VM."""
    prev = None
    for i in range(length):
        node = Node.__new__(Node)
        node.vm = None
        node.prev = [] if prev is None else prev
        node.next = []
        node.trace = None
        node.start = i
        node.safe = True
        node.stack = []
        node.history = {}
        node.depth = i
        node.label_history = {}
        node.label = None
        node.condition = True
        node.entry_stack = None
        node.jd = (i, 0, ())
        if prev is not None:
            prev.next.append(node)
        prev = node
    return prev


def test_a_node_is_not_copied_with_its_trace():
    node = _node_with_a_long_chain()
    trace = [("if", ("eq", node, 1), [("return", 1)], [("revert", 0)])]
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(1000)
    try:
        copied = copy.deepcopy(trace)
        assert copied[0][1][1] is node and copied is not trace and copied[0][2] is not trace[0][2]
        assert copy.copy(node) is node
    finally:
        sys.setrecursionlimit(limit)
    assert str(node) == repr(node) == f"Node({node.jd})"


def test_a_function_whose_trace_holds_a_node_is_built():
    node = _node_with_a_long_chain()
    make_abi({"0x00000001": (0, ())})
    trace = [("if", ("eq", node, 1), [("return", 1)], [("revert", 0)])]
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(1000)
    try:
        f = Function("0x00000001", trace, abi_coder_v2=True)
    finally:
        sys.setrecursionlimit(limit)
    assert f.orig_trace[0][1][1] is node
    assert f.print()

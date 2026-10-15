"""
Execution backends for differential execution.

    pyrevm  revm through pyrevm: fast, no hooks (bulk fuzzing)
    pyevm   py-evm: slower, fully hookable (exact storage reads, call tree,
            branch coverage, comparison operands, deterministic environment)

Both are optional dependencies (`pip install 'scobelix[verify]'`);
`available_backends()` lists the importable ones, and `make_world` raises
`BackendUnavailable` for a missing one.  Every world executes the Cancun
fork by default: the newest one both backends implement.
"""

from __future__ import annotations

import functools
import importlib
from typing import List

from .base import DEFAULT_GAS, BackendUnavailable, BlockSpec, CallResult, HarnessError, World, lower

__all__ = [
    "BACKENDS",
    "DEFAULT_GAS",
    "BackendUnavailable",
    "BlockSpec",
    "CallResult",
    "HarnessError",
    "World",
    "available_backends",
    "lower",
    "make_world",
]

BACKENDS = ("pyrevm", "pyevm")
_MODULES = {"pyrevm": "pyrevm", "pyevm": "eth.vm.forks.cancun.state"}


@functools.lru_cache(maxsize=None)
def _importable(module: str) -> bool:
    try:
        importlib.import_module(module)
        return True
    except Exception:  # ImportError, or a broken install failing at import time
        return False


def available_backends() -> List[str]:
    """The backends whose package is installed, fastest first."""
    return [name for name in BACKENDS if _importable(_MODULES[name])]


def make_world(
    backend: str, block: BlockSpec = BlockSpec(), fork: str = "cancun", **hooks
) -> World:
    """
    A fresh world.  `hooks` (py-evm only): covered=<address>, gas_cap=<int>,
    self_code=(size, hash), cmplog=<bool> - see PyEvmWorld.
    """
    if backend == "pyrevm":
        if hooks:
            raise ValueError(f"pyrevm has no hooks ({sorted(hooks)}): use the pyevm backend")
        from .revm import PyRevmWorld

        return PyRevmWorld(block, fork)
    if backend == "pyevm":
        from .pyevm import PyEvmWorld

        return PyEvmWorld(block, fork, **hooks)
    raise ValueError(f"unknown backend {backend!r} (one of {', '.join(BACKENDS)})")

"""
Solidity reconstruction of a decompiled contract.

    from scobelix.decompiler import decompile_bytecode
    from scobelix.solgen import generate_solidity

    result = generate_solidity(decompile_bytecode(code))
    result.solidity        # the source text
    result.confidence      # {"0xa9059cbb": "medium", ...}
    result.warnings        # ["...", ...]
    result.functions       # per function: name, tier, verdict, flags...

    result = generate_solidity(decompilation, verify=True)
    result.verification    # levels, verdicts, what the verification did
                           # (None when it could not run)

The generated contract keeps the behaviour of the bytecode: what cannot be
written as ordinary Solidity is written with its exact EVM meaning.

Without `verify` nothing is presented as verified: every function has the
verdict "unverified" and a confidence of "medium" at most; the rewriting
passes apply wherever no risk flag forbids it.

`verify=True` runs the verification loop (`scobelix.solgen.tiers`): the
text is compiled and run against the original bytecode, function by
function.  A function keeps a rewritten form only when a run of exactly
that form found no difference; when one is found, the passes of that
function are backed off until none is left, and the functions that cannot
be shown to behave like the original are written in exact form, with
their verdict and, for a difference, the call that shows it.
"""

from typing import Optional

from scobelix.solgen.tiers import SearchBudget
from scobelix.solgen.v2 import CONTRACT_NAME, SolgenResult, generate
from scobelix.solgen.validate import ValidationResult, validate, validate_solidity

__all__ = [
    "SearchBudget",
    "SolgenResult",
    "generate_solidity",
    "ValidationResult",
    "validate",
    "validate_solidity",
]


def generate_solidity(
    decompilation,
    *,
    verify: bool = False,
    target_solc: Optional[str] = None,
    idiom_level: str = "full",
    budget=None,
    allow_solc_download: Optional[bool] = None,
    contract_name: str = CONTRACT_NAME,
) -> SolgenResult:
    """Solidity source for a decompiled contract.

    decompilation        a `scobelix.decompiler.Decompilation`.  One
                         without in-memory functions (only its `json`), or
                         the `json` dict itself, is accepted in a degraded
                         mode: the code is lifted from the JSON traces and
                         kept in exact form, and it cannot be verified
                         without the bytecode.
    verify               run the verification loop: compile the text, run
                         it against the original bytecode and keep, for
                         every function, the most idiomatic form that was
                         seen to behave like the original; the others are
                         written in exact form (needs a solc release and
                         an EVM backend: `pip install 'scobelix[verify]'`;
                         when one is missing the result carries a warning
                         and every function is in exact form, unverified).
    target_solc          the compiler version "X.Y.Z" to write for
                         (default: the original's when it is a 0.8 release,
                         0.8.2 or later, that is installed or may be
                         downloaded; else the newest installed 0.8; else
                         the original's 0.8 release even if absent; else
                         0.8.19 - each time at least the release the
                         constructs of the text need, e.g. 0.8.25 for
                         transient storage).  A requested version older
                         than that is kept, with a warning.
    idiom_level          "full": idiomatic Solidity wherever a rewriting
                         pass applies, the functions whose code carries a
                         risk flag staying in exact form; "exact": no
                         rewriting at all.
    budget               for verify=True: a `scobelix.verify.Budget` (how
                         much every run does), a `SearchBudget` (the limits
                         of the loop: `time_limit` in seconds, 300 by
                         default, `max_rounds`, `l4`, and the verify budget
                         as `verify`), or the fields of both in one dict.
    allow_solc_download  let the generator fetch an official solc release
                         (default: the SCOBELIX_ALLOW_SOLC_DOWNLOAD
                         environment variable).
    contract_name        the name of the generated contract.

    Returns a `SolgenResult`: `solidity`, `confidence` (function key ->
    "high" | "medium" | "low" | "none", see
    `scobelix.solgen.v2.derive_confidence`), `warnings`, `functions`
    (per function: `tier` "idiomatic" | "partial" | "exact", `passes`,
    `disabled_passes`, `verdict`, `calls`, `coverage`, `counterexample`,
    `flags`...), `verification` (with verify=True: the levels L0 to L4,
    the verdict counts and, under `search`, what the loop did; `to_json()`
    gives it as JSON data), `target_solc`, `storage_layout`,
    `original_compiler`.
    """
    return generate(
        decompilation,
        target_solc,
        verify,
        idiom_level,
        allow_download=allow_solc_download,
        budget=budget,
        contract_name=contract_name,
    )

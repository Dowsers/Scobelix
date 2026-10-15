"""
solgen v2 passes: IR -> IR rewrites that make the code idiomatic once they
have proven the idiomatic form equivalent.

A pass is a module `scobelix/solgen/passes/<name>.py`, picked up by the
pass manager (`scobelix.solgen.pipeline`) when its name is in
`pipeline.PASS_ORDER`.  It defines:

    run(fn: ir.Function, ctx: pipeline.PassContext) -> ir.Function
        rewrite one entry point (`fn.key`: "0x<selector>", "_fallback" or
        "_receive"); return `fn` itself when nothing applies.  Never mutate
        nodes (they are frozen): build new ones (`ir.transform`,
        `fn.with_body(body, extra_flags)`).  A rewrite must keep the exact
        EVM semantics of the function, or, when it relies on an
        assumption, add a flag to the function.

and optionally:

    LEVELS = ("full",)
        the idiom levels the pass runs at (default: ("full",); the "exact"
        level runs no pass at all)
    prepare(ctx: pipeline.PassContext) -> None
        contract-level analysis, run once before the functions (storage
        layout, events, ...); results go in `ctx.facts[<name>]`
    finish(ctx: pipeline.PassContext) -> None
        run once after every function: add contract-level declarations
        with `ctx.declare(kind, text)`, kind in `pipeline.DECLARATION_KINDS`
        ("interface", "struct", "event", "error", "constant", "state",
        "modifier", "function"; one Solidity snippet per call, written
        once, in that order; any other kind is an error)

A pass may also fold an entry point into a declaration (`ctx.fold(key,
name)`, the getters pass: a `T public name` state variable or a public
constant whose generated getter behaves exactly like the function): the
function is then not written out (its key is in `ctx.folded`).

`ctx` gives the contract-level facts (see `pipeline.PassContext`): every
lifted body before the passes (`ctx.functions[key]`, for contract-wide
analyses such as the storage layout), the entry specs (`ctx.specs[key]`),
the original metadata and dispatcher, the target compiler, whether the
original used ABI coder v2, the signature lookups
(`scobelix.solgen.sigs`), and the per-function switches.

Rules for passes written side by side:

  * independence: a pass listed in `disabled_passes[key]` (or
    `disabled_passes["*"]`) does not run on that function, so the tier
    search can switch any subset off; a pass must work whether or not the
    passes before it in PASS_ORDER ran (check for the nodes it needs);
  * declarations of an entry point live in `ctx.specs[key]` (the
    abi.EntrySpec contract assembly declares: name, params, returns,
    mutability, payable).  A pass may change the fields it owns (abi:
    params / returns; naming: parameter names), never the selector, and
    names must pass `render.reserved_name` (keywords, builtins and the
    generator's own names are not declarable);
  * idiomatic nodes and what the renderer makes of them are specified in
    `ir.py` (`Typed`, `Cast`, `Bool`, `Not`, `And`, `Or`, `StateRef`,
    `Assign.op`, `For`, `Break`, `Require`, `Assert`, `Emit`,
    `Return.values`, `HighCall`, `Result`, `Transfer`, `Forward`,
    `Builtin`, `ExtCall.ok` / `.ret`): build them only with the meaning
    documented there.
    Checked operations (`Typed(checked=True)`) make the renderer write the
    function outside `unchecked` (render.py explains how wrapping
    operations stay exact there).
"""

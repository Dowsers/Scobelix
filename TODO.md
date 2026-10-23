# TODO

Known limitations that remain open, grouped by component. Most of them are
specified with their observable effect, in French, in the documents under
[docs/](docs/README.md) (contextual notes).

## Decompiler engine

 * `shl` with a computed shift k becomes `mask_shl(256, 0, k, x)`, whose
   output shift is signed: for 2^256 - 256 < k < 2^256 the trace, and the
   generated text through `_maskShl`, shift x right where the EVM gives 0
   (a verification finds such a function DIVERGENT at the exact tier).
 * The dispatcher analysis is conservative: an unrecognised condition above
   the dispatch, or exits reaching the same code with different stacks, give
   a single fallback over the whole code. Vyper >= 0.3.10 jump-table dispatch
   (gas / codesize) is not split: one fallback with
   `jump to a parameter computed at runtime`.
 * Loops the engine does not finish stay `undefined`: the generated function
   is exact, flagged `unstructured`, and can verify `DIVERGENT`.
 * Storage-array copies ignore solc's `32 * len` wrap-around.
 * Signs decided from two sample values (`core/algebra.add_ge_zero`) can give
   negative part lengths when memory writes are split; a memory read cut at a
   symbolic boundary of an unaligned concatenation can then drop a piece
   (wrong log data for strings concatenated then emitted, solc < 0.8). The
   generator writes such code exactly, but it is not what solc compiled.
 * Storage aliasing rests on the Solidity layout assumptions (keccak free of
   collisions, hashed data away from the declared slots): assembly writing
   `keccak(k) + huge index` onto a small slot, or a pre-0.6 corrupted array
   length, would be mis-modelled.
 * Precompile outputs are written as whole words (the EVM writes
   `min(L, output size)`, an invalid `ecrecover` writes nothing); the
   identity precompile has no call line; the value sent to a precompile is
   not modelled; `RETURNDATASIZE` before any call stays symbolic.
 * Residual labels remain when the first discriminating `if` loops back in
   both branches, and for via-IR merge points reached twice with the same
   stack.
 * The display-only readability rule FR-DEC-92 compares the true branch with
   itself.
 * `cleanup_mems` is quadratic (one memory replacement over the rest of the
   trace per memory write): very large functions reach the time limits, and
   results cut by the wall-clock limits depend on the machine's load
   (identical texts across runs are only guaranteed when no limit cuts one).
 * `memloc.split_setmem` writes the rows of a memory `or` one after the
   other: a memory word rewritten with its own bytes moved (assembly only)
   would read bytes an earlier row overwrote. Not reached by any known
   input; not documented as a note.
 * Parameter types the bytecode cannot decide: optimised ABI coder v2 code
   does not check 256-bit types (`bytes32` / `int256` read as `uint256`),
   coder v1 `bytes` reads as an array, and an author's `require(x < K)` or
   `require(x <= 2**64 - 1)` opening a function is taken for a decoder check.
 * Importing the engine raises `sys.set_int_max_str_digits` process-wide to
   at least 157 828 digits.
 * Two vacuous checks in the storage naming of `sparser.py`
   (`replace_names_in_assoc` iterates raw keys,
   `replace_names_in_assoc_bool` tests a pattern never added to
   `used_locs`); no observable effect.

## Solidity generator (`scobelix.solgen`)

 * A creation of empty code (`create(v, p, 0)`: code `None` in the trace)
   is not translated: `_create(v, abi.encodePacked(_unsupported()))` reverts
   where the original creates an account without code (`_create(v, "")`
   would be exact).
 * Exactness limits tied to memory and gas: the call output area past the
   return data, `RETURNDATACOPY` past its end, the gas of reads far into
   memory, helpers that halt on sizes above 2^32 - 1. The emulated-memory
   helpers assume that an offset or size above 2^32 makes the original run
   out of gas; the gas shortcuts of the other exact helpers deserve the same
   audit.
 * Pre-0.8 decoders (short calldata before 0.5, ABI coder v1 memory copies
   without bounds) and a free memory pointer above 0x80 are flagged with
   `@dev` notes, not reproduced: such functions can stay `DIVERGENT`.
 * In exact form, a function declared with calldata array parameters lets
   the target compiler's decoder reject malformed calldata before the
   original's own checks (a different revert), and no flag says so.
 * The stack planner is conservative (it assumes the deepest variable sits
   below everything) and hoists operands that would fit, lengthening some
   bodies.
 * No per-function size bound: a very large exact body can make solc time
   out at L0, after which every pass is switched off and the verification
   budget runs out.
 * The via-IR fallback evaluates binary operands left first, while the
   renderer's evaluation-order assumptions are those of the legacy pipeline.
 * Storage distinctions the bytecode does not carry are not recovered: a
   struct versus separate variables, nested structs, fixed arrays read at
   constant indices, `bytes` versus `string`, `int256` / `bytes32` only
   returned by a getter, keys compared with untyped routed parameters. A
   legacy long-string copy loop makes a `uint256` slot be declared
   `uint256[1]`; 0.5 `bytes` written in the long encoding and never read
   back is declared `uint256[]`; the rule "1-byte field only written 0 or 1
   is a `bool`" has no veto for raw uses of the value.
 * Mutability: `nonpayable` versus `view` / `pure` intent and lowercase
   constant getters cannot be inferred from the bytecode; only trusted
   signature rows restore them.
 * Readability left: constant dynamic returns written
   `_return(abi.encodePacked(...))`; some dynamic events stay raw `_logN`;
   unknown event signatures give anonymous stand-ins;
   `uint256(uint160(msg.sender)) == 0` comparisons and
   `address(uint160(N))` literals; storage-array returns written with the
   emulated memory and a copy loop; `tier=exact` on trivial bodies.
 * A contract without functions or metadata is judged ABI coder v1 and its
   text declares `pragma abicoder v1;`.
 * The module docstring of `scobelix/solgen/storage.py` names enums
   `Enum<i>`; the code names them `Enum<K>` after their member count.

## Verification (`scobelix.verify` and the verification loop)

 * Pending decision: an `EQUIVALENT_REVERTS_ONLY` verdict keeps a rewritten
   form although its accepting paths never ran (confidence `medium`). A
   stricter mode (rewritten forms on `EQUIVALENT` only, or inputs that let
   the original accept calls) would close it.
 * Detection is probabilistic and coverage-guided call selection is
   missing: a reentrancy mutant is caught in about 75 % of seeds at 300
   calls, and `Budget.quick()` misses about 10 % of simple mutants. The
   report keeps one counterexample per function, so a second cause can stay
   hidden.
 * Functions whose accepting paths need state, signatures or multi-word
   answers from other contracts stay `EQUIVALENT_REVERTS_ONLY` (the mocks
   answer one word); routed functions whose dynamic parameters are typed as
   words cannot be fuzzed into their accepting paths.
 * Gas is not modelled beyond comparing the two sides: fixed and full gas
   forwarding are equivalent against the mocks, basefee and gasprice are 0,
   and py-evm-only runs re-check gas at most twice per function.
 * No time is reserved for the final whole-contract run: under the default
   300 s, the search on a large contract can leave less than one run, which
   is then cut, and the entry points it did not finish are written in exact
   form.
 * `passed` is true when L3 is skipped (no EVM backend); the generator's
   `passed` ignores L4 while `scobelix.verify`'s own report counts every
   level.
 * L0 compiles the candidate with the optimizer at 200 runs (and retries
   via-IR) whatever the original's settings: `L0=pass` does not mean the
   text compiles with the original's settings.
 * A slot discovered below the root (a mapping entry under an unseeded key,
   a nested array) gets an untyped word; pyrevm-only runs see slots read on
   reverting paths only through constant slots.
 * Counterexample records are bounded (1024 bytes of calldata, 64 storage
   slots): a long calldata or a large pre-state cannot be replayed from the
   record.
 * Children of `CREATE` are not fuzzed; post-Cancun opcodes (`CLZ`) cannot
   run on the pinned pyrevm 0.3.7 / py-evm 0.12.

## Signature database and names

 * A function the sources know only as an event or an error stays unnamed
   at entry points (lookups are strictly namespaced), for example
   `Transfer(address,uint256)` at `0x69ca02dd`.
 * Invalid JSON in `local_sigs.json` or `extra_sigs.json`, an
   `extra_sigs.json` without `abi`, or a damaged dump makes the whole
   database unavailable, not only that source; two valid dump entries with
   the same key and namespace fail the build with a misleading
   `no writable location` warning.
 * `Building the signature database ... (once)...` is logged before the
   location is checked, also when it is then refused.
 * Superseded `sigdb-*.sqlite` files, their lock files and the old
   `abi_db.shelve` cache are never deleted.
 * The text printer names a tiny constant compared with the calldata
   selector after a vanity signature, names a 4-byte head >= 2^24 of a data
   blob even inside `abi.encodePacked`, and looks the legacy head form
   `mask_shl(32, 224, 0, K)` up without the 2^24 threshold.
 * The log printer pairs event parameters data first, ignoring the
   `indexed` flags; `internalType` is not stored, so struct, enum and
   contract type names are unavailable.
 * An unresolved topic0 is shown as the first 8 digits of its hexadecimal
   writing without leading zeros (`0x00ab...` becomes `0xab000000`).
 * A resolved name containing `unknown` also receives inferred parameters.
 * The regeneration tool writes `{}` over the bundled `local_sigs.json` when
   none of its roots exists and `SCOBELIX_SIGS_OUT` is unset; entries it
   writes with abbreviated types (`uint`) are rejected when the database is
   built.

## Outputs and command line

 * The text printer shows no line for a `log0`, and prints a log whose topics
   are all constants as one `log <topic>: <data>` line per topic (the JSON
   trace and the generated Solidity keep every log as it is).
 * fix JSON serialization: `scobelix 0x4ada9ae7e255449f333c59740cc44f8e9ca7ff1f --function contract_sha256`
   (address mode; not re-checked since the engine changes).
 * Constants and getters whose simplification stopped at its time limit get
   no comment line in the text, only the JSON key `time_limited`.
 * The JSON `trace` is the display trace (readability heuristics); the
   exact trace is only available from Python
   (`Decompilation.functions[key].orig_trace`).
 * An inherited rule shows multiples of 86 400 as `<hours> * 24 * 3600`,
   24 times the real value (the JSON keeps the exact value).
 * The generation options are parsed but silently ignored without
   `--solidity`.
 * With `--solidity` alone, only the verification's warnings reach stderr:
   the generator's other warnings (a requested target too old for the text,
   guarded functions, untranslated code) are only in `--combined-json`
   (`solgen_warnings`) and the Python API.
 * `python -m scobelix --help` prints `usage: __main__.py` (the argument
   parser has no program name).
 * The command line can only allow a solc download, never refuse one that
   `SCOBELIX_ALLOW_SOLC_DOWNLOAD` allows; the missing-compiler message names
   `allow_download=True` and `SCOBELIX_ALLOW_SOLC_DOWNLOAD`, not
   `--allow-solc-download`.
 * Under `--time-budget`, what follows the functions (their
   characterization, the storage layout, the AST and the text) has no time
   limit of its own and can outlive its reserve (10 % of the budget, at
   least 5 s, plus half the time of every function kept less simplified):
   the output came 27 s past a 60 s budget on a 24 KB contract whose
   functions, once done, take 32 s to write out. A first build of the
   signature database is not interrupted either, and a step of the
   symbolic execution or a simplification pass that does not check the
   time is only stopped by the alarm of its function, which then fails.
 * Residues: `-v` accepts the logging library's names `BASIC_FORMAT` (then
   runs at INFO) and `_STYLES` (then fails with exit status 1), which are not
   levels; `--repr` and `--returns` are unreachable; `requests` is declared
   but unused; asserts run at load time.

## Packaging, CI and tests

 * `setuptools<81` (web3 6.0.0-beta.8 needs `pkg_resources`) is not
   declared, and `poetry.lock` has not been re-locked since the `verify`
   extra was added. The dev group pins `pytest ^7`; the suite also passes
   with pytest 9.
 * The version-bump workflow's bot exclusion is inoperative, and the master
   branch has no workflows.
 * The legacy `Jenkinsfile` and `decompile_link.sh` only check that the
   output is not empty; the test suite replaces them.
 * The default test run passes on CPython 3.9.21 (pytest 7.4); the slow
   tests have not been run on 3.9 outside the CI.
 * The default test run is CPU-bound: about 2.5 minutes, close to 3 on a
   loaded machine. The other builds of the fixtures, the longest
   differential runs and some probe builds already run with `-m slow`
   (`tests/solgen/conftest.py`); further growth needs the same treatment.

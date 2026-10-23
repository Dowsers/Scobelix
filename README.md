Scobelix
========

This is an EVM decompiler. It turns runtime bytecode (given directly, or
fetched from a node by contract address) into readable pseudo-code, a
structured JSON AST, and, on request, a Solidity reconstruction that keeps
the behaviour of the bytecode and can be compiled and checked against it.

It's a fork of the Panoramix original repo that's not maintained actively by
its author anymore: https://github.com/eveem-org/panoramix.git, by way of
its author palkeo's own continuation at https://github.com/palkeo/panoramix.

The goal of this fork is to maintain Panoramix in a decent shape, fix some crashes, implement missing opcodes...
It also got rid of the "tilde" syntax that was using a custom python encoding, using vanilla Python instead, and became a proper python package that can be imported.
There is also better support for timeouts: instead of stopping entirely, it falls back and prints whatever was decompiled even if it's not complete.

The code quality is still not great and the software is complex, it's mostly reserved for advanced users.

On top of that, this fork adds: a dispatcher analysis that decompiles every
selector as its own function (plus the fallback and receive functions); an
exact trace next to the readable one; reworked opcode semantics, storage-layout
recovery and parameter inference; detection of known upgradeable-proxy
storage slots (EIP-1967/EIP-1822); a local signature database for functions,
events and custom errors; a Solidity generator (`scobelix.solgen`) with an
optional verification by differential execution (`scobelix.verify`); and a
pytest suite with CI.

The exact behaviour is specified, in French, under [docs/](docs/README.md).

## Installation

```console
$ pip install scobelix
$ pip install "scobelix[verify]"   # adds the EVM backends that --verify runs the code on
```

Scobelix needs Python 3.9 or later. Windows is not supported (the
per-function time budget, and the bound `--time-budget` puts on the
Solidity generation, rely on a POSIX alarm signal).

The optional `verify` extra installs the two EVM backends of the
verification: pyrevm 0.3.7 (fast; installed only where it has prebuilt
wheels: Linux x86_64 up to Python 3.12, macOS and Windows with Python 3.10 to
3.12) and py-evm 0.12.1b1 (instrumented; confirms differences and measures
coverage). Either one alone is enough. Without any backend, `--verify` still
runs the other levels, prints the source with every function in its exact
form, unverified, and says why on stderr.

### Solidity compilers

solc is never a Python dependency. Generation, `--validate-solidity` and
`--verify` use solc release binaries found, in this order: the `solc*` files
of `$SCOBELIX_SOLC_DIR`; the `solc` directory of Scobelix's user cache
directory (where downloads go); `~/.solcx`; `~/.solc-select/artifacts`;
`~/.svm`; hardhat's compiler caches; then `solc*` files on `PATH` (the
solc-select shim excepted). Every candidate is identified by running it with
`--version`; pre-releases are never used. Any version manager will do, for
example:

```console
$ pip install solc-select
$ solc-select install 0.8.19 0.8.31
```

Scobelix can also download the official release it needs from
`https://binaries.soliditylang.org` (SHA-256 checked against the published
list, installed under `$SCOBELIX_SOLC_DIR` or the user cache), but only when
allowed: `--allow-solc-download` on the command line,
`allow_solc_download=True` / `allow_download=True` from Python, or the
environment variable `SCOBELIX_ALLOW_SOLC_DOWNLOAD=1`. When no fitting
compiler is available, validation is `skipped` and the verification says
so; nothing fails.

## Running

You can specify a web3 provider using the environment variable `WEB3_PROVIDER_URI`. In this case a local provider was set.

```console
$ WEB3_PROVIDER_URI=http://localhost:7545 scobelix 0x0d94D81FD712126E7f320b5B10537D01d6a01563
```

You can also provide the runtime bytecode (hexadecimal, `0x` optional),
read it from stdin with `-`, or give several inputs separated by commas
(one output each). An argument of exactly 42 characters is taken as an
address unless `--bytecode` is passed (a 20-byte runtime code has that
length); what `-` reads from stdin is always a bytecode. Invalid bytecode
ends with `scobelix: error: invalid bytecode: ...` and exit status 2.

```console
$ scobelix 6004600d60003960046000f30011223344
$ scobelix - < tests/fixtures/bytecode/SimpleToken.hex
$ scobelix --bytecode 0x602a60005260206000f3602a60005260206000f3
```

By default this prints the pseudo-code text. The options, one example each
(`runtime.hex` holds a runtime bytecode on one line):

```console
# the structured AST as JSON: functions and their traces, storage layout,
# proxy hints, compiler metadata, dispatcher analysis
$ scobelix --json - < runtime.hex

# a Solidity reconstruction, rewritten into idiomatic Solidity wherever a
# rewriting pass applies (not verified)
$ scobelix --solidity - < runtime.hex

# no rewriting at all: every function in the form closest to the bytecode
$ scobelix --solidity --idiom-level exact - < runtime.hex

# write the source for a given compiler version
$ scobelix --solidity --target-solc 0.8.24 - < runtime.hex

# compile the source and run it against the original bytecode, function by
# function; verification summary on stderr
$ scobelix --solidity --verify - < runtime.hex

# the time the whole verification may take, in seconds (default 300)
$ scobelix --solidity --verify --verify-timeout 600 - < runtime.hex

# let the generation and the verification download the solc release they need
$ scobelix --solidity --verify --allow-solc-download - < runtime.hex

# compile the generated source and print a status line to stderr
$ scobelix --solidity --validate-solidity - < runtime.hex

# everything from one decompilation in one JSON object, on one line
$ scobelix --combined-json --solidity --verify --validate-solidity - < runtime.hex

# only the functions whose displayed name starts with a prefix
$ scobelix --function transfer - < runtime.hex

# bound the whole decompilation of each input to 240 seconds (see below)
$ scobelix --combined-json --solidity --time-budget 240 - < runtime.hex
```

The generation options (`--verify`, `--verify-timeout`, `--target-solc`,
`--allow-solc-download`, `--idiom-level`, `--validate-solidity`) only take
effect together with `--solidity`; without it they are silently ignored.
`--bytecode` and `--time-budget` apply to every format.
`--combined-json` takes precedence over `--solidity`, which takes precedence
over `--json`. Other options: `-v LEVEL` (log level, INFO by default),
`--profile` (writes `scobelix.prof` in the current directory), `--verbose`
and `--explain` (diagnostics; `--explain` writes intermediate steps to
stdout, so it breaks the JSON outputs).

### Time budget

`--time-budget SECONDS`, or the environment variable `SCOBELIX_TIME_BUDGET`
when the option is not given (read at every invocation), is the time the
decompilation of each input may take as a whole, the Solidity generation
and validation included. It must be a positive, finite number of seconds
(`2.5` or `1e3` will do); `0`, `-1`, `inf`, `nan` or `soon` end with a
usage error and exit status 2, and an empty variable means no budget. A
budget over 1e9 seconds (about 31 years) is accepted and amounts to no
limit. Every input of a comma-separated list gets the whole budget,
counted once the input is read (and, in address mode, fetched). Without a
budget nothing changes.

Under a budget:

- 10 % of it, at least 5 seconds, is kept for what follows the functions
  (storage layout, AST, text), which has no time limit of its own; every
  function kept less simplified (`time_limited`, below) adds half the time
  it took to that reserve, as what follows takes longer on its larger
  trace. The discovery and every function get the smaller of their own
  limits (the `PANORAMIX_*` variables) and what is left before that
  reserve; the symbolic execution of a function gets the share of the
  function's time it has without a budget (600 of 720 seconds by
  default), so that it ends before the function is cut short; a function
  whose simplification is cut short stays exact, flagged `time_limited`.
- A function reached with less than a second left is not decompiled, nor
  are the following ones: they are listed with the failures (`problems`,
  "I failed with these"), and the Solidity generator writes them as stubs
  that revert. A budget of 6 seconds or less leaves no time to any
  function.
- With `--solidity`, the generation gets what is left less 2 seconds for
  the output: it is skipped when that is under 2 seconds and interrupted
  when it runs longer. With `--verify`, its loop gets that time less the
  larger of a quarter of it and 2 seconds, or its own limit
  (`--verify-timeout`, 300 seconds by default) when that is shorter: the
  loop stops by itself before the generation is interrupted, and writes
  the functions it did not accept in exact form. With
  `--validate-solidity`, the solc runs share what is left then, each
  taking 30 seconds at most: the `--via-ir` retry after a "Stack too deep"
  only gets what the first run left, and is not made when nothing is; the
  validation is `skipped` when nothing is left before it.

The output is partial, never absent (except with `--solidity` alone, see
below), but it is printed only once the input is done. The budget does
not cover the process start, reading the input or fetching the code; a
first build of the signature database counts against it but is not
interrupted (build it ahead of time, see below); and what follows the
functions can outlive its reserve, the more so as the contract is large
and its functions are kept less simplified. Measured one run at a time on
a 16-core machine running other work, with the signature database built,
on contracts of 22 to 24 KB of code: under a 240-second budget, the output
came from 22 seconds before to 4 seconds after the end of the budget;
under 120 seconds, from 10 seconds before to 21 seconds after it (the
latter when a function is kept less simplified just before its alarm);
under 60 seconds, 27 seconds after it (what follows the functions of
Uniswap v4's PoolManager took 32 seconds). In these runs, the budget
plus the larger of 10 % and 30 seconds was always enough. A caller that
kills the process on a timeout must therefore allow such a margin; if
the process is killed earlier, nothing is printed. Only `--combined-json`
reports the budget (`time_budget`, below) and keeps the text and the AST
when the generation is skipped or interrupted: with `--solidity` alone
the command then fails with exit status 1 and prints nothing.

## Solidity reconstruction (`scobelix.solgen`)

`--solidity` writes one Solidity 0.8 contract, `Decompiled`, whose header
comment gives the original and target compilers, the idiom level, the
number of named and routed entry points, the verification status and a
legend of the per-function `@custom:scobelix` tags.

What it does:

- Every entry point found by the dispatcher analysis becomes a function: an
  external function with its name and types when the signature database has
  a usable candidate (its keccak-256 hash is the selector); otherwise a *routed*
  private function `_fn_<selector>` that the fallback calls after testing
  `msg.sig`, so the same calldata produce the same behaviour. The fallback
  and receive functions follow the original.
- Every construct keeps its exact EVM meaning (wrapping arithmetic in
  `unchecked` blocks, inline-assembly helpers where Solidity differs,
  emulated memory, storage by slot), except where a rewriting pass
  established that a usual Solidity form behaves the same. Each function is
  at a *tier*: `exact` (no rewriting), `idiomatic` (rewritten) or `partial`
  (rewritten without some passes). A function whose code carries a risk flag
  (decompiler failure, untranslated construct, reported engine limit) stays
  exact.
- Nothing is dropped silently: a construct the engine did not model becomes
  `revert("scobelix: unsupported construct");` with a comment and the flag
  `unstructured`; a function the decompiler failed on becomes a stub that
  reverts; warnings list what the reader must not miss.
- Each function gets a confidence: `high` only when the verification
  observed it `EQUIVALENT` (and it carries no risk flag), `medium` when it
  is not verified (exact or rewritten), `low` when a difference was found or
  code was not translated, `none` when the decompiler failed on it.

What it does not guarantee:

- Without `--verify` nothing is verified: every function has the verdict
  `unverified` and a confidence of `medium` at most.
- The verification observes the behaviour on the calls it tries; it does
  not prove equivalence. `EQUIVALENT_REVERTS_ONLY` only covers the rejecting
  paths (the original rejected every call tried).
- A function written in exact form can still be `DIVERGENT` when the loss is
  in the decompilation itself (for example a loop the engine did not
  finish); no rewriting can repair that.
- What the bytecode does not hold is not recovered: names of internal
  variables, `nonpayable` versus `view` intent (only trusted signature
  entries restore it), a struct versus separate variables, `bytes` versus
  `string`, state variables the runtime code never touches.
- Some exactness limits tied to memory and gas remain (for example the gas
  cost of reads far into memory).
- `--validate-solidity` attests that the source compiles, nothing more.
- The pseudo-code text and the `trace` key of `--json` are an
  interpretation: readability heuristics apply to them. The Solidity
  generator reads the exact trace instead.

### Verification levels

`--verify` (or `generate_solidity(..., verify=True)`) compiles the source and
runs it against the original bytecode. For every function it keeps the most
idiomatic form whose run was accepted, backing off the rewriting passes that
broke compilation (L0), the storage layout (L2) or the behaviour (L3);
the other functions are written in exact form.

| Level | Checks |
|---|---|
| L0 | the source compiles |
| L1 | same external interface: selectors, payability, events, errors |
| L2 | every declared state variable is at the slot it was inferred at |
| L3 | same behaviour observed by differential execution on generated calls (needs an EVM backend) |
| L4 | the compiled bytecode equals the original, metadata and immutables apart (sought when the original is at most 4096 bytes; a bonus, its absence is not a failure) |

Per-function verdicts: `EQUIVALENT`, `EQUIVALENT_REVERTS_ONLY`, `DIVERGENT`
(with a counterexample call in the function's `@dev` lines), `MISSING`,
`EXTRA`, `ROUTED`, `INCONCLUSIVE` (a difference the environment can explain,
reason `env:`) and `SKIPPED`. The default budget is 300 seconds and 20 runs
for the whole loop; when it runs out, the functions not accepted yet are
written in exact form.

### Combined JSON

`--combined-json` prints one JSON object on one line: `text` and `json`
always; with `--solidity`, `solidity`, `solgen_confidence`,
`solgen_warnings` and `solgen_functions` (per function: `name`,
`signature`, `selector`, `kind`, `routed`, `payable`, `mutability`, `tier`,
`verdict`, `passes`, `disabled_passes`, `flags`, `guards`, `calls`,
`coverage`, `folded`, `abi`, `arith`, `loops`, `naming`, `modifiers`,
`confidence`, plus `counterexample` and `reason` when there are some); with
`--verify`, `solgen_verification` (the report: `passed`, `levels`,
`summary`, `functions`, `sequences`, `original`, `candidate`, `backend`,
`warnings`, `elapsed`, `search`); with `--validate-solidity`,
`solgen_validation` (`status`, `errors`, `warnings`).

When the generation fails (an exception, or the time budget skipping or
interrupting it), the text and the AST are still printed, and so are the
keys above, empty: `solidity` is `""`, `solgen_confidence` and
`solgen_functions` are `{}`, and `solgen_warnings` holds the message, as do
the `warnings` of `solgen_verification` and of `solgen_validation` (then
`skipped`) when they are requested. The next key, `solgen_error`, repeats
the message: `<ExceptionType>: <message>`, `time budget exhausted before
the Solidity generation` or `Solidity generation interrupted by the time
budget`. An exception of the validation alone keeps the source and sets
`solgen_validation` to `skipped` and `solgen_error`. The traceback goes to
the log (stderr), and the exit status stays 0. A validation the time budget
left no time for is only `skipped`, with the warning `time budget exhausted
before the Solidity validation`.

Under a time budget, the last key is `time_budget`, for example:

```json
{"seconds": 240.0, "exhausted": true, "skipped": ["0x23b872dd", "_fallback"]}
```

`exhausted` tells whether the budget ran out before the end of the work
or cut a step of it short: functions left out or interrupted by the time
left to them (then failures), or whose simplification stopped at the time
left to them; the generation skipped or interrupted; the verification
loop stopped at the time left to it; a solc run of the validation cut
short by the time left, or the validation skipped. `skipped` lists the
functions it left out, which are also in `problems`. There is no
`time_budget` key without a budget.

The integers of `json` are written in full: the code copied by a
`CODECOPY` of constant size (up to 64 KiB) becomes one integer, of more
than 4,300 decimal digits from about 1,786 bytes on. Python 3.11 and
later, like the security releases of earlier versions, refuse to parse
integers that long by default: call `sys.set_int_max_str_digits(0)` before
`json.loads`, or keep them as strings with a `parse_int`:

```python
payload = json.loads(out, parse_int=lambda s: int(s) if len(s) <= 4300 else s)
```

### From Python

```python
from scobelix.decompiler import decompile_bytecode
from scobelix.solgen import generate_solidity, validate

decompilation = decompile_bytecode(runtime_hex)
decompilation.text                    # the pseudo-code
decompilation.json                    # the AST

decompilation = decompile_bytecode(runtime_hex, time_budget=240)  # seconds
decompilation.time_budget             # None without one; .seconds, .exhausted, .skipped

result = generate_solidity(decompilation, verify=True, budget={"time_limit": 600})
result.solidity                       # the source
result.confidence                     # {"0xa9059cbb": "high", "_fallback": "medium", ...}
result.functions_json()               # the per-function table
result.verification_json()            # the report (None when it could not run)
validate(result).status               # "valid", "invalid" or "skipped"
```

`time_budget` bounds the decompilation only (`SCOBELIX_TIME_BUDGET` is not
read from Python); `generate_solidity` has no global budget, its `budget`
only limits the verification loop.

`scobelix.verify.verify(original_runtime, source, contract_name=...)`
compares any Solidity source with a runtime bytecode on the same levels.

## Signature database

Function, event and error names come from a local, read-only SQLite
database built from four sources shipped in the package: an internal table
of common selectors, `scobelix/data/extra_sigs.json` (curated ABIs),
`scobelix/data/abi_dump.xz` (a large signature dump) and
`scobelix/data/local_sigs.json`. Every entry is checked against its
keccak-256 hash; nothing is looked up online.

- **Where**: in the user cache directory (`~/.cache/scobelix/` on Linux, or
  `$XDG_CACHE_HOME/scobelix/`), as `sigdb-2-<16 hex digits>.sqlite`, about
  117 MiB. The name depends on the data, so new data selects a new file;
  superseded files are not deleted.
- **When**: built once, by the first lookup of the first process that needs
  it (25 to 100 seconds), into a temporary file renamed atomically under a
  lock; other processes wait, then read it.
- **Elsewhere**: `SCOBELIX_SIGDB=/path/to/sigdb.sqlite` uses (or builds)
  that file instead; a file there that is not a signature database is never
  replaced. When the cache directory is unusable, a private
  `scobelix-<uid>` directory of the system temporary directory is used.
- **Unavailable**: decompilation goes on without names, with a warning.
- **Ahead of time** (for example before running under a time limit):

  ```console
  $ python -c "from scobelix.utils import sigdb; print(sigdb.ensure_built(sigdb.default_path()))"
  ```

- **Regenerating `local_sigs.json`** from your own ABI files:

  ```console
  $ SCOBELIX_ABI_ROOTS=/path/to/abis:/other/abis SCOBELIX_SIGS_OUT=/tmp/local_sigs.json python -m scobelix.tools.build_local_sigs
  ```

  Without `SCOBELIX_SIGS_OUT` the tool overwrites the bundled
  `scobelix/data/local_sigs.json`, which needs write access to the
  installation.

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `PANORAMIX_FUNCTION_TIMEOUT` | 720 | time budget of one function's decompilation, in seconds |
| `PANORAMIX_VM_RUN_TIMEOUT` | 600 | time budget of one function's symbolic execution |
| `PANORAMIX_WHILES_TIMEOUT` | 600 | time limit of one function's simplification (which also stops at 75 % of the function budget; the function is then exact but not fully simplified, flagged `time_limited`) |
| `PANORAMIX_LOADER_TIMEOUT` | 120 | time budget of the function discovery |
| `PANORAMIX_MAX_NODE_COUNT` | 500000 | maximum number of exploration nodes per symbolic execution |
| `SCOBELIX_TIME_BUDGET` | none | time budget of the whole decompilation of each input, in seconds, when `--time-budget` is not given; read at every invocation; a positive, finite number (anything else is a usage error, exit status 2; empty: no budget); see "Time budget" for what it bounds and the margin a caller must allow |
| `SCOBELIX_SIGDB` | user cache directory | signature database file |
| `SCOBELIX_SOLC_DIR` | none | solc directory searched first, and where downloads go |
| `SCOBELIX_ALLOW_SOLC_DOWNLOAD` | refused | `1`, `true`, `yes` or `on` allows downloading a missing solc release |
| `SCOBELIX_ABI_ROOTS`, `SCOBELIX_SIGS_OUT` | none, bundled file | input directories and output file of the regeneration tool |
| `WEB3_PROVIDER_URI` | web3's automatic provider | the node queried in address mode |

Under a time budget, the `PANORAMIX_*_TIMEOUT` limits are capped by what is
left of it, and a value of 0 for the function, symbolic execution or
discovery limit means "what is left" (three quarters of the function's
time for the symbolic execution) instead of "no limit".

## Testing

```console
$ pip install "setuptools<81"        # web3 6.0.0-beta.8 still needs pkg_resources
$ pip install -e ".[verify]"
$ pip install pytest solc-select
$ solc-select install 0.8.19 0.8.31 0.7.6 0.6.12 0.5.17 0.4.26
$ python -m pytest tests/             # default run: long tests excluded
$ python -m pytest tests/ -m slow     # the long-running tests (marked `slow`)
```

A test that compiles with a solc version that is not installed skips
itself, and the tests that execute bytecode skip themselves without an EVM
backend. Building the signature database once beforehand (see above) keeps
that cost out of the first test that needs names.

The fixtures under `tests/fixtures/` are runtime bytecodes
(`bytecode/*.hex`) compiled from the Solidity sources of `sources/` with
the exact compiler, optimizer, IR-pipeline and EVM settings recorded in
`fixtures.json`; `python tests/fixtures/build_fixtures.py` rebuilds them
byte for byte, and `--check` only compares. The solgen and verify tests
compile the generated Solidity and run it against these originals.

## Caveats

Windows is not supported currently.

The pseudo-code is an interpretation of the bytecode, not verified source
code. The Solidity reconstruction keeps the bytecode's behaviour by
construction, within the limits it flags; only `--verify` observes that
behaviour, and only on the calls it tries. Treat every output as a strong
starting point for manual review.

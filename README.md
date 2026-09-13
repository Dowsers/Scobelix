Scobelix
========

This is an EVM decompiler. It turns raw bytecode (or an on-chain address)
into readable pseudo-code, a structured JSON AST, or a best-effort Solidity
reconstruction.

It's a fork of the Panoramix original repo that's not maintained actively by
its author anymore: https://github.com/eveem-org/panoramix.git, by way of
its author palkeo's own continuation at https://github.com/palkeo/panoramix.

The goal of this fork is to maintain Panoramix in a decent shape, fix some crashes, implement missing opcodes...
I also got rid of the "tilde" syntax that was using a custom python encoding and use vanilla Python instead. And I made it a proper python package that can be imported.
There is also a better support of timeouts, as instead of stopping entirely we will fallback and print whatever we decompiled even if it's not complete.

The code quality is still not great and the software is complex, it's mostly reserved for advanced users.

On top of that, this fork adds: resilient storage-layout recovery (one
unresolvable slot no longer blanks out every other slot's name/type),
detection of known upgradeable-proxy storage slots (EIP-1967/EIP-1822), a
portable local-signature builder, and a Solidity code generator (`solgen`,
see below) - plus a real pytest suite and CI, replacing the previous
single-hardcoded-contract smoke test.

## Installation

```console
$ pip install scobelix
```

## Running

You can specify a web3 provider using the environment variable `WEB3_PROVIDER_URI`. In this case a local provider was set.

```console
$ WEB3_PROVIDER_URI=http://localhost:7545 scobelix 0x0d94D81FD712126E7f320b5B10537D01d6a01563
```

You can also provide the bytecode for decompilation.

```console
$ scobelix 6004600d60003960046000f30011223344
```

By default this prints Panoramix's pseudo-code text. Two other output
formats are available:

```console
# the decompiled contract's structured AST (storage layout, per-function
# trace, resolved signatures, detected proxy slots) as JSON
$ scobelix --json 6004600d60003960046000f30011223344

# a best-effort Solidity reconstruction (see "Solidity reconstruction" below)
$ scobelix --solidity 6004600d60003960046000f30011223344

# same, and also compile the result with solc to confirm it's valid
# (skipped automatically if solc isn't installed - it's not a dependency)
$ scobelix --solidity --validate-solidity 6004600d60003960046000f30011223344
```

## Solidity reconstruction (`scobelix.solgen`)

`--solidity` runs the decompiled AST through `scobelix/solgen/`, a
structured emitter that produces a single
`fallback(bytes calldata) external payable returns (bytes memory)`
containing the whole reconstructed contract (Panoramix, for real contracts,
reconstructs one big selector-dispatch function rather than one function per
ABI method - splitting that back apart reliably isn't attempted).

This is a decompiler, not a recompiler: it cannot guarantee the output is
semantically identical to the original source. Every construct it can't
reconstruct with confidence (external calls, unresolved storage shapes,
unrecognized events, unknown opcodes) is emitted with an inline
`// approximation: ...` comment rather than silently guessed at, and a
function that failed to decompile at all still gets an explicit reverting
stub instead of disappearing. A handful of well-known events (Transfer,
Approval, OwnershipTransferred, Upgraded, Paused, ...) are resolved to real
`emit EventName(...)` statements; anything else falls back to a generic,
clearly-labelled placeholder event.

Use `--validate-solidity` (or `scobelix.solgen.validate.validate_solidity()`
from Python) to confirm the generated source actually compiles - solc is an
optional dependency, only needed for that check.

## Testing

```console
$ pip install -e .
$ pip install pytest solc-select   # solc-select only needed for the
$ solc-select install 0.8.19       # solc-based validation tests
$ solc-select use 0.8.19
$ pytest tests/
```

The fixtures under `tests/fixtures/` are real contracts (simple token, an
EIP-1967 proxy, nested structs/mappings, heavy inline assembly, multi-file
inheritance, events, an EIP-2535-style Diamond dispatcher, a loop) compiled
with solc; the CI-gating tests assert that solgen's *generated* Solidity for
each of them actually compiles, not just that it looks plausible.

## Caveats

Windows is not supported currently.

Decompilation - and even more so the `--solidity` reconstruction - is
inherently approximate. Treat the output as a strong starting point for
manual review, not as verified source code.

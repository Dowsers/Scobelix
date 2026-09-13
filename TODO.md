 * log ABI: solgen now resolves a handful of well-known events (Transfer,
   Approval, OwnershipTransferred, Upgraded, Paused, ...) to real
   `emit EventName(...)` statements - arbitrary/custom events, and events
   with more than one non-indexed data field or an array-typed param, still
   fall back to a generic placeholder rather than being decoded.
 * fix JSON serialization: scobelix 0x4ada9ae7e255449f333c59740cc44f8e9ca7ff1f --function contract_sha256
 * loop decompilation only tracks a loop's own counter variable; a second,
   independently-varying accumulator in the same loop (e.g. `total += i`
   alongside `for (i=0; i<n; i++)`) is not recognized as a loop variable -
   see the comment above `VM.replace_loops()` in vm.py for what's been
   root-caused so far.

# Linux 5.15 verifier-budget compatibility plan

## Goal

Restore the published Linux 5.15 support floor for the ordinary mixed-ABI
entry program and the diagnostic ia32 entry program without changing capture,
privacy, owner accounting, or retry semantics.

## Established failure

The exact embedded executable sections that load on Linux 7.0 reach the Linux
5.15 verifier limit of 1,000,000 processed instructions.  The default witness
ends in the task-owner reservation retry path and the diagnostic ia32 witness
ends in the refund retry path.  `p11_owner_start_insert` is a local 892
instruction function, while its eight-attempt reserve and refund loops are
inlined into that caller.

## Approved first experiment

1. Export two separate, non-inlined BPF global functions with no arguments and
   scalar return values: one reservation boundary and one refund boundary.
2. Each function obtains `OWNER_CTL[0]` internally.  No map-value pointer may
   cross the global-function ABI.
3. Preserve all eight CAS attempts, fresh volatile reads, exact comparisons,
   normal and small limits, poisoning and counter behavior.
4. Preserve existing caller health checks.  Refund must remain callable after
   poisoning so cleanup can settle debt without clearing the poison bit.
5. Keep the pointer-taking owner transactions local/static.  Export only the
   two new scalar helpers and extend the exact ELF/BTF/call/relocation contract
   accordingly.
6. Keep all maps, records, attachment order, admission policy and privacy
   behavior unchanged.

If Linux 5.15 still rejects the programs, retain the new verifier frontier and
review a bounded global boundary around the complete owner transaction.  Tail
call partitioning is a last resort because it adds continuation ownership and
failure-state obligations.

## TDD and structural gates

1. Add a RED embedded-object contract for the two absent global boundaries.
2. Add RED actual-C owner tests for CAS success on attempt eight, exhaustion
   after eight attempts, cap refusal, zero-debt refund refusal, and poisoned
   cleanup settlement under normal and small limits.
3. Implement the two helpers and route every existing reserve/refund call
   through them without changing transaction ordering.
4. Require exact GLOBAL DEFAULT `.text` definitions, GLOBAL BTF `FUNC`
   records, no-argument scalar prototypes, BTF.ext records, reachable call
   edges, and `OWNER_CTL` relocation.  Mutation controls must reject static or
   extern linkage, pointer signatures, missing bodies/calls/relocations and
   extra exported owner helpers.
5. Preserve the existing private contract for pointer-taking owner functions,
   expected map/program inventories, source linkage, and privacy allowlist.
6. Run the focused native owner, map-definition, embedded-object and artifact
   tests, then the Rust 1.88 formatting/check/test/Clippy gates.

## Runtime acceptance

For the exact final artifact on Linux 5.15, 6.8 and 7.0:

- load every production and diagnostic executable program and retain verifier
  statistics plus kernel, toolchain and object identities;
- verify the two helpers are independently accepted and that call depth/stack
  limits remain valid;
- run default native64 and ia32 positives;
- run diagnostic native64 and ia32 matches and deliberate opposite-width
  refusals, treating any program-load failure as NONPASS;
- repeat affected canary, owner exhaustion/fault, fork/exec/nonleader-exec,
  exit, root-affiliation, unload and reload gates.

The first decisive runtime check is the unchanged ABI-routing driver on the
retained Ubuntu Jammy 5.15 guest.  A successful local build alone does not
qualify the compatibility fix.

# Jammy interface-list verifier partition

Status: implementation plan. This narrowly supersedes the no-tail-call and
frozen object-inventory assumptions for live interface-list discovery in the
2026-08-18 corrective design and 2026-08-19 production plan.

## Why this exists

The exact production program loads on Linux 6.8 but `interface_list_return`
reaches 1,000,001 processed instructions on Linux 5.15. Source-level call
splitting, a pre-loop address proof, and source-specific emitters all retained
that verdict. Linux 5.15 remains the published floor, so the remaining bounded
16-interface loop needs a verifier boundary.

## Minimum design

- Add one always-present two-slot `TAIL_CALLS` program array.
- Slot 0 always contains a new unattached `interface_list_worker` uretprobe.
- Slot 1 contains `p11_entry_template_second` only when unsafe metadata capture
  is enabled; otherwise exact readback must prove it empty.
- Populate, read back, and freeze the array after all programs load and before
  any producer attaches.
- Keep `DISCOVERY_STATE`; add no state map, public counter, record field, schema
  version, dependency, flag, or sizing knob.
- Keep all existing privacy rules and the 16-interface/104-pointer bounds.

`interface_list_return` copies the entry state, validates the return value,
count, null/zero cases, and final interface address, then replaces the map value
with a continuation and tail-calls slot 0. The continuation stores the
saturated `u32` announced count in bits 8..39 and the interface index in bits
0..7; bits 40..63 must be zero.

The worker copies and validates the continuation, emits exactly one interface,
advances the index even after a per-interface read or ring-reservation failure,
then updates and self-tail-calls or removes the terminal state. Scope loss
removes silently. Missing/invalid state, failed transition/update, tail-call
fallthrough, and failed terminal cleanup perform one best-effort removal and
increment `discovery_state_failures` at most once for that transition.

## TDD sequence

1. Add a focused RED test for continuation packing and the new worker boundary.
2. Implement packing plus the return/worker state machine.
3. Add a focused RED loader contract for exact slot publication, readback, and
   freeze-before-attach ordering; implement it.
4. Update existing exact map/program and live-object oracles without weakening
   initializer, counter, pause, privacy, or unsafe-decoder checks.
5. Build and check all four object variants, then run the canonical workspace
   fmt/check/test/clippy gates.
6. Run one fresh five-program Jammy 5.15 load discriminator. Stop if either the
   return program or worker reaches the verifier limit.
7. Run the identical object on Noble 6.8, then the existing live semantic lanes
   for counts 0, 1, 16, and greater than 16; 104-slot tables; name suppression;
   loss accounting; pause behavior; and cleanup.

## Acceptance and rollback

Accept only if both kernels load the exact candidate, tail-call cookie identity
is preserved, continuations cannot survive terminal paths, all current semantic
lanes pass, and the privacy/schema output is unchanged. Roll back rather than
raising the kernel floor, lowering 16/104, adding public state, or weakening a
checker to make the candidate pass.

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T8 strict-profile workload preparation (lane D)

Preparation only. This recipe pins the exact strict SYSTEM repeat the T8/G18
acceptance needs; it adds no new workload binary and changes no runner. The
strict repeat reuses the unchanged workload, driver cell, and oracle below.
The last strict result stands FAIL, confined to whole-system
observation-exactness (H7-entry gate agreement, 2026-10-14: six physical
fixture targets at 500 calls each, proven drain and owned cleanup held; the
system-cell strict verdict did not pass). Do not relabel a development-gate
pass as strict acceptance.

## Unchanged components (reuse exactly)

- Workload: `tests/fixtures/public-cli/gated.c`, the ledgered six-function
  SoftHSM2 client (`TARGET`/`READY`/`LEDGER` protocol).
- Driver cell: the `system` cell of `scripts/qualify-public-cli.sh`
  (`gated system system ... profile --system --module "$MODULE"
  --duration 25 -o system.json`).
- Oracle: `scripts/public-cli-oracle.py` (strict verdict, unchanged).

## Pinned shape: six separate 500-call functions, 25-second profile

| Function | Table ordinal | Attempts | Successful |
| --- | --- | --- | --- |
| C_GenerateRandom | 64 | 500 | 500 |
| C_DigestInit | 37 | 500 | 500 |
| C_Digest | 38 | 500 | 500 |
| C_FindObjectsInit | 26 | 500 | 500 |
| C_FindObjects | 27 | 500 | 500 |
| C_FindObjectsFinal | 28 | 500 | 500 |

Exact invocation parameters: `ITERS=500`, profile `--duration 25`,
`MODULE` as a private staged copy of the provider library (same bytes as
the system library, distinct inode, hash-verified before launch), owned
`RUNUID`/`RUNGID`, fresh outdir under `/var/tmp/p11scope-ws-tmp`, explicit
`TMPDIR`, preflight with no stale observer/driver/fixture processes.

## Acceptance predicates (strict repeat)

- Every controlled function: ledger attempts and successful exactly 500;
  each of the six `TARGET` records joins the final JSON by mapped
  device/inode/file offset to exactly one physical target with exactly 500
  calls, zero errors, zero in-flight.
- Unchanged physical-copy distinction holds (ambient users of the system
  library cannot join the pinned provider identity).
- `drain_proven` true with proven quiescence and both post-Q flags false;
  correct final drain.
- No unexplained discovery/event/ring/read/state loss; explicit
  refusals/unknowns only; all loss counters zero.
- Observer reap within [0,60]s after `loop_end_mono_ns` on
  `CLOCK_MONOTONIC`; owned cleanup (children, files, descriptors).
- Diagnose any remaining strict failure; do not repeatedly rerun unchanged
  source.

## Ledger-join procedure (independent check)

Join each `system.wl` TARGET record to the final `system.json` by
`(dev, ino, file_offset)`; confirm exactly one physical target and exactly
500 calls per function with zero errors/in-flight, matching the LEDGER
attempts/successes; confirm receipt provider-before/after equality, ledger
completeness, and both exit codes 0. Names, counts, or totals alone never
substitute for the physical join.

## Registration: none in this prep

This recipe registers nothing: the workload, driver, and oracle already
exist and are owned by their current lanes. The controller schedules the
owned installed exact-candidate repeat on the assembled candidate.

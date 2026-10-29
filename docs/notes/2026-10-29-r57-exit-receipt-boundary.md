<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# R57 exit-receipt boundary (investigation, 2026-10-29)

Packet 6.10-R57, v0.6.0. Investigation BEFORE any repair estimate: test-only
port + this note. No production behavior change; no BPF/wire/privacy/lifetime/
schema change. Base `e357ee3f`; donor `ce9b6f40` (preserved, not in base),
manual port, byte-exact against the donor hunk.

## Verdict: no sufficient receipt exists

No structure in the base tree constitutes a completed-observation / held-objects
/ balanced-transaction receipt that could settle a loader transaction after the
original process exits. The packet therefore delivers the concrete boundary and
the material conflict below, not a repair. The old thread-exit signature
(RT_ADD followed by zero `r_state`) is not universal: it cannot distinguish a
benign provider-free exit from a private sparse-provider exit with the same
metadata surface.

## RED-first evidence (observed, not assumed)

Ported `exit_loader_subject` + `finish_exit_loader_subject` + three
`exit_loader_*` tests into `src/discovery/engine_tests.rs` after the anchor
`rt_add_deferral_fallback_after_target_exit_is_bounded_loss_not_fatal`
(`engine_tests.rs:15076-15093`; port at `:15095-15346`).

Donor C checks reproduced on 2026-10-29: gcc `-std=c11 -Wall -Wextra -Werror`
passes for runner and both libraries; `nm -D --defined-only` shows only
`VendorSurface` in both; `BENIGN calls=0 exit=0`, `PRIVATE calls=3 exit=0`.

Selector results on the unchanged runtime (lib test executable, exactly-one
selection each):

1. `exit_loader_balanced_benign_transaction_needs_no_terminal_truncation` —
   **RED**: `discovery_truncated` is 1, expected 0
   (`engine_tests.rs:15311`). The RED is the final settlement assertion, not
   a fixture error: all fixture asserts (arming, record acceptance,
   controlled exit, metadata surface) pass first.
2. `exit_loader_same_metadata_private_sparse_provider_stays_unknown` —
   GREEN-truncated (`discovery_truncated > 0`): the indistinguishability
   guard holds.
3. `exit_loader_live_balanced_benign_transaction_runs_ordinary_scan` —
   GREEN: pending empty, `loader_memory_scan_attempts == 1`,
   `discovery_truncated == 0`: the ordinary live path is unaffected.

Settlement-path probe (temporary, removed before commit): after the exit the
zero-state record does not resolve directly; the deferred-scan fallback
settles the pending entry via `record_pending_loader_scan_end`
(`engine.rs:15364-15368`) with reason "a deferred loader memory scan was
unresolved at expected process exit" (`truncated=1, attempts=1, pending=0`).

Neighbor regression (same executable, all GREEN, exactly-one selection each):

- `rt_add_deferral_fallback_after_target_exit_is_bounded_loss_not_fatal`
- `a_polling_rescan_of_provider_free_processes_is_not_a_loss`
- `probationary_probe_completes_provider_free_newcomer_at_capacity`

## Receipt trace (base `e357ee3f` seams)

(a) Completed observation. The ONLY provider-free prover is
`probe_newcomer_provider_free` (`engine.rs:21346`): it opens a probationary
view, requires `still_the_same()` plus a **complete** scan with **empty**
modules (`:21369-21374`, "completeness flag is load-bearing"), and is consumed
only by the Lane-A P3 last-resort path for live newcomers (`:21412-21430`).
There is no exited-process equivalent. Precedents elsewhere keep the same rule
shape: an absence seal needs a complete enumeration plus a bracketed attach
cell (`image_query.rs:2401`), and only completed observations survive a
deadline (`inventory_cgroup.rs:1514`). Nothing retains a completed loader
observation across exit.

(b) Held objects / pins. `process_loader_record` validates live pins
(`engine.rs:15485-15497`) and scans return `PinnedObjects`, but pins
authenticate a live mapping; they record no completed transaction. After exit
the zero-state record fails validation and the pending entry falls through to
the counted fallback above.

(c) Balanced transaction. `pending_loader_scans` (`engine.rs:617`) retains
only `{view, context}` plus the earliest hook timestamp. ADD/DELETE defers a
memory scan plus a metadata-only pass (`process_loader_record`, `:15523-15555`);
a zero-state record removes the pending entry **without retaining the pairing**
(`:15557`) and runs a memory scan (`:15558-15569`); every exit-time settlement
is a counted truncation — `record_pending_loader_scan_loss` (`:11896`, live
loss) or `record_pending_loader_scan_end` (`:11906`, partial, GT-4 rationale).
`LoaderRegistry` (`loader.rs:114`; contexts `:165-172`) retains identity,
lifecycle and earliest hit only. `scan_retained_view_without_memory`
(`engine.rs:11671`) acquires no runtime tables, so an object with no standard
exports and empty metadata tables can hide a private sparse table — balance
would not change the missing observation.

Producer side: `dl_debug_state_impl` (`crates/ebpf/src/main.rs:1861`) emits
hook address + context cookie + `r_state` only (`:1920-1928`); `r_state`
starts at 0 (`:1898`) and a failed `bpf_probe_read_user` only bumps
`DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES`, leaving 0 (`:1912-1917`).
Zero encodes consistent-zero OR absent state OR failed read. No transaction
object list, no table inventory.

## Material conflict

The desired R57 positive (balanced benign exit settles clean) and the
indistinguishability guard (same-metadata private exit stays unknown) cannot
both be satisfied by any observer that sees only loader-state balance plus an
export/metadata surface: the two subjects are identical in exactly those
channels (same factory, same single `VendorSurface` export, same empty
metadata tables) and differ only in a runtime table the observer never
acquired. Relaxing exit settlement without a retained completed observation
would bless the private provider's unread table as "empty". Unread/dead/
no-exports is not empty.

## Safe continuation (unchanged from donor)

A terminal shortcut needs a typed, already-retained receipt covering the owed
discovery work for the exact original view and loader context: it must bind a
completed live observation to its object pins and transaction boundary, cover
the consumed records gap-free, and refuse later/uncovered loader work.
"Complete" keeps the existing scan meaning and is never upgraded to universal
provider absence. Obtaining that observation requires separately reviewed
means while the original address space is still available, or another explicit
source of equivalent authority. No BPF, wire, privacy, lifetime, or public
schema change is proposed here.

The old "abi-2 fix sketch" (v050 requirements `:630`) is superseded as a
design for v0.6: balanced benign settlement without a retained completed
observation is exactly what the negative twin forbids. Retained only as
limitation history. 6.14 exit-time work must scope itself to live-custody
evidence plus explicit unknown until a verdict-backed authority exists.

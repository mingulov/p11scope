<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T7 capacity decision: adaptive capacity, sustained identity, bounded history

Finish-plan Task 7 box 1 (+ box 2) decision input for the capacity consensus.
Scope: ordinary evidence only — mechanisms, models and gates verifiable
without privilege. Every live proof this decision still owes is listed with
its owner (controller) and expected verdict.

## Basis

- Worktree `p11scope/.worktrees/production-provider-usage`, branch
  `feat/production-provider-usage`; T7 stack on `b2bff33` (= BASE `ed9730b`
  plus the docs-only T0/T0b ledger commit).
- Design inputs, all present (no INPUT-MISSING):
  - I2c C5 (`p11scope/.superpowers/sdd/SYSTEM-PLAN/task-I2c-production-plan.md`,
    capacity contract + C5 table): candidates A/B/C with proof burdens.
  - Adaptive-capacity review
    (`p11scope/audit-notes/perf/2026-09-22-adaptive-capacity-review.md`):
    independent cardinalities, no live-map copy/swap, acceptance boundary.
  - Sol review (`review-system-scale-sol-max-2026-09-22.md`, "Active links,
    finite history and long-running retention"): finite-history contract,
    A/B/C comparison, no in-place live-map resizing.
  - Supporting: `review-over-2000-endpoints-2026-09-22.md`
    (wide-2112 envelope, 296 B/endpoint/CPU, RV 2-key problem).
- Ordinary evidence: `tests/t7_adaptive_capacity.rs` (29 tests) against
  `src/capacity.rs` mechanisms; compile-verified (not run) privileged
  selectors in `src/attach/inventory/activation/privileged_tests.rs`.
  L-T7-5 carries a preflight gate plus a post-failure FD-exhaustion
  classifier (`t7_boundary_preflight`, `t7_is_envelope_exhaustion`,
  `t7_boundary_cell_gate`): out-of-envelope runs emit `T7_ENVELOPE_REFUSAL`
  as a separate result, never a coverage pass or an ambiguous failure.

## Box 1: A/B/C identity comparison

### Ordinary experiment (same workload, all candidates)

Workload: 16,400 lifetimes at live occupancy ≤ 68 (E10 shape), with
reserve/admit/release cycling, tombstoning, and quota/accounting checks.
A runs fully serial; B holds 8 old-domain lifetimes live across the
rollover while 8 new-domain arrivals overlap them; C holds 8 writers live
across the rotation seal. Overlap-concurrency disclosure: the B alias/link
and C writer-proof costs below are measured over genuine overlap (peak
live 16 and 8 respectively), not asserted by construction — but arrival
churn, contention and delayed settlement under overlap stay live-only
(L-T7-7). Results
(`comparison_same_workload_reports_admission_refusal_aliasing_and_cost`,
`serial_lifetimes_past_16384_at_low_occupancy_refuse_then_continue`):

| Candidate | Admitted | Refused | Peak live | Aliases | Rotations | Max link factor |
|---|---|---|---|---|---|---|
| A, v1 (16,384) | 16,384 | 16 | 1 | 0 | 0 | 1 |
| A, wide v2 (2^40) | 16,400 | 0 | 1 | 0 | 0 | 1 |
| B (rollover at 16,384) | 16,400 | 0 | 16 | 8 | 1 | 2 |
| C (wide identity + 1 rotation) | 16,400 | 0 | 8 | 0 | 1 | 1 |

Refusal at the old limit is exact (quota names identity tickets; every
attempt/admission/refusal counted separately). Past the old limit, A-wide
admits with zero aliases and no second domain; B pays link factor 2 while
16 lifetimes genuinely overlap, plus one cross-domain alias per carried
task (8); C pays one writer-proof over 8 live writers plus a covering ack.

### Kernel-ownership proof comparison (source evidence, not assumption)

- Representation: native `cookie_for`
  (`crates/ebpf/native/image_identity.c:36-117`) already runs the whole
  allocator in u64 (`next_ticket`, ticket, `proposed = ticket + 1`);
  `ImageIdentity.task_cookie`, TASK_COOKIE values and COOKIE_CTL are u64.
  16,384 enters only through an explicit policy comparison
  (`control->limit != IMAGE_IDENTITY_TICKET_LIMIT`, quota check) and the
  loader-published control image (`src/attach/inventory.rs`
  WriteCallerControl) validated by `validate_caller_control`. Widening the
  namespace is a versioned policy/config migration, not a representation
  change. Cookie 0 stays reserved (zero-cell refusal).
- A additionally owes live-admission accounting. The storage side is
  kernel-owned: TASK_COOKIE is `BPF_MAP_TYPE_TASK_STORAGE`, whose entries
  the kernel frees on task exit — no userspace reclamation mechanism is
  needed for the storage itself. What A must still prove live: reservation
  rollback/release accounting against actual storage lifetime (implemented
  ordinarily as `LiveAdmission` + `StorageToken`; live proof = controller
  cell L-T7-7 below).
- B owes strictly more new proof with no existing mechanism: cross-domain
  same-task/exec aliases (forbidden to derive from PID/starttime),
  arrival-during-overlap, delayed-callback settlement across domains, and
  transient double links/programs/readers (measured link factor 2).
- C owes a safe writer/readers handoff for evidence maps with no existing
  mechanism; its proof (seal + exact writer redirection + covering ack) is
  implemented ordinarily as `EvidenceRotation` but unproven live.

### Decision: select A; defer B; hold C as the evidence-rotation protocol

Select **A (stable wider monotonic u64 identity + live-admission
accounting)** as the identity-lifetime design because its kernel-ownership
proof is the smallest actually-evidenced one: representation already u64,
storage lifecycle already kernel-owned, remaining proof confined to
accounting. Implemented ordinarily: `TicketPolicy` (v1 pins C1 16,384;
wider needs an explicit reviewed version), `TicketAllocator` (monotonic,
zero reserved, no reuse, quota/create/retry accounting mirroring native),
`LiveAdmission` (reserve/admit/rollback/token-release), and the pure loader
seam `TicketPolicy::control_image` / `validate_control`.

- The live 16,384 limit is UNCHANGED by T7. Publishing a wider limit needs
  the coordinated native check + loader + common review and the live cells
  below; the seam is ready, the migration is not claimed.
- **B is rejected for now**: it renews map limits but doubles transient
  cost and adds cross-domain aliasing — the largest unproven surface — to
  solve a namespace problem A solves without rollover.
- **C is held, not rejected**: its rotation protocol is implemented
  (`EvidenceRotation`) and is the designated mechanism if evidence maps
  need replacement independent of identity. It is not the identity answer.

## Box 2: endpoint segments + outer directory

### Static pins (ordinary)

- Kernels pinned (both ends of the supported range): 5.15
  (`5.15.221-0515221-generic`, plus Ubuntu `5.15.0-187-generic`) and
  current (`7.2.6-070206-generic`). Live matrix evidence
  (`sg-matrix-90b44ff` r1+r2 in the controller's vng cache) is in
  progress and NOT stable: r1 ran 5.15.221 + 6.1/6.6/6.9/6.12/7.2.6
  green on the stop-gate cells but infra-failed the Ubuntu 5.15.0-187
  pair; r2 has re-run 187 green with a large-only cell still running.
  No live segment verdict is claimed from it here — live pins stay
  pending, owner L-T7-8 (load + verifier logs) / L-T7-9 (cost deltas).
- Map-in-map UAPI + loader refs (verified ordinary):
  - Kernel: `BPF_MAP_TYPE_ARRAY_OF_MAPS` /
    `BPF_MAP_TYPE_HASH_OF_MAPS` (`/usr/include/linux/bpf.h`, beside
    `BPF_MAP_TYPE_PERCPU_ARRAY` / `BPF_MAP_TYPE_PERCPU_HASH`). The
    kernel checks inner compat as kind + key/value shape — implemented
    as `SegmentSpec::compatible_with` (`max_entries` may differ);
    array size stays fixed at creation with per-CPU values per
    possible CPU.
  - Aya 0.14.0 (pinned, `Cargo.lock`):
    `aya::maps::{ArrayOfMaps, HashOfMaps}`
    (`src/maps/of_maps/{array,hash_map}.rs`, re-exported at
    `src/maps/mod.rs:104`). Asymmetric API the live loader must
    honor: an outer update takes the inner map FD, but an outer
    lookup returns the inner map ID (Aya converts ID→FD via
    `map_from_id`).
- Verifier notes (static; logs owed live by L-T7-8): every segmented op
  is two lookups — outer (segment routing) then inner (per-CPU payload)
  — modeled as 1+1 in `SegmentCost`, with static `inner_creations` /
  `outer_publications` counts (one each per appended segment). Lookup
  latency and publication syscall deltas stay live-only under L-T7-9.
  Per-CPU inners must agree on key/value width across segments; value
  bytes scale with possible CPUs (the 6530 payload math below).
- 5.15 high-slot cleanup equivalent: the existing per-map worker-exit
  cleanup (`privileged_task4_highslot_2048_worker_exit`, green in the
  matrix on both 5.15 and current kernels) must be re-proven once per
  inner map — each segment's inner needs its own cleanup sweep, and the
  outer shedding an inner must not strand that inner's in-flight exits.
  Owed live (L-T7-8).
- Cost model (`SegmentDirectory::cost`, tested): +1 outer lookup per op,
  1 outer FD + 1 FD per inner, per-CPU payload = Σ len·value·CPUs, links
  unchanged per endpoint, static allocation/publication counts. For the
  6530 union as 2112+2112+2112+194:
  5 FDs, payload 6,530·296·64 = 123,704,320 B (~118 MiB) at 64 possible
  CPUs, 23,194,560 B (~22 MiB) at 12 CPUs. Segments solve *growth*
  (additive capacity without touching live maps), not bytes: the dense
  byte envelope at 6530/64-CPU must pass live preflight or force the
  already-flagged sparse follow-up (never silent eviction).
- Independent-cardinality bound (adaptive-capacity review, confirmed):
  endpoint segments do NOT grow caller/RV capacity. At 2 RVs/endpoint,
  4,097 endpoints need 8,194 RV keys — already 2 over the wide 8,192 map —
  and 6,530 need 13,060. Any Detailed growth past 4,096 endpoints needs
  paired RV growth (per-segment RV maps or a grown global map); caller
  pairs grow independently likewise. The ordinary side models this with
  `FirstTouchLedger` pair budgets and explicit exhaustion.

### Decision: appended segments with compatible inners as the growth mechanism

Select **appended endpoint segments with compatible inner maps in an outer
directory** as the beyond-2112 growth hypothesis, with the compat rule the
kernel checks (equal kind + key/value shape; `max_entries` may differ),
append-only routing, explicit directory exhaustion, and cross-segment
operation identity. Implemented ordinarily: `SegmentDirectory`,
`SegmentSpec::compatible_with`, `SegmentCost`, and the no-loss
counter-replacement fence (`CounterCell` + `WriterSet`: refused replace
touches nothing; every increment lands in a returned old value or the
cell). Never copy/swap a live counter map without that writer transition.

Live proofs still owed: outer/inner load on 5.15 AND current kernels with
verifier logs, measured extra lookup/allocation/publication/FD/link costs,
and the 5.15 high-slot cleanup equivalent for segmented maps (cells
L-T7-8..L-T7-10).

## Box 3: allocation states (defined before implementation)

`AllocState`: Reserved → Initialized → Published → ProducersEnabled →
Retired/Quarantined → SettlementAcked, plus Initialized/Published →
Quarantined for readback/partial-attach failure. Illegal transitions fail
with state and payload preserved; quarantine only settles. Tested in
`allocation_*`. No failed-ID reuse (allocator-level, tested); no
replacement losing a concurrent increment (writer fence, tested).

## Box 5: bounded retention (RAM/history/disk separated)

`RamBudget`, `HistoryBudget`, `DiskBudget` with independent acquire/release
and peak tracking; full-sink refusal semantics on disk. Reclaiming positive
evidence requires stable record IDs, producer cutoff (never a flush or exit
hint), exact final snapshot inclusion (re-verified at stage), and a
two-phase sink ack (write + readback checksum). Staging always takes the
whole pending set, so omission history cannot strand behind positives
(A-F5). Tested: sink failure, partial write, full sink, crash between
stage and commit (stable-ID replay), replay duplication accounting.
`EnvelopeReport` measures peak/current/retained per dimension separately.

## Controller-owned live cells (T7 handoff)

Preflight (ordinary, already green): `capacity_preflight_budgets_for_t7_live_cells`
pins links/FDs/payloads — Inventory N+2 links, 8N payload bytes
(576→578/4,608; 1024→1,026/8,192; 4097→4,099/32,776; 6530→6,532/52,240;
8192→8,194/65,536). Compare against live `ulimit -n` before running.

| Cell | Selector | Expected verdict |
|---|---|---|
| L-T7-1 | `privileged_t7_inventory_n576_lp64` (default) | Full coverage: 578 links, exact all-ID positives, zero loss |
| L-T7-2 | `privileged_t7_inventory_n1024_lp64` (default) | Full coverage: 1,026 links, exact all-ID positives |
| L-T7-3 | `privileged_t7_inventory_n4097_lp64` (default) | Full coverage: 4,099 links, exact all-ID positives |
| L-T7-4 | `privileged_t7_inventory_n6530_lp64` (default) | Full coverage: 6,532 links, exact all-ID positives |
| L-T7-5 | `privileged_t7_inventory_n8192_boundary_lp64` (default) | Full coverage iff preflight fits; else explicit out-of-envelope refusal naming FDs (separate result, not a coverage pass) |
| L-T7-6 | `privileged_t7_detailed_hot_slot_third_rv_lp64` (both profiles) | Slot 0 RVs {0,5,7} exactly once each; old cells exact; START/owner/kernel/counter debt zero |
| L-T7-7 | NEW (loader+native review first): publish reviewed ticket policy v2 on one owned domain; churn >16,384 serial lifetimes at low occupancy | Arrivals continue past 16,384; live/task-storage accounting matches; quota/create/retry counters exact; zero stays reserved |
| L-T7-8 | NEW: outer/inner segment maps load on 5.15 and current kernels | Load + verifier logs both kernels; routing readback exact; compat refusal on mismatched inner shape |
| L-T7-9 | NEW: segment cost measurement at 6530-shaped layout | Measured lookup/allocation/publication/FD/link deltas vs the static model; 64-possible-CPU byte preflight |
| L-T7-10 | NEW: RV pressure past 8,192 distinct (slot,RV) keys | Explicit RV exhaustion with counted failures and intact positives (proves paired RV growth is required) |

Existing gates that stay green as regressions: wide/default 2112 and sweep
cells, `task4_detailed_physical_capacity_refusal` (ordinary over-capacity
refusal both profiles), old 576 Inventory gate.

## Open uncertainties (for the consensus)

1. The 6530 dense byte envelope (~118 MiB payload at 64 possible CPUs,
   before map overhead) may fail live preflight; the sparse non-evicting
   follow-up stays conditional, exactly as the over-2000 review framed it.
2. Which paired RV/caller growth shape (per-segment maps vs grown globals)
   the 5.15 verifier accepts is unmeasured; L-T7-8..L-T7-10 decide.
3. The v1→v2 ticket migration needs the native/config/loader review plus
   L-T7-7 before any claim; T7 changes no live limit.
4. No native/map-lifecycle source changed in T7 (capacity userspace +
   tests + this record only): no independent native/map review is owed by
   box 7's gate, but the consensus review of this record itself is the
   requested verdict before L-T7-7..L-T7-10 implementation starts.

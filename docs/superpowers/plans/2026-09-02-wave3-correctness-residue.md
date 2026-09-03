# Wave 3 — Correctness Residue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use
> `superpowers:subagent-driven-development` task by task. Each production task
> starts with a failing test, makes the smallest root-cause change, runs focused
> tests, then runs the four canonical Rust 1.88 gates before commit. Use only one
> Cargo-heavy command at a time against the shared target directory.

**Goal:** Make W3 product logic release-final: complete `C_GetInterface`
selection tracing and offline probing, remove the two remaining tracing
correctness hazards, ship honest capability/diagnostic tiers, and qualify the
existing per-offset attach path on Linux 5.15 and 6.8.

**Architecture:** Reuse the current discovery ring, process-view lifecycle,
transactional attach plan, exact-object pinning, and render path. Selection is a
bounded sibling of inventory, never a new inventory source. Tracepoint offsets
come from tracefs format metadata; scan-open identity is checked before parsing
the opened object. Capability and attach-mechanism evidence use finite enums.
`uprobe_multi` remains a separate performance optimization, deferred by the
owner until a stable Aya release exposes the required API.

**Tech stack:** Rust 1.88 / edition 2024, Aya 0.14.0 baseline, existing `libc`,
`cryptoki-sys`, and `libloading`. W3 adds no dependency.

**Authorities:**

- [W3 charter](2026-09-01-release-wave-charters.md#w3)
- [release PRD](../specs/2026-09-01-p11scope-release-prd.md)
- [owner requirements](../specs/2026-09-01-release-requirements-and-goal.md)
- [`C_GetInterface` design](../specs/2026-09-02-c-get-interface-selection-design.md)
- [ROADMAP execution protocol](ROADMAP.md#agent-execution-protocol-all-waves)

## Global constraints

- Preserve `docs/privacy/allowlist-v1.md` byte-for-byte. Create v2 explicitly;
  do not broaden target reads or output by implication.
- Preserve Rust 1.88, Linux x86-64 first, Aya 0.14.0, and the 5.15 per-offset
  attach path.
- No raw names, pointers, addresses, PIDs/TIDs, provider errors, or target paths
  in selection or attach-mechanism output.
- Parallel writers may touch only disjoint file sets. Review starts only after
  the writer stops.
- File lists are task-local ownership. A later sequential task may extend the
  unreleased v3 schema/allowlist created by Task 4; no concurrent writer may.
- Privileged/container/VM/runtime lanes are `UNRUN` unless separately
  authorized. Local unit/integration tests and ordinary Cargo gates are not
  privileged.
- Batch review fixes by shared root cause, normally three to five accepted
  findings per round; never weaken a validation boundary to reduce rounds.

## Task 0: Verified anchors and design ruling

**Files:**

- Create: `docs/superpowers/specs/2026-09-02-c-get-interface-selection-design.md`
- Create: this plan
- Modify: `docs/superpowers/plans/2026-09-01-release-wave-charters.md`

- [x] Verify current selection transport, helper, manifest, render, lifecycle,
  and privacy anchors at merged W2 base `a2a2644`.
- [x] Resolve selection/inventory separation, exact provider binding,
  owned-`run` prearm coverage, alias identity, selection-only claim ownership,
  manifest v5, profile v3, and allowlist-v2 wording through delegated
  review-to-zero.
- [x] Owner explicitly authorized autonomous W3 tracing/schema/privacy review
  and implementation in this thread on 2026-09-02; the reviewed design is the
  exact field/allowlist authority and v1 remains immutable.
- [x] Verify W3 charter anchors for tracepoint offsets, scan-open identity,
  capability/diagnostic gaps, and Aya 0.14 `uprobe_multi` feasibility.
- [x] Run pass-2 review over every file/symbol/test command cited below; correct
  stale anchors before Task 1.

Commit: `docs: plan wave 3 correctness residue`

## Task 1: Manifest v5 selection contracts and the ten-query helper

**Files:**

- Modify: `crates/manifest/src/manifest.rs`
- Modify: `crates/manifest/tests/{elf,identity}.rs`
- Modify: `src/manifest_input.rs`, `src/plan.rs`
- Modify: `src/discovery/{engine,identity}.rs`
- Modify: `crates/discover/src/discover.rs`
- Modify: `crates/discover/tests/{cli,fixture_provider,softhsm,version_matrix}.rs`
- Modify: `crates/discover/tests/fixture/{provider,version_matrix}.c`
- Modify: `README.md`, `CHANGELOG.md`, `scripts/lib.sh`
- Modify: `tests/{artifact_contracts,manifest_pinning}.rs`

Design acceptance: §12 items 2, 5, and 9–11.

Current anchors: manifest v4 is fixed at
`crates/manifest/src/manifest.rs:10`; `discover_with_self_memory` begins at
`crates/discover/src/discover.rs:36`; exact v4 validation begins at
`src/manifest_input.rs:134`.

- [x] RED: add exact-shape and mutation tests for manifest v5
  `selection_evidence`: three acquisition states, exact selector/flag matrix,
  result/authority cross-fields, at-most-16 matches, truncation, table IDs
  `0..9`, full-walk/reachability, null slots, unresolved refusal, and orphan
  table rejection. Pin false name/version agreement whenever either compared
  field is null or unreadable. Prove v4 rejection is precise.
- [x] GREEN: add only the design's finite v5 types and structural validation.
  Keep inventory `surfaces`, interfaces, and alias groups unchanged.
- [x] RED: `no_live_manifest_v4_pin_remains` enumerates every live producer,
  consumer, fixture, script, and exact pin and fails before migration.
- [x] GREEN: atomically migrate that set to v5 in this task; old plans,
  reports, changelog history, and observed-profile-v2 documentation remain
  explicitly historical.
- [x] RED: fixture test proves zero calls for absent/outside export and exactly
  ten ordered calls for queried; retain nonzero `CK_RV`, helper failures, full
  returned flags, and all bounded exact aliases.
- [x] RED: `selection_helper_conflicting_semantic_pair_is_truncated` returns
  two different eligible tables with the same returned version/flags pair;
  only the first fixed-order table may receive authority, the later outcome is
  factual with no table reference, and missing truncation is invalid.
- [x] GREEN: add one local raw `C_GetInterface` ABI adapter in
  `p11scope-discover`, using its existing dependencies and no fallback policy.
  Query before `C_Initialize`; do not change the external facts-crate pin.
- [x] Focused checks:
  `cargo +1.88 test --locked -p p11scope-manifest -p p11scope-discover` and
  `cargo +1.88 test --locked --test manifest_pinning`; the RED test names are
  `manifest_v5_selection_matrix_is_exact`,
  `selection_helper_makes_exactly_ten_queries`, and
  `selection_agreement_requires_readable_fields`.
- [x] Four canonical gates; commit.

Commit: `feat: record bounded offline interface selection evidence`

## Task 2: Live selection transport without inventory mutation

**Files:**

- Modify: `crates/ebpf-common/src/lib.rs`
- Modify: `crates/ebpf/src/main.rs`
- Modify: `src/attach.rs`
- Modify: `src/discovery/pause.rs`
- Modify: `src/events.rs`
- Modify: `scripts/check-bpf-map-defs.py`
- Modify: `scripts/check-live-discovery-object.py`
- Modify: `scripts/verify-canaries.sh`
- Modify: `tests/artifact_contracts.rs`
- Modify: `tests/fixtures/live-discovery-provider.c`

Design acceptance: §12 items 2, 3, and 8.

Current anchors: `DiscoveryRecord` at
`crates/ebpf-common/src/lib.rs:342`, `StartState` at `:374`,
`interface_entry`/`interface_return` at
`crates/ebpf/src/main.rs:847,859`.

- [x] RED: ABI tests cover all finite request/result classes, full-width flags
  and `CK_RV`, nonzero return without output dereference, null/unreadable
  success, reserved-zero layout, record size, recursive no-overwrite loss, and
  a dedicated full-width nonzero `u64` binding id. A failed provider outcome
  emits but never requests the owned-child discovery pause.
- [x] GREEN: extend the existing state and kind-4 record only enough to carry
  sanitized classifications/scalars and private return correlation. Emit one
  record for every matched return, including failure.
- [x] RED: static/round-trip contract proves request name bytes and pointers
  never enter BPF maps or records; metrics and non-interface hooks read no new
  arguments.
- [x] GREEN: make kind 4 structurally selection-only. Preserve existing ring,
  maps, read/state/ring counters, and bounded table walker.
- [x] Focused checks:
  `cargo +1.88 test --locked -p p11scope-ebpf-common` and
  `cargo +1.88 test --locked --test artifact_contracts`; the RED test names
  are `selection_transport_round_trips_failures` and
  `selection_transport_never_carries_name_bytes`; the former pins zero-id
  refusal and `u64::MAX` round-trip.
- [x] Four canonical gates; commit.

Commit: `feat: capture bounded C_GetInterface request outcomes`

## Task 3: Selection reduction, ownership, and owned-run coverage

**Files:**

- Modify: `src/discovery/engine.rs`
- Modify: `src/plan.rs`
- Modify: `src/attach.rs`
- Modify: `src/run.rs`
- Modify: `tests/fixtures/live-discovery-{provider,driver}.c`
- Modify: unit tests inside the four Rust modules above
- Modify: `tests/{live_discovery,run_lifecycle}.rs`

Design acceptance: §12 items 1, 2, 4–7, 10, and 12–13, plus the reduction
invariant in item 15.

Current anchors: kind-4 lowering at `src/discovery/engine.rs:3709`, inventory
merge at `:5752`, dispatch at `:7617`, owned-loader prearm at `:6539`, owned
child execution at `src/run.rs:1484`, and physical slot state at
`src/plan.rs:176`.

The 2026-09-02 independent Task-3 pre-mortem adds these execution invariants:

- Allocate a binding only when no existing
  `(loader context, object, hook offset, ABI)` binding exists; refresh and
  loader hits reuse its id. Record a binding whenever an entry/return pair was
  attached, even when the later generation postcheck rejects its authority.
- Keep one capture-lifetime binding fact map. Active attribution additionally
  requires the loader registry/context and exact generation to remain live;
  delayed records after retirement fail closed. Mark confirmed coverage closed
  before removing the loader context that proves the closure.
- Route kind 4 explicitly before generic export lowering. Task 2 deliberately
  leaves these records non-authoritative until this task; they must not become
  generic live-loss skips or inventory mutations.
- Replay every live selection claim into each rebuilt candidate, then prune its
  inactive owners after apply. Preflight a whole selection table against the
  512-slot ceiling before adding any target; a prefix is never admissible.
- Aggregate policy creates no selection binding, tuple, coverage debt, or
  selection loss.

- [x] RED first: `c_get_interface_selection_never_mutates_inventory` proves
  kind 4 changes no caller-independent surface, interface, alias group,
  `fork_safe`, or inventory table.
- [x] GREEN: reject kind 4 from `lower_export_record`; add a dedicated reducer
  with capture-lifetime unique binding IDs, exact provider attribution, bounded
  tuples, factual match retention, `InventorySurfaceKey`, and the
  order-independent standard-export reducer. Agreement is proven equality of
  readable finite fields, never inferred for null or unreadable fields.
- [x] RED: `selection_binding_ids_never_reuse` pins a capture-local
  checked monotonic `u64` allocator: zero is invalid, `u64::MAX` is allocated
  once, the next allocation is refused/`PARTIAL`, retirement removes the active
  lookup, and a delayed record cannot resolve to a later binding.
- [x] GREEN: use one capture-local checked counter plus the existing active
  binding map; no retained-id registry or allocator abstraction is needed.
- [x] RED: `selection_bindings_reuse_existing_physical_attachments` proves
  refresh does not reattach or recount an existing binding and
  `selection_postcheck_failure_retains_attached_binding` proves rollback or
  retirement still owns every link created before a generation postcheck.
- [x] RED: same-address/different-name claims produce occurrence-based
  `table_entries`, one physical `AttachKey`, and one aggregate cell.
- [x] RED: two-view claims retire independently while sharing physical targets.
  Delayed records for retired IDs fail closed. Landed in `484036c`.
- [x] GREEN: implement `SelectionClaimKey -> AttachKey` reference ownership and
  source-local count-only authorization through the existing
  preflight/apply/rollback transaction. Never attach a duplicate offset.
- [x] RED: `owned_run_selection_coverage` proves the private coverage reducer:
  an exact provider prearmed behind the owned-child barrier observes a
  constructor call and classifies a silent completed run as `absent_covered`;
  non-prearmed `run` and `--pid` classify as `absent_uncovered`; normal
  finalization preserves the closed coverage interval. Task 4 alone proves the
  corresponding public JSON.
- [x] GREEN: preattach entry+return to exact freshly pinned provider exports
  before `OwnedChild::release`, then accept proof only after the eventual
  mapping agrees on device, inode, view, and generation.
- [x] RED: `selection_ring_loss_invalidates_silent_coverage` proves nonzero
  discovery-ring loss makes affected silent bindings uncovered and the verdict
  `PARTIAL`; it never becomes an empty/covered result.
- [x] RED: `selection_semantic_key_reuses_same_table_and_refuses_changed_targets`
  permits one distinct table per exact provider generation and standard
  `(returned version, returned flags)` pair, reuses repeated exact claims, and
  refuses a conflicting table as truncated without allocating slots. Unknown
  flag bits remain factual evidence but authorize nothing.
- [x] GREEN: enforce that finite semantic key before the existing indivisible
  512-slot admission; add no separate quota or slot allocator.
- [x] RED: `selection_table_capacity_refusal_mutates_nothing`
  (landed in `a182f93`) proves a table that cannot fit contributes no prefix,
  link, or slot index.
- [x] RED: `manifest_selection_tables_enter_the_attach_transaction` proves a
  reachable manifest-v5 selection table creates source-local count-only claims,
  `semantic_authorized=false`, and `PARTIAL`; an inventory target at the same
  physical key shares one slot, and rollback/retirement remove only the
  applicable owner without mutating inventory.
- [x] GREEN: lower only reachable, structurally validated manifest-v5 tables
  through the existing candidate preflight/apply/rollback path and the same
  `SelectionClaimKey -> AttachKey` reference ownership as live selection. Add
  no manifest-only attach path.
- [x] Focused checks:
  `cargo +1.88 test --locked --lib c_get_interface_selection`,
  `cargo +1.88 test --locked --lib manifest_selection`, and
  `cargo +1.88 test --locked --lib owned_run_selection_coverage`;
  then four canonical gates; review clean after three scoped fix rounds at
  `64b7790` (731 main-library tests plus every integration/crate target); commit.

Commit: `feat: reduce interface selection with exact lifecycle authority`

## Task 4: Profile v3, privacy v2, and selection evidence consumers

**Files:**

- Modify: `src/discovery/engine.rs`, `src/render.rs`, `src/run.rs`,
  `src/trace.rs`
- Create: `docs/schema/observed-profile-v3.md`
- Create: `docs/privacy/allowlist-v2.md`
- Modify: `README.md`, `docs/usage.md`, `src/inspect.rs`
- Modify: `scripts/{check-capture-evidence.py,check-live-discovery-evidence.py,verify-canaries.sh}`
- Inspect and modify if its live-profile pin is active:
  `scripts/matrix/verify-oracle.sh`

Design acceptance: §12 items 3, 14, and 15.

- [x] RED: exact JSON/mutation tests pin `interface_selection`, all finite
  arrays/enums/cross-references, count saturation, every selection loss to
  `PARTIAL`, finite saturating `pid_descendant_gaps` and
  `multi_rebuild_gaps`, and no individual trace-line selection output.
- [x] GREEN: profile and terminal trace use observed-profile v3; metrics stays
  v2-metrics and reads no selection arguments. Preserve v1 allowlist unchanged;
  v2 authorizes only the reviewed finite classes, a finite sorted
  `evidence.attach_mechanisms` array, and the existing offline inventory name
  exception. Derive the array only from successfully owned links and emit only
  `per-offset` in W3; the already-versioned `uprobe-multi` value remains unused
  until its deferred implementation task.
- [x] RED: `profile_v3_selection_contract_is_exact` and the two validator
  self-tests reject missing/extra v3 selection fields, secret canaries, stale
  live profile-v2 pins, and an observer/helper description with reversed roles;
  the public four-state coverage value must be derived exactly from Task 3's
  private reducer.
- [x] GREEN: update docs, exact-schema dispatch, and canaries so the observer
  remains passive while the explicit helper is documented as making ten calls.
  Migrate live profile-v2 exact pins; retain historical records as historical.
  Enforce the 16-tuple bound globally per capture, not independently per
  module, and project public coverage only through Task 3's reducer.
- [x] Focused checks:
  `cargo +1.88 test --locked --lib profile_v3_selection_contract_is_exact`,
  `python3 -I scripts/check-capture-evidence.py --self-test`, and
  `sh scripts/verify-canaries.sh --self-test`; then four canonical gates.
- [x] Independent selection-slice correctness and test-quality review; batch
  accepted fixes until one cycle is zero. Commit.

Commit: `docs: publish versioned interface selection evidence`

Completed through `620372a`: producer and consumer review reached zero after
four related fix batches. The final clean-tip Rust 1.88 gates passed 1,010
tests; their first run also found and closed two stale integration fixtures
(`70775cf`, `620372a`) without changing production behavior. Allowlist v1
remained byte-identical.

## Task 4.5: Exact-tip runtime smoke before more BPF churn

This is an owner-gated evidence checkpoint, not a code-change task. On the
exact clean Task-4 tip, run the real embedded object on the existing Ubuntu
22.04 / Linux 5.15 and Ubuntu 24.04 / Linux 6.8 lanes before Task 5 changes the
fork program again.

- [x] Record `doctor`, the attach e2e, the privacy canary, and induced-gap G3
  as PASS, FAIL, or `UNRUN` on each exact kernel. Do not inherit W1/W2 evidence.
- [ ] Require the real object to load, expected slots to attach, canaries to
  report no leak (including interface-selection names), and G3 to retain exact
  aggregate counts while reporting nonzero loss and `PARTIAL`.
- [x] If privilege or a required VM is unavailable, keep the row `UNRUN` and
  continue only with that explicit evidence debt; never call the W3 tip runtime
  qualified from local Rust gates alone.

Exact-tip checkpoint at `d66e969` on 2026-09-03: all four Jammy 5.15 rows and
all four Noble 6.8 rows were initially recorded `UNRUN`. That record is
superseded: the relocated `overlay.qcow2` files do reference deleted backing
paths, but the standalone Jammy 5.15 and Noble 6.8 cloud images are present and
valid under `/home/user/src/m/p11scope-ws/vm-bases`. Create fresh disposable
overlays from those bases and run the rows on the final W3 tip in Task 8.
Historical evidence is still not inherited.

## Task 5: Dynamic tracepoint offsets and scan-open identity

This is one review batch but permits two disjoint writers:

- Writer A owns `crates/ebpf-common/src/lib.rs`, `crates/ebpf/src/main.rs`,
  `src/attach.rs` (`parse_task_newtask_format` and CONFIG publication), and
  `tests/artifact_contracts.rs`.
- Writer B owns `src/discovery/scan.rs` and `tests/discovery_scan.rs`.
- Neither writer edits the other's files; the primary integrates and runs Cargo
  serially.

Current anchors: literal fork offsets at `crates/ebpf/src/main.rs:1955,1958`;
target open at `src/discovery/scan.rs:970`; size-only `hint_gate` at `:1003`;
scan entry at `:1195`.

- [x] RED A: parse synthetic tracefs format with shifted `parent_pid` and
  `child_pid`; reject missing, duplicate, wrong-size, negative, or overflowing
  fields; static test rejects literal 24/44 reads.
- [x] GREEN A: parse
  `/sys/kernel/tracing/events/task/task_newtask/format`, publish checked
  offsets through existing config-map ownership before attach, and make BPF read
  only those values. Fail closed; add no BTF/CO-RE dependency.
- [x] RED B: pass a same-size replacement inode to the opened-file identity
  boundary and prove it is refused before hint matching; pin the unconditional
  scan call site for hinted and unhinted candidates.
- [x] GREEN B: immediately after `open_in_target`, compare the opened file's
  maps-comparable device/inode against the maps snapshot key using the existing
  identity operation; size remains supplementary only.
- [x] Focused checks:
  `cargo +1.88 test --locked --lib tracepoint_format`,
  `cargo +1.88 test --locked --test artifact_contracts dynamic_task_newtask_offsets`,
  and `cargo +1.88 test --locked --lib opened_file_identity`;
  then four canonical gates and commit the two root fixes together after
  integration review.

Commit: `fix: bind tracing metadata and scan opens to live identities`

Completed at `02eedbd`: both independent reviews passed; focused checks, the
15-test discovery scanner suite, and all four canonical gates passed with
1,017 tests. Allowlist v1 remained byte-identical.

## Task 6: Capability tiers, diagnostics, and verdict honesty

**Files:**

- Modify: `src/doctor.rs`, `src/attach.rs`, `src/run.rs`, `src/render.rs`,
  `src/trace.rs`
- Modify: `tests/proc_access.rs`
- Modify: `scripts/verify-capability-tier.sh`
- Version, do not mutate: historical `FROZEN_CAPS` contract in
  `scripts/check-live-discovery-evidence.py`
- Modify: `docs/usage.md`
- Modify: `docs/superpowers/specs/2026-09-01-p11scope-release-prd.md`
- Modify: `docs/superpowers/plans/2026-09-01-release-wave-charters.md`
- Modify: `docs/notes/2026-08-15-architecture-and-gap-analysis.md`

Charter acceptance: W3 items 4–5.

Current anchors: `CAP_BITS` at `src/doctor.rs:37`, real BPF/attach probe at
`:223-290`, lifecycle degradation around `src/attach.rs:432`, and
evidence/verdict at `src/render.rs:169,506`.

The tier is a `doctor` availability result for the requested host/target/scope,
not capture authority or completeness. Let `H` mean the supported kernel plus
successful load of the real embedded object/maps/programs and an actual
ordinary self-uprobe attach; `R` mean the supplied target generation stayed
stable while required `/proc/<pid>/{maps,mem,root}` and exact provider opens
succeeded; `L` mean the real exec and exit lifecycle links both attached; and
`S` mean every requested scope-specific operation succeeded, including filter
publication, cgroup access, and fork tracing when required.

| Tier | Predicate | Meaning and explicit loss |
| --- | --- | --- |
| T0 offline | `!H` | Offline helper/inspect/report only; no live-call evidence. |
| T1 host attach | `H && (!R or target unassessed)` | Real observer load/attach works; target readability/capture is not claimed. |
| T2 target readable | `H && R && !L` | Exact target/providers can be planned; lifecycle changes may be missed and an attempted capture is `PARTIAL`. |
| T3 lifecycle | `H && R && L && !S` | Base target/lifecycle works; the requested scope-specific lane is unavailable or degraded. |
| T4 current full | `H && R && L && S` | All requested current-product mechanisms preflighted; this is not leased/hardened authority or a `COMPLETE` promise. |

Operational results outrank inferred privilege. Capability bits, uid, sysctls,
Yama, hidepid, dumpability, seccomp, and LSM state are diagnostics only. Return
the highest proven prefix; unknown target/scope inputs produce T1 plus
`unassessed`, never a guessed upper tier. Do not add `tier` to capture JSON or
change `evidence.authority`; actual attach/loss/skipped-object evidence owns the
capture verdict.

- [x] RED: `capability_tier_is_monotonic_without_lease_authority` covers the
  exact `H/R/L/S` truth table, `R=unassessed`, and operational results overriding
  capability guesses; classifier inputs contain no lease, trusted-workload,
  root-authority, or hardened-oracle predicate. Add CAP_DAC_READ_SEARCH bit 2.
  Do not claim CAP_SYS_RESOURCE or an RLIMIT_MEMLOCK requirement.
- [x] GREEN: emit the finite tier and assessed/unassessed state from `doctor`;
  reuse current real probes rather than a toy program. Capture output gains no
  `tier`, lease, or hardened authority field. Document exact losses per tier.
- [x] RED: `eperm_origin_requires_independent_evidence` proves bare `EPERM`
  stays unknown, merely observing seccomp mode 2 is not causal proof, a
  controlled syscall-denial fact selects seccomp, and a proven missing
  capability selects capability. `verifier_diagnostics_are_bounded` accepts
  only Aya's verifier log for the fixed embedded object, escapes controls with
  the existing terminal helper, and caps the complete rendered fragment at
  4096 UTF-8 bytes including a literal ` [truncated]` suffix without splitting
  a scalar; it never includes a target path or generic error chain.
- [x] GREEN: distinguish evidence-backed seccomp denial from missing-capability
  denial without guessing from `EPERM` alone, and surface bounded Aya verifier
  diagnostics on load failure without target data.
- [x] RED: for each discovery loss counter, serialize profile/metrics/terminal
  evidence and prove consumer verdict is `PARTIAL` exactly once.
- [x] RED: process creation is cgroup/event-policy only: PID scope neither
  attaches `task_newtask` nor reports a missing-boundary sentinel. A cgroup
  `task_newtask` record adds one finite selection window gap; ordinary children
  inherit proven semantic state while `CLONE_INTO_CGROUP` children do not.
- [x] GREEN: attach the cgroup `task/task_newtask` boundary, parse its live
  signed `pid` and unsigned `clone_flags` offsets, filter `CLONE_THREAD` before
  reservation, and expose only the existing bounded gap evidence. A missing
  cgroup boundary starts with one explicit gap because early child selection
  coverage cannot be established. PID scope remains exact and reports zero.
- [x] Update capability self-test and docs; privileged rows remain `UNRUN` if
  not authorized. Focused checks:
  `cargo +1.88 test --locked --lib capability_tier`,
  `cargo +1.88 test --locked --lib process_creation`,
  `cargo +1.88 test --locked --test proc_access capability_tier`, and
  `sh scripts/verify-capability-tier.sh --self-test`; then four canonical
  gates; commit.

Commit: `feat: report capability tiers and tracing degradation honestly`

## Deferred Task 7: `uprobe_multi`

**Owner decision 2026-09-03:** `uprobe_multi` is no longer a W3 requirement.
Keep Aya `=0.14.0` and the correct Linux 5.15 per-offset implementation. Reopen
multi-attach as its own post-W3 performance task only after a stable Aya
release exposes the required multi program-load, attach/link ownership, and
process-scoped PID-filter support. Do not pin an upstream PR or add a raw-link
fallback in W3.

The feasibility record and proposed upstream contribution remain in
[`docs/notes/2026-09-02-aya-uprobe-multi-status.md`](../../notes/2026-09-02-aya-uprobe-multi-status.md).
No code, dependency, schema, gate, or runtime row is owed by this deferred task.

## Task 8: W3 closeout and review to zero

**Files:**

- Modify: `src/run.rs`
- Modify: `src/trace.rs`
- Modify: `docs/usage.md`
- Create: `docs/superpowers/reports/2026-09-02-wave3-correctness-closure.md`
- Modify: `docs/superpowers/plans/ROADMAP.md`
- Modify: `docs/superpowers/plans/2026-09-01-release-wave-charters.md` only if
  closeout evidence changes its recorded Aya decision
- Modify: `CHANGELOG.md` only if its existing release convention requires it

- [ ] Emit one terminal machine-readable `COUNT_EVIDENCE` line from `trace`.
  It must contain aggregate `stats_entered`, `stats_returned`, and the number
  of well-formed non-fork `raw_calls` consumed by that trace session. Count a
  call before output truncation or semantic reduction; derive STATS entered as
  completed calls plus in-flight calls. Keep this aggregate-only and do not
  change the privacy allowlist or public profile schema.
- [ ] Do not add a second runtime framework. The owner will run the real
  `pkcs11-check`, Jammy/5.15, and Noble/6.8 qualification after W3 while
  evaluating the candidate. Preserve exact commands and expected relationships
  in the closure report, and record these rows as `UNRUN` until then.
- [ ] Run every unprivileged validator self-test and focused W3 test named in
  Tasks 1–6.
- [ ] Run the four canonical gates on the exact branch tip and record counts.
- [ ] Record privileged/container/VM rows as PASS, FAIL, or `UNRUN`; never
  inherit W1/W2 evidence.
- [ ] Specify the two later product-qualification rows against the exact tip:
  `supported_rate_loss_oracle` (an empirically declared, matrix-specific fixed
  burst/rate with exact agreement between generator-completed calls, STATS
  entered/returned, and raw consumed `CALL` records, zero loss, and induced
  loss forcing `PARTIAL`; never derive a supported events/second claim from
  ring capacity or drain cadence; test the per-offset mechanism)
  and
  `fork_exec_loader_unload_oracle` (fork, exec, `dlopen`, calls, `dlclose`,
  replacement/reload, exact retirement and attribution). These privileged
  runtime rows must PASS before a public runtime-qualified or release claim on
  Linux 5.15 and 6.8 using the per-offset mechanism. Owner decision 2026-09-03:
  they may remain explicitly `UNRUN` for the W3 engineering closeout so the
  resulting candidate can be evaluated manually; never convert that status
  into a working-product claim. W6 repeats the broader release matrix.
- [ ] For those future exact-tip runtime lanes, use the existing documented
  commands and checkers for one operator journey
  (`doctor -> inspect -> run/profile -> trace`). Add an exact-count
  `trace --pid` row against the deterministic PKCS#11 oracle; canary presence
  alone is insufficient. Bind the record to the exact binary and embedded BPF
  object hashes and require actionable insufficient-authority diagnostics.
- [ ] Independent full-diff Sol correctness/security review and Luna
  test-quality/regression review. Add a third distinct reviewer only for a
  genuinely separate risk. Triage with source evidence; batch accepted fixes
  three to five at a time; repeat until a complete cycle accepts zero findings.
- [ ] Update the closure report and ROADMAP with exact commit/test evidence.
- [ ] Use `superpowers:finishing-a-development-branch`: merge locally to main
  only after review-to-zero, rerun all four gates on merged main, and leave
  push/tag/publish untouched.

Commit: `docs: close wave 3 correctness residue`

## Canonical gates

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
```

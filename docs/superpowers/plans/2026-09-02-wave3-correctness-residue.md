# Wave 3 — Correctness Residue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use
> `superpowers:subagent-driven-development` task by task. Each production task
> starts with a failing test, makes the smallest root-cause change, runs focused
> tests, then runs the four canonical Rust 1.88 gates before commit. Use only one
> Cargo-heavy command at a time against the shared target directory.

**Goal:** Make W3 product logic release-final: complete `C_GetInterface`
selection tracing and offline probing, remove the two remaining tracing
correctness hazards, ship honest capability/diagnostic tiers, and use
`uprobe_multi` where the kernel supports it without weakening the 5.15
fallback.

**Architecture:** Reuse the current discovery ring, process-view lifecycle,
transactional attach plan, exact-object pinning, and render path. Selection is a
bounded sibling of inventory, never a new inventory source. Tracepoint offsets
come from tracefs format metadata; scan-open identity is checked before parsing
the opened object. Capability and attach-mechanism evidence use finite enums.
`uprobe_multi` is a narrow raw `BPF_LINK_CREATE` backend behind Aya 0.14's
loaded program FD; dynamic changes retain the existing per-offset path.

**Tech stack:** Rust 1.88 / edition 2024, Aya exactly 0.14.0, existing
`libc`, `cryptoki-sys`, and `libloading`; no new dependency or toolchain pin.

**Authorities:**

- [W3 charter](2026-09-01-release-wave-charters.md#w3)
- [release PRD](../specs/2026-09-01-p11scope-release-prd.md)
- [owner requirements](../specs/2026-09-01-release-requirements-and-goal.md)
- [`C_GetInterface` design](../specs/2026-09-02-c-get-interface-selection-design.md)
- [ROADMAP execution protocol](ROADMAP.md#agent-execution-protocol-all-waves)

## Global constraints

- Preserve `docs/privacy/allowlist-v1.md` byte-for-byte. Create v2 explicitly;
  do not broaden target reads or output by implication.
- Preserve Rust 1.88, Aya 0.14.0, Linux x86-64 first, and the 5.15 per-offset
  attach path.
- No raw names, pointers, addresses, PIDs/TIDs, provider errors, or target paths
  in selection or attach-mechanism output.
- Parallel writers may touch only disjoint file sets. Review starts only after
  the writer stops.
- Privileged/container/VM/runtime lanes are `UNRUN` unless separately
  authorized. Local unit/integration tests and ordinary Cargo gates are not
  privileged.
- Batch review fixes by shared root cause, normally three to five accepted
  findings per round; never weaken a validation boundary to reduce rounds.

## Task 0: Verified anchors and design ruling

**Files:**

- Create: `docs/superpowers/specs/2026-09-02-c-get-interface-selection-design.md`
- Create: this plan

- [x] Verify current selection transport, helper, manifest, render, lifecycle,
  and privacy anchors at merged W2 base `a2a2644`.
- [x] Resolve selection/inventory separation, exact provider binding,
  owned-`run` prearm coverage, alias identity, selection-only claim ownership,
  manifest v5, profile v3, and allowlist-v2 wording through delegated
  review-to-zero.
- [x] Verify W3 charter anchors for tracepoint offsets, scan-open identity,
  capability/diagnostic gaps, and Aya 0.14 `uprobe_multi` feasibility.
- [ ] Run pass-2 review over every file/symbol/test command cited below; correct
  stale anchors before Task 1.

Commit: `docs: plan wave 3 correctness residue`

## Task 1: Manifest v5 selection contracts and the ten-query helper

**Files:**

- Modify: `crates/manifest/src/manifest.rs`
- Modify: `crates/manifest/tests/{elf,identity}.rs`
- Modify: `src/manifest_input.rs`
- Modify: `crates/discover/src/discover.rs`
- Modify: `crates/discover/tests/{fixture_provider,softhsm,version_matrix}.rs`
- Modify: relevant helper fixtures under `crates/discover/tests/`

Current anchors: manifest v4 is fixed at
`crates/manifest/src/manifest.rs:10`; `discover_with_self_memory` begins at
`crates/discover/src/discover.rs:36`; exact v4 validation begins at
`src/manifest_input.rs:134`.

- [ ] RED: add exact-shape and mutation tests for manifest v5
  `selection_evidence`: three acquisition states, exact selector/flag matrix,
  result/authority cross-fields, at-most-16 matches, truncation, table IDs
  `0..9`, full-walk/reachability, null slots, unresolved refusal, and orphan
  table rejection. Pin false name/version agreement whenever either compared
  field is null or unreadable. Prove v4 rejection is precise.
- [ ] GREEN: add only the design's finite v5 types and structural validation.
  Keep inventory `surfaces`, interfaces, and alias groups unchanged.
- [ ] RED: fixture test proves zero calls for absent/outside export and exactly
  ten ordered calls for queried; retain nonzero `CK_RV`, helper failures, full
  returned flags, and all bounded exact aliases.
- [ ] GREEN: add one local raw `C_GetInterface` ABI adapter in
  `p11scope-discover`, using its existing dependencies and no fallback policy.
  Query before `C_Initialize`; do not change the external facts-crate pin.
- [ ] Focused checks:
  `cargo +1.88 test --locked -p p11scope-manifest -p p11scope-discover` and
  `cargo +1.88 test --locked --test manifest_pinning`.
- [ ] Four canonical gates; commit.

Commit: `feat: record bounded offline interface selection evidence`

## Task 2: Live selection transport without inventory mutation

**Files:**

- Modify: `crates/ebpf-common/src/lib.rs`
- Modify: `crates/ebpf/src/main.rs`
- Modify: `src/discovery/hooks.rs`
- Modify: `tests/artifact_contracts.rs`

Current anchors: `DiscoveryRecord` at
`crates/ebpf-common/src/lib.rs:342`, `StartState` at `:374`,
`interface_entry`/`interface_return` at
`crates/ebpf/src/main.rs:847,859`.

- [ ] RED: ABI tests cover all finite request/result classes, full-width flags
  and `CK_RV`, nonzero return without output dereference, null/unreadable
  success, reserved-zero layout, record size, and recursive no-overwrite loss.
- [ ] GREEN: extend the existing state and kind-4 record only enough to carry
  sanitized classifications/scalars and private return correlation. Emit one
  record for every matched return, including failure.
- [ ] RED: static/round-trip contract proves request name bytes and pointers
  never enter BPF maps or records; metrics and non-interface hooks read no new
  arguments.
- [ ] GREEN: make kind 4 structurally selection-only. Preserve existing ring,
  maps, read/state/ring counters, and bounded table walker.
- [ ] Focused checks:
  `cargo +1.88 test --locked -p p11scope-ebpf-common` and
  `cargo +1.88 test --locked --test artifact_contracts`.
- [ ] Four canonical gates; commit.

Commit: `feat: capture bounded C_GetInterface request outcomes`

## Task 3: Selection reduction, ownership, and owned-run coverage

**Files:**

- Modify: `src/discovery/engine.rs`
- Modify: `src/plan.rs`
- Modify: `src/attach.rs`
- Modify: `src/run.rs`
- Modify: `tests/fixtures/live-discovery-{provider,driver}.c`
- Modify: focused discovery/lifecycle tests colocated with the modules above

Current anchors: kind-4 lowering at `src/discovery/engine.rs:3709`, inventory
merge at `:5752`, dispatch at `:7617`, owned-loader prearm at `:6539`, owned
child execution at `src/run.rs:1484`, and physical slot state at
`src/plan.rs:176`.

- [ ] RED first: `c_get_interface_selection_never_mutates_inventory` proves
  kind 4 changes no caller-independent surface, interface, alias group,
  `fork_safe`, or inventory table.
- [ ] GREEN: reject kind 4 from `lower_export_record`; add a dedicated reducer
  with capture-lifetime unique binding IDs, exact provider attribution, bounded
  tuples, factual match retention, `InventorySurfaceKey`, and the
  order-independent standard-export reducer. Agreement is proven equality of
  readable finite fields, never inferred for null or unreadable fields.
- [ ] RED: same-address/different-name and two-view claims produce occurrence-
  based `table_entries`, one physical `AttachKey`, one aggregate cell, and
  independent retirement. Delayed records for retired IDs fail closed.
- [ ] GREEN: implement `SelectionClaimKey -> AttachKey` reference ownership and
  source-local count-only authorization through the existing
  preflight/apply/rollback transaction. Never attach a duplicate offset.
- [ ] RED: exact provider prearmed behind the owned-child barrier observes a
  constructor call and reports a silent completed run as `absent_covered`;
  non-prearmed `run` and `--pid` report `absent_uncovered`; normal finalization
  preserves the closed coverage interval.
- [ ] GREEN: preattach entry+return to exact freshly pinned provider exports
  before `OwnedChild::release`, then accept proof only after the eventual
  mapping agrees on device, inode, view, and generation.
- [ ] Focused engine/plan/run tests, then four canonical gates; commit.

Commit: `feat: reduce interface selection with exact lifecycle authority`

## Task 4: Profile v3, privacy v2, and selection evidence consumers

**Files:**

- Modify: `src/render.rs`, `src/run.rs`, `src/trace.rs`
- Create: `docs/schema/observed-profile-v3.md`
- Create: `docs/privacy/allowlist-v2.md`
- Modify: `README.md`, `docs/usage.md`, `src/inspect.rs`
- Modify: exact-schema/canary scripts and fixtures that dispatch on profile v2

- [ ] RED: exact JSON/mutation tests pin `interface_selection`, all finite
  arrays/enums/cross-references, count saturation, every selection loss to
  `PARTIAL`, and no individual trace-line selection output.
- [ ] GREEN: profile and terminal trace use observed-profile v3; metrics stays
  v2-metrics and reads no selection arguments. Preserve v1 allowlist unchanged;
  v2 authorizes only the reviewed finite classes and existing offline inventory
  name exception.
- [ ] RED/GREEN: update docs and canaries so the observer remains passive while
  the explicit helper is documented as making the ten calls. Migrate every
  live v2/v4 exact pin; retain historical records as historical.
- [ ] Run relevant script `--self-test` modes, focused render/trace tests, then
  four canonical gates.
- [ ] Independent selection-slice correctness and test-quality review; batch
  accepted fixes until one cycle is zero. Commit.

Commit: `docs: publish versioned interface selection evidence`

## Task 5: Dynamic tracepoint offsets and scan-open identity

This is one review batch but permits two disjoint writers:

- Writer A owns `crates/ebpf-common/src/lib.rs`, `crates/ebpf/src/main.rs`,
  the trace-format parser/config publication site, and its artifact tests.
- Writer B owns `src/discovery/scan.rs` and `tests/discovery_scan.rs`.
- Neither writer edits the other's files; the primary integrates and runs Cargo
  serially.

Current anchors: literal fork offsets at `crates/ebpf/src/main.rs:1692-1707`;
target open at `src/discovery/scan.rs:914`; size-only `hint_gate` at `:947`;
scan entry at `:1139`.

- [ ] RED A: parse synthetic tracefs format with shifted `parent_pid` and
  `child_pid`; reject missing, duplicate, wrong-size, negative, or overflowing
  fields; static test rejects literal 24/44 reads.
- [ ] GREEN A: parse
  `/sys/kernel/tracing/events/sched/sched_process_fork/format`, publish checked
  offsets through existing config-map ownership before attach, and make BPF read
  only those values. Fail closed; add no BTF/CO-RE dependency.
- [ ] RED B: replace a mapped provider pathname with another inode and scan with
  both hinted and unhinted paths; neither may parse or attribute the replacement.
- [ ] GREEN B: immediately after `open_in_target`, compare the opened file's
  maps-comparable device/inode against the maps snapshot key using the existing
  identity operation; size remains supplementary only.
- [ ] Focused tests, then four canonical gates; commit the two root fixes
  together after integration review.

Commit: `fix: bind tracing metadata and scan opens to live identities`

## Task 6: Capability tiers, diagnostics, and verdict honesty

**Files:**

- Modify: `src/doctor.rs`, `src/attach.rs`, `src/run.rs`, `src/render.rs`,
  `src/trace.rs`
- Modify: `tests/proc_access.rs`
- Modify: `scripts/verify-capability-tier.sh`
- Version, do not mutate: historical `FROZEN_CAPS` contract in
  `scripts/check-live-discovery-evidence.py`
- Modify: `docs/usage.md` and observed-profile-v3 schema/allowlist v2

Current anchors: `CAP_BITS` at `src/doctor.rs:37`, real BPF/attach probe at
`:223-290`, evidence/verdict at `src/render.rs:169,506`.

- [ ] RED: pure table-driven T0–T4 classification covers uid/capability,
  procfs/Yama/hidepid, non-dumpable target, real-program load/attach, and lease
  inputs; add CAP_DAC_READ_SEARCH bit 2. Do not claim CAP_SYS_RESOURCE or an
  RLIMIT_MEMLOCK requirement.
- [ ] GREEN: emit finite consumer-visible `tier`; reuse current doctor checks
  and real embedded program rather than a toy probe. Document losses per tier.
- [ ] RED/GREEN: distinguish evidence-backed seccomp denial from missing-
  capability denial without guessing from `EPERM` alone; retain unknown when
  origin cannot be proved. Surface bounded Aya verifier diagnostics on load
  failure without exposing target data.
- [ ] RED: for each discovery loss counter, serialize profile/metrics/terminal
  evidence and prove consumer verdict is `PARTIAL` exactly once.
- [ ] Update capability self-test and docs; privileged rows remain `UNRUN` if
  not authorized. Focused tests, then four canonical gates; commit.

Commit: `feat: report capability tiers and tracing degradation honestly`

## Task 7: `uprobe_multi` initial attach with safe fallback

**Files:**

- Modify: `src/attach.rs`, `src/discovery/engine.rs`, `src/render.rs`, `src/run.rs`
- Modify: `docs/schema/observed-profile-v3.md`,
  `docs/privacy/allowlist-v2.md`, `docs/usage.md`
- Modify: `tests/artifact_contracts.rs`, `scripts/verify-attach-e2e.sh`

Current anchors: registered-link ownership around `src/attach.rs:488`, static
attach transaction at `:734`, dynamic attach/detach at `:1450,1564`. Aya 0.14
has no public multi-attach API; `UProbe::fd()` is the retained safe seam.

- [ ] RED: UAPI layout/alignment/offset tests for one private 64-byte
  `BPF_LINK_CREATE` payload; checked count, aligned offsets/cookies, and exactly
  one `OwnedFd` owner.
- [ ] GREEN: group the initial plan by exact `{object, program}` and attach all
  return bundles before entry bundles. Count logical endpoints, not link FDs.
- [ ] RED/GREEN: only the first real preflighted `EINVAL`/`EOPNOTSUPP` selects a
  sticky per-offset fallback. `EPERM`, `EACCES`, identity/process errors, and
  errors after any successful multi link remain real failures.
- [ ] RED/GREEN: selective retirement closes the affected bundle, rechecks
  pins, reattaches surviving siblings per-offset, records the real gap as
  `PARTIAL`, and never orphans/double-attaches an endpoint. Later additions are
  per-offset.
- [ ] Add finite sorted `evidence.attach_mechanisms` containing only
  `uprobe-multi` and/or `per-offset`; authorize it in allowlist v2.
- [ ] Run unit/contracts and the unprivileged e2e self-test. Actual 5.15/6.6
  kernel attachment rows are privileged evidence and remain `UNRUN` unless
  authorized. Four canonical gates; commit.

Commit: `feat: attach initial probe sets with uprobe_multi`

## Task 8: W3 closeout and review to zero

**Files:**

- Create: `docs/superpowers/reports/2026-09-02-wave3-correctness-closure.md`
- Modify: `docs/superpowers/plans/ROADMAP.md`
- Modify: `CHANGELOG.md` only if its existing release convention requires it

- [ ] Run every unprivileged validator self-test and focused W3 test named in
  Tasks 1–7.
- [ ] Run the four canonical gates on the exact branch tip and record counts.
- [ ] Record privileged/container/VM rows as PASS, FAIL, or `UNRUN`; never
  inherit W1/W2 evidence.
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

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Package E subsequent performance work (sysplan/eperf) — report

Base: `32734cb` (D merge; D's writer stopped, `src/run.rs` available).
Branch: `sysplan/eperf` in worktree `p11scope/.worktrees/sysplan-eperf`.
Method: TDD RED→GREEN; Rust 1.88 `--locked --offline`;
`TMPDIR=/var/tmp/p11scope-ws-tmp`.

## Commits

- RED: `fc24b41` — `test: Package E FU-1/FU-2 pins + fork visit + E19/E20/FU-3 (RED)`
- GREEN: `fe2f867` — `feat: Package E tombstone + reducer/map work reduction (GREEN)`

Do not merge (per delegation).

## Scope checklist

- [x] FU-1: same-owner re-mint vs live tombstone (RED pin, GREEN fix)
- [x] FU-2: close/close-all vs live tombstone (RED pins, already correct)
- [x] FU-3: live-provider BPF confirmation fixture + gated cell
- [x] FU-4: finalize-drops-detached-ids preserved (no relaxation)
- [x] E19: first-hotspot selection, op-name + fused lookups, immutable snapshots
- [x] E20: fork grouping + visit-count tests + per-owner ledgers, no key/index change
- [x] E18: measured, no batch reads (fallback + final evidence preserved)
- [x] O-7 diagnostic-only, O-15 rejected (no test-only hot-path claim)

## RED evidence (tests fail)

- `semantics::corrective_tests::e20_fu1_same_owner_remint_on_live_tombstone_preserves_original`
  FAILED: `left: 259 (0x103), right: 257 (0x101)` — re-mint overwrote the
  tombstoned pending; want the original preserved (newcomer dropped).
- `semantics::corrective_tests::fork_visit_count_scales_linearly_not_quadratically`
  FAILED: `fork visited 120000 parent-op examinations for 600 ops; want <= 2000`.
- Pins passing in RED (existing correct behavior, retained as regressions):
  FU-2 reducer + history, E19 equivalence, E20 ledger, FU-3 fixture (live skips).

## GREEN changes (`src/semantics.rs` only, plus RED tests)

1. FU-1: same-owner `ASYNC_GET_ID` on a `collided` key drops the newcomer
   (pending already consumed), keeps the original pending/owner, counts
   `async_duplicates +1`. Non-collided same-owner re-mint still overwrites
   (existing countercontrol preserved).
2. E20 fork: group parent `active_ops` once by `SessionRef` (`BTreeMap`,
   ordered keys preserve per-session op order and stable output ordering),
   then inherit per session from its own group. Visit counter (test-only)
   now counts grouped visits.
3. E19: skip `String` allocation when an operation name is already recorded
   (`BTreeSet<String>::contains(&str)` borrows); fuse mechanism/cgroup/login
   admission probes with entry/insert (probe + one entry/insert, not three
   lookups). Admission-before-insertion preserved in every fused path; a
   refused cell counts nothing (mechanisms/cgroups/logins) or still records
   cgroup attribution where the old path did (`apply_operations`).
4. Preserved, explicitly not changed:
   - `Pending.meta: SlotMeta` stays an immutable owned snapshot (required
     for the `&mut` borrow split; no naked re-resolution).
   - Detached key/index structures unchanged (no new session index; ordered
     `BTreeMap` range processing retained; eviction stays bounded
     oldest-sequence single-victim).
   - `metrics.rs` batch reads not adopted (E18); `trace.rs` buffers unchanged.
   - Finalize/close/retire scope logic unchanged (FU-4).

## Measurements

### E19 — reducer allocations (first hotspot)

Selected first because every `*Init`/operational call pays op-name
allocation + mechanism/cgroup/login lookups, while `SlotMeta` clones are
required for immutable snapshots and the trace path is less frequent.

- Static: repeated op-name re-record goes from 1 `String` alloc/call to 0
  after the first (19,999 allocs avoided over 20k repeated Inits);
  mechanism/cgroup/login paths go from 3 BTree lookups to 2
  (probe + entry/insert-or-update); `param_combos` existing-key path from 2
  to 1 (`get_mut`).
- Dynamic (temporary 20k-repeated-`C_SignInit` bench, debug profile, shared
  lane, 3 reps each; scratch file removed before commit):
  - RED: 35.9ms, 36.1ms, 41.0ms (avg ~37.7ms; ~1.88µs/event)
  - GREEN: 34.4ms, 32.9ms, 42.2ms (avg ~36.5ms; ~1.82µs/event)
  - Delta ~3% (~0.06µs/event), within run-to-run noise on this lane (third
    reps elevated both sides); the `SlotMeta` clone dominates per-event cost
    and is intentionally preserved. Byte-equivalence and admission ordering
    are pinned by the full suite (below), not by this timing.
- Pass: byte-equivalent output/evidence (semantics 58/58, history 34/34,
  full suite green), admission ordering preserved, pseudonyms unchanged,
  immutable pending metadata preserved.

### E20 — fork visits + collision ledgers

- Visit counts (200 sessions × 3 ops = 600 ops, test-only counter):
  - RED: 120,000 examinations (200 × 600, quadratic scan-per-session)
  - GREEN: 600 examinations (one per grouped op, linear)
  - 200× reduction; bound `<= 2000` pins linear scaling alongside the
    existing `<2s` wall-time test (still passes).
- Deliberate-collision workloads drive every key/index decision: return
  pairing, close/finalize and delayed joins are checked against each
  workload's own ledger (`e20_collision_workload_ledgers_stay_independent`
  + history FU-1/FU-2 + existing `e20_*` matrix). No key/index structure
  was changed; ordered-key processing was evaluated and retained.

### E18 — metrics extraction (no change adopted)

- Current stable-map path remains `N + 2R + 10` BPF syscalls before
  auxiliary work (`metrics::read` + `kernel_evidence`), as documented in
  SYSTEM-EXPERIMENTS.md. Batch reads / changed frame snapshots were
  measured against the E18 pass criteria (final totals/evidence unchanged,
  supported-kernel fallback, labeled live snapshots) and not adopted:
  `metrics.rs` is untouched, kernel fallback and full final evidence are
  preserved. Metrics unit tests 6/6 green.

### O-7 / O-15

- O-7 kept diagnostic-only (no product change).
- O-15 test-only hot-path claim rejected (no change justified by test-only
  timing; the E19 dynamic cell above is reported as noise-bounded, not as
  a hot-path proof).

## FU-3 — live-provider BPF confirmation

- `tests/e20_live_collision.rs`:
  - `e20_fu3_trigger_pair_fixture_two_processes_share_one_provider`
    (unprivileged, always runs): two live tasks share one fixture inode,
    distinct PIDs, trigger-pair shape documented.
  - `e20_fu3_live_bpf_same_domain_collision_confirmation`
    (privileged-gated): documents the one-domain/two-task procedure,
    expected reducer evidence, and timing cells (unobserved control + 3
    reps, separate attach/drain/start/end/detach stamps); skips loudly
    without `P11SCOPE_LIVE_BPF=1`.
- Result: fixture passes; live cell skips on this lane (no BPF); reducer
  trigger pair remains pinned by `e20_f75_same_domain_*`.

## FU-4 — finalize condition

No relaxation: `retire_scope`/`clear_scope`/`scoped_detached` untouched.
`finalize_drops_its_own_processs_floating_async_ids`,
`one_processs_finalize_leaves_another_processs_async_state`,
`a_cross_process_join_moves_custody_off_the_previous_holder` and the
history finalize cells all pass (see full suite).

## Gates (Rust 1.88 `--locked --offline`, `TMPDIR=/var/tmp/p11scope-ws-tmp`)

- `cargo +1.88 fmt --check`: clean (exit 0, both commits).
- `cargo +1.88 clippy --locked --offline --workspace --all-targets`:
  zero warnings (exit 0, both commits).
- `cargo +1.88 test --locked --offline --workspace --no-fail-fast`:
  exit 0. 39 `test result` lines, all `ok`, zero failures:
  lib `1273 passed; 0 failed; 4 ignored`; `artifact_contracts` 129/129;
  `e20_live_collision` 4/4; every other integration binary plus all
  workspace members and doc-tests green.

Flake note (same GREEN tree, no tracked changes between runs): one
earlier fail-fast full run stopped in `artifact_contracts` on 3
load-sensitive Python canary/lane13 subprocess timeouts
(`metadata_canary_matrix`, `lane13_evidence_finalizes_only_after_owned_cleanup`,
`stopped_canary_capture_lifecycle`; 60–90 s timeouts over canary scripts
that never touch `src/semantics.rs`). Each passes solo on this tree
(59 s / 95 s / 193 s), all passed in the first full run, and all pass in
the definitive `--no-fail-fast` run above — flaky under full-suite host
load, unrelated to this change.

Targeted suites on GREEN: semantics 58/58, history 34/34, metrics 6/6,
trace 20/20, `e20_live_collision` 4/4 (live BPF cell skips loudly).

## Files

- `src/semantics.rs` (FU-1, fork grouping, E19 fusion, visit counter)
- `src/history_tests.rs` (plan +8/+9 Close slots, FU-1/FU-2 history pins)
- `tests/e20_live_collision.rs` (FU-3)
- `task-Eperf-report.md` (this file)

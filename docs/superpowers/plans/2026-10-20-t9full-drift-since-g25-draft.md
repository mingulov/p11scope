<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T9-full drift since the G25 refresh — DRAFT (pre-freeze analysis)

> **Status: DRAFT.** Read-only comparison for T9-full preparation. No
> live runs, no product changes. Base: `9db9ece1` ("docs: add v0.4.0
> Unreleased changelog section", last G25-freshness commit on the
> candidate line). Tip: `47292662` (`task/v040-t9prep`, shared with
> `v040-h7-object-wire`, `task/v040-matrix-stage`,
> `task/v040-stackfix-reproof`, `task/v040-t11-install`).
> `9db9ece1` is an ancestor of the tip; the range holds **30 commits**.
> Patch-equivalence below was checked with `git cherry` (minus =
> content already in tip, plus = pending).

## Landed in tip (30 commits)

### 1. Candidate line after the refresh (3 commits)

| Commit | Effect on schema surface |
| --- | --- |
| `fae7d426` bpf() syscall observation seam | `src/attach/identity_iter.rs` +38 (counter + test getter). Supports the D4 denial proof (`bpf_delta=0`); no verdict-shape change by itself. |
| `c716aee4` privileged 5.15 identity-denial cell | `src/inspect_system.rs` +161, `run-privileged-lib-tests.sh` +4. Emits the `IDENTITY_515_DENIAL` marker; curated 127/127 in the default campaign. |
| `e31f7aa9` bind denial cell to the release-matrix contract | `scripts/release-matrix-contract.py` +53 (`denial_outcome`, `identity:5.15-denied` judge row), `docs/qualification/release-matrix.md`, 5 hermetic tests. **Verdict enum extended (D4):** denied→`expected-refusal` on the 5.15.221 lane, eligible→`positive-coverage` elsewhere. |

### 2. Soak vehicle (10 commits, `6b6aa75d..f8bb9322`)

Cherry-pick of `task/v040-soak-runner` 9/9 (all minus) plus
integration-only `f8bb9322` (+x bit on the runner). New frozen
surface: soak oracle + verdict + receipts (D11, C4, C1-soak), three
manifest cells with seeded `test_ids`, `SOAK_SELECTORS` in the
verifier, `docs/testing/system-scope-soak.md`, suite registration
(`run-python-suites.py`, CI). Hardening commits (`d5fee75d`,
`23b20418`, `2d092ec9`, `a2a050da`) fail closed on malformed
evidence. No change to existing verdict enums.

### 3. DR37 dashboard/promotion round 2 (12 commits, `da4dcd11..46041593`)

Cherry-pick of `task/v040-dr37-activation` 12/12 (all minus).
Schema-surface deltas (E2/E3, C6):

- Dashboard is no longer read-only: `d` requests Detailed capture
  for the selected pair, `x` cancels (`docs/usage.md`,
  `src/inventory_dashboard.rs` +274, tests +491).
- Full-frame requirement scoped: only `d` needs a fully drawn
  frame; `x` works after shed/cut frames; both ignored on the gaps
  page (`98b49da9`).
- Promotion pipeline reworked: pre-view baselines, staged
  draw-commit, selected-caller coverage rule for baseline reuse,
  capture-lane acquisition, scheduler guards
  (`src/inventory.rs` +478, `promotion.rs` ±175,
  `selected_detailed/baseline.rs` +25).
- `feat/v040-dr37-native-seal` 7/7 also fully landed via
  cherry-pick (native CAS mint receipts, privileged full-loop cell
  curation). Note: its SHA `f111c20a` is NOT in tip history; the
  content is present under batch-8 SHAs.

Allowlist impact: none — DR37 stays inside the approved v3
surface; no allowlist file changed.

### 4. Clippy debt (5 commits, `31786485..47292662`)

Cherry-pick of `task/v040-clippy-debt` 5/5 (all minus):

- `31786485` mechanical lints (incl. `selected_detailed/wire.rs`,
  `attach/object_stop.rs`). No semantic change.
- `754e8f20` justified allows for staged/cold-path lints in 9
  files (baseline, finalizer, selected, joint_driver, …).
  Staged items are explicitly marked, not silently kept.
- **`b432f1b1` removal of staged items:** uncalled
  `tick_collected` (`src/semantic_capture.rs` −19) and
  `begin_with_effects` (`src/semantics_objects.rs` −12), zero
  references including tests. Covered paths use
  `tick_collected_with` and state `begin_with_effects`.
  **Freeze note:** this narrows — but does not settle — the open
  H8 seal-tick owner decision (tick vs tick_collected,
  drain/reader ownership). The freeze must record which tick
  entry is canonical; a later owner ruling the other way
  invalidates the tick boundary.
- `99ebfa63` promotion-test reorder + test-anchored
  staged-storage allow (test-only).
- `47292662` inline fixture init
  (`object_capture/tests.rs` ±6, test-only).

### 5. Explicitly unchanged since the refresh

- `docs/schema/*` and `docs/privacy/*`: **zero changes** in
  range (last touches `bab8e671`/`3a4c64ad`/`56f7a1f4`, all
  ancestors of the base). Presentation schemas and the
  allowlist are stable.
- Changed docs are limited to: `docs/usage.md` (DR37 keys),
  `docs/qualification/release-matrix.md` (denial lane),
  `docs/qualification/system-test-manifest.md` (soak
  selectors), new `docs/testing/system-scope-soak.md`.

## Pending (NOT in tip) — freeze blockers or deferrals

### P1. `task/v040-e17-midfinal`, 6 commits, all PLUS (pending)

Base `44a26ddb` (batch-8); worktree `v040-e17midfinal` clean at
`976330b2` (round 2 "fixing with 10s repro" has no new commits).
Touches only `src/discovery/engine.rs` (+264/−75 total with its
tests): `queue_retirement` no longer records fatal sticky
`GenerationLost` for stale reports the retained pin contradicts
or cannot judge — it defers with a partial mark and re-checks;
proven exits/reuse still retire (`ExpectedRemoval`).

**Yes — midfinal verdict-shape changes are pending.** The E17
`4M-file-midfinal` KNOWN `GenerationLost` expectation (matrix
rerun recipe concern #3) was never exercised on post-be69 bytes
and must be **re-derived after this lands**; freezing the old
expectation would pin a known-wrong outcome. T9-full entry
requires either landing midfinal first or an explicit
controller deferral with the cell marked provisional.

### P2. `fix/v040-g21-residuals`, 5 commits, all PLUS (pending)

Base `0cbe4f53`. Fixture/oracle-side only:
`src/inventory_privileged_tests/operator_diagnostics_wrap.rs`
(+577), `diagnostics-wrap-ledger.c`, `prepare-diagnostics-wrap.py`.
Adds `G21_WRAP_ROUND` markers, startup/pre-round quiesce gates
(20 s wall + 8/12 quiet commits), round-2 `k=0` verdict gating
and round-3 drain-before-stop. No product schema change, but the
G21 5-capture live leg (pid leg incl. the final-bytes
predicate) cannot pass without it. T9-full entry requires the
round-2 landing + live leg, or an explicit deferral.

### P3. BPF diet — ZERO commits; UNCOMMITTED work (blocker)

Branch `fix/v040-bpf-diet` tip is still `0e1599f6` (no commits).
The live work is uncommitted in worktree `v040-bpfdiet` (read-only
status check only; not disturbed):
`crates/ebpf-common/src/object_capture.rs` (348 changed lines),
`object_flow.rs` (+53), `crates/ebpf/Cargo.toml` (+2).
This edits the B4 capture-policy implementation — the same code
the verifier log implicates (`object_capture.rs` loop frames).
Until committed + reviewed + verifier-proven on 7.2.9 (and the
7.0.0-38 universal-cliff twin), **no matrix cell can run and no
freeze is meaningful**: diet bytes change the producer the
freeze would pin. Highest freeze risk; see checklist draft.

Not drift: `v040-h7-sweep-diet` (`5c7c143a`) is already an
ancestor of the base — pre-refresh work, not pending.

## Summary table

| Item | Since `9db9ece1` | Disposition |
| --- | --- | --- |
| Presentation schemas (A1–A8) | unchanged | ready to freeze |
| Privacy allowlist (F1–F3) | unchanged | ready to freeze |
| Release-matrix verdicts (D1–D4) | extended (denial lane) | landed; freeze as-is |
| Manifest + verifier (G, D5, C1) | soak selectors seeded | landed; freeze as-is |
| Soak oracle/vehicle (D11, C4) | new (10 commits) | landed; live run still open (T10) |
| Dashboard/promotion (E1–E3, C6) | reworked (12+7 commits) | landed; installed full-loop V4 still open |
| Clippy removals | `tick_collected`, `begin_with_effects` deleted | landed; record canonical tick entry at freeze |
| Midfinal verdict shape | pending (6 commits) | **blocker-or-deferral** |
| G21 round 2 | pending (5 commits) | **blocker-or-deferral** |
| BPF diet | pending (uncommitted) | **hard blocker** |
| G14 installed observer oracle | missing (`qualify-key-operations.py` absent) | land or record open |

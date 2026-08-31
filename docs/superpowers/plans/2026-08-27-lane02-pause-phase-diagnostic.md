# Lane 02 pause-phase diagnostic plan

Date: 2026-08-27

## Goal

Distinguish whether a 100 ms pause-epoch crossing is primarily associated with
budget already consumed before synchronous Engine entry, long synchronous
Engine work, or both. Select no product fix from mixed or missing evidence.

## Scope and invariants

- Start from production diagnostic commit
  `d30fa4451505157bb99283429d4ad02f70c452d2` and keep
  `CYCLE_NS = 100_000_000`.
- Implement and run this instrumentation only on a diagnostic descendant. Do
  not merge, tag, promote, or use it to amend a release gate.
- Change no deadline anchor, Engine API, attachment behavior, cleanup order,
  pause counters, public JSON, checker oracle, CLI, BPF ABI, or privacy
  allowlist.
- Emit exactly one bounded `pause_diag=` token for one failed Auto attempt and
  append exactly one token to one Always refusal. The new phase-classification
  tokens may encode only the frozen finite timing class; existing fixed
  non-timing diagnostics remain allowed. Diagnostic stderr/refusal never emits
  a raw/numeric timestamp or duration, PID/TID, path, address, digest, cookie,
  or process identity. Predeclared provenance hashes remain allowed in private
  `facts.log`.
- Preserve nested-collector, deadline-before-Engine, first-cause, terminal
  authority, authorization removal, and protective-resume precedence.
- Use four predeclared 100 ms campaigns. Never add or replace a run in response
  to results.

## Frozen classifier

Replace the private `deadline_during_engine_apply` token with exactly three
private variants:

| Rust variant | Exact token |
| --- | --- |
| `DeadlineDuringEngineApplyEntryLowApplyShort` | `deadline_during_engine_apply_entry_low_apply_short` |
| `DeadlineDuringEngineApplyEntryLowApplyLong` | `deadline_during_engine_apply_entry_low_apply_long` |
| `DeadlineDuringEngineApplyEntryHighApplyLong` | `deadline_during_engine_apply_entry_high_apply_long` |

The classifier runs only after the existing condition proves
`before_ns <= deadline < after_ns`.

```text
half_ns = CYCLE_NS / 2
remaining_ns = deadline - before_ns
elapsed_ns = after_ns - before_ns
entry_low = remaining_ns < half_ns
apply_long = elapsed_ns > half_ns
```

Exactly 50 ms remaining is high. Exactly 50 ms elapsed is short.
`entry_high_apply_short` is impossible after a strict crossing because elapsed
must exceed remaining. Missing clock samples retain the existing `None`; do
not add a generic fourth crossing token. `nested_collector_deadline` remains
first precedence and intentionally does not claim an entry/apply split.

## Task 1: RED tests

- [ ] Extend the existing classifier boundary table with:
  - `before=150_000_001`, `after=200_000_001`, `deadline=200_000_000` -> low/short;
  - `before=150_000_001`, `after=200_000_002`, `deadline=200_000_000` -> low/long;
  - `before=150_000_000`, `after=200_000_001`, `deadline=200_000_000` -> high/long;
  - exact-deadline, exact-half, missing-sample, missing-deadline,
    deadline-before-Engine, nested, and incomplete-within-deadline boundaries.
- [ ] Extend the bounded renderer test to cover all three exact tokens and
  require exactly one `pause_diag=` per line.
- [ ] Extend first-cause/reset and typed success/error/cleanup propagation tests
  with representative new variants. Preserve cleanup and authority call order.
- [ ] Add artifact-contract/self-test assertions for every new private evidence
  receipt in Task 3.

## Task 2: Minimum Rust diagnostic

- [ ] In `src/discovery/pause.rs`, replace the one unit enum variant with the
  three frozen variants and fixed token strings.
- [ ] In `classify_apply_diagnostic`, preserve this order:
  1. nested collector deadline;
  2. deadline before Engine entry;
  3. strict crossing classified by the frozen half-epoch table;
  4. incomplete outcome returned within the deadline;
  5. `None`.
- [ ] Use checked arithmetic only inside the proved ordering. Do not use
  saturating arithmetic that could hide malformed clock ordering.
- [ ] Do not change `PauseBatchOutcome`, `PauseBatchError`, coordinator storage,
  emission sites, apply call sites, or production flow.

## Task 3: Retained private receipts

- [ ] In `scripts/verify-task4-lane02.sh`, record `root_fresh=1` only after the
  existing absent/canonical/private checks and exclusive root creation succeed.
- [ ] Record a normalized semantic configuration SHA-256 after replacing only
  one occurrence of the exact evidence-root byte prefix with the fixed
  `EVIDENCE_ROOT` marker. Zero or multiple occurrences fail. Retain both the
  raw and normalized hashes and self-test the byte-exact normalization.
- [ ] Extend the existing exact executable-and-argv absence scan to cover the
  evidence-root `p11scope`, `harness`, and `harness-initial` binaries.
- [ ] After each row's existing observer, harness, pidfile, and atomic-temp
  checks pass, record `<row>.cleanup_exact_process_matches=0` and
  `<row>.cleanup_complete=1`.
- [ ] Repeat the exact absence scan after row 06 and record
  `cleanup_exact_process_matches=0` before `terminal_status`.
- [ ] Keep receipts in private `facts.log`; change no row result or checker
  predicate. A checker failure may retain a truthful cleanup-zero receipt. A
  failed cleanup scan records no false zero receipt and forces terminal
  non-pass even if all six row oracles passed.
- [ ] Durably write `root_fresh=1`, every row cleanup receipt, the final
  cleanup-zero receipt, and terminal facts before a root is comparable.

## Task 4: Verification and review

- [ ] Run focused pause and artifact-contract/self-tests.
- [ ] Run, one Cargo command at a time:

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
sh scripts/verify-task4-lane02.sh --self-test
python3 scripts/check-capture-evidence.py --self-test
git diff --check
```

- [ ] Require independent Sol, Terra, and Luna PASS before any live run.

## Task 5: Predeclared campaign

Use one reviewed diagnostic commit and these exact fresh roots, in order:

```text
/home/user/.local/state/p11scope/lane02-pause-phase-20260827/rep1-d100
/home/user/.local/state/p11scope/lane02-pause-phase-20260827/rep2-d100
/home/user/.local/state/p11scope/lane02-pause-phase-20260827/rep3-d100
/home/user/.local/state/p11scope/lane02-pause-phase-20260827/rep4-d100
```

- [ ] Run the unmodified six-row order in every root. Treat a whole campaign as
  the experimental unit; rows within a campaign are correlated. This order is
  standardized, not counterbalanced, because there is only one treatment.
- [ ] Attempt all four roots in the listed order even when an earlier driver
  exits nonzero. Every root must contain exactly six invocation receipts. Do
  not stop, add, replace, or rerun a campaign in response to its result.
- [ ] Retain commit/tree, exact diagnostic diff, binary/module/driver/checker/
  harness/expected/config hashes, six row commands/results, bounded tokens,
  root freshness, row cleanup, and final exact-process absence receipts.
- [ ] Require identical commit, tree, binary, module, driver, checker, both
  harnesses, expected oracle, and normalized semantic-configuration hashes
  across all four roots. Any divergence makes the set incomparable/mixed.
- [ ] Treat initial-set rows as controls. Product inference comes only from the
  predeclared target `05-dlopen-auto` across all four campaigns. Other rows are
  safety/control evidence and cannot be substituted for the target row.
- [ ] Do not reuse the prior 100/500 ms roots as a result or add a 500 ms arm.

## Frozen decision rules

- Four-of-four target-row `entry_low_apply_short`: investigate reducing
  pre-Engine work.
- Four-of-four target-row `entry_high_apply_long`: investigate isolating or pre-staging
  Engine work before considering checkpoints.
- Four-of-four target-row `entry_low_apply_long`: both phases are
  material; select no single product fix.
- Four-of-four target-row `nested_collector_deadline`: the collector is the first
  target, but this diagnostic selects no timeout, anchor, or checkpoint change.
- A target-row PASS, refusal, generic/fallback token, missing token, missing
  receipt, or category/result difference across the four campaigns is an
  explicit contradiction. Any contradiction, fewer than four comparable
  campaigns, or a cleanup/privacy failure is mixed/unresolved and selects no
  product fix.

The four-of-four rule deliberately preserves the prior campaign's requirement
that matching rows agree across every repetition. A lower threshold is rejected
because it could select a product direction while another predeclared campaign
contradicts it.

## Task 6: Close the diagnostic descendant

- [ ] Require independent Sol, Terra, and Luna review of all four finalized,
  unamended roots and the decision-rule application. The roots remain mutable
  caller-owned files; lack of a cryptographic seal is a retained limitation.
- [ ] Record confirmed, inferred, contradicted, and missing evidence in the
  Lane 02 decisions report and the osslscope lessons report.
- [ ] Remove the diagnostic worktree and branch after review. Retain only its
  unmerged commit hash and private evidence roots.
- [ ] Implement no product change unless one frozen decision rule selects the
  next investigation target and a separately reviewed product plan is approved.
- [ ] Constrain the diagnostic descendant's tracked diff to
  `src/discovery/pause.rs`, `scripts/verify-task4-lane02.sh`,
  `tests/artifact_contracts.rs`, and this plan. The decisions/lessons reports
  are updated only after evidence review.

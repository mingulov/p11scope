# Lane 02 Pause-Epoch Diagnostic Plan

> **For agentic workers:** use `superpowers:subagent-driven-development` and TDD. This plan diagnoses; it does not select a production timeout.

**Goal:** Retain one privacy-safe finite reason for every silent `--pause auto` partial and distinguish post-release incompleteness from work that crosses the hook-derived 100 ms epoch.

**Architecture:** Change only `src/discovery/pause.rs`. Preserve cleanup, authority, counters, the 100 ms production constant, public JSON, CLI, checker, and privacy allowlist. Add bounded stderr/refusal tokens and observational before/after samples around the existing synchronous Engine apply. Compare the reviewed 100 ms diagnostic build with a separate one-line 500 ms diagnostic branch.

## Invariants

- No Engine API, checkpoint, cancellation, deadline enforcement, or attachment behavior changes.
- Diagnostic clock failures are ignored and never affect capture.
- No path, PID/TID, object/provider identity, address, cookie, raw timestamp, or duration is emitted.
- Every Auto partial emits exactly one token from a fixed private enum.
- Always retains the same category in its existing refusal path without changing cleanup order.
- The 500 ms descendant is diagnostic-only and must never be merged, promoted, tagged, or used to amend a gate.

### Task 1: Surface every silent Auto partial

**File:** `src/discovery/pause.rs`

- [ ] Add private `PauseDiagnostic` tokens for:
  - `arm_failed_before_epoch`
  - `post_release_revalidation_incomplete`
  - `pause_helper_rejected`
  - `deadline_before_engine_apply`
  - `deadline_during_engine_apply`
  - `engine_incomplete_within_deadline`
  - `nested_collector_deadline`
  - `later_pause_boundary`
  - `other_auto_nonconfirmed`
- [ ] Add one pure bounded renderer producing only `p11scope: pause: partial [pause_diag=<token>]`.
- [ ] Add one coordinator-owned `Option<PauseDiagnostic>`, reset at attempt boundaries and set with first-cause precedence. No diagnostic state lives in Engine or public evidence.
- [ ] Centralize every recognized fixed pause/deadline message as a private constant; do not scatter substring literals.
- [ ] At the two sites that increment `PauseCounters.partial`, emit exactly one bounded line:
  - `arm_failed` uses `arm_failed_before_epoch`.
  - `finish_nonconfirmed` uses the already classified primary reason.
- [ ] Tag before the policy split:
  - `arm_failed` -> `arm_failed_before_epoch`;
  - fixed post-release incomplete -> `post_release_revalidation_incomplete`;
  - `reject_cycle` -> `pause_helper_rejected`.
- [ ] Before `finish_nonconfirmed` or Always terminal cleanup, assign `other_auto_nonconfirmed` only when no explicit category exists. Append one bounded token to the existing Always primary message; Auto emits only the bounded line, never the dynamic original reason.
- [ ] Exhaustive source table: the three pre-policy paths above use their exact tokens; apply and later-boundary paths use Task 2 tokens; every other non-lifecycle `fail_cycle` source uses `other_auto_nonconfirmed`; lifecycle failures keep lifecycle semantics and may use the same bounded fallback without becoming Auto partial.

### Task 2: Classify the synchronous Engine apply boundary

**File:** `src/discovery/pause.rs`

- [ ] Extend private `PauseBatchOutcome` with `diagnostic: Option<PauseDiagnostic>` and add a private `PauseBatchError { message, diagnostic }`; change only the private `PauseIo::apply_batch` result type. This typed result is the sole failed-apply category path—do not parse an appended token.
- [ ] Update all four constructors: production apply, production revalidation, fake apply, and fake revalidation. Every non-primary-apply constructor uses `diagnostic: None`.
- [ ] Immediately before and after `Engine::apply_discovery_batch_with`, take optional monotonic samples.
- [ ] Pure precedence:
  1. exact existing nested-dequeue deadline text -> `nested_collector_deadline`;
  2. before > deadline -> `deadline_before_engine_apply`;
  3. before <= deadline and after > deadline -> `deadline_during_engine_apply`;
  4. required incomplete and after <= deadline -> `engine_incomplete_within_deadline`;
  5. otherwise no apply category.
- [ ] Samples are observational only; never return early because they cross the deadline.
- [ ] On Engine error, return the existing message plus its typed optional category. Exact centralized nested-dequeue messages select `nested_collector_deadline`; no new collector error type is added.
- [ ] The coordinator adopts an apply outcome/error category only when it has no earlier category. After a successful apply, preserve it when fixed stopped/dequeue/resume deadline messages fail; absent an earlier category, use `later_pause_boundary`.
- [ ] At every wrapper—ordinary/unowned apply, accepted-cycle apply, and failure-cleanup apply—adopt `PauseBatchError.diagnostic` before converting or aggregating its message. Cleanup errors never overwrite an earlier category and never cause a second emission.

### Task 3: TDD and canonical verification

**File:** `src/discovery/pause.rs`

- [ ] RED then GREEN tests for:
  - Auto arm failure keeps `attempts=1, partial=1`, disables rearming, and selects `arm_failed_before_epoch`.
  - Auto post-release incomplete returns `Ok`, keeps the counter lattice, and selects `post_release_revalidation_incomplete`.
  - Always arm failure, helper rejection, post-release incomplete, and apply/boundary failure retain their categories and unchanged remove/resume/detach order.
  - Every silent source maps to one fixed category; unknown input maps only to `other_auto_nonconfirmed`.
  - Every enum variant renders one exact complete line containing exactly one `pause_diag=` and no original dynamic error text.
  - Apply-boundary precedence, strict `>` behavior, missing samples, and successful within-deadline `None`.
  - Both exact nested deadline strings map to `nested_collector_deadline`; unrelated errors do not.
  - Later fixed deadline messages retain an earlier apply category or select `later_pause_boundary`; unrelated errors remain unchanged.
  - Successful apply, failed apply, and failure-cleanup apply preserve primary-category precedence and existing cleanup/authority ordering despite the two observational clock reads.
  - Attempt reset occurs before first-category assignment; emission clears the pending category so it cannot leak into a successor attempt.
- [ ] Run:

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
sh scripts/verify-task4-lane02.sh --self-test
python3 scripts/check-capture-evidence.py --self-test
git diff --check
```

- [ ] Require independent Sol, Terra, and Luna PASS before committing the one-file diagnostic.

### Task 4: Diagnostic-only 100 ms / 500 ms A/B

- [ ] Predeclare four matched campaign pairs with counterbalanced order `A/B`, `B/A`, `A/B`, `B/A`; every run uses a fresh immutable root. Do not adapt sample count or order to results.
- [ ] Create a separate worktree and descendant commit whose only diff from A is:

```rust
const CYCLE_NS: u64 = 500_000_000;
```

- [ ] Prove the A/B diff is exactly that one line and record both commit/binary hashes.
- [ ] Run all eight campaigns with the same fixture, module, config, kernel, checker, command, and row order. Retain hashes for the fixture/harness, module, config, checker, command receipt, commit, and binary in every root; never compare categories to an older non-diagnostic campaign.
- [ ] Interpret:
  - post-release/arm/helper categories at both bounds -> timeout is not the cause;
  - 100 ms apply/nested/later-boundary category and 500 ms confirmation -> epoch sensitivity isolated. Confirmation means the same row passes its exact attachment/count oracle with `confirmed == attempts`, `partial == 0`, and no refusal;
  - incomplete-within-deadline at both -> timeout increase is insufficient;
  - mixed categories -> retain variance and select no single product fix.
- [ ] Require the same per-row result across all four matched pairs before selecting a hypothesis; otherwise use the mixed-variance outcome. Treat empty-catalog initial-set evidence as a control and infer epoch sensitivity only from matching pause-attempt rows.
- [ ] Sol, Terra, and Luna independently review immutable evidence before any product policy decision.
- [ ] Remove the B worktree after review; retain its commit hash only in the evidence/report. Do not merge the 500 ms commit.

## Acceptance

- The implementation commit changes only this plan and `src/discovery/pause.rs`.
- Public JSON/checker/privacy contracts are unchanged; only stderr/refusal gains one bounded token on a failed pause attempt.
- Cleanup, terminal authority, partial counters, and resume behavior are unchanged by tests and review.
- The A/B evidence selects a branch or explicitly leaves the hypothesis unresolved; it never promotes the diagnostic 500 ms value.

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Environmental test failure signatures

These signatures were recorded in September 2026 and identify cases that
have failed intermittently under parallel suite load. Some also failed in
isolation. They are diagnostic history, not evidence that a new failure is
harmless or that the current revision passes. The
[quarantine mapping](test-quarantine.md) names the exact maintained selectors.

## Triage protocol

1. Preserve the original failed run, source revision, build profile, test
   binary, host load and error text. Do not replace a red result with a later
   green log.
2. Run the exact failing selector serially with the same binary/profile.
   Use the private disk-backed `TMPDIR` described in
   [contributor verification](../../CONTRIBUTING.md#verification). For a new
   build, use the pinned repository wrapper and prepared dependencies.
3. Compare a pristine baseline when the cause is ambiguous. A matching
   failure can establish that the regression predates the change, but a
   pass in isolation alone does not establish the cause.
4. Match the actual mechanism to the signature. Retain assertion strength,
   test inventory and bounded deadlines. Fix a demonstrated causal race;
   do not increase budgets merely to make a run green.

## Recorded signatures

| Exact selector | Target | Signature |
| --- | --- | --- |
| `lane13_evidence_finalizes_only_after_owned_cleanup` | `artifact_contracts` | Readiness/deadline race: `setup-ready-timeout`, original exited before return, or a decoy still live. This is a long-running fixture; a “running for over 60 seconds” notice alone is not failure. |
| `metadata_canary_matrix` | `artifact_contracts` | Rotating canary subtest errors under load, including `test_json_acquisition_deadline_includes_exit_after_pipe_eof` with a missing `eof-child.pid`. Preserve the failed native subtest and pidfile/custody evidence. |
| `stopped_canary_capture_lifecycle` | `artifact_contracts` | `test_owned_missing_capture` expected a phase deadline but received a readiness `CustodyError` and custody-close `CleanupError`s. Preserve both the original failure and cleanup outcome. |
| `native_helper_suite_recorded_launcher_requires_authenticated_generations_and_bounded_cleanup` | `artifact_contracts` | Rotating `RecordedLauncherTests` deadline, acknowledgement and cleanup failures; `pidfd-open-gone` after a recorded-launch deadline is one recorded form. |
| `actual_handoff_helpers_preserve_errno_and_retry_without_renewing_deadlines` | library | `Instant::now() < reap_deadline + Duration::from_millis(100)` exceeded under parallel load. The deadline is the contract; an isolated pass does not justify renewing it. |
| `release_seal_denies_the_caller_path_to_every_reached_command` | `artifact_contracts` | Missing `sealed-environment` artifacts, empty output where `sudo` was expected, and related Cargo-home/sysroot closure failures in the same run. |
| `signal_settlement_observes_second_sigint_during_fallback_term_grace` | library | Signal settlement returns `Err(Deadline)` while coordinating SIGINT/SIGTERM across threads. Retain the signal and cleanup sequence when investigating. |

The quarantine lane runs these selectors once, serially, after any failed
check job (`lint`, `audit`, `tests`, a `contracts-N` shard or `scripts`).
It is supporting evidence only: a green quarantine result
never makes the failed workflow pass.

## Live-cell signatures

These failures come from Docker live cells
(`scripts/docker-*-e2e.sh` with `scripts/container-cells-oracle.py`),
not from the Cargo suites, so they carry no test selector or
quarantine entry. The triage protocol above still applies: preserve
the failed evidence directory, rerun the exact cell serially, compare
a pristine-base run with the same selector, and match the mechanism
before calling a rerun green.

### `D1-span-flip-race` (D1 shared-layer cell, span loss gate)

- Signature: the span-kernel evidence carries a pid-less
  `maps attribution` gap,
  `processes mapping pinned provider objects were not attributed to
  them: N identity_mismatch ...` with repeats=P (observed N=2,
  P in 8..13), and the exact span gate
  (`assert not has_identity_loss(span_kernel["gaps"])`,
  `identity loss in span`) refuses it.
- Mechanism: the overlay collapse direction inverts between span
  passes (both `(98 -> 82)` and `(82 -> 98)` collapse gaps in one
  span, that order); a fraction of inverted spans also lose per-process
  attribution for pinned providers. Not yet shown to predate the
  lane: no base span has tripped, and the lane touches the
  admission path (`identity.rs` pair admission, attach-set `by_raw`
  routing), so a lane contribution is not ruled out. In every trip
  the copy-up branches are cold — `anchor_not_installed`,
  0 `pre_copy_up` markers, 0 witness-proven rows, 0 refused lower
  candidates — which bounds but does not settle the question.
- Rates (2026-11-07, dev Docker,
  `--iters-a 400 --iters-b 250 --duration 30 --span 90`): tip
  Saturday-morning 3/7 spans trip (all 7 invert); tip
  Saturday-evening 0/2 (stable direction); base Saturday 0/14
  spans trip, 3/14 invert (evening base 0/8, stable, exact parity
  with tip-evening). The R2 base spans r2-r14 ran the release
  observer (only r1 ran debug); the trip tally is exact.
- Base-hit status: A/B RUNNING (interleaved tip/base release runs
  on the quiet fedora host, same harness fix, ~10 each, stop at
  first base trip; outcome lands below when the batch completes).
- Disposition: named flake; the span gate stays exact. A rerun that
  trips must be preserved and retried serially, never averaged away.
  Future work (out of scope): collapse-order determinism across span
  passes.

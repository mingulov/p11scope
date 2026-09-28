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

The quarantine lane runs these selectors once, serially, after a failed
primary job. It is supporting evidence only: a green quarantine result
never makes the failed workflow pass.

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Flake quarantine mapping (SYSPLAN residual F-29)

The seven ledgered flakes from
[`known-flakes.md`](known-flakes.md), each with its owning lane, its
isolation, and how to triage it. Nothing here weakens a test: the main
suite runs every flake unfiltered, and the quarantine lane
(`scripts/run-flake-quarantine.sh`, CI `quarantine` job, failure-gated)
re-runs each exactly once, serially, as triage evidence. A green
quarantine run never greens the workflow.

Isolation applied to all seven: serial execution (one test at a time, no
lane-parallel siblings), exact `--exact` filters (no neighbor tests in the
binary run), `--test-threads=1`, and a private `CARGO_TARGET_DIR`
(`target/quarantine`, separate from the main build, so build IO never
contends with a running lane).

| # | Flake (filter) | Owning lane | Wall-clock isolation |
|---|---|---|---|
| 1 | `lane13_evidence_finalizes_only_after_owned_cleanup` (`--test artifact_contracts`) | knative receipt lane | Serial: never lane-parallel (the ledgered constraint); private target dir removes build-IO contention with the knative lane. |
| 2 | `metadata_canary_matrix` (`--test artifact_contracts`) | metadata canary matrix | Exact filter + serial: the matrix no longer shares a runner with sibling matrix cells. |
| 3 | `stopped_canary_capture_lifecycle` (`--test artifact_contracts`) | stopped-canary lifecycle lane | Exact filter + serial: lifecycle timing (stop/settle windows) runs alone. |
| 4 | `native_helper_suite_recorded_launcher_requires_authenticated_generations_and_bounded_cleanup` (`--test artifact_contracts`) | native helper suite | Exact filter + serial: launcher generation/cleanup bounds run without sibling load. |
| 5 | `actual_handoff_helpers_preserve_errno_and_retry_without_renewing_deadlines` (`--lib`) | run-lane handoff unit tests | `--test-threads=1` + serial: retry-deadline assertions run without lib-test parallelism. |
| 6 | `release_seal_denies_the_caller_path_to_every_reached_command` (`--test artifact_contracts`) | release-seal lane | Exact filter + serial: caller-path denial runs without sibling lane load. |
| 7 | `signal_settlement_observes_second_sigint_during_fallback_term_grace` (`--lib`) | signal-settlement unit tests | `--test-threads=1` + serial: SIGINT-during-grace timing runs alone. |

Triage: run `scripts/run-flake-quarantine.sh` locally (needs the pinned
1.88 toolchain and prepared dependencies, like `cargo test`). If a flake
fails in isolation too, it is a real regression, not contention — file it
against the owning lane with the quarantine log. If it passes in isolation
but fails in the suite, the contention window narrowed: keep the ledger
entry, do not raise budgets — the budgets are the contract.

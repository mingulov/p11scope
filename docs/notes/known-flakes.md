# Known environmental test flakes (created 2026-09-18, profiling-fixes Task 3)

Full-workspace runs fail ~1 test/run; each entry below is green in
isolation (at least one green single-test run on record), green on other
full runs, and — where a pristine-base comparison was run — identical on
the base tree. Same code, different result ⇒ load/timing flakes, not
logic breaks.

Log pointers in `$TMPDIR` (`/var/tmp/p11scope-ws-tmp/`, uncommitted
scratch from the usability, refactor-queue, and shebang-gate plans) are
named per file so a future triager can match signatures; the committed
profiling-fixes Task 2 gate logs
(`.superpowers/sdd/2026-09-17-profiling-fixes/gates-task2/`) carry entries
5–6 plus fresh isolation evidence for entries 1–3.

## Triage protocol (every entry)

1. **Isolate** — re-run the single test alone:
   `TMPDIR=/var/tmp/p11scope-ws-tmp cargo +1.88 test --locked --offline
   --test artifact_contracts -- <name>` (`--lib` for entry 5). Green ⇒
   load flake; record the log.
2. **Pristine-base compare** — if isolation is red or ambiguous, run the
   same filter on a pristine `git archive HEAD` tree (+ gitignored
   `third-party/src/` copied in). Base-identical behavior exonerates the
   branch.
3. **Never weaken** — no assertion softening, no suite shrinking, no gate
   changes. A red full run needs per-failure triage (isolate + base +
   mechanism match to a signature below) before any code conclusion.

## 1. `lane13_evidence_finalizes_only_after_owned_cleanup` (artifact_contracts)

- **Signature:** readiness/deadline race —
  `setup-ready-timeout: outer exit=1; original exited before return;
  decoy live`; long-runner (200–270 s; "running for over 60 seconds"
  notices while healthy).
- **Evidence:** full-run reds in `usability-t5-run1.log`,
  `usability-t5-run2.log`, `refactor-t7-1.log`, `refactor-t7-gate1.log`,
  `refactor-t7-gate2.log`, `shebang-gate2.log`, `gate-iso-artifact.log`
  (full artifact target), `gate-run-D.log`. Green in isolation:
  `usability-t5-iso-lane13b.log` (271 s), pristine-base
  `usability-t5-base-lane13.log` (253 s),
  `gate-iso-lane13_evidence_finalizes_only_after_owned_cleanup.log`
  (205 s); Task 2 `gates-task2/isolate-lane13.log` (229 s, run-2-only
  failure). One isolation attempt (`usability-t5-iso-lane13.log`) was
  itself red — intermittent even alone, which is the point: timing, not
  code.

## 2. `metadata_canary_matrix` (artifact_contracts)

- **Signature:** rotating subtest failure inside the wrapped
  `scripts/verify-canaries.sh --self-test` (60 s timeout harness, panic
  at `tests/artifact_contracts.rs:1187`) or the native 64-bit canary run
  (`:6321`). Observed instance: `ERROR:
  test_json_acquisition_deadline_includes_exit_after_pipe_eof ...
  FileNotFoundError: .../eof-child.pid` — a pidfile race under load.
- **Evidence:** full-run reds in `usability-t5-run1.log`,
  `usability-t5-run2.log`, `refactor-t7-1.log`, `refactor-t7-gate1.log`,
  `shebang-gate2.log`, `gate-run-D.log`, `gate-iso-artifact.log`. Green
  in isolation: `usability-t5-iso-metadata.log` (107 s); Task 2
  `gates-task2/isolate-metadata-canary.log` (94 s, run-2-only failure).
  Red in `gate-iso-metadata_canary_matrix.log` (96.92 s) — intermittent
  even alone.

## 3. `stopped_canary_capture_lifecycle` (artifact_contracts)

- **Signature:** rotating subtest FAIL in `StoppedCanaryCaptureTests`,
  e.g. `FAIL: test_owned_missing_capture`. Failing in run 3 after
  passing isolation is the textbook load-flake signature.
- **Evidence:** full-run reds in `usability-t5-run1.log`,
  `gate-run-C.log`, `gate-run-D.log`. Green in isolation:
  `usability-t5-iso-stopped.log` (63 s); Task 2
  `gates-task2/isolate-stopped-canary.log` (56 s; failed full runs 2
  AND 3).

## 4. `native_helper_suite_recorded_launcher_requires_authenticated_generations_and_bounded_cleanup` (artifact_contracts)

- **Signature:** rotating FAIL/ERROR across `RecordedLauncherTests`
  deadline/ack/cleanup subtests — different subtests each run
  (`test_correct_ack_consumed_after_deadline_cannot_exec`,
  `test_split_ack_interruption_cleans_up_original_launcher_handle`,
  `test_missing_root_self_resumed_after_deadline_never_enters_target`,
  `test_authenticated_adoption_reaps_only_pinned_orphan`, …). The
  rotation itself is the signature.
- **Evidence:** full-run reds in `usability-t5-run1.log`,
  `refactor-t7-2.log`, `shebang-gate2.log`, `gate-run-D.log`; green in
  18 other logs including the full artifact target
  (`gate-iso-artifact.log`, where two *other* ledgered tests failed —
  failures are independent). Isolation runs are intermittent too
  (`usability-t5-iso-recorded.log` and pristine-base
  `usability-t5-base-recorded.log` both red with *different* subtests),
  which exonerates the branch by base-identical behavior.

## 5. `run::tests::actual_handoff_helpers_preserve_errno_and_retry_without_renewing_deadlines` (lib; new in Task 2)

- **Signature:** 100 ms timing budget exceeded under parallel load:
  `assertion failed: Instant::now() < reap_deadline +
  Duration::from_millis(100)` at `src/run.rs:4455`.
- **Evidence (committed):**
  `gates-task2/full-suite.log` (Task 2 run 1 only),
  `gates-task2/isolate-handoff.log` (PASS, 0.01 s),
  `gates-task2/base-handoff.log` (pristine-base PASS).

## 6. `release_seal_denies_the_caller_path_to_every_reached_command` (artifact_contracts; new in Task 2)

- **Signature:** several `ReleaseSealTests` subtests FAIL/ERROR at once
  under parallel load — seal-env artifacts missing or raced:
  `FileNotFoundError: .../p11scope-release-seal-*/case/sealed-environment`,
  `AssertionError: '' != 'sudo\n'`, plus cargo-home-closure and
  sysroot-closure subtests in the same run.
- **Evidence (committed):**
  `gates-task2/full-suite-retry.log` (Task 2 run 2 only),
  `gates-task2/isolate-release-seal.log` (PASS, 55 s),
  `gates-task2/base-release-seal.log` (pristine-base PASS).

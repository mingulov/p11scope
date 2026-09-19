<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# RT_ADD deferral implementation report

## 2026-09-13 — governing review and initial state

- Read `BRIEF.md` in full, including all six CONTROLLER RULINGS, then
  `.superpowers/sdd/w7-continuation-2026-09-12/HOUSE-RULES.md` in full, then
  only `DESIGN.md` section 2 (lines 83–116), in the controller-requested order.
- `BRIEF.md` says to read HOUSE-RULES first, while the controller explicitly
  required BRIEF first. I followed the controller's higher-priority order.
- The implementation will preserve loader-event authentication, accounting,
  exact-context validation, and export-hook arming. Only bounded memory-scan
  scheduling changes: authenticated `announced_count` 1/2 queues coalesced
  pending work keyed by view plus loader context; zero is only a scan
  opportunity; every terminal path must settle pending work explicitly.
- The existing maps-A/maps-B bracket from e1c2002 and frozen constants,
  including `VERSION_SHAPE_SCANNED == (988, 104, 208)`, are out of scope and
  will not be changed.
- Worktree started at detached HEAD `59195b8`. Pre-existing untracked inputs:
  `BRIEF.md` and `DESIGN.md`. `REPORT.md` did not previously exist.
- No tests had been run and no production files had been changed at this
  checkpoint.

## 2026-09-13 — RED setup and rejected attempts

- Added eight `rt_add_deferral_` mutation tests beside the real loader batch
  route in `src/discovery/engine.rs`, plus inert pending-ledger and test-only
  memory-scan observation fields. The old unconditional loader scan remained
  unchanged for RED.
- First focused command attempted:
  `mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope --lib -- rt_add_deferral_`.
  It did not execute tests because dependency preparation could not download
  `https://static.crates.io/crates/aya/aya-0.14.0.crate` under restricted DNS.
  There was no `test result:` line, so this attempt is UNRUN, not RED.
- Root cause: this worktree had no reconstructed ignored dependency trees and
  the wrapper always invokes `scripts/prepare-dependencies.py`; Cargo's cache
  already held both pinned archives. Their SHA-256 values matched
  `third-party/sources.json`, and
  `python3 -I scripts/prepare-dependencies.py --archive-dir /home/user/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f`
  reconstructed the ignored trees successfully without installation or
  network access.
- The next focused attempt reached compilation but called private
  `LoaderDiscovery::complete`; no tests executed and there was no
  `test result:` line. I corrected the test to assert the public timing and
  state-read-failure fields directly.
- The first executed suite printed:
  `test result: FAILED. 1 passed; 7 failed; 0 ignored; 0 measured; 974 filtered out; finished in 0.51s`.
  I rejected it as the canonical RED because
  `rt_add_deferral_next_tick_falls_back_once_without_record_replay` was a false
  positive: the unfixed immediate scan satisfied its end-state assertions. I
  added pre-fallback assertions requiring one pending item and zero memory
  scans before the independent tick.

## 2026-09-13 — accepted mutation-first RED

- Focused command actually run on unfixed behavior:
  `mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope --lib -- rt_add_deferral_`
- Positive control: Cargo printed `running 8 tests`; every intended mutation
  test executed.
- Literal result line:
  `test result: FAILED. 0 passed; 8 failed; 0 ignored; 0 measured; 974 filtered out; finished in 0.38s`
- Literal decisive failures included:
  - authenticated ADD expected zero immediate memory scans but got
    `left: 1`, `right: 0`;
  - next-tick fallback expected one pending item before the tick but got
    `left: 0`, `right: 1`;
  - the state table at `r_state=1, read_failures=0` expected one pending item
    but got `left: 0`, `right: 1`;
  - exit, context retirement, budget exhaustion, and cancellation/shutdown
    found no `live loader memory discovery` unresolved-loss record.
- This is the canonical RED. The earlier dependency/compile attempts and the
  rejected 1-pass/7-fail run are not represented as behavioral RED evidence.

## 2026-09-13 — matching GREEN for the RT_ADD mutation group

- Implemented the deferral in `src/discovery/engine.rs` and the metadata-only
  scan entry point in `src/discovery/scan.rs`.
- Re-ran the exact focused RED command without changing its filter:
  `mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope --lib -- rt_add_deferral_`.
- Positive control: Cargo printed `running 8 tests` and named all eight
  `rt_add_deferral_` tests as `ok`.
- Literal result line:
  `test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 974 filtered out; finished in 0.53s`
- The recurring mise tracked-config warning is environmental: the sandbox
  cannot create a symlink below `/home/user/.local/state/mise`. It did not
  prevent compilation or test execution.

## 2026-09-13 — implementation by file and line

- `src/discovery/engine.rs:109,156-177` adds a bounded private pending ledger
  keyed by exact `ProcessViewId` plus `LoaderContextId`; duplicate hits retain
  the earliest hook timestamp. No pending identity crosses the render boundary.
- `src/discovery/engine.rs:6789-6847` provides metadata-only orchestration,
  bounded insertion/coalescing, and explicit counted settlement. Each settled
  pending item increments the existing live-discovery loss accumulator even
  when public skip prose deduplicates.
- `src/discovery/engine.rs:6989-6994` settles work created during a cancelled
  capture-start attempt instead of restoring over it silently.
- `src/discovery/engine.rs:8059-8278` separates the already-validated loader
  transaction from record authority. The metadata-only form preserves existing
  accepted tables/interfaces for unchanged exact modules while refreshing
  current mappings, pins, export symbols, and export hooks. The full form uses
  the unchanged bracketed memory scan.
- `src/discovery/engine.rs:8284-8478` implements the state table: 1/2 defer
  after authentication; zero consumes matching pending work as an opportunity
  and performs a full scan. The handler has no early return before export work.
- `src/discovery/engine.rs:10237-10244,10615-10770,10809-10836` settles pending
  work at cancellation/shutdown, exact context removal, expected exit, exec
  refresh, and generation loss.
- `src/discovery/engine.rs:12199-12268` snapshots only work already pending at
  outer-batch entry and gives it one fallback later in that independent tick.
  New ADD/DELETE work cannot fallback in its creation tick, and the fallback
  calls the validated scan transaction directly rather than replaying a record
  or consuming producer-counter authority again.
- `src/discovery/engine.rs:20982-21152` contains the eight mutation-first tests
  covering the required state, accounting/hook, fallback, duplicate, exit,
  retirement, budget, and cancellation/shutdown lanes.
- `src/discovery/scan.rs:1598-1679` adds the metadata-only entry point. It still
  acquires maps A, inventories and pins exact ELF/export facts, acquires maps B,
  validates dependencies, and performs the final generation check. Only the
  `/proc/<pid>/mem` open/table reads are postponed. The ordinary full-scan path
  still selects the pre-existing behavior, and the maps bracket/refusal logic
  itself is unchanged.
- `docs/superpowers/specs/2026-08-18-slice1b2-corrective-live-discovery-design.md:545-559`
  amends §7.1 as authorized.

## Exact §7.1 text amended

> For every accepted hit, userspace revalidates the process generation and exact
> loader context, refreshes mappings, pins new candidate objects, and attaches
> exact standard export symbols available from the pinned ELF. A reported
> `RT_ADD` or `RT_DELETE` (`r_state` 1 or 2) marks bounded memory discovery
> pending for that exact process view and loader context; it defers only the
> bounded memory scan, not hit accounting or export-hook arming. A zero state is
> only another opportunity for the bracketed scan, because absent state and a
> failed state read are also encoded as zero; it is never relocation-ready or
> completeness proof. If no later completion opportunity arrives, userspace makes
> one fallback attempt on the next independent discovery tick with fresh maps and
> the existing capture budget. Exit, context retirement, cancellation, budget
> exhaustion, and shutdown settle any remaining pending work as explicit loss.
> An empty scan is evidence, not relocation proof. When memory scan is
> unavailable, live export hooks remain the table-read path; the loader event
> alone is not called a table scan.

## Focused regression evidence

- Existing loader batch routes:
  `mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope --lib -- loader_batch_route`
  printed `running 3 tests` and
  `test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 979 filtered out; finished in 0.13s`.
- Existing maps-bracket/refusal group:
  `mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope --lib -- p2_`
  printed `running 19 tests` and
  `test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 963 filtered out; finished in 1.63s`.
- Existing loader aggregate/counter group:
  `mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope --lib -- loader_counts_`
  printed `running 3 tests` and
  `test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 979 filtered out; finished in 0.00s`.
- Existing clean context retirement:
  `mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope --lib -- a_cleanly_retired_loader_context_publishes_no_skip`
  printed `running 1 test` and
  `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 981 filtered out; finished in 0.00s`.
- Existing batch deadline cleanup:
  `mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope --lib -- discovery_batch_deadline_is_cleared_after_success_and_error`
  printed `running 1 test` and
  `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 981 filtered out; finished in 0.11s`.
- `mise exec -- rustfmt +1.88 --edition 2024 --check src/discovery/engine.rs src/discovery/scan.rs`
  exited 0 after formatting exactly those two files. `git diff --check` also
  exited 0.

## Boundaries and concerns

- Per controller/HOUSE-RULES, no workspace-wide test, check, or clippy gate was
  run. Those gates remain UNRUN and are not implied by the focused results.
- No privileged, VM, container, live-BPF, or release-driver lane was run. The
  scheduling-dependent product symptom is therefore not requalified here.
- No BPF record layout, privacy allowlist, frozen version shape, schema, or
  capture ceiling changed. `VERSION_SHAPE_SCANNED` remains 988/104/208.
- No subagent was dispatched because HOUSE-RULES explicitly forbids it.
- No controller ruling was found wrong. No commit was created, as required.

## 2026-09-13 — final focused verification

- Fresh final command after all Rust edits and formatting:
  `mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope --lib -- rt_add_deferral_`.
- Positive control: Cargo printed `running 8 tests` and all eight named tests
  were `ok`.
- Literal result line:
  `test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 974 filtered out; finished in 0.54s`
- Final targeted rustfmt check, `git diff --check`, frozen
  `VERSION_SHAPE_SCANNED` assertion, and forbidden-file assertion each exited
  0. HEAD remains `59195b8`; no commit was created.

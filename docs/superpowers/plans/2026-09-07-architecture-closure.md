<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Architecture Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. The primary assigns exclusive file ownership and the Cargo lane before each patch.

**Goal:** Close verified architecture, testability and ownership gaps before
the first release, preserving existing product behavior and evidence.

**Architecture:** Native-language behavioral tests retain thin named Cargo
entry points. Reuse existing production seams for bounded reads, attachment
and evidence validation; remove duplicated test implementations and dead
dispatch only after equivalent behavioral checks exist.

**Tech Stack:** Rust 1.88, edition 2024, existing Aya/libc/tempfile dependencies,
Python standard-library unittest, POSIX shell, existing C fixtures/toolchain.

**Spec:** [Final architecture and test design](../specs/2026-09-07-final-architecture-and-test-design.md).

## Global constraints

- Linux x86-64 first; proper native64 and ia32 support remains required.
- Preserve `docs/privacy/allowlist-v1.md`, source custody, independent golden
  vectors, raw-record oracles and exact refusal/partial-evidence semantics.
- One writer per file set, one Cargo-heavy command at a time; review after the
  relevant writer stops. Preserve unrelated edits and private evidence.
- No publication, push or tag. Local qualification uses the owner's existing
  execution authorization; no process is owned merely because its name matches.
- Private `p11scope-ws` experiments and retained evidence do not supply the
  maintained release test suite. Migrate reusable accepted fixtures, behavioral
  regressions and qualification entry points into this repository before
  release, with ordinary local/CI invocation and no dependency on a sibling
  workspace or its absolute paths. Keep generated evidence/builds untracked.
- W8-A is mandatory. Every accepted finding below must be fixed or disproved
  with recorded evidence; a static review is not runtime qualification.

## Verified baseline and findings ledger

The pre-reorganization W7 candidate passed all four Rust gates: 1,127 tests,
22 test binaries, zero ignored. That receipt predates the new file layout.
Diagnostic BPF has 18 programs/17 maps, default 13/16; both actual objects
passed host and 5.15 loading. Final product qualification remains open.

**Local gates, 2026-09-08:** the earlier frozen checkpoint under private
`workspace-gates-ar17-c4-bqzr439d/` passed all four required commands and
1,167 tests with 322 unchanged inputs. The subsequent integrated run under
`workspace-gates-ar17-c4-8ehreape/` passed formatting and compilation, then
853 library tests and 102/103 artifact contracts. It failed a cleanup fixture's
fixed-delay assumption; Clippy was not reached. A focused reproduction failed
19/24 parallel runs. The fixture now waits for the actual fake kill write,
preserves helper failures, and passes 17 native tests, both affected 24-way
parallel checks and three failure controls after independent rereview. The
new full run under `workspace-gates-ar17-c4-m415it61/` passes all four required
commands and 1,167 tests across 23 binaries, with zero failed or ignored tests
and all 324 recorded inputs unchanged. Kernel, lifecycle and release
qualification remain separate and incomplete.

| ID | Finding | State and task |
| --- | --- | --- |
| AR-01 | Global `pgrep` fixtures can select/signal unrelated matching processes | Closed: owned fixture and independent lifecycle review; proc-access 7/7 and corrected discovery-scan 17/17 |
| AR-02 | Python/shell test programs embedded in Rust strings | Partly migrated to native files; residual discovery driver and smaller embedded programs remain; Tasks 2 and 6 |
| AR-03 | Source-spelling guards accept disabled/comment-only behavior | Descriptor-publication slice closed with actual production tests; remaining ABI/decoder/retirement guards under Tasks 5 and 7 |
| AR-04 | Large scenario families hide independent failures | Confirmed inventory; Task 6 |
| AR-05 | Repeated fixture mechanics and inconsistent failure cleanup | Confirmed sampled paths; Tasks 1 and 6 |
| AR-06 | Empty/untraced independent oracle accepts a capture | Closed: real-validator RED, ten native cases, named Cargo bridge and independent review; Task 3 |
| AR-07 | ELF inventory reads bypass capture I/O/deadline budget | Local fix/review closed, including exact pin cause and actual owned retirement; affected kernel qualification remains under Task 4 |
| AR-08 | Failed-detach prohibition across later discovery batches lacks proof | Closed locally: shared admission policy, corrected nonempty cleanup and dynamic ownership regressions, independent review; kernel limits remain; Task 5 |
| AR-09 | Teardown test exercises a second implementation | Closed: replica deleted, production helper tested with 28 links, independent review clear; Task 5 |
| AR-10 | Export classification retains an unreachable source branch | Closed: sole-caller branch removed, independent review, both inventories and host/5.15 loads; affected capture qualification remains; Task 7 |
| AR-11 | Qualification workload and cleanup contain unbounded waits | Oracle owned hangs and absolute WORK defect confirmed; canary normal/cleanup waits also confirmed unbounded; Task 8 |
| AR-12 | Canary validator is a 1,744-line Python heredoc; receipt self-tests duplicate a model | Confirmed script inventory; Task 6 after correctness fixes |
| AR-13 | Delayed CALL/FORK events can acquire a replacement PID generation's semantic identity | Source-supported AC-01; real-consumer regression and correction/refutation required; Task 8c |
| AR-14 | Owned exec-error pipe and final blocking reap can bypass cancellation bounds | Bounded source correction and focused regressions accepted after independent rereview; final capture qualification remains; Task 8c |
| AR-15 | Mountinfo acquisition bypasses discovery resource admission | Local source correction and independent review accepted; all four integrated Rust gates pass; affected runtime qualification remains; Task 8c |
| AR-16 | Abandoned BPF entry records retain bounded map capacity | Source-supported AC-04; mandatory measured disposition, reclamation conditional on required lifecycle/rate contract; Task 8c |
| AR-17 | Required-lane aggregators can accept SKIP; shared-caller and CI inventory drift | Source findings plus executed CI inventory failure; Tasks 8 and 8c |
| AR-18 | First-use claims and helper ABI/libc delivery are not adequately qualified | Operator/source review; truthful documented workflows and actual delivered-artifact checks; Task 8d |

The primary owns this ledger and every acceptance decision. Task 1 has one
test-lifecycle implementation owner; Task 3 has a separate oracle owner.
Task 2 and integration wrappers are primary-owned. Subsequent tasks receive
one scoped owner at dispatch; overlapping `attach`, `engine` or test files
cannot have concurrent writers. Each task's file and check lists below define
its affected gates. Acceptance receipts are retained under
`p11scope-ws/incoming/2026-09-07-test-architecture/`; a focused pass is recorded
against its exact sources and never promoted into a full release verdict.

As of the 2026-09-08 checkpoint, eight finding groups have accepted local
source corrections (AR-01, 06, 07, 08, 09, 10, 14 and 15); ten remain open or
partly resolved. This counts finding groups, not individual defects or release
gates. Runtime obligations remain for the applicable locally corrected groups.
Passing the Rust suite does not close the remaining embedded-language migration.

## Task 1: Owned non-descendant test fixtures

**Files:** `tests/proc_access.rs`, `tests/discovery_scan.rs`, shared test-only
support under `tests/support/` if needed. No production API expansion.

**Interface:** a fixture guard returns the exact launched non-descendant PID,
owns its validated process generation, and cleans up through a pinned handle.

- [x] Replace the two global process searches with a private launch/readiness
  channel. Validate launch identity before enabling cleanup; receiving a PID
  then opening a pidfd alone does not close PID reuse after an early exit.
- [x] Preserve actual same-UID/non-descendant `/proc` and Yama behavior.
  Bound readiness and cleanup; automatic cleanup covers failed assertions.
- [x] Run multiple concurrent fixture launches, and prove a separately owned
  identical-command decoy survives. Test premature fixture exit as well.
- [x] Run the focused `proc_access` and `discovery_scan` test binaries, then
  independent lifecycle review. Do not rerun old global-match cleanup to
  manufacture a failure against an unrelated process.

Current focused integration: `proc_access` passes 7/7, including concurrency
and exact cancellation errors; independent lifecycle review has no remaining
findings. `discovery_scan` passes 17/17 after the Task 4 budget-test corrections.

## Task 2: Directly runnable process snapshot regression

**Files:** `scripts/lib.sh`, `tests/python/test_process_session_snapshot.py`,
the existing named wrapper in `tests/artifact_contracts.rs`.

**Interface:** `python3 -I tests/python/test_process_session_snapshot.py -v`;
the existing Cargo test name remains unchanged.

- [x] Reproduce ESRCH when a held `/proc/PID/stat` file is read after the
  owned child exits and is reaped. Catch `ProcessLookupError` only on initial
  membership discovery; preserve later hard errors.
- [x] Move the regression into native unittest cases. Test a retained member,
  initial ENOENT/ESRCH, every later read position, permission/I/O/malformed
  errors. Keep execution of actual production code.
- [x] Execute the whole Python file and one selected case from another cwd;
  an isolated old-code mutant must still fail on ESRCH.
- [x] Run the unchanged named Cargo wrapper with all three required native
  selectors; deleted-case and skipped-case mutants both fail.
- [x] Independently review the native test and bridge: Astra xhigh accepted
  with zero findings; direct/selected runs pass and old-code, missing-case and
  skipped-case controls fail. This closes only this bounded migration.

## Task 3: Nonempty independent subset oracle

**Files:** `scripts/matrix/verify-oracle.sh`, new
`scripts/check-subset-oracle.py`, `tests/python/test_subset_oracle.py`; the
primary adds a thin named Cargo wrapper in `tests/artifact_contracts.rs`.

**Interface:** preserve the two report/capture path arguments:

```sh
python3 -I scripts/check-subset-oracle.py REPORT OBSERVED
python3 -I tests/python/test_subset_oracle.py -v
```

- [x] Extract only the existing subset validator into the normal Python file,
  leaving the actual comparison policy unchanged for the RED checkpoint.
- [x] Reproduce rejection-test failures for nonempty reports without traces,
  empty traces and excluded-only traces.
- [x] Refuse an empty aggregate of independent expected calls before claiming
  success. Keep teardown attribution, the exact known exclusion, surplus
  diagnostics and `terminal_capture_is_clean(..., uncorroborated=1)`.
- [x] Pass positive traces/surplus; reject missing/insufficient captured calls
  and dirty/no-probe evidence. Execute both CLI and imported production code.
- [ ] Preserve `-I` and explicit checker loading relative to `__file__`.
  Existing all-tracked-file snapshots must include the new helper in the final
  candidate; no unrelated Knative/native-collector input-list edits are needed.
- [x] Run native tests, shell syntax, receipt self-test and independent review.
  Add no new self-test interface or orchestration framework.

All ten required native cases pass through the named Cargo bridge. The known
exclusion is independently pinned to the approved singleton; add, replace and
remove mutations fail. Final tracked-input custody remains a release gate.

## Task 4: Budgeted ELF acquisition

**Files:** `crates/manifest/src/{elf,identity}.rs`,
`src/discovery/{scan,identity,engine}.rs`, their existing focused tests.

**Interface:** an `ElfSnapshot` reader-injection constructor reuses
`read_object_bytes_with`; one discovery reader applies `allowed_io`,
`record_io` and `check_deadline_now` before each chunk. Existing unbudgeted
offline callers retain their API; capture callers use the bounded path.

- [x] Inventory every capture-time `ElfSnapshot::read` caller, including
  initial scan, loader preparation and live export/selection acquisition.
- [x] Add deterministic small-budget and between-chunk deadline regressions;
  no underlying read may exceed the remaining allowance or occur after expiry.
- [x] Add the shared acquisition seam and migrate all capture callers. Preserve
  same-byte ABI/symbol facts and before/after identity checks. Do not add a cache.
- [x] Add the missing per-chunk deadline check to already-budgeted pin hashing.
  Keep partial-read charging and reject partial snapshots as authority.
- [x] Verify named budget/deadline incomplete evidence and native64/ia32
  controls; update expectations to include actual newly charged reads rather
  than raising default limits to conceal the extra I/O.
- [ ] Independent review and affected discovery/loader runtime qualification.

Review correction: retain ordinary loader-arm errors and pin skips in internal
partial evidence. A resource refusal during loader revalidation must report
unavailable revalidation, not an observed generation change; preserve existing
fail-closed cleanup and finite public rendering categories. Test both precheck
and postcheck failures through production handling. Correct three old budgets
to include ELF reads and restore the memory-prefix test's reachability with a
positive module/export assertion. Acquisition itself passed scoped review;
the combined task remains open until these findings and runtime gates close.

Correction checkpoint: named causes now survive; unavailable revalidation
queues `ExecRefresh` while confirmed mismatch retains generation-loss handling.
Independent review found no remaining production issue. Discovery-scan passes
17/17 and the whole userspace library passes 835/835 at this checkpoint.
The final regression funds the initial locator's EOF probe in its pin case
and requires the exact loader-path skip. It requires the exact postcheck
context to be marked attached, calls production retirement and proves the
exact detach and registry removal. Independent re-review closes both oracle
gaps; the primary's exact named test passes. These focused results do not
establish kernel detachment or quiescence.

## Task 5: Test real teardown and resolve cross-batch detach failure

**Files:** `src/attach.rs`, relevant lifecycle tests in
`src/discovery/engine.rs`; overlap with Task 4 requires sequential ownership.

**Decision:** retain the existing session-wide `detach_failures` evidence as
the admission boundary: after an ownership/bookkeeping detach error, refuse
new producer links for that Session. Existing capture, terminal cleanup,
empty static operations and duplicate dynamic-link no-ops remain available.
Recovery requires a new Session. Astra xhigh independently challenged this
choice and accepted it as the smallest consistent policy; the primary accepts
the availability cost that unrelated new providers are also refused.

The inspected Aya 0.14 implementation exposes no propagated post-take kernel
detach error for these links. This change addresses ownership-accounting
inconsistency; it is not evidence of a retained kernel producer or proof of
kernel quiescence. Use one shared admission predicate in static preflight and
attachment and both dynamic attachment methods. Preserve provenance checks;
place dynamic refusal after existing-link reuse. Loader refusal is `Registry`,
not `KernelUnavailable`, so it cannot select a kernel-availability fallback.

- [x] Replace test-only `detach_producers_with` with cases invoking production
  `detach_selected_with`: every entry/return family, multiple links and an
  injected failure; assert each attempt once and entry-before-return order.

The unchanged named terminal test passes with 28 distinct link tokens, all
three dynamic export pairs and an injected failure. Independent Astra xhigh
review found no remaining issue; formatting passes. Production sorting is
unchanged: dynamic pairs preserve their real entry-before-return registration
order. A reversed synthetic pair would not establish a runtime defect.
- [x] Trace actual Aya failed-detach ownership and record the limited fault
  model and admission decision above.
- [x] Add a two-batch engine case: injected bookkeeping detach failure, then
  rediscovery of the same object/offset with a fresh slot ID. Exercise the
  production admission predicate through the existing fake-session seam;
  prove no new static/dynamic attachments and continued cleanup/evidence.
  The corrected case proves a nonempty attach and exact failed slot-0 cleanup
  before fresh slot-1 refusal. Fake dynamic ownership is removed on retirement,
  with success/failure and retained other-context reuse tested separately.
- [x] Preserve continuing teardown attempts, diagnostic evidence and terminal
  ownership; independent Astra review accepts all three corrections. A fresh
  parent library run passes 841 tests, zero failed/ignored.
- [ ] Run affected lifecycle qualification. Do not assume a bookkeeping error
  means the kernel producer remains active.

## Task 6: Native test organization and focused shared fixtures

**Files:** `tests/task4_build_subjects.rs`, `tests/artifact_contracts.rs`,
native files under `tests/python/`, `tests/shell/` and `tests/fixtures/`; script validator
extraction follows only with its source-custody callers assigned together.

- [x] Start with
  `input_v1_ledger_round_trip_and_encoder_rejects_invalid_vectors`: move its
  Python behavior to named unittest cases, retaining fixed golden inputs and
  a thin Cargo entry. Shared golden bytes belong in a fixture file, not two
  separately maintained language constants.

The first ledger slice passes all three required native cases through its
unchanged named Cargo bridge and has an independent zero-finding review.
The 820-byte golden, other literal vectors and remaining drivers were checked
against the original; missing/skipped mandatory-case controls fail.
- [ ] Migrate semantic-state families next, with fresh module/monkeypatch
  state and case selection. Share only proven setup/identity-observation
  mechanics, preserving exact types and object identity comparisons.
  The topology slice is accepted: four native cases pass directly and
  individually, including all 16 original rejection scenarios; independent
  review has zero findings and its unchanged Cargo entry passes. The other
  semantic-state families retain their existing drivers until migrated.
  The exec-event slice has eight native cases; the restored complete exec/FD/VM
  prefix catches the review mutation and passed independent re-review. Its
  Cargo bridge passes in the fresh eight-family semantic run. The reported
  out-of-scope formatting change was disproved:
  restoring the old function with correct boundaries reproduces the exact
  pre-edit SHA-256. No unrelated source restoration is required.
  The syscall-lifecycle slice now has nine directly selectable families and a
  preserved 125-vector inventory. Native and Cargo paths pass; independent
  review matched all 3,055 ordered, type-tagged calls across the 125 original
  states. Other semantic families remain unchanged.
  The close-outcome slice is accepted: seven native selectors preserve all
  123 vectors and 1,051 ordered calls, including independently compared typed
  pending/owner state. Import-failure restoration and exact outside-function
  custody pass. The fresh parent eight-family semantic Cargo run passes.
  The dup2 and dup slices are independently accepted and pass their named
  parent Cargo bridges. Dup2 preserves 105 vectors in six families and 954
  typed ordered calls; dup preserves 126 vectors in six families and 3,643
  ordered trace events. Independent observation/assertion checks supplement
  the trace's pending/FD-owner coverage; the trace alone is not proof of every
  task field. Open-description now has 21 selectable native families preserving
  all 207 rejection vectors and ordered positive sequences. Independent review
  caught and corrected lost CLOEXEC state in one positional-pipe case; an actual
  mutation now distinguishes before/after. Native all/individual cases, exact
  Cargo bridge, formatting and scoped Clippy pass; the migration is accepted.
  FD-mutator is also accepted: 22 selectable families preserve 265 typed
  rejection checks and ordered owner/pending identity assertions. Independent
  review verified parity and the meaningful owner-index mutation. Two bridge
  assertions needed formatting and an evidence inventory needed corrected
  family labels; both are closed with original receipts preserved. The exact
  Cargo bridge, formatting and scoped Clippy pass. Residual discovery remains
  open; native module isolation is per test family, with fresh state/configuration
  per independent vector/handler.
- [x] Extract the 28 borrowed-descriptor admission vectors into native tests.
  The original 83-line family is removed from the residual Rust string; the
  unchanged-named Cargo bridge selects the native cases. Independent review
  required restoring the per-case discovery bomb and the actual supplied
  ledger's complete bounded bytes. Both restored observations reject causal
  production-copy mutants that passed the first extraction. Native 28/28,
  selected 4/4, focused Cargo and formatting pass; correction1 is accepted.
  Evidence: private `borrowed-descriptor-admission/correction1/`. This closes
  that family only; the large residual discovery driver remains.
- [x] Make all nine migrated native entrypoints reject zero-test selections
  as well as skipped cases. An unmatched `-k` filter reproduced exit zero;
  only the exit guards changed. Independent review verified unchanged test
  bodies, 36 direct all/one/empty/missing checks and 108 guard combinations.
  Fresh parent Cargo checks pass all 13 selected bridge tests across semantic,
  ledger, API, subset, oracle lifecycle and process-snapshot contracts.
- [x] Extract the discovery API contract prefix into one native selectable
  case, preserving the residual discovery driver and CLI deferral block.
  Independent review verified exact custody and operation order. The parent
  exact `input_v1_discovery_api_is_candidate_only` Cargo test passes (1 passed,
  zero failed/ignored), including execution of the retained residual driver.
  Evidence: private `test-architecture/discovery-api/parent-cargo.log` and
  `review.md`. This closes only the API prefix, not the remaining driver.
  The complete residual discovery driver is now ordinary, import-safe Python
  in `tests/python/test_task4_input_v1_contract.py`, called by one explicit
  native selector. Independent review verifies the complete ordered AST modulo
  three documented adaptations and 902 matching ordered entry observations;
  all Rust bytes outside the assigned region remain unchanged. The actual old
  and new contracts and strict result guards pass on Python 3.12.3 and 3.10.12;
  the scoped Rust formatting check passes. Source/native acceptance is recorded
  in private `task4-input-v1-native/parent-source-acceptance.json`. Its focused
  Cargo bridge now passes with the same reviewed source bytes (1 passed, zero
  failed/ignored); `parent-integration-acceptance.json` records that bounded
  acceptance. The coupled scenarios and other embedded drivers still require
  separate migration work.
- [ ] Inventory all labels in discovery/preflight drivers before separating
  scenarios. Preserve causal read/FD order, absence triples, held-root identity,
  flags/offsets, mutation negatives and final cleanup.
- [ ] Retain Rust's independent 128-byte native-record decoder and existing
  ptrace/pidfd/subreaper watchdog containment. Update native `input_paths` when
  the executed driver/support actually moves into new files.
- [x] Move lane-13 shell/C fixtures and separate independent cleanup scenarios.
  Preserve real driver execution, source sealing and authenticated ownership.
- [ ] Extract the canary Python validator with unchanged argument/policy
  behavior, raw-byte oracle, controls and source authority. Move large Python
  test-only sections where direct tests replace their current gate coverage.
  The 1,744-line validator is now in `scripts/check-canary-evidence.py`, with
  ten selectable native tests at each target width and a thin Cargo bridge.
  Independent review found and corrected lost work-directory propagation and
  a cwd-relative gcc fixture. The actual causal REDs, both-width native/shell
  GREENs and three focused Cargo checks are accepted at private
  `canary-module-extraction/correction1/parent-acceptance.json`. Full-matrix
  runtime and final tracked-source custody remain unqualified; the bridge
  executes the real map wrapper, not the complete full-matrix branch.
- [ ] For each slice, compare case/outcome inventory, run direct and Cargo
  paths, test failure cleanup, and complete independent review before the next
  writer touches overlapping files. File relocation alone does not close
  scenario-selection or duplicated-oracle findings.

## Task 7: BPF simplification and behavioral ABI guard proof

**Files:** `crates/ebpf/src/main.rs`, `src/attach.rs`, relevant object/ABI tests
and existing qualification fixtures; one writer per file set and one Cargo lane.

- [x] Replace the six-marker descriptor-publication guard with direct tests
  of production `publish_descriptors`. Make that function accept state and
  set/readback callbacks and call it directly from `start_inner` with one Aya
  Array; do not leave an untested forwarding wrapper or create a generic map
  publication framework. Preserve the fixed 105-entry inventory and error text.
  Test complete indexed writes, write failures at 0/52/104, read failure and
  missing/extra/different readback; successful readback comes from recorded
  writes. Remove only the superseded marker helper/calls/mutations, retaining
  cookie, compiled-object, freeze and startup-order checks. Scope the updated
  publication-call marker to `start_inner`. Astra xhigh challenged this design;
  the primary selects direct testing to avoid a no-op wrapper bypass.
  Kernel adapter behavior, startup error propagation and actual frozen-map
  consumption remain runtime qualification obligations.

  Four production-publication tests and both retained artifact tests pass in
  fresh parent logs. Independent source review has zero findings and matches
  the reviewed hashes. The replacement removes only the superseded six-marker
  proof; the remaining source/compiled-object guards keep their stated limits.

- [x] Remove the unreachable alternate source branch/discriminator in
  `classify_export`; preserve FunctionList and direct InterfaceList behavior.
- [x] Build both variants, check exact inventories and load on the same host
  and 5.15 guest after the dead-branch removal: default 13/16 and diagnostic
  18/17 pass on host 7.0.0-30 and guest 5.15.0-187.
- [ ] Object bytes changed; repeat affected live capture/runtime oracles.
  Load-only success does not qualify ABI routing, privacy or lifecycle.
- [ ] Evaluate the prepared async-key ablation privately; promote only if
  both objects and actual kernels pass, then rerun privacy/function-name cases.
- [ ] Add an actual opposite-width entry-routing refusal oracle using test
  fixtures: no entered count/event and positive ABI refusal evidence. Do not
  expose a production override of retained target ABI.
  Selected Astra-reviewed seam: an explicit `examples/abi-routing.rs` executable
  and thin native qualification script reuse the existing ia32 C fixture and
  actual embedded BPF. Default runs both MIXED-width positives; diagnostic runs
  both matched positives and both opposite-width refusals. Configure real
  COUNT_ONLY inputs, attach only owned stopped children, retain raw events and
  require exact counters/RVs. Missing prerequisites are nonpass. Bound child
  cleanup and retain pinned file identities. Use two isolated diagnostic builds
  disabling each mismatch return to establish actual mutation sensitivity;
  keep existing source guards until that evidence passes. No ignored tests or
  automatic privileged execution enter the ordinary workspace suite.
  The corrected actual host gate passed default 2/2 and diagnostic 4/4 rows
  on 7.0.0-30: exact positive counts/RVs, zero opposite-width calls/events,
  positive refusal counters and clean fixture settlement. Source hashes were
  unchanged during the run. This receipt predates fixture relocation and the
  compatible dependency updates; guest and mutant qualification remain open.
- [ ] Replace misleading spelling-only guards only after behavior/artifact
  replacements fail on the corresponding disabled-behavior mutants.

## Task 8: Bound oracle workload and cleanup

**Files:** `scripts/matrix/verify-oracle.sh`, its native fixture tests.
Sequential with Task 3 on the same script.

**Selected design (independently challenged by Astra xhigh):** keep one receipt
shell, a plain `oracle_body` call under errexit, and one EXIT finalizer. Cleanup
precedes sibling/source checks and terminal publication on success and failure.
Use a native shell workload helper with quoted argv and a fresh in-scope
PID/starttime handshake. Authenticate actual membership before retaining a
cgroup directory FD in the receipt shell. A small native Python helper reopens
that held FD through the live receipt process, validates generation and
device/inode, and uses only directory-relative `cgroup.kill`/`cgroup.events`
access. Probe controls before FIFO release; absence refuses the lane. Never
destroy a scope by name: InvocationID checks cannot make name-based stop atomic.
Bound all waits and management calls, retain creation-time runtime containment
for unacknowledged launches, and report unproved cleanup as nonpass. This is a
qualification-harness capability requirement, not a change to product support.
Native tests must execute the actual functions/helpers, including hanging
children, foreign replacement, signal/errexit, path quoting and publication
failures. Synthetic filesystem controls do not prove kernel cleanup semantics.
Required helper inputs must be included in final tracked source custody.

- [x] Exercise a deliberately hanging owned client substitute and identify
  current unbounded waits, including cleanup-before-scope-stop ordering.
- [ ] Correct the receipt-to-body absolute path handling: the receipt passes
  an absolute `WORK`, which the body incorrectly prefixes with `PWD`. Use
  argument vectors for workload paths, including spaces and apostrophes.
- [ ] Bound client execution in its existing owned scope. Stop/reap only
  authenticated owned processes; an observer duration is not a client deadline.
- [ ] Prove terminal failure evidence and bounded descendant cleanup under
  timeout, signal and launch failure. Preserve substantive subset checks.
  Reclamation now selects actual root-output files plus reports/tokens,
  excluding the FIFO and Cargo tree. Independent review accepts admission
  before traversal. Parent actual-root fixture transfers 12 private objects
  back to the nonroot caller without touching the FIFO/build hardlinks.
  The exact current helper passes empty/retired cgroup checks and actual
  populated root/nested cleanup on host 7.0.0-30 and guest 5.15.0-187. The
  latter proves killed stopped members, outside-bystander survival before
  finalization, direct-child reap and directory removal. Full selected-version
  systemd/SoftHSM receipt remains open; these narrow runtime checks do not
  close that gate.
- [ ] Correct the independently confirmed canary follow-up in
  `scripts/verify-canaries.sh`: normal client/observer waits and cleanup waits
  remain unbounded; authenticated signal helpers alone do not wait or escalate.
  Keep this lifecycle patch separate from validator extraction and preserve
  owned-process identity and all privacy/canary oracles.
- [x] Resolve shared root-launch failure ownership in `scripts/lib.sh` before
  accepting either caller: `launch_root_recorded_process` can invoke a raw-PID
  cleanup after its record wait. A shell may already have reaped that child.
  Establish launcher ownership at creation and preserve it through bounded
  cleanup; sampling a possibly reused PID later is insufficient. Prefer one
  corrected shared helper over duplicate caller launch implementations.
- [ ] Integrate the shared recorded-launch contract in every direct caller:
  oracle, canaries, ia32 compatibility, ABI routing, proxy stack, task4 lane02,
  induced gaps, Docker, kind, shared layer and Knative. Retain the authenticated
  launcher generation at ownership transfer; finalize pending launch failures;
  distinguish gone/zombie from replaced/unknown before a shell wait. Do not
  preserve raw-PID signal fallbacks or replace them with late generation
  sampling. Review descendant containment where a recorded target is itself
  a wrapper. Preserve each lane's substantive oracle and source custody.
  The shared implementation and fixture correction2 have passed independent
  review. The parent Cargo bridge now selects all 55 native cases and passes
  (2026-09-07, 20.73s). A separate actual-sudo smoke passed identity, nonzero
  exit status, concurrent roles and authenticated cleanup. These checks do
  not qualify every caller or kernel lifecycle. Ia32 caller correction3 passed
  independent static review, then the parent ran all 26 native lifecycle cases
  successfully in 22.445s with no skips and unchanged reviewed inputs. Its new
  explicit 26-selector Cargo bridge passed independent static review; the
  actual Cargo bridge and kernel compatibility qualification remain open.
  ABI driver correction2 passed its bounded independent review. Its first
  host gate failed before probes when an x86 ELF inspector hashed the BPF
  object; the bounded RustCrypto hashing correction and seven default/seven
  diagnostic regressions now pass independent review. The corrected actual
  host gate passes all six rows as recorded in Task 7; guest and mutant
  qualification remain open.

## Task 8b: Refresh release supply-chain dependencies

Owner requested this additional release task on 2026-09-07. Complete it before
the final integrated gates and qualification; earlier receipts remain evidence
for their recorded inputs only.

- [ ] Inventory direct and transitive Rust dependencies in both lockfiles,
  Git revisions and patches, Python tooling, CI actions, and pinned downloaded
  tools/container inputs. Distinguish repository inputs from separately
  versioned external qualification workloads.
- [ ] Check current upstream releases and compatibility using authoritative
  sources. Update where feasible while preserving Rust 1.88, edition 2024,
  supported kernels, required Aya behavior and the privacy allowlist. Record
  a concrete reason for each retained pin; do not discard necessary fork fixes
  or raise the toolchain/kernel floor implicitly.
- [ ] Apply updates in bounded groups, preserve reproducible pins and lockfiles,
  review changed APIs/build behavior, and run the affected checks. Do not
  modify source inputs during an active qualification run.
- [ ] Resolve clean acquisition of shared Git revision
  `cbf3d019c43cf424d92a5d2033c6714c9f866f65`. A fresh public fetch from the
  declared pkcs11-proxy-ng URL actually returned `upload-pack: not our ref`
  (exit 128), and the commit API returned 422. Local cache builds do not close
  this release blocker. Keep needed W7 fixes. Select an accessible immutable
  source or recipient-delivered offline source with a documented Cargo
  fetch/replacement/vendoring route for both production workspaces/lockfiles.
  Bind source/provenance and rebuild without prior caches, private credentials
  or user Git rewrites. Merely retaining a private Git bundle is insufficient.
  Prepare the route locally; publication remains owner-controlled.
  A private exact source copy successfully vendors both production locks.
  The first real empty-cache build exposed an additional nightly-sysroot
  resolver dependency (`rustc-literal-escaper`). Syncing the exact pinned
  nightly sysroot lock closes that gap without changing any input lock:
  107 vendor packages and 4,909 file checksums verify. Shared Git crate bytes
  match the clean exact revision; omitted root licenses and a complete,
  empty-repository-verified Git bundle accompany them. Replacement config is
  relative and retains the declared Git identity. Fresh archive extraction
  verifies all bytes, normalized modes and links. Actual root default and
  diagnostic builds pass (56.31s/48.60s) with separate empty Cargo homes/targets;
  source bytes stay unchanged, no registry/Git source payload is acquired,
  and the diagnostic object has the actual root BTF/export flags. Independent
  review accepts this source-delivery feasibility evidence. Installed tools
  and rust-src remain prerequisites. Final assembly/operator-recipe integration
  and release-script qualification remain open; no public Git fix is claimed.
- [ ] Rebuild both BPF variants and run final workspace, native-language,
  kernel/ABI and applicable container/integration gates on the updated inputs.
  Record the final dependency inventory in release evidence. Unsupported or
  unavailable checks remain unqualified rather than silently skipped.

Checkpoint: 76 registry names were inventoried and compatible patch versus
breaking/parent-blocked candidates classified. The first compatible group is
applied: root crc32fast 1.5.1, indexmap 2.14.2, log 0.4.34 and syn 3.0.5;
nested BPF syn 3.0.5 and which 8.0.6. Independent lock inspection confirms
only the requested versions/checksums and Syn references changed; cached
crate hashes match. Git/Aya/Syn 2 and toolchain floors are preserved. Worker
tool results report root check and direct BPF builds passing, with reconstructed
output provenance retained. Direct diagnostic compilation lacked the root
build script's BTF/export flags and is not runtime qualification. Final parent
gates remain open. Both actual root-build variants subsequently passed in the
fresh extracted offline feasibility experiment above; final-candidate runtime
qualification remains open.
The exact official checkout/upload-artifact v7.0.1 pins were updated and
statically checked; hosted execution is unrun. Keep frozen BPF nightly/Aya
requirements separate from the userspace Rust 1.88 floor.

The next SHA-2 group is applied and independently accepted: four direct
declarations pin 0.11.0; two removed-LowerHex call sites reuse the existing hex
helper. Root check, six identity cases, both seven-case ABI hash suites, both
research checks and the i686 helper check pass in retained raw logs. Independent
source/dependency/evidence review has no actionable findings. Final
integrated/runtime gates remain open. Retain libloading 0.8 at the shared
Library type boundary and object 0.39 pending an explicit ELF API migration;
upgrading either direct dependency alone is not a justified release refresh.

Tool acquisition now retains verified registry index/platform bytes for the
two Rust 1.88 helper images and Ubuntu Noble 20260810, plus the three Knative
1.23 YAML assets and their published checksum inputs. The helper-container
script uses the selected immutable image indexes; syntax, its existing
unprivileged oracle self-test and exact substitution reconstruction pass.
Independent patch review accepts the bounded change with zero findings;
actual helper/container qualification remains open. Expected Knative hash
integration is now independently accepted through the real 31-selector Cargo
bridge. All three exact release bodies are checked before apply, and native
tests cover pre-apply corruption and same-size mutation during apply, including
the absence of success/deletion facts. Evidence is in private
`dependency-refresh/knative-expected-pins/parent-acceptance.json`; final fixture
packaging and actual cluster qualification remain open. The kind/node/kubectl
tuple and resolved package provenance remain open. Registry content addressing and
asset checksums are established; full publisher-signature policy validation
is not claimed. Private `dependency-refresh/tool-input-acquisition/` and
`dependency-refresh/discover-image-pins/` retain the supporting bytes and checks.

## Task 8c: Close consequential gaps from the broad release review

The 2026-09-07/08 review covered product/operator, architecture/correctness,
validation/release and public ecosystem in four independent lanes, followed
by a synthesis challenge. The primary accepts targeted closure, without a
wholesale rewrite or new assessment platform. Source findings below need
decisive regressions and fixes or evidence-based refutation; they are not
runtime-reproduced vulnerabilities. Review reports and exact input hashes
are retained privately under `test-architecture/release-gap-3ft97sk9/`.

Each production item is a separate owned patch. AR-14 is accepted. AR-13 is
currently a private feasibility/design lane with no production writer, so the
independent AR-15 bounded-reader correction may proceed while it runs. Finish
and review AR-15 before dispatching an AR-13 production writer: `src/process.rs`
must have only one owner. This scheduling change does not waive either gate.
Before dispatch, verify the
named symbols against the current source and specify the minimal testable
design. Preserve existing source custody, ownership and evidence semantics.

- [x] **AR-14 / AC-02 — bounded owned exec handoff.** In `src/run.rs`, exercise
  real `OwnedChild::release` with the original owned child stopped behind its
  pre-exec barrier, then deliver ordinary cancellation. Prove the current
  failure before fixing pipe readiness/cancellation handling. Preserve exec
  errno, signal identity and original pidfd authority. Ensure `Drop` cannot
  undo the bound through `wait_blocking`. Require bounded return plus actual
  termination/reap for the responsive owned child; retain unresolved cleanup
  explicitly when it cannot be established. Test EINTR and normal exec/errno.
  Primary accepted the independent design: a five-second absolute exec
  handoff limit separate from capture duration, cancellation-aware nonblocking
  pipe reads, exact nonblocking pidfd reaping, and one explicit cleanup budget
  reused by Drop. The regression retains original-handle rescue before
  stopping the child. Initial implementation reproduced RED and passed focused
  checks, but independent review requires four corrections: bound read-EINTR
  retries; recover exact-child natural exit at settlement boundaries; detach
  a live session before preflight-error child settlement and retain all errors;
  make every regression rescue observable. The natural-exit correction also
  covers initial signal forwarding. Correction1 closes all four findings and
  the initial-forward extension. Five focused regressions, 64 run tests and
  five lifecycle tests pass with raw transcripts; fmt, scoped Clippy and
  workspace all-targets check pass. Independent rereview has zero findings;
  the primary accepts this bounded source correction. Full workspace and
  actual capture/kernel qualification remain separate gates below.
- [ ] **AR-13 / AC-01 — generation admission for delayed records.** Exercise
  real CALL/FORK consumers in `src/run.rs` and `Tracker` in `src/process.rs`
  with old INIT/FORK records and a replacement process generation, including
  stat-old/pidfd-new acquisition. Admit a record only to an authenticated
  generation; otherwise retain count-only/ambiguous evidence without carrying
  semantic state across uncertainty. FORK timestamp currently defaults to
  zero: simply comparing the existing CALL timestamp is not a complete fix.
  Review time domains and event protocol before changing BPF/common records.
  Frozen-source design review confirms that a post-pin cutoff alone rejects
  valid first events and tick-rounded timestamps cannot prove ordinary first
  FORK inheritance. Positive inheritance remains required. A bounded kernel
  identity feasibility investigation confirms upstream original-pidfd task
  storage lookup and full birth-field lifetime across nonleader exec. Birth
  timestamps have no enforced uniqueness guarantee; cookies require typed
  pointers, map BTF plumbing, finite allocation and an explicit exec boundary.
  The private C/Aya experiment now compiles and its actual offline CO-RE
  relocation against exact host and Jammy BTF is independently accepted: three
  intended instruction offsets change per target; missing/malformed BTF refuses.
  Evidence: `delayed-generation/compiled-cookie-spike/correction1/parent-acceptance.json`
  under the private architecture evidence root. The minimum owned runtime
  harness is now independently reviewed after its cleanup corrections; 15
  actual tests pass from a fresh target, and reintroducing the pre-detach
  timeout bug fails both targeted tests. The actual host 7.0.0-30 experiment
  passes first-marker and first-FORK rows with original-pidfd cookie equality,
  distinct parent/child identities, post-reap absence, zero control failures
  and completed cleanup. The glibc-linked harness fails before loading BPF
  on Jammy because it requires GLIBC 2.39. The unchanged source built for the
  installed musl target passes all 15 tests, and the same static executable
  and fixture then pass both rows on host 7.0.0-30 and Jammy 5.15.0-187.
  Independent evidence review accepts these minimum mechanism observations;
  `runtime-stage/correction2/parent-runtime-acceptance.json` binds the results.
  The private combined Rust/C ELF now passes independent compile/offline review:
  13 programs, one Rust event ring, exactly two new typed maps, actual bidirectional
  calls and three-only relocations against each target. The final artifact is
  accepted for this mechanism proof. The successful LLVM fallback library is
  unidentified, and initial raw build attempts were overwritten; only final
  receipts and three initial text inspections are retained. These provenance
  limits precede reproducibility claims. Production loader/event integration and
  lifecycle/concurrency qualification remain open; no product BTF requirement
  or production identity design is selected by this proof.
  A subsequent bounded review verifies that current Aya 0.14 can support a
  narrowly checked task-storage/BTF loader adapter; an upstream dependency
  change is not inherently required. Primary selects immutable TaskCookie plus
  kernel u64 self_exec_id for a new private producer/image proof, explicitly
  assuming no counter overflow/reset in the supported retained lineage/capture
  interval. This is conditional engineering identity, not an unconditional
  uniqueness proof. Actual typed reads, entry/return transport, exact new CO-RE
  relocations and leader/nonleader exec behavior must be qualified separately.
  The broad consumer integration stays deferred until that proof. Same-leader
  worker-TID reuse remains a distinct pairing/reclamation question shared with
  AR-16; process-image tokens alone do not close it.
  The completed producer/image proof now has independent compile/offline
  acceptance: all 35 common tests, 13 programs/18 maps, six actual relocations
  per host/Jammy target and entry/return identity guards before saved-pointer
  reads. The final ELF and actually loaded LLVM library are identified; earlier
  overwritten attempts retain their stated evidence limits. A new isolated
  combined-object runtime adapter is being implemented for actual CALL/FORK
  transport. Consumer review confirms that numeric-PID activation remains
  unsafe across delayed same-task exec. Full identity histories are the
  recommended direction; accounting, closed-history loss and first-event
  contracts must be selected explicitly before production integration.
  The primary has now selected event-owned histories, separate finite membership
  and exec watermarks, and explicit partial semantic accounting through a new
  history-loss counter. The private actual-consumer patch passes 16 history-filter,
  48 semantic, 20 trace and one existing cgroup-drain checks; these filter counts
  overlap. Five causal mutants produce meaningful assertion failures, and a
  separate RED/GREEN closes cross-domain detached-async adoption. Final source
  passed independent review after exact original-descriptor collision and trace
  provenance corrections. That private proof's mandatory live membership policy
  is superseded: authentic events from the retained producer domain must admit
  their full historical identity even after reap. The private consumer correction
  implementing this rule now has independent and primary acceptance: causal
  RED4/GREEN6, preserved policy/reducer/drain checks and 94 distinct passing
  test names. Its hardcoded private domain and unimplemented retirement proof
  are not production integration. Exact owned-root exit accounting remains required;
  exit observation alone must not close a history before its queued tail. A
  bounded producer-position fence beside the sole reader is under integration
  design; an empty poll can mean a BUSY record and is not a drain proof.
  The combined adapter's two BTF preflight fixes and a native entry null guard
  are independently accepted. The corrected object passed actual host first
  CALL/FORK, original-pidfd and normal-cleanup checks through three loaded
  programs. Its static musl adapter and unchanged glibc-compatible fixture then
  ran on Ubuntu 5.15.0-187, where the verifier rejected a combined call stack of
  544 bytes. The exact failing output is retained under private
  `producer-null-guard/portable-jammy/parent-jammy-y0it4uxs/`. The subsequent
  `producer-stack-reduction/` derivative changes only four native zero stores;
  independent compiled review reproduces a 480-byte entry chain and a 512-byte
  maximum across all 13 programs. Its exact GNU/musl adapters now pass actual
  first-CALL/FORK runs on host 7.0.0-30 and Jammy 5.15.0-187, with matching
  original-pidfd identities, zero error controls and completed cleanup. The
  independent runtime review and primary acceptance qualify the three loaded
  programs only: entry, return and task_newtask. The original verifier failure
  is preserved. The subsequent controlled exec extension passes one leader
  and one nonleader row on each of host 7.0.0-30 and Jammy 5.15.0-187. The
  original pidfd is retained across exec; an old completed CALL remains in the
  ring until EXEC_READY, then the next CALL uses the new image identity after
  explicit gated reattachment. Independent runtime review and primary
  acceptance bind all four rows and clean supervisor settlement. Jammy also
  passes all fourteen supervisor tests on actual Python 3.10.12. These rows
  qualify entry/return only, without an in-flight CALL or uninterrupted
  attachment across exec. Evidence: private
  `producer-exec-lifecycle/parent-exec-runtime-acceptance.json`. Full program
  loading and production integration remain required.
  The actual production build now links the ordinary native identity helper,
  preserving diagnostic offsets while appending the private identity fields.
  Independent source/object review accepts this bounded precursor: both real
  default and diagnostic objects have a static maximum stack of 512 bytes;
  common, native control, canary and focused artifact checks pass. Evidence is
  in private `production-producer-slice1/parent-acceptance.json`. The mixed-map
  inventory and typed loader/control preparation have since received bounded
  source acceptance, as recorded below. Consumer and lifecycle integration
  remain pending; stale source-contract tests are still open.
  AR-16 production owner/reclamation source is now independently accepted:
  actual native helpers route pairing transactions through physical task owners,
  retain conservative reservation debt on failures, and clean retained original
  keys at raw exec/exit before scope filtering. Independent native normal/small
  checks and all three stopped compiled-object checks pass, with a static stack
  maximum of 512 bytes. Private `abandoned-state/production-owner/parent-acceptance.json`
  records the bounded acceptance. Named evidence counters can undercount under
  contention and cannot establish exact concurrent abandonment totals. The mixed
  map inventory correction is accepted through eight native tests, its Cargo
  bridge and independent review; three preserved malformed-object controls now
  refuse for the intended reasons. Loader preparation initializes, reads back
  and freezes the actual identity/owner controls and requires all programs to
  load before the explicit integration guard. Its doctor correction preserves
  named failure context and skips active diagnostics after setup refusal.
  Real host execution exposed a section-symbol map relocation bug in
  `aya-obj 0.3.0`. A narrow local package patch now resolves the exact map
  definition by section and unsigned addend; 94 library and two application
  map tests pass, with no blocking independent review findings. Evidence:
  private `mixed-map-loader-relocation/parent-patch/parent-acceptance.json`.
  The rebuilt host run gets past the former assertion but the verifier rejects
  `function_list_entry`. The accepted doctor head/tail excerpt correction now
  preserves the terminal reason: the global `p11_owner_discovery_insert` helper
  exposes an unsized pointer argument in BTF. Review of the complete helper
  interface now has an independently accepted correction: remove eight owner
  exports and retain seven callable LOCAL ELF/STATIC BTF helpers with noinline.
  Default, diagnostic and small objects retain the static 512-byte maximum.
  That exact default binary then passes all 13 program loads and map preparation/
  freezing on host 7.0.0-30, reaching IdentityIntegrationPending before any link.
  Evidence is in private owner-helper-btf-integration/parent-runtime1/
  parent-runtime-acceptance.json. The expected doctor exit remains 1 because
  capture activation is deliberately refused. Diagnostic/small kernel execution,
  capture and runtime recovery remain unqualified. This host result predates the
  root-affiliation maps and producer described below; those need a fresh load.
  The new vendored package must
  be included in final source custody and release packaging.
  Fast nonleader exec followed by exit before first drain now has a selected
  root-association interface: a separate private task-storage affiliation,
  seeded through the original pidfd and propagated to threads before wake.
  Its leases are concurrent and refunded at physical exit, independently of
  AR-16 pairing; successful exec preserves the executing worker's affiliation.
  The chosen normal/small affiliation bounds are 16,384/3, without a lifetime
  worker quota. Source feasibility and budget comparison are recorded in the
  private `primary-root-affiliation-selection.md`. The subsequent control
  selection uses separate ROOT_CTL64, leaving OWNER_CTL56 health unchanged,
  and appends a private affiliation field to Event328 while retaining
  CallStart288. Missing parent affiliation is UNKNOWN and mutation-free;
  affiliation-only failure cannot suppress authentic CALL/FORK histories.
  The producer/common/native implementation is now independently accepted in
  private `root-affiliation-producer-integration/parent-acceptance.json`.
  Default/small objects contain 22 maps and 13 programs; diagnostic contains
  23 maps and 18 programs. Common layout checks, actual native failure controls,
  focused Cargo bridges and all 27 compiled linkage mutations pass, with a
  static maximum stack of 512 bytes. This does not establish verifier acceptance.
  Fresh-child admission depends on a new private map, the original seed before
  links, and one pre-wake birth handler making at most one CREATE attempt;
  the helper API cannot independently prove freshness after a NULL lookup.
  Readable existing cells refuse before reservation, and an uncertain CREATE
  retains conservative debt without retry or refund. The primary selection is
  recorded in private `primary-root-affiliation-freshness-selection.md`.
  Original-pidfd seed/readback/freeze plumbing is now independently accepted
  in private `root-seed-loader-integration/parent-final/parent-acceptance.json`.
  The correction review verifies genuinely owned test descriptors and isolated
  FD0, exact tag/control refusal through production validators, and preserved
  six-argument forwarding. Both weakened-validator mutations fail; restoring
  the exact source passes. All 41 attach tests plus the isolated child pass,
  together with formatting, workspace check, Clippy and the default build.
  The corrected default binary then reaches the guard after real preparation
  and all 13 program loads on host 7.0.0-30. Its owned-child route also reaches
  the guard after original-pidfd seed/readback and all six identity freezes;
  process tracing verifies exact original-pidfd reap without workload exec.
  Evidence: private `root-seed-loader-parent-runtime1/parent-runtime-acceptance.json`.
  An earlier owned attempt refused an untrusted output directory before setup;
  the successful retry omitted the output-file option, preserving that check.
  No capture links or root propagation were exercised. The full consumer/domain
  port now has independent scoped source acceptance: actual EVENTS descriptor
  retention, drain-derived authority, immutable State anchoring, the complete
  accepted history reducers, and exact Event328/affiliation validation. Seven
  new domain tests pass; the focused run passed 183/184, exposing an unchanged
  obsolete poll-bound source assertion. A separate one-field renderer-fixture
  correction restores workspace compilation and passes the real-renderer
  checker contract. Evidence is in private
  `consumer-domain-parent-followup/parent-acceptance.json`. The original-owner
  fixed-tail implementation and its signal-cancellation correction now have
  independent review and parent source acceptance. Expected cancellation keeps
  final profile/trace output and malformed accounting without granting retirement;
  genuine errors remain failures. Six cancellation, 13 root, 58 terminal and
  43 trace tests pass, as do all 973 userspace library tests, workspace compilation,
  scoped library Clippy and formatting. Four pre-fix output failures and two
  profile plus two trace causal failures are retained with exact restoration.
  Evidence: private `owned-root-fence-integration/parent-final/parent-acceptance.json`.
  The old poll-bound assertion has become a shared production-orchestration test.
  The full library run also exposed a stale doctor inventory count; its separate
  two-line correction preserves every unrequested-lane check and passes the
  exact regression and full library rerun after independent acceptance. Actual
  two-map identity, same-map drain recreation and retained-descriptor lifetime
  now pass an explicit ignored Rust test on host 7.0.0-30. A second actual
  self-probe reproduced an unsupported THREAD_OWNER map-load failure in the
  hazard checker. Its narrow loader correction preserves verdict/target policy
  and now reaches a measured Clean verdict. Both tests passed again on the
  final copied test binary, and independent source review found no defect in
  the bounded changes. A parallel socket
  fixture failure was traced to another test's fork inheriting the socket until
  exec. Isolating only that fixture preserves its original assertions, requires
  an explicit child completion marker, and passes 24 normal parallel events
  suites. Evidence: private
  `events-domain-hazard-runtime-parent/parent-final/parent-acceptance.json`.
  The accepted pre-runtime-fixture workspace library run passes 980 tests, with two privileged tests
  ignored there and passed separately; workspace check, all-target Clippy and
  formatting pass. Integrated original-root lifecycle, nonempty/BUSY/discard
  progress, the full artifact suite and final kernel/ABI qualification remain
  open; the activation guard remains unconditional.
  The maintained canary validator and native fixtures now use Event328 and
  reject old320/invalid affiliation before oracle effects. Independent review
  accepts the exact current source: 12 native tests pass for each ABI width,
  both checker self-tests pass, and default22/13 and diagnostic23/18 embedded
  inventories pass with opposite-variant refusal controls. The named canary
  Cargo wrapper and formatting pass. Evidence is in private
  `canary-event328-integration/parent-acceptance.json`. Missing Python before
  snapshots limit the historical delta claim; current-source and runtime
  qualification remain distinct, and no kernel canary pass is claimed here.
  An earlier full artifact run recorded 93 passes and 12 failures. Two
  checksum-incoherent lane-13 fixtures now pass individually using checked-in
  pinned YAML and real hashing. Two canary/inventory checks now also pass in
  focused runs. The frozen discovery-evidence bridge also now passes with
  compiled native-helper call and argument-flow checks. Seven original
  source/backend stopping assertions remained at that checkpoint; the newer
  full-suite result is recorded below. The checker correction now rejects unexpected
  counter-value/pointer writes, including register-width aliases and repeated
  increments. Independent rereview found no remaining bounded finding; the
  parent accepted 84 new control executions, 71 retained controls, both actual
  object CLIs and self-tests, and fresh native-owner/frozen-evidence Cargo bridges.
  Evidence: private `owned-discovery-contract-integration/parent-final/parent-acceptance.json`.
  A native birth-hook fixture now exercises successful process-child identity
  forwarding and refusal paths through the real C hook, with a passing Cargo
  bridge and no independent source finding. Fresh native replay receipts close
  current evidence custody while preserving the historical missing-receipt limit.
  Three bounded components now have independent review and parent acceptance.
  The compiled entry checker covers cookie routing, descriptor materialization,
  refusal before admission, distinct map/owner operations, full START keys and
  Event.slot through submission, including overlapping and atomic writes.
  Its CLI remains partial/exit2: selected decoder layout, template specialization
  and final argument wiring still need their own coverage. The host component
  tests the real loaded-object preparation sequence, tail write/readback/freeze,
  actual attach-cookie scheduling and Session privacy. The constructor doctest
  now fails for actual privacy and compiles under the recorded visibility-only
  control. Complete preparation still ends at the real unconditional activation
  guard. The typed-birth/direct-name object checker verifies compiled hook
  linkage and finite classification through the payload passed to emit_export.
  Its correction rejects alternate builder paths and register-width aliases;
  106 negative controls, equivalent safe aliases and six CLI checks pass.
  Evidence: private `entry-consumer-contract-integration/parent-final/`,
  `host-preparation-contract-integration/parent-final/` and
  `birth-name-object-contract-integration/parent-final/parent-acceptance.json`.
  G2/G3 now have bounded parent acceptance: the actual current-feature embedded
  object drives all six typed-birth/name Python test families through Cargo,
  with both default and diagnostic feature bridges passing. The Python driver
  retains dual-object mode, rejects all 11 incomplete/mixed input controls,
  and its disabled-checker control fails as expected. The obsolete typed-birth
  spelling guard is replaced; the redundant descriptor-publication spelling
  guard is removed after the retained 48 host tests and native birth bridge
  passed. Independent review found no material defect in the two-file patch.
  Evidence: private `typed-birth-cargo-bridge-parent/parent-final/parent-acceptance.json`.
  The new full artifact run records **96 passes and 8 failures**: five earlier
  source guards, two additional capture-loop spelling guards, and the lane-13
  readiness assertion. The latter passes isolated replays, so its original
  cause remains unknown. A tests-only comparator correction and readiness
  diagnostics are under independent review; they do not establish a readiness
  fix. The two capture-loop guards need behavioral coverage of real scheduling
  and capture-facts projection before removal. Their old unconditional tick
  retirement and old constructor spelling must not be restored to satisfy them.
  The entry final-sink checker extension is being implemented against frozen
  objects, with CLI partial/exit2 retained pending acceptance. A separate
  ignored native root-exit fixture is in compile-only implementation, using
  real async pending calls, genuine reap, bounded map consumption and distinct
  profile/trace runs. It does not remove the maintained activation guard or
  establish runtime qualification. Selection transport, downstream ring/public-output
  privacy and the remaining host/decoder counterparts are separate obligations;
  a bounded component does not close an architecture group or qualify runtime.
  Actual propagation after freeze, fast post-reap OPEN/PENDING retirement
  through the sole-reader ring fence, failure/availability and required kernel
  qualification remain unrun. The exact root-tail design is now selected:
  retain the successfully reaped original child and seeded map domain, snapshot
  one fixed producer boundary, and stop inside the existing reader's discard
  loop. Retire positive root histories only after prefix reduction, including
  first records decoded after reap; UNKNOWN histories retain pending custody.
  A one-second monotonic timeout preserves an explicit incomplete outcome.
  The additive bounded-reader API is independently accepted in private
  `aya-bounded-reader-integration/parent-final/parent-acceptance.json`: fresh
  producer positions and `next_before` use the existing parser, check the fixed
  stop inside its discard loop, and distinguish Item, Pending, Reached and
  malformed boundaries. Fresh retained receipts show all 176 library tests,
  an optimized wrap case and formatting pass; removing the internal stop makes
  the discard-prefix control fail, and restoring it passes. Six new test panic
  arms were corrected and independently reviewed. Broader vendor test Clippy
  still fails on seven unchanged-file panic findings, with zero reader-file
  findings; historical worker raw receipts remain absent and are not recreated.
  Application integration and runtime qualification remain open.
  The source review for the exit-drain boundary also identifies two Aya
  read-only atomic-load contract corrections and explicit wrapping consumer
  advancement. The primary selected a repository-contained copy of the exact
  published Aya 0.14.0 leaf package, preserving registry dependencies and
  licenses, with narrow fixes/native tests and source-ledger inclusion. This
  costs about 1.15 MB of dependency source; no second ring parser is selected.
  The package passes its 164 native unit tests and six reader regressions in
  three checked/optimized profiles; compiled debug/release review verifies the
  selected read-only loads and consumer store. Its independent source review
  found a copied-fixture omission. The fix passes a real-ledger missing-file
  control and the 29-case Cargo bridge. Two subsequent fixture corrections
  exclude ignored build output and move generated Git-helper control flow into
  an ordinary Python fixture. Independent rereview has zero remaining findings;
  the parent accepted the leaf/native/fixture scope in private
  `aya-leaf-correction/parent-acceptance.json`.
  Full current workspace gates, final source custody and production/runtime
  qualification remain required.
- [ ] **AR-15 / AC-03 — bounded mount-table admission.** Reuse the existing
  resource budget at `ProcessView::open_then_mountinfo` and its discovery
  identity callers. Test complete exact-limit success, over-limit refusal,
  repeated work charging and no reads after deadline/budget exhaustion at the
  actual reader boundary. Preserve object-open-before-mountinfo, namespace
  and generation checks. Never publish identity from a truncated table.
  Source and actual-consumer regression reviews now have zero findings.
  The latest frozen integrated run passes formatting, compilation, all 853
  library tests and all 103 artifact contracts. It then stops at two discovery
  scan integration budget assertions (15 pass, 2 fail). A tests-only correction
  passes both focused cases and all 17 scan tests. Independent review found
  a live-test-process map-drift risk in calibration; a follow-up reuses the
  blocked native driver and existing child cleanup guard. Focused and parallel
  17-test scans, formatting and scoped Clippy pass, and independent rereview
  accepts the correction. Subsequent suites, full Clippy and affected runtime
  qualification remained pending at that checkpoint. A subsequent full run
  exposed a separate publication-test setup dependency on mutable self maps.
  Its helper now supplies controlled scan facts while retaining real executable
  pinning, hashing, native ABI and process-generation checks. Independent review
  accepts the exact two-region test change; the old failing map bytes were not
  retained, so a particular kernel race is not proved. A separate test-only
  `then_some` lint correction precedes the latest passing four-gate checkpoint
  above. Actual affected runtime qualification remains pending; see private
  `mountinfo-budget/parent-source-checkpoint.json` for exact source identities.
- [ ] **AR-16 / AC-04 — abandoned-state test and disposition.** Use the actual
  small-state BPF build for an abandoned ordinary call and an abandoned
  export/selection transaction, each followed by a fresh completed call.
  Record finite duration, distinct abandoned transactions/churn and permitted
  evidence against the existing required rate/lifecycle contract. The
  64-entry discovery map can remain exhausted; duration alone is no bound on
  abandonment. The measurements below now require lifecycle-owned reclamation
  before release; a capacity-only deferral is not selected. The private primary
  reclamation selection records current-task ownership, exact bounded keys and
  conservative failure accounting. Availability under contention and actual
  recovery remain acceptance gates. Do not silently evict live slow HSM calls
  through timeout or LRU.
  The private native protocol is now independently source-reviewed and all six
  controls execute successfully: five fixed fault cases transfer the original
  child pidfd and report exact causes/statuses plus completed cleanup; inherited
  ignored SIGCHLD retains the expected failed launch and actual controller reap.
  A fresh normal run of the unchanged fixture also passes all five rows:
  306 workers, 240 completions and 66 joined abandonments. An isolated cached
  offline build verifies the actual small-state BPF capacities: START=1,
  RV_COUNTS=1, EVENTS=262144, DISCOVERY_STATE=64. The unchanged offline helper
  produces a full legacy 2.40 fixture manifest, unique slot 67, and ten distinct
  non-2.40 queries; the measured live 2.40 request needs no offline subtraction.
  The private external-gate controller and its source corrections are accepted
  after independent review. Sixteen standard native controls and an actual
  pre-ACK original-descriptor cancellation/settlement control are verified.
  The separate after-S sample preserves nonpass and unknown descendant status;
  it does not prove a post-fork boundary and is not promoted to one.
  Actual consumed CALL/COUNT_EVIDENCE and aggregated selection output are the
  selected oracles; no new binary ring reader is required. Successful terminal
  drain must precede fixture finish while its provider is mapped. The chosen
  caller-owned stdout/ledger route avoids an oracle-specific reclamation adapter.
  The output checker and coordinator cleanup corrections also passed independent
  review. A separately retained current-source small-state build passes compilation
  and actual map-capacity checks with all 49 inputs unchanged, under private
  `abandoned-state/small-state-current-9djp1bgs/`. Its explicit build selection
  passed independent review. The first frozen O-control attempt stopped before
  observer launch because the private provider check compared btrfs stat-device
  identity with maps-device identity. A retained-FD mountinfo correction passed
  an actual own-process RED/GREEN, 22 tests and independent review. A new frozen
  O-control attempt then reached the actual observer and CAPTURE marker, but
  stopped before releasing the workload: combined stderr diagnostics were
  rejected by the machine-trace parser. Both attempts retained original-child
  reap and cgroup settlement evidence; forced fixture teardown makes both
  lifecycle nonpass. Neither supplies completed-call or recovery measurements.
  The shared explicit stream split and the finite checker/coordinator corrections
  are now independently accepted. A new frozen campaign under private
  `native-fixture/parent-measurement-c4-bd2vpjat/` completed all five actual rows
  with normal cleanup and unchanged inputs. O-control captured 16/16 calls.
  With the one-entry START map, O-abandon completed eight fresh calls but
  captured zero returns and reported eight insertion failures. Its arithmetic
  in-flight value is nine, not retained-map occupancy; the checker incorrectly
  requires zero. S-one captured all eight completed selections after one
  abandonment. S-churn captured 63/72 completions with 18 state failures and
  zero ring loss; its expected discovery-unavailable skip still fails the
  checker's blanket empty-skip rule. S-control has a distinct loss: 90/136
  selections plus 46 discovery-ring drops, so it is not a valid loss-free
  control. Preserve these nonpasses. Checker correction3 now has independent
  and primary acceptance: 20 native tests pass, and retrospective CLI replay
  admits the exact O-abandon and S-churn source tuples with recovery false.
  S-control still refuses its 46 ring drops. Typed, coupled alternatives retain
  the distinct recovery requirements; no arbitrary loss or PARTIAL waiver was
  added. The original campaign receipts remain unchanged, and another runtime
  campaign requires a fresh input freeze. Reclamation and a separately labelled
  loss-free paced selection control remain open; no recovery or release
  acceptance follows from this checker correction. A separately reviewed native
  paced driver now completes all 136 distinct workers with a 20ms minimum gap.
  Its first actual observer run captures all 136 selections without ring loss,
  but the coordinator's three-second DONE observation window times out around
  the 3.076-second workload. Forced teardown makes that row a lifecycle nonpass.
  Preserve that failed row. The bounded five-second observation correction
  now has independent and primary source acceptance. A fresh frozen retry,
  private `native-fixture/parent-paced-c5-n8meihc8/`, exits zero with 136/136
  selections, zero ring loss and state failures, actual DONE observation,
  terminal evidence before F, normal observer/scope reaping and empty-cgroup
  settlement without rescue. All 171 inputs and nine outputs match their
  recorded hashes. Independent runtime review and primary acceptance now
  establish this single paced capacity control and normal lifecycle. They do
  not establish throughput, abandoned-state recovery or final-drain capability.
- [ ] **AR-17 — actual mandatory-lane admission.** Exercise production
  aggregators/callers, including `scripts/gates.sh`,
  `scripts/verify-capability-tier.sh` and Task 8's caller list. A missing
  prerequisite or absent expected capture must not yield release success.
  Preserve optional developer checks without treating their SKIP as positive
  qualification. Fix obsolete shared-launch arguments and exercise controlled
  failures. The initial `hosted_pipeline_names_every_unrun_privileged_lane`
  failure is corrected: native ABI fixtures now live under tests/shell and
  tests/fixtures, and CI names only the real ABI runtime lane as UNRUN. Exact
  reverse path substitutions preserve prior behavior. The named inventory
  RED/GREEN, native bridge, direct run from /tmp and all four pipeline
  contracts pass; independent review accepts this bounded correction.
  Replace demonstrated model-only receipt checks with actual boundary tests.
  The native lane-13 migration and containment corrections are accepted after
  independent review: 16 real native controls and all 103 artifact contracts
  pass. The initial missing-API/invalid-BPF RED is retained but excluded from
  original-bug sensitivity claims; final actual-helper controls support the
  bounded source acceptance. Production Knative qualification remains open.
  Also correct Knative's early-provenance-refusal diagnostics after the native
  lane-13 fixture migration: refusal can precede WORK/start-ledger creation,
  while cleanup attempts end-ledger files under the nonexistent directory.
  Preserve nonpass and owned cleanup; report the unestablished ledger phase
  without inventing start/end evidence. Private artifact-integration-diagnosis.md
  records the actual failing transcript and source anchors.
  A separate actual helper-boundary reproduction confirms that record_inputs
  can return zero after its Python recorder fails because the final rm succeeds
  under cleanup's set +e. Propagate recording errors explicitly and compare
  ledgers only after their phases succeed. This does not establish full-lane
  false success: later comparisons may still reject. Private
  `knative-ledger-boundary-yq7dcl_7/` retains the raw result and bounded design.
  Production ledger error propagation and explicit successful-start phase now
  have a zero-finding source review. Full artifact execution exposed two test
  failures, followed by bounded test corrections. The synthetic fixture setup
  is reviewed; scheduler-state/closed-fd races and actual live-body control are
  corrected. The final correction retains original handles through inspection
  errors, establishes unconditional fixture failure cleanup and moves the
  embedded Python helper into `controlled-body.py`. Its 15 focused and 28 native
  controls pass and independent review has zero findings. All 103 Cargo artifact
  contracts also pass in the latest full gate run. This closes the bounded test
  corrections, while actual production Knative qualification and the remaining
  mandatory-lane/shared-caller integrations stay open.
- [ ] Independently review each correction, run affected native/Cargo checks,
  then affected actual kernel/capture qualification. Keep all original gap
  controls and independent observations; a source-level pass is insufficient.

## Task 8d: Make the delivered observer usable and truthful

**Files:** `README.md`, `docs/usage.md`, affected output/schema documentation,
and the existing release build/package scripts. Assign helper build changes
separately from documentation; no additional capture-policy authority.

- [ ] Walk through a fresh-extracted release: download/install and checksum,
  binary/helper selection, help/doctor, passive diagnostic capture and output
  interpretation. Update the stale engineering status only to verified facts.
- [ ] Provide a distinct attested semantic workflow. Manifest-free scans are
  count-only; explain explicit manifest attestation and that the offline
  helper executes provider code. Remove parameter-combination promises where
  shipped output is always null/empty; do not add unsafe decoding to fulfill
  misleading documentation.
  The four-file README/usage/v2/v3 wording correction passed independent
  source and CLI review with no findings (PO-02/PO-03). It documents passive
  count-only diagnostics, explicit attestation, helper execution and ABI/libc
  requirements, and default null parameters/empty template operations. Actual
  positive/negative semantic captures and extracted-package use remain open.
- [ ] Show current v3 output, terminal PARTIAL, concrete loss/probe counters
  and exit-status limits. Explain T4 availability versus confined-target
  safety, uretprobe/seccomp SIGSYS and capture duration versus child lifetime.
- [ ] Define observer/helper/provider ABI and libc combinations. Qualify the
  delivered helper on the oldest promised userspace and a usable same-bitness
  ia32 attestation-to-semantic-capture path. A qualified documented build route
  is allowed; no cross-ABI dlopen framework is required. A Bookworm build does
  not by itself prove Jammy incompatibility or compatibility.
  Reuse the existing glibc32/glibc64/musl32/musl64 source-build checkpoint with
  matching-provider loads and opposite-width refusals. Source feasibility is
  already demonstrated; final recipient delivery/capture acceptance is open.
- [ ] Reconcile the finite required kernel/configuration matrix with final
  receipts. Missing ia32 prerequisites are not positive qualification and do
  not authorize silently dropping a required row.

Conventional `--version`/`-V` is now accepted: Cargo package version on stdout,
no capture startup, explicit rejection of trailing arguments. Formatting, build,
17 existing CLI tests, scoped Clippy and five actual process checks pass with
independent zero-finding review. It reports package version, not dirty-tree identity.
Recommended remaining additions are worked per-provider interpretation,
a version-pinned manual comparison example with pkcs11-check,
and resolved build-input recording. The comparison example is optional;
observed coverage versus provider capability must be clear either way.
Universal commercial-HSM coverage, automated pkcs11-lab assessment, extra
decoders, new host architectures, deployment products, producer-schema changes
and broad engine/framework rewrites remain deferred unless a separate concrete
requirement justifies them. Existing required ia32, container, Fedora SELinux
and kernel qualification is retained.

## Task 9: Final architecture gate and integration

Finite required kernel closure follows the existing owner ABI plan and PRD:
Jammy `5.15.0-187-generic`; additional Jammy GA `5.15.0-25-generic`, package
`5.15.0-25.25`, selected with signed-index acquisition and offline BTF
relocation evidence (boot and capture remain unrun); Noble `6.8.0-137-generic`;
`6.17.0-1022-azure`; filtered-target `6.11.0-17-generic`; exact CentOS Stream 9
`5.14.0-741.el9`; and Fedora 44/6.19 with SELinux Enforcing (historical exact
guest `6.19.10-300.fc44.x86_64`). Record the actual selected build and separate
native64/ia32 status; all final-candidate rows remain open. Fixed 6.11.0-29 and
host 7.0 are supplementary, not replacements. Keep the approved orthogonal
kernel/deployment axes; do not invent a full cross-product. Missing ia32
prerequisites do not qualify a positive row. The private broad-review
`required-matrix-checklist.md` retains exact authority anchors, expected
controls and historical evidence; live plan amendments and final receipts
supersede its extraction-time status.

- [ ] Astra xhigh independently challenges the combined design and reviews
  scoped corrections; the primary resolves every finding in this ledger.
- [ ] After writers stop, run `cargo +1.88 fmt --all -- --check`,
  `cargo +1.88 check --locked --workspace --all-targets`,
  `cargo +1.88 test --locked --workspace --all-targets`, and
  `cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings`.
- [ ] Verify direct language tests, named Cargo/CI selection and both embedded
  BPF variants. Record revised case inventory without treating empty suites
  or missing environments as passed qualification.
- [ ] Repeat affected W7/W5/W6 kernel, ABI, privacy and lifecycle evidence on
  the integrated candidate; update the acceptance table and source-custody
  manifests. Run a final independent architecture/gap cycle to zero.
- [ ] Only then proceed through W8 final-tip qualification, receipt, documentation
  and fresh-extracted source/portable bundle verification. Publication remains
  a separate owner decision.

## Bounded acceptance checkpoint — 2026-09-08, root-exit execution

The reviewed original-root regression now executed successfully on the
supplementary Linux x86-64 `7.0.0-30-generic` host. A frozen private diagnostic
build, whose sole source delta permits activation, passed the exact ignored
regression with fresh profile and trace scenarios. Real Engine discovery/pins
and six per-offset endpoints produced two actual call records. Genuine original
reap preceded first dequeue; the saved producer boundary remained 672 bytes;
pending admission survived token construction and ended only when the token
authorized retirement. Each final snapshot had two calls, one closed async
session, zero pending/in-flight/event-loss counters and terminal `PARTIAL`.
The maintained binary separately reached its expected activation refusal after
real discovery. The maintained guard is unchanged. This closes only this finite
host scenario; public capture-loop scheduling, other lifecycle cases, ia32 and
all required K1–K7 final-candidate lanes remain open.

The G4.2 host export-cookie overflow row has bounded parent acceptance after
independent zero-finding review. A fixed private test registry boundary drives
the real collector with a loaded/pinned ELF. Both unchecked-cookie and omitted
partial-evidence mutations cause actual assertion failures. Other G4 rows,
compiled forwarding and final all-target gates remain open.

The lane13 comparator and bounded readiness diagnostic corrections have bounded
parent acceptance after correction of the review finding. Missing/unreadable
ledgers and oversized single-line inputs retain bounded primary diagnostics.
The subsequent full artifact run passed the existing lane13 bridge but failed
overall: 96 passed, eight failed. Seven are the outstanding source guards; the
other is split-ACK launcher handle adoption before intended interruption. Two
isolated launcher replays passed; the original cause remains unknown. The new
Python diagnostic case is absent from the Rust bridge's manual 31-name list;
selecting the whole existing test class and verifying all 32 is still required.

The compiled entry final-sink extension is not accepted. Independent review
reproduced false acceptance when pointer/extent branches were changed from
64-bit to 32-bit register comparisons. Correct the checker's width-sensitive
branch reasoning with causal controls and repeat review before replacing any
legacy guard. Its CLI remains `partial`/exit 2.

These component results do not close architecture groups or change the order
W7 → W5 → W6 → W8. Exact receipts, frozen source/binary identities and parent
acceptances are retained in the private release workspace.

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# System-Scope Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the confirmed system-scope fork and evidence defects, replace misleading coverage claims with behavioral tests, and produce an exact-tip qualification record.

**Architecture:** Keep `scope_auth` as the BPF authorization boundary, make its fork gate admit cgroup and system scopes under event-producing policies, and pin the compiled decision with refusal mutations. Reuse the existing discovery selector, private refresh test adapter, and finite output sanitizer. Separate source/test closure from privileged live qualification.

**Tech Stack:** Rust 1.88, edition 2024; pinned BPF toolchain; native C bridge; Python object/evidence checkers; Linux x86-64 first.

**Spec:** [2026-09-19 project deep review](../reports/2026-09-19-project-deep-review.md), findings F1–F5, at committed feature tip `eb317641e76cad5360c14ffede806c41a8e652e6`; also `AGENTS.md`, `docs/privacy/allowlist-v1.md`, and `docs/superpowers/plans/ROADMAP.md`.

## Global Constraints

- Keep changes scoped and preserve unrelated work. The shared checkout acquired uncommitted candidate edits to several F1/F2/F5 files while this plan was drafted. Treat them as in-progress work: inspect and retain them, then verify each applicable acceptance check before calling a finding closed. Do not reset or overwrite them. Where a candidate already implements a task, prove test sensitivity with a temporary mutation in an isolated edit instead of manufacturing a RED run by undoing someone else's work.
- Preserve `docs/privacy/allowlist-v1.md`; never broaden capture implicitly. Public discovery skips stay categorical even when internal diagnostics gain counts.
- Keep Rust 1.88, edition 2024, and Linux x86-64-first support. Use `mise exec -- ./scripts/cargo.sh +1.88` with `--locked --offline` for Rust checks.
- Test temp I/O uses `TMPDIR=/var/tmp/p11scope-ws-tmp`. Create that directory mode `0700` if missing; leave an existing trusted directory's permissions intact.
- Preserve owner-health refusal, exact CONFIG scope/policy validation, PID-only pause, aggregate suppression of EVENTS, generation ownership, and bounded discovery work. Do not change the Event ABI or activate the legacy `CFG_TASK_NEWTASK_OFFSETS` cell.
- Do not weaken assertions, convert failures to ignored tests, inflate timeouts in place of diagnosis, or treat fixture compatibility as live BPF proof.
- Do not track generated objects or logs. Get explicit approval before privileged or container experiments. Commit each finished, verified task; review after its writer stops. Do not merge, push, rewrite history, tag, or publish under this plan.

## Review Focus

1. Aggregate policy, PID scope, malformed CONFIG, and unhealthy owner must refuse FORK emission: Task 1's host/object refusal tests and the later live rows.
2. A FORK returning “handled” after history rejection must fail the positive test: Task 1 checks inherited state and rejection counters.
3. A non-prefix provider selection can choose fewer than the cap, and refresh can exclude known views: Task 2 checks selected-versus-scanned wording in both paths.
4. A later process must join the **same** engine without replacing the first generation or resetting the budget: Task 3 checks view IDs, claims, and attachment intents.
5. Missing, non-string, unknown, or identity-bearing `capture.scope` must fail current-schema validation, while historical metrics and terminal trace keep their own shapes: Task 4.

## Starting state and file map

The report's original uncommitted-patch description is historical. The feature itself is committed at `eb31764`; the routine check results in the report were run against byte-identical feature sources. At plan-writing time another writer's F1/F2/F5 candidates were present but uncommitted. Before execution record `git status --short --branch`, `git rev-parse HEAD`, and the exact candidate diff. A passing check on a dirty tree is not an exact-tip qualification receipt. An unexecuted check is `UNRUN`, a command that cannot start is `BLOCKED` with its exact error, and an executed failing assertion is `FAIL`.

| File | Responsibility |
| --- | --- |
| `crates/ebpf/src/main.rs`, `crates/ebpf-common/src/lib.rs` | Authenticated fork gate; existing exact CONFIG validator and host matrix |
| `scripts/check-discovery-flow-object.py`, `tests/python/test_discovery_flow_object.py` | Compiled gate recipe and refusal mutations for both BPF objects |
| `tests/artifact_contracts.rs`, `src/run.rs` | Aggregate emit-order contract and positive semantic FORK consumer |
| `src/discovery/engine.rs`, `src/discovery/engine_tests.rs` | Selection diagnostics and retained-engine refresh behavior |
| `tests/system_scope.rs`, `tests/support/` | Accurate unprivileged smoke claim and loaded-provider fixtures |
| `src/render.rs`, `scripts/check-capture-evidence.py` | Final `PARTIAL`/sanitization and current-schema scope validation |
| `src/cli.rs`, `docs/usage.md`, `docs/superpowers/plans/ROADMAP.md` | Error copy and feature/qualification status |

### Task 1: Close the authenticated FORK producer and semantic-consumer loop (F1)

**Files:** Modify `crates/ebpf/src/main.rs:2584-2597`, `scripts/check-discovery-flow-object.py:150-169`, `tests/python/test_discovery_flow_object.py:105-123`, `tests/artifact_contracts.rs:9354-9415`, and `src/run.rs:6877-6900`. Inspect `crates/ebpf-common/src/lib.rs:302-333` and `crates/ebpf/native/image_identity.c:160-190` without changing their ABI.

**Interfaces:** `scope_auth() -> Option<ScopeAuth>` remains the real authorization check; `p11_link_fork_allowed() -> u32` remains the native bridge. The gate's accepted flags are exactly `(FLAG_CGROUP_FILTER | FLAG_SYSTEM_FILTER)` combined with one event-producing policy; `valid_config` already rejects zero/multiple scopes, zero/multiple policies, unknown bits, and pause outside PID scope. `observe_fork(...) -> bool` means “record handled,” not “history accepted.”

- [ ] Inspect the in-progress F1 diff against the original `eb31764` bug. Keep `scope_auth()` before the scope/policy decision, the native gate before identity work and emission, and aggregate refusal. If the candidate still lacks the system bit, make the minimal gate change `scope.flags & (FLAG_CGROUP_FILTER | FLAG_SYSTEM_FILTER) == 0`; retain the separate aggregate check.
- [ ] RED for the compiled producer: temporarily restore the cgroup-only mask in an isolated test edit and run the compiled birth contract below. Require failure specifically at `typed-birth:scope`, then restore the candidate before GREEN. If starting from the unfixed commit, first add the updated checker and observe this RED naturally. Never leave the mutation in a commit.
- [ ] Update/verify the finite object recipe against the rebuilt **default and diagnostic** objects. Its admission mask must be `0x42`, not `0x2`, with the real `scope_auth` call and aggregate refusal still on every emit path. In `tests/python/test_discovery_flow_object.py`, require effective mutations for cgroup-only `0x2`, PID-admitting `0x43`, zero mask, authorization bypass, and aggregate bypass; each mutation must match the disassembly and fail for the intended scope contract.
- [ ] Add or finish a positive `src/run.rs` system FORK regression using distinct parent/child PIDs and nonzero distinct task cookies. Open one fork-safe `C_OpenSession` on the admitted parent, feed a genuine `FORK` to `observe_fork`, then require `state.sessions().inherited == 1` and `state.semantic_evidence().semantic_history_drops == 0`. Replay the same birth and require inheritance remains `1`. Add the old same-PID/zero-cookie shape as a negative control whose rejection evidence changes. The existing `cgroup_process_creation_inherits_once_and_tags_into_cgroup_no_inherit` test at `src/run.rs:5899` supplies the slot, adapter, and event pattern.
- [ ] Retain `aggregate_policy_returns_before_both_events_reserves` in `tests/artifact_contracts.rs`: exactly two `EVENTS.reserve::<Event>(0)` sites, return-path policy gate before reserve, aggregate refusal in the fork gate, and native `p11_link_fork_allowed` before `p11_link_emit_fork`. Update its source-marker only if the code is refactored; a direct gate change should need no weakening.
- [ ] Run GREEN sequentially; the artifact tests build/check embedded BPF objects but do not load them:

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib system_scope_admits_fork_children_without_a_destination_check -- --nocapture
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --test artifact_contracts aggregate_policy_returns_before_both_events_reserves -- --exact
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --test artifact_contracts compiled_birth_and_interface_name_contracts -- --exact
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --features unsafe-unvalidated-metadata --test artifact_contracts compiled_birth_and_interface_name_contracts -- --exact
```

- [ ] Review the complete F1 candidate after its writer stops. Confirm that the positive consumer test would fail on the original malformed event and the object mutations would fail if either scope or policy refusal disappeared. Commit the accepted change as `fix: admit system scope process births`.

### Task 2: Make capped selection diagnostics true without exposing identities (F2 and part of F5)

**Files:** Modify `src/discovery/engine.rs:3428-3545,11836-11915`, `src/discovery/engine_tests.rs:4059-4175,16564-16695`, `tests/system_scope.rs:231-255`, and `src/render.rs` tests near `:3127`.

**Interfaces:** Preserve `select_deep_scan_candidates(&[(u32, Vec<MapEntry>)], usize) -> Vec<u32>`, `capture_skipped_out(&Skipped) -> SkippedOut`, and `Evidence::verdict()`. Add a private `scan_cap_reason(total: usize, selected: usize, cap: usize, live: bool) -> String` used only for internal `Skipped.reason`; `subject` remains `scope_label(scope)`.

- [ ] Add a selection fixture with PIDs `7`, `8`, and `9001` where the rare provider at `9001` wins cap `1`, and a grouped fixture where cap `2` yields one representative. Assert the selected PIDs, not just a `Skipped` string. Add an initial diagnostic assertion that `3` in scope and cap `1` says **selected 1 for deep scanning by provider rarity**; for the grouped case cap `2` says **selected 1**. The case `total <= cap` must create no cap skip.
- [ ] Add a refresh test using the existing private `refresh_inventory_once` helper at `src/discovery/engine_tests.rs:3730`. Keep one known view and introduce a later process, then assert that the refresh diagnostic counts only **new candidates selected for deep scanning** after known-view exclusion. It must not say they were successfully scanned; opening a selected PID can still fail. Preserve the membership-incomplete and partial markers.
- [ ] Run the new `scan_cap_diagnostic_reports_actual_selection` test RED against the original “first N” wording:

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib scan_cap_diagnostic_reports_actual_selection -- --nocapture
```

- [ ] Move initial skip construction after `selected` exists; format `total`, `selected.len()`, and `cap`. In refresh, retain `pids.len()` before consuming `pids`, construct `desired`, subtract known views, and format `new_pids.len()` for the live/new-candidate message before its early return. Use wording such as `3 processes in scope; discovery selected 1 for deep scanning by provider rarity (limit 2); unselected processes may contain undiscovered providers`. For refresh say `live discovery selected 1 new candidate for deep scanning ...`; do not claim successful scans. Preserve `attribution::note`, `object_skips`, and `mark_partial` behavior.
- [ ] Replace `scanned the first` assertions in `src/discovery/engine_tests.rs` and `tests/system_scope.rs` with count/selection assertions. Keep `tests/system_scope.rs` an unprivileged plan-skip smoke test, not a final-evidence proof.
- [ ] In `src/render.rs`, use the existing `evidence()` fixture to assert a cap skip alone changes the verdict from `COMPLETE` to `PARTIAL`. Serialize profile and metrics outputs and assert `evidence.skipped` contains only `{ "name": "discovery subject", "reason": "discovery unavailable" }` for that skip. Do not search the entire document for process identities; provider fields have their own permitted contract. Prove the test is sensitive by temporarily bypassing the skip projection, then restore it.
- [ ] Run GREEN:

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib scan_cap_diagnostic_reports_actual_selection -- --nocapture
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib cap_skip_forces_partial_in_profile_and_metrics -- --nocapture
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --test system_scope
```

- [ ] Review initial versus refresh counts, failure/known-view cases, and unchanged public sanitization; commit as `fix: report actual capped discovery selection`.

### Task 3: Prove same-engine later-process discovery (F3)

**Files:** Modify `src/discovery/engine_tests.rs`, `tests/system_scope.rs`, and, if sharing the existing C fixture is needed, create `tests/support/system_scope.rs` and expose it in `tests/support/mod.rs`. Keep production `Engine` APIs private.

**Interfaces:** Reuse private `Engine::refresh_inventory`, `ScriptedSession::with_records([], 0)`, `Engine::collect_discovery_records`, `PendingViewRetirements::new()`, and `PauseClosure::new(true)` as in `refresh_inventory_once`. Use the existing `build_fixture`, `build_driver`, and `spawn_loaded` bodies at `tests/system_scope.rs:25-87` to create two owned children loading distinct `.so` files.

- [ ] Rename `system_scope_observes_two_processes_and_picks_up_a_new_child` to `system_scope_separate_snapshots_discover_later_process`; update its comment to say it constructs two independent engines. Keep its provider-module smoke assertions.
- [ ] Add `system_scope_refresh_admits_later_generation_in_same_engine` inside `engine_tests.rs`. Spawn child A, call `Engine::discover(&system_args(...), &Scope::System, None)` **once**, and record A's `ProcessViewId`, provider identity, `scan_inputs`, pinned claims, attachment intent, and attempted-I/O budget. Spawn B afterward, then call the actual private `refresh_inventory` with a `ScriptedSession`, collection callback, mutable records/retirements, and pause closure (copy the exact argument pattern from `refresh_inventory_once`).
- [ ] Assert A retains its original view ID and ownership, B gets a distinct view ID and its own provider/slot attribution, both have pinned claims, B has a newly requested attachment intent, and the capture-wide budget did not reset. Refresh once more without changing either child; require stable view IDs and no duplicate B attachment. Reap B through its owned guard before a further refresh and assert A remains. Do not equate PID disappearance alone with owned termination.
- [ ] Run the test RED with a temporary early return immediately before new-view admission; require failure on B's absent view/claim/attachment. Restore it and run GREEN:

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib system_scope_refresh_admits_later_generation_in_same_engine -- --nocapture
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --test system_scope
```

- [ ] Review that one engine survives both child starts, real reconciliation executes, test fixtures own/reap their children, and no public test-only engine API was added. Commit as `test: cover retained system scope refresh`.

### Task 4: Enforce the current-schema `capture.scope` contract (F5)

**Files:** Modify `scripts/check-capture-evidence.py:525-548,1195-1218,1428-1455,1966-2025` and its other current v3 profile validation call sites. Inspect `docs/schema/observed-profile-v3.md:115-117` and the historical metrics/trace validators without changing their schemas.

**Interfaces:** Add `exact_capture_scope(document) -> None`. Invoke it from current v3 profile and metrics validators, including `exact_capture_modules` and `exact_metrics_schema`. Keep `exact_historical_metrics_schema` separate; terminal trace has no `capture` header.

- [ ] Make `document_fixture` emit `"scope": "pid"` for current v3 profile/metrics fixtures. Retain a historical v2-metrics fixture without this new field. In `self_test`, pass valid `pid`, `cgroup`, and `system` values through the real current validators. Add `rejected(...)` mutations for missing, `None`, `False`, a number, list, object, empty string, `unknown`, `pid:424242991`, and `/sys/fs/cgroup/private.scope` in both current profile and metrics paths.
- [ ] Run `python3 -I scripts/check-capture-evidence.py --self-test` RED; the new mutation must be accepted by the old validator and therefore fail with `mutated fixture was accepted`.
- [ ] Implement a finite, non-echoing check:

```python
def exact_capture_scope(document):
    capture = document.get("capture")
    require(isinstance(capture, dict), "capture must be an object")
    scope = capture.get("scope")
    require(
        isinstance(scope, str) and scope in ("pid", "cgroup", "system"),
        "capture.scope must be exactly pid, cgroup, or system",
    )
```

- [ ] Run GREEN and the renderer's existing scope test:

```sh
python3 -I scripts/check-capture-evidence.py --self-test
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib profile_and_metrics_json_disclose_the_scope_kind
```

- [ ] Review all current-schema entry paths, historical isolation, trace shape, and absence of invalid-input echoes. Commit as `fix: validate capture scope evidence`.

### Task 5: Correct CLI copy and feature-status documentation (F5)

**Files:** Modify `src/cli.rs:645-648,1086`, `tests/system_scope.rs:169`, `tests/artifact_contracts.rs:6530`, `docs/usage.md:306-321`, and `docs/superpowers/plans/ROADMAP.md:394-399`.

**Interfaces:** Parsing semantics and accepted scopes stay unchanged. The `run` error must name all three rejected capture selectors.

- [ ] Change the two tests to require the exact error `run has no --pid, --cgroup, or --system: it captures exactly the command it starts`. Run the focused CLI and integration tests RED:

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib cli::tests::run_rejects_scope_flags_an_empty_command_and_unknown_pause_values -- --exact
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --test system_scope system_scope_is_one_of_three_and_mutually_exclusive -- --exact
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --test artifact_contracts usage_documents_every_subcommand_and_capture_needs_no_manifest -- --exact
```

- [ ] Put the exact message in `parse_run`, update the binary-usage artifact assertion, and run the same tests GREEN. The checked filters must each execute one test; a zero-match result is not GREEN.
- [ ] In `docs/usage.md`, describe system admission as all tasks subject to owner/config checks and bounded discovery, with live exact-tip qualification pending. Mark ROADMAP's earlier system-wide deferral as historical, link the report and this plan, and retain its W7 → W5 → W6 → W8 and publication gates. Do not promise that every process/call is captured or imply old receipts qualify this feature.
- [ ] Run `git diff --check`, review wording against the code/receipts, and commit as `docs: clarify system scope status and restrictions`.

### Task 6: Diagnose the static-executable full-suite failure and rerun local gates (F4)

**Files:** Initially inspect `src/discovery/engine_tests.rs:3036-3110`, `src/discovery/engine.rs:5378-5405`, and `docs/notes/known-flakes.md`. Change fixture or production code only if reproduction identifies a mechanism.

**Interfaces:** Preserve static executable `NotArmable`: `Ok(false)`, no object skip, no loader context, zero unavailable growth, and a live child while arming.

- [ ] Run the exact test with `--exact --nocapture`; record exit status and relevant output. A pass alone does not clear the reported full-suite failure:

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib discovery::engine::tests::arming_a_static_executable_is_not_armable_not_partial -- --exact --nocapture
```

- [ ] Run the full library binary at normal parallelism. If it fails, retain the child while recording `/proc/PID/exe`, the exact `/proc/PID/maps` snapshot, retained executable/view identity, child status, and budget/deadline state at the failing boundary, before kill/reap:

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib -- --nocapture
```

- [ ] Classify evidence: if a transient executable-map readiness race is demonstrated, wait boundedly for the exact matching executable map before opening the view; if a production identity/budget defect is demonstrated, add a failing regression and fix that cause; if unreproduced, record it as unresolved and make no speculative timeout/readiness change. Compare on an isolated pristine base only if patch attribution matters, with separate target/temp directories.
- [ ] If code changes, show the reproducer failing before and passing after, repeat the normally parallel library run, stop the writer for independent review, and commit the proven fix. Do not label an isolated pass a known flake.
- [ ] Freeze the corrected source commit and run the four canonical local gates sequentially. Record every binary reached and the exact exit/failure. A failure in the first library binary leaves later binaries unrun in that command:

```sh
mise exec -- ./scripts/cargo.sh +1.88 fmt --all -- --check
mise exec -- ./scripts/cargo.sh +1.88 check --locked --offline --workspace --all-targets
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.88 clippy --locked --offline --workspace --all-targets -- -D warnings
```

- [ ] Review the entire corrected diff for authorization, lifecycle, privacy, and test quality after the writer stops. Resolve accepted findings, rerun affected gates, and record the reviewed commit and receipts. Do not promote the historical passing isolated test or earlier main-branch gates to this exact tip.

## Privileged qualification boundary

Tasks 1–6 establish source and unprivileged-test closure only. The existing `scripts/matrix/verify-fork-scope.sh` is a cgroup oracle; it does not offer a `--system` mode. Prepare a separate reviewed system-scope driver/checker using existing custody and receipt conventions before requesting approval for live execution. It must retain private event order or assert equivalent authenticated semantic ordering: final call counts alone do not prove FORK-before-child-CALL.

| Live row | Acceptance | Current status |
| --- | --- | --- |
| Default-object system profile | Two unrelated providers, later child in one capture, authenticated FORK before child CALL, inherited semantics, exact fixture counts | UNRUN |
| Default-object system trace | Same lifecycle, bounded trace, no prohibited argument/identity expansion | UNRUN |
| Diagnostic object, safe/unsafe profile | Safe allowlist behavior; unsafe only with explicit build/runtime opt-in; same birth behavior | UNRUN |
| System metrics, both objects | Exact aggregate counters, zero CALL/FORK EVENTS, no argument capture | UNRUN |
| Owner-health loss | Controlled failure of this observer's own state closes admission and reports honest terminal evidence | UNRUN |
| Cap/high churn and privacy | Bounded discovery, truthful `PARTIAL`, no stale ownership, existing allowlist canaries on actual captures | UNRUN |
| Kernel/ABI matrix | Required native64 and ia32 positive/refusal rows on selected kernels; unsupported prerequisites distinct | UNRUN |

Only after approval and execution, record exact source commit, both object hashes, observer/workload/checker hashes, kernel, ABI, policy, private raw evidence custody, cleanup, and result. Any later runtime-affecting change invalidates affected rows. ROADMAP's rate/loss, lifecycle, container/SELinux, receipt, and bundle gates remain separate obligations. Unexecuted rows block qualification and publication claims.

## Coverage and handoff

| Finding | Routine closure | Remaining gate |
| --- | --- | --- |
| F1 | Task 1: gate, object refusal mutations, semantic inheritance, aggregate guard | Live authenticated birth/call and owner-health rows |
| F2 | Task 2: initial/refresh selection diagnostics | Runtime cap/loss envelope |
| F3 | Task 3: same-engine generations and attachment intents | Reviewed live system oracle |
| F4 | Task 6: evidence-led diagnosis and four exact-tip gates | Mechanism unknown until reproduced |
| F5 | Tasks 2, 4, 5: `PARTIAL`, finite scope, CLI/docs | Current-schema and live output receipts |

The plan rejects removal of the fork guard, PID-prefix scanning merely to match old text, detailed public skip reasons, a public refresh API solely for tests, an engine rewrite, and speculative F4 timeout changes. Compiled-object tests cannot certify runtime ordering or owner-health behavior.

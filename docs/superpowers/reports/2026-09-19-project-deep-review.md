<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# p11scope project review and gap analysis — 2026-09-19

## Decision and review boundary

The current `feat/system-scope` change is **not ready to integrate or qualify**. Its BPF process-birth gate suppresses every fork event under `--system`, while the userspace consumer and documentation assume those events exist. The full local workspace test command also stopped at one library-test failure. The new unprivileged system-scope tests pass, but they do not exercise an ongoing live capture.

This is a review of the live project at `95ee1f829b1cd73193999a56daee51543261ca0a` plus the pre-existing uncommitted `--system` patch (tracked diff SHA-256 `7027f550ca0267d1e8b9a6fc6c75061049cac78ed4fdf7004cca6779f9447148`) and untracked `tests/system_scope.rs`. No product code was changed during this review. The release documents were used as requirements and historical evidence, not as proof that the present patch passed their gates. The older W7 worktree named in prior handoffs no longer exists here; the live checkout is `p11scope` on `feat/system-scope`.

Rechecked on 2026-09-19 at committed `eb31764`: the tracked feature patch has the same SHA-256 above and `tests/system_scope.rs` is now tracked. This recheck was source and checker-fixture inspection; it did not rerun the Rust gates or qualify live BPF. The original check results below remain results from the earlier, byte-identical source snapshot. Uncommitted candidate fixes appeared in the shared checkout while the follow-up plan was drafted; they are not counted as verified closures in this report.

The lenses were runtime lifecycle/concurrency, contract and test adequacy, privacy and authorization, operator-facing evidence, maintainability, and release readiness. Two independent read-only reviews covered the first two lenses; the primary inspected the cross-cutting paths and ran the checks below. This is not a complete formal security scan or live kernel qualification.

## Findings, ranked

### F1 — P1, confirmed correctness bug: system-scope forks never reach semantic history

`crates/ebpf/src/main.rs:2590` makes `p11_link_fork_allowed()` require `FLAG_CGROUP_FILTER`. `--system` publishes `FLAG_SYSTEM_FILTER` instead (`src/scope.rs:175-205`), so that function always returns zero for a valid system capture. The `task_newtask` producer in `crates/ebpf/native/image_identity.c:176-177` returns before constructing identities or emitting a FORK record. The earlier root-affiliation path handles thread propagation, not a replacement process-birth event (`crates/ebpf/native/root_affiliation.c:66-69`).

The new `Scope::System` branch in `src/run.rs:2579-2614` therefore cannot call `history_birth`/`fork_process` during live capture. That loses the inherited-session and active-operation handling in `src/semantics.rs:2648-2708`; attach can still report the process-creation hook available (`src/attach.rs:1859`). Ordinary CALL identity has an independent path, and `/proc` refresh can discover a child, so this finding does **not** establish that all child calls or process identities disappear.

**Fix:** admit exactly the cgroup and system scope bits in the fork gate, while retaining `scope_auth` owner-health/exact-config checks and aggregate-policy suppression. A small pure predicate shared by the gate and host tests would make this decision testable without a kernel. Update the compiled-object oracle: `scripts/check-discovery-flow-object.py:150-169` currently requires the cgroup-only `r2 &= 0x2` lowering, and `tests/python/test_discovery_flow_object.py:114` mutates that old condition. `tests/artifact_contracts.rs:9354-9400` also pins the literal aggregate-policy expression inside the gate; keep its policy and emit-order assertions meaningful if the predicate moves. Rebuild both BPF variants and revise the oracle against the new finite predicate; do not simply delete the guard.

**Acceptance:** a test of the actual producer admission decision accepts valid system+allowlisted and system+unsafe configurations, rejects aggregate, PID, missing owner and malformed configurations, and preserves cgroup behavior. Repair `src/run.rs:6877`: its synthetic FORK has the same parent/child PID and zero task cookies, so `observe_fork` rejects it while returning `true`; the current assertion is satisfied on the rejection path. Use distinct authenticated identities and assert inherited semantic state and no history rejection. Then run an authorized live fixture showing a system-scope FORK before its child CALL. Until that last check runs, the kernel result is unknown.

### F2 — P2, confirmed diagnostic error: cap text describes a different selection algorithm

When more processes exist than `max_scan_pids`, `select_deep_scan_candidates()` groups mappings and selects representatives by provider rarity (`src/discovery/engine.rs:3428-3478`). The internal initial skip nevertheless says discovery scanned **the first** N processes (`src/discovery/engine.rs:3517-3529`); live refresh repeats this wording at `:11841-11847`. Selection may be non-prefix and may select fewer than N representatives; selected processes can still fail to open during deep scan. The new cap test at `tests/system_scope.rs:236-255` requires the misleading phrase, so it cannot catch this mismatch. `docs/usage.md:311-316` correctly describes rarity-based selection. Public structured output flattens these internal details to a categorical skip (`src/render.rs:555`); this finding concerns the internal diagnostic and optional skip-attribution stderr, not an exposed PID-level reason.

**Fix:** form the diagnostic after selecting candidates and report the actual selected count out of the enumerated count, with a short statement that provider-rarity selection was used. Say **selected**, not **scanned**. Keep the skip as a bounded categorical loss that forces `PARTIAL`, without adding PIDs, paths or numerical selection details to the public evidence. Test a crafted PID order where the rare provider is not among the lowest PIDs, and assert the internal message agrees with the selected set. Apply the same correction to initial discovery and refresh.

### F3 — P2, validation gap: the new integration test restarts discovery instead of exercising live refresh

`tests/system_scope.rs:177-230` starts a child, builds one `Engine::discover`, starts another child, and builds a **new** engine. It proves that separate `/proc` snapshots can find two modules. It does not prove that one running session admits the later process generation, refreshes its attach plan, maintains per-process attribution, or captures calls from that child. The claim in `docs/usage.md:315-320` is stronger than this test. The test file explicitly says it loads no BPF object (`tests/system_scope.rs:1-5`).

**Fix:** retain one engine and drive its actual refresh/reconciliation path after the second child starts; assert both generation views, module ownership and attachment intents. Add a live, approval-gated system-capture oracle with two unrelated processes, a later fork, child calls, owner-health loss, and profile/metrics/trace policy behavior. Record the live row `UNRUN` until it executes. This is an evidence gap, not proof that refresh itself is broken.

### F4 — P2, unresolved local gate failure: full workspace tests are red on this snapshot

`TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline --workspace --all-targets` stopped in the first library binary: **1,063 passed, 1 failed, 3 ignored** (exit 101). The failure was `discovery::engine::tests::arming_a_static_executable_is_not_armable_not_partial`, which recorded `Skipped { subject: "live loader arming", reason: "retained executable has no usable executable mapping" }` at `src/discovery/engine_tests.rs:3088`. The same exact test passed in isolation. `/bin/busybox` on this host is statically linked, so the fixture's basic static assumption holds; the transient mapping snapshot or another parallel-run condition remains unproven. No subsequent test binary in that full command ran.

**Fix/investigation:** reproduce under load while retaining the child's `/proc/PID/exe`, `/proc/PID/maps`, view identity and scan-budget state at the failure boundary. If that confirms an exec/mapping readiness race, extend fixture readiness to include the executable mapping the test needs, with a bounded wait, while keeping the `NotArmable` assertions intact. Compare on a pristine base if attribution to this patch matters. Do not promote the isolated pass to a green workspace gate or soften the assertion. The historical `docs/notes/known-flakes.md` does not list this test, and the 2026-09-19 two-run main gate (`.superpowers/sdd/release-gate-2026-09-19.md`) used an earlier `3176bdb` tree, so neither closes this result.

### F5 — P3, contract and documentation drift around the new scope

- `docs/schema/observed-profile-v3.md:115-117` specifies `capture.scope` as exactly `pid`, `cgroup` or `system`. Rendering emits it (`src/render.rs:1000,1372`) and renderer unit tests cover the three strings (`src/render.rs:3127-3148`), but the inspected capture-evidence checker has no `capture.scope` validation or absence/invalid-value mutation (`scripts/check-capture-evidence.py`, especially `:1195-1218` and its capture checks at `:1692-1694`). Add an exact capture-header check and mutations for missing, unknown and identity-bearing scope values. Preserve the existing privacy allowlist.
- The cap test checks only a plan skip (`tests/system_scope.rs:248-255`), not the final `PARTIAL` verdict or sanitized serialized evidence. Drive that skip through `Evidence::verdict` and the final profile/metrics output; assert the categorical text contains no raw process identity.
- `docs/superpowers/plans/ROADMAP.md:394-399` still defers system-wide discovery, while the current branch documents `--system` as present (`docs/usage.md:306-321`). Mark the roadmap statement as historical and record the feature's actual review/qualification state. `src/cli.rs:645-648` rejects `run --system` correctly but its error names only `--pid`/`--cgroup`; include `--system` in that message and its assertion.

These are contract and usability gaps. The review did not find evidence that adding the `scope` string itself exposes a prohibited PID, cgroup path or call argument.

## Cross-cutting assessment

| View | What current evidence supports | Remaining gate or improvement |
| --- | --- | --- |
| Authorization and privacy | System capture requires an explicit CLI flag, exact one-scope/one-policy CONFIG validation, and the BPF owner-health gate (`src/cli.rs:565-588`, `crates/ebpf-common/src/lib.rs:313-334`, `crates/ebpf/src/main.rs:242-295`). PID-only pause remains enforced. | Qualify the widened all-process admission with default, unsafe-feature and aggregate policies; run the existing privacy canaries against actual system captures. No allowlist expansion is justified. |
| Completeness and performance | A default cap of 256 and a two-phase `/proc` sweep bound deep scans (`src/discovery/engine.rs:2827,3481-3540`). Exceeding the cap publishes a skip. | Measure a high-churn system capture on the selected kernel matrix, including ring loss, refresh latency, process-view capacity and truthful `PARTIAL`. The present test only checks an initial plan skip. |
| Test architecture | Unprivileged parsing, mapping discovery, synthetic ledger/overflow and rendering checks exist; the compiled birth contract passes on the current object. | Add a valid semantic FORK test, same-engine refresh test, final-output cap test and live BPF scenario. The compiled contract currently preserves the cgroup-only bug, so a passing oracle is not sufficient. |
| Maintainability | Scope decisions are spread across BPF, native C, host Rust, object recipes and documentation. `src/discovery/engine.rs` is 13,285 lines and `src/run.rs` is 7,497 lines. | After the behavior is pinned, centralize scope capability decisions (birth tracking, admission, pause) in small predicates and rename the reused `cgroup_*` admission fields/methods to reflect multi-process scope. Keep this bounded; a wholesale engine rewrite is not needed to fix F1. |
| Release/operations | Hosted CI names privileged lanes as `UNRUN` (`.github/workflows/ci.yml`); the release roadmap requires final-tip local gates and independent review (`docs/superpowers/plans/ROADMAP.md:626-744`). | Record a fresh exact-tip receipt after corrections: four Rust gates, both BPF object variants, required native64/ia32 and kernel cells, privacy, lifecycle/rate, container/SELinux, receipt and bundle checks. Historical green runs are useful baselines, not present qualification. Privileged/container rows were not executed in this review. |

The broader architecture plan (`docs/superpowers/plans/2026-09-07-architecture-closure.md:38-94,1159-1181`) still records source/test consolidation and final kernel/lifecycle/receipt work. Its status entries are historical snapshots; this review did not re-adjudicate each AR item. The current system-scope change should be corrected and tested before its results are folded into that release program.

## Checks performed on this snapshot

| Check | Observed result |
| --- | --- |
| `git diff --check` | Exit 0. |
| `mise exec -- ./scripts/cargo.sh +1.88 fmt --all -- --check` | Exit 0. |
| `mise exec -- ./scripts/cargo.sh +1.88 check --locked --offline --workspace --all-targets` | Exit 0. |
| `TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --test system_scope` | Exit 0; 6 passed. |
| `TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --test artifact_contracts compiled_birth_and_interface_name_contracts -- --exact` | Exit 0; 1 passed. It accepts the present cgroup-only producer. |
| `mise exec -- ./scripts/cargo.sh +1.88 clippy --locked --offline --workspace --all-targets -- -D warnings` | Exit 0. |
| Full workspace/all-target tests | Exit 101 at the first library binary; 1,063 passed, 1 failed, 3 ignored. Later binaries unrun in that command. |
| Exact failing library test alone | Exit 0; 1 passed. Cause of full-run difference unknown. |
| Live BPF, privileged, container and kernel-matrix tests | UNRUN in this review; no release claim follows. |

## Recommended order of work

1. Fix F1 with a genuine producer/consumer regression and update the compiled-object guard. Rebuild and verify both BPF variants; then obtain the authorized live fork/call result.
2. Correct F2's published cap text and F5's output/CLI contracts. Add the retained-engine refresh and final `PARTIAL` tests from F3/F5.
3. Diagnose F4 without weakening its assertion; rerun the full four-gate local set on the corrected, stable source snapshot.
4. Run and record the system-scope privacy, loss/rate, kernel/ABI and release checks on that exact tip. Keep any unexecuted row marked `UNRUN`, and perform an independent review of the corrected diff before integration.

The highest-leverage design change is to make every new scope answer the same explicit questions at one reviewable boundary: *which tasks pass the BPF gate, which process-birth records are emitted, which generations can be admitted, and which loss signals force PARTIAL*. F1 exists because those decisions were updated in different layers without one end-to-end assertion tying them together.

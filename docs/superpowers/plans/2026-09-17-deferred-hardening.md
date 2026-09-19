<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Deferred hardening batch (E/A–C/A2 follow-ups: tests + small code)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every deferred test minor and small code-hardening note left by the cgroup-256 A–C/A2–A5/D/E reviews: no vacuous assertions, no flaky timing assumptions, no untested error arms, no wasteful/debug-only edges.

**Architecture:** Five tasks, each recon-first (Step 1 locates the exact sites on current main — line numbers drifted since the reviews) then TDD. Test tasks change test code only and must never weaken an assertion (each report carries a falsification argument: what product breakage still fails the test). Code tasks are boundary-exact with one regression test each. The full TMPDIR suite gates every task.

**Tech Stack:** Rust 1.88 (`cargo +1.88`), existing test fixtures (`engine_tests.rs`, `identity.rs` tests, `manifest_pinning`).

**Spec:** the review/ledger notes themselves (all on main): E `task-1-review.md` obs 1–2, `task-2-review.md` obs 1, `final-review.md` triage; D `known-flakes.md` (3 flakes + specified fixes); ABC `progress.md` minors + `final-review.md` §6; A2 `progress.md` minors. Ledger dir: `.superpowers/sdd/2026-09-16-cgroup-256-{abc,a2-cap,d-cross-ns,e-loader}/` (main checkout; worktree has its own copy only for this plan — read the MAIN checkout paths below, they are the specs).

## Global Constraints

- Toolchain is exactly `cargo +1.88`; every cargo invocation carries `--locked` and `--offline`.
- Every `cargo test` invocation is prefixed with `TMPDIR=/var/tmp/p11scope-ws-tmp` (per AGENTS.md; create 0700 if missing).
- Focused tests: `TMPDIR=/var/tmp/p11scope-ws-tmp cargo +1.88 test --locked --offline -p p11scope --lib <filter>`; full suite before every commit: `TMPDIR=/var/tmp/p11scope-ws-tmp cargo +1.88 test --locked --offline --workspace --all-targets`; plus `cargo +1.88 fmt --all -- --check`, `cargo +1.88 clippy --locked --offline --workspace --all-targets -- -D warnings` clean.
- TDD red-green-refactor for every behavior change; watch each test fail first. Hardened tests are proven by 3× full-`--lib` runs green (flake tasks) or RED-first (new assertions).
- No `sudo`, no timing/probe runs, no network: subagents never run privileged commands.
- Branch is `fix/deferred-hardening`, worktree `.worktrees/fix-deferred-hardening`; never commit on main; never push.
- NO assertion weakening, ever: a hardened test must still FAIL if the product behavior it pins breaks. Each task report states the falsification argument per touched test.
- No new dependencies. Test tasks touch test code + fixtures only (fixtures additive unless the note names an existing one).

## Task 1: E test follow-ups (3 tests)

**Files:**
- Modify (tests only): `src/discovery/engine_tests.rs` (static + genuine tests), `src/discovery/identity.rs` (tests module).

**Interfaces:**
- (a) T1-obs1: the static-executable NotArmable test asserts the child is STILL ALIVE post-arm (kill-signal 0 / alive check on the retained child handle — recon picks the file's existing idiom) IN ADDITION to today's assertions. Frozen: `!armed`, no loader context, no mark, child alive.
- (b) T1-obs2: the genuine-failure pin asserts against the STRING LITERAL of `IO_CEILING_REASON` (read the literal at `src/discovery/scan.rs:43-44` — copy it verbatim into the test) instead of the constant. Frozen: byte-exact mark text equality + `unavailable == 1` (today's assertions otherwise unchanged).
- (c) T2-obs1: new test `failed_re_read_keeps_the_first_error` — `identity_of_in_mountinfo_with_reread` with a stale table and a closure returning `Err("stale".into())` returns the FIRST missing-mount error (byte-exact `mapping identity unavailable: fd mount N is missing from the mount table`) and performs exactly 1 re-read (RefCell counter, same idiom as the sibling tests).

- [ ] **Step 1: Recon.** Locate the 3 sites: the static NotArmable test, the genuine-failure test + the `IO_CEILING_REASON` literal, the `identity_of_in_mountinfo_with_reread` tests. Report file:line for each + the alive-check idiom. **Tripwire:** if any site's current assertions differ from the Interfaces above, STOP and report — the review obs may be stale.
- [ ] **Step 2: Write the failing tests.** (a) add the aliveness assert (fails only if the child died — to prove non-vacuity, ALSO run it once with the arm call removed... no: simpler — assert alive PRE-arm too, proving the handle/idiom works); (b) swap const→literal (must PASS immediately — it pins today's text; RED is N/A, state why); (c) write the Err-arm test (RED: fails to compile — no wait, it compiles against the existing helper and PASSES on first run since the arm exists. RED is N/A for (c) too — instead prove non-vacuity by temporarily... DO NOT mutate prod code for RED theater. Non-vacuity proof: run the test with the closure returning `Ok(stale)` (sibling behavior) and confirm it fails — i.e., the test distinguishes Err-reread from Ok-reread. Record both runs.)
- [ ] **Step 3: Implement** (test-only edits per Interfaces).
- [ ] **Step 4: GREEN runs.** All 3 tests pass; full `--lib` `loader` + `identity` filters green.
- [ ] **Step 5: Gates + commit** per Global Constraints (`test: close E review test follow-ups`).

## Task 2: Known-flakes test-only hardening (3 flakes)

**Files:**
- Modify (tests only): the `id_exhaustion_publishes_skip_instead_of_failing` test, the `hash_budget_charges_the_prefix_read_before_aggregate_exhaustion` test, the `expired_deadline_refuses_pin_hash_before_reading` test (locate via filter; spec: D `known-flakes.md` in the main checkout).

**Interfaces:**
- (a) id_exhaustion: before `Engine::discover`, poll each live child's `/proc/PID/exe` until it resolves (bounded: 5s, 10ms interval — the file's existing wait idiom if one exists) so no child is pre-exec at discover time. All existing assertions byte-identical.
- (b)+(c) hash_budget + expired_deadline: wrap the `scan_self()` call in a bounded retry (≤50 tries, 10ms sleep) while `modules` is empty; proceed with the first non-empty scan, or the last scan if all empty (a deterministically broken scan still fails red). All existing assertions byte-identical.
- Falsification (frozen, argue in report): (a) still fails if exhaustion publishes nothing (poll only stabilizes timing); (b)+(c) still fail on genuinely empty scans (retry exhausts, then asserts run on empty).

- [ ] **Step 1: Recon.** Locate the 3 tests + their wait/sleep idioms; confirm no other test shares their exact helper (no collateral change). Report file:line. **Tripwire:** if a test's failure mode differs from known-flakes.md (scope-truncation-only / Scanned-with-0-modules), STOP and report.
- [ ] **Step 2: Implement** the hardenings (no RED possible for flakes — instead record a 3× full-`--lib` pre-change baseline: run the whole lib suite 3 times, count failures of THESE tests; if 0/3 fail pre-change, the task still proceeds — the mechanism analysis in known-flakes.md is the justification, stated in the report).
- [ ] **Step 3: GREEN proof.** 3× full-`--lib` runs post-change: these 3 tests 0 failures. (Other flakes, if any, are recorded by name, not fixed.)
- [ ] **Step 4: Gates + commit** per Global Constraints (`test: harden three parallel-load flakes without weakening`).

## Task 3: ABC/A2 coverage gaps (9 assertions/tests)

**Files:**
- Modify (tests only unless noted): `src/discovery/engine_tests.rs`, `src/discovery/identity.rs` tests, scan/elf test modules as recon finds.

**Interfaces (each frozen):**
- (a) ABC-T1: the charge-skip engine test gains `assert_eq!(candidates_after_first, 1)` (non-vacuity; find via `candidates_after_first`).
- (b) ABC-T2: the max-scan-pids engine test wraps its sleep children in a drop-guard (killed + reaped on any exit incl. panic — recon picks the file's guard idiom or adds a minimal one in the test).
- (c) ABC-T2: same test (or its sibling) asserts the LOWEST-PID identity of the retained view, not just the view count.
- (d) ABC-T3: new integration test `released_view_ids_are_reused_end_to_end`: admit views → release one via `release_view_id` → admit another → assert the ID value is reused (exact ID equality, not just count).
- (e) ABC-T4: pure selection test gains tie-break (equal rarity → lowest pid), empty-key, and under-cap cases (3 sub-cases, one test fn or three — recon decides by file idiom).
- (f) ABC-T4: live cap test range extends `1..=2` → `1..=4` AND asserts the selected set is minimal for each cap (selected.len() == min(cap, candidates)); fails if selection ever exceeds the minimal set.
- (g) A3-M3: the full-lib-runner failure path records the failing test NAME in its panic/message (find the runner that reported `1024+1` without a name; assert the name appears — recon: if the runner is shared infra, the change must be additive/opt-in, never altering other tests' output).
- (h) A2-T1: same-size content rewrite test — modify fixture bytes WITHOUT changing size (ctime-only rotation) → pin rotates (assert new pin ≠ old pin AND rescan accepts).
- (i) A2-T2: `retain_view_id` path test asserting the retained ID value + the interpolated message text (exact string from the code, copied verbatim).

- [ ] **Step 1: Recon.** Locate all 9 sites; report file:line + the exact assertion/fixture to add. **Tripwire:** any item whose described code no longer exists (renamed/removed post-review) is SKIPPED with a ledger note, not reinvented — report skips explicitly.
- [ ] **Step 2: Write failing tests.** Each new/changed assertion first (RED where reachable: (d)(e)(f)(h)(i) must RED against unmodified behavior or a mutated expectation — state per-item how RED was shown; (a)(b)(c)(g) are additive pins — state the non-vacuity argument instead).
- [ ] **Step 3: Implement** (test-only).
- [ ] **Step 4: GREEN + gates + commit** per Global Constraints (`test: close ABC/A2 coverage gaps`).

## Task 4: Small code hardenings (4, each with a regression test)

**Files:**
- Modify: production code at recon-found sites + tests beside the code.

**Interfaces (each boundary-exact):**
- (a) ABC-T2: `Some(0)` `max_scan_pids` via direct `CaptureArgs` construction clamps to the default (same `unwrap_or(MAX_SCAN_PIDS)` semantics as `None`) — `take(0)` becomes unreachable. Regression test: `Some(0)` behaves identically to `None`.
- (b) ABC-T4: `max_pids == 0` sweep short-circuits to empty (no scanning work). Regression test: cap-0 returns empty + charges ~zero (assert no scan reads — recon picks the observable: budget delta or call count).
- (c) ABC-T3: `release_view_id` double-release hardens to skip-if-absent (no panic in release builds; debug_assert may stay as a complement, never as the only guard). Regression test: double release is a silent no-op, IDs still consistent after.
- (d) A3-M1: `pin_of` I/O errors report their own message (distinguish from changed-file: message names the I/O failure, keeps fail-safe refusal). Regression test: unreadable file pins with the I/O message, still refused.

- [ ] **Step 1: Recon.** Locate the 4 sites; report file:line + current behavior + the exact changed lines planned. **Tripwire:** if a fix requires touching more than the named function + its test, STOP that item and report (scope guard — no drive-by refactors).
- [ ] **Step 2-4: TDD per item** (RED test, minimal fix, GREEN), gates per Global Constraints, one commit (`fix: clamp/tighten four reviewed edges` + body listing the four + tests).

## Task 5: Residual ID-leak carry-forward

**Files:**
- Modify: `discover_plan` scan_and_pin failure path + refresh `new_views` loop (per ABC ledger carry-forward) + regression test.

**Interfaces:**
- IDs allocated but never admitted (scan_and_pin failure; refresh-loop drop) return to the free pool (via the existing `release_view_id` path or the file's free-list idiom — recon decides, reviewer verifies no double-release against Task 4(c)).
- Regression test: drive both drop paths, then assert pool accounting balances (allocated == admitted + released; exact assertion from recon).
- No behavior change on success paths (all existing ID tests green unchanged).

- [ ] **Step 1: Recon.** Find the drop points; confirm they leak (write the accounting test FIRST and watch it fail = RED). Report file:line. **Tripwire:** if the ledger-named paths don't leak on current main (fixed incidentally), verify with the test + close the task test-only (keep the regression test, no prod change).
- [ ] **Step 2-4: Minimal fix, GREEN, gates + commit** per Global Constraints (`fix: release IDs at never-admitted drop points`).

## Self-review (controller, against the spec)

1. Spec coverage: E obs 1–2 + T2-obs1 → Task 1; known-flakes ×3 → Task 2; ABC T1/T2(×2)/T3-e2e/T4(×2)/A3-M3 + A2 T1/T2 → Task 3; ABC T2-clamp/T4-short/T3-double/A3-M1 → Task 4; ID-leak carry-forward → Task 5. A5-M1 (SAFETY comment) verified DONE in code — excluded. A3-M4 + T2-obs2/3/4 ruled `none` in discovery — excluded. No gaps.
2. Placeholder scan: no TBD/TODO; every item names its ledger source, frozen assertion, and gates. Recon-owned mechanics are fenced per-item with tripwires (E-plan precedent).
3. Contract consistency: TMPDIR value identical everywhere; no-weakening rule binds Tasks 1–3; Task 4 items are single-function scoped; Task 5 explicitly coordinates with Task 4(c).

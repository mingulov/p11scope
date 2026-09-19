<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Shebang closure + re-baselined suite gate (remaining-work Units 4–5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close remaining-work Unit 4 (shebang flake — likely overtaken by the `cbb3502` rework, verify with evidence) and Unit 5 (re-baselined suite gate: full suite green twice at current counts).

**Architecture:** Controller recon found the plan-named shebang tests (`path_absolute_shebang_retarget_is_detected_via_final_component`, `path_with_shebang_retarget_is_allowed_as_conservative_exec_chain`) NEVER existed in git history (empty `-S`), and the tree's only shebang test (`src/run.rs:5229` `path_absolute_shebang_retarget_and_exec_chain_prearm_classification_is_conservative`) is deterministic (no timing, no `env python3` script, no sleeps). Task 1 verifies this rigorously (all exec/shebang classification tests located + run 5× + inspected for timing dependence) and EITHER closes Unit 4 as overtaken-by-rework with evidence OR fixes a live flake per the remaining-work sketch. Task 2 runs the re-baselined gate.

**Tech Stack:** Rust 1.88 (`cargo +1.88`), existing exec-classification tests.

**Spec:** `docs/superpowers/plans/2026-09-16-remaining-work.md` Unit 4 (Concrete fix: `gcc -E -P` probe — applies ONLY if a live timing flake exists) + Unit 5 (suite gate, re-baselined counts).

**Out of scope (explicit):** Rewriting exec classification; new shebang features; any production change unless a live flake is proven.

## Global Constraints

- Toolchain is exactly `cargo +1.88`; every cargo invocation carries `--locked` and `--offline`.
- Every `cargo test` invocation is prefixed with `TMPDIR=/var/tmp/p11scope-ws-tmp` (per AGENTS.md; create 0700 if missing).
- Focused tests: `TMPDIR=/var/tmp/p11scope-ws-tmp cargo +1.88 test --locked --offline -p p11scope --lib <filter>`; full suite: `TMPDIR=/var/tmp/p11scope-ws-tmp cargo +1.88 test --locked --offline --workspace --all-targets`; plus `cargo +1.88 fmt --all -- --check`, `cargo +1.88 clippy --locked --offline --workspace --all-targets -- -D warnings` clean.
- TDD red-green-refactor for any behavior change; watch each test fail first.
- No `sudo`, no timing/probe runs, no network: subagents never run privileged commands.
- Branch is `fix/shebang-gate`, worktree `.worktrees/fix-shebang-gate`; never commit on main; never push.
- No new dependencies. No existing test modified unless a live flake is proven (then minimal fix + regression proof).

## Task 1: Unit 4 closure (verify overtaken, or fix a live flake)

**Files:**
- Modify: NOTHING unless a live flake is proven (then the flaky test file only, minimal fix).
- Evidence: report only (or test fix + report).

**Interfaces:**
- Verification set (recon-owned, must include at minimum): `src/run.rs:5229` shebang test + every test matching filters `shebang`, `prearm`, `prepared_executable`, `exec_chain` (union across `--lib` and integration targets — enumerate, don't assume).
- Closure bar (ALL must hold to close without code): (1) every test in the set passes 5× consecutively under the TMPDIR prefix; (2) none contains timing dependence (no sleep/poll/retry-until-exec-probe except the hardened Task-2-style bounded waits — grep `sleep`, `Duration`, `poll`, `Instant` in each test body and justify each hit); (3) none executes an `env python3` (or any interpreter-path) script for classification (grep `env ` + `Command` in each body).
- Fix bar (if ANY closure item fails): implement the remaining-work sketch adapted to current code (`gcc -E -P` probe asserting today's failure is environmental, then fix the test to not depend on interpreter timing), TDD with RED-first proof, then the closure bar re-runs green.

- [ ] **Step 1: Recon.** Enumerate the verification set (filters + grep); report test names + file:line + timing/interpreter grep hits per test. **Tripwire:** if the set is empty (no exec-classification tests at all), STOP and report (NEEDS_CONTEXT) — the area may have moved files.
- [ ] **Step 2: 5× runs.** Run each test in the set 5× focused (TMPDIR-prefixed); record pass/fail per run. Any failure → fix bar.
- [ ] **Step 3: Close or fix.** Either (a) no code change: report closes Unit 4 as overtaken-by-rework with the 5× matrix + grep evidence; or (b) minimal test fix with RED-first proof + closure bar re-green.
- [ ] **Step 4: Gates + commit.** fmt + clippy clean; full TMPDIR suite green. Commit message: `test: close shebang flake (Unit 4)` for a fix, or — if no code changed — NO commit (report-only task; state this in the report and return DONE with `none` as the commit hash).

## Task 2: Re-baselined suite gate (Unit 5)

**Files:**
- Modify: NOTHING (evidence-only task).
- Evidence: report with both runs' counts.

**Interfaces:**
- Two consecutive full runs: `TMPDIR=/var/tmp/p11scope-ws-tmp cargo +1.88 test --locked --offline --workspace --all-targets`, exit 0 both, 0 failed both. Record: lib passed/failed/ignored, per-target `test result` lines, total wall time.
- Expected counts (from the hardening branch tip): lib ~1052 passed / 0 failed / 3 ignored; 28 `test result: ok` lines. Deviations ±flakes are triaged per `known-flakes.md` (main checkout, read-only): name the flake, show isolation-green, re-run.
- Any failure that is NOT a triaged known-flake/environmental issue STOPS the task (BLOCKED with evidence) — a real regression gates the release.

- [ ] **Step 1: Run 1.** Full suite, record counts + log path. Triage any failure before proceeding.
- [ ] **Step 2: Run 2.** Full suite again, record counts + log path. Both green → gate passes.
- [ ] **Step 3: Report.** Write the report (no commit — evidence-only; return DONE with `none` as the commit hash).

## Self-review (controller, against the spec)

1. Spec coverage: Unit 4 (verify-or-fix with the sketch as the fix bar) → Task 1; Unit 5 (green twice at current counts) → Task 2. The stale plan names/counts are superseded by recon + current evidence. No gaps.
2. Placeholder scan: no TBD/TODO; filters, grep terms, run counts, and both bars are exact. Recon-owned enumeration is fenced (minimum set + tripwire).
3. Contract consistency: TMPDIR value identical everywhere; report-only outcomes explicitly allowed (no empty commits); BLOCKED bar for real regressions protects the release gate.

# Refactor queue implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute the pending refactor queue (oracle extraction, checker dedupe, renames, meta-tests, Rust 1.98 probe, test-robustness) with behavior-identical proof.

**Architecture:** Controller recon verified each queue item's done/left status on main@7309bd9. Tasks are ordered extraction → dedupe → renames → meta-tests → probe → robustness → gates, so each task's proof builds on a stable tree. Enumerations marked recon-owned must be re-verified by the implementer (fenced with tripwires).

**Tech Stack:** Bash/sh lane scripts, Python 3.10+ stdlib only, Rust 1.88 (`cargo +1.88`), Rust 1.98 (read-only probe).

**Spec:** `docs/notes/2026-09-16-cgroup-256-trace-everything.md` pending queue items 2–7 + KEEP list, plus `known-flakes.md` test-robustness deferral and the shebang ledger lane13 hypothesis.

## Global Constraints

- Toolchain is exactly `cargo +1.88`; every cargo invocation carries `--locked` and `--offline`.
- Every `cargo test` invocation is prefixed with `TMPDIR=/var/tmp/p11scope-ws-tmp` (per AGENTS.md).
- Full suite: `TMPDIR=/var/tmp/p11scope-ws-tmp cargo +1.88 test --locked --offline --workspace --all-targets`; plus `cargo +1.88 fmt --all -- --check`, `cargo +1.88 clippy --locked --offline --workspace --all-targets -- -D warnings` clean.
- No `sudo`, no network, no new dependencies. Branch `fix/refactor-queue`, worktree `.worktrees/fix-refactor-queue`; never commit on main; never push.
- KEEP (from spec, verbatim intent): Task-N/F5/W3/W8 comments, G-gates/G-lanes (document the two namespaces), lane numbers, `csf_*`, S-stages; historical docs verbatim. Renames cover code/script/test/CI identifiers only — never prose history, never the KEEP list.
- Behavior-identical discipline: no assertion weakened, no gate narrowed, no `.sh` logic change beyond mechanical call-site rewiring; every behavioral claim needs before/after evidence.
- /tmp EDQUOT is a known environmental gate hazard (see shebang ledger): triage per `known-flakes.md`, preserve full logs, never weaken seal tests.

---

## Task 1: Oracle extraction (10 embedded blocks → sibling `.py` + `--help`)

**Files:**
- Modify: the 10 lane scripts (recon-owned list below — verify each holds ≥1 `python3 - ... <<'PY'` block).
- Create: one sibling `.py` per extracted block, same directory, `lane-<name>-oracle.py` naming (verify no collisions first).

**Interfaces:**
- Consumes: nothing (first task).
- Produces: sibling scripts each with `argparse --help`, exit codes unchanged, stdout/stderr byte-identical on identical inputs.

Recon-owned script list (verify with `grep -l "python3 - .*<<'PY'" scripts/*.sh scripts/matrix/*.sh`):
`bench-overhead.sh`, `build-release.sh`, `lib.sh`, `verify-attach-e2e.sh`, `verify-capability-tier.sh`, `verify-induced-gaps.sh`, `verify-inspect-doctor.sh`, `verify-k8s-attach.sh`, `verify-task4-lane02.sh`, `verify-task4-lane16.sh`.

- [ ] **Step 1: Recon + tripwire.** List every `<<'PY'` block per file with line ranges. **Tripwire:** if the count is not 10 files / ≥10 blocks, STOP (NEEDS_CONTEXT) — the area moved.
- [ ] **Step 2: Extract one block (pilot).** Move the block verbatim into its sibling `.py` with an `argparse` wrapper (`--help` text naming the lane + purpose); rewire the call site to `python3 -I <sibling> <same args>`; keep `-I` isolated mode.
- [ ] **Step 3: Prove pilot identical.** Run the touched lane script's `--help`/self-test path if it has one unprivileged; else diff the extracted code byte-for-byte against the heredoc body (`git show HEAD:<script>` vs new file, modulo the argparse wrapper which must be the ONLY delta).
- [ ] **Step 4: Extract remaining blocks** with the same pattern, one commit per script.
- [ ] **Step 5: Gates.** `python3 -m py_compile` every new file; every sibling responds to `--help` exit 0; focused `artifact_contracts` target green (TMPDIR-prefixed); fmt+clippy clean (Rust untouched — must stay clean).
- [ ] **Step 6: Commit** per script: `refactor: extract <lane> oracle to sibling .py`.

## Task 2: Checker importlib driver dedupe (+ `tests/python/` verification)

**Files:**
- Modify: every file repeating the `importlib.util.spec_from_file_location` + `module_from_spec` driver (recon found `scripts/build-offline.py:325-328`, `scripts/capture-stopped-canary.py:28-29` — enumerate fully, there may be more).
- Create: `scripts/_loader.py` (single `load_sibling(name)` helper; private-by-underscore, stdlib only). Verify the name is unclaimed first.

**Interfaces:**
- Consumes: Task 1 siblings (call sites may use the new loader where they already used importlib — no new behavior).
- Produces: `load_sibling(name: str) -> module` used by all former duplication sites.

- [ ] **Step 1: Enumerate + verify `.c` move.** Grep all `spec_from_file_location` sites; confirm `tests/python/*.c` is still empty (recon: 0 `.c` files — if any `.c` reappeared, move to `tests/fixtures/` with reference updates instead of renaming the dir).
- [ ] **Step 2: Failing-first driver test.** Add `tests/python/test_loader.py`: `load_sibling` loads a fixture module by name, raises `FileNotFoundError` naming the file when absent. Run: RED (module missing).
- [ ] **Step 3: Implement `scripts/_loader.py`** (~15 lines: `spec_from_file_location` + `module_from_spec` + `exec_module`). Run test: GREEN.
- [ ] **Step 4: Rewire all sites** to `load_sibling`; delete duplicated blocks. Re-run every touched script's `--help`/`--self-test` unprivileged path.
- [ ] **Step 5: Gates + commit.** py_compile; focused python-driven Rust tests touching these scripts green; commit `refactor: dedupe importlib driver into scripts/_loader.py`.

## Task 3: Renames (task4→receipt, TASK5→unprefixed, lane files, CI+pins in sync)

**Files:**
- Rename: `tests/task4_build_subjects.rs` → `tests/receipt_build_subjects.rs` (verify target name updates in Cargo.toml if explicit); `scripts/verify-task4-lane*.sh` → `scripts/verify-receipt-lane*.sh`; TASK5-prefixed identifiers → unprefixed (enumerate: `grep -rn TASK5 scripts/ tests/*.rs src/ | grep -v Binary`).
- Modify: all references (`.github/workflows/ci.yml`, `scripts/*.sh` call sites, `tests/artifact_contracts.rs` assertions naming these files, docs/usage paths if any).

**Interfaces:**
- Consumes: Tasks 1–2 file layout (rename AFTER extraction so sibling names are final).
- Produces: zero `task4`/`TASK4`/`TASK5` matches in code/script/test/CI paths (docs history exempt per KEEP).

- [ ] **Step 1: Enumerate + tripwire.** Full `grep -rn` inventory with file:line. **Tripwire:** if `src/` or `crates/*/src/` (non-test) holds task4/TASK5 identifiers, STOP (NEEDS_CONTEXT) — product-code rename needs separate approval.
- [ ] **Step 2: `git mv` the files.** Update Cargo target names if explicit; update every reference from the inventory.
- [ ] **Step 3: CI + pins.** Update `ci.yml` job/step names and any SHA pins referencing renamed paths; verify with `grep` that no workflow references a stale path.
- [ ] **Step 4: Gates.** Full TMPDIR suite green; `grep -rn "task4\|TASK4\|TASK5" scripts/ tests/*.rs .github/ | grep -v Binary` empty. Commit per rename group.

## Task 4: Meta-tests (`py_compile` all `scripts/*.py` + heredoc size cap)

**Files:**
- Modify: `tests/artifact_contracts.rs` (new meta-test fns — follow the existing file-shape assertion style).
- Test: the new meta-tests themselves (failing-first by temporarily... no — prove RED by asserting against a fixture violation in a temp dir, never by breaking the tree).

**Interfaces:**
- Consumes: Tasks 1–3 final layout (meta-tests pin the new shape).
- Produces: `scripts_tree_shape_*` tests: (a) every `scripts/**/*.py` compiles; (b) no `<<'PY'` heredoc exceeds 40 lines (cap value recon-owned — implementer: measure current max first; cap = max +20%, rounded, recorded in the test comment).

- [ ] **Step 1: Measure.** `py_compile` baseline (must already pass); heredoc line-count histogram across `scripts/**/*.sh`.
- [ ] **Step 2: Write failing-first tests** using temp-dir fixtures (a syntactically broken `.py` fixture fails (a); an over-cap heredoc fixture fails (b)). Run: RED on fixtures, GREEN on tree.
- [ ] **Step 3: Wire into `artifact_contracts.rs`** in the existing style (tempdir + assertions, no new deps).
- [ ] **Step 4: Gates + commit.** Full lib + `artifact_contracts` green; commit `test: pin scripts tree shape (py_compile + heredoc cap)`.

## Task 5: Rust 1.98 read-only probe (check/clippy/test, migration cost)

**Files:**
- Modify: NOTHING (read-only task).
- Evidence: report with command outputs + migration-cost verdict.

**Interfaces:**
- Consumes: Task 3 tree (probe the final layout).
- Produces: verdict GO (1.98-clean) or COSTED (exact error/warning list + migration estimate). No code change either way.

- [ ] **Step 1: `cargo +1.98 check --locked --offline --workspace --all-targets`** (toolchain `1.98.0` installed). Record errors/warnings verbatim.
- [ ] **Step 2: `cargo +1.98 clippy --locked --offline --workspace --all-targets`** (no `-D`, record-only). Record new lints vs 1.88 baseline.
- [ ] **Step 3: `TMPDIR=... cargo +1.98 test --locked --offline --workspace --all-targets`** ONLY if Steps 1–2 are clean; else stop (test on a red tree proves nothing).
- [ ] **Step 4: Report.** Verdict + cost. Return DONE with `none` (no commit).

## Task 6: Test-robustness batch (known flakes + lane13 hypothesis)

**Files:**
- Modify: the flaky test bodies ONLY (no product code, no assertion weakening):
  - `discovery::engine::tests::id_exhaustion_publishes_skip_instead_of_failing` — wait for children to complete exec (poll `/proc/PID/exe`) before `Engine::discover` (per ledger).
  - `hash_budget_charges_the_prefix_read_before_aggregate_exhaustion`, `expired_deadline_refuses_pin_hash_before_reading` (`tests/manifest_pinning.rs`?) — bounded retry while scan modules are empty (per ledger; verify file first).
  - `tests/python/test_lane13_evidence.py` `close_owned_child` (:478-482), `close_controlled_handle` (:489-499) — harden fixed 2s cleanup deadlines per shebang-ledger hypothesis (bounded retry / reap-aware wait); `assertLess(elapsed, 5)` (:2140) only if it proves to be the recurrer — do NOT touch blindly.

**Interfaces:**
- Consumes: all prior tasks (robustness lands on the final tree).
- Produces: same assertions, deterministic waits; each fix proven by 5× focused runs + 1 full-suite run.

- [ ] **Step 1: Reproduce-or-reason.** For each flake: 5× focused run; flake or no, the ledger/hypothesis mechanism justifies the hardening (bounded waits only — a sleep-then-hope is REJECTED in review).
- [ ] **Step 2: Harden one flake at a time**, minimal diff, one commit each (`test: harden <name> against <mechanism>`).
- [ ] **Step 3: Prove.** 5× focused green per fix + full TMPDIR suite green at batch end. Any assertion change must ADD specificity (review checks the diff hunk-by-hunk).

## Task 7: Gates + behavior-identical proof + merge review

**Files:** none (evidence task).

- [ ] **Step 1: Full suite ×2** (TMPDIR-prefixed), fmt + clippy clean. Record counts + log paths. Triage reds per `known-flakes.md` (Task 6 should have retired them — any recurrence reopens Task 6).
- [ ] **Step 2: Behavior proof.** For Tasks 1–3: `git diff main --stat` reviewed file-by-file; every `.sh` call-site rewiring shows identical argv; every rename shows reference-complete grep-empty.
- [ ] **Step 3: Final review + merge** to main (local merge pre-approved; never push), retire branch/worktree per finishing-a-development-branch.

## Self-review (controller, against the spec)

1. Spec coverage: queue item 2 → Task 1; item 3 → Task 2; item 4 → Task 3; item 5 → Task 4; item 6 → Task 5; item 7 → Task 7; KEEP list → Global Constraints; ledger robustness deferral + lane13 hypothesis → Task 6. No gaps.
2. Placeholder scan: no TBD/TODO; counts, caps, and bars are exact or recon-fenced with tripwires. Heredoc cap is measured-then-set (formula given, not a guess).
3. Contract consistency: TMPDIR/toolchain/branch identical everywhere; report-only outcomes explicit (Tasks 5, 7); Task 6 forbids assertion weakening and blind fixes.

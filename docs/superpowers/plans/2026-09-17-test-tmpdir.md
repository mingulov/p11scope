# Test temp under the workspace tmp dir (kill the /tmp EDQUOT failures)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Amendment 2026-09-17 (Task 2 onward):** TMPDIR is `/var/tmp/p11scope-ws-tmp` (0700, pre-created), NOT the workspace `tmp/` below. Reason: `output.rs:401` trusts an ancestor only if non-group/world-writable or sticky; `/home/user/src` is group-writable (user's shared tree — not ours to chmod), which fails 10 output-trust tests under the workspace path (proven pre-existing on BASE). `/var/tmp` is sticky + 126G free; probe GREEN. Task 1 ran under the original value (history — its pin test holds under any TMPDIR). Every `TMPDIR=...` below now means the `/var/tmp` value.

**Goal:** All Rust test temp I/O lands under a big-disk trusted TMPDIR instead of tmpfs `/tmp` (2.7G, 80% full), so the loader-filter tests stop failing with `EDQUOT Disk quota exceeded`.

**Architecture:** Two minimal changes, no production-code change: (1) the one test-support call site that pins `/tmp` (`tempfile::tempdir_in("/tmp")`) honors `TMPDIR` like every other test-temp call site; (2) the repo's documented test invocations set `TMPDIR` to the workspace tmp dir. Recon (release-discovery 2026-09-17, inlined as spec): every other test-temp site already uses `tempfile::tempdir()` / `TempDir` / `CARGO_TARGET_TMPDIR` (all `TMPDIR`-respecting, all `#[cfg(test)]`); zero production-code `/tmp` use; the EDQUOT failures copy/compile into `tempfile::tempdir()` at `engine_tests.rs:11612-11614` and `:4881-4937`.

**Tech Stack:** Rust 1.88 (`cargo +1.88`), `tempfile`, `AGENTS.md` (repo instruction surface).

**Spec:** release-discovery recon 2026-09-17 (inlined above; full report was the dispatch input — executors needing more re-grep; the claims that matter are: sole bypass is `src/run/root_fence_runtime.rs:588`; everything else honors `TMPDIR`).

**Out of scope (explicit):** `.cargo/config.toml` `[env]` (relative paths resolve per-checkout, fragile across worktrees — ruled out); any production-code change (none uses `/tmp`); deleting `/tmp` contents (user's files, not ours); `scripts/cargo.sh` wrapper changes (SDD implementers invoke bare `cargo +1.88` per Global Constraints).

## Global Constraints

- Toolchain is exactly `cargo +1.88`; every cargo invocation carries `--locked` and `--offline`.
- Every `cargo test` invocation in this plan is prefixed with `TMPDIR=/home/user/src/m/p11scope-ws/tmp` (the fix under test). Non-test invocations (fmt, clippy, check) need no prefix.
- Focused tests: `TMPDIR=/home/user/src/m/p11scope-ws/tmp cargo +1.88 test --locked --offline -p p11scope --lib <filter>`; full suite before every commit: `TMPDIR=/home/user/src/m/p11scope-ws/tmp cargo +1.88 test --locked --offline --workspace --all-targets`; plus `cargo +1.88 fmt --all -- --check`, `cargo +1.88 clippy --locked --offline --workspace --all-targets -- -D warnings` clean.
- TDD red-green-refactor for every behavior change; watch each test fail first.
- No `sudo`, no timing/probe runs, no network: subagents never run privileged commands.
- Branch is `fix/test-workspace-tmp`, worktree `.worktrees/fix-test-workspace-tmp`; never commit on main; never push.
- No new dependencies. Only additive test code; no existing test modified.

## File structure

- `src/run/root_fence_runtime.rs` — owns `run_mode` (:583), the `tempfile::Builder` staging chain (:586-588), and the 108-byte control-socket guard (:596-599). The whole module is `#[cfg(test)]` (`src/run.rs:37-38`); the only caller of `run_mode` is the `#[ignore]`d privileged test `:629-646` requiring `P11SCOPE_ROOT_RUNTIME_STAGE`.
- `AGENTS.md` — owns the `Checks` invocation block (:22-29), the repo's instruction surface for how to run gates.

## Task 1: Staging honors TMPDIR (+ pinning test)

**Files:**
- Modify: `src/run/root_fence_runtime.rs` (staging chain + one helper + one test).
- Test: same file (module is `#[cfg(test)]`; plain `#[test]`, NOT `#[ignore]`).

**Interfaces:**
- New helper (exact signature): `fn control_dir() -> std::io::Result<tempfile::TempDir>` — builds `tempfile::Builder::new().prefix("p11root-").tempdir()` (TMPDIR-honoring; no path argument anywhere).
- `run_mode` calls it as `let directory = control_dir()?;` (the `?` converts via the existing `anyhow::Result` return; no import changes — both paths fully qualified).
- The 108-byte `ensure!` guard stays byte-identical: it still fails loudly if a TMPDIR is ever too long (workspace tmp yields ~60-char socket paths — full headroom).
- Unchanged: prefix (`p11root-`), 0o700/0o600 permissions, chown flow, cleanup combination, the ignored privileged test.

- [ ] **Step 1: Write the failing test.** Append to the file (next to the other tests):
```rust
#[test]
fn control_directory_honors_the_process_temp_dir() {
    let directory = control_dir().expect("control dir must create");
    assert_eq!(
        directory.path().parent(),
        Some(std::env::temp_dir().as_path()),
        "staging must live under TMPDIR, not /tmp"
    );
}
```
- [ ] **Step 2: Run it to verify it fails.** Run: `TMPDIR=/home/user/src/m/p11scope-ws/tmp cargo +1.88 test --locked --offline -p p11scope --lib control_directory_honors_the_process_temp_dir`. Expected: FAIL — compile error (`control_dir` undefined) on unmodified code. (Precondition: the TMPDIR prefix is mandatory for this RED — without it `temp_dir()` is `/tmp` and even old code would pass. After the fix the test passes with AND without the prefix.)
- [ ] **Step 3: Minimal implementation.** Add the helper above `run_mode` (with this comment: `// TMPDIR-honoring: test temp lives under the workspace tmp dir (see AGENTS.md); the 108-byte control-socket guard below still fails loudly if a TMPDIR is ever too long.`) and replace the `tempfile::Builder` chain in `run_mode` with `let directory = control_dir()?;`. Delete the old "Short pathname for sockaddr_un; do not put control sockets in the long evidence stage." comment (superseded — the length guard, not the location, is what protects the socket now).
- [ ] **Step 4: Run the test to verify it passes.** Same command as Step 2. Expected: PASS (1 passed). Also run without the TMPDIR prefix; expected: PASS (no behavior change for default temp).
- [ ] **Step 5: Gates.** Focused `--lib` filter `root_fence` green; `cargo +1.88 fmt --all -- --check` clean; `cargo +1.88 clippy --locked --offline --workspace --all-targets -- -D warnings` clean. Then the full suite per Global Constraints (TMPDIR-prefixed), 0 failures.
- [ ] **Step 6: Commit.** `git add` only `src/run/root_fence_runtime.rs`; message `fix: honor TMPDIR for root-fence control staging` + body citing the sole-bypass recon and gates.

## Task 2: Document the TMPDIR test invocation (+ loader proof)

**Files:**
- Modify: `AGENTS.md` (`Checks` block only).
- Test: no new test code — the contract test is the existing `loader` filter (29 tests incl. the 3 EDQUOT failures) run with and without the prefix.

**Interfaces:**
- The `test` line of the `Checks` block becomes exactly:
```sh
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --workspace --all-targets
```
- One line above the block (exact text): `Test temp I/O goes to /var/tmp/p11scope-ws-tmp (big disk, sticky-trusted; create 0700 if missing), never tmpfs /tmp (EDQUOT at scale): prefix test runs with TMPDIR as below.`
- All other lines byte-identical.

- [ ] **Step 1: RED — prove the prefix matters.** Run `cargo +1.88 test --locked --offline -p p11scope --lib loader` WITHOUT any TMPDIR prefix. Expected: the 3 known EDQUOT failures (`loader_collision_candidate_keeps_provider_retirement_without_loader_id` panics `Disk quota exceeded`; the two `:4937` gcc-fixture tests fail). Record the exact count.
- [ ] **Step 2: Apply the AGENTS.md edit** per Interfaces (edit + nothing else).
- [ ] **Step 3: GREEN — loader filter under the documented prefix.** Run `TMPDIR=/var/tmp/p11scope-ws-tmp cargo +1.88 test --locked --offline -p p11scope --lib loader`. Expected: 29/29 PASS, 0 failed. On any failure: stop — either /tmp pressure moved (check `df -h /tmp`) or a test bypasses TMPDIR (grep the failure for `/tmp`), report which.
- [ ] **Step 4: Gates + full-suite proof.** `cargo +1.88 fmt --all -- --check` clean; `cargo +1.88 clippy --locked --offline --workspace --all-targets -- -D warnings` clean. Then the FULL suite with the new prefix: `TMPDIR=/var/tmp/p11scope-ws-tmp cargo +1.88 test --locked --offline --workspace --all-targets`. Expected: 0 failures everywhere including the 10 output-trust tests (the new path is sticky-trusted — this run establishes the true green baseline Task 1 could not).
- [ ] **Step 5: Commit.** `git add` only `AGENTS.md`; message `docs: route test temp I/O to the workspace tmp dir` + body citing the 29/29 proof and the full-suite result.

## Self-review (controller, against the spec)

1. Spec coverage: sole `/tmp` bypass → Task 1 (TMPDIR-honoring + pin); standardized invocation → Task 2 (AGENTS.md + 29/29 proof); TMPDIR-reroutes-everything recon → relied on in both tasks' expected values; no-production-/tmp → no production task. No gaps.
2. Placeholder scan: no TBD/TODO; helper signature, test body, shell lines, commands, and expected values are exact. The only adaptation is failure triage in Task 2 Step 3, fenced to two named causes with named probes.
3. Contract consistency: `control_dir` signature identical in Interfaces, test, and implementation steps; TMPDIR value identical everywhere (`/home/user/src/m/p11scope-ws/tmp`); Task 2's RED/GREEN uses the same filter string as the recon.

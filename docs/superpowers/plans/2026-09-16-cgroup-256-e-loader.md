<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# cgroup-256 E: loader arming at scale (stop arming the un-armable, survive mount churn)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** At scale the loader strategy aggregate must stop reporting ~145
`unavailable` for views that were never armable. Measured post-D (main
`dc70792`, ~560-proc root cgroup, instrumented build — evidence:
`.superpowers/sdd/2026-09-16-cgroup-256-e-loader/evidence/`, branch-local,
gitignored): D's same-file merge already lifted `debug_state_every_hit` 3 →
109; the remaining arm attempts break down as 128× kernel threads
(`/proc/PID/exe` ENOENT → `open failed`, marked, then redacted to
`discovery unavailable`), 6× `mapping identity unavailable: fd mount N
missing from mount table` on real daemons (mount-table churn / detached
mounts), plus already-armed views returning silent-false on refresh
(normal). A 3-dynamic-sleeper control arms 3/3, so dynamic exes are fine.

**Architecture:** two minimal changes, no evidence-contract change: (1) a
`NotArmable` arm outcome for provably un-armable views (no executable,
static executable) — no partial mark, no context record, retried next tick
like any unarmed view; (2) one mount-table re-read + re-resolve retry on
missing-mount before failing. Redaction (`capture_skipped_out`), the
strategy aggregate shape, the 256 context cap, and the refresh/retry
topology stay untouched.

**Tech Stack:** Rust 1.88 (`cargo +1.88`), `src/discovery/engine.rs`
(arm path), `src/process.rs` (mount table reads), existing loader/identity
test fixtures. `render.rs` is OFF LIMITS (no redaction change).

**Out of scope (explicit):** the ~8× wall-time inflation of big captures
(5s capture takes ~40s; identical pre/post-D — profiling workstream, not
E); `MAX_LOADER_CONTEXTS` (256 contexts were never exhausted: 254
entries); `_dl_debug_state` hit coverage (0 hits is expected when nothing
dlopens); any `capture_skipped_out` change.

## Global Constraints

- Toolchain is exactly `cargo +1.88`; every cargo invocation carries `--locked` and `--offline`.
- Focused tests: `cargo +1.88 test --locked --offline -p p11scope --lib <filter>`; full suite before every commit: `cargo +1.88 test --locked --offline --workspace --all-targets`; plus `cargo +1.88 fmt --all -- --check`, `cargo +1.88 clippy --locked --offline --workspace --all-targets -- -D warnings` clean.
- TDD red-green-refactor for every behavior change; watch each test fail first.
- No `sudo`, no timing/probe runs, no network: subagents never run privileged commands. Live post-fix verification is controller-only.
- Branch is `fix/e-loader-arming`, worktree `.worktrees/fix-e-loader-arming`; never commit on main; never push.
- No PARTIAL-guarantee weakening: every failure that marks today must still mark after E, EXCEPT the two reclassified cases below (no-executable, static-executable), which are provably un-armable rather than un-proven. Genuine arm failures (pin/hash/snapshot/state/preflight) keep today's mark text byte-for-byte.
- No new dependencies. No redaction change. Only additive test fixtures.

## File structure

- `src/discovery/engine.rs` — owns `arm_loader_for_view` (:9773), `arm_loader_or_partial` (:10295), `loader_locator` (:6791), `record_loader_arm` (:6007), `LoaderArmFailure` (:5641), the initial-arm loop (~:12660) and refresh-arm site (:12144).
- `src/process.rs` — owns `open_then_mountinfo` (:424) and the `/proc/PID/mountinfo` read.
- `crates/manifest/src/identity.rs` — owns `mapping_file_key_in_mountinfo` (:112, pure resolver).
- Tests live next to the code they pin (`engine_tests.rs` loader tests; `process.rs`/`identity.rs` tests).

## Task 1: NotArmable outcome for no-executable and static views

**Files:**
- Modify: `src/discovery/engine.rs` (arm path only).
- Test: `src/discovery/engine_tests.rs` (or the module the recon finds the loader-view fixtures in).

**Interfaces:**
- New outcome: arming a view whose `/proc/PID/exe` readlink fails with ENOENT (kernel thread / zombie / already-exited), or whose executable has no PT_INTERP (static; the existing `loader_locator` → `None` path), returns silent `Ok(false)` with NO `mark_partial`, NO loader-registry record, and NO error. Every refresh tick retries such views exactly like today (transient ENOENT on a live process self-heals; dead views retire through the existing path).
- Unchanged: every other failure (pin/hash/snapshot/state/preflight/mismatch/missing-symbol/mapping/canonical-identity) keeps today's mark text, error kind, and record behavior byte-for-byte. `record_loader_arm` is NOT called for NotArmable views (they stay out of the `unavailable` count rather than inflating it).
- Detection rule (frozen): exe-ENOENT is detected by a direct `read_link(/proc/PID/exe)` mapped to NotArmable ONLY on `ErrorKind::NotFound`; any other error (permissions etc.) follows today's `?` error path. Static is detected ONLY by the existing `loader_locator` → `None` return (no new ELF logic). Do NOT consult maps-emptiness (transient-empty maps must never classify a live process).

- [ ] **Step 1: Recon the arm call sites and fixtures.** (a) Read `arm_loader_for_view` (:9773–~:9920), `arm_loader_or_partial` (:10295–~:10340), the initial-arm loop (~:12660–:12680), and the refresh-arm closure (:12144) end to end; report every path that can return silent `Ok(false)` today and confirm the reviewer's claim that dynamic-binary silent-false = already-armed. (b) Find how existing loader tests fake views/exes (search `engine_tests.rs` for loader-locator/arm tests); report the fixture to extend. (c) Confirm `record_loader_arm` has exactly the two known call sites (10309, 12663) and report what each passes. **Tripwire:** if any other silent-`Ok(false)` path exists for a DYNAMIC executable (i.e. a real arm failure that is silent AND unmarked), STOP and report — the NotArmable contract would misclassify it.
- [ ] **Step 2: Write the failing tests.** Following the existing loader fixtures:
```rust
#[test]
fn arming_a_view_without_an_executable_is_not_armable_not_partial() {
    // View whose /proc/PID/exe readlinks ENOENT (kthread shape): arm returns
    // Ok(false), marks nothing, records no loader context, errors nothing.
}
#[test]
fn arming_a_static_executable_is_not_armable_not_partial() {
    // View whose exe has no PT_INTERP (locator None): same silent outcome;
    // unavailable count does not grow.
}
#[test]
fn genuine_arm_failures_still_mark_partial() {
    // Dynamic exe, loader unpinnable (or state-address failure — pick ONE
    // existing marked path): today's mark text appears byte-for-byte.
}
```
Exact fixture mechanics adapt to the file; the assertions (no-mark / mark-text / no-record) do not change.
- [ ] **Step 3: Run them to verify they fail.** Focused `--lib` run. Expected: FAIL (no-exe view errors+marks today; static view records Unbound today).
- [ ] **Step 4: Minimal implementation.** Add the NotArmable outcome per Interfaces. Touch nothing else in the arm path.
- [ ] **Step 5: Loader + render tests.** Full `--lib` loader/identity/render-related filters green; in particular every test pinning `capture_skipped_out` redaction and every loader-mark-text test passes UNCHANGED.
- [ ] **Step 6: Full suite, fmt, clippy.** Green, per Global Constraints.
- [ ] **Step 7: Commit.** `git add` only touched files; message `fix: loader arming skips views without an executable (E)` + body citing the 128× kthread measurement and gates.

## Task 2: One mount-table re-read on missing-mount before failing

**Files:**
- Modify: `src/process.rs` (`open_then_mountinfo` path) and/or `src/discovery/identity.rs` (call-site retry — recon decides; the retry MUST reuse one helper so both loader pinning and scan pinning benefit — report which call sites gain the retry).
- Test: beside the code.

**Interfaces:**
- When `mapping_file_key_in_mountinfo` fails ONLY with a missing-mount-id error (exact current message preserved), re-read the SAME `/proc/PID/mountinfo` table once (same pid, same checked scope) and re-resolve; success returns the key, persistent absence returns today's error text byte-for-byte (still marked, still OrdinaryFailure — no guarantee change). No retry on any other error (open failures, parse errors, budget refusals).
- The fd stays open across the retry (it already does — the helper holds it). No new syscalls on the success path.

- [ ] **Step 1: Recon.** Read `open_then_mountinfo` (`process.rs:424`), `open_then_mountinfo_checked`, `mapping_file_key_in_mountinfo` (`identity.rs:112`), and the missing-mount error construction; enumerate every caller that would gain the retry and confirm none depends on single-read failure (e.g. tests pinning exactly-one-read). Report the insertion point. **Tripwire:** if the missing-mount error string is matched anywhere else (render, dedup, tests) such that a retry would change observable behavior beyond flakiness, STOP and report.
- [ ] **Step 2: Write the failing test.** A resolver/mountinfo test where the FIRST table read lacks the fd's mount id and the SECOND contains it (fixture: two table strings): resolution succeeds. Plus: persistently-missing mount returns today's exact error (pins the unchanged failure).
- [ ] **Step 3: RED run.** Fails (no retry exists).
- [ ] **Step 4: Minimal implementation** per Interfaces.
- [ ] **Step 5–7: Gates + commit** as in Task 1 (`fix: retry mount resolution once on missing mount id (E)`).

## Task 3: Docs + controller verification (split)

- [ ] **Step 1 (subagent):** One paragraph in `docs/usage.md` next to the loader-qual documentation (find it; if none exists, next to the cgroup paragraph): views without an executable (kernel threads) and static executables are not loader-arming candidates and no longer count as `unavailable`. Follow-up docs commit. Gates: fmt + focused loader tests.
- [ ] **Step 2 (controller-only):** No dispatch. The controller rebuilds, re-runs the scale capture, and checks `unavailable` drops to single digits with the remaining ones attributable (EDBG-free this time: the aggregate + redacted skips suffice given unit coverage).

## Self-review (controller, against the spec)

1. Spec coverage: 128× kthread errors → Task 1 (no mark, no unavailable count); 6× mount gaps → Task 2 (retry, unchanged failure); already-armed silent-false → verified normal in Task 1 Step 1, untouched; redaction untouched per constraints; slowness/cap/hits explicitly out of scope. No gaps.
2. Placeholder scan: no TBD/TODO; files, line numbers, commands, assertions, and frozen detection/error-text rules are exact. Fixture mechanics are the only adaptation, fenced to construction with assertions frozen.
3. Contract consistency: NotArmable = (exe-ENOENT via read_link) OR (locator None); nothing else reclassified; every genuine failure keeps mark text/kind/record; retry only on missing-mount, once, same scope; render.rs untouched.

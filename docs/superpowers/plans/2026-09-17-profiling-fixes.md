<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Profiling fixes implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut p11scope's measured per-call overhead where profiling proves waste, and make event-loss tuning truthful — every claim re-benched.

**Architecture:** `docs/notes/phase5-overhead.md` proves the waste: all modes cost ~+3.3µs/call because the eBPF program unconditionally submits ring events even in `metrics` mode (which never drains). The existing CONFIG flags channel (`crates/ebpf/src/main.rs:54`, `valid_config` mask in `crates/ebpf-common`) carries a new mode flag; userspace sets it; BPF skips the submit. Bench proof via `scripts/bench-overhead.sh` (privileged, owner-gated — UNRUN protocol included).

**Tech Stack:** Rust 1.88 (`cargo +1.88`), aya eBPF (`crates/ebpf`), `scripts/bench-overhead.sh`, SoftHSM2 hammer fixture.

**Spec:** `docs/notes/phase5-overhead.md` (Results + Findings) + `docs/usage.md` "Overhead (measured)" + "Capture tuning" sections.

## Global Constraints

- Toolchain is exactly `cargo +1.88`; every cargo invocation carries `--locked` and `--offline`.
- Every `cargo test`/`build`/`run` invocation is prefixed with `TMPDIR=/var/tmp/p11scope-ws-tmp`.
- Full suite: `TMPDIR=/var/tmp/p11scope-ws-tmp cargo +1.88 test --locked --offline --workspace --all-targets`; plus `cargo +1.88 fmt --all -- --check`, `cargo +1.88 clippy --locked --offline --workspace --all-targets -- -D warnings` clean.
- BPF rebuilds need the pinned nightly + bpf-linker per `docs/development.md`; verify the BPF object rebuilds byte-reproducibly before behavior claims.
- No `sudo`/privileged runs by subagents — bench runs are OWNER-GATED (controller asks; unapproved → UNRUN with the exact command recorded). Never weaken the bench sanity checks (`attached_probes > 0`, no `attach failed`).
- No network, no new dependencies. Branch `fix/profiling-pass`, worktree `.worktrees/fix-profiling-pass`; never commit on main; never push.
- /tmp EDQUOT is a known environmental gate hazard: triage per `known-flakes.md`, preserve full logs, never weaken seal tests.

---

## Task 1: Re-baseline bench (owner-gated measurement)

**Files:** none (evidence task; numbers go in the report + `docs/notes/phase5-overhead.md` update in Task 4).

**Interfaces:**
- Consumes: nothing.
- Produces: current-tip overhead table (same 4 conditions × 5 runs) OR honest UNRUN.

- [ ] **Step 1: Ask for the privileged bench.** Command: `scripts/bench-overhead.sh` (uses sudo internally, SoftHSM2 fixture). If approved, run once, record the full table + raw runs.
- [ ] **Step 2: If UNRUN**, record the exact command + environment prerequisites so the owner can run it later; Tasks 2–3 proceed on the phase5 numbers (the waste mechanism is already proven there).
- [ ] **Step 3: Report.** Baseline table or UNRUN. No commit (`none`).

## Task 2: Mode-aware ring submission (metrics skips the submit)

**Files:**
- Modify: `crates/ebpf-common/src/*.rs` (new `FLAG_POLICY_NO_RING` bit + `valid_config` mask — follow the `FLAG_POLICY_AGGREGATE` pattern at :304-315); `crates/ebpf/src/main.rs` (entry/return programs skip `EVENTS` submit when the flag is set — verify every submit site, recon found ring-loss bumps at :301, :2564, :2620); userspace flag-setting site (find where CONFIG flags are written for a capture — `grep CFG_FLAGS src/`).
- Test: BPF-side unit coverage per existing eBPF test pattern (verify how current flag behavior is tested first — `grep FLAG_POLICY_AGGREGATE src/ tests/ crates/`).

**Interfaces:**
- Consumes: Task 1 baseline (proves the waste exists at this tip; if UNRUN, phase5 numbers).
- Produces: metrics-mode captures submit zero ring events; aggregates stay exact; `evidence.completeness` semantics unchanged.

- [ ] **Step 1: Enumerate submit sites + flag tests.** List every `EVENTS` submit/reserve call and every existing CONFIG-flag test. **Tripwire:** if userspace has no per-mode CONFIG write path, STOP (NEEDS_CONTEXT) — the channel assumption is wrong.
- [ ] **Step 2: Failing-first tests.** Flag-set unit test asserting no-submit (BPF test harness) + userspace test asserting metrics mode sets the flag and profile/trace do not. RED.
- [ ] **Step 3: Implement** the flag, mask, BPF branches, userspace wiring. Minimal diff; no other BPF logic touched.
- [ ] **Step 4: Prove aggregates exact.** Existing induced-gaps/aggregate tests green (they are the count authority); new tests GREEN.
- [ ] **Step 5: Gates + commit.** Full suite green can only prove userspace; BPF object must rebuild + reload in its own test path (state which). `perf: skip ring submit in metrics mode`.

## Task 3: Post-fix bench + loss-tuning truth (owner-gated)

**Files:**
- Modify: `docs/usage.md` "Overhead (measured)" + "Capture tuning" sections (numbers only from real bench runs, each citing the script).

**Interfaces:**
- Consumes: Task 2 implementation.
- Produces: post-fix overhead table showing metrics-mode improvement (or honest no-improvement + analysis); tuning guidance validated against measured loss rates.

- [ ] **Step 1: Ask for the post-fix bench** (same command as Task 1). Record table + raws.
- [ ] **Step 2: Analyze.** If metrics improved, quantify (ns/call + %). If not, say so and name the next dominant cost from evidence (do NOT guess — "unresolved, needs BPF-side cycle profiling" is an honest outcome).
- [ ] **Step 3: Tuning guidance.** Update `--ring-bytes`/`--drain-interval-ms` docs ONLY with measured loss-rate numbers (existing 99.1%/122–145k figures or fresh ones). No invented recommendations.
- [ ] **Step 4: Gates + commit.** Doc + numbers; `perf: re-bench overhead after metrics no-ring`.

## Task 4: Gates + merge review

**Files:** none (evidence task).

- [ ] **Step 1: Full suite ×2** (TMPDIR-prefixed), fmt + clippy clean. Record counts + logs.
- [ ] **Step 2: Proof bundle.** Baseline table + post-fix table (or UNRUN pair), `git diff main --stat` reviewed, BPF verifier log clean on rebuild.
- [ ] **Step 3: Final review + merge** to main (local merge pre-approved; never push), retire branch/worktree per finishing-a-development-branch.

## Self-review (controller, against the spec)

1. Spec coverage: phase5 "unconditional in-kernel cost" finding → Task 2; "modes converge" + loss figures → Tasks 1/3; usage.md measured-claims rule → Task 3 (numbers only from runs). No gaps.
2. Placeholder scan: no TBD/TODO; flag pattern, submit sites, and bench commands exact; UNRUN protocol explicit for both bench tasks.
3. Contract consistency: TMPDIR/toolchain/branch identical everywhere; privileged work owner-gated (never by subagents); aggregates-exact invariant pinned by existing tests.

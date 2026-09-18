# Usability pass implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Walk p11scope as a first-time user in six conditions, fix every real friction found, and pin each fix with a regression test.

**Architecture:** Controller recon captured the current UX baseline (global `--help`, per-subcommand help gap, exit codes 0/1/2 verified sane, unprivileged `doctor` verdict good). Task 1 scripts six user journeys as failing-first trials; Tasks 2–4 fix what the trials prove broken; Task 5 gates + merges. No fix without a trial that demonstrates the friction.

**Tech Stack:** Rust 1.88 (`cargo +1.88`), `src/cli.rs` + subcommand dispatch, `docs/usage.md`, `README.md`.

**Spec:** Prior goal text ("usability pass as a potential user in different conditions, fixing what a real user would hit") + controller recon baseline in this plan's Task 1 table.

## Global Constraints

- Toolchain is exactly `cargo +1.88`; every cargo invocation carries `--locked` and `--offline`.
- Every `cargo test` invocation is prefixed with `TMPDIR=/var/tmp/p11scope-ws-tmp` (per AGENTS.md); every `cargo build`/`run` likewise (rustc temp files honor TMPDIR).
- Full suite: `TMPDIR=/var/tmp/p11scope-ws-tmp cargo +1.88 test --locked --offline --workspace --all-targets`; plus `cargo +1.88 fmt --all -- --check`, `cargo +1.88 clippy --locked --offline --workspace --all-targets -- -D warnings` clean.
- No `sudo`, no network, no new dependencies. Branch `fix/usability-pass`, worktree `.worktrees/fix-usability-pass`; never commit on main; never push.
- UX fixes only: CLI copy, help routing, error guidance, docs. No capture/discovery/BPF behavior change. Copy changes keep every quantitative claim cited (usage.md rule).
- /tmp EDQUOT is a known environmental gate hazard: triage per `known-flakes.md`, preserve full logs, never weaken seal tests.

---

## Task 1: Journey trials (six conditions, failing-first)

**Files:**
- Create: `tests/ux_journeys.rs` — scripted journey trials (unprivileged-safe only; privileged lanes stay owner-gated per repo rule).
- Evidence: trial report (per-journey PASS/FRICTION with verbatim output).

**Interfaces:**
- Consumes: nothing (first task).
- Produces: numbered FRICTION list (F1..Fn) with verbatim evidence; each later fix cites its F-number.

Controller recon baseline (implementer: re-verify each row; deviations go in the report):

| # | Probe | Observed |
|---|-------|----------|
| B1 | `p11scope --help` | global usage, exit 0 |
| B2 | `p11scope profile --help` | FULL global usage, no profile-specific section |
| B3 | no args / bad subcommand | names the problem + usage, exit 2 |
| B4 | `--version` | `p11scope 0.1.0`, exit 0 |
| B5 | bad `--pid` | `p11scope: ... cannot pin pid ...`, exit 1 |
| B6 | unprivileged `doctor` | per-row ok/warn/FAIL/n/a + `verdict: capture unavailable; ...`, exit ? (record) |
| B7 | unprivileged `run -- true` | fails (record verbatim message + exit) |

Journeys (each: exact commands, expected-good behavior, record verbatim):

- J1 fresh eyes: `--help`, `profile --help`, `doctor --help` — can a new user learn one subcommand?
- J2 unprivileged: `doctor`, `profile --pid <own-sleep> --duration 1`, `run -- /bin/true`, `inspect --pid <own>` — does every refusal name the missing privilege + the doctor row to check?
- J3 wrong target: nonexistent pid, exited pid, non-ELF script target — is each error specific + actionable?
- J4 bad flags: `--duration banana`, `--ring-bytes 0`, `--mode frobnicate`, `run` without `--` — usage error naming the flag, exit 2?
- J5 offline build docs: follow README + `docs/build-offline.md` in a COPY of the tree (never mutate the worktree for this) — does the documented path work verbatim?
- J6 K8s docs: follow `deploy/k8s/README.md` against kind ONLY if a kind cluster already exists (never create billable infra; else doc-review only, record UNRUN).

- [ ] **Step 1: Re-verify baseline B1–B7**, record verbatim + exits.
- [ ] **Step 2: Run J1–J6**, write the FRICTION list (each: journey, verbatim output, why a real user stalls).
- [ ] **Step 3: Commit trials.** `tests/ux_journeys.rs` encodes each journey as an ignored-by-default doc-testable script? NO — encode as plain `#[test]`s that PASS on current behavior (they pin the baseline); the FRICTION list lives in the report. Commit `test: pin UX journey baseline`.

## Task 2: Help routing (per-subcommand `--help`)

**Files:**
- Modify: `src/cli.rs` (help dispatch), possibly `src/main.rs`.

**Interfaces:**
- Consumes: F-numbers from J1.
- Produces: `<sub> --help` prints that subcommand's section + shared footer, exit 0; `help <sub>` alias if trivial (same code path or skip).

- [ ] **Step 1: Failing-first test** (cli tests module): `profile --help` output contains `[--pid` and does NOT contain `p11scope trace`; `doctor --help` likewise scoped. Run: RED.
- [ ] **Step 2: Implement** scoped help (extract per-subcommand text blocks; global `--help` unchanged byte-for-byte — add a test pinning global help hash/length so it cannot drift silently).
- [ ] **Step 3: Docs sync** if usage.md quotes help output (grep first; update quotes verbatim).
- [ ] **Step 4: Gates + commit.** `test: scope --help per subcommand`.

## Task 3: Error guidance (refusals name the fix)

**Files:**
- Modify: error-construction sites cited by J2/J3 F-numbers (likely `src/run.rs`, `src/doctor.rs` verdict hints, pid-pinning errors).

**Interfaces:**
- Consumes: F-numbers from J2–J4.
- Produces: every in-scope refusal message names (a) what was refused, (b) the concrete next command/flag/doc section. Exit codes unchanged (2 usage, 1 runtime — pinned by tests).

- [ ] **Step 1: Failing-first tests** per F-number: run the CLI as a subprocess (existing harness pattern), assert the new guidance substring + exit code. RED.
- [ ] **Step 2: Implement** message changes only — no control-flow change. Each message ≤3 lines; no new jargon without a doc pointer.
- [ ] **Step 3: Gates + commit** per F-number group. `ux: guide <refusal> to <fix>`.

## Task 4: Docs friction (README/usage/K8s)

**Files:**
- Modify: `README.md`, `docs/usage.md`, `deploy/k8s/README.md` — ONLY lines the J5/J6 trials prove wrong or stalling.

**Interfaces:**
- Consumes: F-numbers from J5–J6.
- Produces: verbatim-workable doc paths; every changed quantitative claim keeps its script citation.

- [ ] **Step 1: Fix J5 findings** (build path). Re-run the doc path in a scratch COPY to prove it works verbatim.
- [ ] **Step 2: Fix J6 findings** (or record UNRUN with the doc-review notes).
- [ ] **Step 3: Gates + commit.** Doc-only; suite untouched but run lib focused tests for any example output pins. `docs: fix <path> friction (J5/J6)`.

## Task 5: Gates + merge review

**Files:** none (evidence task).

- [ ] **Step 1: Full suite ×2** (TMPDIR-prefixed), fmt + clippy clean. Record counts + logs.
- [ ] **Step 2: Journey re-run.** All J1–J6 trials re-executed: every F-number resolved or explicitly deferred with rationale (deferrals need controller approval in review).
- [ ] **Step 3: Final review + merge** to main (local merge pre-approved; never push), retire branch/worktree per finishing-a-development-branch.

## Self-review (controller, against the spec)

1. Spec coverage: "different conditions" → J1–J6; "fixing what a real user would hit" → Tasks 2–4 gated on F-numbers (no drive-by redesigns). No gaps.
2. Placeholder scan: no TBD/TODO; journeys, pins, and exit codes exact. J6 kind-gating is explicit (UNRUN allowed, never billable).
3. Contract consistency: TMPDIR/toolchain/branch identical everywhere; baseline-pinning before fixing; global-help immutability pinned by test.

# Privilege-minimization research plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-measure the capability matrix at the current tip, find provable privilege reductions, and deliver a ranked proposal — research only, no product change without a fresh approval.

**Architecture:** `docs/notes/phase4-privileges.md` states its broader matrix "remains pending rerun" and live-discovery capability output is UNRUN. Task 1 re-runs the matrix protocol (owner-gated privileged runs); Task 2 probes minimization hypotheses against measured rows; Task 3 writes the ranked proposal. Like churn Unit 7: evidence + proposal, code changes need their own approval.

**Tech Stack:** `scripts/matrix/verify-fork-scope.sh`, `scripts/verify-capability-tier.sh`, `capsh`/`setpriv`, file capabilities, `doctor` T0–T4 tiers.

**Spec:** `docs/notes/phase4-privileges.md` (Parts 1–2 + pending-rerun header) + `docs/usage.md` "Privileges, per environment".

## Global Constraints

- No `sudo`/privileged runs by subagents — every privileged measurement is OWNER-GATED (controller asks; unapproved → honest UNRUN with the exact command recorded).
- Every matrix cell records ACTUAL error text, not documentation claims (phase4 rule, verbatim).
- Historical rows stay verbatim; new rows are dated + commit-pinned (`main@<sha>`).
- No product-code change in this plan (research-only). Test/doc updates only to record findings.
- Toolchain `cargo +1.88 --locked --offline`, TMPDIR-prefixed runs. Branch `fix/privmin-research`, worktree `.worktrees/fix-privmin-research`; never commit on main; never push.

---

## Task 1: Matrix re-run (owner-gated measurements)

**Files:**
- Modify: `docs/notes/phase4-privileges.md` (new dated rows only — append, never rewrite history).

**Interfaces:**
- Consumes: nothing.
- Produces: current-tip matrix rows: host (unpriv / CAP_BPF+CAP_PERFMON / CAP_SYS_ADMIN / file-caps minimal / root) × {attach, lifecycle, live-discovery, owned-run} with actual error texts; docker/kind rows re-measured or confirmed UNRUN with reason.

Recon-owned protocol (verify paths exist before asking):
- Host rows: `scripts/matrix/verify-fork-scope.sh` + manual `capsh`/`setpriv` ladder per the note's Part 2 brief.
- Tier assertions: `scripts/verify-capability-tier.sh` (T0 offline … T4 current full).
- Live-discovery capability output: currently UNRUN (note :131) — measure or keep UNRUN with the blocker named.

- [ ] **Step 1: Verify protocol paths** (scripts exist, `--help`/usage known). List the exact command per cell.
- [ ] **Step 2: Ask for the privileged ladder** (cell commands in one batch). Record per-cell: exit, attached/total probes, completeness, skips, verbatim error text.
- [ ] **Step 3: Append dated rows** to the note (`main@<sha>`, host kernel, paranoid/ptrace_scope values). UNRUN cells record the exact command + why.
- [ ] **Step 4: Commit.** `docs: re-measure capability matrix at <sha>`.

## Task 2: Minimization probes (hypothesis × measurement)

**Files:**
- Evidence: report (per-hypothesis PROVEN/REFUTED/UNRUN with numbers).

**Interfaces:**
- Consumes: Task 1 rows.
- Produces: verdict per hypothesis below (each needs a before/after measurement pair or honest UNRUN).

Hypotheses (implementer: attempt in order, all owner-gated):

- H1 file-caps minimal set: is `cap_sys_admin,cap_bpf,cap_perfmon,cap_sys_ptrace,cap_dac_read_search` still minimal, or does a subset attach fully? Bisect by dropping one cap at a time.
- H2 per-command tiers: what is the minimal doctor tier for `inspect` / `profile --mode metrics` / `trace` / `run --pause never`? (Some may need less than full capture.)
- H3 paranoid interaction: does `perf_event_paranoid ≤ 2` drop the CAP_SYS_ADMIN need for uprobe attach on this kernel? (Read-only kernel-param check first; changing it is owner-only.)
- H4 helper seccomp posture: do the offline helpers (`p11scope-discover`, lane scripts) run under a tighter profile without loss? Enumerate their syscalls from evidence, don't guess.
- H5 root-only lanes: which verify scripts still need full root, and which need exactly documents? (Closes the "broader matrix" gap structurally.)

- [ ] **Step 1: Ask for the H1–H5 probe batch** (exact commands listed). Run approved subset.
- [ ] **Step 2: Record verdicts** with before/after pairs. A hypothesis without a measurement pair is UNRUN, never "likely".
- [ ] **Step 3: Report.** No commit (`none`) — findings commit with Task 3.

## Task 3: Ranked proposal + merge review

**Files:**
- Create: `docs/notes/2026-09-17-privmin-proposal.md` (ranked reductions, each with evidence pointer + risk + suggested follow-up plan).
- Modify: `docs/usage.md` "Privileges, per environment" ONLY where Task 1 re-measurements contradict current text (with row citations).

**Interfaces:**
- Consumes: Tasks 1–2 evidence.
- Produces: proposal with falsified alternatives named (not just the winner); STOP for approval before any product change.

- [ ] **Step 1: Write the proposal.** Rank by (evidence strength × risk reduction). Each item: what to change, measured proof, what could regress, suggested verification.
- [ ] **Step 2: Review + merge** the research branch to main (local merge pre-approved; never push), retire worktree per finishing-a-development-branch.

## Self-review (controller, against the spec)

1. Spec coverage: "pending rerun" → Task 1; "UNRUN live-discovery capability" → Task 1; minimization goal → Task 2; usage.md privilege docs → Task 3. No gaps.
2. Placeholder scan: no TBD/TODO; scripts, tiers, hypotheses, and UNRUN protocol exact.
3. Contract consistency: research-only (no product change); privileged work owner-gated; history verbatim + dated new rows.

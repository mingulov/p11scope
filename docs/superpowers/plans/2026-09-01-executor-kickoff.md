# Executor kickoff — p11scope v0.1.0 release program

Hand this file to any agent executing the release program. It is the entry
point; everything else is pointed at, not restated.

## What this is

`p11scope`: non-interposing PKCS#11 observer (eBPF uprobes) for Linux
x86-64. Goal: a real, publishable v0.1.0 — correct first, locally tested
second, breadth (CI/containers/distros/ABIs) third.

**Two directories only:** `/home/user/src/m/pkcs11-scope` (public repo, git)
and `/home/user/src/m/p11scope-ws` (non-public workspace: evidence, VM bases,
preserved artifacts). Nothing durable anywhere else.

## State at handoff (2026-09-01, verified main @ 5d251b76b33b14839a7147e14b5ccd1348855587)

- All four cargo gates green on `main`. Nothing has been pushed by agents;
  `origin/main` (`367cadd`) is a stale 239-commit-old ancestor whose public
  tip sits above a "not ready" wip commit — reconciling it is a W8/owner item.
  Historical reviewed bases (`7d6eff7`, `556f7cf`, and `b86d4d5`) remain
  preserved as history only; W1 execution starts from the verified tip above.
- Wave 1 plan is fully reviewed and executable. Waves 2–8 are defined below.

## Read in this order

1. `CLAUDE.md` — working agreements + the four gate commands.
2. `docs/superpowers/specs/2026-09-01-p11scope-release-prd.md` — product
   truth: scope, tiers, privacy/honesty contracts, §9 acceptance criteria.
3. `docs/superpowers/specs/2026-09-01-release-requirements-and-goal.md` —
   the owner's requirements, priorities, and known-wrong list (§5).
4. `docs/superpowers/plans/ROADMAP.md` §"Release program (2026-09-01)" —
   the W1–W8 wave table and the **Agent execution protocol** (binding: how
   you plan, verify anchors, review-to-zero, branch, commit).
5. Your wave's document:
   - W1: `2026-09-01-release-hardening-wave1-findings.md` (full plan —
     execute via superpowers:subagent-driven-development).
   - W2: `2026-09-01-wave2-storage-consolidation.md` (full plan).
   - W3–W8: `2026-09-01-release-wave-charters.md` (charter; its Task 1 is
     writing the wave's plan under the verified-anchor protocol, two passes).
6. Background only: `docs/notes/2026-09-01-ebpf-comparable-tool-pitfalls.md`
   (two numbering schemes — "checklist N" vs "item #N"; never mix),
   `docs/superpowers/specs/2026-09-01-post-release-feature-slices.md`.

## Non-negotiables (short form; the protocol has the full list)

- Waves in order; a wave ends at four green gates + a full independent
  review cycle accepting zero findings + its evidence rows.
- TDD: every fix lands with a test that fails without it.
- Honest evidence: pass / fail / UNRUN — never inherited, never implied.
- Privacy allowlist (`docs/privacy/allowlist-v1.md`) is never broadened
  implicitly.
- Branch per wave off `main`, commit per task, merge only after
  review-to-zero. **Never push.**

## Owner-gated — surface and STOP, never do autonomously

Push/tag/publish anything; privileged (`sudo`) or container runs; deleting
original evidence or old storage roots; rotating keys; allowlist/schema
revisions' wording; spending money; the W4 hosted-CI push decision.

## Open owner decisions (recorded in the docs — do not resolve them yourself)

1. Spec §6 storage-bullet interpretation (historical paths stay verbatim) —
   PRD §9.6 note, ratified in the W2 relocation record.
2. `pkcs11-check-ws` as a third directory (oracle-lane dependency) —
   OWNER-PENDING in the W2 plan.
3. Hosted CI requires a push decision — W4 starts by surfacing it; a dormant
   pipeline leaves spec §6's CI bullet UNMET and blocks W8 acceptance.
4. Reconciling the stale public remote tip — W8 publication runbook.

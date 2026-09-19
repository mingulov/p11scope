<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# SDD Ledger — system-scale capture (feat/system-scale)

Plan: docs/superpowers/plans/2026-09-19-system-scale.md
Base: main @ 1dd7eef. Integration branch: feat/system-scale.
Gates per task: fmt → clippy(-D warnings) → tests → spec+quality review → merge.
Build env: TMPDIR=/var/tmp/p11scope-ws-tmp cargo +1.88 --locked --offline.

## Task 1.1 — evidence score per candidate table
- Branch: task-1.1/evidence-score @ 3b83163. Merged: bb2314a.
- Scope: TableEvidenceScore + table_evidence_score + order_tables_by_evidence in
  src/discovery/scan.rs; one ordering test in engine_tests.rs.
- Review: spec PASS (pure, no I/O, linked > live_return > manifest > full_walk,
  stable order), quality PASS, test green (verified in worktree).
- fmt: clean. tests (merged tree): PENDING full-suite run at merge time.
- clippy: RED on merged tree — 3 dead_code errors. Root cause (systematic-debug):
  the new items' only consumer is ordered admission, which lands in Task 1.2;
  no prod call site exists yet. NOT suppressed — Task 1.2's wiring is the fix.
  Main stays green; integration branch carries the known-red until 1.2 lands.
- Note: attempt-1 lost to wrong-repo isolation (p11scope-ws @15cc746); re-ran
  with repo-local worktree, verified identity first. Child's "clippy clean"
  claim was false — always re-run gates on the merged tree.

## Task 1.2 — ordered admission + per-object cap (IN PROGRESS)
- Branch: task-1.2/ordered-admission (from bb2314a).
- Brief: wire order_tables_by_evidence into engine admission; per-object K cap;
  first acceptance step clears the 3 dead_code clippy errors above.
- SPEC CORRECTION sent mid-flight (deep review 2026-09-19, claims verified:
  upstream gen-fixed-closures.py defaults to 64, replica cross-check 2 shared
  @ ordinals 65/66, 64x102+2=6530, plan.rs:1437/:1270-1283/:758-780,
  events.rs:64): the 64 tables are deliberate p11_virtual_fixed templates, not
  proven false positives. K=4 now caps UNRESOLVED HEURISTIC tables only;
  corroborated tables bypass K under global budget + atomic refusal; 64-table
  test reframed as resource-bound; added five-published-table, atomic-refusal,
  and two-views-one-cap tests. Followup message queued; acknowledgment pending
  at commit time — confirm at Task 1.2 review.
- Plan v2 committed alongside: F-Scale-1 correction, three-decision admission
  contract (confidence/admission/authorization), 1.2+1.3 one release unit,
  Task 1.4 oracle+baseline, Phase 2 gated on 1.4+3.1, loader comparison
  (Aya PR #1417 = lead to verify), group-rebuild decision, acceptance matrix.
- Plan v3 delta (deep-review follow-up §1.5, all claims verified: virtual.c
  first-free alloc + NULL-on-release + lookup_fall_through substitution +
  shared short_C_* markers; engine.rs:5026-5036, :9252-9255, :9393-9469):
  new Task 1.5 publication-driven admission (option A, 9-case acceptance set);
  Task 1.2 confirmed as option C interim (no new redirect needed); option B
  occupancy adapter explicitly deferred with hard constraints.
- Reviewer-gap probe (all checked, 2026-09-19): (1) REAL GAP — ordering
  degeneracy unstated: scan_interfaces finds 0 interfaces for the 64
  templates, so all score components tie and 1.2 admits first-4-discovered;
  recorded as 1.2 review gate. (2) REAL GAP — option A uncosted against
  discovery I/O + work budgets; added as 1.5 acceptance item. (3) SUSPICION
  REFUTED — 104-name catalog matches p11-kit 0.26.2 pkcs11.h member-for-member
  in order (Digest group genuinely absent, 3.2 extension block matches);
  no 3.x mislabel vector. (4) COSMETIC — review's scan.rs:838 citation drifted
  (now :896; def in external pkcs11-module crate).
- Plan v3.2 (deep-review §10+§11): new heap-allowance hazard VERIFIED in
  source (scan.rs:868-891 documents "without a stable file owner there is no
  identity, so charge"; ceilings 512/53,248 at :35-36) — added as Task 1.5
  Step 5 runtime-table accounting design. Reviewer's costing correction
  ACCEPTED (indexed lookups off snapshots, not per-target file reads) —
  Task 1.5 Step 4 rewritten as full-lifetime costing. §10 storage figures
  all verified exact (SlotStats 296 B, 9.25/117.97 MiB, RV 4096, START 16384,
  dense PerCpuArray). New Task 1.6 coverage-architecture experiment (broad vs
  publication-selected, two lanes, measured decision); open question (7);
  matrix gains wrapper-only failure + nested wrapper→backend. Catalog closed
  for p11-kit 0.26.2 header (scoped). Task 1.2 untouched by this delta.

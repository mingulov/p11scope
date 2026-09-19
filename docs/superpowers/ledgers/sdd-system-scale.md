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

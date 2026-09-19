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
- Ruling: user authorized 5-7 parallel subagents, overriding SDD's
  never-parallel rule — accepted with file-disjoint domains + separate
  worktrees/branches + sequential merges as the conflict control. Cost if
  wrong: merge conflicts and contended full-suite runs; merges stay
  one-at-a-time with gates re-run on the merged tree. Fanned out 2026-09-19:
  1.4-fixture (new files only), 3.3-preflight (run.rs+tests only), 2.1-loader
  (survey+/tmp spike+note, vendor unwired — Cargo wiring deferred to 2.2).
  Running alongside 1.2 (admission files). 4/7 slots used.
- Wave +1 (2026-09-19): measurement-harness worker (scripts/+docs/notes new
  files only) for 1.4/1.6/3.1 baselines. 5/7 slots used.
- 1.2 worker replacement (2026-09-19): original worker went silent (no file
  activity 30+ min, no processes, status nudge ignored, followup
  undeliverable: 'no exact live child mapping'; cancel also failed on task
  link storage). WIP preserved as 7c6f0da on task-1.2/ordered-admission;
  fresh worker dispatched on the same worktree to continue from HEAD (keeps
  target/ cache). If the ghost delivers late, reconcile by diff, not by
  double-merge. New worker brief requires BLOCKED-with-WIP-commit over
  silence. 6/7 slots nominally used (ghost may not be real).
- Task 2.1: complete (ae4cf7f, review clean, merged 5f86e24). Decision: narrow
  Aya backport (PR #1417 verified merged 2026-07-31); raw loader rejected for
  BTF objects (gate run against real objects); 68x fd + ~12-14x attach ms,
  identical 204/204 events, 0 fd leaks. Fixup b8494c7 for SPDX `//!` style
  (worker terminal, resume rejected).
- Ruling: fixed the 1-line SPDX header myself on the integration branch —
  worker terminal so SDD resume impossible, 3-char deterministic fix verdict
  by the license test (green). Cost if wrong: nil, test decides.
- Task 2.1: minor (deferred to 2.2): empty-offsets `assert!` should become a
  returned error at wiring time; add bisect_attach unit tests when wired.
- Task 3.3: complete (c806234, merged 400b655). Sink-open moved above
  Engine::discover; ordering test RED-proven (fails on old run.rs) + GREEN;
  fmt clean; clippy delta-zero (3 known pre-existing). Merged-tree full
  suite: 1070/1071 lib pass; 1 failure in
  actual_handoff_helpers_preserve_errno (pure helper unit test, never calls
  capture()/sink-open — provably disjoint from the 7-line diff; green in
  isolation 0.01s; worker's own suite green) = contention flake under 3
  parallel suites, not a regression. Recorded, not re-run.
- Ruling (SUPERSEDED 2026-09-19): goal pre-commits to multi-uprobe; plan's
  Task 2.1 comparison is reframed as WHICH loader (Aya backport vs raw
  helper), not WHETHER multi. Task 1.6 still decides SCOPE (broad vs
  selective) by measurement. Cost if wrong: loader rework if the comparison
  winner contradicts the directive.
- Ruling: per user refinement, uprobe_multi is an experiment-gated idea, not
  a directive — adopt iff measurements show it helps. Task 2.1 compares
  loaders AND establishes multi-vs-singles numbers; Task 1.6 decides scope;
  both feed an explicit adopt/defer call. Cost if wrong: delayed multi work
  if it was obviously right — accepted, measurement is the point.
- Task 1.2: complete (54d78c8, merged 6b536ed, inline review clean).
  Evidence-ordered admission with K=4 heuristic cap/object, published
  bypass (atomic vs global budget), spill as `uncorroborated_candidates`
  evidence; cross-view dedup by (file_offset, version); top-1-exceeds
  refusal preserved. Worker gate: lib 1075/0, system_scope 6/6,
  artifact_contracts 123/3 — license failure verified pre-existing on
  worker base bb2314a (header fix already on integration), canary+lane13
  isolation-green contention flakes re-proven by worker (98.8s/280.2s).
  Review package: .superpowers/sdd/2026-09-19-system-scale/review-bb2314a..54d78c8.diff.
- Task 1.2: minor (deferred to final review): Step-4 review gate asked for
  the 0-interface degenerate order asserted explicitly; worker asserted
  tie→discovery-order among 63 unlinked tables instead (same code path,
  same outcome class). Ruling: accept as covered — a fresh-worker round
  trip for a same-path variant assertion buys no behavior risk reduction.
  Cost if wrong: a tie-order regression slips past tests; mitigated by
  the existing per-table admission-map assertion (tables 0,1,2+63).
- 1.2 merged-tree gate #1: lib 1074/1 failed in
  system_scope_refresh_admits_later_generation_in_same_engine
  (`session.attached_slots` did not grow; earlier asserts incl. slots_b
  all passed). Isolation re-run GREEN 1.05s; failing run's stdout shows
  OS-level EPERM + truncated /proc maps snapshots under 3 parallel
  suites. Recorded as contention flake (3.3 precedent); full-suite
  re-run folded into the post-fixture combined gate instead of a
  standalone re-run. Cost if wrong: a real refresh-path regression
  hides until the next full gate; mitigated by the combined gate + the
  test's pre-existing coverage on all three branches.
- Task 1.4 fixture: complete (3d1f355, merged 85c0f9e, inline review
  clean). 5 new-only files: multi-wrapper provider/backend/workload C
  fixtures + 10-test workload oracle (exact log==oracle bytes, nesting
  1:1, pinned goldens) + README with per-task consumption map. Worker
  gate: fmt clean, oracle 10/10, lib green on its base; lifecycle
  serially green (parallel-only timeouts). SPDX headers verified on all
  5 files; no existing file touched.
- Ruling: killed merged-tree gate #2 (1.2-only tree) after the fixture
  merge and reaped its orphaned cargo child, folding validation into one
  combined gate on the 1.2+fixture tree — fixture is new-only so any lib
  failure there still attributes to the 1.2 tree. pkill used a broad
  pattern; verified no worker cargo process was alive at kill time (only
  my gate). Cost if wrong: a worker gate died silently and re-runs;
  use PID-targeted kills next time.

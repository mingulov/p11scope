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
- Combined gate on the 1.2+fixture tree (1b6058c): lib 1075/0 green;
  artifact_contracts 124 passed + 2 failed (metadata_canary_matrix,
  lane13_evidence_finalizes_only_after_owned_cleanup), 883s, RC=101.
  Root cause (systematic-debugging, flushed panics): all three inner
  failures are wall-clock timeouts under load-30-on-12-cores — canary
  `timeout 60s` killed verify-canaries.sh mid-suite (67+11 inner
  suites OK until the kill), lane13 body-success outer exit 124,
  lane13 port-forward 12s readiness deadline missed. Merges
  6b536ed/85c0f9e touch none of these paths. Isolation re-runs on
  this tree GREEN: canary 133.5s, lane13 210.7s (worker saw the same
  pair green at 98.8s/280.2s on its base). Recorded as contention
  flakes (3.3 precedent); no test edits — the timeout values are
  load-bearing process-test contracts. Note: my own isolation probe
  overlapped the gate and contributed load; no parallel probes
  during future gates. Cost if wrong: a real canary/lane13
  regression hides until the next full gate on an idle box;
  mitigated by isolation-green on the exact merged tree.
- Task 1.3: implementer DONE (2162716, `feat: table provenance and
  mislabel guard`). Provenance (file_offset, linkage) plan→evidence;
  single `table_name_authorized` predicate gates function_name labels,
  unlinked→`unknown`; also fulfills 1.2's live-return cap bypass.
  Worker gate: lib 1079/0, contracts 126/126, clippy+fmt clean.
- Task 1.3: task review: spec ✅, quality Needs fixes. 1 Important
  (bounded_skip rejects the new public ("unknown","null pointer")
  skip — verified correct against render.rs:563 vs checker:839;
  enters fix loop round 1), 2 Minor (deferred): stale authorized
  name restored on rebuild (plan.rs:736); manifest_supported cap
  bypass untested (plan.rs:1231+engine.rs:4849) — final review
  triages. Reviewer ⚠️ items resolved by controller: TDD red-run
  accepted on report (tests present in diff); suite numbers
  provisional pending merge gate; consumer-grep closed (render uses
  gated plan names; DecodedOccurrence internal-only, no consumers
  outside engine/scan/tests).
- Task 1.3: fix round 1/5 dispatched (bounded_skip alignment +
  self-test pair); FIX_BASE 2162716.
- Task 1.3: fix round 1/5 (1 addressed, 0 open — bounded_skip
  accepts ("unknown","null pointer") via entry_skips + self-test
  pair; commits 2162716..5d78628). Re-review: all findings
  addressed, no breakage. Merge gate on 681784e: checker self-test
  OK, lib 1079/0.
- Task 1.3: complete (commits 246f575..5d78628, review clean after
  1 fix round; 2 minors deferred to final review).
- Task 1.4: implementer DONE (19c6296 oracle re-baseline + b9bc42a
  baseline note; numbers in commit message). Baseline: pid cells
  20006/20006 exact per-name both modes; system cells 20002→0 TRUE
  MISS (K=4 spends 410 slots on dormant p11-kit templates,
  whole-refuses the active provider; stable 4/4). Capacity: honest
  union 774 > 512 → keep 512 + honest refusal for Phase 1, open
  map-resize/epoch follow-up (sized after 1.6). Routed items done:
  scan-only `unknown` re-baselined (e2e green), proxy validator
  rewritten to K=4 shape. Per-PID attach false positive does NOT
  reproduce on this tree.
- Task 1.4: task review: spec ✅, quality Approved, no
  Critical/Important. Oracle edits verified strengthening. 6 minors
  deferred (M1 load folded note; M2 name-the-five sentence; M3
  binary sha256; M4 Δ4 truth note; M5 p11-kit shape brittleness;
  M6 green-log archiving) — final review triages. Controller ⚠️
  closed: W1 records carry full 38-counter universe, zero nulls,
  five mapped explicit (event_loss 0/19226/0/201,
  discovery_ring_loss 0/0/4082/4239; no bare ring_loss key); W2
  numbers in b9bc42a body; W3 follow-up opened here (map-resize/
  epoch, sized after 1.6, must record refused (dev,ino)).
- Task 1.4: complete (commits 681784e..b9bc42a, review clean;
  merged ab3863b). Merge gate: checker self-test OK. Note: proxy
  lane live self-test RC=1 is pre-existing environmental
  (hardcoded WORK=target/matrix-proxy vs fails-closed ancestor
  check on writable /home/user/src; 1.4 untouched that code) —
  not a merge blocker; lane workdir policy is a follow-up, not
  1.4 scope. Cost if wrong: a 1.4 oracle regression hides behind
  the environmental failure; mitigated by checker self-test OK
  (covers rewritten proxy mutations) + reviewer-verified
  strengthening.
- Follow-up OPEN (from 1.4): map-resize/epoch capacity task, sized
  after 1.6. Must record refused (dev,ino) (currently name+reason
  only — audit gap).
- Task 1.5: implementer DONE (ed2c557, `feat: publication-driven
  admission for heap wrappers`). Nine TDD cases (exact sets +
  workload counts), heap lowering via shared bracketed reader,
  RuntimeTableIdentity accounting, full-lifetime costing asserted
  per case. Worker gate: lib 1088/0, publication 9/9, broad
  integration suites green; contracts skipped (loaded box).
- Task 1.5: task review: spec ✅, quality Approved, no
  Critical/Important. Guards extended-not-removed verified by
  symbol+hunk absence; nine cases exact-set; linkage/naming
  contract intact. 8 minors deferred (t6/t8/t4 gap-size pins,
  cross-record bracket sharing, untested refusal/proxy arms,
  preamble duplication, plan.rs spill extra, evidence noise) —
  final review triages. Controller ⚠️ closed:
  `publication_consumed` has no code symbol (plan-concept name);
  all heap publication flows through single
  lower_heap_export_record + shared read_exact_table_bracketed —
  no bypass, constraint intent satisfied structurally.
- Task 1.5: complete (commits ab3863b..ed2c557 + pin hotfix
  75d3432; review clean, 8 minors deferred; merged 3d91366).
  Merge pre-step on idle box: contracts 125/126 — the 1 failure
  was 1.4 fallout (19c6296 renamed the bootstrap self-test
  marker without updating the Rust pin; 1.4's gate never ran
  the wrapper). Controller hotfix: pin synced + new ordinal
  marker pinned (strengthening); targeted test green 0.59s on
  branch, 0.58s on merged tree. Lesson: oracle rewrites must
  run the wrapper tests that pin their markers — add to future
  dispatch gates. Canary + lane13 passed on the idle box,
  confirming the contention-flake diagnosis.
- Task 1.6: implementer DONE (d0904f0 Lane A apparatus +
  9d30d57 stage-hold fix + 7a2ed86 Lane B model/A2 probe/decision
  note). Lane A 6/6 cells exact (broad 387 slots/gap=0 vs
  selected 27 slots/gap=300/120 at beyond-K=4; attach +0.15s;
  detach ~20 probes/s ~38s vs ~3s; all loss counters zero); A2
  real p11-kit selected 410+spill-60 vs broad whole-refusal
  (6530>512); Lane B sparse C=8192 0.19MB vs 1.82MB dense at
  fixture residency, ~+3% at full 6530. Decision: sequenced
  composition — selected-512 now, sparse+detach next, broad
  after. Records: /var/tmp/p11scope-task16-matrix/.
- Task 1.6: review APPROVED, no blockers, 4 minors (2 fixed at
  merge, 2 deferred). Reviewer re-checked all 6 cells from
  record.json, reproduced A2 unprivileged, confirmed
  userspace-only default-off (single env read, pre-existing
  call sites pass false). Fixed: detach projection corrected
  ~5.5min → ~11min (13,060 probes at ~20/s); follow-up sketch
  now lists task_owner.c slot ceilings (slot<512 x3,
  start_count cap, 0..512 scrub). Deferred: t10 VMA-split index
  could derive from live MapLite; t13 python-holder Drop guard
  (#[ignore] manual test). Report-only: worker's drain sentence
  ("one unexplained outlier") is inaccurate — records show a
  systematic ~1.5s lane-correlated pair delta (1.69–1.96s broad
  vs 0.17–0.27s selected); worker report file was never
  committed, so no on-branch correction exists — noted here.
- Task 1.6: complete (commits d0904f0..7a2ed86 + integrator
  fixup 2027693; merged cfa3650). Merge pre-step found 4 REAL
  failures, not flakes: SPDX header on lanes note + hosted-CI
  registration for both lane drivers (UNRUN line for
  sudo-invoked lane-a, --self-test steps 6/6 + 7/7 green
  unprivileged). lane13 failed in-suite but isolation-green
  (181s), same contention signature; full re-run after fixup:
  126/126 green. Lesson: experiment drivers with --self-test
  or sudo argv trip hosted-pipeline contracts — dispatch gates
  must run artifact_contracts (or at least hosted_pipeline +
  license_headers) on the branch before DONE.
- Phase 1 admission truthfulness COMPLETE (1.1–1.6 merged).
  Open follow-ups: map-resize/epoch capacity (from 1.4, now
  sized by 1.6: sparse C=8192 + task_owner.c ceilings +
  EVIDENCE cell); detach fix or Phase 2 multi (1.6: ~11min at
  6530); lane workdir policy (from 1.4); 1.5/1.6 deferred
  minors for final review.
- Task 3.1-measure: implementer DONE (8973935 harness +
  fa6a1cc loss-shares note). 35 live runs rc=0, every count
  attributed: ring-vs-burst digit-exact 7/7, cadence 8303@1s→
  0@200ms, trace slow-sink 0→17191 file→4KB/s pipe, detach
  window 55%, may-remain/quantum 0 at default ring, discovery
  ×1.69 gap inflation on system, profile sink/mode 0. Oracle
  36/36 RED→GREEN, contracts 127/127. Delivery stall: worker
  session terminal but envelope stuck not_ready ~20min —
  recovered verbatim DONE from session log, cancelled stuck
  child (flushed delivery), proceeded from on-disk deliverables.
- Task 3.1-measure: review Spec ✅ / Approved, 1 Important +
  3 minors. Reviewer re-verified numbers from records,
  probed oracle falsifiability both ways, confirmed envelope
  supported with system-call regime honestly conditional.
  I1 (G4m-1 artifacts wiped by tsprobe rm -rf): fix round 1
  (fresh implementer — original cancelled) proved re-run
  impossible as specified, annotated row single-source with
  wipe stated + G4m-2 pointer, committed tsprobe.sh with
  per-cell workdirs + self-test + CI wiring (4fe53b6);
  re-review I1 ADDRESSED, no new breakage. Minors deferred
  (M1 metrics-comparator gap, M2 unused helper, M3 log-vs-
  record repro wording) — final review triages.
- Task 3.1-measure: complete, merged (FF to 4fe53b6).
  Merged-tree verification: artifact_contracts 127/127 green
  (733s). Repair envelope E-burst…E-discovery + conditional
  loss(R) system points + handoff + named gaps recorded in
  docs/notes/2026-09-20-task-3.1-loss-shares.md.
- Task 2.2: implementer DONE (bb62412 tip; 17 commits from
  29f7432 section-pin RED through 48d663c scratch-loader fix,
  467b94e 11-lane note, 2bc41a4 guard marker, bb62412
  corroboration). Mixed loading + regrouped multi attach:
  vendored Aya p2 multi backport (USE for link creation, singles
  path kept), `--attach-backend auto|multi|singles` on every
  capture surface, regroup by (path, entry program), return-first
  grouped orchestration with bisect + fallback sentinel, pid-0
  multi scope, uprobe-multi evidence + doctor self-link row.
  Measurement (note docs/notes/2026-09-20-task-2.2-multi.md):
  11 live lanes (SoftHSM2, 68 slots/136 endpoints) — 136/136 on
  2 multi links vs 136 perf links, 54 vs 188 observer fds,
  identical 227-call distribution, oracle PASS every metrics run;
  reviewer corroboration (104 slots/208 endpoints, 100
  deterministic table calls): singles/multi/auto capture
  identical 100/100 with 0 loss, bpftool census 218 → 12 links,
  setup <1 s, detach 1–2 ms both backends. EINVAL root cause on
  the way: kernel rejects `-` in BPF object names (logless);
  scratch prog renamed, charset pinned by test. Suite: full
  `cargo +1.88 test --locked --offline` green 1451/0 (4 ignored),
  contracts 129/129, fmt clean. Flake history (all disclosed):
  one real stale-marker guard failure (fixed 2bc41a4, property
  preserved); timing singles (history Deadline, root_fence
  Deadline, 2 preexec under a throttled run, lane13 k8s
  port-forward timeout) each green in isolation and in other
  full runs, all in code untouched by this branch, box load
  ~7–12 throughout (siblings + lane VMs).
- Task 2.2: review (self, inline — worker cancelled after its
  note landed): Spec ✅ / Approved. Re-verified: regroup key +
  deterministic order, return-first/entry-paired orchestration
  with failure-path parity to singles, auto session-granularity
  rebuild on BackendFallbackRequired, partial-group retirement
  refuses fail-closed with the Task 2.3 pointer, mechanism labels
  match the oracle rule, CLI on all three capture surfaces,
  doctor self-link Ok measured privileged. No new breakage;
  third-party backport accepted by measurement (section test +
  e2e link census), not by line review.
- Task 2.3: implementer DONE (branch task-2.3/group-rebuild).
  Explicit multi-group rebuild transaction: `Session::detach_slots`
  replaces the partial-retirement refusal with determine-affected
  (transitive closure over group links) → entries-before-returns
  detach with abort-before-reattach on any failure → regrouped
  survivors reattached returns-before-entries to fixpoint (entry-
  partial rollback, exhaustion/fallback explicit remainders) →
  per-member success/failure + reactivation evidence. Retained
  per-slot pinned facts (pruned with links); only fully paired
  survivors count as multi-attached; no overlapping make-before-
  break. Engine applies every report at all six detach sites + the
  replacement site through the existing rules (completions, timing
  loss, deactivation, PARTIAL); `Engine::multi_rebuild_gaps`
  counts disturbed groups into evidence (run.rs was hardcoded 0).
  Measurement (note docs/notes/2026-09-20-task-2.3-rebuild.md):
  5 live lanes (aliasing-downgrade trigger: live second provider
  sharing one manifest-attested slot) — every leg reports exactly
  the 160 ground-truth calls, 0 loss; multi profile legs show
  gaps=1 + uprobe-multi, singles gaps=0 + per-offset; C_Sign
  module-ambiguous on every leg (downgrade proof); stale-start
  counters zero. Suite: full `cargo +1.88 test --locked
  --offline` green 1469/0 (4 ignored, contracts 129/129),
  clippy -D warnings clean, fmt clean. 19 tests added, 0 removed;
  one stale test name updated (refusal→detection, same asserts).
  Late-joiner coalescing stays future work (rebuild covers
  retirement/replacement only).

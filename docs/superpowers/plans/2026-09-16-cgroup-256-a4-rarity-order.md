<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# cgroup-256 A4: file-level rarity-first deep-scan order (Task 5 blocker)

## Why this plan exists

Post-A3 scale-probe: 0 → 136 slots / 272 probes / 2 providers, but
`uniq_found` still False on the whole-root-cgroup run. Controller experiments
(Task 5 round 3):

1. Full coverage (`--max-scan-pids 1024`): uniq still missed. Selection cutoff
   exonerated.
2. Direct `--pid` scan of the uniq sleeper: `uniq_found=True`. Per-view path
   works.
3. Isolated cgroup with only the 151 probe procs: `uniq_found=True`. The true
   container-like 256-scenario passes.
4. Live sweep census (388 procs): 128 distinct provider-mapping sets, 107
   singleton groups — `take(256)` never cuts, so the uniq singleton group IS
   selected at the default cap.
5. Skip census: 276 views (full coverage) / 166 views (default cap) refused at
   maps acquisition with "capture attempted-I/O ceiling reached". Per-view
   MEMORY-scan reads (relocated bytes, not dedupable) are the remaining
   burner; the uniq view scans last and starves.

Root cause: over-cap order sorts singleton groups by lowest pid
(`select_deep_scan_candidates`, engine.rs:3385:
`ordered.sort_by_key(|members| (members.len(), members[0]))`). The freshly
spawned uniq pid is the highest, so its globally-unique provider scans last —
after the budget dies. Set-level rarity cannot see that `uniq-p11.so` is
mapped by exactly 1 pid globally while desktop singleton sets combine
widely-mapped files.

Fix: sort candidate groups by FILE-level rarity — each group's minimum
global pid-count over its mapped files — keeping today's `(len, lowest pid)`
as the tie-break and everything else (under-cap identity, unmapped trailing)
unchanged.

## Global Constraints

- Branch is `refactor/extraction-rename`, worktree
  `.worktrees/refactor-extraction-rename`; never commit on main; never push.
- TDD red-green-refactor; gates `cargo +1.88 test --locked --workspace
  --all-targets`, `cargo +1.88 fmt --all -- --check`, `cargo +1.88 clippy
  --locked --workspace --all-targets -- -D warnings`.
- No `sudo`, no timing/probe runs, no network: implementer runs unprivileged
  gates only. Scale proof stays controller-only (Task 5).
- Pure-function change only: `select_deep_scan_candidates` takes the sweep
  and returns pids; no budget, allocation, or scan-path changes.
- `docs/usage.md` needs no change (no user-visible flags or formats change).

## File structure

- `src/discovery/engine.rs` — `select_deep_scan_candidates` (~line 3385) and
  its unit tests (Task 4's selection tests; Step 1 grounds their location).
- No other production files. No fixture changes.

## Task 1: rarest-file-first group order

**Design (frozen):** after grouping pids by provider-mapping set (unchanged),
count, over the whole sweep, how many pids map each `ObjectKey`. Each group's
sort key becomes `(min_global_count, members.len(), members[0])` where
`min_global_count` is the minimum global pid-count over the group's key set.
Groups whose files are all widely mapped sink; a group containing a file
mapped by exactly 1 pid floats to the front. Unmapped pids still trail as
individuals (unchanged); under-cap input still returns pids ascending
(untouched code path).

**Controller-verified grounding (verify while implementing):**

- (a) CORRECTED (Step-1 tripwire, controller-verified): TWO production
  callers — `discover_plan` (~line 3474, initial capture) and
  `Engine::refresh_inventory` (~line 11718, live-discovery ticks). The
  refresh caller collects the result into `desired: BTreeSet` (order
  discarded) and uses it only to narrow which NEW pids get deep-scanned over
  the cap, where membership is explicitly non-authoritative; retirement via
  `desired.contains` requires `membership_authoritative`, which holds only
  under the cap, where selection is the untouched identity path
  (`inventory_retirement_cause`, engine.rs:5836). The reorder is therefore
  safe for refresh: deterministic per sweep (no new oscillation class) and
  biased toward newly-appeared rare providers, which is the live-discovery
  purpose. No design change; both callers proceed.
- (b) Group keys are `BTreeSet<ObjectKey>`; `ObjectKey` is `Ord` (it already
  keys a `BTreeMap`) — usable in a `BTreeMap<ObjectKey, usize>` census with
  no new traits.
- (c) `is_provider_mapping` (inode != 0, ".so" in raw path) is unchanged; the
  census counts exactly the keys the grouping already built.

- [ ] **Step 1: Ground yourself.** Read `select_deep_scan_candidates` and its
  existing unit tests completely; confirm the single caller and the tie-break
  lines. Report the test names and the exact current sort line in your
  report. No tripwire: the design is fully determined; if any grounding
  claim above is false, STOP with NEEDS_CONTEXT.
- [ ] **Step 2: Write the failing tests.** Pure unit tests beside Task 4's
  selection tests (same fixtures/helpers):
  `globally_rare_file_sorts_before_common_singletons` — sweep with 257+
  pids where a low-pid singleton maps only widely-shared files and a
  HIGH-pid singleton maps one globally-unique file; assert the high pid
  comes first in the returned order (today it comes last → RED);
  `tie_break_stays_len_then_lowest_pid` — two groups with equal
  min-global-count; assert today's `(len, lowest pid)` order is preserved;
  `under_cap_order_unchanged` — ≤cap sweep returns pids ascending
  (guards the untouched path). Expected RED: the first test fails with the
  rare pid last.
- [ ] **Step 3: Run them to verify they fail.** `cargo +1.88 test --locked
  -p p11scope --lib select_deep_scan` (plus the new test names). If the
  rarity test already passes, the test is wrong — investigate before
  proceeding.
- [ ] **Step 4: Minimal implementation.** Build the global per-key pid-count
  census from the sweep keys, change the sort key to `(min_global_count,
  len, lowest_pid)`, nothing else. No signature change, no new modules, no
  budget or scan changes.
- [ ] **Step 5: Focused tests.** The three new tests plus all existing
  `select_deep_scan` tests. Expected: PASS, pristine.
- [ ] **Step 6: Full suite, fmt, clippy.** Green, per Global Constraints.
  Plan-mandated — the review rejects `-p p11scope`-only evidence.
- [ ] **Step 7: Commit.** `git add` only touched files; `git commit -m
  "fix: scan globally-rare providers first over the pid cap"`.

## Self-review (controller, against the spec)

1. Spec coverage: the selected-but-starved uniq view (proven selected by
   census, proven starved by the 166/276 ceiling refusals) scans first, so
   the literal scale-probe flips even under a binding budget. No gaps.
2. Placeholder scan: no TBD/TODO; every step names exact files, line numbers,
   commands, and assertions. The sort key is frozen; tie-breaks fenced.
3. Type consistency: key components `(usize, usize, u32)` — all `Ord`; census
   map reuses `ObjectKey: Ord`. No new types.

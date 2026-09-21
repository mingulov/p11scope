<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Performance optimization opportunities — synthesis report

## Current system review — 2026-09-21, `885ed65`

This section supersedes conflicting priorities and claims in the historical
report below. Reviewed branch: **`feat/system-scale`**, full production SHA
`885ed651f1c549162a0537642b1c78ffc61a83e3`. The user authorized privileged live
tests. Three independent bounded source reviews informed the synthesis;
the primary ran the tests and checked material findings against the code.
No product optimization was implemented in this review.

**System coverage is the immediate problem.** Six PID cells captured all
20,006 expected calls; six true system cells captured zero calls from the
20,002-call post-GO workload. CALL-ring loss was zero in every cell.
All cells exited 0 and reported PARTIAL. Discovery-ring loss in the system
cells was 2,344–4,456. A successful process exit, an attached proxy, or zero
CALL-ring loss therefore cannot qualify system capture.

The detailed backlog is [SYSTEM-EXPERIMENTS.md](SYSTEM-EXPERIMENTS.md);
the architectural alternatives, file ownership and staged delivery gates
are in [SYSTEM-PLAN.md](SYSTEM-PLAN.md). New discovery findings and corrected
audit dispositions are recorded in [FINDINGS.md](../FINDINGS.md).

### Fresh host measurements

Built using `mise exec -- ./scripts/cargo.sh +1.88 build --locked --offline
--release -p p11scope -p p11scope-discover` (exit 0, 37.75 s).
Observer SHA256:
`26f262476beca8a25bd3c5494223c537eee72cc975f6b3e4ffcbfcac26420771`.
Kernel `7.0.0-31-generic`, 12 online CPUs, live desktop/VM/container host;
background load around 5–7 during the campaign. These are reproduction
measurements, not idle-host SLOs or intrinsic probe-cost measurements.

Command for each seed 1/2/3, with a fresh `rN` work directory:

```sh
mise exec -- ./scripts/system-scope-measure.sh --scope both --mode both --duration 8 --n-calls 20000 --seed 1 --no-build --work /var/tmp/p11scope-review-20260921-r1
```

| Scope/mode | Reps | Expected / observed calls per rep | Spawn-to-GO seconds | Process wall seconds | Observer CPU seconds | Sampled peak RSS MiB | Max FDs |
|---|---:|---|---|---|---|---|---|
| PID/metrics | 3 | 20,006 / 20,006 | 2.24–2.52 | 3.40–3.62 | 2.07–2.42 | 40.29–40.30 | 52–53 |
| PID/profile | 3 | 20,006 / 20,006 | 2.22–2.50 | 3.38–5.57 | 2.58–3.82 | 40.36–48.75 | 52–53 |
| system/metrics | 3 | 20,002 / 0 | 61.97–68.67 | 81.12–86.06 | 66.48–73.50 | 694.32–726.32 | 563 |
| system/profile | 3 | 20,002 / 0 | 63.80–67.00 | 84.02–85.74 | 69.38–72.81 | 664.45–725.52 | 609–610 |

PID opens/initializes after GO; system does that before GO, hence the four-call
denominator difference. PID ends when its owned fixture exits: the requested
8 s is not its measured steady-state duration. System uses scan-only
discovery; PID uses a manifest. Do not infer semantic-mode equivalence from
these count comparisons. GO timestamps establish workload ordering; direct
observer phase timestamps and exact capture-boundary proof remain E03 work.
One five-second `perf` sample was taken during
system/metrics repetition 3; that repetition is instrumented and should be
excluded from a timing-only baseline.

Every system cell allocated 478 slots (956 probe endpoints). Initial stderr
refused additional 68-slot SoftHSM and p11-kit-trust objects at the 512 ceiling.
An admitted SoftHSM pathname in another physical object/namespace does not
prove the workload's provider was admitted. Final reports also contain
refusals and discovery omissions. Actual whole-report returned totals were
zero, so the missing owned calls are established independently of the
harness's pathname-matching weakness. The exact contribution of scan-cap
selection versus physical-object admission needs E05/E06's controlled matrix.

### A measured startup hotspot changes O-13's priority

A 99 Hz CPU-clock/DWARF sample of the owned system/metrics observer produced
489 samples with no lost profiler samples. Self-time included `memcmp`
25.15%, `CaptureFacts::merge_current` 9.41%, `DecodedOccurrence::cmp` 7.98%,
malloc 7.57% and memmove 6.13%. Stacks connect these to `merge_current`,
`apply_candidate`, `finalize_candidate`, `arm_loader_or_partial`, planner
rebuilds and cloning pinned/history maps during session startup.

This supports **O-13/F-37 as a system-startup priority**, not merely a possible
steady-state tick issue. It does not prove those percentages describe the
whole run or that every allocation is avoidable. The current attach code
loads a finite program inventory once and reuses program FDs for single/multi
links (`attach.rs:2464,2595,3033,3092`); there is no demonstrated per-target
BPF program-cloning cause. The old claim that setup is simply link-creation
bound is incomplete on this workload.

Propose batched/incremental capture-fact and plan reconciliation with immutable
shared identity data, preserving transaction rollback, proof tombstones and
exact history. Measure transaction count, entries copied/compared and scaling
with process views. Avoid a broad engine rewrite without these invariants.

### Measurement defects discovered during the campaign

- **F-74:** `system-scope-measure.py:708–718` labels `spawn→GO > duration`
  as a collapsed window. Actual `capture_profile` starts its duration clock
  after `start_session` (`run.rs:1509–1513,3054`). Slow setup alone is not
  evidence of an expired capture. The system cells retained 17.38–20.22 s
  from GO to process exit, including teardown. Their coverage failure is real;
  this particular causal explanation is not established.
- `derive_phases:701` takes the first generic `p11scope: discovery:` line.
  Task 3.2 now emits per-class summaries with that prefix before the final
  discovery-count line. FD-plateau timing is also an estimator, not a direct
  attach/loop boundary. Use raw spawn/GO/exit timestamps and observer phase
  timers; do not promote estimated phase splits into precise SLO evidence.
- The harness's owned-module check uses path labels (`:559–655`); namespace
  aliases require a private physical-identity receipt. Its `delivered_derived`
  is derived from aggregate/loss counters, not an independent consumer tally.
- `scheduling.attribution.status=lossless` classifies the CALL event path;
  it appeared alongside thousands of lost discovery records and zero workload
  coverage. Scope that label explicitly in downstream dashboards.

### Rechecked opportunities

| Item | Current disposition and necessary change |
|---|---|
| O-1 | Confirmed. A new consumer is created per readiness quantum, potentially multiple times per tick. Preserve owned lifetime, domain, one cursor, root-tail behavior and **per-poll malformed deltas**; simply retaining today's cumulative drain counter would overcount. CPU savings remain unmeasured until patched. |
| O-2 | Confirmed metadata clones. Prefer immutable `Rc<SlotMeta>`/shared metadata over a bare slot reference. Retired slots are not reused today; future reuse requires epochs. Vector allocations depend on nonempty contents. |
| O-3 | Confirmed repeated operation-label allocation. Static strings may be sufficient before numeric codes; preserve namespace and output ordering. |
| O-4 | Confirmed repeated lookups. Two on common existing-key paths, three on insertion; root/history work is conditional. Preserve admission and generation checks. |
| O-5 | Confirmed allocations; throughput bottleneck unproven. Preserve exact trace bytes, pseudonym lifecycle, escaping and dropped-byte accounting. |
| O-6 | Confirmed deep snapshot clones. Promote map extraction to a separate scale experiment: roughly `N + 2R + 10` syscalls per stable-map frame before auxiliary work, not N+1. |
| O-7 | Diagnostic-only: `observe_templates` returns immediately under the safe default (`semantics.rs:2440`). Demote from default-profile work; extending before budget admission needs correct rollback. |
| O-8/O-9 | Source mechanism confirmed; savings are historical. Cache selected tests only, preserving fresh-loader and width/mutable-state isolation. |
| O-10 | Confirmed; close-all/auth/finalize multiply global scans. Evaluate range/group processing using existing ordered keys before adding an index. |
| O-11 | Confirmed at the combined 16,384 pending/detached limit. The two collections are not each independently 16K; any heap/index must stay bounded through overwrite/purge/join. |
| O-12 | Source mechanism confirmed; savings historical. Guard reordering is smaller than broad memoization; preserve exception and oracle behavior. |
| O-13 | **Promote:** measured merge/comparison/clone work during system startup. Also address the correctness/fairness issues F-70/F-71/F-73; caching a wrong selection policy is insufficient. |
| O-14 | Startup gap is reachable; the historical 10–18% loss cause is not isolated. Instrument release/revalidation/discovery/first-drain before choosing a fix; post-exec loader work can require the child to run. |
| O-15 | **Refuted as a production per-call hotspot.** The repeated `function_id` calls cited are in `corrective_tests`; production caches the id in SlotMeta (`semantics.rs:1629,2383`). Remove from the implementation batch. |

Additional opportunities:

- **O-16 — Remove residual quadratic fork work.** `fork_process` loops over
  sessions and then every parent operation (`semantics.rs:2665,2689`):
  O(sessions × operations). The existing 2,000-session/6,000-op `<2s` test can
  pass 12 million comparisons; add work-count scaling assertions (E20).
- **O-17 — Lifetime resource policy.** Semantic admission is monotonic
  (`semantics.rs:1795–1810`); history retains closed records (`history.rs:170`);
  plan slots append after retirement (`plan.rs:723,784,900`). Small active
  workloads can exhaust long captures. Reclamation needs epoch/replay proofs,
  not unconditional refunds or deletion (E10/E20).
- **O-18 — Bounded mechanism dedup.** `apply_operations:2031–2043` builds a
  BTreeSet for at most 11 operation categories. Compare a stack representation
  while preserving exactly-once distinct-mechanism accounting (E19).

### Corrections to rejected items and priorities

The measured per-call wall delta is **not an established irreducible trap
floor**: it includes BPF work, scheduling and observer contention. Kernel-side
map operations and event representation can be optimized if profiling and
correctness tests justify it. Keep mode choice, but do not dismiss those
experiments as inherently unactionable.

The EVENTS ring has **4 MiB data capacity**. Its 8 MiB virtual data mapping
aliases the same pages twice; `Event=328` plus the 8-byte record header yields
336 bytes/record and about 12,483 records. This follows the selected Aya p2
mapping implementation and the [kernel ring-buffer design](https://docs.kernel.org/bpf/ringbuf.html).
Sparse STATS alone does not remove START/RV/owner/history/ring/link limits.
“Aggregates always exact” is conditional on admission, entry/return pairing,
map failures, scope and terminal boundaries; zero ring loss is insufficient.

Recommended order: close F-01/F-11 safety/interference gaps and correct
measurement/trust defects; preserve coverage on incomplete scans and fix
exploration fairness; measure O-13 startup work and implement O-1 as an
isolated consumer change; then reducer/map improvements.
Broader publication and capacity changes follow their explicit experiments.
Coverage-breaking scale limits belong with correctness work. Lower-impact
cleanup does not need to block a measured performance fix once its safety
and coverage gates pass. Optimizing only the event consumer cannot fix the
observed system miss.

### Evidence custody and limitations

Raw artifacts (not tracked): `/var/tmp/p11scope-review-20260921-r{1,2,3}/`
(each contains a matrix and four condition records/reports), and
`/var/tmp/p11scope-ws-tmp/review-20260921-system/` (build/test logs, binary
hashes, doctor, catalog comparison, profiler data, summary and BPF snapshots).
After all 12 cells, BPF program/map sets matched the initial sets exactly:
70 programs and 7 maps, no new IDs; no p11scope process remained.

The unprivileged system-scope/map/owner suites passed 10 tests. The library
suite passed 1,201 tests, with zero failures and four ignored (162.25 s).
Formatting, workspace/all-targets check and clippy with denied warnings
passed. The full workspace/all-targets test command was not run.
No new VM campaign, exhaustive parser/security scan,
all-function runtime qualification or optimization A/B result is claimed.
Prepared p11scope VM bases were inventoried; running unrelated VM lanes were
left intact. Remaining F/R findings retain their stated review limitations.

## Historical synthesis at `c4c59c9` (retained provenance)

**PROVISIONAL — pre-Task-3.2-merge tree.** Branch `feat/system-scale` @
`c4c59c9` (verified `git rev-parse` this session). All line numbers,
absolute latencies, and CPU figures below are tied to that revision on a
loaded host (loadavg 8–18) and must be re-ratified post-merge on an idle
box before any SLO is treated as a gate. No production code was changed
(read-only synthesis); no subagents used.

Worker inputs: `measure.md` (perf-0, runtime measurement), `static.md`
(perf-1, static hotspot audit), `python.md` (perf-2, Python/CI audit),
`quality.md` (perf-3, SLOs + coverage plan), plus `FINDINGS.md` items
F-29 (suite feedback time), F-40 (no coverage), F-05 (parser surface,
constraint only).

## Methods

- perf-0: release build offline (`cargo.sh +1.88 build --locked --offline
  --release --workspace`, 1m21s); in-repo harness
  `system-scope-measure.sh --scope pid --mode both` (N=20000) plus manual
  gated drivers (`EARLY=0` workload, GO released on first live frame);
  `perf stat` (task-clock), `perf record -e cpu-clock`, `perf trace`
  with args; bpftool footprint/occupancy diffs. `--system` deliberately
  not run (shared host, another agent mapping SoftHSM2).
- perf-1: semgrep unavailable (not installed, no network) — skill
  anti-pattern queries emulated via regex search + manual read of every
  cited body. This synthesis re-opened the H1/H2/H4/M1 bodies and the
  `event_drain` chain to confirm the citations.
- perf-2: `cProfile` + `time.perf_counter`, CPython 3.14.7,
  unprivileged, `/tmp` probes (out of repo); noisy host, ranges reported.
- perf-3: SLOs anchored to plan provisional targets with exact SLI
  sources; coverage-absence claim re-verified by grep over `ci.yml` +
  `gates.sh`; cheapest offline coverage path verified working on a /tmp
  probe (stable 1.88 `-C instrument-coverage` + system llvm tools).

## Per-worker counts

| Worker | Findings carried in | Reused here |
|---|---|---|
| perf-0 measure | 1 headline + overhead/setup/teardown/maps/run-flow | O-1, O-14, floor notes |
| perf-1 static | H1–H8, M1–M6, 7 cleared | O-2–O-7, O-10, O-11, O-13, cleared → rejected |
| perf-2 python | 3 hotspots + 5 non-hotspots + 3 no-role | O-8, O-9, O-12, rest → rejected |
| perf-3 quality | 10 SLOs + 5 coverage risks + verified tool path | E-1, E-2 (enablers) |
| FINDINGS.md | F-29, F-37, F-38, F-40, F-05 | O-13..O-15 context, constraint |

## Ranked opportunities (15)

### O-1 — Retain one RingBuf consumer per session (drop per-tick re-mmap). Batch A
- Evidence: `measure.md` §6. `perf stat`: profile burst 89.2%/90.5% of 1
  core vs metrics 5.1% on the same burst; profile IDLE 44.8%. `perf
  record` (1267 samples): 96.3% kernel, top `zap_present_ptes` /
  `insert_page*`. `perf trace` 5 s: 2611 mmap + 2608 munmap ≈ 60% wall;
  full trace: exactly one 8 MB EVENTS-ring re-mmap per tick (299/300
  polls). Chain verified this session: `src/run.rs:3068` (profile) /
  `:4377` (trace) → `Session::event_drain` (`src/attach.rs:3399`) →
  `Drain::new` (`src/events.rs:373-382`, `RingBuf::try_from` + `info()`)
  constructed and dropped every tick.
- Expected impact: profile observer CPU ~0.9 core → single digits (metrics
  parity modulo real drain work); ~1.7 ms/tick syscall time removed;
  tick cadence and burst throughput up; idle burn eliminated.
- Risk/cost: medium-low. Lifetime rework (consumer must live across
  ticks while `Ebpf` stays borrowed); must preserve the
  domain-id check (`events.rs:379-382`) and single-consumer discipline
  (`attach.rs` readiness-fd comment). Small diff, needs tick/cancel
  regression runs.
- Suggested batch: **A** — first, alone; re-measure with §6's exact
  `perf stat`/`perf trace` protocol before touching H1–H4 so the
  userspace wins below are measurable.

### O-2 — Stop per-event `SlotMeta` heap clone (H1). Batch A
- Evidence: `static.md` H1, body re-verified: `src/semantics.rs:1889`
  `self.slots.get(...).and_then(Clone::clone)`; `SlotMeta` (`:1374-1382`)
  holds `Vec<String>` + `Vec<ModuleId>` → ≥2 Vec + N String allocs per
  CALL (up to ~127k rec/s per `run.rs:2762` comment); 2nd clone in
  `observe_async` (`:2282`), retained per pending op (`:2395-2400`).
- Expected impact: removes the largest per-event alloc in profile mode;
  pairs with O-1 (currently hidden under mmap noise).
- Risk/cost: low-medium. Borrow `&SlotMeta` through the observe chain or
  `Rc`/`Arc` it; store `slot: u32` in `Pending`, re-resolve on completion.
- Suggested batch: **A** (semantics hot-path group with O-3, O-4).

### O-3 — Key mechanism ops by bit/code, not `String` (H2). Batch A
- Evidence: `static.md` H2, re-verified: `src/semantics.rs:1973-1977`
  `name.to_string()` per set op-bit + direct name into
  `BTreeSet<String>`, from `&'static str` tables (`:1514-1533`).
- Expected impact: removes heap alloc + O(log n) String compares per
  Initialize/direct CALL.
- Risk/cost: low. Key by `u16` bit / `u8` direct code, stringify at render.
- Suggested batch: **A**.

### O-4 — Collapse 2–3× map traversals per event (H3). Batch A
- Evidence: `static.md` H3: `contains_key`→`insert`→`get_mut` triples
  (`semantics.rs:1890-1893`, `:1944-1949`, `:1966-1969`,
  `:2520-2533`); 3 history-registry lookups per CALL
  (`history.rs:72,103,110`).
- Expected impact: ~3× fewer B-tree walks on the per-event path.
- Risk/cost: low. `entry` API / `get_mut` fast path; fuse the three
  history mutations into one lookup.
- Suggested batch: **A**.

### O-5 — Single-buffer the trace emit path (H4). Batch B
- Evidence: `static.md` H4, re-verified: `TraceSlot` clone
  (`trace.rs:352-356`), ~5 `format!` temporaries in `format_line`
  (`trace.rs:143-160`), plus a second full copy in `emit_trace_line`
  (`run.rs:4002` `format!("{line}\n")`). ~8 String allocs per traced CALL.
- Expected impact: removes the trace-mode bottleneck at high call rates.
- Risk/cost: low. Reused `String` buffer (`write!`, push `'\n'`, write
  once) or format into the sink buffer.
- Suggested batch: **B**.

### O-6 — Share frame snapshots via `Rc`/`Arc`, not deep clone (M1). Batch B
- Evidence: `static.md` M1, re-verified: `run.rs:3156,3168`
  `reports.clone()` (deep: `Vec<String>` names + `BTreeMap`s per slot)
  served per tick from `snapshot_cache`; `metrics.rs:73-115` full
  `RV_COUNTS` iteration + one `STATS` syscall per slot per frame.
- Expected impact: removes per-tick deep copy (68+ slots × maps); the N+1
  map reads stay (frame cadence makes them cheap).
- Risk/cost: low. Consider also folding `kernel_evidence`'s 9 `EVIDENCE`
  gets (`metrics.rs:138-153`) into fewer reads.
- Suggested batch: **B**.

### O-7 — Single lookup in `record_template` (H6). Batch B
- Evidence: `static.md` H6: `semantics.rs:2504-2510` allocates
  `missing: BTreeSet<u64>` and does up to 8 `self.templates[&key]`
  re-lookups + final `get_mut` per template-bearing event.
- Expected impact: removes per-event BTreeSet alloc + redundant lookups.
- Risk/cost: low. One `get_mut`, extend in place, charge `admit()` from delta.
- Suggested batch: **B**.

### O-8 — Cache receipt subject module across tests (PY1). Batch B
- Evidence: `python.md` §1: `scripts/_loader.py:26` always recompiles
  (bytecode writes disabled); 73–136 ms × 115 tests ≈ **8–16 s** per
  receipt-file run, compile-bound (`builtins.compile` top frame).
  Isolation caveat mapped: only `test_receipt_borrowed_descriptor_admission.py:197`
  and `test_prepare_dependencies.py:365-381` mutate module state.
- Expected impact: ~8–15 s per full receipt-file run; chips at F-29
  feedback time (F-29's 703–783 s is the hosted suite — related, not equal).
- Risk/cost: low. `setUpClass`/module cache keyed by path; fresh loads
  only in the two mutating files. Test-only — landable pre-merge.
- Suggested batch: **B** (parallel-safe with everything).

### O-9 — Cache canary subject/dumper + BPF map defs (PY2). Batch B
- Evidence: `python.md` §2: `test_canary_evidence.py` calls
  `load_subject` 30× (~35–55 ms, incl. `runpy` re-exec of 1302-line
  `check-bpf-map-defs.py` at ~15–18 ms via `initialize`, `:113-127`) +
  `load_dumper` 30× (~21 ms) ≈ **1.7–2.3 s**/run.
- Expected impact: ~2 s per file run.
- Risk/cost: low. Module-level cache keyed by `bits`; load map defs once.
  Test-only — landable pre-merge.
- Suggested batch: **B**.

### O-10 — Session→op secondary index (H5 + M3). Batch C (measure first)
- Evidence: `static.md` H5/M3: `retire_session`/`clear_session_state`
  (`semantics.rs:2540-2563`) full-retains `active_ops` + `pending` +
  `detached` per `C_CloseSession`; same shape in `CLOSE_ALL_SESSIONS`
  (`:2157`), login/logout (`:2197`, `:2248`); `fork_process` (`:2649-2664`)
  scans `open` + `active_ops` per fork.
- Expected impact: only if real HSM workloads open/close (or fork) fast;
  open/close-per-op workloads pay O(live state) per pair today.
- Risk/cost: medium. Index design + invalidation; needs runtime
  session-churn counts first (unresolved in static audit).
- Suggested batch: **C** — instrument counts post-merge, then decide.

### O-11 — O(log n) pending-eviction index (H7). Batch C (measure first)
- Evidence: `static.md` H7: at `pending + detached > 16384`, every
  `queue_pending` runs two full `min_by_key` scans
  (`semantics.rs:2407-2438`, up to 16k entries each).
- Expected impact: removes saturation cliff; zero gain below saturation.
- Risk/cost: medium-low (`BTreeMap<seq, key>` / `BinaryHeap` of
  (reverse-seq, key)). Needs saturation observation first.
- Suggested batch: **C**.

### O-12 — Guard-clause reorder / memoize in contract driver (PY3). Batch C
- Evidence: `python.md` §3: `run_input_v1_contract` 4.8 s wall; two
  `*_allowed` predicates (`:1242`, `:1277`) rebuild `expected_bindings`
  per emulated call (1.47M iterations each, ~2.5 s combined, ~17%).
- Expected impact: ~0.5–1 s of 4.8 s. Test-only.
- Risk/cost: low-medium (predicate semantics must not change; cheap
  discriminators first or memoize per state revision).
- Suggested batch: **C** (smallest CI win; do after O-8/O-9).

### O-13 — Discovery tick clones + `/proc` re-walk (M2, F-37-adjacent). Batch C
- Evidence: `static.md` M2: full frames re-walk `/proc`
  (`engine.rs:3242`) or cgroup trees, rebuild sets (`:12971-12995`),
  clone intent maps (`:12449`, `:13702`); mitigated by shallow-idle skip
  (`:13443`) + 1-in-5 forced full frames. FINDINGS F-37
  (`FINDINGS.md:398-404`): `begin_stage` + `merge_current` clone
  full/visible history per discovery transaction — "needs measurement on
  system scope before refactor."
- Expected impact: dominant tick cost at system scope with many pids;
  unmeasured at that scope (no `--system` capture exists).
- Risk/cost: medium. Iterate by reference; cache `/proc` listing across
  the 5-frame window with generation validation.
- Suggested batch: **C** — after Phase 2 system-scope measurement exists.

### O-14 — Fix `run`-flow early ring loss 10–18% (ramp-up race). Batch C
- Evidence: `measure.md` §9: owned-child `run`, 50k ×3, wall
  3.23/3.14/3.70 s, ring loss 5280/5970/9060 (10–18%) vs attach-flow
  loss 0 on unpaced 200k — burst starts while the drain loop ramps.
  Aggregates exact (ring-independent kernel counts), detail lossy.
  Mechanism inferred from timing correlation, not per-event traced.
- Expected impact: restores full event detail in `run` flow.
- Risk/cost: medium. Options: pre-warm drain before exec, delay child
  start until first frame, larger default ring (4 MiB → hold ~12483
  records per `quality.md`). Needs a design decision + loss-identity
  tests (S-LOSS-1/2).
- Suggested batch: **C**.

### O-15 — Hoist linear `function_id` lookups to const (F-38). Batch A filler
- Evidence: FINDINGS F-38 (`FINDINGS.md:406-412`): ~15 linear
  `.position()` lookups per correlated call sequence + descriptor
  lookups; "small absolute cost, paid on every call."
- Expected impact: small per-call saving; trivial cost makes it worth
  folding into Batch A.
- Risk/cost: very low (`const`/`LazyLock` hoist).
- Suggested batch: **A** (filler in the semantics group).

## Enabling actions (not optimizations — do these to unlock/protect the above)

- E-1 — Collect the coverage baseline, then pin per-file region floors on
  `sink.rs` + `metrics.rs` (quality.md Part 2; F-40). No gate exists
  (empty grep over 213-line `ci.yml` + `gates.sh`); cheapest path
  verified working (1.88 `-C instrument-coverage` + system llvm tools,
  /tmp probe exit 0). Measure first: region coverage on `run.rs`,
  `sink.rs`, `metrics.rs`, `render.rs`, `plan.rs`; exclude `#[cfg(test)]`
  (F-39). Blocked until the tree is free (no full suite while the
  implementer owns it).
- E-2 — Re-ratify the 10 SLOs + per-call overhead on an idle post-merge
  box (quality.md Part 1). System setup/teardown targets (S-SETUP-2,
  S-DOWN-1) stay target-less until Phase 2 multi measurement
  (singles ~54 s attach / ~60 s detach are a documented gap, owned by
  Task 2.2, not a target). Includes the idle-box campaign that resolves
  O-10/O-11/O-13 triggers and the 1-rep metrics CPU thinness.

## Rejected / non-opportunities (with evidence — do not action)

- Per-call uprobe trap cost (+12.2 µs profile / +8.5 µs metrics medians,
  N=200k, `measure.md` §3): structural floor of the uprobe design on
  ~1–3 µs SoftHSM2 calls, not a code defect. The lever is mode choice
  (metrics vs profile), already available.
- Attach ramp (pid 3–8 s; system ~54 s, 956 probes): link-creation bound,
  owned by Task 2.2 / Phase 2 — out of scope for this batch.
- Harness `predicted_burst_loss` pessimism (7523 predicted vs 0 actual):
  model-vs-reality gap, not a bug (`measure.md` §8).
- H8 detached fallback scan (`semantics.rs:2292-2299`): rare path —
  accept; revisit only if async-miss counts say otherwise.
- M4 `purge_modules` (`semantics.rs:1756-1793`): cold unless discovery
  flaps; trigger is observed plan-change storms (none seen).
- M5 `render::live` per-frame allocs, M6 `abort_wait` drain: negligible /
  cancel-path-only (`static.md`).
- Cleared by inspection (`static.md`): no hot-path locks (only
  feature-gated/test `Mutex`es); `admit`'s `Vec::new()` never allocs;
  `check_unchanged` is one fstat per pin; plan-change-only rebuilds;
  O(1) `module_of_slot`; const-bounded eBPF loops; alloc-free `Event`
  decode.
- eBPF per-call map ops (START/ringbuf/stats): inherent; kernel-side
  profile needed to rank vs userspace — not actionable from here.
- Python non-hotspots (measured, `python.md` §§4–7): capture-evidence
  self-test deepcopy (1.9 s but self-test-only; gate path 0.59 ms);
  `parse_ledger` linear 22 µs/row, 7-row real ledgers; measure/launcher/
  sampler/hashing all sub-ms with 500×+ headroom; 37 lane oracles,
  task-1.6 lanes, ledger utils run-once or wall-dominated.
- BPF-side coverage: userspace llvm-cov cannot cover kernel code; rely on
  existing small-ring induced-loss lanes (`quality.md` §5).

## Constraints from adjacent findings

- F-05 (privileged parser surface, no fuzz/PBT): perf refactors touching
  manifest/ELF//proc/hook-spec parsing must not widen the unmeasured
  parser surface — keep O-13's scan-path changes shape-preserving.
- F-29 (703–783 s hosted suite, ~1 flake/run): O-8/O-9/O-12 reduce CI
  time but do not address hosted-suite flakes; throughput stays the
  binding merge constraint.
- F-39 (`#[cfg(test)]` in prod): coverage gates must use
  shipped-lines-only numerators or they overclaim (see E-1).

## Batch summary

| Batch | Items | Entry condition |
|---|---|---|
| A (hot path, first) | O-1, then O-2/O-3/O-4/O-15 | post-merge tree, idle box; O-1 alone first with §6 re-measure |
| B (cheap + parallel-safe) | O-5, O-6, O-7, O-8, O-9 | O-8/O-9 landable pre-merge (test-only); rest after A |
| C (measure-first) | O-10, O-11, O-12, O-13, O-14 | runtime counts / Phase 2 system data (E-2) decide each |

## Unresolved (carried, not dropped)

- `--system` capture unmeasured (safety on shared host); use
  `scripts/system-scope-measure.sh --scope system` on an isolated host.
- All numbers loaded-host provisional; no HW PMU, no call graphs,
  no flamegraph tooling (retained `pr_1.perfdata` for offline use).
- Metrics steady-state CPU is 1 rep; run-flow loss mechanism inferred.
- Full `tests/python` suite wall unmeasured (tree owned); sub-100 ms
  Python timings carry ~2× noise.
- Coverage baseline not collected (same tree constraint).

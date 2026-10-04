<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Known limitations (v0.2.1)

User-facing limits of p11scope v0.2.1, a point release on v0.2.0 (cut
2026-10-04 from merged and green `s2s3-semantics`). v0.2.1 changes only the
proof-stat pool threshold and the `-o` JSON write. The M1 and R4 rows below
were re-measured on v0.2.1 in a quiet window on 2026-10-05; every other
measured number is still the v0.2.0 value. The following move to v0.3.0: C6 (semantics, churn and
capacity, 30-minute endurance), C5b (cgroup/pod scope, namespace-aware BPF
filter), C7 (V1 call counts, 2 MiB inventory ring, kernel-side identity,
allowlist-v3, BPF nightly bump), the full measurement set M2–M7, the full §7
deferred closure, and the §8 Fable audit.

A short measurement tier (M0, M1 at 4,096 processes, M4 churn, and the C5.6
pool) ran on v0.2.0 release day; its numbers are in the M0, M1, M4 and R4
rows below, with M1 and R4 since re-measured on v0.2.1 as noted in those
rows. Method for every row: Linux 7.0 x86-64, observer pinned to CPUs
10,11 (R4: 8–11, plus a v0.2.1 cell on 10,11), 3 cold + 6 warm samples
per cell (M4: 3 + 3; v0.2.1 R4 at 2 CPUs: 5 + 5), each a 30 s run
(M4: 60 s), in a quiet window (load gate 4.0), on glibc release builds
(the shipped observer is musl static-pie): the v0.2.0 candidate b16c858
for the v0.2.0 rows, the v0.2.1 candidate aa62b87 for the re-measured M1
and R4 rows, the v0.2.0 build 6abd2b7 as the R4 base. Ranges below are
the min..max of per-sample p95.

## Kernels and backends

### Optimal path on 6.8 and later (uprobe-multi, probe-proven pid filter)

- What the user sees: on capable kernels the native inventory lane attaches
  each extend's new entries as one immutable uprobe-multi link per provider
  object (8 to 96 entries per link, sized so one attach call stays near
  200 ms). Stopping a system-scale capture closes hundreds of entries in
  well under a second, and `observation.retirement` reads `closed`.
- Kernels/conditions: where a functional probe (run once per capture, never
  a version check) shows the kernel links uprobe-multi and, under `--pid`,
  proves the kernel pid filter covers every thread of the target. Observed
  on Ubuntu 6.8, 6.12 and 7.x; 5.15 refuses Multi with `EINVAL`.
- Disclosure: `observation.attach` (`selection`, `mechanism: "uprobe-multi"`,
  `fallback: null`, `scope_filter: "kernel-pid+bpf"` under `--pid`), the
  start/stop lines naming the mechanism, and classic
  `evidence.attach_mechanisms`.
- Workaround: none needed; this is the default `auto` path.
- Planned: stays the optimal path. Older kernels keep correct fallbacks.

### 5.15: per-offset links, slower detach, retirement unsettled at scale

- What the user sees: every provider entry gets its own per-offset link.
  Detach costs about 18 ms per link, so a 546-link teardown runs about
  9.7 s in a 5.15 guest, and a thousand-endpoint system capture misses the
  10 s stop budget: the report is written first and reads
  `retirement: "unsettled"`.
- Kernels/conditions: 5.15, and any kernel where the Multi probe fails
  (disclosed fallback). The 18 ms/link figure is the 5.15 guest
  measurement (`detach-investigation.md`); host 7.0 Singles cost about
  73 ms/link, which is why Multi is the default there.
- Disclosure: `observation.attach` (`mechanism: "per-offset"`, `fallback`
  naming the probe failure), `observation.retirement: "unsettled"` plus
  the `native capture retirement unsettled` gap, and the stderr detach
  progress lines.
- Workaround: fewer endpoints (`--module`, narrower scope), or a 6.8+
  kernel for system scale.
- Planned: v0.3.0 only if 5.15 system-scale stop time matters
  (5.15-only reaper, DR-C511-REAPER, gated on the Multi probe failing).
  Otherwise stays a documented correct-but-slow fallback per the
  kernel-tier directive.

### 5.15: physical-identity controls and non-leader exec unqualified

- What the user sees: on 5.15 only, four privileged regression cells fail
  that pass on 6.8+. `privileged_task4_detailed_physical_identity_controls`
  and `privileged_task4_inventory_physical_identity_controls` pin two
  byte-identical provider files at distinct inodes, spawn an owned caller
  per file, and prove each caller executes its own physical object; the
  proof fails (`owned caller executes a different physical object`).
  `privileged_detailed_failed_nonleader_exec_preserves_start_and_image`
  and
  `privileged_detailed_nonleader_exec_cleans_old_tid_before_same_session_rebind`
  exec a worker thread (non-leader exec, failing and succeeding) and
  require the provider's executable mapping at the pinned file offset to
  still be present afterwards; it is absent (`actual provider executable
  mapping contains the probed file offset`). Per-copy module attribution
  and exec-handoff accounting are therefore unqualified on 5.15: treat
  same-bytes/distinct-inode provider copies as undistinguished there, and
  calls held across a non-leader exec as unaccounted.
- Kernels/conditions: 5.15 only. Ubuntu 6.8, 6.12 and 7.2 pass all 61
  privileged library cells (57/61 on 5.15).
- Disclosure: the four failing cells; no product gap marks this at
  runtime — this entry is the disclosure.
- Workaround: qualify 5.15 captures without per-copy or exec-handoff
  claims, or capture on 6.8+.
- Planned: v0.3.0 (diagnose the 5.15-only failures; qualify or bound).

### 6.6 to 6.9.11 thread-exact pid filter

- What the user sees: under `inventory --pid`, `auto` keeps per-offset
  links bound to the target where the kernel Multi pid filter is not
  proven (Linux 6.6 to 6.9.11 shipped a thread-exact filter; the probe
  also requires that a forked child process does not fire).
- Kernels/conditions: `--pid` on kernels without a proven pid filter.
- Disclosure: `observation.attach.scope_filter: "perf-task+bpf"`, and the
  in-BPF PID guard stays as a second check either way.
- Workaround: none; the fallback is automatic and honest.
- Planned: stays as the capability-gated fallback.

### Classic `--pid` backend tiers (probe-decided; DR-CLASSIC-PID0 fixed)

- What the user sees: classic `profile`/`trace --attach-backend auto` no
  longer reads the 6.9 version floor (DR-CLASSIC-PID0, fixed in v0.2.0).
  On 5.15 it uses per-offset links with the reason disclosed; on 6.8+
  with a proven kernel pid filter it uses uprobe-multi with pid = target
  (never pid 0); elsewhere under `--pid` it uses per-offset links bound
  to the target.
- Kernels/conditions: classic `--pid` on any kernel; multi needs the
  filter proven (every thread of the target, no other process).
- Disclosure: `evidence.attach_backend` (selection, fallback reason,
  `--pid` scope filter) in profile reports and the trace terminal
  record, plus a stderr line before the readiness line on fallback.
- Workaround: none; the selection is automatic and honest.
- Planned: classic system/cgroup Multi on 6.6–6.8 is probe-gated but not
  yet qualified on those kernels (DR-CLASSIC-F4-66-68, v0.3.0).

## System scale and performance

### Pass time at 4,096 processes (M1) — 1.61–1.70 s p95, over the 1 s target

- What the user sees: a 4,096-process / 1,000-caller `--system` pass takes
  about 1.61 s native and 1.70 s scan on v0.2.1 (pass p95, warm-cell
  medians: native 1,613 ms, range 1,567–2,418 ms, including one slow
  sample at 2,418 ms; scan 1,702 ms, range 1,574–1,916 ms). Native adds
  no measurable cost over scan. At 448 processes / 300 callers the pass
  p95 is about 0.30 s in both lanes (native 297 ms, range 291–409 ms,
  including two slow samples at 373 and 409 ms in one unit; scan
  296 ms, range 290–297 ms). At 4,096 the longest stage is confirm
  (identity proofs) at ~1.06–1.10 s, then sweep at ~0.52 s. RSS peaks at
  ~69 MiB (native) / ~59 MiB (scan) at 4,096 and ~40 MiB / ~15 MiB at
  448; FDs peak at 1,051 / 1,012 and 350 / 312. Newcomer admission age
  was not measured in this tier. The < 1 s target at 4,096 is not met:
  the pass is still about 0.6–0.7 s over it.
- History (v0.2.0): the 4,096 pass p95 was about 2.20 s in both lanes
  (native 2,202 ms, range 2,184–2,248 ms; scan 2,204 ms, range
  2,198–2,708 ms, including one slow sample at 2,708 ms); 448 was about
  0.34 s (native 337 ms, range 335–558 ms; scan 335 ms, range
  332–340 ms). Absolute pass times shift with host state between
  campaigns (the same v0.2.0 binary measured 1.80 s at 2 CPUs in the
  v0.2.1 window against 2.20 s in its own), so the cross-campaign drop
  overstates the code effect; the interleaved R4 A/B below is the clean
  measure of it.
- Kernels/conditions: `--system --capture scan` and `native` at 448 / 4,096
  processes, churn 0, 3 cold + 6 warm 30 s samples per cell.
- Disclosure: `P11SCOPE_STAGE_TIMINGS=1` per-pass stage timings, the
  `observation` block, and this row.
- Workaround: narrow scope (`--pid`, `--module`).
- Planned: the 1 s route is v0.3.0 kernel-side identity (C7). M1 at 10,000
  and the ≤15%-over-scan gate move to v0.3.0 with it.

### Proof-stat pool benefit (C5.6 R4) — v0.2.1 serial below 128 ranges: −230 ms at 2 CPUs, −625 ms at 4 CPUs

- What the user sees: since v0.2.1 the bounded per-collection `map_files`
  proof pool (at most 3 scoped workers) engages only for a batch of 128 or
  more ranges (`MIN_PARALLEL_BATCH`, was 8). Typical per-process batches
  are 30–45 ranges, so by default a pass behaves like the serial path.
  Results are identical by construction; only wall time differs. Why: on
  the author's host (2 physical cores with SMT, Linux 7.0, btrfs) the
  channel round-trip per process (~85 us) cost more than the ~114 us of
  `fstatat` it parallelized. A clean same-history A/B (v0.2.1 aa62b87
  against v0.2.0 6abd2b7, interleaved, scan lane, 4,096 processes)
  measured, as pass p95 warm-cell medians: at 2 CPUs (10,11) 1,797 ms
  pooled vs 1,568 ms serial (ranges 1,761–1,818 ms and 1,536–1,925 ms,
  the serial range including one slow sample at 1,925 ms), a gain of
  about 230 ms per pass, nearly all of it in confirm (1,249 ms vs
  1,041 ms); at 4 CPUs (8–11) 2,220 ms pooled vs 1,595 ms serial (ranges
  2,178–2,240 ms and 1,559–1,839 ms, including one slow serial sample at
  1,839 ms), a gain of about 625 ms per pass, nearly all of it in
  confirm (1,672 ms vs 1,058 ms). Sweep is unchanged within noise.
  The 2-CPU gain is
  smaller than the indicative experiment's ~350 ms on a hotter host; the
  4-CPU gain matches its "more at 4 CPUs".
- History (v0.2.0): scan pass p95 at 4,096 processes was ~2.30 s with the
  v0.2.0 candidate (warm median 2,309 ms, range 2,282–2,329 ms) against
  ~2.02 s with the pre-pool build 570eb7d (warm median 2,035 ms, range
  2,031–2,087 ms). That was not a clean A/B (570eb7d predates other
  slices); the same-history campaign A/B above is the clean answer: the
  pool did not help on this shape.
- Kernels/conditions: `--system` with maps-matched callers past the
  deep-scan cap, scan lane on CPUs 8–11 (2 physical cores with SMT) and
  on CPUs 10,11 for the v0.2.1 2-CPU cell, on kernels where `map_files`
  proofs run. The pool can still engage for a process mapping 128 or more
  examined ranges; its benefit there is not measured.
- Disclosure: stage timings (`confirm`), this row.
- Workaround: none needed; small batches are serial.
- Planned: Cross-pass caching stays out (R-C56-1: inode reuse makes it
  unsound); kernel-side identity is v0.3.0 (C7).

### Harness validity (M0) — PASS

- What the user sees: PASS: all 5 legs classified as expected (29 of 29
  tier-1 units valid): a correct ledgered SoftHSM2 `--pid` capture, an
  induced-loss cell (3,000 exec/s) read as lossy, a killed-sampler cell
  read as missing, a dead-pid refusal read as refused, and a correct
  no-observer control. The v0.2.1 M1/R4 campaign re-ran the same gate:
  PASS, 43 of 43 units valid on the first attempt.
- Kernels/conditions: candidate binary, quiet host, one 30 s sample per
  leg (64-process cells; loss and control in the host namespace).
- Disclosure: campaign receipt; invalid runs are kept with reasons.
- Workaround: none.
- Planned: landed in the v0.2.0 short tier.

### 10,000-process cadence

- What the user sees: the sweep alone costs about 0.9 s, so a 10,000-process
  pass may stay over cadence even with the C5.6 pool. No v0.2.0 number is
  claimed.
- Kernels/conditions: `--system` at 10,000 processes.
- Disclosure: stage timings, pass duration, newcomer queue age.
- Workaround: `--max-scan-pids`, `--module`, narrower scopes.
- Planned: v0.3.0 (C7 kernel-side identity; M1 at 10,000).

### Lifetime identity/ticket budget 16,384 (DR-06)

- What the user sees: long `--cgroup`/`--system` captures of busy hosts can
  spend the 16,384-identity budget (about an hour at 5 new processes/s);
  later processes are counted only as identity refusals, and later callers
  become identity refusals.
- Kernels/conditions: all kernels; Detailed `task_newtask` fork-wrapper
  ticket burn in `--system` Detailed subsets is unmeasured.
- Disclosure: `evidence.kernel_control` (`identity_budget_exhausted`,
  `identity_unavailable`, `owner_admission_failures`), gaps, `PARTIAL`.
- Workaround: `--pid` or a narrow `--cgroup`, or split the capture.
- Planned: v0.3.0 (C6 30-minute churn cell from M5 projections; lazy
  allocation, retirement/recycling, or a declared envelope).

### Provisional P/N defaults (DR-07)

- What the user sees: `P = 65,536` caller pairs and `N = 4,096` endpoints.
  Both are the production defaults (P: `DEFAULT_CALLER_PAIRS`; N: the
  inventory endpoint budget); neither is tuned yet, so wrong values give
  refusals at scale or wasted memory.
- Kernels/conditions: large endpoint/owner populations (>256 owners,
  >6,530 endpoints).
- Disclosure: the coverage reasons `the CALLER_USE seen set is full
  (n/65536 pairs)` / `… went unrecorded past the pair limit` (watches
  withheld), refusal gaps, `observation.native_witnesses`.
- Workaround: none in v0.2.0; refusals are explicit.
- Planned: v0.3.0 (initial tuning in C3, re-tune in C5 R2 after occupancy
  measurements).

### Loader contexts 256 per capture, never recycled (X-1)

- What the user sees: `profile`/`trace --system` with more than 256
  short-lived `dlopen` processes leaves a late provider `dlopen` past 256
  hooked views invisible to the loader path; only `discovery_truncated`
  records it.
- Kernels/conditions: all kernels; compounds per-process loader hooks
  (`OneProcess` scope, deep-scanned views only).
- Disclosure: `discovery_truncated` counter.
- Workaround: narrower scope, longer-lived providers.
- Planned: v0.3.0 (recycle loader contexts and sweep after discovery loss;
  attach `dl_debug_state` once per distinct ld.so inode with a cookie).

### Scan-induced target stalls unmeasured (DR-39)

- What the user sees: system-wide scanning may stall monitored workloads
  (research measured 0.097 ms → 8,020 ms target stall without
  rate-limiting/dedupe). No v0.2.0 rate limit or dedupe is claimed.
- Kernels/conditions: `--system` scans of large process sets.
- Disclosure: none yet beyond stage timings; M6 moves to v0.3.0.
- Workaround: `--module`, narrower scopes.
- Planned: v0.3.0 (C5 R1: measure target-side stall against an unobserved
  control; rate-limit/dedupe if shown).

## Capture loss and coverage

### Lifecycle ring loss under exec churn (M4) — clean at 100 exec/s, ~100/min lost at 1,000

- What the user sees: at 448 processes, native lane: 100 exec/s loses
  nothing (0 lifecycle and 0 ring loss in all 6 samples); 1,000 exec/s
  loses about 100 ring records per minute (84–117 across 6 samples),
  demotes 55 edges per minute-long capture with sticky unproven share
  1.0, and runs 1 recovery rescan per capture. The loss stays disclosed
  (`health_unproven`, demoted edges, the gap). The 64 KiB ring holds
  about 70 920-byte records, and the lane does not drain while a pass
  applies its scan, attaches entries, or reads usage. Churn 0 and
  4,096-process churn cells were not measured in this tier.
- Kernels/conditions: `--system --capture native` under unrelated exec
  churn, 3 cold + 3 warm 60 s samples per cell.
- Disclosure: `observation.lifecycle` (`records`, `ring_loss`, `malformed`,
  `failed_quanta`, `recovery_rescans`), the `native capture lifecycle
  evidence lost` gap, sticky demotion of `watched_no_use`, and an immediate
  bounded recovery rescan (never two in a row).
- Workaround: quiet host, narrower scope.
- Planned: numbers landed in the v0.2.0 short tier; the lossless fix
  (2 MiB inventory-only ring) is v0.3.0 (C7 batched verifier/vng
  campaign).

### Settlement always `unsettled`

- What the user sees: every native inventory document reads
  `observation.settlement: "unsettled"`. A call in flight at stop may still
  be unrecorded; absence of use is claimed only through `watched_no_use`
  intervals ending at the last clean read before stop.
- Kernels/conditions: all native runs (controller ruling D3).
- Disclosure: `observation.settlement`, `observation.retirement`,
  coverage `until_ns`.
- Workaround: none; positives are monotonic `NOEXIST` inserts, so the risk
  is only a missed late positive.
- Planned: stays `unsettled` unless the owner asks for a settled verdict
  (then bundled with the C7 BPF change).

### Watch demotion is global and sticky (DR-40)

- What the user sees: any native identity/pair/usage evidence counter rise
  demotes every `watched_no_use` interval reaching past the last clean read
  to `unknown`/`loss`, including already-ended intervals (retired callers,
  unloaded modules), because the failure cannot be localized per edge.
  System-scope lifecycle loss is sticky: no watch starts again in that
  capture.
- Kernels/conditions: all native runs with loss.
- Disclosure: `usage coverage health regression` gap, `native capture
  lifecycle evidence lost` gap, coverage `unknown`/`loss`.
- Workaround: quiet host, narrower scope.
- Planned: v0.3.0 (measure demotion frequency in 30-min churn; localize per
  provider/scope or accept and document).

### Unbound witnesses for fast CLI callers (DR-05)

- What the user sees: sub-second CLI callers (100 ms at 10/s) may stay
  "used by an unidentified caller image": their `CALLER_USE` rows are
  module-level `unbound_use`, never a caller edge. An exec-chain image
  that was never admitted (a thread exec inside one pass) likewise binds
  nothing: the retired caller's edge reads `unknown`/`use_before_admission`
  and the use is disclosed only via `unbound_use` (see the next entry).
- Kernels/conditions: P4/P5-style exec chains and short-lived callers.
- Disclosure: `modules[].unbound_use`, `observation.native_witnesses`
  (rows/bound/unbound/pending, `unbound_reasons`), and the `used by an
  unidentified caller image` / `native witness without mapping evidence` /
  `without a module` / `rows failed validation` gaps. Zero false joins is
  the hard bar and holds.
- Workaround: long-lived callers (≥2 passes).
- Planned: v0.3.0 (measure unbound ratio per cell after C5; I2c exact-image
  iterator or a documented boundary; D6 rule-3 relaxation only if
  `before_admission` ≥20% with zero false joins on P5).

### Leader-exit and exec-chain callers under `--system` stay unattributed (DR-05)

- What the user sees: a process whose thread-group leader has exited while
  other threads keep running (a zombie leader) is never admitted as a
  caller: it has no `callers[]` record and no edge, and its provider use
  appears only as module-level `modules[].unbound_use` with the
  `used by an unidentified caller image` gap. An exec chain whose images
  exec within one pass likewise binds no image: its rows are unbound as
  `exec_after_admission`, `no_live_caller` or `before_admission`, and the
  retired callers' edges read `unknown`/`use_before_admission`.
- Kernels/conditions: all; `--system` scope (for `--pid`
  see DR-C3-2).
- Disclosure: the pid-less `process view` gap ("a process in scope could
  not be retained or scanned before it changed"), `modules[].unbound_use`
  (`rows`, `reasons`), `observation.native_witnesses.unbound_reasons`, and
  the per-pass `unbound_rows` of the event stream. No pid is named and no
  watch or positive claim is made for these processes.
- Workaround: none for attribution; the module-level use is exact.
- Planned: v0.3.0 (exact image identity, I2c; a zombie-leader admission
  path that pins a live thread).

### Pre-admission use voids the watch (R-C51-1)

- What the user sees: a `CALLER_USE` row refused as `before_admission`
  (or otherwise unmatched) whose pid equals a watched caller's pid makes
  that watch `Unknown`, reason `use_before_admission`, for the life of the
  watch. The kernel records only the first use per (image, module), so a
  later use leaves no row.
- Kernels/conditions: any native run where use precedes admission (the
  real-world case); fail-safe by pid (an earlier holder of the same pid
  also downgrades; documented).
- Disclosure: coverage `unknown`, reason `use_before_admission`, the
  `native pre-admission rows past their bound` gap past 4,096 held pairs,
  and `budgets.native_preadmission` (`limit`, `occupied`, `refused`,
  `pruned`).
- Workaround: none; relaxing the admission rule is not allowed.
- Planned: v0.3.0 (DR-C51-PREADMIT: upgrade to `Witnessed` when proven
  same-incarnation by cookie/start_time).

### Live `quiet` lags a first use by up to one pass (decision horizon)

- What the user sees: on the dashboard and in mid-run `edge_observed`
  records, an edge whose caller has just used the module for the first
  time can still read `capture armed | activity quiet | entries 0` for
  up to one pass (~2 s by default) before it turns `witnessed` (or
  `unknown`). A witness row binds only after a lifecycle drain and a
  health read that both started after the row was read, i.e. at the next
  pass.
- Kernels/conditions: every native run; first use of each (image,
  module) pair.
- Disclosure: `observation.native_witnesses.pending`; the `-o` snapshot
  and the stream's final sweep are exact (no pending row survives stop).
- Workaround: read the `-o` report, or wait one pass before treating a
  live `quiet` as final.
- Planned: v0.3.0 (present an edge with a pending row of its caller as
  `unknown` until decided).

### Gap retention is first-1024-wins (DR-41)

- What the user sees: on busy hosts (ambient ~1,470 gaps observed),
  first-1024-wins ascending-pid retention starves later pids' gaps; user
  workload gaps are suppressed and counted only.
- Kernels/conditions: busy hosts with many gaps.
- Disclosure: `gaps_suppressed`, `budgets.retained_history`.
- Workaround: raise `--max-gaps` (1–65,536; default 1,024).
- Planned: v0.3.0 (per-pid/per-subject fair retention; busy-host cell must
  retain owned gaps).

### PID-scope coverage after leader exit or exec stays Unknown (DR-C3-2)

- What the user sees: after a `--pid` target's leader exits or execs, there
  is no re-attach to the new leader/image; the kernel probe shows
  `OneProcess` stops firing after leader exit on 5.15, 6.8 and 7.0
  (Multi entries on 6.12+/7.x keep firing, but custody reads
  `PidUnproven` either way).
- Kernels/conditions: `--pid` with exec/leader-exit.
- Disclosure: `native capture scope custody unproven` gap, watches ended at
  min(custody instant, last clean read), coverage `unknown`.
- Workaround: restart the capture on the new pid.
- Planned: v0.3.0 (C5/C5b re-attach policy or a documented boundary).

### Per-call overhead on attested endpoints unmeasured (DR-12)

- What the user sees: double probe cost on attested endpoints plus the
  uretprobe hazard for the Detailed subset is unmeasured in v0.2.0.
- Kernels/conditions: attested providers under Detailed capture.
- Disclosure: none yet; M2 moves to v0.3.0.
- Workaround: `metrics` mode for the lowest overhead.
- Planned: v0.3.0 (C5 R5 `bench-overhead.sh` with and without the double
  probe; C6).

### `--json` to a stalled terminal blocks exit (C5.3 F7)

- What the user sees: `inventory --json` writes the whole document to
  stdout at exit; on a stalled terminal (for example after Ctrl-S) the
  write blocks and the process does not exit until the terminal resumes.
  A second signal does not exit early: the report is armed as written
  only after that write completes.
- Kernels/conditions: all; stdout is a terminal with stopped output.
- Disclosure: none while stalled. No data is lost: `-o` and the event
  stream's `ended` are already written.
- Workaround: redirect stdout to a file, or rely on `-o` for the report.
- Planned: v0.3.0 (review follow-up; pre-existing).

### Event-log write error loses the `-o` report (C5.4 I-4)

- What the user sees: if the event stream (`--event-log`) fails while
  writing the closing records (for example a full disk), `inventory`
  aborts before writing the `-o` report, so the report is lost.
- Kernels/conditions: all; event-log I/O errors (ENOSPC).
- Disclosure: the returned I/O error; no partial report is written.
- Workaround: keep the event log on a disk with free space (or omit
  `--event-log` when only the `-o` report matters).
- Planned: v0.3.0 (review follow-up; pre-existing).

## Scopes (cgroup and pod)

### `inventory --cgroup` does not exist (DR-03)

- What the user sees: `inventory` accepts only `--pid | --system`;
  `--cgroup` is refused with a usage error. BPF and activation already
  accept `Scope::Cgroup`, and `profile`/`trace`/`doctor` already take
  `--cgroup`, but inventory has no cgroup collect, membership-churn
  handling, or per-pass cost bound.
- Kernels/conditions: all.
- Disclosure: CLI usage error before any capture.
- Workaround: `profile`/`trace --cgroup` for counting, `inventory --system`
  with `--module`, or the k8s entry script's `--pod-uid` (which runs a
  `--cgroup` capture).
- Planned: v0.3.0 (Task 6 tail with DR-04, before C3; fallback C4).

### No per-caller cgroup/container/pod attribution (DR-04)

- What the user sees: inventory output is node-flat. Even `--system` on a
  node cannot say which pod uses a module; there is no cgroup field in
  `inventory-v1`, the caller registry, or the dashboard.
- Kernels/conditions: all, including kind/Docker and DaemonSet use.
- Disclosure: field absent (never guessed); container cells stay exact
  per-capture but unattributed.
- Workaround: one capture per pod (`k8s-profile-entry --pod-uid`).
- Planned: v0.3.0 (caller-incarnation attribute from `/proc/<pid>/cgroup`
  at admission, sanitized; pod/container mapping display-only; additive
  inventory-v1 field; kind/Docker cells vs independent ledger).

### PID namespaces: `--pid` refused, `--cgroup`/`--system` lossy (DR-30)

- What the user sees: on a node that itself runs in a PID namespace (kind,
  k3d, sysbox, observer without host PID ns), `profile`/`trace`/`run`/
  `inventory --pid` are refused with `pid-namespace-mismatch`;
  `--cgroup`/`--system` run but read `PARTIAL` with cause `pid_namespace`
  and/or `proc_namespace_mismatch`, and `inventory --system` carries a
  scope-level `pid namespace` gap. With no `/proc` entry for the observer
  at all, every capture except `inventory --system` is refused instead.
  Trace PIDs are initial-ns PIDs; inventory/`--pid` PIDs are the mounted
  `/proc` view; they agree only when `observer: initial` and
  `proc_pids: observer`.
- Kernels/conditions: nested observer, or a foreign `/proc` that still
  lists the observer (`unshare --pid` without `--mount-proc`). A `/proc`
  with no entry for the observer at all (`nsenter -m` without `-p`)
  refuses every capture except `inventory --system`.
- Disclosure: `pid_namespace` (`observer`, `kernel_pids: initial`,
  `proc_pids`), `gap_classes.observation`, `verdict_detail: concrete_gap`,
  `doctor` PID-namespace row, stderr warning.
- Workaround: `hostPID: true` on real nodes; run p11scope in the initial
  PID namespace with its own `/proc`; or capture the target's cgroup
  (counts stay exact, discovery may miss mid-capture loads).
- Planned: v0.3.0 (C5b: startup `NSpid` depth check + host-pid normalization
  or honest refusal; namespace-aware BPF filter; normalize or label PID
  numbering across commands).

### `--cgroup` with no visible member reads like "no provider" (DR-K8S-5)

- What the user sees: without hostPID the observer resolves the pod cgroup
  but sees none of its processes; capture exits 0 with "no PKCS#11 modules
  discovered" and 0 probes, not naming the PID-visibility cause.
- Kernels/conditions: cgroup captures without PID visibility.
- Disclosure: troubleshooting doc covers it; the message does not yet name
  hostPID/PID visibility.
- Workaround: run with hostPID.
- Planned: v0.3.0 (name the cause when the cgroup resolves but has no
  visible members).

### Untested cluster shapes (DR-K8S-6, DR-K8S-7)

- What the user sees: the kind e2e is one kind node; per-node observer
  selection (`spec.nodeName`) is documented, not exercised; CRI-O and the
  cgroupfs driver are covered only by the entry script's self-test (fake
  hierarchy). Replacing `SYS_ADMIN` by `BPF`+`PERFMON` at paranoid ≤2 is
  expected to work but is unmeasured (host-global sysctl).
- Kernels/conditions: multi-node, CRI-O, cgroupfs-driver, paranoid ≤2
  clusters.
- Disclosure: `deploy/k8s/README.md` limits; `--command doctor` self-check.
- Workaround: run `--command doctor` on the target node.
- Planned: v0.3.0 (C3 container cells; vng guest cell for paranoid ≤2).

## Counting semantics

### Witness-only usage (no per-call counts) (DR-02, C7)

- What the user sees: the native lane records which caller image used which
  module (`witnessed`, first at `first_ns`) or module-level use by an
  unidentified caller; it never reports per-caller entry counts or recency.
  Every unattested provider (most real providers) shows "used,
  count/recency unavailable".
- Kernels/conditions: all native runs.
- Disclosure: `entries.coverage.state: "witnessed"`, `entries.count: 0`
  with `observation: "unknown (count unavailable; use witnessed)"`,
  dashboard activity `used (recency unknown)`, and
  `observation.native_witnesses`. `counted` stays a contract state the
  producer never emits in v0.2.0; `last_seen` comes only from counted
  entries.
- Workaround: `profile` for exact function-level counts (aggregate maps
  stay exact under event loss).
- Planned: v0.3.0 (C7: V1 non-fetch atomic add in `CALLER_USE`, about
  0–300 ns/call, lower-bound counts since first record, missing row means
  "uncounted" never zero, allowlist-v3 row first; M2 must measure V1
  directly).

### `C_GetInterfaceList`/`C_GetInterface` export calls go uncounted (DR-51)

- What the user sees: a `profile` can read
  `gap_classes.observation.status: "exact"` while missing the app's
  `C_GetInterfaceList`/`C_GetInterface` calls through those functions'
  exported entry points: the named rows probe only the function-table
  slot targets, not the export addresses (only `C_GetFunctionList` gets
  a provisional count-only target at its export). Observed in R0: table
  endpoints 0x3b80/0x3ba0 vs exports 0x4290/0x43f0 on the fixture
  provider.
- Kernels/conditions: all; providers whose exports differ from the table
  targets.
- Disclosure: none yet — no gap is recorded for the bypassed entry
  points.
- Workaround: none in v0.2.0.
- Planned: v0.3.0 (C6 cell in C3: re-test with current
  profile/inventory; fix the label or the contract).

### Semantic summaries withheld in the scan lane (S1/C6)

- What the user sees: scan-lane edges read
  `semantics: "unknown (semantic capture withheld)"`,
  `budgets.semantic_state.status: "withheld"`, `mechanisms`/`operations`
  null. Count-only scanned slots never gain mechanism/session meaning
  without an accepted manifest.
- Kernels/conditions: all scan runs; native runs without an authorized
  semantic feed.
- Disclosure: the `unknown` reason, `unknown_edges`, `refused`, and the
  `semantic capture loss` / `same-file double-load detected` gaps where
  they apply.
- Workaround: attested semantic capture (`p11scope-discover` + `--manifest`)
  for `profile`/`trace` semantics.
- Planned: v0.3.0 (C6: semantics, churn and capacity; Task 3 Stage B for
  the live feed).

### Same-file double-load merges (DR-13)

- What the user sees: a same-file double-load (two loader mappings of one
  file, notably a `dlmopen` private-namespace double-load with distinct
  session namespaces) merges into one module record and one edge per
  caller. When scan evidence shows the double load (duplicate executable
  file-offset coverage), the edge latches to
  `unknown (same-file double-load)` with the `same-file double-load
  detected` gap and its calls establish no claim; without that evidence the
  merge carries no marking. For `dlopen` in one namespace the merge is
  correct.
- Kernels/conditions: callers with duplicate executable file-offset
  coverage.
- Disclosure: `edges[].semantics`, the named gap when detected.
- Workaround: none; the fail-closed latch stays until instance authority
  ships.
- Planned: v0.3.0 (Task 3: per-instance separation with separation +
  uncertainty regressions; F7b guard removal only through the coordinator).

## Platform

### Linux x86-64 only; 5.15 floor; parked platforms

- What the user sees: AArch64, cgroup v1 and kernels below 5.15 are out
  of scope. There is no runtime kernel-version check: an unsupported
  kernel is expected to fail at BPF load with the generic hint (which
  names the 5.15 floor, BTF and lockdown), but that path has not been
  observed on a real sub-5.15, no-BTF or lockdown host. Release binaries
  are x86-64 only.
- Kernels/conditions: anything below 5.15 or off x86-64.
- Disclosure: the load-failure hint; `doctor`.
- Workaround: run on x86-64 Linux 5.15+ with BTF.
- Planned: stays out of scope (owner-declined for v0.2.0; confirm in §7).

### `run` under `sudo` clears supplementary groups (DR-56)

- What the user sees: a workload that needs an HSM/device group fails under
  `sudo p11scope run`; interpreters and `/proc/self/fd` edges behave as
  documented.
- Kernels/conditions: sudo launches.
- Disclosure: usage `run` safety boundary.
- Workaround: `profile`/`trace` against an already-running target, or a
  capability-carrying observer (`setcap ...`, groups intact).
- Planned: v0.3.0 docs review (keep documented or preserve groups).

### One observer per target assumed (DR-52)

- What the user sees: concurrent observers / double attach are unaddressed;
  a DaemonSet plus an ad-hoc `profile` on one node is realistic but
  untested.
- Kernels/conditions: concurrent captures of one target.
- Disclosure: none yet.
- Workaround: one capture per target at a time.
- Planned: v0.3.0 (two-observer cell; document or guard).

### Helper runs vendor code unsandboxed (DR-64)

- What the user sees: `p11scope-discover` executes provider code in its own
  unprivileged process (drops groups/IDs/capabilities, restores dumpability
  only for bounded `/proc/self/mem` reads) but without a seccomp/Landlock
  jail.
- Kernels/conditions: all helper runs.
- Disclosure: usage attested-capture workflow; helper must match the
  provider ABI/libc and never carries capabilities or set-id.
- Workaround: run the helper as an ordinary user on an isolated host.
- Planned: v0.3.0 owner decision (jail policy; hostile-provider tests if
  pursued).

## Packaging

### Toolchain: 1.98.1 only; 1.88 MSRV retired

- What the user sees: the release compiler (`.release-rust-version`,
  currently 1.98.1) is the only supported toolchain (edition 2024, Linux
  x86-64). The 1.88 floor and its CI job are gone; build containers use
  `rust:1.98.1`. `crates/ebpf-common` stays at rust-version 1.97 because
  the pinned BPF nightly-2026-05-20 (rustc 1.97) also compiles it.
- Kernels/conditions: all builds.
- Disclosure: `README.md` build section, `docs/development.md`, contract
  test `ebpf_common_rust_version_matches_the_bpf_nightly`.
- Workaround: install 1.98.1 (`mise install`).
- Planned: v0.3.0 (C7 BPF campaign: bump the nightly in one verifier/vng
  matrix run, then raise `ebpf-common` to the release major.minor).

### No long-soak or continuous-service claim (DR-19)

- What the user sees: no 4 h / 24 h soak evidence exists; 30 minutes is the
  Phase 5 minimum. This document makes no DaemonSet/continuous-service
  claim.
- Kernels/conditions: long runs.
- Disclosure: this row; resource return-to-baseline, losses and tickets
  are reported per run, not as a soak promise.
- Workaround: split long captures; watch `observation.lifecycle` and
  `kernel_control`.
- Planned: v0.3.0 (Task 8/C3: ≥4 h on the final candidate, 24 h if a
  continuous claim is made).

### DaemonSet has no upgrade story

- What the user sees: `deploy/k8s` is manifests plus a kind e2e, not a
  published image or operator. Opaque schema ids and no BPF versioning mean
  a rollout loses the running capture and anything in the pod's `/tmp`
  emptyDir; nothing persists between observer pods.
- Kernels/conditions: in-cluster use.
- Disclosure: `deploy/k8s/README.md`, usage DaemonSet section.
- Workaround: copy results out before a rollout (`kubectl cp`).
- Planned: documented limit for v0.2.0; a shipped/published image stays
  parked (DR-65).

### No improvement-over-v0.1.0 claim (DR-31/32/33)

- What the user sees: no matched v0.1.0-vs-candidate numbers are published
  in v0.2.0. The fresh v0.1.0 baseline build, the historical-trigger
  reproduction (`trace --system --duration 30`), and the live
  capture-to-sample adapter for `bench-discovery --full` are C3 preflight
  and did not run.
- Kernels/conditions: all performance comparisons.
- Disclosure: this row; the short-tier numbers above are absolute, not
  comparative.
- Workaround: none.
- Planned: v0.3.0 (C3: detached tag build in an owned 0700 dir, pinned
  artifacts, adapter from `evidence.scheduling`).

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# v070 rate round-2 measurement (2026-11-08)

Lane `task/v070-rate`, observer rev `47136fc68` (EVENTS staging
drained on every Joint service). Four joint cells plus a CPU re-run
on fedora (kernel 7.2.9-200.fc44, 5 CPUs,
provider `/usr/lib64/pkcs11/libsofthsm2.so`), exclusive lane,
2026-11-08 15:31-16:05 EET. Raw cell dirs lived under
`~/p11scope-live/v070-rate-r2/` on fedora (per-cell `report.json`,
`events.jsonl`, `observer.out`, `oracle.json`, bpftool evidence);
removed at task end per test-host hygiene. This note carries the
numbers and the commands so the claims stay checkable.

## Harness condition: observer at `nice -n -5`

Every round-2 cell below ran the joint observer one step above
best-effort (`scripts/ci/joint-throughput.sh`: `nice -n -5`).
Round-4 re-runs at default priority are tabulated separately below;
operator runs at other priorities may differ. The S1 twin cell
always runs unniced.
`JOINT_NICE` overrides the level; empty now skips nice and runs at
the caller's priority. Correction: the round-3 control re-ran
10k/60s with `JOINT_NICE=` (empty), but the round-3 script ran that
case under a bare `nice`, which adds its default +10 — so the old
control was really a nice +10 run, not a without-nice one (its
Gate-2 exactness held even de-prioritised; its latency comparison
was +10 against −5). Round 4 re-ran the control at true default
priority; its rows are tabulated below.

## Gate 2 exactness and settlement

`operations.calls` / `api_returns.count` from the final inventory
block in each cell's `observer.out`; `issued` from `oracle.json`;
settlement from the `settlement latency` line. `want` is issued
minus the 2 named slot-refused calls in every cell.

| cell | issued | ops.calls / api_returns | settle p50/p99 | ring_loss | staging gaps |
| --- | --- | --- | --- | --- | --- |
| 1k/5s | 5,006 | 5,004 = want | 8/22 ms | 0 | 0 |
| 10k/60s | 600,006 | 600,004 = want | 11/45 ms | 0 | 0 |
| 6.25k/60s | 375,006 | 375,004 = want | 10/45 ms | 0 | 0 |
| 7.5k/60s | 450,006 | 450,004 = want | 11/44 ms | 0 | 0 |
| 10k/60s cpu2 | 600,006 | 600,004 = want | 10/39 ms | 0 | 0 |

started == completed and failed == 0 in all cells; `events_lost` 0,
`final_drain` true, quiesced, `continuity_cuts` 0,
`unrouted_returns` 0, `gaps_suppressed` 0. Settlement samples cover
every applied call (e.g. 600,004/600,004, overflow 0). Gate 1
(`entries.count`) fails in all 60 s cells on the pre-existing
post-GO endpoint-commit lag (~15 s, rate-independent); the oracle
stops there, so later gates are unjudged. `total_ring_loss_sum` is
0 on both EVIDENCE maps in all five cells.

Cell entry load (`results.jsonl`): ~1.0 for the first four cells;
10.88/10.09/1.89 for cpu2 (elevated lane entry; CPU% below is the
observer's own ticks and stands).

## Round 4 (default priority)

One `joint-10k-single` cell per rate at true default priority
(`JOINT_NICE=` empty, fixed script skips `nice`), observer rev
`7871895e7`, same fedora 5-CPU VM, exclusive lane.

| cell | result |
| --- | --- |
| 6.25k/60s | exact: calls 375,004 = want, lost 0, settlement p50 16 ms as reported |
| 10k/60s | lost 271 records, counted (matches bpftool 271); key-operation tracking ended; ~65% of calls unattributed; settlement p50 2.4 s as reported |

This throughput is a local 5-CPU test-VM metric only, not a product
promise: 10k/s with key operations is at this VM's capacity edge — 1
of 4 runs (the two round-2 nice-−5 cells and the round-3 nice-+10
cell were exact) lost records, and every lost record was counted.

## Observer CPU and RSS (cpu2 cell)

1 s `/proc` samples of all `p11scope` procs
(`cpu-sample.py`: cmdline match, follows forks; `cpu-cell2.sh`
starts the sampler, then the cell). Emission window from file
mtimes: GO (`go`) to DONE (`gen.out`), 57.1 s, samples with
12.7 < t <= 69.9 s (n=57). During emission: mean 111%, p50 115%,
p95 136%, max 138% of one CPU; RSS max 123 MiB, p50 112 MiB.
Setup/binding pre-emission mean 59% (n=12); post-emission mean 32%.

## Commands

Delivered from the worktree (`tmp/controller/fedora-deliver.sh`
mirrors the source and sha256-checks the executables), then on
fedora under the exclusive lane:

```sh
T=/home/user/p11scope-live/v070-rate-r2
env RATE=1k MIN_RATE=1000 DURATION=5 CELLS=joint-10k-single \
  SETTLEMENT_LAT=1 STAGE_TIMINGS=1 \
  scripts/ci/joint-throughput.sh $T/p11scope $T/cell-smoke
env RATE=10k DURATION=60 CELLS=joint-10k-single \
  SETTLEMENT_LAT=1 STAGE_TIMINGS=1 \
  scripts/ci/joint-throughput.sh $T/p11scope $T/cell-10k60
env RATE=6.25k MIN_RATE=6250 DURATION=60 CELLS=joint-10k-single \
  SETTLEMENT_LAT=1 STAGE_TIMINGS=1 \
  scripts/ci/joint-throughput.sh $T/p11scope $T/cell-6250-60
env RATE=7.5k MIN_RATE=7500 DURATION=60 CELLS=joint-10k-single \
  SETTLEMENT_LAT=1 STAGE_TIMINGS=1 \
  scripts/ci/joint-throughput.sh $T/p11scope $T/cell-7500-60
python3 $T/cpu-sample.py p11scope $T/cell-10k60-cpu2/observer-cpu.log &
env RATE=10k DURATION=60 CELLS=joint-10k-single \
  SETTLEMENT_LAT=1 STAGE_TIMINGS=1 \
  scripts/ci/joint-throughput.sh $T/p11scope $T/cell-10k60-cpu2
```

Per-cell fields: `oracle.json` (Gate 1), `observer.out` (settlement
line, stop line, final JSON block), `bpftool-evidence.json`
(`total_ring_loss_sum`), `results.jsonl` (host/rate/load row).
A first CPU attempt sampled the pidfile's wrapper PID (all zeros)
and was discarded.

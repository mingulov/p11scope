<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# System-scope measurement harness

Runner: `scripts/system-scope-measure.sh` (+ `system-scope-workload.c`,
`system-scope-sample.py`, `system-scope-ts.py`, `system-scope-measure.py`).
Built for the system-scale plan (`docs/superpowers/plans/2026-09-19-system-scale.md`):
Task 1.4 Step 2 (post-fix baseline), Task 1.6 (coverage-architecture
experiment), Task 3.1 (consumer-scheduling loss shares).

## What it does

Given workload + duration + mode, it runs controlled per-PID and `--system`
captures with an identical deterministic workload and exact binary identity,
and emits per condition BOTH a JSON record (`record.json`, schema
`p11scope/system-scope-measurement/v1`) and a human-readable summary
(`summary.txt`), plus a combined `matrix.json`. Each record contains:

- ledger-paste-ready identity: exact observer command, git revision
  (+ clean / tracked-clean flags), config (mode, duration, ring bytes,
  drain interval, manifest), workload argv + seed, host (kernel/CPU/ncpu);
- phase timings: discovery / load / attach / capture / drain / detach /
  publish / wall, with the raw monotonic markers and method warnings;
- every loss counter: the full `COUNTERS` universe imported read-only from
  `scripts/check-capture-evidence.py` (record states the source; an embedded
  fallback is flagged if the import ever fails), plus attach failures and
  in-flight-at-end;
- verdict (`evidence.completeness`), admitted/refused providers and tables,
  slots allocated vs active-derived, attach mechanisms;
- workload truth vs observed per-function counts with a match boolean;
- observer CPU (user/sys/wall-%), RSS (max/first/last), fds/threads peaks.

## Method

- Workload (`system-scope-workload.c`, compiled by the runner): a gated
  two-phase SoftHSM2 client. READY/go files let the observer attach between
  setup and the measured burst of exactly N `C_GenerateRandom` calls
  (optionally paced with `--pace-us`). Prints `TRUTH_PREGO {...}` at READY
  (setup calls already made, outside the window) and one `TRUTH {...}` line
  at the end with the exact post-go counts — the counting oracle
  (late-map: all 7 call kinds incl. `C_GetFunctionList:1` via dlsym, seen
  by loader/export probes; early-map: `C_GenerateRandom:N`,
  `C_CloseSession:1`, `C_Finalize:1`).
- Mapping time differs by scope (recorded as `map_early`): per-PID runs map
  late, bench-style, with `--manifest`; `--system` runs map early (no
  manifest) so the scan corroborates the workload provider. The generated
  call truth is identical either way; see "Finding" below for why.
- Attach gate: the harness holds the go file until the observer's
  `p11scope: discovery:` stderr marker (dated by `system-scope-ts.py`
  through a FIFO) AND the first live frame on the observer's stdout
  (rendered on capture-loop tick one, strictly after attach — the
  in-observer attach-end signal). An fd plateau is deliberately NOT the
  gate: under load attach stalls mid-ramp and a plateau detector fires
  early (observed once: workload released into a half-attached observer,
  1/20000 calls seen).
- Phases are derived externally (the observer emits no phase timestamps;
  its `capture.start/end` are 1 s precision): discovery = spawn→marker;
  attach = marker→fd-plateau (BPF load folded in, reported as
  `load_s=null`: program/map load precedes the link ramp with no external
  marker); capture = requested `--duration` from plateau; drain/detach/
  publish split the post-expiry window by fd dip (detach start) and return
  to baseline (detach end). Approximate by construction; warnings recorded.
- Observer sampling (`system-scope-sample.py`, 20 Hz under sudo): follows
  the sudo child (re-resolves past transient sudo monitor processes),
  records utime/stime, RSS, fd count, threads from `/proc`.
- Output dir defaults to `/var/tmp/p11scope-system-scope-measure` (0700):
  the observer fails closed on writable ancestors, which rules out `target/`.

## Validation (2026-09-19, this desktop, debug binary, seed 1, N=20000)

Full 2×2 matrix, short captures (6 s, N=20000, debug binary), all four
cells green on counts:

| scope/mode      | verdict | truth → observed (GenerateRandom) | counts_match |
| pid/metrics     | PARTIAL | 20000 → 20000 exact               | True         |
| pid/profile     | PARTIAL | 20000 → 20000 exact               | True         |
| system/metrics  | PARTIAL | 20000 → 20001 (1 foreign call)    | True         |
| system/profile  | PARTIAL | 20000 → 20010 (10 foreign calls)  | True         |

System cells: 416 slots, 832 probes, both p11-kit refusals captured
verbatim (6530/5762 wanted). PARTIAL everywhere is the honest terminal
verdict (detach never proves callback quiescence; plus per-run counters:
uncorroborated/truncation on pid, discovery-ring loss on system).

Two harness bugs were found and fixed during validation: (1) the attach
gate first used an fd plateau, which fires early when attach stalls
mid-ramp under load (1/20000 observed once) — the gate now keys on the
observer's first live frame, the in-observer attach-end signal; (2) the
workload truth first covered pre-go setup calls, which are outside the
window by construction for early-map — truth is now split into
`TRUTH_PREGO` (outside) and `TRUTH` (post-go, compared).

Under sibling load the box also produced collapsed windows: setup
(spawn→capture-live) of 290–565 s against a 6 s duration, so the loop
expires during setup and the burst races teardown at tick granularity.
One system-profile run lost that race (2/20000); the record carries a
`COLLAPSED WINDOW` method warning whenever setup exceeds the duration,
flagging coverage as timing luck rather than margin. System baselines
belong on an idle box (see Limitations).

Sample summary (`pid-metrics/summary.txt`, worktree path and PID redacted):

```
system-scope measurement: pid / metrics / 6s
verdict: PARTIAL

ledger:
  command: sudo --preserve-env=SOFTHSM2_CONF <worktree>/target/debug/p11scope
    profile --pid <pid> --manifest /var/tmp/p11scope-system-scope-measure/manifest.json
    --mode metrics --duration 6 -o /var/tmp/p11scope-system-scope-measure/pid-metrics/report.json
  git_rev: 971c56f61468d1f2161f1cb78c07e9a5557ab4b9 (clean=False tracked_clean=True)
  binary: <worktree>/target/debug/p11scope (debug)
  config: mode=metrics duration=6s ring_bytes=default drain_interval_ms=default
    manifest=/var/tmp/p11scope-system-scope-measure/manifest.json
  workload: ['/var/tmp/p11scope-system-scope-measure/workload',
    '/usr/lib/softhsm/libsofthsm2.so', '20000', '0', '0'] seed=1 n_calls=20000
    pace_us=0 map_early=0
  host: 7.0.0-31-generic AMD Ryzen AI 9 HX PRO 370 w/ Radeon 890M x12

phases (s):
  discovery=0.28s load=n/a attach=5.09s capture=6.00s (requested 6.0s)
  drain=0.04s detach=8.27s publish=0.14s wall=19.82s
  evidence.scan_ms=241

loss counters (nonzero only; full map in record.json):
  discovery_truncated=1
  discovery_uncorroborated=1
  attach_failures=0 in_flight_at_end=0

admission:
  modules admitted=1 refused=0 skipped_views=0
  tables admitted=1 refused=0 (entries seen=68)
  slots allocated=68 active_derived=68 (attached_probes=136)
  attach_mechanisms=None
    admitted: /usr/lib/softhsm/libsofthsm2.so sources=manifest
      corroboration=uncorroborated

truth vs observed:
  truth: {"C_CloseSession": 1, "C_Finalize": 1, "C_GenerateRandom": 20000,
    "C_GetFunctionList": 1, "C_GetSlotList": 1, "C_Initialize": 1,
    "C_OpenSession": 1}
  observed (nonzero; +61 zero-call functions in record.json): {same 7 counts}
  counts_match=True (exact per-PID equality of workload truth vs observed calls)

observer:
  cpu_user=0.32s cpu_sys=3.14s cpu_pct_of_wall=18.15 rss_max=63152128B
  fds_max=187 threads_max=1
  samples=344
```

The `pid-profile` twin matches exactly too (GenerateRandom 20000/20000)
despite `event_loss=19226`: aggregate-map counts stay exact while the ring
overflows — the harness reports both, proving why one counter alone never
establishes completeness.

Validated pre-1.3; re-baselined for 1.3+ trees in Task 1.4
(`docs/notes/2026-09-19-task-1.4-baseline.md`): system cells are scan-only,
so every slot is `unknown` (mislabel guard) and `counts_match` compares
totals instead of per-function names. Pid cells keep exact per-name
equality via the manifest.

## Handoff: ci.yml UNRUN update (needs a writer allowed past new-files-only)

`hosted_pipeline_names_every_unrun_privileged_lane` pins the exact set of
privileged lane scripts, so this harness's two privileged files fail that
test until `.github/workflows/ci.yml` names them. Add after the
`scripts/qualify-task-storage-canary.py` UNRUN line (placement is free; the
test compares sets):

```
UNRUN: scripts/system-scope-measure.sh (privileged/container lane body UNRUN hosted; no self-test; local run needs owner approval)
UNRUN: scripts/system-scope-sample.py (privileged/container lane body UNRUN hosted; no self-test; local run needs owner approval)
```

## Finding (for Task 1.4/1.5): per-PID attach fails when the provider is already mapped

`p11scope profile --pid <wl> --manifest …` against a workload that mapped
SoftHSM2 *before* the observer started fails deterministically with
`starting attach session: the named process generation changed while
attaching`, although the workload is alive and idle. The identical setup
with late dlopen (provider unmapped at attach, manifest-only) succeeds
(rc=0, exact counts). `--system` with an early-mapped workload also
succeeds (416 slots, 832 probes, GenerateRandom 5000/5000), so the stale
check only bites the named (`--pid`) path. Repro: run the workload with
`early=1`, then attach per-PID with the manifest. The harness routes around
it (`map_early=0` for pid scope); the false-positive stale view deserves a
product look (suspects: pidfd-poll error mapping in `still_the_same`, or
scan-path view/pin handling across `start_retained_with`).

## Limitations

- Phase boundaries are externally derived (fd trace + one stderr marker),
  not in-observer timestamps; drain/detach/publish splits are approximate
  (±0.1–0.2 s at 20 Hz sampling, verified synthetically).
- BPF load has no external marker and is folded into `attach_s`.
- Observer CPU/RSS are wall-window samples, noisy under concurrent build
  load (sibling workers shared this host during validation) — perf
  comparisons need an idle box; run noisy perf experiments separately from
  correctness gates per the plan.
- `counts_match` for pid scope requires exact equality including the
  loader-observed `C_GetFunctionList`; for system scope (scan-only, every
  slot `unknown` since the 1.3 mislabel guard) it requires observed total
  ≥ truth total (other processes may add calls).
- Metrics-mode reports lack `attach_mechanisms` (profile-only field);
  recorded as null, honestly.
- Trace mode is not supported yet (text-stream evidence needs its own
  parser); metrics + profile only.
- Under concurrent full-suite load (load 24 on 12 cores) a `--system`
  observer needed a 52 s scan and ~19 min wind-down; system-scope
  baselines must run on an idle box. The harness signals the real
  observer child (never just its sudo parent) and writes record files
  before any terminal output, so a stuck observer or closed stdout
  degrades to a loud failure, never a silent orphan.
- Never pipe the runner's stdout to `head`: redirect to a file and grep
  that instead.

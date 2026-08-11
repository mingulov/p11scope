# Phase 5 Task 3 — measured overhead across capture modes

`scripts/bench-overhead.sh` measures p11scope's real cost against
unobserved SoftHSM2 — deliberately the **worst case** for this
measurement. SoftHSM2's `C_GenerateRandom` is microsecond-scale software
crypto, so uprobe/uretprobe trap cost, map updates, and ring-buffer
submission are proportionally largest relative to the call itself here.
A network HSM whose calls run milliseconds would show a much smaller
*relative* overhead for the identical *absolute* per-call cost — these
numbers should not be read as "p11scope adds ~3.3µs to every PKCS#11
call everywhere," only "...to every call on this workload."

## Environment

- Kernel: `7.0.0-28-generic`
- CPU: `AMD Ryzen AI 9 HX PRO 370 w/ Radeon 890M`
- SoftHSM2: `/usr/lib/softhsm/libsofthsm2.so`
- Workload: `scripts/fixtures/hammer.c` (the induced-gaps suite's
  tight-loop fixture) — 1,000,000 back-to-back `C_GenerateRandom` calls,
  no per-call delay, so per-call cost is resolvable well above process
  start/attach noise.
- 5 runs per condition (script default `RUNS=5`).

## Method

Each run times **only the workload process's own wall-clock**, using the
same go-file synchronization every other `scripts/verify-*.sh` in this
repo uses: the workload waits for a go-file, the observer (where
applicable) is given a 3s warm-up after both processes exist and before
the go-file is touched, so attach latency is never counted inside the
measured window. The observer is stopped with SIGINT (Task 2's clean
shutdown) right after the workload's `wait` returns.

For `trace`, per-line output was written to a plain file (`-o`) **and**
the observer's own stdout was redirected to a plain file rather than a
terminal — `trace` prints one line per completed call, and on a real tty
that I/O would itself become the bottleneck being measured. Both trace
output files (the `-o` file and the redirected stdout, which duplicate
each other) land under `target/bench-overhead/`, not committed.

Every run is sanity-checked before its timing is accepted: `metrics`/
`profile` runs assert `evidence.attached_probes > 0` from the `-o` JSON;
`trace` runs assert no `attach failed` line in the observer's log and a
non-empty output file. An unattached run would otherwise silently
re-measure "unobserved" under an observed label.

## Results

5 runs/condition, 1,000,000 calls/run, this host:

| Condition | median wall-clock | min..max wall-clock | median ns/call | overhead ns/call |
| --- | --- | --- | --- | --- |
| unobserved | 788.2 ms | 779.4..821.4 ms | 788.2 ns | — |
| `profile --mode metrics` | 4041.6 ms | 3992.0..4067.8 ms | 4041.6 ns | **+3253.4 ns** |
| `profile --mode profile` | 4038.7 ms | 4014.0..4085.8 ms | 4038.7 ns | **+3250.5 ns** |
| `trace` | 4180.8 ms | 4120.0..4303.7 ms | 4180.8 ns | **+3392.6 ns** |

Raw per-run wall-clock times (ns), 5 runs each:

```
unobserved: 821445817 779382791 783944906 801066044 788206853
metrics:    4023771255 3992013326 4067816952 4041581025 4056667614
profile:    4038702144 4031394360 4085835678 4013967965 4052465096
trace:      4120041487 4157188480 4303720198 4201452227 4180772294
```

## Findings

**Overhead on this workload is large: ~3.25–3.4µs added to every
~0.8µs unobserved call, a ~5x wall-clock slowdown.** This is the honest
number for SoftHSM2 hammered at 1M calls/sec with no per-call delay; it
is not tuned down. It should be read as a ceiling, not a typical figure
— see the "why the modes converge" note below and the SoftHSM2 caveat
above for why a real deployment's relative overhead will usually be
much smaller.

**All three observed conditions cost almost the same** (4038–4181ms),
despite doing very different amounts of userspace work (`metrics` never
drains the ring buffer at all; `profile` drains it every 1s and runs it
through the semantic state machine; `trace` drains it every 200ms and
renders/prints a line per call). The reason: the eBPF program does not
know which userspace mode is running. Every attached call unconditionally
pays for the uprobe trap, the uretprobe trap, the aggregate map updates,
and a ring-buffer event submission attempt, regardless of whether
userspace ever reads that data. At this call rate, that unconditional
in-kernel cost dominates and swamps the (real, but comparatively small)
difference in userspace drain/render work between the three modes.

**A side effect worth flagging honestly**: at 1,000,000 calls/sec with
the default ring buffer, `profile` and `trace` both lose the overwhelming
majority of events — `event_loss` measured at 991,290–991,350 out of
1,000,000 (99.1%+) for `profile`, and 122,348–145,383 lines actually
written for `trace` (`trace`'s own drain cadence, 200ms vs `profile`'s
1s, meaningfully reduces its loss rate but far from eliminates it). This
does **not** invalidate the timing measurement — `evidence.completeness`
still correctly reports `PARTIAL` and the aggregate map counts (the
count authority; see `docs/notes/phase2-induced-gaps.md` gap 3) stayed
exact in every run, exactly as the induced-gaps suite already proved —
but it is a second, independent finding from this benchmark: **a
workload firing PKCS#11 calls back-to-back at this rate will lose most
`profile`/`trace` per-call events under this build's default ring size**,
same as `verify-induced-gaps.sh` gap 3 (which deliberately shrinks the
ring further to guarantee this on a lighter workload). An operator
capturing a bursty, high-rate workload should expect `PARTIAL` with real
`event_loss`, and should trust the aggregate counts over the per-call
event stream in that case.

## Caveats

- Single host, single point in time. Not reproduced on a second machine.
- `hammer.c`'s workload (`C_GenerateRandom` only) is not representative
  of a mixed-mechanism workload; overhead per call likely varies by
  which PKCS#11 function and mechanism is called (different parameter
  decode cost in `profile`/`trace`), not measured here.
- Wall-clock timing on a shared, non-isolated (no `taskset`/`nice`/cgroup
  CPU reservation) development machine — the min..max spread above
  (roughly 1-2% of the median for observed conditions, up to ~5% for
  unobserved) is a lower bound on real-world variance, not a rigorous
  isolated-benchmark figure.

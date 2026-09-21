<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# System capture experiment backlog — 2026-09-21

Review baseline: `feat/system-scale`, production commit
`885ed651f1c549162a0537642b1c78ffc61a83e3`. This is an experiment plan;
only the explicitly marked completed checks in [REPORT.md](REPORT.md) have
been executed. Implementation sequence: [SYSTEM-PLAN.md](SYSTEM-PLAN.md).

## What success means

Measure separate properties: provider discovery, admission of exact physical
endpoints, first-call coverage, entered/returned aggregate accuracy, event
delivery, semantic authorization, and terminal settlement. A zero ring-loss
counter proves none of the other properties. A missing call is unknown unless
an independent workload ledger supplies the denominator.

The target is provider-independent Linux system observation within an explicit
tested envelope. Preserve `docs/privacy/allowlist-v1.md` and the safe default:
catching PKCS#11 activity does not authorize capturing secrets, arbitrary
arguments, or semantics inferred only from a table-shaped byte sequence.
Calls before attachment and unsupported executable shapes remain explicit
coverage boundaries. Wrapper and backend calls are separate physical events.

## Common protocol

- Pin source SHA, executable SHA256, embedded BPF object/build features,
  kernel, ABI/libc, possible and online CPUs, scope, backend and limits.
- Use private fixture directories and owned workloads; keep source/output
  identities separate from path labels. Retain the actual workload process's
  mount namespace and mapped `(device,inode,offset)` identity in private test
  evidence. A host `stat(path)` or equal SHA256 alone is not that identity.
- Use an independent invocation ledger: process/image generation, physical
  endpoint, sequence, expected entry/return, and expected RV. Keep private
  identity details in test artifacts; public product output remains allowlisted.
- Gate deterministic bursts on a proven observer-ready boundary; timestamp
  exec, publication, attach completion, first drain, workload start/end and
  detach separately. A first-frame heuristic must state its limitations.
- Compare admitted-target counts exactly where an oracle exists; partition
  missed work into pre-attach, admission, entry/pairing, event, reducer, sink
  and terminal losses. Do not add overlapping counters into a fake equation.
- Report workload latency/CPU separately from observer setup, steady-state
  CPU, RSS, map memory, FDs, attach/detach time and final publication time.
  RSS is not a measurement of kernel BPF map/program memory.
- Run one BPF experiment and one Cargo-heavy command at a time; run no Cargo
  build during a timing cell. Record background load and profiling overhead.
  Run an unobserved workload control and at least three independent repetitions
  before interpreting timing trends. Absolute SLOs need an idle dedicated lane.
- Bound each cell; retain exit codes and partial artifacts on failure. Stop
  for unexpected target death, secret leakage, corrupted identity attribution,
  or cleanup failure. Reap owned processes and compare their BPF objects with
  the baseline; never delete unrelated objects or terminate other lanes.

Privileged host tests were explicitly authorized in this review. Future
executors must check current lane custody and authorization. Existing running
VMs observed on this host belonged to `osslscope-ws` and `kryprobe-ws`; their
presence is not permission to reuse or shut them down.

## Priority 0: establish trustworthy observations

### E01 — PID versus true system scope

**Hypothesis:** a workload that is exact under PID scope can be omitted by
system discovery/admission even when CALL-ring loss is zero.

**Workload:** the existing gated SoftHSM fixture, 20,000 `C_GenerateRandom`
calls, metrics/profile, PID/system, three seeds. Do not add a `--module`
filter to make the system cell pass. PID uses the harness manifest; system
uses scanning, so report this authority difference.

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 build --locked --offline --release -p p11scope -p p11scope-discover
mise exec -- ./scripts/system-scope-measure.sh --scope both --mode both --duration 8 --n-calls 20000 --seed 1 --no-build --work /var/tmp/p11scope-system-E01-r1
```

Use fresh work directories for repetitions; the harness replaces its own
fixture token/condition directories. **Oracle:** private workload ledger and
physical module identity, per-function entered/returned totals, admission and
all failure evidence. **Experiment validity:** preserve the independent
denominator, raw observations and phase/identity limitations, including a
failed-coverage result. **Coverage acceptance:** account for every owned call
inside the independently established capture boundary. A valid zero-call cell
with expected calls fails coverage acceptance; process exit 0 is insufficient.
This review executed E01 and established a failed system baseline; results
and remaining phase/identity limitations are in REPORT.md.

### E02 — Doctor and output-contract reality

**Hypothesis:** synthetic tests miss producer/consumer vocabulary drift.
Run the exact binary's privileged `doctor`; compare its successful attach
row with the tier classifier. Exercise `inspect --json` against both an
invalid PID and a readable process whose diagnosis fails. Feed every producer
skip reason into the real evidence validator.

**Oracle/pass:** successful host attach cannot be classified as offline;
JSON requests have a defined machine-readable failure contract; every
producer-emitted reason is accepted or the producer is rejected before output.
Keep the hard-error and soft-diagnosis branches separate. Partly executed here.

### E03 — Validate the benchmark itself

**Hypothesis:** setup timing, pathname matching and derived delivery counts
can misclassify capture quality.

**Workload:** synthetic sampler/marker records with 60 s setup followed by an
8 s capture; early target exit; reordered per-class diagnostic summaries;
same pathname on different inodes and alternate paths to the same inode.
Use the existing `scripts/system-scope-measure.py` parsing functions directly.

**Pass:** setup does not consume a duration started after attach; phases use
explicit boundaries or remain unknown; PID early exit is not an 8 s measured
window; physical identity controls matching. A derived `returned - ring_loss`
value must not be presented as an independently observed consumer count.

### E04 — Persistent EVENTS consumer: measure before and after

**Hypothesis:** repeated `RingBuf::try_from` creates avoidable mmap/munmap
and identity-query work at each readiness quantum.

**Workload:** unchanged idle, paced and burst providers; profile and trace;
4 MiB ring; same frame cadence and output sink. Measure mmap/munmap counts,
map-info queries, allocations, task-clock and maximum drain gap. Profile a
separate cell with `perf record -e cpu-clock -F 99 --call-graph dwarf`.

**Correctness gate before performance:** same domain/map identity and one
consumer cursor across ordinary, root-tail and terminal drains; malformed
record in quantum 1 plus valid records in quantum 2 counted exactly once;
cancel with backlog; detach while a record is held. **Pass:** no output/loss
regression and repeatable reduction beyond run-to-run noise. No promised
single-digit CPU target is established yet.

## Priority 1: coverage under breadth and churn

### E05 — Cross-module admission and physical identity

**Hypothesis:** candidate order lets a large proxy starve unrelated providers.
Sweep 1/4/16 modules and 128/256/512/1,024/6,530 unique endpoints, including
duplicate files, bind mounts, same path/different bytes, same bytes/different
inodes and five-plus wrapper instances. Keep exact alias and forwarding truth.

**Measure:** demand/admission/active/lifetime slots by provider, first-call
coverage, setup, detach, memory and FDs. **Pass:** every requested endpoint is
admitted within the declared envelope; over-envelope omissions name the
exhausted resource and never silently merge independent physical calls.

### E06 — Fair exploration when retained process views are full

**Hypothesis:** long-lived provider-free views occupy the scan cap forever.
Set `max_scan_pids=2`; retain two such processes, introduce a third with a
unique provider and exercise at least eight reconciliation frames. Repeat
with shared-inode endpoints as a countercontrol.

**Oracle:** actual deep-scan/hook/admission events, not maps-file visits.
**Pass:** a specified finite exploration bound reaches the unique provider
without discarding valid active ownership. Current source predicts failure.
Anchor: `src/discovery/engine_tests.rs`,
`reconcile_pass_rereads_maps_rarity_selects_and_advances_cursor`.

### E07 — Keep covered endpoints after an incomplete rescan

**Hypothesis:** a saturated table budget prevents repeat recognition and turns
incomplete evidence into apparent absence.
Create 512 distinct candidate tables sharing a small endpoint set; attach,
then trigger an unchanged full loader scan. Separately exhaust I/O, work and
deadline budgets. Include a genuine unmap/replacement as the negative control.

**Pass:** budget-limited absence does not retire still-validated endpoints;
new candidates are refused with evidence; real invalidation still detaches.
Measure candidate charges, retained endpoints, detach deltas and exact calls.
Anchor: `scan.rs::scan_tables_with_clock` and
`engine.rs::process_validated_loader_scan`.

### E08 — Equivalent factory forms and publication ownership

**Hypothesis:** identical target sets receive different coverage depending on
which PKCS#11 factory publishes them.
Cross `C_GetFunctionList`, `C_GetInterfaceList` and `C_GetInterface` with
named/default-NULL requests; file-backed/heap tables; same-object/forwarded
endpoints; pre-capture and mid-capture publication; 2.40/3.0/3.1/3.2 shapes.

**Pass:** supported equivalent forms yield the same exact count-only endpoint
set. Unsupported forms produce a specific omission. No inferred table name
or successful factory call grants unsafe semantic decoding. Measure factory
return-to-ready latency and calls during that interval separately.

### E09 — Repeated interfaces and deduplication budgets

**Hypothesis:** stable rescans consume the 512-interface lifetime allowance.
Scan one unchanged interface 513 times with adequate independent I/O/work
budgets; then scan a changed table and reuse its address in a new process
generation. Repeat across processes sharing one provider inode.

**Pass:** distinct-interface cardinality is separate from attempted-work
charging; repeats preserve linkage, changed generations are not false repeats,
and bounded exhaustion is explicit. Inspect classification/admission changes,
not only the final PARTIAL bit.

### E10 — Lifetime slot exhaustion at low concurrency

**Hypothesis:** append-only retired slots exhaust capture capacity even with
few simultaneously active providers.
Serially load/unload distinct physical endpoints past 512; keep peak active
endpoints below 68. Include delayed returns/events and pending async work.

**Pass for current behavior:** exact exhaustion point and omission reported.
**Pass for a future reclamation design:** lifetime history remains distinct;
old events cannot use a new descriptor; no double counts or pointer reads
under changed authority. Measure active versus allocated slots separately.

### E11 — Independent kernel map/resource ceilings

**Hypothesis:** enlarging STATS alone shifts failure to START, RV or ownership.
Sweep concurrent in-flight calls around 16,384, distinct `(target,RV)` around
4,096, endpoint residency versus capacity, and 2/12/64 possible CPUs in VMs.
Use induced-small-map builds to reach failures cheaply before full-size runs.

**Pass:** first-touch races retain exact totals, allocation failure is counted,
no LRU eviction conceals loss, and all other resources remain bounded. Compare
dense and NO_PREALLOC sparse storage at empty, sparse and full occupancy.
Test task-owner slot checks/scrubbing and return distributions, not only STATS.

### E12 — Reentrancy, missing returns and long calls

**Hypothesis:** zero event-ring loss does not imply exact returned totals.
Use same-thread recursion into the same physical endpoint, a callback invoking
that endpoint, nested distinct wrapper/backend endpoints, thread exit,
`longjmp`, process death and calls spanning detach/cgroup migration.

**Pass:** exact completed-call counts where supported; explicit pairing loss
elsewhere; no stale START data, raw pointer leakage or wrong latency pairing.
Current NOEXIST collision handling deliberately invalidates an ambiguous
invocation; test it as a limitation, not as successful recursive correlation.

### E13 — First-call gap after activation

**Hypothesis:** publication-selected attachment cannot guarantee the first
call immediately following factory return, especially for pre-published tables.
Publish before capture, after capture and immediately before a burst; vary
0/10/100/1,000 us from factory return to invocation. Compare selected and broad
validated attachment using the fixed-wrapper fixture.

**Pass:** every missed first call has an explicit boundary and quantified gap;
any broad-coverage claim includes dormant wrappers, sparse indexes and failure
paths that never forward. Optional provider filters do not qualify system scope.

### E14 — Lifecycle and namespace recovery

**Hypothesis:** fork/exec/dlopen/dlclose/cgroup movement or one lost lifecycle
record can leave discovery or attribution stale.
Exercise short-lived children, PID reuse, exec without PID change, loader-event
loss, dlmopen namespaces, deleted/memfd providers, bind/overlay paths, cgroup
entry/exit and mount namespaces. Use owned fixtures and exact process epochs.

**Pass:** no cross-generation attribution; reconciliation recovers supported
missed changes within a stated bound; otherwise explicit degraded coverage.
Measure rescan bytes, owner leases and retained historical records after exit.

### E15 — ABI and semantic authority

**Hypothesis:** broadening discovery accidentally broadens decoding authority.
Cross LP64/IA32, glibc/musl, stripped/named providers, aliased slots, alternate
interface names, future-minor/vendor tables and an attested manifest.

**Pass:** exact safe counts or explicit ABI/shape refusal; unknown/colliding
semantics stay count-only. Malicious pointer placement and forged names do
not produce new public fields. Test manifest-free and attested modes separately.

### E16 — Unsupported execution surfaces

**Question:** what happens to direct exports without discoverable tables,
statically linked/inlined wrappers, anonymous executable/JIT trampolines,
remote HSM proxies and nonstandard vendor interfaces?

Build one fixture per surface, with known invocation truth. **Pass:** supported
file-backed targets attach using validated identity; unsupported shapes remain
explicitly unknown. Do not invent offsets or treat network/HSM-internal work
as observed from a client-side PKCS#11 probe.

## Priority 2: throughput, interference and long captures

### E17 — Slow sink, burst fairness and cancellation

Sweep event rates, ring sizes 4 KiB/4 MiB/16 MiB, file/discard/slow-pipe sinks,
and SIGINT/SIGTERM at setup, burst, pause and terminal stages. Test trace max
events and owned `run` children writing to the same stdout pipe.

**Pass:** event/reducer/sink losses remain distinguishable; bounded memory;
no child EAGAIN induced by observer flag changes; cancellation/cleanup within
an explicitly measured limit. Ring enlargement alone cannot pass fairness.

### E18 — Metrics extraction cost

Sweep N allocated slots, R return-code keys, CPU count and frame cadence.
Compare current iteration with proposed batch reads/reused per-CPU buffers.
The current stable-map path is approximately `N + 2R + 10` BPF syscalls before
auxiliary work, not N+1.

**Pass:** final totals/evidence unchanged, supported-kernel fallback works,
live non-atomic snapshots remain labeled, and maps-phase time/drain stalls
improve beyond noise. Avoid reading every retained historical map each tick
if a cheaper live view can preserve final evidence.

### E19 — Reducer and trace allocations

Replay identical authenticated events through count-only and attested
init/update/final/async paths; vary aliases and processes. Measure allocations
and CPU/event for shared SlotMeta, static operation labels, fused lookups,
bounded mechanism dedup and reusable trace buffers, one change at a time.

**Pass:** byte-equivalent public output and evidence, preserved admission
ordering, pseudonyms and immutable pending metadata. Unsafe template-path
optimization is a separate diagnostic-only cell.

### E20 — Semantic churn and algorithmic scaling

Cross 100/500/2,000 sessions with 1–3 operations/session, fork, close-all,
login/logout, finalize, pending saturation and detached joins. Then run many
serial open/close and process generations at low peak concurrency.

**Pass:** operation-visit counts establish the intended scaling, not only a
loose wall-time assertion; unrelated state stays intact; eviction indexes
remain bounded; lifetime budget drops are explicit. Any reclamation preserves
anti-replay and pseudonym lifetime guarantees.

### E21 — Parser and privacy stress

Run the existing parser harness seeds plus coverage-guided malformed
ELF/maps/manifest/interface inputs; separately exercise live hostile-alias and
secret-canary fixtures in safe builds. Keep sanitizers and fuzzers out of
production timing cells.

**Pass:** no reproducible crash/memory violation, bounded work, correct
refusal/evidence, and no sentinel in observer output or its owned BPF maps.
Zero crashes without coverage feedback is not proof of parser safety.

### E22 — Standard catalog versus actual coverage

Compare the authoritative OASIS 3.2 machine-readable function header with
the pinned dependency's ordered catalog, then exercise every supported ABI
descriptor, including 3.2 async and authenticated wrap functions.

**Pass:** exact ordered catalog equality and real descriptor/count/return
tests. The header comparison completed here is 104/104; it does not prove
runtime semantics for all 104 functions or arbitrary vendor extensions.

### E23 — Backend and kernel matrix

On owned 5.15, 6.8 and a capable ≥6.9/current-kernel lane, force singles,
multi and auto with identical exact-target workloads. Include duplicate
aliases, group rebuild, partial attach failure and rollback/detach failure.
Probe actual kernel behavior; distro backports make version-only guesses weak.

**Pass:** supported backends observe identical endpoint/call sets; unsupported
multi has a named refusal or tested auto fallback; no duplicate observation
or stale descriptor after rebuild. Verify confined-target safety on an owned
seccomp fixture; an unknown self-probe cannot justify a broad safety claim.

Run the safety subset first, under Package A: exercise Clean/Affected/Unknown
kernel verdicts with confined, unconfined and unreadable/unspecified targets,
plus an owned child that enables seccomp after attachment. Unknown wide-scope
safety must not silently proceed; preserve explicit override diagnostics and
cleanup. The full backend/kernel matrix remains Package H qualification.

Existing prepared bases: `vm-operational/2026-09-10-release-prerequisites-v2`
and `vm-operational/2026-09-10-release-build-prerequisites` in the workspace.
Their manifests are historical preparation evidence. Use fresh overlays,
verify actual guest tools/kernel and source SHA, and retain cleanup receipts.
No guest runtime qualification was performed in this review.

### E24 — Soak with an explicit coverage envelope

After E05–E15 pass, run 30 minutes, 4 hours and 24 hours of controlled provider,
process and session churn; inject bursts and quiet periods. Record current
and cumulative resource use separately and retain the independent call ledger.

**Pass:** memory/FD/lease growth has an explained bound; current covered
endpoints remain covered; no silent lifetime exhaustion; exact in-envelope
counts and explicit out-of-envelope omissions. Publish a tested envelope
with rates, endpoints, processes, CPUs and duration, not an unconditional
claim to catch everything.

### E25 — Startup reconciliation and history amplification

**Hypothesis:** independently arming many loader contexts repeatedly rebuilds
and clones a large capture-wide history/plan. A five-second sample in this
review observed `merge_current`, comparison and allocation stacks during
`start_session_with`; it does not quantify the whole startup interval.

Sweep retained views and shared/unique modules independently, keeping event
rate zero. Count transactions, history entries copied/compared, candidate
rebuilds, pin clones and actual link syscalls. Timestamp object/program load,
static attachment, loader arming and the first frame separately.

**Pass:** batching/incremental updates preserve proof tombstones, conflict
resolution, ordering, rollback and exact endpoint/history output; startup
CPU/RSS improve beyond noise. Do not attribute RSS to kernel BPF memory or
FD count to link count. This is distinct from O-1's event-consumer remapping.

## Initial campaign order

1. E23 safety and E17 child-stdout subsets, then E01–E03: safe execution,
   correct baseline and measurement contracts.
2. E06/E07/E09: small deterministic discovery regressions before optimization.
3. E04 and E25: independent consumer/startup measurements, then E19 allocations.
4. E05/E08/E10/E11/E13: choose and qualify broader admission/storage.
5. E12/E14/E15/E16/E17/E20: lifecycle, supported surfaces, privacy and
   saturation boundaries; Package H owns E16 before the final envelope.
6. E18/E21/E22/E23, then E24: scaling and final supported-envelope qualification.

Do not run this whole factorial matrix blindly. Start with boundary pairs;
expand the axes that change coverage, failure evidence or measured cost.

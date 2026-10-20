<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Installed operator output matrix

`scripts/qualify-operator-output.py` prepares E17 against the ordinary EVENTS
ring on the actual `trace --pid` route. Inventory's entry witness ring is a
different surface and cannot satisfy this test. No simulated observer can
supply installed acceptance. `test_operator_output_qualification.py` checks
oracle mutations and actual fd behavior only.

The matrix contains exactly27 cells:

| Dimension | Values |
| --- | --- |
| Requested and measured EVENTS map capacity |4KiB,4MiB,16MiB |
| stdout | regular file, `/dev/null`, genuinely backpressured4KiB slow pipe |
| Cancellation | none, after acknowledged capture workload, during observed finalization |

The prebuilt `tests/fixtures/cgroup-trace/caller.c` fixture calls real SoftHSM
`C_GenerateRandom` and records each successful invocation separately on its own
ledger pipe. Provider setup precedes capture readiness and teardown follows
observer reap. The oracle retains independently verified executable identity and mapped held-
provider identity, matches the image0 GenerateRandom target, and requires exactly
one phase ACK after all calls and before independently observed completion.
The observer selects exactly this single-threaded PID; the caller
performs no fork/exec while attached. All issued calls must complete before the
first signal. Setup/teardown cannot substitute for the mandatory main calls.

The oracle keeps four units separate: independently issued/acknowledged API
calls; missing ordinary CALL event records; delivered stdout bytes; stdout shed
bytes. STATS entry/return counts equal issued calls. Raw CALLs equal rendered
rows; issued minus raw equals EVENTS loss in this controlled no-fork population.
Cumulative LOST records agree with final event loss. For readable stdout, complete
saved-trace bytes minus delivered bytes equals the final sink byte counter,
including terminal records. Lossless output must be byte-identical. Lossy
ordinary bytes must remain an ordered subsequence of offered bytes. A complete
stdout terminal may differ only in its three monotone pre-flush sink counters;
partial terminal content that cannot be verified stays unqualified/nonzero. `/dev/null`
has no invented delivered-byte measurement: it must report zero shedding and
zero timeouts. An absent terminal, nonzero observer exit, failed saved output,
malformed record or watchdog invalidates authoritative totals.

Slow-pipe pressure requires positive buffered bytes, kernel `POLLOUT`
nonwritability on the original owned writer while the observer is alive, and
actual product sink timeouts. A4096-byte atomic write can stall behind a169-byte
prefix in the4096-byte pipe; byte occupancy need not equal capacity. The harness
retains that writer only as a readiness witness, closes it at bounded observer
completion, and measures cleanup without waiting for EOF. The independent
regression proves an actual atomic write returns EAGAIN at this partial occupancy
and succeeds after draining the pipe; an empty/nonstalled pipe cannot qualify pressure.

The actual observer's held map FDs are inspected through `/proc/PID/fdinfo` and
`bpftool -j map show id`; EVENTS must really be a ringbuf with the selected
capacity. The CLI argument alone is insufficient. Binary/provider/caller inputs
are held and verified through the existing cgroup-trace process/pin helpers.

Cancellation acknowledgement is the observed stderr `cancel: loop exited`
marker; its reader-arrival timestamp is an upper bound on marker emission, not
a signal-handler timestamp. `run.rs` requests stop and calls
`begin_trace_identity_stop` before this marker. Report the measured<100ms target
separately from the trace normal-stop60s bound. This script does not qualify
Inventory's separate30s bound.

Finalization starts at the actual post-loop `p11scope: longrun:` stderr marker,
observed while the unreaped observer still lives. Buffered saved output cannot
reliably reveal COUNT_EVIDENCE before exit. A natural-stop finalization may
provide no cancellation acknowledgement, since the existing cancel marker is
emitted only for a signalled capture-loop exit. A missed final phase or absent
ACK remains NOT_RUN with a nonzero harness exit. The harness makes this missing
measurement explicit; it does not close mid-final cancellation acceptance.

Optional `--control` runs exercise child-held stdout, repeated signals, blocked
stderr or a real64KiB file-size limit. Pipe completion drains available bytes
after observer reap without waiting for EOF from the held child. A blocked
stderr channel cannot prove its own prompt acknowledgement, so
`--control blocked-stderr` measures it through the independent owned reporter
probe instead: it requires `--reporter-probe` (verified prebuilt helper) and
`--reporter-controls` (a `qualify_reporter_probe.py` summary), resolves the
actual reporter offset from the held candidate, attaches before the workload,
and accepts only a timely main-thread reporter entry with reconciled zero-loss
kernel counters. The same-source, same-candidate `none`, `handlerblocked` and
`wrongworker` controls must have actually passed; anything less stays NOT_RUN
without spawning. Kernel stderr pressure (positive buffered bytes plus
`POLLOUT` nonwritability on the original owned writer while the observer
lives), full stdout pressure/content accounting and probe-before-reap cleanup
are oracles, not waivers. File-size failure is visible as a negative I/O
control, never an authoritative saved trace. Regular-file kernel-blocking
interruption has no claimed hard deadline. Repeated-signal controls require
two actual deliveries to the original held observer; exit before the second
delivery is NOT_RUN.

Run only after the controller schedules the host lane and supplies matching
prebuilt observer and LP64 caller. On Fedora, read `~/AGENTS.md`, check load and
`sudo -n`, hold the host lease, stage under a new disk-backed
`/home/user/p11scope-operator-ID/`, and compare arrival SHA256 with build-side
values. No build, container, controller change or shared cleanup occurs here.
`softhsm2-util`, SoftHSM, Python3 and bpftool must already be available. Copy the
script plus its existing source dependencies (`qualify-cgroup-trace.py`,
`cgroup-trace-oracle.py`, `mapped-provider-pin.py` and this directory); no Cargo target is needed.

```sh
sudo -n python3 -I scripts/qualify-operator-output.py \
  --binary /absolute/staged/p11scope \
  --caller /absolute/staged/caller \
  --provider /usr/lib64/pkcs11/libsofthsm2.so \
  --source-revision EXACT_40_HEX_COMMIT --uid 1000 --gid 1000 \
  --cells 4M-file-none,4M-discard-none,4M-slowpipe-midcapture \
  --out /home/user/p11scope-operator-ID/NEW_RUN
```

Some provider builds construct their tables in `.bss` or on the heap, outside
file-backed scan discovery. For that case, explicitly choose `--manifest
/absolute/helper-output.json` (repeatable) after running the trusted, matching
prebuilt helper on the same held provider:

```sh
/absolute/staged/p11scope-discover --module /absolute/provider.so -o /absolute/helper-output.json
```

The controller verifies helper/source and arrival identity before execution.
The harness pins each manifest, checks its module path and provider object hash
against the pinned workload provider, forwards the explicit choice unchanged,
and records `discovery_mode=explicit-manifest` with input identities. The
observer validates the complete manifest/offset contract. This qualifies output
under explicit operator attestation; it does not qualify default discovery of
that provider. Never infer a passing capture from a zero-probe run.

Omit `--cells` for all27 requested cells. Select ancillary controls explicitly,
for example `--cells 4M-slowpipe-midcapture --control child-held-stdout`.
A blocked-stderr cell adds its independent channel explicitly:

```sh
sudo -n python3 -I scripts/qualify-operator-output.py \
  --binary /absolute/staged/p11scope \
  --caller /absolute/staged/caller \
  --provider /usr/lib64/pkcs11/libsofthsm2.so \
  --source-revision EXACT_40_HEX_COMMIT --uid 1000 --gid 1000 \
  --cells 4M-file-midcapture --control blocked-stderr \
  --reporter-probe /absolute/staged/reporter-probe \
  --reporter-controls /absolute/NEW_REPORTER_RUN/summary.json \
  --out /home/user/p11scope-operator-ID/NEW_RUN
```

`--dry-run` proves the same wiring without privilege: it pins every held
input, binds the controls summary to this exact source and candidate, resolves
the actual reporter file offset and runs the real stderr pressure witness
against a bounded pipe. It spawns nothing, writes nothing and exits nonzero
with a JSON error on any broken input. Use it before scheduling the
privileged lane; it does not replace installed execution.
The16MiB file bound limits retained input memory: each file read requests at
most LIMIT+1 bytes before rejecting oversize. It does not impose a disk quota.
Run output is temporary debugging material. The summary distinguishes PASS,
FAIL and NOT_RUN; every unqualified requested cell makes the command nonzero.
Nothing here qualifies G21 diagnostics wrap/cost, installed saved-inventory diff,
named trace or DR37 promotion. Those have separate controlled workloads.

## Prebuilt G21 demotion inputs

On the development build host, the following prepares four small artifacts from
unchanged `tests/fixtures/public-cli/demotion-ledger.c` and executes their native
phase/ledger/topology controls without an observer or privilege:

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp python3 -I \
  tests/fixtures/operator-output/prepare-demotion.py \
  --out /var/tmp/p11scope-ws-tmp/NEW_G21_INPUTS
```

The helper requires a new output directory, builds common/A/B/workload with the
same flags as `DemotionWorkload::spawn`, and prints temporary arrival-check
SHA256 values to stdout. It checks10 real calls (5A,2shared,1fence,2proof;
6successful and4argument-error returns), distinct provider roots, one physical
shared body and actual A-unmapped/B-retained topology. Temporary FIFO/ledger
controls are removed; the four needed prebuilt inputs remain. Neither these
native acknowledgements nor that ledger claim observer admission/coverage.

The test-only explicit prebuilt interface is `P11SCOPE_DEMOTION_PREBUILT_DIR=/absolute/directory`:
copy those four regular files into the test's existing private directory, then
reuse unchanged FIFO, mapping, callback and ledger assertions. The interface is implemented in
`DemotionWorkload::spawn`; it refuses relative, missing, symlink, nonregular or
nonexecutable workload inputs, with no fallback to compilation on bad opt-in.
Its Rust compilation and focused regression execution remain queued; this
helper native check alone does not qualify the Rust consumer or Fedora cell. No SoftHSM path
change is needed for this owned demotion fixture.

The current fixture permits one ten-call transition and caps64calls/256rows/
110seconds; it cannot produce live default-capacity diagnostic ring wrap. A
subsequent workload must create useful actual native reads/decisions rather
than call the recorder directly. Exceptional records include Withheld/Pending/
Rejected decisions as well as ownership transitions. One candidate is32physical
targets with distinct table pairs: ledger a changed count per pair and observed
pass, drive counted then shared-withheld phases until ordinary and exceptional
produced totals exceed24,576 and8,192, and finish with verified B recovery.
Actual record counts and truthful recent-history/reference status must be
checked after export; guessed records-per-call cannot satisfy either threshold.
Use the identical independently issued schedule with diagnostics disabled and
enabled, compare primary per-edge/API/count/loss facts, and report measured cost
separately. Fixture/runtime changes and installed execution remain open.

## Short startup-fence probe inputs

The same35prebuilt files also support an explicit `probe` workload mode:
exactly three A-only rounds,32real entry calls each, then an ordinary successful
stop. Provider B is never loaded and no shared/fence/proof phase is invented.
The independent native helper can check it with
`check_fixture(directory, counted=3, shared=1, probe=True)`. Its result explicitly
reports32physical caller/object pairs,96calls and three complete per-round
ACKs. Missing calls, foreign physical targets, wrong phases and unacknowledged
rounds fail. This native check establishes fixture behavior, not BPF attribution
or a startup-fence result; the short installed diagnostic probe is separate.

The new ignored selector is
`inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_startup_probe_lp64`.
It uses the same absolute `P11SCOPE_DIAGNOSTICS_WRAP_PREBUILT_DIR` input seam,
with freshly source-matched probe-capable C inputs, default1s production cadence
and a90s bound. Actual committed A1 triggers round2; actual A2, or A1 with
the exact caller-bound per-pair (1,2] startup-fence gap on all32pairs, triggers
round3. The terminal oracle accepts only genuine ordinary A3, or A2 with an
explicit per-pair AwaitingFence disposition and the third unit placed from
base2 on every pair. Both raw observation and exact retained-reference
checks are required. Each C round must finish before its next read PRE; that
read's POST must precede the next issued round. The probe exposes actual
read/decision facts, not a private checkpoint value. Compilation/installed
execution of this new selector remains separate from its native helper and
standalone validator checks; do not run the old long gate as a substitute.

## Paired default-ring useful wrap

The wrap oracle pins the max-accepting edge projection (Sol ORACLE ruling):
ordinary A reads 1, 2, 3 after rounds 1-3 and 400 after round 400;
all-32-fenced reads 1, 1, 2 and 399, with exact1-increments after. The
validated disposition (k of32pairs fenced) carries into final A400/399
expectations and strict paired comparison: both legs must share one
disposition and compare exactly equal, with no count replacement.
Per-pair physical reconciliation stays separate from the edge: eligible A
growth 12,800-k, withheld 8,288+k, terminal proof 660/base 659/staged 1
per pair with staged sum 32. A caller/object pair excludes function
offset, so the fixture provides one slot body per distinct physical object
(`libdemotion-common-00..31.so`):32genuine pairs, each advancing one unit
per round. The original ten-call installed control is independent.

A separately selected short pilot,
`privileged_native_lane_pid_diagnostics_three_round_accelerated_pilot_lp64`,
uses a scoped thread-local10ms scan cadence through the same actual
`run_classic_finalizing`/NativeLane/coordinator path and unchanged default
recorder. Production builds and all unselected tests retain the1s cadence.
The pilot prints declared cadence, real elapsed wall time, actual pass count,
raw read PRE/POST values and actual per-kind footer totals. Its evidence applies
to the declared accelerated engine cadence; it does not establish default CLI
cadence or disabled/enabled cost. The scoped override restores on normal return,
nested calls and panic and cannot alter another thread's test. Run this short
pilot before choosing any longer one-pair schedule; no guessed per-call record
multiplier or arbitrary900s expectation is an acceptance fact.

The new `diagnostics-wrap-ledger.c` physical entry-count fixture uses one PID,
two2.40 tables and32common ELFs with one distinct real entry body each at
slots4–35. Those bodies have the exact fixture type `CK_RV(void)` and return0.
This tests physical entry counting/ownership; it does not qualify PKCS#11
semantics, API behavior or the104-slot ABI. Review its table alignment through
the matching real manifest before live execution. The original ten-call
control remains.

Build/check on the development host:

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp python3 -I \
  tests/fixtures/operator-output/prepare-diagnostics-wrap.py \
  --out /var/tmp/p11scope-ws-tmp/NEW_G21_WRAP_INPUTS
```

The helper reuses the original C clock/VMA/hash/FIFO helpers, disables compiler
identical-function folding, verifies32distinct physical targets each against
its independently mapped common FD, and runs192real calls over a small
schedule. Its missing/duplicate/wrong-slot/clock/return/target/ACK controls
are fixture oracle checks. They do not qualify diagnostics or BPF ring wrap.

The ignored Rust selector is
`inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_wrap_and_primary_parity_lp64`.
Supply `P11SCOPE_DIAGNOSTICS_WRAP_PREBUILT_DIR` pointing at the controller-verified
35-file payload; no runtime compilation fallback exists. Match the prebuilt
Rust test binary/source and arrival hashes, hold the authorized host lane, and
use disk TMPDIR. A compiled test and the failed installed attempt do not qualify
the intended cell.

The bounded system wrap pair (cell 3) reuses the same schedule, fixture seam
and pinned A/B expectations under unfiltered system capture through
`inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_system_diagnostics_wrap_and_primary_parity_lp64`,
registered as a long cell in `scripts/run-privileged-lib-tests.sh`. Its export
validator requires a system header with an explicit null PID filter, owned-only
rows, and terminal pairs bound to the live-observed owned caller; its primary
validator admits the owned caller exactly once and rejects any foreign edge on
an owned module. Foreign-only presence is allowed, but any foreign diagnostic
record fails the cell, so run it on a quiet host. The same paired off/on
parity (one validated disposition, exact owned facts) applies.

Each disabled/enabled run issues exactly400counted rounds,258shared rounds,
then one fence and one proof round, each32per-slot calls. Native ACKs and an
independent per-slot ledger bind all21120calls. Each next counted round waits
for an actual committed production count milestone validated against
caller-bound gap evidence; each shared round consumes one observer pass with
ambiguity-disclosure checkpoints at power-of-two rounds; load-B remains
inside the existing observer callback between passes. Expected primary edge
projections are A400 ordinary / 399 fenced (k validated fenced pairs) and B1
(32 overlapping proofs in one publication). Per-pair physical reconciliation
from the schedule plus ledger gives 12,800-k eligible A growth, 8,256
shared-withheld, 32 fence-withheld and staged sum 32: 8,288+k withheld
entries over 21,120 physical calls. Actual32Bplacements (each edge_total 1,
proving the single-publication batching) and their selected withheld fence
prefixes must remain useful in the exported diagnostics.

Both default rings must really evict: CountObservation eviction proves the
ordinary ring filled, and OwnershipTransition/CaptureHealth eviction proves
the exceptional ring filled. These categories have fixed routing. Their actual
evictions establish produced lower bounds of24576+ordinary-evicted and
8192+exceptional-evicted, without guessing records per call or treating mixed
CountDecision totals as per-ring counters. All footer kind totals must reconcile,
references must report retained/not-retained truthfully and recent B placement
must cover all32distinct pairs. Partial/unrun/failed cells cannot pass.

Run the same independent schedule with diagnostics disabled/enabled and compare
primary count, entry observation, saturation/inflight, capture, presence,
coverage/loss and settlement facts after normalizing run-local IDs/timestamps.
Both legs must validate the same startup disposition; counts compare exactly
with no replacement. Each run has an explicit900s bound; the pair is
approximately22minutes at the current one-second pass cadence. Report actual
runtime/output bytes. Controlled RSS/CPU/performance cost is a separate T10 gate.

Readable stderr accepts either complete once-only main-control-thread marker:
`p11scope: cancel: loop exited on signal N after T ticks` or the truthful late
`p11scope: cancel: signal N observed during finalization after T ticks`. The
parser requires a complete newline, the independently sent first signal and a
finite unsigned tick count; duplicates and a foreign signal fail. The receipt
records phase and channel. Arrival is a conservative upper bound on main-thread
observation, distinct from handler delivery and cleanup completion. The late
marker does not change the recorded capture-loop end reason. These parser
controls do not qualify any new installed candidate or repair the remaining
partial stdout terminal-content cells. Blocked stderr now measures through the
separately reviewed, candidate-bound external reporter witness wired into the
E17 cell; installed execution of the witness, its negative dependencies and the
blocked cell itself remains open.

`reporter-probe.c` and `reporter_probe.py` supply the independent blocked-stderr
measurement, and `qualify-operator-output.py --control blocked-stderr` activates
it: the cell resolves the actual reporter offset from the held candidate,
binds the runtime IP through the actual original observer's executable mapping,
attaches the task-bound entry uprobe before the workload, and reconciles the
bounded perf ring (exactly one timely main-thread sample, zero loss, equal
enabled/running times) before the observer is reaped. The E17 loop detects
exit through the held pidfd on this control so the unreaped child retains
custody through that reconciliation. Build the small C helper on
the development host with `cc -std=c11 -O2 -Wall -Wextra -Werror`, supply it as a
verified prebuilt input, and keep its output in the owned disk task directory.
Fedora must not compile it.

The Python primitives resolve exactly one actual outlined Rust reporter symbol
from the held candidate, validate ELF64/x86-64 executable `PT_LOAD` file-offset
translation, and bind the runtime IP through the actual original observer's
executable mapping. Mapped device identity comes from a read-only mapping of the
held FD through `mapped-provider-pin.py`, separately from `fstat` identity (they
can differ on Btrfs). Missing/stripped/ambiguous symbols or unsupported ELF
surfaces are blockers; no offset may be guessed from another binary.

The helper's live API is `--probe EXE_FD PID BIRTH FILE_OFFSET LIMIT_MS`; the
controller must pass the original held candidate FD into the helper, retain the
unreaped observer and its pidfd, and derive all arguments from those primitives.
It checks the actual executable and birth, attaches a task-bound entry uprobe on
that FD/offset with inheritance disabled, and emits readiness only after enable.
The independent bounded perf ring records only IP, main PID/TID and
`CLOCK_MONOTONIC` time. Malformed, foreign, duplicate, lost or overrun records
fail. Final kernel event count must equal decoded samples, kernel lost count
must be zero, and enabled/running times must agree. Explicit bounded `stop\n`
closes the owned event; task-exit hangup does not supply an acknowledgement.
This creates no global tracefs probe and does not consume product EVENTS.

`--decode-fixture` is a separate unprivileged wire control and always labels its
rows `decode_fixture`; the actual witness validator rejects that mode. Local
controls also compile a small unrelated ELF with the same symbol spelling and
inspect its real PIE mapping to test resolution. They establish neither product
reporter presence nor a kernel attachment positive. The source-restricted real
reporter/first-signal binding (without guessing private Rust argument registers)
is covered by the matching-candidate controls in `qualify_reporter_probe.py`:
readable marker agreement, no signal, main blocked after handler only, wrong
ELF/process/thread, delayed observation and repeated signals. Of those, the
no-signal absence, the wrong-worker delivery and the main-blocked-after-delivery
negatives are hard blocked-stderr acceptance dependencies: the E17 cell refuses
to spawn unless all three actually passed on this exact source and candidate.
Kernel permission/PMU/symbol/clock/loss blockers keep the response unqualified.
Cleanup, pressure, output content and identity-settlement requirements are
separate oracles in `blocked_stderr.py`, applied without waiving any existing
E17 check.

The native ledger's target device is the lexical `/proc/maps` device. Its Rust
postcheck uses `p11scope_manifest::identity::kernel_maps_key_for` on the held
common-fixture FD, rather than the separate `map_files` stat device. A real
Btrfs short-probe attempt exposed this distinction after completing its native
milestones; that failed attempt remains a failure. The separate loaded-file
custody checks still compare opened `map_files` identities like for like. The
normal regression exercises an actual held-FD mapping and rejects foreign
device/inode/offset facts; no capture admission guard is changed.

Actual batch8's demangled symbol table is about28.5MB. Symbol resolution streams
that disk-backed output one bounded64KiB line at a time, with a64MiB disk-input
ceiling and the original10-second command bound. It never allocates the whole
symbol table. A larger-than16MiB healthy table, overlong line, oversized extent
and duplicate reporter are regression controls; these are symbol-reader facts,
not an installed probe positive.

`capture_inventory_pair.py` prepares real saved-input diff origins through the
actual Inventory CLI. It uses the original ten-call prebuilt fixture twice and
captures only A's first five entries in each independent window. A complete
committed armed/mapped edge releases `ready`; a complete committed actual count5
triggers SIGINT. The original remaining five calls and every mapping/topology
handshake finish after observer reap, with the original independent ten-call
ledger oracle. It keeps actual native JSON stdout/file parity, loss/retirement,
image/provider and held-path checks. New output is required. Its bound is30s to
the native milestone and the existing60s graceful observer stop, with owned
failure cleanup. Invoke with absolute `--binary`, `--prebuilt`, `--out` and exact
`--source-revision` in the authorized lane; no compilation occurs. Then pass its
`before/snapshot.json` and `after/snapshot.json` to the existing
`tests/fixtures/cross-command-drive.py --binary ... --before ... --after ...`.
The five-entry ledger control is physical-entry evidence; this path claims
neither semantic API counting nor continuity across these independent windows.
Source controls pass; the new capture adapter needs its actual installed run.

`qualify_reporter_probe.py` is a separate owned-control adapter for the actual
matching reporter, ordinary SoftHSM GenerateRandom caller and prebuilt helper.
It pins the actual candidate/helper/provider/manifest, resolves the actual
executable offset, verifies actual main-thread mapping/clock namespaces and
requires probe readiness before the signal. The observer remains unreaped with
its pidfd until final kernel counters reconcile. Readable and repeated controls
require a real matching marker and exactly one timely reporter sample; no-signal
requires actual zero samples/kernel events. Wrong executable/process controls
must refuse before readiness. `delayed` queues SIGINT while the owned process is
stopped, resumes after150ms and rejects its actual late reporter observation;
it explicitly does not claim handler delivery during that stop. Decoder/wire
loss controls remain separate from actual zero-loss kernel reconciliation.

Invoke only with the authorized lane and explicit absolute inputs, ordinary
`--uid/--gid`, exact `--source-revision` and a new `--out`. Source controls cover
its no-signal oracle; actual helper/PMU observations still need execution. Its
summary carries the top-level candidate identity so the blocked-stderr E17 cell
can bind the same bytes: `none`, `handlerblocked` and `wrongworker` must show
actual passes there before that cell spawns. Main blocked after actual handler
delivery and wrong actual worker thread therefore remain explicit acceptance
dependencies with explicit unqualified status until their installed runs land;
the blocked-stderr pressure/content/cleanup oracles themselves are implemented
in `blocked_stderr.py` and wired into the E17 harness and oracle.

Observer stderr is finished through the existing bounded Reader contract while
the original child remains unreaped, before any no-signal absence or final probe
verdict. An actual exited-child/gated-reader control proves that delayed queued
stderr cannot be accepted as empty merely because the process has exited.

The negative-control helper also supports the finite `callback` role through
`--probe-callback` with the same main-thread arguments. Python resolves only
`p11scope::run::install_stop_flag::{closure#0}` for this role. Its readiness
declares `role=callback` and samples have `kind=callback`; even a prompt,
otherwise valid callback envelope is rejected by the ordinary ACK validator.
Callback entry is delivery evidence only and precedes completed handler work.

`--probe-task EXE_FD TGID TID BIRTH FILE_OFFSET LIMIT_MS reporter|callback`
supports the proposed actual-worker negative. It holds the original
`/proc/TGID/task/TID` directory, checks its identity, actual status TGID/TID,
birth and candidate before enable, and rechecks a worker at final reconciliation.
Exited/replaced workers cannot qualify. The main path still uses TGID=TID and
retains original unreaped-child/pidfd custody through its final counters; an
unreaped main zombie no longer exposes `/proc/PID/exe`. Local controls use a real
live worker plus wrong TGID/TID/birth/directory and exited-worker twins, without
attaching perf. This API is preparation only: no worker or handler-blocked
acceptance cell is activated by these source changes.

`readiness-write-gate.c` is a negative-only preload, separate from every healthy
reporter control. It forwards real main-thread stderr `write`/`writev` bytes
first, recognizes only a complete positive readiness line, and then waits on
private nonblocking control/fact descriptors. It preserves write results/errno,
marks the inherited gate descriptors close-on-exec, and temporarily blocks
SIGINT only between `ppoll` calls. Each `ppoll` atomically restores the original
mask while waiting, so a signal cannot slip between gate entry and arming. The
original mask is restored on every exit. The gate releases on one `R` byte or
returns an error fact at its fixed15s bound. Its entered/interrupted/released
facts report actual main PID/TID and CLOCK_MONOTONIC; none is an ACK.

The unprivileged `readiness-gate-fixture.c` controls complete, split, writev and
real partial4096-byte nonblocking pipe writes, plus prefix/zero-probe/wrong-FD/
wrong-thread refusals. They check unchanged bytes, original errno/mask and
continued gating after actual handler delivery. These fixtures do not substitute
for the source-matched product callback/perf/marker negative or its150ms absence
interval. No product preload control is activated by this preparation alone.

The control adapter's `validate_handler_blocked` oracle reconciles both real
probe envelopes, exact entered/interrupted/released gate facts, same candidate
and main thread, one SIGINT, ready-before-send ordering, at least150ms before
parent release, and reporter entry at/after actual gate release consumption. A
complete matching readable marker remains required. The normal ACK validator
must refuse the late reporter. The redesigned `validate_worker_negative`
requires a prompt genuine worker callback (delivery-only, at most100ms after a
worker-targeted `tgkill`), exact entered/released main gate facts with main
gated at least150ms past the signal, zero worker reporter events with positive
equal enabled/running counters, and a real late main reporter entry after
release plus matching marker. Both the worker delivery and the late main entry
must fail the prompt-ACK validator, and the ordinary main zero validator must
reject the worker identity. Their healthy/mutation documents are validator
controls, not installed negatives. Actual adapters and source-reviewed execution
remain required before dependent blocked-stderr acceptance.

`qualify_reporter_probe.py --cells handlerblocked --readiness-gate /absolute/gate.so`
and `--cells wrongworker --readiness-gate /absolute/gate.so` select the new
adapters explicitly; the default six controls are unchanged, and a negative
cell is selected exactly when the gate is supplied. Supply the same
candidate/provider/caller/helper/manifest, ordinary uid/gid, exact source and
fresh output directory as above. Build the gate with the development-host C
compiler (`-shared -fPIC`) and verify its arrival alongside the actual helper
before use. A baseline preload or gate environment is refused. No preload is
applied to healthy observers or to the ordinary provider caller.

The handler adapter holds and checks the actual preload executable mapping,
waits for complete readiness and gate entry, enables both finite role probes,
performs20 real caller-ledger GenerateRandom calls, and sends SIGINT with
`tgkill(original_tgid, original_main_tid, SIGINT)`. It releases only after the
actual EINTR fact and150ms interval, then retains original observer custody
through complete stderr EOF and both final kernel counters. The worker adapter
anchors on same-process worker delivery instead of worker-side acknowledgement:
it holds main behind the readiness gate, issues ten genuine paced stimulus
calls (span-checked to cover at least400ms) plus a100ms settle so the pin sees
a quiesced observer, and pins the lowest-tid live non-main task with SIGINT
unblocked and caught, recording per-task disposition evidence. A parked-shape
tripwire then attaches a pre-signal reporter probe to the pinned worker and
requires the helper refusal (`kernel event/sample/loss/enabled counters
disagree`), zero samples and zero on-CPU delta; if a future product rethreading
schedules that worker, the tripwire flips loudly instead of silently passing.
Three probes attach (callback-on-worker, reporter-on-worker, reporter-on-main),
one `tgkill(original_tgid, worker_tid, SIGINT)` is sent, and the worker callback
must arrive within100ms while main stays gated at least150ms with no EINTR
fact. Both worker probes reconcile promptly while the pinned worker is still
alive; main is released, and its real reporter entry after release is required.
Mask, identity, lifetime and symbol failures refuse the cell, as do missing or
exited workers, with no replacement/retry. Receipt fields carry the anchor:
`worker_disposition`, `worker_sigint`, `tripwire`, `expected_callback`,
`expected_worker`, `callback_records`, `worker_records`, `worker_delivery_ns`
and the late `late_main_observation_ns`. All timeout/error cleanup releases a
negative gate before waiting for or signalling the observer. These adapters
still need source review and actual same-candidate execution before dependent
blocked-stderr acceptance. Summary `remaining` retains every causal control not
actually passed in that invocation, plus the still-open blocked-stderr E17 cell
execution on the same candidate.

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
stderr channel cannot prove its own prompt acknowledgement and remains
unqualified. File-size failure is visible as a negative I/O control, never an
authoritative saved trace. Regular-file kernel-blocking interruption has no
claimed hard deadline. Repeated-signal controls require two actual deliveries
to the original held observer; exit before the second delivery is NOT_RUN.

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

The same four prebuilt files also support an explicit `probe` workload mode:
exactly three A-only rounds,32real entry calls each, then an ordinary successful
stop. Provider B is never loaded and no shared/fence/proof phase is invented.
The independent native helper can check it with
`check_fixture(directory, counted=3, shared=1, probe=True)`. Its result explicitly
reports one physical caller/object pair,96calls and three complete per-round
ACKs. Missing calls, foreign physical targets, wrong phases and unacknowledged
rounds fail. This native check establishes fixture behavior, not BPF attribution
or a startup-fence result; the short installed diagnostic probe is separate.

The new ignored selector is
`inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_startup_probe_lp64`.
It uses the same absolute `P11SCOPE_DIAGNOSTICS_WRAP_PREBUILT_DIR` input seam,
with freshly source-matched probe-capable C inputs, default1s production cadence
and a90s bound. Actual committed A32 triggers round2; actual A64 or an exact
(32,64] public refusal triggers round3. The terminal oracle accepts only genuine
ordinary A96, or A64 with an explicit32-call AwaitingFence disposition and the
third32 placed from base64. Both raw observation and exact retained-reference
checks are required. Each C round must finish before its next read PRE; that
read's POST must precede the next issued round. The probe exposes actual
read/decision facts, not a private checkpoint value. Compilation/installed
execution of this new selector remains separate from its native helper and
standalone validator checks; do not run the old long gate as a substitute.

## Paired default-ring useful wrap

The current common-ELF fixture is **not acceptance ready**. Its first installed
run stopped at the original900-second bound after two32-call rounds: the native
counter reached64 while the public A count remained32, with the second range
withheld for unproven current physical ownership. The startup-fence explanation
is under investigation; production ownership guards must remain intact.
Separately, a caller/object pair excludes function offset, so32entry bodies in
one common ELF do not establish32diagnostic pairs. The schedule and pair/wrap
predicates below describe the intended cell and need revision before another
long run. The original ten-call installed control is independent.

The new `diagnostics-wrap-ledger.c` physical entry-count fixture uses one PID,
two2.40 tables and one common ELF with32 distinct real entry bodies at slots4–35.
Those bodies have the exact fixture type `CK_RV(void)` and return0. This tests
physical entry counting/ownership; it does not qualify PKCS#11 semantics, API
behavior or the104-slot ABI. Review its table alignment through the matching
real manifest before live execution. The original ten-call control remains.

Build/check on the development host:

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp python3 -I \
  tests/fixtures/operator-output/prepare-diagnostics-wrap.py \
  --out /var/tmp/p11scope-ws-tmp/NEW_G21_WRAP_INPUTS
```

The helper reuses the original C clock/VMA/hash/FIFO helpers, disables compiler
identical-function folding, verifies32distinct physical targets against an
independently mapped common FD, and runs192real calls over a small schedule.
Its missing/duplicate/wrong-slot/clock/return/target/ACK controls are fixture
oracle checks. They do not qualify diagnostics or BPF ring wrap.

The ignored Rust selector is
`inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_wrap_and_primary_parity_lp64`.
Supply `P11SCOPE_DIAGNOSTICS_WRAP_PREBUILT_DIR` pointing at the controller-verified
four-file payload; no runtime compilation fallback exists. Match the prebuilt
Rust test binary/source and arrival hashes, hold the authorized host lane, and
use disk TMPDIR. A compiled test and the failed installed attempt do not qualify
the intended cell.

Each disabled/enabled run issues exactly400counted rounds,258shared rounds,
then one fence and one proof round, each32per-slot calls. Native ACKs and an
independent per-slot ledger bind all21120calls. Each next round waits for an
actual committed production count or withheld-range milestone; load-B remains
inside the existing observer callback between passes. Expected primary totals
are A12800, B32 and8288withheld entries. Actual32Bplacements and their selected
withheld fence prefixes must remain useful in the exported diagnostics.

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
Each run has an explicit900s bound; the pair is approximately22minutes at the
current one-second pass cadence. Report actual runtime/output bytes. Controlled
RSS/CPU/performance cost is a separate T10 gate.

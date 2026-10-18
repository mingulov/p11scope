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
| stdout | regular file, `/dev/null`, genuinely full4KiB slow pipe |
| Cancellation | none, after acknowledged capture workload, during observed finalization |

The prebuilt `tests/fixtures/cgroup-trace/caller.c` fixture calls real SoftHSM
`C_GenerateRandom` and records each successful invocation separately on its own
ledger pipe. Provider setup precedes capture readiness and teardown follows
observer reap. The observer selects exactly this single-threaded PID; the caller
performs no fork/exec while attached. All issued calls must complete before the
first signal. Setup/teardown cannot substitute for the mandatory main calls.

The oracle keeps four units separate: independently issued/acknowledged API
calls; missing ordinary CALL event records; delivered stdout bytes; stdout shed
bytes. STATS entry/return counts equal issued calls. Raw CALLs equal rendered
rows; issued minus raw equals EVENTS loss in this controlled no-fork population.
Cumulative LOST records agree with final event loss. For readable stdout, complete
saved-trace bytes minus delivered bytes equals the final sink byte counter,
including terminal records. Lossless output must be byte-identical. `/dev/null`
has no invented delivered-byte measurement: it must report zero shedding and
zero timeouts. An absent terminal, nonzero observer exit, failed saved output,
malformed record or watchdog invalidates authoritative totals.

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
`cgroup-trace-oracle.py` and this directory); no Cargo target is needed.

```sh
sudo -n python3 -I scripts/qualify-operator-output.py \
  --binary /absolute/staged/p11scope \
  --caller /absolute/staged/caller \
  --provider /usr/lib64/pkcs11/libsofthsm2.so \
  --source-revision EXACT_40_HEX_COMMIT --uid 1000 --gid 1000 \
  --cells 4M-file-none,4M-discard-none,4M-slowpipe-midcapture \
  --out /home/user/p11scope-operator-ID/NEW_RUN
```

Omit `--cells` for all27 requested cells. Select ancillary controls explicitly,
for example `--cells 4M-slowpipe-midcapture --control child-held-stdout`.
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

The current Rust test always compiles these artifacts at runtime. The proposed
small test-only interface is `P11SCOPE_DEMOTION_PREBUILT_DIR=/absolute/directory`:
copy those four regular files into the test's existing private directory, then
reuse unchanged FIFO, mapping, callback and ledger assertions. That interface
is **not implemented** by this helper. The Rust owner must authorize and add it
before the existing test is usable on prebuilt-only Fedora. No SoftHSM path
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

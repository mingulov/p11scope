<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Known limitations (v0.7.0)

v0.7.0 answers "which application called the token": callers carry app
labels and a launcher chain, `inventory --system` binds usage on large
hosts, and a container image ships. The list below is current for this
release; the entries under Prior releases retain their historical context.

New to p11scope? Start here:

- [Quickstart](usage.md#quickstart) — a throwaway SoftHSM token and your first observed workload, in a few minutes.
- [Current release limits](#known-limitations-in-070) — the limits in force for this release.
- [Troubleshooting](troubleshooting.md) — what a refusal or an empty capture means, and the fix.

Live capture requires a Linux x86-64 host with usable `uprobe_multi` load and
self-link capability under the current credentials, normally Linux 6.6+ or a
working backport. Capability is tested, never admitted by version. Missing
capability refuses with `live capture unavailable` or `live capture did not
start` before capture, output changes
or a user workload starts, including explicit `--attach-backend singles`.
Safe scoped Singles remains available on eligible hosts; PID Multi additionally
requires a proven kernel PID filter. Help, version, inspect, discovery, saved
report read/diff and genuine `inventory --capture scan` remain usable without
the live gate. Non-Multi live support may be reconsidered around 0.9.x; no
release commitment is made.

Strict scale and speed limits apply to captures actually using Multi. Eligible
scoped Singles stays correct, finite and disclosed in `observation.attach` and
`evidence.attach_backend`; it does not establish Multi performance coverage.
Readiness bounds are disclosed harness parameters, never a cold-start SLA.

## Known limitations in 0.7.0

The following limits are new or changed in v0.7.0. Limits from
[Known limitations in 0.6.0](#known-limitations-in-060) below still
apply unless a subsection here says otherwise.

### Host-run observer cannot scan confined containers on SELinux hosts

On SELinux-enforcing hosts, an unconfined host process gets EACCES
reading `/proc/<pid>/maps` of `container_t` processes (measured
2026-11-11 on Fedora; the denial is dontaudit-silent, so no AVC is
logged), which covers the maps snapshots a host-run observer takes
of container targets. Prefer the container recipe on SELinux hosts:
`--pid=host` observer containers run as `spc_t`, which reads confined
maps and counts a confined victim exactly.

### Slot revival is same-target only

A retired attach slot revives only when the same provider target
returns: same-file churn reuses its slot, but a different newcomer
still consumes fresh lifetime budget, so distinct-file churn can
starve at the cap. A true retire-to-revive live cell (map, all
mappers exit, remap with same-index reuse) has not been run; 0.7.0
accepts the quarantine/revival probe plus unit twins as revival
evidence. General slot reuse across different targets is 0.7.1
work.

### Changed-evidence revival at a full budget drops ticks

A provider that returns with changed evidence while the slot budget is
full drops that tick's candidate until the provider leaves, instead of
reviving onto its retired slot. Rare, self-healing and fail-closed.

### Copy-up in-place truncation

A spanning capture now attributes both sides of a container copy-up,
but one shape stays a counted gap: a provider file rewritten in place
(truncate plus rewrite) while mapped reads `unresolved`, with the
disclosed gaps `Could not read file magic` and `no comparable pinned
identity`, single-instant edges, and nothing attached. That output is
honest; folding the undigested record into the same-key digested
record is 0.7.x work.

### Same-namespace subreapers shown as launcher

Init, the systemd user manager, container inits, pid-namespace
boundaries and kernel threads are never shown as the launcher. But a
subreaper in the same pid namespace (`tini -s`, s6/runit,
`--pid=host` runtimes) exposes no `/proc` flag, so the walk cannot
tell it from the process that launched the caller and shows its real
name honestly instead of guessing. Reparented callers report the
first-call parent or the counted `launcher exited before read` gap;
an init-only parent shows the systemd unit beside it.

### Per-key rows partial under heavy threading

Totals stay exact when many threads share one provider, but per-key
rows may stay partial: in the 8-thread sign cell, rows plus the named
race buckets (`unbound`, `key_join_lost`) equal the ledger exactly in
every run, while the single-thread control lands every call in one
row. Fixing the per-session key-join race is future work; read the
rows with the race buckets.

### System-wide captures stay PARTIAL under process churn

A `--system` capture on a machine with process churn reports PARTIAL
with `pid_descendant_gaps` and `{discovery subject, discovery
unavailable}` skips: that verdict is true (newcomers the observer
never admitted, or discovery deferred by racing exits), not noise.
Owned-provider counts stay exact with zero loss counters; exact
observation needs a quiescent scope. Initial loader arming also
finishes after the `capturing:` line on `--system` and `--cgroup`
captures the observer does not own; the report carries that window as
a counted gap only when the post-ready completion added coverage (a
new plan slot or a newly attached dynamic export hook), whose calls
before it attached were not counted. `--pid` captures arm before the
`capturing:` line and have no such window.

### Long captures go blind to new processes once the 262,144 identity budget is spent

Every process the kernel links consumes one of 262,144 lifetime
identity tickets, and v0.7.0 never recycles a ticket: the budget is
per capture, not per live process. On a host starting about 20 new
processes/s the budget lasts about 3.6 hours (about 14 hours at 5/s);
from then on every new process is invisible — its calls and fork
records are not captured, providers loaded after that point never
attach, and the newcomer queue stalls. The earlier measurements below
were taken on the old 16,384 budget and are kept for comparison: a 2 h
soak on fedora-sm1 spent it at +12–16 min with 168,027 refusals by the
end (11 late providers, live and calling, absent from that capture
while a fresh `inventory` attached them; 66 pending newcomers, oldest
wait 115 min), and a 6-minute desktop capture at 200 new processes/s
spent it 63 s after `capturing:` with 57,221 refusals.

Disclosure, all at default verbosity: the first refusal prints
`p11scope: kernel could not give a process an identity (N refused so
far; lifetime budget of 262144 identities spent); ...`; the loop-end
`p11scope: longrun:` line carries `identity_budget_exhausted[...]` and
`newcomer_queue_stalled[...]` findings with counts instead of `clean`;
the stalled `p11scope: timing: newcomer queue:` line prints; the
coverage line names `N process identity refusals (lifetime budget
of 262144 identities spent)`; the JSON report is PARTIAL with
`kernel_control.identity_unavailable`,
`identity_budget_exhausted: true`, and the `newcomer_queue` counts.

Workaround: bound the capture (`--duration`) or split by `--pid` or
`--cgroup`. Ticket recycling (bank/incarnation reuse) is planned for
v0.7.1. This supersedes the v0.3.0 DR-06 rate wording ("about an hour
at 5/s") for v0.7.0.

### A provider first loaded after capture start can attach late, or never, under churn

On a host with steady process churn (measured: about 20 new
processes/s), a provider first loaded by an already-running program
after the capture started can take tens of minutes to attach, or not
attach in that run at all. Admission serves a fraction of one new
process per second against about 20 arrivals per second, the refresh
queue stays full, and old waiters sit pending for tens of minutes.
Measured: one run counted 0 of 1,197 calls on the late provider, and
a scale cell joined 0 of 309,861 calls. Missed calls are shed with
exact counts and named causes, never silently dropped.

Avoid it with `--prearm-module PATH`, `run`, or a narrower
`--pid`/`--cgroup` scope. A scheduling redesign is planned for 0.7.1.

### Observer memory grows under heavy process churn

Fixed in v0.7.0: the capture file caches are now capped and the scan
pin layer is restored on every live rebind instead of stacking, so
observer memory no longer grows per short-lived process under churn.
Fifteen-minute churn soaks stay flat: peak (VmHWM) 368 MB on the musl
static observer and 322 MB on glibc (pre-fix peaks on the same soak:
710 MB and 1,837 MB).

Pre-fix measurements, kept for comparison: a long `--system` capture
on a host that starts and ends many processes used more memory over
time: about 35 to 50 KB of peak memory per short-lived process once
the observer's process-identity budget was spent. On a 5-vCPU, 10 GB
test VM with about 700 new processes a minute, the observer's peak
(VmHWM) was:

| Capture, 61 min | Peak during capture | Flat from |
| --- | --- | --- |
| `profile --system` | 906 MB | minute 55 |
| `trace --system` | 977 MB | minute 55 |

`trace` rose to about 1.13 GB once more at the end, while it wrote
its output. Twenty-minute captures on a 3-vCPU VM reached 650 to
720 MB. Whether and how fast it grew depended on the host and on the
callers' binaries: on the same 5-vCPU VM, callers built as non-PIE
executables kept the observer at 110 to 330 MB. v0.6.0 behaves the
pre-fix way. Plan for about 400 MB of observer memory for a
quarter-hour system-wide capture on a busy host; `--pid`, cgroup and
`run` captures of a quiet scope stay far below that. A formal
long-soak ceiling and bounded observer memory are still planned for
v0.8.0.

### Short-lived processes never scanned

Processes that exit before any scan examines them still count only in
the aggregate `short-lived processes never scanned` gap. Exit-time
verdicts (`mapped`/`unknown`, plus `STATIC HINT` identity hints under
`--track-short-lived`) classify them, but full per-caller call
attribution below the discovery floor is still planned.

### One-shot tools under `--system`: first use missed, later runs caught

Under `profile --system` (and `trace --system`), kernel file-open
learning catches the second and later runs of one-shot tools
generically (any vendor, any path, no lists): the observer watches
file opens, proves opened files from their own held bytes, and
attaches providers for all later processes. The learned provider is
listed with its path, the program that first loaded it
(`first_loaded_by`), and its missed first use as an unobserved
window; the capture stays `PARTIAL` with the fixed learned-file gap
row. The first use itself is still missed. Learning covers detailed
`profile`/`trace` under `--system` only (cgroup, pid, run, inventory
and counter scopes keep their existing gaps), needs privilege for
fanotify filesystem marks (a capture without it keeps today's gaps
and files the unavailable-learning gap), caps at 32 learned files per
capture (named aggregate refusal beyond), and cannot see providers
only on filesystems invisible to the observer's mount namespace (such
as a container-private tmpfs): those stay unknown, never guessed.
Wrap such tools in `sudo p11scope run --user $USER -- <tool>` (or
pass `--prearm-module PATH`) when first-run coverage matters.

### File learning sees only the observer's mount namespace

Learning marks come from the observer's own mount table
(`/proc/self/mountinfo`). When the observer's mount namespace differs
from pid 1's — a Docker or Kubernetes observer with `--pid=host`, or
the host watching rootless podman — filesystems outside the
observer's namespace are never marked, so providers opened only
there are never learned. The capture names this scope limit with the
`learned provider file` gap `file learning cannot see filesystems
outside the observer's mount namespace; provider files opened only
there were not learned` (never silent); in-namespace learning still
runs, and ordinary discovery and call counts are unaffected. Marking
through pid 1's mount table is future work.

### FUSE and other zero-fsid filesystems cannot be marked for learning

Since kernel 6.8, `FAN_MARK_FILESYSTEM` on a filesystem with a zero
fsid — FUSE mounts such as GNOME's gvfs and portal mounts — fails
with `ENODEV`, so those filesystems stay unmarked and providers
opened only there are not learned. The unmarked filesystem files the
unavailable-learning gap, which makes desktop `--system` runs
`PARTIAL` for learning only: ordinary discovery, call counts and
attribution are unaffected, and busy desktops are usually `PARTIAL`
already for process churn. There is no per-filesystem workaround;
wrapping the tool in `run` or passing `--prearm-module` covers a
known provider regardless of learning.

### Kernels before 6.12

Per the owner's 2026-11-08 ruling, specific pre-6.12 edge cases are
documented, not fixed: the pre-6.8 overlay maps-key split (a
provider's maps rendering unproven; callers mapping it may stay
unbound), the pre-6.8 pre-arm join shapes, the 5.15 birth race, and
speed claims only on `uprobe_multi` hosts (older kernels stay correct
and finite, never fast) all still apply — see
[Known limitations in 0.6.0](#known-limitations-in-060). The v0.7.0
measurements on those kernels follow.

Guest-suite runs of the 0.7.0 development build at commit
`79108a1c7` on kernels 5.15.221, 6.1.188 and 6.6.157, with a 7.3.1
control run. The guests are virtme-ng virtual machines. No 6.9 kernel
was available in the test cache, so 6.9.12 was not run and the
fixed-filter boundary there stays unverified; 6.7, 6.8, 6.10 and 6.11
were not run either. Each item below names its measured kernel range.
The `inventory --system/--cgroup/--pid` rows below predate the scan
fallback: at `79108a1c7` `--system`/`--cgroup` refused with the live
gate while `--pid` already exited 0 with the older `live capture
refused (...)` reason; current builds fall back to scan (exit 0) on
all three with the `call counts unavailable on this host` reason.

#### 5.15 and 6.1 refuse live capture

- What the user sees: every live capture except default
  `inventory --capture auto` — `profile` (including `--mode metrics`),
  `trace`, `run`, `inventory --capture native`, counter modes and
  `--select-endpoint` — exits 1 with one line and writes no report:

  ```
  p11scope: live capture did not start: attaching p11scope's probes failed (Invalid argument); run 'p11scope doctor' for host readiness, or use 'p11scope inventory --capture scan' or 'p11scope inspect --pid N' for a scan without capture.
  ```

  Native inventory scopes prefix the command (`p11scope: inventory
  --system: live capture did not start: ...` under `--capture native`,
  same for `--cgroup`). A `run`
  workload never starts: a guarded `touch` file was never created in
  the 5.15 test run, and on 6.1 the suite recorded the same failing
  checks with no report file either (the stderr text above is the
  retained 5.15 sample).
- Kernels/conditions: 5.15.221 and 6.1.188 behaved identically at
  `79108a1c7`: all 26 live-capture checks of the guest suite refused
  this way on both (predating the scan fallback), plus the `doctor`
  unready diagnosis (exit 1).
- Why: the functional host probe cannot link uprobe-multi (`Invalid
  argument`), so admission refuses before capture, output changes or
  workload start.
- Workaround: capture on a 6.6+ host with usable uprobe-multi, or stay
  with the scan-only paths below. The historical 5.15/6.1 startup
  figures in [Discovery timing](usage.md#discovery-timing-and-optional-offline-discovery)
  predate host admission; current builds refuse before any
  `capturing:` line.

#### 5.15 and 6.1 keep scan-only paths

- What the user sees: `inspect --pid N` exits 0; default
  `inventory --pid N`, `--system` and `--cgroup` exit 0 with a PARTIAL
  scan report carrying the gap `native usage feed unavailable`
  (`p11scope: native usage feed unavailable, continuing with the scan
  lane: call counts unavailable on this host: ...`);
  `doctor` exits 1 with the honest unready diagnosis
  (`Doctor: requested lane unavailable.` and `Next: use a host with
  uprobe-multi (normally Linux 6.6+) for live capture; ...`).
  [Live host capability](usage.md#live-host-capability-and-unsupported-environments)
  documents that `inventory --capture scan`, help, version, discovery
  and saved-report read/diff remain usable without live capture; that
  list was not re-measured here.
- Kernels/conditions: stderr samples captured on 5.15.221; 6.1.188
  recorded the same suite outcomes (`doctor` exit 1, same refusal
  set). No 6.1 stderr samples were retained.
- Why: these paths need no live probes; `doctor` capability-tests the
  host instead of admitting by version.
- Workaround: none needed. Gate order to be aware of: refusal shapes
  that need a running capture (FIFO `-o`, second-signal cleanup) and
  the startup-to-`capturing:` timing cannot be distinguished here —
  the live refusal fires first.

#### 6.6 runs live; one transient honest gap observed

- What the user sees: live capture works. The 30-check guest suite
  passed 23 of 24 runnable checks in the first 6.6.157 run and 24 of
  24 in the rerun (one smoke-only check plus five checks excluded for
  unrelated reasons — three cgroup checks with known product gaps and
  two 32-bit checks missing their guest prerequisite — sit outside
  the runnable set, identically on the 7.3.1 control). The `--pid`
  checks passed; which attach backend the probe selected was not
  retained in the saved reports. In one of the two runs a 25 s
  `--system` capture reported PARTIAL with exact counts and `1
  discovery step unavailable` (observation `lossy`/`skipped`); the
  rerun showed no discovery gap (observation exact, counts still
  3000; still PARTIAL for withheld attribution, same as the 7.3.1
  control).
- Kernels/conditions: 6.6.157 measured twice; 7.3.1 control clean.
  Kernel-specificity of the single transient is not established.
- Why: live capture is supported where uprobe-multi links. The
  transient left no trace beyond its own disclosed gap (the internal
  step is redacted from capture output by design), so no kernel cause
  is claimed.
- Workaround: rerun the capture if a `--system` window reports the
  `discovery step unavailable` gap with otherwise exact counts.

#### Already documented kernel-ranged items

These pre-existing entries also speak for kernels before 6.12 and are
not re-measured here: the pre-6.8 overlayfs maps-key split
(`provider's maps rendering unproven`) and the pre-6.8 pre-arm join
disclosures, the 5.15 key-operation coverage note, the 6.6 to 6.9.11
thread-exact pid filter with its automatic per-offset fallback (the
6.6.157 probe verdict was not retained in the saved reports, so the
fallback entry stands as written), and the historical 5.15
physical-identity and non-leader-exec qualifications under
[Kernels and backends](#kernels-and-backends).

### Pid-scope caller name after exec

`profile --pid` and `metrics --pid` name the target executable read
when probes attach; if the target execs another program during the
capture, `capture.caller` and the stderr `target:` line keep the
attach-time name while the new program's calls still count. Reporting
the end-of-capture executable is 0.7.x work.

### Key-tracking rate ceiling

In v0.6.0, keys created during the capture that never got a
label were summarised instead of listed: re-measured 2026-11-10 on
fedora.local (5 vCPU, kernel 7.2.9, SoftHSM 2.7.0-rc1), the published
v0.6.0, rc-5 and rc-8 all show 0 per-key rows at 6,250 calls/s for
60 s in the joint-10k-single cell. v0.7.0 lists such keys as per-key
rows labelled `unknown`: on the development host at 6,250 calls/s
for 60 s the cell shows one row with 187,499 started / 187,499
completed. The fedora and sm1 reruns are pending. On small VMs
where hook events are missed, the affected key stays unattributable
for the rest of the capture with a named gap (see [Missed hook
events leave one key unattributable](#missed-hook-events-leave-one-key-unattributable));
plain-path counts stay exact.

### Missed hook events leave one key unattributable

On small VMs the kernel can skip runs of the mapping hooks under
load. Each skip sheds the calls across it with exact counts and a
named cause. If the skipped window covers a key the observer was
proving, that key stays unattributable for the rest of the capture:
its later calls are counted in named `not attributed` reasons with
a named gap, while exact per-key rows continue for the rest. Carrying
a proved key across such a skip is future work.

### Key operations at sustained 6,000+ calls/s arrive late and can show count-only rows

Above about 6,000 key operations per second, joining calls to their
keys can lag by seconds (5-12 s seen at 7,500/s), and part of a
window can be recorded as exact named counts instead of per-call
rows: in one high-rate run about 16 s of calls showed as exact
`rejected demoted count` ranges (271,085 + 103,921 = 375,006 calls),
with the kernel ring losing nothing and every call collected and
joined. If the event ring itself overflows, the overflowed records
are counted and named as event loss; the affected calls are not
silently dropped. Sustained rates above 6,250 key operations per
second with exact per-call rows need the independent event reader,
planned for 0.7.1.

### `trace --system` and `profile` rate ceilings on a small VM

On a 3-vCPU VM (sm1, fedora guest, rc-8 build), `trace --system`
keeps every event up to about 10,000 calls/s with no loss; at
25,000 calls/s the observer is CPU-bound and the loss is named
(3,059,017 records lost at that rate). `profile --pid` and
`profile --cgroup` stayed exact with no loss at 10,000, 25,000,
50,000 and 100,000 calls/s; `profile --system` stayed exact with no
loss up to 50,000 calls/s (448,750 records lost at 100,000/s).

### Browser after a background caller: per-key tracking may not start

A browser started after a background PKCS#11 process is already
running can, intermittently, end without per-key operation tracking
(reported as `bootstrap_unavailable`). Its calls and counts are still
recorded. The fix is planned for 0.7.1.

### Warm Firefox already open: its token calls can go uncounted

If Firefox is already running when a `--system` capture starts, its
sandboxed children can make the softokn provider's identity ambiguous:
the scan sees a second physical identity for `libsoftokn3.so` through
a jailed child view, the collision group is refused (`physical
identity is ambiguous; the collision group was not attached`), the
module never attaches (verbose: `module has no comparable pinned
identity; it was not attached`), and the capture counts 0 calls on
it. Measured: the release candidate counts 0 softokn calls with
Firefox already open, while the same workload counts about 1,280
calls without the defect. The run still reports PARTIAL with the
named gaps. Workaround: start the capture before opening Firefox; a
Firefox started after the capture begins attaches and its calls count
normally (the per-key tracking gap above can still leave it without
per-key operation tracking). A fix is in review; if it misses this
release it lands in 0.7.1.

### Main thread exits first: a later library load can go unreported

p11scope watches library loads per process. When a program's main
thread ends on its own (`pthread_exit`) while its other threads keep
running, p11scope can stop seeing that program's later library loads
and counts a lost load link (`task_uprobe_link_losses`). In `--system`
and `--cgroup` captures the count is withdrawn at capture end if the
whole program has exited by then and p11scope recorded no
library-load, function-list or exec event from any of its threads
after the main thread ended, because an ordinary exit looks the same.
PKCS#11 calls do not count as such an event. So a provider first loaded
in that window can go unreported, even if the threads kept calling
providers p11scope already watches; those calls are still counted.
`--pid`, `run` and selected-endpoint captures keep the count, and so
does any capture that lost or dropped discovery records. The count can still over-report in a few cases
(a thread's record racing the exit, an unknown exit order). Seeing
those later loads needs a kernel-side witness and is 0.7.x work.

### Multi attach steps stall the loop; detach can outlast the report

A 4 s Multi attach step can delay lifecycle-ring service under heavy
exec churn. Detach may finish after the report on desktops with very
many mapping processes.

### Test-only: overlay-witness flake

`witness_every_keep_reason_keeps_todays_window_when_mapped` fails
under full-suite load only (panic `prearm_witness_tests.rs:194`:
`ftrace keeps today's window`, `None` versus `Some([50..900
PreAttach])`): the fixture's post-load refresh missed the mapping.
The same binary passes in isolation and on rerun, so this is a test
fixture race, not a product regression. The fix (make the fixture
wait for the mapping observation) is 0.7.x work; a gate failure still
counts.

## Known limitations in 0.6.0

The following limits apply to the v0.6.0 release. Rate, latency and
start-up figures below were measured on the pre-freeze integration
lane; the [Qualification record](../CHANGELOG.md#qualification-of-this-release)
names the source SHA behind each check the release rounds re-measured.

- Key operations sustain 6,250 calls/s for 60 s with exact per-key rows
  and no capture loss in every measured run at that rate; plain call
  counts stay exact at 10,000 calls/s for 60 s without
  `--key-operations`. With key operations on, a lossy run's call
  counts can fall short; every lost record is counted and named
  (one call writes up to two records). Above 6,250 calls/s (measured
  with the earlier 16 MiB ring; the 32 MiB ring since v0.7.0 has not
  been re-measured and can only overflow later) the event ring can
  overflow between reads and key-operation tracking ends with a named
  gap. 10,000 calls/s with key operations
  is not yet sustained. Re-measured 2026-11-10 on the reference host,
  v0.6.0, rc-5 and rc-8 all show 0 per-key rows at 6,250 calls/s for
  60 s; the cause (keys created during the capture that never got a
  label were summarised instead of listed) is fixed in v0.7.0, which
  lists them; see [Key-tracking rate ceiling](#key-tracking-rate-ceiling).
- Key-operation rows lag their calls: p99 from call return to visible
  row is about 1.6-1.9 s in quiet runs (1,624 ms and 1,895 ms in two
  qualified 60 s runs), against the 1.5 s target; under host load it
  rises toward about 4 s.
- Key-operation tracking may not start at all in about 1 in 4 runs (3
  of 12 measured cells, at every call rate): no birth is offered for
  the tracked process, reported as `joint_birth_unoffered` with "Joint
  birth unavailable; retained S1". Plain call counts stay exact in
  those runs; re-running the capture is the workaround.
- On busy hosts the kernel can skip re-entrant runs of the mapping
  hooks; each skip raises a new fault era. Calls across the skip are
  shed with exact counts and a named cause, affected instance rows read
  `uncertain`, and key operations the observer cannot attribute with
  certainty are counted in named `not attributed` reasons while exact
  rows continue for the rest.
- A call from an untracked process that is still in progress when key
  operations are sealed cannot be accounted for, so it is counted in
  named `not attributed` reasons instead of waiting for the run
  deadline. Exact per-key rows continue for operations the observer can
  attribute with certainty, and the plain per-call counts are
  unaffected.
- The memory of refused processes holds 16,448 entries. Past that,
  every new untracked caller keeps the plain per-call view with the
  same `joint_image_refused` reason; processes refused earlier stay
  refused and tracked callers are unaffected. At one new foreign
  client every 3 seconds that is about 14 hours of capture.
- The ledger that settles transient admission-deferral scan refusals
  when an endpoint is later admitted likewise holds 16,448
  endpoints; entries for admitted tasks are forgotten as their tasks
  retire, while entries for tasks that never admitted stay until the
  cap. Past the cap (or for a caller whose process start time could
  not be read, so its generation is unprovable), deferral refusals
  stay counted and named per reason in `refused_endpoints` even if
  the endpoint later admits with complete data: the run over-reports
  refused endpoints rather than risk hiding one. A run that hit the
  cap says so on its stop scan-refusal gap ("N not settled: ledger
  full").
- About 0.5% of `run` captures on overloaded hosts miss startup
  entirely: the kernel delivers neither loader nor lifecycle records
  for the whole run, so the child runs unwatched. Those runs report
  PARTIAL (incomplete) with the named cause "loader BPF delivery
  failure suspected"; no run reports a wrong count. No miss was seen on
  quiet hosts (0/120 on Fedora).
- A child process can use a provider before it is watched: calls made
  before the watch starts are missed, and the affected watch reads
  `unknown` with reason `use_before_admission`; the JSON also carries a
  `before_semantic_boundary` gap ("physical provider use preceded first
  observed semantic registration") and the late provider's unwatched
  window. Affected runs read PARTIAL. Hold the child with `run --pause
  auto` or keep it alive past attach.
- `run` captures the command with its child processes: the child is
  placed in a dedicated cgroup under the observer's own cgroup before
  release, so fork/exec children, `sh -c` and `env` wrappers and
  double forks are born in the cgroup. Only the direct child is
  paused; descendants are never paused. Killing the observer with
  SIGKILL while the child is held stopped writes no final report (no
  handler can run); the child resumes when the observer dies, through
  its SIGCONT parent-death signal. A pause stop a probe queued in the
  instant the observer dies is not ruled out; check the child with
  `ps` after such a kill.
  A descendant that loads an
  already-attached provider file is observed from its first call, but
  a short-lived descendant that cold-loads the provider can retire
  before admission: its calls are then missing and the run reports
  `PARTIAL` with `pid_descendant_gaps`. Pass `--prearm-module` for
  the provider so cold grandchildren are hooked from their first
  call. (`sudo`/`setuid` inside the command cannot elevate under the
  child's `no_new_privs` hardening, so privilege hops are not a
  supported shape.) Descendants that retire between admission passes
  count `pid_descendant_gaps` like cgroup scope (same lossy-by-design
  rule: exact counts with `PARTIAL` observation when providers are
  prearmed or already attached; unprearmed cold grandchildren may show
  missing calls), and descendants still alive at run end are handed
  back alive, disclosed by count (`run_tree_handed_back` with a `run
  process tree` gap). The run still ends with the direct child's exit.
  Without permission to create the cgroup, `run` degrades to its exact
  child with a named gap. `profile --pid` still observes exactly the named process, never
  its descendants: a fork/exec child, `subprocess` worker, or
  `multiprocessing` spawn child that loads a provider gets no probes
  and its calls are entirely absent, however long it lives. This is the
  exact-PID scope (discovery sweeps only the named PID and probes bind
  to that process alone), not a timing race. Capture such workloads
  with `inventory --system` (or `--cgroup`), which admits short-lived
  processes, or run the leaf command that loads the provider directly
  under `run`.
- Chromium as an owned `run` child needs a short `TMPDIR`. Chromium
  itself aborts (SIGABRT, exit 134) when its
  `$TMPDIR/org.chromium.Chromium.XXXXXX/SingletonSocket` path exceeds
  the 107-byte Unix socket limit, with or without p11scope, so a deep
  `TMPDIR` makes every launch fail. With a short `TMPDIR`, a
  2026-11-09 check (Fedora, kernel 7.2.9, headless Chromium 1248 on
  `about:blank`, no `--module`) completed 4 of 4 runs under the default
  `--pause auto` and 4 of 4 under `--pause never`. The `auto` runs
  report `pause: partial`: one of their six pause cycles ends at its
  deadline while the engine is still applying the attach batch
  (`pause_diag=deadline_during_engine_apply`), so that cycle's load is
  not protected. Flows with a registered provider were not rechecked;
  the browser cells capture Chromium attach-driven.
- Container providers carry named unproven cases: the container checks
  use one kind node, and multi-node clusters, CRI-O and the cgroupfs
  driver are not exercised. Docker shared image layers and copy-up, the
  kind DaemonSet, attach into a pod, a pre-attached provider in a new
  pod, a Knative pod scaled from zero, and a node-wide late provider (a
  reported boundary) were the exercised shapes in the v0.5.0 campaign;
  the 0.6.0 re-proof is a candidate gate. A process that loaded a
  provider before a copy-up reads `unknown` with the
  `original_file_unproven` gap and its later calls are missed; restart
  such processes.
- The overlay-identity witness proves up to 8 refused callers per
  deep scan and per kernel-route sweep pass, and up to 1024
  refused callers per no-route sweep pass (single-shot
  inspect/inventory sweeps prove through the same witness under the
  1024 budget): past each route's budget, callers take turns across
  passes while the rest keep the named loss (`original_file_unproven`
  for deep scans, `overlay_kernel_unavailable` for sweeps). While a
  caller waits for its turn, its edge reads uncertain and its in-flight
  operations end as unknown.
- Strict speed claims apply only on kernels with working uprobe_multi,
  normally 6.6 and newer: the rate and latency numbers above were
  measured there. Older kernels stay correct with a finite stop but are
  not speed-qualified; there `inventory --capture auto` falls back to the
  scan lane (exit 0 with modules and callers, counts unknown under the
  `native usage feed unavailable` gap), while `profile`, `trace`, `run`
  and `inventory --capture native` refuse with a `live capture ...`
  refusal (`unavailable` or `did not start`). A short `--cgroup` fallback
  there publishes its completed first pass like `--pid`/`--system`
  (modules and callers shown, counts unknown); only a run whose
  deadline already passed before the first collection starts still
  reports the empty view with the `no complete collection pass` gap.
- Per-key rows cover operations that start after the attach.
  Attaching to an already-running process (for example a running
  Firefox or Chromium) works: operations that start after the attach
  get rows, earlier operations are counted in named gaps, and a key
  first seen before the attach reads `type unknown (not established
  while observed)`, never dropped. Starting the observer first
  (`--system`, or
  a cgroup scope) and then launching the application also works; no
  restart is needed either way. Call counts, mechanisms and the rest
  of the inventory still work in every case.
- Inventory accepts `--max-endpoints` from 1 through 131072, with a
  32768 default, so a host with several p11-kit copies (about 20K
  endpoints) is covered by `inventory --system` with no flag. This is
  a finite, capture-lifetime physical endpoint budget; unloading does
  not refund IDs. The values are measured on uprobe_multi hosts (the
  only hosts where live capture runs): the endpoint maps cost 8 bytes
  per endpoint of payload, attach costs about 256 bytes of kernel
  memory per attached endpoint, and per-hit cost does not grow with
  the endpoint count. Detailed per-call capture keeps its separate
  2,112-slot budget (512 with `--no-default-features`) and counter modes keep
  their 8192 planner ceiling, because their per-CPU maps scale with
  slot count times CPU count and are not equally cheap to raise.
  Caller-pair, discovery-owner and work limits stay separate, and
  selecting a larger endpoint budget does not increase them.
- Counts seen through the p11-kit proxy can include the backend's
  own internal calls, and can miss calls made before the observer
  attached. Direct providers are exact. For exact counts, point the
  capture at the backend provider directly.
- The key-operations section reason can latch `authority_lost`,
  rendered "per-key tracking stopped", after a watchdog trip or
  disposed staged history, even while exact per-key rows continue
  beside counted loss. The latch names the loss, not a stopped view:
  read the rows and the `not attributed` counts.
- `inventory --pid` leaves a one-shot caller's use unattributed: a
  caller that uses a provider and exits between two passes shows no
  edge entries while its calls fold to the module as unattributed
  use. Use `profile --pid` for one-shot flows (full entry below).

Under a saturating multi-threaded flood (twelve threads spinning PKCS#11
calls for 5 s, about 190,000 calls/s), the userspace drain can lose ring
events on small hosts: on a quiet 3-vCPU sm1 host the twelve-thread
flood lost 356,859 of ~976k events, disclosed as `event_loss` with
PARTIAL coverage, while the same-volume six-thread flood completed
947k calls with zero loss (sm1 live-triage measurements). vng guests
(6.6/6.12/6.18/7.0/7.3.1) hold the twelve-thread flood
in the same runs, except one v6.12 guest `mt-exact` failure observed in
the same campaign — loss-free at twelve threads is typical off the
small host, not guaranteed. For exact captures under a synthetic flood,
size the workload to about two producer threads per CPU; no
real-application rate is claimed.

Measurement modes aggregate on eligible LP64 hosts, subject to independent
feature/load limits. A refused counter-mode or Detailed start exits nonzero
without writing a report or starting the requested `run` program. Latency
banks grow with
the host possible-CPU count and refuse with `counter-memory-limit`
past the per-capture kernel-map memory cap on hosts with many CPUs.
Counter banks share one 65,536-entry return-value pool, and
saturation is reported in the collection health. One bank's unreadable cell
gaps only its slots with a `bank_gaps` count, and a health or kernel read
failure degrades the evidence with a named flag. A gap read publishes the
last good values (stale) until the next exact read telescopes, except the
first read of a generation, which publishes its current rows with zeros as
unknown for the failed slots; either way the report reads PARTIAL.
A legacy aggregate read
that cannot read one slot's counters reports zero for that slot as unknown
with a `legacy_collection` gap, and one unread kernel-evidence cell reads 0
as unknown with its name; the rest stays exact and the report reads PARTIAL.
Per-call
profile/trace capture stays fixed at 512 attach slots (2,112 only in
the WIDE source build). A recognized forwarding layer (such as
p11-kit's proxy closure array, about 6,530 endpoints per copy) is
decided after all providers in every scope and admitted by what it
publishes: only tables with publication evidence (a live
`C_GetFunctionList` / `C_GetInterface(List)` return, interface linkage,
a manifest, or export agreement) attach, taking no heuristic slots, so
the layer can never crowd out a real provider. Calls it forwards are
counted at the attached backend providers, named with counts on the
gap line; calls the layer answered itself, including its errors,
appear only on the separate forwarding line, and one layer call that
reaches several providers counts at each. When nothing is published
yet, a named gap says so and the capture continues. An operator-named
layer (`--module
<path>`) is the sole exception: it keeps a reserve-capped
leading-templates prefix, because a remote client's tables are handed
out before any export probe can observe the return (costs of covering
the layer are measured in
`docs/notes/2026-11-01-p11kit-proxy-layer-measurement.md`). Under
inventory, counter and broad admission a closure array that does not
fit whole is refused whole with its demand stated.
An ordinary provider that does not fit whole in a shared-scope Detailed
capture is admitted on the leading-tables prefix that fits,
with a named `provider_prefix` partial gap stating attached versus
needed endpoints; it is refused whole only when not even its strongest
table fits within its reserve-aware budget, or when its corroborated
(published) tables together do not fit — published tables stay atomic,
since spilling one as uncorroborated would mislabel corroborated
evidence. Inventory admits whole within its endpoint budget (32,768 by
default on `inventory --system` with uprobe_multi, up to 131,072 with
`--max-endpoints`), and counter and broad admission keep their
complete-union whole rule.

Endpoint selection (`--select-endpoint` with `--mode metrics` and
`--counter-mode`) details one function from the broad counter's own
cells between a selection-time read and the close read. It resolves
on `--pid` and owned-`run` captures only; `--cgroup` and `--system`
refuse by name. The name resolves once at start; a provider loaded
after start needs `--prearm-module <provider.so>` (with `run`, usually
required). If the watched process replaces itself (exec) between
the two reads, the slot retires, the close boundary cannot be proven
clean, or discovery ring loss, read failures, or truncation grow
inside the window, the detail is withheld with a named reason while
aggregate counts continue. A leader exit that is the last lifecycle
record ends the window cleanly and the detail renders the calls made
before the exit. Loader scans left unfinished by the exit itself, and
loader rejects the exiting process explains, are counted apart as
exit-only and do not void the detail; other truncation still counts,
including loader rejects the observer cannot tie to the exit. Those
withhold the detail as `broad_stopping`, so an owned `run`
child that loads and exits at once may still void intermittently (about
1 in 10 runs in local testing). A child that keeps running for a
few seconds after its provider loads is unaffected (measured with a
3-second gap). Each bracketing read samples the return-value table
before the slot counters, so a call that completes between the two
passes leaves a torn window and the detail is withheld as
`broad_plan_topology`; against a busy `--pid` target this can withhold
most windows.
With `run`, a host whose kernel and userspace monotonic clocks cannot
be compared (a time namespace offset, or a kernel without the time
namespace files) refuses the selection as `promotion_scope_unsupported`.

A capture follows at most 256 provider loads and tracks at most
262,144 program images; past either limit the report carries a named
gap and reads PARTIAL (full entries below). Stopping a very large
capture can refuse its fixed 384 MiB graph pool: the stop ends as a
finite incomplete stop, with retired objects still reported attached
and the measured peak disclosed (full entry below).

A timed run shorter than the first full pass (5–10 s on a busy
host) still publishes that first collection on every scope: pass 0
runs to completion past the deadline, then the run ends. Modules
and callers are shown; on a live lane counts read `not attached`
with a `stopped before attach` scope gap, since no attach starts
after the stop. Only a run whose deadline already passed before
the first collection starts reports 0 callers with the `no complete
collection pass` gap and one informational stderr line. An operator
stop during a `--cgroup` pass-0 collection still cancels it
promptly, so Ctrl-C stays responsive: that run publishes the
callers scanned so far with the `collection incomplete (stopped by
operator)` gap (scan-only, counts not attached, no completeness
claimed), while `--pid`/`--system` finish the in-flight collection
and keep it scan-only. Overrun past a deadline is bounded by one
full bounded pass (cgroup walk limits: 1M work units, 4096
directories, 65536 members, 8 MiB total, 70 FDs; at most 128 pinned
processes; deep-scan cap default 32; no wall-clock cap; a hung
filesystem call still blocks like before). The first
calls a provider makes after a late load can be missed before its
probes land, and use before admission voids that watch (`unknown`,
`use_before_admission`). Very short-lived callers can stay unbound or
unattributed (see below); the `--track-short-lived` opt-in mode
classifies their gaps into static-linkage hints and exit-time mapping
verdicts instead of leaving bare counts, but full call attribution
for them is still planned.
Short-lived processes missed at system scale are counted only as gaps
(`pid_descendant_gaps`); their calls through attached providers still
count. A process whose main thread had already exited when the capture
first met it is not admitted, and its calls are not counted. The
`short-lived processes never scanned` inventory gap counts only captures
with the native EXEC lane; scan-only captures cannot count inter-pass
deaths, and processes already gone at first contact are never admitted.
Every process admitted after the initial membership sweep — a fork child,
an ambient fork, any newcomer — and every leader exit that matches no
admitted generation counts `pid_descendant_gaps` and keeps the observation
lossy, even when the owned counts prove exact. The gap is a true
disclosure, not an over-broad one: between the process's birth and the
observer's admission (and loader arming), it could have mapped, used, and
unmapped a provider the observer never attached, leaving no trace the
later scan could find. A capture whose scope forks, or a `--system`
capture on a machine with any process churn, is therefore inherently
`PARTIAL` on this axis; exact observation needs a quiescent scope. Loader
hits are different: a load whose record resolves benignly — accepted,
scan complete, no new provider, no suspicious close — is counted in
`loader_discovery.benign_hits` and no longer gates exactness. What still
gates it is an unaccounted hit: a new provider (a true late window), a
close nobody's mapping explains, an incomplete scan, or a lost record.

If a process exits while loader inspection is still pending, the report may
include a `discovery_truncated` gap. Unread metadata remains unavailable;
call coverage is evaluated separately.
A post-exec instance whose semantics cannot be proven appears as a
named gap (`gap [instance semantics refused] instance_unproven`), not
a joined instance. If a multi-threaded program unloads and reloads a
provider at the same address between two scans, the capture shows one
instance; per-caller call totals are unaffected. Finalizing and
re-initializing inside one load (a `C_Finalize`/`C_Initialize` cycle)
is also one instance.

v0.6.0 reports key operations when opted in with `inventory
--key-operations` and rows populate: the `key operations:` line then
counts completions per operation category, and the JSON report carries
the rows under `object_observations`. Without the opt-in, or on a build
without the journal object, the line reads `not reported (per-key
tracking is off)`. With `--key-operations` but a refused subset, the
line names the rerun or check remedy; when the journal start itself is
refused, it names the request and the cause (`requested, but per-key
tracking did not start (<cause>)`). A linked capture whose tracking
never starts reads `not available — per-key tracking never started, so
no key can be named yet`. Mechanisms and API results are reported as
before. An ordinary native-retirement refusal during a `--manifest`
capture ends the first stop with an incomplete report and a nonzero
exit. Uncertain native ownership stays retained and replacement
admission stays blocked; the refusal is not proof of clean detach.

In v0.6.0 release builds, key operations use the per-key-tracking opt-in
`p11scope inventory --key-operations` (default off),
with the following birth-marker limits. If any watched call of a program is
not fully captured — the call ran outside the selected scope, its binary
interface was refused, or the call was dropped (a lost identity, start record
or ring slot, or a thread killed in the middle of the call) — the operations
the observer cannot attribute with certainty are counted in named `not
attributed` reasons, and rows resume at the next clean point. The program's
call counts and per-function summaries continue throughout. For scope
misses, widen the scope (`--cgroup` or `--system`); otherwise re-run the
capture.

Each recording can newly cover only a fixed number of programs (about 16.8
million). Once that budget is spent, programs already in the report keep their
key-operation rows, but programs started afterwards get none. Call counts
continue for all programs. This happens only in very long captures or under
extreme program-start churn; ordinary runs never reach the budget. Split the
capture into shorter runs to stay under it.

On 5.15 kernels, a program that starts while the kernel is momentarily busy
recording it can miss coverage entirely: its later calls are counted but never
joined to key-operation rows. This loses coverage for that program only; it
never produces a wrong row. Re-run the capture so the program starts cleanly.

Under `--pid`, only the named process contributes key operations; it stays
covered when it replaces itself with a new program in place (an exec keeps the
same process). Programs it starts while the capture runs (children) are not
observed, even when they call the same provider. One narrow exception, with
`--attach-backend singles` only: a child started with vfork (as with
posix_spawn) that still shares the target's memory and calls the provider before
starting its own program is marked as not covered. With `multi` the kernel drops
such a call before p11scope sees it, so the child is simply not observed.
(`auto` can pick either.) Neither case is verified live yet.

At very high call rates the kernel's event ring of a native inventory capture
can fill before p11scope reads it. The kernel then refuses new records but
counts them, and p11scope reports every refusal: the report carries a
`native capture events lost` gap, the stop line carries a separate `lost`
count, and `observation.semantic_capture.events_lost` holds the same total.
These records are counted only there, never in `unrouted_returns` or in the
stop line's shed count. If p11scope cannot read the kernel's counter, the
report carries a `native capture events loss unknown` gap instead, and
`events_lost` is never lower once the counter has been read; until a later
read succeeds it may undercount the real loss (the kernel's counter is
cumulative, so that read restores the exact total). Two
limits apply. Prompt draining of a full ring applies only when the capture has
fallen back to its older path (after a `joint machine unavailable` gap), so it
does not raise the call rate an ordinary capture keeps up with. The counter
also counts records, not calls: under `--cgroup` or `--system`, a refused
process-start (fork) record counts as one lost call, so the reported loss can
be higher than the number of calls actually lost, never lower.

A `semantic admission deferred` gap (reason
`semantic_unavailable:no_receipt`) is a note, not a loss. It means a
discovery pass could not yet scan a caller (usually one that has made no
provider call the kernel has seen yet), so key-operation tracking for that
caller starts at a later pass. Calls the caller makes in the meantime wait for that pass and are
counted. If the caller is never admitted (for example, it exits first), each
call it made is shed and reported under the separate
`semantic calls unrouted` loss gap. Waiting calls also share one
capture-wide queue of 1,024 calls: past it, later calls are shed even
while their caller is still waiting to be admitted, and are reported in
the same gap (`pending_capacity=N`). Every other
`semantic admission refused` reason still marks a loss.

Under `--key-operations`, such a shed call ends a caller's key-operation
tracking (`joint_seal_h3_loss_history_loss`) only when p11scope cannot prove
it came from a different process. A call whose kernel-assigned process
identity differs from every caller being tracked is reported under the
lane-wide `semantic calls unrouted from other callers` gap (repeated
drains sum into one counted row per bindings count) and still counts in
the stop line's shed count, but it no longer ends tracking for the other
callers. A call
without that identity, or from a tracked caller (including after its exec),
still ends tracking as before. Calls shed before any caller is tracked are
reported at once in the `semantic calls unrouted` gap (`with 0 bindings`),
and their effect is held (up to 1,024 distinct processes) until the first
caller is tracked. If every one of them came from another process, a
`pre-binding unrouted calls resolved to other callers` note says so and
tracking continues; one from the tracked caller itself, one without an
identity, a full hold, or a stop before any caller is tracked still counts
as the loss that ends tracking. A process whose calls were reported as
another caller's is excluded from key-operation tracking for the rest of
the run: if it later becomes a tracked caller, it keeps the plain
per-call view and a `Joint birth unavailable; retained S1` gap names
`joint_image_refused`. A call from an untracked process that is still in
progress when key operations are sealed cannot be accounted for; tracking
then ends after about 6 s with a `joint audit made no progress` gap
instead of waiting for the run deadline. This ends tracking; it never
hangs, and the plain per-call counts are unaffected.
The memory of refused processes holds 16,448 entries. Past that, every
new untracked caller keeps the plain per-call view with the same
`joint_image_refused` reason; processes refused earlier stay refused and
tracked callers are unaffected. At one new foreign client every 3 seconds
that is about 14 hours of capture.

When callers with provider edges exit before semantic admission
completes — the common shape for suites that spawn one short-lived
process per test — the terminal `callers never admitted` gap counts
them. Callers whose instance registrations were refused for cause
(identity, capacity, ...) count separately under the terminal
`callers refused admission` gap, never as exited before admission.
Callers admitted after their calls were already collected shed
those calls the same way; the terminal `admitted callers with no
joined calls` gap counts them. Their unjoined calls shed instead of
joining (counted under `semantic calls unrouted` and the
key-operations `not attributed` tallies), so no per-key rows can name
them even though discovery saw their provider mappings. This is a
design boundary, not a missed observation: a collected capture fixes
each batch's binding set when the batch is collected, so calls from a
caller the observer has not admitted yet cannot wait for a later
pass. Longer-lived callers row normally once admitted. What
matters is when the calls happen, not just how long the process
lives: a process whose only call runs milliseconds after exec sheds
it even if it then sleeps for seconds, while sustained calling after
admission rows.

Processes that exit before any scan examines them (tens to hundreds
of milliseconds on a loaded host) never gain caller records at all:
they count only in the aggregate `short-lived processes never
scanned` gap together with ambient churn, not in the per-caller
gaps above. Per-caller attribution below the discovery floor needs
exit-time identity the observer does not retain by default.

Identity checks through the userspace backend need extra per-file checks on
btrfs to identify mapped providers correctly. This affects
`inventory --system --identity-backend userspace` and the userspace fallback
when kernel identity is unavailable. A Fedora Linux 7.2.9 comparison of GNU
builds using Rust 1.99.1, 400 processes and 8 mock providers on btrfs completed 10
matched rounds with equal coverage. Against the earlier identity implementation,
confirm-stage p95 rose from 66.600 to 84.055 ms (+26.21%); whole-pass p95 rose from
255.444 to 288.012 ms (+12.75%). Those figures are the 2026-10-27 campaign
(POST `b58ef1b5ec41bcb793b8741c3fc5ba62ae849d8e`, PRE R-14 `96624556`;
H4A FAIL with coverage ok; paired-median total +6.50%, bootstrap 95%
upper +8.10% within its 10% bar, wall ok; record
`tmp/codex-v050/h4a-b58-status.md`). A second 2026-10-31 campaign at
POST `ba92b4e2c29fc4db97b870ec1f0b28d4acabebef` (same PRE, same
400-process/8-provider Btrfs shape, 40/40 runs) is also H4A FAIL with
coverage ok: confirm-stage p95 168.529 to 178.216 ms (+5.75%),
whole-pass p95 612.2 to 850.9 ms (+39.00%; absolutes derived in the
analysis, the gate prints only the percentage), paired-median total
+37.83%, CI95 upper +43.53%, wall ok (controller record
`tmp/muse-jobs/h4a-qual-verdict.md`, analysis `tmp/muse-jobs/616-analysis.md`).
Absolute times are not comparable across campaigns, only
within-campaign ratios are. These are measured costs for that workload, not
bounds for every host. The default `--identity-backend auto` uses kernel
identity where available. Further userspace speed work is unscheduled: the
measured cost stands as disclosed until feasibility measurements identify
removable work.

On some overlayfs setups before Linux 6.8, p11scope may be unable to
prove how a provider file appears in /proc maps: the opened file and
its mappings legitimately carry different keys there, and the kernel
check that reconciles them can come back inconclusive. The provider
pin then carries the note `provider's maps rendering unproven;
callers mapping it may stay unbound`, and callers mapping that provider
may stay unbound. This key split does not happen on Linux 6.8 and later.

On kernels before 6.8, two pre-arm shapes still disclose instead of
joining. A manifest accepted without a scan in view, with the scan
arriving on a later tick, keeps the manifest module on the fd-keyed
entry while the scan files the maps-keyed entry; the live rebuild never
re-files the manifest alias, so that tick still fails with `candidate
contains the same exact provider more than once` (the initial build
joins both halves, and the live rebuild joins the pre-arm half). And a
live 6.6 capture whose scan and pre-arm halves join across the live id
change keeps `unobserved_windows` as `[late_discovery,
mapped_unattached]`: the exactness proof maps are keyed by object id
and cannot span the fd-to-scan id change, so the windows stay disclosed
rather than reading `[]`. Both are fail-closed disclosures; the
structural merge, evidence union and exact observation hold.

File identity on some filesystems has known edge cases, found by a
dedicated test study on 2026-11-03 (Linux 7.0). Since 0.7.0 the inspection
cache key and the pin-merge joins carry the held file's own device, so two
Btrfs subvolume files (39 of 40 back-to-back pairs matched on maps device,
inode, size and change time) and snapshot twins (which keep inode number,
size, change time and content) no longer share inspections or merge; each
case is covered by an automated privileged cell. What remains:

- Two Btrfs snapshot copies of one provider mapped at the same time
  (for example two containers from one image on the btrfs storage driver)
  are not attached; /proc maps shows one device and inode for both, so
  the group is refused with an ambiguity gap.
- A provider on a filesystem without unique inode numbers is not attached
  once two processes map it or it is rescanned: the second observation
  refuses the whole collision group (drops it, with an ambiguity gap)
  rather than attaching either copy. This covers FUSE (virtiofs, AppImage,
  sshfs, fuse-overlayfs), NFS, SMB/CIFS/SMB2, 9p, Ceph, AFS, Coda, tmpfs
  mounted `inode32`, and tmpfs whose mount cannot be resolved (including a
  container tmpfs seen through the observer's mount table, which is
  classified from the observer's table).
- On kernels built without CONFIG_TMPFS_INODE64, tmpfs uses 32-bit inode
  numbers that can repeat after about 4 billion files on one mount;
  p11scope treats them as unique there.
- A file reached through overlayfs is classified by the overlay mount,
  not by its lower layer: overlay over a non-unique lower still counts
  as unique. Filesystems not on the non-unique list are allowed by
  default, including Lustre, GPFS, BeeGFS, OrangeFS, vboxsf, ramfs and
  hugetlbfs.
- Four checks still compare `(st_dev, st_ino)` without refusing on
  non-unique filesystems: the deep-scan mapped-file guard, the
  same-object mapping short-circuit, retained-kernel-file comparison,
  and `--exclude-module` path matching. A detail toggle on such a
  filesystem reports the provider as another file instead of a changed one
  when the pin changed.
- The inspection cache is never cleared within a capture: a device number
  reused after a Btrfs subvolume delete plus snapshot, or a squashfs image
  re-attached on a reused loop device, can hand one file's cached digest
  to another file with an equal key. A future release will key the cache
  by `STATX_MNT_ID_UNIQUE` or `name_to_handle_at`.
- A deleted subvolume's device number is reused at once by the next
  subvolume or by an unrelated tmpfs or FUSE mount. An identity kept after
  its file is released can therefore name a different file.
- The overlay copy-up case described above also reproduces on Linux 7.0.
- XFS, EROFS, squashfs, FUSE mounts, device number reuse and same-path
  files in different mount namespaces are not exercised by automated
  tests yet.

These are edge cases for typical desktop and server systems.

Provider function tables can contain NULLs, unusable entries or fewer readable
words than their version label suggests. Discovery retains usable targets
around those gaps; an unread word is never treated as an observed NULL.
Version metadata alone does not require a wider table. If the evidence cannot
justify an API name, its target remains observable as `unknown`, count-only.
Actual unavailable entries and incomplete observations remain disclosed.

A `profile` or `trace` output has no per-run marker for calls made
before a provider's probes landed, so a missed early burst reads the
same as no calls. Inside a nested PID namespace (a kind node, a
hostPID pod) a newly started process waits for the full discovery
sweep, up to about 7 s, before its provider is attached. A late
provider whose calls finished before its watch began shows that
unwatched window in the JSON (`first_seen_ns` earlier than
`since_ns`).

A process that loads a provider, makes one call within about a
millisecond, and unloads is not observed without `run --pause auto`.
On Linux 7.0.14, for the four provider shapes measured under `p11scope
run --trace` (32 runs at 0/10/100/1000 us load-to-call delays) with
the pre-0.7.0 default `--pause never`, all 32 runs missed the single call (1 of 1 missed, 0 caller-attributed),
each reporting PARTIAL with a proven drain and zero event loss: the
transient exits before discovery attaches anything (0 slots, no
modules). With `run --pause auto`, which holds the child at each
loader hit until its probes attach, the same 32 runs captured the
call every time (0 missed), but the caller stayed `Unknown executable`
(0 attributed): a one-call transient leaves no second witness to name
it. A repeat run on Fedora (Linux 7.2.9) with the same 32 runs showed
the same split: with `--pause never` all 32 missed the call
(0 attributed); with `--pause auto` all 32 captured it (0 missed) and
the caller stayed `Unknown executable`. So for bursts of this shape,
expect a load, one call, unload burst inside ~1 ms of the load to read
the same as no calls unless the child is held with `--pause auto` or
kept alive past attach. Only two kernels, four provider shapes and
`run --trace` were measured.

Container checks run for v0.5.0, each counted against an independent
call ledger: Docker shared image layers and copy-up (Linux 7.0, and
Fedora on Linux 7.2.9 with a private Docker daemon; since v0.6.0 the
copy-up cells assert the stale mapper is unknown with the
`original_file_unproven` gap and the fresh mapper exact), the kind
DaemonSet, `attach-pod` into a kind pod from the node, a pre-attached
provider in a newly created pod, a Knative pod scaled from zero, and a
node-wide late provider that stays a reported boundary. They use one
kind node; multi-node clusters, CRI-O and the cgroupfs driver are
still not exercised.

The Knative warm capture observed all 1,200 calls after attachment. The first
cold request began before probes attached and observed only 84 of 1,200 calls,
with no kernel event loss. That cold result is a disclosed pre-attachment
coverage limit; it does not establish complete cold-start capture. Warm
qualification still requires exact counts.

The final 1,800-second SYSTEM+manifest soak passed on Fedora Linux 7.2.9
with the default FULL build: a 1,860-second observation window captured
162,003 calls from each of two callers, with zero lifecycle ring loss and a
proven final drain. Maximum sampled RSS was 75.5 MiB (78.9 MiB recorded
high-water mark). Semantic accounting separately
reported 324,004 joined calls, two shed calls and 651 named-budget refusals;
key operations remained unavailable. This is a measured 30-minute workload,
not complete semantic attribution or a guarantee for other workloads. The
earlier failed exact-count/final-drain run remains a historical failure.
Longer runs (4 h, 24 h) remain unqualified. Startup and stop figures are
declared per kernel, not a product guarantee.

At high call rates the semantic lane can lose EVENTS records faster
than it drains them: when the kernel ring is full it refuses new
records (counted in `EVIDENCE_RING_LOSS`, never silently
overwritten), and the observer discloses the cumulative loss in a
`native capture events lost` gap with exact counts on the stop line
(`lost`) and in `observation.semantic_capture.events_lost`. The
counter counts records, not calls: at system/cgroup scope a refused
FORK marker counts too, and on a linked (`--key-operations`) capture
one call writes up to two records (its journal BEGIN and its END, or
an ABANDON in place of the END), so one lost call can count up to
twice. A linked capture therefore loads a 32 MiB EVENTS ring (about
3.9 s of 10,000 calls/s), the same size as the default every per-call
capture keeps since v0.7.0 (`--mode metrics` keeps 4 MiB), so the lane adds no locked kernel memory. The Joint
service drains EVENTS into a bounded userspace staging queue on every
service regardless of seal state, so a seal awaiting future input no
longer wedges the ring behind it; the queue holds at most 131,072
records and 48 MiB of ring spans (about 54 MiB worst case with
per-entry overhead). When the queue fills while the ring still holds
records, the service records the named `joint events staging
saturated` gap (identical gaps aggregate by repeats) and the ring
keeps the rest; kernel ring loss still counts any overflow, disclosed
as above. Prompt saturated-tick commits apply to
legacy lanes only; joint-machine lanes service the machine instead
and disclose loss at each publish. Measured sustained rate (one
busy 12-CPU development host, release observer): without
`--key-operations`, every call was joined at 10,000 calls/s for 5, 20
and 60 seconds with no lost records, and entry-to-apply p99 stayed at
or below 236 ms; this excludes the time until the next publication.
With `--key-operations`, the v0.6.0 measurements in
[Known limitations in 0.6.0](#known-limitations-in-060) supersede the
older lane numbers: key operations sustain 6,250 calls/s for 60 s with
exact rows, and key-operation rows lag their calls by about 1.6-1.9 s
p99 in quiet runs. (That 6,250 calls/s ceiling was measured with
the v0.6.0 bucketing bug: keys created during the capture that never
got a label were summarised instead of listed. v0.7.0 lists them; see
[Key-tracking rate ceiling](#key-tracking-rate-ceiling).)
The older 1,000 calls/s ceiling describes the pre-integration
lane, not this release. The `authority_lost` reason is still live: it
latches after a watchdog trip or disposed staged history and renders
"per-key tracking stopped" even while exact rows continue beside
counted loss (see
[Known limitations in 0.6.0](#known-limitations-in-060)).

In long system-wide runs, a live publication can rarely stop making
progress for one session or operation. The affected operations are
counted in named `not attributed` reasons while exact rows continue
for the rest, and the report marks coverage as partial. The capture
does not hang, and nothing is silently dropped.

`--prearm-module` pins the named provider before any mapping and watches
its proved offsets (`watch` on the discovery record, with `attached_at_ns`
and `unobserved_windows` merged at capture end). A quiet pre-armed interval
is a stated watch interval, not proven-exact coverage, except on an owned
`run` whose every declared probe attached at or before the barrier release
while the barrier held the child from its start and whose pause gate
completed a gap-free first epoch: that capture publishes an explicitly
empty `unobserved_windows` on the pre-armed module. A `profile` or `trace`
capture (`--pid`, `--cgroup`, `--system`; detailed and `--mode metrics`)
whose mapping-instant witness finalized `Clear` for the object with every
ordering condition met publishes one too.
Every other capture still discloses its window, including any declared stamp
dated after the release, and a missing `unobserved_windows` key claims
nothing. `run` carries no ordering-evidence proof (the witness is inert
there), nor does inventory. Spurious windows
stay possible where attribution is conservative: provider unmaps by
multi-threaded non-member processes, by remote and kthread contexts, member
migrations within the subtree, and microsecond-scale latch/torn/pending
events at close. Measured idle rate: 0 spurious windows in 186 runs on a
busy desktop and Fedora (184 `[]`, 2 honestly absent;
~1% unknown rather than a false claim). The finalize walk delays the ready
line only with `--prearm-module`: about 0.2 s extrapolated on a 300k-VMA
desktop (the pre-measurement estimate was 0.1 s), 0.71 s
measured at 1M VMAs in a guest. Limits: at most 64 watched files, the
observer must run in the initial pid namespace, LTO kernels are refused, and
the walk fails closed past its 10 s deadline. Overlay files calibrate only
when the observer's mount table names and can stat the layer directories; a
metadata-only upper additionally needs a readable
`trusted.overlay.metacopy` xattr.
Inventory accepts and retains pre-arm inputs, attaches proved offsets
through the inventory lane, and reports one interval row per input in
`prearm[]`. An in-place rewrite that preserves `(ino, size, ctime)`
at the filesystem's granularity is undetectable by the retained-fd checks;
heavier proof is later work. The witness copy-up proofs (the open-time
pin, condition 4, and the finalize re-check) share that premise: a
copy-up landing in the same timestamp tick as the lower file's ctime
leaves an equal pin.

Extensive mode (`--track-short-lived`) publishes a `gap_exe_hints`
split beside `pid_descendant_gaps`, labelled `STATIC HINT`. A hint
resolves the dead executable's identity only against paths live scans
already learned: a binary no scan ever saw (no newcomer scan before
its exit, no surviving same-binary process) classifies `unknown`, as
does anything past the published budgets (depth 2, 32 objects, 128
edges, 1 MiB per executable, 64 MiB per capture, 255-byte names).
`dlopen`-only provider use is invisible by design and reads
`no_static_link_within_scope`, never a use claim. Inventory captures
do not arm extensive mode, so they publish no split. Trace, profile
and metrics captures over `--cgroup`/`--system` publish the gap
splits; `--pid` and owned-`run` captures publish `target_exec_hints`
(one hint per validated target exec, same shape and budgets) with the
gap splits absent there. Hints never
move call or attribution shares; exit records still settle no birth,
admission, absence, or call (R57).

The same opt-in publishes a `gap_exit_mappings` split beside
`pid_descendant_gaps`: at exit the kernel reports the
watched-provider slots it had recorded for the leader. `mapped`
means a slot named a watched provider file with no disqualifying
refusal; everything else reads `unknown`, including two systematic
blind spots. Multi-threaded exits read `unknown`: a process with
more than one mm user never localizes its mappings, so its empty
slots are not a negative. Late watches read `unknown`: a watch
inserted between the process's exec and its exit cannot see
mappings established before it. Shared-mm exits, refused hooks,
and local faults likewise read `unknown`. Admissions and overflow
sentinels carry no verdict, and there is no "did not map" claim:
nothing here proves a process did not map a watched provider.
Under `--mode metrics` the `gap_exit_mappings` key stays absent
because instance hooks never attach there; use profile/trace for
`mapped`.
The live cell qualifying this split builds its fixtures on guest tmpfs
inside virtme-ng guests rather than under `TMPDIR`, so a host `TMPDIR`
naming the shared 9p tree cannot lend the fixtures remapped ownership
or device identity.

A provider file replaced on disk while a program still runs it (an
upgrade that unlinks and recreates the file, or renames a new file
over it) is named, not counted: the running copy keeps its old code
mapped with a ` (deleted)` maps entry the observer cannot open or
identify, so inventory names the running copy with the `replaced on
disk while running; not examined, calls not counted` gap and PARTIAL
coverage, and the program's calls are not counted. The same gap names
any other replaced executable file, not only providers. Restart the
program so it maps the on-disk file.

If the file is replaced during a running inventory capture instead,
inventory keeps the program's collected edge as uncertain at the next
pass ("absent from an incomplete scan") with the gap named, instead of
ending the edge and reporting the module "unloaded"; coverage stays
PARTIAL. Calls made after the replacement stay unattributed
(`rejected demoted count` ranges) until the program is restarted and
a new capture starts. Other programs in the same scope keep their
edges. `profile` counts through the same replacement with
PARTIAL coverage and a "provider file changed during capture" gap.
After the upgrade settles, restart the program and re-run an inventory
capture.

With `--module`, inventory never ends an edge from a missing module:
the hinted scan does not examine every mapping, so a provider a
program unloads (`dlclose`) during the capture reads as uncertain
("absent from an incomplete scan") instead of ended and "unloaded".
Run without `--module` to see unloads ended.

## Planned for later versions

Shipped in 0.6.0 and no longer planned: live key operations
(`inventory --key-operations`) and promoting one endpoint to full
detail during a counter capture (`--select-endpoint`).

- Ordering-evidence pre-arm exactness producer for non-`run` scopes,
  inventory Detailed-subset activation, and same-granularity rewrite proof
  (packet 6.13 follow-ups).
- Bounded observer memory for long system-wide captures on busy hosts
  (v0.8.0), for example by keeping capture data on disk and building the
  report from it separately.
- Longer bounded runs (4 h, 24 h).
- Faster teardown on kernels without uprobe_multi.
- A per-mechanism counter view and per-mechanism key-operation rows.
- Journal/key-operation uniformity for unregistered mechanism ids
  (0.7.0): in v0.6.0 key-operation rows name only registered
  mechanisms.
- A named unknown edge for a late provider's unwatched window.
- Accounting for remaining exit-caused loader rejects that lack a
  pid-and-hook-time binding to the ended process as exit-only, to
  further cut the short-run void rate.
- Tracking short-lived processes that exit before their first binding
  (exit-time mapping verdicts shipped; full call attribution still planned).
- Following the started command's process tree under `run`
  (descendant admission and per-descendant probes, scoped to that tree
  only).
- Parallel BPF program loading for faster startup.
- File identity hardening past 0.7.0 (subvolume/snapshot joins, `inode32`
  refusal and their privileged cells shipped in 0.7.0): refusal on the
  remaining unrefused checks, pin-time classification from each view's
  mount table, a `STATX_MNT_ID_UNIQUE` cache key, and a wider filesystem
  test matrix in CI.
- Overlayfs copy-up attribution (0.7.0): the witness-proven lower
  file is attributed as its own module row (`layer: "pre_copy_up"`)
  with stale-mapping calls counted on it, and fresh calls route to the
  upper row by proof. Honest remaining gaps: without the kernel witness
  (heuristic mode, explicit userspace) the stale join stays `unknown`
  with the `original_file_unproven` gap; a spent witness budget and
  lower candidates no query proves (unopenable, unreadable, escaped, or
  simply another file) keep that gap with the refused count and each
  refusal's stage words (first eight, in stack order, rest counted);
  no path or index is published, never silent; in collapse mode
  spanning upper ranges stay unprobed with the miss disclosed, never
  counted. While both sides of a same-bytes pair stay mapped, the
  module's edges read unknown module-wide (callers of the attached
  pre side included), and the joint arbitration is order-independent
  within one pass only — a plain side admitted in an earlier pass
  still leaves a later pre side refused.
- An independent event reader for sustained 10,000 key
  operations per second with exact per-call rows (0.7.1).
- Per-key tracking for programs started after a background caller
  (0.7.1).
- Narrower count-only windows at high key-operation rates (0.7.1).
- A kernel-side witness for library loads after the main thread
  exits (0.7.x).
- Post-quantum key details, cluster aggregation, telemetry,
  enforcement, AArch64, extra capture fields and syscall/network
  correlation.

## Prior releases

# Known limitations (v0.5.0)

v0.5.0 release builds read object attributes by default (FULL); the P0
build without attribute reads stays an explicit option. The entries
under Prior releases below retain their historical context. Current host
admission below supersedes their old kernel-floor and fallback claims.

Live capture requires a Linux x86-64 host with usable `uprobe_multi` load and
self-link capability under the current credentials, normally Linux 6.6+ or a
working backport. Capability is tested, never admitted by version. Missing
capability refuses with `uprobe-multi-required` before capture, output changes
or a user workload starts, including explicit `--attach-backend singles`.
Safe scoped Singles remains available on eligible hosts; PID Multi additionally
requires a proven kernel PID filter. Help, version, inspect, discovery, saved
report read/diff and genuine `inventory --capture scan` remain usable without
the live gate. Non-Multi live support may be reconsidered around 0.9.x; no
release commitment is made.

Strict scale and speed limits apply to captures actually using Multi. Eligible
scoped Singles stays correct, finite and disclosed in `observation.attach` and
`evidence.attach_backend`; it does not establish Multi performance coverage.
Readiness bounds are disclosed harness parameters, never a cold-start SLA.

Measurement modes aggregate on eligible LP64 hosts, subject to independent
feature/load limits. A refused counter-mode or Detailed start exits nonzero
without writing a report or starting the requested `run` program. Latency
banks grow with
the host possible-CPU count and refuse with `counter-memory-limit`
past the per-capture kernel-map memory cap on hosts with many CPUs.
Counter banks share one 65,536-entry return-value pool, and
saturation is reported in the collection health. Per-call
profile/trace capture stays fixed at 512 attach slots (2,112 only in
the WIDE source build).

A capture follows at most 256 provider loads and tracks at most
262,144 program images; past either limit the report carries a named
gap and reads PARTIAL (full entries below). Stopping a very large
capture can refuse its fixed 384 MiB graph pool: the stop ends as a
finite incomplete stop, with retired objects still reported attached
and the measured peak disclosed (full entry below).

A timed run shorter than the first full pass (5–10 s on a busy host)
discards the collection and reports 0 callers with a `no complete
collection pass` gap and one informational stderr line (v0.7.0
publishes the kept first collection on every scope instead). The first
calls a provider makes after a late load can be missed before its
probes land, and use before admission voids that watch (`unknown`,
`use_before_admission`). Very short-lived callers can stay unbound or
unattributed (see below); tracking them needs a later opt-in mode.
Short-lived processes missed at system scale are counted only as gaps
(`pid_descendant_gaps`); their calls through attached providers still
count. A process whose main thread had already exited when the capture
first met it is not admitted, and its calls are not counted.

If a process exits while loader inspection is still pending, the report may
include a `discovery_truncated` gap. Unread metadata remains unavailable;
call coverage is evaluated separately.
A post-exec instance whose semantics cannot be proven appears as a
named gap (`gap [instance semantics refused] instance_unproven`), not
a joined instance. If a multi-threaded program unloads and reloads a
provider at the same address between two scans, the capture shows one
instance; per-caller call totals are unaffected. Finalizing and
re-initializing inside one load (a `C_Finalize`/`C_Initialize` cycle)
is also one instance.

Per-key tracking is opt-in: without `inventory --key-operations`
(needs `--capture auto` or `native`) the `key operations:` line reads
`not reported (per-key tracking is off)`; mechanisms and API results
are reported as before. Rows need p11scope to see the process start,
or the provider load, after capture begins, may lag their calls, and
tracking may not start at all; plain counts are unaffected and a named
gap says so. An ordinary native-retirement
refusal during a `--manifest` capture ends the first stop with an incomplete
report and a nonzero exit. Uncertain native ownership stays retained and
replacement admission stays blocked; the refusal is not proof of clean detach.

In containers, a process that loaded a provider before the file was
copied up is attributed to the copied-up file and its later calls are
missed, with no marker in the output; restarting such processes is the
workaround, and the kernel identity backend does not help (full entry
below).

Identity checks through the userspace backend need extra per-file checks on
btrfs to identify mapped providers correctly. This affects
`inventory --system --identity-backend userspace` and the userspace fallback
when kernel identity is unavailable. A Fedora Linux 7.2.9 comparison of GNU
builds using Rust 1.99.1, 400 processes and 8 mock providers on btrfs completed 10
matched rounds with equal coverage. Against the earlier identity implementation,
confirm-stage p95 rose from 66.600 to 84.055 ms (+26.21%); whole-pass p95 rose from
255.444 to 288.012 ms (+12.75%). These are measured costs for that workload, not
bounds for every host. The default `--identity-backend auto` uses kernel
identity where available. Further userspace speed work is planned for 0.5.x.

On some overlayfs setups before Linux 6.8, p11scope may be unable to
prove how a provider file appears in /proc maps: the opened file and
its mappings legitimately carry different keys there, and the kernel
check that reconciles them can come back inconclusive. The provider
pin then carries the note `provider's maps rendering unproven;
callers mapping it may stay unbound`, and callers mapping that provider
may stay unbound. This key split does not happen on Linux 6.8 and later.

Provider function tables can contain NULLs, unusable entries or fewer readable
words than their version label suggests. Discovery retains usable targets
around those gaps; an unread word is never treated as an observed NULL.
Version metadata alone does not require a wider table. If the evidence cannot
justify an API name, its target remains observable as `unknown`, count-only.
Actual unavailable entries and incomplete observations remain disclosed.

A `profile` or `trace` output has no per-run marker for calls made
before a provider's probes landed, so a missed early burst reads the
same as no calls. Inside a nested PID namespace (a kind node, a
hostPID pod) a newly started process waits for the full discovery
sweep, up to about 7 s, before its provider is attached. A late
provider whose calls finished before its watch began shows that
unwatched window in the JSON (`first_seen_ns` earlier than
`since_ns`).

A process that loads a provider, makes one call within about a
millisecond, and unloads is not observed without `run --pause auto`.
On Linux 7.0.14, for the four provider shapes measured under `p11scope
run --trace` (32 runs at 0/10/100/1000 us load-to-call delays) with
the pre-0.7.0 default `--pause never`, all 32 runs missed the single call (1 of 1 missed, 0 caller-attributed),
each reporting PARTIAL with a proven drain and zero event loss: the
transient exits before discovery attaches anything (0 slots, no
modules). With `run --pause auto`, which holds the child at each
loader hit until its probes attach, the same 32 runs captured the
call every time (0 missed), but the caller stayed `Unknown executable`
(0 attributed): a one-call transient leaves no second witness to name
it. A repeat run on Fedora (Linux 7.2.9) with the same 32 runs showed
the same split: with `--pause never` all 32 missed the call
(0 attributed); with `--pause auto` all 32 captured it (0 missed) and
the caller stayed `Unknown executable`. So for bursts of this shape,
expect a load, one call, unload burst inside ~1 ms of the load to read
the same as no calls unless the child is held with `--pause auto` or
kept alive past attach. Only two kernels, four provider shapes and
`run --trace` were measured.

Container checks run for v0.5.0, each counted against an independent
call ledger: Docker shared image layers and copy-up (Linux 7.0, and
Fedora on Linux 7.2.9 with a private Docker daemon), the kind
DaemonSet, `attach-pod` into a kind pod from the node, a pre-attached
provider in a newly created pod, a Knative pod scaled from zero, and a
node-wide late provider that stays a reported boundary. They use one
kind node; multi-node clusters, CRI-O and the cgroupfs driver are
still not exercised.

The Knative warm capture observed all 1,200 calls after attachment. The first
cold request began before probes attached and observed only 84 of 1,200 calls,
with no kernel event loss. That cold result is a disclosed pre-attachment
coverage limit; it does not establish complete cold-start capture. Warm
qualification still requires exact counts.

The final 1,800-second SYSTEM+manifest soak passed on Fedora Linux 7.2.9
with the default FULL build: a 1,860-second observation window captured
162,003 calls from each of two callers, with zero lifecycle ring loss and a
proven final drain. Maximum sampled RSS was 75.5 MiB (78.9 MiB recorded
high-water mark). Semantic accounting separately
reported 324,004 joined calls, two shed calls and 651 named-budget refusals;
key operations remained unavailable. This is a measured 30-minute workload,
not complete semantic attribution or a guarantee for other workloads. The
earlier failed exact-count/final-drain run remains a historical failure.
Longer runs (4 h, 24 h) remain unqualified. Startup and stop figures are
declared per kernel, not a product guarantee.

In long system-wide runs, a live publication can rarely stop making
progress. After 6 seconds without progress, p11scope abandons that
publication with a named gap and keeps running, and the report marks
coverage as partial. The capture does not hang, and nothing is
silently dropped. Fixing the underlying stall is planned for a later
release.

## Planned for later versions

- Live key operations (key type and size, sign/verify per key) in 0.6.0.
- Promoting one endpoint to full detail during a counter capture, in 0.6.0.
- Longer bounded runs (4 h, 24 h).
- Faster teardown on kernels without uprobe_multi.
- A per-mechanism counter view and per-mechanism key-operation rows.
- A named unknown edge for the copy-up case above instead of silent
  misattribution, and for a late provider's unwatched window.
- Tracking short-lived processes that exit before their first binding.
- Parallel BPF program loading for faster startup.
- Post-quantum key details, cluster aggregation, telemetry,
  enforcement, AArch64, extra capture fields and syscall/network
  correlation.

# Known limitations (v0.4.0)

v0.4.0 is an intermediate source checkpoint with no new binary bundles.
Its selected P0 build requires `--no-default-features --features
stub-object-attributes`: object-attribute capture is not enabled
(no BPF program reads object attributes). An ordinary source build defaults
to FULL; `--no-default-features` alone does not select P0.
In P0, every profile, metrics and trace
document discloses this as structured evidence
(`evidence.object_capture.available: false`, `reason: "not_enabled"`), and
`p11scope doctor` names it in its `object-attribute capture` row. P0 retains
bounded call/count/mechanism evidence; loss and completeness disclosures still
apply. FULL and broader installed/package qualification remain open.

The unreleased development checkpoint retains the existing metrics path when
`--counter-mode` is omitted. Explicit `counts`, `timestamps` and `latency`
requests are preparatory and refuse before capture setup. Useful public
activation of those measurement modes remains outside this checkpoint;
v0.5.0 activates them (see above).

The G21 FULL-capture wrap legs (660 rounds in 900s, pid + system) are not
qualified in v0.4.0: FULL is absent from the selected P0 build, and earlier legs
exceeded their time budget (correctness of the
wrap accounting proven through 169 fenced rounds pre-split; throughput
red at ~2.3 s/round vs 1.36 s needed). These are historical scoped results.
The T/U throughput work, shared-oracle rework and required green legs remain
acceptance work; smaller focused checks do not qualify those legs.

The full schema/consumer campaign remains open. Current exact identifiers
include `p11scope/observed-profile/v3`, `p11scope/observed-profile/v3-metrics`
and the inventory v1 family; see the
[schema-identifier rules](../RELEASING.md#version-and-schema-identifier-rules).
Their version spellings grant no cross-schema compatibility.

# Known limitations (v0.3.0)

Inventory accepts `--max-endpoints` from 1 through 8192, with the unchanged
4096 default. This is a finite, capture-lifetime physical endpoint budget;
unloading does not refund IDs. The 8192 candidate policy bound does not
qualify native attach/stop cost, supported-kernel behavior or a release
capacity envelope. Caller-pair, discovery-owner and work limits are separate,
and selecting a larger endpoint budget does not increase them. Wider public
native growth and resource measurements remain pending.

User-facing limits of p11scope v0.3.0: per-edge entry counts end to end
(DR-02 closed), load-instance continuity, and sharded discovery.
The v0.2.0 cut was qualified on 2026-10-04 (from merged and green
`s2s3-semantics`); the released v0.2.0 code adds the 128-range proof-stat pool
threshold, the buffered `-o` JSON write and the retried discover self-maps
read on top of that cut. The M1 and R4 rows below were re-measured on the
released v0.2.0 code in a quiet window on 2026-10-05; every other
v0.2.0-era measured number is the cut's. At the time, the following were
planned to move to v0.3.0: C6 (semantics, churn and capacity, 30-minute
endurance), C5b (cgroup/pod scope, namespace-aware BPF filter), C7 (V1 call
counts, 2 MiB inventory ring, kernel-side identity, allowlist-v3, BPF
nightly bump), the full measurement set M2–M7, the full §7 deferred
closure, and the §8 Fable audit. Actual v0.3.0 contents are in
CHANGELOG.md (per-edge counts with the M2 gate, load-instance continuity,
sharded discovery, lifecycle ring, live-label fix, E16 checks);
kernel-side identity and the remaining items move to v0.4.0 per the
2026-10-08 release split.

A short measurement tier (M0, M1 at 4,096 processes, M4 churn, and the C5.6
pool) ran on the cut day (2026-10-04); its numbers are in the M0, M1, M4 and R4
rows below, with M1 and R4 since re-measured on the released code as noted
in those rows. Method for every row: Linux 7.0 x86-64, observer pinned to CPUs
10,11 (R4: 8–11, plus a released-code cell on 10,11), 3 cold + 6 warm samples
per cell (M4: 3 + 3; released-code R4 at 2 CPUs: 5 + 5), each a 30 s run
(M4: 60 s), in a quiet window (load gate 4.0), on glibc release builds
(the shipped observer is musl static-pie): the cut's candidate b16c858
for the cut rows, the released-code build aa62b87 for the re-measured M1
and R4 rows, the cut build 6abd2b7 (pool from 8 ranges) as the R4 base. Ranges below are
the min..max of per-sample p95.

## Offline inventory comparison

`inventory diff` compares the supported projection of two saved inventory v1
snapshots. Exact recorded executable paths are presentation groups; they do
not prove equal executable bytes, processes or deployments. Module SHA-256
matches content, not physical files or load instances. Host/boot, process,
physical continuity and each side's scope completeness remain unknown,
including for empty or gap-free inventories. Not observed after does not
prove removal, and an unchanged projection is not compliance evidence.

Counts remain separate lower-bound entry observations for independent windows;
no count, time, gap-repeat or budget-counter delta is computed. Missing
coverage, witnessed use without a count, loss, saturation and in-flight
entries retain their limits. Instance and detailed semantic changes are not
compared; physical-edge counts are never distributed across load instances.
Missing executable paths/digests remain unresolved rather than matched by
basename, path or build ID. Unknown clock units retain their raw numbers.

The reader accepts only regular inventory v1 JSON files and applies all five
[input limits](schema/inventory-diff-v1.md#input-and-compatibility) together.
The row ceiling does not guarantee acceptance below other bounds, and there
is no numeric report-size or RSS guarantee. Differences and unknown evidence
exit 0; that status means the comparison succeeded, not complete coverage.
See [the operator guide](usage.md#offline-inventory-comparison) for output
publication and errors. This offline capability does not qualify new live
capture behavior or establish the provenance of its input files.

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

Historical measurements below predate v0.5 host admission. Stock non-Multi
hosts are outside current live support; these failures remain historical failures.
The old bounds are measurements, not a product startup SLA.

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

On kernels without uprobe_multi (5.15, 6.1), stopping a capture with many
probes closes the probe links one at a time: about 18 ms per link in a
5.15 guest and tens of ms per link on newer hosts using single links
(host-dependent; for example, 4,227 links take roughly 1.3–5 minutes).
The stop stays correct and finite with no cap: once the estimate reaches
2 s, p11scope prints one up-front estimate line (computed at 50 ms per
link, so on 5.15 it can overstate the wait), then the usual per-second
progress, and a second Ctrl-C stops waiting and leaves the kernel to
finish the remaining closes after exit. Measured on Fedora 7.2.9
(5 vCPU) with the release candidate at 8,194 per-offset links (the
singles path; `--attach-backend singles` selects it where multi-attach
is available): attach 41 s, stop (link release) 339 s, about 41 ms per
link.

### 5.15: physical-identity controls and non-leader exec unqualified

Historical measurements below predate v0.5 host admission. Stock non-Multi
hosts are outside current live support; these failures remain historical failures.
The old bounds are measurements, not a product startup SLA.

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
  On an eligible host it can use scoped per-offset links with the reason
  disclosed; with a proven kernel pid filter it uses uprobe-multi with pid = target
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

### Startup includes sequential BPF program loading

Historical measurements below predate v0.5 host admission. Stock non-Multi
hosts are outside current live support; these failures remain historical failures.
The old bounds are measurements, not a product startup SLA.

- Historical measurements cover discovery to the `capturing:` line,
  rather than complete observer startup. FULL default, 208 probes,
  4 vCPUs: 6.6.157 4.5–4.9 s,
  host 7.0 6.25–6.6 s, 6.1.188 16.7–17.4 s, 5.15.221 17.0–20.2 s;
  0-probe runs take the same time (5.15 14.8–21.5 s under host load),
  showing that these historical runs spent most startup time loading
  programs, rather than attaching probes.
- Current FULL32 setup-only samples on Linux 7.0.0-38-generic with 12 visible CPUs
  took 7.512, 13.133 and 17.217 s from observer launch to readiness.
  The 7.512 s attempt had no usable syscall attribution. A separate
  complete 13.133 s measurement attributed 96.5% of its post-discovery
  interval to `BPF_PROG_LOAD`; it did not distinguish verifier, JIT or
  other work inside that syscall. No GO was released in these diagnostics.
- **Owner-approved test allowance, 2026-10-28:** use a 20 s observer
  readiness bound for the harness's existing modern-kernel timer class,
  preserving the preliminary borrowed-workload allowance at 8 s. Both
  legacy timer allowances stay 30 s; that is historical test policy,
  not permission to run capture on an ineligible non-Multi host.
  The original 8 s FULL32 failure and three unrun cells remain unchanged.
  These setup samples do not qualify calls, privacy, counts or zero loss.
- In the FULL32 object cell, the 6 s capture, native fixture's 30 s GO
  deadline and 30 s stop bound remain unchanged. The native GO clock
  starts before observer startup;
  a 20 s observer allowance does not guarantee the remaining setup and
  stop-to-GO work fits. Missing either real readiness or GO still fails.
- Disclosure: this entry and the canary harness's declared
  per-kernel readiness bound, printed up front in every run as
  `CANARY_READY_BOUND_DECLARED kernel=... seconds=...`. No environment
  variable can replace the declared timer.
- Workaround: keep the workload alive past attach (as in
  [usage](usage.md#discovery-timing-and-optional-offline-discovery)),
  while respecting the current Multi capability requirement.
- Planned: parallel program loading stays an optional later speedup,
  not a correctness fix.

## System scale and performance

### Pass time at 4,096 processes (M1) — 1.61–1.70 s p95, over the 1 s target

- What the user sees: a 4,096-process / 1,000-caller `--system` pass takes
  about 1.61 s native and 1.70 s scan on the released code (pass p95, warm-cell
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
- History (the cut): the 4,096 pass p95 was about 2.20 s in both lanes
  (native 2,202 ms, range 2,184–2,248 ms; scan 2,204 ms, range
  2,198–2,708 ms, including one slow sample at 2,708 ms); 448 was about
  0.34 s (native 337 ms, range 335–558 ms; scan 335 ms, range
  332–340 ms). Absolute pass times shift with host state between
  campaigns (the cut's product code measured 1.80 s scan at 2 CPUs in
  the re-measure window, build 6abd2b7, against 2.20 s in its own window,
  build b16c858), so the cross-campaign drop
  overstates the code effect; the interleaved R4 A/B below is the clean
  measure of it.
- Kernels/conditions: `--system --capture scan` and `native` at 448 / 4,096
  processes, churn 0, 3 cold + 6 warm 30 s samples per cell.
- Disclosure: `P11SCOPE_STAGE_TIMINGS=1` per-pass stage timings, the
  `observation` block, and this row. `P11SCOPE_PROOF_STAT_THREADS=N`
  (diagnostic, `--system` only, read once per run): unset keeps the
  default (usable CPUs, at most 4); `0`/`1` forces the serial proof
  path; a decimal `N` uses at most 4 threads (a leading `+` and
  surrounding whitespace are accepted); anything else keeps the
  default. When set, one stderr note per run, not per pass, reports
  the value used, or that the value was ignored. Since v0.3.0
  (unreleased) it applies only on the serial path (see the next knob).
  `P11SCOPE_SHARD_THREADS=N` (diagnostic, read once per run, same
  parsing and stderr note): the threads the `inventory --system` sweep
  and confirm stages may shard over. It also covers the phase-1 maps
  sweep of `--cgroup` and `--system` capture discovery past
  `--max-scan-pids`. Unset keeps the default (usable CPUs, at most 4);
  `0`/`1` forces the serial path of both stages exactly as before
  sharding (with the proof-stat pool).
- v0.3.0 (unreleased): past the deep-scan cap, the sweep and confirm
  stages run on up to 4 threads (the observer's usable CPUs), one
  contiguous pid range of at least 256 pids per thread. Every budget
  charge, ceiling and loss is then replayed in pid order on one thread,
  so the result is the serial one. A confirmation whose thread's copy of
  the budget had already spent more than the capture budget is redone
  live on that one thread. Under a ceiling the threads can read past the
  point where the serial path would stop; those extra reads are never
  charged or published. Indicative, single host (2 cores with
  SMT, Linux 7.0, btrfs, scan lane), interleaved serial and sharded runs
  at 4,096 processes with both stages sharded: the pass p95 drops from
  about 1.06–1.09 s to about 0.61 s on CPUs 8–11 (sweep p95 about
  545 ms to 220 ms, confirm about 475 ms to 345 ms) and from about
  1.06 s to about 0.75 s on CPUs 10,11, with identical output.
- Workaround: narrow scope (`--pid`, `--module`).
- Planned: the 1 s route is v0.3.0 kernel-side identity (C7). M1 at 10,000
  and the ≤15%-over-scan gate move to v0.3.0 with it.

### Proof-stat pool benefit (C5.6 R4) — serial below 128 ranges: −230 ms at 2 CPUs, −625 ms at 4 CPUs

- What the user sees: the bounded per-collection `map_files`
  proof pool (at most 3 scoped workers) engages only for a batch of 128 or
  more ranges (`MIN_PARALLEL_BATCH`, was 8). Typical per-process batches
  are 30–45 ranges, so by default a pass behaves like the serial path.
  Results are identical by construction; only wall time differs. Why: on
  the author's host (2 physical cores with SMT, Linux 7.0, btrfs) the
  channel round-trip per process (~85 us) cost more than the ~114 us of
  `fstatat` it parallelized. A clean same-history A/B (released code aa62b87
  against the cut 6abd2b7, interleaved, scan lane, 4,096 processes)
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
- History (the cut): scan pass p95 at 4,096 processes was ~2.30 s with the
  cut's candidate (warm median 2,309 ms, range 2,282–2,329 ms) against
  ~2.02 s with the pre-pool build 570eb7d (warm median 2,035 ms, range
  2,031–2,087 ms). That was not a clean A/B (570eb7d predates other
  slices); the same-history campaign A/B above is the clean answer: the
  pool did not help on this shape.
- Kernels/conditions: `--system` with maps-matched callers past the
  deep-scan cap, scan lane on CPUs 8–11 (2 physical cores with SMT) and
  on CPUs 10,11 for the released-code 2-CPU cell, on kernels where `map_files`
  proofs run. The pool can still engage for a process mapping 128 or more
  examined ranges; its benefit there is not measured.
- Disclosure: stage timings (`confirm`), this row.
- Workaround: none needed; small batches are serial.
- v0.3.0 (unreleased, not measured): only executable ranges are proved
  (A6, above), about one range per mapped library instead of 30–45 per
  process, so batches reach the pool threshold even more rarely. When the
  confirm stage is sharded (C7 A5: two or more usable CPUs and at least
  512 swept processes) the pool is not used at all; it runs only on the
  serial path (`P11SCOPE_SHARD_THREADS=1`, one usable CPU, or a smaller
  sweep).
- Planned: Cross-pass caching stays out (R-C56-1: inode reuse makes it
  unsound); kernel-side identity is v0.3.0 (C7).

### Stage A continuity-hook overhead (1d) — ~280-415 ns per mapping event; metrics skips the hooks

- What the user sees (v0.3.0, unreleased): while a profile/trace capture
  is live, its three mapping hooks (`uprobe_mmap`, `uprobe_munmap`, and
  the `copy_vma` fexit) fire on every file-mapping event system-wide.
  Workload-side ABBA medians on the measured host (below): watched
  provider-file churn +1,030 ns per mmap+munmap op (+26.5%, range
  4,849–5,183 vs 3,826–3,922 ns/op) and +1,119 ns per mremap op
  (+33.8%, 4,358–4,516 vs 3,240–3,337 ns/op); unrelated-file churn +782
  ns per mmap+munmap op (+20.4%, 4,566–4,814 vs 3,805–3,865 ns/op) and
  +831 ns per mremap op (+25.3%, 4,097–4,143 vs 3,264–3,303 ns/op).
  Per hook event (2 events per op): about 515 ns watched and 391 ns
  unrelated, of which BPF run-time accounts for about 416/410 ns
  watched and 282/280 ns unrelated; the ~100 ns/event remainder is the
  fentry trampoline, which `run_time_ns` does not time. The miss path is
  not "one hash miss": five CO-RE reads plus two array lookups precede
  it. Metrics (aggregate-only) captures never attach the hooks (the 1d
  gate): they never join per-call records to load instances, so they
  neither pay nor charge the tax. Eight-worker parallel churn could not
  resolve the effect (shared-file lock contention inflates the base to
  ~10 µs/op with ±9% spread; the +100/+215 ns/op deltas sit inside the
  noise), but BPF-side per-event cost rose under contention (602 ns
  watched, 424 ns unrelated), so the tax grows when the host is busiest.
- Scale (D1 deviation, 2026-10-06): the 1d brief asked for churn "at
  4,096 processes"; the campaign ran single-process churn plus 8-worker
  parallel cells only. Contention already raises the per-event cost
  (BPF run-time 602 ns watched / 424 ns unrelated under p8 vs 416/410
  and 282/280 ns solo), so the medians above are plausibly a
  system-scale LOWER bound: expect the per-event tax to grow, not
  shrink, toward full scale. A 4,096-process cell is deferred to the
  Stage 5 qualification windows (M1-4096/M1-10k); see DR-T3A-7.
- Kernels/conditions: any kernel where the hooks attach (non-LTO with a
  readable `/boot/config`; LTO or unverifiable status refuses, as
  before). Campaign: Linux 7.0.0-34-generic x86-64, AMD Ryzen AI 9 HX
  PRO 370, 12 CPUs, commit 301dde4 (binary sha256
  cf6dbcb7e8fcddba14ca0b44991420c169307c3384a507f8a7e7cac902ba843f),
  2026-10-06, quiet host (load gate 4, kind paused),
  `scripts/bench-stagea-overhead.sh` defaults (OPS 1,000,000, 6 cells,
  56 valid samples, ABBA within a round with the starting arm alternating
  per round; off-arm drift under 1% on every resolved cell). Reproduce:
  `flock /var/tmp/p11scope-ws-tmp/privileged.lock
  scripts/bench-stagea-overhead.sh` on that commit, then
  `scripts/bench-stagea-overhead-analyze.py` on the campaign log with
  `--manifest` (the campaign writes `$WORK/campaign.manifest.json`; the
  pre-manifest 1d log re-validates against a derived manifest with legacy
  stdout completion — same MATERIAL table).
- Disclosure: none in product output (no reader consumes the refusal
  yet; Stage B will); `bpftool prog show` names the three attached
  `p11_inst_vma_*` programs while a profile/trace capture is live, and
  metrics sessions carry the internal refusal
  `aggregate-only (metrics) sessions never join per-call records to load
  instances (Task 1d overhead gate)`.
- Workaround: `metrics` mode for the lowest overhead (no hooks attached);
  profile/trace pay the per-event tax above while live.
- Planned: stays gated (metrics skips; profile/trace attach). Open for
  the owner: if the profile/trace-time tax matters on churn-heavy hosts,
  attach the hooks only while Stage B routing is armed, or add a
  documented operator opt-out.

### Per-edge counting overhead (M2) — immaterial on every cell; DR-02 closed

- What the user sees (v0.3.0, unreleased): the native lane counts every
  entry (V1 non-fetch atomic add in `CALLER_USE`, plus the per-pass
  count-refresh reader and counted publish). Workload-side ABBA medians
  on the measured host (below) show no resolvable tax: 1-thread call
  churn -6.0 ns/call (-0.20%, range 2,992–3,064 vs 2,980–3,070 ns/call),
  4-thread +34.4 ns/call (+0.27%, 12,371–13,084 vs 12,438–13,121),
  12-thread -115.2 ns/call (-0.29%, 38,197–45,067 vs 37,994–40,733),
  12-thread padded -76.0 ns/call (-0.19%, 36,633–40,417 vs
  38,267–51,284), and unrelated mapping churn beside an idle capture
  -21.6 ns/op (-0.61%, 3,420–4,022 vs 3,437–3,934 ns/op). Paired medians
  (20 ABBA pairs per cell) read -0.09%, +0.01%, +0.17%, -0.02% and
  -0.44% with bootstrap 95% CI uppers of +0.32%, +0.23%, +1.00%, +0.53%
  and +1.87% — every cell far inside the M2 bar (paired median ≤5% of
  the BASE observed call cost, CI upper ≤10%). BPF program time is
  identical across arms (270/271, 468/466, 787/779 and 780/788 ns/event
  on the four call cells; exactly 1.00 entry events per call): the +1
  XADD sits far below the ~270 ns program body and below run-time
  quantization, and the per-pass refresh adds no resolvable cost at one
  row. Count exactness held on every counted sample: 0 errors over 80
  on-arm samples, each edge exactly TOTAL+2*THREADS+1. For context, the
  native entry path itself costs ~2.4 µs/call at t1 (observed ~3.0 µs
  vs unobserved 0.62 µs: the uprobe trap plus the entry program, paid
  with or without counting) and SoftHSM2 contention dominates t12
  (~39 µs/call observed vs ~30 µs unobserved on either arm).
- Kernels/conditions: any kernel where the native lane attaches.
  Campaign: Linux 7.0.0-34-generic x86-64 on a VM (microsoft), AMD Ryzen
  AI 9 HX PRO 370, 12 CPUs, commit cbd1c65 (candidate sha256
  40615595c0521271700f1d2ab40f92576c495c639d3eba34de515753cda26196;
  witness-only base c34b4d4 sha256
  30e8db074de4b7df1338fe17a91b3e4ffce435a5e5eda9bf14b27bbda1d10a85),
  2026-10-08, quiet host (load gates 4/4, kind paused, builds paused),
  `scripts/bench-count-overhead.sh` defaults (5 cells, 250 valid
  samples, ABBA within a round with the starting arm alternating per
  round plus one unobserved sample per round; off-arm drift ≤1.11%;
  lane multi on every observed sample; no exclusions). Reproduce:
  build the base once (`git archive c34b4d4`, release build) to
  BASE_BIN, then `flock /var/tmp/p11scope-ws-tmp/privileged.lock
  scripts/bench-count-overhead.sh` on that commit, then
  `scripts/bench-count-overhead-analyze.py` on the campaign log.
- Disclosure: the counts are the feature (`entries.count` with
  `coverage.state counted`); the overhead is disclosed here only.
- Workaround: none needed (immaterial). `--capture scan` avoids the
  native entry cost entirely but loses per-edge use.
- Planned: none (gate PASS). DR-02 closed by C4 + C5 + this gate. Open
  for the owner: per-guest counting-cost cells ride with the Stage 5
  qualification windows (counting exactness on 5.15 is already proven
  by the C34 campaign, 3/3 with identical finals).

### Harness validity (M0) — PASS

- What the user sees: PASS: all 5 legs classified as expected (29 of 29
  tier-1 units valid): a correct ledgered SoftHSM2 `--pid` capture, an
  induced-loss cell (3,000 exec/s) read as lossy, a killed-sampler cell
  read as missing, a dead-pid refusal read as refused, and a correct
  no-observer control. The released-code M1/R4 campaign re-ran the same gate:
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

### Lifetime identity/ticket budget 262,144 (DR-06; 16,384 before v0.7.0)

- What the user sees: long `--cgroup`/`--system` captures of busy hosts can
  spend the 262,144-identity budget (about 14 hours at 5 new processes/s,
  about 3.6 hours at 20/s); later processes get no identity: the capture
  prints `p11scope: kernel could not give a process an identity (N refused
  so far; lifetime budget of 262144 identities spent); ...`, counts each
  refusal in `evidence.kernel_control.identity_unavailable` with
  `identity_budget_exhausted: true`, and inventory callers show a `usage
  coverage health regression` gap naming the refused identity counts.
  (Quoted wording before v0.7.0: `... (lifetime budget of 16384 identities
  spent); ...` with no refusal count.)
- Kernels/conditions: all kernels; Detailed `task_newtask` fork-wrapper
  ticket burn in `--system` Detailed subsets is unmeasured.
- Disclosure: `evidence.kernel_control` (`identity_budget_exhausted`,
  `identity_unavailable`, `owner_admission_failures`), gaps, `PARTIAL`.
- Workaround: `--pid` or a narrow `--cgroup`, or split the capture.
- Planned: reusable identity slots are not in 0.6.0; v0.6.0 keeps
  the 16,384 budget with the named gaps above. v0.7.0 widens the budget
  to 262,144 per capture, still never reused; ticket recycling (bank
  epoch rollover) is planned for 0.7.1.

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

- What the user sees: a capture that arms more than 256 provider loads
  refuses the 257th with a named gap: `evidence.discovery_truncated`
  counts it (`N discovery records truncated`), `evidence.skipped` keeps
  the entry (`live loader arming`, or `owned initial-set discovery` on
  the owned path, with `loader context capacity 256 is exhausted`),
  `evidence.loader_discovery.strategies.unavailable` counts it, and the
  report reads `PARTIAL`.
- Kernels/conditions: all kernels; compounds per-process loader hooks
  (`OneProcess` scope, deep-scanned views only).
- Disclosure: `discovery_truncated`, `evidence.skipped`, `PARTIAL`.
- Workaround: narrower scope, longer-lived providers.
- Planned: reusable loader contexts are not in 0.6.0; v0.6.0 keeps
  the 256 limit with the named gap above.

### Stop-time graph pool is one fixed 384 MiB accounting limit

- What the user sees: the stop sequence accounts the collected call graph
  against one fixed 384 MiB limit, sized for 8,192 endpoints, whatever
  `--max-endpoints` is set to. A stop that would exceed it ends as a
  finite incomplete stop, with the retired objects reported attached and
  the measured peak disclosed.
- Kernels/conditions: all kernels; the stop of a large capture.
- Disclosure: the incomplete-stop report with the measured peak.
- Workaround: fewer endpoints (`--module`, narrower scope).
- Planned: stays one fixed accounting limit for every `--max-endpoints`
  value.

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

### Lifecycle ring loss under exec churn (M4) — clean at 100 and 1,000 exec/s; 8 MiB ring since v0.6.0

- What the user sees: at 448 processes, native lane: 100 exec/s loses
  nothing (0 lifecycle and 0 ring loss in all 6 samples); since v0.3.0
  (unreleased) 1,000 exec/s also loses nothing (0 ring loss, 0 demoted
  edges, sticky unproven share 0.0, 0 recovery rescans in all 6
  samples; lifecycle high-water 4–8% of the ring). Previously (v0.2.0,
  64 KiB ring) 1,000 exec/s lost about 100 ring records per minute
  (84–117 across 6 samples), demoted 55 edges per minute-long capture
  with sticky unproven share 1.0, and ran 1 recovery rescan per
  capture. Any loss stays disclosed (`health_unproven`, demoted edges,
  the gap). The 2 MiB ring holds about 2,260 920-byte records, and the
  lane does not drain while a pass applies its scan, attaches entries,
  or reads usage. With the sweep and confirm stages sharded (v0.3.0,
  unreleased), 1,000 exec/s at 448 and at 4,096 processes also loses
  nothing: 0 ring loss, 0 malformed records and 0 recovery rescans in
  all 12 samples (3 rounds of 1 cold + 1 warm per size), high-water
  6–11% of the ring, with one cold 448-process sample at 37%. Churn 0
  cells were not measured in this tier.
- Since v0.6.0 the inventory ring is 8 MiB (about 9,100 records) and the
  lane also drains it while the semantic lane starts. A Joint startup
  under heavy unrelated churn (2 MiB ring, 8,192 held records) lost
  17,977 lifecycle records before the first pass, so both bounds were
  raised: 8 MiB of locked kernel memory per inventory capture (was
  2 MiB), and up to 32,768 held records in user memory (about 29 MiB,
  allocated only as records arrive; was 8,192, about 7.2 MiB).
- Headroom is bounded by pass length, not by the ring alone: while a
  pass collects, the lane holds at most 32,768 drained records and then
  stops draining, so at 1,000 exec/s (about 2,100 records/s) a pass
  absorbs about 15 s of held records plus about 4 s of ring. The
  measurements below used the 2 MiB ring and 8,192 held records. The peak
  fill came at the first pass in every sample above. On a contended
  host (builds running; excluded from the numbers above) cold first
  passes with 3.1–3.5 s of deep scan peaked at 73–79% of the ring with
  no loss, and one pass with 5.7 s of deep scan (load 21) filled the
  ring: 7,557 records lost, 55 edges demoted, 3 recovery rescans, all
  disclosed as below.
- Kernels/conditions: `--system --capture native` under unrelated exec
  churn, 3 cold + 3 warm 60 s samples per cell, host kernel
  7.0.0-34-generic.
- Disclosure: `observation.lifecycle` (`records`, `ring_loss`, `malformed`,
  `failed_quanta`, `recovery_rescans`), the `native capture lifecycle
  evidence lost` gap, sticky demotion of `watched_no_use`, and an immediate
  bounded recovery rescan (never two in a row). The ring's high-water
  fill is `P11SCOPE_STAGE_TIMINGS=1` stderr telemetry only (pass lines
  and stop line), not a schema key.
- Workaround: quiet host, narrower scope.
- Planned: the v0.2.0 numbers landed in the short tier; the 2 MiB
  inventory-only ring (C7 B2) removed the 1,000 exec/s loss. At 3,000
  exec/s and beyond any loss stays explicit, with its demotion rate
  published.

### Busy hosts: skipped mapping hooks start new coverage eras (v0.6.0)

- What the user sees: on a busy host the kernel can skip p11scope's
  mapping hooks (a preempted hook counts a recursion miss). Each skip
  starts a new coverage era: calls in flight are counted as unattributed
  (`fault_era`), and key-operation tracking ends for keys that existed
  before the skip, with a named gap. Each running program's load is
  proven again; a load whose mapping is unchanged keeps its instance
  row (and ID). In an inventory report that row reads `uncertain` /
  `semantic_loss`, as any row crossing a coverage era does: a
  same-address reload hidden by the skip would merge into it. The stop
  line's `eras` count tells these runs apart from runs without skips. A
  changed load gets a new row. Call totals stay exact.
- Measured: under deliberate CPU contention (5 busy loops on a 5-vCPU
  VM, 1,000 calls/s, 60 s) about 1,700-2,800 map and 5,400-5,900 unmap
  misses; 91-93% of calls were joined and the rest were counted as
  unattributed. Before v0.6.0 the first miss ended attribution for the
  rest of the capture.
- Disclosure: the stderr stop line ends with `hook misses N, eras N,
  instances N`; the `semantic calls unrouted` gap counts `fault_era`
  calls; the Joint gap names `joint_seal_fault_changed_history_loss`.
- Workaround: a quieter host, or fewer competing CPU-bound jobs during
  the capture.
- Planned: moving the mapping hooks off preemptible trampolines
  (v0.7.0 list).

### Data-only mappers are not callers; copied code is not inventoried (A6)

- What the user sees: since v0.3.0 (unreleased), a process is a caller of a
  provider only when its `/proc/<pid>/maps` shows an executable (`x`)
  mapping of the provider file and that range passes the identity proof.
  A process that maps the file only without `x` (a scanner or backup tool
  `mmap`-ing it read-only, or a loader between its first `r--` mapping and
  the text) is excluded: no edge, no attribution loss, no coverage gap. A
  process caught mid-`dlopen` is picked up by the next pass.
- Kernels/conditions: all. Changed in v0.3.0 for callers past the
  deep-scan cap (maps matches); a deep scan always required an executable
  mapping.
- Not a spoofing path: an edge still needs the target's own executable
  range, read inside its pidfd/start-time pin and proven against the
  observer's held file. Only the target, or something with ptrace-level
  control over it, can change its mappings.
- Evasion limit: p11scope is an observer, not a security boundary. A
  process that deliberately avoids a file-backed executable mapping of the
  provider (it `read()`s the provider into memory, or copies its code into
  anonymous executable memory) is not inventoried in v0.3.0, and was not in
  earlier versions either. Uprobes on the provider file do not see copied
  code either.
- Disclosure: none; exclusion is the definition of a caller, not a loss.
- Workaround: none needed for ordinary loaders.
- Planned: none.

### Mechanism approval union past 1,024 publishes an official-first subset (v0.6.0)

- What the user sees: the `MECH_SHAPE` map holds 1,024 mechanism ids. When
  the approval union (the official PKCS#11 3.2 catalog plus the configured
  registry) exceeds that, the session publishes the official catalog first
  and then registered ids in ascending order up to the cap, instead of
  refusing to start. Unpublished ids count through the existing unregistered
  path (counted, never decoded). With the shipped registry (465 approved)
  nothing is unpublished.
- Kernels/conditions: all; a registry-growth event, not reachable today.
- Disclosure: `evidence.unpublished_mechanisms` (count, 0 when nothing was
  shed), the `unpublished mechanisms` gap, and `PARTIAL` when nonzero.
  Render-side shape notes are computed over the published subset only.
- Workaround: none needed; the capture continues with the subset.
- Planned: the cap follows the map; growth past it stays a count-gapped
  subset, never a refusal.

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
  module-level `unbound_use`, never a caller edge. The concise summary
  counts them instead: `unidentified callers: at least N calls from M
  caller processes not fully identified (exited or never scanned)`, with
  `modules[].unbound_use.images` per module and
  `observation.native_witnesses.unbound_images` run-wide in JSON
  (`images_saturated` / `unbound_images_saturated` mark lower bounds).
  Each image also lists its historical host pid
  (`modules[].unbound_use.pids`, up to five on the concise line):
  never the process now holding that number, and never re-read
  through `/proc` for the numbers themselves. Each image's
  executable is named beside it (`modules[].unbound_use.executables`,
  grouped with call counts on the concise `unidentified executables`
  line): the EXEC-joined kernel `(dev, ino)` resolved to a path
  through a live `/proc/<pid>/exe` (generation-checked), the scan's
  admitted-caller identities, or the system binary index. An image
  whose EXEC never arrived reads why: `exec_record_lost` (counted)
  under lifecycle loss, `no_exec_record` when the exec predates the
  capture or the ticket was unavailable (PID scope stamps none; a
  fork child that never exec'd has no EXEC record of its own; a
  process that exec'd before the capture, called during it, and
  exited before the first scan pass leaves no record and no loss —
  the known gap), `exe_unavailable` when the kernel read failed, or
  `path_unknown` (deleted file, container overlay, or a binary
  outside the system index). A re-exec keeps its ticket with the
  latest EXEC winning the pair. An exec-chain image that was never admitted
  (a thread exec inside one pass) likewise binds nothing: the
  retired caller's edge reads `unknown`/`use_before_admission` and
  the use is disclosed only via `unbound_use` (see the next entry).
- Kernels/conditions: P4/P5-style exec chains and short-lived callers.
- Disclosure: `modules[].unbound_use` (rows/reasons/entries plus
  `images`/`images_saturated`),
  `observation.native_witnesses` (rows/bound/unbound/pending,
  `unbound_reasons`, `unbound_images`/`unbound_images_saturated`,
  `identity_unavailable`/`identity_budget_exhausted`), and the `used
  by an unidentified caller image` / `native witness without mapping
  evidence` / `without a module` / `rows failed validation` gaps.
  Zero false joins is the hard bar and holds. Caller images that
  never got an identity are missing from the image counts: a nonzero
  `identity_unavailable` (with `identity_budget_exhausted` when the
  ticket budget spent itself) is disclosed on its own concise line.
- Workaround: long-lived callers (≥2 passes).
- Planned: v0.3.0 (measure unbound ratio per cell after C5; I2c exact-image
  iterator or a documented boundary; D6 rule-3 relaxation only if
  `before_admission` ≥20% with zero false joins on P5).

### Leader-exit and exec-chain callers under `--system` stay unattributed (DR-05)

- 2026-10-26 cold admission (qualified at the discovery seams, with a
  live cell): an already-zombie thread-group leader with exactly one
  live survivor admits as a caller with the survivor-served image and
  the leader birth — including a group first met after its leader
  died — and both identity backends then attribute its held mappings
  exactly like the warm path. Two or more live survivors are refused
  (admission names the ambiguity; a live scan reports such a group
  like an exited one); a fully dead group keeps the generic gone
  refusal. Cold callers make no native-use claim (they stay unproven
  for native binding).
- Development checkpoint: discovery can classify a zombie-leader group as
  exited even while a surviving thread runs, and omit that group from its
  membership result. An absent group does not
  prove that its provider use or surviving threads have ended. Complete
  live-group inventory is not supported by this checkpoint.
- What the user sees: a process whose thread-group leader has exited while
  other threads keep running (a zombie leader), and that was left with
  two or more running threads, is still not admitted as a caller: it has no
  `callers[]` record and no edge, and its provider use appears at most as
  module-level `modules[].unbound_use` (only when another process got the
  provider attached, with the `used by an unidentified caller image` gap);
  otherwise only the `process view` gap marks the omission. An exec chain whose images
  exec within one pass likewise binds no image: its rows are unbound as
  `exec_after_admission`, `no_live_caller` or `before_admission`, and the
  retired callers' edges read `unknown`/`use_before_admission`.
  A caller that execs into a different binary while a pass collects can
  bind no image for the rest of the capture: its native calls survive
  only as module-level `exec_after_admission`.
- Kernels/conditions: all; `--system` scope (for `--pid`
  see DR-C3-2).
- Disclosure: the pid-less `process view` gap ("a process in scope could
  not be retained or scanned before it changed"), `modules[].unbound_use`
  (`rows`, `reasons`, `images`, `pids`), `observation.native_witnesses`
  (`unbound_reasons`, `unbound_images`), and the per-pass `unbound_rows`
  of the event stream. The gap names no pid; `pids` lists historical
  host pids only (never the live holder, never re-read). No watch or
  positive claim is made for these processes.
- Workaround: none for complete caller coverage. Module-level observations
  describe captured rows; they do not establish coverage of an omitted group.
- Future work: live-capture enumeration of never-before-seen zombie
  leaders; outside this intermediate checkpoint.

### Overlay xino/copy-up identity divergences (D-C7-2/D-C7-3)

- What the user sees: provider files reached through an overlay merge
  can attribute differently depending on the kernel and on whether a
  file was copied up (the first write through the merge copies the
  lower file to the upper layer). Before 6.8 (lane A) a copy-up splits
  identity: the pre-copy-up anchor names the lower file while new
  mappers name the upper file, so neither side joins (no edge on
  either backend, disclosed). Two mounts over one lower file join on
  the kernel side only before 6.8 (D-C7-2: the kernel correctly
  reports the same underlying file while the userspace side reports a
  named mismatch), and never join on 6.8+ (lane B). A copy-up on
  6.8+ keeps the overlay file number (D-C7-3). A process that loaded
  the provider before the copy-up keeps running the original lower
  file; since v0.6.0 inventory no longer attributes it to the
  copied-up file. A provider file reached through overlayfs (or an
  unproven filesystem) at the same key requires the kernel
  original-file witness before its row joins, one query per file:
  the kernel proves the association or the row is unknown with the
  `original_file_unproven` gap — never a join to the fresh file on
  a proven-another-file verdict, on either identity backend, and
  the deep-scan row takes no userspace `(dev, ino)` fallback.
  Under cgroup-scoped collection the witness is deactivated (the
  userspace-only path), so an unavailable witness there publishes
  the scanned row with the named gap (PARTIAL coverage, no proof
  claimed) instead of an empty view; a proven-another-file verdict
  still never joins. A proven-another-file row's original edge reads `ended`, its
  later calls are not counted, and no new-module edge is emitted; a
  process that maps the upper copy is still attributed exactly. The
  sweep carries the same no-fallback rule: an overlay key (overlayfs
  or an unproven filesystem) never takes the userspace `(dev, ino)`
  fallback anywhere in the sweep ladder. A below-threshold batch still
  runs the kernel for overlay keys, and an unavailable kernel run
  yields the named `overlay_kernel_unavailable` maps-attribution loss
  — never an edge. An overlay key in a batch forces the kernel run
  for the whole batch: non-overlay requests there take kernel proofs
  instead of the below-threshold userspace path (identical only in
  batches with no overlay key) and spend the pass's 3-attempt budget.
  In `inventory --system` with the kernel identity backend, a watched
  overlay provider (attach-set exclusion, for example a provider
  inside a container) proves through a private witness session with no
  exclusions, one query per watched (pid, key) under a per-pass budget
  of 8 queries on kernel-route passes; each pass starts past the
  queries the previous pass spent, so with more than 8 refused callers
  every pass proves a different 8 and each caller alternates between
  joined and the named loss. Passes with no kernel route at all (auto
  fell back: a nested observer's numbering mismatch, missing BTF) prove
  every refused overlay candidate through the same private session under
  a per-pass budget of 1024 queries, rotating past them exactly like the
  kernel-pass window, so turn-taking starts past 1024 there. Single-shot
  sweeps (`inspect --system` and inventory collection, which run no
  kernel run at all) prove through the same witness under the 1024
  budget. A same-file verdict joins, anything else (another file,
  failure, budget exhaustion) keeps the named loss, never a userspace
  join. While a caller waits for its turn, its edge reads uncertain
  and its in-flight operations end as unknown. The witness also
  covers refused overlay ranges from unproven requests in an ordinary
  kernel batch: callers the run never visited, demoted duplicates,
  and zombie batches. A pass whose anchors never installed because
  every anchor is watched takes the same witness route with no sweep
  kernel run. The remaining sweep paths keep the named loss with no
  witness query: cgroup-scoped collection (the userspace-only path),
  a segment after the pass's third kernel run or another run failure
  (sticky, deadline, stream, headroom), an oversized single caller
  (which reads its ranges and then refuses), file-descriptor pressure
  (every pid takes the immediate path, which reads and then refuses,
  including its idle promotions), a failed kernel expectation or
  anchor install that is not capture-excluded, a failed kernel
  session setup (creation error or setup file-descriptor shortage,
  which stays failed so every later pass takes the plain userspace
  path), and the explicit userspace identity backend (which never
  reaches the witness). The pure-userspace sweep reads the ranges and
  then refuses the join; the kernel ladder refuses without reading
  them, except the oversized, cgroup, immediate and failed-install
  paths which read and then refuse (still never an edge).
  One verdict covers the file: the deep-scan witness proves the first
  witness-requiring caller range, and a same-file verdict joins every
  range of the group. A process that maps one provider both before and
  after a copy-up (mappings on both sides of the boundary) would join
  its stale ranges with the fresh ones; per-range proving would
  exhaust the per-scan budget on honest multi-range joins, so the
  packet keeps one query per file and discloses this corner; the
  witness runs at most 8 queries per process scan; past the budget
  further provider files are unknown with the same gap, while files
  that prove not to be providers never spend witness work. The sweep
  witness instead requires every refused range of the key to prove the
  held file from its one confirmation: one another-file range refuses
  the whole key, one unproven range fails it closed (no extra query).
  With xino off,
  equal real file numbers on distinct layers collide on the overlay
  device on 6.8+ (a named mismatch, never an edge), while before 6.8
  each layer keeps its real device in the key so there is no
  collision; with xino off after a copy-up the userspace edge follows
  what the filesystem reports because file numbers there are
  non-persistent.
- Kernels/conditions: overlayfs merges with xino on, off, or
  same-filesystem layers. Measured on 6.1.188 and 6.6.157 (lane A)
  and on 7.0 (lane B: host, plus a 7.0.14 guest run); other 6.8+
  kernels (6.8.0-142, 6.12.111, 7.2.6) have not run these cells.
  Same-layer layouts behave like xino on: that avoids only the
  xino-off collision, not the copy-up false edge. An overlay row is
  only claimed when the stat-based xino check agrees with the
  requested mode (never mountinfo).
- Disclosure: a refused join surfaces as an `identity_mismatch` loss.
  A stale copy-up mapping surfaces as an `original_file_unproven` gap
  under the provider path, with one of four fixed causes (the witness
  proved another file, the witness query budget was exhausted, the
  witness was unavailable, the anchor binding failed). The unavailable
  cause appends the failed stage in plain words after the fixed
  `original_file_unproven: kernel witness unavailable` prefix. A swept overlay
  caller with no covering kernel proof surfaces as the bare
  `overlay_kernel_unavailable` maps-attribution loss (`inventory
  --system` with the kernel identity backend first tries the private
  witness session, 8 queries per kernel-route pass and 1024 per
  no-route pass; exhaustion keeps the same loss); only the deep-scan
  gap carries the failed stage, and a failed sweep query's stage is
  visible only in the `P11SCOPE_STAGE_TIMINGS=1` stderr line.
- Workaround: restart processes that loaded a provider before the file
  changed inside the container (for example by chmod, touch or an
  in-place write) to get exact attribution for their later calls.
  `--identity-backend kernel` does not help here. Same-filesystem
  layer layouts avoid only the xino-off collision.
- Status: the copy-up stale join shipped fixed in v0.6.0 (kernel proof
  or the named gap), and the sweep refuses its userspace fallback for
  overlay keys (kernel proof, witness, or the named loss). The
  xino-off collision and the pre-6.8 lane-A splits above remain
  disclosed limits.

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

### Live `quiet` no longer lags a first use (DR-LIVE-LABEL-LAG fixed)

- What the user sees: on the dashboard and in mid-run `edge_observed`
  records, an edge whose caller has a read-but-undecided first use of
  the module no longer reads `capture armed | activity quiet | entries 0`
  while the row waits (fixed in v0.3.0). It reads
  `capture coverage lost | activity unknown | entries ?` with
  `entries.coverage` `unknown`/`pending_first_use` until the row binds
  (then `witnessed`) or unbinds (then the unbound reason); the watch's
  proven-clean instant is not extended over the undecided row either. A
  witness row still binds only after a lifecycle drain and a health read
  that both started after the row was read, i.e. at the next pass.
- Kernels/conditions: every native run; first use of each (image,
  module) pair.
- Disclosure: `observation.native_witnesses.pending`; the `-o` snapshot
  and the stream's final sweep are exact (no pending row survives stop).
- Workaround: none needed; the live read is honest now.
- Planned: done.

### Gap retention is first-8192-wins (DR-41)

- What the user sees: on busy hosts (ambient ~1,470 gaps observed),
  first-8192-wins ascending-pid retention starves later pids' gaps; user
  workload gaps are suppressed and counted only.
- Kernels/conditions: busy hosts with many gaps.
- Disclosure: `gaps_suppressed`, `budgets.retained_history`.
- Workaround: raise `--max-gaps` (1–65,536; default 8,192).
- Planned: v0.3.0 (per-pid/per-subject fair retention; busy-host cell must
  retain owned gaps).

### A persistently failing inventory pass degrades per pass or per process (v0.7.0)

- What the user sees: one failing inventory pass no longer aborts the
  capture: the pass's delta is dropped, the earlier committed
  plan/pins/modules stay, and one `live inventory pass` gap names the
  first dropped pass (`pass N dropped: <error>`). The capture carries
  exactly one such gap however many passes drop; later drops are
  counted internally for diagnostics and do not change it. The gap
  stays for the rest of the capture, even after later passes succeed.
- Retry and escalation: the first two consecutive dropped ticks keep
  their serviced refresh requests queued for retry. From the third
  consecutive dropped tick on, every serviced request in that tick that
  did not itself fail completes without being applied (already-failed
  ones stay queued for retry), including requests for unrelated
  processes, so later ticks can serve other work. Those processes
  refresh again only on their next loader event, poll or reconcile
  pass. A tick that completes without dropping resets the count;
  dropped batch-tail publications do not count toward it.
- Kernels/conditions: all kernels; any capture whose tick candidate,
  apply or batch-tail merge fails. Transient faults recover on the next
  tick.
- Disclosure: the `live inventory pass` gap (concise/`-v` via the
  existing gap rendering; capture JSON projects it as
  `discovery subject` / `discovery unavailable`) and `PARTIAL` coverage
  for the rest of the capture.
- One broken process: when a not-yet-admitted process's own data breaks
  the pass, that process alone is held back from admission and the pass
  commits everything else, so other processes keep being admitted and
  observed. Each newcomer of the failing pass is tried alone, charged to
  the pass time budget (at least one try per pass); newcomers not tried
  in time wait under the usual pending-newcomer gap and are tried on a
  later pass. The hold carries one named gap (`live process admission`,
  projected as `discovery subject` / `discovery unavailable`), is counted
  internally, keeps `PARTIAL` coverage (never reported complete) and is
  retried after 8 passes, doubling per repeat up to 512. It ends when the
  process exits, execs, or its pid is reused by another process. Exits
  and reuse are acted on only after a process walk that read every scope
  member (below or above the view cap); a walk with skipped members
  keeps the hold and its delay. An exec record for the pid clears the
  hold even when it reports an earlier exec, so such a process may be
  retried before its delay ends.
- Calls while held: the held process's provider modules are not
  discovered or attached through it, so calls through providers that
  only it maps are not observed. If it calls into a provider already
  attached for another process, the kernel filter (by pid or cgroup
  scope, not by admitted process) may still deliver those calls; how
  they are attributed was not checked.
- Evidence checker: the release evidence checker's proxy-capacity check
  treats `discovery subject` / `discovery unavailable` as an ambient
  race, so that check alone does not fail a capture with a held
  process; the capture's coverage is still `PARTIAL`.
- Not isolated: a failure caused by already-admitted processes, by
  several newcomers only in combination, by the apply step rather than
  the candidate, or by committed-state corruption still drops whole
  passes as above while the cause persists; admission resumes once it
  is gone (for example when the breaking process exits). The capture
  still runs to its report with the one gap and the last committed
  state.
- Workaround: none needed for transient faults; restart the capture
  after a persistent failure.
- Planned: none for the isolated case (this is the intended per-process
  degradation); the non-isolated cases have no fix planned yet.

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

### `inventory --pid` leaves a one-shot caller's use unattributed

- What the user sees: a one-shot `pkcs11-tool --sign` (or any caller that
  uses and exits between two ~1 Hz inventory passes) shows its edge with
  no entries (`entries.count=0`, coverage `use_before_admission`,
  `mechanisms=null`) while the module carries the folded calls as
  `unbound_use` with reason `no_live_caller`. The same flow under
  `profile --pid` binds (the identical 7-call sign shows `C_Sign` there).
- Kernels/conditions: all kernels; `--pid` with a caller that exits before
  the next witness drain. Reproduced with and without an exec during
  capture and with and without a manifest (SoftHSM stable shape:
  1 caller retired `exited`, 1 edge, `unbound_use.entries=7`).
- Disclosure: `modules[].unbound_use` (`rows`, `reasons`, `entries`),
  `observation.native_witnesses` (`rows`/`bound`/`unbound`), the edge's
  `use_before_admission` coverage, and the `used by an unidentified
  caller image` gap. No false join is made: the use stays module-level.
- Workaround: `profile --pid` for one-shot flows; long-lived callers
  (alive across at least two passes) for inventory edge counts.
- Planned: bind PID-scope rows to the retained scope incarnation when the
  kernel pid filter proves the generation, or cache the ticket while the
  caller lives. Either needs a design that keeps pid-reuse safety
  (a pid number alone never selects the exited generation).

### Per-call overhead on attested endpoints unmeasured (DR-12)

- What the user sees: double probe cost on attested endpoints plus the
  uretprobe hazard for the Detailed subset is unmeasured in v0.2.0.
- Kernels/conditions: attested providers under Detailed capture.
- Disclosure: none yet; M2 moves to v0.3.0.
- Workaround: `metrics` mode for the lowest overhead.
- Planned: v0.3.0 (C5 R5 `bench-overhead.sh` with and without the double
  probe; C6).

### Final inventory stdout can be incomplete after backpressure or cancellation (C5.3 F7)

- What the user sees: final inventory JSON/text continues while stdout
  accepts bytes, even when the complete document takes more than five
  seconds. Five seconds without a positive write fails stdout; a reader
  pausing at least that long can receive only a prefix and lose the suffix.
  A later delivered SIGINT/SIGTERM/SIGHUP cancels final stdout; the signal
  already used to stop capture permits healthy output. A first signal after
  a duration/key stop begins finalization also cancels. Incomplete output
  gives exit 1. Dashboard text has no final stdout document.
- Kernels/conditions: ordinary Linux pipe/FIFO and TTY/PTY backpressure
  waits. Regular-file/block-device or arbitrary driver writes already in
  the kernel, event sync, atomic report publication, scheduling and
  unsettled native detach have no new wall-clock guarantee. Dashboard may
  separately spend its existing bounded restore/notices budgets.
- Disclosure: best-effort bounded stderr names no progress, cancellation
  or I/O failure and exact locally accepted/total/remaining bytes. A
  stopped stderr can hide the notice; exit 1 remains. Accepted bytes do not
  prove consumer parsing, screen display or durability. A successfully
  committed `-o` report and a sync-confirmed event stream remain available;
  a failure of either sink means its respective guarantee does not hold.
- Workaround: request independent `-o` output and keep stdout's reader
  progressing. A truncated JSON prefix cannot be repaired by the unwritten
  suffix. Dashboard restores saved termios before JSON, but a permanently
  stopped screen may still need `reset` after output resumes; deliberate
  stdout cancellation gives screen-restore retry zero wait budget.

### Returned event-log errors preserve independent reports (C5.4 I-4, fixed)

After the initial `started` record, a returned event-log error retires that
writer and observation continues to its ordinary stop. Inventory attempts
the independent atomic `-o` report and final stdout, identifies each failed
sink, and exits nonzero. The event file may contain a partial record; no
replacement `ended` is invented. An `ended` record may be visible after its
subsequent sync failed, so the record alone does not confirm durable
completion. Event creation and the initial `started` write remain fail-fast.
This fixes returned errors only; stalled final stdout remains limited as
described above.

### Slow stdout can truncate a live trace stream

When stdout is a slow pipe, trace output that cannot be delivered within
the bounded wait is dropped and counted as dropped bytes
(`scheduling.sink_dropped_bytes`), which can cut the last stdout line;
the report then reads PARTIAL. The `-o` file is always complete: every
line is written to it, and a file write failure is an error rather than
a silent drop.

### Runtime-built function tables need publication evidence or a manifest

- What the user sees: automatic discovery finds no table in the
  provider's file-backed data, attaches 0 probes, and reports
  `discovery skipped <path> — no function table was found in its
  file-backed data; ...`. A table stored only in runtime allocation is
  outside the file-data scan's reach. A getter return observed after its
  watch attaches can supply the table; earlier returns are not replayed.
  SoftHSM 2.6.1 on Ubuntu keeps its table in the file and needs no manifest.
- Kernels/conditions: all kernels; any provider that builds its
  function table at run time instead of keeping it in the file.
- Disclosure: the `discovery skipped` line above, which ends with the
  `p11scope-discover` command that observes the provider, and the
  0-probe attach count.
- Workaround: build a manifest with the offline helper and pass it to
  the capture: `p11scope-discover --module <path> -o manifest.json`,
  then `--manifest manifest.json` on the capture command. This supplies
  validated targets to Detailed captures, inventory's ordinary count plan and
  its optional S1 lane. Count inputs must match a provider mapped in the
  selected scope and pass identity/ABI checks before shared admission; they
  do not grant object or interface-selection authority.
- Planned: automatic discovery of run-time-built tables is planned for
  a later version.

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
  scope-level `pid namespace` gap. Exception: `inventory --cgroup` is
  refused for a nested observer with `pid-namespace-mismatch`; use
  `inventory --system`, which proceeds with that scope-level gap. With no
  `/proc` entry for the observer at all, every capture except
  `inventory --system` is refused instead.
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
  but sees none of its processes; a `--cgroup` capture that finds no modules
  and cannot prove every member visible refuses with `pid-namespace-mismatch`,
  naming the container PID namespace and the hostPID remedy (exit nonzero, no
  report). A `--system` capture instead starts on the idle node and keeps
  watching: an empty run reports PARTIAL with the `pid_namespace` cause until
  providers appear, then counts them. Fixed in v0.7.0 (was: exit 0 with "no
  PKCS#11 modules discovered", not naming the cause; `--system` refused the
  same way until rc-18, when idle-node start became the behavior).
- Kernels/conditions: cgroup captures without PID visibility that find zero
  modules and prove no membership; captures that find in-namespace providers,
  and every `--system` capture, proceed with the PID-namespace warning as before.
- Disclosure: the refusal names hostPID/PID visibility; troubleshooting
  doc covers it.
- Workaround: run with hostPID.

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

- What the user sees (v0.2.0): the native lane records which caller image
  used which module (`witnessed`, first at `first_ns`) or module-level use
  by an unidentified caller; it never reports per-caller entry counts or
  recency, so every unattested provider (most real providers) shows "used,
  count/recency unavailable". Since v0.3.0 (C7 C4, this branch) the native
  lane publishes per-edge entry counts: a bound row reads `counted` with a
  saturating lower-bound `count` since the pair's first record and
  `last_seen` at pass resolution, and a missing pair reads `unknown
  (uncounted)` with the `PairInsertFailure` evidence, never 0. The C5
  oracle pins the ledger contract: P1/P2 edges read `counted` (even
  unattested B) with the exact attach-side count when the feed covers
  every in-window call, and must-fail fixtures cover above-ledger,
  published-0, absent-as-0 and pre-admission-counted outputs.
- Kernels/conditions: all native runs.
- Disclosure: `entries.coverage.state` (`counted` since v0.3.0,
  `witnessed` in v0.2.0), `entries.count` with its `observation`, dashboard
  activity, and `observation.native_witnesses`. `last_seen` comes only from
  counted entries.
- Workaround: `profile` for exact function-level counts (aggregate maps
  stay exact under event loss).
- Planned: v0.3.0 (C7: V1 non-fetch atomic add in `CALLER_USE`; C4
  published, C5 oracle landed, M2 cost gate PASS — counting overhead
  immaterial on every cell with 0 count errors — DR-02 closed; see the
  per-edge counting-overhead row).

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

### Linux x86-64 and Multi-capable live hosts

Live capture requires a Linux x86-64 host with usable `uprobe_multi` load and
self-link capability under the current credentials, normally Linux 6.6+ or a
working backport. Capability is tested, never admitted by version. Missing
capability refuses with `live capture unavailable` or `live capture did not
start` before capture, output changes
or a user workload starts, including explicit `--attach-backend singles`.
Safe scoped Singles remains available on eligible hosts; PID Multi additionally
requires a proven kernel PID filter. Help, version, inspect, discovery, saved
report read/diff and genuine `inventory --capture scan` remain usable without
the live gate. Non-Multi live support may be reconsidered around 0.9.x; no
release commitment is made.

BTF, permissions, scope, identity/ABI and required feature checks still apply.
Release binaries are x86-64 only; AArch64 and cgroup v1 remain outside scope.

### `run` under `sudo` restores groups and home (DR-56, fixed in v0.6.0)

- What the user sees: `sudo p11scope run -- tool` starts `tool` as the
  invoking user with the invoker's supplementary groups, so HSM and
  device-group providers (opencryptoki, group-owned SoftHSM token
  directories, pcscd) keep working; `HOME`/`USER`/`LOGNAME`/`SHELL`
  come from the invoker's passwd entry and `XDG_RUNTIME_DIR` from
  `/run/user/<uid>` when that directory exists and is owned by the
  invoker. Interpreters and `/proc/self/fd` edges behave as documented.
  An account the observer cannot resolve refuses with a plain message
  before anything starts.
- Kernels/conditions: sudo launches.
- Disclosure: usage `run` safety boundary.
- Status: shipped fixed in v0.6.0. The child keeps `no_new_privs` with
  clear capabilities; `-v`/`--verbose` prints the restored identity as
  `running <cmd> as <user> (uid <uid>) (groups and home restored)`.
  The old workaround (`profile`/`trace` against an already-running target,
  or a capability-carrying observer) is no longer needed for this.

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
  unprivileged process with capabilities cleared and `no_new_privs` set.
  Elevated invocations clear supplementary groups when changing identity;
  ordinary non-root invocations may retain their non-root groups. It reads
  through a preopened `/proc/self/mem` descriptor and keeps dumpability
  disabled while provider code runs. This is not a seccomp/Landlock jail.
- Kernels/conditions: all helper runs.
- Disclosure: usage attested-capture workflow; helper must match the
  provider ABI/libc and never carries capabilities or set-id.
- Workaround: run the helper as an ordinary user on an isolated host.
- Planned: v0.3.0 owner decision (jail policy; hostile-provider tests if
  pursued).

## Packaging

### Toolchain: 1.99.1 only; 1.88 MSRV retired

- What the user sees: the release compiler (`.release-rust-version`,
  currently 1.99.1) is the only supported toolchain (edition 2024, Linux
  x86-64). The 1.88 floor and its CI job are gone; build containers use
  `rust:1.99.1`. `crates/ebpf-common` stays at rust-version 1.97 because
  the pinned BPF nightly-2026-05-20 (rustc 1.97) also compiles it.
- Kernels/conditions: all builds.
- Disclosure: `docs/install.md` build section, `docs/development.md`, contract
  test `ebpf_common_rust_version_matches_the_bpf_nightly`.
- Workaround: install 1.99.1 (`mise install`).
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

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Using p11scope

This is the operator's guide: what the tool does, what it refuses to do,
how to run it, and what its output actually proves. Measured examples below
name the script that produced them so they can be reproduced; fixed
implementation limits are code contracts, not measurements.

> **Status: unreleased; the current candidate is undergoing release qualification.**
> Memory-scan discovery, `C_GetInterface`, `inspect`, `doctor`, public `run`,
> multi-module capture, schema v3, and owned-child live discovery are
> implemented. The frozen pre-W3 candidate at `ae8494d` passed all six
> semantic/privacy/cleanup rows on Ubuntu 22.04 kernel 5.15 and Ubuntu 24.04
> kernel 6.8. Those historical results do not qualify the current candidate. Fresh
> exact-tip runtime qualification, CI, complete packaging, publication, and
> release remain pending.
> See the
> [safe metadata design](superpowers/specs/2026-08-13-safe-and-unvalidated-metadata-design.md)
> and the
> [productization design](superpowers/specs/2026-08-15-productization-slice1-discovery-and-trust-design.md).

- [What it does](#what-it-does)
- [What it does NOT do](#what-it-does-not-do)
- [Quickstart](#quickstart)
- [PKCS #11 versions and interface names](#pkcs-11-versions-and-interface-names)
- [Privileges, per environment](#privileges-per-environment)
- [Kernel floor and unsupported environments](#kernel-floor-and-unsupported-environments)
- [Overhead (measured)](#overhead-measured)
- [The evidence/completeness model](#the-evidencecompleteness-model)
- [Honest claims](#honest-claims)
- [Related docs](#related-docs)

## What it does

`p11scope` attaches eBPF uprobes to a running process's (or a whole
cgroup's) PKCS#11 provider `.so`, at offsets discovered from the
provider's own function table — no source changes, no config changes, no
replacing the module with a shim. It aggregates function/mechanism/error/
latency counts (`profile`/`metrics` modes) or streams one line per call
for a bounded investigation window (`trace` mode), and writes a versioned
`observed-profile.json` for migration assessment
(`docs/schema/observed-profile-v3.md`) or an operator to read directly.

## What it does NOT intentionally decode

There is no decoder or dump flag for PINs, key material, `CKA_VALUE`, labels,
`CKA_ID`, plaintext, ciphertext, signatures, wrapped blobs, random output,
operation-state blobs, raw mechanism byte arrays, raw session handles, or
ordinary buffers.

The privacy-first 1.0 product boundary is function, registered-mechanism,
return-code, latency, and lifecycle evidence. The default release does not
correlate object handles and does not promise symbolic `CKA_CLASS` or
`CKA_KEY_TYPE` output. The unsafe diagnostic build described below does not
enlarge the default allowlist.

The default capture policy is `allowlisted`. Under it, pointer-derived bytes
reach output only by exact membership in a finite published set — a mechanism
id in the registry, or one of the 104 published function names — so a caller
that aliases a metadata pointer into unrelated readable memory produces no
decoded value rather than an arbitrary read. `metrics` mode uses
`aggregate-only`, which reads no call arguments in the kernel at all.

The older unvalidated fixed-offset decoders still exist as a diagnostic, but
only in a build compiled with the off-by-default `unsafe-unvalidated-metadata`
Cargo feature *and* run with `--unsafe-unvalidated-metadata`. The flag alone
cannot enable code absent from the shipped eBPF object, `metrics` refuses the
flag, and the observer prints a warning naming the exposure when it is active.
The official release artifact is built `--no-default-features`, and packaging
fails if the unsafe path is reachable. See
[docs/superpowers/specs/2026-08-10-p11scope-outputs.md](superpowers/specs/2026-08-10-p11scope-outputs.md#what-you-will-not-see-by-design-in-every-mode)
for the design commitment and
[docs/privacy/allowlist-v2.md](privacy/allowlist-v2.md) for the field-by-field
enforcement (what is captured, why, and how each read is gated — structural
where a leak is impossible by construction, runtime-gated where a length/
null check stands in front of the read, each gate named with the test that
exercises it). The canary matrix includes secret, unterminated, and hostile-
alias `C_GetInterface` names and scans every artifact and observer-owned map
for their bytes.

A profile is evidence of what the application *did* during the capture
window. It is never proof of what the application *cannot* do — see
[Honest claims](#honest-claims).

## PKCS #11 versions and interface names

Support is cumulative: legacy 2.00 (67 slots), 2.01 through 2.40 (68), 3.0
and 3.1 interfaces (92), and the final 3.2 interface (104 published slots).
Newer support does not replace 2.x support.

Two matrices govern two paths, and they agree by scope. The live memory
scan walks the Slice-1 §4.1 plausibility window — 2.x at minor 40 and
below, 3.x at minor 2 and below — and a version-shaped word above that
window is refused with an explicit `unsupported function-table version`
skip plus a `PARTIAL` verdict, never silently. The offline
`p11scope-discover` helper instead implements the wider v0.1 compatibility
matrix (known-prefix decode of newer layouts), because it runs offline
against a provider file rather than live target memory. A future-minor
table therefore decodes on the helper path and refuses loudly on the scan
path; the live-export path converts the same table into counted loss, so
only a never-called provider scanned proactively can vanish, and even that
leaves its version skip behind.

The standard name `"PKCS 11"` is common but not universal. Discovery also
handles alternate, null, unreadable, and non-UTF-8 names. It walks those tables
only when standard export anchors—or an independently acquired legacy 2.40
table—corroborate the expected layout. Such a walk is a known prefix and keeps
the report `PARTIAL`; uncorroborated entries remain present as vendor evidence
and are not decoded. The observer and `p11scope inspect` make zero PKCS #11
calls. Only the explicit offline `p11scope-discover` helper enumerates
`C_GetInterfaceList`, then makes exactly ten bounded `C_GetInterface`
compatibility calls (the fixed selector/version/flag matrix) before
`C_Initialize`; these helper calls are separate from live target observation
and never initialize the provider.

Interface-name discovery reads at most 64 bytes and never crosses the readable
VMA containing the pointer. A name without an in-VMA NUL is unreadable. Text
`inspect` escapes valid names; profile, metrics, and trace publish only bounded
classification consequences, never the name bytes.

## Quickstart

Start with `inspect`: it shows every provider-shaped module the target maps.
An optional `--module` only narrows that set. On the measured p11-kit stack,
p11-kit's fixed closure array exceeds the 512-slot ceiling and is refused
whole, while the later-fitting SoftHSM2 backend attaches; the report is
explicitly `PARTIAL`, not a claim that the proxy layer was captured.

The commands below begin with **passive diagnostics**. Without an accepted
manifest, scanned function slots are count-only: use their aggregate counts,
return values and latency. They still carry standard names when the provider's
own `.dynsym` exports every standard name exactly where its function table
points (`discovery[].tables[].linkage: "exports"`, as SoftHSM2 does); a table
with no such evidence stays unnamed, and its rows read `unknown#<ordinal>` in
the live table and trace (`functions[].ordinals` and `functions[].target` in
JSON), never a guessed name. Missing mechanism or session evidence does not mean
the application used none. For those semantics, use the separate
[attested capture workflow](#attested-semantic-capture).

```bash
# 1. What can this host do, and what does the target map?
p11scope doctor --pid 12345
p11scope inspect --pid 12345

# 2. Count-only diagnostics — no helper or observer-initiated provider calls.
sudo p11scope profile --pid 12345 --duration 60 -o observed-profile.json

# 3. Or stream one line per call.
sudo p11scope trace --cgroup /sys/fs/cgroup/... --duration 15

# 3b. Or capture the whole machine with no PID or cgroup path.
sudo p11scope profile --system --duration 60 -o system-profile.json

# 4. Or start capture before releasing a command that loads the provider.
sudo p11scope run --module /opt/vendor/lib/pkcs11.so \
  -o observed-profile.json --pause auto -- /opt/application/bin/workload
```

> **`run` safety boundary:** `sudo p11scope run` requires valid non-root
> `SUDO_UID` and `SUDO_GID` values naming one existing non-root account and
> drops the child to that identity before releasing its private barrier. Root
> without that explicit target and set-id invocations are refused. These
> environment values select the target account but do not authenticate that
> the launcher was `sudo`. The child has no capabilities, cannot gain
> privilege across exec, receives only `PATH`, C locale, optional `TERM`/`TZ`,
> and `SOFTHSM2_CONF`, and does not inherit unrelated file descriptors. The
> command is an opened ELF executable; invoke scripts explicitly as
> `/bin/sh /path/to/script`, and use `/usr/bin/env NAME=value command` after
> `--` for other application variables. Owned launch requires procfs mounted
> at `/proc`: the opened executable is invoked through `/proc/self/fd` so a
> later path replacement cannot change the selected inode. If that descriptor
> path is unavailable, `run` reports the exec failure and refuses to retry the
> command's original path. The sudo path currently clears
> supplementary groups; use `profile`/`trace` against an already-running
> workload when the application needs an HSM/device group. When the observer
> binary instead carries file capabilities (`setcap
> 'cap_sys_admin,cap_bpf,cap_perfmon,cap_sys_ptrace,cap_dac_read_search+ep'`),
> it runs unprivileged with its groups intact: BPF attach succeeds and
> group-gated providers (e.g. opencryptoki's group-owned shared memory) keep
> working under observation. Measured 2026-09-15 on Fedora 44 (6.19) and
> Ubuntu 22.04 (5.15); see
> [2026-09-15 provider-qual note](notes/2026-09-15-provider-qual-live-capture.md).

### Capture tuning: `--ring-bytes` and `--drain-interval-ms`

Two flags trade burst headroom against drain rate; both accept profile, trace,
and run, and both are disclosed in every JSON report's `capture` block as
`ring_bytes` / `drain_interval_ms`, so a report always says what tuning
produced it.

- `--ring-bytes <n[K|M]>` — the EVENTS ring buffer size: a power of two from
  4K to 64M (default 4M). A larger ring absorbs call bursts without loss; a
  smaller ring overflows sooner. Overflow never corrupts counts — the
  aggregate maps are the count authority — but it is disclosed as `event_loss`
  with a `PARTIAL` verdict instead of `COMPLETE`.
- `--drain-interval-ms <n>` — the frame interval: 5 to 60000 ms (defaults:
  profile 1000 ms, trace 200 ms). A shorter interval refreshes discovery,
  aggregate maps and live output more often, with more observer CPU cost.
  Events drain on every loop tick. The frame interval does not delay a
  `run --pause` stop. While a pause epoch is armed, the loop checks for a
  pending stop on every loop tick (every 2 ms when idle; one map read between
  frames) and services it at once. Busy ticks can spend up to 50 ms draining
  events, and trace ticks can spend up to 250 ms writing output, so the check
  is not a fixed wall-clock polling guarantee. The stop's 500 ms deadline is
  unchanged.

```bash
# Burst-heavy workload: bigger ring, faster drain.
sudo p11scope profile --pid 12345 --ring-bytes 4M --drain-interval-ms 100 \
  --duration 60 -o observed-profile.json
```

The induced-gaps gate (`scripts/verify-induced-gaps.sh`, gap 3/3b) proves both
directions: the small-ring build and the default build with `--ring-bytes 4K`
produce the same disclosed event-loss evidence with exact counts.

Measured loss rates — the only bench-measured tuning data points, from the
`scripts/bench-overhead.sh` run in "Overhead (measured)" (1M back-to-back
calls/sec, then-default 256K ring): `profile` (1s drain) lost 991,290-991,350
of 1,000,000 events (99.1%+); `trace` (200ms drain) wrote only
122,348-145,383 lines. A faster drain cadence meaningfully reduces loss
but does not eliminate it at that call rate. No larger `--ring-bytes`
value and no other `--drain-interval-ms` value has been bench-measured;
tuning beyond these two points is unmeasured, not tuned-down.

### Attested semantic capture

This is an explicit trust decision about the provider's function names and
offsets. Use a helper that can load the exact provider: a 32-bit provider
requires a 32-bit helper, and its loader/libc must be compatible. The observer
remains x86-64. Final release artifact/helper combinations are still undergoing
qualification; a source-build result alone is not a packaged compatibility
guarantee.

```bash
# Run as an ordinary user. This helper loads and executes provider code.
p11scope-discover --module /opt/vendor/lib/pkcs11.so -o provider-manifest.json
```

Review the generated manifest against the provider you intend to observe.
Continue only when you accept its exact object, canonical function names and
offset claims; automatic discovery output is not independent attestation.
Then supply that manifest explicitly:

```bash
sudo p11scope profile --pid 12345 --module /opt/vendor/lib/pkcs11.so \
  --manifest provider-manifest.json --duration 60 -o observed-profile.json
```

The observer still applies object/table/provenance checks. An incompatible,
stale or ambiguous claim is not permission to guess semantics; inspect the
reported discovery evidence rather than treating a successful command exit
as semantic acceptance. A manifest does not recover calls before attachment.

With accepted semantics, the default `allowlisted` profile can report admitted
mechanism IDs and lifecycle evidence. **Every emitted mechanism has
`params: null`, and `templates.operations` is always empty under this policy.**
Those omissions are deliberate policy limits, not evidence that the application
used no parameters or templates. Candidate-provider testing and observed
application coverage remain separate evidence; neither certifies migration
compatibility for unobserved calls or undecoded parameters.

### Discovery timing and optional offline discovery

The memory scan builds the initial attach plan. For an owned command,
`p11scope run` starts capture before releasing the child and can acquire a
provider loaded later. The frozen pre-W3 candidate at `ae8494d` passed the
local six-row campaign on kernels 5.15 and 6.8; that campaign has not been
repeated on the current candidate. For an already running external process, a provider
loaded before attachment can still be
missed. If a suitable manifest was prepared while the same provider identity
was available, pass it
with `--manifest`; it is explicit operator attestation of exact accepted
function-name/offset claims, hash-matched against the pinned file, and
corroborated when the provider is already mapped. Scan-only discovery is
semantics-unverified and count-only, but aggregate counts/RVs/latency remain
available. A helper run after the fact cannot repair a missed capture window,
and `--manifest` remains the explicit-attestation path for that case.

Attach takes time to land (seconds for hundreds of probes), and the first
calls after a `dlopen` can fire before their probes exist — a workload that
exits in milliseconds can be gone before attach completes, even with
`--pause auto`. Measured 2026-09-15: keep the workload alive past attach
(a sleep/hold phase, `LD_PRELOAD=<provider.so>` so the initial scan sees
it, or long-lived daemons via `profile --pid`), and expect the earliest
post-load calls to be absent from the counts.

`p11scope-discover --module <provider.so> -o manifest.json` is that optional
offline path. It executes provider code in its own unprivileged process; the
normal manifest-free path does not execute provider code. `--module` is also
optional and only narrows the memory scan to named providers.
`p11scope-discover --module` must be an absolute path — a relative path is
refused rather than resolved against a surprising directory.

Provider entry points are hooked through five built-ins
(`C_GetFunctionList`, `C_GetInterfaceList`, `C_GetInterface`,
`NSC_GetFunctionList`, `FC_GetFunctionList`). `--hook-symbol NAME[:ABI]`
adds one more symbol to hook; `:ABI` is `functionlist` (the default),
`interfacelist`, or `interface`, and may be repeated. It is accepted by
profile, trace, run, and inspect.

`doctor` has no module-specific probe lane. `doctor --module` is rejected as
unsupported instead of accepting and ignoring operator input; use
`inspect --pid <pid> --module <provider.so>` for module-specific discovery.

### Attaching to an existing Kubernetes pod

`scripts/attach-pod.sh` resolves a pod/container to its host cgroup and runs the
manifest-free `profile --cgroup` path. It copies no helper or provider into the
pod. The operator still needs node access and the privileges described below.

The application may already have mapped the provider at an unrelated ASLR
address. That is expected: discovery converts each live table pointer to an
ELF object identity plus file offset, and uprobes attach to that object/offset
in the selected PID or cgroup. Virtual addresses never have to match.

The default scan reads the target's mapped table; it does not call into the
provider. The optional helper reconstructs a table in its own unprivileged
process and does not read or inject into the target. Its manifest is suitable
only when that independently reconstructed table describes the same hash-pinned
provider. Anonymous or JIT-generated targets and process-specific tables remain
outside this release's completeness guarantee. The kernel keys each accepted
uprobe to the pinned inode and offset, and the BPF scope guard runs before any
argument read.

The optional helper always drops supplementary groups, UID/GID, and active, permitted,
inheritable, and ambient capabilities before loading provider code, even when
invoked from an elevated observer. The module and output directory must
therefore be readable/writable by the invoking unprivileged identity (or the
`nobody` fallback for a direct root invocation). After an ID change, the helper
restores Linux dumpability only to perform bounded reads through
`/proc/self/mem`; it does not restore groups, IDs, or capabilities.

Both `profile` and `trace` require exactly one of `--pid`, `--cgroup`, or
`--system`; `--module` and `--manifest` are repeatable optional discovery
inputs. `--cgroup` matches that
cgroup and every descendant beneath it
(kernel ≥5.15 due to attach cookies), so pointing it at a container's or pod's
directory reaches the workload's actual nested cgroup. `--system` requests
whole-machine capture with no cgroup path: the BPF scope gate admits
all tasks subject to the owner-health and config checks, and userspace
discovery sweeps `/proc` under the same `--max-scan-pids` cap (default 256,
rarest providers first). Scope admission does not promise that every process
or call is captured, and live exact-tip qualification for the system lane is
still pending: earlier receipts from other scopes do not qualify it.
Per-process and per-module attribution is still recorded —
each retained generation keeps its own view and pins — and `capture.scope`
in the JSON report reads `"system"`. Fork children are admitted without a
destination check, and short-lived processes that exit between refreshes
count `pid_descendant_gaps` through the same bounded unmatched-exit ledger
as cgroup scope (overflow latches one lower-bound increment and `PARTIAL`).
`p11scope doctor` needs no scope flags for a system capture: its host
program preflight already covers the whole-machine lane.
`--duration` (bare
seconds or `30s`/`5m`/`1h`) requests shutdown after the given interval. Probe
teardown and final reporting follow; with many attached functions, this can
add seconds, and calls may still be observed while probes are being detached.
Ctrl-C, SIGTERM, or SIGHUP ends a capture cleanly (final frame printed, `-o`
file written) instead of aborting it. Under `run`, a child the pause holds
stopped is resumed before the observer signals it or hands it back. The stop
signal is forwarded to the child's process group; a child still alive gets
SIGTERM 5 s later and SIGKILL 5 s after that, so settling it takes at most
15 s (a second Ctrl-C sends SIGKILL at once). A hangup — a closed terminal or
a dropped ssh session — is handled exactly like SIGTERM, with the same outcome
and exit status, as long as p11scope itself inherited the default SIGHUP
disposition. An inherited ignore (`nohup p11scope ...`) is preserved, so the
capture keeps running after logout. SIGQUIT keeps its default disposition
(core dump, for debugging). SIGKILL cannot be handled, and p11scope installs
no `PR_SET_PDEATHSIG`: if the observer is killed that way there is no final
frame and no `-o` file, and a child the pause holds stopped stays stopped —
its own session leaves its process group already orphaned, so the kernel
sends no hangup when the observer dies; resume or kill the orphan by hand.
The owned command starts with the signal dispositions p11scope itself
inherited: a SIGINT, SIGTERM, or SIGHUP ignored on entry (under `nohup`, or
a background job in a non-interactive shell) stays ignored across the fork,
so the observed program behaves as if started directly. The exception is
SIGPIPE, which the observer's runtime ignores before `main`: the child
resets it to the default, matching `std::process::Command`, so a command
that writes to a closed pipe dies by SIGPIPE instead of seeing EPIPE errors.
If the run is stopped or times out while the
command is still being handed to the child, the child is killed at once,
never resumed, so a command that had not already started never runs. A stop
still waiting for its pause cycle when the capture ends is reported as
`pause: partial`. Under `--pause always` the run fails instead: no profile
report is published (a trace `-o` stream keeps only the lines already
written), and a `--duration` child is terminated rather than handed back. A
signal that lands inside an active pause cycle (which has a 500 ms deadline)
can also end the run with a `pause coordination cancelled` error, after the
same resume and settlement and with the same `-o` outcome.

A `--cgroup` capture sweeps every member's mappings, then deep-scans at most
256 members per pass, rarest providers first; past the cap the capture
publishes a skip naming the bound. The default stays 256 by measurement
(2026-09-17, ~550-process scope: a 600-member run discovered the same
4 modules as the default run at +32% scan time, so the raise buys nothing).
`--max-scan-pids <n>` sets the cap:

sudo p11scope profile --cgroup /sys/fs/cgroup/... --max-scan-pids 512 --duration 60 -o observed-profile.json

Views without an executable (kernel threads) and static executables are not
loader-arming candidates and no longer count as `unavailable`: arming returns
a silent NotArmable outcome, retried next tick like any unarmed view, while
genuine arm failures still mark and record as before.

For cgroup event captures, `task/task_newtask` records ordinary non-thread
creation as a semantic hint and may preserve the parent's proven state while
the child is refreshed; the creator event itself does not increment
`pid_descendant_gaps`. `CLONE_INTO_CGROUP` never inherits state at the hint
boundary. The counter is destination-authenticated by successful membership
refresh admission and by a scoped leader-exit record that cannot match an
admitted generation, with each generation or unmatched exit counted once.
When the bounded unmatched-exit ledger is full, a novel unmatched exit latches
one lower-bound overflow increment. If admission already counted the gap,
coalescing overflow marks `PARTIAL` without another increment. Replayed or
further unremembered exits do not increment again.
Arbitrary enter-then-migrate-out before refresh or exit remains outside W3's
`COMPLETE` and runtime-qualified claims; no migration subsystem is provided.
PID scope remains exact and does not attach process-creation tracking.

Before either command attaches, every accepted object from the scan or an
optional manifest is opened once and pinned by file descriptor. The whole-file
SHA-256 is taken at pin time; manifest identities are matched against it (and
build-id when present). `fstat` (inode, size, ctime) is re-checked before and
after attach and during capture. Attach is refused if that identity changes; a
change during capture sets `evidence.provider_changed`, forces `PARTIAL`, and
shows " · provider changed" on the live line. Renaming over or unlinking the
pinned inode is reported by the same conservative check.

The capture retains each selected process generation through its last target
access and through attach, checking it immediately before and after session
creation. A named PID mismatch is fatal. A changed/disappeared cgroup member is
bounded `PARTIAL` evidence: only that retained view's claims are removed, and
the plan is rebuilt from stable already-opened inputs without reopening files,
rehashing, or renewing discovery budgets. Ordinary-file candidates merge only
after comparable opened-file identity and digest agree; an incomparable
collision group fails closed. The same file observed through two mount
namespaces (a container sharing the host's provider) merges by open-file
identity plus digest instead of failing the group. The existing overlay-only
byte-identical collapse is the sole heuristic exception and publishes
uncertainty that forces `PARTIAL`.

**Historical pre-terminal-drain output**, `profile --mode metrics` against a
SoftHSM2 workload (`scripts/verify-attach-e2e.sh`). Current written captures
end `PARTIAL` even with zero concrete gaps, as explained below:

```
FUNCTION                        CALLS    ERR      p50~      p95~      p99~ IN-FLIGHT
C_GenerateRandom                  100      0     2.0µs     2.0µs    16.4µs         0
C_Digest                           50      0     2.0µs     4.1µs     4.1µs         0
C_DigestInit                       50      0     2.0µs     4.1µs    65.5µs         0
...
Evidence: 136/136 probes attached · 68 slots · 0 aliased · 0 skipped · 0 in-flight → COMPLETE
```

A current capture's evidence line names why it is `PARTIAL`, grouped by the
same classes `evidence.gap_classes` publishes, for example
`→ PARTIAL: attribution withheld (68 semantics-unverified/count-only slots)`
for a clean scan-only capture (`verdict_detail: "attribution_only"`: counts
are exact, only semantic interpretation is withheld), or
`→ PARTIAL: observation lossy (12 events lost)` for a lossy one
(`"concrete_gap"`). `→ PARTIAL: terminal drain unproven` means nothing
concrete is behind the verdict (`"clean_but_unproven"`).

**Historical pre-terminal-drain output**, `trace` against the same workload
(`scripts/verify-attach-e2e.sh`'s harness, captured while writing this doc —
`sess#N` is a per-capture pseudonym, never the provider's raw session handle):

```
22:25:03.790862 pid 431682 tid 431682 sess#1 C_OpenSession → CKR_OK 4.3µs
22:25:03.791056 pid 431682 tid 431682 sess#1 C_DigestInit 0x250 → CKR_OK 155.3µs
22:25:03.791069 pid 431682 tid 431682 sess#1 C_Digest → CKR_OK 9.8µs
22:25:03.791885 pid 431682 tid 431682 sess#1 C_CloseSession → CKR_OK 3.7µs
EVIDENCE {"table_entries":68,"slots":68,...,"completeness":"COMPLETE"}
```

Every trace ends with the same machine-readable evidence object used by
profile output. If the ring buffer drops events, it also emits an explicit
`LOST n events` line rather than silently under-reporting — see
[Overhead](#overhead-measured) for when that actually happens.
Immediately before `EVIDENCE`, trace emits one aggregate-only
`COUNT_EVIDENCE {"stats_entered":…,"stats_returned":…,"raw_calls":…}` line:
the STATS fields include completed and in-flight calls, while `raw_calls`
counts every well-formed non-fork event consumed before truncation.

`slots` and `active_slots` in that evidence object (and in the live `profile`
line's `N slots (M active)`) answer different questions. `slots` is every
endpoint slot the capture has ever allocated: the plan is append-only, a slot
is never reused, and a target exiting, a failed live attach or replacement,
or a lost process generation all retire slots without giving them back — so
`slots` only grows. A service that restarts ten times over a 68-function
provider can end with `"slots":680`.

`active_slots` is the plan's active set right now, when the report is
written — it is not capture-lifetime history like `slots` is. While a
`--pid` target keeps running with everything attached, the two fields read
the same (`68`/`68`). An ordinary exit, a failed live attach or replacement,
and a lost generation can reduce `active_slots` — never `slots` — so each
only ever grows `slots - active_slots`; that difference is not a churn
count and cannot say how many restarts happened, since an exit or a failed
attach grows it.

Whether an exit drives `active_slots` to 0 depends on how the target was
pinned. A scan-only target's object is pinned to the process view that
mapped it, so its exit retires every slot that object held. A
`--manifest`-attested object stays pinned independently of any one process
view — the manifest's own claim on it survives the exit — so `active_slots`
keeps reading equal to `slots` afterward. The historical captures above are
exactly that manifest-backed case (`scripts/verify-attach-e2e.sh`'s
`observed` lane, run with `--manifest … --pid`), so if regenerated today
they would still read `"slots":68,"active_slots":68` in JSON and `68 slots
(68 active)` on the live line, not `0` (the historical output itself
predates `active_slots` and shows only `slots`). The same script's
`observed-scan` lane (manifest-free, memory scan only) exits the identical
kind of workload without a manifest and ends `68`/`0` instead.

### More capture options

- `--max-events <n>` — trace only (including `run --trace`): end the capture
  after `<n>` call events instead of running until `--duration`, interrupt, or
  target exit. Refused with a usage error on profile, which publishes one
  aggregate document.
- `run --trace` — stream one line per completed call (trace semantics) for an
  owned command instead of aggregating a profile.
- `run --kill-on-timeout` — when `--duration` expires, terminate and reap the
  owned child. Without it the default is to hand a still-running child back
  and exit 0.
- `inspect --json` — print the inspection as JSON instead of the human-readable
  text table. A scan that fails soft (the target changed mid-scan) still
  prints JSON: the success schema with `scan.status` failed and the
  reason, exit 1. A target that cannot be read at all stays a hard
  error: one stderr line, empty stdout, exit 1.
- `--allow-uretprobe-on-confined-target` — accept the uretprobe hazard on a
  target that confines syscalls instead of refusing to attach. The default
  refusal is deliberate: on affected kernels a uretprobe on a confined target
  can kill it. An unproven kernel (the self-probe could not reach a verdict)
  refuses the same way wherever the target cannot be shown unconfined —
  unreadable targets, `--cgroup`/`--system` scopes, and `run` children,
  which may confine themselves after attach. See `p11scope doctor` and
  `src/uretprobe_hazard.rs`. When the override is taken, the flag plus the
  hazard reason is recorded in report evidence (`evidence.uretprobe_override`),
  not just on stderr.
- `--version` — print the observer version (`p11scope <semver>`) and exit 0.
  Takes no scope or subcommand; anything after it is a usage error.
- `--attach-backend auto|multi|singles` — the static probe backend. `auto`
  (default) uses one multi-uprobe link per attach group on kernels 6.9+ and
  per-offset links below; `multi` forces multi (needs 6.6+); `singles` forces
  per-offset links everywhere. Dynamic loader and export probes always use
  per-offset links. The backend that owned each link is disclosed per report
  (`evidence.attach_mechanisms`).
- Trace event cap — `trace` (including `run --trace`) without `--max-events`
  still stops at 10,000,000 events: the cap is a default, not unbounded
  streaming, and the no-duration notice says so. The `TRUNCATED` line cites
  the effective cap and names `--max-events` only when the operator passed it.

### Environment (`P11SCOPE_*`)

Every `P11SCOPE_*` switch that can change capture behavior, with its effect
and default. Capture evidence records the active value of the capture-visible
ones (`evidence.p11scope_env`), so a report always says which switches were
live; absent means the narrow default in every row. `--help` lists the two
capture-visible switches; the build/lane inputs below take documented
arguments instead of environment wherever a script is invoked by hand.

- `P11SCOPE_BROAD_ADMIT` — experiment-only broad provider admission for the
  observer. Exactly `1` enables it; anything else (including unset) keeps the
  narrow default. Capture-visible.
- `P11SCOPE_LOADER_ENV_SANITIZED` — `p11scope-discover` loader-environment
  marker. The helper sets it for the provider it executes; a forged value in
  the incoming environment is rejected, never trusted. Capture-visible.
- `P11SCOPE_PRODUCT_BUILD_MODE` — build lane selector for `scripts/`: `ordinary`
  (default) builds with the ambient toolchain, `prepared` builds with the
  pinned prepared-dependency toolchain. Affects builds, never a capture.
- `P11SCOPE_PREPARED_STABLE_CARGO`, `P11SCOPE_PREPARED_STABLE_RUSTC`,
  `P11SCOPE_PREPARED_BPF_CARGO`, `P11SCOPE_PREPARED_BPF_RUSTC`,
  `P11SCOPE_PREPARED_PYTHON`, `P11SCOPE_PREPARED_RUSTUP` — pinned tool paths
  selected by `scripts/prepared-dependency-tools.sh` for prepared builds and
  dependency verification. Build-only.
- `P11SCOPE_K8S_NAMESPACE`, `P11SCOPE_K8S_WORK`, `P11SCOPE_K8S_ALLOW_CONTEXT` —
  Kubernetes lane inputs: the namespace and work directory under test, and the
  explicit context allowlist a lane may touch. Lane-only.
- `P11SCOPE_PKCS11_MODULE` — provider under test for lanes that take one as
  input (notably the capability-tier lane). Lane-only.
- `P11SCOPE_MEASURE_SEED`, `P11SCOPE_CANARY_TARGET_BITS`,
  `P11SCOPE_LANE_EVIDENCE_DIR`, `P11SCOPE_RECEIPT_WORK` — measurement and
  receipt-lane inputs: harness seed, canary word size, and evidence/work
  directories. Lane-only.
- `P11SCOPE_ORACLE_SOURCE_ONLY`, `P11SCOPE_IA32_SOURCE_ONLY`,
  `P11SCOPE_IA32_COMPAT_EVIDENCE` — oracle lane inputs selecting source-only
  checking and ia32-compat evidence paths. Lane-only.

Not operator switches (deliberately undocumented above): C header guards
(`P11SCOPE_*_H`), compile-time size selectors (`P11SCOPE_SMALL_*`), test-only
re-exec markers (`P11SCOPE_*_CHILD`, `P11SCOPE_FIXTURE_*`,
`P11SCOPE_ROOT_RUNTIME_STAGE`), fixture stderr markers (`P11SCOPE_LAZY`), and
internal lane plumbing (`P11SCOPE_LANE13_*`, `P11SCOPE_RECEIPT_*`,
`P11SCOPE_HOLD`, `P11SCOPE_FREEZE`, `P11SCOPE_DISCOVER`, `P11SCOPE_OBSERVER`,
`P11SCOPE_BIN`, `P11SCOPE_STATIC`, `P11SCOPE_DEFAULT`, `P11SCOPE_FEATURE`,
`P11SCOPE_POINTERS`, `P11SCOPE_PROGRAM_HEADERS`, `P11SCOPE_EXPORT_TABLES`,
`P11SCOPE_HASH`, `P11SCOPE_DRIVER_NEEDED`). If a new `P11SCOPE_*` name starts
changing capture behavior, it joins the table above and the `--help` list.

### Exit codes

- `0` — success. `--help` also exits 0. `run` exits 0 when its child exits 0,
  or when a still-running child is handed back (without `--kill-on-timeout`).
- `1` — a runtime failure: one line on stderr, never a panic. `run` reports
  the child's nonzero exit code instead. `doctor` exits 1 when any requested
  lane reports failure (`--extra-strict` refuses on any warning or failure
  in any assessed lane instead); `inspect` exits 1 when the target cannot
  be read.
- `2` — a CLI usage error (unknown flag, missing value, mutually exclusive
  options, removed subcommand).

## Privileges, per environment

`doctor` reports one finite availability tier for the requested host and
target. The tier is preflight evidence, not capture authority or a completeness
promise. With no `--pid`, target readability is explicitly `unassessed`.
`doctor --extra-strict` is the qualification gate: it refuses (exit 1, with
an `extra-strict refusal:` line naming every violating row) when any assessed
lane warns or fails, and states `extra-strict: no qualification violations`
when the host is fully clean.

| Tier | Proven prefix | Meaning and loss |
| --- | --- | --- |
| T0 offline | host attach failed | Offline helper, inspect, and report work only; no live-call evidence. |
| T1 host attach | supported kernel, real embedded BPF object/maps/program load, and an actual self-uprobe | Live observation works on this host; target readability is failed or unassessed. |
| T2 target readable | T1 plus one stable target generation, readable `maps`, `mem`, and `root`, and exact executable/provider identity opens through that root | The target can be planned; lifecycle changes may be missed, so an attempted capture can be `PARTIAL`. |
| T3 lifecycle | T2 plus successful real exec and exit lifecycle links | Base lifecycle coverage works; a requested scope-specific lane is unavailable or degraded. |
| T4 current full | T3 plus every requested scope operation, including filter publication, cgroup access, and process-creation tracing when required | Current mechanisms preflighted; this is neither leased/hardened authority nor a `COMPLETE` promise. |

The doctor runs the real embedded BPF object/map/program inventory and drops a
temporary session after preflighting exec/exit lifecycle links and every
requested PID/cgroup scope. T3/T4 come only from those observed operations;
they are never inferred from uid, seccomp mode, sysctls, or capabilities.
`CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, `CAP_SYS_ADMIN`,
`CAP_PERFMON`, `CAP_BPF`, and `CAP_CHECKPOINT_RESTORE` are diagnostic rows only.
There is no `CAP_SYS_RESOURCE` or `RLIMIT_MEMLOCK` requirement claim.

The current manifest-free matrix was measured on 2026-08-17 by
`scripts/matrix/verify-fork-scope.sh`, against a same-UID non-descendant with
SoftHSM2 already mapped. Host: kernel 7.0.0-28-generic,
`kernel.perf_event_paranoid=4`, `kernel.yama.ptrace_scope=1`. These rows are
Task 14 artifact evidence; Task 15 ran no new privileged experiment.

| Effective capability set | Discovery input | Scan result | Uprobe result |
| --- | --- | --- | --- |
| none | memory scan | unavailable: `ptrace`; capture exits 1 at BPF map creation | not reached |
| `CAP_BPF` + `CAP_PERFMON` | manifest | unavailable: `ptrace` | 0/136 probes |
| `CAP_SYS_ADMIN` | manifest | unavailable: `ptrace` | 136/136 probes |
| `CAP_SYS_ADMIN` | memory scan | unavailable: `ptrace` | 0 probes planned/attached |
| `CAP_SYS_ADMIN` + `CAP_SYS_PTRACE` | memory scan | available | 136/136 probes |

On this host, `CAP_SYS_ADMIN` is required for uprobe attach;
`CAP_BPF`+`CAP_PERFMON` does not suffice under `perf_event_paranoid=4`.
Manifest-free scanning of this same-UID non-descendant additionally needs
`CAP_SYS_PTRACE`. A target that is a descendant of the observer, a target that
opts in with `PR_SET_PTRACER`, or a permissive Yama policy can remove that
additional scan requirement. Cross-UID targets remain subject to the same
ptrace access check. These are host-specific measurements, not a portable
promise; run `p11scope doctor --pid <pid>` against the actual target.

There is no `CAP_LEASE`, `fs.suid_dumpable=0`, or root-owned trusted exec dir
requirement.

## Kernel floor and unsupported environments

Kernel floor: **≥ 5.15**, required by the attach-cookie design and validated
by the supported cgroup-scoped BPF path. This tool does not runtime-check
the kernel version; on an unsupported kernel or configuration it relies on
the same clear-failure path described below. Caveat, stated plainly: the
5.15 number itself was not re-derived against a live sub-5.15 kernel in
this repo — no such kernel was available to test against
(`docs/notes/phase5-unsupported.md`, case 5). It is inherited from the
Phase 4 plan, not independently measured here.

What actually happens today, measured on a real host
(`docs/notes/phase5-unsupported.md`; two real bugs — a swallowed OS error,
and the historical 136 identical unexplained lines — were found while reproducing these
and fixed, not just described):

**No `CAP_BPF`/`CAP_SYS_ADMIN` at all** — fails at BPF map creation, exit
code 1, with the real OS error plus a hint naming what to check:

```
p11scope: starting attach session: loading BPF object: map error: failed to create map `STATS`: failed to create map `STATS`: Operation not permitted (os error 1)
hint: this usually means the environment cannot load or attach BPF programs at all — missing CAP_BPF and/or CAP_SYS_ADMIN (or root), a kernel lockdown mode, a kernel below the supported floor (>= 5.15), missing BTF (/sys/kernel/btf/vmlinux), or a restrictive kernel.perf_event_paranoid sysctl. See docs/notes/phase5-unsupported.md for what each looks like when observed.
```

**`CAP_BPF`+`CAP_PERFMON` but no `CAP_SYS_ADMIN`, restrictive
`perf_event_paranoid`** — map creation succeeds. The current 2026-08-25
measurement recorded 68 attach-failure records/per-slot lines, each with the
real `perf_event_open` refusal, covering 136 probes. One synthesized summary
line follows:

```
attach failed (slot 0): p11_return at /usr/lib/softhsm/libsofthsm2.so+0x265e0: `perf_event_open` failed: Permission denied (os error 13)
...
p11scope: 68/68 attach attempts failed, every one the same way — this almost always means the environment cannot attach BPF uprobes at all: missing CAP_BPF/CAP_SYS_ADMIN (or root), a kernel lockdown mode, or a restrictive kernel.perf_event_paranoid sysctl. First underlying error: p11_return at /usr/lib/softhsm/libsofthsm2.so+0x265e0: `perf_event_open` failed: Permission denied (os error 13)
```

The tool keeps running with `attached_probes: 0`,
`evidence.completeness: "PARTIAL"` — a real, reported partial capture,
never a silent zero-count report that reads as healthy. Exit code 0
(unchanged; `scripts/matrix/verify-fork-scope.sh` depends on this).

**Missing BTF, kernel lockdown, kernel < 5.15** — not inducible on the
host this was measured on (BTF is present, no lockdown LSM loaded, kernel
is far above the floor). Not induced, not faked: these would hit the same
early-failure path as the unprivileged case above (same hint text, which
names BTF, lockdown, and the kernel floor explicitly), architecturally,
but that has not been observed on a real instance of any of the three.
Flagged as the weakest-verified claims in this section
(`docs/notes/phase5-unsupported.md`, cases 4-6).

None of the induced cases produce a panic, a raw verifier dump, or a
silent zero-count capture that reads as healthy.

## Overhead (measured)

Measured by `scripts/bench-overhead.sh` against **unobserved SoftHSM2 —
deliberately the worst case** for this measurement: SoftHSM2's
`C_GenerateRandom` is microsecond-scale software crypto, so uprobe/
uretprobe trap cost, map updates, and ring-buffer submission are
proportionally largest relative to the call itself here. A network HSM
whose calls run milliseconds would show the same *absolute* per-call
overhead as a far smaller *relative* one. Read the numbers below as "the
cost on this workload," not "the cost everywhere." Full method and raw
per-run numbers: `docs/notes/phase5-overhead.md`.

> **Staleness: this table predates policy-specific capture.** It was
> measured before `4f59ff6` ("feat: enforce policy-specific eBPF capture",
> 2026-08-13), which made the eBPF program skip ring submission in
> `metrics` mode. The `metrics` row below no longer describes this tree
> (its cost is expected to be lower, by an unmeasured amount); the
> `profile`/`trace` rows and the event-loss figures remain the best
> measured numbers until the re-bench below is run. Details:
> `docs/notes/phase5-overhead.md` ("Staleness note").

Machine: kernel `7.0.0-28-generic`, CPU `AMD Ryzen AI 9 HX PRO 370 w/
Radeon 890M`. Workload: `scripts/fixtures/hammer.c`, 1,000,000 back-to-back
`C_GenerateRandom` calls, 5 runs/condition (median and min..max spread,
not a single number):

| Condition | median wall-clock (1M calls) | median ns/call | overhead ns/call |
| --- | --- | --- | --- |
| unobserved | 788.2 ms | 788.2 ns | — |
| `profile --mode metrics` | 4041.6 ms | 4041.6 ns | **+3253.4 ns** |
| `profile --mode profile` | 4038.7 ms | 4038.7 ns | **+3250.5 ns** |
| `trace` | 4180.8 ms | 4180.8 ns | **+3392.6 ns** |

**Overhead on this workload is large: roughly a 5x wall-clock slowdown**,
~3.25-3.4µs added to every ~0.8µs unobserved call. This is the honest
number for SoftHSM2 hammered at 1M calls/sec with no per-call delay — a
ceiling, not a typical figure. It should not be read as "p11scope adds
~3.3µs to every PKCS#11 call everywhere," only "...to every call on this
workload." Against a network HSM's millisecond-scale calls, the identical
~3.3µs absolute cost becomes negligible in relative terms.

All three observed conditions cost nearly the same, despite doing very
different amounts of userspace work — the eBPF program pays for the
uprobe/uretprobe trap, the map updates, and a ring-buffer submission
attempt unconditionally, regardless of which userspace mode is running or
whether it ever reads the ring buffer at all. At this call rate that
unconditional in-kernel cost dominates. (Pre-policy-capture finding — see
the staleness note above. Since `4f59ff6`, `metrics` no longer pays the
ring-submission half of that cost, so the three-way convergence no longer
holds as stated; the re-bench below will show what replaced it.)

**Event loss at high call rates.** At 1,000,000 calls/sec with the
default ring buffer, `profile` and `trace` both lose the overwhelming
majority of per-call events — `event_loss` measured at 991,290-991,350
out of 1,000,000 (99.1%+) for `profile`, and only 122,348-145,383 lines
actually written for `trace` (its 200ms drain cadence vs. `profile`'s 1s
meaningfully reduces, but does not eliminate, the loss). This does **not**
invalidate the aggregate counts: `functions[]` is built from the BPF
aggregate maps, which see every attached call and are never subject to
ring-buffer loss — they stayed exact in every run. `evidence.completeness`
correctly reports `PARTIAL` whenever this happens; it is never silently
reported as complete. An operator capturing a bursty, high-rate workload
should expect `PARTIAL` with a real `event_loss` count, and should trust
the aggregate `functions[]` counts over event-derived
`mechanisms`/`sessions`/`logins`/`cgroups` and `trace` lines in that case.
In `--mode metrics` the ring is never drained and `event_loss` is always
reported as 0 by construction (`run.rs` zeroes the kernel counter); a
zero there means "not measured", not "nothing lost" — the aggregate
counts remain the authority in that mode.
Same finding `scripts/verify-induced-gaps.sh` demonstrates
deliberately on a lighter workload (`docs/notes/phase2-induced-gaps.md`).

**Post-fix re-bench: UNRUN.** Re-measuring after `4f59ff6` needs the
privileged bench (owner-gated; never run by automation): exactly
`scripts/bench-overhead.sh` (defaults: `RUNS=5`, 1,000,000 calls per
condition, same 4 conditions as the table above). Prerequisites: run as a
non-root user with passwordless `sudo` (the script attaches via
`sudo --preserve-env=SOFTHSM2_CONF` and chowns root-owned reports back);
`gcc`, `softhsm2-util`, and `python3` on `PATH`; SoftHSM2 installed at
`/usr/lib/softhsm/libsofthsm2.so`; offline Rust toolchains as pinned
(the script builds release via `scripts/cargo.sh +1.88 build --locked
--release --workspace` first). Until it runs, no updated metrics-mode
number may be quoted — "unresolved, needs owner re-bench" is the honest
state.

## The evidence/completeness model

Every `observed-profile.json` carries an `evidence` section
(`docs/schema/observed-profile-v3.md`) ending in a `completeness` verdict:
`"COMPLETE"` or `"PARTIAL"`.

Discovery normally scans the target's mapped memory. An optional `--manifest`
is explicit operator attestation of exact accepted function-name/offset claims,
structurally validated and corroborated against the scan when possible. Every
accepted object is opened once, hash-matched and pinned by file descriptor;
offsets must land in executable ELF segments.
`fstat` (inode, size, ctime) is re-checked before and after attach — attach is
refused on a mismatch — and during capture, where a change sets
`evidence.provider_changed` and forces `PARTIAL`. Inputs are capped at a 16 MiB
manifest, 256 MiB per manifest object, and 512 MiB across one manifest's
objects. Separately, one capture-wide 512 MiB attempted-I/O budget covers
memory scanning and scan-sourced file hashing across every selected process,
retry, and failed pin, with 256 MiB per scan/hash operation (measured
2026-09-17 against libxul.so at 183 MB on disk / 61 MiB readable data, the
largest known real-world object; matches the manifest per-object cap).
Provider export
checks read only the object's ELF tables via demand paging (bounded), so a
large provider costs kilobytes of table reads; the per-object gate no longer
applies to that check, though it still guards memory snapshots and identity
hashing. Decoding stops at
512 accepted table candidates, 53,248 table entries, and 512 interface records;
cgroup discovery considers at most 256 members by default (`--max-scan-pids`)
and planning has 512 attach slots. Every bounded omission forces `PARTIAL`;
no retry renews a budget.

Kernel-side capture state has its own fixed limits, all disclosed in
`evidence.kernel_control` and each forcing `PARTIAL` when exceeded:

- **Identity budget (lifetime).** Detailed capture (`profile`, `trace`) gives
  each process it tracks a private identity ticket. The budget is **16,384
  tickets for the whole capture**; tickets are never reused. Under `--cgroup`
  and `--system`, *every* process created in scope spends tickets at fork
  time (parent and child), whether or not it ever calls PKCS #11. On a host
  creating about 5 processes per second the budget lasts under an hour. Once
  it is spent, new processes in scope get no identity: their fork records
  are dropped and their calls count only as `semantic_capture_failures` and
  in-flight calls. Each refusal is counted in
  `evidence.kernel_control.identity_unavailable`, and
  `identity_budget_exhausted` reads `true`. For long captures of busy
  hosts, prefer `--pid` or a narrow `--cgroup`, or split the capture.
- **Concurrent owners.** At most 16,448 threads can hold an in-flight call
  record at once; an admission beyond that is refused and counted
  (`start_insert_failures`, `kernel_control.owner_admission_failures`).
- **Owner health.** If the in-kernel call-ownership accounting ever detects
  an internal inconsistency, it stops *all* capture for the rest of the run
  rather than guess. The report then carries
  `kernel_control.capture_halted: true` with the finite reason names in
  `kernel_control.owner_poison`, p11scope prints one
  `p11scope: kernel capture halted ...` line to stderr when it first
  sees the halt, and the verdict is a concrete-gap `PARTIAL`: counts after
  that moment are missing, never silently smaller.

An optional manifest's missing or identity-mismatched object is ignored only
after one exact scan-opened table for that object covers every dropped claim
and remains admitted in the final plan. The fallback is per object and is
published in bounded, path/PID-free evidence. Malformed structure, permission
or arbitrary I/O failure, incomparable identity, non-executable offsets, an
ambiguous/incomplete replacement, and a stale sole source remain fatal.

**`COMPLETE`** requires that discovery found a module and planned a slot in
it, that no scan-only semantic claim remains, that the memory scan could read every target, that no module was refused
at the attach ceiling, that no module's targets went uncorroborated,
conflicted or ambiguous, that every discovery surface was fully acquired and
walked, that every planned probe attached, and that there are zero START/RV/
ring, cgroup, process-identity, semantic-state, process-creation, cancellation, async,
template, parameter-decode, or task-uprobe-link-loss gaps. A capture that observed nothing has no
failure to report, so "found something" is part of the verdict rather than
something a reader has to check separately. The schema document lists every
field and the explicitly informational exceptions.

**In a written profile you will not see `COMPLETE`.** Detaching a perf link
stops new probe invocations but does not wait for BPF callbacks already
running on another CPU, so a terminal snapshot cannot honestly claim it
drained everything, and the final document is downgraded to `PARTIAL` on the
way out. The verdict above still governs the live display during capture.
What a clean run looks like is `PARTIAL` with every concrete gap counter at
zero — that is exactly what the release lanes assert, via
`scripts/check-capture-evidence.py: terminal_capture_is_clean`. If you are
diffing against older notes that record `COMPLETE` rows, this is the reason.

`COMPLETE` describes the completeness of the accepted capture window. It is
not a claim that deliberately malicious native provider code truthfully
implements the ABI role named in its own function table.

Memory scanning itself is heuristic discovery. Scan-only discovery is
semantics-unverified and count-only: it retains aggregate
counts/RVs/latency but creates no semantic interpretation. Live and terminal
evidence are PARTIAL while scan-only semantic claims remain. P11Lab joins reject
scan-only and conflict modules. An accepted manifest authorizes only the exact
pinned object, offset, and canonical function name it attests; stale fallback,
hash agreement, path identity, and raw `{dev,ino}` never transfer that
attestation. The owned-child `run` path and capture-history corrections in the
frozen pre-W3 candidate at `ae8494d` passed the local 5.15/6.8 semantic
campaign. Those results have not been repeated on the current candidate. Exact-tip
runtime qualification, CI, complete packaging, publication, and release
remain pending.

**`PARTIAL`** is forced by any single gap in that list — an attach
failure, ring-buffer loss, a template the in-kernel walk couldn't finish
reading, or a mechanism whose parameter decode never once succeeded
despite having a known decodable shape. `PARTIAL` is not a failure state
to hide from an operator; it is the tool refusing to claim more than it
saw.

**Why a `PARTIAL` report is still useful:** the aggregate BPF maps
(`STATS`, `RV_COUNTS` — what `functions[]` is built from) are the *count
authority*. They see every attached call and are never subject to
ring-buffer loss, so function-level call/error/latency counts stay exact
even when `mechanisms`/`sessions`/`logins`/`cgroups` (all built from the
event stream) are degraded by loss. `scripts/verify-induced-gaps.sh`
proves this directly: with a deliberately shrunk ring buffer, ~199,900 of
200,000 events are lost, yet the aggregate `STATS` map stays exact at
200,000 — the report correctly says `PARTIAL`, but the one number an
operator most often wants (how many calls, how many errors, at what
latency) is still trustworthy.

## Honest claims

What this tool proves, and what it deliberately does not claim to:

- **It observes a window, nothing outside it.** `capture.start`/
  `capture.end` bound every claim in the report. Absence of a call in the
  capture means **"not observed in this window,"** never "the application
  cannot do this" — a feature simply not exercised during the capture is
  indistinguishable from a feature the application doesn't have, and the
  report does not pretend otherwise.
- **Aliased table entries are ambiguous by construction, not a bug to fix
  later.** When two or more function names resolve to the same file
  offset (a common ELF-level artifact), their counts are reported
  together, grouped under `evidence.aliased`, because the observer cannot
  tell which name was actually called — there is nothing to disambiguate
  from a file offset alone. This is reported honestly as a group, not
  guessed apart.
- **In unsafe diagnostic captures, requested attributes are what the
  application asked for, never the key's effective policy.** Template
  attribute types and the 11
  policy-boolean flags are available only in a build compiled with
  `unsafe-unvalidated-metadata` and run with the matching flag; the default
  `allowlisted` release does not contain these pointer-following decoders.
  They are recorded as `requested: true` — what the app's `CK_ATTRIBUTE` template
  said. Whether the provider actually *honored* that request (granted
  `CKA_EXTRACTABLE`, enforced `CKA_SENSITIVE`) is a different question
  this tool does not answer; verifying effective policy against a
  candidate provider is `pkcs11-check`'s job, not this tool's.
- **A trace or profile is evidence of what happened, never proof of what
  cannot.** The corollary of the first point: a clean capture with zero
  errors over an hour is not a correctness guarantee for the next hour,
  or for a code path the workload never took during the window.

## Related docs

- [`docs/privacy/allowlist-v2.md`](privacy/allowlist-v2.md) — the
  field-by-field decoder inventory, policy boundary, and implemented
  hostile-pointer canary coverage.
- [`docs/schema/observed-profile-v3.md`](schema/observed-profile-v3.md) —
  the versioned `observed-profile.json` schema (current:
  `p11scope/observed-profile/v3`), the integration boundary
  `pkcs11-lab` reads.
- [`docs/superpowers/specs/2026-08-10-p11scope-outputs.md`](superpowers/specs/2026-08-10-p11scope-outputs.md)
  — the original "what you will see" design commitment.

# Using p11scope

This is the operator's guide: what the tool does, what it refuses to do,
how to run it, and what its output actually proves. Measured examples below
name the script that produced them so they can be reproduced; fixed
implementation limits are code contracts, not measurements.

> **Status: unreleased; the current tree is a W3 engineering candidate.**
> Memory-scan discovery, `C_GetInterface`, `inspect`, `doctor`, public `run`,
> multi-module capture, schema v3, and owned-child live discovery are
> implemented. The frozen pre-W3 candidate at `ae8494d` passed all six
> semantic/privacy/cleanup rows on Ubuntu 22.04 kernel 5.15 and Ubuntu 24.04
> kernel 6.8. Those historical results do not qualify the W3 tip. Fresh
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
[docs/superpowers/specs/2026-08-10-pkcs11-scope-outputs.md](superpowers/specs/2026-08-10-pkcs11-scope-outputs.md#what-you-will-not-see-by-design-in-every-mode)
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

```bash
# 1. What can this host do, and what does the target map?
p11scope doctor --pid 12345
p11scope inspect --pid 12345

# 2. Attach and aggregate — no manifest, no helper, no provider code executed.
sudo p11scope profile --pid 12345 --duration 60 -o observed-profile.json

# 3. Or stream one line per call.
sudo p11scope trace --cgroup /sys/fs/cgroup/... --duration 15

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
> `--` for other application variables. The sudo path currently clears
> supplementary groups; use `profile`/`trace` against an already-running
> workload when the application needs an HSM/device group.

### Discovery timing and optional offline discovery

The memory scan builds the initial attach plan. For an owned command,
`p11scope run` starts capture before releasing the child and can acquire a
provider loaded later. The frozen pre-W3 candidate at `ae8494d` passed the
local six-row campaign on kernels 5.15 and 6.8; that campaign has not been
repeated on the W3 tip. For an already running external process, a provider
loaded before attachment can still be
missed. If a suitable manifest was prepared while the same provider identity
was available, pass it
with `--manifest`; it is explicit operator attestation of exact accepted
function-name/offset claims, hash-matched against the pinned file, and
corroborated when the provider is already mapped. Scan-only discovery is
semantics-unverified and count-only, but aggregate counts/RVs/latency remain
available. A helper run after the fact cannot repair a missed capture window,
and `--manifest` remains the explicit-attestation path for that case.

`p11scope-discover --module <provider.so> -o manifest.json` is that optional
offline path. It executes provider code in its own unprivileged process; the
normal manifest-free path does not execute provider code. `--module` is also
optional and only narrows the memory scan to named providers.

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

Both `profile` and `trace` require either `--pid` or `--cgroup`; `--module` and
`--manifest` are repeatable optional discovery inputs. `--cgroup` matches that
cgroup and every descendant beneath it
(kernel ≥5.15 due to attach cookies), so pointing it at a container's or pod's
directory reaches the workload's actual nested cgroup. `--duration` (bare seconds or `30s`/`5m`/`1h`) bounds
either subcommand; Ctrl-C or SIGTERM also ends a capture cleanly (final frame
printed, `-o` file written) instead of aborting it.

For cgroup event captures, `task/task_newtask` records ordinary non-thread
creation and preserves the parent's proven semantic state while the child is
refreshed. `CLONE_INTO_CGROUP` is recorded as a selection gap without
inheritance because destination membership is unproven. Arbitrary post-start
cgroup migration is outside the `COMPLETE` and runtime-qualified claims; no
migration subsystem is provided. PID scope remains exact and does not attach
process-creation tracking.

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
collision group fails closed. The existing overlay-only byte-identical collapse
is the sole heuristic exception and publishes uncertainty that forces
`PARTIAL`.

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

## Privileges, per environment

`doctor` reports one finite availability tier for the requested host and
target. The tier is preflight evidence, not capture authority or a completeness
promise. With no `--pid`, target readability is explicitly `unassessed`.

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
unconditional in-kernel cost dominates.

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
Same finding `scripts/verify-induced-gaps.sh` demonstrates
deliberately on a lighter workload (`docs/notes/phase2-induced-gaps.md`).

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
retry, and failed pin, with 64 MiB per scan/hash operation. Decoding stops at
512 accepted table candidates, 53,248 table entries, and 512 interface records;
cgroup discovery considers at most 256 members and planning has 512 attach
slots. Every bounded omission forces `PARTIAL`; no retry renews a budget.

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
template, or parameter-decode gaps. A capture that observed nothing has no
failure to report, so "found something" is part of the verdict rather than
something a reader has to check separately. The schema document lists every
field and the four explicitly informational exceptions.

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
campaign. Those results have not been repeated on the W3 tip. Exact-tip
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
  `pkcs11-scope/observed-profile/v3`), the integration boundary
  `pkcs11-lab` reads.
- [`docs/superpowers/specs/2026-08-10-pkcs11-scope-outputs.md`](superpowers/specs/2026-08-10-pkcs11-scope-outputs.md)
  — the original "what you will see" design commitment.

# Using p11scope

This is the operator's guide: what the tool does, what it refuses to do,
how to run it, and what its output actually proves. Every number below
cites the script that produced it — re-run the script to check it
yourself.

- [What it does](#what-it-does)
- [What it does NOT do](#what-it-does-not-do)
- [Quickstart](#quickstart)
- [Privileges, per environment (measured)](#privileges-per-environment-measured)
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
(`docs/schema/observed-profile-v1.md`) or an operator to read directly.

## What it does NOT do

No PINs, no key material, no `CKA_VALUE` contents, no plaintext,
ciphertext, signatures, or wrapped blobs, no random output, no
operation-state blobs, no raw mechanism byte arrays, no raw session
handles, no buffer contents — **in any mode, at any privilege**. Labels
and `CKA_ID` are refused outright; there is no flag that dumps buffers or
label contents. See
[docs/superpowers/specs/2026-08-10-pkcs11-scope-outputs.md](superpowers/specs/2026-08-10-pkcs11-scope-outputs.md#what-you-will-not-see-by-design-in-every-mode)
for the design commitment and
[docs/privacy/allowlist-v1.md](privacy/allowlist-v1.md) for the field-by-field
enforcement (what is captured, why, and how each read is gated — structural
where a leak is impossible by construction, runtime-gated where a length/
null check stands in front of the read, each gate named with the test that
exercises it).

A profile is evidence of what the application *did* during the capture
window. It is never proof of what the application *cannot* do — see
[Honest claims](#honest-claims).

## Quickstart

Point discovery at the *real* provider `.so`, not `p11-kit-proxy.so` —
profiling the proxy layer attributes everything to p11-kit, not the real
vendor library. The tool does not detect or warn about this today;
getting it right is on the operator.

```bash
# 1. Discover the provider's real function offsets (no privileges needed).
p11scope-discover --module /usr/lib/softhsm/libsofthsm2.so -o manifest.json

# 2. Attach and aggregate over a running process or a cgroup.
p11scope profile --manifest manifest.json --pid 12345 --duration 60 -o observed-profile.json
p11scope profile --manifest manifest.json --cgroup /sys/fs/cgroup/kubepods.slice/... --mode metrics

# 3. Or: stream one line per call for a short, bounded investigation.
p11scope trace --manifest manifest.json --pid 12345 --duration 15
```

Both `profile` and `trace` require `--manifest` and either `--pid` or
`--cgroup`; `--cgroup` matches that cgroup and every descendant beneath it
(kernel ≥5.15 ancestor matching), so pointing it at a container's or pod's
directory reaches the workload's actual nested cgroup. `--duration` bounds
either subcommand; Ctrl-C also ends a capture cleanly (final frame printed,
`-o` file written) instead of aborting it.

**Real output**, `profile --mode metrics` against a SoftHSM2 workload
(`scripts/verify-attach-e2e.sh`):

```
FUNCTION                        CALLS    ERR      p50~      p95~      p99~ IN-FLIGHT
C_GenerateRandom                  100      0     2.0µs     2.0µs    16.4µs         0
C_Digest                           50      0     2.0µs     4.1µs     4.1µs         0
C_DigestInit                       50      0     2.0µs     4.1µs    65.5µs         0
...
Evidence: 136/136 probes attached · 68 slots · 0 aliased · 0 skipped · 0 in-flight → COMPLETE
```

**Real output**, `trace` against the same workload (`scripts/verify-attach-e2e.sh`'s
harness, captured while writing this doc — `sess#N` is a per-capture
pseudonym, never the provider's raw session handle):

```
22:25:03.790862 pid 431682 tid 431682 sess#1 C_OpenSession → CKR_OK 4.3µs
22:25:03.791056 pid 431682 tid 431682 sess#1 C_DigestInit 0x250 → CKR_OK 155.3µs
22:25:03.791069 pid 431682 tid 431682 sess#1 C_Digest → CKR_OK 9.8µs
22:25:03.791885 pid 431682 tid 431682 sess#1 C_CloseSession → CKR_OK 3.7µs
```

If the ring buffer drops events, `trace` ends with an explicit
`LOST n events` line rather than silently under-reporting — see
[Overhead](#overhead-measured) for when that actually happens.

## Privileges, per environment (measured)

Measured on real hosts/containers/pods with `capsh`/`setpriv`, dropping
capabilities one at a time and recording the *actual* error text — not
documentation claims. Full detail, including the docker/kind
reproduction: `docs/notes/phase4-privileges.md`
(`scripts/matrix/verify-fork-scope.sh` asserts the host row numerically
from real JSON output).

| Environment | Minimum privilege | Full root needed? |
| --- | --- | --- |
| Host process (`--pid`, same-uid target) | `CAP_SYS_ADMIN` alone | No |
| Docker / kind (`--cgroup`, cross-uid target) | `CAP_SYS_PTRACE` + `CAP_SYS_ADMIN` | No |

`CAP_BPF`+`CAP_PERFMON` alone is documented upstream as sufficient for
BPF+uprobe work without `CAP_SYS_ADMIN` — measured here, it is **not**
enough on a host with `kernel.perf_event_paranoid = 4` (an Ubuntu
hardening level beyond upstream's documented 0-3 range that requires
`CAP_SYS_ADMIN` specifically). This is a real, measured, host-specific
fact — check `sysctl kernel.perf_event_paranoid` on your own host before
assuming it generalizes (`docs/notes/phase4-privileges.md`).

Docker/kind need the extra `CAP_SYS_PTRACE` because the observer runs on
the host and reaches into the target's `/proc/<pid>/root`; procfs gates
that path via `ptrace_may_access`, independent of the target file's own
permissions.

## Kernel floor and unsupported environments

Kernel floor: **≥ 5.15**, traced to `bpf_get_current_ancestor_cgroup_id()`
(cgroup-scoped attach, `src/scope.rs`). This tool does not runtime-check
the kernel version; on an unsupported kernel or configuration it relies on
the same clear-failure path described below. Caveat, stated plainly: the
5.15 number itself was not re-derived against a live sub-5.15 kernel in
this repo — no such kernel was available to test against
(`docs/notes/phase5-unsupported.md`, case 5). It is inherited from the
Phase 4 plan, not independently measured here.

What actually happens today, measured on a real host
(`docs/notes/phase5-unsupported.md`; two real bugs — a swallowed OS error,
and 136 identical unexplained lines — were found while reproducing these
and fixed, not just described):

**No `CAP_BPF`/`CAP_SYS_ADMIN` at all** — fails at BPF map creation, exit
code 1, with the real OS error plus a hint naming what to check:

```
p11scope: starting attach session: loading BPF object: map error: failed to create map `STATS`: failed to create map `STATS`: Operation not permitted (os error 1)
hint: this usually means the environment cannot load or attach BPF programs at all — missing CAP_BPF and/or CAP_SYS_ADMIN (or root), a kernel lockdown mode, a kernel below the supported floor (>= 5.15), missing BTF (/sys/kernel/btf/vmlinux), or a restrictive kernel.perf_event_paranoid sysctl. See docs/notes/phase5-unsupported.md for what each looks like when observed.
```

**`CAP_BPF`+`CAP_PERFMON` but no `CAP_SYS_ADMIN`, restrictive
`perf_event_paranoid`** — map creation succeeds, every individual
`perf_event_open` for the 136 uprobe/uretprobe slots is refused. Each
per-slot line now carries the real OS error, followed by one synthesized
summary line instead of 136 unexplained repeats:

```
attach failed (slot 0): p11_entry at /usr/lib/softhsm/libsofthsm2.so+0x265b0: `perf_event_open` failed: Permission denied (os error 13)
...
p11scope: 0/136 attach attempts failed, every one the same way — this almost always means the environment cannot attach BPF uprobes at all: missing CAP_BPF/CAP_SYS_ADMIN (or root), a kernel lockdown mode, or a restrictive kernel.perf_event_paranoid sysctl. First underlying error: p11_entry at /usr/lib/softhsm/libsofthsm2.so+0x265b0: `perf_event_open` failed: Permission denied (os error 13)
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
the aggregate function/mechanism counts over the per-call event stream
(`mechanisms`/`sessions`/`logins`/`cgroups`, and `trace`'s lines) in that
case. Same finding `scripts/verify-induced-gaps.sh` demonstrates
deliberately on a lighter workload (`docs/notes/phase2-induced-gaps.md`).

## The evidence/completeness model

Every `observed-profile.json` carries an `evidence` section
(`docs/schema/observed-profile-v1.md`) ending in a `completeness` verdict:
`"COMPLETE"` or `"PARTIAL"`.

**`COMPLETE`** requires *all* of: no attach failures, no skipped manifest
entries, no aliasing, no in-flight calls at capture end, every manifest
surface fully walked with a successful acquisition, no undecoded vendor
interfaces, `event_loss == 0`, `malformed_records == 0`,
`templates_truncated == false`, and `shape_decode_total_failures == 0`.

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
- **Requested attributes are what the application asked for, never the
  key's effective policy.** Template attribute types and the 11
  policy-boolean flags (`docs/privacy/allowlist-v1.md`, entries 6-7) are
  recorded as `requested: true` — what the app's `CK_ATTRIBUTE` template
  said. Whether the provider actually *honored* that request (granted
  `CKA_EXTRACTABLE`, enforced `CKA_SENSITIVE`) is a different question
  this tool does not answer; verifying effective policy against a
  candidate provider is `pkcs11-check`'s job, not this tool's.
- **A trace or profile is evidence of what happened, never proof of what
  cannot.** The corollary of the first point: a clean capture with zero
  errors over an hour is not a correctness guarantee for the next hour,
  or for a code path the workload never took during the window.

## Related docs

- [`docs/privacy/allowlist-v1.md`](privacy/allowlist-v1.md) — the
  field-by-field privacy allowlist: every captured field justified, every
  rejected candidate refused, with file:line citations and the canary test
  that enforces each gate.
- [`docs/schema/observed-profile-v1.md`](schema/observed-profile-v1.md) —
  the versioned `observed-profile.json` schema (current:
  `pkcs11-scope/observed-profile/v1.2`), the integration boundary
  `pkcs11-lab` reads.
- [`docs/superpowers/specs/2026-08-10-pkcs11-scope-outputs.md`](superpowers/specs/2026-08-10-pkcs11-scope-outputs.md)
  — the original "what you will see" design commitment.

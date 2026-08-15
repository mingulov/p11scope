# pkcs11-scope

Observe the real PKCS#11 dependency surface of a running Linux application —
functions, mechanisms, errors, latency and safe policy metadata — **without
replacing its module or changing its configuration**.

`p11scope` is a non-interposing PKCS#11 workload profiler and diagnostic
observer built on eBPF uprobes. It discovers the provider's actual function
table (including stripped providers with no `C_*` symbols), attaches probes by
file offset, and produces a versioned `observed-profile.json` for migration
assessment and incident diagnostics.

> **Status: public MVP; productization toward the first tagged release is
> underway.** The source repository is public, but no binary/package release
> has been tagged. The safe-by-default capture policy and the provenance/lease
> authorization protocol are both implemented, and the privileged host and
> container lanes have been rerun against them. What has not happened: the
> final consolidated security re-review (Task 7 of the
> [provenance plan](docs/superpowers/plans/2026-08-13-manifest-provenance.md)),
> and any packaging or release tag. Treat this tree as reviewed engineering
> work pending its release gate, not as a shipped release.

Function-table support is cumulative: legacy PKCS #11 2.00, every 2.01–2.40
table, and standard 3.0, 3.1, and 3.2 interfaces (all 104 slots published in
the final 3.2 header). Exact `"PKCS 11"` interface names take the normal path.
Alternate, null, or unreadable names are not discarded: discovery accepts a
bounded known prefix only when the table is independently corroborated by the
module's standard exports or legacy table, records that evidence as `PARTIAL`,
and leaves deceptive/vendor tables undecoded. It never calls `C_GetInterface`.

**v0.1.0, unreleased.** See [CHANGELOG.md](CHANGELOG.md) for what is in the
tree, and
[docs/usage.md](docs/usage.md) for the full operator's guide (privileges,
kernel floor, overhead, and the evidence/completeness model — every
quantitative claim there cites the script that measured it).

## Why

- **Black-box diagnostics** — "this app intermittently fails against our HSM;
  what is it actually doing?" Calls, return codes, latency distributions,
  concurrency, session lifecycle — with zero app changes.
- **Migration dependency discovery** — which PKCS#11 subset and parameter
  combinations does the application *actually* depend on? Feed the observed
  profile to [pkcs11-check](https://github.com/mingulov/pkcs11-check) /
  `pkcs11-lab` to validate a candidate provider against real usage:

  ```bash
  p11scope-discover --module /opt/vendor/lib/pkcs11.so -o manifest.json
  p11scope profile --manifest manifest.json \
    --provenance-module /opt/vendor/lib/pkcs11.so --pid 12345 \
    -o observed-profile.json
  pkcs11-check test --module /opt/candidate/lib/pkcs11.so --output-file candidate.json
  pkcs11-lab assess --profile observed-profile.json --results candidate.json
  ```

  Full quickstart, real command output, and `trace` mode:
  [docs/usage.md](docs/usage.md#quickstart).

## What it does NOT intentionally decode

There is no decoder or dump switch for PINs, key material, `CKA_VALUE`, labels,
`CKA_ID`, plaintext, ciphertext, signatures, wrapped blobs, random output, raw
mechanism byte arrays, raw session handles, or ordinary buffers.

The default capture policy is `allowlisted`, and it is safe against a caller
that aliases a metadata pointer into unrelated readable memory. Pointer-derived
bytes become output only by *exact* membership in a finite published set: a
mechanism id in the registry, or one of the 104 published function names.
Anything else is dropped in the kernel. That is a containment boundary, not
pointer validation — `bpf_probe_read_user` avoids faults, it does not check
types.

The previous unvalidated parameter/template decoders still exist, but only
behind **both** an off-by-default Cargo feature and an explicit
`--unsafe-unvalidated-metadata` flag; the flag alone cannot enable code that is
absent from the shipped eBPF object, and `metrics` mode refuses it outright.
The official release artifact is built `--no-default-features`, so packaging
fails if the unsafe path is reachable at all.

The inventory is maintained in the written, field-by-field allowlist
([docs/privacy/allowlist-v1.md](docs/privacy/allowlist-v1.md)) and a
secret-canary suite (`scripts/verify-canaries.sh`) that plants sentinel PINs,
key material, and buffer contents in a real workload and scans every output
artifact and every observer-owned BPF map for leaks — including hostile-alias
lanes and the transient raw `pMechanism` address the return probe needs.

See [what you will see](docs/superpowers/specs/2026-08-10-pkcs11-scope-outputs.md)
for the CLI, live output, trace lines, and an example `observed-profile.json`.

## Honest claims

- Zero application changes, no PKCS#11 interposition, attachable to running
  processes and containers (via a reusable manifest whose attach mapping is
  freshly reproduced — calls *before* attach are
  outside the capture window; there is no v1 mid-run auto-discovery). **Not**
  "undetectable", **not** zero overhead: measured at roughly a **5x
  wall-clock slowdown** against unobserved SoftHSM2 — deliberately the worst
  case, since its microsecond-scale software crypto makes probe overhead
  proportionally largest; the same ~3.3µs absolute overhead is negligible
  against a millisecond-scale network HSM
  (`scripts/bench-overhead.sh`, `docs/notes/phase5-overhead.md`; full numbers
  and the event-loss finding at high call rates: [docs/usage.md](docs/usage.md#overhead-measured)).
- Requires elevated privileges, kernel-version-dependent, x86-64 first.
  The measured BPF minimum is `CAP_SYS_ADMIN` on the host, plus
  `CAP_SYS_PTRACE` for cross-UID container paths (`CAP_BPF`+`CAP_PERFMON`
  alone still fails on this kernel's `perf_event_paranoid` setting). The
  hardened observer additionally needs `CAP_LEASE` for provider files its UID
  does not own. The capability lane in `scripts/matrix/verify-fork-scope.sh`
  encodes `CAP_SYS_ADMIN`+`CAP_LEASE`, but has **not** been rerun since the
  lease and terminal-drain changes, so treat the exact minimum set as
  inherited rather than freshly measured. Every live lane that *was* rerun ran
  as root ([docs/usage.md](docs/usage.md#privileges-per-environment)).
  Kernel floor ≥5.15; on an unsupported environment the tool fails with a
  named cause and a hint, never a panic or a raw verifier dump
  (`docs/notes/phase5-unsupported.md`).
- Point it at the **real** provider `.so`, not `p11-kit-proxy.so` — profiling
  the proxy layer attributes everything to p11-kit, not the real vendor
  library. The tool does not detect or warn about this today; getting it
  right is on the operator.
- **Profiles, never replays.** It has only the bounded metadata decoders listed
  in the field allowlist and no intentional secret/buffer decoder. Under the
  default `allowlisted` policy this holds against hostile pointer placement,
  not merely trusted ABI-valid callers.
- A trace is evidence about the observed window only; the profile includes an
  explicit evidence-quality/completeness section (attach failures, aliased
  functions, event loss) — `COMPLETE`/`PARTIAL`, never silently confident.
  **A terminal snapshot is always `PARTIAL`**: detaching a perf link stops new
  invocations but does not wait for BPF callbacks already running on another
  CPU, so a completed capture cannot honestly claim a proven final drain. A
  clean run is `PARTIAL` with every concrete gap counter zero; that is the
  contract the release lanes assert. Absence of a call means "not observed in
  this window," never "the application cannot do it"; aliased table entries are
  ambiguous by construction; requested attributes are what the app asked for,
  not the key's effective policy. Full honest-claims section:
  [docs/usage.md](docs/usage.md#honest-claims).
- The schema is `pkcs11-scope/observed-profile/v1.4` for `profile` and
  `pkcs11-scope/observed-profile/v1.1-metrics` for `metrics`, with discovery
  input at `p11scope-manifest/4`, documented at
  [docs/schema/observed-profile-v1.md](docs/schema/observed-profile-v1.md).
  Schema ids are opaque exact dispatch keys; the major/minor spelling grants
  no compatibility.

## Containers and Kubernetes

Uprobes bind to the file inode, so attaching to a provider `.so` in a shared
image layer observes every container on that node using that layer —
including pods started later (e.g. Knative scale-from-zero). That
inode-sharing property is the headline bet; it depends on the `overlay2`
storage driver and is validated, with exact call counts, against a real
Docker container, two containers sharing one image layer, a Kubernetes pod
(kind), and a Knative service's scale-from-zero cold start
(`docs/notes/phase4-matrix.md`). Cluster-wide packaging (DaemonSet/operator)
comes after v1.

Discovery uses a small unprivileged helper (`p11scope-discover`) that you copy
into the target container (`docker cp`/`kubectl cp`, then `exec`); it dlopens
the provider in the container's own view and prints a manifest the observer
attaches from. Privilege dropping is enforced before provider loading, even
when discovery is launched by an elevated observer.

A stored manifest is evidence and a proposed attach plan, not authority by
itself. The operator must independently name the intended provider bytes with
`--provenance-module`; the manifest cannot select its own authority. There is
no raw-manifest trust bypass, planned or otherwise.

Authorization runs a pinned, non-writable, root-owned sibling helper without
privilege, and accepts a function-name → file-offset mapping only from a
bounded rediscovery pass in which every file-backed executable mapping was
read-leased *before* that pass began. The provider is loaded by its validated
absolute path, never through `/proc/self/fd`, so `$ORIGIN` and lazily loaded
dependencies resolve as the target sees them. Content identity alone is
explicitly insufficient — a pathname can be retargeted to a byte-identical but
unleased inode — so the closure is compared by exact inode with a bounded
retry for churn. Before any BPF load the CLI process becomes a lease
supervisor and forks the capture worker; on a lease break it kills the worker
through its pidfd, releases the leases, and exits 78. Profile output is
published atomically only on normal completion, and an aborted trace still
receives a terminal `EVIDENCE` record marked `PARTIAL` with the break reason,
so a truncated capture cannot read as a complete one.

Two honest limits remain: the hostile-target continuity claim needs a
supervisor identity the workload cannot signal or ptrace, so same-uid
capability-only launches stay trusted-workload lanes; and the boundary assumes
an honest provider — sandboxing malicious provider code is explicitly outside
it.

The helper recreates that table in its own process; it never reads or injects
into the observed process. Uprobes are bound to the verified target inode and
file offset, and the PID/cgroup guard executes before argument capture.

## Project family

| Component | Responsibility |
| --- | --- |
| [pkcs11-check](https://github.com/mingulov/pkcs11-check) | Actively exercises and validates a provider |
| **pkcs11-scope** | Passively observes real application behavior |
| pkcs11-proxy-ng | Controlled interposition, transport, fault injection |
| pkcs11-lab | Combines profiles and test results into migration assessments |

Integration boundary: the versioned `observed-profile.json` schema. The
userspace side is Rust and reuses pkcs11-proxy-ng's PKCS#11 core (official
name tables, mechanism registry, module-loading FFI) rather than duplicating
it; the eBPF observer itself is new code.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option.

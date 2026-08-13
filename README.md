# pkcs11-scope

Observe the real PKCS#11 dependency surface of a running Linux application —
functions, mechanisms, errors, latency and safe policy metadata — **without
replacing its module or changing its configuration**.

`p11scope` is a non-interposing PKCS#11 workload profiler and diagnostic
observer built on eBPF uprobes. It discovers the provider's actual function
table (including stripped providers with no `C_*` symbols), attaches probes by
file offset, and produces a versioned `observed-profile.json` for migration
assessment and incident diagnostics.

> **Unreleased security status:** the current corrective worktree is not
> release-ready. Its default metadata path still follows caller-supplied
> pointers, and its first provenance/lease pass does not yet protect the full
> lazy-dependency closure or ordered teardown. Use it only with trusted,
> ABI-valid workloads. The required safe default and completed authorization
> protocol are specified in
> [the privacy amendment](docs/superpowers/specs/2026-08-13-safe-and-unvalidated-metadata-design.md)
> and [provenance plan](docs/superpowers/plans/2026-08-13-manifest-provenance.md).

Function-table support is cumulative: legacy PKCS #11 2.00, every 2.01–2.40
table, and standard 3.0, 3.1, and 3.2 interfaces (all 104 slots published in
the final 3.2 header). Exact `"PKCS 11"` interface names take the normal path.
Alternate, null, or unreadable names are not discarded: discovery accepts a
bounded known prefix only when the table is independently corroborated by the
module's standard exports or legacy table, records that evidence as `PARTIAL`,
and leaves deceptive/vendor tables undecoded. It never calls `C_GetInterface`.

**v0.1.0.** See [CHANGELOG.md](CHANGELOG.md) for what shipped, and
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
mechanism byte arrays, raw session handles, or ordinary buffers. This decoder
inventory is not yet a hostile-pointer guarantee: in the current unreleased
tree a malicious caller can alias an existing scalar metadata pointer into
unrelated readable memory. The safe-default amendment above closes that output
channel; until it is implemented, use only trusted ABI-valid workloads. The
inventory is maintained in the written, field-by-field allowlist
([docs/privacy/allowlist-v1.md](docs/privacy/allowlist-v1.md)) and a
secret-canary test suite (`scripts/verify-canaries.sh`) that plants sentinel
PINs, key material, and buffer contents in a real workload and scans every
output artifact for leaks. The existing canary does not prove resistance to
malicious pointer aliasing.

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
  The previously measured BPF minimum was `CAP_SYS_ADMIN` on the host, plus
  `CAP_SYS_PTRACE` for cross-UID container paths. The hardened observer also
  needs `CAP_LEASE` when provider files are not owned by its UID (or simply
  run as root); the changed capability matrix awaits an approved privileged
  rerun ([docs/usage.md](docs/usage.md#privileges-per-environment)).
  Kernel floor ≥5.15; on an unsupported environment the tool fails with a
  named cause and a hint, never a panic or a raw verifier dump
  (`docs/notes/phase5-unsupported.md`).
- Point it at the **real** provider `.so`, not `p11-kit-proxy.so` — profiling
  the proxy layer attributes everything to p11-kit, not the real vendor
  library. The tool does not detect or warn about this today; getting it
  right is on the operator.
- **Profiles, never replays.** It has only the bounded metadata decoders listed
  in the field allowlist and no intentional secret/buffer decoder. The current
  unreleased default still assumes trusted ABI-valid pointer placement; the
  safe-default amendment is a release blocker, not an already-shipped claim.
- A trace is evidence about the observed window only; the profile includes an
  explicit evidence-quality/completeness section (attach failures, aliased
  functions, event loss) — `COMPLETE`/`PARTIAL`, never silently confident.
  Absence of a call means "not observed in this window," never "the
  application cannot do it"; aliased table entries are ambiguous by
  construction; requested attributes are what the app asked for, not the
  key's effective policy. Full honest-claims section:
  [docs/usage.md](docs/usage.md#honest-claims).
- The current interim schema is `pkcs11-scope/observed-profile/v1.3` (or
  `v1-metrics`), documented at
  [docs/schema/observed-profile-v1.md](docs/schema/observed-profile-v1.md).
  The safe-policy implementation advances it to v1.4/v1.1-metrics.

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
`--provenance-module`; the manifest cannot select its own authority.
The current first pass runs a pinned, non-writable sibling helper without
privilege and compares provider/object SHA-256 identities and function-name →
file-offset mappings. It is not sufficient for release: loading the provider
through its fd changes `$ORIGIN`, lazily loaded dependencies are not all
pre-leased, and the SIGIO exit path does not prove probes disappear before a
waiting writer proceeds. The corrected bounded exact-inode closure and lease
supervisor are specified in the linked provenance plan. Its hostile-target
continuity claim also requires a supervisor identity the workload cannot
signal or ptrace; same-uid capability-only launches remain trusted-workload
lanes. There is no planned
raw-manifest trust bypass.

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

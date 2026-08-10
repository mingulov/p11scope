# pkcs11-scope

Observe the real PKCS#11 dependency surface of a running Linux application —
functions, mechanisms, errors, latency and safe policy metadata — **without
replacing its module or changing its configuration**.

`p11scope` is a non-interposing PKCS#11 workload profiler and diagnostic
observer built on eBPF uprobes. It discovers the provider's actual function
table (including stripped providers with no `C_*` symbols), attaches probes by
file offset, and produces a versioned `observed-profile.json` for migration
assessment and incident diagnostics.

> **Status: design/planning.** No working code yet. See
> [the design spec](docs/superpowers/specs/2026-08-10-pkcs11-scope-design.md),
> [the roadmap with review gates](docs/superpowers/plans/ROADMAP.md), and
> [the Phase 0 spike plan](docs/superpowers/plans/2026-08-10-phase0-feasibility-spike.md).

## Why

- **Black-box diagnostics** — "this app intermittently fails against our HSM;
  what is it actually doing?" Calls, return codes, latency distributions,
  concurrency, session lifecycle — with zero app changes.
- **Migration dependency discovery** — which PKCS#11 subset and parameter
  combinations does the application *actually* depend on? Feed the observed
  profile to [pkcs11-check](https://github.com/mingulov/pkcs11-check) /
  `pkcs11-lab` to validate a candidate provider against real usage:

  ```bash
  p11scope profile --module /opt/vendor/lib/pkcs11.so --pid 12345 -o observed-profile.json
  pkcs11-check test --module /opt/candidate/lib/pkcs11.so --output-file candidate.json
  pkcs11-lab assess --profile observed-profile.json --results candidate.json
  ```

See [what you will see](docs/superpowers/specs/2026-08-10-pkcs11-scope-outputs.md)
for the CLI, live output, trace lines, and an example `observed-profile.json`.

## Honest claims

- Zero application changes, no PKCS#11 interposition, attachable to running
  processes and containers (via a reusable manifest — calls *before* attach are
  outside the capture window; there is no v1 mid-run auto-discovery). **Not**
  "undetectable", **not** zero overhead — overhead is measured and published in
  Phase 5, not asserted here.
- Requires elevated privileges (root, or `CAP_BPF`+`CAP_PERFMON` and friends,
  kernel-version-dependent), Linux ≥ 5.15, x86-64 first.
- Point it at the **real** provider `.so`, not `p11-kit-proxy.so` — profiling
  the proxy layer attributes everything to p11-kit (the tool warns when it
  detects this).
- **Profiles, never replays.** It records safe semantic metadata via a strict
  per-field allowlist. PINs, key material, plaintext, ciphertext, signatures
  and wrapped blobs are never captured in any mode — enforced by a
  secret-canary test suite as a release gate.
- A trace is evidence about the observed window only; the profile includes an
  explicit evidence-quality/completeness section (attach failures, aliased
  functions, event loss).

## Containers and Kubernetes

Uprobes bind to the file inode, so attaching to a provider `.so` in a shared
image layer is *expected* to observe every container on that node using that
layer — including pods started later (e.g. Knative scale-from-zero). That
inode-sharing property is the headline bet and is the first thing the Phase 0
spike validates (it depends on the `overlay2` storage driver). Docker, kind and
Knative are first-class validation targets; cluster-wide packaging
(DaemonSet/operator) comes after v1.

Discovery uses a small unprivileged helper (`p11scope-discover`) that you copy
into the target container (`docker cp`/`kubectl cp`, then `exec`); it dlopens
the provider in the container's own view and prints a manifest the observer
attaches from. Because it runs vendor constructor code, a manifest can instead
be generated once on a safe host and reused (matched by ELF build-ID).

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

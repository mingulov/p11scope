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
  `pkcs11-lab` to validate a candidate provider against real usage.

## Honest claims

- Zero application changes, no PKCS#11 interposition, attachable to running
  processes and containers. **Not** "undetectable", **not** zero overhead
  (uprobes cost microseconds per call; overhead is measured and published,
  not guessed).
- Requires elevated privileges (root, or `CAP_BPF`+`CAP_PERFMON` and friends),
  Linux ≥ 5.15, x86-64 first.
- **Profiles, never replays.** It records safe semantic metadata via a strict
  per-field allowlist. PINs, key material, plaintext, ciphertext, signatures
  and wrapped blobs are never captured in any mode — enforced by a
  secret-canary test suite as a release gate.
- A trace is evidence about the observed window only; the profile includes an
  explicit evidence-quality/completeness section (attach failures, aliased
  functions, event loss).

## Containers and Kubernetes

Uprobes bind to the file inode, so attaching to a provider `.so` in a shared
image layer observes every container on that node using that layer — including
pods started later (e.g. Knative scale-from-zero). Docker, kind and Knative are
first-class validation targets; cluster-wide packaging (DaemonSet/operator)
comes after v1.

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

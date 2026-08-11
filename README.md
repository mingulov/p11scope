# pkcs11-scope

Observe the real PKCS#11 dependency surface of a running Linux application —
functions, mechanisms, errors, latency and safe policy metadata — **without
replacing its module or changing its configuration**.

`p11scope` is a non-interposing PKCS#11 workload profiler and diagnostic
observer built on eBPF uprobes. It discovers the provider's actual function
table (including stripped providers with no `C_*` symbols), attaches probes by
file offset, and produces a versioned `observed-profile.json` for migration
assessment and incident diagnostics.

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
  p11scope profile --manifest manifest.json --pid 12345 -o observed-profile.json
  pkcs11-check test --module /opt/candidate/lib/pkcs11.so --output-file candidate.json
  pkcs11-lab assess --profile observed-profile.json --results candidate.json
  ```

  Full quickstart, real command output, and `trace` mode:
  [docs/usage.md](docs/usage.md#quickstart).

## What it does NOT do

No PINs, no key material, no `CKA_VALUE` contents, no plaintext, ciphertext,
signatures, or wrapped blobs, no raw mechanism byte arrays, no raw session
handles, no buffer contents — **in any mode, at any privilege**. Labels and
`CKA_ID` are refused outright; there is no flag that dumps buffers. Enforced
by a written, field-by-field allowlist
([docs/privacy/allowlist-v1.md](docs/privacy/allowlist-v1.md)) and a
secret-canary test suite (`scripts/verify-canaries.sh`) that plants sentinel
PINs, key material, and buffer contents in a real workload and scans every
output artifact for leaks.

See [what you will see](docs/superpowers/specs/2026-08-10-pkcs11-scope-outputs.md)
for the CLI, live output, trace lines, and an example `observed-profile.json`.

## Honest claims

- Zero application changes, no PKCS#11 interposition, attachable to running
  processes and containers (via a reusable manifest — calls *before* attach are
  outside the capture window; there is no v1 mid-run auto-discovery). **Not**
  "undetectable", **not** zero overhead: measured at roughly a **5x
  wall-clock slowdown** against unobserved SoftHSM2 — deliberately the worst
  case, since its microsecond-scale software crypto makes probe overhead
  proportionally largest; the same ~3.3µs absolute overhead is negligible
  against a millisecond-scale network HSM
  (`scripts/bench-overhead.sh`, `docs/notes/phase5-overhead.md`; full numbers
  and the event-loss finding at high call rates: [docs/usage.md](docs/usage.md#overhead-measured)).
- Requires elevated privileges, kernel-version-dependent, x86-64 first.
  **Measured**, not assumed: host needs `CAP_SYS_ADMIN` alone; Docker/kind
  need `CAP_SYS_PTRACE` + `CAP_SYS_ADMIN` — neither needs full root
  (`docs/notes/phase4-privileges.md`; details: [docs/usage.md](docs/usage.md#privileges-per-environment-measured)).
  Kernel floor ≥5.15; on an unsupported environment the tool fails with a
  named cause and a hint, never a panic or a raw verifier dump
  (`docs/notes/phase5-unsupported.md`).
- Point it at the **real** provider `.so`, not `p11-kit-proxy.so` — profiling
  the proxy layer attributes everything to p11-kit, not the real vendor
  library. The tool does not detect or warn about this today; getting it
  right is on the operator.
- **Profiles, never replays.** It records safe semantic metadata via a strict
  per-field allowlist. PINs, key material, plaintext, ciphertext, signatures
  and wrapped blobs are never captured in any mode — enforced by a
  secret-canary test suite as a release gate.
- A trace is evidence about the observed window only; the profile includes an
  explicit evidence-quality/completeness section (attach failures, aliased
  functions, event loss) — `COMPLETE`/`PARTIAL`, never silently confident.
  Absence of a call means "not observed in this window," never "the
  application cannot do it"; aliased table entries are ambiguous by
  construction; requested attributes are what the app asked for, not the
  key's effective policy. Full honest-claims section:
  [docs/usage.md](docs/usage.md#honest-claims).
- Schema: `pkcs11-scope/observed-profile/v1.2`, versioned and documented at
  [docs/schema/observed-profile-v1.md](docs/schema/observed-profile-v1.md).

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

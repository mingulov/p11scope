# Changelog

## v0.1.0

First release. A non-interposing PKCS#11 observer: attach to a running
process or cgroup, watch its real PKCS#11 calls, get back a versioned
report — no source changes, no config changes, no replacing the provider
module.

### Discovery and attach

- `p11scope-discover` reads a provider's real function table straight
  from the ELF file — including stripped providers with no `C_*` symbols
  — and writes a manifest of file offsets `p11scope` attaches to. Handles
  both the legacy `C_GetFunctionList` table and PKCS#11 3.x
  `C_GetInterfaceList`.
- `p11scope` attaches eBPF uprobes at those offsets before the workload
  runs, scoped to a `--pid` or a `--cgroup` (and every descendant cgroup
  beneath it — a container or pod directory works even though its
  processes live in a nested child cgroup).
- Attaching to a shared image layer's `.so` observes every container on
  that node using that layer, including containers started after attach
  (proven against Docker, kind, and Knative scale-from-zero).

### Capture modes

- `profile` (default): aggregate function/mechanism/error/latency counts,
  session lifecycle, login activity, template attribute usage, per-cgroup
  breakdown, and a live-refreshing terminal summary while the capture
  runs. `--mode metrics` is a lighter maps-only variant with no event
  stream.
- `trace`: one line per completed call, in arrival order, for a bounded
  investigation window — timestamp, pid/tid, session pseudonym, function,
  mechanism and safe parameters, return code, duration. Reports
  `LOST n events` on its own line whenever the ring buffer dropped
  anything; a trace never silently pretends completeness.
- Ctrl-C (SIGINT) ends either capture cleanly: polling stops, the final
  frame prints, and (with `-o`) the report is written — the same clean
  exit as `--duration` elapsing.

### Privacy

- A written, field-by-field allowlist (`docs/privacy/allowlist-v1.md`):
  every captured field justified, every tempting-but-rejected field
  (PINs, PIN length, key material, plaintext, ciphertext, labels,
  `CKA_ID`, GCM IV/AAD contents, raw session handles, sign/digest/encrypt
  input lengths) refused in code, not just in prose.
- A secret-canary test suite (`scripts/verify-canaries.sh`) plants
  sentinel PINs, key material, labels, and buffer contents in a real
  workload and scans every output artifact and BPF map dump for leaks.
- No PINs, key material, plaintext, ciphertext, signatures, wrapped
  blobs, raw mechanism byte arrays, or raw handles, in any mode, at any
  privilege level.

### Evidence and honesty

- Every `observed-profile.json` (schema `pkcs11-scope/observed-profile/v1.2`,
  `docs/schema/observed-profile-v1.md`) carries an evidence section
  ending in a `COMPLETE`/`PARTIAL` verdict — attach failures, aliased
  functions, ring-buffer event loss, malformed records, truncated
  templates, and undecoded parameters all force `PARTIAL` rather than a
  silently confident report. Aggregate function counts are the count
  authority and stay exact even when the event stream loses data.
- Actionable error messages for unsupported environments: missing
  capabilities, kernel lockdown, and restrictive `perf_event_paranoid`
  all produce a named cause and a hint, never a raw verifier dump or a
  silent zero-count capture (`docs/notes/phase5-unsupported.md`).

### Measured, not asserted

- Privileges required per environment: host needs `CAP_SYS_ADMIN` alone;
  Docker/kind need `CAP_SYS_PTRACE` + `CAP_SYS_ADMIN`. Neither needs full
  root (`docs/notes/phase4-privileges.md`).
- Overhead against unobserved SoftHSM2 (deliberately the worst case:
  microsecond-scale software crypto, so probe overhead is proportionally
  largest here): roughly a 5x wall-clock slowdown, ~3.25-3.4µs added to
  every ~0.8µs call. The same absolute overhead against a millisecond-scale
  network HSM would be comparatively negligible
  (`docs/notes/phase5-overhead.md`, `scripts/bench-overhead.sh`).
- Correctness validated end to end against a deterministic oracle on the
  host, in Docker (single container and a shared image layer), on a
  Kubernetes pod (kind), through a Knative scale-from-zero cold start, on
  a prefork server with cgroup-scoped attach preceding every forked
  child, and against an independent PKCS#11 test client's own call trace
  (`docs/notes/phase4-matrix.md`).

### Release artifacts

- `p11scope`: fully static musl build (the observer never dlopens a
  provider, so a static build is safe and gives one dependency-free
  binary).
- `p11scope-discover`: dynamic glibc and dynamic musl builds (a static
  helper cannot dlopen a provider `.so`).
- Built and verified by `scripts/build-release.sh`.

### Known limitations

- No SIGINT-triggered mid-run auto-discovery; a manifest is generated
  once and reused, matched by ELF build-ID.
- Per-container attribution over a shared cgroup attach is exposed as
  `cgroups[]` in the profile output, keyed by cgroup id; there is no
  narrower Kubernetes cgroup than the node's kubepods root that is stable
  *before* a not-yet-created pod exists (Knative scale-from-zero row,
  `docs/notes/phase4-matrix.md`).
- x86-64 only in this release; AArch64 is the first item planned after
  v1 (`docs/superpowers/plans/ROADMAP.md`).
- The RSA-PSS parameter decode path has no adversarial canary for a
  malformed `ulParameterLen` (the GCM equivalent does); the failure mode
  is a bounded out-of-bounds scalar read, not a secret leak
  (`docs/privacy/allowlist-v1.md`, "Summary of weak points").

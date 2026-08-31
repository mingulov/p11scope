# Changelog

## Unreleased — productization slice 1b MVP

Corrective Tasks 1–5 and the owner-selected semantic-authority implementation
are complete. Public `run`, owned-child live discovery, and capture-history
correction are integrated. The frozen candidate passed all six
semantic/privacy/cleanup rows on Ubuntu 22.04 kernel 5.15 and Ubuntu 24.04
kernel 6.8, and the combined `main` tree passes all four locked workspace
gates. Exact-tip CI, packaging, final security review, and release remain
pending.

- **Discovery**: `profile` and `trace` scan the target's mapped memory once at
  attach, so neither a manifest nor the offline helper is required. Repeatable
  `--module` hints and `--manifest` inputs are optional; manifests are
  corroborated against the scan when possible. `--manifest` is explicit operator
  attestation of exact accepted function-name/offset claims. Scan-only discovery
  is semantics-unverified and count-only; aggregate counts/RVs/latency remain
  available, but live and terminal evidence are PARTIAL while those claims remain.
  P11Lab joins reject scan-only and conflict modules.
- **Diagnostics**: `inspect --pid` reports mapped providers, table surfaces,
  interface discovery and pinned file identities without loading BPF;
  `doctor` probes host/target scan, BPF and uprobe availability before capture.
  It rejects unsupported `doctor --module` input instead of ignoring it; use
  `inspect --pid ... --module ...` for module-specific discovery.
- **Multiple modules**: one capture plan can attach several providers, with
  module-scoped session/operation/async state and explicit count-only evidence
  when two modules publish the same target.
- **Evidence**: profile and metrics schemas are now
  `pkcs11-scope/observed-profile/v2` and `v2-metrics`, with
  `capture.modules[]`, per-function module identity, `evidence.discovery[]`,
  `authority: "hash-pinned"`, and explicit scan/corroboration/capacity gaps.
  Top-level skip records retain exact standard function names but bound all
  other names and reasons to finite categories, so cgroup scans do not publish
  bystander paths, numeric PID labels, `/proc/<pid>` paths, or raw error chains.
- **Owned command**: `p11scope run -- ...` starts capture before releasing the
  child and tracks later provider loads with the loader/export path. Existing
  external processes still use the initial memory scan or a suitable
  pre-existing, hash-matched manifest.
- **Corrective work bounds**: one 512 MiB attempted-I/O budget covers all
  memory scans and scan-sourced hashes in a capture (64 MiB per operation),
  with ceilings of 512 accepted tables, 53,248 decoded entries, 512 interfaces,
  256 cgroup members, and 512 attach slots. Any omission forces `PARTIAL`.
- **Process and file identity**: selected process generations survive through
  attach; stale cgroup views are subtracted before a bounded rebuild from
  retained inputs. Ordinary incomparable file identities fail closed; only the
  existing overlay-specific collapse remains, with explicit `PARTIAL`
  uncertainty.
- **Discovery hygiene**: interface names are confined to one readable VMA and
  escaped in text `inspect`. Stale optional-manifest objects fall back per
  object only after exact scan coverage survives final planning; malformed,
  incomparable, permission/I/O, invalid-offset, and stale-sole-source cases are
  fatal.
- **Privacy-first 1.0**: the default boundary is bounded function,
  registered-mechanism, return-code, latency, and lifecycle evidence. There is
  no object-handle correlation or promised symbolic `CKA_CLASS`/
  `CKA_KEY_TYPE` output.

## Unreleased — productization slice 1a

Trust simplification. The lease/provenance/hardened-oracle authorization lane
described in the corrective-release section below is removed: the observer no
longer forks a lease supervisor, leases candidate objects, runs a sibling
discovery oracle at attach time, or exits 78 on a lease break. Reasoning:
`docs/notes/2026-08-15-architecture-and-gap-analysis.md` (A5, A7) and
`docs/superpowers/specs/2026-08-15-productization-slice1-discovery-and-trust-design.md`
(§4.11, §10.6); restorable from history at `263935a`.

- **CLI**: single parser for `profile`/`trace` with `--duration` suffixes
  (`30`, `30s`, `5m`, `1h`). `--provenance-module`, `--trusted-workload`, and
  the `p11scope discover` subcommand are removed; each now errors with a hint
  pointing at `docs/usage.md`. Discovery is only the separate offline helper,
  `p11scope-discover --module <provider.so> [-o <manifest.json>]` — it
  executes provider code, is opt-in, and is never run by the observer.
- **Provider identity**: manifest objects are structurally validated, opened
  once, and identity-matched (SHA-256, and build-id when present) against the
  pinned file descriptor. `fstat` (inode, size, ctime) is re-checked
  before/after attach — attach is refused on a mismatch — and again during
  capture; an in-place change sets `evidence.provider_changed`, which forces
  `PARTIAL` and shows " · provider changed" on the live line.
- Ctrl-C **or SIGTERM** now ends a capture cleanly (final frame printed, `-o`
  written), not just Ctrl-C.
- `profile -o` is published atomically (private temp beside the target,
  fsync, rename); `trace -o` opens a private 0600 regular file with
  `O_NOFOLLOW`.
- **CI**: a GitHub Actions skeleton (`.github/workflows/ci.yml`) runs the
  unprivileged checks and a sudo e2e gate; first run pending.
- **Scripts**: the release gates (`scripts/gates.sh`, `scripts/lib.sh` —
  renamed from `trusted-p11scope.sh`) run binaries directly under `sudo`,
  dropping the trusted staging directory, `fs.suid_dumpable` sysctl step, and
  provenance/lease steps the removed lane required. `scripts/attach-pod.sh`
  and `scripts/container-authority.py` are deleted; a pod-attach wrapper
  returns in Slice 1b.

## Unreleased corrective release

The gates reopened by the 2026-08-13 deep review — safe metadata,
lazy-dependency provenance, `$ORIGIN`, and lease-break teardown — are
implemented, and the privileged host and container lanes have been rerun
against them. Not yet done: the final consolidated security re-review, and any
packaging, tag, or publication. This is reviewed engineering work awaiting its
release gate.

**Safe by default**

- Capture policy is fixed in the eBPF object before attachment and its policy
  maps are frozen, so the emitted `capture.privacy_mode` describes kernel
  behavior, not userspace intent. `profile`/`trace` default to `allowlisted`;
  `metrics` is always `aggregate-only` and reads no call arguments at all.
- Under `allowlisted`, pointer-derived bytes reach output only by exact
  membership in a finite published set — the mechanism registry, or the 104
  published function names. Aliasing a metadata pointer into unrelated
  readable memory yields no decoded value rather than an arbitrary read.
- The previous unvalidated fixed-offset decoders survive only behind the
  off-by-default `unsafe-unvalidated-metadata` Cargo feature *and* an explicit
  `--unsafe-unvalidated-metadata` flag. The flag cannot reach code absent from
  the object, `metrics` refuses it, and the official artifact is built
  `--no-default-features` with packaging that fails if the unsafe path is
  reachable.

**Provenance and continuity**

- Discovery emits `p11scope-manifest/4`: bounded process-memory pointer
  snapshots, reporting build IDs, mandatory whole-file SHA-256 identities, and
  the exact-inode provenance closure recorded separately from attach objects.
- Stored manifests never authorize probes by themselves. Every attach requires
  bounded fresh unprivileged discovery through a pinned root-owned sibling
  helper, an operator-selected `--provenance-module`, and exact
  function-name/object/offset agreement. There is no raw-manifest bypass.
- Authorization accepts only a pass in which every file-backed executable
  mapping was read-leased beforehand; the provider loads by absolute path so
  `$ORIGIN` and lazy dependencies resolve as the target sees them. Content
  identity alone is treated as insufficient — a path can be retargeted to a
  byte-identical unleased inode — so comparison is by exact inode with a
  bounded churn retry.
- Before any BPF load the CLI becomes a lease supervisor and forks the worker.
  A lease break kills the worker through its pidfd, releases leases, and exits
  78. Profile output publishes atomically only on normal completion; an
  aborted trace still receives a terminal `PARTIAL` `EVIDENCE` record naming
  the break reason, so truncation cannot read as completeness.

**Evidence**

- A written profile is now always `PARTIAL`: a detached perf link does not
  wait for BPF callbacks already running on another CPU, so no terminal
  snapshot can prove a final drain. A clean run is `PARTIAL` with every
  concrete gap counter zero, asserted by
  `scripts/check-capture-evidence.py: terminal_capture_is_clean`.
- Independent START, RV, cgroup, semantic, process, fork, cancellation, and
  async loss evidence still prevents a degraded capture from overclaiming.
- Cumulative function-table support covers 2.00, 2.01–2.40, 3.0, 3.1, and all
  104 published 3.2 slots. Alternate/null interface names are walked only as
  structurally corroborated prefixes; vendor lookalikes stay undecoded.
- Schemas: profile `v1.4`, metrics `v1.1-metrics`. Profile `v1.3` and
  `v1-metrics` were internal waypoints that no consumer received, so the
  published migrations are v1.2→v1.4 and v0-metrics→v1.1-metrics.

**Operations**

- `scripts/attach-pod.sh` wraps the previously manual existing-pod workflow:
  resolve namespace/pod/container to a host cgroup and PID, safe-copy and
  discover the provider, rewrite attach paths, and run the trusted cgroup
  capture. It requires an explicit `--trusted-workload` acknowledgement.
- Container provider copies are byte-capped, so a compromised image cannot
  fill the host filesystem through the copy step.
- The release gates exercise live verifier loading, observer-owned map-id
  canaries, START/RV/ring saturation, and dynamic glibc/musl 68/92/104 walks.

## v0.1.0

First release. A non-interposing PKCS#11 observer: attach to a running
process or cgroup, watch its real PKCS#11 calls, get back a versioned
report — no source changes, no config changes, no replacing the provider
module.

### Discovery and attach

- `p11scope-discover` loads a provider and reads its live function table,
  resolving pointers to mapped ELF objects — including stripped providers
  with no `C_*` symbols
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

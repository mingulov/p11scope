# pkcs11-scope

Observe the real PKCS#11 dependency surface of a running Linux application —
functions, mechanisms, errors, latency and safe policy metadata — **without
replacing its module or changing its configuration**.

`p11scope` is a non-interposing PKCS#11 workload profiler and diagnostic
observer built on eBPF uprobes. It discovers the provider's actual function
table (including stripped providers with no `C_*` symbols), attaches probes by
file offset, and produces a versioned `observed-profile.json` for migration
assessment and incident diagnostics.

> **Status: unreleased; the local MVP candidate is runtime-qualified.**
> Memory-scan discovery, `inspect`, `doctor`, public `run`, multi-module
> capture, schema v2, and owned-child live discovery are implemented. The
> frozen candidate passed all six semantic/privacy/cleanup rows on Ubuntu
> 22.04 kernel 5.15 and Ubuntu 24.04 kernel 6.8, and its merged `main` tree
> passes the four locked workspace gates. The exact-candidate static security
> review is complete and found one high, six medium, and two low issues; the
> default `sudo p11scope run` child-authority finding blocks a public release.
> Exact-tip CI, complete packaging, remediation, publication, and release
> remain pending.

Function-table support is cumulative: legacy PKCS #11 2.00, every 2.01–2.40
table, and standard 3.0, 3.1, and 3.2 interfaces (all 104 slots published in
the final 3.2 header). Exact `"PKCS 11"` interface names take the normal path.
Alternate, null, or unreadable names are not discarded: discovery accepts a
bounded known prefix only when the table is independently corroborated by the
module's standard exports or legacy table, records that evidence as `PARTIAL`,
and leaves deceptive/vendor tables undecoded. The explicit offline helper
performs ten fixed `C_GetInterface` queries before any provider initialization;
live observation remains passive.

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
  profile alongside [pkcs11-check](https://github.com/mingulov/pkcs11-check)
  results to validate a candidate provider against real usage:

  ```bash
  p11scope doctor --pid 12345
  p11scope inspect --pid 12345
  sudo p11scope profile --pid 12345 -o observed-profile.json
  pkcs11-check test --module /opt/candidate/lib/pkcs11.so --output json --output-file candidate.json
  ```

  Combining those two artifacts into a migration assessment is the planned
  `pkcs11-lab` integration; no `pkcs11-lab assess` command exists yet.

  `p11scope-discover` remains available as an optional offline path when a
  suitable manifest can be prepared for a provider the memory scan cannot
  read; the normal path does not execute provider code. `--manifest` is explicit
  operator attestation of exact accepted function-name/offset claims. Scan-only
  discovery is semantics-unverified and count-only, while aggregate
  counts/RVs/latency remain available.

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
([docs/privacy/allowlist-v2.md](docs/privacy/allowlist-v2.md)) and a
secret-canary suite (`scripts/verify-canaries.sh`) that plants sentinel PINs,
key material, and buffer contents in a real workload and scans every output
artifact and every observer-owned BPF map for leaks — including hostile-alias
lanes and the transient raw `pMechanism` address the return probe needs.

See [what you will see](docs/superpowers/specs/2026-08-10-pkcs11-scope-outputs.md)
for the CLI, live output, trace lines, and an example `observed-profile.json`.

## Honest claims

- Zero application changes, no PKCS#11 interposition, attachable to running
  processes and containers. The accepted Slice 1b-1 contract scans mapped
  providers at attach; calls *before* attach are outside the capture window.
  This branch also wires internal live discovery, but capture-history
  correctness and product gates remain incomplete, so late-provider coverage
  is not yet a supported claim. A suitable manifest can still supply offsets
  when one already exists and can be hash-matched (and corroborated when the
  provider is mapped). **Not**
  "undetectable", **not** zero overhead: measured at roughly a **5x
  wall-clock slowdown** against unobserved SoftHSM2 — deliberately the worst
  case, since its microsecond-scale software crypto makes probe overhead
  proportionally largest; the same ~3.3µs absolute overhead is negligible
  against a millisecond-scale network HSM
  (`scripts/bench-overhead.sh`, `docs/notes/phase5-overhead.md`; full numbers
  and the event-loss finding at high call rates: [docs/usage.md](docs/usage.md#overhead-measured)).
- Requires elevated privileges, kernel-version-dependent, x86-64 first. On the
  measured host (`kernel.perf_event_paranoid=4`,
  `kernel.yama.ptrace_scope=1`), uprobe attach required `CAP_SYS_ADMIN`;
  `CAP_BPF`+`CAP_PERFMON` did not suffice. Manifest-free scanning of a same-UID
  non-descendant additionally required `CAP_SYS_PTRACE`, or equivalently a
  descendant target / permissive ptrace policy. No `CAP_LEASE`, no
  `fs.suid_dumpable=0`, no root-owned trusted exec dir
  ([docs/usage.md](docs/usage.md#privileges-per-environment)).
  Kernel floor ≥5.15; on an unsupported environment the tool fails with a
  named cause and a hint, never a panic or a raw verifier dump
  (`docs/notes/phase5-unsupported.md`).
- `inspect` shows every provider-shaped module mapped by the target; an
  optional `--module` only narrows that set. On the measured p11-kit stack,
  p11-kit's fixed closure array exceeds the 512-slot ceiling and is refused
  whole, while the later-fitting SoftHSM2 backend attaches; the report is
  explicitly `PARTIAL`, not a claim that the proxy layer was captured.
- Discovery has one capture-wide 512 MiB attempted-I/O allowance shared by
  memory scans and scan-sourced file hashes across all selected processes and
  retries, with 64 MiB per scan/hash operation. It also stops at 512 accepted
  table candidates, 53,248 decoded entries, 512 interface records, 256 cgroup
  members, and 512 attach slots. Any bounded omission is evidence and forces
  `PARTIAL`; a retry never renews the allowance.
- A named PID's generation is retained through scan, pin, and attach and is
  rechecked before and after session creation. Cgroup members use the same
  retained generation and ownership records; a stale member's contributions
  are removed and the one-shot plan is rebuilt from already-opened stable
  inputs. Incomparable ordinary-file identities fail closed. The overlay-only
  byte-identical collapse remains an explicit uncertainty that forces
  `PARTIAL`.
- Optional manifest staleness falls back per object only when one exact,
  scan-opened table covers every dropped claim and survives final planning.
  Malformed input, permissions/arbitrary I/O, incomparable identity, invalid
  offsets, and stale sole sources remain fatal. Discovery interface names are
  read at most 64 bytes and never beyond their containing readable VMA; only
  escaped names appear in `inspect`, and capture output never contains the
  bytes.
- **Profiles, never replays.** It has only the bounded metadata decoders listed
  in the field allowlist and no intentional secret/buffer decoder. Under the
  default `allowlisted` policy this holds against hostile pointer placement,
  not merely trusted ABI-valid callers.
- **Privacy-first 1.0 boundary.** The default release reports bounded function,
  registered-mechanism, return-code, latency, and lifecycle evidence. It does
  not correlate object handles and does not promise symbolic `CKA_CLASS` or
  `CKA_KEY_TYPE` output. The existing unsafe diagnostic build does not enlarge
  the default allowlist.
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
- The schema is `pkcs11-scope/observed-profile/v3` for `profile` and
  `pkcs11-scope/observed-profile/v2-metrics` for `metrics`, with optional
  discovery input at `p11scope-manifest/5`, documented at
  [docs/schema/observed-profile-v3.md](docs/schema/observed-profile-v3.md).
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

Manifest-free discovery collapses matching overlay mappings in that common
shared-layer case so the kernel point is attached once. Overlayfs classification,
inode metadata, and identical bytes do not prove physical identity across separate
overlay instances, so every such collapse is published as uncertainty and forces
`PARTIAL`; a distinct byte-identical instance could otherwise be under-counted.

Initial discovery and `p11scope inspect` scan provider tables already mapped in
the target and make zero PKCS #11 calls. The explicit unprivileged
`p11scope-discover` helper alone performs exactly ten bounded `C_GetInterface`
compatibility queries before any provider initialization. For a command the observer owns, `p11scope run`
starts capture before releasing the child and loader/export hooks react to
later loads. The
optional unprivileged helper (`p11scope-discover`) can prepare a manifest
offline while the same provider identity is available; a manifest cannot be
conjured after a missed capture to make that window complete.

Provider identity is pinned by SHA-256 at attach and re-checked (`fstat`
ino/size/ctime) before, during, and after capture; a change during capture
sets `evidence.provider_changed`, which forces the report `PARTIAL`. Profile
output is published atomically (private temp beside the target, fsync,
rename).

Memory scanning is heuristic discovery. Live and terminal evidence are PARTIAL
while scan-only semantic claims remain. P11Lab joins reject scan-only and
conflict modules; an accepted manifest may authorize only its exact pinned
object, offset, and canonical function name. The owned-child `run` path and
capture-history corrections passed the local 5.15/6.8 semantic campaign.
The project remains unreleased while exact-tip CI, packaging, and final
security remediation/release review are pending. `p11scope run` never
implicitly releases a root child: a non-root observer keeps its UID/GID while
losing capabilities, and a sudo-root observer requires valid non-root
`SUDO_UID`/`SUDO_GID` values naming one existing non-root account and drops to
them before the release barrier. Root without that explicit target and set-id
invocations are refused; those environment values select the target account
but do not authenticate that the launcher was `sudo`. The child also receives
`no_new_privs`, no capabilities, a small environment allowlist, and no
unrelated inherited file descriptors. Its executable is opened before fork
and executed by descriptor; scripts must be invoked through an explicit ELF
interpreter such as `/bin/sh script`.
For now, the sudo path clears supplementary groups, so workloads needing an
HSM/device group should use an already-running target until explicit run-as
group selection is implemented.

Fresh final-candidate unprivileged self-tests, local packaging subsets, and
the Jammy/Noble owned-run campaign are recorded in the productization evidence
index. Container and Kubernetes results predate the final candidate and remain
historical support evidence, not an exact-tip rerun. No remote exact-tip CI or
complete release-build result is claimed.

When used, the helper recreates the table in its own process; it never reads or
injects into the observed process. Uprobes are bound to the verified target
inode and file offset, and the PID/cgroup guard executes before argument
capture.

## Project family

| Component | Responsibility |
| --- | --- |
| [pkcs11-check](https://github.com/mingulov/pkcs11-check) | Actively exercises and validates a provider |
| **pkcs11-scope** | Passively observes real application behavior |
| pkcs11-proxy-ng | Controlled interposition, transport, fault injection |
| pkcs11-lab (planned) | Will combine profiles and test results into migration assessments |

Integration boundary: the versioned `observed-profile.json` schema. The
userspace side is Rust and reuses pkcs11-proxy-ng's PKCS#11 core (official
name tables, mechanism registry, module-loading FFI) rather than duplicating
it; the eBPF observer itself is new code.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option.

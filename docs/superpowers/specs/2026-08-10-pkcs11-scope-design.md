# pkcs11-scope — Design

**Date:** 2026-08-10
**Status:** Draft — pending owner review (feasibility assessed positive; implementation not started)
**Extended rationale:** [docs/notes/info.md](../../notes/info.md) — this spec records the decisions; the notes record the full reasoning.
**Companion:** [what you will see](2026-08-10-pkcs11-scope-outputs.md) — CLI surface, live/trace output, and the `observed-profile.json` shape.

## One-sentence positioning

> Observe the real PKCS#11 dependency surface of a running Linux application —
> functions, mechanisms, errors, latency and safe policy metadata — without
> replacing its module or changing its configuration.

A non-interposing PKCS#11 workload profiler and diagnostic observer built on
eBPF uprobes. It discovers the provider's real function table, attaches probes
by file offset (no symbols needed), records safe semantic metadata only, and
emits a versioned `observed-profile.json` used for migration assessment and
incident diagnostics.

**Honest claim:** zero application changes and no PKCS#11 interposition — *not*
"undetectable" and *not* "zero overhead". Uprobes add measurable per-call cost,
require elevated privileges, and are visible to host administrators.

## Decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| Repo / product name | `pkcs11-scope` | Chosen by owner; "p11scope" reads like "periscope" — apt for a passive observer |
| Binary names | `p11scope` (observer), `p11scope-discover` (helper) | Short CLI name; helper is a separately copyable artifact (see Architecture) |
| Primary target | **External third-party applications** | The product exists for apps we do not control. `pkcs11-check` (developed locally) is the dev-time workload generator and ground-truth oracle, not the product focus |
| Observer language | Rust + `aya` (BPF side: aya-ebpf or clang-built C; `libbpf-rs` as fallback if aya hits a wall) | The family already has a large Rust PKCS#11 core in `pkcs11-proxy-ng` (official mechanism/CKR/attribute name tables, TOML mechanism registry, 2.x/3.x FFI). The observer never dlopens providers, so it can still be a fully static musl binary. Go rejected: a third language in the family, and it would rebuild tables that already exist (miekg/pkcs11 is 2.x-era — no 3.x interfaces, no vendor registry) |
| Shared decode core | **Improve `pkcs11-proxy-ng`**, don't duplicate: extract its module-FFI (loading + `CK_FUNCTION_LIST`/`_3_0`/`_3_2` field-offset tables + interface caps) from `crates/backend` into a lean crate; pkcs11-scope consumes it and `pkcs11-proxy-ng-types` via git deps | Verified: `types` is dependency-lean (serde/toml/tracing/zeroize); the FFI code exists but is entangled with `proto` (tonic) via `backend` — extraction is a genuine proxy-ng improvement (thinner backend, independently testable loading). The proto/convert marshalling layer stays proxy-only (tonic-coupled); the observer's raw-bytes decoding is new but driven by the same mechanism registry. A standalone shared repo is deferred until publishing pressure exists |
| Discovery helper | Rust bin on the shared crates; shipped as glibc **and** musl *dynamic* builds | dlopen is not viable from a fully static binary (musl static returns failure; glibc static is deprecated and needs the exact matching shared libc at runtime), so the helper ships per-libc *dynamic* builds, copyable into target containers (`docker cp`/`kubectl cp` then `exec`); manifests stay reusable across machines via ELF build-ID. Emits manifest JSON on stdout; no eBPF, no privileges |
| License | Dual MIT / Apache-2.0 | Matches `pkcs11-check` |
| Repository | `github.com/mingulov/pkcs11-scope` | Matches sibling repos (this is the git URL, not a Rust module path) |
| Platform floor | Linux x86-64, kernel ≥ 5.15 | ringbuf needs 5.8+; 5.15 = oldest mainstream LTS in target fleets. AArch64 next, no 32-bit |
| Integration boundary | Versioned JSON schema (`observed-profile.json`) | `pkcs11-check` is Python — no shared code; `pkcs11-lab` consumes both tools' JSON |
| Not a tracer that dumps data | Profile, not replay; allowlist decoding only | See Privacy model |

## Feasibility

### Core mechanism — proven by prior art; novel parts unproven until the spike

- Linux uprobes attach by **file + offset** (`perf_event_open`), no symbol
  table or debug info needed. ASLR/PIE irrelevant. aya's `UProbe::attach`
  takes an in-file **offset**; the Phase 0 spike uses bpftrace's
  `uprobe:binary:offset` form. (Whether a given loader's numeric argument is a
  file offset or a link-time vaddr must be pinned per-tool — see the spike
  plan; for SoftHSM2 the two are numerically equal, so the spike alone does
  **not** settle it. Phase 1 pins aya's semantics explicitly.)
- Return codes and latency come from uretprobes paired with entry uprobes.
  (uretprobe rewrites the return address; a `longjmp`/exception past the frame,
  or a never-returning call, means no return event — accounted for as
  in-flight, see Evidence quality.)
- Non-interposing observation of stripped crypto libraries in containers is
  established practice (ecapture on OpenSSL/BoringSSL, Parca, Datadog USM) —
  that is the *proven* part. **Unproven until the spike:** PKCS#11
  **function-table discovery** on a stripped provider (providers export only
  `C_GetFunctionList` / `C_GetInterfaceList` and may strip everything else),
  cross-container inode sharing, and the semantic/privacy layers. No product
  code exists yet.

### Containers (Docker) — expected to work, and to be a strength (Phase 0 proves it)

- Uprobes bind to the **inode**. The observer resolves the target library via
  `/proc/<host-pid>/root/<path>` and attaches; mount namespaces don't block it.
  A late `dlopen` in an already-probed process (app starts, loads the provider
  minutes later) is caught for the same reason — the probe is on the file, not
  a mapping.
- **Hypothesis to validate, not settled fact:** with the `overlay2` storage
  driver, containers sharing an image layer share the lowerdir inode, so one
  attachment should cover every container on the node using that layer,
  including containers started later (the Knative scale-from-zero story below).
  This is exactly what spike Task 4 tests (2× counts from two containers, one
  attach). It depends on the storage driver (`overlay2`; not
  `fuse-overlayfs`/`devicemapper`/`btrfs`/`zfs`) and on the uprobe binding to
  the shared lower inode rather than a per-container overlay inode. If the
  spike shows 1×, the design falls back to per-container attach and the
  scale-from-zero claim is retracted.
- Caveat: a library modified or copied in a writable layer gets a new inode →
  needs its own attachment. Manifests are file-relative and reusable across
  machines, but only after verifying file identity (ELF build ID or SHA-256).
- Per-workload scoping is done inside BPF (PID / cgroup-id filter maps),
  because inode-attached probes otherwise fire for every process mapping the
  library. **Fork caveat:** a PID filter does not follow `fork()`; prefork /
  fork-per-connection servers (a common PKCS#11 consumer shape) escape a
  PID-scoped capture. v1 default for such targets is **cgroup scoping** (the
  whole pod/service), with per-PID as the opt-in narrow case; the evidence
  section records which scope was used.

### kind / Kubernetes / Knative — works with privileges

- kind nodes are containers on the host kernel; eBPF always executes in the
  host kernel. The observer runs either on the host (nested
  `/proc/<pid>/root` resolves fine) or as a privileged pod (hostPID, host
  `/proc`, `CAP_BPF` + `CAP_PERFMON` or privileged).
- Knative scale-to-zero is handled by the inode property above: attach to the
  provider `.so` in the image layer once, and pods that scale from zero are
  traced from their first call. v1 validates this manually in kind;
  DaemonSet/operator packaging is explicitly post-v1.
- Required privileges (document, never work around): root, or at least
  `CAP_BPF`+`CAP_PERFMON` (+`CAP_SYS_PTRACE`/`CAP_DAC_READ_SEARCH` for
  `/proc/<pid>/root`); some kernels additionally require `CAP_SYS_ADMIN` to
  create a uprobe perf event. The minimal set is kernel-version-dependent —
  Gate G4 measures it per environment rather than asserting it. Kernel lockdown
  (confidentiality mode) may block the BPF/perf/uprobe attach path → detect and
  report "unsupported environment", don't degrade silently. The same
  detect-and-refuse rule applies to a **32-bit target** (CK_ULONG width would
  otherwise garble decoding) — out of scope, so refuse, don't guess.

### Known target topologies (must be handled, not assumed away)

- **p11-kit-proxy.** Many Linux apps load `p11-kit-proxy.so` (or a p11-kit
  client module), not the vendor `.so`. Discovering *that* yields p11-kit's
  dispatch functions, and every mechanism/latency is attributed to the proxy,
  not the real provider. v1 stance: point `--module` at the **real** provider
  path; detect when the target module is p11-kit (by soname/build-ID) and warn
  loudly rather than silently profiling the wrong layer.
- **NSS softokn-style wrappers.** softokn exposes `NSC_*` and FIPS `FC_*`
  tables behind non-standard entry points; naive `C_GetFunctionList` discovery
  can resolve a *different* table than the app uses → probes on wrong offsets,
  zero capture, falsely "complete". This is the concrete "unusually structured
  provider" for the validation matrix (below), not an abstract one.
- **Multiple modules in one process** (NSS + a vendor module, or p11-kit
  fan-out). The state key is `(process, module, session)`, so `--module` may be
  repeated to attach several manifests in one run; each is attributed
  separately. (v1 may implement single-module first and defer repeat — but the
  schema and state machine are multi-module from day one.)

### Residual risk — what the Phase 0 spike must prove

The decisive experiment (unchanged from the analysis notes):

> Can an isolated helper obtain a stripped provider's function table, map
> internal function pointers to stable file offsets, attach before application
> launch, and capture every controlled-harness call with no module
> substitution?

Spike acceptance: works against SoftHSM2 **with a fully stripped copy**, from
inside a Docker container, with capture counts matching the harness's ground
truth. Everything else in this design is conventional engineering.

## Architecture

```
p11scope-discover (Rust, unprivileged, short-lived; glibc + musl builds)
    dlopen(provider.so) via shared proxy-ng module-FFI crate
    C_GetFunctionList / C_GetInterfaceList (3.x)
    map each pointer → containing mapping → ELF file offset
    → probe manifest JSON (stdout): {api, object path, offset, build-id, interface, version}

p11scope (Rust + aya, fully static musl, privileged)
    discover   — runs/execs the helper (locally, or inside the target container)
    profile    — attach uprobes+uretprobes from manifest, aggregate in BPF maps
    trace      — per-event capture via ring buffer, time-bounded
    → live summary + observed-profile.json
```

Data flow: manifest → attach (entry+return probes per discovered function,
scoped by PID/cgroup filter map) → BPF programs update aggregate maps
(profile) or reserve ring-buffer events (trace) → Rust userspace decodes its
own fixed-layout structs, maintains the semantic state machine, writes
outputs. Mechanism/CKR/attribute naming and the param-shape allowlist come
from the shared proxy-ng registry, so scope and proxy speak one dialect.

- Helper runs vendor code (dlopen constructors) — that is why it is a
  separate unprivileged short-lived process, and why a previously generated
  manifest can be reused instead (after build-ID match). **Some modules cannot
  be safely dlopened standalone** (constructors that do license checks, take an
  exclusive device lock, or open network connections). v1 behavior when
  standalone discovery is unsafe or fails: report it and require a
  pre-generated manifest (from a safe host) or the post-v1 live-discovery mode
  — never silently proceed.
- A 3.x provider may return **different tables per interface/version**; the
  helper records the interface each offset came from, probes the union, and
  reports per-interface aliasing rather than collapsing them.
- Fallback live discovery (uretprobe on the exported `C_GetFunctionList`
  of an already-running app) is a documented later mode; it has an
  unavoidable race with `C_Initialize` and is not v1.
- Aliased table entries (several logical functions → one address),
  non-file-backed pointers, and attach failures are **reported as evidence
  gaps**, never silently attributed.

### Semantic state machine

Raw call lists are insufficient (`C_Sign` carries no mechanism — `C_SignInit`
did). Userspace keeps per (process, module, session) state: active
sign/encrypt/digest/find operations with their mechanism and parameters,
session lifecycle, observed login state. This enables per-mechanism latency
histograms and init→update→final sequence accounting. Handles are internal
pseudonyms; raw handle values never appear in reports.

Events also carry **process / thread / cgroup identity** (the latter maps to
container/pod when the target is containerized), so the profile can break down
calls per container even though one inode-attached probe serves the whole node.

**Requested vs effective.** Template attributes are recorded as what the app
*requested* (`C_GenerateKey` asked `CKA_EXTRACTABLE=false`), never asserted as
the key's *effective* policy — the provider may override, default, or reject.
Where safe, a later `C_GetAttributeValue` return can corroborate; proving
effective policy is `pkcs11-check`'s job, not the observer's.

### Capture modes

Two **subcommands** (`profile`, `trace`) selecting three **capture levels**
via `--mode` on `profile`:

| Level (`profile --mode …`) | Contents | Transport |
| --- | --- | --- |
| `metrics` | function, CK_RV, latency, concurrency | BPF aggregate maps, low overhead, long captures |
| `profile` (default) | metrics + mechanisms, safe parameter fields, safe attribute types/policy values | maps + sampled events |
| the `trace` subcommand | per-call events, sequencing, caller stack ID | ring buffer, time-bounded, loss counters mandatory |

(`metrics` and `profile` are levels of the `profile` subcommand; `trace` is a
separate subcommand because its transport and time-bounding differ. This
replaces info.md's `metrics`/`profile`/`debug` naming — `debug` became the
`trace` subcommand.) There is no "dump every pointer" level, at any privilege.

### Evidence quality (always emitted)

Every profile carries a completeness section so a trace is never mistaken for
proof. It records: probe attach failures; aliased functions (several logical
entries → one address — reported as ambiguity, never assigned to one);
non-file-backed pointers; **calls in-flight at capture end** (entry seen, no
return — e.g. `C_WaitForSlotEvent` or a stalled HSM call; distinct from event
loss and excluded from latency percentiles); ring-buffer event loss counters;
capture window; scope used (pid/cgroup); and a `COMPLETE`/`PARTIAL` verdict.
Example completeness block (from info.md): `68 attached / 64 unique / 3 aliased
/ 1 non-file-backed → PARTIAL`.

## Privacy model — foundational, not a feature

Never recorded in any mode: PIN contents, key material, `CKA_VALUE`,
plaintext/ciphertext, signatures, wrapped blobs, random output, operation
state blobs, arbitrary mechanism byte arrays. Labels/`CKA_ID` only behind an
explicit opt-in flag. Decoding is **allowlist-based per field** (e.g. RSA-PSS
hash/MGF/salt length, GCM IV/tag lengths, attribute *types* in templates) —
anything not on the allowlist is dropped in BPF, before it ever reaches
userspace. All pointer/length inputs are treated as hostile.

Even allowlisted metadata needs a written justification per field (Gate G3),
because "metadata" is not automatically safe: PIN *length* leaks policy, a
label carries tenant/cert identity, `CKA_ID` is operationally sensitive, and
sign *input lengths* can characterize messages. v1 records operation input
*lengths* only where the length itself is deemed non-sensitive for that
mechanism; each such field is justified in the allowlist, not assumed.

Enforcement: automated **secret-canary tests** — sentinel values planted in
PINs, keys, labels, buffers, mechanism blobs; CI asserts no output artifact
contains them. This is a release gate, not a best-effort test.

## v1 scope

**In:** Linux x86-64; explicit `--module` path + `--pid`/`--cmd` targeting;
function-table discovery (2.x `C_GetFunctionList` + 3.x interfaces);
entry/return tracing of all discovered functions (ID, timing, CK_RV);
semantic decoding for the small high-value set (mechanism-init functions,
session lifecycle, login user type, search attribute types, safe template
attributes, wrap/unwrap/derive, RSA-PSS/GCM safe params); live summary +
versioned `observed-profile.json`; explicit evidence-quality section
(attach failures, aliases, event loss, capture window, completeness);
secret-canary suite; overhead benchmark (unobserved vs metrics vs trace).

**Out (explicitly):** syscall/network correlation, replay, enforcement or
blocking, Kubernetes-wide/system-wide module discovery, DaemonSet packaging,
GUI, raw-buffer capture, opinionated security findings, AArch64 (next after
v1), 32-bit (never until proven needed).

**CLI, live output, and the profile shape** are specified in the companion
[outputs spec](2026-08-10-pkcs11-scope-outputs.md) — subcommands
(`discover`/`profile`/`trace`), key flags (`--module`, `--pid`/`--cmd`/`--cgroup`,
`--manifest`, `-o`, `--duration`, `--mode`, and the labels/`CKA_ID` opt-in),
and an illustrative `observed-profile.json`.

### Profile schema requirements (drives Gate G2)

The `observed-profile.json` must carry enough for `pkcs11-lab` to produce its
five migration-assessment categories — this is the acceptance list Gate G2
reviews against:

| pkcs11-lab category | Profile must supply |
| --- | --- |
| OBSERVED AND VALIDATED | exact mechanism + full parameter combo (hash/MGF/salt, GCM lengths), per-function call/error counts |
| OBSERVED BUT CANDIDATE DIFFERED | same, keyed so a pkcs11-check result can be joined per mechanism+params |
| OBSERVED BUT NOT COVERED BY CORPUS | raw vendor-defined mechanism IDs (e.g. `0x80001042`) preserved verbatim, not dropped |
| CANDIDATE TESTED, NOT OBSERVED | (pkcs11-check side) — profile just needs to be an authoritative "what was seen" set |
| UNKNOWN | capture-window metadata + evidence completeness, so gaps read as "not observed", never "not needed" |

End-to-end workflow the schema serves (names avoid implying replay —
`assess`, never `--workload`):

```bash
p11scope profile --module /opt/vendor/lib/pkcs11.so --pid 12345 -o observed-profile.json
pkcs11-check test --module /opt/candidate/lib/pkcs11.so --output-file candidate.json
pkcs11-lab assess --profile observed-profile.json --results candidate.json
```

## Validation strategy

1. **Ground-truth oracle:** run `pkcs11-check` (local sibling project) against
   SoftHSM2 with p11scope attached. It exposes per-test `call_log` counts and
   an opt-in `--rv-trace` that records every `C_*` call's CK_RV into
   `report.jsonl`; diff that against the captured profile → automated
   completeness assertion. **Known caveats to design the diff around:** the
   rv-trace resets per test *after* fixture bootstrap + `C_Login`, so
   bootstrap-phase calls appear in p11scope but not the oracle; and
   `--isolation file` spawns many subprocesses (many `C_Initialize` cycles /
   PIDs). Define the diff direction (oracle ⊆ capture) and tolerance
   accordingly. Independent dev-time cross-check: OpenSC `pkcs11-spy` as an
   interposition oracle (dev only — it *is* interposition, which the product
   avoids).
2. **Environment matrix**, each running the same oracle workload:
   host process → Docker container (`overlay2`) → two containers sharing an
   image layer (inode-sharing proof) → kind pod → Knative service in kind
   including a scale-from-zero cycle.
3. **Stripped-provider test:** fully stripped SoftHSM2 copy proves symbol
   independence; **NSS softokn** (non-standard `NSC_*`/`FC_*` tables) is the
   concrete "unusually structured provider" that proves the discovery resolves
   the table the app actually uses, not a decoy.
4. **Secret-canary suite** (release gate, above).
5. **Overhead benchmark** before any performance claim is published.

## Success criteria

- Phase 0 spike passes its acceptance test (stripped provider, in-container,
  counts match oracle).
- v1 captures a complete, correctly attributed profile for the environment
  matrix, with honest evidence-quality reporting for every induced gap
  (e.g. deliberately aliased stub).
- Canary suite green; measured overhead published, not guessed.
- `observed-profile.json` schema versioned and consumed by at least one
  `pkcs11-lab` assessment prototype.

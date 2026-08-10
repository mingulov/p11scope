# pkcs11-scope — Design

**Date:** 2026-08-10
**Status:** Draft — pending owner review (feasibility assessed positive; implementation not started)
**Extended rationale:** [docs/notes/info.md](../../notes/info.md) — this spec records the decisions; the notes record the full reasoning.

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
| Discovery helper | Rust bin on the shared crates; shipped as glibc **and** musl *dynamic* builds | dlopen is impossible from a fully static binary (glibc and musl both), so the helper ships per-libc builds, copyable into target containers (`docker exec` / `kubectl exec`); manifests stay reusable across machines via ELF build-ID. Emits manifest JSON on stdout; no eBPF, no privileges |
| License | Dual MIT / Apache-2.0 | Matches `pkcs11-check` |
| Module path | `github.com/mingulov/pkcs11-scope` | Matches sibling repos |
| Platform floor | Linux x86-64, kernel ≥ 5.15 | ringbuf needs 5.8+; 5.15 = oldest mainstream LTS in target fleets. AArch64 next, no 32-bit |
| Integration boundary | Versioned JSON schema (`observed-profile.json`) | `pkcs11-check` is Python — no shared code; `pkcs11-lab` consumes both tools' JSON |
| Not a tracer that dumps data | Profile, not replay; allowlist decoding only | See Privacy model |

## Feasibility

### Core mechanism — proven

- Linux uprobes attach by **file + offset** (`perf_event_open`), no symbol
  table or debug info needed. ASLR/PIE irrelevant. Supported by `cilium/ebpf`
  (`link.OpenExecutable` + offset attach).
- Return codes and latency come from uretprobes paired with entry uprobes.
- Non-interposing observation of stripped crypto libraries in containers is
  established practice (ecapture on OpenSSL/BoringSSL, Parca, Datadog USM).
  The novel part is PKCS#11 **function-table discovery** — providers export
  only `C_GetFunctionList` / `C_GetInterfaceList` and may strip everything
  else — plus the semantic state machine and the privacy-first profile format.

### Containers (Docker) — works, and is a strength

- Uprobes bind to the **inode**. The observer resolves the target library via
  `/proc/<host-pid>/root/<path>` and attaches; mount namespaces don't block it.
- Overlayfs consequence: containers sharing an image layer share the lowerdir
  inode, so **one attachment covers every container on the node using that
  layer — including containers started later**. No attach race for new
  instances.
- Caveat: a library modified or copied in a writable layer gets a new inode →
  needs its own attachment. Manifests are file-relative and reusable across
  machines, but only after verifying file identity (ELF build ID or SHA-256).
- Per-workload scoping is done inside BPF (PID / cgroup-id filter maps),
  because inode-attached probes otherwise fire for every process mapping the
  library.

### kind / Kubernetes / Knative — works with privileges

- kind nodes are containers on the host kernel; eBPF always executes in the
  host kernel. The observer runs either on the host (nested
  `/proc/<pid>/root` resolves fine) or as a privileged pod (hostPID, host
  `/proc`, `CAP_BPF` + `CAP_PERFMON` or privileged).
- Knative scale-to-zero is handled by the inode property above: attach to the
  provider `.so` in the image layer once, and pods that scale from zero are
  traced from their first call. v1 validates this manually in kind;
  DaemonSet/operator packaging is explicitly post-v1.
- Required privileges (document, never work around): root or
  `CAP_BPF`+`CAP_PERFMON` (+`CAP_SYS_PTRACE`/`CAP_DAC_READ_SEARCH` for
  `/proc/<pid>/root`). Kernel lockdown in confidentiality mode blocks
  user-memory reads → detect and report "unsupported environment", don't
  degrade silently.

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
  manifest can be reused instead (after build-ID match).
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

### Capture modes

| Mode | Contents | Transport |
| --- | --- | --- |
| `metrics` | function, CK_RV, latency, concurrency | BPF aggregate maps, low overhead, long captures |
| `profile` (default) | metrics + mechanisms, safe parameter fields, safe attribute types/policy values | maps + sampled events |
| `trace` | per-call events, sequencing, caller stack ID | ring buffer, time-bounded, loss counters mandatory |

There is no "dump every pointer" mode, at any privilege level.

## Privacy model — foundational, not a feature

Never recorded in any mode: PIN contents, key material, `CKA_VALUE`,
plaintext/ciphertext, signatures, wrapped blobs, random output, operation
state blobs, arbitrary mechanism byte arrays. Labels/`CKA_ID` only behind an
explicit opt-in flag. Decoding is **allowlist-based per field** (e.g. RSA-PSS
hash/MGF/salt length, GCM IV/tag lengths, attribute *types* in templates) —
anything not on the allowlist is dropped in BPF, before it ever reaches
userspace. All pointer/length inputs are treated as hostile.

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

## Validation strategy

1. **Ground-truth oracle:** run `pkcs11-check` (local sibling project) against
   SoftHSM2 with p11scope attached. pkcs11-check knows exactly which calls it
   issued; diff its call log against the captured profile → automated
   completeness assertion, easy local debugging.
2. **Environment matrix**, each running the same oracle workload:
   host process → Docker container → two containers sharing an image layer
   (inode-sharing proof) → kind pod → Knative service in kind including a
   scale-from-zero cycle.
3. **Stripped-provider test:** fully stripped SoftHSM2 copy (and later one
   unusually structured provider) to prove symbol independence.
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

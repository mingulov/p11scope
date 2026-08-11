# pkcs11-scope Roadmap — phases and review gates

Source of truth for *what* each phase delivers and *which review gates it must
pass*. Each phase gets its own detailed implementation plan (same directory,
same format as the Phase 0 plan) written **after** the previous phase's gate —
detailed plans written before their inputs exist would be fiction.

Spec: [2026-08-10-pkcs11-scope-design.md](../specs/2026-08-10-pkcs11-scope-design.md)

## Phase 0 — Feasibility spike ([plan](2026-08-10-phase0-feasibility-spike.md))

Prove: stripped-provider table discovery → file offsets → attach-before-run →
exact capture, on host and across Docker namespaces, incl. shared-inode.

**Gate G0 (go/no-go): PASSED 2026-08-10** — all six checks green, see
[spike-findings.md](../../notes/spike-findings.md). Carried into Phase 1: pin
aya's offset-vs-vaddr semantics explicitly (the spike could not settle it,
SoftHSM2 has `p_offset == p_vaddr`).

## Phase 1 — Shared core (proxy-ng) + discovery helper + attach engine + `metrics` mode

- **In `pkcs11-proxy-ng` (cross-repo precursor):** extract the module-FFI
  **facts** from `crates/backend` into a lean crate (`pkcs11-module`,
  libloading + cryptoki-sys only): raw `function_list()` +
  `interface_list()` primitives, the `CK_FUNCTION_LIST`/`_3_0`/`_3_2`
  field-offset tables, and an unaligned-safe pointer reader. Interface
  selection **policy** (version fallback, quirk handling), host-ABI
  introspection, and interface-caps reporting all stay in backend — the
  discover helper must see only the module's own answers, never
  fallback-resolved lists (those may alias the primary table by design and
  would fabricate false aliasing evidence). The helper always collects
  **both** the legacy 2.40 table and the interface enumeration, and walks
  standard-named (`"PKCS 11"`) surfaces only; vendor interfaces are recorded
  as present-but-undecoded evidence. Two latent proxy bugs land with the
  extraction (name validation of every unnamed `C_GetInterface` result,
  primary and versioned; fallback provenance). See
  [the extraction design](../specs/2026-08-10-module-crate-extraction-design.md).
- `p11scope-discover`: Rust bin on that crate + `pkcs11-proxy-ng-types`;
  2.x `C_GetFunctionList` **and** 3.x `C_GetInterfaceList` (never
  `C_GetInterface` — interface *selection* is proxy policy; the helper
  records what the module reports), ELF build-ID in the manifest, JSON
  output. Shipped as glibc **and** musl
  *dynamic* builds — a fully static binary cannot dlopen.
- `p11scope`: Rust + aya; attach uprobe+uretprobe per manifest entry
  (offset-based), PID/cgroup filter maps, aggregate counts/latency/CK_RV in
  BPF maps, `metrics` mode live summary. Fully static musl build (the
  observer never dlopens providers).
- Phase 1 is executed as two plans: **1a** — offset-semantics pin +
  `p11scope-discover` ([plan](2026-08-11-phase1a-discover.md)); **1b** — aya
  attach engine + `metrics` mode, plan written only after 1a lands (the
  plan-after-inputs rule above). Both have landed; Gate G1 verification
  complete against all criteria: proxy-ng test suite green after extraction
  (verified 2026-08-11, 18 module + 303 backend + 62 quality-gate tests);
  helper verified in ubuntu (glibc) and alpine (musl) containers (68/68,
  `scripts/verify-discover-containers.sh`); manifest reuse refused on
  build-ID mismatch, tested (`tests/reuse.rs`, 4 tests); attach failures and
  aliased offsets surfaced in output rather than dropped (`render::Evidence`,
  COMPLETE only when no attach failures, no skipped entries, no aliasing,
  nothing in flight); end-to-end counts verified against the deterministic
  oracle (9/9 functions matched `spike/expected.txt` exactly, 136/136 probes
  attached, completeness COMPLETE; `scripts/verify-attach-e2e.sh`,
  `docs/notes/phase1b-e2e.md`). Remaining criterion: `/code-review` on both
  repos' branches (human-triggered step, awaiting review).
  The `pkcs11-proxy-ng-types` dependency is deferred until code actually
  needs it (review, 2026-08-11) — the helper consumes only `pkcs11-module`.

**Gate G1 (engineering review):** /code-review on both repos' branches;
proxy-ng test suite green after the extraction; manifest reuse refused on
build-ID mismatch (tested); helper verified in ubuntu (glibc) and alpine
(musl) containers; attach failures and aliased offsets surface in output
rather than being dropped.

## Phase 2 — Semantic state machine + `profile` mode + schema

- Per (process, module, session) operation state: mechanism from `*Init`
  calls, session lifecycle, multipart sequences; per-mechanism latency
  histograms; handle pseudonymization.
- `observed-profile.json` schema v1 (versioned, documented) with the
  evidence-quality section: attach failures, aliases, event loss counters,
  capture window, completeness verdict.

**Gate G2 (schema + honesty review): PASSED 2026-08-11** — Schema validated
per `docs/schema/observed-profile-v1.md` against the design spec's "Profile
schema requirements" table: all five `pkcs11-lab` categories supported
(OBSERVED AND VALIDATED / DIFFERED / NOT COVERED with verbatim vendor
mechanism IDs / TESTED NOT OBSERVED / UNKNOWN with capture-window metadata).
Known v1 gap: mechanism-parameter combos (RSA-PSS hash/MGF/salt, GCM lengths)
not yet decoded (`params: null` with note); Phase 3's allowlist decoder
required before full parameter-based joins. Induced-gap test
(`scripts/verify-induced-gaps.sh` + `docs/notes/phase2-induced-gaps.md`)
confirms honest degradation: Gap 1 (aliasing) — 42 grouped calls (25+17);
Gap 2 (in-flight) — 1 call stranded, latency percentiles null; Gap 3
(event loss) — ~199,900 ring events lost of 200,000, aggregate STATS map
exact at 200,000 (maps are count authority); all three report completeness
PARTIAL, never silently complete.

## Phase 3 — Allowlist semantic decoding + privacy enforcement

- Decode ONLY the v1 allowlist: mechanism-init params (RSA-PSS
  hash/MGF/saltLen, GCM length metadata), login user type (never PIN),
  search/template attribute *types* + selected safe policy values,
  wrap/unwrap/derive. Decoding and dropping happen in BPF, before userspace.
  Which mechanisms have decodable params is driven by proxy-ng's TOML
  mechanism registry (shared param shapes + vendor overrides), not hardcoded.
- Secret-canary suite: sentinel PINs, key material, labels, plaintext,
  mechanism blobs planted by the workload; assert no sentinel appears in any
  event, map dump, log, or output file.

**Gate G3 (privacy review — release-blocking forever after): PASSED 2026-08-11**
(with outstanding items noted below).

1. **Canary suite green:** `scripts/verify-canaries.sh` + `docs/notes/phase3-canaries.md`.
   8 sentinels planted (PIN, CKA_VALUE key material, CKA_LABEL, CKA_ID, digest
   plaintext, GCM pIv, GCM pAAD, malformed >1-byte value on policy-boolean
   attribute). Artifacts scanned: profile JSON, profiler log, 10 BPF map dumps.
   Mandatory positive control proves scanner detects leaks before trusting clean
   result. Result: `=== canaries: NONE LEAKED ===` on two reproducible runs.
   Decisive detail: profile showed GCM decode captured `iv_len=42`/`aad_len=43`,
   exactly the sentinel buffer lengths — proving the decode path executed while
   buffer *contents* never escaped. **Outstanding:** "green in CI" is not yet
   literally true (no CI pipeline in this repo); suite is green when run locally.

2. **Adversarial review of allowlist:** `docs/privacy/allowlist-v1.md` — 9
   allowlisted field groups justified, 9 rejected candidates refused, with
   file:line citations. Self-flags three weak spots: session-pseudonymization
   claim overstates current behavior (no session identifier reaches output at
   all — actually stronger); PSS/GCM parameter length-guard has no adversarial
   canary (real coverage gap); `cgroup_id` captured with no current consumer.
   **Outstanding:** the *writing* is done; actual adversarial review by a
   second party is not complete.

3. **/security-review of decoding paths:** Human-triggered step.
   **Outstanding — awaiting review.**

## Phase 4 — Environment matrix + pkcs11-check oracle

- Same workload validated across: host process → Docker container → two
  containers sharing an image layer → kind pod → Knative service in kind
  including a scale-from-zero cycle.
- `pkcs11-check` (local sibling; Python) run as workload generator against
  SoftHSM2 with p11scope attached. Oracle artifact is its `--rv-trace` output
  in `report.jsonl` plus per-test `call_log` counts. Design the diff around two
  known caveats: rv-trace resets per test *after* fixture bootstrap + login (so
  bootstrap calls are in p11scope but not the oracle), and `--isolation file`
  spawns many subprocesses. Diff direction: **oracle ⊆ capture** (every logged
  call must appear; capture may legitimately hold more). Independent dev-time
  cross-check: OpenSC `pkcs11-spy` (interposition — dev only).

**Gate G4 (validation review): PASSED 2026-08-12** — final matrix table and
known-limitations section: `docs/notes/phase4-matrix.md`.

1. **Matrix table fully green with capture completeness COMPLETE (or
   documented loss counters):** all seven rows (host, Docker single
   container, Docker shared image layer, kind pod, Knative scale-from-zero,
   prefork fork-scoping, independent oracle diff) PASS at
   `completeness: COMPLETE`, `attached_probes: 136/136` — no row reports
   loss counters, so none were needed. Documented limitations exist
   (Knative's node-wide cgroup scope, the `KUBERNETES_MIN_VERSION`
   override, a `p11scope-discover` identity-computation gap worked around
   for the Knative row) but none reduce a row below COMPLETE — see
   `docs/notes/phase4-matrix.md`'s "Known limitations" section.
2. **Oracle ⊆ capture holds (zero logged calls missed) within the
   documented tolerance:** `scripts/matrix/verify-oracle.sh` — 40 logged
   calls across 10 `(function, CK_RV)` pairs from `pkcs11-check`'s own
   `--rv-trace`, all present in the capture at least as often as logged.
   One apparent discrepancy (exact 2x pattern, 6 pairs) investigated and
   traced to `pkcs11-check`'s own trace-attribution bug, not a capture
   gap — full chain of evidence in `docs/notes/phase4-oracle.md`.
3. **Fork-scoping behavior verified (a prefork workload captured via
   cgroup scope):** `scripts/matrix/verify-fork-scope.sh` — cgroup attach
   precedes the prefork parent and all 4 children; summed counts match
   `fork-expected.txt` exactly (e.g. `C_Digest` 20/20, `C_Initialize` 5/5).
4. **Privileges actually required documented per environment (measured,
   not assumed):** `docs/notes/phase4-privileges.md` — host needs
   `CAP_SYS_ADMIN` alone (measured: `CAP_BPF`+`CAP_PERFMON` alone still
   fails on this kernel's `perf_event_paranoid=4`); Docker/kind need
   `CAP_SYS_PTRACE` + `CAP_SYS_ADMIN` (crossing into a different-uid
   container/pod's `/proc/<pid>/root`). Neither environment needs full
   root.

## Phase 5 — Overhead benchmark + docs + v0.1 release

- Benchmark unobserved vs `metrics` vs `trace` on SoftHSM2 (worst case:
  µs-scale software ops, not ms-scale HSM ops) — publish numbers, claim
  nothing unmeasured.
- User docs: privileges, kernel floor (≥5.15), lockdown/unsupported-environment
  behavior, honest-claims section. Release engineering: static builds,
  versioned schema doc.

**Gate G5 (release review):** full-repo review (/code-review ultra candidate)
+ security review of the privileged tool as a whole; README claims
cross-checked against measured reality; canary suite still green.

## Explicitly deferred (post-v1, in design spec's "out" list)

AArch64 → first item after v1. Then, unordered and only on demonstrated need:
live-discovery fallback mode, syscall/network correlation, DaemonSet/operator
packaging, system-wide module discovery, security-findings layer, GUI.

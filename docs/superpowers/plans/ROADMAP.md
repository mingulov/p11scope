# pkcs11-scope Roadmap — phases and review gates

Source of truth for *what* each phase delivers and *which review gates it must
pass*. Each phase gets its own detailed implementation plan (same directory,
same format as the Phase 0 plan) written **after** the previous phase's gate —
detailed plans written before their inputs exist would be fiction.

Spec: [2026-08-10-pkcs11-scope-design.md](../specs/2026-08-10-pkcs11-scope-design.md)

## Phase 0 — Feasibility spike ([plan](2026-08-10-phase0-feasibility-spike.md))

Prove: stripped-provider table discovery → file offsets → attach-before-run →
exact capture, on host and across Docker namespaces, incl. shared-inode.

**Gate G0 (go/no-go):** all six checks in `docs/notes/spike-findings.md` PASS;
any FAIL amends the design spec before Phase 1 planning starts.

## Phase 1 — Discovery helper + attach engine + `metrics` mode

- `p11scope-discover`: product-quality helper in C, musl-static build
  (runs in glibc *and* Alpine containers), PKCS#11 2.x `C_GetFunctionList`
  **and** 3.x `C_GetInterfaceList`/`C_GetInterface`, ELF build-ID in the
  manifest, JSON output.
- `p11scope`: Go + cilium/ebpf; attach uprobe+uretprobe per manifest entry
  (offset-based), PID/cgroup filter maps, aggregate counts/latency/CK_RV in
  BPF maps, `metrics` mode live summary.

**Gate G1 (engineering review):** /code-review on the branch; manifest reuse
refused on build-ID mismatch (tested); helper verified in ubuntu + alpine
containers; attach failures and aliased offsets surface in output rather than
being dropped.

## Phase 2 — Semantic state machine + `profile` mode + schema

- Per (process, module, session) operation state: mechanism from `*Init`
  calls, session lifecycle, multipart sequences; per-mechanism latency
  histograms; handle pseudonymization.
- `observed-profile.json` schema v1 (versioned, documented) with the
  evidence-quality section: attach failures, aliases, event loss counters,
  capture window, completeness verdict.

**Gate G2 (schema + honesty review):** schema reviewed wearing the
`pkcs11-lab`-consumer hat (can an assessment actually be built from it?);
induced-gap test — deliberately alias two entries and drop events (tiny ring
buffer) and assert the report says PARTIAL with correct numbers, never
silently complete.

## Phase 3 — Allowlist semantic decoding + privacy enforcement

- Decode ONLY the v1 allowlist: mechanism-init params (RSA-PSS
  hash/MGF/saltLen, GCM length metadata), login user type (never PIN),
  search/template attribute *types* + selected safe policy values,
  wrap/unwrap/derive. Decoding and dropping happen in BPF, before userspace.
- Secret-canary suite: sentinel PINs, key material, labels, plaintext,
  mechanism blobs planted by the workload; assert no sentinel appears in any
  event, map dump, log, or output file.

**Gate G3 (privacy review — release-blocking forever after):** canary suite
green in CI; adversarial review of the allowlist (each field justified in
writing: why is it safe?); /security-review of the decoding paths (hostile
pointers/lengths).

## Phase 4 — Environment matrix + pkcs11-check oracle

- Same workload validated across: host process → Docker container → two
  containers sharing an image layer → kind pod → Knative service in kind
  including a scale-from-zero cycle.
- `pkcs11-check` (local sibling; Python) run as workload generator against
  SoftHSM2 with p11scope attached; diff its own call log (ground truth)
  against the captured profile — automated completeness assertion and the
  main day-to-day debugging rig.

**Gate G4 (validation review):** matrix table fully green with capture
completeness COMPLETE (or documented loss counters); zero calls missed vs the
pkcs11-check oracle; privileges actually required documented per environment
(measured, not assumed).

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

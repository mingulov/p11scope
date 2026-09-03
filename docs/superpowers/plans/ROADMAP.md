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
  **both** the legacy table and the interface enumeration, and walks exact
  `"PKCS 11"` surfaces plus structurally corroborated alternate/null/
  unreadable-name prefixes; uncorroborated vendor interfaces are recorded as
  present-but-undecoded evidence. Two latent proxy bugs land with the
  extraction (name validation of every unnamed `C_GetInterface` result,
  primary and versioned; fallback provenance). See
  [the extraction design](../specs/2026-08-10-module-crate-extraction-design.md).
- `p11scope-discover`: Rust bin on that crate + `pkcs11-proxy-ng-types`;
  2.x `C_GetFunctionList` **and** 3.x `C_GetInterfaceList` (the Phase-1
  helper did not perform selection; W3 adds the finite `C_GetInterface`
  compatibility closure as separate evidence), ELF build-ID plus whole-file
  SHA-256 in the manifest, JSON output. Shipped as glibc **and** musl
  *dynamic* builds — a fully static binary cannot dlopen.
- `p11scope`: Rust + aya; attach uprobe+uretprobe per manifest entry
  (offset-based), PID/cgroup filter maps, aggregate counts/latency/CK_RV in
  BPF maps, `metrics` mode live summary. Fully static musl build (the
  observer never dlopens providers).
- Phase 1 is executed as two plans: **1a** — offset-semantics pin +
  `p11scope-discover` ([plan](2026-08-11-phase1a-discover.md)); **1b** — aya
  attach engine + `metrics` mode, plan written only after 1a lands (the
  plan-after-inputs rule above). Both have landed; the historical Gate G1
  verification completed its then-recorded criteria: proxy-ng test suite green after extraction
  (verified 2026-08-11, 18 module + 303 backend + 62 quality-gate tests);
  helper verified in ubuntu (glibc) and alpine (musl) containers (68/68,
  `scripts/verify-discover-containers.sh`); manifest reuse refused on
  content-identity mismatch and every attach requires fresh agreement on the
  provider's function-role/object/offset provenance (`tests/reuse.rs` and
  `tests/cli_discover.rs`); attach failures and
  aliased offsets surfaced in output rather than dropped (`render::Evidence`,
  COMPLETE only when no attach failures, no skipped entries, no aliasing,
  nothing in flight); end-to-end counts verified against the deterministic
  oracle (9/9 functions matched `spike/expected.txt` exactly, 136/136 probes
  attached, completeness COMPLETE; `scripts/verify-attach-e2e.sh`,
  `docs/notes/phase1b-e2e.md`). Both shared crates are published and pinned at the exact,
  reachable Git revision `a2aab6cd67d21d140277a4584942e06c903f165b`;
  the lockfile resolves that revision with no local path override. The first
  provenance implementation rejects the original raw-manifest forgery, and the
  `$ORIGIN`, lazy-dependency leasing, and lease-break teardown gaps a later
  maximum review found are closed by Tasks 4–6 of
  `2026-08-13-manifest-provenance.md`. G1's provenance clause is satisfied in
  implementation; the historical `completeness COMPLETE` recorded above is a
  pre-2026-08-14 verdict, since a terminal snapshot is now always `PARTIAL`
  (see the Overall project status below).

**Gate G1 (engineering review):** /code-review on both repos' branches;
proxy-ng test suite green after the extraction; manifest reuse refused on
content-identity or fresh table-provenance mismatch (tested); helper verified in ubuntu (glibc) and alpine
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

**Gate G3 (privacy review — release-blocking forever after): PASSED
2026-08-14**, after being reopened 2026-08-13. The 2026-08-11 result is
historical ordinary-placement canary evidence only; it did not test malicious
pointer aliasing or the safe/unsafe policy split. Both now exist and were
rerun live: `allowlisted` is the default policy, pointer-derived output is
confined to finite published equality oracles, and the canary matrix passed
seven capture lanes plus three START lanes — including hostile-alias cases and
the transient raw `pMechanism` address, scanned in this run's exact map ids.
The remaining caveat is unchanged and structural: the suite is green locally,
not in CI, because this repo still has no CI pipeline.

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

2. **Adversarial review of allowlist:** completed independently on the
   corrective tree. `docs/privacy/allowlist-v1.md` now uses stable symbol
   citations; the live canary covers 15 sentinels in every output and all
   observer-owned BPF maps, including 2.40/3.0/3.2 parameter paths.

3. **Security review of decoding paths:** the 2026-08-12 corrective snapshot
   fixed and source-validated its eight reported classes. A 2026-08-13 deeper
   review then found the remaining pointer-provenance boundary and hash-only
   async-name authorization. Both are closed: the pointer boundary by the
   `allowlisted` default policy (finite published equality oracles, policy
   maps frozen before attach), and async-name authorization by byte-and-length
   exact match with structural coverage proving no hash-only path remains.
   Independent per-slice reviews recorded 0 Critical and 0 Important.

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
   root. Post-fix6 host evidence (2026-08-25) records `CAP_SYS_ADMIN`
   attaching 136 probes with `PARTIAL` evidence, while
   `CAP_BPF`+`CAP_PERFMON` records 68 per-slot `perf_event_open` failures,
   `attached_probes: 0/136`, and `PARTIAL`. These host-specific rows do not
   remeasure Docker/kind; that broader capability matrix remains pending.

**Topology scope qualification (2026-08-27, Slice 1b-2):** The historical
Knative matrix evidence above is retained for the exact preattached provider
capture: shared-inode attachment, `136/136` probes, and expected cold-pod
calls. It is narrower than full late-provider discovery. The historical Lane 13
checker/invocation is complete at checker/lifecycle commit
`34357b5dda71c670250dd3ab336b29c801120d5b` (tree
`ae3346e4b8e137f430f010d0937bcf186cfcff39`) and final invocation/contract
commit `fd3d08ad9bd2f58508eda1ee4a50882c0633d850` (tree
`0decc4dee974707468b5758107fb055c30d44d7d`). Its zero-unavailable PASS oracle
applies only to a topology proposed for supported acceptance. The completed
pre-r3 attempt-6 exclusion is input-bound to
`/home/user/src/m/p11scope-ws/preserved/evidence-roots/task4-lane13-a2fd9ee-20260826T2135EEST/facts.log`
(originally under `~/.local/state/p11scope/`, relocated 2026-09-02)
(SHA-256 `b96cbed6cbc2963dab2c5963b5c52f6378d9bef313479b83a56c259df79b94f3`,
exact HEAD/tree `a2fd9ee8eddfaff34b3fb6b65267688b5a90aa03` /
`f90e2dfe8dbd0a211f9e32055a37ff7320080b88`). The receipt binds the lane
command/script ledger, Kind/Knative releases/images, provider hash/build ID,
kernel/storage, node/workload identities, and clean start/end inputs. Future
negative-control classification permits only candidate and gate identity to
differ from attempt 6, and only when each exactly equals the independently
reviewed pre-run r3 manifest. Every other external topology field from the
receipt must match attempt 6; any mismatch is UNRUN/review before outcome
classification and never inherits the exclusion by outcome alone. In the reproduced Knative node-wide
retained-view topology, full late-provider discovery is
`UNSUPPORTED/NON-PASS`; one overlay plus one unavailable is a required
negative control evaluated only outside the PASS oracle. Attempt 6 is not rerun
in Task 4; Lane 13 runs once in 9.2d as the frozen-candidate negative control.
The checker and zero-unavailable acceptance oracle remain unchanged.

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

1. **Canary suite still green:** re-verified 2026-08-12 —
   `scripts/verify-canaries.sh`: `=== canaries: NONE LEAKED ===`, positive
   control OK, GCM/PSS decode correctness re-checked (same result as
   Phase 3's original run). Additionally spot-checked the same sentinel
   workload under `trace` (a new output path since Phase 3, not covered
   by the script itself): `=== trace canaries: NONE LEAKED ===` across
   both the `-o` file and stdout, consistent with the ad hoc check
   already recorded in Phase 5 Task 1's report. Full detail:
   `.superpowers/sdd/2026-08-12-phase5-release/task-7-report.md`.
2. **README claims cross-checked against measured reality:** every
   quantitative/behavioral claim in `README.md` and `docs/usage.md`
   checked against its cited source (a script or a notes file); full
   claim-by-claim table in `task-7-report.md`. Two real drifts found and
   fixed, not softened:
   - Both docs claimed "the tool warns when it detects" the
     `p11-kit-proxy.so` case — no such detection exists anywhere in the
     code (`rg p11-kit src/ crates/` finds nothing); the false claim was
     deleted from both files.
   - The original outputs-spec draft
     (`docs/superpowers/specs/2026-08-10-pkcs11-scope-outputs.md`) said
     Labels/`CKA_ID` would be available "behind an explicit opt-in flag"
     — the shipped tool is stricter (refused outright, no such flag
     exists); corrected to match, since README and `docs/usage.md` both
     cite that file as the privacy commitment and their own wording
     ("refused outright") already matched reality.
   Every other checked claim — overhead numbers, measured privileges,
   unsupported-environment error text, the kernel-floor inheritance
   caveat, schema version string, the `COMPLETE`/`PARTIAL` gate list, the
   `cgroups[]` per-cgroup claim — matched its cited source exactly, no
   change needed.
3. **Full-repo review:** open. Every implementation slice carried its own
   independent security/correctness and spec reviews at 0 Critical and
   0 Important, but those are per-slice. The final cross-cutting re-review
   over the fixed classes — manifest self-authorization, helper replacement
   and pre-main injection, provider/dependency/inode mutation, `$ORIGIN` and
   closure churn, lease acquisition/break/teardown ordering, terminal
   trace-abort evidence, same-uid signal authority, and safe/unsafe pointer
   aliasing plus immutable policy publication — is Task 7 of the provenance
   plan and has not run.
4. **Security review of the privileged tool as a whole:** open, and gated on
   item 3. The corrected provenance and safe-metadata designs are now
   implemented, so this review is unblocked rather than premature.

On the earlier corrective snapshot, all other verification scripts were re-run the same day as this gate
(release blockers per this phase's Global Constraints, not G5 criteria
themselves): `cargo test --workspace` (109 passed, 0 failed),
`verify-attach-e2e.sh`, `verify-induced-gaps.sh`, all six
`scripts/matrix/*.sh` (docker, shared-layer, kind-pod, knative, oracle,
fork-scope), `bench-overhead.sh` (full unshortened run, 5 runs/condition
— numbers consistent with `docs/notes/phase5-overhead.md` within normal
run-to-run noise), and `build-release.sh`. Zero failures across all of
them. Full table: `task-7-report.md`.

Corrective-snapshot verification on 2026-08-12 additionally passed 166
locked Rust tests, formatting, Clippy, the release eBPF build, privacy canaries,
all five induced-gap cases, static-musl packaging, Ubuntu/glibc and Alpine/musl
68/92/104-entry discovery, the fork/cgroup matrix, and the 284-file
`pkcs11-check` RV oracle (10 RV pairs, 40 calls, `COMPLETE`). NSS discovery
reported legacy 2.40 plus standard 3.0/2.40 interfaces; the configured proxy
shim reported its actual legacy/interface 2.40 surfaces. BouncyHSM and Kryoptic
were not provisioned and are not claimed.

### Overall project status (2026-08-14: blockers closed, G5 open on final review)

Phases 0-4 retain their recorded historical gate evidence (G0-G4 PASSED, see
each phase above), and the former shared-crate revision blocker is cleared:
the manifests and `Cargo.lock` pin reachable revision `a2aab6c` with no local
path patch.

All four release blockers confirmed by the 2026-08-13 deep re-review are now
implemented and independently reviewed (0 Critical, 0 Important per slice):

- **`$ORIGIN`** — the provider loads by validated absolute path, never through
  `/proc/self/fd`, so a wrapper with an adjacent lazy backend resolves;
- **lazy-dependency leasing** — authorization accepts only a bounded pass in
  which the complete file-backed executable mapping closure was read-leased
  beforehand, compared by exact inode with a bounded churn retry;
- **ordered teardown** — the CLI becomes a lease supervisor and forks the
  worker; a break kills the worker by pidfd, releases leases, and exits 78,
  leaving a terminal `PARTIAL` `EVIDENCE` record on the trace sink;
- **safe metadata** — `allowlisted` is the default policy, pointer-derived
  output is confined to finite published equality oracles, and the old
  unvalidated decoders require both an off-by-default Cargo feature and an
  explicit flag.

The approval-gated lanes were rerun and passed: privileged host attach
(136/136 probes, exact counts, `PARTIAL` with zero concrete gap counters), the
full canary matrix (seven capture lanes, three START lanes), induced gaps
G1–G5, and the container matrix (Ubuntu/Alpine discovery, Docker 68/68/136,
shared layer broad 2x plus both leaf 1x, kind pod 68/68/136, Knative
cold-start capture from a pod created after attach) — each recording
read-lease, filesystem-type, and `lease-break-time` evidence.

**Provenance Task 7 Steps 1–4 passed on 2026-08-14** (regressions, four gates,
and both re-review clauses; one defect found and fixed in that pass's own new
code — see the plan's "Task 7 pass of 2026-08-14"). **Step 5, the multi-agent
maximum code review, is the remaining G5 criterion** and is user-triggered
(`/code-review ultra`); it cannot be launched from a session. Plans:
`2026-08-13-manifest-provenance.md` (Tasks 1–6 done) and
`2026-08-13-safe-and-unvalidated-metadata.md` (Tasks 1–5 done, Task 6 Step 6
partial). Slice-by-slice evidence including every deferred Minor is under
`.superpowers/sdd/`; the adjudicated review that started this work is
`docs/notes/2026-08-13-metadata-and-provenance-review.md`.

**Unrun, and therefore not claimed:**

- `scripts/matrix/verify-fork-scope.sh` and `scripts/matrix/verify-oracle.sh`
  both asserted a terminal `COMPLETE` that the drain change made impossible.
  They were corrected to the shared `terminal_capture_is_clean` predicate on
  2026-08-14 and have not been rerun. The post-fix6 host capability rows are
  separately measured, but the broader fork-scope capability matrix remains
  pending. Every lane that was rerun ran as root.
- The container lanes predate the provider-copy byte cap, and
  `scripts/attach-pod.sh` has never run against a live cluster — it is
  unprivileged-tested for argument refusal only.
- Packaging, publication, push, and tag: NOT PERFORMED.

**Other verified limitations:**

- **The kernel floor (≥5.15) is inherited, not independently verified.**
  The current cgroup filter works on older kernels; 5.15 is retained for
  uprobe attach-cookie support and has not been tested against a live
  sub-5.15 kernel in this repo — no such kernel was available
  (`docs/notes/phase5-unsupported.md`, case 5). `docs/usage.md` states
  this caveat explicitly, next to the kernel-floor claim itself.
- **The canary suite is green locally, not in CI** — there is still no
  CI pipeline in this repo (a Phase 3 G3 finding that remains true).
- **Matrix limitations still standing**, per
  `docs/notes/phase4-matrix.md`: Knative's `--cgroup` scope is node-wide,
  not per-Service (an honest limit of what Kubernetes exposes, not a
  bug); namespace-rewritten or stable-layer attach paths require an
  unprivileged byte-identical `--provenance-module` safe copy (providers whose
  dependent target objects cannot be reproduced are refused);
  privilege minimums are measured on one host only. (The
  previously-listed "`cgroup_id` has no consumer" limitation is now
  resolved — Phase 4 Task 6's `cgroups[]` breakdown gave it a consumer;
  `docs/notes/phase4-matrix.md` and this ROADMAP's Phase 3 G3 entry were
  both stale on this point and are corrected as part of this gate.)
- x86-64 only in this release; AArch64 is the first post-v1 item (see
  "Explicitly deferred" below).

## Explicitly deferred (post-v1, in design spec's "out" list)

AArch64 → first item after v1. Raw tracepoint lifecycle migration is post-v1.
Then, unordered and only on demonstrated need: live-discovery fallback mode,
syscall/network correlation, DaemonSet/operator packaging, system-wide module
discovery, security-findings layer, GUI.

## Productization (2026-08-15 →)

Input: `docs/notes/2026-08-15-architecture-and-gap-analysis.md` (review + decisions A1–A7)
and `docs/superpowers/specs/2026-08-15-productization-slice1-discovery-and-trust-design.md`.

**Consolidation checkpoint (2026-08-31):** The shipping baseline, Slice 1b-2
Task 4 prerequisites, the exact accepted Stage 3A3 GREEN6 pair, and the
dual-kernel-qualified MVP lifecycle fixes through `ae8494d` are integrated on
`main`. The combined tree passed all four locked workspace gates at the
runtime-qualified checkpoint.
The frozen MVP candidate passed the six-row semantic/privacy/cleanup campaign
on Jammy 5.15 and Noble 6.8. The tree remains unreleased; exact-tip CI,
complete packaging, remaining security remediation, and release gates are
still pending. The exact `3e10be9` static security closeout found one high,
six medium, and two low findings. The owned-child root-authority finding is
remediated and independently accepted in the current revision; privileged VM
confirmation and the lower-severity release work remain pending. The
historical 9.2d/9.3/9.4 volume campaign is retained as
post-MVP hardening rather than a prerequisite for declaring the local MVP
runtime-qualified; it remains UNRUN and is not claimed. See the tracked
[productization evidence index](../reports/2026-08-31-productization-evidence-index.md)
for exact commits, hashes, portable history, runtime evidence, and claim
boundaries.

- **Slice 1a — trust simplification** ([plan](2026-08-15-productization-slice1a-trust-simplification.md)):
  the lease/provenance/hardened-oracle lane of `2026-08-13-manifest-provenance.md` is
  **scheduled for removal** (status flips to "removed" in the plan's deletion task; kept in
  git history; reasoning in the spec §4.11 and §10.6). Object identity becomes hash-pinned
  (SHA-256 once, `fstat` change detection). CLI drops `--provenance-module`,
  `--trusted-workload`, the `p11scope discover` subcommand and exit code 78. CI skeleton.
  **Status (2026-08-16): landed on branch `productization/slice1a` (b8e4fc3..HEAD, 27
  commits; lane removed in 263935a with the history note); −13,727 lines net across
  `src`/`crates`/`tests`/`scripts` (2,798 added, 16,525 deleted). Verified: the four cargo
  checks and the unprivileged suite green (all test binaries 0 failed, incl. 14 pinning tests,
  10 artifact contracts). Root gates (owner-approved, 2026-08-16, all exit=0):
  `scripts/gates.sh` (incl. canary matrix) 462s; matrix — docker 15s, shared-layer 24s,
  fork-scope 42s, oracle 158s, kind-pod 68s, knative 225s; `verify-discover-containers.sh`
  47s; `build-release.sh` (first run needed one manual `kill -CONT` of the self-suspended
  sudo in the hardened-target smoke — same class as 2d2cc32, fixed by resuming `$LPID`;
  clean re-run after the fix: ALL OK); `bench-overhead.sh` — overhead ns/call: unobserved
  0, metrics 3366.6, profile 3754.4, trace 4127.8 (5 runs/condition, 1M calls each,
  kernel 7.0.0-28-generic; consistent with the documented ~3.3µs). CI e2e: PASS — first
  push, run
  [31935749796](https://github.com/mingulov/pkcs11-scope/actions/runs/31935749796)
  (2026-08-16, `checks-and-e2e` success). Follow-ups noted for 1b: rerun the post-fix6 `--cgroup`
  capability matrix, one privileged `--cgroup` smoke after
  the `_cgroup_file` removal, prune the now-unused root `p11scope-discover` dev-dependency.**
- **Slice 1b — discovery engine and commands.** Split in two independently shippable plans
  when 1a landed (2026-08-16), because the memory scan needs no BPF change while the live
  hooks need the attach-cookie/dynamic-slot refactor:
  - **Slice 1b-1 — memory-scan discovery, `inspect`, `doctor`**
    ([plan](2026-08-16-productization-slice1b-1-discovery-scan.md)): scan the target's
    mappings for `CK_FUNCTION_LIST`/`CK_INTERFACE`, pin and attach without a manifest or the
    helper, multi-module plans and per-module semantic state, `--module`/`--manifest`
    optional, evidence `discovery[]`/`authority`, schema v2. The eBPF object is unchanged.
    Scanning happens once at attach time; a module loaded later is not discovered (1b-2).
    **Status (2026-08-19): Contract A with explicit-manifest operator attestation is
    implemented. Scan-only claims are count-only, `PARTIAL`, and semantically
    unjoinable; accepted manifest claims may authorize only the exact pinned object +
    offset + canonical name. Corrective Tasks 1–5 and their
    task-local review fix rounds are implemented on the recovery branch: one capture-wide
    attempted-I/O/cardinality budget; VMA-confined interface names; fail-closed comparable
    file identity with the existing overlay-only uncertainty; retained process generations
    and per-view ownership through attach; and exact per-object stale-manifest fallback.
    These changes do not implement Slice 1b-2. Task 6 rejects unsupported
    `doctor --module`. Final whole-range correctness/security reviews and the
    exact-candidate local matrix passed on 2026-08-19. CI remains pending, so no
    release or security-clearance claim applies yet.**
  - **Slice 1b-2 — live discovery and `run`**: BPF loader (`_dl_debug_state`) and export
    uretprobes, `DESCRIPTORS` + attach-cookie semantics with dynamic slot allocation,
    `discovery::Engine`, `pause.rs`, `run -- cmd`, `attach_gap_ms`, mid-capture
    module-ambiguity purge. **Research status (2026-08-19): final frozen Gate A
    PASS on 5.15/6.8. The frozen-oracle Gate B KVM campaign recorded 120/120,
    all as outcome B, but controller review found owner-2 cleanup and outcome-A
    causal-deadline defects plus an oracle mismatch. It is immutable pre-fix
    feasibility evidence; promotion is blocked and the amended no-busy-wait
    campaign is UNRUN. The retained Noble TCG Gate B campaign is
    TIMEOUT/INCOMPLETE because the accepted 150,091-insn program takes 253 s
    under TCG. The ptrace-free loader event path passed on both kernels. The
    attach-first experiment recorded 160/160 for its narrow fixture, but it is
    historical diagnostic evidence only: non-promotable, zero product attempts,
    and not proof of generic initial-set or all-export-ABI coverage. Task 9
    timing catalog was skipped by D3. **Amended-candidate status (2026-08-20):**
    Task 1 is reviewed, but its first owner-approved KVM campaign is
    environment/lifecycle NON-PASS. Jammy 5.15 Gate A passed; transient host
    KVM access disappeared before Noble booted, so Noble and all Gate B lanes
    are UNRUN. No replacement was made and Task 5 remains locked. A new complete
    campaign requires stable real `kvm` group membership and fresh owner
    approval. **Stable-group rerun (2026-08-20):** the approved replacement
    campaign completed all eight KVM lanes on one frozen identity. Gate A
    passed on both kernels; Gate B was Jammy FAIL/PASS/PASS and Noble
    FAIL/FAIL/FAIL, retaining 58 positive rows and four canonical Outcome-B
    oracle negatives. Each negative fails only the strict comparison between
    the prior cycle's post-syscall `resume_completed_ns` sample and the resumed
    child's earlier hook timestamp (18–74 us), while successor consumption and
    every stopped-set/attach/drain/resume/marker/cleanup predicate pass.
    Independent review classifies this as an oracle/proof timestamp defect,
    not an observed unsafe pause, but the campaign remains NON-PASS and Task 5
    stays locked pending a reviewed correction and a new qualifying campaign.
    **Corrected-oracle campaign (2026-08-20):** the reviewed correction at
    `ae96c451` replaced that overconstrained timestamp comparison with the
    required successful-resume-before-successor-dequeue boundary, without
    changing BPF, maps, fixture, protocol, privacy, or timeout. The fixed KVM
    matrix passed Gate A 2/2 and Gate B 120/120 (72 Outcome A, 48 Outcome B),
    all eight lanes rc0 with no retries. The 943-entry ledger and independent
    semantic/privacy/lifecycle review passed. Task 2 is complete. **Product
    checkpoint (2026-08-24):** Tasks 3–7 are implemented and independently
    reviewed on the isolated productization branch. A short-lived Docker
    diagnostic exposed capture-history ownership loss after ordinary exit, so
    the newly formalized Task 6E history/lifecycle correction blocks Task 8.
    Public `run`, supported live-capture claims, Task 9 runtime evidence,
    required CI, release, and security clearance remain incomplete or
    unclaimed. See the
    [pause amendment](../specs/2026-08-19-slice1b2-no-busy-wait-pause-amendment.md).**

    **Fixed-ceiling disposition (2026-08-27):** The reviewed
    [500 ms amendment](../specs/2026-08-27-slice1b2-500ms-pause-amendment.md)
    passed fresh Gate A on Jammy 5.15 and Noble 6.8, Gate B 120/120 across
    three cold boots per kernel, and the isolated host Lane 02 matrix 6/6.
    Independent Sol, Terra, and Luna evidence review unanimously passed. This
    selects the candidate only: Task 4 rehashes and compatibility-checks the
    already frozen Lane 02 result, then executes remaining lanes beginning at
    Lane 07. The distinct post-r3 9.2d campaign retains its existing Lane 02
    gate position. r3/9.2d, 9.3, CI, Task 10, and release remain pending.**

    **Topology scope ruling (2026-08-27):** The exact reproduced node-wide
    retained-view late-provider case is an expected `UNSUPPORTED/NON-PASS`
    negative control with one overlay plus one unavailable; it is evaluated
    only outside the zero-unavailable PASS oracle. The receipt-bound attempt-6
    history is complete pre-r3 and is not rerun in Task 4; Lane 13 runs once in
    9.2d as the frozen-candidate negative control. Any receipt-input mismatch,
    different public shape, additional gap, or lifecycle/input/cleanup failure
    stops as UNRUN/review or NON-PASS as applicable. The retained
    preattached-provider Knative evidence remains `136/136` with expected
    cold-pod calls. Remaining applicable Task 4 lanes and r3 may proceed only
    after this additive amendment is independently reviewed and committed; Lane
    13 PASS is not an unlock condition. The Gate Closure Task 5
    capability-validator integration is complete through exact commit
    `7a0c1eddac0b0b81340206ac742884ca2f31f691`, whose live capability gate
    exited 0 without changing Lane 13. Public README/usage wording remains
    reserved for Task 10; no design-spec, production, privacy/schema, or
    procfs/mmap/eBPF fallback change is made here.**

    **Task 4 receipt architecture ruling (2026-08-28):** Remaining-lane gate
    receipts use one private Python-stdlib sealed-envelope helper, one shared
    privacy scanner, six lane-owned checkers, and seven committed contracts
    (`07`, `09`, `10`, `11`, `14`, `16-never`, `16-auto`). After accepted
    input/build-subject closure, the blueprint gate requires seven independently
    reviewed, design-complete, non-executable
    blueprints that select future literal sets,
    normative checker ABIs, resources, privacy mappings, cardinalities, and
    fail-closed caps before implementation; they make no current-output claim.
    All checker and
    helper interfaces resolve before promotion, and the runtime helper rejects
    blueprint schema with exit 77 before root creation. Promotion yields
    interface-complete manifests, not lane acceptance; executability begins only
    after migrated-driver exact registration/replay passes. The exact
    194-row Lane 14 canary/privacy crosswalk contains 191 scan targets, two
    input-only manifests, and one must-detect positive control; it does not
    replace Lane 14 distribution/attach/protocol/release/smoke artifact rows.
    Existing checkers remain the domain oracles; the
    envelope validates only declaration equality, custody, provenance, resource
    lifecycle, replay isolation, privacy scanning, sealing, and terminal
    publication. The rejected live Rust observer, FD-5 protocol, global
    `facts-v1` interpreter, and duplicated lane-local receipt wrappers are not
    implementation authority. Frozen Lane 02 evidence is compatibility-checked
    rather than rerun in Task 4; Lane 13 history is neither amended nor rerun
    and remains the single frozen-candidate 9.2d negative control. Product
    Rust/BPF, public v2 schemas, `allowlist-v1`, lane oracles, runtime order, r3,
    9.2d, 9.3, 9.4, exact-tip CI, and Task 10 remain unchanged.**

    **Task 4 build-subject correction (2026-08-28, accepted):** The first
    seven-blueprint candidate is rejected because selected source rows do not
    close Cargo or Docker inputs. Before blueprint acceptance, add one reviewed
    rootless build-subject discovery/production freeze with exhaustive
    transitive input authority, a fresh sealed Lane 09 image, and final-tip
    product-affecting compatibility. Lanes 07/09/10/11/16 consume private
    copied subjects, validate exact registered subject-checker argv before any
    privilege/container/BPF/resource and again at final replay, and do not run
    Cargo. Lane 14 remains the source-bound build/distribution contract. The
    schema and custody helper remain unchanged. Independent Sol/Terra/Luna
    review accepted `2026-08-28-task4-build-subject-decision.md`; all build and
    runtime claims remain UNRUN. BS2a is candidate-only discovery and cannot
    authorize a subject; `produce` remains exit 77. One BS2b runner call is the
    sole production boundary and owns the complete four-profile and Lane 09
    image build set, exact-object preflight, filesystem restriction, fresh
    rootless PID/mount/network isolation with private `/proc`, inherited
    network/FD-theft/process-injection denial with no external daemon,
    trace/process lifecycle, reconciliation, postflight, and no-replace
    publication beneath a held fsync-capable private-parent descriptor.**

    **Stage3 authority amendment (2026-08-30, accepted):** The
    [accepted decision's Stage3 amendment](../reports/2026-08-28-task4-build-subject-decision.md#stage3-authority-amendment-2026-08-30-accepted)
    governs BS2b capacity, exact constants, raw-symlink custody, and order.
    The phase order is `3A0` -> `3A1` -> `3A2` -> `3A3`, each limited to RED,
    GREEN, and review after docs acceptance; Stage3 code remains gated until
    independent review/commit. No build, child/build-root, Landlock
    implementation/probe, producer, runtime, publication, or release is
    authorized by this amendment. The privacy allowlist and schema row limits
    remain unchanged.**
- **Slice 2 — capture quality** and **Slice 3 — structure** are deferred by
  default: see [the deferred feature slices doc](../specs/2026-09-01-post-release-feature-slices.md)
  (also holds the parked items: AArch64, 32-bit counting mode, freezer pause,
  manifest catalog, raw-tracepoint variants, packages/images). Deferral is a
  default, not a lock — the owner may pull items into v0.1.0 depending on
  pace. `uprobe_multi` was pulled into W3 on 2026-09-01, then deferred again by
  the owner on 2026-09-03 until a stable Aya release exposes the required API.

**Gate for each slice:** the four cargo checks, the unprivileged suite, and the CI e2e job
green; root gates run locally only with owner approval and are otherwise recorded UNRUN.

## 2026-09-01 MVP portability checkpoint

`main` is the sole working tree and authoritative product branch. Accepted
Stage 3A3 GREEN6 history is reachable from it. Product commit `1d3837b` closes
initial mapped-provider export attachment before readiness and passed the
local Rust 1.88 workspace gates plus an independent review.

The same product commit passed Fedora Cloud 44 on kernel 6.19 with SELinux
`Enforcing`: exact workspace gates, release build, Fedora SoftHSM core capture,
the three-export initial-set fixture, inspect/doctor, all seven privacy-canary
lanes, zero AVCs, and cleanup. This is post-MVP portability evidence, not a
release declaration. Remaining work is release hardening, hosted CI,
container/deployment refresh, the complete receipt, and publication authority.

## Release program (2026-09-01) — waves W1–W8 to v0.1.0

Authority for sequencing the first public release. Product truth:
[the release PRD](../specs/2026-09-01-p11scope-release-prd.md). Work method and
priority: [the owner requirements spec](../specs/2026-09-01-release-requirements-and-goal.md).
Post-release scope: [the feature-slices doc](../specs/2026-09-01-post-release-feature-slices.md).

Each wave: entry gate = previous wave's exit gate. Exit gate = the four
canonical cargo gates green on `main` **plus** a full independent review +
gap-analysis cycle with zero accepted findings **plus** the wave's own
evidence row(s), recorded pass/fail/UNRUN — never inherited. A wave's detailed
plan is written at wave start under the verified-anchor protocol below —
detailed plans written before their inputs exist would be fiction (this file's
founding rule).

| Wave | Scope | Plan / charter |
| --- | --- | --- |
| W1 | **Task 0 custody rescue first**, then eight scan findings (Tasks 1–8), TDD, review-to-zero; private SDD trove only in `p11scope-ws` | [full plan, reviewed 2026-09-01](2026-09-01-release-hardening-wave1-findings.md) |
| W2 | Storage consolidation: two-directory rule, migrate + repoint, `p11scope-ws` custody | [full plan](2026-09-01-wave2-storage-consolidation.md) |
| W3 | **Priority 1: `C_GetInterface` compatibility closure** (partial passive behavior → separate live request/result/failure evidence plus finite offline helper matrix; selection authority limited to exact retained generation or attested exact provider, never inventory); then tracepoint offsets, opened-inode identity, capability tiers, honest-degradation fixes, and per-offset qualification inputs | [plan](2026-09-02-wave3-correctness-residue.md) / [closure](../reports/2026-09-02-wave3-correctness-closure.md) |
| W4 | Hosted CI running the full suite; "green locally, not in CI" dies | [charter](2026-09-01-release-wave-charters.md#w4) |
| W7 | ia32 targets on x86-64 hosts | [charter](2026-09-01-release-wave-charters.md#w7) |
| W5 | Container/K8s requalification (provisional; W8 re-runs on the final tip) + seccomp/SELinux artifacts | [charter](2026-09-01-release-wave-charters.md#w5) |
| W6 | Multi-distro/kernel matrix; support restated "5.15.x, tested on ⟨list⟩"; load-only CI matrix; run the supported-rate/loss and fork-exec-loader-unload product oracles on the per-offset path | [charter](2026-09-01-release-wave-charters.md#w6) |
| W8 | Release assembly: receipt, docs truth pass, final review-to-zero, repeat both product oracles on the exact release tip, ready-to-publish bundle | [charter](2026-09-01-release-wave-charters.md#w8) |

Publication (push, tag, release) is NOT a wave — it is an explicit owner
decision after W8.

**W3 engineering gate: CLOSED AND LOCALLY INTEGRATED 2026-09-03.** The final production tip
`ec5e0ae` passed the four Rust 1.88 gates with 1,072 tests and independent
correctness/security plus test-quality review accepted zero findings.
Privileged Jammy/5.15, Noble/6.8, `pkcs11-check`, and lifecycle/rate product
oracles remain explicitly `UNRUN`; they are W6/W8 qualification gates and no
runtime-qualified or release claim is made. `uprobe_multi` remains a separate
post-W3 optimization after suitable stable Aya support.

The two product oracles are release gates, not inherited historical evidence:

- `supported_rate_loss_oracle`: an empirically declared, matrix-specific fixed
  PKCS#11 burst/rate must produce exact agreement between generator-completed
  calls, STATS entered/returned, and raw consumed `CALL` records with zero
  loss; ring capacity and drain cadence alone never establish a supported
  events/second claim. Test the runtime-selected mechanism for each matrix
  cell. A deliberately constrained ring must report exact nonzero loss and
  force `PARTIAL`.
- `fork_exec_loader_unload_oracle`: one adversarial lifecycle must cover
  fork, exec, `dlopen`, calls, `dlclose`, pathname replacement/reload, terminal
  drain, exact attachment retirement, and absence of stale attribution.

W3 supplies their correctness primitives. W6 establishes the kernel/rate
envelope, including the Linux 5.15 per-offset path. W8 repeats both on the
exact release candidate; `UNRUN` is honest evidence but cannot establish
publication readiness.

### Agent execution protocol (all waves)

Any fresh agent (or agent team) executing a wave follows this; it is the
generalization of how wave 1 was planned and reviewed on 2026-09-01.

1. **Read first:** the PRD, the owner requirements spec, this section, the
   wave's plan/charter, and `CLAUDE.md`. Memory notes are background, not
   authority.
2. **Verified-anchor planning:** dispatch independent read-only verifiers
   over EVERY cited file:line anchor and behavioral claim; adjudicate; fold
   corrections into the document and commit it. A plan whose anchors don't
   verify is not executable. **Charter waves run this twice:** pass 1 over
   the charter's own anchors and claims BEFORE writing the plan; pass 2 over
   the written plan BEFORE executing it.
3. **Superpowers chain:** brainstorming (if design is open) → writing-plans →
   subagent-driven-development or executing-plans → requesting/receiving-code-review
   → verification-before-completion. TDD per task: failing test first, minimal
   fix, gates after every task.
4. **Review-to-zero:** wave end = two independent review agents (adversarial
   correctness/security + test-quality/regression) over the wave's full diff;
   triage with reasoning; fix accepted findings TDD-style; repeat with fresh
   agents until a full cycle accepts zero findings.
5. **Subagent policy:** use the configured p11scope roles by their real names:
   Luna high for narrow read-only searches and inventories, Luna worker xhigh
   for one bounded patch, and Sol xhigh for architecture, lifecycle,
   concurrency, security, adjudication, and final review. Add a distinct Terra
   xhigh lane only when a third independent review materially reduces risk.
6. **Branch/commit:** one branch per wave (`hardening/<wave-name>`), one
   commit per task, merge to `main` only after review-to-zero; rerun gates on
   `main`. Never push, except the owner-approved W4 test/CI branch.
7. **Honest evidence:** privileged/container lanes run only with owner
   approval; otherwise recorded UNRUN. Never claim an unrun lane.
8. **Owner-gated (never do autonomously):** push/tag/publish, privileged or
   container experiments, deleting original evidence, rotating keys,
   broadening the privacy allowlist, spending money.
9. **Storage:** durable output only in the two directories; non-public
   material only in `p11scope-ws` (commit it there — text/metadata in git,
   large binaries gitignored but sha256-manifested).

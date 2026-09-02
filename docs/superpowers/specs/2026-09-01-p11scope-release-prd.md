# p11scope v0.1.0 — Product Requirements (release PRD)

**Date:** 2026-09-01
**Status:** Owner-approved product definition for the first public release.
**Owner:** Denis Mingulov
**Authority relationships:** This PRD is the product-truth authority — *what ships
and what it must be true of it*. The owner requirements spec
(`2026-09-01-release-requirements-and-goal.md`) is the authority for *how the
hardening work is done and prioritized*; `docs/superpowers/plans/ROADMAP.md`
§"Release program" is the authority for *sequencing*. Post-release feature work
lives in `2026-09-01-post-release-feature-slices.md`, not here.
**Scope decision (owner, 2026-09-01):** the release baseline is the **hardened
current feature set plus `uprobe_multi` attach** (owner: "more
straightforward" — pulled into release scope explicitly). Slice 2/3 and the
other deferred items are **deferred by default, not excluded**: depending on
execution speed the owner may pull any of them into v0.1.0 — the deferral
list is a default, the owner decides per item. Shippable artifact set is
**tag + binaries + docs** (no container images, no distro packages).

## 1. Product statement

`p11scope` observes the real PKCS#11 dependency surface of a running Linux
application — functions, mechanisms, return codes, latency, and safe policy
metadata — **without replacing its module or changing its configuration**. It is
a non-interposing eBPF-uprobe observer: it discovers the provider's actual
function table (including stripped providers), attaches by file offset, and
produces versioned capture documents.

**Users and jobs:**

1. **Incident diagnostics** (operator of an app talking to an HSM/token):
   "this app intermittently fails against our HSM — what is it actually doing?"
   → `doctor`, `inspect`, `profile`/`trace` with zero app changes.
2. **Migration dependency discovery** (engineer replacing a provider): which
   PKCS#11 subset does the app *actually* use? → `observed-profile.json`
   consumed alongside `pkcs11-check` results.

"A real p11scope" (owner's bar): a tool that can be handed to someone else and
used — not a tree that passes its own gates.

## 2. Release definition

**Version:** v0.1.0, public. Publication (push, tag, release) is an explicit
owner decision; the program's end state is a verified, receipt-bound,
ready-to-publish bundle.

**Shippable artifact set:**

- Git tag on `main` + GitHub release.
- `p11scope` — fully static musl x86-64 binary (the observer never dlopens).
- `p11scope-discover` — glibc and musl *dynamic* builds (it must dlopen).
- SHA-256 checksums and the complete Lane 14 build receipt (input-trust rules
  enforced; capture bound literally — wave-1 Tasks 7/8).
- Docs: `README.md`, `docs/usage.md`, `CHANGELOG.md`,
  `docs/privacy/allowlist-v1.md` — every quantitative claim citing the script
  that measured it.

**Not in the default artifact set** (deferrals per §8, not exclusions):
container images, K8s manifests as supported artifacts (a qualification
report is published instead), deb/rpm packages, AArch64 builds.

## 3. Feature inventory (release scope = as built, hardened)

The behavior authority is `docs/usage.md`; this list fixes *scope*, not detail.

- **Commands:** `run` (owned child), `trace`, `profile`, `inspect`, `doctor`;
  metrics is `--mode metrics` on `profile`/`run`, not a subcommand; `-o`
  capture documents (schema v2); `--pid`/`--cgroup` scoping.
- **Discovery:** in-memory function-table scan of the live process (2.00–2.40
  legacy tables and 3.0/3.1/3.2 interfaces, all 104 slots); corroborated
  alternate/null-name prefixes recorded as PARTIAL; deceptive/vendor tables
  left undecoded. `C_GetInterface` selection behavior is investigated and
  recorded as separate selection evidence (owner decision 2026-09-01 — §8
  defines both mechanisms and the inventory-separation invariant; W3).
  `p11scope-discover` remains the
  optional offline manifest path (explicit operator attestation).
- **Multi-module capture**, including proxy stacks (p11-kit/proxy-ng style):
  release-qualified with at least one proxy-over-provider configuration lane
  (`scripts/matrix/verify-proxy-stack.sh`, rerun in W6 and on the final tip in
  W8) — qualification of what exists, not new proxy features. Known honest
  limit carried into the release: p11-kit's fixed closure array exceeds the
  512-slot ceiling and is refused whole with a PARTIAL report (README §known
  limits) — the release documents this, it does not fix it.
- **Attach engine:** offset-based uprobe/uretprobe, PID/cgroup filter maps,
  in-kernel ring-loss counters, PidPin (pidfd + starttime) generation guard.
  **`uprobe_multi` attach is release scope** (owner decision 2026-09-01):
  used only when the runtime
  `ProcessScopedPidFilter` feature probe returns `Ok(true)`, with the existing
  per-offset attach otherwise. Link creation began in 6.6, but that version
  fact alone does not prove process-scoped filtering. The attach mechanism in
  use is recorded in evidence (W3).
- **Capture policy:** `allowlisted` default; pointer-derived bytes only by
  exact membership in the published finite sets.

Fixes required to call this inventory "correct" are enumerated in the
requirements spec §5 (eight scan findings + three research issues) and closed
by waves W1/W3.

## 4. Capability and privilege model (release requirement)

The release ships a **current-product availability ladder**. The older proposed
leased/hardened T3/T4 meanings in
`docs/notes/2026-08-15-architecture-and-gap-analysis.md` §4 are historical:
Productization Slice 1a deliberately removed those authorization lanes, and W3
must not restore them.

The monotonic tiers are: T0 offline when the real embedded object and ordinary
self-uprobe cannot load/attach; T1 when that real host probe succeeds but no
requested target is proved readable; T2 when the exact target generation,
required procfs views, and provider opens are readable but exec/exit lifecycle
links are unavailable; T3 when base lifecycle links also work but a requested
scope-specific mechanism does not; and T4 when every mechanism required by the
requested current-product lane preflights. T4 means availability, not leased or
hardened authority and not a promise that the eventual capture is `COMPLETE`.

- Documented minimum capability set per feature; `CAP_DAC_READ_SEARCH` added
  to the model (aya tracefs mount check), `CAP_SYS_RESOURCE` dropped (memlock
  is memcg-accounted at the 5.15 floor).
- Graceful degradation: with reduced capabilities, p11scope does what it can
  and **reports its highest proven availability tier honestly** (`doctor`
  probes procfs mount options,
  Yama `ptrace_scope`, non-dumpable targets, and reports a degraded tier —
  never a silent blind spot).
- The tier probe must load the real BPF program with real map sizes and
  actually attach — a toy probe that says "supported" while the real load
  fails is a known industry failure (research checklist #5).
- Capability bits, uid, sysctls, Yama, hidepid, dumpability, seccomp, and LSM
  state explain operational probe results; they never override them. Tier is a
  `doctor` preflight result. Capture loss and `PARTIAL` evidence remain separate.

## 5. Privacy contract

`docs/privacy/allowlist-v1.md` is binding and is **never broadened
implicitly**. No decoder or dump switch exists for PINs, key material,
`CKA_VALUE`, labels, `CKA_ID`, plain/ciphertext, signatures, wrapped blobs,
random output, raw mechanism byte arrays, raw session handles, or ordinary
buffers. Target-controlled bytes never reach a terminal unescaped and never
enter the capture document in `/proc/self/fd/N` form. Non-public evidence
(PIDs, addresses, raw captures) lives in `p11scope-ws`, never in the public
tree.

## 6. Honesty and evidence model

- A lossy, degraded, truncated, or blind run is distinguishable from a clean
  one **at the consumer level** (EVIDENCE line: completeness, ring loss,
  `trace_truncated`, PARTIAL reasons). The verdict-binding gap named by the
  research report (checklist 9: the loss counters exist, the consumer-level
  verdict must provably reflect them) is a W3 exit-evidence row, not an
  assumed property.
- "No providers found" is never the report for a non-dumpable, hidepid, or
  gone target — those are recorded expected outcomes.
- Environment results are recorded as pass, fail, or UNRUN — never inherited
  from a prior candidate. Every quantitative doc claim cites its measurement.

## 7. Supported matrix (release statement form)

Support is stated as **"kernel 5.15.x floor, tested on ⟨exact list⟩"** —
verifier behaviour is not monotonic across point releases, so an untested
kernel is *expected to work*, not *supported*.

- **Tested at release (minimum):** Ubuntu 22.04 (5.15), Ubuntu 24.04 (6.8),
  Fedora 44 (6.19, SELinux Enforcing) — all three **re-run at the release tip
  in W6/W8, never inherited** from the earlier candidates — plus the W6
  additions; a load-only CI kernel matrix backs the list.
- **Host arch:** x86-64 only. **Target ABI:** 64-bit and 32-bit (ia32)
  processes on x86-64 hosts (W7).
- **Containers:** Docker (including older seccomp profiles that block
  `openat2`/`bpf()` — degraded honestly, with a shippable localhost seccomp
  profile), kind/Kubernetes, Knative — requalified on the release tip (W5
  provisional; final-tip requalification in W8).
- **LSM:** SELinux Enforcing qualified; policy/caveats documented.

## 8. Non-goals and default deferrals for v0.1.0

**Hard non-goals** (not in v0.1.0 under any pace): interposition mode
(non-interposing observation is the product's identity); key/PIN decoding
under any flag (privacy contract, §5); macOS/Windows.

**`C_GetInterface` — investigated, with one narrow invariant (owner decision
2026-09-01, superseding the earlier blanket "never calls" stance).**
`C_GetInterface` is the usual 3.x entry point and MUST be investigated: the
release records both what is requested and what comes back, two ways (W3):

- **Live selection observation:** `C_GetInterface` is a mandatory export, so
  it is offset-probed like any other function. The capture records the
  target's own calls: requested interface name (matched against the known
  finite name set per the allowlist discipline — a non-matching name is
  recorded as present-but-unnamed, never leaked), requested version and
  flags, and the returned interface identity-mapped to its enumerated table.
  Honest timing limit: an already-running `--pid` target usually made this
  call before attach — `run` (owned child, attach-before-exec) captures it;
  a missed call is a recorded absence, not silence.
- **Known-parameter probing (offline helper path):** the helper queries the
  finite standard set — interfaceName NULL (the module default, which the
  spec guarantees), `"PKCS 11"` with no version, `"PKCS 11"` ×
  {3.0, 3.1, 3.2}, standard flag variants — and records each request→result
  pair, with the returned table identity-mapped to the enumeration.

The surviving invariant is narrow: **selection results are recorded as
selection evidence beside the inventory, never merged into it.** The call is
parameterized — its answer depends on the query and on which PKCS#11
versions the module supports, with possible fallback — so a selection result
describes what a caller gets, while `C_GetFunctionList` +
`C_GetInterfaceList` enumeration stays the caller-independent inventory.
Kept separate, aliasing between a selection result and an enumerated table
becomes *explicit recorded evidence* instead of a fabrication risk. New
captured fields follow the existing allowlist discipline (§5 — exact
membership in published finite sets; an addition is an explicit versioned
allowlist revision, never implicit).

**Deferred by default — pullable by owner decision if pace allows:** AArch64
host; raw-tracepoint variants (tracefs stays a requirement meanwhile); Slice 2
capture features (filters, snapshots, per-module profile sections, ring/epoll
budgets); Slice 3 restructuring; container images / distro packages;
`pkcs11-lab assess`. All tracked with entry conditions in
`2026-09-01-post-release-feature-slices.md`; pulling an item in is an owner
decision recorded there and in the ROADMAP, and adds the item to a wave with
full gate coverage — deferral is the default, never a lock.

## 9. Acceptance (release criteria)

The requirements spec §6 definition of done, plus, in PRD terms:

1. Every §5 finding and research issue closed with a test that fails without
   the fix; a full independent review + gap-analysis cycle returns zero
   accepted findings.
2. Four canonical gates green on `main`; hosted CI runs the suite.
3. Tier ladder implemented and documented; `doctor` reports degraded tiers.
4. Container/K8s qualification rerun on the release tip; multi-distro/kernel
   and ia32-target results recorded honestly.
5. Proxy-stack lane qualified.
6. All durable state in the two directories (`pkcs11-scope`, `p11scope-ws`);
   no tracked **executable or live-navigation** path depends on
   `~/.local/state`, `~/p11scope-vm-bases`, or `/tmp` roots (W2). Historical
   run records keep their original paths verbatim — rewriting them would
   falsify evidence — and the W2 relocation record maps every old root to its
   new home. (This is the working interpretation of spec §6's storage bullet;
   flagged to the owner in the W2 relocation record.)
7. `README.md`/`docs/usage.md` claims match measured reality; receipt binds
   the literal release capture.
8. Ready-to-publish bundle produced; **publication remains the owner's
   explicit decision.**

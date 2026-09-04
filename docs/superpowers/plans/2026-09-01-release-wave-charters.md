# Release wave charters — W3–W8

**Date:** 2026-09-01. Charters, not plans: each fixes a wave's scope, inputs,
and exit gate so a fresh agent can start it. **Task 1 of every wave is to
produce the wave's detailed implementation plan** via superpowers:writing-plans
**plus the verified-anchor protocol** (`ROADMAP.md` §"Agent execution
protocol" step 2) — plans written earlier would cite code that W1–W3 change
(this repo's founding plan-after-inputs rule). Entry gate for each wave = the
previous wave's exit gate; exit gate = four cargo gates + review-to-zero +
the wave's evidence rows, pass/fail/UNRUN, never inherited.

Shared inputs for all waves: the release PRD
(`../specs/2026-09-01-p11scope-release-prd.md`), the owner requirements spec
(`../specs/2026-09-01-release-requirements-and-goal.md`), the research report
(`../../notes/2026-09-01-ebpf-comparable-tool-pitfalls.md`), `CLAUDE.md`.

**Research citation convention (the report has TWO numberings — do not mix):**
"checklist N" = its `## Top 10 hardening checklist` (1–10); "item #N" = its
tier-section bullets (`#1`–`#22`). Every citation below names its scheme.

**Evidence staleness rule:** W5/W6 evidence is gathered when those waves run,
but W7 still changes the uprobe read path afterwards — so W5/W6 results are
*provisional*; the release evidence is W8's final-tip requalification set.
Spec §3.3/§6 "on the release tip" is satisfied by W8, not by W5/W6.

---

## W3 — Correctness residue {#w3}

**Objective:** begin with the `C_GetInterface` compatibility closure, then
close the remaining Tier-1 research findings and ship the capability-tier
model — after this wave the *product logic* is release-final.

**Execution priority:** W3 starts with `C_GetInterface` selection evidence.
Only after that compatibility slice is closed does it proceed to
capability breadth and the remaining correctness residue. The existing
implementation is only partial: passive return discovery/inventory exists,
but selection requests, failures, and aliases are not yet release-complete.

**Scope:**
1. **`C_GetInterface` selection evidence (owner decision 2026-09-01 —
   release scope; PRD §8 defines the requirement):** current behavior is only
   partial passive return discovery/inventory; W3 adds separate live request,
   result, and failure evidence plus a finite offline helper matrix. *Live:*
   offset-probe the provider's exported `C_GetInterface` (mandatory export in
   3.x) — uprobe reads the requested interfaceName (bounded read, exact-match
   against the known finite name set per the allowlist; non-matching →
   present-but-unnamed), requested version, and flags; uretprobe reads the
   returned `CK_INTERFACE` (name, version, function-list pointer) and userspace
   maps the returned table to its enumerated interface. A `--pid` target
   selected before attach records preattach absence explicitly; `run` mode is
   the covered attach-before-exec path. *Offline:* query the finite standard
   set — interfaceName NULL (module default), `"PKCS 11"` unversioned,
   `"PKCS 11"` × {3.0, 3.1, 3.2}, and standard flag variants — recording each
   request→result/failure pair with the returned table identity-mapped to the
   enumeration. Cover null/exact/unknown names, versions/flags, failure,
   aliases, preattach absence, and privacy escaping. A successful live
   selection may authorize a selection-scoped table only for that exact
   retained process generation; an offline finite-query result may authorize
   only with explicit manifest attestation and exact provider identity.
   Neither result becomes inventory, and unmatched enumeration remains
   explicit/PARTIAL. Add an open design ruling recording these authority
   limits. New fields require owner approval for both schema and allowlist
   wording; target-controlled name bytes surface only by exact membership in
   the published name set.
2. **Tracepoint offsets (checklist 1 / item #1):** stop hardcoding field
   offsets. Parse the live `/sys/kernel/tracing/events/task/task_newtask/format`
   at load, pass offsets
   via a config map, hard-assert on mismatch (the bcc precedent failed
   *silently with wrong data* — an error is the required behavior). Preserve
   BTF-independence (item #12): no CO-RE dependency may enter.
3. **Opened-file identity (checklist 2 / item #3):** after opening
   `/proc/<pid>/root{path}` (`src/discovery/scan.rs:687`), verify the opened
   file's (dev, inode) against the maps-line key for BOTH hinted and unhinted
   paths (today `hint_gate` at `scan.rs:864-882` compares only size, only for
   `--module` hints). Closes the rename/copy/swap misattribution class.
4. **Capability tier ladder** (PRD §4; standing owner requirement): implement
   the current-product T0–T4 availability ladder defined by the W3 execution
   plan Task 6. The earlier leased/hardened T3/T4 proposal in
   `docs/notes/2026-08-15-architecture-and-gap-analysis.md` §4.2/§4.4 is
   superseded: commit `3a3ec2808e14c77f78e2021723c1c9c75979f02d`
   deliberately removed those lanes and W3 does not restore them. The wave
   creates the shipped table in `docs/usage.md` and the code model in
   `src/doctor.rs` (`CAP_BITS` currently at :37-43).
   Add `CAP_DAC_READ_SEARCH` to `CAP_BITS` (checklist 4 / item #8 — aya
   tracefs mount check). **`CAP_SYS_RESOURCE`:** it appears NOWHERE in the
   code and no `RLIMIT_MEMLOCK` bump exists — the "drop" is (a) confirm +
   document that no such requirement exists (memcg accounting since 5.11
   makes it moot at the 5.15 floor), and (b) version — never mutate — the
   frozen evidence constant `FROZEN_CAPS` in
   `scripts/check-live-discovery-evidence.py:196`, which does list it
   (mutating it invalidates existing live-discovery evidence). The tier
   probe loads the REAL program with REAL map sizes and attaches
   (checklist 5); `doctor` probes procfs mount options, Yama `ptrace_scope`,
   non-dumpable targets and reports the highest proven availability tier plus
   any unassessed target/scope predicate (item #15); tiered degradation replaces
   all-or-nothing failure (standing owner requirement, requirements spec §3).
5. **Diagnostics and verdict honesty:** distinguish seccomp-EPERM from
   capability-EPERM (checklist 7); log aya's `VerifierLog` on load failure
   (checklist 8 — aya reports verifier rejections as bare `EACCES`); prove
   the loss-counter → consumer-verdict binding with a test (checklist 9 —
   PRD §6 requires it as evidence, not assumption).
6. **Deferred `uprobe_multi` (owner decision 2026-09-03):** multi-attach is a
   performance optimization, not a W3 correctness or product-qualification
   requirement. Keep Aya `=0.14.0` and the Linux 5.15 per-offset path. Reopen
   multi-attach as a standalone post-W3 task only after a stable Aya release
   exposes the required multi load/attach/link and process-scoped PID-filter
   support. W3 does not pin an upstream PR, add a raw syscall, or claim
   `uprobe-multi` evidence.
**Owner-gated:** any privileged e2e verification lanes (unprivileged rows
run; privileged rows recorded UNRUN unless approved); all allowlist/schema
revision wording for selection-evidence fields.

**Known facts for the planner:** aya pinned `=0.14.0` (`Cargo.toml:24`),
build `--locked` (item #16 posture); anchor lines above were verified
2026-09-01 at `fb3dffc` (and the :1704,:1707 correction re-checked) but MUST
be re-verified after W1 merges (W1 touches `scan.rs`).

**Exit evidence:** each item closed with a test failing without the fix; the
selection matrix separately records live request/result/failure rows and
finite offline queries under the exact-generation/attested-identity authority
rule, with unmatched enumeration explicit/PARTIAL; one
   tier-degradation matrix row per current ladder tier in W3 Task 6 / PRD §4
(unprivileged rows run; privileged rows UNRUN unless owner-approved); the
checklist-9 verdict-binding test named in the wave report.

---

## W4 — Hosted CI {#w4}

**Objective:** the four canonical gates + the unprivileged suite + the
container-less e2e lanes run hosted, and the "the canary/privileged suite is
green locally, not in CI" caveat (ROADMAP "canary suite" bullet) is restated
honestly rather than left overbroad. The privileged lanes stay local by
design, so "the full suite runs hosted" was never the achievable objective.

**Scope:** a hosted pipeline running the four canonical gates + the
unprivileged test suite + the container-less e2e lanes on x86-64; run logs
retained (`upload-artifact` plus an archived copy in `p11scope-ws`) — junit
only if a producer is adopted, since stable `cargo test` emits none; no
default-branch badge (origin/main lags, so a `main` badge would be
untruthful) — status is reported per branch/commit in the wave report.
Privileged/root lanes stay local-with-owner-approval — CI records them UNRUN,
visibly, **in the log and summary, not via exit status**: `verify-capability-tier.sh`
prints `UNRUN:` and exits 0, so a green step does not prove a lane ran. Pin
toolchain 1.88 and the lockfile; cache honestly (no cache-poisoned green) —
the pipeline currently has no cache at all, so "honest" is today trivially
true and must stay so if a cache is added.

**Release-blocking defect found during W4 pass-1 (2026-09-05) — fix in this
wave, TDD:** the frozen BPF map inventory in `scripts/check-bpf-map-defs.py`
is **stale**. W3 commit `02eedbd` changed `CONFIG` from
`Array::with_max_entries(1, …)` to `(2, …)` (a second entry for the
parent/child tracepoint offsets) without updating the freeze, which still
pins `"CONFIG": (2, 4, 8, 1, 128)` — `max_entries` 1. Reproduced against a
real built object: `--policy-inventory` exits `default map inventory
differs`. A full field-by-field diff of the object against the freeze shows
**exactly one** drift, `CONFIG.max_entries 1 → 2`, with no map added or
removed — so this is a stale count, **not** a capture-surface or privacy
regression, and the freeze's actual security purpose (no unexpected map can
appear) is intact.

It is release-blocking because `--policy-inventory` is invoked by
`scripts/verify-canaries.sh` (the G3 privacy canary lane),
`scripts/verify-induced-gaps.sh` (full), and `scripts/build-release.sh` (the
W8 Lane 14 receipt) — all three fail the moment they run. It survived because
CI and the four cargo gates run only `--self-test`, which validates the
script against its own constant and is therefore self-consistent and blind to
this class of drift.

Root cause, and the real W4 deliverable: the freeze can drift from the code
with no gate noticing. Fixing the constant alone leaves the hole open —
**put an inventory comparison against a built object into the hosted
pipeline** (ci.yml already installs bpf-linker and the pinned nightly, so
this is affordable) so the next such drift fails immediately rather than at
release assembly.

**Owner-gated:** choice of CI host if it implies accounts/spend; ANY push to
the remote (including a CI-enablement push).

**Known constraint for the planner (re-verified 2026-09-05; the 2026-09-01
text below it was stale on every number):** `origin/main` = **`a2a2644`**
("docs: close wave 2 storage consolidation"), pushed from this clone on
2026-09-02 15:04 +0300 — **not** `367cadd`, and **not** 239 commits behind.
It is a strict fast-forwardable ancestor **74** commits behind local `main`
`a50f841`. W1 and W2 are therefore **already public**. The "not ready" wip
checkpoint `6fa7fb3` is still public but now sits ~293 commits deep in
history, not one below the tip. `origin/main` here is a local
remote-tracking copy, unfetched since 2026-08-21 — re-verify before acting.
Critically, `.github/workflows/ci.yml` is **already on origin/main**,
byte-identical to local, and **has already run hosted successfully** (run
`31935749796`, 2026-08-16, `checks-and-e2e` success). So this wave is not
building a pipeline from nothing; it is widening an existing, proven one.

**Owner decision (2026-09-05) — supersedes the "wave STARTS by surfacing that
decision" instruction, which is now discharged:** CI is enabled by pushing a
**CI test branch only** (e.g. `ci/w4-hosted`); `origin/main` stays at
`a2a2644` until W8's publication runbook reconciles it. A completed hosted run
on that branch is the hosted-run evidence; `act`/local dry-run is optional and
strictly weaker (act cannot run this pipeline faithfully — `rustup toolchain
install` needs network and root BPF attach needs a privileged container on the
host kernel), so it is not the evidence path. The **UNMET** rule now applies
only if no hosted run of the current pipeline completes. Never treat a dormant
pipeline as satisfying the requirements spec §6 bullet.

Note for the report's honesty section: because the branch push publishes the
same content on a visible non-default branch, "stale main" hides W3+ from the
default view only — it is not a privacy control, and W1/W2 are public already.

**Exit evidence:** pipeline definition merged; a complete hosted run with its
run URL/ID, `success` conclusion, the run's commit SHA **and tree hash matching
local `main`'s W4-closing tip**, the log archived in `p11scope-ws`, and the
verbatim UNRUN lane list. Absent that, the explicit UNMET record.

---

## W5 — Container/Kubernetes requalification {#w5}

**Objective:** the existing Docker/kind/Knative evidence predates the final
candidate; requalify on the release tip and ship the runtime-security
artifacts.

**Scope:** rerun the container, kind, and Knative qualification lanes against
the W4-exit tip (provisional — see the staleness rule above; W8 re-runs on
the final tip); qualify against runtime seccomp/LSM defaults, not just "a
container" (old Docker profiles block `openat2` and `bpf()` — item #9;
W1 Task 4's fallback must be exercised here); ship a localhost seccomp
profile adding `bpf` + `perf_event_open` to RuntimeDefault instead of
recommending Unconfined (checklist 7); ship/document the SELinux policy
module with `capability2 { bpf perfmon }` version-gated, tested Enforcing
(checklist 6, RHBZ 2046362); document the caps table per runtime; PID-ns
attribution verified or refused (item #14) for the in-container lanes.

**Owner-gated:** every privileged/container run (CLAUDE.md).

**Exit evidence:** fresh pass/fail rows for each runtime lane on the W4-exit
tip; the seccomp profile + SELinux module as tracked artifacts with their
verification lanes; a qualification report (this report, not images, is the
shipped K8s artifact — PRD §2).

---

## W6 — Multi-distro / multi-kernel matrix {#w6}

**Objective:** restate support honestly as "5.15.x, tested on ⟨list⟩" with
evidence behind every list entry.

**Scope:** re-run Jammy 5.15, Noble 6.8, and Fedora 44 6.19 on the current
tip — their existing evidence is from older candidates and MUST NOT be
inherited (spec §6) — then extend: planner selects the additions (candidates:
Debian stable, RHEL/Alma 9, an Arch or Tumbleweed rolling kernel, one 5.15.x
point release distinct from Jammy's — verifier behaviour is not monotonic,
item #11); add the load-only kernel matrix to CI (checklist 8): boot kernel,
load+attach the real program, real map sizes, assert verifier acceptance —
cheap enough to run per-kernel where full e2e is not; run the proxy-stack
lane (`scripts/matrix/verify-proxy-stack.sh` — a PRD §9.5 acceptance
criterion whose first qualification this wave owns; W8 re-runs it on the
final tip) as a matrix row; record every cell
pass/fail/UNRUN; update README/usage support statement to the tested list
(PRD §7).

For attachment evidence, record the actual per-offset mechanism for every
kernel. The supported-rate oracle compares the generator's completed calls,
STATS entered/returned, and raw consumed `CALL` records. Multi-attach is not a
W6 prerequisite unless its separately planned task has already landed from a
stable Aya release.

**Owner-gated:** VM-based lanes (uses `p11scope-ws/vm-bases` after W2).

**Exit evidence:** the matrix table (three re-run legacy rows + additions +
the proxy-stack row) with a run artifact per non-UNRUN cell; the support
statement updated in the same commit as the evidence.

---

## W7 — ia32 targets on x86-64 {#w7}

**Objective:** observe a 32-bit target process on an x86-64 host (PRD §7
minimum; item #2 / checklist 10).

**Scope (re-verified 2026-09-05 — the original wording understated the
problem and overstated the machinery):** make the **target ABI**, not merely
"pointer stride", a parameter of the uprobe path. Three things change on
ia32, not one: (i) **argument fetch** — an ia32 cdecl callee takes arguments
at `esp+4+4i`, not in `rdi..r9`, so `arg_u64` and the `ctx.arg::<u64>(n)`
call sites are the largest break and are not `probe_read` sites at all;
(ii) **width** — pointers *and* `CK_ULONG` are 4 bytes (`gcc -m32`:
`sizeof(unsigned long)==4`), so there is no class of "ABI-independent
`CK_ULONG`/handle/length" reads that stays 8-byte; (iii) **struct offsets** —
`CK_FUNCTION_LIST`, `CK_INTERFACE`, `CK_MECHANISM`, `CK_ATTRIBUTE`,
`CK_GCM_PARAMS`, `CK_RSA_PKCS_PSS_PARAMS`, and `r_debug` all shrink. The
plan carries the authoritative per-site list split into MUST-parameterize
and MUST-NOT-touch (`CK_VERSION` `[u8;2]`, `CK_BBOOL`, `probe_read_user_str`
byte reads, `ctx.ret()`, the tracepoints, and the `pid_tgid`/cookie keying
all stay).

Determine ABI from the **pinned object's ELF class at plan/attach time**
(`crates/manifest/src/elf.rs::parse` already computes `is_64()` — and today
*refuses* anything else) and carry it in the **attach cookie**; the static
cookie is `slot | descriptor<<32` with descriptor < 105, so bits 39-63 are
free. **No per-TGID map, no exec-time cache, no kernel-struct read** — the
charter's original "cache per-TGID" is unbuildable as written (`PID_FILTER`
is `RDONLY_PROG` and its value is an exactly-read-back generation token) and
unnecessary, since the dynamic loader refuses mixed-class objects, making ABI
a property of the attached object. Avoiding a `task_struct` read also keeps
BTF independence. `in_ia32_syscall()` remains correctly ruled out
(checklist 10) and is moot — no BPF helper exposes it.

**Delete from scope:** "parse maps addresses width-agnostically" — already
true (`crates/manifest/src/maps.rs` uses `u64::from_str_radix`, verified
against a real 32-bit process's `/proc/<pid>/maps`). Replace with a test row
feeding a 32-bit maps snapshot through `parse_maps`.

**W7 is NOT a BPF-only wave.** `elf.rs::parse` refuses non-64-bit objects and
the `/proc/<pid>/mem` scan hard-codes `WORD=8` / `INTERFACE_BYTES=24`, so
live discovery is in scope too. The 64-bit `p11scope-discover` helper cannot
`dlopen` an ELFCLASS32 provider and stays refused-with-reason unless an i686
build is owner-approved.

Honest refusal reuses the existing `Skipped { subject, reason }` →
`modules_skipped` → `PARTIAL` path (a 32-bit module already lands there).
Fix the one silent-wrong spot: `src/run.rs` refuses a 32-bit ELF launch as
*"must be an ELF executable"* rather than as *32-bit*.

**Owner decision needed — "observe" is undefined and the deferral wording is
self-contradictory:** feature-slices calls the deferred item "32-bit counting
mode (full ia32 capture …)", but in this codebase counting/aggregate is the
*least* demanding mode (`p11_entry_impl` returns before any user read) while
full capture is the most. **Default adopted for planning, pullable by the
owner:** observe = metrics/aggregate + allowlisted profile scalars
(session/slot/flags/mechanism/rv); `unsafe-unvalidated-metadata` templates
and params, and the ia32 loader hook, are refused-with-reason and force
`PARTIAL`. Correct the feature-slices wording in the same commit.

**Owner-gated:** the privileged 32-bit e2e lane (uprobe attach needs root —
CLAUDE.md; unprivileged development rows run, the privileged lane is UNRUN
until approved).

**Exit evidence:** an e2e lane with a 32-bit SoftHSM (or fixture) target on
x86-64, capture verified against the oracle; documented scope statement.

---

## W8 — Release assembly {#w8}

**Objective:** the ready-to-publish bundle; everything in PRD §9 checked.

**Scope:** **final-tip requalification set** (the release evidence — W5/W6
rows were provisional per the staleness rule): container lanes, the
proxy-stack lane, the three legacy distro rows, the 32-bit lane, all on the
frozen release tip; complete Lane 14 receipt on that tip (input-trust +
literal capture binding from W1 T7/T8 now enforced); README/usage truth pass
— every claim matched to measured reality or removed (spec §6); CHANGELOG
finalized; refreshed portable bundle + evidence archive into `p11scope-ws`
with adjacent checksum; final program-wide review-to-zero (fresh agents, full
diff since W1's base); the PRD §9 acceptance table filled in with evidence
pointers, one row per criterion (including the W4 hosted-CI row — UNMET
blocks closure absent an owner DoD amendment); tag-ready bundle staged
locally.

**Owner-gated:** the privileged + container Lane 14 receipt run
(`build-release.sh` hard-requires `sudo -n` and docker — CLAUDE.md) and every
requalification lane; and publication itself (push, tag, GitHub release) —
the wave ENDS at "staged and verified"; the last artifact is a one-page
publication runbook for the owner, which MUST address reconciling the stale
public remote (re-verified 2026-09-05: its tip is `a2a2644`, the W2 closure
pushed 2026-09-02 — **not** `367cadd` — leaving it 74+ commits behind local
main; the "not ready" wip checkpoint `6fa7fb3` is already public but now sits
deep in history, not one below the tip; and W3+ content is additionally public
on the `ci/w4-hosted` branch after W4).

**Exit evidence:** the filled acceptance table; the staged bundle's checksums;
zero accepted findings in the final cycle.

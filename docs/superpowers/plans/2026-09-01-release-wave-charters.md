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

**Objective:** close the two remaining Tier-1 research findings and ship the
capability-tier model — after this wave the *product logic* is release-final.

**Scope:**
1. **Tracepoint offsets (checklist 1 / item #1):** stop hardcoding field
   offsets — the literal `24`/`44` reads for `sched_process_fork` are at
   `crates/ebpf/src/main.rs:1704,1707` (the research note and spec §5 cite
   :1703,:1706 — off by one, the comment line; corrected here 2026-09-01).
   Parse `/sys/kernel/tracing/events/sched/*/format` at load, pass offsets
   via a config map, hard-assert on mismatch (the bcc precedent failed
   *silently with wrong data* — an error is the required behavior). Preserve
   BTF-independence (item #12): no CO-RE dependency may enter.
2. **Opened-file identity (checklist 2 / item #3):** after opening
   `/proc/<pid>/root{path}` (`src/discovery/scan.rs:687`), verify the opened
   file's (dev, inode) against the maps-line key for BOTH hinted and unhinted
   paths (today `hint_gate` at `scan.rs:864-882` compares only size, only for
   `--module` hints). Closes the rename/copy/swap misattribution class.
3. **Capability tier ladder** (PRD §4; standing owner requirement): implement
   the ladder from `docs/notes/2026-08-15-architecture-and-gap-analysis.md`
   §4.2/§4.4 (the only place the ladder exists — there is NO "tier table"
   artifact in the tree yet; the wave creates the shipped one in
   `docs/usage.md` and the code model in `src/doctor.rs` `CAP_BITS` :37-43).
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
   non-dumpable targets and reports a degraded tier (item #15); tiered
   degradation replaces all-or-nothing failure (standing owner requirement,
   requirements spec §3).
4. **Diagnostics and verdict honesty:** distinguish seccomp-EPERM from
   capability-EPERM (checklist 7); log aya's `VerifierLog` on load failure
   (checklist 8 — aya reports verifier rejections as bare `EACCES`); prove
   the loss-counter → consumer-verdict binding with a test (checklist 9 —
   PRD §6 requires it as evidence, not assumption).
5. **`uprobe_multi` attach (owner decision 2026-09-01 — release scope):**
   attach all offsets of an object via `uprobe_multi` where the running
   kernel supports it (link type landed in 6.6), keeping the existing
   per-offset attach as the mandatory fallback at the 5.15 floor. Runtime
   feature detection, never a compile-time split; the attach mechanism in use
   is recorded in the evidence output; both paths covered by the e2e oracle
   lane. **Planner must verify first:** aya 0.14.0's uprobe_multi support
   surface (API or raw link syscall needed) and interaction with the
   PidPin/attach-before-run flow — do not assume the crate exposes it.
   **Fallback decision rule:** if aya 0.14.0 lacks the surface, implement via
   the raw bpf-link syscall behind the pinned aya (no aya version bump
   without an owner decision); if that proves disproportionate, stop and
   present the options to the owner rather than silently dropping the item.

**Owner-gated:** any privileged e2e verification lanes (unprivileged rows
run; privileged rows recorded UNRUN unless approved).

**Known facts for the planner:** aya pinned `=0.14.0` (`Cargo.toml:24`),
build `--locked` (item #16 posture); anchor lines above were verified
2026-09-01 at `fb3dffc` (and the :1704,:1707 correction re-checked) but MUST
be re-verified after W1 merges (W1 touches `scan.rs`).

**Exit evidence:** each item closed with a test failing without the fix; one
tier-degradation matrix row per ladder tier of gap-analysis §4.4
(unprivileged rows run; privileged rows UNRUN unless owner-approved); the
checklist-9 verdict-binding test named in the wave report.

---

## W4 — Hosted CI {#w4}

**Objective:** the full suite runs hosted; the "green locally, not in CI"
caveat standing since Phase 3 G3 dies.

**Scope:** a hosted pipeline running the four canonical gates + the
unprivileged test suite + the container-less e2e lanes on x86-64; artifacts
(logs, junit) retained; badge/status truthful. Privileged/root lanes stay
local-with-owner-approval — CI records them UNRUN, visibly. Pin toolchain
1.88 and the lockfile; cache honestly (no cache-poisoned green).

**Owner-gated:** choice of CI host if it implies accounts/spend; ANY push to
the remote (including a CI-enablement push).

**Known constraint for the planner (corrected 2026-09-01):** the repo HAS a
remote with old history — `origin/main` = `367cadd` (`.codex`), a strict
fast-forwardable ancestor 234 commits behind local `main`, whose public tip
sits one commit above a "not ready" wip checkpoint. So hosted CI is
technically enableable on the existing remote, but bringing it current means
pushing 234 commits — an owner decision. **The wave STARTS by surfacing that
decision.** If the owner defers the push: deliver the complete pipeline
definition (`.github/workflows/` or equivalent) with `act`/local dry-run
evidence, and record — visibly, in the wave report and the W8 acceptance
table — that spec §6's "CI runs the suite hosted" bullet is **UNMET** until
the owner authorizes; W8 cannot close the acceptance table without either
the hosted run or an owner amendment of the DoD. Never treat the dormant
pipeline as satisfying spec §6.

**Exit evidence:** pipeline definition merged; a complete hosted run log —
or, under a deferred push, the dry-run log PLUS the explicit UNMET record.

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

**Owner-gated:** VM-based lanes (uses `p11scope-ws/vm-bases` after W2).

**Exit evidence:** the matrix table (three re-run legacy rows + additions +
the proxy-stack row) with a run artifact per non-UNRUN cell; the support
statement updated in the same commit as the evidence.

---

## W7 — ia32 targets on x86-64 {#w7}

**Objective:** observe a 32-bit target process on an x86-64 host (PRD §7
minimum; item #2 / checklist 10).

**Scope:** make userspace pointer stride a parameter — every
`bpf_probe_read_user(x as *const u64)` in the uprobe path assumes 8-byte
pointers today; determine target ABI from the ELF class at exec and cache
per-TGID (`in_ia32_syscall()` is invalid in uprobe context and always
returns false — checklist 10); parse maps addresses width-agnostically;
32-bit fixture provider (`gcc -m32`) through discovery, attach, and capture;
honest refusal (recorded outcome, not silence) for whatever 32-bit corner
stays unsupported. Full 32-bit *counting mode* is deferred by default
(feature-slices doc) — this wave is observe-a-target only.

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
public remote (its tip `367cadd` sits one commit above a "not ready" wip
checkpoint that is already public).

**Exit evidence:** the filled acceptance table; the staged bundle's checksums;
zero accepted findings in the final cycle.

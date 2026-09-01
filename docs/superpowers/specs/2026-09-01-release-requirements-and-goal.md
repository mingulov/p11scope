# p11scope — owner requirements and goal (release hardening)

**Date:** 2026-09-01
**Status:** Owner-stated requirements, captured verbatim in intent. This file is the
authority for *what the owner wants*; plans and designs argue from it.
**Owner:** Denis Mingulov
**Supersedes for scope/priority:** the "Next order" list in
`docs/superpowers/reports/2026-08-31-consolidation-status.md` (that list is now a
subset of §3 below).

## 1. Goal (owner's words)

> Do a real p11scope — with a release hardening, like adversarial scan-complexity
> fixes, hosted CI, refreshed Docker/Kubernetes qualification, remaining
> receipt/lifecycle issues, ensuring it is working in different Linux versions,
> different containers, different versions, different ABIs (like 32-bit version at
> least on x64). But briefly I want to ensure that basic version works fine — and
> issues are fixed etc, + everything is covered by local tests / test framework also.

**Priority order that follows from it:**

1. **The basic version works and its issues are fixed.** This comes first. Not new
   features, not breadth — correctness of what exists.
2. **Everything is covered by local tests / the test framework.** A fix without a
   test that fails without it is not done.
3. Then breadth: CI, containers, distros/kernels, ABIs.

"A real p11scope" means a tool that can be handed to someone else and used, not a
tree that passes its own gates.

## 2. How the work is to be done (owner's words)

> Use superpowers, but do decisions by yourself — so do separate reviews and gap
> analyses, fixes — until no issues remain. Use subagents with Opus and Sonnet where
> it is ok to ensure enough time can be spent for this project.

Operating rules that follow:

- **Decide autonomously.** Do not stop to ask which option to take. Ask only for
  destructive or genuinely irreversible actions (deleting evidence, rotating keys,
  pushing/publishing, privileged/container experiments per `CLAUDE.md`).
- **Iterate to zero.** Every wave ends with independent review + gap analysis by
  fresh agents, findings triaged and fixed, repeated until a full cycle finds
  nothing. One review pass is not the bar; a clean cycle is.
- **Spend the time.** Use Opus/Sonnet subagents liberally and in parallel for
  research, briefs, implementation, and review. Depth is preferred over speed.
- **Follow the superpowers skills** (brainstorming → writing-plans →
  subagent-driven-development / executing-plans → requesting/receiving-code-review →
  verification-before-completion).

## 3. Scope of release hardening

Named by the owner, in the order stated (all of it is in scope; §1 sets the priority):

| # | Item | Notes |
| --- | --- | --- |
| 3.1 | Adversarial scan-complexity fixes | Bounded computation, not just bounded bytes. Scan finding `csf_ce5962b`; research item #3 (the maps read itself is unbudgeted; distro default `vm.max_map_count` is now 1048576). |
| 3.2 | Hosted CI | A pipeline that actually runs the suite; the "green locally, not in CI" caveat standing since Phase 3 G3 must die. Load-only kernel matrix (research #8/#11). |
| 3.3 | Refreshed Docker/Kubernetes qualification | Existing container/kind/Knative evidence predates the final candidate; rerun against the release tip. |
| 3.4 | Remaining receipt/lifecycle issues | Findings `csf_014eb65`, `csf_19fb2f` (the Lane 14 receipt mis-binding is a *live* bug — every prior receipt bound the wrong capture). |
| 3.5 | Different Linux versions and kernels | Beyond Jammy 5.15 / Noble 6.8 / Fedora 44 6.19. Support must be restated as "5.15.x, tested on <list>" — verifier behaviour is not monotonic across point releases (research #11). |
| 3.6 | Different containers and versions | Runtimes and their seccomp/LSM defaults, not just "a container". Old Docker profiles block `openat2` and `bpf()` (research #9). |
| 3.7 | Different ABIs — 32-bit (ia32) targets on x86-64 | At minimum: observe a 32-bit target process on an x86-64 host. Every userspace pointer read currently assumes 8-byte stride (research #2/#10). |
| 3.8 | Local test coverage for all of the above | The test framework is the deliverable alongside the fix. |

Standing requirements carried in from earlier decisions (still binding):

- **Reduced capability / graceful tiers.** p11scope must be usable with the minimum
  capabilities and degrade honestly rather than all-or-nothing. Add
  `CAP_DAC_READ_SEARCH` to the model (aya needs it for the tracefs mount check) and
  drop `CAP_SYS_RESOURCE` (memlock is memcg-accounted at the 5.15 floor).
- **Multi-module, including proxy stacks.**
- **Privacy allowlist is never broadened implicitly** (`docs/privacy/allowlist-v1.md`).
- **Honest evidence.** A lossy, degraded, or blind run must be distinguishable from a
  clean one at the consumer level; "no providers found" must never be the report for
  a non-dumpable, hidepid, or gone target.

## 4. Storage and repository layout (owner requirement, 2026-09-01)

> Now it is in multiple folders. Use `/home/user/src/m/p11scope-ws` and
> `/home/user/src/m/pkcs11-scope` — only. Do not use all other subfolders, too many
> of them — and `.local` will definitely be lost on the movement to another PC, for
> example. So use `p11scope-ws` for some non-public data etc if needed (I initialized
> git there), and `/home/user/src/m/pkcs11-scope` as public project etc. So 'ws' —
> workspace.

**Binding rules:**

1. **Exactly two directories.** `/home/user/src/m/pkcs11-scope` = the public project
   (git, published). `/home/user/src/m/p11scope-ws` = the workspace for everything
   non-public (git-initialized by the owner; had no commits as of 2026-09-01).
2. **Nothing durable may live anywhere else.** In particular
   `/home/user/.local/state/p11scope/` is **not** durable — it will be lost when the
   work moves to another machine. Every artifact still referenced by the project must
   be migrated into `p11scope-ws` and re-pointed. Same for
   `/home/user/p11scope-vm-bases/` and any `/tmp` roots.
3. **The migration is itself a work item** (see §6): evidence roots, portable
   packages, security-scan findings, VM base images, and every absolute path in
   tracked files and scripts that names one of the old locations.
4. Non-public material (raw captures, VM artifacts, campaign evidence, anything
   carrying PIDs/addresses barred from tracked files) belongs in `p11scope-ws`, not
   in the public repo.
5. The `pkcs11-scope-evidence` symlink and the `p11scope-ws/source` symlink are
   compatibility shims; keep them working or remove them deliberately along with the
   tracked references that use them (e.g. `spike/slice1b2-loader/run-lanes.sh`).

## 5. What is already known to be wrong (do not re-derive)

Eight open findings from static security scan `3e10be9`, with a full implementation
plan at `docs/superpowers/plans/2026-09-01-release-hardening-wave1-findings.md`:

| Finding | Severity | Site |
| --- | --- | --- |
| `csf_f5953ae` helper keeps inherited fds/env before `dlopen` | MEDIUM | `crates/discover/src/main.rs:134` |
| `csf_6f180d5` cgroup pathname reopened after publish | MEDIUM | `src/attach.rs:277` |
| `csf_ce5962b` scan budgets bytes, not computation | MEDIUM | `src/discovery/scan.rs:308` |
| `csf_ad79ebb` trace output has no cumulative bound | MEDIUM | `src/cli.rs:168` |
| `csf_c94c662` output ancestry trusts writable parents | MEDIUM | `src/output.rs:50` |
| `csf_014eb65` release receipt misses untracked inputs / PATH tools | MEDIUM | `scripts/build-release.sh:202` |
| `csf_b8067e3` raw terminal control bytes in headings | LOW | `crates/manifest/src/maps.rs:111` |
| `csf_19fb2f` Lane 14 receipt binds the wrong capture | LOW (live bug) | `scripts/build-release.sh:231` |

Two of these are worse than the scan said: the Lane 14 receipt has **never** bound
the release's own capture (`find | sort | head -1` always picks the attach-e2e
capture), and `-o` output is **hard-broken** under seccomp profiles that block
`openat2` (no `ENOSYS`/`EPERM` fallback) — a functional bug, not only a security one.

Additionally, comparable-tool research (`docs/notes/2026-09-01-ebpf-comparable-tool-pitfalls.md`)
identifies three high-confidence issues not in the scan:

1. **Hardcoded tracepoint field offsets** (`crates/ebpf/src/main.rs:1703,1706`) — a
   sibling `sched:` tracepoint already changed layout inside the supported range;
   the bcc precedent failed *silently with wrong data*.
2. **The opened file is never verified to be the mapped file** — only size, and only
   for `--module` hints; the unhinted path never compares the opened inode against
   the maps-derived key.
3. **The maps read is outside the work budget** — see §3.1.

## 6. Definition of done

The owner considers this finished when:

- Every finding in §5 is closed with a test that fails without the fix.
- A full independent review + gap-analysis cycle returns zero accepted findings.
- All four canonical gates are green (`CLAUDE.md` §Checks) on `main`.
- CI runs the suite hosted, not only locally.
- Container/Kubernetes qualification is rerun on the release tip.
- Multi-distro/kernel and 32-bit-target results are recorded honestly (pass, fail, or
  UNRUN — never inherited).
- All durable state lives in the two directories of §4, with no path referencing
  `~/.local/state`, `~/p11scope-vm-bases`, or `/tmp` roots.
- The claims in `README.md`/`docs/usage.md` match measured reality.

Publication (push, tag, release) remains an explicit owner decision and is not
implied by the above.

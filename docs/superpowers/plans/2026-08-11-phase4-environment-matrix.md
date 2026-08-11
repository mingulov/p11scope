# Phase 4 — Environment matrix + `pkcs11-check` oracle — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the observer works where PKCS#11 workloads actually run — host, container, containers sharing an image layer, Kubernetes pod, and a Knative service through a scale-from-zero cycle — and validate its output against an independent oracle rather than against itself.

**Architecture:** No new product features. Each task is a verification script under `scripts/` plus recorded evidence under `docs/notes/`. Where the observer needs a fix to work in an environment, that fix is the task's real deliverable and the script is its proof.

## Global Constraints

- **Every environment result is measured, never assumed.** "It should work because Phase 0 proved the mechanism" is not evidence; a green script run is.
- **Privileges are measured per environment**, not copied from documentation: for each, record what actually failed without a capability and what the minimum working set was.
- The oracle diff direction is **oracle ⊆ capture**: every call `pkcs11-check` logged must appear in the capture; the capture may legitimately hold more (bootstrap calls, other processes). A capture missing a logged call is a failure.
- Two documented `pkcs11-check` caveats shape the diff and must be handled explicitly, not tolerated silently: its `--rv-trace` resets per test *after* fixture bootstrap and `C_Login`, so bootstrap-phase calls appear in the capture but not the oracle; and `--isolation file` spawns many subprocesses (many `C_Initialize` cycles and PIDs), which argues for cgroup scope rather than `--pid`.
- `set -eu` as an explicit line in every script body — a shebang's flags are inert under `sh script`.
- An environment that genuinely cannot run here is recorded as **BLOCKED with the reason and what was tried**, never quietly dropped or reported as passing. Partial matrix coverage honestly reported beats a fabricated green row.
- Captures in the matrix must reach `completeness: COMPLETE`, or the loss counters must be documented and explained for that row.
- Do not weaken `verify-attach-e2e.sh`, `verify-induced-gaps.sh`, or `verify-canaries.sh`. All three keep passing.
- Commit style: short prefix + imperative.

## Inherited facts (verified)

- Phase 3 HEAD `2d47f11`; 89 tests green; all three verification scripts pass.
- Phase 0 proved cross-mount-namespace capture works via `/proc/<pid>/root` (requires root) and that two containers sharing an overlay2 image layer share the provider inode, so one attach observes both.
- `p11scope profile --manifest M --pid N | --cgroup PATH --mode metrics|profile --duration S -o OUT`. `p11scope discover --module PATH [--helper P]` execs the unprivileged helper. Manifest reuse is refused on identity mismatch (no `--force`).
- **Known gap this phase must address**: cgroup scope currently matches only the *exact* cgroup id, not descendants (`bpf_get_current_cgroup_id()` returns the leaf). Kubernetes and Knative put workload processes in nested cgroups, and `pkcs11-check --isolation file` forks subprocesses. Descendant matching (`bpf_get_current_ancestor_cgroup_id`, kernel ≥5.15) is Task 1 and everything else depends on it.
- `cgroup_id` is already captured on every event but has no consumer — Task 6 gives it one (per-container breakdown).
- Tooling present: `kind` (`/home/user/go/bin/kind`), `kubectl` (`/snap/bin/kubectl`), `docker`, `sudo -n`. No kind clusters exist yet.
- `pkcs11-check` is at `/home/user/src/m/pkcs11-check-ws/pkcs11-check` (Python, `pyproject.toml`, `src/pkcs11_check/`), with `rv_trace` config (`src/pkcs11_check/config.py:48-50`) and `docs/rv-trace-design.md`. Read its README/AGENTS.md before driving it.

---

### Task 1: Cgroup descendant matching

**Files:** `crates/ebpf/src/main.rs`, `src/scope.rs`, `src/main.rs` (USAGE), tests.

Today a `--cgroup` capture sees only processes in that exact cgroup. Every remaining task in this phase puts workloads in nested cgroups, so this is the prerequisite.

Use `bpf_get_current_ancestor_cgroup_id(level)` — available since 5.15, the project floor — or an equivalent ancestor walk, so a task in any descendant of the target cgroup matches. Userspace must supply whatever the chosen helper needs (typically the target's *level* in the hierarchy, derivable from its path depth under `/sys/fs/cgroup`).

Keep the exact-match behavior available and correct; descendant matching must not accidentally widen a capture to unrelated cgroups (that would be an over-capture, the opposite failure of the current under-capture).

Tests: unit-test the level derivation from a cgroup path; a live test that a process in a child cgroup is observed while a process in a sibling cgroup is not. Update the USAGE note that currently documents exact-match semantics.

Commit: `ebpf: match descendant cgroups for container-scoped capture`

---

### Task 2: Docker container capture

**Files:** `scripts/matrix/verify-docker.sh`, `docs/notes/phase4-matrix.md` (started here).

Run the deterministic workload (`spike/harness.c` pattern) inside a Docker container with SoftHSM2; discover and attach from the host.

Two things to get right: the provider path inside the container is not the host path, so discovery must run in the container's mount view (`p11scope discover --pid` is designed for this, or run the helper inside the container and copy the manifest out — pick one and say which); and the capture is scoped by the container's cgroup.

Assert exact call counts against the same oracle `spike/expected.txt` uses, and `completeness: COMPLETE`.

Record measured privileges: what fails as an unprivileged user, and the minimum that works.

Commit: `matrix: docker container capture verified`

---

### Task 3: Shared image layer (inode-sharing proof)

**Files:** `scripts/matrix/verify-shared-layer.sh`, matrix notes.

Start **two** containers from the same image, so their `libsofthsm2.so` is the same overlay2 inode. Attach **once**. Both containers' calls must be observed, and the report must attribute them separately — the events carry `cgroup_id`, so a per-container breakdown is possible (Task 6 renders it; here, assert the raw distinction is available).

Then verify the negative: with a cgroup scope naming only container A, container B's calls must NOT appear. That is what proves scoping actually scopes, rather than the capture simply seeing everything on the inode.

Commit: `matrix: shared-image-layer capture with per-container attribution`

---

### Task 4: Kubernetes pod capture (kind)

**Files:** `scripts/matrix/verify-kind-pod.sh`, matrix notes, any manifest YAML under `scripts/matrix/`.

Create a kind cluster, run the workload as a pod, capture from the node (kind runs the node as a container, so the observer runs inside that node container or on the host targeting the node's namespaces — pick one, document which and why).

Assert exact counts and COMPLETE. Record what the pod's cgroup path looks like (`kubepods.slice/...`) since that is what an operator will actually pass to `--cgroup`, and record the measured privileges.

Tear the cluster down at the end, but leave it up on failure so the state can be inspected.

Commit: `matrix: kubernetes pod capture verified on kind`

---

### Task 5: Knative service with scale-from-zero

**Files:** `scripts/matrix/verify-knative.sh`, matrix notes.

Install Knative Serving on kind, deploy the workload as a service, scale to zero, then drive a request that forces a cold start — and capture the PKCS#11 calls of the newly created pod.

This is the hardest row and the most valuable: it proves the observer can attach to a workload that **did not exist when the capture started**. If attach-on-new-pod requires anything the tool cannot currently do, that limitation is the finding — document it precisely rather than working around it with a pre-warmed pod, which would prove nothing.

If Knative cannot be installed in this environment, record BLOCKED with the exact failure and what was attempted.

Commit: `matrix: knative scale-from-zero capture verified`

---

### Task 6: Per-container attribution in the profile

**Files:** `src/semantics.rs`, `src/render.rs`, `docs/schema/observed-profile-v1.md`.

`cgroup_id` is captured on every event and currently consumed by nothing (flagged in the Phase 3 allowlist doc as a dead capture — either justify it or drop it; this task justifies it).

Add a per-cgroup breakdown to the profile: calls, errors, and mechanisms per `cgroup_id`, so one node-wide attach over a shared inode can be split per container/pod. Include the raw `cgroup_id` (it is an inode number, not sensitive — say so in the allowlist doc) and, where the capture can resolve it, a human label.

Update the allowlist justification for `cgroup_id` from "captured, no consumer" to its real justification.

Tests: two synthetic cgroup ids produce two separate breakdown entries with correct counts.

Commit: `scope: per-cgroup breakdown in the observed profile`

---

### Task 7: `pkcs11-check` oracle diff

**Files:** `scripts/matrix/verify-oracle.sh`, `docs/notes/phase4-oracle.md`.

Run `pkcs11-check` against SoftHSM2 with p11scope attached, then assert **oracle ⊆ capture**.

Read `pkcs11-check`'s README/AGENTS.md and `docs/rv-trace-design.md` first to learn how to enable `--rv-trace` and where `report.jsonl` lands. Handle both documented caveats explicitly:
- rv-trace resets per test after bootstrap + login → bootstrap calls are in the capture but not the oracle. Since the direction is oracle ⊆ capture, this is *tolerable by construction* — state that reasoning in the script rather than filtering blindly.
- `--isolation file` spawns subprocesses → use cgroup scope (Task 1's descendant matching) so all of them are captured, and say so.

The assertion: for every `(function, CK_RV)` the oracle logged, the capture contains at least that many. Report any oracle-only call as a failure with its name and counts. Also report capture-only calls as informational (expected: bootstrap).

Commit: `matrix: pkcs11-check oracle diff (oracle subset of capture)`

---

### Task 8: Fork-scoping and privilege matrix

**Files:** `scripts/matrix/verify-fork-scope.sh`, `docs/notes/phase4-privileges.md`.

Two Gate G4 criteria neither of which is covered above:

1. **Fork scoping**: a workload that forks *before* doing PKCS#11 work (a prefork server shape) must be fully captured under cgroup scope, including children that did not exist at attach time. Assert counts across parent and children sum to the expected total.
2. **Privileges, measured**: for each matrix environment, determine empirically the minimum privilege that works — try unprivileged, then specific capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`), and record what each failure looked like. Do not copy claims from documentation; run it and record the actual error.

Commit: `matrix: fork scoping and measured privilege requirements`

---

### Task 9: Matrix table + Gate G4 bookkeeping

**Files:** `docs/notes/phase4-matrix.md` (final table), `docs/superpowers/plans/ROADMAP.md`.

Assemble the full matrix table — one row per environment, each with: result, completeness verdict, measured privileges, and a link to the script that proves it. BLOCKED rows state why.

Map each Gate G4 criterion to evidence: matrix green with COMPLETE (or documented loss); oracle ⊆ capture with zero missed logged calls; fork-scoping verified; privileges documented per environment as measured. Anything not achieved is stated as outstanding.

Commit: `plan: record phase 4 status against gate G4 criteria`

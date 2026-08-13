# Phase 4 Task 8 — fork scoping and measured privileges

> Historical measurement note: these results predate the 2026-08-13
> same-inode hardening. Current authorization requires file ownership or
> `CAP_LEASE` in addition to the BPF/procfs capabilities measured here. The
> script is updated, but that privileged rerun is still pending approval.

## Part 1: fork scoping

`scripts/matrix/fork-harness.c` is a prefork-server-shape workload: it
`dlopen`s the module, then `fork()`s **4 children before anyone — parent
or child — makes a single PKCS#11 call**. Each child does a fixed, known
sequence (`C_Initialize`, `C_GetSlotList`, `C_OpenSession`, 5×
`C_DigestInit`+`C_Digest`, `C_CloseSession`, `C_Finalize`); the parent
does its own fixed sequence (`C_Initialize`, `C_GetInfo`, `C_Finalize`)
after forking. Ground truth: `scripts/matrix/fork-expected.txt`.

The observer attaches to a cgroup (`systemd-run --scope`, created before
the harness is even `exec`'d, gated behind the same go-file busy-loop
every other script in this matrix uses) **before the harness process, let
alone any of its children, exists**. Cgroup membership is inherited across
`fork()`, so every child — none of which existed at attach time — is
still a descendant of the attached cgroup (Task 1's descendant matching).

Measured, `scripts/matrix/verify-fork-scope.sh`:

```
ok C_CloseSession: 4
ok C_Digest: 20
ok C_DigestInit: 20
ok C_Finalize: 5
ok C_GetInfo: 1
ok C_GetSlotList: 4
ok C_Initialize: 5
ok C_OpenSession: 4
evidence: 136 probes, COMPLETE
```

Every count is an **exact** match against `fork-expected.txt` (not just
"at least") — summed across the parent and all 4 children. Reproduced on
a second, independent run with identical results.

A plain `mkdir`+`chown` of a fresh cgroup does **not** let an unprivileged
user migrate itself in — verified directly while building this script:
cgroup v2 process migration needs write access up the whole
common-ancestor chain, not just the leaf `cgroup.procs`; a bare `chown`
gets `EACCES`. `systemd-run --scope` (via `sudo`) sidesteps this because
it talks to the system manager, which already has the necessary access.

## Part 2: privileges, measured

The brief: try unprivileged first, then specific capabilities
(`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`) via
`capsh`/`setpriv`, and record the **actual** error text — not documentation
claims. All rows below are real command output from this host, captured
while building this task (host row is also asserted as numbers inside
`scripts/matrix/verify-fork-scope.sh`; docker/kind rows were measured
interactively, reusing Task 2/4's own container/pod so as not to duplicate
their cluster/container lifecycle a third time in a script — see "Why
docker/kind aren't re-automated" below).

This host: Ubuntu 24.04.4, kernel 7.0.0-28-generic,
`kernel.perf_event_paranoid = 4`, Yama `ptrace_scope = 1`.

### Host (`--pid`, same-uid target)

A bare `sleep 30 &` is a sufficient attach target: with `--pid`, p11scope
reads the plain host-path manifest directly (no `/proc/<pid>/root`
indirection — that only exists for container/pod targets), so the target
process doesn't even need the module mapped at attach time.

| Privilege | Result | Actual error text |
| --- | --- | --- |
| unprivileged | FAIL | `p11scope: starting attach session: loading BPF object: map error: failed to create map \`CONFIG\`: failed to create map \`CONFIG\`: Operation not permitted (os error 1)` |
| `CAP_BPF` + `CAP_PERFMON` (no `CAP_SYS_ADMIN`) | FAIL | map creation succeeds; every attach fails: `` attach failed (slot N): p11_entry at /usr/lib/softhsm/libsofthsm2.so+0x...: \`perf_event_open\` failed `` (×136, `attached_probes: 0`, `completeness: PARTIAL`) |
| `CAP_SYS_ADMIN` alone | **PASS** | `attached_probes: 136`, `completeness: COMPLETE` |
| full root | PASS | (already established in Tasks 2-5) |

**Measured minimum on host: `CAP_SYS_ADMIN` alone** — no need for
`CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_PTRACE` individually, and no need for
full root. `CAP_BPF`+`CAP_PERFMON` failing here is itself a finding: on
upstream kernels those two are documented as sufficient for BPF+uprobe
work without `CAP_SYS_ADMIN`. Not on this kernel — Ubuntu's
`kernel.perf_event_paranoid = 4` is a hardening level beyond the upstream
0-3 range that requires `CAP_SYS_ADMIN` specifically for
`perf_event_open()`, overriding the `CAP_PERFMON` bypass path. This is a
real, measured, host-specific fact, not something to generalize from
without re-checking `sysctl kernel.perf_event_paranoid` on another box.

### Docker / kind (`--cgroup`, cross-uid target: container/pod root ≠ invoking user)

Both rows go through the identical code path: the observer runs on the
host, targeting `/proc/<container-or-pod-host-pid>/root/...` (see
`verify-docker.sh`/`verify-kind-pod.sh`), and the container/pod's own
process runs as root (Docker's default, no userns-remap) — a **different**
uid than the invoking user, unlike the host row above.

Measured against a live `verify-docker.sh`-shaped container:

| Privilege | Result | Actual error text |
| --- | --- | --- |
| unprivileged | FAIL | `ls: cannot read symbolic link '/proc/<pid>/root': Permission denied` (confirmed directly with `ls`, independent of p11scope) |
| `CAP_SYS_PTRACE` alone (no `CAP_SYS_ADMIN`) | FAIL, but past the file check | `ls` with `CAP_SYS_PTRACE` alone **succeeds** reading `/proc/<pid>/root/...`; `p11scope profile` still fails at the BPF stage: `p11scope: starting attach session: loading BPF object: map error: failed to create map \`SLOT_KIND\`: failed to create map \`SLOT_KIND\`: Operation not permitted (os error 1)` |
| `CAP_SYS_ADMIN` alone (no `CAP_SYS_PTRACE`) | FAIL | `p11scope: /proc/<pid>/root/usr/lib/softhsm/libsofthsm2.so: cannot identify the file now (read failed: Permission denied (os error 13))` / `p11scope: manifest does not match the current files; refusing to attach` |
| `CAP_SYS_PTRACE` + `CAP_SYS_ADMIN` | **PASS** | `attached_probes: 136`, `completeness: COMPLETE` |
| full root (`sudo`) | PASS | (established in Tasks 2-5) |

**Measured minimum for docker: `CAP_SYS_PTRACE` + `CAP_SYS_ADMIN`** — two
capabilities, **not** full root. `CAP_SYS_PTRACE` is what's needed to
traverse `/proc/<pid>/root` of a different-uid process at all (procfs
gates this via `ptrace_may_access(PTRACE_MODE_READ_FSCREDS)`, independent
of the target file's own DAC permissions — confirmed directly: the same
`ls` with `CAP_DAC_READ_SEARCH` instead of `CAP_SYS_PTRACE` still gets
`Permission denied`, ruling out the more obvious-sounding "it's just a
file permission" explanation). `CAP_SYS_ADMIN` is the same BPF/uprobe
requirement as the host row.

Re-measured identically against a live kind pod
(`verify-kind-pod.sh`-shaped, kind v0.29.0 / Kubernetes v1.33.1): same
three failures with the same error text shapes (host pid substituted),
same two-capability minimum, same `attached_probes: 136` /
`completeness: COMPLETE` on success. Not assumed identical from the
docker row — independently spun up and independently measured.

### Why docker/kind aren't re-automated inside `verify-fork-scope.sh`

`verify-docker.sh` and `verify-kind-pod.sh` already own the
container/cluster lifecycle (build image, start container/pod, discover,
rewrite manifest, tear down) and already assert the coarse
unprivileged-vs-root privilege boundary. Re-building a second full
container/cluster lifecycle inside `verify-fork-scope.sh` purely to re-run
a `capsh` sweep would duplicate that infrastructure a third time in this
repo for no additional coverage — the finer-grained
capability-vs-full-root distinction measured above does not depend on
*which* container or cluster is running, only on the `/proc/<pid>/root`
+ BPF mechanics both scripts already exercise identically. The host row
(Part 2's first table) *is* automated with real numeric assertions inside
`verify-fork-scope.sh`, since it needs no extra infrastructure beyond
what that script already builds.

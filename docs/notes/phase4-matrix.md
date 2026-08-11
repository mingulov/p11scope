# Phase 4 environment matrix — results

Ground truth for every row: `spike/harness.c`, oracle `spike/expected.txt`
(the same 9-function-call oracle `verify-attach-e2e.sh` uses). Host:
Ubuntu 24.04.4, glibc 2.39, kernel 7.0.0-28-generic, Docker 29.7.2
(storage driver `overlay2`, cgroup driver `systemd`, cgroup2 unified
hierarchy).

| Environment | Script | Result | Completeness | Measured privileges |
| --- | --- | --- | --- | --- |
| Docker, single container | `scripts/matrix/verify-docker.sh` | PASS — exact counts, positive isolation via discover-in-container + `/proc/<pid>/root` prefix | COMPLETE (136/136 probes) | Unprivileged `p11scope profile`: exit 1, `... cannot identify the file now (read failed: Permission denied (os error 13))` reading `/proc/<pid>/root/...`, refuses to attach. `docker exec` discovery step needs no host root (works as the `docker` group member that ran it). Minimum working set: root (via `sudo`) for `p11scope profile`; no special privilege for `p11scope-discover` run inside the container. |
| Docker, shared image layer (2 containers, 1 attach) | `scripts/matrix/verify-shared-layer.sh` | PASS — one attach observes both containers (counts == 2x oracle); a cgroup scope naming only container A excludes container B's concurrent calls (counts == 1x oracle for each of A-only and B-only, never 2x) | COMPLETE on all three captures (136/136 probes each) | Same as the single-container row (same code path): unprivileged `p11scope profile` fails identically at the `/proc/<pid>/root` identity check before touching BPF. |
| Kubernetes pod (kind) | `scripts/matrix/verify-kind-pod.sh` | PASS — exact counts, observer runs on the host (see Row 3 below for why) | COMPLETE (136/136 probes) | Unprivileged `p11scope profile`: exit 1, identical `Permission denied (os error 13)` reading `/proc/<host-pid>/root/...` before BPF is touched. Minimum working set: root (via `sudo`) for `p11scope profile`; `kubectl exec` for discovery needs no host root. |

## Row 1: Docker container capture (Task 2)

Two problems, both solved explicitly in `verify-docker.sh`:

1. **Provider path inside the container is not the host path.**
   `p11scope-discover` has no `--pid` flag (checked
   `crates/discover/src/main.rs`: only `--module`/`-o`/`--help`) — the
   brief's "designed for this" reading doesn't match the current CLI. So
   this row runs the helper **inside** the container via `docker exec`
   (bind-mounted in from the host build — this host is Ubuntu 24.04/glibc
   2.39, the same as the `ubuntu:24.04` image, so the host-built dynamic
   binary runs unmodified, no cross-container build needed) and copies the
   resulting manifest out. The manifest's object paths come out
   container-relative (SoftHSM2 resolves through a symlink to
   `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`); the script then
   rewrites every object path with a `/proc/<container-pid>/root/` prefix
   before handing the manifest to `p11scope profile`. This one rewrite
   feeds two separate consumers that both read `manifest.objects[].path`
   directly with no namespace awareness of their own: `attach.rs`'s
   `prog.attach(point, &slot.object, ...)` (the actual uprobe target) and
   `verify.rs::check_reuse` (the identity re-check gate). Matches the
   Phase 0 spike's bpftrace path-prefix trick exactly (see
   `docs/superpowers/plans/2026-08-10-phase0-feasibility-spike.md`, Task
   4).
2. **Scope by the container's cgroup.** `--cgroup /sys/fs/cgroup$(sed
   's/^0:://' /proc/<pid>/cgroup)` — the container's own leaf cgroup, using
   Task 1's descendant matching so this is correct whether or not the
   workload runs in a nested sub-cgroup.

Exact call counts matched `spike/expected.txt` on every function;
`evidence.completeness == "COMPLETE"`, `attached_probes == 136` (68 slots
x2 uprobe+uretprobe).

## Row 2: Shared image layer / inode-sharing proof (Task 3)

`verify-shared-layer.sh` starts two containers (`p11scope-matrix-shared-a`,
`-b`) from the identical image, under one dedicated cgroup parent slice
(`--cgroup-parent=p11scope-shared.slice` on both — systemd auto-nests this
under `p11scope.slice`, giving a clean common ancestor with no unrelated
host services under it).

**Inode-sharing proof (measured, not assumed):** `docker exec <A> stat -c
%i /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so` and the same in B both
returned **51969427** — the identical inode number, confirming the overlay2
image layer is genuinely shared before the capture claims anything about
it. The script hard-fails with BLOCKED-style output (and prints the
storage driver) if the inodes ever differ.

**Positive:** discover once (in container A's mount view), attach **once**
with `--cgroup` set to the shared parent slice, run the harness in *both*
containers during that single attach window. Observed counts were exactly
double the oracle (e.g. `C_GenerateRandom: 200`, `C_Digest: 100`) —
one attach, both containers' calls captured, `completeness: COMPLETE`.

**Negative isolation (the important one):** two further captures, each a
fresh `p11scope profile` invocation scoped to only one container's leaf
cgroup (`A-only`, `B-only`), but with **both** containers' harnesses run
during each capture's window — so the excluded container's calls are real,
concurrent, and land on the very inode the probe is attached to. Both
scoped captures came back at exactly **1x** the oracle, never 2x:
scoping the capture to A while B was actively calling into the same
probed `.so` produced zero B calls in A's report, and symmetrically for B.
This is the proof that cgroup scoping filters by *task*, not by *inode* —
the earlier under-scoping bug this phase's Task 1 fixed (descendant
matching) is the mechanism that makes this exclusion correct rather than
accidental.

Per-container attribution via `cgroup_id` is not yet exposed through the
CLI/JSON output (that consumer is Task 6 — `cgroup_id` is already captured
on every event per the phase plan's inherited facts, just unconsumed). The
brief's own fallback — "two scoped runs" — is what this row uses to
demonstrate the raw distinction is recoverable: the A-only and B-only
captures above *are* that per-container breakdown, produced by cgroup
scope rather than by a not-yet-built event-level field.

## Row 3: Kubernetes pod capture on kind (Task 4)

**Observer placement decision: the observer runs on the HOST, not inside
the kind node container.** kind's "node" is itself a Docker container, but
a Docker container's own pid/mount/cgroup namespaces are still descendants
of the true host's namespaces — namespaces nest transitively through
whichever runtime created them, and the host sits at the root of that
chain for every process on the machine. This was measured directly while
building the script, not assumed: `docker exec <node> ps aux` shows a pod
process under one PID (numbered relative to the node container's own pid
namespace), while `sudo ps aux` run on the true host shows the *same*
process under a *different*, host-visible PID — e.g. node-relative pid
`1853` for a `sleep 3600` test pod was host pid `347844`. That host pid's
`/proc/<pid>/root` and `/proc/<pid>/cgroup` behave exactly like the Docker
rows' container pids: `/proc/<pid>/cgroup` read from the true host shows
the complete, real, un-namespaced absolute path (Docker's default private
cgroup namespace for the node container doesn't hide this from an outside
reader), and `/proc/<pid>/root` gives the pod's mount view. Running the
observer on the host reuses the exact Docker-row attach mechanism
(Task 2) with zero new code and needs no p11scope binary inside the node
image.

Discovery still runs **inside** the pod, via `kubectl exec` (same
reasoning as `verify-docker.sh`: `p11scope-discover` has no `--pid` flag,
so the provider's resolved path needs the pod's own mount view). Unlike
the Docker rows, the harness and `p11scope-discover` binaries are baked
into the pod's image at build time (`scripts/matrix/Dockerfile.kind`)
rather than bind-mounted in, since a plain `kubectl`-created pod has no
host-bind-mount equivalent to `docker run -v` without extra kind cluster
config (`extraMounts`) — baking in was the smaller diff.

**Real pod cgroup path, measured (kind v0.29.0, Kubernetes v1.33.1,
cgroupfs driver inside the node, one control-plane node):**

```
/sys/fs/cgroup/system.slice/docker-<node-container-id>.scope/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod<pod-uid-with-underscores>.slice/cri-containerd-<container-id>.scope
```

This is kind's cgroupfs-driver equivalent of a real cluster's
`kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod<uid>.slice/...`
— nested one level deeper than a bare cluster because the whole kubelet
hierarchy is itself nested under the kind node's own
`docker-<id>.scope`. The script finds the `cri-containerd-<id>.scope`
leaf by searching `/sys/fs/cgroup` for that exact directory name (robust
to the slice-naming scheme) rather than hardcoding the systemd slice
convention, then uses its **parent** directory — the pod-level slice — as
the `--cgroup` argument, because that's what an operator actually names
(the pod, not one specific container inside it). Task 1's descendant
matching is what makes scoping to the pod-level cgroup reach the
container-level leaf underneath.

Exact call counts matched `spike/expected.txt` on every function;
`evidence.completeness == "COMPLETE"`, `attached_probes == 136`. The
cluster is torn down (`kind delete cluster`) on success; the script
leaves it up for inspection if any step fails.

## Not yet covered by this file

Knative (Task 5) is not run here.

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
| Knative Serving, scale-from-zero (kind) | `scripts/matrix/verify-knative.sh` | PASS — attach starts with zero pods for the Service existing, then a cold-start request creates a new pod (created 7.9s after attach start, measured) whose calls match the oracle exactly | COMPLETE (136/136 probes) | Same as the kind-pod row: unprivileged `p11scope profile` fails identically at `/proc/<pid>/root` with `Permission denied`. |
| Prefork server, fork scoping (host) | `scripts/matrix/verify-fork-scope.sh` | PASS — cgroup attach precedes both the parent harness process and all 4 forked children; summed parent+children counts match `fork-expected.txt` exactly | COMPLETE (136/136 probes) | Measured, host `--pid` (same-uid target): unprivileged fails at BPF map creation (`Operation not permitted`); `CAP_BPF`+`CAP_PERFMON` alone still fails every attach (`perf_event_open` failed, `kernel.perf_event_paranoid=4` on this kernel); **`CAP_SYS_ADMIN` alone is sufficient** — no full root needed. Finer-grained than the rows above; see `docs/notes/phase4-privileges.md`. |

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

## Row 4: Knative scale-from-zero capture (Task 5)

This is the row that proves the observer can capture a workload that
**did not exist when the capture started**. `scripts/matrix/verify-knative.sh`
installs Knative Serving + Kourier (`knative-v1.23.0`) on a fresh kind
cluster, deploys the workload as a Knative Service with
`min-scale: "0"`/`max-scale: "1"` and a 30s scale-to-zero grace period,
waits for the initial readiness-check pod to be scaled away (confirmed
zero pods for the Service), starts the capture, *then* drives one HTTP
request through Kourier that forces Knative to cold-start a brand new pod.

**Scope: "stable ahead of pod existence".** Kubernetes/kind give no
per-namespace or per-Service cgroup — cgroups are created only per-pod
(see Row 3). The finest cgroup that genuinely predates the not-yet-created
pod is the node's whole kubepods hierarchy root
(`.../kubelet.slice/kubelet-kubepods.slice`, kind's cgroupfs-driver
equivalent, nested under the node's own `docker-<id>.scope`), which exists
as soon as kubelet starts (kube-system pods are already under it). This is
coarser than "the Service" — an honest limitation of what Kubernetes
exposes, not a chosen simplification, recorded here as required. It is
also the *only* option stable across workload shapes: measured directly,
the Knative pod's QoS class is **Burstable** (the injected queue-proxy
sidecar carries resource requests) while a plain `kubectl`-created pod
(Row 3) is **BestEffort** — so even the QoS-level slice one level below
`kubepods.slice` isn't a safe target to hard-code.

**Resolving a manifest path without any live pod.** `p11scope-discover`
takes a bare `--module <path>` (no `--pid`), so the Docker/kind-pod rows'
"run discover inside the live container" trick doesn't apply — there is
no live container at attach time. The fix: `kind load docker-image`
unpacks the image's layers into containerd's overlayfs snapshot store
immediately, independent of any container ever running from it (verified
directly: `find /var/lib/containerd/.../snapshots/*/fs -name
libsofthsm2.so` succeeds right after `kind load`, before any pod exists).
That snapshot file is real, on-disk, and reachable from the host via
`/proc/<node-container-host-pid>/root/...` — and the node container's own
host pid is stable for the whole cluster lifetime (unlike a pod's pid), so
this path stays valid before, during, and after the cold-start pod's life.
This reuses the exact "shared image layer" fact Task 3 proved, for a
temporal purpose instead of a multi-container one. (When more than one
image's layers matched, the script picks the highest-numbered snapshot id
— containerd allocates them monotonically, so the highest one belongs to
whichever image was unpacked most recently, i.e. the one this run just
loaded.)

**A genuine tool gap, found and worked around precisely (not faked
around).** `p11scope-discover` computes each object's identity
(`crates/manifest/src/identity.rs`) by re-reading the path it resolved
from *its own* `/proc/self/maps`
(`crates/discover/src/discover.rs:60`, via `maps.rs`). When discover is
invoked directly against a magic `/proc/<pid>/root/...` path, the kernel's
maps entry for the dlopen'd library reports the path canonicalized to its
own owning mount — with no `/proc/<pid>/root` prefix — which is
unreachable from discover's own mount namespace. `identity()`'s
`fs::read` then fails with ENOENT and the object is recorded
`Unavailable`/`reusable: false`. `p11scope profile` then refuses to
attach ("manifest identity is not reusable"), even though the (separately
rewritten) object *path* is perfectly valid and readable as root. This
was reproduced and confirmed by direct code reading, not assumed:
`crates/discover/src/discover.rs` L14-20 (dlopen, then reads
`/proc/self/maps`), L54-66 (`identity::identify(&path)` on that
maps-derived path), and `crates/manifest/src/identity.rs` L33-44 (the
failing `std::fs::read`). There is no existing flag or hook to make
identity computation use the already-accessible `--module` path instead —
this is a real, narrow gap in `p11scope-discover`, not a documented or
avoidable behavior.

**The workaround does not touch or fake the actual capture mechanism.**
`identity` is bookkeeping consumed only by the manifest-reuse gate
(`src/verify.rs`); the actual uprobe attach (`src/attach.rs`) uses
`objects[].path` directly and never looks at `identity`. The script
recomputes the GNU build-id out-of-band with `readelf -n` — the exact
same authoritative source `identity.rs` itself falls back to — and patches
the manifest's identity field before handing it to `p11scope profile`.
The eBPF attach, the cgroup scoping, and the timing proof (attach before
pod creation) are all real and unmodified; only a metadata field that
discover currently computes incorrectly for this one path shape was
corrected. **Recommended follow-up (not done here, out of this task's
scope): teach `p11scope-discover` to compute identity against the
already-accessible `--module` argument's resolved form instead of the
maps-derived one**, so this class of magic-symlink-crossing invocation
works without an external patch step.

**Kubernetes-version floor.** `knative-v1.23.0`'s controller/webhook/etc.
refuse to start against kind's default node (Kubernetes v1.33.1):
`"kubernetes version 1.33.1 is not compatible, need at least 1.34.0-0"` —
Knative's own `knative.dev/pkg` version gate, officially overridable via
the `KUBERNETES_MIN_VERSION` env var (stated in the error message itself).
The script sets it on the affected Deployments after install; this is a
version-compatibility accommodation, not a functional change to anything
under test.

**Result, measured:** attach started with zero pods for the Service
existing (`kubectl get pods -l serving.knative.dev/service=... | wc -l`
== 0, checked immediately before starting `p11scope profile`); the
triggering request's cold-start pod was created **7.9 seconds after**
attach start (`metadata.creationTimestamp` compared programmatically
against the recorded attach-start instant); the capture matched
`spike/expected.txt` exactly for a single request/single harness run;
`evidence.completeness == "COMPLETE"`, `attached_probes == 136`. The new
pod's actual leaf cgroup (informational, not the `--cgroup` used):
`.../kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope`.

## Row 5: independent oracle diff — `pkcs11-check` (Task 7)

`scripts/matrix/verify-oracle.sh` is the first check in this phase against
an oracle p11scope did not write: `pkcs11-check`
(`/home/user/src/m/pkcs11-check-ws/pkcs11-check`), a separate,
vendor-neutral PKCS#11 test client with its own per-call `CK_RV` trace
(`--rv-trace`). Direction: **oracle ⊆ capture** — every `(function, CK_RV)`
pair the oracle logged must appear in the capture at least that many
times; the capture may hold more.

Run against SoftHSM2, `--marker smoke --isolation file --rv-trace`, scoped
by a `systemd-run --scope` cgroup created (and attached to) before
pkcs11-check is even exec'd — the same attach-before-run pattern as every
other row, with `--cgroup` standing in for `--pid` because `--isolation
file` forks one subprocess per test file (many `C_Initialize` cycles, many
PIDs, most nonexistent at attach time).

Result: `attached_probes: 136`, `completeness: COMPLETE`, every
oracle-logged `(function, CK_RV)` pair present in the capture at least as
often as logged. One apparent discrepancy (an exact 2x pattern across a
6-function, 8-call flow) was investigated and traced to pkcs11-check's own
rv-trace attributing one physical call sequence to two adjacent test node
IDs — not a p11scope capture gap (proven: the "recipient" test takes no
session/module fixture and is physically incapable of making a PKCS#11
call). Full investigation, evidence, and the exact excluded node ID:
`docs/notes/phase4-oracle.md`.

A `uv`-is-a-snap-package infrastructure gotcha (snap confinement silently
moves the process out of the target cgroup, `systemd-run --scope`
reporting the unit "Deactivated successfully" within the same second)
took the longest to isolate; the fix (invoke the venv's own installed
console script instead of `uv run`) is recorded in the same notes file.

## Row 6: fork scoping + measured privileges (Task 8)

Fork-scoping proof: see the "Prefork server, fork scoping (host)" table
row above, `scripts/matrix/verify-fork-scope.sh`, full detail in
`docs/notes/phase4-privileges.md`.

Privileges, measured (not copied from docs) for all three environments —
host, Docker, kind — down to the specific capability, not just
unprivileged-vs-root: `docs/notes/phase4-privileges.md`. Headline finding:
host needs only `CAP_SYS_ADMIN`; Docker/kind (crossing into a
different-uid container/pod process's `/proc/<pid>/root`) need
`CAP_SYS_PTRACE` + `CAP_SYS_ADMIN` — neither environment needs full root,
which the earlier rows' coarser "root via sudo" privilege notes did not
distinguish.

## Not yet covered by this file

Nothing — Tasks 2 through 8 (Docker, shared layer, kind pod, Knative, the
`pkcs11-check` oracle diff, fork scoping, and measured privileges) are all
recorded above.

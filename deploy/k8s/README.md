<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# p11scope on Kubernetes

A node observer DaemonSet: one idle agent pod per node that runs one-shot,
operator-triggered captures of a target pod (`kubectl exec`). Nothing is
copied into or out of the target container. The observer reads the target's
memory through hostPID + `/proc`, opens the provider through
`/proc/<pid>/root` and attaches eBPF uprobes to it, exactly like
`scripts/attach-pod.sh` does from a node shell.

It is an example deployment built from this tree, not a published image or
an operator. Capture is never continuous: every capture has a human trigger,
a bounded `--duration` and its own output file.

## Layout

Files are numbered because `kubectl apply -f deploy/k8s/` applies them in
name order and the namespace must exist first.

- `00-namespace.yaml` — the `p11scope` namespace, labelled for the Pod
  Security Admission `privileged` level (hostPID and the added capabilities
  are outside `baseline`). Keep it for the observer only.
- `10-serviceaccount.yaml` — the observer identity:
  `automountServiceAccountToken: false` and **no Role or RoleBinding**. The
  observer never talks to the API.
- `20-daemonset.yaml` — the agent (privileges and blast radius below).
- `e2e/workloads.yaml` — **test-only** ledgered SoftHSM2 pods and an idle
  negative control, used by `scripts/kind-e2e.sh`. `kubectl apply -f
  deploy/k8s/` does not recurse into it.
- `../Dockerfile.observer`, `../Dockerfile.holder` — image builds (holder is
  test-only).
- `../../scripts/k8s-profile-entry.sh` — the in-pod entry: resolves a pod UID
  (or container id) to its pod cgroup from the node's cgroup hierarchy and
  execs `p11scope profile|trace|doctor --cgroup <pod cgroup>`.
- `../../scripts/kind-e2e.sh` — the committed end-to-end test (below).

## Deploy and capture

Build the images from the repository root (the static observer first), then
make them available to the nodes (a registry, or `kind load docker-image` on
kind) and adjust `image:`/`imagePullPolicy` in `20-daemonset.yaml` to match.
Run the commands below from the parent of the checkout, so the `p11scope/...`
paths resolve (from the repo root itself they do not exist):

```sh
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo +"$(cat p11scope/.release-rust-version)" build --manifest-path p11scope/Cargo.toml \
  --locked --release --no-default-features --target x86_64-unknown-linux-musl --bin p11scope
docker build -f p11scope/deploy/Dockerfile.observer -t p11scope-observer:1 p11scope
kubectl apply -f p11scope/deploy/k8s/
```

A capture targets one pod by UID, from the observer pod on the same node:

```sh
NS=my-app POD=my-app-0
UID_=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.metadata.uid}')
NODE=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')
OBS=$(kubectl -n p11scope get pod -l app.kubernetes.io/component=observer \
  --field-selector "spec.nodeName=$NODE" -o jsonpath='{.items[0].metadata.name}')
# preflight on that node, then a 60 s profile of every container in the pod
kubectl -n p11scope exec "$OBS" -- k8s-profile-entry --pod-uid "$UID_" --command doctor
kubectl -n p11scope exec "$OBS" -- k8s-profile-entry --pod-uid "$UID_" -- \
  --duration 60 -o /tmp/capture.json
kubectl -n p11scope cp "$OBS:/tmp/capture.json" capture.json
```

The entry script accepts only an exact kubelet pod cgroup: anchored at the
kubelet root (`kubepods/`, `kubepods.slice/` or
`kubelet.slice/kubelet-kubepods.slice/`) at the QoS depth, with a plain
`[A-Za-z0-9._-]` name and the requested UID. Look-alike directories elsewhere
(including decoys a workload creates inside its own delegated cgroup subtree)
are reported and ignored, and two valid matches are refused. It also refuses,
with a named error, a pod with no process visible to the observer (hostPID
missing) and a pod whose process memory the observer cannot open
(CAP_SYS_PTRACE / CAP_DAC_READ_SEARCH missing). It prints `pod cgroup: <path> (N visible process(es), M with
readable memory)` before every capture.

`--command trace` streams one line per call instead; everything after `--`
goes to `p11scope` verbatim. Which processes on the node map a provider:
`kubectl -n p11scope exec "$OBS" -- p11scope inventory --system -o
/tmp/inventory.json` (scan-only in this release: callers and mappings, no
usage counts). `/tmp` is the only writable path; copy results out before the
pod is replaced, because the emptyDir does not survive a rollout.

## Privileges and why

The observer pod is **root on its node**. Its job (read any process's memory,
attach to any binary) needs that, and the hardening in `20-daemonset.yaml`
narrows the surface, not the power. Read [Blast radius](#blast-radius) and
[Who may exec into the observer](#who-may-exec-into-the-observer) before
deploying.

What it does not have: `privileged: true`, hostNetwork, host IPC, hostPath
mounts other than the read-only cgroup tree, a ServiceAccount token, RBAC.
It runs with a read-only root filesystem, seccomp `RuntimeDefault`,
`allowPrivilegeEscalation: false`, and capabilities `drop: [ALL]` plus
exactly three.

Each grant was removed in turn on kind (Linux 7.0.0-34, cgroup v2,
`kernel.perf_event_paranoid=4`, `kernel.yama.ptrace_scope=1`; 2026-10-03)
while capturing two ledgered pods: **A**, root, provider at its package path,
6 x 400 calls; **P**, uid 1000, provider copied into a 0700 directory, 6 x 300
calls. "exact" means every one of the six functions counted the ledger and
nothing else was counted.

| Variant | A (root, public provider) | P (uid 1000, private provider) |
| --- | --- | --- |
| shipped: `SYS_ADMIN SYS_PTRACE DAC_READ_SEARCH`, hostPID, cgroupfs | exact | exact |
| + `BPF PERFMON` (the previous five-cap set) | exact | exact |
| without `SYS_ADMIN` (`BPF PERFMON SYS_PTRACE DAC_READ_SEARCH`) | exit 1: uretprobe self-probe `perf_event_open` EACCES; doctor T0 | same |
| same, seccomp `Unconfined` | same failure (not seccomp) | same |
| without `SYS_PTRACE` | p11scope: `/proc/<pid>/mem` EACCES, 0 modules, 0 probes; entry script now refuses first ("0 with readable memory") | same |
| without `DAC_READ_SEARCH` | p11scope: counts exact but memory scan EACCES (`scan_unavailable: ptrace`, `concrete_gap`); entry script now refuses first ("1 with readable memory" of 2) | p11scope: 0 modules; entry refuses ("0 with readable memory") |
| without `BPF` (with `SYS_ADMIN`) / without `PERFMON` (with `SYS_ADMIN`) | exact | exact |
| no capabilities | exit 1: map create EPERM | same |
| `hostPID: false` | p11scope alone: "no PKCS#11 modules discovered", 0 probes, exit 0 (looks like success); entry script now refuses: "no process of <cgroup> is visible ... needs hostPID: true" | same |
| no cgroupfs hostPath | entry script: pod cgroup not found, exit 1 | same |
| shipped set, `--attach-backend singles` / `multi` | exact / exact | exact / exact |

Why each grant:

- **hostPID** — the target's processes must be visible to scan their memory
  and open `/proc/<pid>/root`.
- **CAP_SYS_ADMIN** — BPF load and perf-event attach. The uretprobe
  self-probe always attaches through `perf_event_open()` (even where the
  capture itself uses uprobe-multi), and `perf_event_paranoid >= 3` (the
  Debian/Ubuntu default) refuses that without CAP_SYS_ADMIN. While it is held
  the kernel accepts it for every CAP_BPF/CAP_PERFMON check, so those two
  are not listed. It also grants `/proc/<pid>/map_files` access (otherwise
  `CAP_CHECKPOINT_RESTORE`), which `inventory` needs to attribute callers
  past its scan cap.
- **CAP_SYS_PTRACE** — ptrace-mode access to other processes'
  `/proc/<pid>/mem` and `maps` (Yama scope 1, other UIDs).
- **CAP_DAC_READ_SEARCH** — the memory scan without CAP_DAC_OVERRIDE, and
  providers in directories only their application can traverse.
- **cgroupfs (read-only hostPath)** — the pod's own cgroup namespace shows
  only itself; the target's pod cgroup is named from the node view.
- **Not needed** (none mounted, every cell above passes): `/sys/fs/bpf`
  (nothing is pinned), tracefs/debugfs (raw and BTF tracepoints, uprobes via
  the perf PMU), a `/sys/kernel/btf` mount (the container's sysfs shows it).

**Gated variant**: on nodes with `kernel.perf_event_paranoid <= 2` the
`perf_event_open()` refusal does not apply, but **do not simply drop
`SYS_ADMIN`**: it also covers `/proc/<pid>/map_files`, which `inventory`'s
caller attribution past the scan cap reads and which needs `CAP_SYS_ADMIN` or
`CAP_CHECKPOINT_RESTORE` (without either, those callers are reported as
`map_files_unavailable`). The variant is therefore `BPF` + `PERFMON` +
`CHECKPOINT_RESTORE` in place of `SYS_ADMIN` (plus `SYS_PTRACE` and
`DAC_READ_SEARCH` as before). This repository has **not** measured it (the
sysctl is host-global). Prove a node with `--command doctor`: `uprobe attach
(self) ... ok` and `verdict: capture available`.

### Blast radius

Measured in the observer pod on kind (2026-10-03, the shipped manifest; the
"host" is the kind node container, on a real cluster it is the node):

- **Host filesystem, read and write.** hostPID + CAP_SYS_PTRACE +
  CAP_DAC_READ_SEARCH let uid 0 open `/proc/1/root`: the whole host root,
  `/etc/shadow` included, whatever is or is not mounted. Writing works too:
  without CAP_DAC_OVERRIDE, root still owns most host files and directories,
  so owner permission bits apply (`echo > /proc/1/root/etc/<file>`
  succeeded). The same holds for every container's root through
  `/proc/<pid>/root`.
- **Host namespaces.** CAP_SYS_ADMIN allows `setns()`: `nsenter -t 1 -n -u
  -i` entered the host network, UTS and IPC namespaces. Entering the host
  mount namespace failed only because CAP_SYS_CHROOT is dropped, which is no
  barrier given `/proc/1/root`.
- **Mounts.** CAP_SYS_ADMIN allows `mount()`: `mount -o remount,rw
  /sys/fs/cgroup` turned the "read-only" cgroup mount writable (and with it
  every cgroup limit and membership on the node).
- **`allowPrivilegeEscalation: false`** sets `no_new_privs`, which is no
  boundary for a process that already holds CAP_SYS_ADMIN. The API refuses
  the combination when the capability is spelled `CAP_SYS_ADMIN` ("cannot set
  `allowPrivilegeEscalation` to false and `capabilities.Add` CAP_SYS_ADMIN",
  server dry-run) and accepts it only because the manifest spells it
  `SYS_ADMIN`.
- **Every node.** `tolerations: [operator: Exists]` places one such pod on
  every node, control plane included.

### Who may exec into the observer

Anyone who can run a command in an observer pod is root on that node, and so
on every node. In the `p11scope` namespace, grant these only to node
administrators:

- `create` on `pods/exec` and `pods/attach`;
- `patch`/`update` on `pods/ephemeralcontainers` (an ephemeral container in
  an observer pod shares its PID view and can be given its own capabilities);
- `create`/`update`/`patch`/`delete` on `pods` and `daemonsets` (the
  namespace admits `privileged` pods, so whoever can create a pod there can
  create any privileged pod).

Kubernetes RBAC only adds permissions, so restricting means not granting:
do not bind the built-in `admin` or `edit` ClusterRoles in this namespace,
remember that a ClusterRoleBinding of `admin`, `edit` or `cluster-admin`
grants all of the above here too, and audit with
`kubectl auth can-i create pods/exec -n p11scope --as <user>` (and
`--as-group`). A minimal Role for the node administrators who run captures
(not shipped; adjust the group):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: p11scope-operator, namespace: p11scope}
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: p11scope-operator, namespace: p11scope}
subjects:
  - {kind: Group, name: node-admins, apiGroup: rbac.authorization.k8s.io}
roleRef: {kind: Role, name: p11scope-operator, apiGroup: rbac.authorization.k8s.io}
```

(`kubectl cp` of a capture is a `pods/exec` of `tar`, so this Role covers it.)
Where an admission policy engine or audit pipeline exists, alert on any
`pods/exec`, `pods/attach` or ephemeral-container request in this namespace.
Scale the DaemonSet down (or delete it) when no capture is planned: nothing
it holds needs to persist.

**Read-only root**: the root filesystem is read-only; the only writable path
is the `scratch` emptyDir at `/tmp` (capped at 256 Mi by `sizeLimit`; the
kubelet evicts the pod past it), so captures write `-o /tmp/<name>`.
Kubelet creates that mount 0777 without the sticky bit, which the observer's
output trust check refuses; `k8s-profile-entry.sh` restores 1777 first.

Resources: requests 50m CPU / 64 Mi, limits 1 CPU / 512 Mi. The observer
pod's measured peak memory over a full e2e run (profile, trace, inventory and
BPF maps included) was 55-104 MB across six runs on a one-node kind cluster
(every run from 99 MB up held two captures at once);
the e2e records it as `observer-memory`. A node with many processes and providers
needs more for `inventory --system`; raise the limit rather than risk an
OOM kill in the middle of a capture.

## End-to-end test: `scripts/kind-e2e.sh`

Builds the static observer and both images from this tree (base images pinned
by digest; the holder's apt packages still float with the archive), creates a
uniquely named kind cluster with a private kubeconfig, applies this directory
exactly as documented (`kubectl apply -f` on a copy where only the image name
is rendered), and checks:

- posture: the live capability set equals the manifest's, seccomp is active,
  no token is mounted, the ServiceAccount cannot get/list pods, nodes or
  secrets anywhere, the root filesystem is read-only;
- `doctor` in the pod reports capture available;
- **positive control and isolation**: two concurrent captures, one of
  `ledger-a` and one of `ledger-b` (same image, same provider inode, same
  node), count exactly 6 x 400 and 6 x 250, and both are proven still running
  (`kill -0`) when both ledgers have completed, so each pod's calls happened
  inside the other's capture window;
- a non-root pod with a private 0700 provider: exactly 6 x 300;
- `trace`: exactly 6 x 200 call lines;
- **negative control**: the idle pod (SoftHSM2 on disk, never mapped) yields
  no module and no call, while the entry script proves its processes were
  visible and readable (so "no module" cannot mean "not seen"); and
  `inventory --system` lists every ledger pod as a caller of the provider and
  the idle pod as scanned with no edge;
- **nested PID namespace** (a kind node is a container): `doctor` reports
  `PID scope unavailable`, every capture names `pid_namespace.observer:
  nested` and carries exactly the `pid_namespace` cause (lossy,
  `concrete_gap`) while its counts stay exact, and `profile --pid` is refused
  with `pid-namespace-mismatch:` and writes no report;
- record-only (never counted as passed checks): which PID namespace `trace`
  prints, the observer's peak memory.

The default toolchain is `.release-rust-version`; it needs the
`x86_64-unknown-linux-musl` target (the script checks and prints the
`rustup target add` command), or set `P11SCOPE_K8S_TOOLCHAIN` /
`P11SCOPE_K8S_OBSERVER_BIN`.

The cluster and images are always deleted on exit (`--keep` keeps them).
`P11SCOPE_K8S_LOCK=<file>` serializes each docker/kind/capture step with
other privileged work on the host. Evidence lands in a 0700 directory under
`$TMPDIR` (`summary.jsonl`, every capture, the rendered manifests).

## Limits

- **PID namespaces (DR-30).** The observer's PID view must equal the
  initial PID namespace. On a normal node `hostPID` gives exactly that. Where
  the node itself runs in a PID namespace (kind, k3d, sysbox, any
  "node in a container"), it does not, and then:
  - `profile --pid` (and every other PID-scoped capture) is refused with
    `pid-namespace-mismatch: refusing --pid N: ...`. Before that refusal
    existed it attached and counted **zero** calls without a gap (measured in
    kind: 0 of 600). Use `--cgroup` (the entry script's `--pod-uid`), whose
    counts stay exact there.
  - Every report publishes `pid_namespace` (`observer: nested`) and the
    observation cause `pid_namespace`, so a `--cgroup` or `--system` capture
    reads lossy (`concrete_gap`) even when its counts are exact: `trace`
    prints initial-namespace PIDs the observer's `/proc` does not have, and
    `inventory` lists the observer's view. `doctor` says `PID scope
    unavailable`.
  - p11scope has no `NSpid` translation (DR-30); it names the mismatch
    instead.
- **inventory** is scan-only in this release (no usage counts), and on a
  node where several pods map one provider through separate overlay mounts it
  repeats the same overlay-collapse gap on every pass of a `--duration` run.
- **No upgrade story.** Nothing persists between observer pods (no pinned
  BPF state, no state file), so a rollout simply replaces idle pods; a
  capture running at that moment is killed with its pod (its report is not
  written) and `/tmp` is lost. There is no BPF/schema versioning between
  observer versions. Run captures between rollouts.
- x86-64 nodes only (`nodeSelector kubernetes.io/arch: amd64`); cgroup v2
  only (the entry script checks `cgroup.controllers`). Tested on a real node:
  containerd with the systemd cgroup driver (kind). The entry script also
  resolves CRI-O (`crio-<id>.scope`, `crio-<id>`), cri-dockerd
  (`docker-<id>.scope`) and the cgroupfs driver (`pod<uid>`), but those
  layouts are verified only against a synthetic hierarchy in its
  `--self-test`, never on a real node.
- A provider the pod loads after the capture starts is discovered live, but
  calls before attach completes are not counted; a workload's first calls
  right after `dlopen` can be missed (see `docs/usage.md`).

## Troubleshooting

- **`could not locate the pod cgroup ... (is the target on this node?)`** —
  exec into the observer on the target's node (`spec.nodeName`), check the
  UID, and that `/sys/fs/cgroup` is the node's cgroup v2 hostPath mount.
- **`ignored N match(es) that are not kubelet pod cgroups`** — directories
  named like the pod or container exist outside the kubelet's pod cgroups
  (for example inside a workload's own delegated cgroup); they were skipped.
- **`refusing: N kubelet pod cgroups match`** — the target is ambiguous;
  nothing is captured rather than a wider scope.
- **`is not a cgroup v2 hierarchy`** — the node runs cgroup v1 (unsupported)
  or the hostPath is not mounted.
- **`no process of <cgroup> is visible in this PID namespace`** — the pod
  lacks `hostPID: true`, or the target pod has no running process.
- **`cannot open /proc/<pid>/mem of N pod process(es)`** — CAP_SYS_PTRACE or
  CAP_DAC_READ_SEARCH is missing (or an LSM denies ptrace).
- **`cannot load p11scope's BPF programs even as root (attaching the
  uretprobe self-probe: perf_event_open ... Permission denied)`** — the node's
  `kernel.perf_event_paranoid` is >= 3 and the pod lacks CAP_SYS_ADMIN. (The
  message blames lockdown/LSM/seccomp, and doctor's paranoid row says
  BPF+PERFMON suffice; on these nodes both are misleading — the
  `uprobe attach (self)` row is the real answer.)
- **`map error ... Operation not permitted`** — no BPF-capable capability:
  check the DaemonSet's `capabilities.add` and admission (PSA must allow
  `privileged` in the namespace).
- **`no PKCS#11 modules discovered in cgroup ...`** (after the entry script's
  visibility line) — the target maps no provider yet; it may load one later.
- **`-o` refused / output trust errors** — write under `/tmp` only; run
  captures through `k8s-profile-entry` so `/tmp` is 1777.
- **`pid-namespace-mismatch: refusing --pid N`** — the node runs in a PID
  namespace (see the limit above); use `--pod-uid`.
- Pod Security Admission rejects the DaemonSet — the namespace must carry
  `pod-security.kubernetes.io/enforce: privileged` (as `00-namespace.yaml`
  does). `kubectl apply -f deploy/k8s/` failing with `namespaces "p11scope"
  not found` means an unnumbered manifest sorted before `00-namespace.yaml`.

## Image base rationale (measured 2026-09-15)

- **Observer: `alpine:3.24` + musl-static binary.** The observer's deps are
  pure Rust + `libc` (BPF via aya, no libbpf C library), so a static-pie build
  works: `file` says `static-pie linked`. Static needs no libc, so Alpine's
  musl is fine and the binary runs anywhere. No curl/jq since the observer
  stopped using the API.
- **Not distroless**: the entry script needs a shell; Alpine keeps the size
  small while keeping `kubectl exec` debuggability. Revisit only if a
  shell-free policy demands it.
- **Holder: `ubuntu:26.04` (test-only)**, multi-stage: gcc builds the
  ledgered client, the final stage carries only SoftHSM2 and the client.
- **Maintenance note**: bump `alpine:3.24` and its pinned digest together in
  `Dockerfile.observer` when EOL approaches (one line + e2e re-run); the
  holder pins `ubuntu:26.04` the same way.

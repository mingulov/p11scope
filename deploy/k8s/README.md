# p11scope on Kubernetes

Node-side observer as a DaemonSet: one agent pod per node that idles and
performs one-shot `profile --cgroup` captures of target pods on operator
request. Nothing is copied into or out of the target container — the
observer reads target memory via hostPID + `/proc` and opens the provider
through `/proc/<pid>/root`, exactly like `scripts/attach-pod.sh`.

## Layout

- `namespace.yaml`, `serviceaccount.yaml`, `rbac.yaml` — `p11scope`
  namespace, observer identity, least-privilege `Role` (`pods`
  get/list in that namespace) + binding. For multi-namespace
  observation, replicate the Role/Binding per target namespace or
  promote to a (documented, not shipped) ClusterRole — the DaemonSet
  needs no change.
- `daemonset.yaml` — the agent. HostPID, cgroupfs (ro) + bpffs (rw)
  mounts, caps `BPF PERFMON SYS_PTRACE DAC_READ_SEARCH SYS_ADMIN`
  (`SYS_ADMIN` is required when `kernel.perf_event_paranoid >= 3`;
  `doctor` says so explicitly — drop it on `<= 2` hosts). No
  `privileged:true`, no hostNetwork. Command is `sleep infinity`: every
  capture keeps an explicit human trigger via `kubectl exec`.
- `holder.yaml` — test-only SoftHSM holder pod for the e2e.
- `../Dockerfile.observer`, `../Dockerfile.holder` — image builds.
- `../../scripts/k8s-profile-entry.sh` — entry script (also the image
  ENTRYPOINT): resolves pod → container id through the in-cluster API
  under the bound ServiceAccount, locates the pod cgroup from the node
  view, execs `p11scope profile --cgroup`.
- `../../scripts/verify-k8s-attach.sh` — committed Gate K1 e2e:
  builds + loads both images into every kind node (via `ctr`, no
  `kind load` dependency), applies the manifests, captures the holder,
  asserts the oracle (hash-pinned, probes + slots, libsofthsm2.so),
  cleans up. Refuses non-`kind-*` contexts unless
  `P11SCOPE_K8S_ALLOW_CONTEXT=1`.

## Image base rationale (measured 2026-09-15)

- **Observer: `alpine:3.24` + musl-static binary (34.6 MB).** The
  observer's deps are pure Rust + `libc` (BPF via aya, no libbpf C
  library; no openssl/sqlite in the tree), so a static-pie build works
  first try: `file` says `static-pie linked`, `ldd` says `statically
  linked`, 6.9 MB. Static needs no libc, so Alpine's musl is fine and
  the binary runs anywhere. e2e-proven: full BPF capture (136/136)
  from the static binary.
- **Not distroless**: would require rewriting the sh entrypoint (shell
  + curl + jq) for an image family that ships none of them. Analyzed,
  not implemented: Alpine already delivers the size (~35 MB total)
  while keeping `kubectl exec` debuggability. Revisit only if a
  shell-free policy demands it.
- **Holder: `ubuntu:26.04` (test-only, 162 MB).** Chosen for the longer
  support window over 24.04 (2031 vs 2029); `softhsm2` installs cleanly
  there (build-asserted). The observer itself has no distro dependency,
  so its base carries no EOL risk beyond the Alpine pin.
- **Maintenance note**: Alpine pins age on a ~2-year cadence: bump
  `alpine:3.24` in `Dockerfile.observer` when EOL approaches (one line
  + e2e re-run). Historical footnote: the first cut was `ubuntu:24.04`
  + dynamic binary + jq (140 MB); measured bases then were
  ubuntu:24.04 115 MB, debian:trixie-slim 118 MB, ubuntu:26.04 159 MB.

## Manual flow

Run the commands below from the parent of the checkout, so the
`p11scope/...` paths resolve (from the repo root itself they do not exist).

```sh
# images (needs target/release/p11scope)
docker build -f p11scope/deploy/Dockerfile.observer -t p11scope-observer:1 p11scope
docker build -f p11scope/deploy/Dockerfile.holder -t p11scope-holder:1 p11scope
# load into a kind node (kind CLI not required)
docker save p11scope-observer:1 p11scope-holder:1 \
  | docker exec -i <node-container> ctr -n k8s.io images import -
# deploy + capture
kubectl apply -f p11scope/deploy/k8s/
kubectl -n p11scope exec daemonset/p11scope-observer -- k8s-profile-entry \
  --pod p11scope-holder -- --mode metrics --duration 30 -o /tmp/cap.json
```

Proven 2026-09-15 on kind (k8s v1.34, kernel 7.0.0-31):
`136/136 probes attached · 68 slots` on the holder's preloaded
libsofthsm2.so, in-cluster API resolution + RBAC exercised.

## Privilege posture (documented, by design)

hostPID + BPF/PERFMON/SYS_PTRACE/DAC_READ_SEARCH (+ SYS_ADMIN on
`perf_event_paranoid >= 3` hosts) is node-root-equivalent for any such agent;
there is no untrusted input path (operator-triggered `kubectl exec` only),
so this is posture to document, not a vulnerability to fix:

- **Gated variant**: on `perf_event_paranoid <= 2` hosts with kernels >= 5.8,
  drop SYS_ADMIN from `daemonset.yaml` — BPF+PERFMON suffice.
  `scripts/verify-capability-tier.sh` proves which tier a node is on; keep
  SYS_ADMIN only where the tier gate demands it.
- **Read-only root**: the container sets `readOnlyRootFilesystem: true`;
  the only writable path is the `scratch` emptyDir at `/tmp`, so captures
  must pass `-o /tmp/<name>.json` (Gate K1 does) and `kubectl cp` the file
  out afterwards. Kubelet creates that mount 0777 without the sticky bit,
  which the observer's output trust check refuses — `k8s-profile-entry.sh`
  restores 1777 on `/tmp` before every exec (K1-proven).
- **Seccomp**: `RuntimeDefault`, proven by Gate K1 on kind (2026-09-15):
  the containerd default profile allows `bpf()`, `perf_event_open()`,
  `openat2()`, pidfd, and the process-inspection syscalls the observer
  needs — the K1 oracle passes unchanged with the filter active
  (`Seccomp: 2`, verified in-pod). Capabilities `drop: [ALL]` then add back
  the five BPF-observation caps; `allowPrivilegeEscalation: false`.

#!/bin/sh
# Phase 4 Task 4: Kubernetes pod capture (kind). Runs the deterministic
# workload (spike/harness.c, oracle spike/expected.txt) as a pod on a kind
# cluster and attaches from the host.
#
# Observer placement decision: the observer (p11scope) runs ON THE HOST,
# targeting the pod's namespaces from outside -- NOT inside the kind node
# container. Why: kind's "node" is itself a Docker container, but a
# Docker container's own pid/mount/cgroup namespaces are still descendants
# of the true host's namespaces (namespaces nest transitively through
# whichever container runtime created them). Measured directly while
# building this script: `docker exec <node> ps aux` shows a pod process
# under one PID (node-namespace-relative), while `sudo ps aux` on the true
# host shows the SAME process under a DIFFERENT, host-visible PID -- and
# that host PID's /proc/<pid>/root and /proc/<pid>/cgroup both work exactly
# like the Docker rows' container PIDs (verify-docker.sh). Running the
# observer on the host means no p11scope binary needs to exist inside the
# node image, and reuses the exact attach mechanism already proven for
# Docker (Task 2) with zero new code.
#
# Discovery still runs INSIDE the pod (kubectl exec), for the same reason
# as verify-docker.sh: the provider's path as resolved by the dynamic
# linker depends on the pod's own mount view, and p11scope-discover has no
# --pid flag. The harness and p11scope-discover binaries are baked into
# the pod's image at build time (Dockerfile.kind) rather than bind-mounted,
# since a plain kubectl-created pod has no host-bind-mount equivalent to
# `docker run -v` without extra kind cluster config.
#
# Cgroup path: found by searching /sys/fs/cgroup on the host for the
# container's `cri-containerd-<id>.scope` directory (robust to kind's
# cgroup driver/slice-naming, rather than hardcoding the systemd slice
# scheme). Its PARENT directory is the pod-level cgroup -- kind's
# cgroupfs-equivalent of a real cluster's `kubepods.slice/...` path,
# concretely `kubelet-kubepods-besteffort-pod<uid>.slice` nested under the
# node's own `docker-<id>.scope` -- and THAT is what gets passed to
# `--cgroup`, because that's what an operator would actually name (the
# pod, not one specific container inside it). Task 1's descendant matching
# is what makes scoping to the pod-level cgroup reach the container-level
# leaf cgroup underneath.
set -eu
cd "$(dirname "$0")/../.."

MODULE_IN_POD=/usr/lib/softhsm/libsofthsm2.so
WORK=target/matrix-kind
TRUST_DIR="$PWD/$WORK/trusted"
PROVENANCE_MODULE="$PWD/$WORK/provider-provenance.so"
IMAGE=p11scope-matrix-k8s
CLUSTER=p11scope-matrix
POD=p11scope-matrix-pod
. scripts/trusted-p11scope.sh

command -v kind >/dev/null || { echo "kind required"; exit 1; }
command -v kubectl >/dev/null || { echo "kubectl required"; exit 1; }
command -v docker >/dev/null || { echo "docker required"; exit 1; }

CLUSTER_CREATED=0
FAILED=1
SPID=
cleanup() {
    [ -z "$SPID" ] || kill "$SPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    if [ "$FAILED" -eq 0 ]; then
        kubectl delete pod "$POD" --wait=true --ignore-not-found >/dev/null 2>&1 || true
        if [ "$CLUSTER_CREATED" -eq 1 ]; then
            kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
        fi
    else
        echo "FAILED -- leaving cluster '$CLUSTER' and pod '$POD' up for inspection"
    fi
    remove_trusted_p11scope "$TRUST_DIR"
}
trap cleanup EXIT

echo "=== build product + workload ==="
cargo build --release --workspace
mkdir -p "$WORK/build"
gcc -O0 -o "$WORK/build/harness" spike/harness.c -ldl
cp target/release/p11scope-discover "$WORK/build/p11scope-discover"

echo "=== build pod image (harness + discover baked in) ==="
docker build -q -t "$IMAGE" -f scripts/matrix/Dockerfile.kind "$WORK" >/dev/null

echo "=== create kind cluster ==="
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    echo "cluster '$CLUSTER' already exists, reusing"
else
    kind create cluster --name "$CLUSTER"
    CLUSTER_CREATED=1
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null
kubectl wait --for=condition=Ready node --all --timeout=120s

echo "=== load image into cluster ==="
kind load docker-image "$IMAGE" --name "$CLUSTER"

echo "=== deploy pod ==="
kubectl delete pod "$POD" --wait=true --ignore-not-found >/dev/null 2>&1 || true
cat > "$WORK/pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD
  labels:
    app: p11scope-matrix
spec:
  containers:
  - name: workload
    image: $IMAGE
    imagePullPolicy: Never
    command: ["sleep", "infinity"]
  restartPolicy: Never
EOF
kubectl apply -f "$WORK/pod.yaml"
kubectl wait --for=condition=Ready "pod/$POD" --timeout=60s

echo "=== discover inside the pod's mount view ==="
kubectl exec "$POD" -- p11scope-discover --module "$MODULE_IN_POD" -o /tmp/manifest.json
kubectl exec "$POD" -- cat /tmp/manifest.json > "$WORK/manifest.json"
test -s "$WORK/manifest.json" || { echo "manifest not produced"; exit 1; }
kubectl exec "$POD" -- cat "$MODULE_IN_POD" > "$PROVENANCE_MODULE"

echo "=== resolve container id, host pid, and cgroup paths ==="
CID=$(kubectl get pod "$POD" -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's#containerd://##')
test -n "$CID" || { echo "could not get container id"; exit 1; }
echo "container id: $CID"
CONTAINER_CG=$(sudo find /sys/fs/cgroup -type d -name "cri-containerd-${CID}.scope" 2>/dev/null | head -n1)
test -n "$CONTAINER_CG" || { echo "could not find container cgroup under /sys/fs/cgroup"; exit 1; }
POD_CG=$(dirname "$CONTAINER_CG")
echo "container-level cgroup: $CONTAINER_CG"
echo "pod-level cgroup (what an operator passes to --cgroup): $POD_CG"
HOSTPID=$(sudo cat "$CONTAINER_CG/cgroup.procs" | head -n1)
test -n "$HOSTPID" || { echo "no host pid found in container cgroup"; exit 1; }
echo "pod main process, host-visible pid: $HOSTPID"

echo "=== rewrite manifest object paths with /proc/<host-pid>/root prefix ==="
python3 - "$WORK/manifest.json" "$WORK/manifest-host.json" "/proc/$HOSTPID/root" <<'PY'
import json, sys
inp, outp, prefix = sys.argv[1], sys.argv[2], sys.argv[3]
m = json.load(open(inp))
m["module_path"] = prefix + m["module_path"]
for o in m["objects"]:
    o["path"] = prefix + o["path"]
json.dump(m, open(outp, "w"))
PY

echo "=== measure privileges: unprivileged profile attempt ==="
set +e
UNPRIV_OUT=$(./target/release/p11scope profile --manifest "$WORK/manifest-host.json" \
    --provenance-module "$PROVENANCE_MODULE" --cgroup "$POD_CG" \
    --mode metrics --duration 1 2>&1)
UNPRIV_RC=$?
set -e
echo "$UNPRIV_OUT"
echo "unprivileged exit code: $UNPRIV_RC"
if [ "$UNPRIV_RC" -eq 0 ]; then
    echo "expected unprivileged profile to fail, but it exited 0"
    exit 1
fi
echo "$UNPRIV_OUT" | grep -q "Permission denied" \
    || { echo "expected 'Permission denied' in unprivileged failure text"; exit 1; }
echo "measured: unprivileged run fails identifying /proc/<pid>/root/... (EACCES) before BPF is even touched"

echo "=== observe: attach-before-run against the pod, scoped to the POD-level cgroup ==="
stage_trusted_p11scope target/release/p11scope \
    target/release/p11scope-discover "$TRUST_DIR"
sudo "$TRUST_DIR/p11scope" profile \
    --manifest "$WORK/manifest-host.json" --cgroup "$POD_CG" \
    --provenance-module "$PROVENANCE_MODULE" \
    --mode metrics --duration 20 -o "$WORK/observed.json" \
    > "$WORK/profile.log" 2>&1 &
SPID=$!
sleep 3            # let attach complete
kubectl exec "$POD" -- /usr/local/bin/harness "$MODULE_IN_POD"
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "pod profiler failed: $status"; tail -n 20 "$WORK/profile.log"; exit "$status"; fi
tail -n 15 "$WORK/profile.log"

echo "=== verify against spike/expected.txt ==="
python3 - "$WORK/observed.json" spike/expected.txt <<'PY'
import json, sys
obs = json.load(open(sys.argv[1]))
counts = {}
for f in obs["functions"]:
    for n in f["names"]:
        counts[n] = counts.get(n, 0) + f["calls"]
fail = 0
for line in open(sys.argv[2]):
    name, want = line.split()
    got = counts.get(name, 0)
    if got != int(want):
        print(f"MISMATCH {name}: want {want}, got {got}")
        fail = 1
    else:
        print(f"ok {name}: {got}")
ev = obs["evidence"]
print("evidence:", ev["attached_probes"], "probes,", ev["completeness"])
if ev["attached_probes"] == 0:
    print("no probes attached")
    fail = 1
if ev["completeness"] != "COMPLETE":
    print(f"completeness: want COMPLETE, got {ev['completeness']!r}")
    fail = 1
sys.exit(fail)
PY

FAILED=0
echo "=== kind pod: ALL OK ==="

#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Task 6: capture a deterministic SoftHSM workload in one kind pod.
#
# Manifest-free: nothing is copied out of the pod. The observer runs on the node,
# scans the pod process's memory and opens its provider through /proc/<pid>/root.
#
# P11SCOPE_BIN=/abs/p11scope reuses a prebuilt product instead of building one.
# P11SCOPE_KIND_CLUSTER=<name> reuses an existing kind cluster: the lane then
# creates only its own namespace, pod and node image, and removes exactly those.
# Without it the lane creates and deletes a private cluster. The work directory
# is a fresh private temporary directory, because the observer refuses `-o`
# below a group-writable checkout.
set -eu
cd "$(dirname "$0")/../.."

MODULE_IN_POD=/usr/lib/softhsm/libsofthsm2.so
TOKEN=$(date +%s%N)-$$
WORK=
PRODUCT=target/matrix-product
IMAGE="p11scope-matrix-k8s:$TOKEN"
CLUSTER=${P11SCOPE_KIND_CLUSTER:-"p11scope-matrix-$TOKEN"}
NAMESPACE="p11scope-matrix-$TOKEN"
POD="p11scope-matrix-pod-$TOKEN"
KUBECONFIG=
export KUBECONFIG
SPID=
WPID=
SUPERVISOR_PID=
SUPERVISOR_STARTTIME=
ROOT_LAUNCH_PID=
ROOT_PROCESS_PID=
ROOT_PROCESS_STARTTIME=
CLUSTER_CREATED=
NAMESPACE_CREATED=
NODE_IMAGE_LOADED=
IMAGE_CREATED=
. scripts/lib.sh
. scripts/matrix/matrix-lib.sh
require_non_root_caller

# Only for a reused cluster: the image this run loaded into each node.
remove_node_images() {
    rni_status=0
    for rni_node in $(kind get nodes --name "$CLUSTER"); do
        timeout --signal=TERM --kill-after=5s 60s docker exec "$rni_node" \
            crictl rmi "docker.io/library/$IMAGE" >/dev/null || rni_status=1
    done
    return "$rni_status"
}

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    launcher=${SPID:-$ROOT_LAUNCH_PID}
    recorded_pid=${SUPERVISOR_PID:-$ROOT_PROCESS_PID}
    recorded_starttime=${SUPERVISOR_STARTTIME:-$ROOT_PROCESS_STARTTIME}
    if [ -n "$launcher" ]; then
        if [ -n "$recorded_pid" ] && [ -n "$recorded_starttime" ]; then
            cleanup_step signal_verified_root_process TERM \
                "$recorded_pid" "$recorded_starttime"
        else
            kill "$launcher" 2>/dev/null || true
        fi
        cleanup_step wait "$launcher"
    fi
    [ -z "$WPID" ] || cleanup_step wait "$WPID"
    if [ -n "$CLUSTER_CREATED" ]; then
        cleanup_step timeout --signal=TERM --kill-after=5s 120s \
            kind delete cluster --name "$CLUSTER"
    else
        # A reused cluster keeps everything this run did not create.
        [ -z "$NAMESPACE_CREATED" ] || cleanup_step timeout --signal=TERM --kill-after=5s 180s \
            kubectl delete namespace "$NAMESPACE" --wait=true --timeout=150s
        [ -z "$NODE_IMAGE_LOADED" ] || cleanup_step remove_node_images
    fi
    [ -z "$IMAGE_CREATED" ] || cleanup_step timeout --signal=TERM --kill-after=5s 30s \
        docker image rm -f "$IMAGE"
    [ -z "$KUBECONFIG" ] || cleanup_step rm -f -- "$KUBECONFIG"
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

for command in cargo docker gcc kind kubectl python3 timeout; do
    command -v "$command" >/dev/null || { echo "$command required" >&2; exit 1; }
done
echo "=== build product, workload, and unique pod image ==="
if ! matrix_prebuilt_product; then
    timeout --signal=TERM --kill-after=5s 600s scripts/cargo.sh +1.88 build --locked --release \
        --workspace --target-dir "$PRODUCT"
    P11SCOPE_EXE=$PRODUCT/release/p11scope
fi
matrix_report_product
sudo -n true 2>/dev/null || { echo "passwordless sudo required" >&2; exit 1; }
matrix_private_work kind
KUBECONFIG="$WORK/kubeconfig"
mkdir -p "$WORK/build"
IMAGE_CREATED=1
timeout --signal=TERM --kill-after=5s 60s gcc -O0 -o "$WORK/build/harness" \
    spike/harness.c -ldl
timeout --signal=TERM --kill-after=5s 600s docker build -q -t "$IMAGE" \
    ${P11SCOPE_MATRIX_BUILD_NETWORK:+--network "$P11SCOPE_MATRIX_BUILD_NETWORK"} \
    -f scripts/matrix/Dockerfile.kind "$WORK" >/dev/null

rm -f "$KUBECONFIG"
if [ -n "${P11SCOPE_KIND_CLUSTER-}" ]; then
    echo "=== reuse kind cluster $CLUSTER: private namespace and pod ==="
    kind get clusters | grep -Fqx "$CLUSTER" \
        || { echo "kind cluster $CLUSTER does not exist" >&2; exit 1; }
    timeout --signal=TERM --kill-after=5s 60s \
        kind get kubeconfig --name "$CLUSTER" > "$KUBECONFIG"
else
    echo "=== create isolated kind cluster and pod ==="
    CLUSTER_CREATED=1
    timeout --signal=TERM --kill-after=5s 300s kind create cluster --name "$CLUSTER" \
        --kubeconfig "$KUBECONFIG"
fi
timeout --signal=TERM --kill-after=5s 60s \
    kubectl config use-context "kind-$CLUSTER" >/dev/null
timeout --signal=TERM --kill-after=5s 180s kubectl wait --for=condition=Ready \
    node --all --timeout=120s
NODE_IMAGE_LOADED=1
timeout --signal=TERM --kill-after=5s 300s kind load docker-image "$IMAGE" --name "$CLUSTER"
NAMESPACE_CREATED=1
timeout --signal=TERM --kill-after=5s 60s kubectl create namespace "$NAMESPACE" >/dev/null
timeout --signal=TERM --kill-after=5s 60s \
    kubectl config set-context --current --namespace="$NAMESPACE" >/dev/null
cat > "$WORK/pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD
  namespace: $NAMESPACE
spec:
  containers:
  - name: workload
    image: $IMAGE
    imagePullPolicy: Never
    command: ["sleep", "infinity"]
  restartPolicy: Never
EOF
timeout --signal=TERM --kill-after=5s 60s kubectl apply -f "$WORK/pod.yaml"
timeout --signal=TERM --kill-after=5s 90s kubectl wait --for=condition=Ready \
    "pod/$POD" --timeout=60s

echo "=== resolve pod cgroup and host pid ==="
CID=$(timeout --signal=TERM --kill-after=5s 60s kubectl get pod "$POD" \
    -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's#containerd://##')
case $CID in ''|*[!0-9a-f]*) echo "pod container id invalid" >&2; exit 1 ;; esac
CONTAINER_CG=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    find /sys/fs/cgroup -type d -name "cri-containerd-${CID}.scope" \
    -print -quit 2>/dev/null)
test -n "$CONTAINER_CG" || { echo "pod cgroup missing" >&2; exit 1; }
POD_CG=$(dirname "$CONTAINER_CG")
HOSTPID=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    awk 'NR == 1 { print; exit }' "$CONTAINER_CG/cgroup.procs")
case $HOSTPID in ''|*[!0-9]*) echo "pod host pid missing" >&2; exit 1 ;; esac

echo "=== start the pod workload: it maps the provider, then waits ==="
# The scan runs once, at attach time, so the provider must already be mapped;
# harness dlopens it and only then blocks on the go-file, so attach-before-run
# still holds for every PKCS#11 call the oracle counts.
timeout --signal=TERM --kill-after=5s 60s kubectl exec "$POD" -- rm -f /tmp/go
timeout --signal=TERM --kill-after=5s 90s kubectl exec "$POD" -- \
    /usr/local/bin/harness "$MODULE_IN_POD" /tmp/go > "$WORK/workload.log" 2>&1 &
WPID=$!
wait_for_cgroup_provider "$POD_CG" libsofthsm2.so

echo "=== unprivileged diagnostic: the container provider must be unreadable without privileges ==="
set +e
DOCTOR_OUT=$(timeout --signal=TERM --kill-after=5s 60s \
    "$P11SCOPE_EXE" doctor --pid "$MAPPED_PROVIDER_PID" 2>&1)
DOCTOR_RC=$?
set -e
printf '%s\n' "$DOCTOR_OUT"
[ "$DOCTOR_RC" -ne 0 ] || { echo "unprivileged doctor unexpectedly succeeded" >&2; exit 1; }
printf '%s\n' "$DOCTOR_OUT" | grep -Eq \
    "/proc/$MAPPED_PROVIDER_PID/maps +\\.+ +FAIL +EACCES — module discovery unavailable" \
    || { echo "doctor did not surface the target module-discovery denial" >&2; exit 1; }
printf '%s\n' "$DOCTOR_OUT" \
    | grep -Fq "/proc/$MAPPED_PROVIDER_PID/mem" \
    || { echo "doctor did not diagnose the mapped provider process" >&2; exit 1; }
printf '%s\n' "$DOCTOR_OUT" | grep -Eq 'FAIL +EACCES — memory scan unavailable' \
    || { echo "doctor did not surface the target memory-scan denial" >&2; exit 1; }
set +e
UNPRIV_OUT=$(timeout --signal=TERM --kill-after=5s 60s \
    "$P11SCOPE_EXE" profile \
    --cgroup "$POD_CG" --mode metrics --duration 1 2>&1)
UNPRIV_RC=$?
set -e
echo "$UNPRIV_OUT"
[ "$UNPRIV_RC" -ne 0 ] || { echo "unprivileged profile unexpectedly succeeded" >&2; exit 1; }
printf '%s\n' "$UNPRIV_OUT" | is_linux_permission_denial \
    || { echo "unprivileged profile did not fail closed" >&2; exit 1; }

echo "=== attach before the pod workload makes a single call ==="
set -- python3 -I "$MATRIX_PTY" timeout --signal=TERM --kill-after=5s 45s \
    "$P11SCOPE_EXE" profile \
    --cgroup "$POD_CG" \
    --mode metrics --duration 20 -o "$WORK/observed.json"
launch_root_recorded_process "$WORK/observer.pid" "$WORK/profile.log" "$@"
SPID=$ROOT_LAUNCH_PID
SUPERVISOR_PID=$ROOT_PROCESS_PID
SUPERVISOR_STARTTIME=$ROOT_PROCESS_STARTTIME
wait_for_capture_ready "$WORK/profile.log" aggregate-only metrics
# Release the workload from the node, through the harness's own mount view.
# `kubectl exec ... touch` would start a short-lived process inside the pod
# cgroup during the capture; live discovery must then account for a process
# that may exit before its mappings can be read, which the capture honestly
# reports as a discovery loss. The docker lanes release their workload from
# the host the same way (a bind-mounted go-file).
sudo -n touch "/proc/$MAPPED_PROVIDER_PID/root/tmp/go"
if wait "$WPID"; then
    WPID=
else
    status=$?
    WPID=
    echo "pod workload failed: $status" >&2
    cat "$WORK/workload.log" >&2 || true
    exit "$status"
fi
if wait "$SPID"; then
    SPID=
    SUPERVISOR_PID=
    SUPERVISOR_STARTTIME=
    ROOT_LAUNCH_PID=
    ROOT_PROCESS_PID=
    ROOT_PROCESS_STARTTIME=
else
    status=$?
    SPID=
    SUPERVISOR_PID=
    SUPERVISOR_STARTTIME=
    ROOT_LAUNCH_PID=
    ROOT_PROCESS_PID=
    ROOT_PROCESS_STARTTIME=
    tail -n 20 "$WORK/profile.log" || true
    exit "$status"
fi
reclaim_root_output "$WORK/observed.json"
python3 scripts/check-capture-evidence.py clean-metrics \
    "$WORK/observed.json" spike/expected.txt
python3 -I scripts/matrix/check-count-multiset.py "$WORK/observed.json" spike/expected.txt
python3 - "$WORK/observed.json" <<'KIND'
import json, sys
doc = json.load(open(sys.argv[1]))
ev = doc["evidence"]
assert [m["sources"] for m in ev["discovery"]] == [["scan"]], ev["discovery"]
assert ev["scan_unavailable"] is None, ev["scan_unavailable"]
module = doc["capture"]["modules"][0]
assert module["path"].endswith("libsofthsm2.so"), module
print("pod provider pinned from the node:", module["path"], module["dev"], module["ino"])
print("identity_source:", [o["identity_source"] for o in ev["discovery"][0]["objects"]])
KIND

echo "=== kind pod: ALL OK ==="

#!/bin/sh
# Task 6: capture a deterministic SoftHSM workload in one kind pod.
set -eu
cd "$(dirname "$0")/../.."

MODULE_IN_POD=/usr/lib/softhsm/libsofthsm2.so
TOKEN=$(date +%s%N)-$$
WORK="target/matrix-kind/$TOKEN"
PRODUCT=target/matrix-product
IMAGE="p11scope-matrix-k8s:$TOKEN"
CLUSTER="p11scope-matrix-$TOKEN"
POD="p11scope-matrix-pod-$TOKEN"
KUBECONFIG="$PWD/$WORK/kubeconfig"
export KUBECONFIG
SPID=
SUPERVISOR_PID=
SUPERVISOR_STARTTIME=
ROOT_LAUNCH_PID=
ROOT_PROCESS_PID=
ROOT_PROCESS_STARTTIME=
CLUSTER_CREATED=
IMAGE_CREATED=
. scripts/lib.sh
require_non_root_caller

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
    [ -z "$CLUSTER_CREATED" ] || cleanup_step timeout --signal=TERM --kill-after=5s 120s \
        kind delete cluster --name "$CLUSTER"
    [ -z "$IMAGE_CREATED" ] || cleanup_step timeout --signal=TERM --kill-after=5s 30s \
        docker image rm -f "$IMAGE"
    cleanup_step rm -f -- "$KUBECONFIG"
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

for command in cargo docker gcc kind kubectl python3 tar timeout; do
    command -v "$command" >/dev/null || { echo "$command required" >&2; exit 1; }
done
sudo -n true 2>/dev/null || { echo "passwordless sudo required" >&2; exit 1; }

echo "=== build product, workload, and unique pod image ==="
mkdir -p "$WORK"
rm -rf "$WORK/build" "$WORK/provider-safe"
timeout --signal=TERM --kill-after=5s 600s cargo +1.88 build --locked --release \
    --workspace --target-dir "$PRODUCT"
mkdir -p "$WORK/build" "$WORK/provider-safe"
IMAGE_CREATED=1
timeout --signal=TERM --kill-after=5s 60s gcc -O0 -o "$WORK/build/harness" \
    spike/harness.c -ldl
timeout --signal=TERM --kill-after=5s 600s docker build -q -t "$IMAGE" \
    -f scripts/matrix/Dockerfile.kind "$WORK" >/dev/null

echo "=== create isolated kind cluster and pod ==="
rm -f "$KUBECONFIG"
CLUSTER_CREATED=1
timeout --signal=TERM --kill-after=5s 300s kind create cluster --name "$CLUSTER" \
    --kubeconfig "$KUBECONFIG"
timeout --signal=TERM --kill-after=5s 60s \
    kubectl config use-context "kind-$CLUSTER" >/dev/null
timeout --signal=TERM --kill-after=5s 180s kubectl wait --for=condition=Ready \
    node --all --timeout=120s
timeout --signal=TERM --kill-after=5s 300s kind load docker-image "$IMAGE" --name "$CLUSTER"
cat > "$WORK/pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD
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

echo "=== resolve pod authority and copy the provider directory as regular files ==="
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

PROVIDER_REAL=$(timeout --signal=TERM --kill-after=5s 60s kubectl exec "$POD" -- \
    readlink -f "$MODULE_IN_POD")
PROVIDER_DIR=${PROVIDER_REAL%/*}
PROVIDER_NAME=${PROVIDER_REAL##*/}
capped_container_tar "$WORK/provider.tar" \
    timeout --signal=TERM --kill-after=5s 60s kubectl exec "$POD" -- \
    tar -chC "$PROVIDER_DIR" .
tar -xf "$WORK/provider.tar" -C "$WORK/provider-safe"

echo "=== host-generate manifest v4 against the pod's mount namespace ==="
discover_copied_provider "$PWD/$WORK/provider-safe" "$PROVIDER_NAME" \
    "$PRODUCT/release/p11scope-discover" "/proc/$HOSTPID/root$PROVIDER_DIR" \
    "$WORK/manifest-host.json"

echo "=== unprivileged diagnostic: the container provider must be unreadable without privileges ==="
set +e
UNPRIV_OUT=$(timeout --signal=TERM --kill-after=5s 60s \
    "$PRODUCT/release/p11scope" profile \
    --manifest "$WORK/manifest-host.json" \
    --cgroup "$POD_CG" --mode metrics --duration 1 2>&1)
UNPRIV_RC=$?
set -e
echo "$UNPRIV_OUT"
[ "$UNPRIV_RC" -ne 0 ] || { echo "unprivileged profile unexpectedly succeeded" >&2; exit 1; }
printf '%s\n' "$UNPRIV_OUT" | grep -Fq 'cannot open the file now (open failed: Permission denied' \
    || { echo "unprivileged run failed for an unexpected reason" >&2; exit 1; }

echo "=== attach before running the pod workload ==="
set -- timeout --signal=TERM --kill-after=5s 45s \
    "$PRODUCT/release/p11scope" profile --manifest "$WORK/manifest-host.json" \
    --cgroup "$POD_CG" \
    --mode metrics --duration 20 -o "$WORK/observed.json"
launch_root_recorded_process "$WORK/observer.pid" "$WORK/profile.log" "$@"
SPID=$ROOT_LAUNCH_PID
SUPERVISOR_PID=$ROOT_PROCESS_PID
SUPERVISOR_STARTTIME=$ROOT_PROCESS_STARTTIME
wait_for_capture_ready "$WORK/profile.log" aggregate-only metrics
timeout --signal=TERM --kill-after=5s 60s kubectl exec "$POD" -- \
    /usr/local/bin/harness "$PROVIDER_REAL"
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

echo "=== kind pod: ALL OK ==="

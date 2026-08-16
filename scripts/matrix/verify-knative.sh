#!/bin/sh
# Task 6: attach before a Knative scale-from-zero pod exists.
set -eu
cd "$(dirname "$0")/../.."

MODULE_IN_POD=/usr/lib/softhsm/libsofthsm2.so
TOKEN=$(date +%s%N)-$$
WORK="target/matrix-knative/$TOKEN"
PRODUCT=target/matrix-product
IMAGE="kind.local/p11scope-matrix-knative:$TOKEN"
CLUSTER="p11scope-knative-$TOKEN"
KSVC="p11scope-ksvc-$TOKEN"
ANCHOR="p11scope-anchor-$TOKEN"
KNATIVE_VERSION=knative-v1.23.0
KUBECONFIG="$PWD/$WORK/kubeconfig"
export KUBECONFIG
SPID=
SUPERVISOR_PID=
SUPERVISOR_STARTTIME=
ROOT_LAUNCH_PID=
ROOT_PROCESS_PID=
ROOT_PROCESS_STARTTIME=
PF_PID=
CLUSTER_CREATED=
IMAGE_CREATED=
. scripts/lib.sh
require_non_root_caller

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    if [ -n "$PF_PID" ]; then
        kill "$PF_PID" 2>/dev/null || true
        wait "$PF_PID" 2>/dev/null || true
    fi
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

for command in cargo curl docker gcc kind kubectl python3 tar timeout; do
    command -v "$command" >/dev/null || { echo "$command required" >&2; exit 1; }
done
sudo -n true 2>/dev/null || { echo "passwordless sudo required" >&2; exit 1; }

echo "=== build product and unique Knative workload image ==="
mkdir -p "$WORK"
rm -rf "$WORK/build" "$WORK/provider-safe"
timeout --signal=TERM --kill-after=5s 600s cargo +1.88 build --locked --release \
    --workspace --target-dir "$PRODUCT"
mkdir -p "$WORK/build" "$WORK/provider-safe"
timeout --signal=TERM --kill-after=5s 60s gcc -O0 -o "$WORK/build/harness" \
    spike/harness.c -ldl
cp scripts/matrix/knative-server.py "$WORK/build/knative-server.py"
IMAGE_CREATED=1
timeout --signal=TERM --kill-after=5s 600s docker build -q -t "$IMAGE" \
    -f scripts/matrix/Dockerfile.knative "$WORK" >/dev/null

echo "=== create isolated kind cluster and install Knative ==="
rm -f "$KUBECONFIG"
CLUSTER_CREATED=1
timeout --signal=TERM --kill-after=5s 300s kind create cluster --name "$CLUSTER" \
    --kubeconfig "$KUBECONFIG"
timeout --signal=TERM --kill-after=5s 60s \
    kubectl config use-context "kind-$CLUSTER" >/dev/null
timeout --signal=TERM --kill-after=5s 180s kubectl wait --for=condition=Ready \
    node --all --timeout=120s
timeout --signal=TERM --kill-after=5s 300s kind load docker-image "$IMAGE" --name "$CLUSTER"
timeout --signal=TERM --kill-after=5s 210s kubectl apply \
    -f "https://github.com/knative/serving/releases/download/${KNATIVE_VERSION}/serving-crds.yaml"
timeout --signal=TERM --kill-after=5s 210s kubectl apply \
    -f "https://github.com/knative/serving/releases/download/${KNATIVE_VERSION}/serving-core.yaml"
timeout --signal=TERM --kill-after=5s 210s kubectl apply \
    -f "https://github.com/knative/net-kourier/releases/download/${KNATIVE_VERSION}/kourier.yaml"
timeout --signal=TERM --kill-after=5s 60s kubectl patch \
    configmap/config-network -n knative-serving --type merge \
    -p '{"data":{"ingress-class":"kourier.ingress.networking.knative.dev"}}'
for deployment in controller webhook net-kourier-controller activator autoscaler; do
    timeout --signal=TERM --kill-after=5s 60s \
        kubectl get deployment "$deployment" -n knative-serving \
        >/dev/null 2>&1 || continue
    container=$(timeout --signal=TERM --kill-after=5s 60s \
        kubectl get deployment "$deployment" -n knative-serving \
        -o jsonpath='{.spec.template.spec.containers[0].name}')
    timeout --signal=TERM --kill-after=5s 60s kubectl set env \
        deployment/"$deployment" -n knative-serving -c "$container" \
        KUBERNETES_MIN_VERSION=1.33.0 >/dev/null
done
timeout --signal=TERM --kill-after=5s 210s kubectl wait --for=condition=Available \
    deployment --all -n knative-serving --timeout=180s
timeout --signal=TERM --kill-after=5s 210s kubectl wait --for=condition=Available \
    deployment --all -n kourier-system --timeout=180s

echo "=== retain one same-image anchor for mount and inode authority ==="
cat > "$WORK/anchor.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $ANCHOR
spec:
  containers:
  - name: anchor
    image: $IMAGE
    imagePullPolicy: Never
    command: ["sleep", "infinity"]
  restartPolicy: Never
EOF
timeout --signal=TERM --kill-after=5s 60s kubectl apply -f "$WORK/anchor.yaml"
timeout --signal=TERM --kill-after=5s 90s kubectl wait --for=condition=Ready \
    "pod/$ANCHOR" --timeout=60s
ANCHOR_CID=$(timeout --signal=TERM --kill-after=5s 60s kubectl get pod "$ANCHOR" \
    -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's#containerd://##')
case $ANCHOR_CID in ''|*[!0-9a-f]*) echo "anchor container id invalid" >&2; exit 1 ;; esac
ANCHOR_CG=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    find /sys/fs/cgroup -type d -name "cri-containerd-${ANCHOR_CID}.scope" \
    -print -quit 2>/dev/null)
test -n "$ANCHOR_CG" || { echo "anchor cgroup missing" >&2; exit 1; }
ANCHOR_PID=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    awk 'NR == 1 { print; exit }' "$ANCHOR_CG/cgroup.procs")
case $ANCHOR_PID in ''|*[!0-9]*) echo "anchor host pid missing" >&2; exit 1 ;; esac
KUBEPODS=
ancestor=$ANCHOR_CG
while [ "$ancestor" != /sys/fs/cgroup ]; do
    case ${ancestor##*/} in *kubepods*.slice|kubepods) KUBEPODS=$ancestor ;; esac
    ancestor=${ancestor%/*}
done
test -n "$KUBEPODS" || { echo "stable kubepods cgroup missing" >&2; exit 1; }

PROVIDER_REAL=$(timeout --signal=TERM --kill-after=5s 60s kubectl exec "$ANCHOR" -- \
    readlink -f "$MODULE_IN_POD")
PROVIDER_DIR=${PROVIDER_REAL%/*}
PROVIDER_NAME=${PROVIDER_REAL##*/}
capped_container_tar "$WORK/provider.tar" \
    timeout --signal=TERM --kill-after=5s 60s kubectl exec "$ANCHOR" -- \
    tar -chC "$PROVIDER_DIR" .
tar -xf "$WORK/provider.tar" -C "$WORK/provider-safe"
discover_copied_provider "$PWD/$WORK/provider-safe" "$PROVIDER_NAME" \
    "$PRODUCT/release/p11scope-discover" "/proc/$ANCHOR_PID/root$PROVIDER_DIR" \
    "$WORK/manifest-host.json"

echo "=== deploy service, then prove its initial pod scaled to zero ==="
cat > "$WORK/ksvc.yaml" <<EOF
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: $KSVC
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/min-scale: "0"
        autoscaling.knative.dev/max-scale: "1"
    spec:
      timeoutSeconds: 10
      containerConcurrency: 1
      containers:
      - image: $IMAGE
        imagePullPolicy: Never
        ports:
        - containerPort: 8080
EOF
timeout --signal=TERM --kill-after=5s 60s kubectl apply -f "$WORK/ksvc.yaml"
timeout --signal=TERM --kill-after=5s 210s kubectl wait --for=condition=Ready \
    "ksvc/$KSVC" --timeout=180s
HOST=$(timeout --signal=TERM --kill-after=5s 60s \
    kubectl get ksvc "$KSVC" -o jsonpath='{.status.url}' | sed 's#http://##')
service_pod_count() {
    service_pods=$(timeout --signal=TERM --kill-after=1s 5s kubectl get pods \
        -l "serving.knative.dev/service=$KSVC" -o name) || return
    set -- $service_pods
    printf '%s\n' "$#"
}
attempt=0
while [ "$attempt" -lt 36 ]; do
    SERVICE_PODS=$(service_pod_count)
    [ "$SERVICE_PODS" -eq 0 ] && break
    attempt=$((attempt + 1))
    sleep 5
done
[ "$SERVICE_PODS" -eq 0 ] || { echo "service did not scale to zero" >&2; exit 1; }

echo "=== unprivileged diagnostic: the container provider must be unreadable without privileges ==="
set +e
UNPRIV_OUT=$(timeout --signal=TERM --kill-after=5s 60s \
    "$PRODUCT/release/p11scope" profile \
    --manifest "$WORK/manifest-host.json" \
    --cgroup "$KUBEPODS" --mode metrics --duration 1 2>&1)
UNPRIV_RC=$?
set -e
echo "$UNPRIV_OUT"
[ "$UNPRIV_RC" -ne 0 ] || { echo "unprivileged profile unexpectedly succeeded" >&2; exit 1; }
printf '%s\n' "$UNPRIV_OUT" | grep -Fq 'cannot open the file now (open failed: Permission denied' \
    || { echo "unprivileged run failed for an unexpected reason" >&2; exit 1; }

echo "=== attach before the cold-start pod exists ==="
SERVICE_PODS=$(service_pod_count)
[ "$SERVICE_PODS" -eq 0 ] || { echo "service pods appeared before attach" >&2; exit 1; }
set -- timeout --signal=TERM --kill-after=5s 70s \
    "$PRODUCT/release/p11scope" profile --manifest "$WORK/manifest-host.json" \
    --cgroup "$KUBEPODS" \
    --mode metrics --duration 40 -o "$WORK/observed.json"
launch_root_recorded_process "$WORK/observer.pid" "$WORK/profile.log" "$@"
SPID=$ROOT_LAUNCH_PID
SUPERVISOR_PID=$ROOT_PROCESS_PID
SUPERVISOR_STARTTIME=$ROOT_PROCESS_STARTTIME
wait_for_capture_ready "$WORK/profile.log" aggregate-only metrics
SERVICE_PODS=$(service_pod_count)
[ "$SERVICE_PODS" -eq 0 ] \
    || { echo "service pods appeared after attach readiness" >&2; exit 1; }
ATTACH_READY=$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat())')

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
timeout --signal=TERM --kill-after=5s 70s \
    kubectl port-forward -n kourier-system svc/kourier-internal "$PORT:80" \
    > "$WORK/portforward.log" 2>&1 &
PF_PID=$!
port_attempt=0
while [ "$port_attempt" -lt 600 ]; do
    python3 -c 'import socket,sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1).close()' \
        "$PORT" 2>/dev/null && break
    kill -0 "$PF_PID" 2>/dev/null || { echo "port-forward exited" >&2; exit 1; }
    port_attempt=$((port_attempt + 1))
    sleep 0.05
done
[ "$port_attempt" -lt 600 ] || { echo "port-forward was not ready" >&2; exit 1; }
curl -fsS -H "Host: $HOST" "http://127.0.0.1:$PORT/" --max-time 60
kill "$PF_PID" 2>/dev/null || true
if wait "$PF_PID"; then PF_PID=; else PF_PID=; fi

echo "=== prove the cold pod postdates attach and shares the attached inode ==="
NEWPOD=$(timeout --signal=TERM --kill-after=5s 60s kubectl get pods \
    -l "serving.knative.dev/service=$KSVC" \
    --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')
test -n "$NEWPOD" || { echo "cold pod missing" >&2; exit 1; }
NEWPOD_TS=$(timeout --signal=TERM --kill-after=5s 60s \
    kubectl get pod "$NEWPOD" -o jsonpath='{.metadata.creationTimestamp}')
python3 - "$ATTACH_READY" "$NEWPOD_TS" <<'PY'
import datetime
import sys
# creationTimestamp has whole-second resolution; the zero-pod check at
# readiness already proves the ordering, so compare at that resolution.
attach = datetime.datetime.fromisoformat(sys.argv[1]).replace(microsecond=0)
created = datetime.datetime.fromisoformat(sys.argv[2].replace("Z", "+00:00"))
if created < attach:
    raise SystemExit(f"cold pod did not postdate attach: created {created} < attach {attach}")
PY
NEW_CID=$(timeout --signal=TERM --kill-after=5s 60s kubectl get pod "$NEWPOD" \
    -o jsonpath='{.status.containerStatuses[?(@.name=="user-container")].containerID}' \
    | sed 's#containerd://##')
case $NEW_CID in ''|*[!0-9a-f]*) echo "cold container id invalid" >&2; exit 1 ;; esac
NEW_CG=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    find /sys/fs/cgroup -type d -name "cri-containerd-${NEW_CID}.scope" \
    -print -quit 2>/dev/null)
test -n "$NEW_CG" || { echo "cold pod cgroup missing" >&2; exit 1; }
NEW_PID=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    awk 'NR == 1 { print; exit }' "$NEW_CG/cgroup.procs")
case $NEW_PID in ''|*[!0-9]*) echo "cold pod host pid invalid" >&2; exit 1 ;; esac
ANCHOR_KEY=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    stat -Lc '%d:%i' "/proc/$ANCHOR_PID/root$PROVIDER_REAL")
NEW_KEY=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    stat -Lc '%d:%i' "/proc/$NEW_PID/root$PROVIDER_REAL")
ANCHOR_INODE=${ANCHOR_KEY#*:}
NEW_INODE=${NEW_KEY#*:}
[ "$ANCHOR_INODE" = "$NEW_INODE" ] \
    || { echo "cold pod provider inode differs" >&2; exit 1; }
echo "cold pod provider overlay inode: $NEW_INODE (host identities $ANCHOR_KEY vs $NEW_KEY)"

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

echo "=== knative scale-from-zero: ALL OK ==="

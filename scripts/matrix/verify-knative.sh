#!/bin/sh
# Phase 4 Task 5: Knative scale-from-zero capture. Installs Knative Serving
# on kind, deploys the deterministic workload (spike/harness.c, oracle
# spike/expected.txt) as a Knative Service, lets it scale to zero, then
# proves the observer can attach BEFORE the pod that will serve the
# cold-start request exists, and still capture that pod's calls exactly.
#
# THE HARD PART, solved here (read in full before touching this script):
#
# 1. Scope must be "stable ahead of pod existence". Kubernetes/kind give
#    no per-namespace or per-Service cgroup -- cgroups are created only
#    per-pod (see verify-kind-pod.sh's cgroup-path notes). The finest
#    cgroup that genuinely predates the not-yet-created pod is the node's
#    whole kubepods hierarchy root (kind's cgroupfs-driver equivalent:
#    .../kubelet.slice/kubelet-kubepods.slice, nested under the node's own
#    docker-<id>.scope), which exists as soon as kubelet starts (kube-system
#    pods are already under it). This is coarser than "the Service" -- an
#    honest limitation, not a chosen simplification, and documented as
#    such in docs/notes/phase4-matrix.md. Measured fact: the workload
#    pod's QoS class is Burstable (Knative's queue-proxy sidecar carries
#    resource requests), while a plain kubectl pod (verify-kind-pod.sh) is
#    BestEffort -- so even the QoS-level slice isn't a stable choice
#    across workload shapes; only the kubepods.slice root is.
#
# 2. The manifest's object path must be resolvable WITHOUT any live pod
#    pid, since none exists at attach time. `p11scope-discover --module`
#    takes a bare path (crates/discover/src/main.rs), no --pid, so the
#    Docker/kind-pod rows' trick of running it inside a live container
#    doesn't apply here -- there is no live container yet. The fix:
#    `kind load docker-image` unpacks the image's layers into containerd's
#    overlayfs snapshot store immediately, independent of any container
#    ever running from it (verified directly: searching
#    /var/lib/containerd/.../snapshots/*/fs for libsofthsm2.so succeeds
#    right after `kind load`, before any pod exists). That snapshot
#    directory is real, on-disk, host-reachable via
#    /proc/<node-container-host-pid>/root/... -- and the node container's
#    own host pid is stable for the cluster's whole lifetime (unlike a
#    pod's pid), so this path stays valid before, during, and after the
#    cold-start pod's life. This is the same "shared image layer" fact
#    Task 3 proved, used here for a temporal purpose instead of a
#    multi-container one.
#
# 3. Fresh provenance is mandatory even though no pod exists. The exact image
#    layer ELF is copied to an unprivileged safe path for discovery, while the
#    manifest's attach path is retargeted to the stable snapshot inode.
#    `--provenance-module` binds those two views by whole-file SHA-256 and every
#    function offset; a raw rewritten manifest is never trusted.
#
# 4. Knative's latest release (knative-v1.23.0) refuses to start against
#    kind's default node (Kubernetes 1.33.1): "kubernetes version 1.33.1
#    is not compatible, need at least 1.34.0-0" -- an artificial version
#    floor in knative.dev/pkg, officially overridable via the
#    KUBERNETES_MIN_VERSION env var (their own error message says so).
#    This script sets it on every affected Deployment after install.
#
# Cluster is torn down on success; left up (with the ksvc) for inspection
# on any failure.
set -eu
cd "$(dirname "$0")/../.."

WORK=target/matrix-knative
TRUST_DIR="$PWD/$WORK/trusted"
IMAGE_LOCAL=kind.local/p11scope-matrix-knative:latest
IMAGE_TAG=p11scope-matrix-knative
CLUSTER=p11scope-knative
KSVC=p11scope-matrix-ksvc
KNATIVE_VERSION=knative-v1.23.0
. scripts/trusted-p11scope.sh

command -v kind >/dev/null || { echo "kind required"; exit 1; }
command -v kubectl >/dev/null || { echo "kubectl required"; exit 1; }
command -v docker >/dev/null || { echo "docker required"; exit 1; }

CLUSTER_CREATED=0
FAILED=1
PF_PID=""
SPID=
cleanup() {
    [ -n "$PF_PID" ] && kill "$PF_PID" >/dev/null 2>&1 || true
    [ -z "$SPID" ] || kill "$SPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    if [ "$FAILED" -eq 0 ]; then
        kubectl delete ksvc "$KSVC" --wait=true --ignore-not-found >/dev/null 2>&1 || true
        if [ "$CLUSTER_CREATED" -eq 1 ]; then
            kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
        fi
    else
        echo "FAILED -- leaving cluster '$CLUSTER' and ksvc '$KSVC' up for inspection"
    fi
    remove_trusted_p11scope "$TRUST_DIR"
}
trap cleanup EXIT

echo "=== build product + workload image ==="
cargo build --release --workspace
mkdir -p "$WORK/build"
gcc -O0 -o "$WORK/build/harness" spike/harness.c -ldl
cp scripts/matrix/knative-server.py "$WORK/build/knative-server.py"
docker build -q -t "$IMAGE_TAG" -f scripts/matrix/Dockerfile.knative "$WORK" >/dev/null
docker tag "$IMAGE_TAG" "$IMAGE_LOCAL"

echo "=== create kind cluster ==="
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    echo "cluster '$CLUSTER' already exists, reusing"
else
    kind create cluster --name "$CLUSTER"
    CLUSTER_CREATED=1
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null
kubectl wait --for=condition=Ready node --all --timeout=120s

echo "=== load workload image into cluster ==="
kind load docker-image "$IMAGE_LOCAL" --name "$CLUSTER"

echo "=== install Knative Serving + Kourier ($KNATIVE_VERSION) ==="
kubectl apply -f "https://github.com/knative/serving/releases/download/${KNATIVE_VERSION}/serving-crds.yaml"
kubectl apply -f "https://github.com/knative/serving/releases/download/${KNATIVE_VERSION}/serving-core.yaml"
kubectl apply -f "https://github.com/knative/net-kourier/releases/download/${KNATIVE_VERSION}/kourier.yaml"
kubectl patch configmap/config-network -n knative-serving --type merge \
    -p '{"data":{"ingress-class":"kourier.ingress.networking.knative.dev"}}'

echo "=== override Knative's Kubernetes-version floor (see header, point 4) ==="
for d in controller webhook net-kourier-controller activator autoscaler; do
    kubectl get deployment "$d" -n knative-serving >/dev/null 2>&1 || continue
    cname=$(kubectl get deployment "$d" -n knative-serving -o jsonpath='{.spec.template.spec.containers[0].name}')
    kubectl set env deployment/"$d" -n knative-serving -c "$cname" KUBERNETES_MIN_VERSION=1.33.0 >/dev/null
done

echo "=== wait for Knative + Kourier to be ready ==="
kubectl wait --for=condition=Available deployment --all -n knative-serving --timeout=180s
kubectl wait --for=condition=Available deployment --all -n kourier-system --timeout=180s

echo "=== deploy the Knative Service ==="
kubectl delete ksvc "$KSVC" --wait=true --ignore-not-found >/dev/null 2>&1 || true
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
        autoscaling.knative.dev/scale-to-zero-grace-period: "30s"
    spec:
      containerConcurrency: 1
      containers:
      - image: $IMAGE_LOCAL
        imagePullPolicy: Never
        ports:
        - containerPort: 8080
EOF
kubectl apply -f "$WORK/ksvc.yaml"
kubectl wait --for=condition=Ready "ksvc/$KSVC" --timeout=180s
HOST=$(kubectl get ksvc "$KSVC" -o jsonpath='{.status.url}' | sed 's#http://##')
echo "ksvc host: $HOST"

echo "=== wait for scale-to-zero (the initial readiness-check pod must go away) ==="
i=0
while true
    do N=$(kubectl get pods -l "serving.knative.dev/service=$KSVC" --no-headers 2>/dev/null | grep -vc Terminating || true)
    echo "pod count: $N"
    [ "$N" -eq 0 ] && break
    i=$((i + 1))
    [ "$i" -ge 18 ] && { echo "gave up waiting for scale-to-zero"; exit 1; }
    sleep 10
done
echo "confirmed: zero pods for $KSVC before attach"

echo "=== resolve stable ancestor cgroup + locate the image layer on disk ==="
NODE="${CLUSTER}-control-plane"
NODE_CID=$(docker inspect -f '{{.Id}}' "$NODE")
NODEPID=$(docker inspect -f '{{.State.Pid}}' "$NODE")
KUBEPODS="/sys/fs/cgroup/system.slice/docker-${NODE_CID}.scope/kubelet.slice/kubelet-kubepods.slice"
test -d "$KUBEPODS" || { echo "stable ancestor cgroup missing: $KUBEPODS"; exit 1; }
echo "stable ancestor (--cgroup target, exists before any pod): $KUBEPODS"

CANDIDATES=$(sudo find "/proc/$NODEPID/root/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots" \
    -path '*/fs/usr/lib/softhsm/libsofthsm2.so' 2>/dev/null || true)
test -n "$CANDIDATES" || { echo "libsofthsm2.so not found in any containerd snapshot"; exit 1; }
# Highest snapshot id = most recently unpacked = this run's just-loaded image.
SNAP_PATH=$(echo "$CANDIDATES" | sed -E 's#.*/snapshots/([0-9]+)/fs/.*#\1 &#' | sort -n | tail -1 | cut -d' ' -f2-)
echo "provider file on the node's disk, reachable via the node's own long-lived pid: $SNAP_PATH"

echo "=== discover against the pre-existing image layer (no live pod needed) ==="
# Discovery cannot inherit the observer's root authority. Copy the exact ELF
# bytes into the user-owned work directory, discover there, then retarget the
# manifest to the verified snapshot inode used for attachment.
DISCOVERY_COPY="$PWD/$WORK/provider-discovery.so"
sudo cp "$SNAP_PATH" "$DISCOVERY_COPY"
sudo chown "$(id -u):$(id -g)" "$DISCOVERY_COPY"
./target/release/p11scope-discover --module "$DISCOVERY_COPY" -o "$WORK/manifest-raw.json"
BUILDID=$(sudo readelf -n "$SNAP_PATH" 2>/dev/null | grep "Build ID" | awk '{print $3}')
test -n "$BUILDID" || { echo "could not read build-id via readelf"; exit 1; }
echo "provider build-id (readelf, corroborating evidence -- see header point 3): $BUILDID"
python3 - "$WORK/manifest-raw.json" "$WORK/manifest-host.json" "$SNAP_PATH" "$BUILDID" <<'PY'
import json, sys
inp, outp, target, buildid = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
m = json.load(open(inp))
assert len(m["objects"]) == 1, "SoftHSM fixture unexpectedly spans multiple objects"
m["module_path"] = target
m["objects"][0]["path"] = target
assert m["objects"][0]["identity"]["value"] == buildid
json.dump(m, open(outp, "w"))
PY

echo "=== measure privileges: unprivileged profile attempt ==="
set +e
UNPRIV_OUT=$(./target/release/p11scope profile --manifest "$WORK/manifest-host.json" \
    --provenance-module "$DISCOVERY_COPY" --cgroup "$KUBEPODS" \
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

echo "=== ATTACH before the pod exists, then drive the cold-start request ==="
N=$(kubectl get pods -l "serving.knative.dev/service=$KSVC" --no-headers 2>/dev/null | grep -vc Terminating || true)
test "$N" -eq 0 || { echo "expected zero pods immediately before attach, got $N"; exit 1; }
ATTACH_START=$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat())')
echo "attach start (UTC): $ATTACH_START -- zero pods for $KSVC exist at this instant"

stage_trusted_p11scope target/release/p11scope \
    target/release/p11scope-discover "$TRUST_DIR"
sudo "$TRUST_DIR/p11scope" profile \
    --manifest "$WORK/manifest-host.json" --cgroup "$KUBEPODS" \
    --provenance-module "$DISCOVERY_COPY" \
    --mode metrics --duration 40 -o "$WORK/observed.json" \
    > "$WORK/profile.log" 2>&1 &
SPID=$!
sleep 5   # let attach complete before any pod can possibly exist

kubectl port-forward -n kourier-system svc/kourier-internal 18080:80 \
    > "$WORK/portforward.log" 2>&1 &
PF_PID=$!
sleep 3
echo "--- driving the request that forces the cold start ---"
curl -sS -H "Host: $HOST" "http://127.0.0.1:18080/" --max-time 60
echo
kill "$PF_PID" >/dev/null 2>&1 || true
PF_PID=""
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "Knative profiler failed: $status"; tail -n 20 "$WORK/profile.log"; exit "$status"; fi
tail -n 15 "$WORK/profile.log"

echo "=== verify: the new pod genuinely postdates attach start ==="
NEWPOD=$(kubectl get pods -l "serving.knative.dev/service=$KSVC" \
    --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')
NEWPOD_TS=$(kubectl get pod "$NEWPOD" -o jsonpath='{.metadata.creationTimestamp}')
echo "newest pod: $NEWPOD created at $NEWPOD_TS"
python3 - "$ATTACH_START" "$NEWPOD_TS" <<'PY'
import datetime, sys
attach = datetime.datetime.fromisoformat(sys.argv[1])
created = datetime.datetime.fromisoformat(sys.argv[2].replace("Z", "+00:00"))
print(f"attach start:   {attach.isoformat()}")
print(f"pod created at: {created.isoformat()}")
if created <= attach:
    print("FAIL: pod was created before (or at) attach start -- this would not prove scale-from-zero")
    sys.exit(1)
print(f"ok: pod created {(created - attach).total_seconds():.1f}s AFTER attach started")
PY

echo "=== record the new pod's cgroup path (informational) ==="
NEWCID=$(kubectl get pod "$NEWPOD" -o jsonpath='{.status.containerStatuses[?(@.name=="user-container")].containerID}' | sed 's#containerd://##')
NEWCG=$(sudo find /sys/fs/cgroup -type d -name "cri-containerd-${NEWCID}.scope" 2>/dev/null | head -n1)
echo "new pod's actual (leaf) cgroup: $NEWCG"

echo "=== verify captured counts against spike/expected.txt (one request == one oracle run) ==="
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
echo "=== knative scale-from-zero: ALL OK ==="

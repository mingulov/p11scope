#!/bin/sh
# Gate K1: the DaemonSet node observer captures a provider mapped in another
# pod, end to end, through the committed deploy/k8s manifests. Oracle: the
# capture JSON names libsofthsm2.so with attached probes and slots.
#
# Requires a kind cluster reachable by kubectl (guarded: refuses non-kind
# contexts unless P11SCOPE_K8S_ALLOW_CONTEXT=1), docker for the image build,
# and target/release/p11scope. Images load into every kind node container
# via ctr (no `kind load` dependency). Cleans up the namespace afterwards
# unless --keep.
set -eu
cd "$(dirname "$0")/.."

NS=${P11SCOPE_K8S_NAMESPACE:-p11scope}
WORK=${P11SCOPE_K8S_WORK:-target/k8s-e2e}
KEEP=0

assert_k8s_evidence() {
    python3 -I - "$@" <<'PY'
import copy
import json
import sys


def oracle(document):
    evidence = document["evidence"]
    assert evidence["authority"] == "hash-pinned", evidence["authority"]
    assert evidence["attached_probes"] > 0, evidence["attached_probes"]
    assert evidence["slots"] > 0, evidence["slots"]
    paths = [m["path"] for m in document["capture"]["modules"]]
    assert any(p.endswith("libsofthsm2.so") for p in paths), paths


def good():
    return {
        "evidence": {
            "authority": "hash-pinned",
            "attached_probes": 136,
            "slots": 68,
        },
        "capture": {"modules": [{"path": "/usr/lib/softhsm/libsofthsm2.so"}]},
    }


def mutate(document, path, value):
    mutated = copy.deepcopy(document)
    cursor = mutated
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return mutated


if sys.argv[1] == "--self-test":
    oracle(good())
    for label, path, value in [
        ("authority", ["evidence", "authority"], "unpinned"),
        ("attached", ["evidence", "attached_probes"], 0),
        ("slots", ["evidence", "slots"], 0),
        ("captured module", ["capture", "modules"], []),
    ]:
        try:
            oracle(mutate(good(), path, value))
        except (AssertionError, KeyError, IndexError):
            continue
        raise SystemExit(f"mutation accepted: {label}")
    print("k8s-e2e oracle mutations rejected: OK")
    raise SystemExit(0)

oracle(json.load(open(sys.argv[1])))
print("k8s capture: OK")
PY
}

usage() {
    echo "usage: $0 [--self-test] [--keep]" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --self-test)
            [ "$#" -eq 1 ] || usage
            assert_k8s_evidence --self-test
            echo "verify-k8s-attach self-test: OK"
            exit 0
            ;;
        --keep) KEEP=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

. scripts/lib.sh
require_non_root_caller
for command in kubectl docker python3; do
    command -v "$command" >/dev/null || { echo "$command required" >&2; exit 1; }
done
[ -x target/release/p11scope ] || {
    echo "target/release/p11scope is missing; build with: cargo +1.88 build --locked --release" >&2
    exit 1
}
kubectl cluster-info >/dev/null 2>&1 || { echo "no cluster reachable by kubectl" >&2; exit 1; }
CONTEXT=$(kubectl config current-context 2>/dev/null || true)
case $CONTEXT in
    kind-*) : ;;
    *)
        [ "${P11SCOPE_K8S_ALLOW_CONTEXT:-0}" = 1 ] || {
            echo "refusing non-kind context '$CONTEXT' (set P11SCOPE_K8S_ALLOW_CONTEXT=1 to override)" >&2
            exit 1
        } ;;
esac

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    if [ "$KEEP" -eq 0 ]; then
        kubectl delete namespace "$NS" --wait=false >/dev/null 2>&1 || true
    else
        echo "kept namespace $NS (--keep)" >&2
    fi
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

echo "=== build images (context: $CONTEXT) ==="
docker build -f deploy/Dockerfile.observer -t p11scope-observer:1 . || exit 1
docker build -f deploy/Dockerfile.holder -t p11scope-holder:1 . || exit 1

echo "=== load images into kind nodes ==="
NODES=$(docker ps --format '{{.Names}}' --filter "label=io.x-k8s.kind.cluster" 2>/dev/null || true)
[ -n "$NODES" ] || { echo "no kind node containers found" >&2; exit 1; }
echo "$NODES" | while read -r node; do
    [ -n "$node" ] || continue
    echo "--- $node"
    docker save p11scope-observer:1 p11scope-holder:1 \
        | docker exec -i "$node" ctr -n k8s.io images import - || exit 1
done

echo "=== apply manifests ==="
kubectl apply -f deploy/k8s/namespace.yaml \
    -f deploy/k8s/serviceaccount.yaml \
    -f deploy/k8s/rbac.yaml \
    -f deploy/k8s/daemonset.yaml \
    -f deploy/k8s/holder.yaml || exit 1
kubectl -n "$NS" wait --for=condition=ready pod \
    -l app.kubernetes.io/component=observer --timeout=180s || exit 1
kubectl -n "$NS" wait --for=condition=ready pod/p11scope-holder --timeout=180s || exit 1

echo "=== RBAC check (in-cluster identity resolves the holder) ==="
kubectl -n "$NS" auth can-i get pods \
    --as "system:serviceaccount:$NS:p11scope-observer" | grep -q '^yes' \
    || { echo "observer ServiceAccount cannot get pods" >&2; exit 1; }

echo "=== capture via the DaemonSet observer ==="
OBSERVER_POD=$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=observer \
    -o jsonpath='{.items[0].metadata.name}')
[ -n "$OBSERVER_POD" ] || { echo "no observer pod" >&2; exit 1; }
kubectl -n "$NS" exec "$OBSERVER_POD" -- k8s-profile-entry \
    --pod p11scope-holder --namespace "$NS" -- \
    --mode metrics --duration 15 -o /tmp/k8s-e2e.json || exit 1

echo "=== fetch + assert ==="
(umask 077; mkdir -p "$WORK")
kubectl -n "$NS" cp "$OBSERVER_POD:/tmp/k8s-e2e.json" "$WORK/capture.json" || exit 1
assert_k8s_evidence "$WORK/capture.json"

trap - EXIT INT TERM
if [ "$KEEP" -eq 0 ]; then
    kubectl delete namespace "$NS" --wait=true >/dev/null 2>&1 || true
else
    echo "kept namespace $NS (--keep)" >&2
fi
echo "=== k8s e2e: ALL OK ==="

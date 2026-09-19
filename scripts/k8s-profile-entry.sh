#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# In-cluster twin of scripts/attach-pod.sh: run INSIDE the p11scope-observer
# DaemonSet pod (via `kubectl exec`) to profile a target pod's cgroup.
# Resolves pod -> container id through the in-cluster API under the bound
# ServiceAccount (Role: pods get/list), locates the pod cgroup from the
# node view (/sys/fs/cgroup mount), and execs `p11scope profile --cgroup`.
set -eu

usage() {
    cat >&2 <<'EOF'
usage: k8s-profile-entry --pod NAME [--namespace NS] [--container NAME]
                         [--cid HEX64] [-- p11scope-args...]

  --pod NAME          target pod to observe (required unless --cid)
  --namespace NS      pod namespace (default: p11scope)
  --container NAME    container in the pod (default: the first one)
  --cid HEX64         skip API resolution with an explicit container id
  --                  everything after this is passed to `p11scope profile`
                      verbatim, e.g. -- --mode metrics --duration 30 -o out.json
EOF
    exit 2
}

NAMESPACE=p11scope
POD=
CONTAINER=
CID=
OBSERVER=${P11SCOPE_OBSERVER:-/usr/local/bin/p11scope}

valid_name() {
    case $1 in
        ''|*[!a-z0-9.-]*) return 1 ;;
        -*|.*|*-|*.) return 1 ;;
        *) [ "${#1}" -le 253 ] ;;
    esac
}

self_test() {
    for bad in "" "--pod" "--pod -bad" "--pod ok --namespace UPPER" \
               "--pod ok --container bad_name" "--pod ok --bogus" "--bogus" \
               "--cid xyz" "--cid gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"; do
        status=0
        # shellcheck disable=SC2086
        sh "$0" $bad >/dev/null 2>&1 || status=$?
        [ "$status" -eq 2 ] || {
            echo "k8s-profile-entry exited $status (want 2) for: [$bad]" >&2
            exit 1
        }
    done
    for name in ok my-pod pod.1 a; do
        valid_name "$name" || { echo "valid_name rejected $name" >&2; exit 1; }
    done
    for name in "" "-x" "x-" "Upper" "under_score" ".dot" "dot."; do
        if valid_name "$name"; then echo "valid_name accepted $name" >&2; exit 1; fi
    done
    # Pretty-printed API sample: statuses must parse across newlines and the
    # container id must stay paired with its container (not the pod name).
    POD_JSON='{
  "metadata": { "name": "p11scope-holder" },
  "status": {
    "containerStatuses": [
      {
        "containerID": "containerd://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "image": "p11scope-holder:1",
        "lastState": {},
        "name": "holder",
        "ready": true,
        "restartCount": 0,
        "started": true,
        "state": { "running": { "startedAt": "2026-09-15T07:50:52Z" } }
      },
      {
        "containerID": "containerd://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "name": "sidecar",
        "state": { "running": {} }
      }
    ]
  }
}'
    CONTAINER=
    extract_cid || { echo "extract_cid failed on sample" >&2; exit 1; }
    [ "$CONTAINER" = "holder" ] || { echo "default container wrong: $CONTAINER" >&2; exit 1; }
    [ "$CID" = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ] || {
        echo "default cid wrong: $CID" >&2; exit 1; }
    CONTAINER=sidecar
    extract_cid || { echo "extract_cid failed for sidecar" >&2; exit 1; }
    [ "$CID" = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ] || {
        echo "sidecar cid wrong: $CID" >&2; exit 1; }
    echo "k8s-profile-entry argument self-test: OK"
    exit 0
}

# Sets CONTAINER (default: first status entry) and CID from POD_JSON.
# containerID reads "<runtime>://<hex>"; nested state objects make shell
# pairing unreliable, so parse properly with jq (in the image, ~2 MB).
extract_cid() {
    command -v jq >/dev/null || { echo "jq required" >&2; return 1; }
    PAIR=$(printf '%s' "$POD_JSON" | jq -r --arg want "$CONTAINER" '
        .status.containerStatuses
        | if $want == "" then .[0]
          else map(select(.name == $want))[0] end
        | select(.) | "\(.name) \(.containerID)"') || return 1
    [ -n "$PAIR" ] && [ "$PAIR" != "null null" ] || {
        echo "no such container in pod $POD" >&2; return 1; }
    CONTAINER=${PAIR%% *}
    REF=${PAIR#* }
    case $REF in *://*) CID=${REF##*://} ;; *) echo "no container id for $CONTAINER in pod $POD" >&2; return 1 ;; esac
    case $CID in ''|*[!0-9a-f]*) echo "no container id for $CONTAINER in pod $POD" >&2; return 1 ;; esac
}

[ "${1-}" != "--self-test" ] || self_test

while [ "$#" -gt 0 ]; do
    case $1 in
        --namespace) [ "$#" -ge 2 ] || usage; NAMESPACE=$2; shift 2 ;;
        --pod) [ "$#" -ge 2 ] || usage; POD=$2; shift 2 ;;
        --container) [ "$#" -ge 2 ] || usage; CONTAINER=$2; shift 2 ;;
        --cid) [ "$#" -ge 2 ] || usage; CID=$2; shift 2 ;;
        --) shift; break ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

case $CID in
    '') : ;;
    *[!0-9a-f]*|'') echo "--cid must be lowercase hex" >&2; usage ;;
    *) [ "${#CID}" -eq 64 ] || { echo "--cid must be 64 hex chars" >&2; usage; } ;;
esac
if [ -z "$CID" ]; then
    valid_name "$POD" || { echo "--pod must be a DNS-1123 name" >&2; usage; }
    valid_name "$NAMESPACE" || { echo "--namespace must be a DNS-1123 name" >&2; usage; }
    [ -z "$CONTAINER" ] || valid_name "$CONTAINER" || {
        echo "--container must be a DNS-1123 name" >&2
        usage
    }
fi

[ -x "$OBSERVER" ] || { echo "$OBSERVER is missing" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl required" >&2; exit 1; }

if [ -z "$CID" ]; then
    echo "=== resolve pod container id via in-cluster API ===" >&2
    TOKEN_FILE=/var/run/secrets/kubernetes.io/serviceaccount/token
    CA_FILE=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    [ -f "$TOKEN_FILE" ] || { echo "no serviceaccount token mounted" >&2; exit 1; }
    : "${KUBERNETES_SERVICE_HOST:?KUBERNETES_SERVICE_HOST is unset}"
    : "${KUBERNETES_SERVICE_PORT:?KUBERNETES_SERVICE_PORT is unset}"
    POD_JSON=$(curl -sf --cacert "$CA_FILE" \
        -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
        "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/$NAMESPACE/pods/$POD") \
        || { echo "API read of pod $NAMESPACE/$POD failed" >&2; exit 1; }
    extract_cid || exit 1
    echo "container: $CONTAINER id: $CID" >&2
fi

echo "=== resolve pod cgroup (node view) ===" >&2
CONTAINER_CG=
for candidate in "cri-containerd-$CID.scope" "crio-$CID.scope" "docker-$CID.scope" "$CID"; do
    CONTAINER_CG=$(find /sys/fs/cgroup -type d -name "$candidate" -print -quit 2>/dev/null)
    [ -z "$CONTAINER_CG" ] || break
done
test -n "$CONTAINER_CG" || { echo "could not locate the container cgroup for $CID" >&2; exit 1; }
POD_CG=$(dirname "$CONTAINER_CG")
echo "pod cgroup: $POD_CG" >&2

# Kubelet creates the scratch emptyDir 0777 without the sticky bit, which the
# observer's output trust check refuses. Restore classic /tmp mode so `-o
# /tmp/<name>.json` (the only writable path under the read-only root) works.
chmod 1777 /tmp || { echo "cannot harden the scratch mount" >&2; exit 1; }

exec "$OBSERVER" profile --cgroup "$POD_CG" "$@"

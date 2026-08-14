#!/bin/sh
# Attach p11scope to a PKCS#11 provider inside an existing Kubernetes pod.
#
# Run this on the node that hosts the pod, as a non-root user with passwordless
# sudo. It performs the documented manual workflow: resolve the pod's container
# to a host cgroup and PID, copy the provider directory out as regular files,
# discover the function table from that copy, rewrite the attach paths to the
# target's /proc view, and run the trusted cgroup capture.
#
# The pod is NOT created or owned by this script. Capturing an existing
# workload through its cgroup requires --trusted-workload: the cgroup lane
# assumes an honest, ABI-valid provider. There is no hostile-target guarantee
# here; the fixed-PID static observer lane is the hostile-target gate.
set -eu
INVOCATION_DIR=$PWD
cd "$(dirname "$0")/.."

usage() {
    cat >&2 <<'EOF'
usage: scripts/attach-pod.sh --pod NAME --module PATH-IN-POD --trusted-workload
                             [--namespace NS] [--container NAME]
                             [--mode profile|metrics] [--duration SECONDS]
                             [-o OUTPUT.json]

  --pod NAME               existing pod to observe (required)
  --module PATH-IN-POD     provider .so as the pod sees it (required)
  --trusted-workload       acknowledge the honest-provider cgroup lane (required)
  --namespace NS           pod namespace (default: default)
  --container NAME         container in the pod (default: the first one)
  --mode profile|metrics   capture mode (default: profile)
  --duration SECONDS       capture duration (default: 60)
  -o OUTPUT.json           where to publish the profile (default: observed-profile.json)

Point --module at the real vendor provider, not p11-kit-proxy.so.
EOF
    exit 2
}

NAMESPACE=default
POD=
CONTAINER=
MODULE_IN_POD=
MODE=profile
DURATION=60
OUTPUT=observed-profile.json
TRUSTED=
OBSERVER=${P11SCOPE_OBSERVER:-target/release/p11scope}
DISCOVER=${P11SCOPE_DISCOVER:-target/release/p11scope-discover}

while [ "$#" -gt 0 ]; do
    case $1 in
        --namespace) [ "$#" -ge 2 ] || usage; NAMESPACE=$2; shift 2 ;;
        --pod) [ "$#" -ge 2 ] || usage; POD=$2; shift 2 ;;
        --container) [ "$#" -ge 2 ] || usage; CONTAINER=$2; shift 2 ;;
        --module) [ "$#" -ge 2 ] || usage; MODULE_IN_POD=$2; shift 2 ;;
        --mode) [ "$#" -ge 2 ] || usage; MODE=$2; shift 2 ;;
        --duration) [ "$#" -ge 2 ] || usage; DURATION=$2; shift 2 ;;
        -o) [ "$#" -ge 2 ] || usage; OUTPUT=$2; shift 2 ;;
        --trusted-workload) TRUSTED=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

[ -n "$POD" ] && [ -n "$MODULE_IN_POD" ] || usage
[ -n "$TRUSTED" ] || {
    echo "refusing to attach without --trusted-workload: capturing an existing" >&2
    echo "pod through its cgroup assumes an honest, ABI-valid provider" >&2
    exit 2
}
case $MODULE_IN_POD in /*) ;; *) echo "--module must be absolute" >&2; exit 2 ;; esac
case $MODE in profile|metrics) ;; *) echo "--mode must be profile or metrics" >&2; exit 2 ;; esac
case $DURATION in ''|*[!0-9]*) echo "--duration must be a whole number of seconds" >&2; exit 2 ;; esac
# Paths the operator typed are relative to where they ran this, not the repo.
case $OUTPUT in /*) ;; *) OUTPUT="$INVOCATION_DIR/$OUTPUT" ;; esac

TOKEN=$(date +%s%N)-$$
WORK="target/attach-pod/$TOKEN"
TRUST_DIR=
RUN_DIR=
SPID=
SUPERVISOR_PID=
SUPERVISOR_STARTTIME=
ROOT_LAUNCH_PID=
ROOT_PROCESS_PID=
ROOT_PROCESS_STARTTIME=
PUBLISH_TMP=
. scripts/trusted-p11scope.sh
require_non_root_caller

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    if [ -n "$SPID" ]; then
        if [ -n "$SUPERVISOR_PID" ] && [ -n "$SUPERVISOR_STARTTIME" ]; then
            cleanup_step signal_verified_root_process TERM \
                "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME"
        else
            kill "$SPID" 2>/dev/null || true
        fi
        cleanup_step wait "$SPID"
    fi
    cleanup_step restore_suid_dumpable
    [ -z "$PUBLISH_TMP" ] || cleanup_step rm -f -- "$PUBLISH_TMP"
    cleanup_step remove_trusted_p11scope "$TRUST_DIR"
    cleanup_step remove_protected_output_dir "$RUN_DIR"
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

for command in kubectl python3 stat timeout; do
    command -v "$command" >/dev/null || { echo "$command required" >&2; exit 1; }
done
sudo -n true 2>/dev/null || { echo "passwordless sudo required" >&2; exit 1; }
for binary in "$OBSERVER" "$DISCOVER"; do
    [ -x "$binary" ] || {
        echo "$binary is missing; build with: cargo +1.88 build --locked --release --workspace" >&2
        exit 1
    }
done

kube() {
    timeout --signal=TERM --kill-after=5s 60s kubectl -n "$NAMESPACE" "$@"
}

echo "=== resolve pod container, cgroup, and host pid ==="
mkdir -p "$WORK"
rm -rf "$WORK/provider-safe"
mkdir -p "$WORK/provider-safe"
if [ -z "$CONTAINER" ]; then
    CONTAINER=$(kube get pod "$POD" -o jsonpath='{.status.containerStatuses[0].name}')
    [ -n "$CONTAINER" ] || { echo "pod $POD has no running container" >&2; exit 1; }
fi
CID_REF=$(kube get pod "$POD" \
    -o jsonpath="{.status.containerStatuses[?(@.name==\"$CONTAINER\")].containerID}")
case $CID_REF in
    containerd://*|cri-o://*|docker://*) ;;
    '') echo "container $CONTAINER in pod $POD has no container id" >&2; exit 1 ;;
    *) echo "unsupported container runtime reference: $CID_REF" >&2; exit 1 ;;
esac
CID=${CID_REF##*/}
case $CID in ''|*[!0-9a-f]*) echo "container id invalid: $CID_REF" >&2; exit 1 ;; esac

CONTAINER_CG=
for candidate in "cri-containerd-$CID.scope" "crio-$CID.scope" "docker-$CID.scope" "$CID"; do
    CONTAINER_CG=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
        find /sys/fs/cgroup -type d -name "$candidate" -print -quit 2>/dev/null)
    [ -z "$CONTAINER_CG" ] || break
done
test -n "$CONTAINER_CG" || { echo "could not locate the container cgroup for $CID" >&2; exit 1; }
POD_CG=$(dirname "$CONTAINER_CG")
HOSTPID=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    awk 'NR == 1 { print; exit }' "$CONTAINER_CG/cgroup.procs")
case $HOSTPID in ''|*[!0-9]*) echo "container cgroup has no live process" >&2; exit 1 ;; esac
echo "pod cgroup: $POD_CG"
echo "host pid:   $HOSTPID"

echo "=== copy the resolved provider directory out as regular files ==="
PROVIDER_REAL=$(kube exec "$POD" -c "$CONTAINER" -- readlink -f "$MODULE_IN_POD")
case $PROVIDER_REAL in
    /*/*) ;;
    *) echo "invalid resolved provider path: $PROVIDER_REAL" >&2; exit 1 ;;
esac
PROVIDER_DIR=${PROVIDER_REAL%/*}
PROVIDER_NAME=${PROVIDER_REAL##*/}
capped_container_tar "$WORK/provider.tar" \
    kube exec "$POD" -c "$CONTAINER" -- tar -chC "$PROVIDER_DIR" .
tar -xf "$WORK/provider.tar" -C "$WORK/provider-safe"
rm -f "$WORK/provider.tar"
SAFE_MODULE="$PWD/$WORK/provider-safe/$PROVIDER_NAME"
timeout --signal=TERM --kill-after=5s 60s python3 \
    scripts/container-authority.py validate-copy "$PWD/$WORK/provider-safe" "$SAFE_MODULE"

echo "=== stage the trusted observer pair and discover from the safe copy ==="
TRUST_DIR=$(create_trusted_exec_dir)
RUN_DIR=$(create_protected_output_dir)
stage_trusted_p11scope "$OBSERVER" "$DISCOVER" "$TRUST_DIR"
stage_container_authority scripts/container-authority.py "$TRUST_DIR"
timeout --signal=TERM --kill-after=5s 60s "$TRUST_DIR/p11scope" discover \
    --module "$SAFE_MODULE" -o "$WORK/manifest-raw.json"
timeout --signal=TERM --kill-after=5s 60s python3 scripts/container-authority.py rewrite \
    "$WORK/manifest-raw.json" "$WORK/manifest-host.json" \
    "$PWD/$WORK/provider-safe" "/proc/$HOSTPID/root$PROVIDER_DIR"
sudo -n install -o root -g root -m 0600 "$WORK/manifest-host.json" "$RUN_DIR/manifest.json"
sudo -n timeout --signal=TERM --kill-after=5s 60s \
    python3 "$TRUST_DIR/container-authority.py" lease-evidence \
    "$RUN_DIR/manifest.json" "$RUN_DIR/lease-evidence.json"

echo "=== attach and capture for ${DURATION}s ==="
set_suid_dumpable_zero
CAPTURE_DEADLINE=$((DURATION + 45))
set -- timeout --signal=TERM --kill-after=5s "${CAPTURE_DEADLINE}s" \
    "$TRUST_DIR/p11scope" profile --manifest "$RUN_DIR/manifest.json" \
    --provenance-module "$SAFE_MODULE" --cgroup "$POD_CG" --trusted-workload \
    --mode "$MODE" --duration "$DURATION" -o "$RUN_DIR/observed.json"
launch_root_recorded_process "$RUN_DIR/observer.pid" "$WORK/profile.log" "$@"
SPID=$ROOT_LAUNCH_PID
SUPERVISOR_PID=$ROOT_PROCESS_PID
SUPERVISOR_STARTTIME=$ROOT_PROCESS_STARTTIME
wait_for_capture_ready "$WORK/profile.log" allowlisted "$MODE"
echo "attached; capturing whatever the pod does for the next ${DURATION}s"
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
    tail -n 20 "$WORK/profile.log" >&2 || true
    exit "$status"
fi
restore_suid_dumpable

publish_protected_file "$RUN_DIR" observed.json "$WORK" observed.json
publish_protected_file "$RUN_DIR" lease-evidence.json "$WORK" lease-evidence.json
mkdir -p "$(dirname "$OUTPUT")"
cp -f "$WORK/observed.json" "$OUTPUT"
echo "=== wrote $OUTPUT (lease evidence: $WORK/lease-evidence.json) ==="

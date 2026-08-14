#!/bin/sh
# Task 6: one Docker container, host-side authority discovery, and exact capture.
set -eu
cd "$(dirname "$0")/../.."

MODULE_IN_CONTAINER=/usr/lib/softhsm/libsofthsm2.so
RUN_ID=$(date +%s%N)-$$
WORK="target/matrix-docker/$RUN_ID"
IMAGE="p11scope-matrix-docker:$RUN_ID"
NAME="p11scope-matrix-docker-$RUN_ID"
PRODUCT=target/matrix-product
SAFE_ROOT="$PWD/$WORK/provider-safe"
TRUST_DIR=
RUN_DIR=
PROVENANCE_MODULE=
WPID=
SPID=
SUPERVISOR_PID=
SUPERVISOR_STARTTIME=
ROOT_LAUNCH_PID=
ROOT_PROCESS_PID=
ROOT_PROCESS_STARTTIME=
PUBLISH_TMP=
IMAGE_CREATED=
CONTAINER_STARTED=
. scripts/trusted-p11scope.sh

require_non_root_caller
for tool in cargo docker gcc python3 tar timeout; do
    command -v "$tool" >/dev/null || { echo "$tool required"; exit 1; }
done
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }
mkdir -p "$WORK/shared"

remove_owned_container() {
    timeout --signal=TERM --kill-after=5s 30s docker rm -f "$NAME" >/dev/null 2>&1
}

remove_owned_image() {
    timeout --signal=TERM --kill-after=5s 30s docker image rm "$IMAGE" >/dev/null 2>&1
}

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    launcher=${SPID:-$ROOT_LAUNCH_PID}
    recorded_pid=${SUPERVISOR_PID:-$ROOT_PROCESS_PID}
    recorded_starttime=${SUPERVISOR_STARTTIME:-$ROOT_PROCESS_STARTTIME}
    if [ -n "$recorded_pid" ] && [ -n "$recorded_starttime" ]; then
        signal_verified_root_process TERM "$recorded_pid" "$recorded_starttime" \
            2>/dev/null || true
    fi
    [ -z "$launcher" ] || wait "$launcher" 2>/dev/null || true
    cleanup_step restore_suid_dumpable
    [ -z "$CONTAINER_STARTED" ] || cleanup_step remove_owned_container
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$IMAGE_CREATED" ] || cleanup_step remove_owned_image
    [ -z "$PUBLISH_TMP" ] || cleanup_step rm -f -- "$PUBLISH_TMP"
    cleanup_step remove_trusted_p11scope "$TRUST_DIR"
    cleanup_step remove_protected_output_dir "$RUN_DIR"
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

echo "=== build product + workload ==="
rm -rf "$SAFE_ROOT"
timeout --signal=TERM --kill-after=5s 600s cargo +1.88 build --locked --release \
    --workspace --target-dir "$PRODUCT"
timeout --signal=TERM --kill-after=5s 60s gcc -O0 -o "$WORK/harness" \
    spike/harness.c -ldl

echo "=== build and start owned container ==="
IMAGE_CREATED=1
timeout --signal=TERM --kill-after=5s 600s docker build -q -t "$IMAGE" \
    -f scripts/matrix/Dockerfile scripts/matrix >/dev/null
TRUST_DIR=$(create_trusted_exec_dir)
RUN_DIR=$(create_protected_output_dir)
stage_trusted_p11scope "$PRODUCT/release/p11scope" \
    "$PRODUCT/release/p11scope-discover" "$TRUST_DIR"
stage_container_authority scripts/container-authority.py "$TRUST_DIR"
rm -f "$WORK/shared/go"
CONTAINER_STARTED=1
timeout --signal=TERM --kill-after=5s 60s docker run -d --name "$NAME" \
    -v "$PWD/$WORK/harness:/usr/local/bin/harness:ro" \
    -v "$PWD/$WORK/shared:/shared" \
    "$IMAGE" >/dev/null
PID=$(timeout --signal=TERM --kill-after=5s 60s \
    docker inspect -f '{{.State.Pid}}' "$NAME")
case $PID in ''|*[!0-9]*|0) echo "could not get container pid"; exit 1 ;; esac

echo "=== copy resolved provider directory and discover on the host ==="
PROVIDER_REAL=$(timeout --signal=TERM --kill-after=5s 60s \
    docker exec "$NAME" readlink -f -- "$MODULE_IN_CONTAINER")
case $PROVIDER_REAL in /*/*) ;; *) echo "invalid resolved provider path: $PROVIDER_REAL"; exit 1 ;; esac
PROVIDER_DIR=${PROVIDER_REAL%/*}
PROVIDER_BASE=${PROVIDER_REAL##*/}
mkdir -p "$SAFE_ROOT"
capped_container_tar "$WORK/provider.tar" \
    timeout --signal=TERM --kill-after=5s 60s docker exec "$NAME" \
    tar -h -c -f - -C "$PROVIDER_DIR" .
tar -xf "$WORK/provider.tar" -C "$SAFE_ROOT"
rm -f "$WORK/provider.tar"
PROVENANCE_MODULE="$SAFE_ROOT/$PROVIDER_BASE"
test -f "$PROVENANCE_MODULE" && [ ! -L "$PROVENANCE_MODULE" ] \
    || { echo "provenance module is not a regular copied file"; exit 1; }
timeout --signal=TERM --kill-after=5s 60s python3 \
    scripts/container-authority.py validate-copy "$SAFE_ROOT" "$PROVENANCE_MODULE"
timeout --signal=TERM --kill-after=5s 60s "$TRUST_DIR/p11scope" discover \
    --module "$PROVENANCE_MODULE" \
    -o "$WORK/.manifest-safe.json"
timeout --signal=TERM --kill-after=5s 60s python3 scripts/container-authority.py rewrite \
    "$WORK/.manifest-safe.json" "$WORK/.manifest-host.json" \
    "$SAFE_ROOT" "/proc/$PID/root$PROVIDER_DIR"
sudo -n install -o root -g root -m 0600 "$WORK/.manifest-host.json" \
    "$RUN_DIR/manifest-host.json"
rm -f "$WORK/.manifest-safe.json" "$WORK/.manifest-host.json"
sudo -n timeout --signal=TERM --kill-after=5s 60s \
    python3 "$TRUST_DIR/container-authority.py" lease-evidence \
    "$RUN_DIR/manifest-host.json" "$RUN_DIR/lease-evidence.json"
publish_protected_file "$RUN_DIR" lease-evidence.json "$WORK" lease-evidence.json
publish_protected_file "$RUN_DIR" manifest-host.json "$WORK" manifest-host.json

echo "=== resolve container cgroup ==="
CGROUP_REL=$(awk -F: '$1 == "0" && $2 == "" { print $3; exit }' "/proc/$PID/cgroup")
case $CGROUP_REL in /*) ;; *) echo "unified cgroup entry missing for container $PID"; exit 1 ;; esac
CGROUP_PATH="/sys/fs/cgroup$CGROUP_REL"
test -d "$CGROUP_PATH" || { echo "cgroup path does not exist: $CGROUP_PATH"; exit 1; }

echo "=== unprivileged diagnostic ==="
set +e
UNPRIV_OUT=$(timeout --signal=TERM --kill-after=5s 60s \
    "$TRUST_DIR/p11scope" profile --manifest "$WORK/manifest-host.json" \
    --provenance-module "$PROVENANCE_MODULE" --cgroup "$CGROUP_PATH" \
    --trusted-workload --mode metrics --duration 1 2>&1)
UNPRIV_RC=$?
set -e
printf '%s\n' "$UNPRIV_OUT"
[ "$UNPRIV_RC" -ne 0 ] || { echo "unprivileged profile unexpectedly succeeded"; exit 1; }
require_rewritten_authority_refusal "$UNPRIV_OUT" "/proc/$PID/root$PROVIDER_REAL" \
    || { echo "unprivileged failure missed the rewritten-object authority boundary"; exit 1; }

echo "=== capture one container after observer readiness ==="
timeout --signal=TERM --kill-after=5s 60s docker exec "$NAME" sh -c \
    'while [ ! -f /shared/go ]; do sleep 0.05; done; exec /usr/local/bin/harness "$1"' \
    sh "$MODULE_IN_CONTAINER" > "$WORK/workload.log" 2>&1 &
WPID=$!
set_suid_dumpable_zero
launch_root_recorded_process "$RUN_DIR/profile.pid" "$WORK/profile.log" \
    timeout --signal=TERM --kill-after=35s 45s \
    "$TRUST_DIR/p11scope" profile --manifest "$RUN_DIR/manifest-host.json" \
    --provenance-module "$PROVENANCE_MODULE" --cgroup "$CGROUP_PATH" \
    --trusted-workload --mode metrics --duration 30 -o "$RUN_DIR/observed.json"
SPID=$ROOT_LAUNCH_PID
SUPERVISOR_PID=$ROOT_PROCESS_PID
SUPERVISOR_STARTTIME=$ROOT_PROCESS_STARTTIME
wait_for_capture_ready "$WORK/profile.log" aggregate-only metrics
touch "$WORK/shared/go"
if wait "$WPID"; then
    WPID=
else
    status=$?
    WPID=
    echo "container workload failed: $status"
    cat "$WORK/workload.log" || true
    exit "$status"
fi
signal_verified_root_process INT "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME"
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
    echo "container profiler failed: $status"
    tail -n 30 "$WORK/profile.log" || true
    exit "$status"
fi
restore_suid_dumpable
publish_protected_file "$RUN_DIR" observed.json "$WORK" observed.json
python3 scripts/check-capture-evidence.py clean-metrics \
    "$WORK/observed.json" spike/expected.txt

echo "=== docker: ALL OK ==="

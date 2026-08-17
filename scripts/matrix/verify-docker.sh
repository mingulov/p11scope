#!/bin/sh
# Task 6: one Docker container, manifest-free discovery, and exact capture.
#
# Nothing is copied into or out of the container. The observer runs on the host,
# scans the container process's memory through /proc/<pid>/mem and opens the
# provider through /proc/<pid>/root — which is what answers spike §6.4: whether
# a provider on an overlay2 upper layer can be pinned by the mapping's identity.
set -eu
cd "$(dirname "$0")/../.."

MODULE_IN_CONTAINER=/usr/lib/softhsm/libsofthsm2.so
RUN_ID=$(date +%s%N)-$$
WORK="target/matrix-docker/$RUN_ID"
IMAGE="p11scope-matrix-docker:$RUN_ID"
NAME="p11scope-matrix-docker-$RUN_ID"
PRODUCT=target/matrix-product
WPID=
SPID=
SUPERVISOR_PID=
SUPERVISOR_STARTTIME=
ROOT_LAUNCH_PID=
ROOT_PROCESS_PID=
ROOT_PROCESS_STARTTIME=
IMAGE_CREATED=
CONTAINER_STARTED=
. scripts/lib.sh

require_non_root_caller
for tool in cargo docker gcc python3 timeout; do
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
    [ -z "$CONTAINER_STARTED" ] || cleanup_step remove_owned_container
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$IMAGE_CREATED" ] || cleanup_step remove_owned_image
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

echo "=== build product + workload ==="
timeout --signal=TERM --kill-after=5s 600s cargo +1.88 build --locked --release \
    --workspace --target-dir "$PRODUCT"
timeout --signal=TERM --kill-after=5s 60s gcc -O0 -o "$WORK/harness" \
    spike/harness.c -ldl

echo "=== build and start owned container ==="
IMAGE_CREATED=1
timeout --signal=TERM --kill-after=5s 600s docker build -q -t "$IMAGE" \
    -f scripts/matrix/Dockerfile scripts/matrix >/dev/null
rm -f "$WORK/shared/go"
CONTAINER_STARTED=1
timeout --signal=TERM --kill-after=5s 60s docker run -d --name "$NAME" \
    -v "$PWD/$WORK/harness:/usr/local/bin/harness:ro" \
    -v "$PWD/$WORK/shared:/shared" \
    "$IMAGE" >/dev/null
PID=$(timeout --signal=TERM --kill-after=5s 60s \
    docker inspect -f '{{.State.Pid}}' "$NAME")
case $PID in ''|*[!0-9]*|0) echo "could not get container pid"; exit 1 ;; esac

echo "=== resolve container cgroup ==="
CGROUP_REL=$(awk -F: '$1 == "0" && $2 == "" { print $3; exit }' "/proc/$PID/cgroup")
case $CGROUP_REL in /*) ;; *) echo "unified cgroup entry missing for container $PID"; exit 1 ;; esac
CGROUP_PATH="/sys/fs/cgroup$CGROUP_REL"
test -d "$CGROUP_PATH" || { echo "cgroup path does not exist: $CGROUP_PATH"; exit 1; }

echo "=== start the container workload: it maps the provider, then waits ==="
# The scan runs once, at attach time, so the provider must already be mapped.
# harness dlopens it and only then blocks on the go-file, so no PKCS#11 call has
# been made yet either — attach-before-run still holds.
rm -f "$WORK/shared/go"
timeout --signal=TERM --kill-after=5s 60s docker exec "$NAME" \
    /usr/local/bin/harness "$MODULE_IN_CONTAINER" /shared/go > "$WORK/workload.log" 2>&1 &
WPID=$!
wait_for_cgroup_provider "$CGROUP_PATH" libsofthsm2.so

echo "=== unprivileged diagnostic: the container provider must be unreadable without privileges ==="
set +e
DOCTOR_OUT=$(timeout --signal=TERM --kill-after=5s 60s \
    "$PRODUCT/release/p11scope" doctor --pid "$MAPPED_PROVIDER_PID" 2>&1)
DOCTOR_RC=$?
set -e
printf '%s\n' "$DOCTOR_OUT"
[ "$DOCTOR_RC" -ne 0 ] || { echo "unprivileged doctor unexpectedly succeeded"; exit 1; }
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
    "$PRODUCT/release/p11scope" profile \
    --cgroup "$CGROUP_PATH" --mode metrics --duration 1 2>&1)
UNPRIV_RC=$?
set -e
printf '%s\n' "$UNPRIV_OUT"
[ "$UNPRIV_RC" -ne 0 ] || { echo "unprivileged profile unexpectedly succeeded"; exit 1; }
printf '%s\n' "$UNPRIV_OUT" | is_linux_permission_denial \
    || { echo "unprivileged profile did not fail closed" >&2; exit 1; }

echo "=== capture one container after observer readiness ==="
launch_root_recorded_process "$WORK/profile.pid" "$WORK/profile.log" \
    timeout --signal=TERM --kill-after=35s 45s \
    "$PRODUCT/release/p11scope" profile \
    --cgroup "$CGROUP_PATH" \
    --mode metrics --duration 30 -o "$WORK/observed.json"
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
reclaim_root_output "$WORK/observed.json"
python3 scripts/check-capture-evidence.py clean-metrics \
    "$WORK/observed.json" spike/expected.txt

echo "=== the provider was pinned inside the container, by the scan alone ==="
python3 - "$WORK/observed.json" "$MODULE_IN_CONTAINER" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
ev = doc["evidence"]
assert [m["sources"] for m in ev["discovery"]] == [["scan"]], ev["discovery"]
assert ev["authority"] == "hash-pinned", ev["authority"]
assert ev["scan_unavailable"] is None, ev["scan_unavailable"]
# The path is the container's, resolved through /proc/<pid>/root, and the
# identity is the mapping's own — spike §6.4's overlay2 question, answered.
module = doc["capture"]["modules"][0]
assert module["path"].endswith("libsofthsm2.so"), module
assert len(module["sha256"]) == 64, module
assert module["ino"] > 0, module
print("container provider pinned from the host:", module["path"], module["dev"], module["ino"])
print("identity_source:", [o["identity_source"] for o in ev["discovery"][0]["objects"]])
PY

echo "=== docker: ALL OK ==="

#!/bin/sh
# Task 6: one shared image-layer inode, broad and leaf cgroup authority.
set -eu
cd "$(dirname "$0")/../.."

MODULE_IN_CONTAINER=/usr/lib/softhsm/libsofthsm2.so
RUN_ID=$(date +%s%N)-$$
WORK="target/matrix-shared/$RUN_ID"
IMAGE="p11scope-matrix-shared:$RUN_ID"
NAME_A="p11scope-matrix-shared-a-$RUN_ID"
NAME_B="p11scope-matrix-shared-b-$RUN_ID"
CGROUP_PARENT="p11scope-shared-$RUN_ID.slice"
PRODUCT=target/matrix-product
SAFE_ROOT="$PWD/$WORK/provider-safe"
SAFE_MODULE=
WA=
WB=
SPID=
SUPERVISOR_PID=
SUPERVISOR_STARTTIME=
ROOT_LAUNCH_PID=
ROOT_PROCESS_PID=
ROOT_PROCESS_STARTTIME=
IMAGE_CREATED=
CONTAINER_A_STARTED=
CONTAINER_B_STARTED=
. scripts/lib.sh

require_non_root_caller
for tool in cargo docker gcc python3 tar timeout; do
    command -v "$tool" >/dev/null || { echo "$tool required"; exit 1; }
done
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }
mkdir -p "$WORK/shared-a" "$WORK/shared-b"

remove_owned_container() {
    timeout --signal=TERM --kill-after=5s 30s docker rm -f "$1" >/dev/null 2>&1
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
    [ -z "$CONTAINER_A_STARTED" ] || cleanup_step remove_owned_container "$NAME_A"
    [ -z "$CONTAINER_B_STARTED" ] || cleanup_step remove_owned_container "$NAME_B"
    [ -z "$WA" ] || wait "$WA" 2>/dev/null || true
    [ -z "$WB" ] || wait "$WB" 2>/dev/null || true
    [ -z "$IMAGE_CREATED" ] || cleanup_step remove_owned_image
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

echo "=== build product + workload ==="
rm -rf "$SAFE_ROOT"
timeout --signal=TERM --kill-after=5s 600s cargo +1.88 build --locked --release \
    --workspace --target-dir "$PRODUCT"
timeout --signal=TERM --kill-after=5s 60s gcc -O0 -o "$WORK/harness" \
    spike/harness.c -ldl

echo "=== build and start two owned containers ==="
IMAGE_CREATED=1
timeout --signal=TERM --kill-after=5s 600s docker build -q -t "$IMAGE" \
    -f scripts/matrix/Dockerfile scripts/matrix >/dev/null
rm -f "$WORK/shared-a/go" "$WORK/shared-b/go"
CONTAINER_A_STARTED=1
timeout --signal=TERM --kill-after=5s 60s docker run -d --name "$NAME_A" \
    --cgroup-parent="$CGROUP_PARENT" \
    -v "$PWD/$WORK/harness:/usr/local/bin/harness:ro" \
    -v "$PWD/$WORK/shared-a:/shared" "$IMAGE" >/dev/null
CONTAINER_B_STARTED=1
timeout --signal=TERM --kill-after=5s 60s docker run -d --name "$NAME_B" \
    --cgroup-parent="$CGROUP_PARENT" \
    -v "$PWD/$WORK/harness:/usr/local/bin/harness:ro" \
    -v "$PWD/$WORK/shared-b:/shared" "$IMAGE" >/dev/null
PID_A=$(timeout --signal=TERM --kill-after=5s 60s \
    docker inspect -f '{{.State.Pid}}' "$NAME_A")
PID_B=$(timeout --signal=TERM --kill-after=5s 60s \
    docker inspect -f '{{.State.Pid}}' "$NAME_B")
case $PID_A in ''|*[!0-9]*) echo "invalid container pid A: $PID_A"; exit 1 ;; esac
case $PID_B in ''|*[!0-9]*) echo "invalid container pid B: $PID_B"; exit 1 ;; esac
[ "$PID_A" -gt 0 ] && [ "$PID_B" -gt 0 ] || { echo "container pid is zero"; exit 1; }

echo "=== prove the provider is one shared host inode ==="
PROVIDER_REAL=$(timeout --signal=TERM --kill-after=5s 60s \
    docker exec "$NAME_A" readlink -f -- "$MODULE_IN_CONTAINER")
PROVIDER_REAL_B=$(timeout --signal=TERM --kill-after=5s 60s \
    docker exec "$NAME_B" readlink -f -- "$MODULE_IN_CONTAINER")
[ "$PROVIDER_REAL" = "$PROVIDER_REAL_B" ] \
    || { echo "provider resolves differently: $PROVIDER_REAL vs $PROVIDER_REAL_B"; exit 1; }
case $PROVIDER_REAL in /*/*) ;; *) echo "invalid resolved provider path: $PROVIDER_REAL"; exit 1 ;; esac
DEVINO_A=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    stat -Lc '%d:%i' "/proc/$PID_A/root$PROVIDER_REAL")
DEVINO_B=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    stat -Lc '%d:%i' "/proc/$PID_B/root$PROVIDER_REAL")
INODE_A=${DEVINO_A#*:}
INODE_B=${DEVINO_B#*:}
[ "$INODE_A" = "$INODE_B" ] || {
    echo "BLOCKED: provider overlay inode differs ($DEVINO_A vs $DEVINO_B)"
    exit 1
}
echo "shared provider overlay inode: $INODE_A (host identities $DEVINO_A vs $DEVINO_B)"

echo "=== copy resolved provider directory and discover on the host ==="
PROVIDER_DIR=${PROVIDER_REAL%/*}
PROVIDER_BASE=${PROVIDER_REAL##*/}
mkdir -p "$SAFE_ROOT"
capped_container_tar "$WORK/provider.tar" \
    timeout --signal=TERM --kill-after=5s 60s docker exec "$NAME_A" \
    tar -h -c -f - -C "$PROVIDER_DIR" .
tar -xf "$WORK/provider.tar" -C "$SAFE_ROOT"
rm -f "$WORK/provider.tar"
SAFE_MODULE="$SAFE_ROOT/$PROVIDER_BASE"
test -f "$SAFE_MODULE" && [ ! -L "$SAFE_MODULE" ] \
    || { echo "copied provider is not a regular file"; exit 1; }
timeout --signal=TERM --kill-after=5s 60s "$PRODUCT/release/p11scope-discover" \
    --module "$SAFE_MODULE" \
    -o "$WORK/.manifest-safe.json"
rewrite_container_manifest "$WORK/.manifest-safe.json" "$WORK/manifest-host.json" \
    "$SAFE_ROOT" "/proc/$PID_A/root$PROVIDER_DIR"
rm -f "$WORK/.manifest-safe.json"

echo "=== resolve and compare broad/leaf cgroups ==="
CGROUP_A_REL=$(awk -F: '$1 == "0" && $2 == "" { print $3; exit }' "/proc/$PID_A/cgroup")
CGROUP_B_REL=$(awk -F: '$1 == "0" && $2 == "" { print $3; exit }' "/proc/$PID_B/cgroup")
case $CGROUP_A_REL:$CGROUP_B_REL in /*:/*) ;; *) echo "unified container cgroups missing"; exit 1 ;; esac
CGROUP_A_PARENT=${CGROUP_A_REL%/*}
CGROUP_B_PARENT=${CGROUP_B_REL%/*}
[ "$CGROUP_A_PARENT" = "$CGROUP_B_PARENT" ] || {
    echo "shared cgroup parent differs: $CGROUP_A_PARENT vs $CGROUP_B_PARENT"
    exit 1
}
BROAD_PATH="/sys/fs/cgroup$CGROUP_A_PARENT"
LEAF_A_PATH="/sys/fs/cgroup$CGROUP_A_REL"
LEAF_B_PATH="/sys/fs/cgroup$CGROUP_B_REL"
for path in "$BROAD_PATH" "$LEAF_A_PATH" "$LEAF_B_PATH"; do
    test -d "$path" || { echo "cgroup path does not exist: $path"; exit 1; }
done

echo "=== unprivileged diagnostic: attach must fail without privileges ==="
set +e
UNPRIV_OUT=$(timeout --signal=TERM --kill-after=5s 60s \
    "$PRODUCT/release/p11scope" profile --manifest "$WORK/manifest-host.json" \
    --cgroup "$BROAD_PATH" --mode metrics --duration 1 2>&1)
UNPRIV_RC=$?
set -e
printf '%s\n' "$UNPRIV_OUT"
[ "$UNPRIV_RC" -ne 0 ] || { echo "unprivileged profile unexpectedly succeeded"; exit 1; }

run_capture() {
    label=$1
    cgroup=$2
    multiplier=$3
    echo "--- capture: $label (scope=$cgroup) ---"
    rm -f "$WORK/shared-a/go" "$WORK/shared-b/go"
    timeout --signal=TERM --kill-after=5s 60s docker exec "$NAME_A" sh -c \
        'while [ ! -f /shared/go ]; do sleep 0.05; done; exec /usr/local/bin/harness "$1"' \
        sh "$MODULE_IN_CONTAINER" > "$WORK/$label-workload-a.log" 2>&1 &
    WA=$!
    timeout --signal=TERM --kill-after=5s 60s docker exec "$NAME_B" sh -c \
        'while [ ! -f /shared/go ]; do sleep 0.05; done; exec /usr/local/bin/harness "$1"' \
        sh "$MODULE_IN_CONTAINER" > "$WORK/$label-workload-b.log" 2>&1 &
    WB=$!
    launch_root_recorded_process "$WORK/$label.pid" "$WORK/$label.log" \
        timeout --signal=TERM --kill-after=35s 45s \
        "$PRODUCT/release/p11scope" profile --manifest "$WORK/manifest-host.json" \
        --cgroup "$cgroup" \
        --mode metrics --duration 30 -o "$WORK/$label.json"
    SPID=$ROOT_LAUNCH_PID
    SUPERVISOR_PID=$ROOT_PROCESS_PID
    SUPERVISOR_STARTTIME=$ROOT_PROCESS_STARTTIME
    wait_for_capture_ready "$WORK/$label.log" aggregate-only metrics
    touch "$WORK/shared-a/go" "$WORK/shared-b/go"
    if wait "$WA"; then
        WA=
    else
        status=$?
        WA=
        echo "$label workload A failed: $status"
        cat "$WORK/$label-workload-a.log" || true
        exit "$status"
    fi
    if wait "$WB"; then
        WB=
    else
        status=$?
        WB=
        echo "$label workload B failed: $status"
        cat "$WORK/$label-workload-b.log" || true
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
        echo "$label profiler failed: $status"
        tail -n 30 "$WORK/$label.log" || true
        exit "$status"
    fi
    # The observer ran as root, so its published report is root-owned 0600.
    sudo -n chown "$(id -u):$(id -g)" "$WORK/$label.json"
    python3 scripts/check-capture-evidence.py clean-metrics \
        "$WORK/$label.json" spike/expected.txt "$multiplier"
}

run_capture broad "$BROAD_PATH" 2
run_capture a-only "$LEAF_A_PATH" 1
run_capture b-only "$LEAF_B_PATH" 1

echo "=== shared-layer: ALL OK ==="

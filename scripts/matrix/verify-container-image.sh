#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# verify-container-image.sh -- permanent container-image cell.
#
# The observer image (built here from a musl binary, or prebuilt and loaded)
# captures a SoftHSM workload on the host and inside a second container with
# exact counts attributed to the right provider file, then proves the two
# refusal legs: a --pid capture without --pid=host, and a capture with
# CAP_SYS_PTRACE dropped. Nothing is copied into or out of the workload
# container; the observer reads it through hostPID + /proc like the k8s lane.
#
# Usage:
#   verify-container-image.sh (--observer-bin ABS|--image NAME) --out DIR
# --observer-bin stages the musl binary (must be static-pie) plus the entry
# script into a minimal context and builds with --network=none after pulling
# the Dockerfile's pinned base (the CI path). --image uses an already-loaded
# image (the fedora path: the caller delivers the tarball, checks its sha256
# and loads it). --out collects every log, report and results.jsonl.
#
# Rows in OUT/results.jsonl (judged with scripts/ci/check-cell-results.py):
#   host-exact        containerized profile --pid of a host workload: both
#                     count oracles exact, module (mountinfo device,
#                     sha256) is the host provider file, scan-only,
#                     hash-pinned, drain proven
#   container-exact   containerized profile --cgroup of the second
#                     container: same oracles, module (device, sha256)
#                     is the victim's provider file through /proc/<pid>/root
#   refusal-pidns     without --pid=host, --pid is refused naming
#                     pid-namespace-mismatch (no report is written)
#   refusal-cap       without CAP_SYS_PTRACE the capture fails naming the
#                     mount-namespace denial (no report is written)
# The target outlives every capture (go-file + finish-file), so a short-lived
# target never donates discovery-unavailable skips to a clean oracle.
#
# Exit codes: 0 every leg passed; 1 a leg failed; 2 harness/setup error
# (bad args, image or workload setup failed); 77 a prerequisite is missing.
# Runs as a non-root user with passwordless sudo; owns every docker name it
# creates (RUN_ID-suffixed) and removes them. P11SCOPE_MATRIX_BUILD_NETWORK
# is passed to the workload image build, like the other matrix lanes.
# P11SCOPE_CONTAINER_IMAGE_{MODULE,BTF,CGROUP} are test hooks for the stub
# suite (a path that must still exist); production leaves them unset.
set -euo pipefail
cd "$(dirname "$0")/../.." || exit 2
umask 022

print_usage() {
    cat <<'EOF'
usage: verify-container-image.sh (--observer-bin ABS|--image NAME) --out DIR
EOF
}

OBSERVER_BIN=
PREBUILT_IMAGE=
OUT=
while [ "$#" -gt 0 ]; do
    case $1 in
        --observer-bin)
            [ "$#" -ge 2 ] || { print_usage >&2; exit 2; }
            OBSERVER_BIN=$2
            shift 2
            ;;
        --image)
            [ "$#" -ge 2 ] || { print_usage >&2; exit 2; }
            PREBUILT_IMAGE=$2
            shift 2
            ;;
        --out)
            [ "$#" -ge 2 ] || { print_usage >&2; exit 2; }
            OUT=$2
            shift 2
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            print_usage >&2
            exit 2
            ;;
    esac
done
[ -n "$OUT" ] || { print_usage >&2; exit 2; }
if [ -n "$OBSERVER_BIN" ] && [ -n "$PREBUILT_IMAGE" ]; then
    print_usage >&2
    exit 2
fi
if [ -z "$OBSERVER_BIN" ] && [ -z "$PREBUILT_IMAGE" ]; then
    print_usage >&2
    exit 2
fi
if [ -n "$OBSERVER_BIN" ]; then
    case $OBSERVER_BIN in
        /*) ;;
        *) print_usage >&2; exit 2 ;;
    esac
    [ -f "$OBSERVER_BIN" ] && [ -x "$OBSERVER_BIN" ] || {
        echo "observer binary is not an executable file: $OBSERVER_BIN" >&2
        exit 2
    }
fi
mkdir -p "$OUT" 2>/dev/null || { echo "cannot create OUT: $OUT" >&2; exit 2; }
OUT=$(cd "$OUT" && pwd -P) || { echo "cannot resolve OUT: $OUT" >&2; exit 2; }
: >"$OUT/results.jsonl"

. scripts/lib.sh
. scripts/matrix/matrix-lib.sh

RUN_ID=$(date +%s%N)-$$
# No test container needs the network (the observer and the workload never
# touch it), so every run in this lane is hermetic -- and immune to the
# host's bridge state, which a shared test host may break out from under us.
NET_FLAGS=(--network none)
OBS_IMAGE=
OBS_IMAGE_OWNED=
VICTIM_IMAGE="p11scope-container-victim:$RUN_ID"
VICTIM_NAME="p11scope-container-victim-$RUN_ID"
HPID_H=
WPID=
HPID_R=
OPID=
SPID=
TABLE_CLASS_HOST=
TABLE_CLASS_CONTAINER=

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    for pid in "${HPID_H-}" "${WPID-}" "${HPID_R-}" "${OPID-}"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    for name in "$VICTIM_NAME" \
        "p11scope-container-obs1-$RUN_ID" "p11scope-container-obs2-$RUN_ID" \
        "p11scope-container-obs3-$RUN_ID" "p11scope-container-obs4-$RUN_ID"; do
        docker rm -f "$name" >/dev/null 2>&1 || true
    done
    docker image rm "$VICTIM_IMAGE" >/dev/null 2>&1 || true
    if [ -n "${OBS_IMAGE_OWNED-}" ] && [ -n "${OBS_IMAGE-}" ]; then
        docker image rm "$OBS_IMAGE" >/dev/null 2>&1 || true
    fi
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

require_non_root_caller || exit 2
for tool in docker gcc python3 file softhsm2-util sudo; do
    command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 77; }
done
matrix_private_work container-image || exit 77
mkdir -p "$WORK/shared"
matrix_select_timeout || exit 77
sudo -n true 2>/dev/null || { echo "passwordless sudo required" >&2; exit 77; }
# Every `docker` below (bare or under `timeout`, which cannot see shell
# functions) resolves through this shim. Hosts whose caller is outside
# the docker group (the fedora test host) reach the daemon through
# passwordless sudo instead.
DOCKER_BIN=$(command -v docker)
mkdir -p "$WORK/bin"
if "$DOCKER_BIN" info >/dev/null 2>&1; then
    ln -s "$DOCKER_BIN" "$WORK/bin/docker"
elif sudo -n "$DOCKER_BIN" info >/dev/null 2>&1; then
    printf '#!/bin/sh\nexec sudo -n "%s" "$@"\n' "$DOCKER_BIN" >"$WORK/bin/docker"
    chmod 0755 "$WORK/bin/docker"
else
    echo "docker daemon unavailable (docker info failed)" >&2
    exit 77
fi
PATH="$WORK/bin:$PATH"
export PATH
BTF_PATH=${P11SCOPE_CONTAINER_IMAGE_BTF:-/sys/kernel/btf/vmlinux}
CGROUP_PATH=${P11SCOPE_CONTAINER_IMAGE_CGROUP:-/sys/fs/cgroup/cgroup.controllers}
test -s "$BTF_PATH" || { echo "BTF unavailable ($BTF_PATH)" >&2; exit 77; }
test -f "$CGROUP_PATH" || { echo "cgroup v2 unavailable" >&2; exit 77; }
if [ -n "${P11SCOPE_CONTAINER_IMAGE_MODULE-}" ]; then
    MODULE=$P11SCOPE_CONTAINER_IMAGE_MODULE
    [ -f "$MODULE" ] || { echo "SoftHSM2 not installed (probed Debian/Fedora paths)" >&2; exit 77; }
elif MODULE_PROBED=$(python3 -I scripts/release-matrix-contract.py --select-module 2>/dev/null) \
    && [ -n "$MODULE_PROBED" ]; then
    MODULE=$MODULE_PROBED
else
    MODULE=
    for candidate in /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib64/softhsm/libsofthsm2.so /usr/lib64/pkcs11/libsofthsm2.so; do
        if [ -f "$candidate" ]; then MODULE=$candidate; break; fi
    done
    unset candidate
    [ -n "$MODULE" ] || { echo "SoftHSM2 not installed (probed Debian/Fedora paths)" >&2; exit 77; }
fi
unset MODULE_PROBED

record() {
    python3 -I - "$OUT/results.jsonl" "$1" "$2" "$3" "$4" <<'PY'
import json, sys
path, cell, passed, qualification, detail = sys.argv[1:6]
with open(path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps({"cell": cell, "pass": passed == "1",
                             "qualification": qualification, "detail": detail}) + "\n")
PY
}

echo "=== observer image ==="
if [ -n "$OBSERVER_BIN" ]; then
    file -b "$OBSERVER_BIN" | grep -q "static-pie linked" || {
        echo "observer binary is not static-pie: $OBSERVER_BIN" >&2
        exit 2
    }
    sha256sum "$OBSERVER_BIN" | tee "$OUT/packaged-observer.sha256"
    OCTX="$OUT/context-observer"
    mkdir -p "$OCTX/target/x86_64-unknown-linux-musl/release" "$OCTX/scripts"
    cp "$OBSERVER_BIN" "$OCTX/target/x86_64-unknown-linux-musl/release/p11scope"
    cp scripts/k8s-profile-entry.sh "$OCTX/scripts/"
    BASE=$(sed -n 's/^FROM //p' deploy/Dockerfile.observer)
    test -n "$BASE" || { echo "Dockerfile has no FROM line" >&2; exit 2; }
    test "$(printf '%s\n' "$BASE" | wc -l)" -eq 1 || { echo "Dockerfile has no single base" >&2; exit 2; }
    case $BASE in *@sha256:*) ;; *) echo "base is not digest-pinned: $BASE" >&2; exit 2 ;; esac
    timeout --signal=TERM --kill-after=10s 600s docker pull "$BASE" || exit 2
    OBS_IMAGE="p11scope-container-observer:$RUN_ID"
    timeout --signal=TERM --kill-after=10s 600s docker build --network=none -q \
        -f deploy/Dockerfile.observer -t "$OBS_IMAGE" "$OCTX" >"$OUT/observer-build.log" 2>&1 || {
        tail -n 30 "$OUT/observer-build.log" >&2 || true
        exit 2
    }
    OBS_IMAGE_OWNED=1
else
    OBS_IMAGE=$PREBUILT_IMAGE
    docker inspect "$OBS_IMAGE" >/dev/null 2>&1 || {
        echo "prebuilt image is not loaded: $OBS_IMAGE" >&2
        exit 2
    }
fi
docker inspect --format '{{.Id}}' "$OBS_IMAGE" | tee "$OUT/observer-image-id.txt"
grep -Eq '^sha256:[0-9a-f]{64}$' "$OUT/observer-image-id.txt" || {
    echo "unreadable image id for $OBS_IMAGE" >&2
    exit 2
}
ENTRYPOINT=$(docker inspect --format '{{.Config.Entrypoint}}' "$OBS_IMAGE")
test "$ENTRYPOINT" = "[/usr/local/bin/p11scope]" || {
    echo "image entrypoint is not the observer: $ENTRYPOINT" >&2
    exit 2
}
timeout --signal=TERM --kill-after=10s 60s docker run --rm "${NET_FLAGS[@]}" "$OBS_IMAGE" --version \
    >"$OUT/observer-version.txt" 2>&1 || {
    echo "image does not run the observer entrypoint" >&2
    exit 2
}
cat "$OUT/observer-version.txt"
docker info --format '{{json .}}' >"$OUT/docker-info.json"

echo "=== token, harness and workload image ==="
export SOFTHSM2_CONF="$OUT/softhsm2.conf"
mkdir -m 700 "$OUT/tokens"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' \
    "$OUT" >"$SOFTHSM2_CONF"
SOFTHSM2_CONF="$SOFTHSM2_CONF" softhsm2-util --init-token --free --label container-cell \
    --so-pin 5678 --pin 1234 || exit 2
timeout --signal=TERM --kill-after=10s 60s gcc -O0 -o "$WORK/harness" spike/harness.c -ldl || exit 2
timeout --signal=TERM --kill-after=10s 600s docker build -q -t "$VICTIM_IMAGE" \
    ${P11SCOPE_MATRIX_BUILD_NETWORK:+--network "$P11SCOPE_MATRIX_BUILD_NETWORK"} \
    -f scripts/matrix/Dockerfile scripts/matrix >"$OUT/victim-build.log" 2>&1 || {
    tail -n 30 "$OUT/victim-build.log" >&2 || true
    exit 2
}

SE_FLAGS=()
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = Enforcing ]; then
    # SELinux-enforcing hosts (Fedora): confinement is not what is under
    # test, and confined test containers cannot use the bind mounts below,
    # so both run unconfined.
    SE_FLAGS+=(--security-opt label=disable)
fi
OBS_FLAGS=(--pid=host --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH)
if [ -r /sys/module/apparmor/parameters/enabled ] \
    && grep -q Y /sys/module/apparmor/parameters/enabled 2>/dev/null; then
    OBS_FLAGS+=(--security-opt apparmor=unconfined)
fi
OBS_FLAGS+=("${SE_FLAGS[@]}")
OBS_FLAGS+=("${NET_FLAGS[@]}")
OBS_FLAGS+=(-v /sys/fs/cgroup:/sys/fs/cgroup:ro)
echo "observer flags: ${OBS_FLAGS[*]}"

MODULE_IN_CONTAINER=/usr/lib/softhsm/libsofthsm2.so
DURATION=12

assert_module_identity() {
    # The report names the attributed provider file by (path, mountinfo
    # device, sha256) as seen from the target: the mount's major:minor from
    # the target's mountinfo (longest-prefix match, like the observer's
    # mountinfo identity source) and the content hash of the expected file.
    # stat st_dev is deliberately not used (on btrfs it disagrees with
    # mountinfo's major:minor for the same file), and so is the inode
    # number: the container overlay aliases one provider's bytes under two
    # inodes depending on whether lookup passes through the compatibility
    # symlink. The caller captures the mountinfo and hash while the target
    # is known alive; the oracle only reads files, so it needs no
    # privilege.
    python3 -I - "$1" "$2" "$3" <<'PY' || return 1
import json, sys
observed, mountinfo, expected_sha256 = sys.argv[1], sys.argv[2], sys.argv[3]
document = json.load(open(observed, encoding="utf-8"))
modules = document["capture"]["modules"]
assert len(modules) == 1, modules
module = modules[0]
path = module["path"]
assert path.endswith("libsofthsm2.so"), module
best = None
with open(mountinfo, encoding="utf-8") as handle:
    for line in handle:
        pre = line.split(" - ", 1)[0].split(" ")
        mountpoint, major_minor = pre[4], pre[2]
        if path == mountpoint or path.startswith(mountpoint.rstrip("/") + "/"):
            if best is None or len(mountpoint) > len(best[0]):
                major, minor = (int(part) for part in major_minor.split(":"))
                best = (mountpoint, major, minor)
assert best is not None, f"no mount covers {path} in {mountinfo}"
assert module["dev"] == [best[1], best[2]], (module, best)
assert expected_sha256 == module["sha256"], (module, expected_sha256)
evidence = document["evidence"]
assert [m["sources"] for m in evidence["discovery"]] == [["scan"]], evidence["discovery"]
assert evidence["authority"] == "hash-pinned", evidence["authority"]
assert evidence["scan_unavailable"] is None, evidence["scan_unavailable"]
assert evidence["drain_proven"] is True, evidence
print("attributed:", module["path"], module["dev"], module["sha256"][:16])
PY
}

classify_provider_tables() {
    # The host leg runs against the host's SoftHSM, whose table shape is
    # environmental: 2.6 publishes one 68-entry exports table ([2,40]),
    # while 2.7 publishes the same 68 slots twice (exports plus the live
    # C_GetFunctionList return, [3,2] -- scripts/ci/fedora-softhsm-cell.sh
    # agrees this {3,2} 68-slot shape is the real 2.7 provider). Prints
    # 26 or 27 and fails closed on anything else. For 27 it also runs the
    # version-independent core of the capture oracle (the oracle's own
    # functions, not a copy): schema, common, counters, capture modules,
    # scan-only sources, uncorroborated. check-capture-evidence.py
    # clean-metrics itself stays 2.6-calibrated and judges the 26 path.
    python3 -I - "$1" <<'PY' || return 1
import importlib.util
import json
import sys
observed = sys.argv[1]
document = json.load(open(observed, encoding="utf-8"))
spec = importlib.util.spec_from_file_location(
    "check_capture_evidence", "scripts/check-capture-evidence.py")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
oracle.exact_metrics_schema(document)
discovery = document["evidence"]["discovery"]
assert len(discovery) == 1, discovery
tables = sorted(
    (t["entries"], t["exports_agreeing"], t["linkage"], tuple(t["version"]))
    for t in (discovery[0].get("tables") or [])
)
if tables == [(68, 68, "exports", (2, 40))]:
    print("26")
elif tables == [(68, 68, "exports", (3, 2)), (68, 68, "live_return", (3, 2))]:
    evidence = document["evidence"]
    oracle.exact_common(evidence, aliases=[], skipped=[], in_flight=0)
    oracle.exact_counters(evidence)
    oracle.exact_capture_modules(document)
    sources = [m["sources"] for m in evidence["discovery"]]
    assert sources == [["scan"]], sources
    corroborated = [m["corroborated"] for m in evidence["discovery"]]
    assert corroborated == [False], corroborated
    print("27")
else:
    raise SystemExit(f"unknown provider table shape: {tables}")
PY
}

kill_obs() {
    if [ -n "${OPID-}" ]; then
        kill "$OPID" 2>/dev/null || true
        wait "$OPID" 2>/dev/null || true
        OPID=
    fi
    SPID=
}

leg_host() {
    echo "=== leg: host-exact ==="
    local name log hlog
    name="p11scope-container-obs1-$RUN_ID"
    log="$OUT/host-observer.log"
    hlog="$OUT/host-harness.log"
    rm -f "$WORK/shared/go-h" "$WORK/shared/fin-h" || return 1
    SOFTHSM2_CONF="$SOFTHSM2_CONF" "$WORK/harness" "$MODULE" \
        "$WORK/shared/go-h" "$WORK/shared/fin-h" >"$hlog" 2>&1 &
    HPID_H=$!
    local attempt
    attempt=0
    while [ "$attempt" -lt 200 ]; do
        grep -Fq libsofthsm2.so "/proc/$HPID_H/maps" 2>/dev/null && break
        attempt=$((attempt + 1))
        sleep 0.05
    done
    grep -Fq libsofthsm2.so "/proc/$HPID_H/maps" 2>/dev/null || return 1
    cat "/proc/$HPID_H/mountinfo" >"$OUT/host-mountinfo.txt" || return 1
    local host_sha
    host_sha=$(sha256sum "$MODULE" | cut -d' ' -f1) || return 1
    timeout --signal=TERM --kill-after=10s 90s docker run --name "$name" "${OBS_FLAGS[@]}" \
        "$OBS_IMAGE" profile --pid "$HPID_H" --mode metrics --duration "$DURATION" \
        -o /tmp/host.json >"$log" 2>&1 &
    OPID=$!
    SPID=$OPID
    wait_for_capture_ready "$log" aggregate-only metrics || {
        kill_obs
        docker rm -f "$name" >/dev/null 2>&1 || true
        return 1
    }
    SPID=
    touch "$WORK/shared/go-h" || return 1
    wait "$OPID" || {
        OPID=
        docker rm -f "$name" >/dev/null 2>&1 || true
        return 1
    }
    OPID=
    touch "$WORK/shared/fin-h" || return 1
    wait "$HPID_H" || return 1
    HPID_H=
    docker cp "$name:/tmp/host.json" "$OUT/host.json" >/dev/null 2>&1 || {
        docker rm -f "$name" >/dev/null 2>&1 || true
        return 1
    }
    reclaim_root_output "$OUT/host.json" || return 1
    docker rm -f "$name" >/dev/null 2>&1 || return 1
    python3 -I scripts/matrix/check-count-multiset.py "$OUT/host.json" spike/expected.txt \
        >>"$OUT/host-oracle.log" 2>&1 || return 1
    local table_class
    table_class=$(classify_provider_tables "$OUT/host.json" 2>>"$OUT/host-oracle.log") || return 1
    echo "provider table class: $table_class" >>"$OUT/host-oracle.log"
    TABLE_CLASS_HOST=$table_class
    case $table_class in
        26)
            python3 -I scripts/check-capture-evidence.py clean-metrics "$OUT/host.json" spike/expected.txt \
                >>"$OUT/host-oracle.log" 2>&1 || return 1
            ;;
        27) ;;
        *)
            echo "unknown provider table shape: $table_class" >&2
            return 1
            ;;
    esac
    assert_module_identity "$OUT/host.json" "$OUT/host-mountinfo.txt" "$host_sha" \
        >>"$OUT/host-oracle.log" 2>&1 || return 1
    return 0
}

leg_container() {
    echo "=== leg: container-exact ==="
    local name log wlog
    name="p11scope-container-obs2-$RUN_ID"
    log="$OUT/container-observer.log"
    wlog="$OUT/container-workload.log"
    rm -f "$WORK/shared/go-c" "$WORK/shared/fin-c" || return 1
    timeout --signal=TERM --kill-after=10s 60s docker run -d --name "$VICTIM_NAME" "${SE_FLAGS[@]}" \
        "${NET_FLAGS[@]}" \
        -v "$WORK/harness:/usr/local/bin/harness:ro" -v "$WORK/shared:/shared" \
        "$VICTIM_IMAGE" >/dev/null || return 1
    local vpid
    vpid=$(timeout --signal=TERM --kill-after=10s 60s docker inspect -f '{{.State.Pid}}' "$VICTIM_NAME") \
        || return 1
    case $vpid in ''|*[!0-9]*|0) echo "could not get container pid" >&2; return 1 ;; esac
    echo "$vpid" >"$OUT/victim-pid.txt"
    local cgroup_rel
    cgroup_rel=$(awk -F: '$1 == "0" && $2 == "" { print $3; exit }' "/proc/$vpid/cgroup") || return 1
    case $cgroup_rel in /*) ;; *) echo "unified cgroup entry missing for container $vpid" >&2; return 1 ;; esac
    local cgroup_path
    cgroup_path="/sys/fs/cgroup$cgroup_rel"
    test -d "$cgroup_path" || return 1
    echo "$cgroup_path" >"$OUT/victim-cgroup.txt"
    timeout --signal=TERM --kill-after=10s 150s docker exec "$VICTIM_NAME" \
        /usr/local/bin/harness "$MODULE_IN_CONTAINER" /shared/go-c /shared/fin-c \
        >"$wlog" 2>&1 &
    WPID=$!
    wait_for_cgroup_provider "$cgroup_path" libsofthsm2.so || return 1
    sudo -n cat "/proc/$vpid/mountinfo" >"$OUT/victim-mountinfo.txt" || return 1
    local victim_sha
    victim_sha=$(sudo -n sha256sum "/proc/$vpid/root$MODULE_IN_CONTAINER" | cut -d' ' -f1) || return 1
    timeout --signal=TERM --kill-after=10s 90s docker run --name "$name" "${OBS_FLAGS[@]}" \
        "$OBS_IMAGE" profile --cgroup "$cgroup_path" --mode metrics --duration "$DURATION" \
        -o /tmp/container.json >"$log" 2>&1 &
    OPID=$!
    SPID=$OPID
    wait_for_capture_ready "$log" aggregate-only metrics || {
        kill_obs
        docker rm -f "$name" >/dev/null 2>&1 || true
        return 1
    }
    SPID=
    touch "$WORK/shared/go-c" || return 1
    wait "$OPID" || {
        OPID=
        docker rm -f "$name" >/dev/null 2>&1 || true
        return 1
    }
    OPID=
    touch "$WORK/shared/fin-c" || return 1
    wait "$WPID" || return 1
    WPID=
    docker cp "$name:/tmp/container.json" "$OUT/container.json" >/dev/null 2>&1 || {
        docker rm -f "$name" >/dev/null 2>&1 || true
        return 1
    }
    reclaim_root_output "$OUT/container.json" || return 1
    docker rm -f "$name" >/dev/null 2>&1 || return 1
    # clean-metrics stays 2.6-calibrated while the victim image floats with
    # its archive: prove the victim is still 2.6-shaped first, and fail
    # closed (not multiset-degraded) when it drifts, so the drift gets a
    # conscious re-qualification instead of a silently weaker leg.
    local table_class
    table_class=$(classify_provider_tables "$OUT/container.json" 2>>"$OUT/container-oracle.log") || return 1
    echo "provider table class: $table_class" >>"$OUT/container-oracle.log"
    TABLE_CLASS_CONTAINER=$table_class
    case $table_class in
        26) ;;
        *)
            echo "victim provider table class $table_class is not 2.6-shaped" >&2
            return 1
            ;;
    esac
    python3 -I scripts/check-capture-evidence.py clean-metrics "$OUT/container.json" spike/expected.txt \
        >>"$OUT/container-oracle.log" 2>&1 || return 1
    python3 -I scripts/matrix/check-count-multiset.py "$OUT/container.json" spike/expected.txt \
        >>"$OUT/container-oracle.log" 2>&1 || return 1
    assert_module_identity "$OUT/container.json" "$OUT/victim-mountinfo.txt" "$victim_sha" \
        >>"$OUT/container-oracle.log" 2>&1 || return 1
    docker rm -f "$VICTIM_NAME" >/dev/null 2>&1 || return 1
    return 0
}

start_refusal_target() {
    rm -f "$WORK/shared/go-r" || return 1
    SOFTHSM2_CONF="$SOFTHSM2_CONF" "$WORK/harness" "$MODULE" "$WORK/shared/go-r" \
        >"$OUT/refusal-harness.log" 2>&1 &
    HPID_R=$!
    local attempt
    attempt=0
    while [ "$attempt" -lt 200 ]; do
        grep -Fq libsofthsm2.so "/proc/$HPID_R/maps" 2>/dev/null && break
        attempt=$((attempt + 1))
        sleep 0.05
    done
    grep -Fq libsofthsm2.so "/proc/$HPID_R/maps" 2>/dev/null || return 1
    return 0
}

stop_refusal_target() {
    if [ -n "${HPID_R-}" ]; then
        kill "$HPID_R" 2>/dev/null || true
        wait "$HPID_R" 2>/dev/null || true
        HPID_R=
    fi
}

leg_refusal_pidns() {
    echo "=== leg: refusal-pidns ==="
    local name log flag
    name="p11scope-container-obs3-$RUN_ID"
    log="$OUT/refusal-pidns.log"
    local -a rflags
    rflags=()
    for flag in "${OBS_FLAGS[@]}"; do
        [ "$flag" = "--pid=host" ] || rflags+=("$flag")
    done
    [[ " ${rflags[*]} " != *" --pid=host "* ]] || {
        echo "pidns flag filter failed" >&2
        return 1
    }
    [[ " ${rflags[*]} " == *" SYS_PTRACE "* ]] || {
        echo "pidns leg lost a cap" >&2
        return 1
    }
    local rc
    rc=0
    timeout --signal=TERM --kill-after=10s 60s docker run --name "$name" "${rflags[@]}" \
        "$OBS_IMAGE" profile --pid "$HPID_R" --mode metrics --duration 5 \
        -o /tmp/ref-pidns.json >"$log" 2>&1 || rc=$?
    [ "$rc" -ne 0 ] || {
        echo "refusal leg unexpectedly succeeded" >&2
        return 1
    }
    grep -Fq 'pid-namespace-mismatch: refusing --pid' "$log" || return 1
    grep -Fq 'docker: --pid=host' "$log" || return 1
    if docker cp "$name:/tmp/ref-pidns.json" "$OUT/ref-pidns.json" >/dev/null 2>&1; then
        echo "refusal wrote a report" >&2
        return 1
    fi
    docker rm -f "$name" >/dev/null 2>&1 || return 1
    return 0
}

leg_refusal_cap() {
    echo "=== leg: refusal-cap ==="
    local name log
    name="p11scope-container-obs4-$RUN_ID"
    log="$OUT/refusal-cap.log"
    local -a rflags
    rflags=()
    local i n
    i=0
    n=${#OBS_FLAGS[@]}
    while [ "$i" -lt "$n" ]; do
        if [ "${OBS_FLAGS[$i]}" = "--cap-add" ] && [ "$((i + 1))" -lt "$n" ] \
            && [ "${OBS_FLAGS[$((i + 1))]}" = "SYS_PTRACE" ]; then
            i=$((i + 2))
        else
            rflags+=("${OBS_FLAGS[$i]}")
            i=$((i + 1))
        fi
    done
    [[ " ${rflags[*]} " != *" SYS_PTRACE "* ]] || {
        echo "cap filter kept SYS_PTRACE" >&2
        return 1
    }
    [[ " ${rflags[*]} " == *" SYS_ADMIN "* ]] || {
        echo "cap leg lost SYS_ADMIN" >&2
        return 1
    }
    [[ " ${rflags[*]} " == *" DAC_READ_SEARCH "* ]] || {
        echo "cap leg lost DAC_READ_SEARCH" >&2
        return 1
    }
    local rc
    rc=0
    timeout --signal=TERM --kill-after=10s 60s docker run --name "$name" "${rflags[@]}" \
        "$OBS_IMAGE" profile --pid "$HPID_R" --mode metrics --duration 5 \
        -o /tmp/ref-cap.json >"$log" 2>&1 || rc=$?
    [ "$rc" -ne 0 ] || {
        echo "refusal leg unexpectedly succeeded" >&2
        return 1
    }
    grep -Fq 'cannot identify process mount namespace: Permission denied' "$log" || return 1
    grep -Fq 'named process view was not retained' "$log" || return 1
    if docker cp "$name:/tmp/ref-cap.json" "$OUT/ref-cap.json" >/dev/null 2>&1; then
        echo "refusal wrote a report" >&2
        return 1
    fi
    docker rm -f "$name" >/dev/null 2>&1 || return 1
    return 0
}

echo "=== legs ==="
FAILED=0
if leg_host; then
    if [ "$TABLE_CLASS_HOST" = 26 ]; then
        record host-exact 1 qualified "exact counts, host provider file attributed (provider table class 26)"
    else
        record host-exact 1 qualified "multiset counts plus oracle core, host provider file attributed (provider table class $TABLE_CLASS_HOST)"
    fi
else
    record host-exact 0 failed "see host-observer.log and host-oracle.log"
    FAILED=1
fi
if leg_container; then
    record container-exact 1 qualified "exact counts, victim provider file attributed (provider table class $TABLE_CLASS_CONTAINER)"
else
    record container-exact 0 failed "see container-observer.log and container-oracle.log"
    FAILED=1
fi
if start_refusal_target; then
    if leg_refusal_pidns; then
        record refusal-pidns 1 qualified "pid-namespace-mismatch named, no report"
    else
        record refusal-pidns 0 failed "see refusal-pidns.log"
        FAILED=1
    fi
    if leg_refusal_cap; then
        record refusal-cap 1 qualified "mount-namespace denial named, no report"
    else
        record refusal-cap 0 failed "see refusal-cap.log"
        FAILED=1
    fi
    stop_refusal_target
else
    record refusal-pidns 0 failed "refusal target never mapped its provider"
    record refusal-cap 0 failed "refusal target never mapped its provider"
    FAILED=1
    stop_refusal_target
fi

python3 -I - "$OUT/results.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
passed = sum(1 for row in rows if row["pass"])
failed = [row["cell"] for row in rows if not row["pass"]]
print(f"SUMMARY pass={passed} fail={len(failed)} failed={failed}")
PY
if [ "$FAILED" -ne 0 ]; then exit 1; fi
echo "=== container-image: ALL OK ==="
exit 0

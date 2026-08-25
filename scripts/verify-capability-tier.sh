#!/bin/sh
# Measure the two host capability rows that differ only by tracefs access.
set -eu
cd "$(dirname "$0")/.."

self_test() {
    python3 - <<'PY'
degraded = {
    "evidence": {
        "attached_probes": 136,
        "completeness": "PARTIAL",
        "attach_failures": [],
        "skipped": [{"name": "discovery subject", "reason": "discovery unavailable"}],
    }
}
refused = {
    "evidence": {
        "attached_probes": 0,
        "completeness": "PARTIAL",
        "attach_failures": ["permission denied"],
    }
}

def degraded_oracle(document):
    evidence = document["evidence"]
    assert evidence["attached_probes"] == 136
    assert evidence["completeness"] == "PARTIAL"
    assert evidence["attach_failures"] == []
    assert {item["reason"] for item in evidence["skipped"]} >= {"discovery unavailable"}

def refused_oracle(document):
    evidence = document["evidence"]
    assert evidence["attached_probes"] == 0
    assert evidence["completeness"] == "PARTIAL"
    assert evidence["attach_failures"]

degraded_oracle(degraded)
refused_oracle(refused)
for document in [
    {**degraded, "evidence": {**degraded["evidence"], "attached_probes": 135}},
    {**degraded, "evidence": {**degraded["evidence"], "completeness": "COMPLETE"}},
    {**refused, "evidence": {**refused["evidence"], "attached_probes": 1}},
]:
    try:
        (degraded_oracle if document["evidence"]["attached_probes"] else refused_oracle)(document)
    except AssertionError:
        continue
    raise SystemExit("capability-tier oracle accepted a mutation")
print("capability-tier self-test: OK")
PY
}

[ "${1-}" != "--self-test" ] || { [ "$#" -eq 1 ] || exit 2; self_test; exit 0; }
[ "$#" -eq 0 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }

command -v cargo >/dev/null || { echo "cargo required" >&2; exit 1; }
command -v gcc >/dev/null || { echo "gcc required" >&2; exit 1; }
command -v capsh >/dev/null || { echo "capsh required" >&2; exit 1; }
sudo -n true 2>/dev/null || { echo "passwordless sudo required" >&2; exit 1; }

MODULE=/usr/lib/softhsm/libsofthsm2.so
[ -f "$MODULE" ] || { echo "SoftHSM2 not installed at $MODULE" >&2; exit 1; }
WORK=target/capability-tier
BIN="$PWD/target/release/p11scope"
HARNESS="$WORK/harness"
MANIFEST="$WORK/manifest.json"
TARGET_PID=

cleanup() {
    status=$?
    [ -z "$TARGET_PID" ] || kill -TERM "$TARGET_PID" 2>/dev/null || true
    [ -z "$TARGET_PID" ] || wait "$TARGET_PID" 2>/dev/null || true
    exit "$status"
}
trap cleanup EXIT INT TERM

cargo +1.88 build --locked --release --workspace
mkdir -p "$WORK"
gcc -O2 -o "$HARNESS" spike/harness.c -ldl
"$PWD/target/release/p11scope-discover" --module "$MODULE" -o "$MANIFEST"

wait_for_mapping() {
    tries=0
    while [ "$tries" -lt 100 ]; do
        grep -Fq libsofthsm2.so "/proc/$TARGET_PID/maps" 2>/dev/null && return 0
        kill -0 "$TARGET_PID" 2>/dev/null || return 1
        tries=$((tries + 1))
        sleep 0.05
    done
    return 1
}

start_target() {
    rm -f "$WORK/go"
    "$HARNESS" "$MODULE" "$WORK/go" >"$WORK/harness.log" 2>&1 &
    TARGET_PID=$!
    wait_for_mapping || { echo "target did not map SoftHSM2" >&2; return 1; }
}

stop_target() {
    kill -TERM "$TARGET_PID" 2>/dev/null || true
    wait "$TARGET_PID" 2>/dev/null || true
    TARGET_PID=
}

run_row() {
    label=$1
    caps=$2
    ambient=$3
    out="$WORK/$label.json"
    log="$WORK/$label.log"
    rm -f "$out" "$log"
    start_target
    set +e
    sudo capsh --caps="$caps" --keep=1 --user="$(id -un)" $ambient -- \
        -c "'$BIN' profile --manifest '$PWD/$MANIFEST' --pid $TARGET_PID --mode metrics --duration 1 -o '$PWD/$out'" \
        >"$log" 2>&1
    rc=$?
    set -e
    stop_target
    printf '%s\n' "$rc"
}

SYSADMIN_CAPS='cap_sys_admin+eip cap_setpcap,cap_setuid,cap_setgid+ep'
SYSADMIN_AMBIENT='--addamb=cap_sys_admin'
BPF_PERFMON_CAPS='cap_bpf,cap_perfmon+eip cap_setpcap,cap_setuid,cap_setgid+ep'
BPF_PERFMON_AMBIENT='--addamb=cap_bpf --addamb=cap_perfmon'

# The row is meaningful only when Aya cannot read either tracefs ID path as
# the capability-restricted observer. Do not silently measure the enhanced tier.
if ! sudo capsh --caps="$SYSADMIN_CAPS" --keep=1 --user="$(id -un)" $SYSADMIN_AMBIENT -- \
    -c 'test ! -r /sys/kernel/tracing/events/sched/sched_process_exec/id && test ! -r /sys/kernel/debug/tracing/events/sched/sched_process_exec/id'
then
    echo "UNRUN: tracefs is readable for the CAP_SYS_ADMIN observer; enhanced tier measured instead" >&2
    exit 2
fi

SYSADMIN_RC=$(run_row sysadmin "$SYSADMIN_CAPS" "$SYSADMIN_AMBIENT")
python3 - "$WORK/sysadmin.json" "$SYSADMIN_RC" <<'PY'
import json, os, sys

path, rc = sys.argv[1:]
assert os.path.exists(path), f"CAP_SYS_ADMIN produced no document (exit {rc})"
evidence = json.load(open(path))["evidence"]
assert evidence["attached_probes"] == 136, evidence["attached_probes"]
assert evidence["completeness"] == "PARTIAL", evidence["completeness"]
assert evidence["attach_failures"] == [], evidence["attach_failures"]
assert any(item["reason"] == "discovery unavailable" for item in evidence["skipped"]), evidence["skipped"]
print("CAP_SYS_ADMIN: 136 probes, degraded lifecycle evidence, PARTIAL")
PY

BPF_PERFMON_RC=$(run_row bpf-perfmon "$BPF_PERFMON_CAPS" "$BPF_PERFMON_AMBIENT")
if [ -s "$WORK/bpf-perfmon.json" ]; then
    python3 - "$WORK/bpf-perfmon.json" <<'PY'
import json, sys
evidence = json.load(open(sys.argv[1]))["evidence"]
assert evidence["attached_probes"] == 0, evidence["attached_probes"]
assert evidence["completeness"] == "PARTIAL", evidence["completeness"]
assert evidence["attach_failures"], evidence["attach_failures"]
print("CAP_BPF+CAP_PERFMON: zero-probe refusal shape")
PY
else
    grep -Eq 'Permission denied|Operation not permitted' "$WORK/bpf-perfmon.log" || {
        echo "CAP_BPF+CAP_PERFMON failed unexpectedly (exit $BPF_PERFMON_RC)" >&2
        exit 1
    }
    echo "CAP_BPF+CAP_PERFMON: no document; permission refusal (exit $BPF_PERFMON_RC)"
fi

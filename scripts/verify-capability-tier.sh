#!/bin/sh
# Measure the two host capability rows that differ only by tracefs access.
set -eu
cd "$(dirname "$0")/.."

check_row() {
    python3 - "$@" <<'PY'
import json
import os
import sys

if len(sys.argv) != 4:
    raise SystemExit("usage: checker ROW EXIT_STATUS DOCUMENT")
row, raw_status, path = sys.argv[1:]
try:
    status = int(raw_status)
except ValueError:
    raise SystemExit(f"{row}: invalid exit status {raw_status!r}")
if status != 0:
    raise SystemExit(f"{row}: expected exit 0, got {status}")
if not os.path.isfile(path):
    raise SystemExit(f"{row}: produced no document")
try:
    with open(path, encoding="utf-8") as source:
        evidence = json.load(source)["evidence"]
except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
    raise SystemExit(f"{row}: invalid document: {error}")
if not isinstance(evidence, dict):
    raise SystemExit(f"{row}: evidence is not an object")
if evidence.get("completeness") != "PARTIAL":
    raise SystemExit(f"{row}: expected PARTIAL, got {evidence.get('completeness')!r}")
attached_probes = evidence.get("attached_probes")
if type(attached_probes) is not int:
    raise SystemExit(f"{row}: attached_probes is not an integer")
failures = evidence.get("attach_failures")
if not isinstance(failures, list):
    raise SystemExit(f"{row}: attach_failures is not a list")
skipped = evidence.get("skipped")
has_sanitized_discovery_skips = isinstance(skipped, list) and bool(skipped) and all(
    isinstance(skip, dict)
    and set(skip) == {"name", "reason"}
    and skip["name"] == "discovery subject"
    and skip["reason"] == "discovery unavailable"
    for skip in skipped
)
if row == "sysadmin":
    if attached_probes != 136:
        raise SystemExit(f"{row}: expected 136 attached probes, got {attached_probes!r}")
    if failures != []:
        raise SystemExit(f"{row}: expected zero attach failures, got {failures!r}")
    if not has_sanitized_discovery_skips or len(skipped) != 2:
        raise SystemExit(f"{row}: expected exactly two sanitized discovery-unavailable skips")
elif row == "bpf-perfmon":
    if attached_probes != 0:
        raise SystemExit(f"{row}: expected zero attached probes, got {attached_probes!r}")
    if len(failures) != 68:
        raise SystemExit(f"{row}: expected 68 attach failures, got {len(failures)}")
    if not all(
        type(failure) is str and "`perf_event_open` failed: Permission denied" in failure
        for failure in failures
    ):
        raise SystemExit(f"{row}: expected perf_event_open refusal for every attach failure")
    if not has_sanitized_discovery_skips or len(skipped) != 4:
        raise SystemExit(f"{row}: expected exactly four sanitized discovery-unavailable skips")
else:
    raise SystemExit(f"unknown capability row {row!r}")
print(f"{row}: expected capability-tier shape")
PY
}

write_self_test_document() {
    python3 - "$@" <<'PY'
import json
import sys

path, row, mutation = sys.argv[1:]
perf_event_open_refusal = (
    "p11_entry at /usr/lib/softhsm/libsofthsm2.so+0x265b0: "
    "`perf_event_open` failed: Permission denied (os error 13)"
)
document = {"evidence": {
    "attached_probes": 136 if row == "sysadmin" else 0,
    "completeness": "PARTIAL",
    "attach_failures": [] if row == "sysadmin" else [perf_event_open_refusal] * 68,
    "skipped": [{"name": "discovery subject", "reason": "discovery unavailable"}] * (
        2 if row == "sysadmin" else 4
    ),
}}
evidence = document["evidence"]
if mutation == "wrong-attached":
    evidence["attached_probes"] = 135 if row == "sysadmin" else 1
elif mutation == "boolean-attached":
    evidence["attached_probes"] = False
elif mutation == "complete":
    evidence["completeness"] = "COMPLETE"
elif mutation == "wrong-skip-name":
    evidence["skipped"] = [{"name": "another subject", "reason": "discovery unavailable"}]
elif mutation == "too-few-skips":
    evidence["skipped"] = evidence["skipped"][:-1]
elif mutation == "too-many-skips":
    evidence["skipped"].append({"name": "discovery subject", "reason": "discovery unavailable"})
elif mutation == "missing-sysadmin-skip":
    evidence["skipped"] = []
elif mutation == "nonlist-sysadmin-skip":
    evidence["skipped"] = "discovery unavailable"
elif mutation == "malformed-skip-reason":
    evidence["skipped"] = [{"name": "discovery subject", "reason": ["discovery unavailable"]}]
elif mutation == "extra-skip-field":
    evidence["skipped"] = [{"name": "discovery subject", "reason": "discovery unavailable", "extra": True}]
elif mutation == "nonempty-sysadmin-failures":
    evidence["attach_failures"] = ["slot 0: permission denied"]
elif mutation == "nonobject-evidence":
    document["evidence"] = []
elif mutation == "nonlist-attach-failures":
    evidence["attach_failures"] = "none"
elif mutation == "short-bpf-failures":
    evidence["attach_failures"] = evidence["attach_failures"][:-1]
elif mutation == "arbitrary-bpf-failure":
    evidence["attach_failures"] = ["slot 0: arbitrary failure"] * 68
elif mutation == "nonstring-bpf-failure":
    evidence["attach_failures"][0] = None
elif mutation == "unexpected-bpf-skip":
    evidence["skipped"] = [{"name": "another subject", "reason": "discovery unavailable"}]
elif mutation != "baseline":
    raise SystemExit(f"unknown self-test mutation {mutation!r}")
with open(path, "w", encoding="utf-8") as output:
    json.dump(document, output)
PY
}

self_test() {
    work=$(mktemp -d)
    self_test_cleanup() { rm -rf "$work"; }
    trap self_test_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    sysadmin="$work/sysadmin.json"
    bpf_perfmon="$work/bpf-perfmon.json"
    write_self_test_document "$sysadmin" sysadmin baseline
    write_self_test_document "$bpf_perfmon" bpf-perfmon baseline
    check_row sysadmin 0 "$sysadmin"
    check_row bpf-perfmon 0 "$bpf_perfmon"
    reject() {
        row=$1
        status=$2
        document=$3
        mutation=$4
        if check_row "$row" "$status" "$document"; then
            echo "capability-tier $row oracle accepted $mutation" >&2
            exit 1
        fi
    }
    reject_mutation() {
        row=$1
        mutation=$2
        document="$work/$row-$mutation.json"
        write_self_test_document "$document" "$row" "$mutation"
        reject "$row" 0 "$document" "$mutation"
    }
    reject sysadmin 0 "$work/missing.json" missing-document
    reject sysadmin 1 "$sysadmin" nonzero-status
    reject_mutation sysadmin wrong-attached
    reject_mutation sysadmin complete
    reject_mutation sysadmin wrong-skip-name
    reject_mutation sysadmin too-few-skips
    reject_mutation sysadmin too-many-skips
    reject_mutation sysadmin missing-sysadmin-skip
    reject_mutation sysadmin nonlist-sysadmin-skip
    reject_mutation sysadmin malformed-skip-reason
    reject_mutation sysadmin extra-skip-field
    reject_mutation sysadmin nonempty-sysadmin-failures
    reject_mutation sysadmin nonobject-evidence
    reject_mutation sysadmin nonlist-attach-failures
    reject bpf-perfmon 0 "$work/missing.json" missing-document
    reject bpf-perfmon 1 "$bpf_perfmon" nonzero-status
    reject_mutation bpf-perfmon wrong-attached
    reject_mutation bpf-perfmon boolean-attached
    reject_mutation bpf-perfmon complete
    reject_mutation bpf-perfmon too-few-skips
    reject_mutation bpf-perfmon too-many-skips
    reject_mutation bpf-perfmon short-bpf-failures
    reject_mutation bpf-perfmon arbitrary-bpf-failure
    reject_mutation bpf-perfmon nonstring-bpf-failure
    reject_mutation bpf-perfmon unexpected-bpf-skip
    echo "capability-tier self-test: OK"
}

[ "${1-}" != "--self-test" ] || { [ "$#" -eq 1 ] || exit 2; self_test; exit 0; }
[ "$#" -eq 0 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }
command -v cargo >/dev/null || { echo "cargo required" >&2; exit 1; }
command -v gcc >/dev/null || { echo "gcc required" >&2; exit 1; }
command -v capsh >/dev/null || { echo "capsh required" >&2; exit 1; }
sudo -n true 2>/dev/null || { echo "passwordless sudo required" >&2; exit 1; }

MODULE=${P11SCOPE_PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}
[ -f "$MODULE" ] || { echo "SoftHSM2 not installed at $MODULE" >&2; exit 1; }
# See verify-canaries.sh: the observer refuses an output directory with a
# group/world-writable non-sticky ancestor, which this checkout has. This lane
# has no work-path override, so the private 0700 root is its only work root.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-verify-XXXXXX")/target/capability-tier
echo "work root: $WORK"
BIN="$PWD/target/release/p11scope"
HARNESS="$WORK/harness"
MANIFEST="$WORK/manifest.json"
TARGET_PID=
CURRENT_ROW=

record_metadata() {
    {
        printf 'head='; git rev-parse HEAD
        printf 'binary_sha256='; sha256sum "$BIN" | awk '{print $1}'
        printf 'uid_gid='; id
        printf 'capabilities='; grep '^Cap' /proc/self/status
        printf 'capsh='; capsh --print
        printf 'kernel='; uname -a
        printf 'perf_event_paranoid='; cat /proc/sys/kernel/perf_event_paranoid
        printf 'ptrace_scope='; cat /proc/sys/kernel/yama/ptrace_scope
        printf 'tracefs_mounts\n'; grep -E 'tracefs|debugfs' /proc/mounts || true
        for path in /sys/kernel/tracing /sys/kernel/debug/tracing \
            /sys/kernel/tracing/events/sched/sched_process_exec/id \
            /sys/kernel/debug/tracing/events/sched/sched_process_exec/id; do
            if stat -c 'stat %n mode=%a uid=%u gid=%g' "$path"; then :; else
                printf 'stat %s unavailable\n' "$path"
            fi
            if [ -r "$path" ]; then printf 'readable %s=yes\n' "$path"; else
                printf 'readable %s=no\n' "$path"
            fi
        done
    } >"$WORK/metadata.txt"
}
row_metadata() { printf '%s\n' "$2" >>"$WORK/$1.metadata"; }

stop_target() {
    [ -n "$TARGET_PID" ] || return 0
    target=$TARGET_PID
    if kill -TERM "$target" 2>/dev/null; then signal=sent; else signal=not-needed; fi
    set +e
    wait "$target"
    wait_status=$?
    set -e
    TARGET_PID=
    if [ "$wait_status" -eq 127 ]; then
        row_metadata "${CURRENT_ROW:-cleanup}" "cleanup signal=$signal wait_status=$wait_status quiescent=no"
        return 1
    fi
    row_metadata "${CURRENT_ROW:-cleanup}" "cleanup signal=$signal wait_status=$wait_status quiescent=yes"
}
cleanup() {
    if ! stop_target; then
        echo "capability-tier cleanup could not quiesce target" >&2
        return 1
    fi
}
on_exit() {
    status=$?
    trap - EXIT
    if ! cleanup && [ "$status" -eq 0 ]; then status=1; fi
    exit "$status"
}
on_signal() { status=$1; trap - EXIT INT TERM; cleanup || :; exit "$status"; }
trap on_exit EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

cargo +1.88 build --locked --release --workspace
(umask 077; mkdir -p "$WORK")
record_metadata
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
    row_metadata "$CURRENT_ROW" "target_pid=$TARGET_PID"
    if wait_for_mapping; then
        row_metadata "$CURRENT_ROW" "target_mapping=observed"
    else
        row_metadata "$CURRENT_ROW" "target_mapping=not-observed"
        stop_target || true
        return 1
    fi
}
run_row() {
    label=$1
    caps=$2
    ambient=$3
    CURRENT_ROW=$label
    out="$WORK/$label.json"
    stdout="$WORK/$label.stdout"
    stderr="$WORK/$label.stderr"
    meta="$WORK/$label.metadata"
    rm -f "$out" "$stdout" "$stderr" "$meta"
    start_target || return 1
    set +e
    sudo capsh --caps="$caps" --keep=1 --user="$(id -un)" $ambient -- \
        -c "{
            printf 'uid_gid='; id
            printf 'capabilities='; grep '^Cap' /proc/self/status
            printf 'capsh='; capsh --print
            printf 'command=%s\\n' '$BIN profile --manifest $MANIFEST --pid $TARGET_PID --mode metrics --duration 1 -o $out'
        } >> '$meta'
        exec '$BIN' profile --manifest '$MANIFEST' --pid '$TARGET_PID' --mode metrics --duration 1 -o '$out'" \
        >"$stdout" 2>"$stderr"
    status=$?
    set -e
    row_metadata "$label" "exit_status=$status"
    row_metadata "$label" "stderr=$stderr"
    if [ -f "$stderr" ]; then
        printf 'stderr_sha256=' >>"$meta"
        sha256sum "$stderr" | awk '{print $1}' >>"$meta"
    fi
    if ! stop_target; then
        row_metadata "$label" "row_status=cleanup-failed"
        return 125
    fi
    return "$status"
}

SYSADMIN_CAPS='cap_sys_admin+eip cap_setpcap,cap_setuid,cap_setgid+ep'
SYSADMIN_AMBIENT='--addamb=cap_sys_admin'
BPF_PERFMON_CAPS='cap_bpf,cap_perfmon+eip cap_setpcap,cap_setuid,cap_setgid+ep'
BPF_PERFMON_AMBIENT='--addamb=cap_bpf --addamb=cap_perfmon'

# The row is meaningful only when Aya cannot read either tracefs ID path as
# the capability-restricted observer. Do not silently measure the enhanced tier.
if ! sudo capsh --caps="$SYSADMIN_CAPS" --keep=1 --user="$(id -un)" $SYSADMIN_AMBIENT -- \
    -c 'test ! -r /sys/kernel/tracing/events/sched/sched_process_exec/id && test ! -r /sys/kernel/debug/tracing/events/sched/sched_process_exec/id' \
    >"$WORK/sysadmin.tracefs-readability" 2>&1
then
    echo "UNRUN: tracefs is readable for the CAP_SYS_ADMIN observer; enhanced tier measured instead" >&2
    exit 2
fi
if run_row sysadmin "$SYSADMIN_CAPS" "$SYSADMIN_AMBIENT"; then SYSADMIN_RC=0; else SYSADMIN_RC=$?; fi
check_row sysadmin "$SYSADMIN_RC" "$WORK/sysadmin.json"
row_metadata sysadmin "row_status=oracle-accepted"
if run_row bpf-perfmon "$BPF_PERFMON_CAPS" "$BPF_PERFMON_AMBIENT"; then BPF_PERFMON_RC=0; else BPF_PERFMON_RC=$?; fi
check_row bpf-perfmon "$BPF_PERFMON_RC" "$WORK/bpf-perfmon.json"
row_metadata bpf-perfmon "row_status=oracle-accepted"
echo "capability-tier: expected measured row shapes"

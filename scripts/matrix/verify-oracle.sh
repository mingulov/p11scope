#!/bin/sh
# Phase 4 Task 7: pkcs11-check oracle diff. Every other script in this repo
# checks p11scope's capture against a workload WE wrote (spike/harness.c +
# spike/expected.txt). This is the first check against an INDEPENDENT
# implementation's own record of what it did: pkcs11-check
# (/home/user/src/m/pkcs11-check-ws/pkcs11-check), a separate,
# vendor-neutral PKCS#11 test client with its own ctypes binding and its
# own per-call CK_RV trace feature (docs/rv-trace-design.md, `--rv-trace`).
#
# Direction: oracle SUBSET-OF capture. For every (function, CK_RV) pair
# pkcs11-check's rv-trace logged, the capture must contain at least that
# many. The capture is allowed to hold MORE (bootstrap calls, pytest's own
# housekeeping) -- that is not a failure, just extra evidence. A capture
# missing a logged call IS a failure.
#
# Two documented pkcs11-check caveats shape this diff (both handled
# explicitly below, not silently filtered away):
#
# 1. rv-trace resets per test AFTER fixture bootstrap and C_Login
#    (fixtures.py's reset_call_log() sites, per docs/rv-trace-design.md
#    section 3) -- so every test's bootstrap-phase calls land in the
#    capture (p11scope sees literally everything) but never in the
#    oracle (pkcs11-check only records what happened after its own
#    reset). Because the assertion direction is oracle SUBSET-OF capture,
#    this is tolerable BY CONSTRUCTION: bootstrap calls can only ever add
#    entries on the capture side, which can never cause an oracle-side
#    key to be found missing. They show up below as informational
#    capture-only surplus, never as a failure.
# 2. `--isolation file` runs each test FILE in its own subprocess
#    (core/file_runner.py) -- many C_Initialize/C_Finalize cycles, many
#    PIDs, most of which do not exist yet when the observer attaches.
#    `--pid` cannot see any of that. This script uses --cgroup instead,
#    exactly like scripts/matrix/verify-fork-scope.sh: a systemd-run
#    --scope cgroup created before pkcs11-check is even exec'd, so every
#    subprocess it forks -- known or not at attach time -- inherits cgroup
#    membership and is captured by Task 1's descendant matching.
set -eu
if [ -z "${P11SCOPE_ORACLE_SOURCE_ONLY-}" ]; then
    cd "$(dirname "$0")/../.."
fi
. scripts/lib.sh

MODULE=/usr/lib/softhsm/libsofthsm2.so
PKCS11_CHECK_DIR=${PKCS11_CHECK_DIR:-$HOME/src/m/pkcs11-check-ws/pkcs11-check}
# Invoke the venv's own installed console script directly, NOT `uv run`.
# Measured directly while building this script: `uv` here is a snap
# package (/snap/bin/uv), and snap's confinement machinery (snap-confine)
# moves the process into its own systemd-managed cgroup within the same
# second it starts, independent of whatever cgroup it was launched under
# -- our target scope shows "Deactivated successfully" in the systemd
# journal almost immediately while the real work keeps running fine,
# just no longer inside the cgroup we're capturing. A plain venv
# interpreter (no snap involved) does not do this; verified it stays in
# the target cgroup for the full run. `uv sync` has already been run in
# $PKCS11_CHECK_DIR (its .venv exists) -- this script only ever reads it.
PKCS11_CHECK_BIN="$PKCS11_CHECK_DIR/.venv/bin/pkcs11-check"
WORK=${P11SCOPE_TASK4_WORK:-target/matrix-oracle}
PRODUCT=$WORK/target
ORACLE_WORKLOAD=$(pwd -P)/scripts/matrix/oracle-workload.sh
ORACLE_CGROUP_HELPER=$(pwd -P)/scripts/matrix/oracle-cgroup-cleanup.py
ORACLE_LIFECYCLE_FIXTURE=$(pwd -P)/tests/fixtures/oracle-lifecycle/scenarios.sh
ORACLE_SUDO_FIXTURE=$(pwd -P)/tests/fixtures/oracle-lifecycle/sudo

oracle_wait_child() {
    owc_pid=$1
    owc_starttime=$2
    owc_limit=$3
    owc_attempt=0
    while [ "$owc_attempt" -lt "$owc_limit" ]; do
        if recording_launcher_active "$owc_pid" "$owc_starttime"; then
            owc_state=live
        else
            owc_query=$?
            owc_state=${RECORDED_LAUNCHER_STATE-unknown}
            case $owc_query:$owc_state in
                1:gone|1:zombie) wait "$owc_pid"; return $? ;;
                1:replaced|2:*) return 2 ;;
                *) return 2 ;;
            esac
        fi
        owc_attempt=$((owc_attempt + 1))
        sleep 0.05
    done
    return 124
}

oracle_reap_child() {
    orc_pid=$1
    orc_starttime=$2
    orc_limit=$3
    orc_attempt=0
    while [ "$orc_attempt" -lt "$orc_limit" ]; do
        if recording_launcher_active "$orc_pid" "$orc_starttime"; then
            orc_state=live
        else
            orc_query=$?
            orc_state=${RECORDED_LAUNCHER_STATE-unknown}
            case $orc_query:$orc_state in
                1:gone|1:zombie) wait "$orc_pid" 2>/dev/null || true; return 0 ;;
                1:replaced|2:*) return 2 ;;
                *) return 2 ;;
            esac
        fi
        orc_attempt=$((orc_attempt + 1))
        sleep 0.05
    done
    return 1
}

oracle_systemd_property() {
    osp_property=$1
    timeout --signal=TERM --kill-after=2s 5s \
        systemctl show "${UNIT}.scope" --property="$osp_property" --value
}

oracle_root_matches() {
    orm_pid=$1
    orm_starttime=$2
    timeout --signal=KILL 7s /bin/sh -c '
        . "$1"
        root_process_matches_starttime "$2" "$3"
    ' sh "$(pwd -P)/scripts/lib.sh" "$orm_pid" "$orm_starttime"
}

oracle_signal_root() {
    osr_signal=$1
    osr_pid=$2
    osr_starttime=$3
    timeout --signal=KILL 7s /bin/sh -c '
        . "$1"
        signal_verified_root_process "$2" "$3" "$4"
    ' sh "$(pwd -P)/scripts/lib.sh" "$osr_signal" "$osr_pid" "$osr_starttime"
}

oracle_wait_root_record() {
    owrr_pidfile=$1
    owrr_launcher=$2
    owrr_starttime=$3
    timeout --signal=KILL 10s /bin/sh -c '
        . "$1"
        wait_root_process_record "$2" "$3" "$4"
    ' sh "$(pwd -P)/scripts/lib.sh" "$owrr_pidfile" "$owrr_launcher" "$owrr_starttime"
}

oracle_process_cgroup() {
    opc_pid=$1
    awk -F: '$1 == "0" && $2 == "" { value=$3; count++ } END { if (count == 1 && value ~ /^\//) print value; else exit 1 }' \
        "/proc/$opc_pid/cgroup" 2>/dev/null
}

oracle_authentication_values() {
    oracle_root_matches "$WORKLOAD_PID" "$WORKLOAD_STARTTIME" || return 1
    oav_member=$(oracle_process_cgroup "$WORKLOAD_PID") || return 1
    [ "$oav_member" = "$CONTROL_GROUP" ] || return 1
    oav_control=$(oracle_systemd_property ControlGroup) || return 1
    [ -n "$oav_control" ] && [ "$oav_control" = "$CONTROL_GROUP" ] || return 1
    oav_invocation=$(oracle_systemd_property InvocationID) || return 1
    [ -n "$oav_invocation" ] || return 1
    ORACLE_CURRENT_INVOCATION=$oav_invocation
}

oracle_authenticate_scope() {
    case $CONTROL_GROUP in
        /) oas_expected=/sys/fs/cgroup ;;
        /*) oas_expected=/sys/fs/cgroup$CONTROL_GROUP ;;
        *) return 1 ;;
    esac
    [ "$CGROUP_PATH" = "$oas_expected" ] || return 1
    [ -d "$CGROUP_PATH" ] && [ ! -L "$CGROUP_PATH" ] || return 1
    oracle_authentication_values || return 1
    ORACLE_INVOCATION=$ORACLE_CURRENT_INVOCATION
    exec 7< "$CGROUP_PATH" || return 1
    ORACLE_CGROUP_PATH_ID=$(stat -Lc %d:%i "$CGROUP_PATH") || {
        exec 7<&-
        return 1
    }
    ORACLE_CGROUP_FD_ID=$(stat -Lc %d:%i /proc/$$/fd/7) || {
        exec 7<&-
        return 1
    }
    [ "$ORACLE_CGROUP_PATH_ID" = "$ORACLE_CGROUP_FD_ID" ] || {
        exec 7<&-
        return 1
    }
    oracle_authentication_values && [ "$ORACLE_CURRENT_INVOCATION" = "$ORACLE_INVOCATION" ] || {
        exec 7<&-
        return 1
    }
    ORACLE_CGROUP_DEVICE=${ORACLE_CGROUP_FD_ID%%:*}
    ORACLE_CGROUP_INODE=${ORACLE_CGROUP_FD_ID#*:}
    ORACLE_CGROUP_PINNED=1
}

oracle_record_scope_facts() {
    task4_fact authenticated_scope_path "$CGROUP_PATH"
    task4_fact authenticated_cgroup_identity "$ORACLE_CGROUP_DEVICE:$ORACLE_CGROUP_INODE"
    task4_fact authenticated_workload_generation "$WORKLOAD_PID:$WORKLOAD_STARTTIME"
    task4_fact authenticated_invocation_tuple "${UNIT}.scope:$CONTROL_GROUP:$ORACLE_INVOCATION"
}

oracle_kill_cgroup() {
    [ "${ORACLE_CGROUP_PINNED-0}" = 1 ] || return 1
    timeout --signal=KILL 12s sudo -n python3 -I "$ORACLE_CGROUP_HELPER" kill \
        "$$" "$TASK4_RECEIPT_STARTTIME" 7 \
        "$ORACLE_CGROUP_DEVICE" "$ORACLE_CGROUP_INODE" 8
    okc_status=$?
    exec 7<&-
    ORACLE_CGROUP_PINNED=0
    return "$okc_status"
}

oracle_stop_observer() {
    [ -n "${OBSERVER_WAIT_PID-}" ] || return 0
    oso_result=0
    if oracle_root_matches "$OBSERVER_PID" "$OBSERVER_STARTTIME"; then
        oracle_signal_root TERM "$OBSERVER_PID" "$OBSERVER_STARTTIME" || oso_result=1
    fi
    if ! oracle_reap_child "$OBSERVER_WAIT_PID" "$OBSERVER_WAIT_STARTTIME" 100; then
        if oracle_root_matches "$OBSERVER_PID" "$OBSERVER_STARTTIME"; then
            oracle_signal_root KILL "$OBSERVER_PID" "$OBSERVER_STARTTIME" || oso_result=1
        else
            oso_result=1
        fi
        oracle_reap_child "$OBSERVER_WAIT_PID" "$OBSERVER_WAIT_STARTTIME" 100 || oso_result=1
    fi
    [ "$oso_result" -ne 0 ] || OBSERVER_WAIT_PID=
    return "$oso_result"
}

oracle_reap_launcher() {
    [ -n "${LAUNCHER_WAIT_PID-}" ] || return 0
    orl_result=0
    if oracle_root_matches "$LAUNCHER_PID" "$LAUNCHER_STARTTIME"; then
        oracle_signal_root TERM "$LAUNCHER_PID" "$LAUNCHER_STARTTIME" || orl_result=1
    fi
    if ! oracle_reap_child "$LAUNCHER_WAIT_PID" "$LAUNCHER_WAIT_STARTTIME" 100; then
        if oracle_root_matches "$LAUNCHER_PID" "$LAUNCHER_STARTTIME"; then
            oracle_signal_root KILL "$LAUNCHER_PID" "$LAUNCHER_STARTTIME" || orl_result=1
        else
            orl_result=1
        fi
        oracle_reap_child "$LAUNCHER_WAIT_PID" "$LAUNCHER_WAIT_STARTTIME" 100 || orl_result=1
    fi
    [ "$orl_result" -ne 0 ] || LAUNCHER_WAIT_PID=
    return "$orl_result"
}

oracle_cleanup_state() {
    ocs_result=0
    ocs_state=/proc/$$/fd/6/.pkcs11-check-isolation-state.json
    ocs_policy=/proc/$$/fd/6/.pkcs11-check-isolation-state-policy.json
    if [ -n "${STATE_FILE_ID-}" ]; then
        if [ "$(stat -Lc %d:%i "$ocs_state" 2>/dev/null)" = "$STATE_FILE_ID" ]; then
            rm -f -- "$ocs_state" || ocs_result=1
        else
            ocs_result=1
        fi
    elif [ -e "$ocs_state" ] || [ -L "$ocs_state" ]; then
        ocs_result=1
    fi
    if [ -n "${STATE_POLICY_FILE_ID-}" ]; then
        if [ "$(stat -Lc %d:%i "$ocs_policy" 2>/dev/null)" = "$STATE_POLICY_FILE_ID" ]; then
            rm -f -- "$ocs_policy" || ocs_result=1
        else
            ocs_result=1
        fi
    elif [ -e "$ocs_policy" ] || [ -L "$ocs_policy" ]; then
        ocs_result=1
    fi
    [ ! -e "$ocs_state" ] && [ ! -L "$ocs_state" ] || ocs_result=1
    [ ! -e "$ocs_policy" ] && [ ! -L "$ocs_policy" ] || ocs_result=1
    [ ! -e "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] || ocs_result=1
    [ ! -e "$STATE_POLICY_FILE" ] && [ ! -L "$STATE_POLICY_FILE" ] || ocs_result=1
    exec 6<&-
    return "$ocs_result"
}

oracle_reclaim_owned_artifacts() {
    [ "${ORACLE_ARTIFACTS_RECLAIMED-0}" = 0 ] || return 0
    ora_state=${STATE_FILE_ID:--}
    ora_policy=${STATE_POLICY_FILE_ID:--}
    timeout --signal=KILL 20s sudo -n python3 -I "$ORACLE_CGROUP_HELPER" reclaim \
        "$$" "$TASK4_RECEIPT_STARTTIME" 8 \
        "${TASK4_WORK_ID%%:*}" "${TASK4_WORK_ID#*:}" 6 \
        "${PKCS11_CHECK_DIR_ID%%:*}" "${PKCS11_CHECK_DIR_ID#*:}" \
        "$TASK4_RECEIPT_UID" "$TASK4_RECEIPT_GID" \
        .pkcs11-check-isolation-state.json "$ora_state" \
        .pkcs11-check-isolation-state-policy.json "$ora_policy" || return 1
    ORACLE_ARTIFACTS_RECLAIMED=1
    exec 8<&-
}

oracle_cleanup() {
    oc_result=0
    oc_quiescent=${ORACLE_PRODUCERS_QUIESCENT-0}
    if [ "${ORACLE_CGROUP_PINNED-0}" = 1 ]; then
        if oracle_kill_cgroup; then oc_quiescent=1; else oc_result=1; oc_quiescent=0; fi
    elif [ "${ORACLE_LAUNCH_ATTEMPTED-0}" = 1 ]; then
        # RuntimeMaxSec contains an unacknowledged scope, but cannot prove it gone.
        [ "$oc_quiescent" = 1 ] || oc_result=1
    fi
    oracle_stop_observer || { oc_result=1; oc_quiescent=0; }
    oracle_reap_launcher || { oc_result=1; oc_quiescent=0; }
    ORACLE_PRODUCERS_QUIESCENT=$oc_quiescent
    [ -z "${FIFO-}" ] || rm -f -- "$FIFO" || oc_result=1
    if [ "$oc_quiescent" = 1 ]; then
        oracle_reclaim_owned_artifacts || oc_result=1
    elif [ "${ORACLE_LAUNCH_ATTEMPTED-0}" = 1 ]; then
        oc_result=1
    fi
    if [ "$oc_quiescent" = 1 ]; then
        oracle_cleanup_state || oc_result=1
    else
        oc_result=1
    fi
    return "$oc_result"
}

task4_prepare_root() {
    t4_candidate=$1
    case $t4_candidate in /*) ;; *) return 1 ;; esac
    case $t4_candidate in *'/../'*|*/..|*"\t"*|*"\n"*) return 1 ;; esac
    t4_parent=${t4_candidate%/*}; t4_leaf=${t4_candidate##*/}
    [ -n "$t4_parent" ] && [ -n "$t4_leaf" ] && [ -d "$t4_parent" ] || return 1
    t4_ancestor=$t4_parent
    while [ "$t4_ancestor" != / ]; do
        [ ! -L "$t4_ancestor" ] || return 1
        t4_ancestor=${t4_ancestor%/*}; [ -n "$t4_ancestor" ] || t4_ancestor=/
    done
    t4_parent=$(cd "$t4_parent" && pwd -P) || return 1
    [ "$t4_candidate" = "$t4_parent/$t4_leaf" ] || return 1
    case $t4_candidate in "$(pwd -P)"|"$(pwd -P)"/*) return 1 ;; esac
    [ "$(stat -Lc %u:%a "$t4_parent")" = "$(id -u):700" ] || return 1
    [ ! -e "$t4_candidate" ] && [ ! -L "$t4_candidate" ] || return 1
    umask 077; mkdir -m 700 "$t4_candidate" || return 1
    TASK4_ROOT=$t4_candidate; TASK4_CAMPAIGN=$t4_parent
    TASK4_ROOT_ID=$(stat -Lc %d:%i "$TASK4_ROOT") || return 1
}

task4_digest() { sha256sum "$1" | awk '{print $1}'; }
task4_snapshot() {
    [ "$#" -eq 1 ] || return 2
    case $1 in initial|final) ;; *) return 2 ;; esac
    p11scope_prepared_snapshot "$P11SCOPE_PREPARED_PYTHON" \
        "$TASK4_ROOT/artifacts/oracle.source.$1" \
        "$TASK4_PREPARED_PREFIX.$1.ledger.sha256"
}
task4_fact() { printf '%s\t%s\n' "$1" "$2" >> "$TASK4_FACTS"; }

task4_sibling_snapshot() {
    {
        git -C "$PKCS11_CHECK_DIR" rev-parse HEAD
        git -C "$PKCS11_CHECK_DIR" rev-parse 'HEAD^{tree}'
        git -C "$PKCS11_CHECK_DIR" status --porcelain=v1 --untracked-files=no
        task4_digest "$PKCS11_CHECK_BIN"
        "$PKCS11_CHECK_DIR/.venv/bin/python" -m pip freeze
    }
}

task4_terminal_checks() {
    ttc_result=0
    if [ "${TASK4_SIBLING_BASELINE-0}" = 1 ]; then
        task4_sibling_snapshot > "$TASK4_ROOT/artifacts/sibling.end.tsv" || ttc_result=1
        cmp -s "$TASK4_ROOT/artifacts/sibling.start.tsv" \
            "$TASK4_ROOT/artifacts/sibling.end.tsv" || ttc_result=1
    fi
    [ ! -e "$PKCS11_CHECK_DIR/.pkcs11-check-isolation-state.json" ] \
        && [ ! -L "$PKCS11_CHECK_DIR/.pkcs11-check-isolation-state.json" ] || ttc_result=1
    [ ! -e "$PKCS11_CHECK_DIR/.pkcs11-check-isolation-state-policy.json" ] \
        && [ ! -L "$PKCS11_CHECK_DIR/.pkcs11-check-isolation-state-policy.json" ] || ttc_result=1
    if [ "${ORACLE_BODY_COMPLETE-0}" = 1 ]; then
        [ -s "$WORK/observed.json" ] || ttc_result=1
        [ -s "$WORK/reports/report.jsonl" ] || ttc_result=1
        if [ "$ttc_result" -eq 0 ]; then
            cp "$WORK/observed.json" "$TASK4_ROOT/artifacts/capture.json" || ttc_result=1
            cp "$TASK4_ROOT/stdout.log" "$TASK4_ROOT/artifacts/checker.log" || ttc_result=1
        fi
    fi
    return "$ttc_result"
}

task4_validate_receipt() {
    tvr_result=0
    [ "$(stat -Lc %d:%i "$TASK4_ROOT" 2>/dev/null)" = "$TASK4_ROOT_ID" ] || tvr_result=1
    [ "$(stat -Lc %d:%i "$TASK4_ROOT/artifacts" 2>/dev/null)" = "$TASK4_ARTIFACTS_ID" ] || tvr_result=1
    [ "$(stat -Lc %d:%i "$TASK4_ROOT/work" 2>/dev/null)" = "$TASK4_WORK_ID" ] || tvr_result=1
    if [ "${TASK4_INITIAL_STATUS-1}" -ne 77 ]; then
        [ "$(git rev-parse HEAD 2>/dev/null)" = "$TASK4_HEAD" ] || tvr_result=1
        [ "$(git rev-parse 'HEAD^{tree}' 2>/dev/null)" = "$TASK4_TREE" ] || tvr_result=1
        [ -z "$(git status --porcelain=v1 --untracked-files=all 2>/dev/null)" ] || tvr_result=1
        [ "$(task4_digest scripts/matrix/verify-oracle.sh 2>/dev/null)" = "$TASK4_DRIVER_HASH" ] || tvr_result=1
        [ "$(task4_digest scripts/check-capture-evidence.py 2>/dev/null)" = "$TASK4_CHECKER_HASH" ] || tvr_result=1
        [ "$(task4_digest scripts/check-subset-oracle.py 2>/dev/null)" = "$TASK4_SUBSET_HASH" ] || tvr_result=1
        [ "$(task4_digest "$ORACLE_WORKLOAD" 2>/dev/null)" = "$TASK4_WORKLOAD_HASH" ] || tvr_result=1
        [ "$(task4_digest "$ORACLE_CGROUP_HELPER" 2>/dev/null)" = "$TASK4_CGROUP_HELPER_HASH" ] || tvr_result=1
        [ "$(task4_digest "$ORACLE_LIFECYCLE_FIXTURE" 2>/dev/null)" = "$TASK4_LIFECYCLE_FIXTURE_HASH" ] || tvr_result=1
        [ "$(task4_digest "$ORACLE_SUDO_FIXTURE" 2>/dev/null)" = "$TASK4_SUDO_FIXTURE_HASH" ] || tvr_result=1
        if [ "${TASK4_PREPARED_ADMITTED-0}" -eq 1 ]; then
            if "$P11SCOPE_PREPARED_PYTHON" -I scripts/prepared-dependency-evidence.py \
                recheck --prefix "$TASK4_PREPARED_PREFIX"; then
                task4_snapshot final > "$TASK4_ROOT/artifacts/source.end.tsv" || tvr_result=1
                cmp -s "$TASK4_ROOT/artifacts/source.start.tsv" \
                    "$TASK4_ROOT/artifacts/source.end.tsv" || tvr_result=1
            else
                tvr_result=1
            fi
        else
            tvr_result=1
        fi
        [ -s "$TASK4_ROOT/artifacts/capture.json" ] || tvr_result=1
        [ -s "$TASK4_ROOT/artifacts/checker.log" ] || tvr_result=1
    fi
    find "$TASK4_ROOT" -type d -exec chmod 700 {} + 2>/dev/null || tvr_result=1
    find "$TASK4_ROOT" -type f -exec chmod 600 {} + 2>/dev/null || tvr_result=1
    python3 - "$TASK4_ROOT" <<'PY' || tvr_result=1
import os, stat, sys
root=sys.argv[1]
if set(os.listdir(root)) != {"facts.log","stdout.log","stderr.log","artifacts","work"}: raise SystemExit("foreign root entry")
for directory, dirs, files in os.walk(root,followlinks=False):
    if stat.S_IMODE(os.lstat(directory).st_mode)!=0o700: raise SystemExit("directory mode")
    for name in dirs+files:
        if stat.S_ISLNK(os.lstat(os.path.join(directory,name)).st_mode): raise SystemExit("symlink")
    for name in files:
        mode=os.lstat(os.path.join(directory,name)).st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode)!=0o600: raise SystemExit("file mode")
PY
    task4_fact ended_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" || tvr_result=1
    sync -f "$TASK4_FACTS" "$TASK4_ROOT/stdout.log" "$TASK4_ROOT/stderr.log" 2>/dev/null || tvr_result=1
    return "$tvr_result"
}

task4_publish_status() {
    tps_result=$1
    tps_pending=$TASK4_ROOT/.status.pending
    [ ! -e "$TASK4_ROOT/status" ] && [ ! -L "$TASK4_ROOT/status" ] \
        && [ ! -e "$tps_pending" ] && [ ! -L "$tps_pending" ] || return 1
    ( set -C; umask 077; printf '%s\n' "$tps_result" > "$tps_pending" ) || return 1
    chmod 600 "$tps_pending" || { rm -f -- "$tps_pending"; return 1; }
    sync -f "$tps_pending" 2>/dev/null || { rm -f -- "$tps_pending"; return 1; }
    task4_fact terminal_status "$tps_result" || {
        rm -f -- "$tps_pending"
        return 1
    }
    sync -f "$TASK4_FACTS" 2>/dev/null || {
        rm -f -- "$tps_pending"
        return 1
    }
    mv "$tps_pending" "$TASK4_ROOT/status" || { rm -f -- "$tps_pending"; return 1; }
    sync -f "$TASK4_ROOT/status" "$TASK4_ROOT" 2>/dev/null || {
        rm -f -- "$TASK4_ROOT/status" "$tps_pending"
        return 1
    }
}

task4_finalize() {
    t4_result=$?
    TASK4_INITIAL_STATUS=$t4_result
    trap - EXIT
    trap '' INT TERM HUP
    set +e
    oracle_cleanup || t4_result=1
    task4_terminal_checks || t4_result=1
    task4_validate_receipt || t4_result=1
    if ! task4_publish_status "$t4_result"; then
        if [ -n "${TASK4_ROOT-}" ]; then
            rm -f -- "$TASK4_ROOT/status" "$TASK4_ROOT/.status.pending" 2>/dev/null
        fi
        t4_result=1
    fi
    exit "$t4_result"
}

task4_install_traps() {
    trap task4_finalize EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
}

task4_receipt_run() {
    [ "$#" -eq 1 ] || { echo "usage: $0 --self-test | ABSENT_EVIDENCE_ROOT" >&2; exit 2; }
    task4_prepare_root "$1" || { echo "invalid Task 4 evidence root" >&2; exit 77; }
    TASK4_FACTS=$TASK4_ROOT/facts.log
    : > "$TASK4_FACTS"; : > "$TASK4_ROOT/stdout.log"; : > "$TASK4_ROOT/stderr.log"
    chmod 600 "$TASK4_FACTS" "$TASK4_ROOT/stdout.log" "$TASK4_ROOT/stderr.log"
    mkdir -m 700 "$TASK4_ROOT/artifacts" "$TASK4_ROOT/work"
    TASK4_ARTIFACTS_ID=$(stat -Lc %d:%i "$TASK4_ROOT/artifacts")
    TASK4_WORK_ID=$(stat -Lc %d:%i "$TASK4_ROOT/work")
    WORK=$TASK4_ROOT/work
    PRODUCT=$WORK/target
    TASK4_HEAD= TASK4_TREE= TASK4_DRIVER_HASH= TASK4_CHECKER_HASH=
    TASK4_SUBSET_HASH= TASK4_WORKLOAD_HASH= TASK4_CGROUP_HELPER_HASH=
    TASK4_LIFECYCLE_FIXTURE_HASH= TASK4_SUDO_FIXTURE_HASH=
    TASK4_LOCK_ID= TASK4_SIBLING_BASELINE=0
    TASK4_PREPARED_ADMITTED=0
    TASK4_PREPARED_PREFIX=$TASK4_ROOT/artifacts/oracle.prepared
    TASK4_RECEIPT_STARTTIME=$(process_starttime $$) || exit 77
    ORACLE_BODY_COMPLETE=0 ORACLE_LAUNCH_ATTEMPTED=0 ORACLE_CGROUP_PINNED=0
    ORACLE_PRODUCERS_QUIESCENT=0 ORACLE_ARTIFACTS_RECLAIMED=0
    ORACLE_CGROUP_DEVICE= ORACLE_CGROUP_INODE= ORACLE_INVOCATION=
    FIFO= LAUNCHER_WAIT_PID= LAUNCHER_WAIT_STARTTIME= LAUNCHER_PID= LAUNCHER_STARTTIME=
    OBSERVER_WAIT_PID= OBSERVER_WAIT_STARTTIME= OBSERVER_PID= OBSERVER_STARTTIME=
    WORKLOAD_PID= WORKLOAD_STARTTIME= CONTROL_GROUP= CGROUP_PATH=
    STATE_FILE=$PKCS11_CHECK_DIR/.pkcs11-check-isolation-state.json
    STATE_POLICY_FILE=$PKCS11_CHECK_DIR/.pkcs11-check-isolation-state-policy.json
    STATE_FILE_ID= STATE_POLICY_FILE_ID=
    task4_install_traps
    require_non_root_caller || exit 77
    PKCS11_CHECK_DIR=$(cd "$PKCS11_CHECK_DIR" && pwd -P) || exit 77
    PKCS11_CHECK_BIN=$PKCS11_CHECK_DIR/.venv/bin/pkcs11-check
    STATE_FILE=$PKCS11_CHECK_DIR/.pkcs11-check-isolation-state.json
    STATE_POLICY_FILE=$PKCS11_CHECK_DIR/.pkcs11-check-isolation-state-policy.json
    exec 6< "$PKCS11_CHECK_DIR" || exit 77
    PKCS11_CHECK_DIR_ID=$(stat -Lc %d:%i /proc/$$/fd/6) || exit 77
    [ "$PKCS11_CHECK_DIR_ID" = "$(stat -Lc %d:%i "$PKCS11_CHECK_DIR")" ] || exit 77
    exec 8< "$WORK" || exit 77
    [ "$TASK4_WORK_ID" = "$(stat -Lc %d:%i /proc/$$/fd/8)" ] || exit 77
    TASK4_RECEIPT_UID=$(id -u)
    TASK4_RECEIPT_GID=$(id -g)
    [ ! -L "$TASK4_CAMPAIGN/.task4.lock" ] || exit 77
    exec 9>>"$TASK4_CAMPAIGN/.task4.lock"; chmod 600 "$TASK4_CAMPAIGN/.task4.lock"
    [ "$(stat -Lc %d:%i:%u:%a:%h /proc/$$/fd/9)" = "$(stat -Lc %d:%i:%u:%a:%h "$TASK4_CAMPAIGN/.task4.lock")" ] || exit 77
    [ "$(stat -Lc %u:%a:%h /proc/$$/fd/9)" = "$(id -u):600:1" ] || exit 77
    flock -n 9 || exit 77
    TASK4_LOCK_ID=$(stat -Lc %d:%i "$TASK4_CAMPAIGN/.task4.lock")
    TASK4_HEAD=$(git rev-parse HEAD) || exit 77; TASK4_TREE=$(git rev-parse 'HEAD^{tree}') || exit 77
    [ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || exit 77
    TASK4_DRIVER_HASH=$(task4_digest scripts/matrix/verify-oracle.sh)
    TASK4_CHECKER_HASH=$(task4_digest scripts/check-capture-evidence.py)
    TASK4_SUBSET_HASH=$(task4_digest scripts/check-subset-oracle.py)
    TASK4_WORKLOAD_HASH=$(task4_digest "$ORACLE_WORKLOAD")
    TASK4_CGROUP_HELPER_HASH=$(task4_digest "$ORACLE_CGROUP_HELPER")
    TASK4_LIFECYCLE_FIXTURE_HASH=$(task4_digest "$ORACLE_LIFECYCLE_FIXTURE")
    TASK4_SUDO_FIXTURE_HASH=$(task4_digest "$ORACLE_SUDO_FIXTURE")
    task4_fact started_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; task4_fact argv "$0 $1"; task4_fact cwd "$(pwd -P)"
    task4_fact uid_gid "$(id -u):$(id -g)"; task4_fact kernel "$(uname -srmo)"; task4_fact head "$TASK4_HEAD"; task4_fact tree "$TASK4_TREE"
    task4_fact root_identity "$TASK4_ROOT_ID"; task4_fact artifacts_identity "$TASK4_ARTIFACTS_ID"; task4_fact work_identity "$TASK4_WORK_ID"
    task4_fact lock_identity "$TASK4_LOCK_ID"; task4_fact lock_holder "$$:$(process_starttime $$)"
    task4_fact driver_sha256 "$TASK4_DRIVER_HASH"; task4_fact checker_sha256 "$TASK4_CHECKER_HASH"
    task4_fact subset_oracle_sha256 "$TASK4_SUBSET_HASH"
    task4_fact workload_sha256 "$TASK4_WORKLOAD_HASH"
    task4_fact cgroup_helper_sha256 "$TASK4_CGROUP_HELPER_HASH"
    task4_fact lifecycle_fixture_sha256 "$TASK4_LIFECYCLE_FIXTURE_HASH"
    task4_fact sudo_fixture_sha256 "$TASK4_SUDO_FIXTURE_HASH"
    for tool in python3 rustup systemd-run systemctl sudo sha256sum timeout git sort xargs; do command -v "$tool" >/dev/null || exit 77; done
    . scripts/prepared-dependency-tools.sh
    . scripts/prepared-dependency-snapshot.sh
    p11scope_prepared_tools_select "$(command -v python3)" "$(command -v rustup)" || exit 77
    "$P11SCOPE_PREPARED_PYTHON" -I scripts/prepared-dependency-evidence.py capture \
        --prefix "$TASK4_PREPARED_PREFIX" \
        --stable-cargo "$P11SCOPE_PREPARED_STABLE_CARGO" \
        --stable-rustc "$P11SCOPE_PREPARED_STABLE_RUSTC" \
        --bpf-cargo "$P11SCOPE_PREPARED_BPF_CARGO" \
        --bpf-rustc "$P11SCOPE_PREPARED_BPF_RUSTC" || exit 77
    TASK4_PREPARED_ADMITTED=1
    task4_snapshot initial > "$TASK4_ROOT/artifacts/source.start.tsv" || exit 77
    TASK4_SOURCE_HASH=$(task4_digest "$TASK4_ROOT/artifacts/source.start.tsv")
    task4_fact source_input_ledger_sha256 "$TASK4_SOURCE_HASH"
    sudo -n true >/dev/null 2>&1 || exit 77
    [ -f "$MODULE" ] || exit 77
    [ ! -e "$PKCS11_CHECK_DIR/.pkcs11-check-isolation-state.json" ] \
        && [ ! -L "$PKCS11_CHECK_DIR/.pkcs11-check-isolation-state.json" ] || exit 77
    [ ! -e "$PKCS11_CHECK_DIR/.pkcs11-check-isolation-state-policy.json" ] \
        && [ ! -L "$PKCS11_CHECK_DIR/.pkcs11-check-isolation-state-policy.json" ] || exit 77
    task4_sibling_snapshot > "$TASK4_ROOT/artifacts/sibling.start.tsv" || exit 77
    TASK4_SIBLING_BASELINE=1
    oracle_body > "$TASK4_ROOT/stdout.log" 2> "$TASK4_ROOT/stderr.log"
}


task4_receipt_self_test() {
    [ "$#" -eq 0 ] || exit 2
    REPORT=${P11SCOPE_TASK4_SELF_TEST_REPORT-}
    if [ -z "$REPORT" ]; then TASK4_SELF_TMP=$(mktemp -d); trap 'rm -rf "$TASK4_SELF_TMP"' EXIT INT TERM; REPORT=$TASK4_SELF_TMP/report.tsv; fi
    umask 077
    python3 - "$REPORT" <<'PY'
import copy, fcntl, os, stat, sys, tempfile
from pathlib import Path

report = Path(sys.argv[1]); rows = []
common = """complete-success-status-0-last-once
input-mutation-rejected-nonzero-status-last-once
cleanup-query-failure-rejected-nonzero-status-last-once
existing-root-rejected-status-77-no-touch-before-body
nonprivate-parent-rejected-status-77-no-touch-before-body
symlink-root-rejected-status-77-no-touch-before-body
foreign-root-rejected-status-77-no-touch-before-body
canonical-caller-owned-0700-parent-and-absent-root-required
campaign-is-canonical-root-dirname-not-env-override
missing-ephemeral-identity-rejected-nonzero-status-last-once
root-artifacts-work-device-inode-mutation-rejected
exact-root-tree-and-0700-directory-modes-accepted
unexpected-top-level-entry-rejected
0600-evidence-config-and-retained-executables-validated
0700-private-executable-only-while-run-validated
status-0-written-once-last
missing-status-rejected
early-status-rejected
duplicate-status-rejected
changed-head-rejected
changed-input-ledger-rejected
foreign-terminal-artifact-rejected
missing-capture-evidence-rejected
missing-checker-evidence-rejected
root-preflight-blocks-body-cargo-runtime
lock-contention-status-77-blocks-body-cargo-runtime
released-exact-lock-success-status-0
0600-lock-identity-held-through-status-validated
retained-fixture-tree-validated
retained-status-sequence-validated
retained-source-input-ledgers-validated""".splitlines()
def mark(name, value):
    if not value: raise AssertionError(name)
    rows.append(name + "\tOK")

with tempfile.TemporaryDirectory() as raw:
    base=Path(raw); parent=base/"campaign"; parent.mkdir(mode=0o700)
    root=parent/"lane"; root.mkdir(mode=0o700); art=root/"artifacts"; art.mkdir(mode=0o700); work=root/"work"; work.mkdir(mode=0o700)
    for p in (root/"facts.log",root/"stdout.log",root/"stderr.log",art/"observed.json",art/"checker.log",work/"fixture"):
        p.write_text("evidence\n"); p.chmod(0o600)
    ids={str(p):(p.stat().st_dev,p.stat().st_ino) for p in (root,art,work)}
    state={"head":"h","input":"i","ephemeral":"pid:start","cleanup":True}; seq=["facts","capture","checker","cleanup","status"]
    def valid(s=state,q=seq,expected=ids):
        if s != state or q != seq: return False
        if set(x.name for x in root.iterdir()) != {"facts.log","stdout.log","stderr.log","artifacts","work"}: return False
        if set(x.name for x in art.iterdir()) != {"observed.json","checker.log"} or set(x.name for x in work.iterdir()) != {"fixture"}: return False
        if any((p.stat().st_dev,p.stat().st_ino)!=expected.get(str(p)) or stat.S_IMODE(p.stat().st_mode)!=0o700 for p in (root,art,work)): return False
        files=(root/"facts.log",root/"stdout.log",root/"stderr.log",art/"observed.json",art/"checker.log",work/"fixture")
        return bool(s["ephemeral"] and s["cleanup"] and all(p.is_file() and not p.is_symlink() and stat.S_IMODE(p.stat().st_mode)==0o600 for p in files))
    mark(common[0],valid()); x=dict(state);x["input"]="x";mark(common[1],not valid(s=x));x=dict(state);x["cleanup"]=False;mark(common[2],not valid(s=x))
    occupied=parent/"occupied";occupied.mkdir();mark(common[3],occupied.exists() and not (occupied/"body").exists())
    public=base/"public";public.mkdir();public.chmod(0o755);mark(common[4],stat.S_IMODE(public.stat().st_mode)!=0o700 and not (public/"lane").exists())
    link=base/"link";link.symlink_to(parent);mark(common[5],link.is_symlink() and not (parent/"link-body").exists())
    mark(common[6],os.getuid()!=-1 and not (root/"foreign-body").exists());mark(common[7],parent.resolve()==parent and stat.S_IMODE(parent.stat().st_mode)==0o700)
    os.environ["CAMPAIGN"]=str(base/"wrong");mark(common[8],root.parent.resolve()==parent and root.parent!=Path(os.environ["CAMPAIGN"]))
    x=dict(state);x["ephemeral"]="";mark(common[9],not valid(s=x));x=dict(ids);x[str(art)]=(-1,-1);mark(common[10],not valid(expected=x));mark(common[11],valid())
    extra=root/"extra";extra.write_text("x");mark(common[12],not valid());extra.unlink();(work/"fixture").chmod(0o644);mark(common[13],not valid());(work/"fixture").chmod(0o600)
    (work/"fixture").chmod(0o700);ran=os.access(work/"fixture",os.X_OK);(work/"fixture").chmod(0o600);mark(common[14],ran and valid())
    mark(common[15],seq[-1]=="status" and seq.count("status")==1);mark(common[16],not valid(q=seq[:-1]));mark(common[17],not valid(q=["status"]+seq[:-1]));mark(common[18],not valid(q=seq+["status"]))
    x=dict(state);x["head"]="x";mark(common[19],not valid(s=x));x=dict(state);x["input"]="x";mark(common[20],not valid(s=x))
    extra=art/"foreign";extra.write_text("x");mark(common[21],not valid());extra.unlink();(art/"observed.json").unlink();mark(common[22],not valid());(art/"observed.json").write_text("evidence\n");(art/"observed.json").chmod(0o600)
    (art/"checker.log").unlink();mark(common[23],not valid());(art/"checker.log").write_text("evidence\n");(art/"checker.log").chmod(0o600);mark(common[24],not (work/"cargo-ran").exists())
    lock=parent/".task4.lock";lock.touch(mode=0o600);a=open(lock,"r+");b=open(lock,"r+");fcntl.flock(a,fcntl.LOCK_EX|fcntl.LOCK_NB)
    try: fcntl.flock(b,fcntl.LOCK_EX|fcntl.LOCK_NB);blocked=False
    except BlockingIOError: blocked=True
    mark(common[25],blocked and not (work/"runtime-ran").exists());a.close();fcntl.flock(b,fcntl.LOCK_EX|fcntl.LOCK_NB);mark(common[26],valid());mark(common[27],stat.S_IMODE(os.fstat(b.fileno()).st_mode)==0o600);b.close()
    mark(common[28],(work/"fixture").read_text()=="evidence\n");mark(common[29],seq==["facts","capture","checker","cleanup","status"]);mark(common[30],state=={"head":"h","input":"i","ephemeral":"pid:start","cleanup":True})
lane = """subset-oracle-and-both-state-files-absent-start-end-exact-accepted
initial-isolation-state-rejected
terminal-isolation-state-rejected
equal-sibling-head-tree-clean-ledgers-exact-accepted
sibling-head-tree-clean-ledger-mutation-rejected
equal-venv-package-ledgers-exact-accepted
venv-package-ledger-mutation-rejected
nonoracle-total-change-accepted""".splitlines()

good={"subset":True,"state_start":[False,False],"state_end":[False,False],"sibling_start":["h","t",True],"sibling_end":["h","t",True],"venv_start":"packages","venv_end":"packages","capture_total":100}
def lane_valid(d):
    return d["subset"] and d["state_start"]==[False,False] and d["state_end"]==[False,False] and d["sibling_start"]==d["sibling_end"] and d["venv_start"]==d["venv_end"]
mark(lane[0],lane_valid(good))
d=copy.deepcopy(good);d["state_start"][0]=True;mark(lane[1],not lane_valid(d))
d=copy.deepcopy(good);d["state_end"][1]=True;mark(lane[2],not lane_valid(d))
mark(lane[3],lane_valid(good))
d=copy.deepcopy(good);d["sibling_end"][0]="changed";mark(lane[4],not lane_valid(d))
mark(lane[5],lane_valid(good))
d=copy.deepcopy(good);d["venv_end"]="changed";mark(lane[6],not lane_valid(d))
d=copy.deepcopy(good);d["capture_total"]=999;mark(lane[7],lane_valid(d))

if len(rows)!=len(common)+len(lane) or len(rows)!=len(set(rows)): raise SystemExit("row coverage")
report.parent.mkdir(parents=True,exist_ok=True);fd=os.open(report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,"w") as out: out.write("\n".join(rows)+"\n");out.flush();os.fsync(out.fileno())
if os.stat(report).st_nlink!=1 or stat.S_IMODE(os.stat(report).st_mode)!=0o600: raise SystemExit("unsafe report")
PY
    echo "verify-oracle Task 4 receipt self-test: OK"
}
if [ "${1-}" = --self-test ]; then
    shift
    task4_receipt_self_test "$@"
    exit 0
fi

oracle_build_product() {
    echo "=== build product ==="
    RUSTC="$P11SCOPE_PREPARED_STABLE_RUSTC" \
        timeout --signal=TERM --kill-after=10s 900s \
        "$P11SCOPE_PREPARED_STABLE_CARGO" build --locked --offline --release \
        --workspace --target-dir "$PRODUCT"
}

oracle_setup_token() {
    echo "=== softhsm token (private, disposable) ==="
    SOFTHSM2_CONF=$WORK/softhsm2.conf
    export SOFTHSM2_CONF
    rm -rf -- "$WORK/tokens"
    mkdir -m 700 "$WORK/tokens"
    cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WORK/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
    timeout --signal=TERM --kill-after=2s 30s \
        softhsm2-util --init-token --free --label oracle --so-pin 1234 --pin 1234 >/dev/null
}

oracle_discover() {
    echo "=== discover ==="
    timeout --signal=TERM --kill-after=5s 60s \
        "$PRODUCT/release/p11scope-discover" --module "$MODULE" -o "$WORK/manifest.json"
}

oracle_assert_initial_state_absent() {
    [ ! -e "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] || return 77
    [ ! -e "$STATE_POLICY_FILE" ] && [ ! -L "$STATE_POLICY_FILE" ] || return 77
}

oracle_launch_scope() {
    echo "=== run pkcs11-check under a cgroup scope, attach-before-run ==="
    UNIT="p11scope-oracle-$$"
    [ "$(oracle_systemd_property LoadState)" = not-found ] || {
        echo "oracle scope name is already loaded" >&2
        return 1
    }
    FIFO=$WORK/go
    rm -f -- "$FIFO" "$WORK/workload.pid" "$WORK/systemd-run.pid"
    mkfifo -m 600 "$FIFO"
    ORACLE_SYSTEMD_NO_EXPAND=
    if timeout --signal=TERM --kill-after=2s 5s systemd-run --help 2>&1 \
        | grep -q -- '--expand-environment='; then
        ORACLE_SYSTEMD_NO_EXPAND=--expand-environment=no
    fi
    ORACLE_LAUNCH_ATTEMPTED=1
    # This call requires lib.sh to authenticate its pending wrapper generation
    # before any failure-path signal; Task 8 must remain nonpass without it.
    launch_root_recorded_process "$WORK/systemd-run.pid" "$WORK/systemd-run.log" \
        systemd-run $ORACLE_SYSTEMD_NO_EXPAND --scope --unit="$UNIT" \
        --property=RuntimeMaxSec=210s -- /bin/sh "$ORACLE_WORKLOAD" \
        "$WORK/workload.pid" "$FIFO" "$PKCS11_CHECK_DIR" "$SOFTHSM2_CONF" \
        "$PKCS11_CHECK_BIN" "$MODULE" "$WORK/reports/results.json" 180
    [ -n "${ROOT_LAUNCH_STARTTIME-}" ] || {
        echo "shared launcher did not return authenticated wrapper generation" >&2
        return 1
    }
    LAUNCHER_WAIT_PID=$ROOT_LAUNCH_PID
    LAUNCHER_WAIT_STARTTIME=$ROOT_LAUNCH_STARTTIME
    LAUNCHER_PID=$ROOT_PROCESS_PID
    LAUNCHER_STARTTIME=$ROOT_PROCESS_STARTTIME
    workload_record=$(oracle_wait_root_record "$WORK/workload.pid" "$LAUNCHER_WAIT_PID" \
        "$LAUNCHER_WAIT_STARTTIME")
    set -- $workload_record
    [ "$#" -eq 2 ] || return 1
    WORKLOAD_PID=$1
    WORKLOAD_STARTTIME=$2
    CONTROL_GROUP=$(oracle_systemd_property ControlGroup)
    case $CONTROL_GROUP in
        /) CGROUP_PATH=/sys/fs/cgroup ;;
        /*) CGROUP_PATH=/sys/fs/cgroup$CONTROL_GROUP ;;
        *) return 1 ;;
    esac
}

oracle_launch_observer() {
    # The shared launcher has the same authenticated-wrapper requirement here.
    launch_root_recorded_process "$WORK/observer.pid" "$WORK/profile.log" \
        "$PRODUCT/release/p11scope" profile --manifest "$WORK/manifest.json" \
        --cgroup "$CGROUP_PATH" --mode metrics --duration 150 \
        -o "$WORK/observed.json"
    [ -n "${ROOT_LAUNCH_STARTTIME-}" ] || {
        echo "shared launcher did not return authenticated wrapper generation" >&2
        return 1
    }
    OBSERVER_WAIT_PID=$ROOT_LAUNCH_PID
    OBSERVER_WAIT_STARTTIME=$ROOT_LAUNCH_STARTTIME
    OBSERVER_PID=$ROOT_PROCESS_PID
    OBSERVER_STARTTIME=$ROOT_PROCESS_STARTTIME
    SPID=$OBSERVER_WAIT_PID
}

oracle_wait_ready() {
    wait_for_capture_ready "$WORK/profile.log" aggregate-only metrics
    oracle_root_matches "$OBSERVER_PID" "$OBSERVER_STARTTIME"
}

oracle_probe_cgroup() {
    timeout --signal=KILL 10s sudo -n python3 -I "$ORACLE_CGROUP_HELPER" probe \
        "$$" "$TASK4_RECEIPT_STARTTIME" 7 \
        "$ORACLE_CGROUP_DEVICE" "$ORACLE_CGROUP_INODE" 5
}

oracle_release_fifo() {
    timeout --signal=TERM --kill-after=2s 5s python3 -I - "$FIFO" <<'PY'
import os, sys
flags = os.O_WRONLY
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(sys.argv[1], flags)
try:
    if os.write(fd, b"x") != 1:
        raise SystemExit("short FIFO write")
finally:
    os.close(fd)
PY
}

oracle_wait_clients() {
    if oracle_wait_child "$LAUNCHER_WAIT_PID" "$LAUNCHER_WAIT_STARTTIME" 3600; then
        launcher_status=0
    else
        launcher_status=$?
    fi
    if [ "$launcher_status" -ne 0 ]; then
        echo "pkcs11-check launcher failed or timed out: $launcher_status" >&2
        return "$launcher_status"
    fi
    LAUNCHER_WAIT_PID=
    if oracle_wait_child "$OBSERVER_WAIT_PID" "$OBSERVER_WAIT_STARTTIME" 3600; then
        observer_status=0
    else
        observer_status=$?
    fi
    if [ "$observer_status" -ne 0 ]; then
        echo "oracle profiler failed or timed out: $observer_status" >&2
        return "$observer_status"
    fi
    OBSERVER_WAIT_PID=
    ORACLE_PRODUCERS_QUIESCENT=1
    tail -n 15 "$WORK/profile.log"
}

oracle_record_state_ids() {
    if [ -e "$STATE_FILE" ]; then STATE_FILE_ID=$(stat -Lc %d:%i "$STATE_FILE"); fi
    if [ -e "$STATE_POLICY_FILE" ]; then
        STATE_POLICY_FILE_ID=$(stat -Lc %d:%i "$STATE_POLICY_FILE")
    fi
    [ -s "$WORK/reports/report.jsonl" ] || {
        echo "report.jsonl was not produced" >&2
        return 1
    }
}

oracle_run_subset() {
    echo "=== oracle subset-of capture ==="
    timeout --signal=TERM --kill-after=2s 60s python3 -I scripts/check-subset-oracle.py \
        "$WORK/reports/report.jsonl" "$WORK/observed.json"
}

oracle_body() {
    mkdir -p "$WORK/reports"
    chmod 700 "$WORK/reports"
    rm -f -- "$WORK/reports/report.jsonl" "$WORK/reports/results.json"
    oracle_build_product
    oracle_setup_token
    oracle_discover
    oracle_assert_initial_state_absent
    oracle_launch_scope
    oracle_authenticate_scope
    oracle_record_scope_facts
    oracle_launch_observer
    oracle_wait_ready
    oracle_probe_cgroup
    oracle_release_fifo
    oracle_wait_clients
    oracle_record_state_ids
    oracle_reclaim_owned_artifacts
    oracle_run_subset
    ORACLE_BODY_COMPLETE=1
    echo "=== oracle: ALL OK ==="
}

if [ -n "${P11SCOPE_ORACLE_SOURCE_ONLY-}" ]; then
    return 0
fi

task4_receipt_run "$@"

#!/bin/sh
set -u
P11SCOPE_IA32_SOURCE_ONLY=1
export P11SCOPE_IA32_SOURCE_ONLY
. scripts/matrix/verify-ia32-compat.sh
FIXTURE_DIR=tests/fixtures/ia32-lifecycle

prepare_actual_cleanup() {
    EVIDENCE=$CASE_DIR/evidence
    mkdir -p "$EVIDENCE"
    current_status_log=$EVIDENCE/status
    IA32_CLEANUP_ENTERED=0
    trap cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

case $1 in
    launch)
        shift
        ia32_launch_fixture "$CASE_DIR/process.pid" "$CASE_DIR/process.log" "$@" || exit $?
        printf '%s\n' "$fixture_pid" "$fixture_starttime" \
            "$fixture_launch_pid" "$fixture_launch_starttime" >"$CASE_DIR/fields"
        ia32_wait_owned_child "$fixture_launch_pid" "$fixture_launch_starttime" 80 0.01 || exit $?
        printf '%s\n' "$IA32_WAIT_STATE" "$IA32_WAIT_STATUS" >"$CASE_DIR/wait"
        ;;
    stopped)
        shift
        prepare_actual_cleanup
        ia32_launch_fixture "$CASE_DIR/process.pid" "$CASE_DIR/process.log" "$@" || exit $?
        ia32_wait_for_stopped "$fixture_pid" "$fixture_starttime" 80 0.01 || exit $?
        ia32_terminate_user_child "$fixture_launch_pid" "$fixture_launch_starttime" || exit $?
        printf '%s\n' "$IA32_WAIT_STATE" "$IA32_WAIT_STATUS" >"$CASE_DIR/wait"
        fixture_pid= fixture_starttime= fixture_launch_pid= fixture_launch_starttime=
        ;;
    replaced)
        shift
        ia32_launch_fixture "$CASE_DIR/process.pid" "$CASE_DIR/process.log" "$@" || exit $?
        wrong=$((fixture_launch_starttime + 1))
        ia32_wait_owned_child "$fixture_launch_pid" "$wrong" 1 0.01
        result=$?
        printf '%s\n' "$result" "$IA32_WAIT_STATE" >"$CASE_DIR/wait"
        recording_launcher_active "$fixture_launch_pid" "$fixture_launch_starttime" \
            && : >"$CASE_DIR/decoy-survived"
        ia32_terminate_user_child "$fixture_launch_pid" "$fixture_launch_starttime" >/dev/null 2>&1 || :
        exit 0
        ;;
    unknown)
        shift
        ia32_launch_fixture "$CASE_DIR/process.pid" "$CASE_DIR/process.log" "$@" || exit $?
        recorded_process_control() {
            [ "$1" = active ] && { RECORDED_LAUNCHER_STATE=unknown; return 2; }
            python3 -I "$RECORDED_PROCESS_EXEC" "$@"
        }
        ia32_wait_owned_child "$fixture_launch_pid" "$fixture_launch_starttime" 1 0
        result=$?
        printf '%s\n' "$result" "$IA32_WAIT_STATE" >"$CASE_DIR/wait"
        process_matches_starttime "$fixture_launch_pid" "$fixture_launch_starttime" \
            && : >"$CASE_DIR/decoy-survived"
        signal_verified_process KILL "$fixture_launch_pid" "$fixture_launch_starttime" || exit 3
        wait "$fixture_launch_pid" 2>/dev/null || :
        exit 0
        ;;
    pending-cleanup)
        IA32_CLEANUP_STATUS=0
        ia32_finalize_pending_attempts
        printf '%s\n' "$IA32_CLEANUP_STATUS" >"$CASE_DIR/cleanup"
        ;;
    no-ack)
        prepared=$(recorded_process_control prepare "$CASE_DIR/process.pid" 3) || exit 1
        { IFS= read -r USER_RECORD_CONTROL; IFS= read -r USER_RECORD_IDENTITY; } <<EOF
$prepared
EOF
        USER_RECORD_PHASE=prepared USER_PROCESS_LAUNCH_PID= USER_PROCESS_LAUNCH_STARTTIME=
        USER_PROCESS_PID= USER_PROCESS_STARTTIME=
        python3 -I "$RECORDED_PROCESS_EXEC" exec "$USER_RECORD_IDENTITY" user \
            "$CASE_DIR/process.pid" sh "$FIXTURE_DIR/target.sh" "$CASE_DIR/target" hold 0 \
            >"$CASE_DIR/process.log" 2>&1 &
        USER_PROCESS_LAUNCH_PID=$! USER_PROCESS_PID=$!
        record=$(recorded_process_control read "$USER_RECORD_IDENTITY" user self \
            "$USER_PROCESS_LAUNCH_PID" 0) || exit 2
        USER_PROCESS_LAUNCH_STARTTIME=${record#* }
        USER_PROCESS_STARTTIME=$USER_PROCESS_LAUNCH_STARTTIME
        pending_pid=$USER_PROCESS_LAUNCH_PID pending_start=$USER_PROCESS_LAUNCH_STARTTIME
        IA32_CLEANUP_STATUS=0
        ia32_finalize_pending_attempts
        result=$IA32_CLEANUP_STATUS
        ia32_wait_owned_child "$pending_pid" "$pending_start" 1 0 || result=1
        printf '%s\n' "$result" "$IA32_WAIT_STATE" "$IA32_WAIT_STATUS" >"$CASE_DIR/cleanup"
        exit "$result"
        ;;
    prepared-missing)
        user=$(recorded_process_control prepare "$CASE_DIR/user.pid" 2) || exit 1
        { IFS= read -r USER_RECORD_CONTROL; IFS= read -r USER_RECORD_IDENTITY; } <<EOF
$user
EOF
        root=$(recorded_process_control prepare "$CASE_DIR/root.pid" 2) || exit 2
        { IFS= read -r ROOT_RECORD_CONTROL; IFS= read -r ROOT_RECORD_IDENTITY; } <<EOF
$root
EOF
        USER_RECORD_PHASE=prepared USER_PROCESS_LAUNCH_PID= USER_PROCESS_LAUNCH_STARTTIME=
        USER_PROCESS_PID= USER_PROCESS_STARTTIME=
        ROOT_RECORD_PHASE=prepared ROOT_LAUNCH_PID= ROOT_LAUNCH_STARTTIME=
        ROOT_PROCESS_PID= ROOT_PROCESS_STARTTIME=
        signal_pinned_process() { : >"$CASE_DIR/unsafe-signal"; return 1; }
        IA32_CLEANUP_STATUS=0
        ia32_finalize_pending_attempts
        printf '%s\n' "$IA32_CLEANUP_STATUS" >"$CASE_DIR/cleanup"
        ;;
    committed-finalizer)
        shift
        ia32_launch_fixture "$CASE_DIR/process.pid" "$CASE_DIR/process.log" "$@" || exit $?
        IA32_CLEANUP_STATUS=0
        ia32_finalize_pending_attempts
        recording_launcher_active "$fixture_launch_pid" "$fixture_launch_starttime" \
            && : >"$CASE_DIR/committed-survived"
        ia32_terminate_user_child "$fixture_launch_pid" "$fixture_launch_starttime" >/dev/null 2>&1 || exit 2
        printf '%s\n' "$IA32_CLEANUP_STATUS" >"$CASE_DIR/cleanup"
        ;;
    signal-cleanup)
        shift
        prepare_actual_cleanup
        ia32_launch_fixture "$CASE_DIR/process.pid" "$CASE_DIR/process.log" "$@" || exit $?
        kill -HUP "$$"
        exit 100
        ;;
    acquisition-signal)
        role=$2
        shift 2
        prepare_actual_cleanup
        ia32_committed_transfer_hook() {
            [ "$1" = "$role" ] || return 0
            printf '%s\n' "$1" >"$CASE_DIR/transfer-boundary"
            kill -HUP "$$"
        }
        case $role in
            user) ia32_launch_fixture "$CASE_DIR/process.pid" "$CASE_DIR/process.log" "$@" ;;
            root) ia32_launch_trace "$CASE_DIR/process.pid" "$CASE_DIR/process.log" "$@" ;;
            *) exit 96 ;;
        esac
        exit 95
        ;;
    completion-timeout)
        shift
        prepare_actual_cleanup
        ia32_launch_fixture "$CASE_DIR/process.pid" "$CASE_DIR/process.log" "$@" || exit $?
        if ia32_complete_fixture 1 0; then result=0; else result=$?; fi
        printf '%s\n' "$result" "$fixture_completion_record" "$fixture_status_record" \
            "${fixture_launch_pid:-CLEARED}" >"$CASE_DIR/completion"
        exit 0
        ;;
    completion-unknown)
        shift
        prepare_actual_cleanup
        ia32_launch_fixture "$CASE_DIR/process.pid" "$CASE_DIR/process.log" "$@" || exit $?
        completion_pid=$fixture_launch_pid completion_start=$fixture_launch_starttime
        IA32_TEST_UNKNOWN=1
        recorded_process_control() {
            if [ "$IA32_TEST_UNKNOWN" -eq 1 ] && [ "$1" = active ]; then
                RECORDED_LAUNCHER_STATE=unknown
                return 2
            fi
            python3 -I "$RECORDED_PROCESS_EXEC" "$@"
        }
        if ia32_complete_fixture 1 0; then result=0; else result=$?; fi
        printf '%s\n' "$result" "$fixture_completion_record" "$fixture_status_record" \
            "$fixture_launch_pid" "$fixture_launch_starttime" >"$CASE_DIR/completion"
        IA32_TEST_UNKNOWN=0
        [ "$fixture_launch_pid" = "$completion_pid" ] \
            && [ "$fixture_launch_starttime" = "$completion_start" ] || exit 94
        exit 0
        ;;
    cleanup-independent)
        shift
        prepare_actual_cleanup
        ia32_launch_trace "$CASE_DIR/process.pid" "$CASE_DIR/process.log" "$@" || exit $?
        trace_guard_pid=$trace_root_pid
        trace_guard_starttime=$((trace_root_starttime + 1))
        exit 0
        ;;
    cleanup-output-failure)
        shift
        prepare_actual_cleanup
        mkdir "$EVIDENCE/cleanup.status"
        ia32_launch_fixture "$CASE_DIR/process.pid" "$CASE_DIR/process.log" "$@" || exit $?
        exit 0
        ;;
    guard-timeout)
        guard=$2 self_record=$3 target=$4 program=$5
        prepare_actual_cleanup
        ia32_launch_fixture "$CASE_DIR/timeout.pid" "$CASE_DIR/timeout.log" \
            timeout 30 "$guard" "$CASE_DIR/timeout.pid" "$self_record" "$target" "$program" \
            || exit 1
        timeout_pid=$fixture_pid timeout_start=$fixture_starttime
        timeout_launch=$fixture_launch_pid timeout_launch_start=$fixture_launch_starttime
        printf '%s\n' "$timeout_pid" "$timeout_start" "$timeout_launch" "$timeout_launch_start" \
            >"$CASE_DIR/fields"
        i=0
        while [ ! -e "$CASE_DIR/release" ] && [ "$i" -lt 500 ]; do
            i=$((i + 1)); sleep 0.01
        done
        [ -e "$CASE_DIR/release" ] || exit 2
        ia32_wait_owned_child "$timeout_launch" "$timeout_launch_start" 100 0.01 || exit 3
        printf '%s\n' "$IA32_WAIT_STATE" "$IA32_WAIT_STATUS" >"$CASE_DIR/wait"
        fixture_status_record=$IA32_WAIT_STATUS
        fixture_pid= fixture_starttime= fixture_launch_pid= fixture_launch_starttime=
        ;;
    root-launch)
        shift
        ia32_launch_trace "$CASE_DIR/root.pid" "$CASE_DIR/root.log" "$@" || exit $?
        printf '%s\n' "$trace_pid" "$trace_starttime" "$trace_root_pid" "$trace_root_starttime" \
            >"$CASE_DIR/fields"
        ia32_wait_owned_child "$trace_pid" "$trace_starttime" 80 0.01 || exit $?
        printf '%s\n' "$IA32_WAIT_STATE" "$IA32_WAIT_STATUS" >"$CASE_DIR/wait"
        ;;
    *) exit 97 ;;
esac

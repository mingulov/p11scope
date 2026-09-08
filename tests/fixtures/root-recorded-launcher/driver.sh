#!/bin/sh
set -u
. scripts/lib.sh
recorded_process_control() {
    if [ "$1" = prepare ]; then
        python3 -I "$RECORDED_PROCESS_EXEC" prepare "$2" "${CASE_DEADLINE:-2}"
        return $?
    fi
    if [ -n "${HOOK_OPERATION:-}" ]; then
        "$REAL_PYTHON" -I "$FIXTURE_DIR/owned-exec.py" hook \
            "$REAL_PYTHON" -I "$FIXTURE_DIR/hook.py" "$@" || return $?
    fi
    python3 -I "$RECORDED_PROCESS_EXEC" "$@"
}
# Numeric signals must be visible in the RED run without risking a decoy.
kill() { printf '%s\n' "$*" >> "$CASE_DIR/numeric-signals"; return 1; }
case $1 in
    terminate) terminate_recording_launcher "$2" "${3-}" user; exit $? ;;
    active)
        recording_launcher_active "$2" "${3-}"; result=$?
        printf '%s\n' "${RECORDED_LAUNCHER_STATE-}"
        exit "$result" ;;
    wait-record) wait_root_process_record "$2" "$3" "$4"; exit $? ;;
    prepared-finalize)
        prepared=$(recorded_process_control prepare "$CASE_DIR/process.pid" 2) || exit 1
        { IFS= read -r ROOT_RECORD_CONTROL; IFS= read -r ROOT_RECORD_IDENTITY; } <<EOF
$prepared
EOF
        ROOT_RECORD_PHASE=prepared ROOT_LAUNCH_PID= ROOT_LAUNCH_STARTTIME=
        finalize_root_recorded_process; result=$?
        printf '%s\n' "$ROOT_RECORD_CONTROL" "$ROOT_RECORD_IDENTITY"
        exit "$result" ;;
    pending-repeat)
        launch_root_recorded_process "$CASE_DIR/first.pid" "$CASE_DIR/first.log" sleep 300 && exit 1
        first=$ROOT_LAUNCH_PID first_start=$ROOT_LAUNCH_STARTTIME context=$ROOT_RECORD_IDENTITY
        launch_root_recorded_process "$CASE_DIR/second.pid" "$CASE_DIR/second.log" sleep 300 && exit 2
        [ "$ROOT_LAUNCH_PID:$ROOT_LAUNCH_STARTTIME:$ROOT_RECORD_IDENTITY" = "$first:$first_start:$context" ] || exit 3
        printf '%s\n' "$ROOT_LAUNCH_PID" "$ROOT_LAUNCH_STARTTIME" "" "" > "$CASE_DIR/fields"
        exit 0 ;;
    signal) signal_pinned_process user "$2" "$3" "$4"; exit $? ;;
    sequential)
        launch_root_recorded_process "$CASE_DIR/first.pid" "$CASE_DIR/first.log" sleep 300 || exit 1
        first=$ROOT_PROCESS_PID first_start=$ROOT_PROCESS_STARTTIME
        launch_root_recorded_process "$CASE_DIR/second.pid" "$CASE_DIR/second.log" sleep 300 || exit 2
        recording_launcher_active "$first" "$first_start" || exit 3
        finalize_root_recorded_process || exit 4
        recording_launcher_active "$ROOT_PROCESS_PID" "$ROOT_PROCESS_STARTTIME" || exit 5
        terminate_recording_launcher "$first" "$first_start" user || exit 6
        terminate_recording_launcher "$ROOT_PROCESS_PID" "$ROOT_PROCESS_STARTTIME" user || exit 7
        wait "$first" 2>/dev/null || true
        wait "$ROOT_LAUNCH_PID" 2>/dev/null || true
        exit 0 ;;
esac
mode=$1
shift
if [ "$mode" = split ]; then
    launch_root_recorded_process_split "$CASE_DIR/process.pid" "$CASE_DIR/stdout space's.log" \
        "$CASE_DIR/stderr space's.log" "$@"
    result=$?
    printf '%s\n' "${ROOT_LAUNCH_PID-}" "${ROOT_LAUNCH_STARTTIME-}" \
        "${ROOT_PROCESS_PID-}" "${ROOT_PROCESS_STARTTIME-}" "${ROOT_RECORD_PHASE-}" > "$CASE_DIR/fields"
    if [ "$result" -ne 0 ] && [ "${FINALIZE:-0}" = 1 ]; then
        finalize_root_recorded_process
        printf '%s\n' "$?" "${ROOT_LAUNCH_PID-}" "${ROOT_LAUNCH_STARTTIME-}" \
            "${ROOT_PROCESS_PID-}" "${ROOT_PROCESS_STARTTIME-}" "${ROOT_RECORD_IDENTITY-}" > "$CASE_DIR/finalized"
    fi
    [ "$result" -eq 0 ] || exit "$result"
    wait "$ROOT_LAUNCH_PID"
elif [ "$mode" = split-paths ]; then
    split_stdout=$1 split_stderr=$2
    shift 2
    launch_root_recorded_process_split "$CASE_DIR/process.pid" "$split_stdout" "$split_stderr" "$@"
    result=$?
    printf '%s\n' "${ROOT_LAUNCH_PID-}" "${ROOT_LAUNCH_STARTTIME-}" \
        "${ROOT_PROCESS_PID-}" "${ROOT_PROCESS_STARTTIME-}" "${ROOT_RECORD_PHASE-}" > "$CASE_DIR/fields"
    if [ "$result" -ne 0 ] && [ "${FINALIZE:-0}" = 1 ]; then
        finalize_root_recorded_process
        printf '%s\n' "$?" "${ROOT_LAUNCH_PID-}" "${ROOT_LAUNCH_STARTTIME-}" \
            "${ROOT_PROCESS_PID-}" "${ROOT_PROCESS_STARTTIME-}" "${ROOT_RECORD_IDENTITY-}" > "$CASE_DIR/finalized"
    fi
    [ "$result" -eq 0 ] || exit "$result"
    wait "$ROOT_LAUNCH_PID"
elif [ "$mode" = root ]; then
    launch_root_recorded_process "$CASE_DIR/process.pid" "$CASE_DIR/target.log" "$@"
    result=$?
    printf '%s\n' "${ROOT_LAUNCH_PID-}" "${ROOT_LAUNCH_STARTTIME-}" \
        "${ROOT_PROCESS_PID-}" "${ROOT_PROCESS_STARTTIME-}" "${ROOT_RECORD_PHASE-}" > "$CASE_DIR/fields"
    if [ "$result" -ne 0 ] && [ "${FINALIZE:-0}" = 1 ]; then
        finalize_root_recorded_process
        printf '%s\n' "$?" "${ROOT_LAUNCH_PID-}" "${ROOT_LAUNCH_STARTTIME-}" \
            "${ROOT_PROCESS_PID-}" "${ROOT_PROCESS_STARTTIME-}" "${ROOT_RECORD_IDENTITY-}" > "$CASE_DIR/finalized"
    fi
    [ "$result" -eq 0 ] || exit "$result"
    wait "$ROOT_LAUNCH_PID"
else
    launch_user_recorded_process "$CASE_DIR/process.pid" "$CASE_DIR/target.log" "$@"
    result=$?
    printf '%s\n' "${USER_PROCESS_LAUNCH_PID-}" "${USER_PROCESS_LAUNCH_STARTTIME-}" \
        "${USER_PROCESS_PID-}" "${USER_PROCESS_STARTTIME-}" "${USER_RECORD_PHASE-}" > "$CASE_DIR/fields"
    [ "$result" -eq 0 ] || exit "$result"
    wait "$USER_PROCESS_LAUNCH_PID"
fi

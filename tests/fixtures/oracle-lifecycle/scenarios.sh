#!/bin/sh
set -eu

driver=$1
scenario=$2
shift 2
P11SCOPE_ORACLE_SOURCE_ONLY=1
export P11SCOPE_ORACLE_SOURCE_ONLY
. "$driver"

mark() { printf '%s\n' "$1" >> "$events"; }

case $scenario in
body)
    events=$1
    WORK=$events.work
    PRODUCT=$WORK/target
    mkdir -p "$WORK"
    oracle_build_product() { mark build; }
    oracle_setup_token() { mark token; }
    oracle_discover() { mark discover; return "${FAIL_DISCOVER-0}"; }
    oracle_assert_initial_state_absent() { mark state-start; }
    oracle_launch_scope() { mark launch; }
    oracle_authenticate_scope() { mark authenticate; }
    oracle_record_scope_facts() { mark scope-facts; }
    oracle_launch_observer() { mark observer; }
    oracle_wait_ready() { mark ready; }
    oracle_probe_cgroup() { mark probe; return "${FAIL_PROBE-0}"; }
    oracle_release_fifo() { mark fifo; }
    oracle_wait_clients() { mark waits; }
    oracle_record_state_ids() { mark state-ids; }
    oracle_reclaim_owned_artifacts() { mark reclaim; }
    oracle_run_subset() { mark subset; }
    oracle_body
    ;;
finalizer)
    events=$1
    action=${2-success}
    oracle_cleanup() {
        mark cleanup-start
        case $action in
        repeated-term) kill -TERM $$; kill -TERM $$ ;;
        repeated-int) kill -INT $$; kill -INT $$ ;;
        repeated-hup) kill -HUP $$; kill -HUP $$ ;;
        esac
        mark cleanup-finished
        return "${CLEANUP_RC-0}"
    }
    task4_terminal_checks() { mark terminal-checks; return 0; }
    task4_validate_receipt() { mark validate; return 0; }
    task4_publish_status() { mark "publish:$1"; return "${PUBLISH_RC-0}"; }
    task4_install_traps
    case $action in
    success) : ;;
    failure) false ;;
    term|repeated-term) kill -TERM $$ ;;
    repeated-int) kill -INT $$ ;;
    repeated-hup) kill -HUP $$ ;;
    *) exit 2 ;;
    esac
    ;;
publication)
    TASK4_ROOT=$1
    TASK4_FACTS=$TASK4_ROOT/facts.log
    : > "$TASK4_FACTS"
    mkdir "$TASK4_ROOT/.status.pending"
    if task4_publish_status 0; then exit 0; else exit $?; fi
    ;;
cleanup)
    events=$1
    sentinel=$2
    ORACLE_LAUNCH_ATTEMPTED=1
    ORACLE_CGROUP_PINNED=${PINNED-0}
    ORACLE_PRODUCERS_QUIESCENT=0
    FIFO=
    oracle_kill_cgroup() { mark cgroup; }
    oracle_stop_observer() { mark observer; }
    oracle_reap_launcher() { mark launcher; }
    oracle_reclaim_owned_artifacts() { mark reclaim; }
    oracle_cleanup_state() { mark state; }
    if oracle_cleanup; then exit 0; else exit $?; fi
    ;;
wait-deadline)
    sleep 30 & child=$!
    start=$(process_starttime "$child")
    if oracle_wait_child "$child" "$start" 2; then rc=0; else rc=$?; fi
    kill "$child" 2>/dev/null || :
    wait "$child" 2>/dev/null || :
    exit "$rc"
    ;;
wait-query-error)
    foreign=$1
    recording_launcher_active() { RECORDED_LAUNCHER_STATE=unknown; return 2; }
    process_matches_starttime() { return 1; }
    timeout --signal=KILL 1s sleep 30 & child=$!
    start=$(process_starttime "$child")
    if oracle_wait_child "$child" "$start" 2; then wait_rc=0; else wait_rc=$?; fi
    kill "$child" 2>/dev/null || :
    wait "$child" 2>/dev/null || :
    timeout --signal=KILL 1s sleep 30 & child=$!
    start=$(process_starttime "$child")
    if oracle_reap_child "$child" "$start" 2; then reap_rc=0; else reap_rc=$?; fi
    kill "$child" 2>/dev/null || :
    wait "$child" 2>/dev/null || :
    kill -0 "$foreign"
    printf 'wait=%s reap=%s foreign=live\n' "$wait_rc" "$reap_rc"
    ;;
hung-clients)
    identity=$1
    owned_hung_pid= owned_hung_start= owned_observer_pid= owned_observer_start=
    fixture_terminate_owned() {
        fto_pid=$1
        fto_start=$2
        if recording_launcher_active "$fto_pid" "$fto_start"; then
            signal_verified_process KILL "$fto_pid" "$fto_start" || return 2
        else
            fto_query=$?
            fto_state=${RECORDED_LAUNCHER_STATE-unknown}
            case $fto_query:$fto_state in
            1:gone|1:zombie) : ;;
            *) return 2 ;;
            esac
        fi
        oracle_reap_child "$fto_pid" "$fto_start" 20
    }
    fixture_cleanup_owned() {
        fco_status=$?
        trap - EXIT
        fco_cleanup=0
        if [ -n "$owned_observer_pid" ] && [ -n "$owned_observer_start" ]; then
            fixture_terminate_owned "$owned_observer_pid" "$owned_observer_start" \
                || fco_cleanup=$?
        fi
        if [ -n "$owned_hung_pid" ] && [ -n "$owned_hung_start" ]; then
            fixture_terminate_owned "$owned_hung_pid" "$owned_hung_start" \
                || fco_cleanup=$?
        fi
        [ "$fco_status" -ne 0 ] || fco_status=$fco_cleanup
        exit "$fco_status"
    }
    trap 'fixture_cleanup_owned' EXIT

    sleep 30 & owned_hung_pid=$!
    owned_hung_start=$(process_starttime "$owned_hung_pid")
    printf '%s %s\n' "$owned_hung_pid" "$owned_hung_start" > "$identity"
    [ "${STOP_AFTER_IDENTITY-0}" = 0 ] || kill -STOP $$
    if oracle_wait_child "$owned_hung_pid" "$owned_hung_start" 2; then hung_rc=0; else hung_rc=$?; fi
    [ "$hung_rc" -eq 124 ]
    fixture_terminate_owned "$owned_hung_pid" "$owned_hung_start"
    owned_hung_pid= owned_hung_start=

    /bin/false & owned_observer_pid=$!
    owned_observer_start=$(process_starttime "$owned_observer_pid")
    if oracle_wait_child "$owned_observer_pid" "$owned_observer_start" 20; then observer_rc=0; else observer_rc=$?; fi
    [ "$observer_rc" -ne 1 ] || owned_observer_pid= owned_observer_start=
    [ "$observer_rc" -eq 1 ]
    printf 'hung=%s observer=%s\n' "$hung_rc" "$observer_rc"
    ;;
authentication)
    membership=$1
    cgroup=$2
    invocation_state=${3-}
    WORKLOAD_PID=$$
    WORKLOAD_STARTTIME=$(process_starttime $$)
    CONTROL_GROUP=$membership
    CGROUP_PATH=$cgroup
    UNIT=controlled
    [ "${WRONG_START-0}" = 0 ] || WORKLOAD_STARTTIME=$((WORKLOAD_STARTTIME + 1))
    oracle_systemd_property() {
        case $1 in
        ControlGroup)
            [ "${CONTROL_FAIL-0}" = 0 ] || return 1
            printf '%s\n' "$CONTROL_GROUP"
            ;;
        InvocationID)
            if [ -n "$invocation_state" ]; then
                if [ -e "$invocation_state" ]; then
                    printf '%s\n' replacement
                else
                    : > "$invocation_state"
                    printf '%s\n' original
                fi
            else
                printf '%s\n' test-invocation
            fi
            ;;
        esac
    }
    oracle_root_matches() { process_matches_starttime "$@"; }
    oracle_authenticate_scope
    ;;
scope-facts)
    TASK4_FACTS=$1
    CGROUP_PATH=/sys/fs/cgroup/system.slice/p11scope-oracle.scope
    ORACLE_CGROUP_DEVICE=42
    ORACLE_CGROUP_INODE=99
    WORKLOAD_PID=123
    WORKLOAD_STARTTIME=456
    UNIT=p11scope-oracle
    CONTROL_GROUP=/system.slice/p11scope-oracle.scope
    ORACLE_INVOCATION=invocation-id
    oracle_record_scope_facts
    ;;
reclaim)
    WORK=$1
    PKCS11_CHECK_DIR=$2
    TASK4_WORK_ID=$(stat -Lc %d:%i "$WORK")
    PKCS11_CHECK_DIR_ID=$(stat -Lc %d:%i "$PKCS11_CHECK_DIR")
    TASK4_RECEIPT_STARTTIME=$(process_starttime $$)
    TASK4_RECEIPT_UID=$(id -u)
    TASK4_RECEIPT_GID=$(id -g)
    STATE_FILE_ID=
    STATE_POLICY_FILE_ID=
    ORACLE_ARTIFACTS_RECLAIMED=0
    exec 6< "$PKCS11_CHECK_DIR"
    exec 8< "$WORK"
    oracle_reclaim_owned_artifacts
    ;;
*)
    printf 'unknown scenario: %s\n' "$scenario" >&2
    exit 2
    ;;
esac

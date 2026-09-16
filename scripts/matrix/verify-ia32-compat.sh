#!/bin/sh
# Kernel feasibility gate for x86-64 hosts observing native x86-64 and ia32
# uprobes. This does not exercise Aya or qualify p11scope's producer/verifier.
if [ "${P11SCOPE_IA32_SOURCE_ONLY:-0}" != 1 ]; then
    set -eu
    cd "$(dirname "$0")/../.."
fi
. scripts/lib.sh

current_status_log=
fixture_status_record=UNRUN
fixture_completion_record=UNRUN
bystander_status_record=UNRUN
trace_status_record=UNRUN
fixture_pid=
fixture_starttime=
fixture_launch_pid=
fixture_launch_starttime=
fixture_acquisition=idle
trace_pid=
trace_starttime=
trace_root_pid=
trace_root_starttime=
trace_guard_pid=
trace_guard_starttime=
trace_acquisition=idle
CLEANUP_STATUS=0
write_status() {
    [ -n "$current_status_log" ] || return 0
    {
        echo "fixture_status=$fixture_status_record"
        echo "fixture_completion=$fixture_completion_record"
        echo "bystander_status=$bystander_status_record"
        echo "tracer_status=$trace_status_record"
    } >"$current_status_log"
}

ia32_committed_transfer_hook() { :; }

ia32_adopt_committed_transfers() {
    case ${fixture_acquisition:-idle} in
        launching|committed)
            if [ -n "${USER_PROCESS_LAUNCH_PID:-}" ] \
                && [ -n "${USER_PROCESS_LAUNCH_STARTTIME:-}" ] \
                && [ -n "${USER_PROCESS_PID:-}" ] \
                && [ -n "${USER_PROCESS_STARTTIME:-}" ] \
                && [ -z "${USER_RECORD_IDENTITY:-}" ]; then
                fixture_launch_pid=$USER_PROCESS_LAUNCH_PID \
                    fixture_launch_starttime=$USER_PROCESS_LAUNCH_STARTTIME \
                    fixture_pid=$USER_PROCESS_PID fixture_starttime=$USER_PROCESS_STARTTIME
                fixture_acquisition=idle
            fi
            ;;
    esac
    case ${trace_acquisition:-idle} in
        launching|committed)
            if [ -n "${ROOT_LAUNCH_PID:-}" ] && [ -n "${ROOT_LAUNCH_STARTTIME:-}" ] \
                && [ -n "${ROOT_PROCESS_PID:-}" ] && [ -n "${ROOT_PROCESS_STARTTIME:-}" ] \
                && [ -z "${ROOT_RECORD_IDENTITY:-}" ]; then
                trace_pid=$ROOT_LAUNCH_PID trace_starttime=$ROOT_LAUNCH_STARTTIME \
                    trace_root_pid=$ROOT_PROCESS_PID trace_root_starttime=$ROOT_PROCESS_STARTTIME
                trace_acquisition=idle
            fi
            ;;
    esac
}

# Classify and reap only an authenticated direct shell child. Replaced and
# unknown identities never authorize a numeric wait or signal.
ia32_wait_owned_child() {
    iwoc_pid=$1 iwoc_starttime=$2 iwoc_attempts=$3 iwoc_delay=$4
    IA32_WAIT_STATE=unknown IA32_WAIT_STATUS=
    while [ "$iwoc_attempts" -gt 0 ]; do
        if recording_launcher_active "$iwoc_pid" "$iwoc_starttime"; then
            iwoc_state=live
        else
            iwoc_result=$? iwoc_state=$RECORDED_LAUNCHER_STATE
            case $iwoc_result:$iwoc_state in
                1:gone|1:zombie)
                    if wait "$iwoc_pid"; then IA32_WAIT_STATUS=0; else IA32_WAIT_STATUS=$?; fi
                    IA32_WAIT_STATE=$iwoc_state
                    return 0
                    ;;
                1:replaced|2:unknown)
                    IA32_WAIT_STATE=$iwoc_state
                    return 2
                    ;;
                *) IA32_WAIT_STATE=unknown; return 2 ;;
            esac
        fi
        iwoc_attempts=$((iwoc_attempts - 1))
        [ "$iwoc_attempts" -eq 0 ] || sleep "$iwoc_delay"
    done
    IA32_WAIT_STATE=$iwoc_state
    return 1
}

ia32_wait_for_stopped() {
    iwfs_pid=$1 iwfs_starttime=$2 iwfs_attempts=$3 iwfs_delay=$4
    while [ "$iwfs_attempts" -gt 0 ]; do
        iwfs_record=$(awk '{ sub(/^[0-9]+ \(.*\) /, ""); split($0, tail, " "); print tail[1], tail[20]; exit }' \
            "/proc/$iwfs_pid/stat" 2>/dev/null) || return 2
        iwfs_state=${iwfs_record%% *} iwfs_current=${iwfs_record#* }
        [ "$iwfs_current" = "$iwfs_starttime" ] || return 2
        case $iwfs_state in T|t) return 0 ;; esac
        iwfs_attempts=$((iwfs_attempts - 1))
        [ "$iwfs_attempts" -eq 0 ] || sleep "$iwfs_delay"
    done
    return 1
}

ia32_terminate_user_child() {
    ituc_pid=$1 ituc_starttime=$2
    if recording_launcher_active "$ituc_pid" "$ituc_starttime"; then
        terminate_recording_launcher "$ituc_pid" "$ituc_starttime" user || return $?
    else
        ituc_result=$?
        case $ituc_result:$RECORDED_LAUNCHER_STATE in
            1:gone|1:zombie) ;;
            *) IA32_WAIT_STATE=$RECORDED_LAUNCHER_STATE; IA32_WAIT_STATUS=; return 2 ;;
        esac
    fi
    ia32_wait_owned_child "$ituc_pid" "$ituc_starttime" 1 0
}

ia32_launch_fixture() {
    ilf_pidfile=$1 ilf_log=$2
    shift 2
    [ "${fixture_acquisition:-idle}" = idle ] \
        && [ -z "${fixture_launch_pid:-}${fixture_launch_starttime:-}${fixture_pid:-}${fixture_starttime:-}" ] \
        || return 2
    fixture_acquisition=launching
    if ! launch_user_recorded_process "$ilf_pidfile" "$ilf_log" "$@"; then
        fixture_status_record=STARTUP_FAILED
        return 1
    fi
    fixture_acquisition=committed
    fixture_status_record=STARTED
    ia32_committed_transfer_hook user
    ia32_adopt_committed_transfers
    [ "$fixture_acquisition" = idle ] || { fixture_status_record=OWNERSHIP_UNRESOLVED; return 2; }
}

ia32_launch_trace() {
    ilt_pidfile=$1 ilt_log=$2
    shift 2
    [ "${trace_acquisition:-idle}" = idle ] \
        && [ -z "${trace_pid:-}${trace_starttime:-}${trace_root_pid:-}${trace_root_starttime:-}" ] \
        || return 2
    trace_acquisition=launching
    if ! launch_root_recorded_process "$ilt_pidfile" "$ilt_log" "$@"; then
        trace_status_record=STARTUP_FAILED
        return 1
    fi
    trace_acquisition=committed
    trace_status_record=STARTED
    ia32_committed_transfer_hook root
    ia32_adopt_committed_transfers
    [ "$trace_acquisition" = idle ] || { trace_status_record=OWNERSHIP_UNRESOLVED; return 2; }
}

ia32_complete_fixture() {
    icf_attempts=$1 icf_delay=$2
    fixture_completion_record=WAITING
    if ia32_wait_owned_child "$fixture_launch_pid" "$fixture_launch_starttime" \
        "$icf_attempts" "$icf_delay"; then
        fixture_status_record=$IA32_WAIT_STATUS
        fixture_completion_record=COMPLETE
        fixture_pid= fixture_starttime= fixture_launch_pid= fixture_launch_starttime=
        return 0
    else
        icf_wait_result=$?
    fi
    case $icf_wait_result:$IA32_WAIT_STATE in
        1:*) fixture_completion_record=DEADLINE_EXPIRED ;;
        *) fixture_completion_record=IDENTITY_UNRESOLVED ;;
    esac
    if ia32_terminate_user_child "$fixture_launch_pid" "$fixture_launch_starttime"; then
        fixture_status_record=$IA32_WAIT_STATUS
        fixture_pid= fixture_starttime= fixture_launch_pid= fixture_launch_starttime=
    else
        fixture_status_record=UNKNOWN
    fi
    return 1
}

ia32_finalize_pending_attempts() {
    : "${IA32_CLEANUP_STATUS:=0}"
    IA32_PENDING_USER_PID= IA32_PENDING_USER_STARTTIME=
    IA32_PENDING_ROOT_PID= IA32_PENDING_ROOT_STARTTIME=
    if [ -n "${USER_RECORD_IDENTITY:-}" ]; then
        IA32_PENDING_USER_PID=${USER_PROCESS_LAUNCH_PID:-}
        IA32_PENDING_USER_STARTTIME=${USER_PROCESS_LAUNCH_STARTTIME:-}
    fi
    if [ -n "${ROOT_RECORD_IDENTITY:-}" ]; then
        IA32_PENDING_ROOT_PID=${ROOT_LAUNCH_PID:-}
        IA32_PENDING_ROOT_STARTTIME=${ROOT_LAUNCH_STARTTIME:-}
    fi
    finalize_user_recorded_process || IA32_CLEANUP_STATUS=1
    finalize_root_recorded_process || IA32_CLEANUP_STATUS=1
    return 0
}

IA32_CLEANUP_ENTERED=0
ia32_begin_cleanup() {
    [ "$IA32_CLEANUP_ENTERED" -eq 0 ] || return 1
    IA32_CLEANUP_ENTERED=1
    IA32_ORIGINAL_STATUS=$1
    trap - EXIT HUP INT TERM
    trap '' HUP INT TERM
    set +e
}

ia32_cleanup() {
    ia32_begin_cleanup "$1" || return 1
    CLEANUP_STATUS=0
    ia32_adopt_committed_transfers
    [ "${fixture_acquisition:-idle}" = idle ] || CLEANUP_STATUS=1
    [ "${trace_acquisition:-idle}" = idle ] || CLEANUP_STATUS=1
    if [ -n "$fixture_launch_pid" ] && [ -n "$fixture_launch_starttime" ]; then
        if ia32_terminate_user_child "$fixture_launch_pid" "$fixture_launch_starttime"; then
            fixture_status_record=$IA32_WAIT_STATUS
            fixture_pid= fixture_starttime= fixture_launch_pid= fixture_launch_starttime=
        else
            CLEANUP_STATUS=1
            fixture_status_record=UNKNOWN
        fi
    fi
    if [ -n "$trace_guard_pid" ] && [ -n "$trace_guard_starttime" ]; then
        guard_cleanup_status=0
        terminate_recording_launcher "$trace_guard_pid" "$trace_guard_starttime" root \
            || guard_cleanup_status=1
        if [ "$guard_cleanup_status" -eq 0 ]; then
            if recording_launcher_active "$trace_guard_pid" "$trace_guard_starttime"; then
                guard_cleanup_status=1
            else
                cleanup_state=$?
                case $cleanup_state:$RECORDED_LAUNCHER_STATE in
                    1:gone|1:zombie) trace_guard_pid= trace_guard_starttime= ;;
                    *) guard_cleanup_status=1 ;;
                esac
            fi
        fi
        [ "$guard_cleanup_status" -eq 0 ] || CLEANUP_STATUS=1
    fi
    if [ -n "$trace_root_pid" ] && [ -n "$trace_root_starttime" ]; then
        timeout_cleanup_status=0
        if recording_launcher_active "$trace_root_pid" "$trace_root_starttime"; then
            signal_verified_root_process CONT "$trace_root_pid" "$trace_root_starttime" \
                >/dev/null 2>&1 || timeout_cleanup_status=1
        else
            cleanup_state=$?
            case $cleanup_state:$RECORDED_LAUNCHER_STATE in
                1:gone|1:zombie) ;;
                *) timeout_cleanup_status=1 ;;
            esac
        fi
        if terminate_recording_launcher "$trace_root_pid" "$trace_root_starttime" root; then
            if recording_launcher_active "$trace_root_pid" "$trace_root_starttime"; then
                timeout_cleanup_status=1
            else
                cleanup_state=$?
                case $cleanup_state:$RECORDED_LAUNCHER_STATE in
                    1:gone|1:zombie) trace_root_pid= trace_root_starttime= ;;
                    *) timeout_cleanup_status=1 ;;
                esac
            fi
        else
            timeout_cleanup_status=1
        fi
        [ "$timeout_cleanup_status" -eq 0 ] || CLEANUP_STATUS=1
    fi
    if [ -n "$trace_pid" ] && [ -n "$trace_starttime" ]; then
        if ia32_wait_owned_child "$trace_pid" "$trace_starttime" 120 0.05; then
            trace_status_record=$IA32_WAIT_STATUS
            trace_pid= trace_starttime=
        else
            CLEANUP_STATUS=1
            trace_status_record=UNKNOWN
        fi
    elif [ "$trace_status_record" = STARTED ]; then
        trace_status_record=UNKNOWN
        CLEANUP_STATUS=1
    fi
    IA32_CLEANUP_STATUS=$CLEANUP_STATUS
    ia32_finalize_pending_attempts
    CLEANUP_STATUS=$IA32_CLEANUP_STATUS
    if [ -n "$IA32_PENDING_USER_PID" ] && [ -n "$IA32_PENDING_USER_STARTTIME" ] \
        && [ -z "${USER_RECORD_IDENTITY:-}" ]; then
        ia32_wait_owned_child "$IA32_PENDING_USER_PID" "$IA32_PENDING_USER_STARTTIME" 120 0.05 \
            || CLEANUP_STATUS=1
    fi
    if [ -n "$IA32_PENDING_ROOT_PID" ] && [ -n "$IA32_PENDING_ROOT_STARTTIME" ] \
        && [ -z "${ROOT_RECORD_IDENTITY:-}" ]; then
        ia32_wait_owned_child "$IA32_PENDING_ROOT_PID" "$IA32_PENDING_ROOT_STARTTIME" 120 0.05 \
            || CLEANUP_STATUS=1
    fi
    write_status || CLEANUP_STATUS=1
    if [ -n "${EVIDENCE:-}" ]; then
        printf 'cleanup_status=%s\n' "$CLEANUP_STATUS" >"$EVIDENCE/cleanup.status" \
            || CLEANUP_STATUS=1
    else
        CLEANUP_STATUS=1
    fi
    final_status=$IA32_ORIGINAL_STATUS
    [ "$final_status" -ne 0 ] || final_status=$CLEANUP_STATUS
    if [ "$CLEANUP_STATUS" -eq 0 ]; then
        echo "CLEANUP_RESULT=PASS status=$final_status"
    else
        echo "CLEANUP_RESULT=NONPASS status=$final_status"
    fi
    return "$final_status"
}

cleanup() {
    original_status=$?
    ia32_cleanup "$original_status"
    exit $?
}

check_log() {
    abi=$1
    log=$2
    case $abi in
        32) cs=35; offset=12; vendor_rv=2147483649 ;;
        64) cs=51; offset=24; vendor_rv=1311768467015204865 ;;
        *) return 1 ;;
    esac
    awk -v abi="$abi" -v cs="$cs" -v offset="$offset" -v vendor_rv="$vendor_rv" '
        $0 == "PROBE_READY abi=" abi { ready++; next }
        $0 == "ENTRY abi=" abi " n=1 cs=" cs " a0=1 a1=2 a2=3 a3=4 a4=5 a5=6 a6=7" { e1++; next }
        $0 == "RETURN abi=" abi " n=1 rv=0" { r1++; next }
        $0 == "ENTRY abi=" abi " n=2 cs=" cs " a0=11 a1=22 a2=33 a3=44 a4=55 a5=66 a6=77" { e2++; next }
        $0 == "RETURN abi=" abi " n=2 rv=" vendor_rv { r2++; next }
        $0 == "LOADER abi=" abi " n=1 cs=" cs " ip_nonzero=1 state=1 offset=" offset " width=4" { l1++; next }
        $0 == "LOADER abi=" abi " n=2 cs=" cs " ip_nonzero=1 state=0 offset=" offset " width=4" { l2++; next }
        $0 == "LOADER abi=" abi " n=3 cs=" cs " ip_nonzero=1 state=2 offset=" offset " width=4" { l3++; next }
        $0 == "LOADER abi=" abi " n=4 cs=" cs " ip_nonzero=1 state=0 offset=" offset " width=4" { l4++; next }
        NF { bad++ }
        END {
            exit !(bad == 0 && ready == 1 && e1 == 1 && r1 == 1 &&
                   e2 == 1 && r2 == 1 && l1 == 1 && l2 == 1 &&
                   l3 == 1 && l4 == 1)
        }
    ' "$log"
}

check_invalid_read_log() {
    grep -q '^INVALID_READ_ATTEMPT=1 value=0$' "$1" &&
        grep -Eq 'WARNING: Failed to probe_read_user|^Additional Info - helper: probe_read_user, retcode: -14$' "$1"
}

self_test() {
    work=$(mktemp -d)
    EVIDENCE=$work/evidence
    mkdir "$EVIDENCE"
    IA32_CLEANUP_ENTERED=0
    self_test_cleanup() {
        self_test_status=$?
        ia32_cleanup "$self_test_status"
        self_test_status=$?
        rm -rf "$work"
        exit "$self_test_status"
    }
    trap self_test_cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    good=$work/good
    cat >"$good" <<'EOF'
PROBE_READY abi=32
LOADER abi=32 n=1 cs=35 ip_nonzero=1 state=1 offset=12 width=4
LOADER abi=32 n=2 cs=35 ip_nonzero=1 state=0 offset=12 width=4
LOADER abi=32 n=3 cs=35 ip_nonzero=1 state=2 offset=12 width=4
LOADER abi=32 n=4 cs=35 ip_nonzero=1 state=0 offset=12 width=4
ENTRY abi=32 n=1 cs=35 a0=1 a1=2 a2=3 a3=4 a4=5 a5=6 a6=7
RETURN abi=32 n=1 rv=0
ENTRY abi=32 n=2 cs=35 a0=11 a1=22 a2=33 a3=44 a4=55 a5=66 a6=77
RETURN abi=32 n=2 rv=2147483649
EOF
    check_log 32 "$good"
    sed 's/a6=77/a6=76/' "$good" >"$work/wrong-arg"
    if check_log 32 "$work/wrong-arg"; then return 1; fi
    sed 's/rv=2147483649/rv=1/' "$good" >"$work/truncated-rv"
    if check_log 32 "$work/truncated-rv"; then return 1; fi
    sed 's/rv=2147483649/rv=1311768467015204865/' "$good" >"$work/upper32-poison"
    if check_log 32 "$work/upper32-poison"; then return 1; fi
    sed '/RETURN abi=32 n=2/d' "$good" >"$work/missing-return"
    if check_log 32 "$work/missing-return"; then return 1; fi
    sed 's/n=2 cs=35 ip_nonzero=1 state=0/n=2 cs=35 ip_nonzero=1 state=2/' "$good" >"$work/swapped-loader"
    if check_log 32 "$work/swapped-loader"; then return 1; fi
    sed '/LOADER abi=32 n=4/a\LOADER abi=32 n=5 cs=35 ip_nonzero=1 state=0 offset=12 width=4' "$good" >"$work/extra-loader"
    if check_log 32 "$work/extra-loader"; then return 1; fi
    sed '/LOADER abi=32 n=3/d' "$good" >"$work/missing-loader"
    if check_log 32 "$work/missing-loader"; then return 1; fi
    sed '2i\stdin:1: WARNING: Failed to probe_read_user: Bad address (-14)' "$good" >"$work/read-failure"
    if check_log 32 "$work/read-failure"; then return 1; fi
    printf '%s\n' 'INVALID_READ_ATTEMPT=1 value=0' \
        'stdin:1: WARNING: Failed to probe_read_user: Bad address (-14)' >"$work/invalid-read-old"
    check_invalid_read_log "$work/invalid-read-old"
    printf '%s\n' 'INVALID_READ_ATTEMPT=1 value=0' 'stdin:1: WARNING: Bad address' \
        'Additional Info - helper: probe_read_user, retcode: -14' >"$work/invalid-read-new"
    check_invalid_read_log "$work/invalid-read-new"
    sed 's/probe_read_user/probe_read_kernel/' "$work/invalid-read-new" >"$work/wrong-helper"
    if check_invalid_read_log "$work/wrong-helper"; then return 1; fi
    fixture_pid= fixture_starttime= fixture_launch_pid= fixture_launch_starttime=
    fixture_status_record=UNRUN
    fixture_completion_record=UNRUN
    ia32_launch_fixture "$work/stopped.pid" "$work/stopped.log" \
        sh -c 'kill -STOP "$$"; exec sleep 300' || return 1
    ia32_wait_for_stopped "$fixture_pid" "$fixture_starttime" 100 0.01 || return 1
    ia32_terminate_user_child "$fixture_launch_pid" "$fixture_launch_starttime" || return 1
    fixture_pid= fixture_starttime= fixture_launch_pid= fixture_launch_starttime=
    status=0
    timeout --kill-after=1 -s INT 1 sh -c 'trap "" INT TERM; while :; do :; done' \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 137 ]
    current_status_log=$work/injected.status
    fixture_status_record=UNRUN
    bystander_status_record=UNRUN
    trace_status_record=UNRUN
    write_status || return 1
    fixture_pid= fixture_starttime= fixture_launch_pid= fixture_launch_starttime=
    ia32_launch_fixture "$work/injected.pid" "$work/injected.log" \
        sh -c 'echo injected-launch-error >&2; exit 9' || return 1
    trace_status_record=STARTED
    write_status || return 1
    grep -q '^tracer_status=STARTED$' "$current_status_log"
    ia32_wait_owned_child "$fixture_launch_pid" "$fixture_launch_starttime" 100 0.01 || return 1
    status=$IA32_WAIT_STATUS
    fixture_pid= fixture_starttime= fixture_launch_pid= fixture_launch_starttime=
    trace_status_record=$status
    write_status || return 1
    grep -q '^tracer_status=9$' "$current_status_log"
    grep -q '^injected-launch-error$' "$work/injected.log"
    current_status_log=
    echo "SELF_TEST=PASS"
    echo "SELF_TEST_UPPER32_POISON=SYNTHETIC_ONLY"
}

if [ "${P11SCOPE_IA32_SOURCE_ONLY:-0}" = 1 ]; then return 0 2>/dev/null || exit 0; fi
if [ "${1-}" = --self-test ]; then self_test; exit 0; fi

require_non_root_caller
command -v gcc >/dev/null || { echo "RESULT=SKIP reason=no_gcc"; exit 77; }
command -v readelf >/dev/null || { echo "RESULT=SKIP reason=no_readelf"; exit 77; }
command -v bpftrace >/dev/null || { echo "RESULT=SKIP reason=no_bpftrace"; exit 77; }
command -v timeout >/dev/null || { echo "RESULT=SKIP reason=no_timeout"; exit 77; }
[ "$(uname -m)" = x86_64 ] || { echo "RESULT=SKIP reason=host_not_x86_64"; exit 77; }
sudo -n true 2>/dev/null || { echo "RESULT=SKIP reason=no_passwordless_sudo"; exit 77; }

EVIDENCE=${1:-${P11SCOPE_IA32_COMPAT_EVIDENCE:-}}
[ -n "$EVIDENCE" ] || { echo "RESULT=SKIP reason=evidence_root_required"; exit 77; }
[ ! -e "$EVIDENCE" ] || { echo "RESULT=NONPASS reason=evidence_root_exists"; exit 1; }
mkdir -m 700 "$EVIDENCE"
WORK=$EVIDENCE/work
mkdir -m 700 "$WORK"
SRC=scripts/matrix/ia32-compat-harness.c
. scripts/cleanup-traps.sh
trap 'exit 129' HUP

{
    echo "kernel_release=$(uname -r)"
    echo "kernel_version=$(uname -v)"
    echo "gcc_version=$(gcc -dumpfullversion -dumpversion)"
    echo "bpftrace_version=$(bpftrace --version | sed 's/^bpftrace v//')"
} >"$EVIDENCE/environment.status"
TRACE_GUARD_SRC=scripts/matrix/ia32-compat-trace-exec.c
TRACE_GUARD_BIN=$WORK/ia32-compat-trace-exec
sha256sum "$SRC" scripts/matrix/verify-ia32-compat.sh scripts/lib.sh \
    scripts/recorded-process-exec.py scripts/cleanup-traps.sh "$TRACE_GUARD_SRC" \
    >"$EVIDENCE/source.sha256"

build_abi() {
    abi=$1
    cfi=
    [ "$abi" = 32 ] && cfi=-fcf-protection=branch
    gcc "-m$abi" -O1 -g -Wall -Wextra -Werror -fno-omit-frame-pointer \
        $cfi -rdynamic -o "$WORK/harness-$abi" "$SRC" -ldl || return
    gcc "-m$abi" -O1 -g -Wall -Wextra -Werror -fPIC -shared \
        -DIA32_COMPAT_DSO -o "$WORK/second-$abi.so" "$SRC" || return
}
build_trace_guard() {
    gcc -O2 -Wall -Wextra -Werror -o "$TRACE_GUARD_BIN" "$TRACE_GUARD_SRC" || return
    sha256sum "$TRACE_GUARD_BIN" >>"$EVIDENCE/source.sha256"
}
loader_path() { readelf -l "$1" | sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p'; }
symbol_value() { readelf -Ws "$1" | awk -v name="$2" '$8 ~ ("^" name "(@@.*)?$") { print "0x" $2; exit }'; }

run_abi() {
    abi=$1
    mode=${2:-core}
    tag=abi${abi}-${mode}
    bin=$WORK/harness-$abi
    so=$WORK/second-$abi.so
    fixture_log=$EVIDENCE/$tag-fixture.log
    bystander_log=$EVIDENCE/$tag-bystander.log
    trace_log=$EVIDENCE/$tag-trace.log
    status_log=$EVIDENCE/$tag.status
    program=$EVIDENCE/$tag.bt
    root_pidfile=$EVIDENCE/$tag-tracer.pid
    fixture_pidfile=$EVIDENCE/$tag-fixture.pid
    guard_pidfile=$EVIDENCE/$tag-guard.pid
    current_status_log=$status_log
    fixture_status_record=UNRUN
    fixture_completion_record=UNRUN
    bystander_status_record=UNRUN
    trace_status_record=UNRUN
    write_status || return 1
    loader=$(loader_path "$bin")
    [ -n "$loader" ] && [ -e "$loader" ] || return 77
    loader=$(readlink -f "$loader")
    hook=$(symbol_value "$loader" _dl_debug_state) debug=$(symbol_value "$loader" _r_debug)
    [ -n "$hook" ] && [ -n "$debug" ] || return 77
    delta=$((debug - hook))
    if [ "$abi" = 32 ]; then
        args='*(uint32 *)(reg("sp") + 4), *(uint32 *)(reg("sp") + 8), *(uint32 *)(reg("sp") + 12), *(uint32 *)(reg("sp") + 16), *(uint32 *)(reg("sp") + 20), *(uint32 *)(reg("sp") + 24), *(uint32 *)(reg("sp") + 28)'
        offset=12 abi_flag='(uint32)'
    else
        args='reg("di"), reg("si"), reg("dx"), reg("cx"), reg("r8"), reg("r9"), *(uint64 *)(reg("sp") + 8)'
        offset=24 abi_flag=
    fi
    if [ "$mode" = xol ]; then
        ia32_launch_fixture "$fixture_pidfile" "$fixture_log" setarch i386 -R "$bin" "$so" || return 1
    else
        ia32_launch_fixture "$fixture_pidfile" "$fixture_log" "$bin" "$so" || return 1
    fi
    write_status || return 1
    i=0
    while ! grep -q "^FIXTURE_READY=$abi\$" "$fixture_log" && [ "$i" -lt 100 ]; do
        if recording_launcher_active "$fixture_launch_pid" "$fixture_launch_starttime"; then :; else break; fi
        i=$((i + 1)); sleep 0.05
    done
    grep -q "^FIXTURE_READY=$abi\$" "$fixture_log" || {
        fixture_status_record=STARTUP_FAILED
        write_status || return 1
        return 1
    }
    ia32_wait_for_stopped "$fixture_pid" "$fixture_starttime" 100 0.05 || {
        fixture_status_record=STARTUP_FAILED
        write_status || return 1
        return 1
    }
    if [ "$mode" = invalid-read ]; then
        cat >"$program" <<EOF
BEGIN { printf("PROBE_READY abi=$abi\\n"); }
uprobe:$bin:abi_probe /pid == $fixture_pid/ {
  printf("INVALID_READ_ATTEMPT=1 value=%llu\\n", *(uint32 *)uptr(1));
  exit();
}
EOF
        [ -s "$program" ] || return 1
    else
        cat >"$program" <<EOF
BEGIN { @next[$fixture_pid] = 0; @active[$fixture_pid] = 0; @loader[$fixture_pid] = 0; printf("PROBE_READY abi=$abi\\n"); }
uprobe:$bin:abi_probe /pid == $fixture_pid/ {
  @next[tid] = @next[tid] + 1; @active[tid] = @next[tid];
  printf("ENTRY abi=$abi n=%llu cs=%llu a0=%llu a1=%llu a2=%llu a3=%llu a4=%llu a5=%llu a6=%llu\\n", @active[tid], reg("cs"), $args);
}
uretprobe:$bin:abi_probe /pid == $fixture_pid && @active[tid] != 0/ {
  printf("RETURN abi=$abi n=%llu rv=%llu\\n", @active[tid], ${abi_flag}retval);
  if (@active[tid] == 2) { exit(); } delete(@active[tid]);
}
uprobe:$loader:_dl_debug_state /pid == $fixture_pid/ {
  @loader[tid] = @loader[tid] + 1;
  printf("LOADER abi=$abi n=%llu cs=%llu ip_nonzero=%llu state=%llu offset=$offset width=4\\n", @loader[tid], reg("cs"), reg("ip") != 0, *(uint32 *)(reg("ip") + $delta + $offset));
}
END { clear(@next); clear(@active); clear(@loader); }
EOF
        [ -s "$program" ] || return 1
    fi
    # Predicates scope every probe. On the qualified Jammy bpftrace 0.14,
    # adding -p loses loader hits; our own timeout and cleanup bound lifetime.
    bpftrace_path=$(command -v bpftrace) || return 1
    bpftrace_path=$(readlink -f "$bpftrace_path") || return 1
    ia32_launch_trace "$root_pidfile" "$trace_log" \
        timeout --kill-after=2 -s INT 20 "$TRACE_GUARD_BIN" \
        "$root_pidfile" "$guard_pidfile" "$bpftrace_path" "$program" || {
            write_status || return 1
            return 1
    }
    write_status || return 1
    guard_record=$(wait_root_process_record "$guard_pidfile" "$trace_pid" "$trace_starttime") || return 1
    trace_guard_pid=${guard_record% *}
    trace_guard_starttime=${guard_record#* }
    i=0
    while ! grep -q "^PROBE_READY abi=$abi\$" "$trace_log" && [ "$i" -lt 200 ]; do
        if recording_launcher_active "$trace_guard_pid" "$trace_guard_starttime" \
            && recording_launcher_active "$trace_pid" "$trace_starttime"; then :; else break; fi
        i=$((i + 1)); sleep 0.05
    done
    grep -q "^PROBE_READY abi=$abi\$" "$trace_log" || {
        trace_status_record=STARTUP_FAILED
        write_status || return 1
        return 1
    }
    [ -s "$guard_pidfile.exec" ] || return 1
    reclaim_root_output "$root_pidfile" "$guard_pidfile" "$guard_pidfile.exec" || return 1
    bystander_status_record=STARTED
    write_status || return 1
    bystander_status=0
    timeout --kill-after=1 5 "$bin" "$so" bystander >"$bystander_log" 2>&1 || bystander_status=$?
    bystander_status_record=$bystander_status
    write_status || return 1
    [ "$bystander_status" -eq 0 ] && grep -q "^FIXTURE_DONE=$abi\$" "$bystander_log" || return 1
    recording_launcher_active "$fixture_launch_pid" "$fixture_launch_starttime" \
        && recording_launcher_active "$trace_pid" "$trace_starttime" || return 1
    ia32_wait_for_stopped "$fixture_pid" "$fixture_starttime" 1 0 || return 1
    signal_verified_process CONT "$fixture_pid" "$fixture_starttime" || return 1
    fixture_completion_failed=0
    ia32_complete_fixture 100 0.05 || fixture_completion_failed=1
    fixture_status=$fixture_status_record
    write_status || return 1
    [ "$fixture_completion_failed" -eq 0 ] || return 1
    ia32_wait_owned_child "$trace_pid" "$trace_starttime" 500 0.05 || return 1
    trace_status=$IA32_WAIT_STATUS
    trace_pid= trace_starttime=
    trace_status_record=$trace_status
    if recording_launcher_active "$trace_guard_pid" "$trace_guard_starttime"; then return 1; else
        trace_ended=$?
        case $trace_ended:$RECORDED_LAUNCHER_STATE in
            1:gone|1:zombie) trace_guard_pid= trace_guard_starttime= ;;
            *) return 1 ;;
        esac
    fi
    if recording_launcher_active "$trace_root_pid" "$trace_root_starttime"; then return 1; else
        trace_ended=$?
        case $trace_ended:$RECORDED_LAUNCHER_STATE in
            1:gone|1:zombie) trace_root_pid= trace_root_starttime= ;;
            *) return 1 ;;
        esac
    fi
    write_status || return 1
    [ "$fixture_status" -eq 0 ] && [ "$trace_status" -eq 0 ] || return 1
    grep -q "^FIXTURE_DONE=$abi\$" "$fixture_log" || return 1
    if [ "$mode" = invalid-read ]; then
        check_invalid_read_log "$trace_log" || return 1
        echo "INVALID_READ_RESULT=PASS abi=$abi"
    elif ! check_log "$abi" "$trace_log"; then
        return 1
    elif [ "$mode" = xol ]; then echo "XOL_RESULT=PASS abi=$abi aslr=process_disabled"
    else echo "RESULT=PASS abi=$abi"; fi
}

build_abi 64 || { echo "RESULT=SKIP reason=abi_64_toolchain_unavailable"; exit 77; }
build_abi 32 || { echo "RESULT=SKIP reason=abi_32_toolchain_unavailable"; exit 77; }
build_trace_guard || { echo "RESULT=SKIP reason=trace_guard_toolchain_unavailable"; exit 77; }
run_abi 64 core || { status=$?; echo "RESULT=NONPASS abi=64 mode=core status=$status"; exit 1; }
run_abi 64 invalid-read || { status=$?; echo "INVALID_READ_RESULT=NONPASS abi=64 status=$status"; exit 1; }
run_abi 32 core || { status=$?; echo "RESULT=NONPASS abi=32 mode=core status=$status"; exit 1; }
if command -v setarch >/dev/null && command -v objdump >/dev/null \
    && setarch i386 -R true 2>/dev/null \
    && objdump -d "$WORK/harness-32" | awk '/<abi_probe>:/ { getline; if ($0 ~ /endbr32/) ok=1 } END { exit !ok }'; then
    run_abi 32 xol || { status=$?; echo "XOL_RESULT=NONPASS abi=32 status=$status"; exit 1; }
else echo "XOL_RESULT=SKIP reason=process_aslr_or_endbr32_unavailable"; fi
echo "QUALIFICATION=KERNEL_FEASIBILITY_ONLY aya_gate=UNRUN"

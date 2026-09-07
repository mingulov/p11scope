#!/bin/sh
# Kernel feasibility gate for x86-64 hosts observing native x86-64 and ia32
# uprobes. This does not exercise Aya or qualify p11scope's producer/verifier.
set -eu
cd "$(dirname "$0")/../.."
. scripts/lib.sh

current_status_log=
fixture_status_record=UNRUN
bystander_status_record=UNRUN
trace_status_record=UNRUN
write_status() {
    [ -n "$current_status_log" ] || return 0
    {
        echo "fixture_status=$fixture_status_record"
        echo "bystander_status=$bystander_status_record"
        echo "tracer_status=$trace_status_record"
    } >"$current_status_log"
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
    trap 'rm -rf "$work"' EXIT HUP INT TERM
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
    sh -c 'kill -STOP $$' & stopped=$!
    terminate_recording_launcher "$stopped"
    if recording_launcher_active "$stopped"; then return 1; fi
    status=0
    timeout --kill-after=1 -s INT 1 sh -c 'trap "" INT TERM; while :; do :; done' \
        >/dev/null 2>&1 || status=$?
    [ "$status" -eq 137 ]
    current_status_log=$work/injected.status
    fixture_status_record=UNRUN
    bystander_status_record=UNRUN
    trace_status_record=UNRUN
    write_status || return 1
    sh -c 'echo injected-launch-error >&2; exit 9' >"$work/injected.log" 2>&1 &
    injected=$!
    trace_status_record=STARTED
    write_status || return 1
    grep -q '^tracer_status=STARTED$' "$current_status_log"
    status=0
    wait "$injected" || status=$?
    trace_status_record=$status
    write_status || return 1
    grep -q '^tracer_status=9$' "$current_status_log"
    grep -q '^injected-launch-error$' "$work/injected.log"
    current_status_log=
    echo "SELF_TEST=PASS"
    echo "SELF_TEST_UPPER32_POISON=SYNTHETIC_ONLY"
}

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
fixture_pid=
fixture_starttime=
trace_pid=
trace_root_pid=
trace_root_starttime=
CLEANUP_STATUS=0
cleanup() {
    original_status=$?
    CLEANUP_STATUS=0
    if [ -n "$fixture_pid" ] && process_matches_starttime "$fixture_pid" "$fixture_starttime" \
        && recording_launcher_active "$fixture_pid"; then
        cleanup_step signal_verified_process CONT "$fixture_pid" "$fixture_starttime"
        if terminate_recording_launcher "$fixture_pid"; then
            if [ "$fixture_status_record" = STARTUP_FAILED ]; then
                fixture_status_record=STARTUP_FAILED_TERMINATED
            else
                fixture_status_record=TERMINATED
            fi
        else
            CLEANUP_STATUS=1
            fixture_status_record=UNKNOWN
        fi
    elif [ -n "$fixture_pid" ]; then
        terminate_recording_launcher "$fixture_pid" || CLEANUP_STATUS=1
        fixture_status_record=UNKNOWN
    fi
    if [ -n "$trace_root_pid" ] && root_process_matches_starttime "$trace_root_pid" "$trace_root_starttime"; then
        cleanup_step signal_verified_root_process TERM "$trace_root_pid" "$trace_root_starttime"
        cleanup_wait=0
        while root_process_matches_starttime "$trace_root_pid" "$trace_root_starttime" \
            && [ "$cleanup_wait" -lt 40 ]; do
            cleanup_wait=$((cleanup_wait + 1)); sleep 0.05
        done
        if root_process_matches_starttime "$trace_root_pid" "$trace_root_starttime"; then
            cleanup_step signal_verified_root_process KILL "$trace_root_pid" "$trace_root_starttime"
        fi
    fi
    if [ -n "$trace_pid" ]; then
        trace_was_active=0
        recording_launcher_active "$trace_pid" && trace_was_active=1
        if terminate_recording_launcher "$trace_pid" && [ "$trace_was_active" -eq 1 ]; then
            if [ "$trace_status_record" = STARTUP_FAILED ]; then
                trace_status_record=STARTUP_FAILED_TERMINATED
            else
                trace_status_record=TERMINATED
            fi
        elif [ "$trace_was_active" -eq 0 ]; then
            trace_status_record=UNKNOWN
        else
            CLEANUP_STATUS=1
            trace_status_record=UNKNOWN
        fi
    elif [ "$trace_status_record" = STARTED ]; then
        trace_status_record=UNKNOWN
    fi
    write_status || CLEANUP_STATUS=1
    printf 'cleanup_status=%s\n' "$CLEANUP_STATUS" >"$EVIDENCE/cleanup.status"
    [ "$CLEANUP_STATUS" -eq 0 ] || exit "$CLEANUP_STATUS"
    return "$original_status"
}
. scripts/cleanup-traps.sh

{
    echo "kernel_release=$(uname -r)"
    echo "kernel_version=$(uname -v)"
    echo "gcc_version=$(gcc -dumpfullversion -dumpversion)"
    echo "bpftrace_version=$(bpftrace --version | sed 's/^bpftrace v//')"
} >"$EVIDENCE/environment.status"
sha256sum "$SRC" scripts/matrix/verify-ia32-compat.sh >"$EVIDENCE/source.sha256"

build_abi() {
    abi=$1
    cfi=
    [ "$abi" = 32 ] && cfi=-fcf-protection=branch
    gcc "-m$abi" -O1 -g -Wall -Wextra -Werror -fno-omit-frame-pointer \
        $cfi -rdynamic -o "$WORK/harness-$abi" "$SRC" -ldl || return
    gcc "-m$abi" -O1 -g -Wall -Wextra -Werror -fPIC -shared \
        -DIA32_COMPAT_DSO -o "$WORK/second-$abi.so" "$SRC" || return
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
    current_status_log=$status_log
    fixture_status_record=UNRUN
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
    if [ "$mode" = xol ]; then setarch i386 -R "$bin" "$so" >"$fixture_log" 2>&1 &
    else "$bin" "$so" >"$fixture_log" 2>&1 & fi
    fixture_pid=$!
    fixture_status_record=STARTED
    write_status || return 1
    fixture_starttime=$(process_starttime "$fixture_pid") || {
        fixture_status_record=STARTUP_FAILED
        write_status || return 1
        return 1
    }
    i=0
    while ! grep -q "^FIXTURE_READY=$abi\$" "$fixture_log" && [ "$i" -lt 100 ]; do
        recording_launcher_active "$fixture_pid" || break
        i=$((i + 1)); sleep 0.05
    done
    grep -q "^FIXTURE_READY=$abi\$" "$fixture_log" || {
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
    launch_root_recorded_process "$root_pidfile" "$trace_log" \
        timeout --kill-after=2 --foreground -s INT 20 bpftrace -kk -q -B line \
        "$program" || {
            trace_pid=${ROOT_LAUNCH_PID:-}
            trace_root_pid=${ROOT_PROCESS_PID:-}
            trace_root_starttime=${ROOT_PROCESS_STARTTIME:-}
            trace_status_record=STARTUP_FAILED
            write_status || return 1
            return 1
        }
    trace_pid=$ROOT_LAUNCH_PID
    trace_root_pid=$ROOT_PROCESS_PID
    trace_root_starttime=$ROOT_PROCESS_STARTTIME
    trace_status_record=STARTED
    write_status || return 1
    reclaim_root_output "$root_pidfile" || return 1
    i=0
    while ! grep -q "^PROBE_READY abi=$abi\$" "$trace_log" && [ "$i" -lt 200 ]; do
        recording_launcher_active "$trace_pid" || break
        i=$((i + 1)); sleep 0.05
    done
    grep -q "^PROBE_READY abi=$abi\$" "$trace_log" || {
        trace_status_record=STARTUP_FAILED
        write_status || return 1
        return 1
    }
    bystander_status_record=STARTED
    write_status || return 1
    bystander_status=0
    timeout --kill-after=1 5 "$bin" "$so" bystander >"$bystander_log" 2>&1 || bystander_status=$?
    bystander_status_record=$bystander_status
    write_status || return 1
    [ "$bystander_status" -eq 0 ] && grep -q "^FIXTURE_DONE=$abi\$" "$bystander_log" || return 1
    recording_launcher_active "$fixture_pid" && recording_launcher_active "$trace_pid" || return 1
    signal_verified_process CONT "$fixture_pid" "$fixture_starttime" || return 1
    i=0
    while recording_launcher_active "$fixture_pid" && [ "$i" -lt 100 ]; do
        i=$((i + 1)); sleep 0.05
    done
    fixture_status=0
    if recording_launcher_active "$fixture_pid"; then
        fixture_status=124
        terminate_recording_launcher "$fixture_pid" || fixture_status=125
    else
        wait "$fixture_pid" || fixture_status=$?
    fi
    fixture_pid=
    fixture_status_record=$fixture_status
    write_status || return 1
    trace_status=0; wait "$trace_pid" || trace_status=$?; trace_pid=
    trace_status_record=$trace_status
    trace_root_pid=
    trace_root_starttime=
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
run_abi 64 core || { status=$?; echo "RESULT=NONPASS abi=64 mode=core status=$status"; exit 1; }
run_abi 64 invalid-read || { status=$?; echo "INVALID_READ_RESULT=NONPASS abi=64 status=$status"; exit 1; }
run_abi 32 core || { status=$?; echo "RESULT=NONPASS abi=32 mode=core status=$status"; exit 1; }
if command -v setarch >/dev/null && command -v objdump >/dev/null \
    && setarch i386 -R true 2>/dev/null \
    && objdump -d "$WORK/harness-32" | awk '/<abi_probe>:/ { getline; if ($0 ~ /endbr32/) ok=1 } END { exit !ok }'; then
    run_abi 32 xol || { status=$?; echo "XOL_RESULT=NONPASS abi=32 status=$status"; exit 1; }
else echo "XOL_RESULT=SKIP reason=process_aslr_or_endbr32_unavailable"; fi
echo "QUALIFICATION=KERNEL_FEASIBILITY_ONLY aya_gate=UNRUN"

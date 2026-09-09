#!/bin/sh
# Shared helpers for the gate scripts: non-root caller check, cleanup traps,
# container tar cap, root process pinning/signalling, capture-ready wait.

# Observers run under sudo, so their published reports are root-owned 0600.
# Hand them back to the caller before reading them.
reclaim_root_output() {
    sudo -n chown "$(id -u):$(id -g)" "$@"
}

require_non_root_caller() {
    [ "$(id -u)" -ne 0 ] || {
        echo "run this gate as a non-root user with passwordless sudo" >&2
        return 1
    }
}

# Linux reports permission refusal as EACCES or EPERM depending on which
# privileged operation failed. Both are denial; neither authorizes proceeding.
is_linux_permission_denial() {
    grep -Eq 'Permission denied|Operation not permitted'
}

cleanup_step() {
    "$@"
    cleanup_step_status=$?
    if [ "$CLEANUP_STATUS" -eq 0 ] && [ "$cleanup_step_status" -ne 0 ]; then
        CLEANUP_STATUS=$cleanup_step_status
    fi
    return 0
}

# A controlled provider directory is a few megabytes. Cap the stream so a
# compromised or hostile image cannot fill the host filesystem through the
# copy step, and refuse a stream that reaches the cap rather than attaching
# from a silently truncated archive.
MAX_CONTAINER_TAR_BYTES=${MAX_CONTAINER_TAR_BYTES:-268435456}

capped_container_tar() {
    cct_out=$1
    shift
    "$@" | head -c "$MAX_CONTAINER_TAR_BYTES" > "$cct_out" || return 1
    cct_size=$(stat -Lc %s "$cct_out") || return 1
    [ "$cct_size" -gt 0 ] || {
        echo "container provider stream produced no bytes" >&2
        return 1
    }
    [ "$cct_size" -lt "$MAX_CONTAINER_TAR_BYTES" ] || {
        echo "container provider stream reached the $MAX_CONTAINER_TAR_BYTES byte cap" >&2
        return 1
    }
}

# Gate scripts source this library from the repository root. Capture that
# location before a caller changes cwd; the helper never consumes command stdin.
RECORDED_PROCESS_EXEC=$(pwd -P)/scripts/recorded-process-exec.py

recorded_process_control() {
    python3 -I "$RECORDED_PROCESS_EXEC" "$@"
}

# Read the coordinator's own Linux identity without forking, changing caller
# positional parameters, or retaining a modified IFS.
recorded_process_coordinator_identity() {
    RECORDED_COORDINATOR_PID=
    RECORDED_COORDINATOR_STARTTIME=
    if ! IFS= read -r _rp_coordinator_stat </proc/self/stat; then
        unset _rp_coordinator_stat
        return 1
    fi
    _rp_coordinator_pid=${_rp_coordinator_stat%% *}
    _rp_coordinator_tail=${_rp_coordinator_stat##*) }
    if [ "$_rp_coordinator_tail" = "$_rp_coordinator_stat" ]; then
        unset _rp_coordinator_stat _rp_coordinator_pid _rp_coordinator_tail
        return 1
    fi
    if ! IFS=' ' read -r _rp_coordinator_state _rp_coordinator_ppid _rp_coordinator_pgrp \
        _rp_coordinator_session _rp_coordinator_tty _rp_coordinator_tpgid _rp_coordinator_flags \
        _rp_coordinator_minflt _rp_coordinator_cminflt _rp_coordinator_majflt \
        _rp_coordinator_cmajflt _rp_coordinator_utime _rp_coordinator_stime \
        _rp_coordinator_cutime _rp_coordinator_cstime _rp_coordinator_priority \
        _rp_coordinator_nice _rp_coordinator_threads _rp_coordinator_itrealvalue \
        _rp_coordinator_starttime _rp_coordinator_rest <<EOF
$_rp_coordinator_tail
EOF
    then
        unset _rp_coordinator_stat _rp_coordinator_pid _rp_coordinator_tail \
            _rp_coordinator_state _rp_coordinator_ppid _rp_coordinator_pgrp \
            _rp_coordinator_session _rp_coordinator_tty _rp_coordinator_tpgid \
            _rp_coordinator_flags _rp_coordinator_minflt _rp_coordinator_cminflt \
            _rp_coordinator_majflt _rp_coordinator_cmajflt _rp_coordinator_utime \
            _rp_coordinator_stime _rp_coordinator_cutime _rp_coordinator_cstime \
            _rp_coordinator_priority _rp_coordinator_nice _rp_coordinator_threads \
            _rp_coordinator_itrealvalue _rp_coordinator_starttime _rp_coordinator_rest
        return 1
    fi
    case $_rp_coordinator_pid:$_rp_coordinator_starttime in
        ''|*[!0-9:]*|0:*|*:0)
            unset _rp_coordinator_stat _rp_coordinator_pid _rp_coordinator_tail \
                _rp_coordinator_state _rp_coordinator_ppid _rp_coordinator_pgrp \
                _rp_coordinator_session _rp_coordinator_tty _rp_coordinator_tpgid \
                _rp_coordinator_flags _rp_coordinator_minflt _rp_coordinator_cminflt \
                _rp_coordinator_majflt _rp_coordinator_cmajflt _rp_coordinator_utime \
                _rp_coordinator_stime _rp_coordinator_cutime _rp_coordinator_cstime \
                _rp_coordinator_priority _rp_coordinator_nice _rp_coordinator_threads \
                _rp_coordinator_itrealvalue _rp_coordinator_starttime _rp_coordinator_rest
            return 1
            ;;
    esac
    RECORDED_COORDINATOR_PID=$_rp_coordinator_pid
    RECORDED_COORDINATOR_STARTTIME=$_rp_coordinator_starttime
    unset _rp_coordinator_stat _rp_coordinator_pid _rp_coordinator_tail \
        _rp_coordinator_state _rp_coordinator_ppid _rp_coordinator_pgrp \
        _rp_coordinator_session _rp_coordinator_tty _rp_coordinator_tpgid \
        _rp_coordinator_flags _rp_coordinator_minflt _rp_coordinator_cminflt \
        _rp_coordinator_majflt _rp_coordinator_cmajflt _rp_coordinator_utime \
        _rp_coordinator_stime _rp_coordinator_cutime _rp_coordinator_cstime \
        _rp_coordinator_priority _rp_coordinator_nice _rp_coordinator_threads \
        _rp_coordinator_itrealvalue _rp_coordinator_starttime _rp_coordinator_rest
}

# 0: exact generation live; 1: gone/replaced/zombie; 2: observation unknown.
recording_launcher_active() {
    RECORDED_LAUNCHER_STATE=unknown
    [ "$#" -eq 2 ] || return 2
    if rla_state=$(recorded_process_control active "$1" "$2"); then rla_status=0; else rla_status=$?; fi
    case $rla_status:$rla_state in
        0:live|1:gone|1:zombie|1:replaced) RECORDED_LAUNCHER_STATE=$rla_state; return "$rla_status" ;;
        *) return 2 ;;
    esac
}

# Successful termination proves the original generation ended. Reaping remains
# the owning caller's job; a numeric wait here could wait on a reused child PID.
terminate_recording_launcher() {
    [ "$#" -ge 2 ] && [ "$#" -le 3 ] || return 2
    trl_pid=$1
    trl_starttime=$2
    trl_privilege=${3:-user}
    case $trl_privilege in user|root) ;; *) return 2 ;; esac
    if recording_launcher_active "$trl_pid" "$trl_starttime"; then
        trl_state=0
    else
        trl_state=$?
    fi
    case $trl_state in 1) return 0 ;; 0) ;; *) return 2 ;; esac
    for trl_signal in TERM KILL; do
        if ! signal_pinned_process "$trl_privilege" "$trl_signal" "$trl_pid" "$trl_starttime"; then
            if recording_launcher_active "$trl_pid" "$trl_starttime"; then return 1; else trl_state=$?; fi
            [ "$trl_state" -eq 1 ] && return 0
            return 2
        fi
        if recorded_process_control wait-gone "$trl_pid" "$trl_starttime" >/dev/null; then
            trl_state=0
        else
            trl_state=$?
        fi
        case $trl_state in 1) return 0 ;; 0) ;; *) return 2 ;; esac
    done
    return 1
}

# Publish every field in the calling shell before issuing the matching ACK.
# ROOT/USER_RECORD_IDENTITY contains the full pinned context (including the
# absolute monotonic deadline); CONTROL is its path and PHASE is trap-visible.
publish_recorded_process_fields() {
    if [ "$_rp_mode" = root ]; then
        ROOT_RECORD_CONTROL=$_rp_path ROOT_RECORD_IDENTITY=$_rp_context ROOT_RECORD_PHASE=$_rp_phase
        ROOT_LAUNCH_PID=$_rp_launcher ROOT_LAUNCH_STARTTIME=$_rp_launch_start
        ROOT_PROCESS_PID=$_rp_process ROOT_PROCESS_STARTTIME=$_rp_process_start
        export ROOT_RECORD_CONTROL ROOT_RECORD_IDENTITY ROOT_RECORD_PHASE ROOT_LAUNCH_PID \
            ROOT_LAUNCH_STARTTIME ROOT_PROCESS_PID ROOT_PROCESS_STARTTIME
    else
        USER_RECORD_CONTROL=$_rp_path USER_RECORD_IDENTITY=$_rp_context USER_RECORD_PHASE=$_rp_phase
        USER_PROCESS_LAUNCH_PID=$_rp_launcher USER_PROCESS_LAUNCH_STARTTIME=$_rp_launch_start
        USER_PROCESS_PID=$_rp_process USER_PROCESS_STARTTIME=$_rp_process_start
        export USER_RECORD_CONTROL USER_RECORD_IDENTITY USER_RECORD_PHASE USER_PROCESS_LAUNCH_PID \
            USER_PROCESS_LAUNCH_STARTTIME USER_PROCESS_PID USER_PROCESS_STARTTIME
    fi
}

recorded_process_launch_failed() {
    recorded_process_control cancel "$_rp_context" || return 1
    # No tuple is erased on failure. A caller trap owns bounded finalization.
    return 1
}

launch_recorded_process() {
    _rp_mode=$1 _rp_pidfile=$2 _rp_log=$3 _rp_stderr=$4
    shift 4
    [ "$#" -gt 0 ] || return 1
    if [ "$_rp_mode" = root ]; then
        [ -z "${ROOT_RECORD_CONTROL:-}" ] || return 1
    else
        [ -z "${USER_RECORD_CONTROL:-}" ] || return 1
    fi
    _rp_prepared=$(recorded_process_control prepare "$_rp_pidfile" 8) || return 1
    { IFS= read -r _rp_path; IFS= read -r _rp_context; } <<EOF
$_rp_prepared
EOF
    _rp_launcher= _rp_launch_start= _rp_process= _rp_process_start= _rp_phase=prepared
    publish_recorded_process_fields
    if ! recorded_process_coordinator_identity \
        || ! recorded_process_control bind-coordinator "$_rp_context" \
            "$RECORDED_COORDINATOR_PID" "$RECORDED_COORDINATOR_STARTTIME"; then
        recorded_process_control cleanup "$_rp_context" || return 1
        _rp_path= _rp_context= _rp_phase=finalized
        publish_recorded_process_fields
        return 1
    fi
    # Async POSIX shells otherwise replace inherited stdin with /dev/null.
    # Explicit duplication preserves it, without using it as a control channel.
    if [ "$_rp_mode" = root ]; then
        set -- python3 -I "$RECORDED_PROCESS_EXEC" exec "$_rp_context" launcher - \
            sudo -n python3 -I "$RECORDED_PROCESS_EXEC" exec "$_rp_context" root "$_rp_pidfile" "$@"
    else
        set -- python3 -I "$RECORDED_PROCESS_EXEC" exec "$_rp_context" user "$_rp_pidfile" "$@"
    fi
    if [ -n "$_rp_stderr" ]; then
        "$@" <&9 9<&- > "$_rp_log" 2> "$_rp_stderr" &
    else
        "$@" <&9 9<&- > "$_rp_log" 2>&1 &
    fi
    _rp_launcher=$!
    _rp_phase=spawned
    publish_recorded_process_fields
    if [ "$_rp_mode" = root ]; then _rp_self_phase=launcher; else _rp_self_phase=user; fi
    _rp_record=$(recorded_process_control read "$_rp_context" "$_rp_self_phase" self "$_rp_launcher" 0) \
        || { recorded_process_launch_failed; return 1; }
    # Strict native parsing has already required exactly these two integers.
    _rp_launch_start=${_rp_record#* }
    if [ "$_rp_mode" = user ]; then _rp_process=$_rp_launcher; _rp_process_start=$_rp_launch_start; fi
    # ACK publication itself can be interrupted. This phase conservatively
    # means execution may be authorized, even before the ACK helper returns.
    _rp_phase=$_rp_self_phase-acknowledging
    publish_recorded_process_fields
    recorded_process_control ack "$_rp_context" "$_rp_self_phase" "$_rp_launcher" "$_rp_launch_start" \
        || { recorded_process_launch_failed; return 1; }
    _rp_phase=$_rp_self_phase-acknowledged
    publish_recorded_process_fields
    if [ "$_rp_mode" = root ]; then
        _rp_record=$(recorded_process_control read "$_rp_context" root self 0 0) \
            || { recorded_process_launch_failed; return 1; }
        _rp_process=${_rp_record% *} _rp_process_start=${_rp_record#* } _rp_phase=root-acknowledging
        publish_recorded_process_fields
        recorded_process_control ack "$_rp_context" root "$_rp_process" "$_rp_process_start" \
            || { recorded_process_launch_failed; return 1; }
        _rp_phase=root-acknowledged
        publish_recorded_process_fields
    fi
    recorded_process_control read "$_rp_context" "$_rp_mode" committed "$_rp_process" "$_rp_process_start" >/dev/null \
        || { recorded_process_launch_failed; return 1; }
    recorded_process_control cleanup "$_rp_context" || return 1
    # A successful launch transfers its tuples to the caller. Only pending
    # attempts block the next launch; finalizers must not kill transferred roles.
    _rp_phase=committed _rp_path= _rp_context=
    publish_recorded_process_fields
}

launch_root_recorded_process() {
    [ "$#" -ge 3 ] || return 1
    _lrrp_pidfile=$1 _lrrp_log=$2
    shift 2
    launch_recorded_process root "$_lrrp_pidfile" "$_lrrp_log" "" "$@" 9<&0
}

launch_root_recorded_process_split() {
    [ "$#" -ge 4 ] && [ -n "$3" ] || return 1
    _lrrps_pidfile=$1 _lrrps_stdout=$2 _lrrps_stderr=$3
    shift 3
    launch_recorded_process root "$_lrrps_pidfile" "$_lrrps_stdout" "$_lrrps_stderr" "$@" 9<&0
}

launch_user_recorded_process() {
    [ "$#" -ge 3 ] || return 1
    _lurp_pidfile=$1 _lurp_log=$2
    shift 2
    launch_recorded_process user "$_lurp_pidfile" "$_lurp_log" "" "$@" 9<&0
}

finalize_recorded_process() {
    frp_mode=$1
    if [ "$frp_mode" = root ]; then
        frp_context=${ROOT_RECORD_IDENTITY:-} frp_launcher=${ROOT_LAUNCH_PID:-}
        frp_start=${ROOT_LAUNCH_STARTTIME:-} frp_pid=${ROOT_PROCESS_PID:-} frp_pstart=${ROOT_PROCESS_STARTTIME:-}
    else
        frp_context=${USER_RECORD_IDENTITY:-} frp_launcher=${USER_PROCESS_LAUNCH_PID:-}
        frp_start=${USER_PROCESS_LAUNCH_STARTTIME:-} frp_pid=${USER_PROCESS_PID:-} frp_pstart=${USER_PROCESS_STARTTIME:-}
    fi
    [ -n "$frp_context" ] || return 0
    recorded_process_control cancel "$frp_context" || return 1
    # The shell may have been interrupted between backgrounding and storing
    # $!. Even an empty tentative PID is not evidence that no wrapper exists.
    [ -n "$frp_launcher" ] && [ -n "$frp_start" ] || return 1
    if [ -n "$frp_pid" ]; then terminate_recording_launcher "$frp_pid" "$frp_pstart" "$frp_mode" || return 1; fi
    if [ -n "$frp_launcher" ]; then
        # Tentative $! alone never authorizes a signal, wait, or clearing custody.
        [ -n "$frp_start" ] || return 1
        terminate_recording_launcher "$frp_launcher" "$frp_start" "$frp_mode" || return 1
    fi
    recorded_process_control cleanup "$frp_context" || return 1
    if [ "$frp_mode" = root ]; then
        ROOT_RECORD_CONTROL= ROOT_RECORD_IDENTITY= ROOT_RECORD_PHASE=finalized
        ROOT_LAUNCH_PID= ROOT_LAUNCH_STARTTIME= ROOT_PROCESS_PID= ROOT_PROCESS_STARTTIME=
    else
        USER_RECORD_CONTROL= USER_RECORD_IDENTITY= USER_RECORD_PHASE=finalized
        USER_PROCESS_LAUNCH_PID= USER_PROCESS_LAUNCH_STARTTIME= USER_PROCESS_PID= USER_PROCESS_STARTTIME=
    fi
}

finalize_root_recorded_process() { finalize_recorded_process root; }
finalize_user_recorded_process() { finalize_recorded_process user; }

# Generic durable reader: it never acknowledges an unrelated workload record.
wait_root_process_record() {
    [ "$#" -eq 3 ] || return 2
    wrpr_pidfile=$1 wrpr_launcher=$2 wrpr_starttime=$3 wrpr_attempt=0
    while [ "$wrpr_attempt" -lt 160 ]; do
        if wrpr_record=$(sudo -n python3 -I "$RECORDED_PROCESS_EXEC" durable-read "$wrpr_pidfile"); then
            printf '%s\n' "$wrpr_record"
            return 0
        else wrpr_status=$?; fi
        [ "$wrpr_status" -eq 3 ] || return 2
        if recording_launcher_active "$wrpr_launcher" "$wrpr_starttime"; then :; else
            wrpr_status=$?
            return "$wrpr_status"
        fi
        wrpr_attempt=$((wrpr_attempt + 1))
        sleep 0.05
    done
    echo "root process identity was not recorded" >&2
    return 1
}

process_starttime() {
    pst_pid=$1
    case $pst_pid in ''|*[!0-9]*) return 1 ;; esac
    pst_value=$(awk '{ sub(/^[0-9]+ \(.*\) /, ""); split($0, tail, " "); print tail[20]; exit }' \
        "/proc/$pst_pid/stat" 2>/dev/null) || return 1
    case $pst_value in ''|*[!0-9]*) return 1 ;; esac
    printf '%s\n' "$pst_value"
}

root_process_starttime() {
    rpst_pid=$1
    case $rpst_pid in ''|*[!0-9]*) return 1 ;; esac
    rpst_value=$(sudo -n awk '{ sub(/^[0-9]+ \(.*\) /, ""); split($0, tail, " "); print tail[20]; exit }' \
        "/proc/$rpst_pid/stat" 2>/dev/null) || return 1
    case $rpst_value in ''|*[!0-9]*) return 1 ;; esac
    printf '%s\n' "$rpst_value"
}

process_matches_starttime() {
    pms_pid=$1
    pms_expected=$2
    pms_current=$(process_starttime "$pms_pid") || return 1
    [ "$pms_current" = "$pms_expected" ]
}

process_session_id() {
    psid_pid=$1
    case $psid_pid in ''|*[!0-9]*) return 1 ;; esac
    psid_value=$(awk '{ sub(/^[0-9]+ \(.*\) /, ""); split($0, tail, " "); print tail[4]; exit }' \
        "/proc/$psid_pid/stat" 2>/dev/null) || return 1
    case $psid_value in ''|*[!0-9]*) return 1 ;; esac
    printf '%s\n' "$psid_value"
}

process_matches_session() {
    pms_pid=$1
    pms_starttime=$2
    pms_sid=$3
    process_matches_starttime "$pms_pid" "$pms_starttime" \
        && [ "$(process_session_id "$pms_pid")" = "$pms_sid" ]
}

root_process_matches_starttime() {
    rpms_pid=$1
    rpms_expected=$2
    rpms_current=$(root_process_starttime "$rpms_pid") || return 1
    [ "$rpms_current" = "$rpms_expected" ]
}

signal_pinned_process() {
    spp_privilege=$1
    shift
    case $spp_privilege in
        user) spp_python='python3 -I' ;;
        root) spp_python='sudo -n python3 -I' ;;
        *) return 1 ;;
    esac
    $spp_python - "$@" <<'PY'
import os
import signal
import sys

signals = {
    "CONT": signal.SIGCONT,
    "INT": signal.SIGINT,
    "KILL": signal.SIGKILL,
    "STOP": signal.SIGSTOP,
    "TERM": signal.SIGTERM,
}
if len(sys.argv) not in (4, 5) or sys.argv[1] not in signals:
    raise SystemExit("usage: SIGNAL PID STARTTIME [SID]")

pid, expected = int(sys.argv[2]), int(sys.argv[3])
expected_sid = int(sys.argv[4]) if len(sys.argv) == 5 else None
fd = os.pidfd_open(pid)
raw = open(f"/proc/{pid}/stat", "rb").read()
tail = raw.rsplit(b") ", 1)[1].split()
if len(tail) < 20 or int(tail[19]) != expected:
    raise SystemExit(f"refusing changed process identity {pid}")
if expected_sid is not None and int(tail[3]) != expected_sid:
    raise SystemExit(f"refusing changed process session {pid}")
signal.pidfd_send_signal(fd, signals[sys.argv[1]], None, 0)
PY
}

signal_verified_process() {
    signal_pinned_process user "$@"
}

signal_verified_root_process() {
    signal_pinned_process root "$@"
}

# Start a user-owned command as its own session/process group and retain the
# identity that makes a later pidfd signal safe across PID reuse.
launch_user_recorded_process_group() {
    lurpg_pidfile=$1
    lurpg_log=$2
    shift 2
    [ "$#" -gt 0 ] || return 1
    [ ! -e "$lurpg_pidfile" ] || {
        echo "user process-group identity file already exists" >&2
        return 1
    }
    umask 077
    USER_PROCESS_SID=
    export USER_PROCESS_SID
    python3 -I - "$lurpg_pidfile" "$@" > "$lurpg_log" 2>&1 <<'PY' &
import json
import os
import sys


def stat(pid):
    raw = open(f"/proc/{pid}/stat", "rb").read()
    _, separator, tail = raw.rpartition(b") ")
    if not separator:
        raise ValueError("malformed proc stat")
    fields = tail.split()
    if len(fields) < 20:
        raise ValueError("short proc stat")
    return int(fields[19]), int(fields[2]), int(fields[3])


pidfile, command = sys.argv[1], sys.argv[2:]
if not command:
    raise SystemExit("missing command")
os.umask(0o077)
os.setsid()
pid = os.getpid()
starttime, pgid, sid = stat(pid)
if pid != pgid or pid != sid:
    raise SystemExit("new session leader does not lead its session and process group")
record = json.dumps(
    {"pid": pid, "starttime": starttime, "pgid": pgid, "sid": sid, "argv": command},
    separators=(",", ":"),
).encode() + b"\n"
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(pidfile, flags, 0o600)
try:
    os.write(fd, record)
    os.fsync(fd)
finally:
    os.close(fd)
directory = os.open(os.path.dirname(os.path.abspath(pidfile)) or ".", os.O_RDONLY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
os.execvp(command[0], command)
PY
    USER_PROCESS_LAUNCH_PID=$!
    # This direct child identity is trap-visible before the durable group
    # record appears. It is never refreshed after launch failure.
    USER_PROCESS_PID=$USER_PROCESS_LAUNCH_PID
    USER_PROCESS_STARTTIME=$(process_starttime "$USER_PROCESS_LAUNCH_PID" 2>/dev/null || true)
    USER_PROCESS_INITIAL_STARTTIME=$USER_PROCESS_STARTTIME
    USER_PROCESS_PGID=
    USER_PROCESS_PIDFILE=$lurpg_pidfile
    lurpg_attempt=0
    while [ ! -s "$lurpg_pidfile" ] && [ "$lurpg_attempt" -lt 160 ]; do
        kill -0 "$USER_PROCESS_LAUNCH_PID" 2>/dev/null || {
            echo "user process group exited before recording its identity" >&2
            USER_PROCESS_LAUNCH_PID=
            return 1
        }
        lurpg_attempt=$((lurpg_attempt + 1))
        sleep 0.05
    done
    [ -s "$lurpg_pidfile" ] || {
        echo "user process group identity was not recorded" >&2
        return 1
    }
    lurpg_record=$(python3 -I - "$lurpg_pidfile" "$USER_PROCESS_LAUNCH_PID" \
        "$USER_PROCESS_INITIAL_STARTTIME" "$@" <<'PY'
import json
import sys


record = json.load(open(sys.argv[1], encoding="utf-8"))
launcher = int(sys.argv[2])
initial_starttime = int(sys.argv[3])
expected_argv = sys.argv[4:]
if set(record) != {"pid", "starttime", "pgid", "sid", "argv"}:
    raise SystemExit("malformed user process-group identity")
if not all(isinstance(record[name], int) and record[name] > 0 for name in ("pid", "starttime", "pgid", "sid")):
    raise SystemExit("malformed user process-group identity")
if not isinstance(record["argv"], list) or not all(isinstance(item, str) for item in record["argv"]):
    raise SystemExit("malformed user process-group argv")
if record["pid"] != launcher or record["starttime"] != initial_starttime:
    raise SystemExit("user process-group identity does not match launch")
if record["pid"] != record["pgid"] or record["pid"] != record["sid"] or record["argv"] != expected_argv:
    raise SystemExit("user process-group identity does not match launch")
print(record["pid"], record["starttime"], record["pgid"], record["sid"])
PY
) || {
        lurpg_status=$?
        return "$lurpg_status"
    }
    set -- $lurpg_record
    [ "$#" -eq 4 ] || return 1
    USER_PROCESS_PID=$1
    USER_PROCESS_STARTTIME=$2
    USER_PROCESS_PGID=$3
    USER_PROCESS_SID=$4
    export USER_PROCESS_SID

    python3 -I - "$USER_PROCESS_PID" "$USER_PROCESS_STARTTIME" "$USER_PROCESS_PGID" "$USER_PROCESS_SID" <<'PY'
import sys


def stat(pid):
    raw = open(f"/proc/{pid}/stat", "rb").read()
    _, separator, tail = raw.rpartition(b") ")
    if not separator:
        raise ValueError("malformed proc stat")
    fields = tail.split()
    if len(fields) < 20:
        raise ValueError("short proc stat")
    return int(fields[19]), int(fields[2]), int(fields[3])


pid, starttime, pgid, sid = map(int, sys.argv[1:5])
actual_starttime, actual_pgid, actual_sid = stat(pid)
if actual_starttime != starttime or actual_pgid != pgid or actual_sid != sid or pid != pgid or pid != sid:
    raise SystemExit("user process-session identity changed before use")
PY
    lurpg_status=$?
    [ "$lurpg_status" -eq 0 ] || {
        return "$lurpg_status"
    }
}

# Emit a closed, sorted JSON projection of one current user-owned process
# session. A process that races or cannot be identified invalidates the snapshot.
snapshot_user_process_session() {
    sups_sid=$1
    case $sups_sid in ''|*[!0-9]*) return 1 ;; esac
    python3 -I - "$sups_sid" <<'PY'
import glob
import hashlib
import json
import os
import sys


def stat(pid):
    raw = open(f"/proc/{pid}/stat", "rb").read()
    _, separator, tail = raw.rpartition(b") ")
    if not separator:
        raise ValueError("malformed proc stat")
    fields = tail.split()
    if len(fields) < 20:
        raise ValueError("short proc stat")
    return int(fields[19]), int(fields[1]), int(fields[2]), int(fields[3])


sids = int(sys.argv[1])
if sids <= 0:
    raise SystemExit("invalid process session")
members = []
for path in glob.glob("/proc/[0-9]*"):
    pid = int(path.rsplit("/", 1)[1])
    try:
        starttime, ppid, actual_pgid, actual_sid = stat(pid)
    except (FileNotFoundError, ProcessLookupError):
        # No membership can be established for a process that vanished before
        # its first stat read. Once the target group is identified below, any
        # later disappearance is a hard error.
        continue
    except (OSError, ValueError) as error:
        raise SystemExit(f"cannot inspect process {pid}: {error}")
    if actual_sid != sids:
        continue
    try:
        def projection():
            digest = hashlib.sha256()
            with open(f"/proc/{pid}/exe", "rb") as source:
                for block in iter(lambda: source.read(131072), b""):
                    digest.update(block)
            raw_argv = open(f"/proc/{pid}/cmdline", "rb").read()
            if not raw_argv or not raw_argv.endswith(b"\0"):
                raise ValueError("malformed argv")
            argv = [item.decode("utf-8", "strict") for item in raw_argv[:-1].split(b"\0")]
            if not argv or not argv[0]:
                raise ValueError("empty argv")
            return digest.hexdigest(), argv

        digest, argv = projection()
        middle = stat(pid)
        final_digest, final_argv = projection()
        final = stat(pid)
    except (FileNotFoundError, OSError, UnicodeError, ValueError) as error:
        raise SystemExit(f"cannot close process-group member {pid}: {error}")
    if middle != (starttime, ppid, actual_pgid, actual_sid) or final != middle:
        raise SystemExit(f"process-session member {pid} changed during snapshot")
    if (final_digest, final_argv) != (digest, argv):
        raise SystemExit(f"process-group member {pid} execed during snapshot")
    members.append(
        {
            "pid": pid,
            "starttime": starttime,
            "ppid": ppid,
            "pgid": actual_pgid,
            "sid": actual_sid,
            "exe_sha256": digest,
            "argv": argv,
        }
    )
print(json.dumps(sorted(members, key=lambda member: member["pid"]), separators=(",", ":")))
PY
}

snapshot_user_process_group() {
    snapshot_user_process_session "$@"
}

# This slice scans once, at attach time: a provider mapped later is not
# discovered. Every manifest-free lane therefore starts its workload first and
# waits here until the provider is really mapped, before the observer attaches.
# Reads /proc/<pid>/maps through sudo so the same helper works for a container
# process owned by another uid.
wait_for_mapped_provider() {
    wfmp_pid=$1
    wfmp_name=$2
    wfmp_attempt=0
    while [ "$wfmp_attempt" -lt 200 ]; do
        sudo -n grep -Fq "$wfmp_name" "/proc/$wfmp_pid/maps" 2>/dev/null && return 0
        kill -0 "$wfmp_pid" 2>/dev/null || sudo -n test -d "/proc/$wfmp_pid" || {
            echo "target $wfmp_pid exited before mapping $wfmp_name" >&2
            return 1
        }
        wfmp_attempt=$((wfmp_attempt + 1))
        sleep 0.05
    done
    echo "target $wfmp_pid never mapped $wfmp_name" >&2
    return 1
}

# The same wait for a --cgroup lane, where the process that maps the provider is
# inside a container and its host pid is not known up front. Descendants are
# searched too, exactly as `--cgroup` itself matches them: a pod cgroup holds no
# processes of its own, they live in its per-container leaves.
wait_for_cgroup_provider() {
    wfcp_cgroup=$1
    wfcp_name=$2
    MAPPED_PROVIDER_PID=
    wfcp_attempt=0
    while [ "$wfcp_attempt" -lt 200 ]; do
        for wfcp_pid in $(sudo -n find "$wfcp_cgroup" -name cgroup.procs -exec cat {} + 2>/dev/null); do
            if sudo -n grep -Fq "$wfcp_name" "/proc/$wfcp_pid/maps" 2>/dev/null; then
                MAPPED_PROVIDER_PID=$wfcp_pid
                return 0
            fi
        done
        wfcp_attempt=$((wfcp_attempt + 1))
        sleep 0.05
    done
    echo "no process in $wfcp_cgroup mapped $wfcp_name" >&2
    return 1
}

wait_for_capture_ready() {
    wcr_log=$1
    wcr_privacy=$2
    wcr_kind=$3
    wcr_attempt=0
    while [ "$wcr_attempt" -lt 160 ]; do
        case $wcr_kind in
            trace) grep -Fqx "CAPTURE privacy=$wcr_privacy" "$wcr_log" 2>/dev/null && return 0 ;;
            profile|metrics) grep -Fq " — privacy=$wcr_privacy" "$wcr_log" 2>/dev/null && return 0 ;;
            *) echo "unknown readiness kind: $wcr_kind" >&2; return 1 ;;
        esac
        [ -z "${SPID-}" ] || kill -0 "$SPID" 2>/dev/null || {
            case $wcr_kind in
                trace) grep -Fqx "CAPTURE privacy=$wcr_privacy" "$wcr_log" 2>/dev/null && return 0 ;;
                profile|metrics) grep -Fq " — privacy=$wcr_privacy" "$wcr_log" 2>/dev/null && return 0 ;;
            esac
            echo "observer exited before capture readiness: $wcr_log" >&2
            # Name the reason, not just the file: on a hosted runner the log is
            # discarded with the workspace, so a bare path is unactionable.
            tail -30 "$wcr_log" >&2 2>/dev/null || :
            return 1
        }
        wcr_attempt=$((wcr_attempt + 1))
        sleep 0.05
    done
    echo "observer never reported capture readiness: $wcr_log" >&2
    tail -30 "$wcr_log" >&2 2>/dev/null || :
    return 1
}

# Discover on the host copy of a container's provider directory and rewrite
# the manifest for the container's mount namespace:
#   discover_copied_provider SAFE_ROOT PROVIDER_BASENAME DISCOVER_BIN TARGET_DIR OUT_MANIFEST
discover_copied_provider() {
    dcp_module="$1/$2"
    test -f "$dcp_module" && [ ! -L "$dcp_module" ] || {
        echo "copied provider is not a regular file" >&2
        return 1
    }
    timeout --signal=TERM --kill-after=5s 60s "$3" --module "$dcp_module" -o "$5.raw" || return 1
    rewrite_container_manifest "$5.raw" "$5" "$1" "$4" || return 1
    rm -f "$5.raw"
}

# Container discovery runs on a host copy of the container's provider
# directory, so the manifest it emits names host paths. Point module_path
# and every attach object at the same file inside the container's mount
# namespace, refusing any object that escapes the copied directory.
rewrite_container_manifest() {
    timeout --signal=TERM --kill-after=5s 60s python3 -I - "$@" <<'PY'
import json
import sys
from pathlib import Path

source, destination, safe_root, target_root = sys.argv[1:5]
safe_root = Path(safe_root).resolve(strict=True)
target_root = Path(target_root)
if not target_root.is_absolute():
    raise SystemExit(f"target root is not absolute: {target_root}")
manifest = json.loads(Path(source).read_text(encoding="utf-8"))
if manifest.get("schema") != "p11scope-manifest/5":
    raise SystemExit(f"container manifest is not schema v5: {manifest.get('schema')!r}")
if not manifest.get("objects"):
    raise SystemExit("container manifest has no attach objects")


def target(path):
    resolved = Path(path).resolve(strict=True)
    try:
        relative = resolved.relative_to(safe_root)
    except ValueError:
        raise SystemExit(f"attach object escapes the copied directory: {resolved}")
    return str(target_root / relative)


manifest["module_path"] = target(manifest["module_path"])
for item in manifest["objects"]:
    item["path"] = target(item["path"])
if manifest["objects"][0]["path"] != manifest["module_path"]:
    raise SystemExit("object zero is not the module")
Path(destination).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY
}

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

recording_launcher_active() {
    rla_pid=$1
    kill -0 "$rla_pid" 2>/dev/null || return 1
    ! awk '{ sub(/^[0-9]+ \(.*\) /, ""); exit(substr($0, 1, 1) == "Z" ? 0 : 1) }' \
        "/proc/$rla_pid/stat" 2>/dev/null
}

terminate_recording_launcher() {
    trl_pid=$1
    case $trl_pid in ''|*[!0-9]*) return 1 ;; esac
    kill "$trl_pid" 2>/dev/null || true
    trl_attempt=0
    while recording_launcher_active "$trl_pid" && [ "$trl_attempt" -lt 100 ]; do
        trl_attempt=$((trl_attempt + 1))
        sleep 0.05
    done
    if recording_launcher_active "$trl_pid"; then
        kill -KILL "$trl_pid" 2>/dev/null || return 1
        trl_attempt=0
        while recording_launcher_active "$trl_pid" && [ "$trl_attempt" -lt 100 ]; do
            trl_attempt=$((trl_attempt + 1))
            sleep 0.05
        done
    fi
    recording_launcher_active "$trl_pid" && return 1
    wait "$trl_pid" 2>/dev/null || true
}

launch_root_recorded_process() {
    lrrp_pidfile=$1
    lrrp_log=$2
    shift 2
    sudo -n sh -c '
        umask 077
        starttime=$(awk '\''{ sub(/^[0-9]+ \(.*\) /, ""); split($0, tail, " "); print tail[20]; exit }'\'' "/proc/$$/stat") || exit 1
        set -C
        printf "%s %s\n" "$$" "$starttime" > "$1" || exit 1
        shift
        exec "$@"
    ' sh "$lrrp_pidfile" "$@" > "$lrrp_log" 2>&1 &
    ROOT_LAUNCH_PID=$!
    lrrp_record=$(wait_root_process_record "$lrrp_pidfile" "$ROOT_LAUNCH_PID") || {
        lrrp_status=$?
        if terminate_recording_launcher "$ROOT_LAUNCH_PID"; then
            ROOT_LAUNCH_PID=
            return "$lrrp_status"
        fi
        return 1
    }
    set -- $lrrp_record
    [ "$#" -eq 2 ] || return 1
    ROOT_PROCESS_PID=$1
    ROOT_PROCESS_STARTTIME=$2
}

wait_root_process_record() {
    wrpr_pidfile=$1
    wrpr_launcher=$2
    wrpr_attempt=0
    while ! sudo -n test -s "$wrpr_pidfile" && [ "$wrpr_attempt" -lt 160 ]; do
        recording_launcher_active "$wrpr_launcher" || {
            echo "root process exited before recording its identity" >&2
            return 1
        }
        wrpr_attempt=$((wrpr_attempt + 1))
        sleep 0.05
    done
    sudo -n test -s "$wrpr_pidfile" || {
        echo "root process identity was not recorded" >&2
        return 1
    }
    set -- $(sudo -n cat "$wrpr_pidfile")
    [ "$#" -eq 2 ] || return 1
    case $1:$2 in *[!0-9:]*) return 1 ;; esac
    printf '%s %s\n' "$1" "$2"
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
    except FileNotFoundError:
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
            return 1
        }
        wcr_attempt=$((wcr_attempt + 1))
        sleep 0.05
    done
    echo "observer never reported capture readiness: $wcr_log" >&2
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
if manifest.get("schema") != "p11scope-manifest/4":
    raise SystemExit(f"container manifest is not schema v4: {manifest.get('schema')!r}")
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

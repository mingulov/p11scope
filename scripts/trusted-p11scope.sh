#!/bin/sh
# Stage the observer and its discovery oracle as one root-owned sibling pair.
# Privileged captures intentionally refuse a user-writable helper.

require_non_root_caller() {
    [ "$(id -u)" -ne 0 ] || {
        echo "run this gate as a non-root user with passwordless sudo" >&2
        return 1
    }
}

set_suid_dumpable_zero() {
    [ -z "${SUID_DUMPABLE_CHANGED-}" ] || return 0
    SUID_DUMPABLE_ORIGINAL=$(cat /proc/sys/fs/suid_dumpable) || return 1
    case $SUID_DUMPABLE_ORIGINAL in 0|1|2) ;; *) return 1 ;; esac
    SUID_DUMPABLE_CHANGED=1
    if [ "$SUID_DUMPABLE_ORIGINAL" != 0 ]; then
        printf '%s\n' 0 | sudo -n tee /proc/sys/fs/suid_dumpable >/dev/null || return 1
    fi
    [ "$(cat /proc/sys/fs/suid_dumpable)" = 0 ] || {
        echo "privileged discovery requires /proc/sys/fs/suid_dumpable=0" >&2
        return 1
    }
}

restore_suid_dumpable() {
    [ -n "${SUID_DUMPABLE_CHANGED-}" ] || return 0
    if ! printf '%s\n' "$SUID_DUMPABLE_ORIGINAL" \
        | sudo -n tee /proc/sys/fs/suid_dumpable >/dev/null \
        || [ "$(cat /proc/sys/fs/suid_dumpable)" != "$SUID_DUMPABLE_ORIGINAL" ]; then
        echo "failed to restore /proc/sys/fs/suid_dumpable=$SUID_DUMPABLE_ORIGINAL" >&2
        return 1
    fi
    SUID_DUMPABLE_CHANGED=
}

validate_protected_parent() {
    directory=$1
    owner=$(stat -Lc %u "$directory")
    mode=$(stat -Lc %a "$directory")
    [ "$owner" -eq 0 ] && [ $((0$mode & 022)) -eq 0 ] || {
        echo "$directory is not a protected root-owned directory" >&2
        return 1
    }
}

is_immediate_child() {
    child=$1
    parent=$2
    prefix=$3
    base=${child##*/}
    [ "$child" = "$parent/$base" ] || return 1
    case $base in
        "$prefix"?*) return 0 ;;
        *) return 1 ;;
    esac
}

is_trusted_exec_destination() {
    trusted_path=$1
    is_immediate_child "$trusted_path" /usr/local/bin .p11scope. && return 0
    trusted_parent=${trusted_path%/*}
    trusted_leaf=${trusted_path##*/}
    is_immediate_child "$trusted_parent" /usr/local/bin .p11scope. || return 1
    [ "$trusted_path" = "$trusted_parent/$trusted_leaf" ] || return 1
    case $trusted_leaf in
        ''|.*|*/*|*[!A-Za-z0-9._-]*) return 1 ;;
    esac
}

create_trusted_exec_dir() {
    for directory in /usr /usr/local /usr/local/bin; do
        validate_protected_parent "$directory" || return 1
    done
    mount_options=$(findmnt -n -o OPTIONS -T /usr/local/bin)
    case ,$mount_options, in
        *,noexec,*) echo "/usr/local/bin is mounted noexec" >&2; return 1 ;;
    esac
    destination=$(sudo -n mktemp -d /usr/local/bin/.p11scope.XXXXXXXX) || return 1
    if ! sudo -n chmod 0755 "$destination"; then
        sudo -n rmdir "$destination" 2>/dev/null || true
        return 1
    fi
    printf '%s\n' "$destination"
}

create_protected_output_dir() {
    validate_protected_parent /run || return 1
    destination=$(sudo -n mktemp -d /run/p11scope-output.XXXXXXXX) || return 1
    if ! sudo -n chmod 0700 "$destination"; then
        sudo -n rmdir "$destination" 2>/dev/null || true
        return 1
    fi
    printf '%s\n' "$destination"
}

stage_trusted_p11scope() {
    observer=$1
    helper=$2
    destination=$3
    is_trusted_exec_destination "$destination" || {
        echo "refusing unexpected executable staging path: $destination" >&2
        return 1
    }
    sudo -n install -d -o root -g root -m 0755 "$destination"
    sudo -n install -o root -g root -m 0755 "$observer" "$destination/p11scope"
    sudo -n install -o root -g root -m 0755 "$helper" "$destination/p11scope-discover"
}

stage_container_authority() {
    source=$1
    destination=$2
    is_trusted_exec_destination "$destination" || {
        echo "refusing unexpected executable staging path: $destination" >&2
        return 1
    }
    sudo -n install -o root -g root -m 0555 "$source" "$destination/container-authority.py"
}

remove_trusted_p11scope() {
    destination=$1
    [ -z "$destination" ] && return
    is_trusted_exec_destination "$destination" || {
        echo "refusing unexpected executable staging path: $destination" >&2
        return 1
    }
    rtp_status=0
    sudo -n rm -f "$destination/p11scope" "$destination/p11scope-discover" \
        "$destination/container-authority.py" \
        || rtp_status=$?
    sudo -n rmdir "$destination" 2>/dev/null || {
        rtp_rmdir_status=$?
        [ "$rtp_status" -ne 0 ] || rtp_status=$rtp_rmdir_status
    }
    return "$rtp_status"
}

remove_trusted_exec_root() {
    destination=$1
    [ -z "$destination" ] && return
    is_immediate_child "$destination" /usr/local/bin .p11scope. || {
        echo "refusing unexpected executable staging path: $destination" >&2
        return 1
    }
    sudo -n rmdir "$destination"
}

remove_protected_output_dir() {
    destination=$1
    [ -z "$destination" ] && return
    is_immediate_child "$destination" /run p11scope-output. || {
        echo "refusing unexpected output staging path: $destination" >&2
        return 1
    }
    rpod_status=0
    sudo -n find "$destination" -mindepth 1 -maxdepth 1 -type f -delete \
        || rpod_status=$?
    sudo -n rmdir "$destination" || {
        rpod_rmdir_status=$?
        [ "$rpod_status" -ne 0 ] || rpod_status=$rpod_rmdir_status
    }
    return "$rpod_status"
}

cleanup_step() {
    "$@"
    cleanup_step_status=$?
    if [ "$CLEANUP_STATUS" -eq 0 ] && [ "$cleanup_step_status" -ne 0 ]; then
        CLEANUP_STATUS=$cleanup_step_status
    fi
    return 0
}

require_rewritten_authority_refusal() {
    printf '%s\n' "$1" \
        | grep -F "$2: cannot open the file now (" \
        | grep -Fq "Permission denied"
}

publish_protected_file() {
    run_dir=$1
    source=$2
    work_dir=$3
    destination=$4
    is_immediate_child "$run_dir" /run p11scope-output. || {
        echo "refusing unexpected protected source directory: $run_dir" >&2
        return 1
    }
    for leaf in "$source" "$destination"; do
        case $leaf in
            ''|.*|*/*|*[!A-Za-z0-9._-]*)
                echo "refusing unexpected publication name: $leaf" >&2
                return 1
                ;;
        esac
    done
    PUBLISH_TMP=$(mktemp "$work_dir/.${destination}.XXXXXXXX") || return 1
    if ! sudo -n cat "$run_dir/$source" > "$PUBLISH_TMP" \
        || ! mv -f "$PUBLISH_TMP" "$work_dir/$destination"; then
        rm -f -- "$PUBLISH_TMP"
        PUBLISH_TMP=
        return 1
    fi
    PUBLISH_TMP=
    test -s "$work_dir/$destination" || {
        echo "$destination was not published" >&2
        return 1
    }
}

publish_protected_mapdump_lane() {
    ppml_run_dir=$1
    ppml_work_dir=$2
    ppml_lane=$3
    for ppml_path in $(sudo -n find "$ppml_run_dir" -mindepth 1 -maxdepth 1 -type f \
        -name "mapdump_*_$ppml_lane.json" -print); do
        publish_protected_file "$ppml_run_dir" "${ppml_path##*/}" \
            "$ppml_work_dir" "${ppml_path##*/}"
    done
    ppml_manifest="mapdump_manifest_$ppml_lane.json"
    publish_protected_file "$ppml_run_dir" "$ppml_manifest" \
        "$ppml_work_dir" "$ppml_manifest"
    PUBLISH_TMP=$(mktemp "$ppml_work_dir/.${ppml_manifest}.XXXXXXXX") || return 1
    if ! python3 - "$ppml_work_dir/$ppml_manifest" "$ppml_work_dir" \
        > "$PUBLISH_TMP" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
for item in manifest:
    if "file" in item:
        item["file"] = str(Path(sys.argv[2]) / Path(item["file"]).name)
json.dump(manifest, sys.stdout, indent=2)
print()
PY
    then
        rm -f -- "$PUBLISH_TMP"
        PUBLISH_TMP=
        return 1
    fi
    mv -f "$PUBLISH_TMP" "$ppml_work_dir/$ppml_manifest"
    PUBLISH_TMP=
}

is_protected_output_file() {
    ipof_path=$1
    ipof_parent=${ipof_path%/*}
    ipof_leaf=${ipof_path##*/}
    is_immediate_child "$ipof_parent" /run p11scope-output. || return 1
    case $ipof_leaf in
        ''|.*|*/*|*[!A-Za-z0-9._-]*) return 1 ;;
    esac
}

launch_root_recorded_process() {
    lrrp_pidfile=$1
    lrrp_log=$2
    shift 2
    is_protected_output_file "$lrrp_pidfile" || {
        echo "refusing unexpected root process record: $lrrp_pidfile" >&2
        return 1
    }
    sudo -n sh -c '
        umask 077
        starttime=$(awk '\''{ sub(/^[0-9]+ \(.*\) /, ""); split($0, tail, " "); print tail[20]; exit }'\'' "/proc/$$/stat") || exit 1
        printf "%s %s\n" "$$" "$starttime" > "$1"
        shift
        exec "$@"
    ' sh "$lrrp_pidfile" "$@" > "$lrrp_log" 2>&1 &
    ROOT_LAUNCH_PID=$!
    lrrp_record=$(wait_root_process_record "$lrrp_pidfile" "$ROOT_LAUNCH_PID") || {
        lrrp_status=$?
        kill "$ROOT_LAUNCH_PID" 2>/dev/null || true
        wait "$ROOT_LAUNCH_PID" 2>/dev/null || true
        ROOT_LAUNCH_PID=
        return "$lrrp_status"
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
        kill -0 "$wrpr_launcher" 2>/dev/null || {
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
        user) spp_python=python3 ;;
        root) spp_python='sudo -n python3' ;;
        *) return 1 ;;
    esac
    $spp_python - "$@" <<'PY'
import os
import select
import signal
import sys

signals = {
    "CONT": signal.SIGCONT,
    "INT": signal.SIGINT,
    "KILL": signal.SIGKILL,
    "STOP": signal.SIGSTOP,
    "TERM": signal.SIGTERM,
}
if len(sys.argv) not in (4, 6) or sys.argv[1] not in signals:
    raise SystemExit("usage: SIGNAL PID STARTTIME [PARENT_PID PARENT_STARTTIME]")


def identity(pid_text, start_text):
    pid, expected = int(pid_text), int(start_text)
    fd = os.pidfd_open(pid)
    raw = open(f"/proc/{pid}/stat", "rb").read()
    tail = raw.rsplit(b") ", 1)[1].split()
    if len(tail) < 20 or int(tail[19]) != expected:
        os.close(fd)
        raise SystemExit(f"refusing changed process identity {pid}")
    return pid, fd, int(tail[1])


parent = None
if len(sys.argv) == 6:
    parent = identity(sys.argv[4], sys.argv[5])
target = identity(sys.argv[2], sys.argv[3])
if parent is not None:
    if target[2] != parent[0]:
        raise SystemExit("worker is not a live child of the pinned supervisor")
    poller = select.poll()
    poller.register(parent[1], select.POLLIN)
    if poller.poll(0):
        raise SystemExit("pinned supervisor exited before worker signal")
signal.pidfd_send_signal(target[1], signals[sys.argv[1]], None, 0)
if parent is not None and poller.poll(0):
    raise SystemExit("pinned supervisor exited during worker signal")
PY
}

signal_verified_process() {
    signal_pinned_process user "$@"
}

signal_verified_root_process() {
    signal_pinned_process root "$@"
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
            echo "observer exited before capture readiness: $wcr_log" >&2
            return 1
        }
        wcr_attempt=$((wcr_attempt + 1))
        sleep 0.05
    done
    echo "observer never reported capture readiness: $wcr_log" >&2
    return 1
}

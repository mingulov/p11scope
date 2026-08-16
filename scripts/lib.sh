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

launch_root_recorded_process() {
    lrrp_pidfile=$1
    lrrp_log=$2
    shift 2
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
import signal
import sys

signals = {
    "CONT": signal.SIGCONT,
    "INT": signal.SIGINT,
    "KILL": signal.SIGKILL,
    "STOP": signal.SIGSTOP,
    "TERM": signal.SIGTERM,
}
if len(sys.argv) != 4 or sys.argv[1] not in signals:
    raise SystemExit("usage: SIGNAL PID STARTTIME")

pid, expected = int(sys.argv[2]), int(sys.argv[3])
fd = os.pidfd_open(pid)
raw = open(f"/proc/{pid}/stat", "rb").read()
tail = raw.rsplit(b") ", 1)[1].split()
if len(tail) < 20 or int(tail[19]) != expected:
    raise SystemExit(f"refusing changed process identity {pid}")
signal.pidfd_send_signal(fd, signals[sys.argv[1]], None, 0)
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
    timeout --signal=TERM --kill-after=5s 60s python3 - "$@" <<'PY'
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

#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# In-cluster twin of scripts/attach-pod.sh: run INSIDE the p11scope-observer
# DaemonSet pod (via `kubectl exec`) to capture one target pod's cgroup.
#
# The target is named by pod UID (or container id). Both are resolved from the
# node's cgroup v2 hierarchy (the read-only /sys/fs/cgroup hostPath mount), so
# the observer needs no Kubernetes API access: no ServiceAccount token, no
# Role. The operator resolves the UID with their own credentials:
#   kubectl -n NS get pod NAME -o jsonpath='{.metadata.uid}'
set -eu

usage() {
    cat >&2 <<'EOF'
usage: k8s-profile-entry (--pod-uid UID | --cid HEX64)
                         [--command profile|trace|doctor] [-- p11scope-args...]

  --pod-uid UID       target pod UID (metadata.uid); every container in the pod
  --cid HEX64         target container id (status.containerStatuses[].containerID
                      without the runtime:// prefix); its whole pod is captured
  --command CMD       p11scope subcommand run against the pod cgroup
                      (default: profile)
  --                  everything after this is passed to p11scope verbatim,
                      e.g. -- --mode metrics --duration 30 -o /tmp/out.json
                      (/tmp is the only writable path in the observer pod)
EOF
    exit 2
}

POD_UID=
CID=
COMMAND=profile
OBSERVER=${P11SCOPE_OBSERVER:-/usr/local/bin/p11scope}
CGROUP_ROOT=${P11SCOPE_CGROUP_ROOT:-/sys/fs/cgroup}

valid_uid() {
    case $1 in
        *[!0-9a-f-]*) return 1 ;;
        ????????-????-????-????-????????????) return 0 ;;
        *) return 1 ;;
    esac
}

valid_cid() {
    case $1 in
        ''|*[!0-9a-f]*) return 1 ;;
        *) [ "${#1}" -eq 64 ] ;;
    esac
}

# Prints every candidate pod cgroup directory for POD_UID or CID, one per
# line. The systemd cgroup driver names a pod slice
# `...-pod<uid with _ for ->.slice` and a container `cri-containerd-<id>.scope`
# (containerd) or `crio-<id>.scope` (CRI-O); the cgroupfs driver uses
# `pod<uid>` and the bare id (containerd) or `crio-<id>` (CRI-O). Only the
# containerd + systemd layout is exercised on a real node (scripts/kind-e2e.sh);
# the others are checked against a synthetic hierarchy in --self-test.
pod_cgroup_candidates() {
    if [ -n "$POD_UID" ]; then
        underscored=$(printf '%s' "$POD_UID" | tr '-' '_')
        find "$CGROUP_ROOT" -maxdepth 6 -type d \
            \( -name "*-pod$underscored.slice" -o -name "pod$POD_UID" \) -print 2>/dev/null
        return 0
    fi
    find "$CGROUP_ROOT" -maxdepth 7 -type d \
        \( -name "cri-containerd-$CID.scope" -o -name "crio-$CID.scope" -o -name "crio-$CID" \
        -o -name "docker-$CID.scope" -o -name "$CID" \) -print 2>/dev/null \
        | while read -r container_cg; do dirname "$container_cg"; done
}

# True when $1 is exactly a kubelet pod cgroup: the path relative to
# CGROUP_ROOT must START at the kubelet hierarchy root and the pod directory
# must sit at the QoS depth, nothing deeper:
#   systemd:  kubepods.slice/[kubepods-<qos>.slice/]kubepods[-<qos>]-pod<uid_>.slice
#             kubelet.slice/kubelet-kubepods.slice/[kubelet-kubepods-<qos>.slice/]
#                 kubelet-kubepods[-<qos>]-pod<uid_>.slice
#   cgroupfs: kubepods/[<qos>/]pod<uid>
# (<qos> is burstable or besteffort; guaranteed pods sit directly under the
# root). A workload with a delegated cgroup subtree can create directories
# named like any of these inside its own cgroup; anchoring at the root and
# fixing the depth keeps such a decoy from ever being accepted. Names with
# anything but [A-Za-z0-9._-] (newlines, control characters, spaces) are
# refused outright. With POD_UID set, the uid in the name must be that uid.
valid_pod_cgroup_path() (
    case $1 in "$CGROUP_ROOT"/*) ;; *) exit 1 ;; esac
    rel=${1#"$CGROUP_ROOT"/}
    case $rel in ''|*[!A-Za-z0-9._/-]*|*//*|/*|*/) exit 1 ;; esac
    set -f
    IFS=/
    # shellcheck disable=SC2086
    set -- $rel
    case $1 in
        kubepods.slice) stem=kubepods; shift ;;
        kubelet.slice)
            [ "$#" -ge 2 ] && [ "$2" = kubelet-kubepods.slice ] || exit 1
            stem=kubelet-kubepods
            shift 2
            ;;
        kubepods) stem=; shift ;;
        *) exit 1 ;;
    esac
    if [ -n "$stem" ]; then
        case $# in
            1) pod=$1 prefix=$stem-pod ;;
            2)
                case $1 in "$stem-burstable.slice"|"$stem-besteffort.slice") ;; *) exit 1 ;; esac
                qos=${1%.slice}
                pod=$2 prefix=$qos-pod
                ;;
            *) exit 1 ;;
        esac
        case $pod in "$prefix"*.slice) ;; *) exit 1 ;; esac
        id=${pod#"$prefix"}
        id=$(printf '%s' "${id%.slice}" | tr '_' '-')
    else
        case $# in
            1) pod=$1 ;;
            2) case $1 in burstable|besteffort) ;; *) exit 1 ;; esac; pod=$2 ;;
            *) exit 1 ;;
        esac
        case $pod in pod*) ;; *) exit 1 ;; esac
        id=${pod#pod}
    fi
    valid_uid "$id" || exit 1
    [ -z "$POD_UID" ] || [ "$id" = "$POD_UID" ] || exit 1
)

# Sets POD_CG to the single pod cgroup, or explains and returns 1. Only
# candidates that are exact kubelet pod cgroups count (decoys found elsewhere
# are reported and ignored, so they can neither widen the scope nor block the
# real pod); more than one valid candidate is refused, never guessed.
resolve_pod_cgroup() {
    valid=
    count=0
    ignored=0
    candidates=$(pod_cgroup_candidates)
    while IFS= read -r candidate; do
        [ -n "$candidate" ] || continue
        if valid_pod_cgroup_path "$candidate"; then
            valid=$candidate
            count=$((count + 1))
        else
            ignored=$((ignored + 1))
        fi
    done <<EOF
$candidates
EOF
    [ "$ignored" -eq 0 ] || echo "ignored $ignored match(es) that are not kubelet pod cgroups (decoys or foreign scopes)" >&2
    if [ "$count" -eq 0 ]; then
        echo "could not locate the pod cgroup under $CGROUP_ROOT's kubepods hierarchy (is the target on this node?)" >&2
        return 1
    fi
    if [ "$count" -gt 1 ]; then
        echo "refusing: $count kubelet pod cgroups match the target, expected exactly one" >&2
        return 1
    fi
    POD_CG=$valid
}

require_cgroup_v2() {
    [ -f "$CGROUP_ROOT/cgroup.controllers" ] || {
        echo "$CGROUP_ROOT is not a cgroup v2 hierarchy (no cgroup.controllers); p11scope needs the node's unified cgroup tree mounted there" >&2
        return 1
    }
}

# Prints the pod's processes visible in this PID namespace, one per line.
# cgroup.procs lists a task outside the reader's PID namespace as 0.
visible_pids() {
    find "$1" -name cgroup.procs -type f -exec cat {} \; 2>/dev/null \
        | while read -r vp_pid; do
            [ "$vp_pid" != 0 ] && [ -d "/proc/$vp_pid" ] && echo "$vp_pid"
        done
    return 0
}

# Prints the visible pids whose memory this process may open (the memory
# scan needs exactly that: ptrace access, plus DAC traversal).
memory_readable_pids() {
    for mr_pid in $1; do
        if ( : < "/proc/$mr_pid/mem" ) 2>/dev/null; then echo "$mr_pid"; fi
    done
    return 0
}

self_test() {
    uid=0123abcd-4567-89ef-0123-456789abcdef
    cid=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    for bad in "" "--pod-uid" "--pod-uid UPPER" "--pod-uid 0123abcd" \
               "--pod-uid $uid --cid $cid" "--pod-uid $uid --command run" \
               "--pod-uid $uid --command" "--pod-uid $uid --bogus" "--bogus" \
               "--cid xyz" "--cid gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg" \
               "--cid ${cid}0" "--pod NAME"; do
        status=0
        # shellcheck disable=SC2086
        sh "$0" $bad >/dev/null 2>&1 || status=$?
        [ "$status" -eq 2 ] || {
            echo "k8s-profile-entry exited $status (want 2) for: [$bad]" >&2
            exit 1
        }
    done
    valid_uid "$uid" || { echo "valid_uid rejected $uid" >&2; exit 1; }
    for bad in "" "0123ABCD-4567-89ef-0123-456789abcdef" "0123abcd_4567_89ef_0123_456789abcdef" \
               "0123abcd-4567-89ef-0123-456789abcde" "../../../../../../../../../../../../.."; do
        if valid_uid "$bad"; then echo "valid_uid accepted $bad" >&2; exit 1; fi
    done
    # Lookup against a synthetic hierarchy in both driver layouts.
    root=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-entry-XXXXXX")
    trap 'rm -rf "$root"' EXIT
    u2=fedcba98-7654-3210-fedc-ba9876543210
    systemd_pod="$root/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod$(printf '%s' "$uid" | tr '-' '_').slice"
    c4=4444444444444444444444444444444444444444444444444444444444444444
    mkdir -p "$systemd_pod/cri-containerd-$cid.scope" "$root/kubepods/burstable/pod$u2/$c4"
    CGROUP_ROOT=$root
    POD_UID=$uid CID=''
    resolve_pod_cgroup && [ "$POD_CG" = "$systemd_pod" ] || { echo "systemd uid lookup failed" >&2; exit 1; }
    POD_UID='' CID=$cid
    resolve_pod_cgroup && [ "$POD_CG" = "$systemd_pod" ] || { echo "systemd cid lookup failed" >&2; exit 1; }
    POD_UID=$u2 CID=''
    resolve_pod_cgroup && [ "$POD_CG" = "$root/kubepods/burstable/pod$u2" ] || { echo "cgroupfs uid lookup failed" >&2; exit 1; }
    POD_UID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa CID=''
    if resolve_pod_cgroup 2>/dev/null; then echo "absent uid resolved" >&2; exit 1; fi
    # CRI-O under the cgroupfs driver: crio-<id>, no .scope.
    c2=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
    u3=11111111-2222-3333-4444-555555555555
    mkdir -p "$root/kubepods/besteffort/pod$u3/crio-$c2"
    POD_UID='' CID=$c2
    resolve_pod_cgroup && [ "$POD_CG" = "$root/kubepods/besteffort/pod$u3" ] \
        || { echo "cri-o cgroupfs cid lookup failed" >&2; exit 1; }
    # A container scope outside kubepods must not widen the scope to its parent.
    c3=abababababababababababababababababababababababababababababababab
    mkdir -p "$root/system.slice/docker-$c3.scope"
    POD_UID='' CID=$c3
    if resolve_pod_cgroup 2>/dev/null; then echo "non-kubepods scope accepted: $POD_CG" >&2; exit 1; fi
    # A decoy pod slice outside the kubelet root is ignored: the real pod
    # still resolves, the decoy never does.
    mkdir -p "$root/system.slice/decoy-pod$(printf '%s' "$uid" | tr '-' '_').slice"
    POD_UID=$uid CID=''
    resolve_pod_cgroup 2>/dev/null && [ "$POD_CG" = "$systemd_pod" ] \
        || { echo "system.slice decoy changed the uid resolution: $POD_CG" >&2; exit 1; }
    # Decoys a workload could create inside its own delegated cgroup subtree.
    # (a) the victim's uid named under a pod's own container scope: ignored.
    u_=$(printf '%s' "$uid" | tr '-' '_')
    mkdir -p "$systemd_pod/cri-containerd-$cid.scope/kubelet-kubepods-pod$u_.slice"
    resolve_pod_cgroup 2>/dev/null && [ "$POD_CG" = "$systemd_pod" ] \
        || { echo "nested same-uid decoy changed the resolution: $POD_CG" >&2; exit 1; }
    # (b) a whole decoy kubepods path deeper inside a pod: never a pod cgroup.
    u5=55555555-5555-5555-5555-555555555555
    u5_=$(printf '%s' "$u5" | tr '-' '_')
    nested=$systemd_pod/cri-containerd-$cid.scope/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod$u5_.slice
    mkdir -p "$nested" "$root/kubepods/burstable/pod$u2/$c4/kubepods/pod$u5"
    POD_UID=$u5 CID=''
    if resolve_pod_cgroup 2>/dev/null; then echo "nested decoy kubepods path accepted: $POD_CG" >&2; exit 1; fi
    # (c) a decoy container scope nested under a pod: its parent is not a pod cgroup.
    c5=5555555555555555555555555555555555555555555555555555555555555555
    mkdir -p "$systemd_pod/cri-containerd-$cid.scope/inner/cri-containerd-$c5.scope"
    POD_UID='' CID=$c5
    if resolve_pod_cgroup 2>/dev/null; then echo "nested decoy container accepted: $POD_CG" >&2; exit 1; fi
    # Exact shape checks, independent of the filesystem.
    for good in "$systemd_pod" "$root/kubepods/burstable/pod$u2" "$root/kubepods/pod$u2" \
                "$root/kubepods.slice/kubepods-pod$u5_.slice" \
                "$root/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod$u5_.slice"; do
        POD_UID=''
        valid_pod_cgroup_path "$good" || { echo "valid pod cgroup rejected: $good" >&2; exit 1; }
    done
    nl='
'
    tab=$(printf '\t')
    for bad in "$root" "$root/kubepods" "$root/kubepods/burstable" "$root/kubepods/guaranteed/pod$u2" \
               "$root/kubepods/burstable/pod$u2/$c4" "$root/system.slice/kubepods/pod$u2" \
               "$root/x/kubepods.slice/kubepods-pod$u5_.slice" "$nested" \
               "$root/kubepods.slice/kubepods-besteffort.slice/kubepods-burstable-pod$u5_.slice" \
               "$root/kubepods.slice/kubepods-pod$u5_.slice/inner" "$root/kubepods/podnot-a-uid" \
               "$root/kubepods/pod$u2$nl" "$root/kubepods/pod$u2${tab}x" "$root/kubepods/pod $u2" \
               "/elsewhere/kubepods/pod$u2" "$root/kubepods//pod$u2" "$root/kubepods/pod$u2/"; do
        POD_UID=''
        if valid_pod_cgroup_path "$bad"; then echo "invalid pod cgroup accepted: [$bad]" >&2; exit 1; fi
    done
    POD_UID=$u2
    if valid_pod_cgroup_path "$root/kubepods/pod$u5"; then echo "uid mismatch accepted" >&2; exit 1; fi
    # A lone decoy outside kubepods is refused too.
    u4=99999999-8888-7777-6666-555555555555
    mkdir -p "$root/user.slice/x-pod$(printf '%s' "$u4" | tr '-' '_').slice"
    POD_UID=$u4 CID=''
    if resolve_pod_cgroup 2>/dev/null; then echo "decoy uid accepted: $POD_CG" >&2; exit 1; fi
    # cgroup v2 marker.
    if require_cgroup_v2 2>/dev/null; then echo "cgroup v2 check passed without cgroup.controllers" >&2; exit 1; fi
    : > "$root/cgroup.controllers"
    require_cgroup_v2 || { echo "cgroup v2 check failed with cgroup.controllers" >&2; exit 1; }
    # Visible processes: 0 entries (outside this PID namespace) do not count.
    printf '0\n0\n' > "$systemd_pod/cri-containerd-$cid.scope/cgroup.procs"
    [ -z "$(visible_pids "$systemd_pod")" ] || { echo "invisible pids counted" >&2; exit 1; }
    printf '0\n%s\n' "$$" > "$systemd_pod/cri-containerd-$cid.scope/cgroup.procs"
    [ "$(visible_pids "$systemd_pod")" = "$$" ] || { echo "visible pid missed" >&2; exit 1; }
    [ "$(memory_readable_pids self)" = self ] || { echo "own memory not readable" >&2; exit 1; }
    [ -z "$(memory_readable_pids 999999999)" ] || { echo "absent pid memory readable" >&2; exit 1; }
    rm -rf "$root"
    trap - EXIT
    echo "k8s-profile-entry argument self-test: OK"
    exit 0
}

[ "${1-}" != "--self-test" ] || self_test

while [ "$#" -gt 0 ]; do
    case $1 in
        --pod-uid) [ "$#" -ge 2 ] || usage; POD_UID=$2; shift 2 ;;
        --cid) [ "$#" -ge 2 ] || usage; CID=$2; shift 2 ;;
        --command) [ "$#" -ge 2 ] || usage; COMMAND=$2; shift 2 ;;
        --) shift; break ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

case $COMMAND in profile|trace|doctor) ;; *) echo "--command must be profile, trace or doctor" >&2; usage ;; esac
if [ -n "$POD_UID" ] && [ -n "$CID" ]; then
    echo "pass exactly one of --pod-uid and --cid" >&2
    usage
fi
if [ -n "$POD_UID" ]; then
    valid_uid "$POD_UID" || { echo "--pod-uid must be a lowercase pod UID" >&2; usage; }
elif [ -n "$CID" ]; then
    valid_cid "$CID" || { echo "--cid must be 64 lowercase hex chars" >&2; usage; }
else
    echo "one of --pod-uid or --cid is required" >&2
    usage
fi

[ -x "$OBSERVER" ] || { echo "$OBSERVER is missing" >&2; exit 1; }

echo "=== resolve pod cgroup (node view) ===" >&2
require_cgroup_v2 || exit 1
resolve_pod_cgroup || exit 1

# A missing hostPID or a missing ptrace/DAC grant would otherwise read as "no
# provider in this pod" (a clean-looking empty capture): name it instead.
VISIBLE=$(visible_pids "$POD_CG")
[ -n "$VISIBLE" ] || {
    echo "no process of $POD_CG is visible in this PID namespace: the observer pod needs hostPID: true (or the target pod has no running process)" >&2
    exit 1
}
READABLE=$(memory_readable_pids "$VISIBLE")
N_VISIBLE=$(printf '%s\n' "$VISIBLE" | grep -c .)
N_READABLE=$(printf '%s\n' "$READABLE" | grep -c . || true)
echo "pod cgroup: $POD_CG ($N_VISIBLE visible process(es), $N_READABLE with readable memory)" >&2
if [ "$N_READABLE" -lt "$N_VISIBLE" ]; then
    echo "cannot open /proc/<pid>/mem of $((N_VISIBLE - N_READABLE)) pod process(es): the memory scan needs CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH" >&2
    # doctor reports what is missing; a capture would silently miss providers.
    [ "$COMMAND" = doctor ] || exit 1
fi

# Kubelet creates the scratch emptyDir 0777 without the sticky bit, which the
# observer's output trust check refuses. Restore classic /tmp mode so `-o
# /tmp/<name>.json` (the only writable path under the read-only root) works.
chmod 1777 /tmp || { echo "cannot harden the scratch mount" >&2; exit 1; }

exec "$OBSERVER" "$COMMAND" --cgroup "$POD_CG" "$@"

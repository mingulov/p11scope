#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Attach to a Kubernetes pod's cgroup and profile whatever PKCS#11 providers its
# processes have mapped. Nothing is copied into or out of the container: the
# observer reads the pod's memory and opens its provider through /proc/<pid>/root.
#
# Run this on the node that hosts the pod, as a non-root user with passwordless
# sudo. The pod is not created or owned by this script.
#
# The scan happens once, at attach time (Slice 1b-1): a provider the pod dlopens
# after this attaches is not discovered. `p11scope inspect --pid <host pid>` says
# what is mapped right now; run it first if the capture reports no modules.
set -eu
INVOCATION_DIR=$PWD
cd "$(dirname "$0")/.."

usage() {
    cat >&2 <<'EOF'
usage: scripts/attach-pod.sh --pod NAME [--namespace NS] [--container NAME]
                             [-- p11scope-args...]

  --pod NAME          existing pod to observe (required)
  --namespace NS      pod namespace (default: default)
  --container NAME    container in the pod (default: the first one)
  --                  everything after this is passed to `p11scope profile`
                      verbatim, e.g. -- --mode metrics --duration 60 -o out.json

Discovery scans the pod's mapped memory, so no provider manifest and no offline
discovery step is needed. Pass `-- --module PATH-IN-POD` to narrow the scan to
one provider.
EOF
    exit 2
}

NAMESPACE=default
POD=
CONTAINER=
OBSERVER=${P11SCOPE_OBSERVER:-target/release/p11scope}

# A pod, namespace or container name goes into a kubectl JSONPath filter and a
# cgroup glob, so refuse anything that is not the DNS-1123 label Kubernetes
# actually allows before it reaches either.
valid_name() {
    case $1 in
        ''|*[!a-z0-9.-]*) return 1 ;;
        -*|.*|*-|*.) return 1 ;;
        *) [ "${#1}" -le 253 ] ;;
    esac
}

self_test() {
    # Every refusal is an explicit branch: `set -e` ignores a `!`-negated command.
    for bad in "" "--pod" "--pod -bad" "--pod ok --namespace UPPER" \
               "--pod ok --container bad_name" "--pod ok --bogus" "--bogus"; do
        status=0
        # shellcheck disable=SC2086
        sh "$0" $bad >/dev/null 2>&1 || status=$?
        [ "$status" -eq 2 ] || {
            echo "attach-pod exited $status (want 2) for: [$bad]" >&2
            exit 1
        }
    done
    for name in ok my-pod pod.1 a; do
        valid_name "$name" || { echo "valid_name rejected $name" >&2; exit 1; }
    done
    for name in "" "-x" "x-" "Upper" "under_score" ".dot" "dot."; do
        if valid_name "$name"; then echo "valid_name accepted $name" >&2; exit 1; fi
    done
    if [ "$(id -u)" -ne 0 ]; then
        fetch_self_test
        resolve_self_test
    fi
    echo "attach-pod argument self-test: OK"
    exit 0
}

# A container name fetched from the cluster is validated before it reaches
# the JSONPath filter, exactly like a CLI-provided one: stub kubectl serves
# one good name and one filter-breaking name, stub timeout/sudo get out of
# the way, and nothing here needs a cluster.
fetch_self_test() {
    stub=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-attach-stub-XXXXXX")
    trap 'rm -rf "$stub"' EXIT
    cat > "$stub/timeout" <<'EOF'
#!/bin/sh
while [ $# -gt 0 ]; do
    case $1 in
        --signal=*|--kill-after=*) shift ;;
        --signal|--kill-after) shift 2 ;;
        -*) shift ;;
        *) break ;;
    esac
done
shift
exec "$@"
EOF
    cat > "$stub/sudo" <<'EOF'
#!/bin/sh
if [ "${1-}" = "-n" ] && [ "${2-}" = "true" ]; then exit 0; fi
[ "${1-}" = "-n" ] && shift
exec "$@"
EOF
    : > "$stub/observer"
    chmod +x "$stub/timeout" "$stub/sudo" "$stub/observer"
    cat > "$stub/kubectl" <<'EOF'
#!/bin/sh
case " $* " in
    *"containerStatuses[0].name"*)
        printf '%s' "$FETCH_NAME" ;;
    *"metadata.uid"*)
        printf '%s' "${FETCH_UID-}" ;;
    *"containerID"*)
        printf '%s' "containerd://abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" ;;
esac
EOF
    chmod +x "$stub/kubectl"

    # Evil cluster: the fetched name must be refused before the filter runs.
    status=0
    FETCH_NAME='x"]}.foo' PATH="$stub:$PATH" P11SCOPE_OBSERVER="$stub/observer" \
        sh "$0" --pod evil --namespace default >"$stub/evil.log" 2>&1 || status=$?
    [ "$status" -eq 1 ] || {
        echo "attach-pod exited $status (want 1) for a hostile fetched name" >&2
        exit 1
    }
    grep -q "DNS-1123" "$stub/evil.log" || {
        echo "hostile fetched name was not refused as a name:" >&2
        cat "$stub/evil.log" >&2
        exit 1
    }

    # Good cluster: fetch and validation pass, and the run fails later, at
    # the cgroup lookup that genuinely needs the node. The lookup runs against
    # an empty v2 tree so the refusal is deterministic on any host.
    mkdir -p "$stub/empty-cg"
    : > "$stub/empty-cg/cgroup.controllers"
    status=0
    FETCH_NAME='good-name' FETCH_UID='0123abcd-4567-89ef-0123-456789abcdef' \
        PATH="$stub:$PATH" P11SCOPE_OBSERVER="$stub/observer" \
        P11SCOPE_CGROUP_ROOT="$stub/empty-cg" \
        sh "$0" --pod good --namespace default >"$stub/good.log" 2>&1 || status=$?
    [ "$status" -eq 1 ] || {
        echo "attach-pod exited $status (want 1) for a good fetched name" >&2
        exit 1
    }
    grep -q "could not locate the pod cgroup" "$stub/good.log" || {
        echo "good fetched name did not reach the cgroup lookup:" >&2
        cat "$stub/good.log" >&2
        exit 1
    }
    rm -rf "$stub"
    trap - EXIT
}

# The scope-selection regression (Sol-full F1): a foreign subtree with a
# colliding container scope name must neither hijack the observation scope
# nor block the real pod, and two valid matches must be refused loudly. The
# script runs end to end against a fabricated cgroup tree; P11SCOPE_CGROUP_ROOT
# reaches the resolver only through the stub sudo below, while production sudo
# drops it, so a real run always resolves against the node's own hierarchy.
resolve_self_test() {
    stub=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-attach-resolve-XXXXXX")
    trap 'rm -rf "$stub"' EXIT
    cat > "$stub/timeout" <<'EOF'
#!/bin/sh
while [ $# -gt 0 ]; do
    case $1 in
        --signal=*|--kill-after=*) shift ;;
        --signal|--kill-after) shift 2 ;;
        -*) shift ;;
        *) break ;;
    esac
done
shift
exec "$@"
EOF
    cat > "$stub/sudo" <<'EOF'
#!/bin/sh
[ "${1-}" = "-n" ] && shift
exec "$@"
EOF
    cat > "$stub/kubectl" <<'EOF'
#!/bin/sh
case " $* " in
    *"containerStatuses[0].name"*)
        printf '%s' "good-name" ;;
    *"metadata.uid"*)
        printf '%s' "$FETCH_UID" ;;
    *"containerID"*)
        printf '%s' "containerd://$FETCH_CID" ;;
esac
EOF
    cat > "$stub/observer" <<EOF
#!/bin/sh
printf '%s\n' "\$@" > "$stub/argv"
exit 0
EOF
    chmod +x "$stub/timeout" "$stub/sudo" "$stub/kubectl" "$stub/observer"
    cid=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    uid=0123abcd-4567-89ef-0123-456789abcdef
    u2=99999999-8888-7777-6666-555555555555
    u3=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    u_=$(printf '%s' "$uid" | tr '-' '_')
    u2_=$(printf '%s' "$u2" | tr '-' '_')
    real=$stub/cg/kubepods.slice/kubepods-pod${u_}.slice
    # The foreign subtree is created first so an unanchored traversal meets it
    # first, exactly the hijack shape.
    mkdir -p "$stub/cg/aaa-foreign.slice/cri-containerd-$cid.scope"
    mkdir -p "$real/cri-containerd-$cid.scope"
    : > "$stub/cg/cgroup.controllers"
    run_case() {
        rc_uid=$1
        rc_status=0
        FETCH_UID=$rc_uid FETCH_CID=$cid PATH="$stub:$PATH" \
            P11SCOPE_OBSERVER="$stub/observer" P11SCOPE_CGROUP_ROOT="$stub/cg" \
            sh "$0" --pod good --namespace default -- --mode metrics \
            >"$stub/$2.log" 2>&1 || rc_status=$?
        printf '%s' "$rc_status"
    }
    # Collision: the foreign decoy is reported and ignored, the real pod is
    # selected exactly.
    status=$(run_case "$uid" ok)
    [ "$status" -eq 0 ] || {
        echo "attach-pod exited $status (want 0) with a foreign decoy present" >&2
        cat "$stub/ok.log" >&2
        exit 1
    }
    selected=$(grep -A1 -- '--cgroup' "$stub/argv" | tail -1)
    [ "$selected" = "$real" ] || {
        echo "attach-pod selected [$selected] (want [$real])" >&2
        exit 1
    }
    grep -q "ignored 1 match" "$stub/ok.log" || {
        echo "foreign decoy was not reported:" >&2
        cat "$stub/ok.log" >&2
        exit 1
    }
    # Disambiguation: the same container id under another pod's valid path
    # does not disturb the UID-bound selection.
    mkdir -p "$stub/cg/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod${u2_}.slice/cri-containerd-$cid.scope"
    status=$(run_case "$uid" disamb)
    [ "$status" -eq 0 ] || {
        echo "attach-pod exited $status (want 0) for a uid-bound container id" >&2
        cat "$stub/disamb.log" >&2
        exit 1
    }
    selected=$(grep -A1 -- '--cgroup' "$stub/argv" | tail -1)
    [ "$selected" = "$real" ] || {
        echo "attach-pod selected [$selected] (want [$real])" >&2
        exit 1
    }
    # Ambiguity: the requested UID itself matching two valid pod cgroups is
    # refused loudly, never guessed.
    mkdir -p "$stub/cg/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod${u_}.slice/cri-containerd-$cid.scope"
    status=$(run_case "$uid" amb)
    [ "$status" -eq 1 ] || {
        echo "attach-pod exited $status (want 1) for an ambiguous container id" >&2
        exit 1
    }
    grep -q "refusing" "$stub/amb.log" || {
        echo "ambiguous match was not refused loudly:" >&2
        cat "$stub/amb.log" >&2
        exit 1
    }
    # UID binding: the same container id under pods carrying other UIDs is not
    # the requested pod.
    status=$(run_case "$u3" mismatch)
    [ "$status" -eq 1 ] || {
        echo "attach-pod exited $status (want 1) for a uid mismatch" >&2
        exit 1
    }
    grep -q "could not locate the pod cgroup" "$stub/mismatch.log" || {
        echo "uid mismatch was not refused as absent:" >&2
        cat "$stub/mismatch.log" >&2
        exit 1
    }
    rm -rf "$stub"
    trap - EXIT
}

[ "${1-}" != "--self-test" ] || self_test

while [ "$#" -gt 0 ]; do
    case $1 in
        --namespace) [ "$#" -ge 2 ] || usage; NAMESPACE=$2; shift 2 ;;
        --pod) [ "$#" -ge 2 ] || usage; POD=$2; shift 2 ;;
        --container) [ "$#" -ge 2 ] || usage; CONTAINER=$2; shift 2 ;;
        --) shift; break ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

valid_name "$POD" || { echo "--pod must be a DNS-1123 name" >&2; usage; }
valid_name "$NAMESPACE" || { echo "--namespace must be a DNS-1123 name" >&2; usage; }
[ -z "$CONTAINER" ] || valid_name "$CONTAINER" || {
    echo "--container must be a DNS-1123 name" >&2
    usage
}

. scripts/lib.sh
require_non_root_caller
for command in kubectl timeout; do
    command -v "$command" >/dev/null || { echo "$command required" >&2; exit 1; }
done
sudo -n true 2>/dev/null || { echo "passwordless sudo required" >&2; exit 1; }
[ -x "$OBSERVER" ] || {
    echo "$OBSERVER is missing; build with: cargo +$(cat .release-rust-version) build --locked --release" >&2
    exit 1
}
case $OBSERVER in /*) ;; *) OBSERVER="$PWD/$OBSERVER" ;; esac

kube() {
    timeout --signal=TERM --kill-after=5s 60s kubectl -n "$NAMESPACE" "$@"
}

echo "=== resolve pod container and cgroup ===" >&2
if [ -z "$CONTAINER" ]; then
    CONTAINER=$(kube get pod "$POD" -o jsonpath='{.status.containerStatuses[0].name}')
    [ -n "$CONTAINER" ] || { echo "pod $POD has no running container" >&2; exit 1; }
    # A name from the cluster is no more trusted than one from argv: it is
    # interpolated into the JSONPath filter below, so it must be a DNS-1123
    # name before it gets there.
    valid_name "$CONTAINER" || {
        echo "pod $POD reported a container name that is not a DNS-1123 name" >&2
        exit 1
    }
fi
POD_UID=$(kube get pod "$POD" -o jsonpath='{.metadata.uid}')
[ -n "$POD_UID" ] || { echo "pod $POD has no uid" >&2; exit 1; }
# The UID travels to the resolver as an argv word (never interpolated), which
# also validates its shape and refuses a malformed one loudly.
CID_REF=$(kube get pod "$POD" \
    -o jsonpath="{.status.containerStatuses[?(@.name==\"$CONTAINER\")].containerID}")
case $CID_REF in
    containerd://*|cri-o://*|docker://*) ;;
    '') echo "container $CONTAINER in pod $POD has no container id" >&2; exit 1 ;;
    *) echo "unsupported container runtime reference: $CID_REF" >&2; exit 1 ;;
esac
CID=${CID_REF##*/}
case $CID in ''|*[!0-9a-f]*) echo "container id invalid: $CID_REF" >&2; exit 1 ;; esac

# The pod's cgroup is resolved on the node, not inside the container: with a
# cgroup namespace the pod's own /proc/self/cgroup reads "/" and names nothing.
# Resolution is the shared kubelet-anchored resolver from
# scripts/k8s-profile-entry.sh: the container's parent must be exactly one
# kubelet pod cgroup carrying this pod's UID. A foreign subtree with a
# colliding scope name is ignored (and reported), while ambiguity and absence
# are refused loudly; the wrapper never guesses a scope.
ENTRY=$PWD/scripts/k8s-profile-entry.sh
if ! POD_CG=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
        sh "$ENTRY" --print-pod-cgroup --pod-uid "$POD_UID" --cid "$CID"); then
    exit 1
fi
[ -n "$POD_CG" ] || { echo "pod cgroup resolution printed nothing" >&2; exit 1; }
echo "pod cgroup: $POD_CG" >&2

# Paths the operator typed (-o out.json) are relative to where they ran this,
# not to the repository root this script cd'd into.
cd "$INVOCATION_DIR"
exec sudo -n "$OBSERVER" profile --cgroup "$POD_CG" "$@"

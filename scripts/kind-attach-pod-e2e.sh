#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Cell K2: attach-pod.sh against a kind pod, from the kind node container.
#
# A private kind cluster runs the test-only workloads (deploy/k8s/e2e/
# workloads.yaml, ledger-a plus the idle negative control). The kind node
# container is provisioned for scripts/attach-pod.sh, run there verbatim: a
# non-root user with passwordless sudo (sudo itself is installed into the
# node, a recorded download), kubectl with API access, the static observer
# and the attach tree layout (scripts/ beside lib.sh, the observer where
# attach-pod.sh looks). Legs, all through kind-e2e-oracle.py with
# --expect-observer nested (the node is a container, so the observer is
# always in a nested PID namespace):
#   primary  attach to ledger-a, release its gate from the node (never
#            kubectl/docker exec into the captured pod: runc exec stages
#            count as pid_descendant_gaps), count exactly 6x400
#   negative attach to idle: no module, no call, with a visibility line
#            from k8s-profile-entry proving the pod was seen
#   scan     attach to idle, then exec a ledger run inside it (the provider
#            is mapped AFTER attach): the late provider must not be silently
#            zero -- either discovered-live with a named pre-attach gap, or
#            absent-with-disclosure. runc exec stages are excluded from the
#            disclosure set, and the twin fails if the exec artifacts are the
#            only gap.
#
# The CONTROLLER runs every docker/kind/kubectl command below. Workers only run
# `sh $0 --self-test`, which is unprivileged (PATH stubs) and proves the arg
# refusals, the pins, the private kubeconfig, the cleanup trap and the oracle
# hooks.
set -eu
cd "$(dirname "$0")/.."

ORACLE=scripts/kind-e2e-oracle.py
HOLDER_DOCKERFILE=deploy/Dockerfile.holder
# Pinned base reused from deploy/Dockerfile.holder (both FROM lines); the
# self-test requires the Dockerfile to carry exactly this digest twice.
HOLDER_BASE=ubuntu:26.04@sha256:3595d7fc4286a33fad0fd853a4063e654287a9c3787437d7937c94ca3f7a804e
WORKLOADS=deploy/k8s/e2e/workloads.yaml
WL_NS=p11scope-e2e
K2_USER=p11k2
K2_ROOT=/opt/k2
# kind's node container exports KUBECONFIG=/etc/kubernetes/admin.conf, which
# only root can read; the caller's kubectl runs name the caller's own copy.
K2_KUBECONFIG=/home/p11k2/.kube/config
ITERS_A_DEFAULT=400
ITERS_SCAN_DEFAULT=250
DURATION_DEFAULT=30
NEG_DURATION_DEFAULT=5
# The scan twin covers an exec'd token init plus a 250-iteration ledger.
SCAN_DURATION_DEFAULT=90

usage() {
    cat >&2 <<'EOF'
usage: scripts/kind-attach-pod-e2e.sh --observer BIN [options]
       scripts/kind-attach-pod-e2e.sh --self-test | --help

  Cell K2 driver. Private kind cluster + holder image + test workloads,
  node provisioned for attach-pod.sh, then the primary (ledger-a exact),
  negative (idle) and scan-limit (late provider) legs, all checked with
  scripts/kind-e2e-oracle.py --expect-observer nested.

  --observer BIN        static x86-64 p11scope binary, copied into the node
                        (reuse the K1 build target/x86_64-unknown-linux-musl/release/p11scope)
  --token TOKEN         run token, short [a-z0-9-] (default <time>-<pid>)
  --duration S          primary capture seconds (default 30)
  --node-image IMG      kind node image (default: kind's own; recorded)
  --work DIR            evidence directory (must not exist; default fresh 0700
                        under $TMPDIR)
  --keep                keep the cluster and images for debugging (prints the
                        delete commands)
  --self-test           unprivileged checks (PATH stubs, no docker/kind/kubectl)
  --help                this text

Exit codes: 0 PASS, 1 FAIL, 2 usage, 3 UNRUN (cell not run, see SUMMARY reason).
Every run prints a final SUMMARY line: SUMMARY cell=K2 verdict=... reason="...".

CONTROLLER (from the repo root; BIN = the K1-built static binary):
  sh scripts/kind-attach-pod-e2e.sh --observer BIN --token <TOKEN>
EOF
    exit 2
}

valid_token() {
    case $1 in
        ''|*[!a-z0-9-]*|-*|*-) return 1 ;;
        *) [ "${#1}" -le 40 ] ;;
    esac
}

valid_count() {
    case $1 in
        ''|*[!0-9]*|0*) return 1 ;;
        *) [ "${#1}" -le 7 ] ;;
    esac
}

self_test() {
    [ "$#" -eq 0 ] || usage
    command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }
    # The Dockerfile pin this cell reuses: both stages, exactly this digest.
    [ "$(grep -c "FROM $HOLDER_BASE" "$HOLDER_DOCKERFILE")" -eq 2 ] \
        || { echo "holder base pin drifted" >&2; exit 1; }
    [ "$(grep -c 'image: p11scope-holder:1$' "$WORKLOADS")" -eq 6 ] \
        || { echo "workloads.yaml lost an image anchor" >&2; exit 1; }
    for tree_file in scripts/attach-pod.sh scripts/k8s-profile-entry.sh \
                     scripts/lib.sh .release-rust-version; do
        [ -f "$tree_file" ] || { echo "node tree file missing: $tree_file" >&2; exit 1; }
    done
    [ "$ITERS_A_DEFAULT" -eq 400 ] && [ "$ITERS_SCAN_DEFAULT" -eq 250 ] \
        || { echo "ledger defaults drifted" >&2; exit 1; }
    for bad in "" "--observer" "--observer /nonexistent" \
               "--observer /bin/true --observer /bin/true" \
               "--observer /bin/true --token" \
               "--observer /bin/true --token UPPER" \
               "--observer /bin/true --token -x" \
               "--observer /bin/true --token $(printf 'a%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41)" \
               "--observer /bin/true --duration 0" \
               "--observer /bin/true --duration 01" \
               "--observer /bin/true --duration x" \
               "--observer /bin/true --node-image" \
               "--observer /bin/true --work /tmp --work /tmp" \
               "--bogus" "--keep --bogus" "--self-test extra"; do
        status=0
        # shellcheck disable=SC2086
        sh "$0" $bad >/dev/null 2>&1 || status=$?
        [ "$status" -eq 2 ] || {
            echo "k2 driver exited $status (want 2) for: [$bad]" >&2
            exit 1
        }
    done
    k2_help_self_test
    python3 -I "$ORACLE" --self-test
    k2_stub_self_test
    echo "kind-attach-pod-e2e self-test: OK"
    exit 0
}

k2_help_self_test() {
    help=$(sh "$0" --help 2>&1 || true)
    for marker in "--observer BIN" "kind-attach-pod-e2e.sh --observer" \
                  "SUMMARY cell=K2"; do
        case $help in
            *"$marker"*) ;;
            *) echo "help lost its controller line: $marker" >&2; exit 1 ;;
        esac
    done
}

# Every docker/kind/kubectl/timeout call below is a PATH stub: no daemon, no
# network, no cluster. STUB_CALLS records each call; STUB_FAIL names one
# substring whose call fails; the STUB_*_CANNED vars shape the answers.
k2_stub_self_test() {
    stub=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-k2-stub-XXXXXX")
    # shellcheck disable=SC2064
    trap "rm -rf '$stub'" EXIT
    : > "$stub/observer"
    chmod +x "$stub/observer"
    mkdir -p "$stub/work"
    : > "$stub/work/facts.log"
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
    cat > "$stub/docker" <<'EOF'
#!/bin/sh
printf '%s\n' "docker $*" >> "$STUB_CALLS"
if [ -n "${STUB_FAIL-}" ]; then
    case "$*" in *"$STUB_FAIL"*) exit 1 ;; esac
fi
case " $* " in
    *" dpkg-query "*) printf '%s\n' "1.9.16p2-1" ;;
    *" kubectl version --client"*) printf '%s\n' "Client Version: v0.0.0-stub" ;;
    *" command -v kubectl "*) [ "${STUB_NODE_KUBECTL-1}" = 1 ]; exit $? ;;
    *" crictl inspect "*) printf '%s\n' "${STUB_NODE_PID-1234}" ;;
    *" exec node-stub cat /tmp/"*)
        [ -n "${STUB_NODE_FILE-}" ] || exit 1
        printf '%s\n' "$STUB_NODE_FILE" ;;
    *"{{.Driver}} {{.ServerVersion}}"*) printf '%s\n' "overlayfs 29.8.1" ;;
    *"{{.CgroupDriver}}"*) printf '%s\n' "systemd" ;;
    *"{{.DockerRootDir}}"*) printf '%s\n' "/var/lib/docker" ;;
    *"{{.Config.Image}}"*) printf '%s\n' "kindest/node:stub" ;;
    *"{{.Image}}"*) printf '%s\n' "sha256:node-image-id-stub" ;;
    *"{{.RepoDigests}}"*) printf '%s\n' "[kindest/node@sha256:stubdigest]" ;;
    *"{{.Id}}"*) printf '%s\n' "sha256:holder-id-stub" ;;
    *" build "*) printf '%s\n' "sha256:build-id-stub" ;;
esac
exit 0
EOF
    cat > "$stub/kind" <<'EOF'
#!/bin/sh
printf '%s\n' "kind $*" >> "$STUB_CALLS"
if [ -n "${STUB_FAIL-}" ]; then
    case "$*" in *"$STUB_FAIL"*) exit 1 ;; esac
fi
case " $* " in
    " get clusters "*) printf '%s\n' "${STUB_CLUSTERS-}" ;;
    " get nodes "*) printf '%s\n' "${STUB_NODES-}" ;;
esac
exit 0
EOF
    cat > "$stub/kubectl" <<'EOF'
#!/bin/sh
printf '%s\n' "kubectl $*" >> "$STUB_CALLS"
if [ -n "${STUB_FAIL-}" ]; then
    case "$*" in *"$STUB_FAIL"*) exit 1 ;; esac
fi
case " $* " in
    *" version --client"*) printf '%s\n' "Client Version: v0.0.0-stub" ;;
    *" logs "*) printf '%s\n' "${STUB_LOGS-}" ;;
    *containerStatuses\[0\].containerID*) printf '%s' "${STUB_CID-}" ;;
    *metadata.uid*) printf '%s' "${STUB_UID-}" ;;
esac
exit 0
EOF
    cat > "$stub/oracle" <<'EOF'
#!/usr/bin/env python3
import os
import sys
with open(os.environ["STUB_CALLS"], "a", encoding="utf-8") as handle:
    handle.write(" ".join(sys.argv[1:]) + "\n")
print('{"check":"stub","ok":true}')
sys.exit(int(os.environ["STUB_ORACLE_STATUS"]))
EOF
    chmod +x "$stub/timeout" "$stub/docker" "$stub/kind" "$stub/kubectl" "$stub/oracle"
    : > "$stub/calls.txt"
    # kc as the run path defines it, against the stubs.
    kc() {
        timeout --signal=TERM --kill-after=10s 300s kubectl "$@"
    }

    # A cluster of our name is refused before anything is created or deleted.
    if STUB_CLUSTERS="p11scope-k2-t" STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" \
            assert_cluster_free p11scope-k2-t >/dev/null 2>&1; then
        echo "existing cluster name accepted" >&2
        exit 1
    fi
    STUB_CLUSTERS="other" STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" \
        assert_cluster_free p11scope-k2-t \
        || { echo "free cluster name refused" >&2; exit 1; }
    # Exactly one node, never zero or two.
    got=$(CLUSTER=p11scope-k2-t STUB_NODES="p11scope-k2-t-control-plane" \
        STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" node_name) \
        || { echo "single node refused" >&2; exit 1; }
    [ "$got" = "p11scope-k2-t-control-plane" ] || { echo "node resolved to $got" >&2; exit 1; }
    for nodes in "" "n1
n2"; do
        if CLUSTER=p11scope-k2-t STUB_NODES="$nodes" STUB_CALLS=$stub/calls.txt \
                PATH="$stub:$PATH" node_name >/dev/null 2>&1; then
            echo "bad node list accepted: [$nodes]" >&2
            exit 1
        fi
    done
    # Tool facts record every version line the harness contract names.
    : > "$stub/calls.txt"
    WORK=$stub/work FACTS=$stub/work/facts.log STUB_CALLS=$stub/calls.txt \
        PATH="$stub:$PATH" record_tool_facts \
        || { echo "tool facts refused" >&2; exit 1; }
    for marker in "kind-version=" "kubectl-version=Client Version" \
                  "docker-info=overlayfs 29.8.1" "cgroup-driver=systemd" \
                  "docker-root=/var/lib/docker" "kernel="; do
        grep -q "$marker" "$stub/work/facts.log" \
            || { echo "facts lost: $marker" >&2; exit 1; }
    done
    if STUB_FAIL="version" WORK=$stub/work FACTS=$stub/work/facts.log \
            STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" \
            record_tool_facts >/dev/null 2>&1; then
        echo "failed tool facts accepted" >&2
        exit 1
    fi
    # Clear the failure hook: a leftover STUB_FAIL would refuse later stub calls.
    STUB_FAIL=
    # Node facts record the kind node image digest the harness contract names.
    WORK=$stub/work FACTS=$stub/work/facts.log NODE=node-stub \
        STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" record_node_facts \
        || { echo "node facts refused" >&2; exit 1; }
    grep -Fq "node=node-stub image-ref=kindest/node:stub image-id=sha256:node-image-id-stub repo-digests=[kindest/node@sha256:stubdigest]" "$stub/work/facts.log" \
        || { echo "node image digest not recorded" >&2; exit 1; }
    if WORK=$stub/work FACTS=$stub/work/facts.log NODE=node-stub STUB_FAIL="inspect" \
            STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" \
            record_node_facts >/dev/null 2>&1; then
        echo "failed node facts accepted" >&2
        exit 1
    fi
    STUB_FAIL=
    # The holder build stages the K1 context and records the image id.
    : > "$stub/calls.txt"
    WORK=$stub/work FACTS=$stub/work/facts.log HOLD_IMAGE=img:t \
        STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" build_holder >/dev/null \
        || { echo "holder build refused" >&2; exit 1; }
    grep -q "docker build -q -f deploy/Dockerfile.holder -t img:t" "$stub/calls.txt" \
        || { echo "holder build argv drifted" >&2; exit 1; }
    grep -q "holder-image=img:t id=sha256:holder-id-stub" "$stub/work/facts.log" \
        || { echo "holder image id not recorded" >&2; exit 1; }
    [ -f "$stub/work/context-holder/tests/fixtures/public-cli/gated.c" ] \
        || { echo "holder context lost gated.c" >&2; exit 1; }
    [ -f "$stub/work/context-holder/deploy/holder-entry.sh" ] \
        || { echo "holder context lost holder-entry.sh" >&2; exit 1; }
    if WORK=$stub/work FACTS=$stub/work/facts.log HOLD_IMAGE=img:t STUB_FAIL="build" \
            STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" build_holder >/dev/null 2>&1; then
        echo "failed holder build accepted" >&2
        exit 1
    fi
    STUB_FAIL=

    k2_provision_self_test "$stub"
    k2_capture_self_test "$stub"
    k2_oracle_self_test "$stub"
    k2_scan_self_test "$stub"
    k2_cleanup_self_test "$stub"
    rm -rf "$stub"
    trap - EXIT
}

# Node provisioning replays end to end against the stubs: the user, the sudo
# download, the sudoers file, kubectl both present and missing, the
# kubeconfig, and the attach tree layout.
k2_provision_self_test() {
    pst_stub=$1
    : > "$pst_stub/calls.txt"
    WORK=$pst_stub/work FACTS=$pst_stub/work/facts.log NODE=node-stub \
        OBSERVER=$pst_stub/observer STUB_NODE_KUBECTL=1 STUB_CALLS=$pst_stub/calls.txt \
        PATH="$pst_stub:$PATH" provision_node \
        || { echo "provisioning refused" >&2; exit 1; }
    for marker in "useradd -m -s /bin/sh p11k2" "apt-get install -y sudo" \
                  "/etc/sudoers.d/p11k2" "chmod 440" "sudo -n true" \
                  "admin.conf" "wait --for=condition=Ready" \
                  "get pod ledger-a" \
                  "/opt/k2/scripts/attach-pod.sh" "/opt/k2/scripts/lib.sh" \
                  "/opt/k2/target/release/p11scope"; do
        grep -q "$marker" "$pst_stub/calls.txt" \
            || { echo "provisioning lost: $marker" >&2; exit 1; }
    done
    # kind's node container exports KUBECONFIG=/etc/kubernetes/admin.conf
    # (root-only), so every kubectl the caller runs must name its own copy:
    # the default-config probe and attach-pod.sh both get it explicitly.
    grep -q "docker exec -u p11k2 -e KUBECONFIG=/home/p11k2/.kube/config node-stub kubectl -n p11scope-e2e get pod ledger-a" \
        "$pst_stub/calls.txt" \
        || { echo "default-config probe inherits the node's root-only KUBECONFIG" >&2; exit 1; }
    : > "$pst_stub/calls.txt"
    WORK=$pst_stub/work NODE=node-stub STUB_CALLS=$pst_stub/calls.txt PATH="$pst_stub:$PATH" \
        start_attach k2-t ledger-a 5 /tmp/k2-t.json
    wait "$STARTED_PID" || { echo "stubbed attach failed" >&2; exit 1; }
    grep -q "docker exec -u p11k2 -e KUBECONFIG=/home/p11k2/.kube/config -w /opt/k2 node-stub sh /opt/k2/scripts/attach-pod.sh" \
        "$pst_stub/calls.txt" \
        || { echo "attach-pod.sh inherits the node's root-only KUBECONFIG" >&2; exit 1; }
    grep -q "node-sudo-version=1.9.16p2-1" "$pst_stub/work/facts.log" \
        || { echo "sudo download version not recorded" >&2; exit 1; }
    grep -q "node-kubectl=Client Version: v0.0.0-stub (node image)" "$pst_stub/work/facts.log" \
        || { echo "node kubectl version not recorded" >&2; exit 1; }
    if grep -q "docker cp .*/usr/local/bin/kubectl" "$pst_stub/calls.txt"; then
        echo "present node kubectl was overwritten" >&2
        exit 1
    fi
    # Missing node kubectl: the host's is copied in and recorded.
    : > "$pst_stub/calls.txt"
    WORK=$pst_stub/work FACTS=$pst_stub/work/facts.log NODE=node-stub \
        OBSERVER=$pst_stub/observer STUB_NODE_KUBECTL=0 STUB_CALLS=$pst_stub/calls.txt \
        PATH="$pst_stub:$PATH" provision_node \
        || { echo "provisioning without node kubectl refused" >&2; exit 1; }
    grep -q "docker cp .*/usr/local/bin/kubectl" "$pst_stub/calls.txt" \
        || { echo "missing node kubectl was not copied in" >&2; exit 1; }
    grep -q "(copied from host" "$pst_stub/work/facts.log" \
        || { echo "copied kubectl not recorded" >&2; exit 1; }
    # Each provisioning step fails the run, never skipped silently.
    for step in useradd "apt-get" "sudoers.d" "sudo -n true" "admin.conf" \
                "condition=Ready" "attach-pod.sh"; do
        if WORK=$pst_stub/work FACTS=$pst_stub/work/facts.log NODE=node-stub \
                OBSERVER=$pst_stub/observer STUB_NODE_KUBECTL=1 STUB_FAIL="$step" \
                STUB_CALLS=$pst_stub/calls.txt PATH="$pst_stub:$PATH" provision_node \
                >/dev/null 2>&1; then
            echo "failed provisioning step accepted: $step" >&2
            exit 1
        fi
    done
    STUB_FAIL=
}

# Capture waiters, pod identity and the LEDGER rule, all without a cluster.
k2_capture_self_test() {
    cst_stub=$1
    # Profile readiness: the capture line only.
    printf '%s\n' 'pod cgroup: /sys/fs/cgroup/x' \
        'p11scope: capturing: 3 probe(s) attached; stop with Ctrl-C' > "$cst_stub/work/ready.err"
    WORK=$cst_stub/work wait_ready ready 999999 \
        || { echo "capture readiness missed" >&2; exit 1; }
    printf '%s\n' 'pod cgroup: /sys/fs/cgroup/x' > "$cst_stub/work/early.err"
    if WORK=$cst_stub/work wait_ready early 999999 >/dev/null 2>&1; then
        echo "readiness accepted without the capture line" >&2
        exit 1
    fi
    # Pod log waits through the stubbed kc.
    STUB_LOGS="READY pid=1
LEDGER good" STUB_CALLS=$cst_stub/calls.txt PATH="$cst_stub:$PATH" \
        wait_log ledger-a '^LEDGER ' 5 \
        || { echo "pod LEDGER wait missed" >&2; exit 1; }
    if STUB_LOGS="READY pid=1" STUB_CALLS=$cst_stub/calls.txt PATH="$cst_stub:$PATH" \
            wait_log ledger-a '^LEDGER ' 1 >/dev/null 2>&1; then
        echo "absent LEDGER waited out as present" >&2
        exit 1
    fi
    # Report fetch: kind mounts the node's /tmp as tmpfs, which `docker cp`
    # cannot read, so the report is streamed out with `docker exec cat`; a
    # missing or empty report fails the capture.
    : > "$cst_stub/calls.txt"
    (sleep 0 &
     STUB_NODE_FILE='{"schema":"stub"}' WORK=$cst_stub/work NODE=node-stub \
        STUB_CALLS=$cst_stub/calls.txt PATH="$cst_stub:$PATH" \
        finish_attach fetch /tmp/k2-fetch.json "$cst_stub/work/k2-fetch.json" $!) \
        || { echo "report fetch refused" >&2; exit 1; }
    [ "$(cat "$cst_stub/work/k2-fetch.json")" = '{"schema":"stub"}' ] \
        || { echo "report fetch lost the node report" >&2; exit 1; }
    for fetch_bad in "" " "; do
        rm -f "$cst_stub/work/k2-fetch-bad.json"
        if (sleep 0 &
            STUB_NODE_FILE=$fetch_bad WORK=$cst_stub/work NODE=node-stub \
                STUB_CALLS=$cst_stub/calls.txt PATH="$cst_stub:$PATH" \
                finish_attach fetch /tmp/k2-fetch.json "$cst_stub/work/k2-fetch-bad.json" $!) \
                >/dev/null 2>&1; then
            echo "missing or empty node report accepted: '$fetch_bad'" >&2
            exit 1
        fi
    done
    # Pod identity: the container id reaches crictl on the node, and a
    # malformed id or uid is refused before it gets there.
    cst_cid=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    : > "$cst_stub/calls.txt"
    got=$(STUB_CID="containerd://$cst_cid" STUB_NODE_PID=4321 NODE=node-stub \
        STUB_CALLS=$cst_stub/calls.txt PATH="$cst_stub:$PATH" node_pid ledger-a) \
        || { echo "node pid refused" >&2; exit 1; }
    [ "$got" = 4321 ] || { echo "node pid resolved to $got" >&2; exit 1; }
    grep -q "crictl inspect .* $cst_cid" "$cst_stub/calls.txt" \
        || { echo "container id never reached crictl" >&2; exit 1; }
    for bad_cid in "" "containerd://xyz" "docker://$cst_cid"; do
        if STUB_CID="$bad_cid" NODE=node-stub STUB_CALLS=$cst_stub/calls.txt \
                PATH="$cst_stub:$PATH" node_pid ledger-a >/dev/null 2>&1; then
            echo "bad container id accepted: $bad_cid" >&2
            exit 1
        fi
    done
    # Gate release: from the node through /proc/<pid>/root, never exec
    # into a captured pod; a failed release fails the run.
    : > "$cst_stub/calls.txt"
    STUB_CID="containerd://$cst_cid" STUB_NODE_PID=4321 NODE=node-stub \
        STUB_CALLS=$cst_stub/calls.txt PATH="$cst_stub:$PATH" release_pod ledger-a \
        || { echo "gate release refused" >&2; exit 1; }
    grep -q "touch /proc/4321/root/tmp/gate" "$cst_stub/calls.txt" \
        || { echo "gate release missed the node path" >&2; exit 1; }
    if grep "kubectl " "$cst_stub/calls.txt" | grep -q "touch"; then
        echo "gate release touched through the pod" >&2
        exit 1
    fi
    if STUB_CID="containerd://$cst_cid" STUB_NODE_PID=4321 NODE=node-stub \
            STUB_FAIL="touch" STUB_CALLS=$cst_stub/calls.txt \
            PATH="$cst_stub:$PATH" release_pod ledger-a >/dev/null 2>&1; then
        echo "failed gate release accepted" >&2
        exit 1
    fi
    STUB_FAIL=
    cst_uid=0123abcd-4567-89ef-0123-456789abcdef
    got=$(STUB_UID="$cst_uid" STUB_CALLS=$cst_stub/calls.txt PATH="$cst_stub:$PATH" \
        pod_uid idle) || { echo "pod uid refused" >&2; exit 1; }
    [ "$got" = "$cst_uid" ] || { echo "pod uid resolved to $got" >&2; exit 1; }
    for bad_uid in "" "UPPER" "01_23"; do
        if STUB_UID="$bad_uid" STUB_CALLS=$cst_stub/calls.txt PATH="$cst_stub:$PATH" \
                pod_uid idle >/dev/null 2>&1; then
            echo "bad pod uid accepted: $bad_uid" >&2
            exit 1
        fi
    done
    # LEDGER lines: exactly one complete JSON ledger with 6xN successes.
    printf '%s\n' 'READY pid=1' \
        'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":1,"complete":true,"functions":[{"name":"C_GenerateRandom","attempts":400,"successful":400},{"name":"C_DigestInit","attempts":400,"successful":400},{"name":"C_Digest","attempts":400,"successful":400},{"name":"C_FindObjectsInit","attempts":400,"successful":400},{"name":"C_FindObjects","attempts":400,"successful":400},{"name":"C_FindObjectsFinal","attempts":400,"successful":400}]}' \
        > "$cst_stub/good.log"
    PATH="$cst_stub:$PATH" ledger_check "$cst_stub/good.log" 400 \
        || { echo "good LEDGER refused" >&2; exit 1; }
    printf '%s\n' 'READY pid=1' 'LEDGER iterations=400 nonzero_rv=0' > "$cst_stub/legacy.log"
    printf '%s\n' 'READY pid=1' 'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":1,"complete":false,"functions":[{"name":"C_GenerateRandom","attempts":400,"successful":400},{"name":"C_DigestInit","attempts":400,"successful":400},{"name":"C_Digest","attempts":400,"successful":400},{"name":"C_FindObjectsInit","attempts":400,"successful":400},{"name":"C_FindObjects","attempts":400,"successful":400},{"name":"C_FindObjectsFinal","attempts":400,"successful":400}]}' \
        > "$cst_stub/incomplete.log"
    printf '%s\n' 'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":1,"complete":true,"functions":[{"name":"C_GenerateRandom","attempts":399,"successful":399}]}' \
        > "$cst_stub/short.log"
    printf '%s\n' 'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":1,"complete":true,"functions":[{"name":"C_GenerateRandom","attempts":400,"successful":399},{"name":"C_DigestInit","attempts":400,"successful":400},{"name":"C_Digest","attempts":400,"successful":400},{"name":"C_FindObjectsInit","attempts":400,"successful":400},{"name":"C_FindObjects","attempts":400,"successful":400},{"name":"C_FindObjectsFinal","attempts":400,"successful":400}]}' \
        > "$cst_stub/failed.log"
    printf '%s\n' 'READY pid=1' > "$cst_stub/missing.log"
    for bad in legacy incomplete short failed missing; do
        if PATH="$cst_stub:$PATH" ledger_check "$cst_stub/$bad.log" 400 >/dev/null 2>&1; then
            echo "bad LEDGER accepted: $bad" >&2
            exit 1
        fi
    done
}

# The oracle hooks: the exact subcommand argv the legs use, and an oracle
# refusal fails the leg.
k2_oracle_self_test() {
    ost_stub=$1
    : > "$ost_stub/calls.txt"
    ORACLE=$ost_stub/oracle STUB_ORACLE_STATUS=0 STUB_CALLS=$ost_stub/calls.txt \
        oracle_profile "$ost_stub/k2.json" 400 >/dev/null \
        || { echo "profile hook refused" >&2; exit 1; }
    ORACLE=$ost_stub/oracle STUB_ORACLE_STATUS=0 STUB_CALLS=$ost_stub/calls.txt \
        oracle_negative "$ost_stub/k2-negative.json" "$ost_stub/doctor.err" >/dev/null \
        || { echo "negative hook refused" >&2; exit 1; }
    grep -q -- "--expect-observer nested profile-exact $ost_stub/k2.json 400" "$ost_stub/calls.txt" \
        || { echo "profile hook argv drifted" >&2; exit 1; }
    grep -q -- "--expect-observer nested negative $ost_stub/k2-negative.json $ost_stub/doctor.err" \
        "$ost_stub/calls.txt" || { echo "negative hook argv drifted" >&2; exit 1; }
    if ORACLE=$ost_stub/oracle STUB_ORACLE_STATUS=1 STUB_CALLS=$ost_stub/calls.txt \
            oracle_profile "$ost_stub/k2.json" 400 >/dev/null 2>&1; then
        echo "refusing profile oracle accepted" >&2
        exit 1
    fi
    if ORACLE=$ost_stub/oracle STUB_ORACLE_STATUS=1 STUB_CALLS=$ost_stub/calls.txt \
            oracle_negative "$ost_stub/k2-negative.json" "$ost_stub/doctor.err" >/dev/null 2>&1; then
        echo "refusing negative oracle accepted" >&2
        exit 1
    fi
}

# The scan-limit rule: the scan leg's report is judged against its own
# LEDGER line. Each ledger function must count exactly its LEDGER
# successful value (leg counted-exact, whatever the disclosure causes) or
# zero with a named disclosure for the miss (legs absent/attached-zero);
# loss, partial counts and silent zeros fail. The run3/run4 fixtures copy
# the live shapes (single vs doubled function tables, setup calls,
# causes); unknown causes are recorded, never gated.
k2_scan_self_test() {
    sst_stub=$1
    # The scan exec log the check reads the LEDGER line from: READY plus
    # one LEDGER line with the six gated.c functions at $2 successful each
    # ($2 = missing writes no LEDGER line; $3 = complete flag).
    scan_exec() {
        printf 'READY pid=14\n' >"$sst_stub/$1.log"
        if [ "$2" = "missing" ]; then
            return 0
        fi
        se_fns=""
        for name in C_GenerateRandom C_DigestInit C_Digest C_FindObjectsInit C_FindObjects C_FindObjectsFinal; do
            se_fns="$se_fns{\"name\":\"$name\",\"attempts\":$2,\"successful\":$2},"
        done
        se_fns=${se_fns%,}
        printf 'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":14,"complete":%s,"functions":[%s]}\n' \
            "${3-true}" "$se_fns" >>"$sst_stub/$1.log"
    }
    # $1 base, $2 causes JSON, $3 calls in every ledger row, $4 modules JSON.
    scan_fixture() {
        cat > "$sst_stub/$1.json" <<EOF
{"pid_namespace":{"observer":"nested","kernel_pids":"initial","proc_pids":"observer"},"evidence":{"verdict_detail":"concrete_gap","gap_classes":{"observation":{"causes":$2,"status":"lossy"}}},"capture":{"scope":"cgroup","modules":$4},"functions":[{"calls":$3,"errors":0,"names":["C_GenerateRandom"]},{"calls":$3,"errors":0,"names":["C_DigestInit"]},{"calls":$3,"errors":0,"names":["C_Digest"]},{"calls":$3,"errors":0,"names":["C_FindObjectsInit"]},{"calls":$3,"errors":0,"names":["C_FindObjects"]},{"calls":$3,"errors":0,"names":["C_FindObjectsFinal"]}]}
EOF
    }
    # scan_pass BASE EXEC WANT_LEG: the shape must pass with that leg.
    scan_pass() {
        sp_out=$(PATH="$sst_stub:$PATH" scan_limit_check "$sst_stub/$1.json" "$sst_stub/$2.log" 2>"$sst_stub/$1.err") \
            || { echo "scan shape refused: $1 ($(cat "$sst_stub/$1.err"))" >&2; exit 1; }
        sp_leg=$(printf '%s' "$sp_out" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["leg"])')
        if [ "$sp_leg" != "$3" ]; then
            echo "scan leg is $sp_leg, want $3: $1" >&2
            exit 1
        fi
    }
    # scan_fail BASE EXEC WANT_REASON: the shape must fail naming that reason.
    scan_fail() {
        if PATH="$sst_stub:$PATH" scan_limit_check "$sst_stub/$1.json" "$sst_stub/$2.log" >/dev/null 2>"$sst_stub/$1.err"; then
            echo "scan shape accepted: $1" >&2
            exit 1
        fi
        if ! grep -q -F "$3" "$sst_stub/$1.err"; then
            echo "scan failure misnamed (want [$3]): $1 ($(cat "$sst_stub/$1.err"))" >&2
            exit 1
        fi
    }
    sst_provider='[{"path":"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"}]'
    scan_exec exec250 250
    scan_exec exec100 100
    scan_exec execmissing missing
    scan_exec execincomplete 250 false
    # Live run 3: single table, 250 each, nested discovery skip + exec gaps.
    scan_fixture run3 '["skipped","pid_namespace","pid_descendant_gaps"]' 250 "$sst_provider"
    # Live run 4: doubled tables (setup calls plus zero ledger rows, then
    # 250 ledger rows), six causes. Counts must sum across the duplicate
    # rows; the 16 setup calls are reported, never subtracted.
    cat > "$sst_stub/run4.json" <<'EOF'
{"pid_namespace":{"observer":"nested","kernel_pids":"initial","proc_pids":"observer"},"evidence":{"verdict_detail":"concrete_gap","gap_classes":{"observation":{"causes":["skipped","pid_namespace","unprotected_live_windows","discovery_truncated","loader_discovery","pid_descendant_gaps"],"status":"lossy"}}},"capture":{"scope":"cgroup","modules":[{"path":"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"}]},"functions":[{"calls":2,"errors":0,"names":["C_Initialize"]},{"calls":2,"errors":0,"names":["C_Finalize"]},{"calls":1,"errors":0,"names":["C_GetFunctionList"]},{"calls":3,"errors":0,"names":["C_GetSlotList"]},{"calls":3,"errors":0,"names":["C_GetTokenInfo"]},{"calls":1,"errors":0,"names":["C_InitPIN"]},{"calls":2,"errors":0,"names":["C_OpenSession"]},{"calls":2,"errors":0,"names":["C_Login"]},{"calls":0,"errors":0,"names":["C_GenerateRandom"]},{"calls":0,"errors":0,"names":["C_DigestInit"]},{"calls":0,"errors":0,"names":["C_Digest"]},{"calls":0,"errors":0,"names":["C_FindObjectsInit"]},{"calls":0,"errors":0,"names":["C_FindObjects"]},{"calls":0,"errors":0,"names":["C_FindObjectsFinal"]},{"calls":250,"errors":0,"names":["C_GenerateRandom"]},{"calls":250,"errors":0,"names":["C_DigestInit"]},{"calls":250,"errors":0,"names":["C_Digest"]},{"calls":250,"errors":0,"names":["C_FindObjectsInit"]},{"calls":250,"errors":0,"names":["C_FindObjects"]},{"calls":250,"errors":0,"names":["C_FindObjectsFinal"]}]}
EOF
    # A burst split across the attach: three functions exact, three zero.
    cat > "$sst_stub/split.json" <<'EOF'
{"pid_namespace":{"observer":"nested","kernel_pids":"initial","proc_pids":"observer"},"evidence":{"verdict_detail":"concrete_gap","gap_classes":{"observation":{"causes":["pid_namespace","unprotected_live_windows"],"status":"lossy"}}},"capture":{"scope":"cgroup","modules":[{"path":"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"}]},"functions":[{"calls":250,"errors":0,"names":["C_GenerateRandom"]},{"calls":250,"errors":0,"names":["C_DigestInit"]},{"calls":250,"errors":0,"names":["C_Digest"]},{"calls":0,"errors":0,"names":["C_FindObjectsInit"]},{"calls":0,"errors":0,"names":["C_FindObjects"]},{"calls":0,"errors":0,"names":["C_FindObjectsFinal"]}]}
EOF
    scan_fixture live '["pid_namespace","unprotected_live_windows"]' 250 "$sst_provider"
    scan_fixture absent '["pid_namespace","pid_descendant_gaps","discovery","slots"]' 0 '[]'
    scan_fixture silent '["pid_namespace"]' 0 '[]'
    scan_fixture exec-only '["pid_namespace","pid_descendant_gaps"]' 0 '[]'
    scan_fixture silent-attached '["pid_namespace","pid_descendant_gaps"]' 0 "$sst_provider"
    scan_fixture attached-zero '["pid_namespace","unprotected_live_windows","skipped"]' 0 "$sst_provider"
    scan_fixture exact '["pid_namespace"]' 250 "$sst_provider"
    scan_fixture bogus '["pid_namespace","totally_bogus_future_cause"]' 250 "$sst_provider"
    scan_fixture partial '["pid_namespace"]' 100 "$sst_provider"
    scan_fixture ledgermismatch '["skipped","pid_namespace","pid_descendant_gaps"]' 250 "$sst_provider"
    scan_fixture ledger100 '["pid_namespace","skipped"]' 100 "$sst_provider"
    scan_fixture lossexact '["pid_namespace","event_loss"]' 250 "$sst_provider"
    scan_fixture losszero '["pid_namespace","event_loss"]' 0 '[]'
    scan_fixture nonumbering '["discovery"]' 0 '[]'
    scan_pass run4 exec250 counted-exact
    scan_pass run3 exec250 counted-exact
    scan_pass live exec250 counted-exact
    scan_pass exact exec250 counted-exact
    scan_pass bogus exec250 counted-exact
    scan_pass absent exec250 absent
    scan_pass attached-zero exec250 attached-zero
    scan_pass ledger100 exec100 counted-exact
    for cause in discovery slots unprotected_live_windows skipped; do
        scan_fixture "only-$cause" "[\"pid_namespace\",\"$cause\"]" 0 '[]'
        scan_pass "only-$cause" exec250 absent
    done
    for bad in silent exec-only silent-attached; do
        scan_fail "$bad" exec250 "late provider silently zero"
    done
    scan_fail partial exec250 "partial scan count"
    scan_fail split exec250 "partial scan count"
    scan_fail ledgermismatch exec100 "partial scan count"
    scan_fail lossexact exec250 "scan loss"
    scan_fail losszero exec250 "scan loss"
    # A nested capture without its pid_namespace cause is not this cell.
    scan_fail nonumbering exec250 "nested capture without its pid_namespace cause"
    # Without the scan leg's LEDGER line there is nothing to compare with.
    scan_fail run3 execmissing "scan ledger"
    scan_fail run3 execincomplete "scan ledger incomplete"
    # The run 4 verdict reports the ledger total plus the setup calls, never
    # subtracted: 1500 counted, 16 extra.
    rv4_out=$(PATH="$sst_stub:$PATH" scan_limit_check "$sst_stub/run4.json" "$sst_stub/exec250.log") \
        || { echo "run4 verdict refused" >&2; exit 1; }
    printf '%s' "$rv4_out" | python3 -I -c '
import json, sys
verdict = json.load(sys.stdin)
assert verdict["leg"] == "counted-exact", verdict
assert verdict["counted_calls"] == 1500, verdict
assert sum(verdict["extra_calls"].values()) == 16, verdict
assert verdict["extra_calls"]["C_Login"] == 2, verdict
assert verdict["errors"] == 0, verdict
assert verdict["modules"] == 1, verdict
assert set(verdict["ledger"]) == {"C_GenerateRandom", "C_DigestInit", "C_Digest", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal"}, verdict
assert set(verdict["ledger"].values()) == {250}, verdict
' || { echo "run4 verdict content wrong: $rv4_out" >&2; exit 1; }
}

# Cleanup deletes its own cluster and image, keeps nothing by default, and
# the --keep path prints the exact delete commands.
k2_cleanup_self_test() {
    dst_stub=$1
    : > "$dst_stub/calls.txt"
    CLUSTER=p11scope-k2-t KUBECONFIG=$dst_stub/work/kubeconfig CLUSTER_CREATED=1 \
        HOLD_IMAGE=img:t IMAGES_BUILT=1 STUB_CALLS=$dst_stub/calls.txt \
        PATH="$dst_stub:$PATH" delete_owned \
        || { echo "delete_owned failed" >&2; exit 1; }
    grep -q "kind delete cluster --name p11scope-k2-t" "$dst_stub/calls.txt" \
        || { echo "cleanup lost its cluster deletion" >&2; exit 1; }
    grep -q "docker image rm -f img:t" "$dst_stub/calls.txt" \
        || { echo "cleanup lost its image removal" >&2; exit 1; }
    # A run that died before the cluster existed still removes its image.
    : > "$dst_stub/calls.txt"
    CLUSTER=p11scope-k2-t KUBECONFIG=$dst_stub/work/kubeconfig CLUSTER_CREATED= \
        HOLD_IMAGE=img:t IMAGES_BUILT=1 STUB_CALLS=$dst_stub/calls.txt \
        PATH="$dst_stub:$PATH" delete_owned \
        || { echo "delete_owned failed" >&2; exit 1; }
    if grep -q "kind delete cluster" "$dst_stub/calls.txt"; then
        echo "cleanup deleted a cluster it never created" >&2
        exit 1
    fi
    grep -q "docker image rm -f img:t" "$dst_stub/calls.txt" \
        || { echo "cleanup lost its image removal" >&2; exit 1; }
    keep_out=$(CLUSTER=p11scope-k2-t KUBECONFIG=$dst_stub/work/kubeconfig CLUSTER_CREATED=1 \
        HOLD_IMAGE=img:t IMAGES_BUILT=1 keep_message 2>&1)
    case $keep_out in
        *"kind delete cluster --name p11scope-k2-t"*"docker image rm -f img:t"*) ;;
        *) echo "keep path lost its delete commands: $keep_out" >&2; exit 1 ;;
    esac
}

# ------------------------------------------------------------------ run path

say() {
    printf '%s\n' "$1"
}

fact() {
    printf '%s\n' "$1" >>"$FACTS"
}

summarize() {
    line="SUMMARY cell=K2 verdict=$1 reason=\"$2\""
    printf '%s\n' "$line"
    if [ -n "${FACTS-}" ]; then
        printf '%s\n' "$line" >>"$FACTS"
    fi
}

unrun() {
    summarize UNRUN "$1"
    exit 3
}

fail_cell() {
    summarize FAIL "$1"
    exit 1
}

record() {
    printf '%s\n' "$1" | tee -a "$SUMMARY_JSONL"
}

assert_cluster_free() {
    clusters=$(kind get clusters 2>/dev/null) \
        || { echo "kind get clusters failed" >&2; return 1; }
    if printf '%s\n' "$clusters" | grep -Fqx "$1"; then
        echo "kind cluster $1 already exists; refusing to reuse or delete it" >&2
        return 1
    fi
}

# The cluster's single node (single-node cluster, exactly one line).
node_name() {
    nodes=$(kind get nodes --name "$CLUSTER" 2>/dev/null) \
        || { echo "kind get nodes failed" >&2; return 1; }
    [ "$(printf '%s\n' "$nodes" | grep -c .)" -eq 1 ] \
        || { echo "want exactly one node, got: $nodes" >&2; return 1; }
    printf '%s\n' "$nodes"
}

record_tool_facts() {
    kv=$(kind version) || { echo "kind version failed" >&2; return 1; }
    fact "kind-version=$kv"
    cv=$(kubectl version --client) || { echo "kubectl version failed" >&2; return 1; }
    fact "kubectl-version=$cv"
    di=$(docker info --format '{{.Driver}} {{.ServerVersion}}') \
        || { echo "docker info failed" >&2; return 1; }
    fact "docker-info=$di"
    cg=$(docker info --format '{{.CgroupDriver}}') \
        || { echo "docker info failed" >&2; return 1; }
    fact "cgroup-driver=$cg"
    dr=$(docker info --format '{{.DockerRootDir}}') \
        || { echo "docker info failed" >&2; return 1; }
    fact "docker-root=$dr backing-fs=$(stat -f -c '%T' "$dr" 2>/dev/null)"
    fact "kernel=$(uname -sr) $(uname -m)"
}

record_node_facts() {
    NODE_IMAGE_REF=$(docker inspect "$NODE" --format '{{.Config.Image}}') \
        || { echo "node image ref failed" >&2; return 1; }
    NODE_IMAGE_ID=$(docker inspect "$NODE" --format '{{.Image}}') \
        || { echo "node image id failed" >&2; return 1; }
    NODE_DIGESTS=$(docker image inspect "$NODE_IMAGE_REF" --format '{{.RepoDigests}}' 2>/dev/null || true)
    fact "node=$NODE image-ref=$NODE_IMAGE_REF image-id=$NODE_IMAGE_ID repo-digests=$NODE_DIGESTS"
}

build_holder() {
    [ "$(grep -c "FROM $HOLDER_BASE" "$HOLDER_DOCKERFILE")" -eq 2 ] \
        || { echo "holder base pin drifted" >&2; return 1; }
    HCTX=$WORK/context-holder
    mkdir -p "$HCTX/tests/fixtures/public-cli" "$HCTX/deploy"
    cp tests/fixtures/public-cli/gated.c "$HCTX/tests/fixtures/public-cli/"
    cp deploy/holder-entry.sh "$HCTX/deploy/"
    timeout --signal=TERM --kill-after=10s 1200s \
        docker build -q -f "$HOLDER_DOCKERFILE" -t "$HOLD_IMAGE" "$HCTX" || return 1
    HOLD_ID=$(docker inspect --format '{{.Id}}' "$HOLD_IMAGE") \
        || { echo "holder image id failed" >&2; return 1; }
    fact "holder-image=$HOLD_IMAGE id=$HOLD_ID base=$HOLDER_BASE"
}

# Provision the node container for attach-pod.sh: a non-root caller with
# passwordless sudo (sudo is installed into the node, a recorded download),
# kubectl with API access, and the attach tree (scripts beside lib.sh, the
# observer where attach-pod.sh looks). kubectl is already on the node image;
# the host's is copied in only if that ever changes.
provision_node() {
    docker exec "$NODE" sh -c 'id p11k2 2>/dev/null || useradd -m -s /bin/sh p11k2' \
        || { echo "node user setup failed" >&2; return 1; }
    docker exec "$NODE" sh -c 'apt-get update && apt-get install -y sudo' \
        >"$WORK/apt-sudo.log" 2>&1 || { echo "node sudo install failed" >&2; return 1; }
    SUDO_VERSION=$(docker exec "$NODE" dpkg-query -W -f='${Version}\n' sudo) \
        || { echo "node sudo version failed" >&2; return 1; }
    [ -n "$SUDO_VERSION" ] || { echo "node sudo has no version" >&2; return 1; }
    fact "node-sudo-version=$SUDO_VERSION (apt download; see apt-sudo.log)"
    docker exec "$NODE" sh -c 'echo "p11k2 ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/p11k2; chmod 440 /etc/sudoers.d/p11k2' \
        || { echo "node sudoers setup failed" >&2; return 1; }
    docker exec -u "$K2_USER" "$NODE" sudo -n true \
        || { echo "node passwordless sudo failed" >&2; return 1; }
    if docker exec "$NODE" command -v kubectl >/dev/null 2>&1; then
        NODE_KUBECTL=$(docker exec "$NODE" kubectl version --client) \
            || { echo "node kubectl version failed" >&2; return 1; }
        fact "node-kubectl=$NODE_KUBECTL (node image)"
    else
        HOST_KUBECTL=$(command -v kubectl) \
            || { echo "host kubectl missing" >&2; return 1; }
        docker cp "$HOST_KUBECTL" "$NODE:/usr/local/bin/kubectl" \
            || { echo "kubectl copy into the node failed" >&2; return 1; }
        NODE_KUBECTL=$(docker exec "$NODE" kubectl version --client) \
            || { echo "node kubectl version failed" >&2; return 1; }
        fact "node-kubectl=$NODE_KUBECTL (copied from host $HOST_KUBECTL)"
    fi
    docker exec "$NODE" sh -c "mkdir -p /home/p11k2/.kube && cp /etc/kubernetes/admin.conf $K2_KUBECONFIG && chown -R p11k2 /home/p11k2/.kube" \
        || { echo "node kubeconfig setup failed" >&2; return 1; }
    docker exec -u "$K2_USER" "$NODE" kubectl --kubeconfig "$K2_KUBECONFIG" \
        -n "$WL_NS" wait --for=condition=Ready pod --all --timeout=240s \
        || { echo "workloads never became Ready inside the node" >&2; return 1; }
    # attach-pod.sh resolves kubectl through the caller's environment: prove
    # that path, not just the explicit --kubeconfig one.
    docker exec -u "$K2_USER" -e "KUBECONFIG=$K2_KUBECONFIG" "$NODE" kubectl -n "$WL_NS" get pod ledger-a >/dev/null \
        || { echo "default node kubeconfig cannot read pods" >&2; return 1; }
    docker exec "$NODE" mkdir -p "$K2_ROOT/scripts" "$K2_ROOT/target/release" \
        || { echo "node tree setup failed" >&2; return 1; }
    docker cp scripts/attach-pod.sh "$NODE:$K2_ROOT/scripts/attach-pod.sh" || return 1
    docker cp scripts/k8s-profile-entry.sh "$NODE:$K2_ROOT/scripts/k8s-profile-entry.sh" || return 1
    docker cp scripts/lib.sh "$NODE:$K2_ROOT/scripts/lib.sh" || return 1
    docker cp .release-rust-version "$NODE:$K2_ROOT/.release-rust-version" || return 1
    docker cp "$OBSERVER" "$NODE:$K2_ROOT/target/release/p11scope" || return 1
    docker exec "$NODE" chmod -R a+rX "$K2_ROOT" \
        || { echo "node tree permissions failed" >&2; return 1; }
    docker exec -u "$K2_USER" "$NODE" sh -c "test -x $K2_ROOT/target/release/p11scope && test -f $K2_ROOT/scripts/lib.sh" \
        || { echo "node tree unreadable to $K2_USER" >&2; return 1; }
    fact "node-tree=$K2_ROOT scripts=attach-pod.sh,k8s-profile-entry.sh,lib.sh observer=target/release/p11scope"
}

wait_log() {
    wl_i=0
    while [ "$wl_i" -lt $(($3 * 2)) ]; do
        kc -n "$WL_NS" logs "$1" 2>/dev/null | grep -q "$2" && return 0
        sleep 0.5
        wl_i=$((wl_i + 1))
    done
    echo "pod $1 never printed $2" >&2
    kc -n "$WL_NS" logs "$1" >&2 || true
    return 1
}

wait_file_line() {
    wf_i=0
    while [ "$wf_i" -lt $(($3 * 2)) ]; do
        grep -q "$2" "$1" 2>/dev/null && return 0
        sleep 0.5
        wf_i=$((wf_i + 1))
    done
    echo "$1 never printed $2" >&2
    return 1
}

# Profile readiness: the capture line (a timed inventory has none, but every
# K2 capture is a profile).
wait_ready() {
    wr_i=0
    while [ "$wr_i" -lt 360 ]; do
        if grep -q 'p11scope: capturing:' "$WORK/$1.err" 2>/dev/null; then
            return 0
        fi
        kill -0 "$2" 2>/dev/null || break
        sleep 0.5
        wr_i=$((wr_i + 1))
    done
    echo "capture $1 never became ready" >&2
    cat "$WORK/$1.err" >&2
    return 1
}

pod_uid() {
    pu=$(kc -n "$WL_NS" get pod "$1" -o jsonpath='{.metadata.uid}') || return 1
    case $pu in ''|*[!0-9a-f-]*) echo "bad uid for $1: $pu" >&2; return 1 ;; esac
    printf '%s\n' "$pu"
}

# The pod's main pid as the node numbers it, through the node's crictl.
node_pid() {
    np_cid=$(kc -n "$WL_NS" get pod "$1" -o jsonpath='{.status.containerStatuses[0].containerID}') \
        || return 1
    np_cid=${np_cid#containerd://}
    case $np_cid in ''|*[!0-9a-f]*) echo "bad container id for $1" >&2; return 1 ;; esac
    np=$(docker exec "$NODE" crictl inspect -o go-template --template '{{.info.pid}}' "$np_cid") \
        || return 1
    case $np in ''|*[!0-9]*) echo "bad node pid for $1: $np" >&2; return 1 ;; esac
    printf '%s\n' "$np"
}

# Create the workload's gate file from the node, through its own root: a
# `kubectl exec touch` would add short-lived processes to the captured pod,
# which the capture rightly counts as pid_descendant_gaps.
release_pod() {
    rel_pid=$(node_pid "$1") || return 1
    docker exec "$NODE" touch "/proc/$rel_pid/root/tmp/gate" || return 1
}

# Exactly one complete gated JSON ledger with 6xN successes (gated.c prints
# `READY pid=` once and one `LEDGER {...}` line with complete/attempts/
# successful), the same rule as the K1 check and the container-cell drivers.
ledger_check() {
    python3 -I - "$1" "$2" <<'PY'
import json, sys
path, iters = sys.argv[1], int(sys.argv[2])
ledgers = []
ready = 0
with open(path, encoding="utf-8") as handle:
    for line in handle:
        if line.startswith("READY "):
            ready += 1
        elif line.startswith("LEDGER "):
            ledgers.append(json.loads(line[len("LEDGER "):]))
if ready < 1 or len(ledgers) != 1:
    raise SystemExit(f"want >=1 READY and 1 LEDGER, got {ready} and {len(ledgers)}")
ledger = ledgers[0]
if ledger.get("schema") != "p11scope/public-cli-ledger/v1":
    raise SystemExit("bad ledger schema")
if ledger.get("complete") is not True:
    raise SystemExit("ledger incomplete")
functions = ledger.get("functions")
if not isinstance(functions, list) or len(functions) != 6:
    raise SystemExit("want 6 ledger functions")
names = set()
for row in functions:
    if row.get("attempts") != iters or row.get("successful") != iters:
        raise SystemExit(f"ledger row is not 6x{iters}: {row}")
    names.add(row.get("name"))
if len(names) != 6:
    raise SystemExit("ledger function names are not distinct")
PY
}

pod_ledger_is() {
    kc -n "$WL_NS" logs "$1" > "$WORK/logs-$1.txt" || return 1
    ledger_check "$WORK/logs-$1.txt" "$2" || {
        echo "$1 did not ledger $2 clean iterations" >&2
        return 1
    }
}

# The late-provider rule: the capture must name a disclosure beyond the PID
# numbering and the runc exec artifacts (src/render.rs observation causes).
# Either accepted shape passes -- discovered-live with a named pre-attach
# gap, or absent-with-disclosure -- and every silent shape fails, including
# an exact count across the attach-time scan limit. The disclosure
# vocabulary is frozen: an unknown cause fails loudly, never passes as
# disclosure.
scan_limit_check() {
    python3 -I - "$1" <<'PY'
import json, sys
# Frozen scan-disclosure vocabulary (OQ4 pattern): discovery/slots are the
# built binary's absent-leg output (K1 negative.json: an idle cgroup with
# no provider); unprotected_live_windows is the expected live-leg cause
# (src/render.rs gap_classes, observed-profile-v3.md); skipped is what the
# first live K2 run (k2-dev-3, binary 5ce42784) printed for the nested
# observer: evidence.skipped "discovery subject: discovery unavailable"
# (src/render.rs "skipped" cause), with the late provider counted exactly.
# Anything else -- loss, failure, future or misspelled cause -- fails
# loudly for triage from facts.log.
ALLOWED_SCAN_DISCLOSURE = {
    "discovery": "K1 negative.json observation causes (built binary)",
    "slots": "K1 negative.json observation causes (built binary)",
    "unprotected_live_windows": "src/render.rs gap_classes",
    "skipped": "live K2 run 3 scan leg (nested observer, discovery unavailable)",
}
BENIGN_SCAN_CAUSES = {"pid_namespace", "proc_namespace_mismatch", "pid_descendant_gaps"}
document = json.load(open(sys.argv[1], encoding="utf-8"))
causes = set(document["evidence"]["gap_classes"]["observation"]["causes"])
if "pid_namespace" not in causes:
    raise SystemExit("nested capture without its pid_namespace cause")
unknown = causes - BENIGN_SCAN_CAUSES - set(ALLOWED_SCAN_DISCLOSURE)
if unknown:
    raise SystemExit(f"unknown scan cause: {sorted(unknown)} "
                     f"(frozen disclosure: {sorted(ALLOWED_SCAN_DISCLOSURE)})")
disclosure = causes - BENIGN_SCAN_CAUSES
counted = sum(row["calls"] for row in document["functions"] if row["calls"])
modules = document["capture"]["modules"]
if not disclosure:
    raise SystemExit(f"late provider silently resolved: {counted} calls, causes {sorted(causes)}")
leg = "discovered-live" if (counted or modules) else "absent"
print(json.dumps({"check": "scan-limit", "ok": True, "leg": leg,
                  "counted_calls": counted, "modules": len(modules),
                  "disclosure": sorted(disclosure), "causes": sorted(causes)},
                 sort_keys=True))
PY
}

oracle_profile() {
    python3 -I "$ORACLE" --expect-observer nested profile-exact "$1" "$2"
}

oracle_negative() {
    python3 -I "$ORACLE" --expect-observer nested negative "$1" "$2"
}

# attach NAME POD DURATION NODE_OUT: background the node's attach-pod.sh; the
# capture's stdout/stderr land in WORK/NAME.{out,err}. STARTED_PID is the new
# local `docker exec`, which lives exactly as long as the capture in the node;
# CAPTURE_PIDS keeps every live one for cleanup.
start_attach() {
    docker exec -u "$K2_USER" -e "KUBECONFIG=$K2_KUBECONFIG" -w "$K2_ROOT" "$NODE" sh "$K2_ROOT/scripts/attach-pod.sh" \
        --pod "$2" --namespace "$WL_NS" -- --duration "$3" -o "$4" \
        >"$WORK/$1.out" 2>"$WORK/$1.err" &
    CAPTURE_PIDS="${CAPTURE_PIDS-} $!"
    STARTED_PID=$!
}

# finish_attach NAME NODE_OUT LOCAL PID: the capture must exit 0, then its
# report is streamed out of the node.
finish_attach() {
    fa_status=0
    wait "$4" || fa_status=$?
    [ "$fa_status" -eq 0 ] || {
        echo "capture $1 exited $fa_status" >&2
        cat "$WORK/$1.err" >&2
        return 1
    }
    # kind mounts the node's /tmp as tmpfs, which `docker cp` cannot read:
    # stream the report out instead, and refuse a missing or blank one.
    docker exec "$NODE" cat "$2" >"$3" || return 1
    grep -q '[^[:space:]]' "$3" || { echo "capture $1 wrote an empty report" >&2; return 1; }
}

# Its own cluster and image, nothing else (the trap calls this).
delete_owned() {
    [ -z "${CLUSTER_CREATED-}" ] || timeout --signal=TERM --kill-after=10s 300s \
        kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 || true
    [ -z "${IMAGES_BUILT-}" ] || docker image rm -f "$HOLD_IMAGE" >/dev/null 2>&1 || true
}

keep_message() {
    [ -z "${CLUSTER_CREATED-}" ] || echo "kept cluster $CLUSTER (--keep): KUBECONFIG=$KUBECONFIG; delete with: kind delete cluster --name $CLUSTER --kubeconfig $KUBECONFIG" >&2
    [ -z "${IMAGES_BUILT-}" ] || echo "kept image $HOLD_IMAGE (--keep); delete with: docker image rm -f $HOLD_IMAGE" >&2
}

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    for capture_pid in ${CAPTURE_PIDS-}; do
        kill "$capture_pid" 2>/dev/null
    done
    if [ "${KEEP-0}" -eq 1 ]; then
        keep_message
    else
        delete_owned
    fi
    echo "evidence directory: ${WORK-unknown}" >&2
    exit "$CLEANUP_STATUS"
}

OBSERVER=
TOKEN=
DURATION=$DURATION_DEFAULT
NODE_IMAGE=
WORK_OPT=
KEEP=0

while [ "$#" -gt 0 ]; do
    case $1 in
        --observer) [ "$#" -ge 2 ] || usage; [ -z "$OBSERVER" ] || usage; OBSERVER=$2; shift 2 ;;
        --token) [ "$#" -ge 2 ] || usage; [ -z "$TOKEN" ] || usage; TOKEN=$2; shift 2 ;;
        --duration) [ "$#" -ge 2 ] || usage; DURATION=$2; shift 2 ;;
        --node-image) [ "$#" -ge 2 ] || usage; [ -z "$NODE_IMAGE" ] || usage; NODE_IMAGE=$2; shift 2 ;;
        --work) [ "$#" -ge 2 ] || usage; [ -z "$WORK_OPT" ] || usage; WORK_OPT=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --self-test) [ "$#" -eq 1 ] || usage; self_test ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

[ -n "$OBSERVER" ] || usage
[ -x "$OBSERVER" ] || usage
[ -n "$TOKEN" ] || TOKEN=$(date +%s)-$$
valid_token "$TOKEN" || usage
valid_count "$DURATION" || usage

. scripts/lib.sh
require_non_root_caller
[ "$(uname -m)" = x86_64 ] || { echo "the observer binary is x86-64 only" >&2; exit 1; }
for command in docker kind kubectl python3 timeout; do
    command -v "$command" >/dev/null || { echo "$command required" >&2; exit 1; }
done

CLUSTER=p11scope-k2-$TOKEN
HOLD_IMAGE=p11scope-k2-holder:$TOKEN
if [ -n "$WORK_OPT" ]; then
    [ ! -e "$WORK_OPT" ] || { echo "$WORK_OPT already exists" >&2; exit 1; }
    mkdir -m 0700 "$WORK_OPT"
    WORK=$(cd "$WORK_OPT" && pwd -P)
else
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-k2-XXXXXX")
fi
KUBECONFIG=$WORK/kubeconfig
export KUBECONFIG
FACTS=$WORK/facts.log
SUMMARY_JSONL=$WORK/summary.jsonl
: >"$SUMMARY_JSONL"
CLUSTER_CREATED=
IMAGES_BUILT=
CAPTURE_PIDS=
. scripts/cleanup-traps.sh

kc() {
    timeout --signal=TERM --kill-after=10s 300s kubectl "$@"
}

fact "cell=K2 token=$TOKEN date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fact "observer=$OBSERVER sha256=$(sha256sum "$OBSERVER" | awk '{print $1}')"
fact "image=$HOLD_IMAGE duration=$DURATION"
record_tool_facts || unrun "tool versions unavailable"
assert_cluster_free "$CLUSTER" || unrun "cluster $CLUSTER already exists"

say "=== build holder image $HOLD_IMAGE ==="
build_holder || unrun "holder image build failed"
IMAGES_BUILT=1

say "=== create kind cluster $CLUSTER (private kubeconfig) ==="
# Set before create: a create killed half-way must still be deleted. The name
# was proven unused above and carries this run's token.
CLUSTER_CREATED=1
timeout --signal=TERM --kill-after=10s 900s kind create cluster --name "$CLUSTER" \
    --kubeconfig "$KUBECONFIG" --wait 180s \
    ${NODE_IMAGE:+--image "$NODE_IMAGE"} || unrun "kind cluster creation failed"
NODE=$(node_name) || unrun "kind cluster has no single node"
record_node_facts || unrun "node image identity unavailable"
say "=== load holder image ==="
timeout --signal=TERM --kill-after=10s 1200s \
    kind load docker-image --name "$CLUSTER" "$HOLD_IMAGE" || unrun "image load failed"

say "=== apply workloads ==="
sed "s#image: p11scope-holder:1\$#image: $HOLD_IMAGE#" "$WORKLOADS" > "$WORK/workloads.yaml"
[ "$(grep -c "image: $HOLD_IMAGE" "$WORK/workloads.yaml")" -eq 6 ] \
    || unrun "workloads render lost an image anchor"
kc apply -f "$WORK/workloads.yaml" || unrun "workloads apply failed"
kc -n "$WL_NS" wait --for=condition=Ready pod --all --timeout=240s \
    || unrun "workloads never became Ready"
wait_log ledger-a '^READY ' 120 || unrun "ledger-a never became ready"

say "=== provision the node for attach-pod.sh ==="
provision_node || unrun "node provisioning failed"

say "=== primary: attach to ledger-a, exactly 6x$ITERS_A_DEFAULT ==="
start_attach k2 ledger-a "$DURATION" /tmp/k2.json
PID_CAP=$STARTED_PID
wait_ready k2 "$PID_CAP" || fail_cell "primary capture never became ready"
release_pod ledger-a || fail_cell "gate release failed for ledger-a"
wait_log ledger-a '^LEDGER ' 120 || fail_cell "ledger-a ledger never completed"
kill -0 "$PID_CAP" 2>/dev/null || fail_cell "ledger-a ledger completed outside the capture window"
finish_attach k2 /tmp/k2.json "$WORK/k2.json" "$PID_CAP" || fail_cell "primary capture failed"
pod_ledger_is ledger-a "$ITERS_A_DEFAULT" || fail_cell "ledger-a ledger is not 6x$ITERS_A_DEFAULT"
grep -h '^LEDGER ' "$WORK/logs-ledger-a.txt" >>"$FACTS"
RESULT=$(oracle_profile "$WORK/k2.json" "$ITERS_A_DEFAULT") \
    || fail_cell "primary oracle refused"
record "$RESULT"

say "=== negative twin: attach to idle ==="
UID_IDLE=$(pod_uid idle) || fail_cell "no uid for idle"
start_attach k2-negative idle "$NEG_DURATION_DEFAULT" /tmp/k2-negative.json
PID_NEG=$STARTED_PID
wait_ready k2-negative "$PID_NEG" || fail_cell "negative capture never became ready"
finish_attach k2-negative /tmp/k2-negative.json "$WORK/k2-negative.json" "$PID_NEG" \
    || fail_cell "negative capture failed"
# The visibility line: attach-pod.sh prints no process counts, so the entry
# script proves the idle pod was seen and readable on the same node.
docker exec -u "$K2_USER" -w "$K2_ROOT" "$NODE" sudo -n env \
    "P11SCOPE_OBSERVER=$K2_ROOT/target/release/p11scope" \
    sh "$K2_ROOT/scripts/k8s-profile-entry.sh" --pod-uid "$UID_IDLE" --command doctor \
    >"$WORK/k2-doctor.out" 2>"$WORK/k2-doctor.err" || fail_cell "idle visibility probe failed"
RESULT=$(oracle_negative "$WORK/k2-negative.json" "$WORK/k2-doctor.err") \
    || fail_cell "negative oracle refused"
record "$RESULT"

say "=== scan-limit twin: a ledger mapped after attach is never silently zero ==="
start_attach k2-scan idle "$SCAN_DURATION_DEFAULT" /tmp/k2-scan.json
PID_SCAN=$STARTED_PID
wait_ready k2-scan "$PID_SCAN" || fail_cell "scan capture never became ready"
# The gate is released from inside the same exec (holder-entry deletes any
# pre-created gate at startup); the exec is the workload, so its runc stages
# are expected and excluded from the disclosure set.
kc -n "$WL_NS" exec idle -- sh -c '(sleep 10; touch /tmp/gate) & exec holder-entry ledger 250' \
    >"$WORK/k2-scan-exec.log" 2>&1 &
EXEC_PID=$!
CAPTURE_PIDS="$CAPTURE_PIDS $EXEC_PID"
wait_file_line "$WORK/k2-scan-exec.log" '^READY ' 120 \
    || fail_cell "scan ledger never became ready"
wait_file_line "$WORK/k2-scan-exec.log" '^LEDGER ' 120 \
    || fail_cell "scan ledger never completed"
kill -0 "$PID_SCAN" 2>/dev/null || fail_cell "scan ledger completed outside the capture window"
kill "$EXEC_PID" 2>/dev/null || true
ledger_check "$WORK/k2-scan-exec.log" "$ITERS_SCAN_DEFAULT" \
    || fail_cell "scan ledger is not 6x$ITERS_SCAN_DEFAULT"
grep -h '^LEDGER ' "$WORK/k2-scan-exec.log" >>"$FACTS"
finish_attach k2-scan /tmp/k2-scan.json "$WORK/k2-scan.json" "$PID_SCAN" \
    || fail_cell "scan capture failed"
RESULT=$(scan_limit_check "$WORK/k2-scan.json") || fail_cell "scan-limit twin failed: late provider silently zero"
record "$RESULT"
fact "scan-limit=$RESULT"

summarize PASS "K2 attach-pod from the kind node captured ledger-a exactly; idle negative and scan-limit twins held"

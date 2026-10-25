#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Cell C3: a pre-attached-provider cold pod is captured exactly.
#
# A private kind cluster runs the DaemonSet node observer (deploy/k8s,
# rendered as in scripts/kind-e2e.sh) plus the test-only workloads
# (deploy/k8s/e2e/workloads.yaml). The flow anchors the provider on the
# node, then cold-starts a pod after the anchor:
#   anchor   release ledger-a (400) and capture it once through
#            k8s-profile-entry: exactly 6x400, the already-attached leg
#   cold     delete and recreate ledger-b as a NEW pod (its UID must
#            change), release it (250) and capture:
#     cmd1   per-pod profile of the cold pod: exactly 6x250
#     cmd2   node-wide `inventory --system`: both A and B are callers
#            with edges to the provider, idle is scanned with no edge
#   twin     delete B and re-run inventory: the capture must first pass
#            as a healthy scan (caller A keeps its edge, idle scanned
#            edgeless), then the old B pid is absent from callers or
#            present-with-no-edge (never an edge), and the positive
#            oracle refuses that JSON, proving it distinguishes
#            included from not.
# Every capture is checked with scripts/kind-e2e-oracle.py
# --expect-observer nested (the node is a container, so the observer is
# always in a nested PID namespace). Gates are released from the node,
# never kubectl/docker exec into a captured pod: runc exec stages count
# as pid_descendant_gaps.
#
# The CONTROLLER runs every docker/kind/kubectl command below. Workers only run
# `sh $0 --self-test`, which is unprivileged (PATH stubs) and proves the arg
# refusals, the pins, the private kubeconfig, the cleanup trap and the oracle
# hooks.
set -eu
cd "$(dirname "$0")/.."

ORACLE=scripts/kind-e2e-oracle.py
OBSERVER_DOCKERFILE=deploy/Dockerfile.observer
# Pinned bases reused from the Dockerfiles; the self-test requires each
# Dockerfile to carry exactly its digest.
OBSERVER_BASE=alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
HOLDER_DOCKERFILE=deploy/Dockerfile.holder
HOLDER_BASE=ubuntu:26.04@sha256:3595d7fc4286a33fad0fd853a4063e654287a9c3787437d7937c94ca3f7a804e
WORKLOADS=deploy/k8s/e2e/workloads.yaml
OBS_NS=p11scope
WL_NS=p11scope-e2e
ITERS_A_DEFAULT=400
ITERS_B_DEFAULT=250
DURATION_DEFAULT=30

usage() {
    cat >&2 <<'EOF'
usage: scripts/cold-pod-e2e.sh --observer BIN [options]
       scripts/cold-pod-e2e.sh --self-test | --help

  Cell C3 driver. Private kind cluster + DaemonSet observer + test
  workloads, anchor ledger-a, cold-start ledger-b after the anchor, then
  the per-pod profile and the node-wide inventory, all checked with
  scripts/kind-e2e-oracle.py --expect-observer nested.

  --observer BIN        static x86-64 p11scope binary, packaged into the
                        observer image (reuse the K1 build
                        target/x86_64-unknown-linux-musl/release/p11scope)
  --token TOKEN         run token, short [a-z0-9-] (default <time>-<pid>)
  --duration S          profile capture seconds (default 30)
  --node-image IMG      kind node image (default: kind's own; recorded)
  --work DIR            evidence directory (must not exist; default fresh 0700
                        under $TMPDIR)
  --keep                keep the cluster and images for debugging (prints the
                        delete commands)
  --self-test           unprivileged checks (PATH stubs, no docker/kind/kubectl)
  --help                this text

Exit codes: 0 PASS, 1 FAIL, 2 usage, 3 UNRUN (cell not run, see SUMMARY reason).
Every run prints a final SUMMARY line: SUMMARY cell=C3 verdict=... reason="...".

CONTROLLER (from the repo root; BIN = the K1-built static binary):
  sh scripts/cold-pod-e2e.sh --observer BIN --token <TOKEN>
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
    # The Dockerfile pins this cell reuses.
    [ "$(grep -c "FROM $OBSERVER_BASE" "$OBSERVER_DOCKERFILE")" -eq 1 ] \
        || { echo "observer base pin drifted" >&2; exit 1; }
    [ "$(grep -c "FROM $HOLDER_BASE" "$HOLDER_DOCKERFILE")" -eq 2 ] \
        || { echo "holder base pin drifted" >&2; exit 1; }
    [ "$(grep -c 'image: p11scope-observer:1$' deploy/k8s/20-daemonset.yaml)" -eq 1 ] \
        || { echo "daemonset lost its observer image anchor" >&2; exit 1; }
    [ "$(grep -c 'image: p11scope-holder:1$' "$WORKLOADS")" -eq 6 ] \
        || { echo "workloads.yaml lost an image anchor" >&2; exit 1; }
    # `kubectl apply -f deploy/k8s/` applies files in name order: the
    # namespace must sort before everything that lives in it.
    set -- deploy/k8s/*.yaml
    [ "$1" = deploy/k8s/00-namespace.yaml ] \
        || { echo "deploy/k8s/00-namespace.yaml must sort first" >&2; exit 1; }
    [ "$ITERS_A_DEFAULT" -eq 400 ] && [ "$ITERS_B_DEFAULT" -eq 250 ] \
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
            echo "c3 driver exited $status (want 2) for: [$bad]" >&2
            exit 1
        }
    done
    c3_help_self_test
    python3 -I "$ORACLE" --self-test
    c3_stub_self_test
    echo "cold-pod-e2e self-test: OK"
    exit 0
}

c3_help_self_test() {
    help=$(sh "$0" --help 2>&1 || true)
    for marker in "--observer BIN" "cold-pod-e2e.sh --observer" \
                  "SUMMARY cell=C3"; do
        case $help in
            *"$marker"*) ;;
            *) echo "help lost its controller line: $marker" >&2; exit 1 ;;
        esac
    done
}

# Every docker/kind/kubectl/timeout call below is a PATH stub: no daemon, no
# network, no cluster. STUB_CALLS records each call; STUB_FAIL names one
# substring whose call fails; the STUB_* vars shape the answers.
c3_stub_self_test() {
    stub=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-c3-stub-XXXXXX")
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
    *" crictl inspect "*) printf '%s\n' "${STUB_NODE_PID-1234}" ;;
    *"{{.Driver}} {{.ServerVersion}}"*) printf '%s\n' "overlayfs 29.8.1" ;;
    *"{{.CgroupDriver}}"*) printf '%s\n' "systemd" ;;
    *"{{.DockerRootDir}}"*) printf '%s\n' "/var/lib/docker" ;;
    *"{{.Config.Image}}"*) printf '%s\n' "kindest/node:stub" ;;
    *"{{.Image}}"*) printf '%s\n' "sha256:node-image-id-stub" ;;
    *"{{.RepoDigests}}"*) printf '%s\n' "[kindest/node@sha256:stubdigest]" ;;
    *"{{.Id}}"*) printf '%s\n' "sha256:image-id-stub" ;;
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
    if STUB_CLUSTERS="p11scope-c3-t" STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" \
            assert_cluster_free p11scope-c3-t >/dev/null 2>&1; then
        echo "existing cluster name accepted" >&2
        exit 1
    fi
    STUB_CLUSTERS="other" STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" \
        assert_cluster_free p11scope-c3-t \
        || { echo "free cluster name refused" >&2; exit 1; }
    # Exactly one node, never zero or two.
    got=$(CLUSTER=p11scope-c3-t STUB_NODES="p11scope-c3-t-control-plane" \
        STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" node_name) \
        || { echo "single node refused" >&2; exit 1; }
    [ "$got" = "p11scope-c3-t-control-plane" ] || { echo "node resolved to $got" >&2; exit 1; }
    for nodes in "" "n1
n2"; do
        if CLUSTER=p11scope-c3-t STUB_NODES="$nodes" STUB_CALLS=$stub/calls.txt \
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
    STUB_FAIL=
    # Both image builds stage the K1 contexts and record the image ids.
    : > "$stub/calls.txt"
    WORK=$stub/work FACTS=$stub/work/facts.log OBSERVER=$stub/observer \
        OBS_IMAGE=obs:t HOLD_IMAGE=img:t \
        STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" build_images >/dev/null \
        || { echo "image builds refused" >&2; exit 1; }
    grep -q "docker build -q -f deploy/Dockerfile.observer -t obs:t" "$stub/calls.txt" \
        || { echo "observer build argv drifted" >&2; exit 1; }
    grep -q "docker build -q -f deploy/Dockerfile.holder -t img:t" "$stub/calls.txt" \
        || { echo "holder build argv drifted" >&2; exit 1; }
    grep -q "observer-image=obs:t id=sha256:image-id-stub" "$stub/work/facts.log" \
        || { echo "observer image id not recorded" >&2; exit 1; }
    grep -q "holder-image=img:t id=sha256:image-id-stub" "$stub/work/facts.log" \
        || { echo "holder image id not recorded" >&2; exit 1; }
    [ -f "$stub/work/context-observer/target/x86_64-unknown-linux-musl/release/p11scope" ] \
        || { echo "observer context lost the binary" >&2; exit 1; }
    [ -f "$stub/work/context-observer/scripts/k8s-profile-entry.sh" ] \
        || { echo "observer context lost the entry script" >&2; exit 1; }
    [ -f "$stub/work/context-holder/tests/fixtures/public-cli/gated.c" ] \
        || { echo "holder context lost gated.c" >&2; exit 1; }
    [ -f "$stub/work/context-holder/deploy/holder-entry.sh" ] \
        || { echo "holder context lost holder-entry.sh" >&2; exit 1; }
    if WORK=$stub/work FACTS=$stub/work/facts.log OBSERVER=$stub/observer \
            OBS_IMAGE=obs:t HOLD_IMAGE=img:t STUB_FAIL="build" \
            STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" build_images >/dev/null 2>&1; then
        echo "failed image build accepted" >&2
        exit 1
    fi
    STUB_FAIL=

    c3_capture_self_test "$stub"
    c3_cold_self_test "$stub"
    c3_oracle_self_test "$stub"
    c3_twin_self_test "$stub"
    c3_cleanup_self_test "$stub"
    rm -rf "$stub"
    trap - EXIT
}

# Capture waiters, pod identity and the LEDGER rule, all without a cluster.
c3_capture_self_test() {
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
    cst_uid=0123abcd-4567-89ef-0123-456789abcdef
    got=$(STUB_UID="$cst_uid" STUB_CALLS=$cst_stub/calls.txt PATH="$cst_stub:$PATH" \
        pod_uid ledger-b) || { echo "pod uid refused" >&2; exit 1; }
    [ "$got" = "$cst_uid" ] || { echo "pod uid resolved to $got" >&2; exit 1; }
    for bad_uid in "" "UPPER" "01_23"; do
        if STUB_UID="$bad_uid" STUB_CALLS=$cst_stub/calls.txt PATH="$cst_stub:$PATH" \
                pod_uid ledger-b >/dev/null 2>&1; then
            echo "bad pod uid accepted: $bad_uid" >&2
            exit 1
        fi
    done
    # LEDGER lines: exactly one complete JSON ledger with 6xN successes.
    printf '%s\n' 'READY pid=1' \
        'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":1,"complete":true,"functions":[{"name":"C_GenerateRandom","attempts":250,"successful":250},{"name":"C_DigestInit","attempts":250,"successful":250},{"name":"C_Digest","attempts":250,"successful":250},{"name":"C_FindObjectsInit","attempts":250,"successful":250},{"name":"C_FindObjects","attempts":250,"successful":250},{"name":"C_FindObjectsFinal","attempts":250,"successful":250}]}' \
        > "$cst_stub/good.log"
    PATH="$cst_stub:$PATH" ledger_check "$cst_stub/good.log" 250 \
        || { echo "good LEDGER refused" >&2; exit 1; }
    printf '%s\n' 'READY pid=1' 'LEDGER iterations=250 nonzero_rv=0' > "$cst_stub/legacy.log"
    printf '%s\n' 'READY pid=1' 'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":1,"complete":false,"functions":[{"name":"C_GenerateRandom","attempts":250,"successful":250},{"name":"C_DigestInit","attempts":250,"successful":250},{"name":"C_Digest","attempts":250,"successful":250},{"name":"C_FindObjectsInit","attempts":250,"successful":250},{"name":"C_FindObjects","attempts":250,"successful":250},{"name":"C_FindObjectsFinal","attempts":250,"successful":250}]}' \
        > "$cst_stub/incomplete.log"
    printf '%s\n' 'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":1,"complete":true,"functions":[{"name":"C_GenerateRandom","attempts":249,"successful":249}]}' \
        > "$cst_stub/short.log"
    printf '%s\n' 'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":1,"complete":true,"functions":[{"name":"C_GenerateRandom","attempts":250,"successful":249},{"name":"C_DigestInit","attempts":250,"successful":250},{"name":"C_Digest","attempts":250,"successful":250},{"name":"C_FindObjectsInit","attempts":250,"successful":250},{"name":"C_FindObjects","attempts":250,"successful":250},{"name":"C_FindObjectsFinal","attempts":250,"successful":250}]}' \
        > "$cst_stub/failed.log"
    printf '%s\n' 'READY pid=1' > "$cst_stub/missing.log"
    for bad in legacy incomplete short failed missing; do
        if PATH="$cst_stub:$PATH" ledger_check "$cst_stub/$bad.log" 250 >/dev/null 2>&1; then
            echo "bad LEDGER accepted: $bad" >&2
            exit 1
        fi
    done
}

# The cold start: the ledger-b document is extracted alone from the rendered
# workloads, and the recreated pod must carry a new UID.
c3_cold_self_test() {
    cst_stub=$1
    extract_pod_doc "$WORKLOADS" ledger-b "$cst_stub/ledger-b.yaml" \
        || { echo "ledger-b extraction refused" >&2; exit 1; }
    grep -q 'kind: Pod' "$cst_stub/ledger-b.yaml" \
        || { echo "extracted ledger-b is not a Pod" >&2; exit 1; }
    grep -q 'name: ledger-b' "$cst_stub/ledger-b.yaml" \
        || { echo "extracted ledger-b lost its name" >&2; exit 1; }
    grep -q '"ledger", "250"' "$cst_stub/ledger-b.yaml" \
        || { echo "extracted ledger-b lost its args" >&2; exit 1; }
    if grep -q '^---$' "$cst_stub/ledger-b.yaml"; then
        echo "extracted ledger-b carries document separators" >&2
        exit 1
    fi
    for other in ledger-a idle; do
        if grep -q "name: $other" "$cst_stub/ledger-b.yaml"; then
            echo "extracted ledger-b carries $other" >&2
            exit 1
        fi
    done
    if extract_pod_doc "$WORKLOADS" ledger-zzz "$cst_stub/none.yaml" >/dev/null 2>&1; then
        echo "absent pod extraction accepted" >&2
        exit 1
    fi
    cat "$cst_stub/ledger-b.yaml" > "$cst_stub/dup.yaml"
    printf '%s\n' '---' >> "$cst_stub/dup.yaml"
    cat "$cst_stub/ledger-b.yaml" >> "$cst_stub/dup.yaml"
    if extract_pod_doc "$cst_stub/dup.yaml" ledger-b "$cst_stub/dup-out.yaml" >/dev/null 2>&1; then
        echo "duplicated pod extraction accepted" >&2
        exit 1
    fi
    assert_uid_changed 0123abcd-4567-89ef-0123-456789abcdef fedcba98-7654-3210-fedc-ba9876543210 \
        || { echo "changed uid refused" >&2; exit 1; }
    for same in "0123abcd-4567-89ef-0123-456789abcdef 0123abcd-4567-89ef-0123-456789abcdef" \
                "0123abcd-4567-89ef-0123-456789abcdef " " fedcba98-7654-3210-fedc-ba9876543210"; do
        # shellcheck disable=SC2086
        if assert_uid_changed $same >/dev/null 2>&1; then
            echo "unchanged uid accepted: [$same]" >&2
            exit 1
        fi
    done
}

# The oracle hooks: the exact subcommand argv the legs use, and an oracle
# refusal fails the leg.
c3_oracle_self_test() {
    ost_stub=$1
    : > "$ost_stub/calls.txt"
    ORACLE=$ost_stub/oracle STUB_ORACLE_STATUS=0 STUB_CALLS=$ost_stub/calls.txt \
        oracle_profile "$ost_stub/c3-b.json" 250 >/dev/null \
        || { echo "profile hook refused" >&2; exit 1; }
    ORACLE=$ost_stub/oracle STUB_ORACLE_STATUS=0 STUB_CALLS=$ost_stub/calls.txt \
        oracle_inventory "$ost_stub/c3-inv.json" --caller 10 --caller 11 --non-caller 12 >/dev/null \
        || { echo "inventory hook refused" >&2; exit 1; }
    grep -q -- "--expect-observer nested profile-exact $ost_stub/c3-b.json 250" "$ost_stub/calls.txt" \
        || { echo "profile hook argv drifted" >&2; exit 1; }
    grep -q -- "--expect-observer nested inventory $ost_stub/c3-inv.json --caller 10 --caller 11 --non-caller 12" \
        "$ost_stub/calls.txt" || { echo "inventory hook argv drifted" >&2; exit 1; }
    if ORACLE=$ost_stub/oracle STUB_ORACLE_STATUS=1 STUB_CALLS=$ost_stub/calls.txt \
            oracle_profile "$ost_stub/c3-b.json" 250 >/dev/null 2>&1; then
        echo "refusing profile oracle accepted" >&2
        exit 1
    fi
    if ORACLE=$ost_stub/oracle STUB_ORACLE_STATUS=1 STUB_CALLS=$ost_stub/calls.txt \
            oracle_inventory "$ost_stub/c3-inv.json" --caller 10 >/dev/null 2>&1; then
        echo "refusing inventory oracle accepted" >&2
        exit 1
    fi
}

# The failure twin: a deleted pid is absent or edgeless, never a caller with
# an edge. Each accepted shape passes; a phantom edge fails.
c3_twin_self_test() {
    tst_stub=$1
    cat > "$tst_stub/absent.json" <<'EOF'
{"schema":"p11scope/inventory/v1","callers":[{"id":"c0","pid":10}],"modules":[{"id":"m0","paths":["/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"]}],"edges":[{"caller":"c0","module":"m0"}],"gaps":[],"pid_namespace":{"observer":"nested","kernel_pids":"initial","proc_pids":"observer"}}
EOF
    cat > "$tst_stub/edgeless.json" <<'EOF'
{"schema":"p11scope/inventory/v1","callers":[{"id":"c0","pid":10},{"id":"c1","pid":11}],"modules":[{"id":"m0","paths":["/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"]}],"edges":[{"caller":"c0","module":"m0"}],"gaps":[],"pid_namespace":{"observer":"nested","kernel_pids":"initial","proc_pids":"observer"}}
EOF
    cat > "$tst_stub/phantom.json" <<'EOF'
{"schema":"p11scope/inventory/v1","callers":[{"id":"c0","pid":10},{"id":"c1","pid":11}],"modules":[{"id":"m0","paths":["/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"]}],"edges":[{"caller":"c0","module":"m0"},{"caller":"c1","module":"m0"}],"gaps":[],"pid_namespace":{"observer":"nested","kernel_pids":"initial","proc_pids":"observer"}}
EOF
    PATH="$tst_stub:$PATH" absent_or_edgeless "$tst_stub/absent.json" 11 >/dev/null \
        || { echo "absent pid refused" >&2; exit 1; }
    PATH="$tst_stub:$PATH" absent_or_edgeless "$tst_stub/edgeless.json" 11 >/dev/null \
        || { echo "edgeless pid refused" >&2; exit 1; }
    if PATH="$tst_stub:$PATH" absent_or_edgeless "$tst_stub/phantom.json" 11 >/dev/null 2>&1; then
        echo "phantom edge accepted" >&2
        exit 1
    fi
    # The twin's positive control: the twin capture must still be a healthy
    # scan -- caller A keeps its edge, idle still scanned edgeless -- before
    # B's absence proves anything. An empty or broken twin capture refuses,
    # so the twin proves absence against a healthy scan, never vacuously.
    cat > "$tst_stub/twin-healthy.json" <<'EOF'
{"schema":"p11scope/inventory/v1","callers":[{"id":"c0","pid":10},{"id":"c1","pid":12}],"modules":[{"id":"m0","paths":["/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"]}],"edges":[{"caller":"c0","module":"m0"}],"gaps":[{"subject":"pid namespace","caller":null,"module":null,"pid":null}],"pid_namespace":{"observer":"nested","kernel_pids":"initial","proc_pids":"observer"}}
EOF
    cat > "$tst_stub/twin-empty.json" <<'EOF'
{"schema":"p11scope/inventory/v1","callers":[],"modules":[],"edges":[],"gaps":[],"pid_namespace":{"observer":"nested","kernel_pids":"initial","proc_pids":"observer"}}
EOF
    cat > "$tst_stub/twin-a-edgeless.json" <<'EOF'
{"schema":"p11scope/inventory/v1","callers":[{"id":"c0","pid":10},{"id":"c1","pid":12}],"modules":[{"id":"m0","paths":["/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"]}],"edges":[],"gaps":[{"subject":"pid namespace","caller":null,"module":null,"pid":null}],"pid_namespace":{"observer":"nested","kernel_pids":"initial","proc_pids":"observer"}}
EOF
    # The healthy twin capture is a genuine twin: B's pid is gone from it.
    PATH="$tst_stub:$PATH" absent_or_edgeless "$tst_stub/twin-healthy.json" 11 >/dev/null \
        || { echo "twin capture without B refused" >&2; exit 1; }
    twin_positive_control "$tst_stub/twin-healthy.json" 10 12 >/dev/null \
        || { echo "healthy twin scan refused" >&2; exit 1; }
    for bad in twin-empty twin-a-edgeless; do
        if twin_positive_control "$tst_stub/$bad.json" 10 12 >/dev/null 2>&1; then
            echo "broken twin scan accepted: $bad" >&2
            exit 1
        fi
    done
}

# Cleanup deletes its own cluster and images, keeps nothing by default, and
# the --keep path prints the exact delete commands.
c3_cleanup_self_test() {
    dst_stub=$1
    : > "$dst_stub/calls.txt"
    CLUSTER=p11scope-c3-t KUBECONFIG=$dst_stub/work/kubeconfig CLUSTER_CREATED=1 \
        OBS_IMAGE=obs:t HOLD_IMAGE=img:t IMAGES_BUILT=1 STUB_CALLS=$dst_stub/calls.txt \
        PATH="$dst_stub:$PATH" delete_owned \
        || { echo "delete_owned failed" >&2; exit 1; }
    grep -q "kind delete cluster --name p11scope-c3-t" "$dst_stub/calls.txt" \
        || { echo "cleanup lost its cluster deletion" >&2; exit 1; }
    grep -q "docker image rm -f obs:t img:t" "$dst_stub/calls.txt" \
        || { echo "cleanup lost its image removal" >&2; exit 1; }
    # A run that died before the cluster existed still removes its images.
    : > "$dst_stub/calls.txt"
    CLUSTER=p11scope-c3-t KUBECONFIG=$dst_stub/work/kubeconfig CLUSTER_CREATED= \
        OBS_IMAGE=obs:t HOLD_IMAGE=img:t IMAGES_BUILT=1 STUB_CALLS=$dst_stub/calls.txt \
        PATH="$dst_stub:$PATH" delete_owned \
        || { echo "delete_owned failed" >&2; exit 1; }
    if grep -q "kind delete cluster" "$dst_stub/calls.txt"; then
        echo "cleanup deleted a cluster it never created" >&2
        exit 1
    fi
    grep -q "docker image rm -f obs:t img:t" "$dst_stub/calls.txt" \
        || { echo "cleanup lost its image removal" >&2; exit 1; }
    keep_out=$(CLUSTER=p11scope-c3-t KUBECONFIG=$dst_stub/work/kubeconfig CLUSTER_CREATED=1 \
        OBS_IMAGE=obs:t HOLD_IMAGE=img:t IMAGES_BUILT=1 keep_message 2>&1)
    case $keep_out in
        *"kind delete cluster --name p11scope-c3-t"*"docker image rm -f obs:t img:t"*) ;;
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
    line="SUMMARY cell=C3 verdict=$1 reason=\"$2\""
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

# Both images from staged minimal contexts, exactly as scripts/kind-e2e.sh
# builds them: the static observer plus the entry script, and the holder.
build_images() {
    [ "$(grep -c "FROM $OBSERVER_BASE" "$OBSERVER_DOCKERFILE")" -eq 1 ] \
        || { echo "observer base pin drifted" >&2; return 1; }
    [ "$(grep -c "FROM $HOLDER_BASE" "$HOLDER_DOCKERFILE")" -eq 2 ] \
        || { echo "holder base pin drifted" >&2; return 1; }
    OCTX=$WORK/context-observer
    HCTX=$WORK/context-holder
    mkdir -p "$OCTX/target/x86_64-unknown-linux-musl/release" "$OCTX/scripts" \
        "$HCTX/tests/fixtures/public-cli" "$HCTX/deploy"
    cp "$OBSERVER" "$OCTX/target/x86_64-unknown-linux-musl/release/p11scope"
    cp scripts/k8s-profile-entry.sh "$OCTX/scripts/"
    cp tests/fixtures/public-cli/gated.c "$HCTX/tests/fixtures/public-cli/"
    cp deploy/holder-entry.sh "$HCTX/deploy/"
    timeout --signal=TERM --kill-after=10s 1200s \
        docker build -q -f "$OBSERVER_DOCKERFILE" -t "$OBS_IMAGE" "$OCTX" || return 1
    timeout --signal=TERM --kill-after=10s 1200s \
        docker build -q -f "$HOLDER_DOCKERFILE" -t "$HOLD_IMAGE" "$HCTX" || return 1
    OBS_ID=$(docker inspect --format '{{.Id}}' "$OBS_IMAGE") \
        || { echo "observer image id failed" >&2; return 1; }
    HOLD_ID=$(docker inspect --format '{{.Id}}' "$HOLD_IMAGE") \
        || { echo "holder image id failed" >&2; return 1; }
    fact "observer-image=$OBS_IMAGE id=$OBS_ID base=$OBSERVER_BASE"
    fact "holder-image=$HOLD_IMAGE id=$HOLD_ID base=$HOLDER_BASE"
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

# Profile readiness: the capture line (the inventories are synchronous
# one-shot execs, not background captures).
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

# The pod's main pid as the node (and so the hostPID observer) numbers it.
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

# Extract one pod's document from a multi-document workloads file: exactly
# one match, written alone (the cold pod is deleted and recreated from it).
extract_pod_doc() {
    python3 -I - "$1" "$2" "$3" <<'PY'
import sys
docs, current = [], []
with open(sys.argv[1], encoding="utf-8") as handle:
    for line in handle:
        if line.strip() == "---":
            docs.append(current)
            current = []
        else:
            current.append(line)
docs.append(current)
texts = ["".join(doc) for doc in docs]
matches = [text for text in texts if f"name: {sys.argv[2]}\n" in text]
if len(matches) != 1:
    raise SystemExit(f"want 1 {sys.argv[2]} document, got {len(matches)}")
with open(sys.argv[3], "w", encoding="utf-8") as handle:
    handle.write(matches[0])
PY
}

# The recreated pod must be a NEW pod: a reused UID would make the cold
# start vacuous.
assert_uid_changed() {
    [ "$#" -eq 2 ] && [ -n "$1" ] && [ -n "$2" ] && [ "$1" != "$2" ] || {
        echo "cold pod uid did not change: [${1-}] -> [${2-}]" >&2
        return 1
    }
}

# The failure twin: a deleted pid is absent from callers, or present with
# no edge. An edge for the deleted pid is phantom attribution.
absent_or_edgeless() {
    python3 -I - "$1" "$2" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
pid = int(sys.argv[2])
pid_of = {caller["id"]: caller["pid"] for caller in document["callers"]}
if pid not in pid_of.values():
    print(json.dumps({"check": "failure-twin", "ok": True, "shape": "absent", "pid": pid},
                     sort_keys=True))
    raise SystemExit(0)
caller_ids = {cid for cid, p in pid_of.items() if p == pid}
for edge in document["edges"]:
    if edge["caller"] in caller_ids:
        raise SystemExit(f"deleted pid {pid} still has a caller edge")
print(json.dumps({"check": "failure-twin", "ok": True, "shape": "present-with-no-edge",
                  "pid": pid}, sort_keys=True))
PY
}

# The twin's positive control: the twin capture must still be a healthy
# scan (caller A keeps its edge, idle still scanned edgeless) before B's
# absence proves anything; without it an empty twin capture passes
# vacuously (absent B, refused positive oracle).
twin_positive_control() {
    oracle_inventory "$1" --caller "$2" --non-caller "$3" || {
        echo "twin inventory is not a healthy scan" >&2
        return 1
    }
}

oracle_profile() {
    python3 -I "$ORACLE" --expect-observer nested profile-exact "$1" "$2"
}

oracle_inventory() {
    oi_file=$1
    shift
    python3 -I "$ORACLE" --expect-observer nested inventory "$oi_file" "$@"
}

# capture NAME [k8s-profile-entry args...]: background `kubectl exec`; the
# capture's stdout/stderr land in WORK/NAME.{out,err}.
# STARTED_PID is the new capture's local `kubectl exec`, which lives exactly as
# long as the capture in the pod; CAPTURE_PIDS keeps every live one for cleanup.
start_capture() {
    sc_name=$1
    shift
    kc -n "$OBS_NS" exec "$OBS" -- "$@" > "$WORK/$sc_name.out" 2> "$WORK/$sc_name.err" &
    CAPTURE_PIDS="${CAPTURE_PIDS-} $!"
    STARTED_PID=$!
}

# finish_capture NAME EXT PID
finish_capture() {
    fc_status=0
    wait "$3" || fc_status=$?
    [ "$fc_status" -eq 0 ] || {
        echo "capture $1 exited $fc_status" >&2
        cat "$WORK/$1.err" >&2
        return 1
    }
    kc -n "$OBS_NS" cp "$OBS:/tmp/$1.$2" "$WORK/$1.$2" >/dev/null
}

# Its own cluster and images, nothing else (the trap calls this).
delete_owned() {
    [ -z "${CLUSTER_CREATED-}" ] || timeout --signal=TERM --kill-after=10s 300s \
        kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 || true
    [ -z "${IMAGES_BUILT-}" ] || docker image rm -f "$OBS_IMAGE" "$HOLD_IMAGE" >/dev/null 2>&1 || true
}

keep_message() {
    [ -z "${CLUSTER_CREATED-}" ] || echo "kept cluster $CLUSTER (--keep): KUBECONFIG=$KUBECONFIG; delete with: kind delete cluster --name $CLUSTER --kubeconfig $KUBECONFIG" >&2
    [ -z "${IMAGES_BUILT-}" ] || echo "kept images $OBS_IMAGE $HOLD_IMAGE (--keep); delete with: docker image rm -f $OBS_IMAGE $HOLD_IMAGE" >&2
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

CLUSTER=p11scope-c3-$TOKEN
OBS_IMAGE=p11scope-c3-observer:$TOKEN
HOLD_IMAGE=p11scope-c3-holder:$TOKEN
if [ -n "$WORK_OPT" ]; then
    [ ! -e "$WORK_OPT" ] || { echo "$WORK_OPT already exists" >&2; exit 1; }
    mkdir -m 0700 "$WORK_OPT"
    WORK=$(cd "$WORK_OPT" && pwd -P)
else
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-c3-XXXXXX")
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

observe() {
    kc -n "$OBS_NS" exec "$OBS" -- "$@"
}

fact "cell=C3 token=$TOKEN date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fact "observer=$OBSERVER sha256=$(sha256sum "$OBSERVER" | awk '{print $1}')"
fact "images=$OBS_IMAGE,$HOLD_IMAGE duration=$DURATION"
record_tool_facts || unrun "tool versions unavailable"
assert_cluster_free "$CLUSTER" || unrun "cluster $CLUSTER already exists"

say "=== build images $OBS_IMAGE $HOLD_IMAGE ==="
build_images || unrun "image builds failed"
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
say "=== load images ==="
timeout --signal=TERM --kill-after=10s 1200s \
    kind load docker-image --name "$CLUSTER" "$OBS_IMAGE" "$HOLD_IMAGE" \
    || unrun "image load failed"

say "=== apply deploy/k8s as documented (directory apply; image names rendered) ==="
MANIFESTS=$WORK/manifests
mkdir -p "$MANIFESTS/k8s"
for manifest in deploy/k8s/*.yaml; do
    sed "s#image: p11scope-observer:1\$#image: $OBS_IMAGE#" "$manifest" > "$MANIFESTS/k8s/${manifest##*/}"
done
grep -q "image: $OBS_IMAGE" "$MANIFESTS/k8s/20-daemonset.yaml" \
    || unrun "daemonset render lost its image anchor"
kc apply -f "$MANIFESTS/k8s/" || unrun "daemonset apply failed"
sed "s#image: p11scope-holder:1\$#image: $HOLD_IMAGE#" "$WORKLOADS" > "$MANIFESTS/workloads.yaml"
[ "$(grep -c "image: $HOLD_IMAGE" "$MANIFESTS/workloads.yaml")" -eq 6 ] \
    || unrun "workloads render lost an image anchor"
kc apply -f "$MANIFESTS/workloads.yaml" || unrun "workloads apply failed"
kc -n "$OBS_NS" rollout status daemonset/p11scope-observer --timeout=240s \
    || unrun "observer never rolled out"
kc -n "$WL_NS" wait --for=condition=Ready pod --all --timeout=240s \
    || unrun "workloads never became Ready"
wait_log ledger-a '^READY ' 120 || unrun "ledger-a never became ready"
wait_log ledger-b '^READY ' 120 || unrun "ledger-b never became ready"

OBS=$(kc -n "$OBS_NS" get pod -l app.kubernetes.io/component=observer -o jsonpath='{.items[0].metadata.name}')
[ -n "$OBS" ] || unrun "no observer pod"
UID_A=$(pod_uid ledger-a) || unrun "no uid for ledger-a"
UID_B_OLD=$(pod_uid ledger-b) || unrun "no uid for ledger-b"

say "=== anchor: release ledger-a ($ITERS_A_DEFAULT), capture it once ==="
start_capture c3-anchor k8s-profile-entry --pod-uid "$UID_A" -- \
    --duration "$DURATION" -o /tmp/c3-anchor.json
PID_ANCHOR=$STARTED_PID
wait_ready c3-anchor "$PID_ANCHOR" || fail_cell "anchor capture never became ready"
release_pod ledger-a || fail_cell "gate release failed for ledger-a"
wait_log ledger-a '^LEDGER ' 120 || fail_cell "ledger-a ledger never completed"
kill -0 "$PID_ANCHOR" 2>/dev/null || fail_cell "ledger-a ledger completed outside the capture window"
finish_capture c3-anchor json "$PID_ANCHOR" || fail_cell "anchor capture failed"
pod_ledger_is ledger-a "$ITERS_A_DEFAULT" || fail_cell "ledger-a ledger is not 6x$ITERS_A_DEFAULT"
grep -h '^LEDGER ' "$WORK/logs-ledger-a.txt" >>"$FACTS"
RESULT=$(oracle_profile "$WORK/c3-anchor.json" "$ITERS_A_DEFAULT") \
    || fail_cell "anchor oracle refused"
record "$RESULT"

say "=== cold start: delete and recreate ledger-b as a NEW pod ==="
PID_B_OLD=$(node_pid ledger-b) || fail_cell "no node pid for old ledger-b"
fact "pid-b-old=$PID_B_OLD uid-b-old=$UID_B_OLD"
kc -n "$WL_NS" delete pod ledger-b || fail_cell "old ledger-b deletion failed"
kc -n "$WL_NS" wait --for=delete pod/ledger-b --timeout=120s \
    || fail_cell "old ledger-b never deleted"
extract_pod_doc "$MANIFESTS/workloads.yaml" ledger-b "$WORK/ledger-b.yaml" \
    || fail_cell "ledger-b extraction failed"
grep -q "image: $HOLD_IMAGE" "$WORK/ledger-b.yaml" \
    || fail_cell "extracted ledger-b lost its rendered image"
kc apply -f "$WORK/ledger-b.yaml" || fail_cell "cold ledger-b apply failed"
kc -n "$WL_NS" wait --for=condition=Ready pod/ledger-b --timeout=240s \
    || fail_cell "cold ledger-b never became Ready"
wait_log ledger-b '^READY ' 120 || fail_cell "cold ledger-b never became ready"
UID_B_NEW=$(pod_uid ledger-b) || fail_cell "no uid for cold ledger-b"
assert_uid_changed "$UID_B_OLD" "$UID_B_NEW" || fail_cell "cold ledger-b is not a new pod"
PID_B_NEW=$(node_pid ledger-b) || fail_cell "no node pid for cold ledger-b"
fact "pid-b-new=$PID_B_NEW uid-b-new=$UID_B_NEW"

say "=== command 1: per-pod profile of the cold pod, exactly 6x$ITERS_B_DEFAULT ==="
start_capture c3-b k8s-profile-entry --pod-uid "$UID_B_NEW" -- \
    --duration "$DURATION" -o /tmp/c3-b.json
PID_B_CAP=$STARTED_PID
wait_ready c3-b "$PID_B_CAP" || fail_cell "cold-pod capture never became ready"
release_pod ledger-b || fail_cell "gate release failed for ledger-b"
wait_log ledger-b '^LEDGER ' 120 || fail_cell "ledger-b ledger never completed"
kill -0 "$PID_B_CAP" 2>/dev/null || fail_cell "ledger-b ledger completed outside the capture window"
finish_capture c3-b json "$PID_B_CAP" || fail_cell "cold-pod capture failed"
pod_ledger_is ledger-b "$ITERS_B_DEFAULT" || fail_cell "ledger-b ledger is not 6x$ITERS_B_DEFAULT"
grep -h '^LEDGER ' "$WORK/logs-ledger-b.txt" >>"$FACTS"
RESULT=$(oracle_profile "$WORK/c3-b.json" "$ITERS_B_DEFAULT") \
    || fail_cell "cold-pod oracle refused"
record "$RESULT"

say "=== command 2: node-wide inventory, both A and B are callers ==="
PID_A=$(node_pid ledger-a) || fail_cell "no node pid for ledger-a"
PID_B=$(node_pid ledger-b) || fail_cell "no node pid for ledger-b"
PID_IDLE=$(node_pid idle) || fail_cell "no node pid for idle"
fact "pid-a=$PID_A pid-b=$PID_B pid-idle=$PID_IDLE"
observe p11scope inventory --system --caller-metadata none -o /tmp/c3-inv.json \
    > "$WORK/c3-inv.out" 2> "$WORK/c3-inv.err" || {
        cat "$WORK/c3-inv.err" >&2
        fail_cell "inventory capture failed"
    }
kc -n "$OBS_NS" cp "$OBS:/tmp/c3-inv.json" "$WORK/c3-inv.json" >/dev/null \
    || fail_cell "inventory copy failed"
RESULT=$(oracle_inventory "$WORK/c3-inv.json" \
    --caller "$PID_A" --caller "$PID_B" --non-caller "$PID_IDLE") \
    || fail_cell "inventory oracle refused"
record "$RESULT"

say "=== failure twin: B deleted, the oracle must refuse ==="
kc -n "$WL_NS" delete pod ledger-b || fail_cell "twin ledger-b deletion failed"
kc -n "$WL_NS" wait --for=delete pod/ledger-b --timeout=120s \
    || fail_cell "twin ledger-b never deleted"
observe p11scope inventory --system --caller-metadata none -o /tmp/c3-inv-nob.json \
    > "$WORK/c3-inv-nob.out" 2> "$WORK/c3-inv-nob.err" || {
        cat "$WORK/c3-inv-nob.err" >&2
        fail_cell "twin inventory capture failed"
    }
kc -n "$OBS_NS" cp "$OBS:/tmp/c3-inv-nob.json" "$WORK/c3-inv-nob.json" >/dev/null \
    || fail_cell "twin inventory copy failed"
RESULT=$(twin_positive_control "$WORK/c3-inv-nob.json" "$PID_A" "$PID_IDLE") \
    || fail_cell "twin inventory is not a healthy scan (caller A lost its edge)"
record "$RESULT"
RESULT=$(absent_or_edgeless "$WORK/c3-inv-nob.json" "$PID_B") \
    || fail_cell "deleted B still has an edge (phantom attribution)"
record "$RESULT"
if oracle_inventory "$WORK/c3-inv-nob.json" \
        --caller "$PID_A" --caller "$PID_B" --non-caller "$PID_IDLE" >/dev/null 2>&1; then
    fail_cell "inventory oracle still attributes deleted B"
fi

summarize PASS "C3 cold pod joined exactly with an edge; anchor exact; deleted-B twin distinguished"

#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Kubernetes e2e for the DaemonSet node observer (deploy/k8s) on a private,
# uniquely named kind cluster that this script creates and always deletes.
#
#   1. builds the static observer from this tree (or takes
#      P11SCOPE_K8S_OBSERVER_BIN, or packages P11SCOPE_K8S_RELEASE_TARBALL)
#      and both images from a staged minimal context;
#   2. creates the cluster with a private kubeconfig (the caller's kubeconfig
#      and every other cluster are never touched) and loads the images;
#   3. applies deploy/k8s/ as documented (a directory apply of a copy where only
#      the image name is rendered), plus
#      the test-only workloads (deploy/k8s/e2e/workloads.yaml): ledgered
#      SoftHSM2 clients with known call counts and an idle negative control;
#   4. asserts the live posture (exact capability set, no API token, no RBAC,
#      read-only root, seccomp) and runs the cells below through
#      `kubectl exec` + scripts/k8s-profile-entry.sh, checking every capture
#      against the workload's own ledger with scripts/kind-e2e-oracle.py.
#
# Cells (each workload runs its ledgered loop once, released from the node):
#   doctor    `doctor --cgroup` in the pod reports capture available, and
#             names the nested PID namespace (PID scope unavailable)
#   profile-a positive control and isolation: two concurrent captures, one
#   profile-b per pod, count exactly 6 x 400 (ledger-a) and 6 x 250 (ledger-b;
#             same image, provider inode and node); both must still be running
#             (kill -0) once both ledgers are complete
#   profile-p non-root workload, provider in a private 0700 directory: exactly
#             6 x 300 (the CAP_DAC_READ_SEARCH case)
#   trace-t   exactly 6 x 200 call lines; records which PID namespace the
#             printed pid belongs to
#   negative  the idle pod (SoftHSM2 on disk, never mapped): no module, no
#             call, and its processes provably visible and readable
#   copy-up-neg (F11) the ledger-c pod stages the provider into its own
#             writable layer, side S maps and ledgers 400, one unmapped
#             byte is rewritten in place (same inode: a genuine change,
#             never a copy-up), and side F maps the changed file after an
#             8 s settle and ledgers 250. The spanning capture must count
#             exactly 6 x 400 on the one stale row, never admit F as a
#             second object, and disclose provider_changed (the oracle
#             subcommand is copy-up-neg; the module suffix is the staged
#             path /tmp/copyup/libsofthsm2.so)
#   inventory `inventory --system`: every ledger pod is a caller of the
#             provider; the idle pod is scanned with no edge
#   pid-probe `profile --pid <pid as the observer sees it>` is refused with
#             `pid-namespace-mismatch:` before anything runs, and writes no
#             report (DR-30/DR-K8S-1: a nested PID namespace cannot scope by
#             pid, so a silent zero must never happen)
#
# A kind node is a container, so the observer (hostPID: the node's namespace)
# is always in a nested PID namespace: every capture document must say so
# (`pid_namespace.observer` = nested) and carry exactly the `pid_namespace`
# observation cause, which makes it lossy (`concrete_gap`) while the ledger
# counts stay exact. The oracle applies that with --expect-observer nested.
#
# Usage: scripts/kind-e2e.sh [--keep] | --self-test
#   --keep  keep the cluster and images for debugging (prints how to delete)
# Environment:
#   P11SCOPE_K8S_TOKEN         optional owned image token (short DNS label)
#   P11SCOPE_K8S_CLUSTER       cluster name (default p11scope-e2e-<time>-<pid>);
#                              refused if a cluster of that name already exists
#   P11SCOPE_K8S_OBSERVER_BIN  prebuilt static x86-64 p11scope to package
#                              (exclusive with P11SCOPE_K8S_RELEASE_TARBALL)
#   P11SCOPE_K8S_RELEASE_TARBALL release tarball
#                              (p11scope-<version>-x86_64-linux-musl.tar.gz) to
#                              package via deploy/Dockerfile.observer-release
#                              instead of building
#   P11SCOPE_K8S_RELEASE_SHA256SUMS SHA256SUMS file the release tarball
#                              must verify against (required with
#                              P11SCOPE_K8S_RELEASE_TARBALL)
#   P11SCOPE_K8S_TOOLCHAIN     cargo toolchain (default: .release-rust-version)
#   P11SCOPE_K8S_WORK          evidence directory (must not exist; default a
#                              fresh 0700 directory under $TMPDIR)
#   P11SCOPE_K8S_LOCK          lock file serializing each docker/kind/capture
#                              step with other privileged lanes on this host
#   P11SCOPE_K8S_NODE_IMAGE    kind node image (default: kind's own)
set -eu
cd "$(dirname "$0")/.."

ORACLE=scripts/kind-e2e-oracle.py
PIDNS_OBSERVER=nested
OBS_NS=p11scope
WL_NS=p11scope-e2e
KEEP=0

usage() {
    echo "usage: $0 [--keep] | --self-test" >&2
    exit 2
}

valid_cluster() {
    case $1 in
        ''|*[!a-z0-9-]*|-*|*-) return 1 ;;
        *) [ "${#1}" -le 40 ] ;;
    esac
}

# Verify a release tarball before it becomes the observer image: it must be
# a readable gzip tar holding exactly one `*/p11scope` regular file and no
# absolute or parent-climbing members, and when $2 (a SHA256SUMS file) is
# given, the tarball's entry there must match.
verify_release_tarball() {
    [ -f "$1" ] && [ -r "$1" ] || { echo "release tarball is not a readable file: $1" >&2; return 1; }
    members=$(tar -tzf "$1" 2>/dev/null) || { echo "release tarball does not list: $1" >&2; return 1; }
    verbose=$(tar -tzvf "$1" 2>/dev/null) || { echo "release tarball does not list: $1" >&2; return 1; }
    if printf '%s\n' "$members" | grep -qE '(^/|(^|/)\.\.(/|$))'; then
        echo "release tarball has unsafe members: $1" >&2
        return 1
    fi
    # Exactly one regular file member (a symlink or directory named
    # `p11scope` does not count); spaced names fail closed.
    [ "$(printf '%s\n' "$verbose" | grep -cE '^-.* [^ ]*/p11scope$')" -eq 1 ] \
        || { echo "release tarball must hold exactly one p11scope binary: $1" >&2; return 1; }
    if [ -n "${2-}" ]; then
        [ -f "$2" ] || { echo "SHA256SUMS file is missing: $2" >&2; return 1; }
        base=${1##*/}
        line=$(awk -v want="$base" '$2 == want' "$2" | head -n 1)
        [ -n "$line" ] || { echo "SHA256SUMS has no entry for $base" >&2; return 1; }
        (cd "${1%/*}" 2>/dev/null || cd .; printf '%s\n' "$line" | sha256sum -c --status -) \
            || { echo "release tarball checksum mismatch: $1" >&2; return 1; }
    fi
}

# Print the verified sha256 of a release tarball from its SHA256SUMS
# entry (the TARBALL_SHA256 docker build arg). The checksum is verified
# here, not just looked up, so the printed hash is the checked one.
release_tarball_sha256() {
    [ -f "$2" ] || { echo "SHA256SUMS file is missing: $2" >&2; return 1; }
    base=${1##*/}
    line=$(awk -v want="$base" '$2 == want' "$2" | head -n 1)
    [ -n "$line" ] || { echo "SHA256SUMS has no entry for $base" >&2; return 1; }
    (cd "${1%/*}" 2>/dev/null || cd .; printf '%s\n' "$line" | sha256sum -c --status -) \
        || { echo "release tarball checksum mismatch: $1" >&2; return 1; }
    printf '%s\n' "$line" | awk '{print $1}'
}

# Exactly one complete gated JSON ledger with 6xN successes (gated.c prints
# `READY pid=` once and one `LEDGER {...}` line with complete/attempts/
# successful), the same rule as the container-cell drivers.
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

ledger_is() {
    ledger_tmp=$(mktemp "${TMPDIR:-/tmp}/p11scope-kind-ledger-XXXXXX") || return 1
    kc -n "$WL_NS" logs "$1" > "$ledger_tmp" || {
        echo "cannot read logs for $1" >&2
        rm -f "$ledger_tmp"
        return 1
    }
    ledger_check "$ledger_tmp" "$2" || {
        echo "$1 did not ledger $2 clean iterations" >&2
        cat "$ledger_tmp" >&2
        rm -f "$ledger_tmp"
        return 1
    }
    rm -f "$ledger_tmp"
}

# Two complete gated JSON ledgers: side S ran 6x$2, side F 6x$3, in that
# order (the copy-up negative pod runs both sides through one gate).
ledgers2_check() {
    python3 -I - "$1" "$2" "$3" <<'PY'
import json, sys
ready = 0
ledgers = []
for line in open(sys.argv[1]).read().splitlines():
    if line.startswith("READY "):
        ready += 1
    elif line.startswith("LEDGER "):
        ledgers.append(json.loads(line[len("LEDGER "):]))
if ready != 2 or len(ledgers) != 2:
    raise SystemExit(f"want 2 READY and 2 LEDGER, got {ready} and {len(ledgers)}")
for ledger, iters in zip(ledgers, (int(sys.argv[2]), int(sys.argv[3]))):
    if ledger.get("schema") != "p11scope/public-cli-ledger/v1":
        raise SystemExit("bad ledger schema")
    if ledger.get("complete") is not True:
        raise SystemExit("ledger incomplete")
    functions = ledger.get("functions")
    if not isinstance(functions, list) or len(functions) != 6:
        raise SystemExit("want 6 ledger functions")
    for row in functions:
        if row.get("attempts") != iters or row.get("successful") != iters:
            raise SystemExit(f"ledger row is not 6x{iters}: {row}")
    if len({row.get("name") for row in functions}) != 6:
        raise SystemExit("ledger function names are not distinct")
PY
}

ledgers2_is() {
    ledger_tmp=$(mktemp "${TMPDIR:-/tmp}/p11scope-kind-ledger-XXXXXX") || return 1
    kc -n "$WL_NS" logs "$1" > "$ledger_tmp" || {
        rm -f "$ledger_tmp"
        return 1
    }
    ledgers2_check "$ledger_tmp" "$2" "$3" || {
        echo "$1 did not ledger 6x$2 then 6x$3" >&2
        cat "$ledger_tmp" >&2
        rm -f "$ledger_tmp"
        return 1
    }
    rm -f "$ledger_tmp"
}

self_test() {
    python3 -I "$ORACLE" --self-test
    sh scripts/k8s-profile-entry.sh --self-test
    sh deploy/holder-entry.sh --self-test
    # Rendering replaces exactly these anchors; a manifest edit that drops one
    # would silently deploy the wrong image.
    [ "$(cat deploy/k8s/*.yaml | grep -c 'image: ghcr.io/mingulov/p11scope:0.7.0$')" -eq 1 ] \
        || { echo "deploy/k8s lost its single observer image anchor" >&2; exit 1; }
    # `kubectl apply -f deploy/k8s/` applies files in name order: the
    # namespace must sort before everything that lives in it.
    set -- deploy/k8s/*.yaml
    [ "$1" = deploy/k8s/00-namespace.yaml ] \
        || { echo "deploy/k8s/00-namespace.yaml must sort first" >&2; exit 1; }
    [ "$(grep -c 'image: p11scope-holder:1$' deploy/k8s/e2e/workloads.yaml)" -eq 6 ] \
        || { echo "workloads.yaml lost an image anchor" >&2; exit 1; }
    [ "$(grep -c 'image: p11scope-holder:1$' deploy/k8s/e2e/workloads-copyup.yaml)" -eq 1 ] \
        || { echo "workloads-copyup.yaml lost its image anchor" >&2; exit 1; }
    for name in ok p11scope-e2e-1-2 a; do
        valid_cluster "$name" || { echo "valid_cluster rejected $name" >&2; exit 1; }
    done
    for name in "" -x x- Upper under_score "a.b" 01234567890123456789012345678901234567890; do
        if valid_cluster "$name"; then echo "valid_cluster accepted $name" >&2; exit 1; fi
    done
    for bad in "--bogus" "--keep --bogus" "--self-test extra"; do
        status=0
        # shellcheck disable=SC2086
        sh "$0" $bad >/dev/null 2>&1 || status=$?
        [ "$status" -eq 2 ] || { echo "kind-e2e exited $status (want 2) for: [$bad]" >&2; exit 1; }
    done
    # The K pods print the JSON ledger: holder-entry execs the gated client
    # built from tests/fixtures/public-cli/gated.c. Each form goes through
    # ledger_is with a stubbed kc, no cluster.
    kc() {
        cat "$LEDGER_STUB_LOG"
    }
    ledger_stub=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-kind-ledger-XXXXXX")
    # shellcheck disable=SC2064
    trap "rm -rf '$ledger_stub'" EXIT
    printf '%s\n' 'READY pid=1' \
        'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":1,"complete":true,"functions":[{"name":"C_GenerateRandom","attempts":400,"successful":400},{"name":"C_DigestInit","attempts":400,"successful":400},{"name":"C_Digest","attempts":400,"successful":400},{"name":"C_FindObjectsInit","attempts":400,"successful":400},{"name":"C_FindObjects","attempts":400,"successful":400},{"name":"C_FindObjectsFinal","attempts":400,"successful":400}]}' \
        > "$ledger_stub/good.log"
    printf '%s\n' 'READY pid=1' 'LEDGER iterations=400 nonzero_rv=0' > "$ledger_stub/legacy.log"
    printf '%s\n' 'READY pid=1' 'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":1,"complete":false,"functions":[{"name":"C_GenerateRandom","attempts":400,"successful":400},{"name":"C_DigestInit","attempts":400,"successful":400},{"name":"C_Digest","attempts":400,"successful":400},{"name":"C_FindObjectsInit","attempts":400,"successful":400},{"name":"C_FindObjects","attempts":400,"successful":400},{"name":"C_FindObjectsFinal","attempts":400,"successful":400}]}' \
        > "$ledger_stub/incomplete.log"
    printf '%s\n' 'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":1,"complete":true,"functions":[{"name":"C_GenerateRandom","attempts":399,"successful":399}]}' \
        > "$ledger_stub/short.log"
    printf '%s\n' 'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":1,"complete":true,"functions":[{"name":"C_GenerateRandom","attempts":400,"successful":399},{"name":"C_DigestInit","attempts":400,"successful":400},{"name":"C_Digest","attempts":400,"successful":400},{"name":"C_FindObjectsInit","attempts":400,"successful":400},{"name":"C_FindObjects","attempts":400,"successful":400},{"name":"C_FindObjectsFinal","attempts":400,"successful":400}]}' \
        > "$ledger_stub/failed.log"
    printf '%s\n' 'READY pid=1' > "$ledger_stub/missing.log"
    LEDGER_STUB_LOG=$ledger_stub/good.log
    ledger_is stub-pod 400 || { echo "good JSON LEDGER refused" >&2; exit 1; }
    for bad in legacy incomplete short failed missing; do
        LEDGER_STUB_LOG=$ledger_stub/$bad.log
        if ledger_is stub-pod 400 >/dev/null 2>&1; then
            echo "bad LEDGER accepted: $bad" >&2
            exit 1
        fi
    done
    # verify_release_tarball: a layout-identical good tarball passes with and
    # without sums; every bad shape refuses. No docker needed.
    tar_stub=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-kind-tarball-XXXXXX")
    # shellcheck disable=SC2064
    trap "rm -rf '$ledger_stub' '$tar_stub'" EXIT
    mkdir -p "$tar_stub/good/p11scope-0.7.0-x86_64-linux-musl" "$tar_stub/out"
    printf '#!/bin/sh\necho test-observer\n' > "$tar_stub/good/p11scope-0.7.0-x86_64-linux-musl/p11scope"
    chmod 0755 "$tar_stub/good/p11scope-0.7.0-x86_64-linux-musl/p11scope"
    printf '{"version":"0.7.0"}\n' > "$tar_stub/good/p11scope-0.7.0-x86_64-linux-musl/RELEASE.json"
    (cd "$tar_stub/good" && tar -czf "$tar_stub/out/good.tar.gz" p11scope-0.7.0-x86_64-linux-musl)
    (cd "$tar_stub/out" && sha256sum good.tar.gz > SHA256SUMS)
    verify_release_tarball "$tar_stub/out/good.tar.gz" "$tar_stub/out/SHA256SUMS" \
        || { echo "good tarball refused" >&2; exit 1; }
    verify_release_tarball "$tar_stub/out/good.tar.gz" "" \
        || { echo "good tarball refused without sums" >&2; exit 1; }
    (cd "$tar_stub/out" && sha256sum good.tar.gz | sed 's/^../zz/' > WRONG.sums)
    if verify_release_tarball "$tar_stub/out/good.tar.gz" "$tar_stub/out/WRONG.sums" >/dev/null 2>&1; then
        echo "checksum mismatch accepted" >&2; exit 1
    fi
    printf '%s  %s\n' \
        0000000000000000000000000000000000000000000000000000000000000000 \
        other.tar.gz > "$tar_stub/out/OTHER.sums"
    if verify_release_tarball "$tar_stub/out/good.tar.gz" "$tar_stub/out/OTHER.sums" >/dev/null 2>&1; then
        echo "sums without the tarball entry accepted" >&2; exit 1
    fi
    if verify_release_tarball "$tar_stub/out/good.tar.gz" "$tar_stub/out/missing.sums" >/dev/null 2>&1; then
        echo "missing sums file accepted" >&2; exit 1
    fi
    # release_tarball_sha256 prints the checked hash for the docker build
    # arg; mismatches and missing entries refuse. No docker needed.
    want_hash=$(cd "$tar_stub/out" && sha256sum good.tar.gz | awk '{print $1}')
    got_hash=$(release_tarball_sha256 "$tar_stub/out/good.tar.gz" "$tar_stub/out/SHA256SUMS") \
        || { echo "good tarball hash refused" >&2; exit 1; }
    [ "$got_hash" = "$want_hash" ] || { echo "wrong tarball hash: $got_hash" >&2; exit 1; }
    if release_tarball_sha256 "$tar_stub/out/good.tar.gz" "$tar_stub/out/WRONG.sums" >/dev/null 2>&1; then
        echo "mismatched hash accepted" >&2; exit 1
    fi
    if release_tarball_sha256 "$tar_stub/out/good.tar.gz" "$tar_stub/out/OTHER.sums" >/dev/null 2>&1; then
        echo "sums without the tarball entry accepted" >&2; exit 1
    fi
    if release_tarball_sha256 "$tar_stub/out/good.tar.gz" "$tar_stub/out/missing.sums" >/dev/null 2>&1; then
        echo "missing sums file accepted for the hash" >&2; exit 1
    fi
    mkdir -p "$tar_stub/none/p-0" && printf '{}\n' > "$tar_stub/none/p-0/RELEASE.json"
    (cd "$tar_stub/none" && tar -czf "$tar_stub/out/none.tar.gz" p-0)
    if verify_release_tarball "$tar_stub/out/none.tar.gz" "" >/dev/null 2>&1; then
        echo "tarball without a binary accepted" >&2; exit 1
    fi
    mkdir -p "$tar_stub/two/p-a" "$tar_stub/two/p-b"
    printf 'x\n' > "$tar_stub/two/p-a/p11scope"
    printf 'x\n' > "$tar_stub/two/p-b/p11scope"
    (cd "$tar_stub/two" && tar -czf "$tar_stub/out/two.tar.gz" p-a p-b)
    if verify_release_tarball "$tar_stub/out/two.tar.gz" "" >/dev/null 2>&1; then
        echo "tarball with two binaries accepted" >&2; exit 1
    fi
    mkdir -p "$tar_stub/link/p-0" && ln -s /bin/true "$tar_stub/link/p-0/p11scope"
    (cd "$tar_stub/link" && tar -czf "$tar_stub/out/link.tar.gz" p-0)
    if verify_release_tarball "$tar_stub/out/link.tar.gz" "" >/dev/null 2>&1; then
        echo "tarball with a symlinked binary accepted" >&2; exit 1
    fi
    (cd "$tar_stub/good" && tar -czf "$tar_stub/out/abs.tar.gz" -P "$tar_stub/good/p11scope-0.7.0-x86_64-linux-musl/p11scope")
    if verify_release_tarball "$tar_stub/out/abs.tar.gz" "" >/dev/null 2>&1; then
        echo "tarball with an absolute member accepted" >&2; exit 1
    fi
    if verify_release_tarball "$tar_stub/out/missing.tar.gz" "" >/dev/null 2>&1; then
        echo "missing tarball accepted" >&2; exit 1
    fi
    rm -rf "$tar_stub"
    led2() {
        printf '%s\n' "READY pid=$1" \
            "LEDGER {\"schema\":\"p11scope/public-cli-ledger/v1\",\"pid\":$1,\"complete\":true,\"functions\":[{\"name\":\"C_GenerateRandom\",\"attempts\":$2,\"successful\":$2},{\"name\":\"C_DigestInit\",\"attempts\":$2,\"successful\":$2},{\"name\":\"C_Digest\",\"attempts\":$2,\"successful\":$2},{\"name\":\"C_FindObjectsInit\",\"attempts\":$2,\"successful\":$2},{\"name\":\"C_FindObjects\",\"attempts\":$2,\"successful\":$2},{\"name\":\"C_FindObjectsFinal\",\"attempts\":$2,\"successful\":$2}]}"
    }
    { led2 10 400; led2 11 250; } > "$ledger_stub/good2.log"
    { led2 10 400; echo 'READY pid=11'; } > "$ledger_stub/half2.log"
    { led2 10 250; led2 11 400; } > "$ledger_stub/swapped2.log"
    LEDGER_STUB_LOG=$ledger_stub/good2.log
    ledgers2_is stub-pod 400 250 || { echo "good double LEDGER refused" >&2; exit 1; }
    for bad in half2 swapped2 good missing; do
        LEDGER_STUB_LOG=$ledger_stub/$bad.log
        if ledgers2_is stub-pod 400 250 >/dev/null 2>&1; then
            echo "bad double LEDGER accepted: $bad" >&2
            exit 1
        fi
    done
    rm -rf "$ledger_stub"
    trap - EXIT
    echo "kind-e2e self-test: OK"
    exit 0
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --self-test) [ "$#" -eq 1 ] || usage; self_test ;;
        --keep) KEEP=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

. scripts/lib.sh
require_non_root_caller
[ "$(uname -m)" = x86_64 ] || { echo "the observer image is x86-64 only" >&2; exit 1; }
for command in docker kind kubectl python3 timeout; do
    command -v "$command" >/dev/null || { echo "$command required" >&2; exit 1; }
done

TOKEN=${P11SCOPE_K8S_TOKEN:-$(date +%s)-$$}
valid_cluster "$TOKEN" || { echo "image token must be a short DNS label" >&2; exit 1; }
CLUSTER=${P11SCOPE_K8S_CLUSTER:-p11scope-e2e-$TOKEN}
valid_cluster "$CLUSTER" || { echo "cluster name must be a short DNS label: $CLUSTER" >&2; exit 1; }
NODE=$CLUSTER-control-plane
TOOLCHAIN=${P11SCOPE_K8S_TOOLCHAIN:-$(cat .release-rust-version)}
OBSERVER_BIN=${P11SCOPE_K8S_OBSERVER_BIN:-}
RELEASE_TARBALL=${P11SCOPE_K8S_RELEASE_TARBALL:-}
RELEASE_SUMS=${P11SCOPE_K8S_RELEASE_SHA256SUMS:-}
if [ -n "$RELEASE_TARBALL" ] && [ -n "$OBSERVER_BIN" ]; then
    echo "P11SCOPE_K8S_RELEASE_TARBALL and P11SCOPE_K8S_OBSERVER_BIN are exclusive" >&2
    exit 1
fi
if [ -n "$RELEASE_TARBALL" ] && [ -z "$RELEASE_SUMS" ]; then
    echo "P11SCOPE_K8S_RELEASE_TARBALL requires P11SCOPE_K8S_RELEASE_SHA256SUMS" >&2
    exit 1
fi
LOCK=${P11SCOPE_K8S_LOCK:-}
[ -z "$LOCK" ] || command -v flock >/dev/null || { echo "flock required for P11SCOPE_K8S_LOCK" >&2; exit 1; }
OBS_IMAGE=p11scope-observer:e2e-$TOKEN
HOLD_IMAGE=p11scope-holder:e2e-$TOKEN
if [ -n "${P11SCOPE_K8S_WORK-}" ]; then
    [ ! -e "$P11SCOPE_K8S_WORK" ] || { echo "$P11SCOPE_K8S_WORK already exists" >&2; exit 1; }
    mkdir -m 0700 "$P11SCOPE_K8S_WORK"
    WORK=$(cd "$P11SCOPE_K8S_WORK" && pwd -P)
else
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-kind-e2e-XXXXXX")
fi
KUBECONFIG=$WORK/kubeconfig
export KUBECONFIG
CLUSTER_CREATED=
IMAGES_BUILT=
SUMMARY=$WORK/summary.jsonl
CAPTURE_PIDS=
: > "$SUMMARY"

# One step holds the host lock at a time; fd 9 is never held across steps.
lock_step() {
    [ -z "$LOCK" ] || { exec 9>>"$LOCK" && flock 9; }
}
unlock_step() {
    [ -z "$LOCK" ] || { flock -u 9; exec 9>&-; }
}

kc() {
    timeout --signal=TERM --kill-after=10s 300s kubectl "$@"
}

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    for capture_pid in ${CAPTURE_PIDS-}; do
        kill "$capture_pid" 2>/dev/null
    done
    unlock_step 2>/dev/null
    if [ -n "$CLUSTER_CREATED" ] && [ "$KEEP" -eq 1 ]; then
        echo "kept cluster $CLUSTER (--keep): KUBECONFIG=$KUBECONFIG;" \
            "delete with: kind delete cluster --name $CLUSTER" >&2
    elif [ -n "$CLUSTER_CREATED" ]; then
        lock_step
        cleanup_step timeout --signal=TERM --kill-after=10s 300s \
            kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG"
        unlock_step
    fi
    if [ -n "$IMAGES_BUILT" ] && [ "$KEEP" -eq 0 ]; then
        cleanup_step docker image rm -f "$OBS_IMAGE" "$HOLD_IMAGE" >/dev/null
    fi
    echo "evidence directory: $WORK" >&2
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

# Gated results carry "ok": true; record-only lines carry "record_only": true
# and never count as a passed check.
record() {
    printf '%s\n' "$1" | tee -a "$SUMMARY"
}

if kind get clusters 2>/dev/null | grep -Fqx "$CLUSTER"; then
    echo "kind cluster $CLUSTER already exists; refusing to reuse or delete it" >&2
    exit 1
fi

OBS_DOCKERFILE=deploy/Dockerfile.observer
OBS_TARBALL_ARG=
OBS_TARBALL_SHA256=
if [ -n "$RELEASE_TARBALL" ]; then
    echo "=== verify the release tarball and unpack the observer ==="
    verify_release_tarball "$RELEASE_TARBALL" "$RELEASE_SUMS"
    OBS_TARBALL_SHA256=$(release_tarball_sha256 "$RELEASE_TARBALL" "$RELEASE_SUMS") || exit 1
    mkdir -p "$WORK/rel"
    member=$(tar -tzf "$RELEASE_TARBALL" | grep -E '/p11scope$')
    tar -xzf "$RELEASE_TARBALL" -C "$WORK/rel" "$member"
    OBSERVER_BIN=$WORK/rel/$member
    OBS_DOCKERFILE=deploy/Dockerfile.observer-release
    OBS_TARBALL_ARG=${RELEASE_TARBALL##*/}
elif [ -z "$OBSERVER_BIN" ]; then
    echo "=== build the static observer (cargo +$TOOLCHAIN, x86_64-unknown-linux-musl) ==="
    command -v musl-gcc >/dev/null || { echo "musl-gcc required (musl-tools)" >&2; exit 1; }
    SYSROOT=$(rustc "+$TOOLCHAIN" --print sysroot) \
        || { echo "toolchain $TOOLCHAIN is not installed: rustup toolchain install $TOOLCHAIN" >&2; exit 1; }
    [ -d "$SYSROOT/lib/rustlib/x86_64-unknown-linux-musl" ] || {
        echo "toolchain $TOOLCHAIN has no x86_64-unknown-linux-musl target;" \
            "run: rustup target add --toolchain $TOOLCHAIN x86_64-unknown-linux-musl" \
            "(or set P11SCOPE_K8S_TOOLCHAIN / P11SCOPE_K8S_OBSERVER_BIN)" >&2
        exit 1
    }
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
        timeout --signal=TERM --kill-after=10s 3600s scripts/cargo.sh "+$TOOLCHAIN" build \
        --locked --release --no-default-features \
        --target x86_64-unknown-linux-musl --bin p11scope
    OBSERVER_BIN=target/x86_64-unknown-linux-musl/release/p11scope
fi
[ -x "$OBSERVER_BIN" ] || { echo "$OBSERVER_BIN is not an executable" >&2; exit 1; }

echo "=== stage minimal build contexts ==="
OCTX=$WORK/context-observer
HCTX=$WORK/context-holder
mkdir -p "$OCTX/target/x86_64-unknown-linux-musl/release" "$OCTX/scripts" \
    "$HCTX/tests/fixtures/public-cli" "$HCTX/deploy"
if [ -n "$OBS_TARBALL_ARG" ]; then
    cp "$RELEASE_TARBALL" "$OCTX/$OBS_TARBALL_ARG"
    sha256sum "$RELEASE_TARBALL" | tee "$WORK/release-tarball.sha256"
    tar -tzf "$RELEASE_TARBALL" > "$WORK/release-tarball.members"
else
    cp "$OBSERVER_BIN" "$OCTX/target/x86_64-unknown-linux-musl/release/p11scope"
fi
cp scripts/k8s-profile-entry.sh "$OCTX/scripts/"
cp LICENSE COPYRIGHT "$OCTX/"
cp -r LICENSES "$OCTX/"
cp tests/fixtures/public-cli/gated.c "$HCTX/tests/fixtures/public-cli/"
cp tests/fixtures/public-cli/patch-unmapped.c "$HCTX/tests/fixtures/public-cli/"
cp deploy/holder-entry.sh "$HCTX/deploy/"
sha256sum "$OBSERVER_BIN" | tee "$WORK/observer.sha256"

echo "=== build images $OBS_IMAGE $HOLD_IMAGE ==="
lock_step
IMAGES_BUILT=1
if [ -n "$OBS_TARBALL_ARG" ]; then
    timeout --signal=TERM --kill-after=10s 1200s \
        docker build -q -f "$OBS_DOCKERFILE" --build-arg "TARBALL=$OBS_TARBALL_ARG" \
        --build-arg "TARBALL_SHA256=$OBS_TARBALL_SHA256" \
        -t "$OBS_IMAGE" "$OCTX"
else
    timeout --signal=TERM --kill-after=10s 1200s \
        docker build -q -f "$OBS_DOCKERFILE" -t "$OBS_IMAGE" "$OCTX"
fi
timeout --signal=TERM --kill-after=10s 1200s \
    docker build -q -f deploy/Dockerfile.holder -t "$HOLD_IMAGE" "$HCTX"
unlock_step

echo "=== create kind cluster $CLUSTER (private kubeconfig) ==="
lock_step
# Set before create: a create killed half-way must still be deleted. The name
# was proven unused above and carries this run's token by default.
CLUSTER_CREATED=1
timeout --signal=TERM --kill-after=10s 900s kind create cluster --name "$CLUSTER" \
    --kubeconfig "$KUBECONFIG" --wait 180s \
    ${P11SCOPE_K8S_NODE_IMAGE:+--image "$P11SCOPE_K8S_NODE_IMAGE"}
unlock_step
lock_step
timeout --signal=TERM --kill-after=10s 1200s \
    python3 -I scripts/kubernetes-runtime.py load-images --cluster "$CLUSTER" \
    ${P11SCOPE_K8S_NODE_IMAGE:+--node-image "$P11SCOPE_K8S_NODE_IMAGE"} "$OBS_IMAGE" "$HOLD_IMAGE"
unlock_step

echo "=== apply deploy/k8s as documented (directory apply; image names rendered) ==="
# The same top-level file set `kubectl apply -f deploy/k8s/` reads, in the same
# name order; only the image name changes.
MANIFESTS=$WORK/manifests
mkdir -p "$MANIFESTS/k8s"
for manifest in deploy/k8s/*.yaml; do
    sed "s#image: ghcr.io/mingulov/p11scope:0.7.0\$#image: $OBS_IMAGE#" "$manifest" > "$MANIFESTS/k8s/${manifest##*/}"
done
DAEMONSET=$MANIFESTS/k8s/20-daemonset.yaml
grep -q "image: $OBS_IMAGE" "$DAEMONSET"
kc apply -f "$MANIFESTS/k8s/"
sed "s#image: p11scope-holder:1\$#image: $HOLD_IMAGE#" deploy/k8s/e2e/workloads.yaml > "$MANIFESTS/workloads.yaml"
kc apply -f "$MANIFESTS/workloads.yaml"
sed "s#image: p11scope-holder:1\$#image: $HOLD_IMAGE#" deploy/k8s/e2e/workloads-copyup.yaml > "$MANIFESTS/workloads-copyup.yaml"
[ "$(grep -c "image: $HOLD_IMAGE" "$MANIFESTS/workloads-copyup.yaml")" -eq 1 ] \
    || { echo "workloads-copyup render lost its image anchor" >&2; exit 1; }
kc apply -f "$MANIFESTS/workloads-copyup.yaml"
kc -n "$OBS_NS" rollout status daemonset/p11scope-observer --timeout=240s
kc -n "$WL_NS" wait --for=condition=Ready pod --all --timeout=240s

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
for pod in ledger-a ledger-b ledger-p ledger-t ledger-n ledger-c; do
    wait_log "$pod" '^READY ' 120
done

pod_uid() {
    pu=$(kc -n "$WL_NS" get pod "$1" -o jsonpath='{.metadata.uid}')
    case $pu in ''|*[!0-9a-f-]*) echo "bad uid for $1: $pu" >&2; return 1 ;; esac
    printf '%s\n' "$pu"
}
# The pod's main pid as the node (and so the hostPID observer) numbers it.
node_pid() {
    np_cid=$(kc -n "$WL_NS" get pod "$1" -o jsonpath='{.status.containerStatuses[0].containerID}')
    np_cid=${np_cid#containerd://}
    case $np_cid in ''|*[!0-9a-f]*) echo "bad container id for $1" >&2; return 1 ;; esac
    np=$(docker exec "$NODE" crictl inspect -o go-template --template '{{.info.pid}}' "$np_cid")
    case $np in ''|*[!0-9]*) echo "bad node pid for $1: $np" >&2; return 1 ;; esac
    printf '%s\n' "$np"
}
# The same process as the host (initial PID namespace) numbers it: the NSpid
# chain host -> node -> container, inside this cluster's node container.
host_pid() {
    python3 -I - "$1" "$(docker inspect -f '{{.Id}}' "$NODE")" <<'PY'
import os, sys
node_pid, node_id = sys.argv[1], sys.argv[2]
for entry in os.listdir("/proc"):
    if not entry.isdigit():
        continue
    try:
        status = open(f"/proc/{entry}/status").read()
        cgroup = open(f"/proc/{entry}/cgroup").read()
    except OSError:
        continue
    nspid = [l.split()[1:] for l in status.splitlines() if l.startswith("NSpid:")]
    if nspid and len(nspid[0]) == 3 and nspid[0][1] == node_pid and node_id in cgroup:
        print(nspid[0][0])
        break
PY
}
# Create each workload's gate file from the node, through its own root: a
# `kubectl exec touch` would add a short-lived process to the captured pod.
release() {
    rl_paths=
    for pod in "$@"; do
        rl_pid=$(node_pid "$pod")
        rl_paths="$rl_paths /proc/$rl_pid/root/tmp/gate"
    done
    # shellcheck disable=SC2086
    docker exec "$NODE" touch $rl_paths
    for pod in "$@"; do
        wait_log "$pod" '^LEDGER ' 120
    done
}
OBS=$(kc -n "$OBS_NS" get pod -l app.kubernetes.io/component=observer -o jsonpath='{.items[0].metadata.name}')
[ -n "$OBS" ] || { echo "no observer pod" >&2; exit 1; }
observe() {
    kc -n "$OBS_NS" exec "$OBS" -- "$@"
}

echo "=== posture: capabilities, seccomp, token, RBAC, read-only root ==="
observe grep -E '^(CapEff|CapBnd|Seccomp):' /proc/self/status | tee "$WORK/posture.txt"
python3 -I - "$DAEMONSET" "$WORK/posture.txt" <<'PY'
import re, sys
bits = {"DAC_READ_SEARCH": 2, "SYS_PTRACE": 19, "SYS_ADMIN": 21, "PERFMON": 38, "BPF": 39}
manifest = open(sys.argv[1]).read()
added = re.search(r"add:\n((?:\s+- [A-Z_]+.*\n)+)", manifest).group(1)
want = 0
for name in re.findall(r"- ([A-Z_]+)", added):
    want |= 1 << bits[name]
status = dict(line.split(":\t") for line in open(sys.argv[2]).read().splitlines())
for key in ("CapEff", "CapBnd"):
    assert int(status[key], 16) == want, (key, status[key], hex(want))
assert status["Seccomp"].strip() == "2", status["Seccomp"]
print(f"capability set exactly the manifest's: {want:#x}; seccomp filter active")
PY
# Both run inside the pod and succeed only on the hardened answer, so a failed
# exec cannot pass for one.
observe sh -c '! test -e /var/run/secrets/kubernetes.io/serviceaccount' \
    || { echo "a ServiceAccount token is mounted in the observer" >&2; exit 1; }
observe sh -c 'if touch /p11scope-rootfs-probe 2>/dev/null; then exit 1; fi' \
    || { echo "the observer root filesystem is writable" >&2; exit 1; }
for verb_resource in "get pods" "list pods" "list nodes" "get secrets"; do
    # shellcheck disable=SC2086
    answer=$(kc auth can-i $verb_resource --all-namespaces \
        --as "system:serviceaccount:$OBS_NS:p11scope-observer" 2>/dev/null || true)
    [ "$answer" = no ] || { echo "observer ServiceAccount can $verb_resource ($answer)" >&2; exit 1; }
done
record '{"check": "posture", "ok": true, "token_mounted": false, "rbac": "none", "read_only_root": true}'

# capture NAME [k8s-profile-entry args...]: background `kubectl exec`; the
# capture's stdout/stderr land in WORK/NAME.{out,err}.
# CAPTURE_PID is the new capture's local `kubectl exec`, which lives exactly as
# long as the capture in the pod; CAPTURE_PIDS keeps every live one for cleanup.
start_capture() {
    sc_name=$1
    shift
    kc -n "$OBS_NS" exec "$OBS" -- "$@" > "$WORK/$sc_name.out" 2> "$WORK/$sc_name.err" &
    CAPTURE_PID=$!
    CAPTURE_PIDS="$CAPTURE_PIDS $CAPTURE_PID"
}
# wait_ready NAME PID
wait_ready() {
    wr_i=0
    while [ "$wr_i" -lt 360 ]; do
        grep -q 'p11scope: capturing:' "$WORK/$1.err" && return 0
        kill -0 "$2" 2>/dev/null || break
        sleep 0.5
        wr_i=$((wr_i + 1))
    done
    echo "capture $1 never became ready" >&2
    cat "$WORK/$1.err" >&2
    return 1
}
# finish_capture NAME EXT PID
finish_capture() {
    fc_status=0
    wait "$3" || fc_status=$?
    [ "$fc_status" -eq 0 ] || { echo "capture $1 exited $fc_status" >&2; cat "$WORK/$1.err" >&2; return 1; }
    kc -n "$OBS_NS" cp "$OBS:/tmp/$1.$2" "$WORK/$1.$2" >/dev/null
}

UID_A=$(pod_uid ledger-a)
UID_B=$(pod_uid ledger-b)
UID_P=$(pod_uid ledger-p)
UID_T=$(pod_uid ledger-t)
UID_IDLE=$(pod_uid idle)
UID_C=$(pod_uid ledger-c)

echo "=== doctor in the observer pod ==="
lock_step
observe k8s-profile-entry --pod-uid "$UID_A" --command doctor -- -v > "$WORK/doctor.out" 2>&1 \
    || { cat "$WORK/doctor.out" >&2; exit 1; }
unlock_step
grep -E '^(capability tier|verdict):' "$WORK/doctor.out"
grep -q '^verdict: capture available' "$WORK/doctor.out" || { cat "$WORK/doctor.out" >&2; exit 1; }
grep -q '^verdict: .*PID scope unavailable' "$WORK/doctor.out" \
    || { echo "doctor did not report the nested PID namespace" >&2; cat "$WORK/doctor.out" >&2; exit 1; }
TIER=$(sed -n 's/^capability tier: //p' "$WORK/doctor.out")
record "{\"check\": \"doctor\", \"ok\": true, \"tier\": \"$TIER\"}"

echo "=== profile-a + profile-b: positive control and cross-pod isolation ==="
# ledger-a and ledger-b share the image, the provider inode and the node. Two
# concurrent captures, one per pod, must each count exactly their own ledger,
# and both must still be running when both ledgers are complete, so b's calls
# provably happened inside a's capture window.
lock_step
start_capture profile-a k8s-profile-entry --pod-uid "$UID_A" -- \
    --duration 30 -o /tmp/profile-a.json
PID_A=$CAPTURE_PID
start_capture profile-b k8s-profile-entry --pod-uid "$UID_B" -- \
    --duration 30 -o /tmp/profile-b.json
PID_B=$CAPTURE_PID
wait_ready profile-a "$PID_A"
wait_ready profile-b "$PID_B"
release ledger-a ledger-b
if kill -0 "$PID_A" 2>/dev/null && kill -0 "$PID_B" 2>/dev/null; then
    OVERLAP=true
else
    echo "a capture ended before both ledgers completed: isolation unproven" >&2
    exit 1
fi
finish_capture profile-a json "$PID_A"
finish_capture profile-b json "$PID_B"
unlock_step
ledger_is ledger-a 400
ledger_is ledger-b 250
RESULT=$(python3 -I "$ORACLE" --expect-observer "$PIDNS_OBSERVER" profile-exact "$WORK/profile-a.json" 400)
record "$RESULT"
RESULT=$(python3 -I "$ORACLE" --expect-observer "$PIDNS_OBSERVER" profile-exact "$WORK/profile-b.json" 250)
record "$RESULT"
record "{\"check\": \"isolation\", \"ok\": $OVERLAP, \"capture_a_running_when_ledgers_done\": $OVERLAP, \"capture_b_running_when_ledgers_done\": $OVERLAP}"

echo "=== profile-p: non-root workload, provider in a private 0700 directory ==="
lock_step
start_capture profile-p k8s-profile-entry --pod-uid "$UID_P" -- \
    --duration 20 -o /tmp/profile-p.json
wait_ready profile-p "$CAPTURE_PID"
release ledger-p
finish_capture profile-p json "$CAPTURE_PID"
unlock_step
ledger_is ledger-p 300
RESULT=$(python3 -I "$ORACLE" --expect-observer "$PIDNS_OBSERVER" profile-exact "$WORK/profile-p.json" 300 /tmp/private/libsofthsm2.so)
record "$RESULT"

echo "=== trace-t: one line per call ==="
lock_step
start_capture trace-t k8s-profile-entry --pod-uid "$UID_T" --command trace -- \
    --duration 20 -o /tmp/trace-t.txt
wait_ready trace-t "$CAPTURE_PID"
release ledger-t
finish_capture trace-t txt "$CAPTURE_PID"
unlock_step
ledger_is ledger-t 200
TRACE=$(python3 -I "$ORACLE" --expect-observer "$PIDNS_OBSERVER" trace-exact "$WORK/trace-t.txt" 200)
record "$TRACE"
T_NODE=$(node_pid ledger-t)
T_HOST=$(host_pid "$T_NODE")
T_PRINTED=$(printf '%s' "$TRACE" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["trace_pids"][0])')
case $T_HOST in ''|*[!0-9]*) T_HOST=null ;; esac
if [ "$T_PRINTED" = "$T_NODE" ]; then T_NS=observer; elif [ "$T_PRINTED" = "$T_HOST" ]; then T_NS=initial; else T_NS=unknown; fi
record "{\"check\": \"trace-pid-namespace\", \"record_only\": true, \"printed\": $T_PRINTED, \"observer_view\": $T_NODE, \"host_view\": $T_HOST, \"printed_namespace\": \"$T_NS\"}"

echo "=== copy-up-neg: a genuine in-place change blocks and is disclosed ==="
# ledger-c runs side S (400), rewrites one unmapped byte in place, settles
# 8 s so the observer's ticks see the change, then runs side F (250) on
# the changed file. The window must cover both ledgers plus the settle.
lock_step
start_capture copy-up-neg k8s-profile-entry --pod-uid "$UID_C" -- \
    --duration 60 -o /tmp/copy-up-neg.json
wait_ready copy-up-neg "$CAPTURE_PID"
release ledger-c
finish_capture copy-up-neg json "$CAPTURE_PID"
unlock_step
ledgers2_is ledger-c 400 250
RESULT=$(python3 -I "$ORACLE" --expect-observer "$PIDNS_OBSERVER" copy-up-neg "$WORK/copy-up-neg.json" 400 250 /tmp/copyup/libsofthsm2.so)
record "$RESULT"

echo "=== negative: the idle pod maps no provider ==="
lock_step
observe k8s-profile-entry --pod-uid "$UID_IDLE" -- --duration 5 -o /tmp/negative.json \
    > "$WORK/negative.out" 2> "$WORK/negative.err" || { cat "$WORK/negative.err" >&2; exit 1; }
unlock_step
kc -n "$OBS_NS" cp "$OBS:/tmp/negative.json" "$WORK/negative.json" >/dev/null
# The entry log proves the idle pod's process was visible and readable, so
# "no module" means unmapped, not unseen (a missing hostPID would fail here).
RESULT=$(python3 -I "$ORACLE" --expect-observer "$PIDNS_OBSERVER" negative "$WORK/negative.json" "$WORK/negative.err")
record "$RESULT"

echo "=== inventory: ledger pods are callers, the idle pod is not ==="
lock_step
observe p11scope inventory --system -o /tmp/inventory.json \
    > "$WORK/inventory.out" 2> "$WORK/inventory.err" || { cat "$WORK/inventory.err" >&2; exit 1; }
unlock_step
kc -n "$OBS_NS" cp "$OBS:/tmp/inventory.json" "$WORK/inventory.json" >/dev/null
CALLER_ARGS=
for pod in ledger-a ledger-b ledger-p ledger-t ledger-n; do
    pid=$(node_pid "$pod")
    CALLER_ARGS="$CALLER_ARGS --caller $pid"
done
IDLE_PID=$(node_pid idle)
# shellcheck disable=SC2086
RESULT=$(python3 -I "$ORACLE" --expect-observer "$PIDNS_OBSERVER" inventory "$WORK/inventory.json" $CALLER_ARGS --non-caller "$IDLE_PID")
record "$RESULT"

echo "=== pid-probe: profile --pid is refused in a nested PID namespace ==="
# ledger-n is alive (it is an inventory caller above) and visible to the
# observer under this pid; the refusal must still name the namespace, exit
# non-zero and leave no report, so a pid-scoped capture can never be a silent
# zero (DR-30/DR-K8S-1).
N_NODE=$(node_pid ledger-n)
lock_step
PROBE_STATUS=0
observe p11scope profile --pid "$N_NODE" --duration 15 -o /tmp/pid-probe.json \
    > "$WORK/pid-probe.out" 2> "$WORK/pid-probe.err" || PROBE_STATUS=$?
unlock_step
PROBE_REPORT=0
observe sh -c '! test -e /tmp/pid-probe.json' || PROBE_REPORT=1
RESULT=$(python3 -I "$ORACLE" pid-refusal "$WORK/pid-probe.err" "$PROBE_STATUS" "$N_NODE" "$PROBE_REPORT") \
    || { cat "$WORK/pid-probe.err" >&2; exit 1; }
record "$RESULT"

echo "=== observer resource use ==="
OBS_UID=$(kc -n "$OBS_NS" get pod "$OBS" -o jsonpath='{.metadata.uid}' | tr '-' '_')
PEAK=$(docker exec "$NODE" sh -c "cat \$(find /sys/fs/cgroup -maxdepth 5 -type d -name '*pod$OBS_UID.slice' -print -quit)/memory.peak")
record "{\"check\": \"observer-memory\", \"record_only\": true, \"memory_peak_bytes\": $PEAK}"

GATED=$(grep -c '"ok": true' "$SUMMARY")
RECORDED=$(grep -c '"record_only": true' "$SUMMARY")
echo "=== kind e2e: ALL OK ($GATED gated checks passed; $RECORDED record-only lines; summary $SUMMARY) ==="

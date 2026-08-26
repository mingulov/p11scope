#!/bin/sh
# Task 6: attach before a Knative scale-from-zero pod exists.
set -eu
cd "$(dirname "$0")/../.."

MODULE_IN_POD=/usr/lib/softhsm/libsofthsm2.so
if [ "${P11SCOPE_LANE13_BODY+x}" = x ]; then
    [ "${P11SCOPE_LANE13_BODY}" = 1 ] || {
        echo "invalid private lane-13 body marker" >&2
        exit 2
    }
    TOKEN=${P11SCOPE_LANE13_TOKEN-}
else
    [ -z "${P11SCOPE_LANE13_TOKEN+x}" ] || {
        echo "P11SCOPE_LANE13_TOKEN is private lane state" >&2
        exit 2
    }
    [ -z "${P11SCOPE_LANE13_CAP+x}" ] || {
        echo "P11SCOPE_LANE13_CAP is private lane state" >&2
        exit 2
    }
    [ -z "${P11SCOPE_LANE13_OUTER_ARGV+x}" ] || {
        echo "P11SCOPE_LANE13_OUTER_ARGV is private lane state" >&2
        exit 2
    }
    [ -z "${P11SCOPE_LANE13_OUTER_PID+x}" ] || {
        echo "P11SCOPE_LANE13_OUTER_PID is private lane state" >&2
        exit 2
    }
    TOKEN=$(date +%s%N)-$$
fi
WORK="target/matrix-knative/$TOKEN"
PRODUCT="$WORK/product"
IMAGE="kind.local/p11scope-matrix-knative:$TOKEN"
CLUSTER="p11scope-knative-$TOKEN"
KSVC="p11scope-ksvc-$TOKEN"
ANCHOR="p11scope-anchor-$TOKEN"
KNATIVE_VERSION=knative-v1.23.0
KUBECONFIG="$PWD/$WORK/kubeconfig"
export KUBECONFIG
SPID=
SUPERVISOR_PID=
SUPERVISOR_STARTTIME=
ROOT_LAUNCH_PID=
ROOT_PROCESS_PID=
ROOT_PROCESS_STARTTIME=
PF_LAUNCH_PID=
PF_PID=
PF_STARTTIME=
PF_PGID=
PF_SID=
PF_GROUP_SNAPSHOT=
PF_GROUP_SNAPSHOT_AFTER=
PF_SESSION_EMPTY=1
LANE13_BODY_PID=
LANE13_BODY_STARTTIME=
LANE13_BODY_PGID=
LANE13_BODY_SID=
LANE13_BODY_SIGNAL=
LANE13_BODY_SIGNAL_STATUS=0
CLUSTER_CREATED=
IMAGE_CREATED=
IMAGE_CLEANUP_ARMED=
CLUSTER_CLEANUP_ARMED=
KUBECONFIG_CREATED=
WORK_CREATED=
KUBECONFIG_DEV_INO=
WORK_DEV_INO=
KUBECONFIG_ABSENT=1
IMAGE_ABSENT=1
CLUSTER_ABSENT=1
IMAGE_ID=
CLUSTER_NODE=
CLUSTER_NODE_ID=
CLUSTER_NODE_IMAGE_ID=
CLUSTER_NODE_IMAGE_REF=
EVIDENCE=
EVIDENCE_OWNED=0
LANE13_OUTER_EXIT_ARMED=0
LANE13_OUTER_PENDING_STATUS=
FACTS=
. scripts/lib.sh
require_non_root_caller

lane13_fact() {
    printf '%s\n' "$1" >> "$FACTS"
}

lane13_prepare_diagnostics() {
    [ "$#" -eq 0 ] || { echo "verify-knative.sh takes no arguments" >&2; return 1; }
    case ${P11SCOPE_LANE_EVIDENCE_DIR-} in
        /*) ;;
        *) echo "P11SCOPE_LANE_EVIDENCE_DIR must be an absolute path" >&2; return 1 ;;
    esac
    case $P11SCOPE_LANE_EVIDENCE_DIR in *'/../'*|../*|*/..)
        echo "P11SCOPE_LANE_EVIDENCE_DIR may not contain dot-dot components" >&2; return 1 ;;
    esac
    lane13_root_exists=0
    if [ -e "$P11SCOPE_LANE_EVIDENCE_DIR" ] || [ -L "$P11SCOPE_LANE_EVIDENCE_DIR" ]; then
        lane13_root_exists=1
        [ -d "$P11SCOPE_LANE_EVIDENCE_DIR" ] && [ ! -L "$P11SCOPE_LANE_EVIDENCE_DIR" ] || {
            echo "lane-13 evidence root is not a directory" >&2; return 1;
        }
    fi
    lane13_parent=${P11SCOPE_LANE_EVIDENCE_DIR%/*}
    lane13_leaf=${P11SCOPE_LANE_EVIDENCE_DIR##*/}
    [ -n "$lane13_parent" ] && [ -n "$lane13_leaf" ] && [ -d "$lane13_parent" ] || {
        echo "lane-13 evidence parent is not an existing directory" >&2; return 1;
    }
    lane13_ancestor=$lane13_parent
    while [ "$lane13_ancestor" != / ]; do
        [ ! -L "$lane13_ancestor" ] || { echo "lane-13 evidence parent has a symlink ancestor" >&2; return 1; }
        lane13_ancestor=${lane13_ancestor%/*}
        [ -n "$lane13_ancestor" ] || lane13_ancestor=/
    done
    lane13_parent=$(cd "$lane13_parent" && pwd -P)
    lane13_worktree=$(pwd -P)
    [ "$P11SCOPE_LANE_EVIDENCE_DIR" = "$lane13_parent/$lane13_leaf" ] || {
        echo "P11SCOPE_LANE_EVIDENCE_DIR must use its canonical spelling" >&2; return 1;
    }
    case $lane13_parent/$lane13_leaf in "$lane13_worktree"|"$lane13_worktree"/*)
        echo "P11SCOPE_LANE_EVIDENCE_DIR must be outside the physical worktree" >&2; return 1 ;;
    esac
    python3 - "$lane13_parent" <<'PY'
import os
import stat
import sys

status = os.stat(sys.argv[1])
if status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) & 0o077:
    raise SystemExit("lane-13 evidence parent must be caller-owned and private")
PY
    P11SCOPE_LANE_EVIDENCE_DIR=$lane13_parent/$lane13_leaf
    umask 077
    if [ "$lane13_root_exists" -eq 0 ]; then
        mkdir -m 700 "$P11SCOPE_LANE_EVIDENCE_DIR"
    fi
    python3 - "$P11SCOPE_LANE_EVIDENCE_DIR" <<'PY'
import os
import stat
import sys

status = os.stat(sys.argv[1])
if status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) != 0o700:
    raise SystemExit("lane-13 evidence root must be caller-owned mode 0700")
PY
    EVIDENCE=$P11SCOPE_LANE_EVIDENCE_DIR
    FACTS=$EVIDENCE/facts.log
    : > "$FACTS"
    chmod 600 "$FACTS"
    lane13_fact "diagnostic_phase=D1-pre-runtime"
    lane13_fact "start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    lane13_fact "cwd=$PWD"
    lane13_fact "physical_cwd=$lane13_worktree"
    lane13_fact "argv=$0"
    lane13_git_object_format=$(git rev-parse --show-object-format) || return 1
    lane13_git_head=$(git rev-parse HEAD) || return 1
    lane13_git_tree=$(git rev-parse HEAD^{tree}) || return 1
    lane13_git_status=$(git status --porcelain=v1) || return 1
    python3 - "$lane13_git_object_format" "$lane13_git_head" "$lane13_git_tree" "$lane13_git_status" <<'PY'
import re
import sys

object_format, head, tree, status = sys.argv[1:]
width = {"sha1": 40, "sha256": 64}.get(object_format)
if width is None or not re.fullmatch(rf"[0-9a-f]{{{width}}}", head) or not re.fullmatch(rf"[0-9a-f]{{{width}}}", tree):
    raise SystemExit("invalid lane-13 Git identity")
if "\x00" in status:
    raise SystemExit("invalid lane-13 Git status")
PY
    git diff --quiet && git diff --cached --quiet || {
        echo "lane-13 consumed tracked inputs are dirty" >&2; return 1;
    }
    lane13_untracked=$(git ls-files --others --exclude-standard -- \
        .cargo src crates scripts spike Cargo.toml Cargo.lock build.rs)
    [ -z "$lane13_untracked" ] || { echo "lane-13 consumed input is untracked" >&2; return 1; }
    lane13_git_status_projection=$(python3 - "$lane13_git_status" <<'PY'
import sys
print(sys.argv[1].replace("\n", "|"))
PY
    ) || return 1
    lane13_fact "git_object_format=$lane13_git_object_format"
    lane13_fact "git_head=$lane13_git_head"
    lane13_fact "git_tree=$lane13_git_tree"
    lane13_fact "git_status_begin=$lane13_git_status_projection"
    lane13_kernel=$(uname -sr) || return 1
    lane13_cargo_stable=$(cargo +1.88 --version) || return 1
    lane13_rustc_stable=$(rustc +1.88 --version) || return 1
    lane13_cargo_nightly=$(cargo +nightly --version) || return 1
    lane13_rustc_nightly=$(rustc +nightly --version) || return 1
    lane13_python=$(python3 --version) || return 1
    lane13_gcc=$(gcc --version) || return 1
    lane13_docker_version=$(docker version --format '{{.Server.Version}}') || return 1
    lane13_docker_storage=$(docker info --format '{{.Driver}}') || return 1
    lane13_curl_output=$(curl --version) || return 1
    lane13_curl_version=$(printf '%s\n' "$lane13_curl_output" | awk 'NR == 1 { print $2 }')
    lane13_require_curl "$lane13_curl_version"
    lane13_kind=$(kind version) || return 1
    lane13_kubectl=$(kubectl version --client --output=yaml) || return 1
    lane13_kubectl_version=$(printf '%s\n' "$lane13_kubectl" | awk '/gitVersion:/ { print $2; exit }')
    [ -n "$lane13_kernel" ] && [ -n "$lane13_cargo_stable" ] && [ -n "$lane13_rustc_stable" ] \
        && [ -n "$lane13_cargo_nightly" ] && [ -n "$lane13_rustc_nightly" ] \
        && [ -n "$lane13_python" ] && [ -n "$lane13_gcc" ] && [ -n "$lane13_docker_version" ] \
        && [ -n "$lane13_docker_storage" ] && [ -n "$lane13_kind" ] && [ -n "$lane13_kubectl_version" ] || return 1
    lane13_fact "kernel=$lane13_kernel"
    lane13_fact "cargo_stable=$lane13_cargo_stable"
    lane13_fact "rustc_stable=$lane13_rustc_stable"
    lane13_fact "cargo_nightly=$lane13_cargo_nightly"
    lane13_fact "rustc_nightly=$lane13_rustc_nightly"
    lane13_fact "python=$lane13_python"
    lane13_fact "gcc=$(printf '%s\n' "$lane13_gcc" | sed -n '1p')"
    lane13_fact "docker_version=$lane13_docker_version"
    lane13_fact "docker_storage=$lane13_docker_storage"
    lane13_fact "curl_version=$lane13_curl_version"
    lane13_fact "kind_version=$lane13_kind"
    lane13_fact "kubectl_version=$lane13_kubectl_version"
}

lane13_require_curl() {
    python3 - "$1" <<'PY'
import re
import sys
parts = sys.argv[1].split(".")
if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", sys.argv[1]) or tuple(map(int, parts)) < (8, 4, 0):
    raise SystemExit("curl 8.4.0 or newer required")
PY
}

lane13_record_inputs() {
    # The retained facts use fixed input_ledger_start= and input_ledger_end= keys.
    lane13_input_phase=${1:-start}
    case $lane13_input_phase in start|end) ;; *) return 1 ;; esac
    lane13_input_ledger=$WORK/.lane13-inputs-$lane13_input_phase
    git ls-files -z -- \
        Cargo.toml Cargo.lock build.rs \
        src crates/discover crates/manifest crates/ebpf-common crates/ebpf \
        scripts/matrix/verify-knative.sh scripts/lib.sh scripts/cleanup-traps.sh \
        scripts/check-capture-evidence.py spike/expected.txt \
        scripts/matrix/Dockerfile.knative scripts/matrix/knative-server.py spike/harness.c \
        > "$WORK/.lane13-inputs-list"
    python3 - "$FACTS" "$WORK/.lane13-inputs-list" "$lane13_input_ledger" "$lane13_input_phase" <<'PY'
import hashlib
import os
import sys

facts, listing, ledger, phase = sys.argv[1:]
paths = [path for path in open(listing, "rb").read().split(b"\0") if path]
if not paths or len(paths) != len(set(paths)):
    raise SystemExit("invalid consumed-input list")
with open(ledger, "w", encoding="utf-8") as output:
    for raw in sorted(paths):
        path = os.fsdecode(raw)
        if not os.path.isfile(path) or os.path.islink(path):
            raise SystemExit(f"invalid consumed input: {path}")
        digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
        output.write(f"input_ledger_{phase}={digest} path={path}\n")
with open(facts, "a", encoding="utf-8") as output:
    output.write(open(ledger, encoding="utf-8").read())
PY
    rm -f -- "$WORK/.lane13-inputs-list"
}

lane13_record_facts() {
    lane13_facts_phase=${1:-start}
    lane13_fact "facts_phase=$lane13_facts_phase"
    lane13_fact "body_status=${BODY_STATUS:-unknown}"
    lane13_fact "cleanup_status_at_phase_${lane13_facts_phase}=${CLEANUP_STATUS:-unknown}"
    lane13_fact "work=$WORK"
    lane13_fact "product=$PRODUCT"
    lane13_fact "outer_argv=${P11SCOPE_LANE13_OUTER_ARGV:-unknown}"
    lane13_fact "body_argv=$0"
    lane13_git_phase=$lane13_facts_phase
    lane13_git_phase_head=$(git rev-parse HEAD) || return 1
    lane13_git_phase_tree=$(git rev-parse HEAD^{tree}) || return 1
    lane13_git_phase_status=$(git status --porcelain=v1) || return 1
    lane13_git_phase_clean=1
    git diff --quiet || lane13_git_phase_clean=0
    lane13_git_phase_index_clean=1
    git diff --cached --quiet || lane13_git_phase_index_clean=0
    lane13_fact "git_head_${lane13_git_phase}=$lane13_git_phase_head"
    lane13_fact "git_tree_${lane13_git_phase}=$lane13_git_phase_tree"
    lane13_git_phase_status_projection=$(printf '%s\n' "$lane13_git_phase_status" | tr '\n' '|')
    lane13_fact "git_status_${lane13_git_phase}=$lane13_git_phase_status_projection"
    lane13_fact "git_worktree_clean_${lane13_git_phase}=$lane13_git_phase_clean"
    lane13_fact "git_index_clean_${lane13_git_phase}=$lane13_git_phase_index_clean"
    {
        printf 'head=%s\n' "$lane13_git_phase_head"
        printf 'tree=%s\n' "$lane13_git_phase_tree"
        printf 'worktree_clean=%s\n' "$lane13_git_phase_clean"
        printf 'index_clean=%s\n' "$lane13_git_phase_index_clean"
        printf 'status_begin\n%s\nstatus_end\n' "$lane13_git_phase_status"
    } > "$WORK/.lane13-git-$lane13_git_phase"
    lane13_record_inputs "$lane13_facts_phase"
}

lane13_compare_input_ledgers() {
    python3 - "$1" "$2" <<'PY'
import sys

def projection(path):
    entries = []
    for line in open(path, encoding="utf-8"):
        prefix, separator, value = line.partition("=")
        if separator != "=" or not prefix.startswith("input_ledger_"):
            raise SystemExit(f"invalid input ledger entry in {path}")
        entries.append(value)
    return entries

if projection(sys.argv[1]) != projection(sys.argv[2]):
    raise SystemExit("consumed input ledger changed")
PY
}

lane13_record_file_fact() {
    lane13_file_label=$1
    lane13_file_path=$2
    [ -f "$lane13_file_path" ] && [ ! -L "$lane13_file_path" ] || return 1
    lane13_file_size=$(stat -Lc %s "$lane13_file_path") || return 1
    lane13_file_digest=$(lane13_sha256 "$lane13_file_path") || return 1
    lane13_file_build_id=$(readelf -n "$lane13_file_path" 2>/dev/null | awk '/Build ID:/ { print $3; exit }') || return 1
    [ -n "$lane13_file_build_id" ] || return 1
    lane13_fact "${lane13_file_label}_path=$lane13_file_path"
    lane13_fact "${lane13_file_label}_size=$lane13_file_size"
    lane13_fact "${lane13_file_label}_sha256=$lane13_file_digest"
    lane13_fact "${lane13_file_label}_build_id=$lane13_file_build_id"
}

lane13_record_manifest_provider() {
    lane13_manifest_path=$1
    lane13_expected_path=$2
    lane13_provider_path=$3
    lane13_manifest_projection=$(python3 - "$lane13_manifest_path" "$lane13_expected_path" "$lane13_provider_path" <<'PY'
import json
import os
import sys

manifest, expected, provider = sys.argv[1:]
data = json.load(open(manifest, encoding="utf-8"))
if data.get("module_path") != expected or not data.get("objects"):
    raise SystemExit("manifest-selected provider does not match capture locator")
if data["objects"][0].get("path") != expected:
    raise SystemExit("manifest object zero does not match module locator")
if os.path.basename(data["module_path"]) != os.path.basename(provider):
    raise SystemExit("manifest-selected provider basename differs from copied provider")
print(data["module_path"])
PY
) || return 1
    lane13_manifest_provider_size=$(stat -Lc %s "$lane13_provider_path") || return 1
    lane13_manifest_provider_sha=$(lane13_sha256 "$lane13_provider_path") || return 1
    lane13_manifest_provider_build=$(readelf -n "$lane13_provider_path" 2>/dev/null | awk '/Build ID:/ { print $3; exit }') || return 1
    [ -n "$lane13_manifest_provider_build" ] || return 1
    lane13_fact "manifest_selected_provider_path=$lane13_manifest_projection"
    lane13_fact "manifest_selected_provider_size=$lane13_manifest_provider_size"
    lane13_fact "manifest_selected_provider_sha256=$lane13_manifest_provider_sha"
    lane13_fact "manifest_selected_provider_build_id=$lane13_manifest_provider_build"
}

lane13_record_capture_provider() {
    lane13_capture_provider_path=/proc/$ANCHOR_PID/root$PROVIDER_REAL
    lane13_capture_provider_size=$(sudo -n stat -Lc %s "$lane13_capture_provider_path") || return 1
    lane13_capture_provider_sha=$(sudo -n sha256sum "$lane13_capture_provider_path" | awk '{ print $1; exit }') || return 1
    lane13_capture_provider_build=$(sudo -n readelf -n "$lane13_capture_provider_path" 2>/dev/null | awk '/Build ID:/ { print $3; exit }') || return 1
    [ -n "$lane13_capture_provider_size" ] && [ -n "$lane13_capture_provider_sha" ] \
        && [ -n "$lane13_capture_provider_build" ] || return 1
    [ "$lane13_capture_provider_size" = "$lane13_manifest_provider_size" ] \
        && [ "$lane13_capture_provider_sha" = "$lane13_manifest_provider_sha" ] \
        && [ "$lane13_capture_provider_build" = "$lane13_manifest_provider_build" ] || return 1
    lane13_fact "capture_provider_path=$PROVIDER_REAL"
    lane13_fact "capture_provider_size=$lane13_capture_provider_size"
    lane13_fact "capture_provider_sha256=$lane13_capture_provider_sha"
    lane13_fact "capture_provider_build_id=$lane13_capture_provider_build"
}

lane13_record_generated_bpf() (
    lane13_bpf_list=$WORK/.lane13-bpf-list
    find "$PRODUCT/release/build" -type f \
        -path "$PRODUCT/release/build/p11scope-*/out/p11scope-ebpf" \
        -print > "$lane13_bpf_list" || { rm -f -- "$lane13_bpf_list"; exit 1; }
    lane13_bpf_count=$(awk 'NF { count += 1 } END { print count + 0 }' "$lane13_bpf_list")
    [ "$lane13_bpf_count" -eq 1 ] || { rm -f -- "$lane13_bpf_list"; exit 1; }
    lane13_bpf_path=$(cat "$lane13_bpf_list")
    rm -f -- "$lane13_bpf_list"
    [ -f "$lane13_bpf_path" ] && [ ! -L "$lane13_bpf_path" ] || exit 1
    exec 9< "$lane13_bpf_path" || exit 1
    lane13_bpf_fd=/proc/self/fd/9
    lane13_bpf_stat_before=$(LC_ALL=C stat -Lc '%d:%i:%s:%z' "$lane13_bpf_fd") || exit 1
    lane13_bpf_size=$(LC_ALL=C stat -Lc %s "$lane13_bpf_fd") || exit 1
    lane13_bpf_digest=$(LC_ALL=C lane13_sha256 "$lane13_bpf_fd") || exit 1
    lane13_bpf_header=$(LC_ALL=C readelf -h "$lane13_bpf_fd" 2>/dev/null) || exit 1
    lane13_bpf_class=$(printf '%s\n' "$lane13_bpf_header" | awk -F: '
        $1 ~ /^[[:space:]]*Class[[:space:]]*$/ { count += 1; value = $2 }
        END { if (count != 1) exit 1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value }
    ') || exit 1
    lane13_bpf_data=$(printf '%s\n' "$lane13_bpf_header" | awk -F: '
        $1 ~ /^[[:space:]]*Data[[:space:]]*$/ { count += 1; value = $2 }
        END { if (count != 1) exit 1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value }
    ') || exit 1
    lane13_bpf_type=$(printf '%s\n' "$lane13_bpf_header" | awk -F: '
        $1 ~ /^[[:space:]]*Type[[:space:]]*$/ { count += 1; value = $2 }
        END { if (count != 1) exit 1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value }
    ') || exit 1
    lane13_bpf_machine=$(printf '%s\n' "$lane13_bpf_header" | awk -F: '
        $1 ~ /^[[:space:]]*Machine[[:space:]]*$/ { count += 1; value = $2 }
        END { if (count != 1) exit 1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value }
    ') || exit 1
    [ "$lane13_bpf_class" = ELF64 ] || exit 1
    [ "$lane13_bpf_data" = "2's complement, little endian" ] || exit 1
    [ "$lane13_bpf_type" = "REL (Relocatable file)" ] || exit 1
    [ "$lane13_bpf_machine" = "Linux BPF" ] || exit 1
    if lane13_bpf_notes=$(LC_ALL=C readelf -n "$lane13_bpf_fd" 2>/dev/null); then
        lane13_bpf_build_id_count=$(printf '%s\n' "$lane13_bpf_notes" | awk '/Build ID:/ { count += 1 } END { print count + 0 }')
        case $lane13_bpf_build_id_count in
            0) lane13_bpf_build_id=absent ;;
            1)
                lane13_bpf_build_id=$(printf '%s\n' "$lane13_bpf_notes" | awk '/Build ID:/ { if (NF != 3) exit 1; print $3 }') || exit 1
                printf '%s\n' "$lane13_bpf_build_id" | LC_ALL=C grep -Eq '^[0-9a-f]+$' || exit 1
                ;;
            *) exit 1 ;;
        esac
    else
        exit 1
    fi
    lane13_bpf_stat_after=$(LC_ALL=C stat -Lc '%d:%i:%s:%z' "$lane13_bpf_fd") || exit 1
    [ "$lane13_bpf_stat_before" = "$lane13_bpf_stat_after" ] || exit 1
    [ -f "$lane13_bpf_path" ] && [ ! -L "$lane13_bpf_path" ] || exit 1
    lane13_bpf_path_stat=$(LC_ALL=C stat -Lc '%d:%i:%s:%z' "$lane13_bpf_path") || exit 1
    [ "$lane13_bpf_stat_after" = "$lane13_bpf_path_stat" ] || exit 1
    lane13_fact "generated_bpf_path=$lane13_bpf_path"
    lane13_fact "generated_bpf_size=$lane13_bpf_size"
    lane13_fact "generated_bpf_sha256=$lane13_bpf_digest"
    lane13_fact "generated_bpf_build_id=$lane13_bpf_build_id"
    lane13_fact generated_bpf_elf_class=ELF64
    lane13_fact generated_bpf_elf_data=LSB
    lane13_fact generated_bpf_elf_type=ET_REL
    lane13_fact generated_bpf_elf_machine=EM_BPF
)

lane13_record_pod_identity() {
    lane13_pod_namespace=$1
    lane13_pod_name=$2
    lane13_pod_json=$WORK/.lane13-pod
    kubectl get pod "$lane13_pod_name" -n "$lane13_pod_namespace" -o json > "$lane13_pod_json" || return 1
    if ! python3 - "$FACTS" "$lane13_pod_namespace" "$lane13_pod_name" "$lane13_pod_json" <<'PY'
import json
import sys

facts, namespace, expected_name, path = sys.argv[1:]
pod = json.load(open(path, encoding="utf-8"))
metadata = pod.get("metadata") or {}
spec = pod.get("spec") or {}
status = pod.get("status") or {}
name = metadata.get("name")
uid = metadata.get("uid")
if metadata.get("namespace") != namespace or name != expected_name or not isinstance(uid, str) or not uid:
    raise SystemExit("pod identity is incomplete")
declared = spec.get("containers") or []
observed = {item.get("name"): item for item in status.get("containerStatuses") or []}
if not declared or any(not isinstance(item.get("name"), str) or not item.get("image") for item in declared):
    raise SystemExit("pod declared image identity is incomplete")
with open(facts, "a", encoding="utf-8") as output:
    output.write(f"pod_namespace={namespace} pod_name={name} pod_uid={uid}\n")
    for container in declared:
        container_name = container["name"]
        runtime = observed.get(container_name) or {}
        container_id = runtime.get("containerID")
        image_id = runtime.get("imageID")
        ready = runtime.get("ready")
        restarts = runtime.get("restartCount")
        if not isinstance(container_id, str) or not container_id or not isinstance(image_id, str) or not image_id:
            raise SystemExit("runtime container identity is incomplete")
        if not isinstance(ready, bool) or not isinstance(restarts, int) or restarts < 0:
            raise SystemExit("runtime container readiness is incomplete")
        output.write(
            f"pod_container={container_name} declared_image={container['image']} "
            f"runtime_id={container_id} runtime_image_id={image_id} ready={int(ready)} "
            f"restart_count={restarts}\n"
        )
PY
    then
        rm -f -- "$lane13_pod_json"
        return 1
    fi
    rm -f -- "$lane13_pod_json"
}

lane13_record_namespace_identities() {
    lane13_identity_namespace=$1
    lane13_identity_pods=$(kubectl get pods -n "$lane13_identity_namespace" \
        -o jsonpath='{.items[*].metadata.name}') || return 1
    [ -n "$lane13_identity_pods" ] || return 1
    for lane13_identity_pod in $lane13_identity_pods; do
        lane13_record_pod_identity "$lane13_identity_namespace" "$lane13_identity_pod" || return 1
    done
}

lane13_preflight() {
    lane13_reject_symlink_ancestors "$WORK" || return 1
    lane13_reject_symlink_ancestors "$KUBECONFIG" || return 1
    [ ! -e "$WORK" ] && [ ! -L "$WORK" ] || {
        echo "lane-13 work path already exists" >&2; return 1;
    }
    [ ! -e "$KUBECONFIG" ] && [ ! -L "$KUBECONFIG" ] || {
        echo "lane-13 kubeconfig path already exists" >&2; return 1;
    }
    if ! lane13_image_absent "$IMAGE"; then
        echo "cannot establish lane-13 workload-tag absence" >&2
        return 1
    fi
    lane13_clusters=$(kind get clusters) || {
        echo "cannot establish lane-13 Kind-cluster absence" >&2
        return 1
    }
    if printf '%s\n' "$lane13_clusters" | grep -Fqx "$CLUSTER"; then
        echo "lane-13 Kind cluster already exists" >&2
        return 1
    fi
}

lane13_reject_symlink_ancestors() {
    case $1 in
        /*) lane13_path=$1 ;;
        *) lane13_path=$PWD/$1 ;;
    esac
    lane13_path=${lane13_path%/*}
    while [ "$lane13_path" != / ]; do
        [ ! -L "$lane13_path" ] || {
            echo "lane-13 path has a symlink ancestor: $1" >&2
            return 1
        }
        lane13_path=${lane13_path%/*}
        [ -n "$lane13_path" ] || lane13_path=/
    done
}

lane13_image_absent() {
    lane13_image_state "$@"
    [ "$?" -eq 0 ]
}

lane13_image_state() {
    lane13_image_ref=$1
    lane13_image_projection=$EVIDENCE/.lane13-image-projection
    if docker image ls --no-trunc --format '{{.Repository}}\t{{.Tag}}\t{{.ID}}' "$lane13_image_ref" \
        > "$lane13_image_projection"; then
        lane13_image_query_status=0
    else
        lane13_image_query_status=$?
    fi
    if [ "$lane13_image_query_status" -ne 0 ]; then
        rm -f -- "$lane13_image_projection"
        return 2
    fi
    python3 - "$lane13_image_ref" "$lane13_image_projection" <<'PY'
import sys

reference, path = sys.argv[1:]
for line in open(path, encoding="utf-8").read().splitlines():
    fields = line.split("\t")
    if len(fields) != 3 or not all(fields):
        raise SystemExit("invalid Docker image projection")
    if f"{fields[0]}:{fields[1]}" == reference:
        raise SystemExit(3)
PY
    lane13_image_status=$?
    rm -f -- "$lane13_image_projection"
    return "$lane13_image_status"
}

lane13_image_facts() {
    lane13_image_label=$1
    lane13_image_ref=$2
    lane13_image_json=$WORK/.lane13-image-$lane13_image_label
    docker image inspect "$lane13_image_ref" > "$lane13_image_json"
    python3 - "$FACTS" "$lane13_image_label" "$lane13_image_json" <<'PY'
import json
import sys

facts, label, path = sys.argv[1:]
images = json.load(open(path, encoding="utf-8"))
if len(images) != 1:
    raise SystemExit("image inspection is not unique")
image = images[0]
identifier = image.get("Id")
layers = image.get("RootFS", {}).get("Layers")
digests = image.get("RepoDigests") or []
if not isinstance(identifier, str) or not identifier or not isinstance(layers, list) or not all(isinstance(item, str) for item in layers):
    raise SystemExit("image identity is incomplete")
if not all(isinstance(item, str) for item in digests):
    raise SystemExit("image repository digests are invalid")
with open(facts, "a", encoding="utf-8") as output:
    output.write(f"image_{label}_id={identifier}\n")
    output.write(f"image_{label}_repo_digests={' '.join(digests)}\n")
    output.write(f"image_{label}_diff_ids={' '.join(layers)}\n")
PY
    rm -f -- "$lane13_image_json"
}

lane13_record_base_and_build() {
    timeout --signal=TERM --kill-after=5s 120s docker pull ubuntu:24.04 >/dev/null
    docker image inspect ubuntu:24.04 > "$WORK/base-before.json"
    lane13_image_facts base ubuntu:24.04
    IMAGE_ID=$(timeout --signal=TERM --kill-after=5s 600s docker build --pull=false -q -t "$IMAGE" \
        -f scripts/matrix/Dockerfile.knative "$WORK")
    case $IMAGE_ID in ''|*[!a-zA-Z0-9:.-]*) return 1 ;; esac
    lane13_image_facts workload "$IMAGE"
    docker image inspect ubuntu:24.04 > "$WORK/base-after.json"
    docker image inspect "$IMAGE" > "$WORK/workload-image.json"
    python3 - "$FACTS" "$IMAGE_ID" "$WORK/base-before.json" "$WORK/base-after.json" \
        "$WORK/workload-image.json" <<'PY'
import json
import sys

facts, build_id = sys.argv[1:3]
base_before, base_after, workload = (json.load(open(path))[0] for path in sys.argv[3:])
def identity(image):
    identifier = image.get("Id")
    digests = image.get("RepoDigests") or []
    layers = image.get("RootFS", {}).get("Layers")
    if not isinstance(identifier, str) or not identifier or not all(isinstance(item, str) for item in digests) or not isinstance(layers, list) or not all(isinstance(item, str) for item in layers):
        raise SystemExit("image identity is incomplete")
    return identifier, digests, layers

before_id, before_digests, base_layers = identity(base_before)
after_id, after_digests, after_layers = identity(base_after)
workload_id, _, workload_layers = identity(workload)
if (before_id, before_digests, base_layers) != (after_id, after_digests, after_layers):
    raise SystemExit("base image changed during lane-13 build")
if workload_id != build_id:
    raise SystemExit("workload tag does not resolve to the captured build ID")
workload_layers = workload.get("RootFS", {}).get("Layers")
if not base_layers or workload_layers[:len(base_layers)] != base_layers:
    raise SystemExit("workload rootfs does not retain the recorded base prefix")
with open(facts, "a", encoding="utf-8") as output:
    output.write(f"image_base_before_id={before_id}\n")
    output.write(f"image_base_before_repo_digests={' '.join(before_digests)}\n")
    output.write(f"image_base_before_diff_ids={' '.join(base_layers)}\n")
    output.write(f"image_base_after_id={after_id}\n")
    output.write(f"image_base_after_repo_digests={' '.join(after_digests)}\n")
    output.write(f"image_base_after_diff_ids={' '.join(after_layers)}\n")
    output.write(f"image_workload_build_id={build_id}\n")
PY
    rm -f -- "$WORK/base-before.json" "$WORK/base-after.json" "$WORK/workload-image.json"
    IMAGE_CREATED=1
    lane13_fact "image_created=1"
}

lane13_create_cluster() {
    timeout --signal=TERM --kill-after=5s 300s kind create cluster --name "$CLUSTER" \
        --kubeconfig "$KUBECONFIG"
    CLUSTER_NODE=$(kind get nodes --name "$CLUSTER")
    [ "$(printf '%s\n' "$CLUSTER_NODE" | awk 'NF { count += 1 } END { print count + 0 }')" = 1 ] || {
        echo "lane-13 Kind cluster did not yield exactly one node" >&2
        return 1
    }
    CLUSTER_NODE_ID=$(docker container inspect --format '{{.Id}}' "$CLUSTER_NODE")
    case $CLUSTER_NODE_ID in ''|*[!a-zA-Z0-9:.-]*) return 1 ;; esac
    CLUSTER_NODE_IMAGE_ID=$(docker container inspect --format '{{.Image}}' "$CLUSTER_NODE")
    CLUSTER_NODE_IMAGE_REF=$(docker container inspect --format '{{.Config.Image}}' "$CLUSTER_NODE")
    case $CLUSTER_NODE_IMAGE_ID:$CLUSTER_NODE_IMAGE_REF in *[!a-zA-Z0-9:./@_-]*) return 1 ;; esac
    lane13_image_facts cluster_node "$CLUSTER_NODE_IMAGE_ID"
    [ -f "$KUBECONFIG" ] && [ ! -L "$KUBECONFIG" ] || {
        echo "lane-13 Kind cluster did not create its kubeconfig" >&2
        return 1
    }
    CLUSTER_CREATED=1
    KUBECONFIG_CREATED=1
    KUBECONFIG_DEV_INO=$(stat -Lc '%d:%i' "$KUBECONFIG") || return 1
    [ "$(stat -Lc %u "$KUBECONFIG")" = "$(id -u)" ] || return 1
    [ "$(stat -Lc %a "$KUBECONFIG")" = 600 ] || return 1
    lane13_fact "kubeconfig_dev_ino=$KUBECONFIG_DEV_INO"
    lane13_fact "owned_cluster_name=$CLUSTER"
    lane13_fact "owned_workload_tag=$IMAGE"
    lane13_fact "cluster_node=$CLUSTER_NODE"
    lane13_fact "cluster_node_id=$CLUSTER_NODE_ID"
    lane13_fact "cluster_node_image_id=$CLUSTER_NODE_IMAGE_ID"
    lane13_fact "cluster_node_image_ref=$CLUSTER_NODE_IMAGE_REF"
    lane13_fact "cluster_created=1"
}

lane13_delete_owned_image() {
    lane13_image_state "$IMAGE"
    lane13_image_state_status=$?
    [ "$lane13_image_state_status" -eq 0 ] && return 0
    [ "$lane13_image_state_status" -eq 3 ] || return 1
    lane13_cleanup_image_json=$WORK/.lane13-cleanup-image
    docker image inspect "$IMAGE" > "$lane13_cleanup_image_json" || return 1
    lane13_cleanup_image_id=$(python3 - "$lane13_cleanup_image_json" <<'PY'
import json
import sys

images = json.load(open(sys.argv[1], encoding="utf-8"))
if len(images) != 1:
    raise SystemExit("image inspection is not unique")
image = images[0]
identifier = image.get("Id")
layers = image.get("RootFS", {}).get("Layers")
digests = image.get("RepoDigests")
if not isinstance(identifier, str) or not identifier or not isinstance(layers, list) or not layers or not all(isinstance(item, str) and item for item in layers):
    raise SystemExit("image identity is incomplete")
if not isinstance(digests, list) or not all(isinstance(item, str) and item for item in digests):
    raise SystemExit("image repository digests are invalid")
print(identifier)
PY
    ) || { rm -f -- "$lane13_cleanup_image_json"; return 1; }
    rm -f -- "$lane13_cleanup_image_json"
    if [ -n "$IMAGE_ID" ] && [ "$lane13_cleanup_image_id" != "$IMAGE_ID" ]; then
        echo "refusing to remove a retagged lane-13 workload image" >&2
        return 1
    fi
    IMAGE_ID=${IMAGE_ID:-$lane13_cleanup_image_id}
    timeout --signal=TERM --kill-after=5s 30s docker image rm -f "$IMAGE"
    lane13_image_absent "$IMAGE"
}

lane13_container_absent() {
    lane13_container_name=$1
    lane13_container_id=$2
    lane13_container_projection=$EVIDENCE/.lane13-container-projection
    if docker container ls --all --no-trunc --format '{{.ID}}\t{{.Names}}' \
        > "$lane13_container_projection"; then
        lane13_container_query_status=0
    else
        lane13_container_query_status=$?
    fi
    if [ "$lane13_container_query_status" -ne 0 ]; then
        rm -f -- "$lane13_container_projection"
        return 1
    fi
    python3 - "$lane13_container_name" "$lane13_container_id" "$lane13_container_projection" <<'PY'
import sys

expected_name, expected_id, path = sys.argv[1:]
for line in open(path, encoding="utf-8"):
    fields = line.rstrip("\n").split("\t")
    if len(fields) != 2 or not all(fields):
        raise SystemExit("invalid Docker container projection")
    if fields[0] == expected_id or fields[1] == expected_name:
        raise SystemExit("lane-13 owned container is still present")
PY
    lane13_container_status=$?
    rm -f -- "$lane13_container_projection"
    return "$lane13_container_status"
}

lane13_delete_owned_cluster() {
    lane13_clusters=$(kind get clusters) || return 1
    lane13_cluster_count=$(printf '%s\n' "$lane13_clusters" | awk -v expected="$CLUSTER" '$0 == expected { count += 1 } END { print count + 0 }')
    [ "$lane13_cluster_count" -eq 0 ] && { CLUSTER_ABSENT=1; return 0; }
    [ "$lane13_cluster_count" -eq 1 ] || return 1
    lane13_nodes=$(kind get nodes --name "$CLUSTER") || return 1
    lane13_node_count=$(printf '%s\n' "$lane13_nodes" | awk 'NF { count += 1 } END { print count + 0 }')
    [ "$lane13_node_count" -eq 1 ] || return 1
    lane13_node=$(printf '%s\n' "$lane13_nodes")
    lane13_node_id=$(docker container inspect --format '{{.Id}}' "$lane13_node") || return 1
    lane13_node_image_id=$(docker container inspect --format '{{.Image}}' "$lane13_node") || return 1
    lane13_node_image_ref=$(docker container inspect --format '{{.Config.Image}}' "$lane13_node") || return 1
    case $lane13_node:$lane13_node_id:$lane13_node_image_id:$lane13_node_image_ref in
        ''|*[!a-zA-Z0-9:./@_-]*) return 1 ;;
    esac
    if [ -n "$CLUSTER_NODE" ] && [ "$lane13_node" != "$CLUSTER_NODE" ]; then
        echo "refusing to delete a replaced lane-13 Kind node" >&2
        return 1
    fi
    if [ -n "$CLUSTER_NODE_ID" ] && [ "$lane13_node_id" != "$CLUSTER_NODE_ID" ]; then
        echo "refusing to delete a replaced lane-13 Kind node" >&2
        return 1
    fi
    CLUSTER_NODE=$lane13_node
    CLUSTER_NODE_ID=$lane13_node_id
    CLUSTER_NODE_IMAGE_ID=$lane13_node_image_id
    CLUSTER_NODE_IMAGE_REF=$lane13_node_image_ref
    lane13_image_facts cleanup_cluster_node "$CLUSTER_NODE_IMAGE_ID" || return 1
    timeout --signal=TERM --kill-after=5s 120s kind delete cluster --name "$CLUSTER"
    lane13_clusters=$(kind get clusters) || return 1
    ! printf '%s\n' "$lane13_clusters" | grep -Fqx "$CLUSTER" || return 1
    lane13_container_absent "$CLUSTER_NODE" "$CLUSTER_NODE_ID" || return 1
    CLUSTER_ABSENT=1
}

lane13_fetch_release() {
    lane13_url=$1
    lane13_name=$2
    case $lane13_url:$lane13_name in
        "https://github.com/knative/serving/releases/download/${KNATIVE_VERSION}/serving-crds.yaml:serving-crds.yaml"|\
        "https://github.com/knative/serving/releases/download/${KNATIVE_VERSION}/serving-core.yaml:serving-core.yaml"|\
        "https://github.com/knative/net-kourier/releases/download/${KNATIVE_VERSION}/kourier.yaml:kourier.yaml") ;;
        *) return 1 ;;
    esac
    mkdir -p "$WORK/releases"
    lane13_release=$WORK/releases/$lane13_name
    [ ! -e "$lane13_release" ] && [ ! -L "$lane13_release" ] || return 1
    lane13_fetch_meta=$(curl --fail --silent --show-error --retry 0 --connect-timeout 30 --max-time 180 \
        --max-filesize 16777216 --proto '=https' --proto-redir '=https' --location --max-redirs 1 \
        --output "$lane13_release" --write-out '%{url_effective}\n%{num_redirects}' "$lane13_url") || return 1
    lane13_release_projection=$(python3 - "$lane13_fetch_meta" <<'PY'
import sys
from urllib.parse import urlsplit, urlunsplit

parts = sys.argv[1].splitlines()
if len(parts) != 2 or not parts[1].isdigit() or int(parts[1]) > 1:
    raise SystemExit("invalid release redirect count")
url = urlsplit(parts[0])
if url.scheme != "https" or url.hostname not in {"github.com", "release-assets.githubusercontent.com"}:
    raise SystemExit("unapproved release effective URL")
if url.username or url.password or url.fragment or url.port not in {None, 443}:
    raise SystemExit("unsafe release effective URL")
print(urlunsplit(("https", url.hostname, url.path, "", "")), parts[1], sep="\t")
PY
) || return 1
    lane13_safe_url=${lane13_release_projection%%	*}
    lane13_redirects=${lane13_release_projection#*	}
    lane13_size=$(stat -Lc %s "$lane13_release") || return 1
    case $lane13_size in ''|*[!0-9]*) return 1 ;; esac
    [ "$lane13_size" -gt 0 ] && [ "$lane13_size" -le 16777216 ] || return 1
    lane13_before=$(lane13_sha256 "$lane13_release") || return 1
    lane13_fact "release_declared=$lane13_url"
    lane13_fact "release_effective=$lane13_safe_url"
    lane13_fact "release_redirects=$lane13_redirects"
    lane13_fact "release_pre_size=$lane13_size"
    lane13_fact "release_pre_sha256=$lane13_before"
    lane13_applied="$WORK/releases/.lane13-applied"
    if ! timeout --signal=TERM --kill-after=5s 210s kubectl apply -f "$lane13_release" -o name > "$lane13_applied"; then
        rm -f -- "$lane13_applied"
        return 1
    fi
    lane13_after_size=$(stat -Lc %s "$lane13_release") || return 1
    lane13_after=$(lane13_sha256 "$lane13_release") || return 1
    [ "$lane13_after_size" = "$lane13_size" ] || return 1
    [ "$lane13_before" = "$lane13_after" ] || return 1
    python3 - "$FACTS" "$lane13_name" "$WORK/releases/.lane13-applied" <<'PY' || return 1
import re
import sys

facts, logical_name, projection = sys.argv[1:]
raw = open(projection, "rb").read()
if not raw or not raw.endswith(b"\n") or any((byte < 32 and byte != 10) or byte == 127 for byte in raw):
    raise SystemExit("invalid local release apply bytes")
try:
    text = raw.decode("ascii")
except UnicodeDecodeError:
    raise SystemExit("invalid local release apply encoding")
items = text[:-1].split("\n")
if not items or items != sorted(items) or any(not item for item in items) or len(items) != len(set(items)) or not all(
    re.fullmatch(r"[a-z0-9][a-z0-9.-]*/[a-z0-9][a-z0-9.-]*", item) for item in items
):
    raise SystemExit("invalid local release apply projection")
with open(facts, "a", encoding="utf-8") as output:
    for item in items:
        output.write(f"release_apply_{logical_name}={item}\n")
PY
    rm -f -- "$WORK/releases/.lane13-applied"
    lane13_fact "release_apply_success_${lane13_name}=1"
    lane13_fact "release_post_size=$lane13_after_size"
    lane13_fact "release_post_sha256=$lane13_after"
    rm -f -- "$lane13_release"
    [ ! -e "$lane13_release" ] && [ ! -L "$lane13_release" ] || return 1
    lane13_fact "release_deleted=$lane13_name"
    lane13_fact "release_absent=$lane13_name"
}

lane13_sha256() {
    python3 - "$1" <<'PY'
import hashlib
import sys

digest = hashlib.sha256()
with open(sys.argv[1], "rb") as source:
    for block in iter(lambda: source.read(131072), b""):
        digest.update(block)
print(digest.hexdigest())
PY
}

lane13_preserve_diagnostics() {
    [ -n "${WORK_CREATED-}" ] || return 0
    [ -d "$WORK" ] && [ ! -L "$WORK" ] || return 1
    [ "$(stat -Lc '%d:%i' "$WORK")" = "$WORK_DEV_INO" ] || return 1
    [ "$(stat -Lc %u "$WORK")" = "$(id -u)" ] || return 1
    lane13_copy_status=0
    for lane13_name in observed.json manifest-host.json profile.log portforward.log \
        portforward.group.before.json portforward.group.after.json; do
        lane13_source=$WORK/$lane13_name
        lane13_target=$EVIDENCE/$lane13_name
        if [ -e "$lane13_source" ] || [ -L "$lane13_source" ]; then
            lane13_file_copy_status=0
            [ -f "$lane13_source" ] && [ ! -L "$lane13_source" ] || {
                lane13_copy_status=1
                continue
            }
            case $lane13_name in profile.log)
                reclaim_root_output "$lane13_source" || lane13_file_copy_status=1 ;;
            esac
            cp -- "$lane13_source" "$lane13_target" || lane13_file_copy_status=1
            chmod 600 "$lane13_target" 2>/dev/null || lane13_file_copy_status=1
            [ "$lane13_file_copy_status" -eq 0 ] || lane13_copy_status=1
        fi
    done
    if [ "${BODY_STATUS:-1}" -eq 0 ]; then
        for lane13_name in observed.json manifest-host.json profile.log portforward.log \
            portforward.group.before.json portforward.group.after.json; do
            [ -f "$EVIDENCE/$lane13_name" ] && [ ! -L "$EVIDENCE/$lane13_name" ] || lane13_copy_status=1
        done
    fi
    return "$lane13_copy_status"
}

lane13_remove_owned_work() {
    [ -z "${WORK_CREATED-}" ] && return 0
    [ -d "$WORK" ] && [ ! -L "$WORK" ] || return 1
    [ "$(stat -Lc '%d:%i' "$WORK")" = "$WORK_DEV_INO" ] || return 1
    [ "$(stat -Lc %u "$WORK")" = "$(id -u)" ] || return 1
    rm -rf -- "$WORK" || return 1
    [ ! -e "$WORK" ] && [ ! -L "$WORK" ]
}

lane13_remove_owned_kubeconfig() {
    [ -f "$KUBECONFIG" ] && [ ! -L "$KUBECONFIG" ] || return 1
    [ "$(stat -Lc '%d:%i' "$KUBECONFIG")" = "$KUBECONFIG_DEV_INO" ] || return 1
    [ "$(stat -Lc %u "$KUBECONFIG")" = "$(id -u)" ] || return 1
    rm -f -- "$KUBECONFIG" || return 1
    [ ! -e "$KUBECONFIG" ] && [ ! -L "$KUBECONFIG" ]
}

lane13_record_absence_fact() {
    lane13_absence_path=$1
    lane13_absence_label=$2
    if [ ! -e "$lane13_absence_path" ] && [ ! -L "$lane13_absence_path" ]; then
        lane13_fact "$lane13_absence_label=1"
        return 0
    fi
    lane13_fact "$lane13_absence_label=0"
    return 1
}

lane13_validate_retained_root() {
    python3 - "$EVIDENCE" <<'PY'
import os
import stat
import sys

root = sys.argv[1]
allowed = {
    "stdout.log", "stderr.log", "facts.log", "status",
    "observed.json", "manifest-host.json", "profile.log", "portforward.log",
    "portforward.group.before.json", "portforward.group.after.json",
}
required = {"stdout.log", "stderr.log", "facts.log", "status"}
if stat.S_IMODE(os.stat(root).st_mode) != 0o700 or os.path.islink(root):
    raise SystemExit("lane-13 retained root has unsafe mode")
entries = list(os.scandir(root))
if not required.issubset({entry.name for entry in entries}):
    raise SystemExit("lane-13 retained root is missing mandatory diagnostics")
for entry in entries:
    if entry.name not in allowed or not entry.is_file(follow_symlinks=False):
        raise SystemExit(f"lane-13 retained root contains {entry.name}")
    if stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode) != 0o600:
        raise SystemExit(f"lane-13 retained file has unsafe mode: {entry.name}")
PY
}

lane13_canonical_script() {
    lane13_script_input=$1
    case $lane13_script_input in
        /*) lane13_script_input=$lane13_script_input ;;
        *) lane13_script_input=$PWD/$lane13_script_input ;;
    esac
    lane13_script_dir=$(dirname "$lane13_script_input")
    lane13_script_name=$(basename "$lane13_script_input")
    (cd "$lane13_script_dir" && printf '%s/%s\n' "$(pwd -P)" "$lane13_script_name")
}

lane13_authorize_body() {
    [ "$#" -eq 1 ] && [ "$1" = --lane13-private-body ] || return 1
    [ -r /proc/$$/fd/9 ] || return 1
    lane13_capability=$(cat <&9) || return 1
    IFS='|' read -r lane13_cap_version lane13_cap_pid lane13_cap_start \
        lane13_cap_script lane13_cap_hash lane13_cap_nonce <<EOF
$lane13_capability
EOF
    [ "$lane13_cap_version" = lane13-v1 ] || return 1
    case $lane13_cap_pid:$lane13_cap_start in *[!0-9:]*) return 1 ;; esac
    case $lane13_cap_hash:$lane13_cap_nonce in *[!a-zA-Z0-9:]*) return 1 ;; esac
    [ "${P11SCOPE_LANE13_CAP-}" = "$lane13_cap_nonce" ] || return 1
    [ "$PPID" = "$lane13_cap_pid" ] || return 1
    process_matches_starttime "$lane13_cap_pid" "$lane13_cap_start" || return 1
    lane13_expected_script=$(lane13_canonical_script "$0") || return 1
    [ "$lane13_expected_script" = "$lane13_cap_script" ] || return 1
    [ "$(lane13_sha256 "$lane13_expected_script")" = "$lane13_cap_hash" ] || return 1
    python3 - "$lane13_cap_pid" "$lane13_cap_script" <<'PY'
import os
import sys

pid, expected = sys.argv[1:]
raw = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
if len(raw) < 2 or b"--lane13-private-body" in raw:
    raise SystemExit("private body parent is not the outer script")
arg = os.fsdecode(raw[1])
cwd = os.readlink(f"/proc/{pid}/cwd")
actual = os.path.realpath(arg if os.path.isabs(arg) else os.path.join(cwd, arg))
if actual != expected:
    raise SystemExit("private body parent script differs")
PY
}

lane13_signal_body_group() {
    lane13_body_signal=$1
    [ -n "$LANE13_BODY_SID" ] || return 1
    if process_matches_session "$LANE13_BODY_PID" "$LANE13_BODY_STARTTIME" \
        "$LANE13_BODY_SID"; then
        signal_verified_process "$lane13_body_signal" "$LANE13_BODY_PID" \
            "$LANE13_BODY_STARTTIME" "$LANE13_BODY_SID" || return 1
    fi
    lane13_body_members=$(snapshot_user_process_session "$LANE13_BODY_SID") || return 1
    lane13_body_records=$(printf '%s\n' "$lane13_body_members" | python3 -c '
import json
import sys

body_pid, body_start, sid = map(int, sys.argv[1:])
members = json.loads(sys.stdin.read() or "[]")
if sum((member["pid"], member["starttime"], member["sid"]) == (body_pid, body_start, sid) for member in members) != 1:
    raise SystemExit("recorded lane-13 body is absent from its process session")
for member in members:
    if member["sid"] != sid:
        raise SystemExit("body member escaped its recorded process session")
    if (member["pid"], member["starttime"]) == (body_pid, body_start):
        continue
    print(member["pid"], member["starttime"])
' "$LANE13_BODY_PID" "$LANE13_BODY_STARTTIME" "$LANE13_BODY_SID") || return 1
    while read -r lane13_body_member_pid lane13_body_member_start; do
        [ -n "$lane13_body_member_pid" ] || continue
        if [ -e "/proc/$lane13_body_member_pid" ] \
            && ! process_matches_session "$lane13_body_member_pid" \
                "$lane13_body_member_start" "$LANE13_BODY_SID"; then
            return 1
        fi
        if ! signal_verified_process "$lane13_body_signal" \
            "$lane13_body_member_pid" "$lane13_body_member_start" \
            "$LANE13_BODY_SID" 2>/dev/null; then
            process_matches_starttime "$lane13_body_member_pid" "$lane13_body_member_start" \
                || continue
            return 1
        fi
    done <<EOF
$lane13_body_records
EOF
}


lane13_outer_terminal_failure() {
    lane13_terminal_status=${1:-1}
    if [ "${EVIDENCE_OWNED:-0}" -ne 1 ]; then
        trap - EXIT
        exit "$lane13_terminal_status"
    fi
    [ "${LANE13_OUTER_STATUS_WRITTEN-0}" -eq 1 ] && exit "$lane13_terminal_status"
    [ "$lane13_terminal_status" -eq 0 ] && lane13_terminal_status=1
    trap ':' EXIT
    trap ':' INT
    trap ':' TERM
    set +e
    for lane13_terminal_file in stdout.log stderr.log facts.log status; do
        [ -e "$EVIDENCE/$lane13_terminal_file" ] || : > "$EVIDENCE/$lane13_terminal_file"
    done
    chmod 600 "$EVIDENCE/stdout.log" "$EVIDENCE/stderr.log" \
        "$EVIDENCE/facts.log" "$EVIDENCE/status"
    printf '%s\n' "$lane13_terminal_status" > "$EVIDENCE/status"
    LANE13_OUTER_STATUS_WRITTEN=1
    exit "$lane13_terminal_status"
}

lane13_outer_signal() {
    if [ "${LANE13_OUTER_EXIT_ARMED:-0}" -eq 1 ] \
        && [ "${EVIDENCE_OWNED:-0}" -ne 1 ]; then
        LANE13_OUTER_PENDING_STATUS=$1
        return 0
    fi
    [ "${LANE13_OUTER_STATUS_WRITTEN-0}" -eq 1 ] || exit "$1"
}

lane13_outer() {
    LANE13_OUTER_STATUS_WRITTEN=0
    trap 'lane13_outer_signal 130' INT
    trap 'lane13_outer_signal 143' TERM
    [ "$#" -eq 0 ] || { echo "verify-knative.sh takes no arguments" >&2; return 2; }
    [ -z "${P11SCOPE_LANE13_BODY-}" ] || {
        echo "private lane-13 body marker is not a public input" >&2
        return 2
    }
    case ${P11SCOPE_LANE_EVIDENCE_DIR-} in
        /*) ;;
        *) echo "P11SCOPE_LANE_EVIDENCE_DIR must be an absolute path" >&2; return 2 ;;
    esac
    case $P11SCOPE_LANE_EVIDENCE_DIR in *'/../'*|../*|*/..)
        echo "P11SCOPE_LANE_EVIDENCE_DIR may not contain dot-dot components" >&2; return 2 ;;
    esac
    [ ! -e "$P11SCOPE_LANE_EVIDENCE_DIR" ] && [ ! -L "$P11SCOPE_LANE_EVIDENCE_DIR" ] || {
        echo "lane-13 evidence root already exists" >&2; return 2;
    }
    lane13_outer_parent=${P11SCOPE_LANE_EVIDENCE_DIR%/*}
    lane13_outer_leaf=${P11SCOPE_LANE_EVIDENCE_DIR##*/}
    [ -n "$lane13_outer_parent" ] && [ -n "$lane13_outer_leaf" ] \
        && [ -d "$lane13_outer_parent" ] || {
        echo "lane-13 evidence parent is not an existing directory" >&2; return 2;
    }
    lane13_outer_ancestor=$lane13_outer_parent
    while [ "$lane13_outer_ancestor" != / ]; do
        [ ! -L "$lane13_outer_ancestor" ] || {
            echo "lane-13 evidence parent has a symlink ancestor" >&2; return 2;
        }
        lane13_outer_ancestor=${lane13_outer_ancestor%/*}
        [ -n "$lane13_outer_ancestor" ] || lane13_outer_ancestor=/
    done
    lane13_outer_parent=$(cd "$lane13_outer_parent" && pwd -P) || return 2
    lane13_outer_worktree=$(pwd -P)
    [ "$P11SCOPE_LANE_EVIDENCE_DIR" = "$lane13_outer_parent/$lane13_outer_leaf" ] || {
        echo "P11SCOPE_LANE_EVIDENCE_DIR must use its canonical spelling" >&2; return 2;
    }
    case $P11SCOPE_LANE_EVIDENCE_DIR in "$lane13_outer_worktree"|"$lane13_outer_worktree"/*)
        echo "P11SCOPE_LANE_EVIDENCE_DIR must be outside the physical worktree" >&2; return 2 ;;
    esac
    python3 - "$lane13_outer_parent" <<'PY'
import os
import stat
import sys
status = os.stat(sys.argv[1])
if status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) & 0o077:
    raise SystemExit("lane-13 evidence parent must be caller-owned and private")
PY
    EVIDENCE=$P11SCOPE_LANE_EVIDENCE_DIR
    EVIDENCE_OWNED=0
    LANE13_OUTER_EXIT_ARMED=1
    LANE13_OUTER_PENDING_STATUS=
    trap 'lane13_outer_terminal_failure "$?"' EXIT
    umask 077
    mkdir -m 700 "$P11SCOPE_LANE_EVIDENCE_DIR" || return 1
    [ -d "$EVIDENCE" ] && [ ! -L "$EVIDENCE" ] \
        && [ "$(stat -Lc %u "$EVIDENCE")" = "$(id -u)" ] \
        && [ "$(stat -Lc %a "$EVIDENCE")" = 700 ] || return 1
    EVIDENCE_OWNED=1
    if [ -n "$LANE13_OUTER_PENDING_STATUS" ]; then
        lane13_outer_terminal_failure "$LANE13_OUTER_PENDING_STATUS"
    fi
    : > "$EVIDENCE/stdout.log" || return 1
    : > "$EVIDENCE/stderr.log" || return 1
    : > "$EVIDENCE/status" || return 1
    chmod 600 "$EVIDENCE/stdout.log" "$EVIDENCE/stderr.log" "$EVIDENCE/status" || return 1
    lane13_outer_script=$(lane13_canonical_script "$0") || return 1
    lane13_outer_starttime=$(process_starttime $$) || return 1
    lane13_outer_nonce=$(python3 -c 'import secrets; print(secrets.token_hex(32))') || return 1
    lane13_outer_capability="$EVIDENCE/.lane13-capability.$$"
    printf 'lane13-v1|%s|%s|%s|%s|%s\n' \
        "$$" "$lane13_outer_starttime" "$lane13_outer_script" \
        "$(lane13_sha256 "$lane13_outer_script")" "$lane13_outer_nonce" \
        > "$lane13_outer_capability" || return 1
    chmod 600 "$lane13_outer_capability" || return 1
    exec 9< "$lane13_outer_capability" || return 1
    rm -f -- "$lane13_outer_capability" || return 1
    lane13_outer_pidfile="$EVIDENCE/.lane13-body.pid"
    lane13_outer_launchlog="$EVIDENCE/.lane13-body-launch.log"
    trap 'LANE13_BODY_SIGNAL=INT; [ -z "$LANE13_BODY_PID" ] || lane13_signal_body_group INT || LANE13_BODY_SIGNAL_STATUS=1' INT
    trap 'LANE13_BODY_SIGNAL=TERM; [ -z "$LANE13_BODY_PID" ] || lane13_signal_body_group TERM || LANE13_BODY_SIGNAL_STATUS=1' TERM
    set +e
    P11SCOPE_LANE13_BODY=1 P11SCOPE_LANE13_CAP=$lane13_outer_nonce \
        P11SCOPE_LANE13_TOKEN=$TOKEN P11SCOPE_LANE13_OUTER_ARGV=$0 \
        P11SCOPE_LANE_EVIDENCE_DIR=$EVIDENCE \
        launch_user_recorded_process_group "$lane13_outer_pidfile" "$lane13_outer_launchlog" \
        env P11SCOPE_LANE13_BODY=1 P11SCOPE_LANE13_CAP=$lane13_outer_nonce \
        P11SCOPE_LANE13_TOKEN=$TOKEN P11SCOPE_LANE13_OUTER_ARGV=$0 \
        P11SCOPE_LANE13_OUTER_PID=$$ \
        P11SCOPE_LANE_EVIDENCE_DIR=$EVIDENCE /bin/sh -c \
        'exec /bin/sh "$1" --lane13-private-body >"$2" 2>"$3"' \
        sh "$0" "$EVIDENCE/stdout.log" "$EVIDENCE/stderr.log"
    lane13_outer_launch_status=$?
    LANE13_BODY_PID=$USER_PROCESS_PID
    LANE13_BODY_STARTTIME=$USER_PROCESS_STARTTIME
    LANE13_BODY_PGID=$USER_PROCESS_PGID
    LANE13_BODY_SID=$USER_PROCESS_SID
    [ -z "$LANE13_BODY_SIGNAL" ] || lane13_signal_body_group "$LANE13_BODY_SIGNAL" || LANE13_BODY_SIGNAL_STATUS=1
    if [ "$lane13_outer_launch_status" -eq 0 ]; then
        wait "$USER_PROCESS_LAUNCH_PID"
        lane13_outer_body_status=$?
    else
        lane13_outer_body_status=$lane13_outer_launch_status
    fi
    set -e
    lane13_outer_status=$lane13_outer_body_status
    lane13_outer_group_empty=0
    if [ -n "$LANE13_BODY_SID" ] \
        && lane13_outer_group_snapshot=$(snapshot_user_process_session "$LANE13_BODY_SID" 2>/dev/null) \
        && [ "$lane13_outer_group_snapshot" = "[]" ]; then
        lane13_outer_group_empty=1
    else
        lane13_outer_status=1
    fi
    if [ "$lane13_outer_group_empty" -eq 1 ]; then
        rm -f -- "$lane13_outer_pidfile" "$lane13_outer_launchlog" \
            || lane13_outer_status=1
    fi
    exec 9<&-
    if [ ! -e "$WORK" ] && [ ! -L "$WORK" ]; then :; else lane13_outer_status=1; fi
    if ! lane13_validate_retained_root; then lane13_outer_status=1; fi
    # Cleanup is complete but terminal evidence is not yet committed. A signal
    # in this window invalidates the transaction rather than becoming evidence
    # that cleanup was interrupted.
    trap 'lane13_outer_signal 1' INT
    trap 'lane13_outer_signal 1' TERM
    [ "$LANE13_BODY_SIGNAL_STATUS" -eq 0 ] || lane13_outer_status=1
    if ! printf '%s\n' "$lane13_outer_status" > "$EVIDENCE/status"; then
        lane13_outer_status=1
        return 1
    fi
    LANE13_OUTER_STATUS_WRITTEN=1
    trap - EXIT
    return "$lane13_outer_status"
}

terminate_port_forward() {
    [ -n "$PF_PID" ] || return 0
    [ -n "$PF_STARTTIME" ] || {
        echo "port-forward lifecycle lacks its recorded identity" >&2
        return 1
    }
    [ -n "$PF_PGID" ] || PF_PGID=$PF_SID
    PF_SESSION_EMPTY=0
    pf_forced=
    pf_state=
    if [ -z "$PF_PGID" ]; then
        if process_matches_starttime "$PF_PID" "$PF_STARTTIME"; then
            signal_verified_process TERM "$PF_PID" "$PF_STARTTIME" || true
            pf_attempt=0
            while process_matches_starttime "$PF_PID" "$PF_STARTTIME" && [ "$pf_attempt" -lt 100 ]; do
                pf_attempt=$((pf_attempt + 1))
                sleep 0.05
            done
            if process_matches_starttime "$PF_PID" "$PF_STARTTIME"; then
                signal_verified_process KILL "$PF_PID" "$PF_STARTTIME" || true
                pf_forced=1
            fi
            if process_matches_starttime "$PF_PID" "$PF_STARTTIME"; then
                echo "port-forward partial generation remains live; refusing an unbounded wait" >&2
            else
                wait "$PF_LAUNCH_PID" 2>/dev/null || true
            fi
        fi
        echo "port-forward launch interrupted before group authorization" >&2
        return 1
    fi
    pf_error=0
    pf_absent=0
    process_matches_starttime "$PF_PID" "$PF_STARTTIME" || pf_absent=1
    pf_authorization=${PF_GROUP_SNAPSHOT:-"$WORK/portforward.group.authorization"}
    if [ -n "$PF_GROUP_SNAPSHOT" ] \
        && [ -f "$pf_authorization" ] && [ ! -L "$pf_authorization" ]; then
        pf_authorized=1
    elif [ "$pf_absent" -eq 0 ] \
        && snapshot_user_process_session "$PF_SID" > "$pf_authorization"; then
        pf_authorized=1
    else
        pf_authorized=0
        pf_error=1
        echo "port-forward leader is absent or snapshot failed before authorization" >&2
    fi
    if [ "$pf_authorized" -eq 1 ] && ! python3 - "$pf_authorization" "$PF_PID" "$PF_STARTTIME" "$PF_SID" <<'PY'
import json
import sys

members = json.load(open(sys.argv[1], encoding="utf-8"))
leader = (int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))
if any(member.get("sid") != leader[2] for member in members):
    raise SystemExit("invalid port-forward authorization snapshot")
if not all(set(member) == {"pid", "starttime", "ppid", "pgid", "sid", "exe_sha256", "argv"} for member in members):
    raise SystemExit("invalid port-forward session snapshot")
if sum((member["pid"], member["starttime"], member["sid"]) == leader for member in members) != 1:
    raise SystemExit("recorded port-forward leader is absent from authorization snapshot")
PY
    then
        pf_error=1
        pf_authorized=0
    fi
    [ "$pf_absent" -eq 0 ] || pf_error=1
    if [ "$pf_authorized" -eq 1 ]; then
        pf_member_records=$(python3 - "$pf_authorization" <<'PY'
import json
import sys

for member in json.load(open(sys.argv[1], encoding="utf-8")):
    print(member["pid"], member["starttime"])
PY
        ) || { pf_member_records=; pf_error=1; }
        while read -r pf_member_pid pf_member_starttime; do
            [ -n "$pf_member_pid" ] || continue
            if [ -e "/proc/$pf_member_pid" ] \
                && ! process_matches_session "$pf_member_pid" "$pf_member_starttime" "$PF_SID"; then
                pf_error=1
                continue
            fi
            if ! signal_verified_process TERM "$pf_member_pid" "$pf_member_starttime" "$PF_SID" \
                && process_matches_session "$pf_member_pid" "$pf_member_starttime" "$PF_SID"; then
                pf_error=1
            fi
        done <<EOF
$pf_member_records
EOF
    fi

    if process_matches_starttime "$PF_PID" "$PF_STARTTIME"; then
        pf_attempt=0
        while [ "$pf_attempt" -lt 100 ]; do
            process_matches_starttime "$PF_PID" "$PF_STARTTIME" || break
            pf_state=$(awk '$1 == "State:" { print $2; exit }' "/proc/$PF_PID/status" 2>/dev/null || true)
            [ "$pf_state" = Z ] && break
            pf_attempt=$((pf_attempt + 1))
            sleep 0.05
        done
        if [ "$pf_state" != Z ] \
            && process_matches_starttime "$PF_PID" "$PF_STARTTIME"; then
            if [ "$pf_authorized" -eq 1 ] \
                && process_matches_session "$PF_PID" "$PF_STARTTIME" "$PF_SID"; then
                if signal_verified_process KILL "$PF_PID" "$PF_STARTTIME" "$PF_SID"; then
                    pf_forced=1
                elif process_matches_session "$PF_PID" "$PF_STARTTIME" "$PF_SID"; then
                    pf_error=1
                fi
            else
                pf_error=1
            fi
            pf_attempt=0
            while [ "$pf_attempt" -lt 100 ]; do
                process_matches_starttime "$PF_PID" "$PF_STARTTIME" || break
                pf_state=$(awk '$1 == "State:" { print $2; exit }' "/proc/$PF_PID/status" 2>/dev/null || true)
                [ "$pf_state" = Z ] && break
                pf_attempt=$((pf_attempt + 1))
                sleep 0.05
            done
            if process_matches_starttime "$PF_PID" "$PF_STARTTIME" \
                && [ "$pf_state" != Z ]; then
                echo "port-forward survived its pinned KILL" >&2
                pf_error=1
            fi
        fi
    fi

    if process_matches_starttime "$PF_PID" "$PF_STARTTIME" && [ "${pf_state-}" != Z ]; then
        echo "port-forward remains live; refusing an unbounded wait" >&2
        pf_error=1
        pf_wait_status=
    elif [ "$pf_absent" -eq 1 ]; then
        pf_wait_status=0
    elif wait "$PF_LAUNCH_PID"; then
        pf_wait_status=0
    else
        pf_wait_status=$?
    fi
    case $pf_wait_status in
        0|143) ;;
        137) echo "port-forward required or received SIGKILL" >&2; pf_forced=1; pf_error=1 ;;
        '') ;;
        *) echo "port-forward exited with unexpected status $pf_wait_status" >&2; pf_error=1 ;;
    esac
    if process_matches_starttime "$PF_PID" "$PF_STARTTIME"; then
        echo "port-forward leader remains after wait" >&2
        pf_error=1
    elif [ -d "/proc/$PF_PID" ]; then
        echo "port-forward PID identity is ambiguous after wait" >&2
        pf_error=1
    fi
    PF_GROUP_SNAPSHOT_AFTER=${PF_GROUP_SNAPSHOT_AFTER:-"$WORK/portforward.group.after.json"}
    if ! snapshot_user_process_session "$PF_SID" > "$PF_GROUP_SNAPSHOT_AFTER"; then
        pf_error=1
    elif [ "$(cat "$PF_GROUP_SNAPSHOT_AFTER")" != "[]" ]; then
        pf_member_records=$(python3 - "$PF_GROUP_SNAPSHOT_AFTER" "$pf_authorization" "$PF_SID" <<'PY'
import json
import sys

members = json.load(open(sys.argv[1], encoding="utf-8"))
authorized = {
    (member["pid"], member["starttime"])
    for member in json.load(open(sys.argv[2], encoding="utf-8"))
}
sid = int(sys.argv[3])
if any(member["sid"] != sid or (member["pid"], member["starttime"]) not in authorized for member in members):
    raise SystemExit("port-forward session contains an unauthorized member")
for member in members:
    print(member["pid"], member["starttime"])
PY
        ) || {
            pf_error=1
            pf_member_records=
        }
        while [ -n "$pf_member_records" ] && read -r pf_member_pid pf_member_starttime; do
            if [ -e "/proc/$pf_member_pid" ] \
                && ! process_matches_session "$pf_member_pid" "$pf_member_starttime" "$PF_SID"; then
                pf_error=1
                continue
            fi
            if ! signal_verified_process KILL "$pf_member_pid" "$pf_member_starttime" "$PF_SID" \
                && process_matches_session "$pf_member_pid" "$pf_member_starttime" "$PF_SID"; then
                pf_error=1
            fi
        done <<EOF
$pf_member_records
EOF
        pf_attempt=0
        while [ "$pf_attempt" -lt 100 ]; do
            [ "$(snapshot_user_process_session "$PF_SID")" = "[]" ] && break
            pf_attempt=$((pf_attempt + 1))
            sleep 0.05
        done
        if [ "$(snapshot_user_process_session "$PF_SID")" != "[]" ]; then
            echo "port-forward process session remains after pinned cleanup" >&2
            pf_error=1
        fi
        echo "port-forward authorized member remained after leader exit" >&2
        pf_error=1
    fi
    if [ "$(snapshot_user_process_session "$PF_SID" 2>/dev/null || printf '?')" = "[]" ]; then
        PF_LAUNCH_PID=
        PF_PID=
        PF_STARTTIME=
        PF_PGID=
        PF_SID=
        PF_GROUP_SNAPSHOT=
        USER_PROCESS_LAUNCH_PID=
        USER_PROCESS_PID=
        USER_PROCESS_STARTTIME=
        USER_PROCESS_PGID=
        USER_PROCESS_SID=
        USER_PROCESS_INITIAL_STARTTIME=
        USER_PROCESS_PIDFILE=
        PF_SESSION_EMPTY=1
    else
        pf_error=1
    fi
    [ -z "$pf_forced" ] || pf_error=1
    return "$pf_error"
}

cleanup() {
    BODY_STATUS=$?
    CLEANUP_STATUS=$BODY_STATUS
    trap - EXIT INT TERM
    set +e
    if [ -z "$PF_PID" ] \
        && [ -n "${USER_PROCESS_PID-}" ] && [ -n "${USER_PROCESS_STARTTIME-}" ]; then
        PF_LAUNCH_PID=${USER_PROCESS_LAUNCH_PID-}
        PF_PID=$USER_PROCESS_PID
        PF_STARTTIME=$USER_PROCESS_STARTTIME
        PF_PGID=
        PF_SID=$USER_PROCESS_SID
        [ -n "${USER_PROCESS_PIDFILE-}" ] || USER_PROCESS_PIDFILE=$WORK/portforward.pid
        if [ -n "${USER_PROCESS_PIDFILE-}" ] && [ -s "$USER_PROCESS_PIDFILE" ]; then
            pf_handoff=$(python3 - "$USER_PROCESS_PIDFILE" "$PF_PID" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
if record.get("pid") != int(sys.argv[2]):
    raise SystemExit(1)
if not all(isinstance(record.get(field), int) and record[field] > 0 for field in ("starttime", "pgid", "sid")):
    raise SystemExit(1)
if record["pid"] != record["pgid"] or record["pid"] != record["sid"]:
    raise SystemExit(1)
print(record["starttime"], record["pgid"], record["sid"])
PY
            ) && {
                PF_STARTTIME=${pf_handoff%% *}
                pf_handoff_rest=${pf_handoff#* }
                PF_PGID=${pf_handoff_rest%% *}
                PF_SID=${pf_handoff_rest#* }
            }
        fi
    fi
    [ -z "$PF_PID" ] || cleanup_step terminate_port_forward
    launcher=${SPID:-$ROOT_LAUNCH_PID}
    recorded_pid=${SUPERVISOR_PID:-$ROOT_PROCESS_PID}
    recorded_starttime=${SUPERVISOR_STARTTIME:-$ROOT_PROCESS_STARTTIME}
    if [ -n "$launcher" ]; then
        if [ -n "$recorded_pid" ] && [ -n "$recorded_starttime" ]; then
            cleanup_step signal_verified_root_process TERM \
                "$recorded_pid" "$recorded_starttime"
        else
            cleanup_step false
        fi
        cleanup_step wait "$launcher"
    fi
    [ -z "${EVIDENCE-}" ] || cleanup_step lane13_preserve_diagnostics
    [ -z "${CLUSTER_CLEANUP_ARMED-}" ] || {
        cleanup_step lane13_delete_owned_cluster
        if [ "$cleanup_step_status" -eq 0 ]; then
            CLUSTER_ABSENT=1
            cleanup_step lane13_fact cluster_absent=1
        else
            CLUSTER_ABSENT=0
            cleanup_step lane13_fact cluster_absent=0
        fi
    }
    [ -z "${IMAGE_CLEANUP_ARMED-}" ] || {
        cleanup_step lane13_delete_owned_image
        if [ "$cleanup_step_status" -eq 0 ]; then
            IMAGE_ABSENT=1
            cleanup_step lane13_fact workload_tag_absent=1
        else
            IMAGE_ABSENT=0
            cleanup_step lane13_fact workload_tag_absent=0
        fi
    }
    [ -z "${CLUSTER_CLEANUP_ARMED-}" ] || {
        cleanup_step_status=0
        if [ -e "$KUBECONFIG" ] || [ -L "$KUBECONFIG" ]; then
            if [ -z "$KUBECONFIG_DEV_INO" ] && [ -f "$KUBECONFIG" ] && [ ! -L "$KUBECONFIG" ]; then
                KUBECONFIG_DEV_INO=$(stat -Lc '%d:%i' "$KUBECONFIG")
            fi
            cleanup_step lane13_remove_owned_kubeconfig
        fi
        if [ "$cleanup_step_status" -eq 0 ] || { [ ! -e "$KUBECONFIG" ] && [ ! -L "$KUBECONFIG" ]; }; then
            KUBECONFIG_ABSENT=1
            cleanup_step lane13_fact kubeconfig_absent=1
        else
            KUBECONFIG_ABSENT=0
            cleanup_step lane13_fact kubeconfig_absent=0
        fi
    }
    [ -z "${EVIDENCE-}" ] || cleanup_step lane13_record_facts end
    [ -z "${EVIDENCE-}" ] || cleanup_step lane13_compare_input_ledgers \
        "$WORK/.lane13-inputs-start" "$WORK/.lane13-inputs-end"
    [ -z "${EVIDENCE-}" ] || cleanup_step cmp "$WORK/.lane13-git-start" "$WORK/.lane13-git-end"
    if [ -n "${WORK_CREATED-}" ] \
        && [ "$PF_SESSION_EMPTY" -eq 1 ] \
        && [ "$CLUSTER_ABSENT" -eq 1 ] \
        && [ "$IMAGE_ABSENT" -eq 1 ] \
        && [ "$KUBECONFIG_ABSENT" -eq 1 ]; then
        cleanup_step rm -f -- "$WORK/.lane13-inputs-start" "$WORK/.lane13-inputs-end"
        cleanup_step rm -f -- "$WORK/.lane13-git-start" "$WORK/.lane13-git-end"
        cleanup_step lane13_remove_owned_work
    else
        [ -z "${WORK_CREATED-}" ] || cleanup_step false
    fi
    [ -z "${EVIDENCE-}" ] || cleanup_step lane13_record_absence_fact "$WORK" work_absent
    [ ! -e "$KUBECONFIG" ] && [ ! -L "$KUBECONFIG" ] || cleanup_step false
    [ -z "${WORK_CREATED-}" ] || {
        [ ! -e "$WORK" ] && [ ! -L "$WORK" ] || cleanup_step false
    }
    [ -z "${EVIDENCE-}" ] || cleanup_step lane13_fact "cleanup_status=$CLEANUP_STATUS"
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

if [ "${P11SCOPE_LANE13_BODY-}" = 1 ]; then
    lane13_authorize_body "$@" || {
        trap - EXIT INT TERM
        echo "lane-13 private body authorization failed" >&2
        exit 2
    }
    shift
else
    lane13_outer "$@"
    exit $?
fi

for command in cargo curl docker gcc kind kubectl python3 tar timeout; do
    command -v "$command" >/dev/null || { echo "$command required" >&2; exit 1; }
done
sudo -n true 2>/dev/null || { echo "passwordless sudo required" >&2; exit 1; }
lane13_prepare_diagnostics "$@"
lane13_preflight
IMAGE_CLEANUP_ARMED=1
CLUSTER_CLEANUP_ARMED=1

echo "=== build product and unique Knative workload image ==="
mkdir "$WORK"
WORK_CREATED=1
WORK_DEV_INO=$(stat -Lc '%d:%i' "$WORK")
[ "$(stat -Lc %u "$WORK")" = "$(id -u)" ] && [ "$(stat -Lc %a "$WORK")" = 700 ]
lane13_fact "work_dev_ino=$WORK_DEV_INO"
lane13_record_facts start
timeout --signal=TERM --kill-after=5s 600s cargo +1.88 build --locked --release \
    --workspace --target-dir "$PRODUCT"
lane13_record_file_fact p11scope "$PRODUCT/release/p11scope"
lane13_record_file_fact p11scope_discover "$PRODUCT/release/p11scope-discover"
lane13_record_generated_bpf
mkdir -p "$WORK/build" "$WORK/provider-safe"
timeout --signal=TERM --kill-after=5s 60s gcc -O0 -o "$WORK/build/harness" \
    spike/harness.c -ldl
cp scripts/matrix/knative-server.py "$WORK/build/knative-server.py"
lane13_record_base_and_build

echo "=== create isolated kind cluster and install Knative ==="
lane13_create_cluster
timeout --signal=TERM --kill-after=5s 60s \
    kubectl config use-context "kind-$CLUSTER" >/dev/null
timeout --signal=TERM --kill-after=5s 180s kubectl wait --for=condition=Ready \
    node --all --timeout=120s
timeout --signal=TERM --kill-after=5s 300s kind load docker-image "$IMAGE" --name "$CLUSTER"
lane13_fetch_release \
    "https://github.com/knative/serving/releases/download/${KNATIVE_VERSION}/serving-crds.yaml" \
    serving-crds.yaml
lane13_fetch_release \
    "https://github.com/knative/serving/releases/download/${KNATIVE_VERSION}/serving-core.yaml" \
    serving-core.yaml
lane13_fetch_release \
    "https://github.com/knative/net-kourier/releases/download/${KNATIVE_VERSION}/kourier.yaml" \
    kourier.yaml
timeout --signal=TERM --kill-after=5s 60s kubectl patch \
    configmap/config-network -n knative-serving --type merge \
    -p '{"data":{"ingress-class":"kourier.ingress.networking.knative.dev"}}'
for deployment in controller webhook net-kourier-controller activator autoscaler; do
    timeout --signal=TERM --kill-after=5s 60s \
        kubectl get deployment "$deployment" -n knative-serving \
        >/dev/null 2>&1 || continue
    container=$(timeout --signal=TERM --kill-after=5s 60s \
        kubectl get deployment "$deployment" -n knative-serving \
        -o jsonpath='{.spec.template.spec.containers[0].name}')
    timeout --signal=TERM --kill-after=5s 60s kubectl set env \
        deployment/"$deployment" -n knative-serving -c "$container" \
        KUBERNETES_MIN_VERSION=1.33.0 >/dev/null
done
timeout --signal=TERM --kill-after=5s 210s kubectl wait --for=condition=Available \
    deployment --all -n knative-serving --timeout=180s
timeout --signal=TERM --kill-after=5s 210s kubectl wait --for=condition=Available \
    deployment --all -n kourier-system --timeout=180s
lane13_record_namespace_identities knative-serving
lane13_record_namespace_identities kourier-system

echo "=== retain one same-image anchor for mount and inode authority ==="
cat > "$WORK/anchor.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $ANCHOR
spec:
  containers:
  - name: anchor
    image: $IMAGE
    imagePullPolicy: Never
    command: ["sleep", "infinity"]
  restartPolicy: Never
EOF
timeout --signal=TERM --kill-after=5s 60s kubectl apply -f "$WORK/anchor.yaml"
timeout --signal=TERM --kill-after=5s 90s kubectl wait --for=condition=Ready \
    "pod/$ANCHOR" --timeout=60s
ANCHOR_CID=$(timeout --signal=TERM --kill-after=5s 60s kubectl get pod "$ANCHOR" \
    -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's#containerd://##')
case $ANCHOR_CID in ''|*[!0-9a-f]*) echo "anchor container id invalid" >&2; exit 1 ;; esac
lane13_record_pod_identity default "$ANCHOR"
ANCHOR_CG=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    find /sys/fs/cgroup -type d -name "cri-containerd-${ANCHOR_CID}.scope" \
    -print -quit 2>/dev/null)
test -n "$ANCHOR_CG" || { echo "anchor cgroup missing" >&2; exit 1; }
ANCHOR_PID=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    awk 'NR == 1 { print; exit }' "$ANCHOR_CG/cgroup.procs")
case $ANCHOR_PID in ''|*[!0-9]*) echo "anchor host pid missing" >&2; exit 1 ;; esac
KUBEPODS=
ancestor=$ANCHOR_CG
while [ "$ancestor" != /sys/fs/cgroup ]; do
    case ${ancestor##*/} in *kubepods*.slice|kubepods) KUBEPODS=$ancestor ;; esac
    ancestor=${ancestor%/*}
done
test -n "$KUBEPODS" || { echo "stable kubepods cgroup missing" >&2; exit 1; }

PROVIDER_REAL=$(timeout --signal=TERM --kill-after=5s 60s kubectl exec "$ANCHOR" -- \
    readlink -f "$MODULE_IN_POD")
PROVIDER_DIR=${PROVIDER_REAL%/*}
PROVIDER_NAME=${PROVIDER_REAL##*/}
# This lane keeps the copy-and-discover apparatus every other container lane
# dropped, and must. The whole point is attaching *before the pod exists*: the
# service is scaled to zero, so at attach time there is no process to scan and
# no mapping to read. Only a manifest, taken from an anchor pod that runs the
# same image, can describe a provider that has not been loaded yet -- so the
# capture reports it uncorroborated. Discovering a provider in a pod that
# cold-starts after attach is Slice 1b-2's live discovery, not this slice's.
capped_container_tar "$WORK/provider.tar" \
    timeout --signal=TERM --kill-after=5s 60s kubectl exec "$ANCHOR" -- \
    tar -chC "$PROVIDER_DIR" .
tar -xf "$WORK/provider.tar" -C "$WORK/provider-safe"
    discover_copied_provider "$PWD/$WORK/provider-safe" "$PROVIDER_NAME" \
        "$PRODUCT/release/p11scope-discover" "/proc/$ANCHOR_PID/root$PROVIDER_DIR" \
        "$WORK/manifest-host.json"
lane13_record_file_fact copied_provider "$WORK/provider-safe/$PROVIDER_NAME"
lane13_record_manifest_provider "$WORK/manifest-host.json" \
    "/proc/$ANCHOR_PID/root$PROVIDER_REAL" "$WORK/provider-safe/$PROVIDER_NAME"
lane13_record_capture_provider

echo "=== deploy service, then prove its initial pod scaled to zero ==="
cat > "$WORK/ksvc.yaml" <<EOF
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: $KSVC
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/min-scale: "0"
        autoscaling.knative.dev/max-scale: "1"
    spec:
      timeoutSeconds: 10
      containerConcurrency: 1
      containers:
      - image: $IMAGE
        imagePullPolicy: Never
        ports:
        - containerPort: 8080
EOF
timeout --signal=TERM --kill-after=5s 60s kubectl apply -f "$WORK/ksvc.yaml"
timeout --signal=TERM --kill-after=5s 210s kubectl wait --for=condition=Ready \
    "ksvc/$KSVC" --timeout=180s
HOST=$(timeout --signal=TERM --kill-after=5s 60s \
    kubectl get ksvc "$KSVC" -o jsonpath='{.status.url}' | sed 's#http://##')
service_pod_count() {
    service_pods=$(timeout --signal=TERM --kill-after=1s 5s kubectl get pods \
        -l "serving.knative.dev/service=$KSVC" -o name) || return
    set -- $service_pods
    printf '%s\n' "$#"
}
attempt=0
while [ "$attempt" -lt 36 ]; do
    SERVICE_PODS=$(service_pod_count)
    [ "$SERVICE_PODS" -eq 0 ] && break
    attempt=$((attempt + 1))
    sleep 5
done
[ "$SERVICE_PODS" -eq 0 ] || { echo "service did not scale to zero" >&2; exit 1; }

echo "=== unprivileged diagnostic: the container provider must be unreadable without privileges ==="
set +e
UNPRIV_OUT=$(timeout --signal=TERM --kill-after=5s 60s \
    "$PRODUCT/release/p11scope" profile \
    --manifest "$WORK/manifest-host.json" \
    --cgroup "$KUBEPODS" --mode metrics --duration 1 2>&1)
UNPRIV_RC=$?
set -e
echo "$UNPRIV_OUT"
[ "$UNPRIV_RC" -ne 0 ] || { echo "unprivileged profile unexpectedly succeeded" >&2; exit 1; }
printf '%s\n' "$UNPRIV_OUT" | grep -Fq 'cannot inspect the file locator now (Permission denied' \
    || { echo "unprivileged run failed for an unexpected reason" >&2; exit 1; }

echo "=== attach before the cold-start pod exists ==="
SERVICE_PODS=$(service_pod_count)
[ "$SERVICE_PODS" -eq 0 ] || { echo "service pods appeared before attach" >&2; exit 1; }
set -- timeout --signal=TERM --kill-after=5s 70s \
    "$PRODUCT/release/p11scope" profile --manifest "$WORK/manifest-host.json" \
    --cgroup "$KUBEPODS" \
    --mode metrics --duration 40 -o "$WORK/observed.json"
launch_root_recorded_process "$WORK/observer.pid" "$WORK/profile.log" "$@"
SPID=$ROOT_LAUNCH_PID
SUPERVISOR_PID=$ROOT_PROCESS_PID
SUPERVISOR_STARTTIME=$ROOT_PROCESS_STARTTIME
wait_for_capture_ready "$WORK/profile.log" aggregate-only metrics
SERVICE_PODS=$(service_pod_count)
[ "$SERVICE_PODS" -eq 0 ] \
    || { echo "service pods appeared after attach readiness" >&2; exit 1; }
ATTACH_READY=$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat())')

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
PF_PENDING_STATUS=
trap 'PF_PENDING_STATUS=${PF_PENDING_STATUS:-130}' INT
trap 'PF_PENDING_STATUS=${PF_PENDING_STATUS:-143}' TERM
set +e
launch_user_recorded_process_group "$WORK/portforward.pid" "$WORK/portforward.log" \
    kubectl port-forward -n kourier-system svc/kourier-internal "$PORT:80"
pf_launch_status=$?
set -e
PF_LAUNCH_PID=$USER_PROCESS_LAUNCH_PID
PF_PID=$USER_PROCESS_PID
PF_STARTTIME=$USER_PROCESS_STARTTIME
PF_PGID=$USER_PROCESS_PGID
PF_SID=$USER_PROCESS_SID
PF_GROUP_SNAPSHOT=
. scripts/cleanup-traps.sh
[ -z "$PF_PENDING_STATUS" ] || exit "$PF_PENDING_STATUS"
[ "$pf_launch_status" -eq 0 ] || exit "$pf_launch_status"
port_attempt=0
while [ "$port_attempt" -lt 600 ]; do
    python3 -c 'import socket,sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1).close()' \
        "$PORT" 2>/dev/null && break
    process_matches_starttime "$PF_PID" "$PF_STARTTIME" \
        || { echo "port-forward identity changed before readiness" >&2; exit 1; }
    port_attempt=$((port_attempt + 1))
    sleep 0.05
done
[ "$port_attempt" -lt 600 ] || { echo "port-forward was not ready" >&2; exit 1; }
snapshot_user_process_session "$PF_SID" > "$WORK/portforward.group.before.json"
PF_GROUP_SNAPSHOT="$WORK/portforward.group.before.json"
PF_GROUP_SNAPSHOT_AFTER="$WORK/portforward.group.after.json"
python3 - "$PF_GROUP_SNAPSHOT" "$PF_PID" "$PF_STARTTIME" "$PF_SID" "$PORT" <<'PY'
import json
import sys

members = json.load(open(sys.argv[1], encoding="utf-8"))
expected = ["kubectl", "port-forward", "-n", "kourier-system", "svc/kourier-internal", f"{sys.argv[5]}:80"]
leader = (int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))
if len(members) != 1:
    raise SystemExit("port-forward process session has unexpected descendants")
member = members[0]
if (member["pid"], member["starttime"], member["sid"]) != leader or member["argv"] != expected:
    raise SystemExit("port-forward process session does not match its recorded command")
PY
process_matches_starttime "$PF_PID" "$PF_STARTTIME" \
    || { echo "port-forward identity changed before request" >&2; exit 1; }
curl -fsS -H "Host: $HOST" "http://127.0.0.1:$PORT/" --max-time 60
terminate_port_forward

echo "=== prove the cold pod postdates attach and shares the attached inode ==="
NEWPOD=$(timeout --signal=TERM --kill-after=5s 60s kubectl get pods \
    -l "serving.knative.dev/service=$KSVC" \
    --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')
test -n "$NEWPOD" || { echo "cold pod missing" >&2; exit 1; }
NEWPOD_TS=$(timeout --signal=TERM --kill-after=5s 60s \
    kubectl get pod "$NEWPOD" -o jsonpath='{.metadata.creationTimestamp}')
python3 - "$ATTACH_READY" "$NEWPOD_TS" <<'PY'
import datetime
import sys
# creationTimestamp has whole-second resolution; the zero-pod check at
# readiness already proves the ordering, so compare at that resolution.
attach = datetime.datetime.fromisoformat(sys.argv[1]).replace(microsecond=0)
created = datetime.datetime.fromisoformat(sys.argv[2].replace("Z", "+00:00"))
if created < attach:
    raise SystemExit(f"cold pod did not postdate attach: created {created} < attach {attach}")
PY
NEW_CID=$(timeout --signal=TERM --kill-after=5s 60s kubectl get pod "$NEWPOD" \
    -o jsonpath='{.status.containerStatuses[?(@.name=="user-container")].containerID}' \
    | sed 's#containerd://##')
case $NEW_CID in ''|*[!0-9a-f]*) echo "cold container id invalid" >&2; exit 1 ;; esac
lane13_record_pod_identity default "$NEWPOD"
NEW_CG=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    find /sys/fs/cgroup -type d -name "cri-containerd-${NEW_CID}.scope" \
    -print -quit 2>/dev/null)
test -n "$NEW_CG" || { echo "cold pod cgroup missing" >&2; exit 1; }
NEW_PID=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    awk 'NR == 1 { print; exit }' "$NEW_CG/cgroup.procs")
case $NEW_PID in ''|*[!0-9]*) echo "cold pod host pid invalid" >&2; exit 1 ;; esac
ANCHOR_KEY=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    stat -Lc '%d:%i' "/proc/$ANCHOR_PID/root$PROVIDER_REAL")
NEW_KEY=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    stat -Lc '%d:%i' "/proc/$NEW_PID/root$PROVIDER_REAL")
ANCHOR_INODE=${ANCHOR_KEY#*:}
NEW_INODE=${NEW_KEY#*:}
[ "$ANCHOR_INODE" = "$NEW_INODE" ] \
    || { echo "cold pod provider inode differs" >&2; exit 1; }
echo "cold pod provider overlay inode: $NEW_INODE (host identities $ANCHOR_KEY vs $NEW_KEY)"

if wait "$SPID"; then
    SPID=
    SUPERVISOR_PID=
    SUPERVISOR_STARTTIME=
    ROOT_LAUNCH_PID=
    ROOT_PROCESS_PID=
    ROOT_PROCESS_STARTTIME=
else
    status=$?
    SPID=
    SUPERVISOR_PID=
    SUPERVISOR_STARTTIME=
    ROOT_LAUNCH_PID=
    ROOT_PROCESS_PID=
    ROOT_PROCESS_STARTTIME=
    tail -n 20 "$WORK/profile.log" || true
    exit "$status"
fi
reclaim_root_output "$WORK/observed.json"
python3 scripts/check-capture-evidence.py lane13-knative-metrics \
    "$WORK/observed.json" spike/expected.txt

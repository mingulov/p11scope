#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Gate G2: five induced gaps plus one policy-map immutability control.
# Every capture must disclose its exact gap rather than overclaiming.
#
#   1. Aliasing    — two names, one address: counts belong to the group.
#   2. In-flight    — a call entered but not returned by capture end.
#   3. Event loss   — a tiny ring buffer overflowed under a call burst,
#                      but the aggregate maps (the count authority) still
#                      show the exact right number despite the loss. Run both
#                      ways: the small-ring build (3) and the default build
#                      with a flag-set ring (3b, `--ring-bytes 4K`).
#   4. Start loss   — a one-entry START map sees concurrent live calls.
#   5. RV loss      — a one-entry RV map sees distinct completed slots.
#   6. Immutability — every published control map rejects a matched valid
#                      mutation while dynamic accounting still advances.
set -eu
cd "$(dirname "$0")/.."

MODULE=${P11SCOPE_PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}
WORK=${P11SCOPE_RECEIPT_WORK:-target/induced-gaps}
case $WORK in /*) WORK_ABS=$WORK ;; *) WORK_ABS=$PWD/$WORK ;; esac
FIX=scripts/fixtures
. scripts/lib.sh

write_freeze_policy_maps_source() {
    cat > "$1" <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int bpf(enum bpf_cmd cmd, union bpf_attr *attr) {
    return (int)syscall(SYS_bpf, cmd, attr, sizeof(*attr));
}
static void die(const char *what) { perror(what); exit(1); }
static int fd_by_id(enum bpf_cmd cmd, uint32_t id) {
    union bpf_attr attr = {.map_id = id};
    int fd = bpf(cmd, &attr); if (fd < 0) die("BPF_MAP_GET_FD_BY_ID/BPF_PROG_GET_FD_BY_ID"); return fd;
}
static struct bpf_map_info info_for(int fd) {
    struct bpf_map_info info = {0};
    union bpf_attr attr = {.info.bpf_fd = (uint32_t)fd, .info.info_len = sizeof(info),
                           .info.info = (uintptr_t)&info};
    if (bpf(BPF_OBJ_GET_INFO_BY_FD, &attr)) die("BPF_OBJ_GET_INFO_BY_FD");
    return info;
}
static int map_create(const struct bpf_map_info *info) {
    union bpf_attr attr = {.map_type = info->type, .key_size = info->key_size,
        .value_size = info->value_size, .max_entries = info->max_entries,
        .map_flags = info->map_flags};
    memcpy(attr.map_name, "freeze_control", sizeof("freeze_control"));
    int fd = bpf(BPF_MAP_CREATE, &attr); if (fd < 0) die("BPF_MAP_CREATE matched control"); return fd;
}
static int lookup(int fd, void *key, void *value) {
    union bpf_attr attr = {.map_fd = (uint32_t)fd, .key = (uintptr_t)key,
                           .value = (uintptr_t)value};
    return bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}
static int first_key(int fd, void *key) {
    union bpf_attr attr = {.map_fd = (uint32_t)fd, .next_key = (uintptr_t)key};
    return bpf(BPF_MAP_GET_NEXT_KEY, &attr);
}
static int update(int fd, void *key, void *value) {
    union bpf_attr attr = {.map_fd = (uint32_t)fd, .key = (uintptr_t)key,
                           .value = (uintptr_t)value, .flags = BPF_ANY};
    return bpf(BPF_MAP_UPDATE_ELEM, &attr);
}
static int remove_key(int fd, void *key) {
    union bpf_attr attr = {.map_fd = (uint32_t)fd, .key = (uintptr_t)key};
    return bpf(BPF_MAP_DELETE_ELEM, &attr);
}
static int matched_result(int control_rc, int target_rc, int target_errno) {
    return control_rc == 0 && target_rc == -1 && target_errno == EPERM;
}
static void require_match(int control_rc, int target_rc, int target_errno, const char *name) {
    if (!matched_result(control_rc, target_rc, target_errno)) {
        fprintf(stderr, "%s frozen mutation: expected Operation not permitted (EPERM), rc=%d errno=%d\n",
                name, target_rc, target_errno); exit(1);
    }
}
static void ordinary(const char *name, int target, const struct bpf_map_info *info,
                     uint32_t workload_pid) {
    unsigned char *key = calloc(1, info->key_size), *value = calloc(1, info->value_size);
    if (!key || !value) die("calloc");
    if (!strcmp(name, "PID_FILTER")) {
        memcpy(key, &workload_pid, sizeof(workload_pid)); value[0] = 1;
    } else {
        if (first_key(target, key) || lookup(target, key, value)) die("reading policy entry");
    }
    int control = map_create(info);
    int control_rc = update(control, key, value);
    if (control_rc) die("unfrozen matched control update");
    errno = 0; int target_rc = update(target, key, value); int target_errno = errno;
    require_match(control_rc, target_rc, target_errno, name);
    close(control); free(value); free(key);
}
static void fd_array(const char *name, int target, const struct bpf_map_info *info,
                     const char *cgroup_path) {
    uint32_t key = 0, object_id = 0;
    int object_fd;
    if (!strcmp(name, "CGROUP_FILTER")) {
        object_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (object_fd < 0) die("open cgroup");
    } else {
        if (lookup(target, &key, &object_id)) die("lookup TAIL_CALLS program id");
        object_fd = fd_by_id(BPF_PROG_GET_FD_BY_ID, object_id);
    }
    int control = map_create(info);
    if (update(control, &key, &object_fd)) die("populate unfrozen fd-array control");
    int control_rc = remove_key(control, &key);
    if (control_rc) die("unfrozen matched control delete");
    errno = 0; int target_rc = remove_key(target, &key); int target_errno = errno;
    require_match(control_rc, target_rc, target_errno, name);
    close(control); close(object_fd);
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--self-test")) {
        if (!matched_result(0, -1, EPERM) || matched_result(-1, -1, EPERM)
            || matched_result(0, -1, EINVAL) || matched_result(0, 0, 0)) return 1;
        puts("freeze matched-result self-test: OK"); return 0;
    }
    if (argc != 11) { fprintf(stderr, "usage: %s PID CGROUP NAME=ID...\n", argv[0]); return 2; }
    uint32_t workload_pid = (uint32_t)strtoul(argv[1], NULL, 10);
    for (int i = 3; i < argc; i++) {
        char *eq = strchr(argv[i], '='); if (!eq) return 2; *eq = '\0';
        uint32_t id = (uint32_t)strtoul(eq + 1, NULL, 10);
        int target = fd_by_id(BPF_MAP_GET_FD_BY_ID, id);
        struct bpf_map_info info = info_for(target);
        if (info.id != id || strncmp((char *)info.name, argv[i], BPF_OBJ_NAME_LEN)) {
            fprintf(stderr, "%s=%u exact map identity mismatch: id=%u name=%s\n",
                    argv[i], id, info.id, info.name); return 1;
        }
        if (!strcmp(argv[i], "CGROUP_FILTER") || !strcmp(argv[i], "TAIL_CALLS"))
            fd_array(argv[i], target, &info, argv[2]);
        else ordinary(argv[i], target, &info, workload_pid);
        printf("%s id=%u: unfrozen matched control succeeded; frozen mutation EPERM\n", argv[i], id);
        close(target);
    }
    return 0;
}
EOF
}

# Gap 1 and gap 2 own inline oracles beyond the shared checker, and the
# policy-map lane owns two more. Each lives in exactly one place and accepts
# `--self-test`, which runs the same assertions over synthetic evidence and
# requires every claimed field to refuse a mutation, unprivileged.
assert_gap1() {
    python3 -I scripts/lane-induced-gaps-oracle-1.py "$@"
}

assert_gap2() {
    python3 -I scripts/lane-induced-gaps-oracle-2.py "$@"
}

policy_map_ids() {
    # `--self-test` runs unprivileged; the real lane reads a root-owned dump.
    case ${1-} in
        --self-test) pmi_python=python3 ;;
        *) pmi_python="sudo python3" ;;
    esac
    $pmi_python -I scripts/lane-induced-gaps-oracle-3.py "$@"
}

assert_dynamic_maps_advanced() {
    # `--self-test` runs unprivileged; the real lane reads root-owned dumps.
    case ${1-} in
        --self-test) adma_python=python3 ;;
        *) adma_python="sudo python3" ;;
    esac
    $adma_python -I scripts/lane-induced-gaps-oracle-4.py "$1" "$2"
}

receipt_prepare_root() {
    t4_candidate=$1
    case $t4_candidate in /*) ;; *) return 1 ;; esac
    case $t4_candidate in *'/../'*|*/..|*"\t"*|*"\n"*) return 1 ;; esac
    t4_parent=${t4_candidate%/*}; t4_leaf=${t4_candidate##*/}
    [ -n "$t4_parent" ] && [ -n "$t4_leaf" ] && [ -d "$t4_parent" ] || return 1
    t4_ancestor=$t4_parent
    while [ "$t4_ancestor" != / ]; do
        [ ! -L "$t4_ancestor" ] || return 1
        t4_ancestor=${t4_ancestor%/*}; [ -n "$t4_ancestor" ] || t4_ancestor=/
    done
    t4_parent=$(cd "$t4_parent" && pwd -P) || return 1
    [ "$t4_candidate" = "$t4_parent/$t4_leaf" ] || return 1
    case $t4_candidate in "$(pwd -P)"|"$(pwd -P)"/*) return 1 ;; esac
    [ "$(stat -Lc %u:%a "$t4_parent")" = "$(id -u):700" ] || return 1
    [ ! -e "$t4_candidate" ] && [ ! -L "$t4_candidate" ] || return 1
    umask 077; mkdir -m 700 "$t4_candidate" || return 1
    RECEIPT_ROOT=$t4_candidate; RECEIPT_CAMPAIGN=$t4_parent
    RECEIPT_ROOT_ID=$(stat -Lc %d:%i "$RECEIPT_ROOT") || return 1
}

receipt_digest() { sha256sum "$1" | awk '{print $1}'; }
receipt_snapshot() {
    [ "$#" -eq 1 ] || return 2
    case $1 in initial|final) ;; *) return 2 ;; esac
    p11scope_prepared_snapshot "$P11SCOPE_PREPARED_PYTHON" \
        "$RECEIPT_ROOT/artifacts/induced.source.$1" \
        "$RECEIPT_PREPARED_PREFIX.$1.ledger.sha256"
}
receipt_fact() { printf '%s\t%s\n' "$1" "$2" >> "$RECEIPT_FACTS"; }

receipt_finalize() {
    t4_result=$?
    trap - EXIT INT TERM HUP
    set +e
    [ "$(stat -Lc %d:%i "$RECEIPT_ROOT" 2>/dev/null)" = "$RECEIPT_ROOT_ID" ] || t4_result=1
    [ "$(stat -Lc %d:%i "$RECEIPT_ROOT/artifacts" 2>/dev/null)" = "$RECEIPT_ARTIFACTS_ID" ] || t4_result=1
    [ "$(stat -Lc %d:%i "$RECEIPT_ROOT/work" 2>/dev/null)" = "$RECEIPT_WORK_ID" ] || t4_result=1
    if [ "$t4_result" -ne 77 ]; then
        [ "$(git rev-parse HEAD 2>/dev/null)" = "$RECEIPT_HEAD" ] || t4_result=1
        [ "$(git rev-parse 'HEAD^{tree}' 2>/dev/null)" = "$RECEIPT_TREE" ] || t4_result=1
        git diff --quiet && git diff --cached --quiet || t4_result=1
        [ "$(receipt_digest scripts/verify-induced-gaps.sh 2>/dev/null)" = "$RECEIPT_DRIVER_HASH" ] || t4_result=1
        [ "$(receipt_digest scripts/check-capture-evidence.py 2>/dev/null)" = "$RECEIPT_CHECKER_HASH" ] || t4_result=1
        if [ "${RECEIPT_PREPARED_ADMITTED-0}" -eq 1 ]; then
            if "$P11SCOPE_PREPARED_PYTHON" -I scripts/prepared-dependency-evidence.py \
                recheck --prefix "$RECEIPT_PREPARED_PREFIX"; then
                receipt_snapshot final > "$RECEIPT_ROOT/artifacts/source.end.tsv" || t4_result=1
                cmp -s "$RECEIPT_ROOT/artifacts/source.start.tsv" \
                    "$RECEIPT_ROOT/artifacts/source.end.tsv" || t4_result=1
            else
                t4_result=1
            fi
        else
            t4_result=1
        fi
        [ -s "$RECEIPT_ROOT/artifacts/capture.json" ] || t4_result=1
        [ -s "$RECEIPT_ROOT/artifacts/checker.log" ] || t4_result=1
    fi
    find "$RECEIPT_ROOT" -type d -exec chmod 700 {} + 2>/dev/null || t4_result=1
    find "$RECEIPT_ROOT" -type f -exec chmod 600 {} + 2>/dev/null || t4_result=1
    python3 -I scripts/lane-induced-gaps-oracle-5.py "$RECEIPT_ROOT" || t4_result=1
    receipt_fact ended_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" || t4_result=1
    receipt_fact terminal_status "$t4_result" || t4_result=1
    sync -f "$RECEIPT_FACTS" "$RECEIPT_ROOT/stdout.log" "$RECEIPT_ROOT/stderr.log" 2>/dev/null || t4_result=1
    if [ ! -e "$RECEIPT_ROOT/status" ] && [ ! -L "$RECEIPT_ROOT/status" ]; then
        printf '%s\n' "$t4_result" > "$RECEIPT_ROOT/status"; chmod 600 "$RECEIPT_ROOT/status"; sync -f "$RECEIPT_ROOT/status" 2>/dev/null || t4_result=1
    else
        t4_result=1
    fi
    exit "$t4_result"
}

receipt_receipt_run() {
    [ "$#" -eq 1 ] || { echo "usage: $0 --self-test | ABSENT_EVIDENCE_ROOT" >&2; exit 2; }
    receipt_prepare_root "$1" || { echo "invalid Task 4 evidence root" >&2; exit 77; }
    RECEIPT_FACTS=$RECEIPT_ROOT/facts.log
    : > "$RECEIPT_FACTS"; : > "$RECEIPT_ROOT/stdout.log"; : > "$RECEIPT_ROOT/stderr.log"
    chmod 600 "$RECEIPT_FACTS" "$RECEIPT_ROOT/stdout.log" "$RECEIPT_ROOT/stderr.log"
    mkdir -m 700 "$RECEIPT_ROOT/artifacts" "$RECEIPT_ROOT/work"
    RECEIPT_ARTIFACTS_ID=$(stat -Lc %d:%i "$RECEIPT_ROOT/artifacts")
    RECEIPT_WORK_ID=$(stat -Lc %d:%i "$RECEIPT_ROOT/work")
    RECEIPT_HEAD= RECEIPT_TREE= RECEIPT_DRIVER_HASH= RECEIPT_CHECKER_HASH=
    RECEIPT_PREPARED_ADMITTED=0
    RECEIPT_PREPARED_PREFIX=$RECEIPT_ROOT/artifacts/induced.prepared
    trap receipt_finalize EXIT INT TERM HUP
    [ ! -L "$RECEIPT_CAMPAIGN/.receipt.lock" ] || exit 77
    exec 9>>"$RECEIPT_CAMPAIGN/.receipt.lock"; chmod 600 "$RECEIPT_CAMPAIGN/.receipt.lock"
    [ "$(stat -Lc %d:%i:%u:%a:%h /proc/$$/fd/9)" = "$(stat -Lc %d:%i:%u:%a:%h "$RECEIPT_CAMPAIGN/.receipt.lock")" ] || exit 77
    [ "$(stat -Lc %u:%a:%h /proc/$$/fd/9)" = "$(id -u):600:1" ] || exit 77
    flock -n 9 || exit 77
    RECEIPT_LOCK_ID=$(stat -Lc %d:%i "$RECEIPT_CAMPAIGN/.receipt.lock")
    RECEIPT_HEAD=$(git rev-parse HEAD) || exit 77; RECEIPT_TREE=$(git rev-parse 'HEAD^{tree}') || exit 77
    git diff --quiet && git diff --cached --quiet || exit 77
    RECEIPT_DRIVER_HASH=$(receipt_digest scripts/verify-induced-gaps.sh); RECEIPT_CHECKER_HASH=$(receipt_digest scripts/check-capture-evidence.py)
    receipt_fact started_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; receipt_fact argv "$0 $1"; receipt_fact cwd "$(pwd -P)"
    receipt_fact uid_gid "$(id -u):$(id -g)"; receipt_fact kernel "$(uname -srmo)"; receipt_fact head "$RECEIPT_HEAD"; receipt_fact tree "$RECEIPT_TREE"
    receipt_fact root_identity "$RECEIPT_ROOT_ID"; receipt_fact artifacts_identity "$RECEIPT_ARTIFACTS_ID"; receipt_fact work_identity "$RECEIPT_WORK_ID"
    receipt_fact lock_identity "$RECEIPT_LOCK_ID"; receipt_fact lock_holder "$$:$(process_starttime $$)"
    receipt_fact driver_sha256 "$RECEIPT_DRIVER_HASH"; receipt_fact checker_sha256 "$RECEIPT_CHECKER_HASH"
    for tool in gcc python3 rustup bpftool systemd-run sudo sha256sum git sort xargs; do command -v "$tool" >/dev/null || exit 77; done
    . scripts/prepared-dependency-tools.sh
    . scripts/prepared-dependency-snapshot.sh
    p11scope_prepared_tools_select "$(command -v python3)" "$(command -v rustup)" || exit 77
    "$P11SCOPE_PREPARED_PYTHON" -I scripts/prepared-dependency-evidence.py capture \
        --prefix "$RECEIPT_PREPARED_PREFIX" \
        --stable-cargo "$P11SCOPE_PREPARED_STABLE_CARGO" \
        --stable-rustc "$P11SCOPE_PREPARED_STABLE_RUSTC" \
        --bpf-cargo "$P11SCOPE_PREPARED_BPF_CARGO" \
        --bpf-rustc "$P11SCOPE_PREPARED_BPF_RUSTC" || exit 77
    RECEIPT_PREPARED_ADMITTED=1
    receipt_snapshot initial > "$RECEIPT_ROOT/artifacts/source.start.tsv" || exit 77
    RECEIPT_SOURCE_HASH=$(receipt_digest "$RECEIPT_ROOT/artifacts/source.start.tsv")
    receipt_fact source_input_ledger_sha256 "$RECEIPT_SOURCE_HASH"
    sudo -n true >/dev/null 2>&1 || exit 77
    [ -f "$MODULE" ] || exit 77
    P11SCOPE_RECEIPT_BODY=1 P11SCOPE_RECEIPT_WORK="$RECEIPT_ROOT/work" \
        P11SCOPE_PREPARED_STABLE_CARGO="$P11SCOPE_PREPARED_STABLE_CARGO" \
        P11SCOPE_PREPARED_STABLE_RUSTC="$P11SCOPE_PREPARED_STABLE_RUSTC" \
        P11SCOPE_PREPARED_BPF_CARGO="$P11SCOPE_PREPARED_BPF_CARGO" \
        P11SCOPE_PREPARED_BPF_RUSTC="$P11SCOPE_PREPARED_BPF_RUSTC" \
        /bin/sh "$0" > "$RECEIPT_ROOT/stdout.log" 2> "$RECEIPT_ROOT/stderr.log"
    t4_capture=$(find "$RECEIPT_ROOT/work" -type f -name '*observed*.json' -print | sort | head -n 1)
    [ -n "$t4_capture" ] || exit 1
    cp "$t4_capture" "$RECEIPT_ROOT/artifacts/capture.json"
    cp "$RECEIPT_ROOT/stdout.log" "$RECEIPT_ROOT/artifacts/checker.log"
}

if [ "${1-}" = "--self-test" ]; then
    [ "$#" -eq 1 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }
    # Unprivileged: the delegated validators' own mutation suites, this
    # script's four inline oracles, and the C freeze harness's matched-result
    # control. No BPF, no sudo, no workload, no build of the observer.
    command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
    python3 scripts/check-bpf-map-defs.py --self-test
    python3 scripts/check-capture-evidence.py --self-test
    assert_gap1 --self-test
    assert_gap2 --self-test
    SELF_TEST_WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-induced-selftest-XXXXXX")
    trap 'rm -rf "$SELF_TEST_WORK"' EXIT INT TERM
    policy_map_ids --self-test "$SELF_TEST_WORK"
    assert_dynamic_maps_advanced --self-test "$SELF_TEST_WORK"
    write_freeze_policy_maps_source "$SELF_TEST_WORK/freeze-policy-maps.c"
    gcc -std=c11 -O2 -Wall -Wextra -Werror -o "$SELF_TEST_WORK/freeze-policy-maps" \
        "$SELF_TEST_WORK/freeze-policy-maps.c"
    "$SELF_TEST_WORK/freeze-policy-maps" --self-test
    REPORT=${P11SCOPE_RECEIPT_SELF_TEST_REPORT:-$SELF_TEST_WORK/report.tsv}
    python3 -I scripts/lane-induced-gaps-oracle-6.py "$REPORT"
    echo "verify-induced-gaps Task 4 receipt self-test: OK"
    exit 0
fi
if [ -z "${P11SCOPE_RECEIPT_BODY-}" ]; then
    receipt_receipt_run "$@"
    exit 0
fi
[ "$#" -eq 0 ] || exit 2
[ -n "${P11SCOPE_PREPARED_STABLE_CARGO-}" ] \
    && [ -n "${P11SCOPE_PREPARED_STABLE_RUSTC-}" ] \
    && [ -n "${P11SCOPE_PREPARED_BPF_CARGO-}" ] \
    && [ -n "${P11SCOPE_PREPARED_BPF_RUSTC-}" ] \
    || { echo "prepared stable/BPF Cargo/rustc handoff required" >&2; exit 1; }
require_non_root_caller
mkdir -p "$WORK"

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v clang-18 >/dev/null || { echo "clang-18 required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
command -v llvm-objcopy >/dev/null || { echo "llvm-objcopy required"; exit 1; }
command -v llvm-readelf >/dev/null || { echo "llvm-readelf required"; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
command -v systemd-run >/dev/null || { echo "systemd-run required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }

rm -rf "$WORK/task-storage-reader"
scripts/build-task-storage-reader.sh "$WORK_ABS/task-storage-reader"
TASK_STORAGE_READER=$WORK_ABS/task-storage-reader/dump-task-storage
TASK_STORAGE_OBJECT=$WORK_ABS/task-storage-reader/dump-task-storage.bpf.o
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }

WPID=
WORKLOAD_STARTTIME=
WORKLOAD_LAUNCHER_PID=
WORKLOAD_UNIT=
SPID=
OBSERVER_PID=
OBSERVER_STARTTIME=
cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    if [ -n "$OBSERVER_PID" ] && [ -n "$OBSERVER_STARTTIME" ]; then
        signal_verified_root_process TERM "$OBSERVER_PID" "$OBSERVER_STARTTIME" \
            2>/dev/null || true
    elif [ -n "$SPID" ]; then
        kill -TERM "$SPID" 2>/dev/null || true
    fi
    if [ -n "$WPID" ] && [ -n "$WORKLOAD_STARTTIME" ]; then
        signal_verified_process KILL "$WPID" "$WORKLOAD_STARTTIME" 2>/dev/null || true
    elif [ -n "$WPID" ]; then
        kill -TERM "$WPID" 2>/dev/null || true
    fi
    [ -z "$WORKLOAD_LAUNCHER_PID" ] \
        || kill -CONT "$WORKLOAD_LAUNCHER_PID" 2>/dev/null || true
    # Release the workload BEFORE waiting on its launcher. Until the barrier is
    # written the workload blocks in `read`, so the launcher cannot exit and a
    # wait here never returns. An early exit before the barrier is written -- any
    # failure between launching the workload and releasing it -- then hangs the
    # lane instead of reporting why it failed. Stopping the scope is the
    # authority; removing the fifo only stops a later reader from blocking.
    [ -z "$WORKLOAD_UNIT" ] || sudo systemctl stop "${WORKLOAD_UNIT}.scope" >/dev/null 2>&1 || true
    rm -f "$WORK/freeze-barrier"
    [ -z "$WORKLOAD_LAUNCHER_PID" ] || wait "$WORKLOAD_LAUNCHER_PID" 2>/dev/null || true
    [ -n "$WORKLOAD_LAUNCHER_PID" ] || [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

echo "=== build isolated default + induced-gap variants ==="
rm -rf "$WORK/default-build" "$WORK/ring-build" "$WORK/state-build" "$WORK/freeze-build"
RUSTC="$P11SCOPE_PREPARED_STABLE_RUSTC" \
    P11SCOPE_PREPARED_BPF_CARGO="$P11SCOPE_PREPARED_BPF_CARGO" \
    P11SCOPE_PREPARED_BPF_RUSTC="$P11SCOPE_PREPARED_BPF_RUSTC" \
    "$P11SCOPE_PREPARED_STABLE_CARGO" build --locked --offline --release --workspace \
    --target-dir "$WORK/default-build"
DISCOVER="$WORK/default-build/release/p11scope-discover"

echo "=== build small-ring p11scope (Gap 3 only; default build untouched) ==="
# RING_BYTES override mechanism: crates/ebpf-common's `small-ring` Cargo
# feature (off by default) shrinks RING_BYTES 4MiB -> 4KiB; build.rs
# forwards it to the eBPF crate's build only when P11SCOPE_SMALL_RING is
# set. A separate --target-dir keeps this build fully out of target/release
# so scripts/verify-attach-e2e.sh's binary is never touched by this script.
P11SCOPE_SMALL_RING=1 RUSTC="$P11SCOPE_PREPARED_STABLE_RUSTC" \
    P11SCOPE_PREPARED_BPF_CARGO="$P11SCOPE_PREPARED_BPF_CARGO" \
    P11SCOPE_PREPARED_BPF_RUSTC="$P11SCOPE_PREPARED_BPF_RUSTC" \
    "$P11SCOPE_PREPARED_STABLE_CARGO" build --locked --offline --release --workspace \
    --target-dir "$WORK/ring-build"
echo "=== build small-state-map p11scope (Gaps 4/5 only) ==="
P11SCOPE_SMALL_STATE_MAPS=1 RUSTC="$P11SCOPE_PREPARED_STABLE_RUSTC" \
    P11SCOPE_PREPARED_BPF_CARGO="$P11SCOPE_PREPARED_BPF_CARGO" \
    P11SCOPE_PREPARED_BPF_RUSTC="$P11SCOPE_PREPARED_BPF_RUSTC" \
    "$P11SCOPE_PREPARED_STABLE_CARGO" build --locked --offline --release --workspace \
    --target-dir "$WORK/state-build"
RUSTC="$P11SCOPE_PREPARED_STABLE_RUSTC" \
    P11SCOPE_PREPARED_BPF_CARGO="$P11SCOPE_PREPARED_BPF_CARGO" \
    P11SCOPE_PREPARED_BPF_RUSTC="$P11SCOPE_PREPARED_BPF_RUSTC" \
    "$P11SCOPE_PREPARED_STABLE_CARGO" build --locked --offline --release --workspace \
    --features unsafe-unvalidated-metadata \
    --target-dir "$WORK/freeze-build"
P11SCOPE="$WORK/default-build/release/p11scope"
P11SCOPE_SMALLRING="$WORK/ring-build/release/p11scope"
P11SCOPE_SMALLSTATE="$WORK/state-build/release/p11scope"
P11SCOPE_FREEZE="$WORK/freeze-build/release/p11scope"

python3 scripts/check-bpf-map-defs.py --self-test
set -- "$WORK"/default-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "default BPF object is not unique"; exit 1; }
DEFAULT_BPF=$1
set -- "$WORK"/ring-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "small-ring BPF object is not unique"; exit 1; }
RING_BPF=$1
set -- "$WORK"/state-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "small-state BPF object is not unique"; exit 1; }
STATE_BPF=$1
set -- "$WORK"/freeze-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "feature BPF object is not unique"; exit 1; }
FREEZE_BPF=$1
python3 scripts/check-bpf-map-defs.py "$DEFAULT_BPF" EVENTS=4194304 START=16384 RV_COUNTS=4096
python3 scripts/check-bpf-map-defs.py "$RING_BPF" EVENTS=4096 START=16384 RV_COUNTS=4096
python3 scripts/check-bpf-map-defs.py "$STATE_BPF" EVENTS=4194304 START=1 RV_COUNTS=1
python3 scripts/check-bpf-map-defs.py --policy-inventory "$DEFAULT_BPF" "$FREEZE_BPF"

pin_workload() {
    WORKLOAD_STARTTIME=$(process_starttime "$WPID") || {
        echo "workload $WPID identity unavailable" >&2
        return 1
    }
}

# The workload publishes READY and then waits for the GO gate, and it REFUSES
# to start if GO already exists (canary_workload.c, "GO already exists"). So GO
# must be created only after the workload is up, never before it is released.
wait_for_workload_ready() {
    wfwr_attempt=0
    while [ "$wfwr_attempt" -lt 400 ]; do
        [ -f "$WORK/freeze-ready" ] && return 0
        process_matches_starttime "$WPID" "$WORKLOAD_STARTTIME" || {
            echo "workload $WPID exited before publishing READY" >&2
            return 1
        }
        wfwr_attempt=$((wfwr_attempt + 1))
        sleep 0.05
    done
    echo "workload $WPID never published READY" >&2
    return 1
}

wait_for_workload_stopped() {
    wfws_attempt=0
    while [ "$wfws_attempt" -lt 400 ]; do
        process_matches_starttime "$WPID" "$WORKLOAD_STARTTIME" || {
            echo "workload $WPID exited or changed identity" >&2
            return 1
        }
        wfws_state=$(awk '$1 == "State:" { print $2; exit }' \
            "/proc/$WPID/status" 2>/dev/null || true)
        [ "$wfws_state" = T ] && return 0
        wfws_attempt=$((wfws_attempt + 1))
        sleep 0.05
    done
    echo "workload $WPID did not stop after completing its calls" >&2
    return 1
}

resume_and_wait_workload() {
    raww_label=$1
    signal_verified_process CONT "$WPID" "$WORKLOAD_STARTTIME"
    # systemd-run mirrors a stopped scope command's job-control state. Resume
    # the script-owned launcher too so it can reap the continued workload.
    [ -z "$WORKLOAD_LAUNCHER_PID" ] \
        || kill -CONT "$WORKLOAD_LAUNCHER_PID" 2>/dev/null || true
    raww_wait_pid=${WORKLOAD_LAUNCHER_PID:-$WPID}
    if wait "$raww_wait_pid"; then
        raww_status=0
        WPID=
        WORKLOAD_STARTTIME=
        WORKLOAD_LAUNCHER_PID=
        WORKLOAD_UNIT=
    else
        raww_status=$?
        WPID=
        WORKLOAD_STARTTIME=
        WORKLOAD_LAUNCHER_PID=
        WORKLOAD_UNIT=
    fi
    [ "$raww_status" -eq 0 ] || {
        echo "$raww_label workload failed: $raww_status" >&2
        return "$raww_status"
    }
}

# Approval-gated live policy-map mutation. The C UAPI harness derives each
# map's definition through BPF_OBJ_GET_INFO_BY_FD, creates an equivalent
# unfrozen matched control, requires its operation to succeed, then requires
# that exact operation against the observer map to fail with numeric EPERM.
# It never freezes the maps itself, so the test cannot prove a tautology.
freeze_policy_maps() {
    workload_pid=$1
    cgroup_path=$2
    manifest=$3
    policy_map_ids "$manifest" "$WORK/freeze-policy-map-ids"
    set -- $(sudo cat "$WORK/freeze-policy-map-ids")
    sudo "$WORK/freeze-policy-maps" "$workload_pid" "$cgroup_path" \
        "$@"
    # Written root-owned under sudo; the unprivileged receipt finalizer must be
    # able to chmod every retained file, so hand it back to the caller.
    reclaim_root_output "$WORK/freeze-policy-map-ids"
}

write_freeze_policy_maps_source "$WORK/freeze-policy-maps.c"
gcc -std=c11 -O2 -Wall -Wextra -Werror -o "$WORK/freeze-policy-maps" \
    "$WORK/freeze-policy-maps.c"

# The ordinary Rust suite owns mechanism-union refusal without loading BPF.
# cargo test: approval_capacity_refuses_the_whole_oversized_union

##############################################################################
echo "=== policy-map immutability control with live dynamic maps ==="
##############################################################################
gcc -shared -fPIC -Wall -Wextra -DPRIVACY_FIXTURE=1 \
    -o "$WORK/freeze-provider.so" crates/discover/tests/fixture/version_matrix.c
gcc -std=c11 -O0 -Wall -Wextra -o "$WORK/freeze-workload" \
    scripts/fixtures/canary_workload.c -ldl -pthread
"$WORK/freeze-build/release/p11scope-discover" \
    --module "$WORK_ABS/freeze-provider.so" -o "$WORK/freeze-manifest.json"

rm -f "$WORK/freeze-ready" "$WORK/freeze-go" "$WORK/freeze-observed.json" \
    "$WORK/freeze-profile.log" "$WORK/freeze-workload.log" \
    "$WORK/freeze-workload.pid" "$WORK/freeze-barrier" \
    "$WORK"/mapdump_*_freeze-before.json "$WORK"/mapdump_*_freeze-after.json \
    "$WORK"/mapdump_*_freeze-before.bin "$WORK"/mapdump_*_freeze-after.bin \
    "$WORK/mapdump_manifest_freeze-before.json" "$WORK/mapdump_manifest_freeze-after.json"
mkfifo "$WORK/freeze-barrier"
WORKLOAD_UNIT="p11scope-freeze-$$"
CGROUP_PATH="/sys/fs/cgroup/system.slice/${WORKLOAD_UNIT}.scope"
SYSTEMD_RUN_NO_EXPAND=
systemd-run --help 2>&1 | grep -q -- '--expand-environment=' \
    && SYSTEMD_RUN_NO_EXPAND=--expand-environment=no
( sudo systemd-run $SYSTEMD_RUN_NO_EXPAND --scope --unit="$WORKLOAD_UNIT" \
    --uid="$(id -u)" --gid="$(id -g)" -- sh -c \
    "umask 077; \
     starttime=\$(awk '{ sub(/^[0-9]+ \\(.*\\) /, \"\"); split(\$0, tail, \" \"); print tail[20]; exit }' /proc/\$\$/stat) || exit 1; \
     printf '%s %s\\n' \"\$\$\" \"\$starttime\" > '$WORK_ABS/freeze-workload.pid'; \
     read -r _ < '$WORK_ABS/freeze-barrier'; \
     exec '$WORK_ABS/freeze-workload' '$WORK_ABS/freeze-provider.so' matrix \
         '$WORK_ABS/freeze-ready' '$WORK_ABS/freeze-go'" ) \
    > "$WORK/freeze-workload.log" 2>&1 &
WORKLOAD_LAUNCHER_PID=$!
# The launcher generation is pinned the moment it is forked: the reader below
# refuses a pid whose start time no longer matches, so a launcher that dies and
# has its pid reused cannot be mistaken for one still recording.
WORKLOAD_LAUNCHER_STARTTIME=$(process_starttime "$WORKLOAD_LAUNCHER_PID") \
    || { echo "freeze workload launcher start time was not readable"; exit 1; }
# The freeze workload runs as the INVOKING USER inside a root-created scope
# (--uid/--gid above), so its record is user-owned and must be read as that
# user. The observer below is a genuinely root-recorded process and keeps the
# root reader.
workload_record=$(wait_user_process_record \
    "$WORK/freeze-workload.pid" "$WORKLOAD_LAUNCHER_PID" \
    "$WORKLOAD_LAUNCHER_STARTTIME")
set -- $workload_record
[ "$#" -eq 2 ] || { echo "freeze workload identity was not recorded"; exit 1; }
WPID=$1
WORKLOAD_STARTTIME=$2
[ -d "$CGROUP_PATH" ] || { echo "workload cgroup path missing: $CGROUP_PATH"; exit 1; }

launch_root_recorded_process "$WORK/freeze-observer.pid" "$WORK/freeze-profile.log" \
    "$P11SCOPE_FREEZE" profile --manifest "$WORK/freeze-manifest.json" \
    --cgroup "$CGROUP_PATH" \
    --mode profile --unsafe-unvalidated-metadata --duration 20 \
    -o "$WORK/freeze-observed.json"
SPID=$ROOT_LAUNCH_PID
OBSERVER_PID=$ROOT_PROCESS_PID
OBSERVER_STARTTIME=$ROOT_PROCESS_STARTTIME
wait_for_capture_ready "$WORK/freeze-profile.log" unsafe-unvalidated-metadata profile
root_process_matches_starttime "$OBSERVER_PID" "$OBSERVER_STARTTIME" || exit 1
sudo python3 -I scripts/dump-owned-bpf-maps.py \
    "$OBSERVER_PID" "$WORK" freeze-before 0 16384 \
    "$TASK_STORAGE_READER" "$TASK_STORAGE_OBJECT"
freeze_policy_maps "$WPID" "$CGROUP_PATH" \
    "$WORK/mapdump_manifest_freeze-before.json"
printf '\n' > "$WORK/freeze-barrier"
wait_for_workload_ready
touch "$WORK/freeze-go"
wait_for_workload_stopped
sudo python3 -I scripts/dump-owned-bpf-maps.py \
    "$OBSERVER_PID" "$WORK" freeze-after 0 16384 \
    "$TASK_STORAGE_READER" "$TASK_STORAGE_OBJECT"
assert_dynamic_maps_advanced "$WORK/mapdump_manifest_freeze-before.json" \
    "$WORK/mapdump_manifest_freeze-after.json"
signal_verified_root_process INT "$OBSERVER_PID" "$OBSERVER_STARTTIME"
if wait "$SPID"; then SPID=; OBSERVER_PID=; OBSERVER_STARTTIME=; else status=$?; SPID=; OBSERVER_PID=; OBSERVER_STARTTIME=; echo "freeze observer failed: $status"; exit "$status"; fi
resume_and_wait_workload freeze
reclaim_root_output "$WORK/freeze-observed.json" "$WORK/freeze-observer.pid"
test -s "$WORK/freeze-observed.json" || { echo "freeze observer produced no output"; exit 1; }
python3 scripts/check-capture-evidence.py canary feature-unsafe-profile \
    "$WORK/freeze-observed.json"
# 30, not the 27 frozen on 2026-08-14: the shared workload gained exactly three
# C_GetInterface calls since then (`get_interface(` appears 0 times at 7774bf6
# and 3 times now), and the capture reports C_GetInterface 3. The delta is
# accounted for call-for-call rather than fitted to whatever the lane emitted --
# this lane could not run between those dates, so the count was never revalidated.
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); n=sum(f["calls"] for f in d["functions"]); assert n == 30, n' \
    "$WORK/freeze-observed.json"
echo "freeze target identity remained live through exact terminal evidence: OK"

echo "=== private softhsm token (gap 3) ==="
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
rm -rf "$WORK/tokens"
mkdir -p "$WORK/tokens"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WORK_ABS/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
softhsm2-util --init-token --free --label induced-gaps --so-pin 1234 --pin 1234 >/dev/null

##############################################################################
echo "=== gap 1/5: aliasing ==="
##############################################################################
# helper.so's SONAME (baked into provider.so's DT_NEEDED) is "helper.so",
# so the file itself must keep that exact name for the rpath lookup below
# to find it — matching crates/discover/tests/fixture_provider.rs.
mkdir -p "$WORK/g1"
gcc -shared -fPIC -Wl,-soname,helper.so -o "$WORK/g1/helper.so" \
    crates/discover/tests/fixture/helper.c
gcc -shared -fPIC -o "$WORK/g1/provider.so" \
    crates/discover/tests/fixture/provider.c "$WORK/g1/helper.so" \
    -Wl,-rpath,"$WORK_ABS/g1"
gcc -O0 -o "$WORK/g1_workload" "$FIX/alias_workload.c"

"$DISCOVER" --module "$WORK_ABS/g1/provider.so" -o "$WORK/g1_manifest.json"

rm -f "$WORK/g1_go" "$WORK/g1_observed.json" "$WORK/g1_profile.log"
( while [ ! -f "$WORK/g1_go" ]; do sleep 0.05; done
  export P11SCOPE_HOLD=1
  exec "$WORK/g1_workload" "$WORK_ABS/g1/provider.so" 25 17 ) &
WPID=$!
pin_workload
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" profile \
    --manifest "$WORK/g1_manifest.json" --pid "$WPID" \
    --mode profile --duration 8 -o "$WORK/g1_observed.json" \
    > "$WORK/g1_profile.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/g1_profile.log" allowlisted profile
touch "$WORK/g1_go"
wait_for_workload_stopped
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "alias profiler failed: $status"; exit "$status"; fi
resume_and_wait_workload alias
reclaim_root_output "$WORK/g1_observed.json"
tail -n 5 "$WORK/g1_profile.log"
python3 scripts/check-capture-evidence.py induced G1 "$WORK/g1_observed.json"

assert_gap1 "$WORK/g1_observed.json"

##############################################################################
echo "=== gap 2/5: in-flight at end ==="
##############################################################################
gcc -shared -fPIC -o "$WORK/g2_provider.so" "$FIX/blocking_provider.c"
gcc -O0 -o "$WORK/g2_workload" "$FIX/blocking_workload.c" -ldl

"$DISCOVER" --module "$WORK_ABS/g2_provider.so" -o "$WORK/g2_manifest.json"

rm -f "$WORK/g2_go" "$WORK/g2_observed.json" "$WORK/g2_profile.log"
( while [ ! -f "$WORK/g2_go" ]; do sleep 0.05; done
  exec "$WORK/g2_workload" "$WORK_ABS/g2_provider.so" ) &
WPID=$!
pin_workload
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" profile \
    --manifest "$WORK/g2_manifest.json" --pid "$WPID" \
    --mode profile --duration 6 -o "$WORK/g2_observed.json" \
    > "$WORK/g2_profile.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/g2_profile.log" allowlisted profile
touch "$WORK/g2_go"
# The workload blocks for ~60s in the probed call; only the profiler exits
# on its own (--duration). Don't `wait` on the still-blocked workload.
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "in-flight profiler failed: $status"; exit "$status"; fi
reclaim_root_output "$WORK/g2_observed.json"
tail -n 5 "$WORK/g2_profile.log"
signal_verified_process KILL "$WPID" "$WORKLOAD_STARTTIME" 2>/dev/null || true
wait "$WPID" 2>/dev/null || true
WPID=
WORKLOAD_STARTTIME=
python3 scripts/check-capture-evidence.py induced G2 "$WORK/g2_observed.json"

assert_gap2 "$WORK/g2_observed.json"

##############################################################################
echo "=== gap 3/5: event loss (tiny ring buffer, high call rate) ==="
##############################################################################
gcc -O0 -o "$WORK/g3_hammer" "$FIX/hammer.c" -ldl
"$DISCOVER" --module "$MODULE" -o "$WORK/g3_manifest.json"

N_CALLS=200000
rm -f "$WORK/g3_go" "$WORK/g3_observed.json" "$WORK/g3_profile.log"
( while [ ! -f "$WORK/g3_go" ]; do sleep 0.05; done
  export P11SCOPE_HOLD=1
  exec "$WORK/g3_hammer" "$MODULE" "$N_CALLS" ) &
WPID=$!
pin_workload
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE_SMALLRING" profile \
    --manifest "$WORK/g3_manifest.json" --pid "$WPID" \
    --mode profile --duration 15 -o "$WORK/g3_observed.json" \
    > "$WORK/g3_profile.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/g3_profile.log" allowlisted profile
touch "$WORK/g3_go"
wait_for_workload_stopped
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "event-loss profiler failed: $status"; exit "$status"; fi
resume_and_wait_workload hammer
reclaim_root_output "$WORK/g3_observed.json"
tail -n 5 "$WORK/g3_profile.log"
python3 scripts/check-capture-evidence.py induced G3 "$WORK/g3_observed.json"
echo "gap 3 exact event-loss/count-authority evidence OK"

##############################################################################
echo "=== gap 3b/5: event loss via --ring-bytes (default build, flag-set ring) ==="
##############################################################################
# Way B: the default build with a load-time `--ring-bytes 4K` must produce the
# same event-loss evidence as Way A's small-ring build above: the flag is the
# supported equivalent of the baked-in RING_BYTES override. The capture
# discloses its effective tuning, which is asserted exactly here.
N_CALLS=200000
rm -f "$WORK/g3b_go" "$WORK/g3b_observed.json" "$WORK/g3b_profile.log"
( while [ ! -f "$WORK/g3b_go" ]; do sleep 0.05; done
  export P11SCOPE_HOLD=1
  exec "$WORK/g3_hammer" "$MODULE" "$N_CALLS" ) &
WPID=$!
pin_workload
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" profile \
    --manifest "$WORK/g3_manifest.json" --pid "$WPID" \
    --ring-bytes 4K --drain-interval-ms 1000 \
    --mode profile --duration 15 -o "$WORK/g3b_observed.json" \
    > "$WORK/g3b_profile.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/g3b_profile.log" allowlisted profile
touch "$WORK/g3b_go"
wait_for_workload_stopped
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "event-loss profiler failed: $status"; exit "$status"; fi
resume_and_wait_workload hammer
reclaim_root_output "$WORK/g3b_observed.json"
tail -n 5 "$WORK/g3b_profile.log"
python3 scripts/check-capture-evidence.py induced G3 "$WORK/g3b_observed.json"
python3 -I scripts/lane-induced-gaps-oracle-7.py "$WORK/g3b_observed.json"
echo "gap 3b flag-set ring event-loss/count-authority evidence OK"

##############################################################################
echo "=== gap 4/5: START insertion loss (one-entry map, live concurrency) ==="
##############################################################################
gcc -shared -fPIC -Wall -Wextra -DPRIVACY_FIXTURE=1 -DPRIVACY_BLOCKS=1 \
    -o "$WORK/g4_provider.so" crates/discover/tests/fixture/version_matrix.c
gcc -O0 -Wall -Wextra -pthread -o "$WORK/privacy_stack_workload" \
    "$FIX/privacy-stack-workload.c" -ldl
"$DISCOVER" --module "$WORK_ABS/g4_provider.so" -o "$WORK/g4_manifest.json"

rm -f "$WORK/g4_go" "$WORK/g4_observed.json" "$WORK/g4_profile.log"
( while [ ! -f "$WORK/g4_go" ]; do sleep 0.05; done
  exec "$WORK/privacy_stack_workload" "$WORK_ABS/g4_provider.so" ) \
    > "$WORK/g4_workload.log" 2>&1 &
WPID=$!
pin_workload
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE_SMALLSTATE" profile \
    --manifest "$WORK/g4_manifest.json" --pid "$WPID" \
    --mode profile --duration 7 -o "$WORK/g4_observed.json" \
    > "$WORK/g4_profile.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/g4_profile.log" allowlisted profile
touch "$WORK/g4_go"
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "START-loss profiler failed: $status"; exit "$status"; fi
reclaim_root_output "$WORK/g4_observed.json"
signal_verified_process TERM "$WPID" "$WORKLOAD_STARTTIME" 2>/dev/null || true
wait "$WPID" 2>/dev/null || true
WPID=
WORKLOAD_STARTTIME=
python3 scripts/check-capture-evidence.py induced G4 "$WORK/g4_observed.json"
echo "gap 4 exact evidence OK"

##############################################################################
echo "=== gap 5/5: RV update loss (one-entry map, distinct completed slots) ==="
##############################################################################
gcc -shared -fPIC -Wall -Wextra -DPRIVACY_FIXTURE=1 \
    -o "$WORK/g5_provider.so" crates/discover/tests/fixture/version_matrix.c
"$DISCOVER" --module "$WORK_ABS/g5_provider.so" -o "$WORK/g5_manifest.json"

rm -f "$WORK/g5_go" "$WORK/g5_observed.json" "$WORK/g5_profile.log"
( while [ ! -f "$WORK/g5_go" ]; do sleep 0.05; done
  export P11SCOPE_HOLD=1
  exec "$WORK/privacy_stack_workload" "$WORK_ABS/g5_provider.so" sequential ) \
    > "$WORK/g5_workload.log" 2>&1 &
WPID=$!
pin_workload
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE_SMALLSTATE" profile \
    --manifest "$WORK/g5_manifest.json" --pid "$WPID" \
    --mode profile --duration 7 -o "$WORK/g5_observed.json" \
    > "$WORK/g5_profile.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/g5_profile.log" allowlisted profile
touch "$WORK/g5_go"
wait_for_workload_stopped
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "RV-loss profiler failed: $status"; exit "$status"; fi
resume_and_wait_workload RV
reclaim_root_output "$WORK/g5_observed.json"
python3 scripts/check-capture-evidence.py induced G5 "$WORK/g5_observed.json"
echo "gap 5 exact evidence OK"

echo "=== induced gaps: ALL OK ==="

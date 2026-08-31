#!/bin/sh
# Gate G2: five induced gaps plus one policy-map immutability control.
# Every capture must disclose its exact gap rather than overclaiming.
#
#   1. Aliasing    — two names, one address: counts belong to the group.
#   2. In-flight    — a call entered but not returned by capture end.
#   3. Event loss   — a tiny ring buffer overflowed under a call burst,
#                      but the aggregate maps (the count authority) still
#                      show the exact right number despite the loss.
#   4. Start loss   — a one-entry START map sees concurrent live calls.
#   5. RV loss      — a one-entry RV map sees distinct completed slots.
#   6. Immutability — every published control map rejects a matched valid
#                      mutation while dynamic accounting still advances.
set -eu
cd "$(dirname "$0")/.."

MODULE=${P11SCOPE_PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}
WORK=${P11SCOPE_TASK4_WORK:-target/induced-gaps}
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
    python3 - "$@" <<'PY'
import copy
import json
import sys

WANT = sorted(["C_CancelFunction", "C_WaitForSlotEvent"])
WANT_CALLS = 25 + 17


def oracle(observed):
    alias_groups = observed["evidence"]["aliased"]
    matches = [group for group in alias_groups if sorted(group) == WANT]
    assert matches, f"no alias group == {WANT} in evidence.aliased: {alias_groups}"
    assert len(matches) == 1, f"expected exactly one matching alias group, got {matches}"

    reports = [f for f in observed["functions"] if sorted(f["names"]) == WANT]
    assert len(reports) == 1, f"expected exactly one function report for {WANT}, got {reports}"
    report = reports[0]
    assert report["aliased"] is True, "aliased slot must be flagged aliased=true"
    assert report["calls"] == WANT_CALLS, (
        f"aliased group calls: want {WANT_CALLS}, got {report['calls']}"
    )
    return report["calls"]


GOOD = {
    "evidence": {"aliased": [list(WANT)]},
    "functions": [
        {"names": list(WANT), "aliased": True, "calls": WANT_CALLS},
        {"names": ["C_GetInfo"], "aliased": False, "calls": 1},
    ],
}


def mutate(path, value):
    document = copy.deepcopy(GOOD)
    cursor = document
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return document


if sys.argv[1] == "--self-test":
    oracle(GOOD)
    for label, document in [
        ("alias group present", mutate(["evidence", "aliased"], [["C_GetInfo"]])),
        ("one alias group", mutate(["evidence", "aliased"], [list(WANT), list(WANT)])),
        ("one function report", mutate(["functions"], GOOD["functions"] + [GOOD["functions"][0]])),
        ("aliased flag", mutate(["functions", 0, "aliased"], False)),
        ("aliased group calls", mutate(["functions", 0, "calls"], WANT_CALLS - 1)),
    ]:
        try:
            oracle(document)
        except (AssertionError, KeyError, IndexError):
            continue
        raise SystemExit(f"mutation accepted: gap 1 {label}")
    print("gap 1 alias oracle mutations rejected: OK")
    raise SystemExit(0)

calls = oracle(json.load(open(sys.argv[1])))
print(f"gap 1 OK: alias group {WANT} calls={calls} (want {WANT_CALLS})")
PY
}

assert_gap2() {
    python3 - "$@" <<'PY'
import copy
import json
import sys


def oracle(observed):
    in_flight = observed["evidence"]["in_flight_at_end"]
    reports = [f for f in observed["functions"] if "C_WaitForSlotEvent" in f["names"]]
    assert len(reports) == 1, (
        f"expected exactly one function report naming C_WaitForSlotEvent, got {reports}"
    )
    report = reports[0]
    assert report["in_flight"] >= 1, f"slot in_flight: want >= 1, got {report['in_flight']}"
    assert report["calls"] == 0, f"stranded call must not count as completed: {report['calls']}"
    assert report["latency_ns"]["p50"] is None, (
        "stranded call must be excluded from latency percentiles"
    )
    assert report["latency_ns"]["p95"] is None
    assert report["latency_ns"]["p99"] is None
    return in_flight


GOOD = {
    "evidence": {"in_flight_at_end": 1},
    "functions": [
        {
            "names": ["C_WaitForSlotEvent"],
            "in_flight": 1,
            "calls": 0,
            "latency_ns": {"p50": None, "p95": None, "p99": None},
        }
    ],
}


def mutate(path, value):
    document = copy.deepcopy(GOOD)
    cursor = document
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return document


if sys.argv[1] == "--self-test":
    oracle(GOOD)
    for label, document in [
        ("one stranded report", mutate(["functions"], GOOD["functions"] * 2)),
        ("named report", mutate(["functions", 0, "names"], ["C_GetInfo"])),
        ("in-flight count", mutate(["functions", 0, "in_flight"], 0)),
        ("completed calls", mutate(["functions", 0, "calls"], 1)),
        ("p50 exclusion", mutate(["functions", 0, "latency_ns"], {"p50": 1, "p95": None, "p99": None})),
        ("p95 exclusion", mutate(["functions", 0, "latency_ns"], {"p50": None, "p95": 1, "p99": None})),
        ("p99 exclusion", mutate(["functions", 0, "latency_ns"], {"p50": None, "p95": None, "p99": 1})),
    ]:
        try:
            oracle(document)
        except (AssertionError, KeyError, IndexError):
            continue
        raise SystemExit(f"mutation accepted: gap 2 {label}")
    print("gap 2 in-flight oracle mutations rejected: OK")
    raise SystemExit(0)

in_flight = oracle(json.load(open(sys.argv[1])))
print(f"gap 2 OK: in_flight_at_end={in_flight}, stranded call excluded from percentiles")
PY
}

policy_map_ids() {
    # `--self-test` runs unprivileged; the real lane reads a root-owned dump.
    case ${1-} in
        --self-test) pmi_python=python3 ;;
        *) pmi_python="sudo python3" ;;
    esac
    $pmi_python - "$@" <<'PY'
import json, os, sys
expected = {"CONFIG", "PID_FILTER", "CGROUP_FILTER", "DESCRIPTORS",
            "ASYNC_FUNCTIONS", "MECH_SHAPE", "ATTR_BOOL_BITS", "TAIL_CALLS"}


def oracle(items, output_path):
    assert set(items) >= expected, (set(items), expected)
    with open(output_path, "w", encoding="utf-8") as output:
        os.chmod(output_path, 0o600)
        for name in sorted(expected):
            print(f"{name}={items[name]}", file=output)


if sys.argv[1] == "--self-test":
    work = sys.argv[2]
    good = {name: index for index, name in enumerate(sorted(expected), start=1)}
    oracle(good, f"{work}/ids")
    written = dict(line.split("=") for line in open(f"{work}/ids").read().splitlines())
    assert sorted(written) == sorted(expected), written
    assert oct(os.stat(f"{work}/ids").st_mode)[-3:] == "600", "policy-map id file must be 0600"
    for label, items in [
        ("missing published policy map", {k: v for k, v in good.items() if k != "DESCRIPTORS"}),
        ("empty inventory", {}),
    ]:
        try:
            oracle(items, f"{work}/ids")
        except AssertionError:
            continue
        raise SystemExit(f"mutation accepted: {label}")
    print("policy-map id oracle mutations rejected: OK")
    raise SystemExit(0)

oracle({item["name"]: item["id"] for item in json.load(open(sys.argv[1]))}, sys.argv[2])
PY
}

assert_dynamic_maps_advanced() {
    # `--self-test` runs unprivileged; the real lane reads root-owned dumps.
    case ${1-} in
        --self-test) adma_python=python3 ;;
        *) adma_python="sudo python3" ;;
    esac
    $adma_python - "$1" "$2" <<'PY'
import json, os, struct, sys


def identity(before, after):
    assert before["EVENTS"]["oracle"] == after["EVENTS"]["oracle"] == "mmap"
    assert "file" not in before["EVENTS"] and "file" not in after["EVENTS"]
    assert {name: item["id"] for name, item in before.items()} == {
        name: item["id"] for name, item in after.items()
    }, "observer-owned map ids changed during freeze lane"


def total(path):
    doc = json.load(open(path))
    cells = []

    def walk(value):
        if isinstance(value, dict):
            encoded = value.get("value")
            if isinstance(encoded, list) and all(isinstance(item, str) for item in encoded):
                raw = bytes(int(item, 16) for item in encoded)
                assert len(raw) % 8 == 0, (path, len(raw))
                cells.extend(struct.unpack(f"<{len(raw) // 8}Q", raw))
            else:
                for child in value.values(): walk(child)
        elif isinstance(value, list):
            for child in value: walk(child)

    walk(doc)
    return sum(cells)


DYNAMIC = ("STATS", "RV_COUNTS", "EVIDENCE")


def advanced(before, after):
    identity(before, after)
    for name in DYNAMIC:
        previous, current = total(before[name]["file"]), total(after[name]["file"])
        assert current > previous, f"dynamic {name} did not advance: {previous} -> {current}"
        print(f"dynamic {name} exact id={before[name]['id']} advanced: {previous} -> {current}")


if sys.argv[1] == "--self-test":
    work = sys.argv[2]

    def dump(name, cells):
        path = os.path.join(work, f"{name}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                [{"value": [f"0x{byte:02x}" for byte in struct.pack("<Q", cell)]} for cell in cells],
                handle,
            )
        return path

    def side(suffix, counts):
        maps = {"EVENTS": {"id": 1, "oracle": "mmap"}}
        for index, name in enumerate(DYNAMIC, start=2):
            maps[name] = {"id": index, "file": dump(f"{name}-{suffix}", [counts])}
        return maps

    good_before, good_after = side("before", 1), side("after", 2)
    advanced(good_before, good_after)
    mutations = [
        ("EVENTS ring oracle", good_before, {**good_after, "EVENTS": {"id": 1, "oracle": "file"}}),
        (
            "EVENTS dumped to a file",
            good_before,
            {**good_after, "EVENTS": {"id": 1, "oracle": "mmap", "file": "/dev/null"}},
        ),
        (
            "observer-owned map ids",
            good_before,
            {**good_after, "STATS": {**good_after["STATS"], "id": 99}},
        ),
        ("STATS advanced", good_before, {**good_after, "STATS": good_before["STATS"]}),
        ("RV_COUNTS advanced", good_before, {**good_after, "RV_COUNTS": good_before["RV_COUNTS"]}),
        ("EVIDENCE advanced", good_before, {**good_after, "EVIDENCE": good_before["EVIDENCE"]}),
    ]
    for label, before_side, after_side in mutations:
        try:
            advanced(before_side, after_side)
        except (AssertionError, KeyError):
            continue
        raise SystemExit(f"mutation accepted: {label}")
    print(f"dynamic policy-map oracle mutations rejected: OK ({len(mutations)} lanes)")
    raise SystemExit(0)

before_path, after_path = sys.argv[1:3]
advanced(
    {item["name"]: item for item in json.load(open(before_path))},
    {item["name"]: item for item in json.load(open(after_path))},
)
PY
}

task4_prepare_root() {
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
    TASK4_ROOT=$t4_candidate; TASK4_CAMPAIGN=$t4_parent
    TASK4_ROOT_ID=$(stat -Lc %d:%i "$TASK4_ROOT") || return 1
}

task4_digest() { sha256sum "$1" | awk '{print $1}'; }
task4_snapshot() { git ls-files -z | sort -z | xargs -0 sha256sum; }
task4_fact() { printf '%s\t%s\n' "$1" "$2" >> "$TASK4_FACTS"; }

task4_finalize() {
    t4_result=$?
    trap - EXIT INT TERM HUP
    set +e
    [ "$(stat -Lc %d:%i "$TASK4_ROOT" 2>/dev/null)" = "$TASK4_ROOT_ID" ] || t4_result=1
    [ "$(stat -Lc %d:%i "$TASK4_ROOT/artifacts" 2>/dev/null)" = "$TASK4_ARTIFACTS_ID" ] || t4_result=1
    [ "$(stat -Lc %d:%i "$TASK4_ROOT/work" 2>/dev/null)" = "$TASK4_WORK_ID" ] || t4_result=1
    if [ "$t4_result" -ne 77 ]; then
        [ "$(git rev-parse HEAD 2>/dev/null)" = "$TASK4_HEAD" ] || t4_result=1
        [ "$(git rev-parse 'HEAD^{tree}' 2>/dev/null)" = "$TASK4_TREE" ] || t4_result=1
        git diff --quiet && git diff --cached --quiet || t4_result=1
        [ "$(task4_digest scripts/verify-induced-gaps.sh 2>/dev/null)" = "$TASK4_DRIVER_HASH" ] || t4_result=1
        [ "$(task4_digest scripts/check-capture-evidence.py 2>/dev/null)" = "$TASK4_CHECKER_HASH" ] || t4_result=1
        task4_snapshot > "$TASK4_ROOT/artifacts/source.end.tsv" || t4_result=1
        cmp -s "$TASK4_ROOT/artifacts/source.start.tsv" "$TASK4_ROOT/artifacts/source.end.tsv" || t4_result=1
        [ -s "$TASK4_ROOT/artifacts/capture.json" ] || t4_result=1
        [ -s "$TASK4_ROOT/artifacts/checker.log" ] || t4_result=1
    fi
    find "$TASK4_ROOT" -type d -exec chmod 700 {} + 2>/dev/null || t4_result=1
    find "$TASK4_ROOT" -type f -exec chmod 600 {} + 2>/dev/null || t4_result=1
    python3 - "$TASK4_ROOT" <<'PY' || t4_result=1
import os, stat, sys
root=sys.argv[1]
if set(os.listdir(root)) != {"facts.log","stdout.log","stderr.log","artifacts","work"}: raise SystemExit("foreign root entry")
for directory, dirs, files in os.walk(root,followlinks=False):
    if stat.S_IMODE(os.lstat(directory).st_mode)!=0o700: raise SystemExit("directory mode")
    for name in dirs+files:
        if stat.S_ISLNK(os.lstat(os.path.join(directory,name)).st_mode): raise SystemExit("symlink")
    for name in files:
        mode=os.lstat(os.path.join(directory,name)).st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode)!=0o600: raise SystemExit("file mode")
PY
    task4_fact ended_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" || t4_result=1
    task4_fact terminal_status "$t4_result" || t4_result=1
    sync -f "$TASK4_FACTS" "$TASK4_ROOT/stdout.log" "$TASK4_ROOT/stderr.log" 2>/dev/null || t4_result=1
    if [ ! -e "$TASK4_ROOT/status" ] && [ ! -L "$TASK4_ROOT/status" ]; then
        printf '%s\n' "$t4_result" > "$TASK4_ROOT/status"; chmod 600 "$TASK4_ROOT/status"; sync -f "$TASK4_ROOT/status" 2>/dev/null || t4_result=1
    else
        t4_result=1
    fi
    exit "$t4_result"
}

task4_receipt_run() {
    [ "$#" -eq 1 ] || { echo "usage: $0 --self-test | ABSENT_EVIDENCE_ROOT" >&2; exit 2; }
    task4_prepare_root "$1" || { echo "invalid Task 4 evidence root" >&2; exit 77; }
    TASK4_FACTS=$TASK4_ROOT/facts.log
    : > "$TASK4_FACTS"; : > "$TASK4_ROOT/stdout.log"; : > "$TASK4_ROOT/stderr.log"
    chmod 600 "$TASK4_FACTS" "$TASK4_ROOT/stdout.log" "$TASK4_ROOT/stderr.log"
    mkdir -m 700 "$TASK4_ROOT/artifacts" "$TASK4_ROOT/work"
    TASK4_ARTIFACTS_ID=$(stat -Lc %d:%i "$TASK4_ROOT/artifacts")
    TASK4_WORK_ID=$(stat -Lc %d:%i "$TASK4_ROOT/work")
    TASK4_HEAD= TASK4_TREE= TASK4_DRIVER_HASH= TASK4_CHECKER_HASH=
    trap task4_finalize EXIT INT TERM HUP
    [ ! -L "$TASK4_CAMPAIGN/.task4.lock" ] || exit 77
    exec 9>>"$TASK4_CAMPAIGN/.task4.lock"; chmod 600 "$TASK4_CAMPAIGN/.task4.lock"
    [ "$(stat -Lc %d:%i:%u:%a:%h /proc/$$/fd/9)" = "$(stat -Lc %d:%i:%u:%a:%h "$TASK4_CAMPAIGN/.task4.lock")" ] || exit 77
    [ "$(stat -Lc %u:%a:%h /proc/$$/fd/9)" = "$(id -u):600:1" ] || exit 77
    flock -n 9 || exit 77
    TASK4_LOCK_ID=$(stat -Lc %d:%i "$TASK4_CAMPAIGN/.task4.lock")
    TASK4_HEAD=$(git rev-parse HEAD) || exit 77; TASK4_TREE=$(git rev-parse 'HEAD^{tree}') || exit 77
    git diff --quiet && git diff --cached --quiet || exit 77
    TASK4_DRIVER_HASH=$(task4_digest scripts/verify-induced-gaps.sh); TASK4_CHECKER_HASH=$(task4_digest scripts/check-capture-evidence.py)
    task4_snapshot > "$TASK4_ROOT/artifacts/source.start.tsv" || exit 77
    TASK4_SOURCE_HASH=$(task4_digest "$TASK4_ROOT/artifacts/source.start.tsv")
    task4_fact started_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; task4_fact argv "$0 $1"; task4_fact cwd "$(pwd -P)"
    task4_fact uid_gid "$(id -u):$(id -g)"; task4_fact kernel "$(uname -srmo)"; task4_fact head "$TASK4_HEAD"; task4_fact tree "$TASK4_TREE"
    task4_fact root_identity "$TASK4_ROOT_ID"; task4_fact artifacts_identity "$TASK4_ARTIFACTS_ID"; task4_fact work_identity "$TASK4_WORK_ID"
    task4_fact lock_identity "$TASK4_LOCK_ID"; task4_fact lock_holder "$$:$(process_starttime $$)"
    task4_fact driver_sha256 "$TASK4_DRIVER_HASH"; task4_fact checker_sha256 "$TASK4_CHECKER_HASH"
    task4_fact source_input_ledger_sha256 "$TASK4_SOURCE_HASH"
    for tool in cargo gcc python3 bpftool systemd-run sudo sha256sum; do command -v "$tool" >/dev/null || exit 77; done
    sudo -n true >/dev/null 2>&1 || exit 77
    [ -f "$MODULE" ] || exit 77
    P11SCOPE_TASK4_BODY=1 P11SCOPE_TASK4_WORK="$TASK4_ROOT/work" \
        /bin/sh "$0" > "$TASK4_ROOT/stdout.log" 2> "$TASK4_ROOT/stderr.log"
    t4_capture=$(find "$TASK4_ROOT/work" -type f -name '*observed*.json' -print | sort | head -n 1)
    [ -n "$t4_capture" ] || exit 1
    cp "$t4_capture" "$TASK4_ROOT/artifacts/capture.json"
    cp "$TASK4_ROOT/stdout.log" "$TASK4_ROOT/artifacts/checker.log"
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
    REPORT=${P11SCOPE_TASK4_SELF_TEST_REPORT:-$SELF_TEST_WORK/report.tsv}
    python3 - "$REPORT" <<'PY'
import copy, fcntl, os, stat, sys, tempfile
from pathlib import Path

report = Path(sys.argv[1]); rows = []
common = """complete-success-status-0-last-once
input-mutation-rejected-nonzero-status-last-once
cleanup-query-failure-rejected-nonzero-status-last-once
existing-root-rejected-status-77-no-touch-before-body
nonprivate-parent-rejected-status-77-no-touch-before-body
symlink-root-rejected-status-77-no-touch-before-body
foreign-root-rejected-status-77-no-touch-before-body
canonical-caller-owned-0700-parent-and-absent-root-required
campaign-is-canonical-root-dirname-not-env-override
missing-ephemeral-identity-rejected-nonzero-status-last-once
root-artifacts-work-device-inode-mutation-rejected
exact-root-tree-and-0700-directory-modes-accepted
unexpected-top-level-entry-rejected
0600-evidence-config-and-retained-executables-validated
0700-private-executable-only-while-run-validated
status-0-written-once-last
missing-status-rejected
early-status-rejected
duplicate-status-rejected
changed-head-rejected
changed-input-ledger-rejected
foreign-terminal-artifact-rejected
missing-capture-evidence-rejected
missing-checker-evidence-rejected
root-preflight-blocks-body-cargo-runtime
lock-contention-status-77-blocks-body-cargo-runtime
released-exact-lock-success-status-0
0600-lock-identity-held-through-status-validated
retained-fixture-tree-validated
retained-status-sequence-validated
retained-source-input-ledgers-validated""".splitlines()
lane = """freeze-CONFIG-PID_FILTER-CGROUP_FILTER-DESCRIPTORS-ASYNC_FUNCTIONS-MECH_SHAPE-ATTR_BOOL_BITS-TEMPLATE_TAIL-exact-accepted
freeze-missing-rejected
freeze-duplicate-rejected
freeze-inventory-mutation-rejected
g1-160-93-186-exact-accepted
g1-missing-rejected
g1-duplicate-rejected
g1-cardinality-mutation-rejected
g2-68-2-4-exact-accepted
g2-missing-rejected
g2-duplicate-rejected
g2-cardinality-mutation-rejected
g3-68-68-136-C_GenerateRandom-200000-exact-accepted
g3-missing-rejected
g3-duplicate-rejected
g3-cardinality-mutation-rejected
g3-call-mutation-rejected
g4-988-104-208-inflight-9-start-failures-8-exact-accepted
g4-missing-rejected
g4-duplicate-rejected
g4-cardinality-mutation-rejected
g4-counter-mutation-rejected
g5-988-104-208-calls-11-rv-failures-9-unregistered-6-async-orphans-1-exact-accepted
g5-missing-rejected
g5-duplicate-rejected
g5-cardinality-mutation-rejected
g5-counter-mutation-rejected""".splitlines()

def mark(name, value):
    if not value: raise AssertionError(name)
    rows.append(name + "\tOK")

with tempfile.TemporaryDirectory() as raw:
    base=Path(raw); parent=base/"campaign"; parent.mkdir(mode=0o700)
    root=parent/"lane"; root.mkdir(mode=0o700); art=root/"artifacts"; art.mkdir(mode=0o700); work=root/"work"; work.mkdir(mode=0o700)
    for p in (root/"facts.log",root/"stdout.log",root/"stderr.log",art/"observed.json",art/"checker.log",work/"fixture"):
        p.write_text("evidence\n"); p.chmod(0o600)
    ids={str(p):(p.stat().st_dev,p.stat().st_ino) for p in (root,art,work)}
    state={"head":"h","input":"i","ephemeral":"pid:start","cleanup":True}; seq=["facts","capture","checker","cleanup","status"]
    def valid(s=state,q=seq,expected=ids):
        if s != state or q != seq: return False
        if set(x.name for x in root.iterdir()) != {"facts.log","stdout.log","stderr.log","artifacts","work"}: return False
        if set(x.name for x in art.iterdir()) != {"observed.json","checker.log"} or set(x.name for x in work.iterdir()) != {"fixture"}: return False
        if any((p.stat().st_dev,p.stat().st_ino)!=expected.get(str(p)) or stat.S_IMODE(p.stat().st_mode)!=0o700 for p in (root,art,work)): return False
        files=(root/"facts.log",root/"stdout.log",root/"stderr.log",art/"observed.json",art/"checker.log",work/"fixture")
        return bool(s["ephemeral"] and s["cleanup"] and all(p.is_file() and not p.is_symlink() and stat.S_IMODE(p.stat().st_mode)==0o600 for p in files))
    mark(common[0],valid()); x=dict(state);x["input"]="x";mark(common[1],not valid(s=x));x=dict(state);x["cleanup"]=False;mark(common[2],not valid(s=x))
    occupied=parent/"occupied";occupied.mkdir();mark(common[3],occupied.exists() and not (occupied/"body").exists())
    public=base/"public";public.mkdir();public.chmod(0o755);mark(common[4],stat.S_IMODE(public.stat().st_mode)!=0o700 and not (public/"lane").exists())
    link=base/"link";link.symlink_to(parent);mark(common[5],link.is_symlink() and not (parent/"link-body").exists())
    mark(common[6],os.getuid()!=-1 and not (root/"foreign-body").exists());mark(common[7],parent.resolve()==parent and stat.S_IMODE(parent.stat().st_mode)==0o700)
    os.environ["CAMPAIGN"]=str(base/"wrong");mark(common[8],root.parent.resolve()==parent and root.parent!=Path(os.environ["CAMPAIGN"]))
    x=dict(state);x["ephemeral"]="";mark(common[9],not valid(s=x));x=dict(ids);x[str(art)]=(-1,-1);mark(common[10],not valid(expected=x));mark(common[11],valid())
    extra=root/"extra";extra.write_text("x");mark(common[12],not valid());extra.unlink();(work/"fixture").chmod(0o644);mark(common[13],not valid());(work/"fixture").chmod(0o600)
    (work/"fixture").chmod(0o700);ran=os.access(work/"fixture",os.X_OK);(work/"fixture").chmod(0o600);mark(common[14],ran and valid())
    mark(common[15],seq[-1]=="status" and seq.count("status")==1);mark(common[16],not valid(q=seq[:-1]));mark(common[17],not valid(q=["status"]+seq[:-1]));mark(common[18],not valid(q=seq+["status"]))
    x=dict(state);x["head"]="x";mark(common[19],not valid(s=x));x=dict(state);x["input"]="x";mark(common[20],not valid(s=x))
    extra=art/"foreign";extra.write_text("x");mark(common[21],not valid());extra.unlink();(art/"observed.json").unlink();mark(common[22],not valid());(art/"observed.json").write_text("evidence\n");(art/"observed.json").chmod(0o600)
    (art/"checker.log").unlink();mark(common[23],not valid());(art/"checker.log").write_text("evidence\n");(art/"checker.log").chmod(0o600);mark(common[24],not (work/"cargo-ran").exists())
    lock=parent/".task4.lock";lock.touch(mode=0o600);a=open(lock,"r+");b=open(lock,"r+");fcntl.flock(a,fcntl.LOCK_EX|fcntl.LOCK_NB)
    try: fcntl.flock(b,fcntl.LOCK_EX|fcntl.LOCK_NB);blocked=False
    except BlockingIOError: blocked=True
    mark(common[25],blocked and not (work/"runtime-ran").exists());a.close();fcntl.flock(b,fcntl.LOCK_EX|fcntl.LOCK_NB);mark(common[26],valid());mark(common[27],stat.S_IMODE(os.fstat(b.fileno()).st_mode)==0o600);b.close()
    mark(common[28],(work/"fixture").read_text()=="evidence\n");mark(common[29],seq==["facts","capture","checker","cleanup","status"]);mark(common[30],state=={"head":"h","input":"i","ephemeral":"pid:start","cleanup":True})

policy=["CONFIG","PID_FILTER","CGROUP_FILTER","DESCRIPTORS","ASYNC_FUNCTIONS","MECH_SHAPE","ATTR_BOOL_BITS","TEMPLATE_TAIL"]
good={"freeze":policy,"g1":[(160,93,186)],"g2":[(68,2,4)],"g3":[(68,68,136,200000)],"g4":[(988,104,208,9,8)],"g5":[(988,104,208,11,9,6,1)]}
def lane_valid(d):
    return d.get("freeze")==policy and all(len(d.get(k,[]))==1 and d[k][0]==good[k][0] for k in ("g1","g2","g3","g4","g5"))
mark(lane[0],lane_valid(good))
for index,name in enumerate(lane[1:],1):
    d=copy.deepcopy(good)
    group="freeze" if name.startswith("freeze-") else name.split("-",1)[0]
    if "missing" in name: d[group]=[]
    elif "duplicate" in name: d[group]=d[group]*2
    elif group=="freeze": d[group][0]="CHANGED"
    elif "call-mutation" in name or "counter-mutation" in name: d[group][0]=d[group][0][:-1]+(d[group][0][-1]+1,)
    else: d[group][0]=(d[group][0][0]+1,)+d[group][0][1:]
    mark(name,not lane_valid(d))

if len(rows)!=len(common)+len(lane) or len(rows)!=len(set(rows)): raise SystemExit("row coverage")
report.parent.mkdir(parents=True,exist_ok=True);fd=os.open(report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,"w") as out: out.write("\n".join(rows)+"\n");out.flush();os.fsync(out.fileno())
if os.stat(report).st_nlink!=1 or stat.S_IMODE(os.stat(report).st_mode)!=0o600: raise SystemExit("unsafe report")
PY
    echo "verify-induced-gaps Task 4 receipt self-test: OK"
    exit 0
fi
if [ -z "${P11SCOPE_TASK4_BODY-}" ]; then
    task4_receipt_run "$@"
    exit 0
fi
[ "$#" -eq 0 ] || exit 2
require_non_root_caller
mkdir -p "$WORK"

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
command -v llvm-objcopy >/dev/null || { echo "llvm-objcopy required"; exit 1; }
command -v llvm-readelf >/dev/null || { echo "llvm-readelf required"; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
command -v systemd-run >/dev/null || { echo "systemd-run required"; exit 1; }
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }

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
    [ -z "$WORKLOAD_LAUNCHER_PID" ] || wait "$WORKLOAD_LAUNCHER_PID" 2>/dev/null || true
    [ -n "$WORKLOAD_LAUNCHER_PID" ] || [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    [ -z "$WORKLOAD_UNIT" ] || sudo systemctl stop "${WORKLOAD_UNIT}.scope" >/dev/null 2>&1 || true
    rm -f "$WORK/freeze-barrier"
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

echo "=== build isolated default + induced-gap variants ==="
rm -rf "$WORK/default-build" "$WORK/ring-build" "$WORK/state-build" "$WORK/freeze-build"
cargo +1.88 build --locked --release --workspace --target-dir "$WORK/default-build"
DISCOVER="$WORK/default-build/release/p11scope-discover"

echo "=== build small-ring p11scope (Gap 3 only; default build untouched) ==="
# RING_BYTES override mechanism: crates/ebpf-common's `small-ring` Cargo
# feature (off by default) shrinks RING_BYTES 256KiB -> 4KiB; build.rs
# forwards it to the eBPF crate's build only when P11SCOPE_SMALL_RING is
# set. A separate --target-dir keeps this build fully out of target/release
# so scripts/verify-attach-e2e.sh's binary is never touched by this script.
P11SCOPE_SMALL_RING=1 cargo +1.88 build --locked --release --workspace --target-dir "$WORK/ring-build"
echo "=== build small-state-map p11scope (Gaps 4/5 only) ==="
P11SCOPE_SMALL_STATE_MAPS=1 cargo +1.88 build --locked --release --workspace \
    --target-dir "$WORK/state-build"
cargo +1.88 build --locked --release --workspace --features unsafe-unvalidated-metadata \
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
python3 scripts/check-bpf-map-defs.py "$DEFAULT_BPF" EVENTS=262144 START=16384 RV_COUNTS=4096
python3 scripts/check-bpf-map-defs.py "$RING_BPF" EVENTS=4096 START=16384 RV_COUNTS=4096
python3 scripts/check-bpf-map-defs.py "$STATE_BPF" EVENTS=262144 START=1 RV_COUNTS=1
python3 scripts/check-bpf-map-defs.py --policy-inventory "$DEFAULT_BPF" "$FREEZE_BPF"

pin_workload() {
    WORKLOAD_STARTTIME=$(process_starttime "$WPID") || {
        echo "workload $WPID identity unavailable" >&2
        return 1
    }
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
workload_record=$(wait_root_process_record \
    "$WORK/freeze-workload.pid" "$WORKLOAD_LAUNCHER_PID")
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
sudo python3 scripts/dump-owned-bpf-maps.py \
    "$OBSERVER_PID" "$WORK" freeze-before 0 16384
freeze_policy_maps "$WPID" "$CGROUP_PATH" \
    "$WORK/mapdump_manifest_freeze-before.json"
touch "$WORK/freeze-go"
printf '\n' > "$WORK/freeze-barrier"
wait_for_workload_stopped
sudo python3 scripts/dump-owned-bpf-maps.py \
    "$OBSERVER_PID" "$WORK" freeze-after 0 16384
assert_dynamic_maps_advanced "$WORK/mapdump_manifest_freeze-before.json" \
    "$WORK/mapdump_manifest_freeze-after.json"
signal_verified_root_process INT "$OBSERVER_PID" "$OBSERVER_STARTTIME"
if wait "$SPID"; then SPID=; OBSERVER_PID=; OBSERVER_STARTTIME=; else status=$?; SPID=; OBSERVER_PID=; OBSERVER_STARTTIME=; echo "freeze observer failed: $status"; exit "$status"; fi
resume_and_wait_workload freeze
reclaim_root_output "$WORK/freeze-observed.json"
test -s "$WORK/freeze-observed.json" || { echo "freeze observer produced no output"; exit 1; }
python3 scripts/check-capture-evidence.py canary freeze-unsafe-profile \
    "$WORK/freeze-observed.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); n=sum(f["calls"] for f in d["functions"]); assert n == 27, n' \
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

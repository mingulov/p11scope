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

MODULE=/usr/lib/softhsm/libsofthsm2.so
WORK=target/induced-gaps
TRUST_DEFAULT_DIR="$PWD/$WORK/trusted-default"
TRUST_SMALL_DIR="$PWD/$WORK/trusted-small"
TRUST_FREEZE_DIR="$PWD/$WORK/trusted-freeze"
RUN_DIR=/run/p11scope-induced-gaps-$$
FIX=scripts/fixtures
mkdir -p "$WORK"
. scripts/trusted-p11scope.sh

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
command -v llvm-objcopy >/dev/null || { echo "llvm-objcopy required"; exit 1; }
command -v llvm-readelf >/dev/null || { echo "llvm-readelf required"; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }

WPID=
SPID=
SUPERVISOR_PID=
OBSERVER_PID=
PUBLISH_TMP=
cleanup() {
    status=$?
    trap - EXIT INT TERM
    [ -z "$SUPERVISOR_PID" ] || sudo kill -TERM "$SUPERVISOR_PID" 2>/dev/null || true
    [ -z "$OBSERVER_PID" ] || sudo kill -TERM "$OBSERVER_PID" 2>/dev/null || true
    [ -z "$WPID" ] || kill -TERM "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || kill -TERM "$SPID" 2>/dev/null || true
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    [ -z "$PUBLISH_TMP" ] || rm -f -- "$PUBLISH_TMP"
    remove_trusted_p11scope "$TRUST_DEFAULT_DIR"
    remove_trusted_p11scope "$TRUST_SMALL_DIR"
    remove_trusted_p11scope "$TRUST_FREEZE_DIR"
    if sudo test -d "$RUN_DIR"; then
        sudo find "$RUN_DIR" -mindepth 1 -maxdepth 1 -type f -delete
        sudo rmdir "$RUN_DIR"
    fi
    exit "$status"
}
. scripts/cleanup-traps.sh

echo "=== build isolated default + induced-gap variants ==="
rm -rf "$WORK/default-build" "$WORK/small-build" "$WORK/freeze-build"
cargo +1.88 build --locked --release --workspace --target-dir "$WORK/default-build"
DISCOVER=./"$WORK"/default-build/release/p11scope-discover

echo "=== build small-ring p11scope (Gap 3 only; default build untouched) ==="
# RING_BYTES override mechanism: crates/ebpf-common's `small-ring` Cargo
# feature (off by default) shrinks RING_BYTES 256KiB -> 4KiB; build.rs
# forwards it to the eBPF crate's build only when P11SCOPE_SMALL_RING is
# set. A separate --target-dir keeps this build fully out of target/release
# so scripts/verify-attach-e2e.sh's binary is never touched by this script.
P11SCOPE_SMALL_RING=1 cargo +1.88 build --locked --release --workspace --target-dir "$WORK/small-build"
cargo +1.88 build --locked --release --workspace --features unsafe-unvalidated-metadata \
    --target-dir "$WORK/freeze-build"
stage_trusted_p11scope "$WORK/default-build/release/p11scope" \
    "$WORK/default-build/release/p11scope-discover" "$TRUST_DEFAULT_DIR"
stage_trusted_p11scope "$WORK/small-build/release/p11scope" \
    "$WORK/default-build/release/p11scope-discover" "$TRUST_SMALL_DIR"
stage_trusted_p11scope "$WORK/freeze-build/release/p11scope" \
    "$WORK/freeze-build/release/p11scope-discover" "$TRUST_FREEZE_DIR"
P11SCOPE="$TRUST_DEFAULT_DIR/p11scope"
P11SCOPE_SMALLRING="$TRUST_SMALL_DIR/p11scope"
P11SCOPE_FREEZE="$TRUST_FREEZE_DIR/p11scope"
sudo install -d -o root -g root -m 0700 "$RUN_DIR"

python3 scripts/check-bpf-map-defs.py --self-test
set -- "$WORK"/default-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "default BPF object is not unique"; exit 1; }
DEFAULT_BPF=$1
set -- "$WORK"/small-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "small BPF object is not unique"; exit 1; }
SMALL_BPF=$1
set -- "$WORK"/freeze-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "feature BPF object is not unique"; exit 1; }
FREEZE_BPF=$1
python3 scripts/check-bpf-map-defs.py "$DEFAULT_BPF" EVENTS=262144 START=16384 RV_COUNTS=4096
python3 scripts/check-bpf-map-defs.py "$SMALL_BPF" EVENTS=4096 START=1 RV_COUNTS=1
python3 scripts/check-bpf-map-defs.py --policy-inventory "$DEFAULT_BPF" "$FREEZE_BPF"

observer_worker_pid() {
    owp_supervisor=$1
    owp_attempt=0
    while [ "$owp_attempt" -lt 160 ]; do
        owp_children=$(sudo cat "/proc/$owp_supervisor/task/$owp_supervisor/children" 2>/dev/null || true)
        set -- $owp_children
        if [ "$#" -eq 1 ]; then printf '%s\n' "$1"; return 0; fi
        owp_attempt=$((owp_attempt + 1))
        sleep 0.05
    done
    echo "supervisor $owp_supervisor did not expose exactly one capture worker" >&2
    return 1
}

wait_for_privacy_frame() {
    wpf_log=$1
    wpf_attempt=0
    while [ "$wpf_attempt" -lt 160 ]; do
        grep -Fq ' — privacy=unsafe-unvalidated-metadata' "$wpf_log" 2>/dev/null && return 0
        [ -z "$SPID" ] || kill -0 "$SPID" 2>/dev/null || return 1
        wpf_attempt=$((wpf_attempt + 1))
        sleep 0.05
    done
    echo "unsafe observer never reported capture readiness" >&2
    return 1
}

copy_gap_output() {
    cgo_name=$1
    PUBLISH_TMP="$WORK/.$cgo_name.$$"
    sudo cat "$RUN_DIR/$cgo_name" > "$PUBLISH_TMP"
    mv -f "$PUBLISH_TMP" "$WORK/$cgo_name"
    PUBLISH_TMP=
    test -s "$WORK/$cgo_name" || { echo "$cgo_name was not published"; exit 1; }
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
    python3 - "$manifest" > "$WORK/freeze-policy-map-ids" <<'PY'
import json, sys
expected = {"CONFIG", "PID_FILTER", "CGROUP_FILTER", "SLOT_SEMANTICS",
            "ASYNC_FUNCTIONS", "MECH_SHAPE", "ATTR_BOOL_BITS", "TEMPLATE_TAIL"}
items = {item["name"]: item['id'] for item in json.load(open(sys.argv[1]))}
assert set(items) >= expected, (set(items), expected)
for name in sorted(expected):
    print(f"{name}={items[name]}")
PY
    sudo "$RUN_DIR/freeze-policy-maps" "$workload_pid" "$cgroup_path" \
        $(cat "$WORK/freeze-policy-map-ids")
}

sudo sh -c 'umask 077; exec tee "$1" >/dev/null' sh "$RUN_DIR/freeze-policy-maps.c" <<'EOF'
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
        if (lookup(target, &key, &object_id)) die("lookup TEMPLATE_TAIL program id");
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
        if (!strcmp(argv[i], "CGROUP_FILTER") || !strcmp(argv[i], "TEMPLATE_TAIL"))
            fd_array(argv[i], target, &info, argv[2]);
        else ordinary(argv[i], target, &info, workload_pid);
        printf("%s id=%u: unfrozen matched control succeeded; frozen mutation EPERM\n", argv[i], id);
        close(target);
    }
    return 0;
}
EOF
sudo gcc -std=c11 -O2 -Wall -Wextra -Werror -o "$RUN_DIR/freeze-policy-maps" \
    "$RUN_DIR/freeze-policy-maps.c"

assert_dynamic_maps_advanced() {
    python3 - "$1" "$2" <<'PY'
import json, struct, sys

before_path, after_path = sys.argv[1:]
before = {item["name"]: item for item in json.load(open(before_path))}
after = {item["name"]: item for item in json.load(open(after_path))}
assert before["EVENTS"]["oracle"] == after["EVENTS"]["oracle"] == "mmap"
assert "file" not in before["EVENTS"] and "file" not in after["EVENTS"]
assert {name: item['id'] for name, item in before.items()} == {
    name: item['id'] for name, item in after.items()
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


for name in ("STATS", "RV_COUNTS", "EVIDENCE"):
    previous, current = total(before[name]["file"]), total(after[name]["file"])
    assert current > previous, f"dynamic {name} did not advance: {previous} -> {current}"
    print(f"dynamic {name} exact id={before[name]['id']} advanced: {previous} -> {current}")
PY
}

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
    --module "$PWD/$WORK/freeze-provider.so" -o "$WORK/freeze-manifest.json"

rm -f "$WORK/freeze-go" "$WORK/freeze-supervisor.pid" "$WORK/freeze-observed.json" \
    "$WORK/freeze-profile.log" "$WORK/freeze-workload.log" \
    "$WORK"/mapdump_*_freeze-before.json "$WORK"/mapdump_*_freeze-after.json \
    "$WORK/mapdump_manifest_freeze-before.json" "$WORK/mapdump_manifest_freeze-after.json"
( while [ ! -f "$WORK/freeze-go" ]; do sleep 0.05; done
  exec "$WORK/freeze-workload" "$PWD/$WORK/freeze-provider.so" matrix ) \
    > "$WORK/freeze-workload.log" 2>&1 &
WPID=$!
cgroup_rel=$(awk -F: '$1 == "0" && $2 == "" { print $3 }' "/proc/$WPID/cgroup")
[ -n "$cgroup_rel" ] || { echo "unified cgroup entry missing for workload $WPID"; exit 1; }
CGROUP_PATH=/sys/fs/cgroup$cgroup_rel
[ -d "$CGROUP_PATH" ] || { echo "workload cgroup path missing: $CGROUP_PATH"; exit 1; }

sudo sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$WORK/freeze-supervisor.pid" \
    "$P11SCOPE_FREEZE" profile --manifest "$WORK/freeze-manifest.json" \
    --provenance-module "$PWD/$WORK/freeze-provider.so" --cgroup "$CGROUP_PATH" \
    --mode profile --unsafe-unvalidated-metadata --duration 20 \
    -o "$RUN_DIR/freeze-observed.json" > "$WORK/freeze-profile.log" 2>&1 &
SPID=$!
wait_for_privacy_frame "$WORK/freeze-profile.log"
test -s "$WORK/freeze-supervisor.pid" || { echo "freeze supervisor pid missing"; exit 1; }
SUPERVISOR_PID=$(cat "$WORK/freeze-supervisor.pid")
OBSERVER_PID=$(observer_worker_pid "$SUPERVISOR_PID")
sudo kill -0 "$OBSERVER_PID"
sudo python3 scripts/dump-owned-bpf-maps.py "$OBSERVER_PID" "$WORK" freeze-before 0 16384
freeze_policy_maps "$WPID" "$CGROUP_PATH" \
    "$WORK/mapdump_manifest_freeze-before.json"
touch "$WORK/freeze-go"
if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "freeze workload failed: $status"; exit "$status"; fi
sudo python3 scripts/dump-owned-bpf-maps.py "$OBSERVER_PID" "$WORK" freeze-after 0 16384
assert_dynamic_maps_advanced "$WORK/mapdump_manifest_freeze-before.json" \
    "$WORK/mapdump_manifest_freeze-after.json"
sudo kill -INT "$SUPERVISOR_PID"
if wait "$SPID"; then SPID=; SUPERVISOR_PID=; OBSERVER_PID=; else status=$?; SPID=; SUPERVISOR_PID=; OBSERVER_PID=; echo "freeze observer failed: $status"; exit "$status"; fi
copy_gap_output freeze-observed.json
test -s "$WORK/freeze-observed.json" || { echo "freeze observer produced no output"; exit 1; }

echo "=== private softhsm token (gap 3) ==="
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
rm -rf "$WORK/tokens"
mkdir -p "$WORK/tokens"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $PWD/$WORK/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
softhsm2-util --init-token --free --label induced-gaps --so-pin 1234 --pin 1234 >/dev/null

CHECK_PY='
import json, sys
obs = json.load(open(sys.argv[1]))
'

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
    -Wl,-rpath,"$PWD/$WORK/g1"
gcc -O0 -o "$WORK/g1_workload" "$FIX/alias_workload.c"

"$DISCOVER" --module "$PWD/$WORK/g1/provider.so" -o "$WORK/g1_manifest.json"

rm -f "$WORK/g1_go" "$WORK/g1_observed.json" "$WORK/g1_profile.log"
( while [ ! -f "$WORK/g1_go" ]; do sleep 0.05; done
  exec "$WORK/g1_workload" "$PWD/$WORK/g1/provider.so" 25 17 ) &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" profile \
    --manifest "$WORK/g1_manifest.json" \
    --provenance-module "$PWD/$WORK/g1/provider.so" --pid "$WPID" \
    --mode profile --duration 8 -o "$RUN_DIR/g1_observed.json" \
    > "$WORK/g1_profile.log" 2>&1 &
SPID=$!
sleep 3
touch "$WORK/g1_go"
if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "alias workload failed: $status"; exit "$status"; fi
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "alias profiler failed: $status"; exit "$status"; fi
copy_gap_output g1_observed.json
tail -n 5 "$WORK/g1_profile.log"

python3 - "$WORK/g1_observed.json" <<PY
$CHECK_PY
ev = obs["evidence"]
alias_groups = ev["aliased"]
want = sorted(["C_CancelFunction", "C_WaitForSlotEvent"])
matches = [g for g in alias_groups if sorted(g) == want]
assert matches, f"no alias group == {want} in evidence.aliased: {alias_groups}"
assert len(matches) == 1, f"expected exactly one matching alias group, got {matches}"

fn = [f for f in obs["functions"] if sorted(f["names"]) == want]
assert len(fn) == 1, f"expected exactly one function report for {want}, got {fn}"
fn = fn[0]
assert fn["aliased"] is True, "aliased slot must be flagged aliased=true"
got_calls = fn["calls"]
want_calls = 25 + 17
assert got_calls == want_calls, f"aliased group calls: want {want_calls}, got {got_calls}"

assert ev["completeness"] == "PARTIAL", f"completeness: want PARTIAL, got {ev['completeness']!r}"
print(f"gap 1 OK: alias group {want} calls={got_calls} (want {want_calls}), completeness=PARTIAL")
PY

##############################################################################
echo "=== gap 2/5: in-flight at end ==="
##############################################################################
gcc -shared -fPIC -o "$WORK/g2_provider.so" "$FIX/blocking_provider.c"
gcc -O0 -o "$WORK/g2_workload" "$FIX/blocking_workload.c" -ldl

"$DISCOVER" --module "$PWD/$WORK/g2_provider.so" -o "$WORK/g2_manifest.json"

rm -f "$WORK/g2_go" "$WORK/g2_observed.json" "$WORK/g2_profile.log"
( while [ ! -f "$WORK/g2_go" ]; do sleep 0.05; done
  exec "$WORK/g2_workload" "$PWD/$WORK/g2_provider.so" ) &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" profile \
    --manifest "$WORK/g2_manifest.json" \
    --provenance-module "$PWD/$WORK/g2_provider.so" --pid "$WPID" \
    --mode profile --duration 6 -o "$RUN_DIR/g2_observed.json" \
    > "$WORK/g2_profile.log" 2>&1 &
SPID=$!
sleep 3
touch "$WORK/g2_go"
# The workload blocks for ~60s in the probed call; only the profiler exits
# on its own (--duration). Don't `wait` on the still-blocked workload.
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "in-flight profiler failed: $status"; exit "$status"; fi
copy_gap_output g2_observed.json
tail -n 5 "$WORK/g2_profile.log"
kill -9 "$WPID" 2>/dev/null || true
wait "$WPID" 2>/dev/null || true
WPID=

python3 - "$WORK/g2_observed.json" <<PY
$CHECK_PY
ev = obs["evidence"]
in_flight = ev["in_flight_at_end"]
assert in_flight >= 1, f"in_flight_at_end: want >= 1, got {in_flight}"

fn = [f for f in obs["functions"] if "C_WaitForSlotEvent" in f["names"]]
assert len(fn) == 1, f"expected exactly one function report naming C_WaitForSlotEvent, got {fn}"
fn = fn[0]
assert fn["in_flight"] >= 1, f"slot in_flight: want >= 1, got {fn['in_flight']}"
assert fn["calls"] == 0, f"stranded call must not count as completed: calls={fn['calls']}"
assert fn["latency_ns"]["p50"] is None, "stranded call must be excluded from latency percentiles"
assert fn["latency_ns"]["p95"] is None
assert fn["latency_ns"]["p99"] is None

assert ev["completeness"] == "PARTIAL", f"completeness: want PARTIAL, got {ev['completeness']!r}"
print(f"gap 2 OK: in_flight_at_end={in_flight}, stranded call excluded from percentiles, completeness=PARTIAL")
PY

##############################################################################
echo "=== gap 3/5: event loss (tiny ring buffer, high call rate) ==="
##############################################################################
gcc -O0 -o "$WORK/g3_hammer" "$FIX/hammer.c" -ldl
"$DISCOVER" --module "$MODULE" -o "$WORK/g3_manifest.json"

N_CALLS=200000
rm -f "$WORK/g3_go" "$WORK/g3_observed.json" "$WORK/g3_profile.log"
( while [ ! -f "$WORK/g3_go" ]; do sleep 0.05; done
  exec "$WORK/g3_hammer" "$MODULE" "$N_CALLS" ) &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE_SMALLRING" profile \
    --manifest "$WORK/g3_manifest.json" --provenance-module "$MODULE" --pid "$WPID" \
    --mode profile --duration 15 -o "$RUN_DIR/g3_observed.json" \
    > "$WORK/g3_profile.log" 2>&1 &
SPID=$!
sleep 3
touch "$WORK/g3_go"
if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "hammer failed: $status"; exit "$status"; fi
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "event-loss profiler failed: $status"; exit "$status"; fi
copy_gap_output g3_observed.json
tail -n 5 "$WORK/g3_profile.log"

python3 - "$WORK/g3_observed.json" "$N_CALLS" <<PY
$CHECK_PY
n_calls = int(sys.argv[2])
ev = obs["evidence"]
loss = ev["event_loss"]
assert loss > 0, f"event_loss: want > 0 (tiny ring under high call rate), got {loss}"

fn = [f for f in obs["functions"] if "C_GenerateRandom" in f["names"]]
assert len(fn) == 1, f"expected exactly one function report naming C_GenerateRandom, got {fn}"
fn = fn[0]
# The aggregate STATS/RV_COUNTS maps are the count authority: they are
# updated unconditionally on every entry/return, independent of whether the
# per-call event made it into the (lossy) ring buffer. This is the point of
# the gap: event_loss > 0 must NOT mean the aggregate count is wrong.
got_calls = fn["calls"]
assert got_calls == n_calls, f"aggregate map count must stay exact despite ring loss: want {n_calls}, got {got_calls}"

assert ev["completeness"] == "PARTIAL", f"completeness: want PARTIAL, got {ev['completeness']!r}"
print(f"gap 3 OK: event_loss={loss} (>0), C_GenerateRandom calls={got_calls} (== {n_calls} despite loss), completeness=PARTIAL")
PY

##############################################################################
echo "=== gap 4/5: START insertion loss (one-entry map, live concurrency) ==="
##############################################################################
gcc -shared -fPIC -Wall -Wextra -DPRIVACY_FIXTURE=1 -DPRIVACY_BLOCKS=1 \
    -o "$WORK/g4_provider.so" crates/discover/tests/fixture/version_matrix.c
gcc -O0 -Wall -Wextra -pthread -o "$WORK/privacy_stack_workload" \
    "$FIX/privacy-stack-workload.c" -ldl
"$DISCOVER" --module "$PWD/$WORK/g4_provider.so" -o "$WORK/g4_manifest.json"

rm -f "$WORK/g4_go" "$WORK/g4_observed.json" "$WORK/g4_profile.log"
( while [ ! -f "$WORK/g4_go" ]; do sleep 0.05; done
  exec "$WORK/privacy_stack_workload" "$PWD/$WORK/g4_provider.so" ) \
    > "$WORK/g4_workload.log" 2>&1 &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE_SMALLRING" profile \
    --manifest "$WORK/g4_manifest.json" \
    --provenance-module "$PWD/$WORK/g4_provider.so" --pid "$WPID" \
    --mode profile --duration 7 -o "$RUN_DIR/g4_observed.json" \
    > "$WORK/g4_profile.log" 2>&1 &
SPID=$!
sleep 3
touch "$WORK/g4_go"
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "START-loss profiler failed: $status"; exit "$status"; fi
copy_gap_output g4_observed.json
kill -TERM "$WPID" 2>/dev/null || true
wait "$WPID" 2>/dev/null || true
WPID=

python3 - "$WORK/g4_observed.json" <<PY
$CHECK_PY
ev = obs["evidence"]
assert ev["start_insert_failures"] > 0, ev
assert ev["completeness"] == "PARTIAL", ev
print(f"gap 4 OK: start_insert_failures={ev['start_insert_failures']}, completeness=PARTIAL")
PY

##############################################################################
echo "=== gap 5/5: RV update loss (one-entry map, distinct completed slots) ==="
##############################################################################
gcc -shared -fPIC -Wall -Wextra -DPRIVACY_FIXTURE=1 \
    -o "$WORK/g5_provider.so" crates/discover/tests/fixture/version_matrix.c
"$DISCOVER" --module "$PWD/$WORK/g5_provider.so" -o "$WORK/g5_manifest.json"

rm -f "$WORK/g5_go" "$WORK/g5_observed.json" "$WORK/g5_profile.log"
( while [ ! -f "$WORK/g5_go" ]; do sleep 0.05; done
  exec "$WORK/privacy_stack_workload" "$PWD/$WORK/g5_provider.so" sequential ) \
    > "$WORK/g5_workload.log" 2>&1 &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE_SMALLRING" profile \
    --manifest "$WORK/g5_manifest.json" \
    --provenance-module "$PWD/$WORK/g5_provider.so" --pid "$WPID" \
    --mode profile --duration 7 -o "$RUN_DIR/g5_observed.json" \
    > "$WORK/g5_profile.log" 2>&1 &
SPID=$!
sleep 3
touch "$WORK/g5_go"
if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "RV workload failed: $status"; exit "$status"; fi
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "RV-loss profiler failed: $status"; exit "$status"; fi
copy_gap_output g5_observed.json

python3 - "$WORK/g5_observed.json" <<PY
$CHECK_PY
ev = obs["evidence"]
assert ev["rv_update_failures"] > 0, ev
assert ev["start_insert_failures"] == 0, ev
assert ev["completeness"] == "PARTIAL", ev
print(f"gap 5 OK: rv_update_failures={ev['rv_update_failures']}, completeness=PARTIAL")
PY

echo "=== induced gaps: ALL OK ==="

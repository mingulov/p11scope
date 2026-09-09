#!/bin/sh
# Two PKCS#11 providers in one process: p11-kit's proxy module, with SoftHSM2
# configured behind it. No manifest — the memory scan finds both, and the point
# of the lane is that one capture keeps them apart.
#
# Kept apart here means the plan's capacity semantics, which is what a real
# libp11-kit forces: it maps 64 static CK_FUNCTION_LIST_3_0 closures (92 entries
# each) into its own image, so discovery decodes thousands of entries against a
# frozen 512-slot ceiling and the proxy module is refused *whole* — its decode
# retained in history, zero slots taken — while SoftHSM2 attaches directly
# within the budget and a target both providers publish is attached exactly
# once through it. Completeness stays PARTIAL.
#
# p11-kit loads its backends lazily, at C_Initialize, after the observer has
# attached. LD_PRELOAD maps SoftHSM2 at exec instead, so both providers are
# mapped before attach; p11-kit then dlopens the same inode and its refcount
# rises, which is exactly the "two providers, one process" shape being tested.
set -eu
cd "$(dirname "$0")/../.."

PROXY=/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so
MODULE=/usr/lib/softhsm/libsofthsm2.so
WORK=target/matrix-proxy
WPID=
SPID=
NESTED_ROOT_PID=
NESTED_ROOT_START=
NESTED=
. scripts/lib.sh
require_non_root_caller

test -f "$PROXY" || { echo "SKIP: p11-kit proxy not installed at $PROXY"; exit 0; }
test -f "$MODULE" || { echo "SKIP: SoftHSM2 not installed at $MODULE"; exit 0; }
command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
mkdir -p "$WORK"

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    touch "$WORK/go" 2>/dev/null
    [ -z "$NESTED" ] || touch "$NESTED/finish"
    if [ -n "$NESTED_ROOT_PID" ] && root_process_matches_starttime "$NESTED_ROOT_PID" "$NESTED_ROOT_START"; then
        signal_verified_root_process INT "$NESTED_ROOT_PID" "$NESTED_ROOT_START"
        attempts=0
        while root_process_matches_starttime "$NESTED_ROOT_PID" "$NESTED_ROOT_START" && [ "$attempts" -lt 40 ]; do
            attempts=$((attempts + 1)); sleep 0.05
        done
        if root_process_matches_starttime "$NESTED_ROOT_PID" "$NESTED_ROOT_START"; then
            signal_verified_root_process KILL "$NESTED_ROOT_PID" "$NESTED_ROOT_START"
        fi
    fi
    [ -z "$WPID" ] || kill "$WPID" 2>/dev/null
    [ -z "$SPID" ] || kill "$SPID" 2>/dev/null
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

echo "=== build ==="
scripts/cargo.sh +1.88 build --locked --release --workspace --target-dir "$WORK/build"
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }
gcc -O0 -o "$WORK/harness" spike/harness.c -ldl

echo "=== softhsm token (private, disposable) ==="
export SOFTHSM2_CONF="$PWD/$WORK/softhsm2.conf"
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
softhsm2-util --init-token --free --label proxy --so-pin 1234 --pin 1234 >/dev/null

echo "=== p11-kit config: exactly one backend behind the proxy ==="
# XDG_CONFIG_HOME keeps this inside the worktree: no file under ~ or /etc is
# read or written. `user-config: only` makes p11-kit ignore the system module
# directory, so the proxy loads SoftHSM2 and nothing else.
export XDG_CONFIG_HOME="$PWD/$WORK/xdg"
rm -rf "$XDG_CONFIG_HOME"
mkdir -p "$XDG_CONFIG_HOME/pkcs11/modules"
printf 'user-config: only\n' > "$XDG_CONFIG_HOME/pkcs11/pkcs11.conf"
printf 'module: %s\n' "$MODULE" > "$XDG_CONFIG_HOME/pkcs11/modules/softhsm2.module"

echo "=== observe the proxy stack (manifest-free) ==="
rm -f "$WORK/go"
LD_PRELOAD="$MODULE" "$WORK/harness" "$PROXY" "$WORK/go" > "$WORK/workload.log" 2>&1 &
WPID=$!
wait_for_mapped_provider "$WPID" libsofthsm2.so
wait_for_mapped_provider "$WPID" p11-kit
sudo --preserve-env=SOFTHSM2_CONF --preserve-env=XDG_CONFIG_HOME \
    "$WORK/build/release/p11scope" profile --pid "$WPID" \
    --mode metrics --duration 20 -o "$WORK/observed.json" > "$WORK/profile.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/profile.log" aggregate-only metrics || {
    echo "--- observer log ---"
    cat "$WORK/profile.log"
    exit 1
}
touch "$WORK/go"
if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "workload failed: $status"; cat "$WORK/workload.log"; exit "$status"; fi
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "profiler failed: $status"; tail -n 20 "$WORK/profile.log"; exit "$status"; fi
tail -n 3 "$WORK/profile.log"
reclaim_root_output "$WORK/observed.json"

echo "=== verify: the proxy stack's two providers, kept apart ==="
python3 - "$WORK/observed.json" "$(readlink -f "$MODULE")" <<'PY'
import importlib.util, json, sys

spec = importlib.util.spec_from_file_location(
    "check_capture_evidence", "scripts/check-capture-evidence.py"
)
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)

doc = json.load(open(sys.argv[1]))
ev = doc["evidence"]

# The plan's capacity semantics are this lane's expected outcome, not a
# fallback. A real libp11-kit maps 64 static CK_FUNCTION_LIST_3_0 closures into
# the scanned image — thousands of decoded entries against the frozen 512-slot
# ceiling — so the proxy module is always discovered and always refused whole:
# its decode stays in history and it takes zero slots, while SoftHSM2 attaches
# directly within the budget and a target both providers publish is attached
# exactly once through it (plan:1120-1136, Task 6E refusal rules). No p11-kit
# module-directory scoping can change that: the closures are part of the
# mapped image, not of any backend it loads. `exact_capture_modules`, every
# count's attribution, the retained refused decode, and the sticky PARTIAL are
# all inside the oracle, where they have mutation lanes.
oracle.validate_proxy_capacity_fallback(doc, module_path=sys.argv[2])

module = doc["capture"]["modules"][0]
refused = ev["modules_skipped"][0]
called = sum(item["calls"] for item in doc["functions"])
print("proxy stack capacity refusal: OK")
print("  attached:", module["path"])
print("  slots:", ev["slots"], "probes:", ev["attached_probes"], "calls:", called)
print("  decoded entries:", ev["table_entries"], "over", len(ev["surfaces"]), "surfaces")
print("  refused whole:", refused)
PY

echo "=== nested function-list and interface-list exports ==="
NESTED=$(mktemp -d "$PWD/$WORK/nested-XXXXXX")
SRC=scripts/matrix/export-nesting-harness.c
sha256sum "$SRC" > "$NESTED/source.sha256"
for provider in 1 2; do
    gcc -m64 -std=c11 -O1 -Wall -Wextra -Werror -fPIC -shared -Wl,-Bsymbolic \
        "-DPROVIDER_ID=$provider" -o "$NESTED/provider-$provider.so" "$SRC"
done
gcc -m64 -std=c11 -O1 -Wall -Wextra -Werror -DNESTING_DRIVER -o "$NESTED/driver" "$SRC" -ldl
"$NESTED/driver" "$NESTED/provider-1.so" "$NESTED/provider-2.so" \
    "$NESTED/go" "$NESTED/finish" > "$NESTED/workload.log" 2>&1 &
WPID=$!
wait_for_mapped_provider "$WPID" provider-1.so
wait_for_mapped_provider "$WPID" provider-2.so
launch_root_recorded_process "$NESTED/observer.pid" "$NESTED/profile.log" \
    "$WORK/build/release/p11scope" profile --pid "$WPID" \
    --mode metrics --duration 10 -o "$NESTED/observed.json"
SPID=$ROOT_LAUNCH_PID
NESTED_ROOT_PID=$ROOT_PROCESS_PID
NESTED_ROOT_START=$ROOT_PROCESS_STARTTIME
wait_for_capture_ready "$NESTED/profile.log" aggregate-only metrics
touch "$NESTED/go"
attempts=0
while recording_launcher_active "$SPID" && [ "$attempts" -lt 600 ]; do
    attempts=$((attempts + 1)); sleep 0.05
done
[ "$attempts" -lt 600 ] || { echo "nested observer exceeded 30 seconds" >&2; exit 1; }
wait "$SPID"
SPID=
NESTED_ROOT_PID=
touch "$NESTED/finish"
wait "$WPID"
WPID=
reclaim_root_output "$NESTED/observed.json" "$NESTED/observer.pid"
grep -q '^NESTED_EXPORTS_DONE function_lists=2 interface_lists=2$' "$NESTED/workload.log"
python3 - "$NESTED/observed.json" "$NESTED" <<'PY'
import copy, importlib.util, json, sys
from collections import Counter

spec = importlib.util.spec_from_file_location("oracle", "scripts/check-capture-evidence.py")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
paths = {f"{sys.argv[2]}/provider-{index}.so" for index in (1, 2)}

def validate(doc):
    oracle.exact_metrics_schema(doc)
    oracle.exact_capture_modules(doc)
    ev = doc["evidence"]
    oracle.exact_counters(ev)
    assert ev["slots"] == 4 and ev["attached_probes"] == 8
    assert ev["table_entries"] == 136 and ev["completeness"] == "PARTIAL"
    assert ev["attach_failures"] == ev["modules_skipped"] == ev["skipped"] == []
    assert ev["in_flight_at_end"] == 0 and ev["provider_changed"] is False
    assert {module["path"] for module in doc["capture"]["modules"]} == paths
    assert len(ev["discovery"]) == 2
    for module in ev["discovery"]:
        assert module["path"] in paths and module["interfaces"] == 1
        assert module["tables"] == [{"entries": 68, "source": "scan", "version": [2, 40]}]
        assert len(module["objects"]) == 1
        target = module["objects"][0]
        assert all(target[key] == module[key] for key in ("path", "dev", "ino", "sha256"))
    assert Counter((s["source"], s["functions"], s["acquisition"], s["walk"]) for s in ev["surfaces"]) == Counter(
        [(f"{path} table 2.40", 68, "ok", "full") for path in paths]
        + [("interface[0] exact_standard", 68, "ok", "full")] * 2
    )
    called = [item for item in doc["functions"] if item["calls"]]
    assert len(called) == 2
    assert len({(tuple(item["module"]["dev"]), item["module"]["ino"]) for item in called}) == 2
    for item in called:
        assert item["names"] == ["C_GetFunctionList"] and item["calls"] == 1
        assert item["rv_counts"] == {"0x0000000000000000": 1}
        assert item["errors"] == item["in_flight"] == item["pending_returns"] == 0

doc = json.load(open(sys.argv[1]))
validate(doc)
for mutate in (
    lambda d: d["evidence"].update(discovery_state_failures=3),
    lambda d: d["evidence"]["discovery"][1].update(interfaces=0),
    lambda d: d["evidence"]["surfaces"].pop(),
    lambda d: d["evidence"]["discovery"][0].update(objects=[]),
    lambda d: d["evidence"]["discovery"][0].update(objects=d["evidence"]["discovery"][1]["objects"]),
    lambda d: next(item for item in d["functions"] if item["calls"]).update(calls=2),
):
    bad = copy.deepcopy(doc)
    mutate(bad)
    try:
        validate(bad)
    except AssertionError:
        continue
    raise AssertionError("nested export oracle accepted corrupted evidence")
print("nested FunctionList/InterfaceList: exact evidence and mutations OK")
PY
echo "=== proxy stack: ALL OK ==="

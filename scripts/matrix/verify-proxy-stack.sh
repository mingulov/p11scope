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
. scripts/lib.sh
require_non_root_caller

test -f "$PROXY" || { echo "SKIP: p11-kit proxy not installed at $PROXY"; exit 0; }
test -f "$MODULE" || { echo "SKIP: SoftHSM2 not installed at $MODULE"; exit 0; }
command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }

mkdir -p "$WORK"

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    touch "$WORK/go" 2>/dev/null
    [ -z "$WPID" ] || kill "$WPID" 2>/dev/null
    [ -z "$SPID" ] || kill "$SPID" 2>/dev/null
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

echo "=== build ==="
cargo +1.88 build --locked --release --workspace --target-dir "$WORK/build"
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

echo "=== proxy stack: ALL OK ==="

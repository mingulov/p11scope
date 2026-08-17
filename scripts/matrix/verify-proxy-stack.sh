#!/bin/sh
# Two PKCS#11 providers in one process: p11-kit's proxy module, with SoftHSM2
# configured behind it. No manifest — the memory scan finds both, and the point
# of the lane is that one capture keeps them apart: two modules with distinct
# sha256, every count attributed to the module that published the entry, and a
# target shared by both counted once (module_ambiguous).
#
# p11-kit loads its backends lazily, at C_Initialize — after the observer has
# attached, and this slice scans once at attach time (Slice 1b-2 adds live
# discovery). LD_PRELOAD maps SoftHSM2 at exec instead, so both providers are
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

echo "=== verify: two providers, kept apart ==="
python3 - "$WORK/observed.json" <<'PY'
import importlib.util, json, re, sys

spec = importlib.util.spec_from_file_location(
    "check_capture_evidence", "scripts/check-capture-evidence.py"
)
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)

doc = json.load(open(sys.argv[1]))
ev = doc["evidence"]
# capture.modules[] == evidence.discovery[], every count attributed to a
# declared module or explicitly ambiguous, every module hash-pinned.
oracle.exact_capture_modules(doc)

modules = doc["capture"]["modules"]
if len(modules) == 1:
    module = modules[0]
    assert "softhsm" in module["path"].lower(), module["path"]
    assert "p11-kit" not in module["path"].lower(), module["path"]
    assert len(ev["discovery"]) == 1, ev["discovery"]
    assert ev["discovery"][0]["sources"] == ["scan"], ev["discovery"]
    assert ev["authority"] == "hash-pinned", ev["authority"]
    assert ev["scan_unavailable"] is None, ev["scan_unavailable"]
    assert ev["completeness"] == "PARTIAL", ev["completeness"]
    assert ev["slots"] == 68, ev["slots"]
    assert ev["attached_probes"] == 136, ev["attached_probes"]
    assert ev["attach_failures"] == [], ev["attach_failures"]
    assert ev["module_ambiguous"] == 0, ev["module_ambiguous"]
    assert len(ev["modules_skipped"]) == 1, ev["modules_skipped"]
    refused = ev["modules_skipped"][0]
    assert "p11-kit" in refused["name"].lower(), refused
    match = re.fullmatch(
        r"module needs ([0-9]+) more of the 512 attach slots; 0 are in use "
        r"— refusing to attach a prefix",
        refused["reason"],
    )
    assert match and int(match.group(1)) > 512, refused
    assert len(doc["functions"]) == 68, len(doc["functions"])
    identity = (module["sha256"], tuple(module["dev"]), module["ino"])
    called = 0
    for item in doc["functions"]:
        assert item["module_ambiguous"] is False, item
        if not item["calls"]:
            continue
        called += item["calls"]
        owner = item["module"]
        assert owner is not None, item
        assert (owner["sha256"], tuple(owner["dev"]), owner["ino"]) == identity, item
    assert called > 0, "the SoftHSM2 backend handled no calls"
    print("proxy stack capacity fallback: OK")
    print("  module:", module["path"])
    print("  slots:", ev["slots"], "probes:", ev["attached_probes"], "calls:", called)
    print("  refused:", refused)
    sys.exit(0)

assert len(modules) == 2, [m["path"] for m in modules]
digests = {m["sha256"] for m in modules}
assert len(digests) == 2, f"the two providers share a digest: {digests}"
paths = sorted(m["path"] for m in modules)
assert any("softhsm" in p for p in paths), paths
assert any("p11-kit" in p or "p11kit" in p for p in paths), paths
assert all(m["sources"] == ["scan"] for m in ev["discovery"]), ev["discovery"]
assert ev["authority"] == "hash-pinned", ev["authority"]
assert ev["scan_unavailable"] is None, ev["scan_unavailable"]
assert ev["modules_skipped"] == [], ev["modules_skipped"]

# Every observed call is attributed, and both providers were observed: a
# capture that silently folded one into the other would show one owner here.
identities = {
    (m["sha256"], tuple(m["dev"]), m["ino"]): m["path"] for m in modules
}
observed, ambiguous = {}, 0
for item in doc["functions"]:
    if not item["calls"]:
        continue
    owner = item["module"]
    if owner is None:
        assert item["module_ambiguous"] is True, item
        ambiguous += 1
        continue
    key = (owner["sha256"], tuple(owner["dev"]), owner["ino"])
    assert key in identities, item
    observed.setdefault(identities[key], 0)
    observed[identities[key]] += item["calls"]

# A target both providers publish is one slot, not two: it is counted once and
# reported as ambiguous rather than attributed to a guess.
assert (ambiguous > 0) == (ev["module_ambiguous"] > 0), (ambiguous, ev["module_ambiguous"])
# One slot per {object, offset}: a shared target attached twice would push
# attached_probes past 2 per slot.
assert ev["attached_probes"] == 2 * ev["slots"], (ev["attached_probes"], ev["slots"])
assert len(doc["functions"]) == ev["slots"], (len(doc["functions"]), ev["slots"])

print("proxy stack: OK")
print("  modules:", paths)
print("  slots:", ev["slots"], "probes:", ev["attached_probes"],
      "module_ambiguous:", ev["module_ambiguous"])
print("  calls per provider:", observed)
assert len(observed) == 2, f"only one provider was ever observed: {observed}"
PY

echo "=== proxy stack: ALL OK ==="

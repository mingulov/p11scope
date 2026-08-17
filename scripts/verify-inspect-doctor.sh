#!/bin/sh
# Unprivileged contract lane: inspect finds a provider the target loaded, and
# doctor's verdict matches what this host can actually do. No sudo, no BPF.
#
# Two targets, both same-uid:
#   ptracer  — calls prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) before it
#              dlopens, so /proc/<pid>/mem is readable and the scan decodes
#              tables whatever kernel.yama.ptrace_scope is set to;
#   plain    — does not, so on a hardened host the scan is refused and only
#              /proc/<pid>/maps + .dynsym remain.
# The lane never asserts a fixed answer for either: it asserts that `doctor
# --pid` and `inspect --pid` agree about the same target. That is the claim
# ("doctor says what this host can do") and it holds at any ptrace_scope.
set -eu
cd "$(dirname "$0")/.."
MODULE=/usr/lib/softhsm/libsofthsm2.so
WORK=target/inspect
PTRACER_PID=
PLAIN_PID=
. scripts/lib.sh
require_non_root_caller
mkdir -p "$WORK"

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    touch "$WORK/go" 2>/dev/null
    [ -z "$PTRACER_PID" ] || kill "$PTRACER_PID" 2>/dev/null
    [ -z "$PLAIN_PID" ] || kill "$PLAIN_PID" 2>/dev/null
    [ -z "$PTRACER_PID" ] || wait "$PTRACER_PID" 2>/dev/null
    [ -z "$PLAIN_PID" ] || wait "$PLAIN_PID" 2>/dev/null
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }
cargo +1.88 build --locked --release --target-dir "$WORK/build"
P11SCOPE="$WORK/build/release/p11scope"

# The target dlopens the provider itself, so this lane also proves the scan
# sees a provider loaded by dlopen (not one the loader mapped at exec).
cat > "$WORK/target.py" <<'PY'
import ctypes, os, sys, time

if len(sys.argv) != 4:
    raise SystemExit("usage: target.py <module.so> <go-file> yes|no")
if sys.argv[3] == "yes":
    # PR_SET_PTRACER (0x59616d61) / PR_SET_PTRACER_ANY (-1): the documented Yama
    # escape hatch, so the lane needs no sysctl change and no privileges.
    ctypes.CDLL("libc.so.6", use_errno=True).prctl(
        0x59616D61, ctypes.c_ulong(2**64 - 1), 0, 0, 0
    )
ctypes.CDLL(sys.argv[1], mode=os.RTLD_NOW)
print("ready", flush=True)
while not os.path.exists(sys.argv[2]):
    time.sleep(0.05)
PY

start_target() {
    st_log="$WORK/$1.log"
    : > "$st_log"
    python3 "$WORK/target.py" "$MODULE" "$WORK/go" "$2" > "$st_log" 2>&1 &
    st_pid=$!
    st_attempt=0
    while [ "$st_attempt" -lt 200 ]; do
        grep -Fqx ready "$st_log" 2>/dev/null && { echo "$st_pid"; return 0; }
        kill -0 "$st_pid" 2>/dev/null || { echo "target $1 exited early" >&2; cat "$st_log" >&2; return 1; }
        st_attempt=$((st_attempt + 1))
        sleep 0.05
    done
    echo "target $1 never became ready" >&2
    return 1
}

rm -f "$WORK/go"
PTRACER_PID=$(start_target ptracer yes)
PLAIN_PID=$(start_target plain no)

for pid in "$PTRACER_PID" "$PLAIN_PID"; do
    echo "=== inspect --pid $pid ==="
    "$P11SCOPE" inspect --pid "$pid" --json > "$WORK/inspect-$pid.json"
    "$P11SCOPE" inspect --pid "$pid"
    echo "=== doctor --pid $pid ==="
    "$P11SCOPE" doctor --pid "$pid" > "$WORK/doctor-$pid.txt" 2>&1 || true
    grep -q "^verdict:" "$WORK/doctor-$pid.txt" || { echo "doctor printed no verdict"; exit 1; }
    python3 - "$WORK/inspect-$pid.json" "$WORK/doctor-$pid.txt" <<'PY'
import json, sys

doc = json.load(open(sys.argv[1]))
assert doc["schema"] == "pkcs11-scope/inspect/v1", doc["schema"]
paths = [m["path"] for m in doc["modules"]]
# Listing the provider needs only /proc/<pid>/maps and .dynsym, so it must
# hold on both targets whether or not the memory scan could run.
assert any(p.endswith("libsofthsm2.so") for p in paths), paths

verdict = [l for l in open(sys.argv[2]).read().splitlines() if l.startswith("verdict:")][-1]
scanned = doc["scan"]["status"] == "scanned"
assert scanned == ("memory scan available" in verdict), (doc["scan"], verdict)
if scanned:
    # The scan decoded the provider's own table, at the version SoftHSM2
    # publishes; a scan that "succeeded" and found nothing would be a gap.
    tables = [t for m in doc["modules"] if m["path"].endswith("libsofthsm2.so") for t in m["tables"]]
    assert tables, doc["modules"]
    assert all(t["entries"] > 0 for t in tables), tables
    print("inspect: OK", paths, [(t["version"], t["walk"], t["entries"]) for t in tables])
else:
    assert doc["scan"]["reason"], doc["scan"]
    print("inspect: OK (scan refused, maps-only)", paths, doc["scan"]["reason"])
PY
done

touch "$WORK/go"
wait "$PTRACER_PID" || true
wait "$PLAIN_PID" || true
PTRACER_PID=
PLAIN_PID=

echo "=== doctor (host only) ==="
"$P11SCOPE" doctor > "$WORK/doctor.txt" 2>&1 || true
cat "$WORK/doctor.txt"
echo
grep -q "^verdict:" "$WORK/doctor.txt" || { echo "doctor printed no verdict"; exit 1; }
# No --pid and no --cgroup: those two lanes must be reported n/a, never failed.
grep -q "^/proc/<pid>/maps .* n/a" "$WORK/doctor.txt" || { echo "doctor did not report maps n/a"; exit 1; }
grep -q "^cgroup path .* n/a" "$WORK/doctor.txt" || { echo "doctor did not report cgroup n/a"; exit 1; }

echo "=== inspect/doctor: ALL OK ==="

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

# This lane's oracle, in one place: inspect and doctor must agree about the
# same target, and the host lane must report the two absent scopes as n/a.
# `--self-test` runs the same assertions over synthetic documents and requires
# every claimed field to refuse a mutation, unprivileged.
assert_inspect_doctor() {
    python3 -I scripts/lane-inspect-doctor-oracle.py "$@"
}

if [ "${1-}" = "--self-test" ]; then
    [ "$#" -eq 1 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }
    assert_inspect_doctor --self-test
    echo "verify-inspect-doctor self-test: OK"
    exit 0
fi

MODULE=${P11SCOPE_PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}
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
scripts/cargo.sh +1.88 build --locked --release --target-dir "$WORK/build"
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
    assert_inspect_doctor "$WORK/inspect-$pid.json" "$WORK/doctor-$pid.txt"
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
assert_inspect_doctor --host "$WORK/doctor.txt"

echo "=== inspect/doctor: ALL OK ==="

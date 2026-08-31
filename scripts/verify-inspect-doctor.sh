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
    python3 - "$@" <<'PY'
import copy
import json
import sys


def oracle(document, doctor):
    assert document["schema"] == "pkcs11-scope/inspect/v1", document["schema"]
    paths = [module["path"] for module in document["modules"]]
    # Listing the provider needs only /proc/<pid>/maps and .dynsym, so it must
    # hold on both targets whether or not the memory scan could run.
    assert any(path.endswith("libsofthsm2.so") for path in paths), paths
    verdict = [line for line in doctor.splitlines() if line.startswith("verdict:")][-1]
    scanned = document["scan"]["status"] == "scanned"
    assert scanned == ("memory scan available" in verdict), (document["scan"], verdict)
    if scanned:
        provider = next(
            module
            for module in document["modules"]
            if module["path"].endswith("libsofthsm2.so")
        )
        tableless = {
            "subject": provider["path"],
            "reason": "no function table was found in its file-backed data; a table built at run time in .bss or on the heap is outside the memory scan's reach",
        }
        tableless_skips = [skip for skip in document.get("skipped", []) if skip == tableless]
        if provider["tables"]:
            assert not tableless_skips, document.get("skipped", [])
            assert all(table["entries"] > 0 for table in provider["tables"]), provider["tables"]
            return "inspect: OK", paths, [
                (table["version"], table["walk"], table["entries"])
                for table in provider["tables"]
            ]
        assert tableless_skips == [tableless], document.get("skipped", [])
        return "inspect: OK (runtime-built table)", paths, tableless["reason"]
    assert document["scan"]["reason"], document["scan"]
    return "inspect: OK (scan refused, maps-only)", paths, document["scan"]["reason"]


def host_oracle(doctor):
    lines = doctor.splitlines()
    assert [line for line in lines if line.startswith("verdict:")], doctor
    # No --pid and no --cgroup: those two lanes must be reported n/a, never failed.
    for name in ("/proc/<pid>/maps", "cgroup path"):
        assert any(
            line.startswith(name) and " n/a" in line for line in lines
        ), (name, doctor)


def mutate(document, path, value):
    mutated = copy.deepcopy(document)
    cursor = mutated
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return mutated


SCANNED = {
    "schema": "pkcs11-scope/inspect/v1",
    "scan": {"status": "scanned", "reason": None},
    "modules": [
        {
            "path": "/usr/lib/softhsm/libsofthsm2.so",
            "tables": [{"version": "2.40", "walk": "full", "entries": 68}],
        }
    ],
}
SCANNED_TABLELESS = {
    "schema": "pkcs11-scope/inspect/v1",
    "scan": {"status": "scanned", "reason": None},
    "modules": [
        {
            "path": "/usr/lib64/pkcs11/libsofthsm2.so",
            "tables": [],
        }
    ],
    "skipped": [
        {
            "subject": "/usr/lib64/pkcs11/libsofthsm2.so",
            "reason": "no function table was found in its file-backed data; a table built at run time in .bss or on the heap is outside the memory scan's reach",
        }
    ],
}
REFUSED = {
    "schema": "pkcs11-scope/inspect/v1",
    "scan": {"status": "refused", "reason": "ptrace_scope"},
    "modules": [{"path": "/usr/lib/softhsm/libsofthsm2.so", "tables": []}],
}
SCANNED_DOCTOR = "verdict: memory scan available\n"
REFUSED_DOCTOR = "verdict: maps only\n"
HOST_DOCTOR = (
    "/proc/<pid>/maps .................. n/a    no --pid\n"
    "cgroup path ....................... n/a    no --cgroup\n"
    "verdict: capture available\n"
)

if sys.argv[1] == "--self-test":
    oracle(SCANNED, SCANNED_DOCTOR)
    oracle(SCANNED_TABLELESS, SCANNED_DOCTOR)
    oracle(REFUSED, REFUSED_DOCTOR)
    host_oracle(HOST_DOCTOR)
    mutations = [
        ("inspect schema", SCANNED, mutate(SCANNED, ["schema"], "other/v1"), SCANNED_DOCTOR),
        (
            "provider listed",
            SCANNED,
            mutate(SCANNED, ["modules", 0, "path"], "/usr/lib/other.so"),
            SCANNED_DOCTOR,
        ),
        ("scan/doctor agreement", SCANNED, SCANNED, REFUSED_DOCTOR),
        ("refused/doctor agreement", REFUSED, REFUSED, SCANNED_DOCTOR),
        (
            "decoded tables",
            SCANNED,
            mutate(SCANNED, ["modules", 0, "tables"], []),
            SCANNED_DOCTOR,
        ),
        (
            "decoded entries",
            SCANNED,
            mutate(SCANNED, ["modules", 0, "tables"], [{"version": "2.40", "walk": "full", "entries": 0}]),
            SCANNED_DOCTOR,
        ),
        (
            "tableless reason",
            SCANNED_TABLELESS,
            mutate(SCANNED_TABLELESS, ["skipped", 0, "reason"], "other"),
            SCANNED_DOCTOR,
        ),
        (
            "tableless subject",
            SCANNED_TABLELESS,
            mutate(SCANNED_TABLELESS, ["skipped", 0, "subject"], "/usr/lib64/other.so"),
            SCANNED_DOCTOR,
        ),
        ("refusal reason", REFUSED, mutate(REFUSED, ["scan", "reason"], ""), REFUSED_DOCTOR),
    ]
    for label, _, document, doctor in mutations:
        try:
            oracle(document, doctor)
        except (AssertionError, KeyError, IndexError):
            continue
        raise SystemExit(f"mutation accepted: {label}")
    maps_line, cgroup_line, verdict_line = HOST_DOCTOR.splitlines(keepends=True)
    for label, doctor in [
        ("host verdict", maps_line + cgroup_line),
        ("maps n/a", cgroup_line + verdict_line),
        ("cgroup n/a", maps_line + verdict_line),
        (
            "maps failed not n/a",
            maps_line.replace(" n/a ", " FAIL ") + cgroup_line + verdict_line,
        ),
    ]:
        try:
            host_oracle(doctor)
        except (AssertionError, IndexError):
            continue
        raise SystemExit(f"mutation accepted: {label}")
    print("inspect/doctor oracle mutations rejected: OK")
    raise SystemExit(0)

if sys.argv[1] == "--host":
    host_oracle(open(sys.argv[2]).read())
    print("doctor host lane: OK")
    raise SystemExit(0)

print(*oracle(json.load(open(sys.argv[1])), open(sys.argv[2]).read()))
PY
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

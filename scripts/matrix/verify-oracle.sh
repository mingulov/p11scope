#!/bin/sh
# Phase 4 Task 7: pkcs11-check oracle diff. Every other script in this repo
# checks p11scope's capture against a workload WE wrote (spike/harness.c +
# spike/expected.txt). This is the first check against an INDEPENDENT
# implementation's own record of what it did: pkcs11-check
# (/home/user/src/m/pkcs11-check-ws/pkcs11-check), a separate,
# vendor-neutral PKCS#11 test client with its own ctypes binding and its
# own per-call CK_RV trace feature (docs/rv-trace-design.md, `--rv-trace`).
#
# Direction: oracle SUBSET-OF capture. For every (function, CK_RV) pair
# pkcs11-check's rv-trace logged, the capture must contain at least that
# many. The capture is allowed to hold MORE (bootstrap calls, pytest's own
# housekeeping) -- that is not a failure, just extra evidence. A capture
# missing a logged call IS a failure.
#
# Two documented pkcs11-check caveats shape this diff (both handled
# explicitly below, not silently filtered away):
#
# 1. rv-trace resets per test AFTER fixture bootstrap and C_Login
#    (fixtures.py's reset_call_log() sites, per docs/rv-trace-design.md
#    section 3) -- so every test's bootstrap-phase calls land in the
#    capture (p11scope sees literally everything) but never in the
#    oracle (pkcs11-check only records what happened after its own
#    reset). Because the assertion direction is oracle SUBSET-OF capture,
#    this is tolerable BY CONSTRUCTION: bootstrap calls can only ever add
#    entries on the capture side, which can never cause an oracle-side
#    key to be found missing. They show up below as informational
#    capture-only surplus, never as a failure.
# 2. `--isolation file` runs each test FILE in its own subprocess
#    (core/file_runner.py) -- many C_Initialize/C_Finalize cycles, many
#    PIDs, most of which do not exist yet when the observer attaches.
#    `--pid` cannot see any of that. This script uses --cgroup instead,
#    exactly like scripts/matrix/verify-fork-scope.sh: a systemd-run
#    --scope cgroup created before pkcs11-check is even exec'd, so every
#    subprocess it forks -- known or not at attach time -- inherits cgroup
#    membership and is captured by Task 1's descendant matching.
set -eu
cd "$(dirname "$0")/../.."

MODULE=/usr/lib/softhsm/libsofthsm2.so
PKCS11_CHECK_DIR=/home/user/src/m/pkcs11-check-ws/pkcs11-check
# Invoke the venv's own installed console script directly, NOT `uv run`.
# Measured directly while building this script: `uv` here is a snap
# package (/snap/bin/uv), and snap's confinement machinery (snap-confine)
# moves the process into its own systemd-managed cgroup within the same
# second it starts, independent of whatever cgroup it was launched under
# -- our target scope shows "Deactivated successfully" in the systemd
# journal almost immediately while the real work keeps running fine,
# just no longer inside the cgroup we're capturing. A plain venv
# interpreter (no snap involved) does not do this; verified it stays in
# the target cgroup for the full run. `uv sync` has already been run in
# $PKCS11_CHECK_DIR (its .venv exists) -- this script only ever reads it.
PKCS11_CHECK_BIN="$PKCS11_CHECK_DIR/.venv/bin/pkcs11-check"
WORK=target/matrix-oracle

command -v softhsm2-util >/dev/null || { echo "BLOCKED: softhsm2-util required"; exit 1; }
command -v systemd-run >/dev/null || { echo "BLOCKED: systemd-run required"; exit 1; }
sudo -n true 2>/dev/null || { echo "BLOCKED: passwordless sudo required"; exit 1; }
test -f "$MODULE" || { echo "BLOCKED: SoftHSM2 not installed at $MODULE"; exit 1; }
test -x "$PKCS11_CHECK_BIN" || { echo "BLOCKED: pkcs11-check venv not found/synced at $PKCS11_CHECK_BIN (run 'uv sync' in $PKCS11_CHECK_DIR)"; exit 1; }

mkdir -p "$WORK" "$WORK/reports"
rm -f "$WORK/reports/report.jsonl" "$WORK/reports/results.json"
UNIT="p11scope-oracle-$$"
CGROUP_PATH="/sys/fs/cgroup/system.slice/${UNIT}.scope"
LAUNCHER_PID=
PROFILE_PID=

cleanup() {
    status=$?
    trap - EXIT INT TERM
    [ -z "$PROFILE_PID" ] || sudo kill -TERM "$PROFILE_PID" >/dev/null 2>&1 || true
    [ -z "$LAUNCHER_PID" ] || kill -TERM "$LAUNCHER_PID" >/dev/null 2>&1 || true
    [ -z "$PROFILE_PID" ] || wait "$PROFILE_PID" 2>/dev/null || true
    [ -z "$LAUNCHER_PID" ] || wait "$LAUNCHER_PID" 2>/dev/null || true
    sudo systemctl stop "${UNIT}.scope" >/dev/null 2>&1 || true
    exit "$status"
}
. scripts/cleanup-traps.sh

echo "=== build product ==="
cargo build --release --workspace

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
softhsm2-util --init-token --free --label oracle --so-pin 1234 --pin 1234 >/dev/null

echo "=== discover ==="
./target/release/p11scope-discover --module "$MODULE" -o "$WORK/manifest.json"

# file_runner's resume/checkpoint state (core/file_runner.py) persists
# between invocations as .pkcs11-check-isolation-state[/-policy].json in
# $PKCS11_CHECK_DIR. Measured directly while building this script: a
# stale state file from an earlier run in the same directory makes a
# later run fold old, already-"passed" per-file results (from BEFORE this
# capture's attach window) into the new report.jsonl -- the oracle then
# claims calls the capture genuinely never saw during this run, which is
# a false FAIL, not a capture gap. A clean slate avoids it.
rm -f "$PKCS11_CHECK_DIR/.pkcs11-check-isolation-state.json" \
      "$PKCS11_CHECK_DIR/.pkcs11-check-isolation-policy.json"

echo "=== run pkcs11-check under a cgroup scope, attach-before-run ==="
echo "cgroup unit: ${UNIT}.scope"
rm -f "$WORK/go"
# --marker smoke: the fast slice (~27 tests / ~5s un-isolated); with
# --isolation file (one subprocess per test FILE) real wall time measured
# during development was ~90s for the full 284-file collection (most
# files deselect everything and still pay subprocess start-up). --duration
# 150 below gives headroom over that.
( sudo systemd-run --scope --unit="$UNIT" -- sh -c \
    "while [ ! -f '$PWD/$WORK/go' ]; do sleep 0.05; done; \
     cd '$PKCS11_CHECK_DIR' && exec env SOFTHSM2_CONF='$SOFTHSM2_CONF' '$PKCS11_CHECK_BIN' test \
        --module '$MODULE' --pin 1234 --slot 0 --marker smoke --isolation file --rv-trace \
        --output json --output-file '$PWD/$WORK/reports/results.json'" ) &
LAUNCHER_PID=$!
sleep 1     # let systemd-run establish the cgroup
test -d "$CGROUP_PATH" || { echo "cgroup was not created: $CGROUP_PATH"; exit 1; }

sudo target/release/p11scope profile --manifest "$WORK/manifest.json" \
    --cgroup "$CGROUP_PATH" \
    --mode metrics --duration 150 -o "$WORK/observed.json" \
    > "$WORK/profile.log" 2>&1 &
PROFILE_PID=$!
sleep 3     # let attach complete before pkcs11-check is released
touch "$WORK/go"
if wait "$LAUNCHER_PID"; then
    LAUNCHER_PID=
    LAUNCHER_RC=0
else
    LAUNCHER_RC=$?
    LAUNCHER_PID=
fi
if wait "$PROFILE_PID"; then
    PROFILE_PID=
else
    status=$?
    PROFILE_PID=
    echo "oracle profiler failed: $status"
    exit "$status"
fi
tail -n 15 "$WORK/profile.log"
# The observer ran under sudo, so its published report is root-owned 0600.
sudo chown "$(id -u):$(id -g)" "$WORK/observed.json"
test "$LAUNCHER_RC" -eq 0 || { echo "pkcs11-check exited nonzero ($LAUNCHER_RC) -- see $WORK/reports/results.json"; exit 1; }
test -s "$WORK/reports/report.jsonl" || { echo "report.jsonl was not produced"; exit 1; }

echo "=== oracle subset-of capture ==="
python3 - "$WORK/reports/report.jsonl" "$WORK/observed.json" <<'PY'
import json, sys


def evidence_oracle():
    """Load the canonical evidence oracle so gap counters live in one place."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_capture_evidence", "scripts/check-capture-evidence.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



report_path, observed_path = sys.argv[1], sys.argv[2]

# Oracle counts, keyed by (function, CK_RV hex). Sourced ONLY from
# "teardown"-phase report.jsonl records: per docs/rv-trace-design.md
# section 3, pkcs11_rv_trace is drained unconditionally onto the teardown
# TestReport for every test (pass, fail, xfail alike); a separate
# makereport hookwrapper ALSO copies the same trace onto the "call"-phase
# report for failed/xfail/xpass outcomes. Reading both would double-count
# any test that isn't a plain pass. Reading only "teardown" avoids that
# without losing any test this run's --marker smoke can produce (a hard
# crash has no teardown at all, but smoke selects no crash-inducing
# tests).
# Caveat 3 (found and investigated while building this script -- NOT one
# of the two documented upstream, and NOT a p11scope capture issue): a
# small, fixed set of report.jsonl teardown records carry a pkcs11_rv_trace
# that could not possibly be theirs. The one found on this run,
# TestInterfaceV32::test_v32_interface_negotiated, takes only
# `p11_interface_version: str` -- a plain, already-cached session-scoped
# string (fixtures.py:138-141) -- and its body is a single skip-or-assert
# with no PKCS11 handle in scope at all (testcases/test_interface.py:
# 124-128): it is physically incapable of making a C_* call. Its recorded
# trace exactly duplicates the immediately preceding test's
# (TestInterfaceV30::test_v30_encrypt_decrypt_aes) GenerateKey/
# EncryptInit/Encrypt/Encrypt/DecryptInit/Decrypt/Decrypt/DestroyObject
# sequence -- pkcs11-check's OWN rv-trace attribution, not p11scope's
# capture, attaches one physical call sequence to two adjacent node ids.
# Independent evidence this is the oracle's bug, not a capture gap:
# p11scope's function counts (aggregate BPF maps, the documented count
# authority, never subject to ring-buffer loss) show exactly ONE
# execution of that sequence -- matching test_v30 alone, exactly. Excluded
# by nodeid (not by pattern), so this stays narrow and goes inert on its
# own if pkcs11-check fixes the misattribution upstream.
KNOWN_ORACLE_MISATTRIBUTION_NODEIDS = {
    "src/pkcs11_check/testcases/test_interface.py::TestInterfaceV32::test_v32_interface_negotiated",
}

oracle = {}
oracle_tests = 0
excluded = 0
with open(report_path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("when") != "teardown":
            continue
        props = dict(rec.get("user_properties") or [])
        trace = props.get("pkcs11_rv_trace")
        if trace is None:
            continue
        if rec.get("nodeid") in KNOWN_ORACLE_MISATTRIBUTION_NODEIDS:
            excluded += 1
            continue
        oracle_tests += 1
        for entry in trace:
            key = (entry["fn"], f"0x{entry['rv'] & 0xffffffffffffffff:016x}")
            oracle[key] = oracle.get(key, 0) + 1

print(f"oracle: {oracle_tests} tests carried a CK_RV trace, {len(oracle)} distinct (function, CK_RV) pairs, {sum(oracle.values())} total calls logged")
if excluded:
    print(f"oracle: excluded {excluded} teardown record(s) matching a known oracle-side misattribution nodeid (see comment above; docs/notes/phase4-oracle.md)")

# Capture counts, keyed the same way, from the aggregate-map-sourced
# `functions` section (the count authority -- never subject to
# ring-buffer loss; see docs/schema/observed-profile-v1.md).
observed = json.load(open(observed_path))
capture = {}
capture_by_name = {}
for f in observed["functions"]:
    for name in f["names"]:
        capture_by_name[name] = capture_by_name.get(name, 0) + f["calls"]
        for rv_hex, count in f["rv_counts"].items():
            key = (name, rv_hex)
            capture[key] = capture.get(key, 0) + count

fail = 0
missing = []
for key, want in sorted(oracle.items()):
    got = capture.get(key, 0)
    if got < want:
        fn, rv = key
        print(f"FAIL oracle-only: {fn} {rv}: oracle logged {want}, capture has {got}")
        missing.append((fn, rv, want, got))
        fail = 1

if not fail:
    print("oracle subset-of capture: every (function, CK_RV) pair pkcs11-check logged is present in the capture at least as many times")

# Informational only: capture-only surplus. Expected and NOT a failure --
# this is exactly caveat 1 (bootstrap/C_Login calls before pkcs11-check's
# own rv-trace reset) plus ordinary pytest-plugin housekeeping the raw
# ctypes layer never routes through rv-trace at all (module load probing,
# etc). Listed for visibility only.
oracle_names = {fn for fn, _rv in oracle}
surplus_names = sorted(n for n in capture_by_name if n not in oracle_names)
print(f"informational: {len(surplus_names)} function names appear in the capture with zero oracle-logged calls (expected: bootstrap-only functions)")
for n in surplus_names[:20]:
    print(f"  capture-only: {n} calls={capture_by_name[n]}")
if len(surplus_names) > 20:
    print(f"  ... and {len(surplus_names) - 20} more")

ev = observed["evidence"]
print("evidence:", ev["attached_probes"], "probes,", ev["completeness"])
if ev["attached_probes"] == 0:
    print("no probes attached")
    fail = 1
try:
    evidence_oracle().terminal_capture_is_clean(ev)
except AssertionError as error:
    print(f"terminal evidence: {error}")
    fail = 1

sys.exit(fail)
PY

echo "=== oracle: ALL OK ==="

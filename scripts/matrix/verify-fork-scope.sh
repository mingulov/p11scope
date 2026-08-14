#!/bin/sh
# Phase 4 Task 8, part 1: fork scoping. A prefork-server-shape workload
# (scripts/matrix/fork-harness.c) forks N children BEFORE any PKCS#11 call
# is made by anyone -- the whole point is that the children do not exist as
# processes at the moment the observer attaches. Under --cgroup scope, the
# capture must still include every one of them, because cgroup membership
# is inherited across fork(): a child born after attach is still a
# descendant of the cgroup the observer is watching (Task 1's descendant
# matching is what makes this reach the exact right set of tasks, no more
# and no less).
#
# How the cgroup is created and populated: `systemd-run --scope --unit=X`
# creates a fresh transient cgroup (/sys/fs/cgroup/system.slice/X.scope)
# and enters it *before* running the given command -- so the cgroup exists,
# and p11scope can attach to it, before the harness process is even exec'd,
# let alone before it forks. The harness's own exec is gated behind a
# go-file busy-loop (same attach-before-run pattern as every other script
# in this matrix): the shell inside the scope blocks on the go-file, so
# neither the parent harness process nor any of its children make their
# first PKCS#11 call -- or exist at all, in the children's case -- until
# well after attach has completed. Plain `mkdir`+chown of a cgroup does
# NOT let an unprivileged user migrate itself in (verified while building
# this script: cgroup v2 process migration needs write access up the
# common-ancestor chain, not just the leaf cgroup.procs -- got EACCES);
# systemd-run sidesteps that because it talks to the system manager
# (running as root via sudo), which already has it.
#
# Part 2 (privilege measurement) is below the fork-scoping proof.
set -eu
cd "$(dirname "$0")/../.."

MODULE=/usr/lib/softhsm/libsofthsm2.so
WORK=target/matrix-fork
TRUST_DIR="$PWD/$WORK/trusted"
EXPECTED=scripts/matrix/fork-expected.txt
. scripts/trusted-p11scope.sh

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
command -v systemd-run >/dev/null || { echo "systemd-run required"; exit 1; }
command -v capsh >/dev/null || { echo "capsh required"; exit 1; }
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }

mkdir -p "$WORK"
UNIT="p11scope-fork-$$"
CGROUP_PATH="/sys/fs/cgroup/system.slice/${UNIT}.scope"
LAUNCHER_PID=
PROFILE_PID=
PRIV_PID=

cleanup() {
    status=$?
    trap - EXIT INT TERM
    [ -z "$PROFILE_PID" ] || sudo kill -TERM "$PROFILE_PID" >/dev/null 2>&1 || true
    [ -z "$LAUNCHER_PID" ] || kill -TERM "$LAUNCHER_PID" >/dev/null 2>&1 || true
    [ -z "$PRIV_PID" ] || kill -TERM "$PRIV_PID" >/dev/null 2>&1 || true
    [ -z "$PROFILE_PID" ] || wait "$PROFILE_PID" 2>/dev/null || true
    [ -z "$LAUNCHER_PID" ] || wait "$LAUNCHER_PID" 2>/dev/null || true
    [ -z "$PRIV_PID" ] || wait "$PRIV_PID" 2>/dev/null || true
    sudo systemctl stop "${UNIT}.scope" >/dev/null 2>&1 || true
    remove_trusted_p11scope "$TRUST_DIR"
    exit "$status"
}
. scripts/cleanup-traps.sh

echo "=== build product + fork-harness ==="
cargo build --release --workspace
stage_trusted_p11scope target/release/p11scope \
    target/release/p11scope-discover "$TRUST_DIR"
gcc -O0 -o "$WORK/fork-harness" scripts/matrix/fork-harness.c -ldl

echo "=== softhsm token (private, disposable) ==="
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
softhsm2-util --init-token --free --label forkscope --so-pin 1234 --pin 1234 >/dev/null

echo "=== discover ==="
./target/release/p11scope-discover --module "$MODULE" -o "$WORK/manifest.json"

echo "=== Part 1: fork-scoping capture ==="
echo "cgroup unit: ${UNIT}.scope"
rm -f "$WORK/go"
( sudo systemd-run --scope --unit="$UNIT" -- sh -c \
    "while [ ! -f '$PWD/$WORK/go' ]; do sleep 0.05; done; \
     exec env SOFTHSM2_CONF='$SOFTHSM2_CONF' '$PWD/$WORK/fork-harness' '$MODULE'" ) &
LAUNCHER_PID=$!
sleep 1     # let systemd-run establish the cgroup
test -d "$CGROUP_PATH" || { echo "cgroup was not created: $CGROUP_PATH"; exit 1; }

sudo "$TRUST_DIR/p11scope" profile --manifest "$WORK/manifest.json" \
    --provenance-module "$MODULE" --cgroup "$CGROUP_PATH" \
    --mode metrics --duration 20 -o "$WORK/observed.json" \
    > "$WORK/profile.log" 2>&1 &
PROFILE_PID=$!
sleep 3     # let attach complete -- neither the parent harness process nor
            # any child exists yet at this point; both are still blocked
            # behind the go-file wait, which is the whole point of this test
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
    echo "fork-scope profiler failed: $status"
    exit "$status"
fi
tail -n 15 "$WORK/profile.log"
test "$LAUNCHER_RC" -eq 0 || { echo "fork-harness (parent+children) failed, rc=$LAUNCHER_RC"; exit 1; }

echo "=== verify: summed counts across parent + all children match fork-expected.txt exactly ==="
python3 - "$WORK/observed.json" "$EXPECTED" <<'PY'
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


obs = json.load(open(sys.argv[1]))
counts = {}
for f in obs["functions"]:
    for n in f["names"]:
        counts[n] = counts.get(n, 0) + f["calls"]
fail = 0
for line in open(sys.argv[2]):
    name, want = line.split()
    got = counts.get(name, 0)
    if got != int(want):
        print(f"MISMATCH {name}: want {want}, got {got}")
        fail = 1
    else:
        print(f"ok {name}: {got}")
ev = obs["evidence"]
print("evidence:", ev["attached_probes"], "probes,", ev["completeness"])
if ev["attached_probes"] != 136:
    print(f"attached_probes: want 136, got {ev['attached_probes']}")
    fail = 1
try:
    evidence_oracle().terminal_capture_is_clean(ev)
except AssertionError as error:
    print(f"terminal evidence: {error}")
    fail = 1
sys.exit(fail)
PY
echo "fork-scoping: children that did not exist at attach time were fully captured, exact counts"

echo "=== Part 2: measured privileges (host) ==="
# A bare placeholder process is enough to probe attach privileges: with
# --pid, p11scope only needs a live pid to scope the attach to (the plain
# host-path manifest is read directly, not through /proc/<pid>/root --
# that indirection only exists for container/pod targets, see
# verify-docker.sh / verify-kind-pod.sh). Verified directly while building
# this script: attach succeeds against a bare `sleep`, with no PKCS#11
# call ever made by it.
sleep 30 &
PRIV_PID=$!

echo "--- unprivileged ---"
set +e
UNPRIV_OUT=$("$TRUST_DIR/p11scope" profile --manifest "$WORK/manifest.json" \
    --provenance-module "$MODULE" --pid "$PRIV_PID" --mode metrics --duration 1 2>&1)
UNPRIV_RC=$?
set -e
echo "$UNPRIV_OUT"
echo "exit code: $UNPRIV_RC"
test "$UNPRIV_RC" -ne 0 || { echo "expected unprivileged attach to fail, it exited 0"; exit 1; }
echo "$UNPRIV_OUT" | grep -q "required read lease" \
    || { echo "expected the root-owned provider lease to fail without CAP_LEASE"; exit 1; }

echo "--- CAP_BPF + CAP_PERFMON + CAP_LEASE (no CAP_SYS_ADMIN) ---"
set +e
CAPS_OUT=$(sudo capsh --caps="cap_bpf,cap_perfmon,cap_lease+eip cap_setpcap,cap_setuid,cap_setgid+ep" \
    --keep=1 --user="$(whoami)" --addamb=cap_bpf --addamb=cap_perfmon --addamb=cap_lease \
    -- -c "'$TRUST_DIR/p11scope' profile --manifest '$WORK/manifest.json' --provenance-module '$MODULE' --pid $PRIV_PID --mode metrics --duration 1 -o '$WORK/priv-bpf-perfmon.json'" 2>&1)
set -e
echo "$CAPS_OUT" | tail -5
ATTACHED=$(python3 -c "import json;print(json.load(open('$WORK/priv-bpf-perfmon.json'))['evidence']['attached_probes'])")
echo "attached_probes with CAP_BPF+CAP_PERFMON+CAP_LEASE: $ATTACHED"
# Measured, not assumed: on this kernel kernel.perf_event_paranoid=4 is an
# Ubuntu hardening level that blocks perf_event_open() for uprobes even
# with CAP_PERFMON, unlike the upstream-documented behavior. CAP_SYS_ADMIN
# is still required for attach; CAP_LEASE is carried separately for the
# root-owned provider. See docs/notes/phase4-privileges.md.
test "$ATTACHED" -eq 0 || { echo "expected 0 attached probes without CAP_SYS_ADMIN on this kernel, got $ATTACHED"; exit 1; }

echo "--- CAP_SYS_ADMIN + CAP_LEASE ---"
sudo capsh --caps="cap_sys_admin,cap_lease+eip cap_setpcap,cap_setuid,cap_setgid+ep" \
    --keep=1 --user="$(whoami)" --addamb=cap_sys_admin --addamb=cap_lease \
    -- -c "'$TRUST_DIR/p11scope' profile --manifest '$WORK/manifest.json' --provenance-module '$MODULE' --pid $PRIV_PID --mode metrics --duration 1 -o '$WORK/priv-sysadmin.json'" \
    > "$WORK/priv-sysadmin.log" 2>&1
tail -5 "$WORK/priv-sysadmin.log"
ATTACHED2=$(python3 -c "import json;print(json.load(open('$WORK/priv-sysadmin.json'))['evidence']['attached_probes'])")
COMPLETE2=$(python3 -c "import json;print(json.load(open('$WORK/priv-sysadmin.json'))['evidence']['completeness'])")
echo "attached_probes with CAP_SYS_ADMIN+CAP_LEASE: $ATTACHED2 ($COMPLETE2)"
test "$ATTACHED2" -eq 136 || { echo "expected 136 attached probes with CAP_SYS_ADMIN+CAP_LEASE, got $ATTACHED2"; exit 1; }
# Terminal snapshots are PARTIAL by construction since the drain became
# unprovable; the capability claim is that attach and capture worked, which
# attached_probes plus the absence of any concrete gap already proves.
test "$COMPLETE2" = "PARTIAL" || { echo "expected PARTIAL with CAP_SYS_ADMIN+CAP_LEASE, got $COMPLETE2"; exit 1; }
python3 - "$WORK/priv-sysadmin.json" <<'PY'
import importlib.util, json, sys

spec = importlib.util.spec_from_file_location(
    "check_capture_evidence", "scripts/check-capture-evidence.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.terminal_capture_is_clean(json.load(open(sys.argv[1]))["evidence"])
PY

kill "$PRIV_PID" >/dev/null 2>&1 || true
wait "$PRIV_PID" 2>/dev/null || true
PRIV_PID=

echo "=== fork-scope + privileges: ALL OK ==="
echo "expected hardened minimum on host for a root-owned provider: CAP_SYS_ADMIN+CAP_LEASE."
echo "docker/kind measurements (different code path -- /proc/<pid>/root of a"
echo "different-uid process): see docs/notes/phase4-privileges.md."

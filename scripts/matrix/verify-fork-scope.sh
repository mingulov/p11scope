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
EXPECTED=scripts/matrix/fork-expected.txt

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
command -v systemd-run >/dev/null || { echo "systemd-run required"; exit 1; }
command -v capsh >/dev/null || { echo "capsh required"; exit 1; }
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }

mkdir -p "$WORK"
UNIT="p11scope-fork-$$"
CGROUP_PATH="/sys/fs/cgroup/system.slice/${UNIT}.scope"

cleanup() {
    sudo systemctl stop "${UNIT}.scope" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== build product + fork-harness ==="
cargo build --release --workspace
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

sudo ./target/release/p11scope profile --manifest "$WORK/manifest.json" \
    --cgroup "$CGROUP_PATH" --mode metrics --duration 20 -o "$WORK/observed.json" \
    > "$WORK/profile.log" 2>&1 &
PROFILE_PID=$!
sleep 3     # let attach complete -- neither the parent harness process nor
            # any child exists yet at this point; both are still blocked
            # behind the go-file wait, which is the whole point of this test
touch "$WORK/go"
wait "$LAUNCHER_PID"
LAUNCHER_RC=$?
wait "$PROFILE_PID"
tail -n 15 "$WORK/profile.log"
test "$LAUNCHER_RC" -eq 0 || { echo "fork-harness (parent+children) failed, rc=$LAUNCHER_RC"; exit 1; }

echo "=== verify: summed counts across parent + all children match fork-expected.txt exactly ==="
python3 - "$WORK/observed.json" "$EXPECTED" <<'PY'
import json, sys
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
if ev["completeness"] != "COMPLETE":
    print(f"completeness: want COMPLETE, got {ev['completeness']!r}")
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
priv_cleanup() { kill "$PRIV_PID" >/dev/null 2>&1 || true; cleanup; }
trap priv_cleanup EXIT

echo "--- unprivileged ---"
set +e
UNPRIV_OUT=$(./target/release/p11scope profile --manifest "$WORK/manifest.json" \
    --pid "$PRIV_PID" --mode metrics --duration 1 2>&1)
UNPRIV_RC=$?
set -e
echo "$UNPRIV_OUT"
echo "exit code: $UNPRIV_RC"
test "$UNPRIV_RC" -ne 0 || { echo "expected unprivileged attach to fail, it exited 0"; exit 1; }
echo "$UNPRIV_OUT" | grep -q "Operation not permitted" \
    || { echo "expected 'Operation not permitted' in unprivileged failure text"; exit 1; }

echo "--- CAP_BPF + CAP_PERFMON only (no CAP_SYS_ADMIN) ---"
set +e
CAPS_OUT=$(sudo capsh --caps="cap_bpf,cap_perfmon+eip cap_setpcap,cap_setuid,cap_setgid+ep" \
    --keep=1 --user="$(whoami)" --addamb=cap_bpf --addamb=cap_perfmon \
    -- -c "./target/release/p11scope profile --manifest '$WORK/manifest.json' --pid $PRIV_PID --mode metrics --duration 1 -o '$WORK/priv-bpf-perfmon.json'" 2>&1)
set -e
echo "$CAPS_OUT" | tail -5
ATTACHED=$(python3 -c "import json;print(json.load(open('$WORK/priv-bpf-perfmon.json'))['evidence']['attached_probes'])")
echo "attached_probes with CAP_BPF+CAP_PERFMON only: $ATTACHED"
# Measured, not assumed: on this kernel kernel.perf_event_paranoid=4 is an
# Ubuntu hardening level that blocks perf_event_open() for uprobes even
# with CAP_PERFMON, unlike the upstream-documented behavior -- only
# CAP_SYS_ADMIN (or full root) gets through. See docs/notes/phase4-privileges.md.
test "$ATTACHED" -eq 0 || { echo "expected 0 attached probes with CAP_BPF+CAP_PERFMON alone on this kernel, got $ATTACHED"; exit 1; }

echo "--- CAP_SYS_ADMIN alone ---"
sudo capsh --caps="cap_sys_admin+eip cap_setpcap,cap_setuid,cap_setgid+ep" \
    --keep=1 --user="$(whoami)" --addamb=cap_sys_admin \
    -- -c "./target/release/p11scope profile --manifest '$WORK/manifest.json' --pid $PRIV_PID --mode metrics --duration 1 -o '$WORK/priv-sysadmin.json'" \
    > "$WORK/priv-sysadmin.log" 2>&1
tail -5 "$WORK/priv-sysadmin.log"
ATTACHED2=$(python3 -c "import json;print(json.load(open('$WORK/priv-sysadmin.json'))['evidence']['attached_probes'])")
COMPLETE2=$(python3 -c "import json;print(json.load(open('$WORK/priv-sysadmin.json'))['evidence']['completeness'])")
echo "attached_probes with CAP_SYS_ADMIN alone: $ATTACHED2 ($COMPLETE2)"
test "$ATTACHED2" -eq 136 || { echo "expected 136 attached probes with CAP_SYS_ADMIN alone, got $ATTACHED2"; exit 1; }
test "$COMPLETE2" = "COMPLETE" || { echo "expected COMPLETE with CAP_SYS_ADMIN alone, got $COMPLETE2"; exit 1; }

kill "$PRIV_PID" >/dev/null 2>&1 || true
wait "$PRIV_PID" 2>/dev/null || true

echo "=== fork-scope + privileges: ALL OK ==="
echo "measured minimum on host (--pid, same-uid target): CAP_SYS_ADMIN alone."
echo "docker/kind measurements (different code path -- /proc/<pid>/root of a"
echo "different-uid process): see docs/notes/phase4-privileges.md."

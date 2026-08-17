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
# stable FIFO barrier (the same attach-before-run pattern as every other script
# in this matrix): the shell inside the scope blocks in its `read` builtin, so
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
. scripts/lib.sh

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
    rm -f "$WORK/go"
    exit "$status"
}
. scripts/cleanup-traps.sh

echo "=== build product + fork-harness ==="
cargo +1.88 build --locked --release --workspace
gcc -O0 -o "$WORK/fork-harness" scripts/matrix/fork-harness.c -ldl
gcc -O0 -o "$WORK/harness" spike/harness.c -ldl

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
# This lane keeps its manifest, and must. Nothing has dlopened the provider when
# the observer attaches -- the parent harness has not been exec'd and the
# children do not exist yet, which is the whole point of the test -- so the
# memory scan has nothing in scope to find. A manifest is the only source that
# can describe a provider that is not mapped yet; the capture reports it as
# uncorroborated, and that is the honest reading. Live discovery of a module
# loaded after attach is Slice 1b-2.
./target/release/p11scope-discover --module "$MODULE" -o "$WORK/manifest.json"

echo "=== Part 1: fork-scoping capture ==="
echo "cgroup unit: ${UNIT}.scope"
rm -f "$WORK/go"
mkfifo "$WORK/go"
( sudo systemd-run --scope --unit="$UNIT" -- sh -c \
    "read -r _ < '$PWD/$WORK/go'; \
     exec env SOFTHSM2_CONF='$SOFTHSM2_CONF' '$PWD/$WORK/fork-harness' '$MODULE'" ) &
LAUNCHER_PID=$!
sleep 1     # let systemd-run establish the cgroup
test -d "$CGROUP_PATH" || { echo "cgroup was not created: $CGROUP_PATH"; exit 1; }

sudo target/release/p11scope profile --manifest "$WORK/manifest.json" \
    --cgroup "$CGROUP_PATH" \
    --mode metrics --duration 20 -o "$WORK/observed.json" \
    > "$WORK/profile.log" 2>&1 &
PROFILE_PID=$!
wait_for_capture_ready "$WORK/profile.log" aggregate-only metrics
# Neither the parent harness process nor any child exists yet; the stable shell
# generation is still blocked in its builtin read.
printf '\n' > "$WORK/go"
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
reclaim_root_output "$WORK/observed.json"
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
    evidence_oracle().terminal_capture_is_clean(ev, uncorroborated=1)
except AssertionError as error:
    print(f"terminal evidence: {error}")
    fail = 1
sys.exit(fail)
PY
echo "fork-scoping: children that did not exist at attach time were fully captured, exact counts"

echo "=== Part 2: measured privileges (host) ==="
# Re-measured for Slice 1b-1, because discovery changed what privileges are for.
# There are now two separable questions, and one capability set no longer
# answers both:
#
#   attach  -- load the BPF object and open the uprobes;
#   scan    -- read /proc/<pid>/mem to find the provider's tables.
#
# The target below has *mapped* SoftHSM2 and is waiting on a go-file, so the
# scan has something real to find, and it is a same-uid non-descendant of every
# observer started here -- the case Yama actually governs. CAP_LEASE is gone
# from both sets: the read-lease requirement was removed in Slice 1a, and the
# earlier runs granted it without measuring its absence.
echo "kernel.yama.ptrace_scope   = $(cat /proc/sys/kernel/yama/ptrace_scope)"
echo "kernel.perf_event_paranoid = $(cat /proc/sys/kernel/perf_event_paranoid)"
PTRACE_SCOPE=$(cat /proc/sys/kernel/yama/ptrace_scope)
PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid)

rm -f "$WORK/priv-go"
"$WORK/harness" "$MODULE" "$WORK/priv-go" > "$WORK/priv-workload.log" 2>&1 &
PRIV_PID=$!
wait_for_mapped_provider "$PRIV_PID" libsofthsm2.so

# `capsh --caps=... --user=...` then runs p11scope with exactly that set, as an
# ordinary same-uid process. Prints "<probes> <scan_unavailable>" for the run,
# or "- -" when it produced no document at all.
measure_privileges() {
    mp_label=$1
    mp_caps=$2
    mp_amb=$3
    mp_out="$WORK/priv-$mp_label.json"
    shift 3
    rm -f "$mp_out"
    set +e
    sudo capsh --caps="$mp_caps" --keep=1 --user="$(whoami)" $mp_amb \
        -- -c "'$PWD/target/release/p11scope' profile $* --pid $PRIV_PID \
               --mode metrics --duration 1 -o '$mp_out'" \
        > "$WORK/priv-$mp_label.log" 2>&1
    mp_rc=$?
    set -e
    if [ -s "$mp_out" ]; then
        python3 - "$mp_out" <<'MEASURE'
import json, sys
ev = json.load(open(sys.argv[1]))["evidence"]
print(ev["attached_probes"], ev["scan_unavailable"] or "none")
MEASURE
    else
        echo "- - (exit $mp_rc)"
    fi
}

echo "--- unprivileged, manifest-free ---"
set +e
UNPRIV_OUT=$(target/release/p11scope profile --pid "$PRIV_PID" \
    --mode metrics --duration 1 2>&1)
UNPRIV_RC=$?
set -e
echo "$UNPRIV_OUT" | tail -5
echo "exit code: $UNPRIV_RC"
test "$UNPRIV_RC" -ne 0 || { echo "expected unprivileged attach to fail, it exited 0"; exit 1; }
echo "$UNPRIV_OUT" | grep -Eq 'Operation not permitted|Permission denied' \
    || { echo "unprivileged attach failed for an unexpected reason"; exit 1; }

echo "--- measured capability matrix (probes, scan) ---"
BPF_PERFMON=$(measure_privileges bpf-perfmon \
    "cap_bpf,cap_perfmon+eip cap_setpcap,cap_setuid,cap_setgid+ep" \
    "--addamb=cap_bpf --addamb=cap_perfmon" --manifest "$WORK/manifest.json")
SYSADMIN=$(measure_privileges sysadmin \
    "cap_sys_admin+eip cap_setpcap,cap_setuid,cap_setgid+ep" \
    "--addamb=cap_sys_admin" --manifest "$WORK/manifest.json")
SYSADMIN_SCAN=$(measure_privileges sysadmin-scan \
    "cap_sys_admin+eip cap_setpcap,cap_setuid,cap_setgid+ep" \
    "--addamb=cap_sys_admin")
SYSADMIN_PTRACE=$(measure_privileges sysadmin-ptrace \
    "cap_sys_admin,cap_sys_ptrace+eip cap_setpcap,cap_setuid,cap_setgid+ep" \
    "--addamb=cap_sys_admin --addamb=cap_sys_ptrace")
printf '%-34s %s\n' \
    "CAP_BPF+CAP_PERFMON, manifest"   "$BPF_PERFMON" \
    "CAP_SYS_ADMIN, manifest"         "$SYSADMIN" \
    "CAP_SYS_ADMIN, scan"             "$SYSADMIN_SCAN" \
    "CAP_SYS_ADMIN+PTRACE, scan"      "$SYSADMIN_PTRACE"
echo "(columns: attached_probes, evidence.scan_unavailable; measured at"
echo " ptrace_scope=$PTRACE_SCOPE perf_event_paranoid=$PARANOID)"

# Measured, not assumed. On this kernel perf_event_paranoid=4 is an Ubuntu
# hardening level that blocks perf_event_open() for uprobes even with
# CAP_PERFMON, unlike the upstream-documented behaviour: CAP_SYS_ADMIN is
# required for attach. See docs/notes/phase4-privileges.md.
ATTACHED=${BPF_PERFMON%% *}
test "$ATTACHED" = 0 || { echo "expected 0 attached probes without CAP_SYS_ADMIN on this kernel, got $ATTACHED"; exit 1; }
ATTACHED2=${SYSADMIN%% *}
test "$ATTACHED2" -eq 136 || { echo "expected 136 attached probes with CAP_SYS_ADMIN, got $ATTACHED2"; exit 1; }
# Not `terminal_capture_is_clean`: a deliberately capability-restricted observer
# is not a clean-capture lane, and pretending otherwise would either weaken that
# shared oracle or hide the very gap being measured. What must hold is narrower
# and stated here -- every probe attached, nothing failed to attach, and the
# document says plainly which half of discovery the missing capability cost.
python3 - "$WORK/priv-sysadmin.json" <<'PY'
import json, sys

evidence = json.load(open(sys.argv[1]))["evidence"]
assert evidence["completeness"] == "PARTIAL", evidence["completeness"]
assert evidence["attach_failures"] == [], evidence["attach_failures"]
assert evidence["attached_probes"] == 136, evidence["attached_probes"]
assert evidence["authority"] == "hash-pinned", evidence["authority"]
assert evidence["event_loss"] == 0, evidence["event_loss"]
# Whatever the scan could or could not do, it is named, never silently absent.
scan, uncorroborated = evidence["scan_unavailable"], evidence["discovery_uncorroborated"]
assert (scan is not None) == (uncorroborated == 1), (scan, uncorroborated)
print(f"CAP_SYS_ADMIN + manifest: 136 probes, scan={scan or 'ok'}")
PY

# The scan half, stated as a rule rather than a fixed answer, so it holds at any
# ptrace_scope: CAP_SYS_PTRACE must never make the scan *worse*, and where Yama
# is enforcing, it is what makes the difference.
SCAN_ADMIN=${SYSADMIN_SCAN#* }
SCAN_PTRACE=${SYSADMIN_PTRACE#* }
test "$SCAN_PTRACE" = none || {
    echo "CAP_SYS_ADMIN+CAP_SYS_PTRACE still could not scan: $SCAN_PTRACE"
    exit 1
}
if [ "$PTRACE_SCOPE" -ge 1 ] && [ "$SCAN_ADMIN" = none ]; then
    echo "note: CAP_SYS_ADMIN alone scanned a same-uid non-descendant at"
    echo "      ptrace_scope=$PTRACE_SCOPE -- record this, it is not what Yama documents"
fi

touch "$WORK/priv-go"
wait "$PRIV_PID" || true
kill "$PRIV_PID" >/dev/null 2>&1 || true
wait "$PRIV_PID" 2>/dev/null || true
PRIV_PID=

echo "=== fork-scope + privileges: ALL OK ==="
echo "measured minimum on host: CAP_SYS_ADMIN to attach; the memory scan"
echo "additionally needs ptrace access to the target (CAP_SYS_PTRACE, or"
echo "ptrace_scope=0, or a descendant). CAP_LEASE is neither granted nor needed."
echo "docker/kind measurements (different code path -- /proc/<pid>/root of a"
echo "different-uid process): see docs/notes/phase4-privileges.md."

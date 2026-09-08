#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
ABI_ROUTING_DRIVER_LIBRARY_ONLY=1 . scripts/matrix/verify-abi-routing.sh

fail() { echo "FAIL: $*" >&2; exit 1; }

# These subprocess modes make $$ the actual interrupted driver, allowing the
# production committed-transfer and pending-ACK trap boundaries to be tested.
if [ "${1:-}" = --interrupt ]; then
    mode=$2 case_parent=$3 shim_dir=$4
    PATH=$shim_dir:$PATH
    export PATH
    abi_prepare_evidence_root "$case_parent/evidence" || exit 91
    EVIDENCE=$ABI_EVIDENCE_PIN WORK=$EVIDENCE/work
    mkdir -m 700 "$WORK"
    target=$WORK/target
    cat >"$target" <<'SH'
#!/bin/sh
sleep 30
SH
    chmod 700 "$target"
    ABI_RUNTIME_DURATION=10
    trap abi_driver_cleanup EXIT
    trap 'exit 143' TERM
    if [ "$mode" = committed ]; then
        abi_committed_transfer_hook() { kill -TERM "$$"; }
    else
        ABI_ROUTING_REAL_HELPER=$RECORDED_PROCESS_EXEC
        ABI_ROUTING_ACK_MODE=block
        ABI_ROUTING_ACK_BLOCK_SECONDS=2
        RECORDED_PROCESS_EXEC=$PWD/tests/fixtures/abi-routing/fail-ack.py
        export ABI_ROUTING_REAL_HELPER ABI_ROUTING_ACK_MODE ABI_ROUTING_ACK_BLOCK_SECONDS
    fi
    abi_launch_variant_runtime "$mode" "$target" "$EVIDENCE/$mode" "$EVIDENCE/$mode.log" a b c d
    exit 92
fi

test_parent=$(mktemp -d "$PWD/.abi-routing-driver.XXXXXX")
trap 'rm -rf -- "$test_parent"' EXIT HUP INT TERM
shim_dir=$test_parent/shim
mkdir -m 700 "$shim_dir"
ln -s "$PWD/tests/fixtures/abi-routing/fail-ack.py" "$shim_dir/sudo"

# A canonical caller-owned 0700 parent is accepted and retained by identity.
test_root=$test_parent/evidence
abi_prepare_evidence_root "$test_root" || fail private-root
mv -- "$test_root" "$test_parent/original"
mkdir -m 700 -- "$test_root"
printf foreign >"$test_root/sentinel"
printf retained >"$ABI_EVIDENCE_PIN/marker"
[ -f "$test_parent/original/marker" ] || fail pinned-root-lost
[ ! -e "$test_root/marker" ] || fail replacement-selected
[ "$(cat "$test_root/sentinel")" = foreign ] || fail replacement-mutated
exec 8<&-

mkdir -m 755 "$test_parent/public"
abi_prepare_evidence_root "$test_parent/public/evidence" && fail public-parent-accepted
mkdir -m 700 "$test_parent/private"
ln -s "$test_parent/private" "$test_parent/link"
abi_prepare_evidence_root "$test_parent/link/evidence" && fail symlink-parent-accepted

# All remaining cases use the production root-launch function, pinned WORK
# PIDFILE construction, exact timeout layout, and a distinct same-UID sudo shim.
launch_parent=$test_parent/launch
mkdir -m 700 "$launch_parent"
abi_prepare_evidence_root "$launch_parent/evidence" || fail launch-evidence
EVIDENCE=$ABI_EVIDENCE_PIN WORK=$EVIDENCE/work
mkdir -m 700 "$WORK"
target=$WORK/native-target
cat >"$target" <<'SH'
#!/usr/bin/env python3
import os, signal, sys, time
name = sys.argv[1]
if name.endswith("nonzero"):
    raise SystemExit(7)
if name.endswith("success"):
    raise SystemExit(0)
if name.endswith("running") or name.endswith("stale"):
    raw = open(f"/proc/{os.getpid()}/stat", "rb").read().rsplit(b") ", 1)[1].split()
    with open(name + ".target", "w", encoding="ascii") as stream:
        stream.write(f"{os.getpid()} {int(raw[19])}\n")
    if name.endswith("running"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(30)
    raise SystemExit(0)
raise SystemExit(90)
SH
chmod 700 "$target"
old_path=$PATH
PATH=$shim_dir:$PATH
export PATH
ABI_RUNTIME_DURATION=3

ABI_ROUTING_SUDO_POST_WAIT=0.5
export ABI_ROUTING_SUDO_POST_WAIT
abi_launch_variant_runtime natural "$target" "$EVIDENCE/nonzero" "$EVIDENCE/natural.log" a b c d || fail natural-launch
[ "$ABI_RUNTIME_LAUNCH_PID" -ne "$ABI_RUNTIME_PROCESS_PID" ] || fail roles-not-distinct
attempt=0
while [ "$ABI_RUNTIME_PROCESS_OWNED" -eq 1 ] && [ "$attempt" -lt 100 ]; do
    abi_refresh_runtime_ownership || refresh_status=$?
    attempt=$((attempt + 1))
    sleep 0.01
done
[ "$ABI_RUNTIME_PROCESS_OWNED" -eq 0 ] || fail root-completion-not-observed
[ "$ABI_RUNTIME_LAUNCH_OWNED" -eq 1 ] || fail wrapper-cleared-with-root
abi_wait_runtime || fail natural-wait
[ "$ABI_RUNTIME_STATUS" -eq 7 ] || fail natural-status
[ "$ABI_RUNTIME_OWNED" -eq 0 ] || fail natural-custody
unset ABI_ROUTING_SUDO_POST_WAIT

abi_launch_variant_runtime success "$target" "$EVIDENCE/success" "$EVIDENCE/success.log" a b c d || fail sequential-success-launch
abi_wait_runtime || fail sequential-success-wait
[ "$ABI_RUNTIME_STATUS" -eq 0 ] || fail sequential-success-status

abi_launch_variant_runtime running "$target" "$EVIDENCE/running" "$EVIDENCE/running.log" a b c d || fail running-launch
attempt=0
while [ ! -s "$EVIDENCE/running.target" ] && [ "$attempt" -lt 100 ]; do attempt=$((attempt + 1)); sleep 0.02; done
[ -s "$EVIDENCE/running.target" ] || fail running-target-ready
read -r running_pid running_start <"$EVIDENCE/running.target"
abi_stop_runtime || fail running-stop
[ "$ABI_RUNTIME_OWNED" -eq 0 ] || fail running-custody
if recording_launcher_active "$running_pid" "$running_start"; then fail contained-target-live; else running_state=$?; fi
[ "$running_state" -eq 1 ] || fail contained-target-unknown

# Failed ACK uses the actual root path and must finish pending custody.
real_helper=$RECORDED_PROCESS_EXEC
ABI_ROUTING_REAL_HELPER=$real_helper ABI_ROUTING_ACK_MODE=fail
export ABI_ROUTING_REAL_HELPER ABI_ROUTING_ACK_MODE
RECORDED_PROCESS_EXEC=$PWD/tests/fixtures/abi-routing/fail-ack.py
abi_launch_variant_runtime noack "$target" "$EVIDENCE/success" "$EVIDENCE/noack.log" a b c d && fail missing-ack-accepted
[ "$ABI_RUNTIME_ACQUIRING" -eq 0 ] || fail missing-ack-acquiring
[ "$ABI_RUNTIME_OWNED" -eq 0 ] || fail missing-ack-runtime-owned
[ -z "${ROOT_RECORD_IDENTITY:-}" ] || fail missing-ack-pending
RECORDED_PROCESS_EXEC=$real_helper

# An unresolved tuple refuses a sequential launch before mutating any custody.
abi_launch_variant_runtime stale "$target" "$EVIDENCE/stale" "$EVIDENCE/stale.log" a b c d || fail stale-launch
saved_launch_pid=$ABI_RUNTIME_LAUNCH_PID saved_launch_start=$ABI_RUNTIME_LAUNCH_STARTTIME
saved_process_pid=$ABI_RUNTIME_PROCESS_PID saved_process_start=$ABI_RUNTIME_PROCESS_STARTTIME
saved_pidfile=$ABI_RUNTIME_PIDFILE
ABI_RUNTIME_LAUNCH_STARTTIME=$((saved_launch_start + 1))
abi_wait_runtime && fail stale-generation-wait
abi_launch_variant_runtime forbidden "$target" "$EVIDENCE/success" "$EVIDENCE/forbidden.log" a b c d && fail unresolved-launch-accepted
[ "$ABI_RUNTIME_LAUNCH_PID:$ABI_RUNTIME_PROCESS_PID:$ABI_RUNTIME_PIDFILE" = "$saved_launch_pid:$saved_process_pid:$saved_pidfile" ] || fail unresolved-tuple-overwritten
recording_launcher_active "$saved_process_pid" "$saved_process_start" || fail original-process-not-live
ABI_RUNTIME_LAUNCH_STARTTIME=$saved_launch_start
abi_stop_runtime || fail stale-cleanup

# Committed transfer interrupted before caller publication is adopted and
# contained by cleanup. The durable root identity must no longer be live.
committed_parent=$test_parent/committed
mkdir -m 700 "$committed_parent"
committed_status=0
sh "$0" --interrupt committed "$committed_parent" "$shim_dir" || committed_status=$?
[ "$committed_status" -eq 143 ] || fail committed-interrupt-status
read -r committed_pid committed_start <"$committed_parent/evidence/work/run-committed.pid"
if recording_launcher_active "$committed_pid" "$committed_start"; then fail committed-process-live; else committed_state=$?; fi
[ "$committed_state" -eq 1 ] || fail committed-process-unknown
grep -q '^result=NONPASS$' "$committed_parent/evidence/driver.status" || fail committed-receipt

# A TERM during blocked ACK exercises pending finalization through the same
# actual root-launch function. Only the direct driver child is signalled here.
pending_parent=$test_parent/pending
mkdir -m 700 "$pending_parent"
sh "$0" --interrupt pending "$pending_parent" "$shim_dir" &
pending_driver=$!
attempt=0
while ! find "$pending_parent" -name launcher.self -print -quit | grep -q .; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 100 ] || fail pending-ready
    sleep 0.02
done
kill -TERM "$pending_driver" || fail pending-signal
pending_status=0
wait "$pending_driver" || pending_status=$?
[ "$pending_status" -eq 143 ] || fail pending-interrupt-status
grep -q '^result=NONPASS$' "$pending_parent/evidence/driver.status" || fail pending-receipt

PATH=$old_path
export PATH
exec 8<&-
echo 'PASS: abi-routing production-path driver custody and launcher behavior'

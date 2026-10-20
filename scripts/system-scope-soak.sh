#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# system-scope-soak.sh — the soak vehicle for the acceptance manifest's
# soak.* cells (soak.1800s is required for the bounded release claim).
#
# One long pid-scope metrics capture of a continuous paced owned workload
# against the INSTALLED observer artifact, with independent workload/loss
# accounting (workload TRUTH + epoch lines joined to the observer report
# by system-scope-measure.py) and resource accounting (the /proc sampler
# trace), evaluated by system-scope-soak-oracle.py into a verdict plus the
# p11scope/test-execution/v1 execution receipt the manifest consumes.
# Pid scope is deliberate: only per-PID capture gives the exact
# generated==observed denominator a soak gate can check.
#
# Usage (live 30-minute qualification; run under the privileged lock):
#   flock /var/tmp/p11scope-ws-tmp/privileged.lock \
#     scripts/system-scope-soak.sh --cell soak.1800s \
#       --installed /opt/p11scope/bin/p11scope --work /var/tmp/soak-1800s
# Dry-run wiring trial (unprivileged, short horizon, stub observer):
#   scripts/system-scope-soak.sh --cell soak.1800s --dry-run \
#     --observer-stub scripts/fixtures/soak-observer-stub.py \
#     --horizon 8 --epoch-s 2 --epoch-calls 5 --pace-us 350000 \
#     --work /var/tmp/p11scope-ws-tmp/wave12-soakrunner/trial-green
#
# Pre-free rule: this script never invokes cargo and performs no builds
# beyond the lane-free gcc workload compile. Build and install the
# candidate first, FREE the cargo lane, then start the run; it refuses
# when the lane is busy at start, and the controller keeps heavy builds
# off the host until the window closes (a concurrent build corrupts the
# resource accounting and risks the attach). Live mode additionally
# requires an ancestor holding the privileged lock (the bench-count
# recipe); it never nests qualify-release-matrix.sh or any other lane.
# No --self-test: the privileged body never runs hosted (see the UNRUN
# line); the oracle's --self-test plus dry-run trials prove the gates.
#
# Tuning rule (fail-closed): the paced workload estimate must cover
# 85%..97% of the horizon, so epochs provably span the window yet the
# workload always finishes inside the capture. Epochs must divide the
# horizon evenly. --require-duration (default: the horizon) is the
# oracle's duration floor and is recorded in run.json; a short trial
# receipt carries its short window and the verifier refuses it for the
# 1800s cell. --stub-arg (repeatable, dry-run only) forwards extra stub
# argv for red-leg trials and is recorded verbatim in run.json.
set -eu
cd "$(dirname "$0")/.."
. scripts/lib.sh

CELL=
HORIZON=
REQUIRE_DURATION=
EPOCH_S=60
EPOCH_CALLS=570
PACE_US=100000
SEED=1
WORK=/var/tmp/p11scope-system-scope-soak
INSTALLED=
DRY_RUN=0
OBSERVER_STUB=
STUB_ARGS=
KERNEL_PROFILE=current/default
TEST_ID=
SOURCE_MODULE=/usr/lib/softhsm/libsofthsm2.so
MODULE=
LOCK=${LOCK:-/var/tmp/p11scope-ws-tmp/privileged.lock}
CARGO_LANE=${CARGO_LANE:-/var/tmp/p11scope-ws-tmp/v040-cargo-lane.lock}
# Capture the exact invocation before the parse loop consumes "$@" — this
# argv becomes the manifest execution row's command.
HARNESS_ARGV_JSON=$(python3 -I -c "import json,sys; print(json.dumps(sys.argv[1:]))" "$0" "$@")

while [ "$#" -gt 0 ]; do
    case "$1" in
        --cell) CELL=$2; shift 2 ;;
        --horizon) HORIZON=$2; shift 2 ;;
        --require-duration) REQUIRE_DURATION=$2; shift 2 ;;
        --epoch-s) EPOCH_S=$2; shift 2 ;;
        --epoch-calls) EPOCH_CALLS=$2; shift 2 ;;
        --pace-us) PACE_US=$2; shift 2 ;;
        --seed) SEED=$2; shift 2 ;;
        --work) WORK=$2; shift 2 ;;
        --installed) INSTALLED=$2; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --observer-stub) OBSERVER_STUB=$2; shift 2 ;;
        --stub-arg) STUB_ARGS="$STUB_ARGS $2"; shift 2 ;;
        --kernel-profile) KERNEL_PROFILE=$2; shift 2 ;;
        --test-id) TEST_ID=$2; shift 2 ;;
        -h|--help) sed -n '2,43p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

refuse() {
    echo "system-scope-soak: refused: $1" >&2
    exit 1
}

case "$CELL" in
    soak.1800s) CELL_MINIMUM=1800 ;;
    soak.14400s) CELL_MINIMUM=14400 ;;
    soak.86400s) CELL_MINIMUM=86400 ;;
    *) refuse "unknown --cell: $CELL (want soak.1800s|soak.14400s|soak.86400s)" ;;
esac
if [ -z "$HORIZON" ]; then HORIZON=$CELL_MINIMUM; fi
if [ -z "$REQUIRE_DURATION" ]; then REQUIRE_DURATION=$HORIZON; fi
if [ -z "$TEST_ID" ]; then TEST_ID="$CELL::continuous-owned-workload"; fi
case "$HORIZON" in *[!0-9]*|"") refuse "bad --horizon: $HORIZON" ;; esac
case "$REQUIRE_DURATION" in *[!0-9]*|"") refuse "bad --require-duration: $REQUIRE_DURATION" ;; esac
case "$EPOCH_S" in *[!0-9]*|"") refuse "bad --epoch-s: $EPOCH_S" ;; esac
case "$EPOCH_CALLS" in *[!0-9]*|"") refuse "bad --epoch-calls: $EPOCH_CALLS" ;; esac
case "$PACE_US" in *[!0-9]*|"") refuse "bad --pace-us: $PACE_US" ;; esac
[ "$HORIZON" -ge 1 ] || refuse "bad --horizon: $HORIZON"
[ "$REQUIRE_DURATION" -ge 1 ] || refuse "bad --require-duration: $REQUIRE_DURATION"
[ "$EPOCH_S" -ge 1 ] || refuse "bad --epoch-s: $EPOCH_S"
[ "$EPOCH_CALLS" -ge 1 ] || refuse "bad --epoch-calls: $EPOCH_CALLS"
[ "$(( HORIZON % EPOCH_S ))" -eq 0 ] || refuse "epochs do not divide the horizon: $HORIZON % $EPOCH_S"
EPOCHS=$(( HORIZON / EPOCH_S ))
N_CALLS=$(( EPOCHS * EPOCH_CALLS ))
# Integer microseconds: the paced estimate must cover 85%..97% of the
# horizon (tuning rule above). Shell arithmetic is 64-bit; horizons far
# below overflow.
ESTIMATE_US=$(( EPOCHS * EPOCH_CALLS * PACE_US ))
HORIZON_US=$(( HORIZON * 1000000 ))
[ "$ESTIMATE_US" -ge $(( HORIZON_US * 85 / 100 )) ] || \
    refuse "paced estimate covers less than 85% of the horizon (epochs=$EPOCHS calls=$EPOCH_CALLS pace_us=$PACE_US)"
[ "$ESTIMATE_US" -le $(( HORIZON_US * 97 / 100 )) ] || \
    refuse "paced estimate exceeds 97% of the horizon (epochs=$EPOCHS calls=$EPOCH_CALLS pace_us=$PACE_US)"

if [ "$DRY_RUN" -eq 1 ]; then
    [ -z "$INSTALLED" ] || refuse "--dry-run refuses --installed (a stub carries no installed authority)"
    [ -n "$OBSERVER_STUB" ] || refuse "--dry-run requires --observer-stub"
    case "$OBSERVER_STUB" in /*) ;; *) OBSERVER_STUB="$PWD/$OBSERVER_STUB" ;; esac
    [ -f "$OBSERVER_STUB" ] || refuse "no stub at $OBSERVER_STUB"
    MODE=dry-run
else
    [ -n "$INSTALLED" ] || refuse "live mode requires --installed (the packaged observer artifact)"
    [ -z "$OBSERVER_STUB" ] || refuse "live mode refuses --observer-stub"
    [ -z "$STUB_ARGS" ] || refuse "live mode refuses --stub-arg"
    case "$INSTALLED" in /*) ;; *) INSTALLED="$PWD/$INSTALLED" ;; esac
    [ -x "$INSTALLED" ] || refuse "no installed observer at $INSTALLED"
    DISCOVER="$(dirname "$INSTALLED")/p11scope-discover"
    [ -x "$DISCOVER" ] || refuse "no installed discover alongside $INSTALLED"
    MODE=live
fi
case "$WORK" in /*) ;; *) WORK="$PWD/$WORK" ;; esac

WPID=
WPID_STARTTIME=
WPID_RECEIPT=
WTARGET_PID=
WTARGET_STARTTIME=
SPID=
SPID_STARTTIME=
SPID_RECEIPT=
STARGET_PID=
STARGET_STARTTIME=
SMPID=
SMPID_STARTTIME=
SMPID_RECEIPT=
TSPID=
TSPID_STARTTIME=
TSPID_RECEIPT=
CFIFO=
P11SCOPE_RECEIPT_HELPER="$PWD/scripts/system-scope-receipt.py"
export P11SCOPE_RECEIPT_HELPER
. scripts/system-scope-owned.sh

cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [ -n "$TSPID" ] && [ -n "$TSPID_STARTTIME" ] &&
       ! owned_finish "$TSPID" "$TSPID_STARTTIME" "$TSPID_RECEIPT" 0; then
        echo "timestamp helper teardown failed; left unreaped" >&2
    fi
    if [ -n "$SMPID" ] && [ -n "$SMPID_STARTTIME" ] &&
       ! owned_finish "$SMPID" "$SMPID_STARTTIME" "$SMPID_RECEIPT" 0; then
        echo "sampler teardown failed; left unreaped" >&2
    fi
    if [ -n "$SPID" ] && [ -n "$SPID_STARTTIME" ] &&
       ! owned_finish "$SPID" "$SPID_STARTTIME" "$SPID_RECEIPT" 0; then
        echo "observer teardown failed; left unreaped" >&2
    fi
    if [ -n "$WPID" ] && [ -n "$WPID_STARTTIME" ] &&
       ! owned_finish "$WPID" "$WPID_STARTTIME" "$WPID_RECEIPT" 0; then
        echo "workload teardown failed; left unreaped" >&2
    fi
    [ -z "$CFIFO" ] || rm -f "$CFIFO" || true
    exit "$status"
}
. scripts/cleanup-traps.sh

umask 022
require_non_root_caller || refuse "run as a non-root user (with passwordless sudo for live mode)"
command -v gcc >/dev/null || refuse "gcc required"
command -v softhsm2-util >/dev/null || refuse "softhsm2-util required"
command -v python3 >/dev/null || refuse "python3 required"
command -v timeout >/dev/null || refuse "timeout required"
command -v flock >/dev/null || refuse "flock required"
if [ "$MODE" = live ]; then
    sudo -n true || refuse "passwordless sudo required for live mode"
fi
test -f "$SOURCE_MODULE" || refuse "SoftHSM2 not installed at $SOURCE_MODULE"
: "${TMPDIR:=/var/tmp/p11scope-ws-tmp}"
export TMPDIR
mkdir -p "$TMPDIR" "$WORK"
# The observer fails closed on untrusted output dirs: 0700 caller-owned.
chmod 700 "$WORK"

# Pre-free rule: refuse when the cargo lane is busy at start. This probes
# once; the controller keeps heavy builds off the host for the window.
flock -n "$CARGO_LANE" true || \
    refuse "cargo lane $CARGO_LANE is busy: free it before the window"

if [ "$MODE" = live ]; then
    # An ancestor must hold the privileged lock: a concurrent privileged
    # test or capture would charge these samples. Run under
    # `flock "$LOCK" $0`. Dry-run takes no lock (nothing privileged runs).
    python3 -I - "$LOCK" "$$" <<'EOF' || refuse "run under flock $LOCK: no ancestor holds the privileged lock"
import os, sys
path, me = sys.argv[1], int(sys.argv[2])
try:
    inode = str(os.stat(path).st_ino)
except OSError:
    sys.exit(1)
holders = []
for line in open("/proc/locks"):
    fields = line.split()
    if "->" in fields:
        continue
    if (len(fields) >= 6 and fields[1] == "FLOCK" and fields[3] == "WRITE"
            and fields[5].rsplit(":", 1)[-1] == inode):
        holders.append(int(fields[4]))
chain, pid = {me}, me
while pid > 1:
    try:
        status = open(f"/proc/{pid}/status").read()
    except OSError:
        break
    pid = int(next(l.split()[1] for l in status.splitlines() if l.startswith("PPid:")))
    chain.add(pid)
sys.exit(0 if any(h in chain for h in holders) else 1)
EOF
fi

# The receipt pins an exact source subject: a dirty tracked tree cannot
# be attested. Untracked helpers never affect the installed bytes.
if [ -n "$(git status --porcelain | grep -v '^??')" ]; then
    refuse "tracked tree is dirty: commit before a soak run"
fi
GIT_REV=$(git rev-parse HEAD)
GIT_TREE=$(git rev-parse 'HEAD^{tree}')
HARNESS_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

mono_ns() {
    python3 -I -c 'import time; print(time.monotonic_ns())'
}
KERNEL=$(uname -r)
CPU=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')
NCPU=$(nproc)
POSSIBLE_CPUS=$(python3 -I scripts/system-scope-measure.py --possible-cpu-count 2>/dev/null) || POSSIBLE_CPUS=null

# Every run gets a private provider inode. System totals from an unrelated
# host process using the packaged SoftHSM object can therefore never
# satisfy this workload's physical-identity oracle.
mkdir -p "$WORK/provider"
chmod 700 "$WORK/provider"
MODULE="$WORK/provider/libsofthsm2-owned.so"
rm -f "$MODULE"
python3 -I scripts/system-scope-receipt.py file --path "$SOURCE_MODULE" \
    > "$WORK/provider-source.identity.json"
install -m 0555 "$SOURCE_MODULE" "$MODULE"
python3 -I scripts/system-scope-receipt.py file --path "$MODULE" \
    > "$WORK/provider-copy.identity.json"

echo "=== build ==="
gcc -O0 -o "$WORK/workload" scripts/system-scope-workload.c -ldl

if [ "$MODE" = live ]; then
    INSTALLED_SHA_PRE=$(sha256sum "$INSTALLED" | cut -d' ' -f1)
    INSTALLED_SIZE=$(stat -c%s "$INSTALLED")
    mkdir -p "$WORK/installed"
    chmod 700 "$WORK/installed"
    rm -f "$WORK/installed/p11scope" "$WORK/installed/p11scope-discover"
    install -m 0555 "$INSTALLED" "$WORK/installed/p11scope"
    install -m 0555 "$DISCOVER" "$WORK/installed/p11scope-discover"
    INSTALLED_COPY="$WORK/installed/p11scope"
    DISCOVER_COPY="$WORK/installed/p11scope-discover"
    chmod 500 "$WORK/installed"
    python3 -I scripts/system-scope-receipt.py file --path "$INSTALLED" \
        > "$WORK/installed-source.identity.json"
    python3 -I scripts/system-scope-receipt.py file --path "$INSTALLED_COPY" \
        > "$WORK/installed-copy.identity.json"
    OBSERVER_PRIVILEGE=root
    SAMPLER_PRIVILEGE=root
else
    STUB_SHA=$(sha256sum "$OBSERVER_STUB" | cut -d' ' -f1)
    # A private stub copy, mirroring the installed-copy discipline: the
    # receipt metadata requires a distinct physical observer file.
    mkdir -p "$WORK/stub"
    chmod 700 "$WORK/stub"
    rm -f "$WORK/stub/soak-observer-stub.py"
    install -m 0555 "$OBSERVER_STUB" "$WORK/stub/soak-observer-stub.py"
    STUB_COPY="$WORK/stub/soak-observer-stub.py"
    chmod 500 "$WORK/stub"
    OBSERVER_PRIVILEGE=user
    SAMPLER_PRIVILEGE=user
fi

echo "=== private softhsm token ==="
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
rm -rf "$WORK/tokens"
mkdir -p "$WORK/tokens"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WORK/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
softhsm2-util --init-token --free --label sys-scope-soak --so-pin 1234 --pin 1234 >/dev/null

echo "=== discover ==="
if [ "$MODE" = live ]; then
    "$DISCOVER_COPY" --module "$MODULE" -o "$WORK/manifest.json"
else
    # Dry-run writes its own labeled manifest: no discover binary runs,
    # so trials need no cargo lane at all.
    cat > "$WORK/manifest.json" <<EOF
{"schema": "soak-dry-run-manifest/v1", "module": "$MODULE", "note": "shape stand-in; the stub checks existence only"}
EOF
fi

# wait_file <path> <timeout_s> — poll for a file to appear.
wait_file() {
    end=$(( $(date +%s) + $2 ))
    while [ ! -f "$1" ]; do
        [ "$(date +%s)" -lt "$end" ] || return 1
        sleep 0.05
    done
    return 0
}

# Classify one exact process generation without signalling it. Permission to
# send a signal says nothing about liveness for a root observer.
owned_require_live() {
    owned_live_state=$(owned_process_state "$1" "$2") || return 2
    case "$owned_live_state" in
        live) return 0 ;;
        terminal) return 1 ;;
        unknown) return 2 ;;
    esac
    return 2
}

# wait_file_alive <path> <observer-pid> <observer-birth>
#   <workload-pid> <workload-birth> <timeout_s> — a missing mapped handshake is a
# harness failure, and an observer that exits before owned calls are released
# cannot be turned into a short successful capture.
wait_file_alive() {
    end=$(( $(date +%s) + $6 ))
    while [ ! -f "$1" ]; do
        owned_live_status=0
        owned_require_live "$2" "$3" || owned_live_status=$?
        case "$owned_live_status" in 0) ;; 1) return 2 ;; *) return 4 ;; esac
        owned_live_status=0
        owned_require_live "$4" "$5" || owned_live_status=$?
        case "$owned_live_status" in 0) ;; 1) return 3 ;; *) return 5 ;; esac
        [ "$(date +%s)" -lt "$end" ] || return 1
        sleep 0.05
    done
    return 0
}

# collect_receipt — run while the owned child is alive and gated. Live mode
# crosses into the mapping pin with passwordless sudo (hosts whose ptrace
# policy denies a sibling process access to map_files); dry-run attempts
# the same receipt unprivileged and records the refusal when the host
# denies it, which fails the ownership gate honestly.
collect_receipt() {
    python3 -I scripts/system-scope-receipt.py verify-file \
        --identity "$WORK/provider-source.identity.json" \
        --path "$SOURCE_MODULE" >/dev/null || return 1
    python3 -I scripts/system-scope-receipt.py verify-file \
        --identity "$WORK/provider-copy.identity.json" --path "$MODULE" >/dev/null \
        || return 1
    if [ "$MODE" = live ]; then
        timeout --signal=TERM --kill-after=5s 30s \
          sudo -n python3 -I "$PWD/scripts/system-scope-receipt.py" mapping \
            --handshake "$WORK/mapped" --expected-file "$MODULE" \
            --source-file "$SOURCE_MODULE" > "$WORK/workload-mapping-receipt.json" \
            || return 1
    else
        timeout --signal=TERM --kill-after=5s 30s \
          python3 -I "$PWD/scripts/system-scope-receipt.py" mapping \
            --handshake "$WORK/mapped" --expected-file "$MODULE" \
            --source-file "$SOURCE_MODULE" > "$WORK/workload-mapping-receipt.json" \
            2>"$WORK/mapping-receipt.stderr" || return 1
    fi
    timeout --signal=TERM --kill-after=5s 30s \
      python3 -I scripts/system-scope-receipt.py metadata \
        --receipt "$WORK/workload-mapping-receipt.json" --observer "$OBSERVER_BIN" \
        --observer-source "$OBSERVER_SOURCE" \
        --source-file "$SOURCE_MODULE" --copy-file "$MODULE" \
        > "$WORK/receipt-metadata.json" || return 1
}

# wait_attach — hold the go file until discovery is done (marker on the
# timestamped stderr passthrough) AND the attach session is complete (the
# "p11scope: capturing: N probe(s) attached" line). readiness means the
# attach session completed; post-hoc counts prove the window. Returns 2
# if the observer is terminal and 3 if its identity is unknown.
wait_attach() {
    end=$(( $(date +%s) + $4 ))
    while :; do
        owned_live_status=0
        owned_require_live "$2" "$3" || owned_live_status=$?
        case "$owned_live_status" in 0) ;; 1) return 2 ;; *) return 3 ;; esac
        [ "$(date +%s)" -lt "$end" ] || return 1
        if grep -q "p11scope: discovery:" "$1/stderr.txt" 2>/dev/null \
            && grep -q -E "p11scope: capturing: [0-9]+ probe\(s\) attached" "$1/stderr.txt" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
}

echo "=== soak: $CELL mode=$MODE horizon=${HORIZON}s epochs=$EPOCHS ==="
rm -f "$WORK/go" "$WORK/mapped" "$WORK/receipt-ready" \
    "$WORK/workload-mapping-receipt.json" "$WORK/receipt-metadata.json" \
    "$WORK/mapping-receipt.stderr"
# Bench-style late mapping: per-PID attach on this HEAD fails when the
# provider is already mapped, so the workload reports READY first and
# maps after GO (MAP_EARLY=0).
owned_launch user - "$WORK/workload.log" = -- env P11SCOPE_MEASURE_SEED="$SEED" \
    "$WORK/workload" "$MODULE" "$N_CALLS" "$PACE_US" 0 \
    "$WORK/ready" "$WORK/go" "$WORK/mapped" "$WORK/receipt-ready" "$EPOCH_CALLS"
WPID=$OWNED_PID
WPID_STARTTIME=$OWNED_STARTTIME
WPID_RECEIPT=$OWNED_RECEIPT
owned_verify_launch "$WPID" "$WPID_STARTTIME" "$WPID_RECEIPT" || exit 1
WTARGET_PID=$OWNED_COMMAND_PID
WTARGET_STARTTIME=$OWNED_COMMAND_STARTTIME
wait_file "$WORK/ready" 60 || { echo "workload never became ready" >&2; cat "$WORK/workload.log" >&2; exit 1; }

CFIFO="$WORK/stderr.fifo"
rm -f "$CFIFO"
mkfifo "$CFIFO"
owned_launch user "$CFIFO" /dev/null "$WORK/ts-helper.stderr" -- \
    python3 -I scripts/system-scope-ts.py --out "$WORK/stderr-ts.jsonl" \
    --passthrough "$WORK/stderr.txt"
TSPID=$OWNED_PID
TSPID_STARTTIME=$OWNED_STARTTIME
TSPID_RECEIPT=$OWNED_RECEIPT

if [ "$MODE" = live ]; then
    OBSERVER_BIN=$INSTALLED_COPY
    OBSERVER_SOURCE=$INSTALLED
    set -- "$INSTALLED_COPY" profile \
        --pid "$WTARGET_PID" --manifest "$WORK/manifest.json" \
        --mode metrics --duration "$HORIZON" -o "$WORK/report.json"
else
    OBSERVER_BIN=$STUB_COPY
    OBSERVER_SOURCE=$OBSERVER_STUB
    # shellcheck disable=SC2086
    set -- python3 -I "$STUB_COPY" profile \
        --pid "$WTARGET_PID" --manifest "$WORK/manifest.json" \
        --mode metrics --duration "$HORIZON" -o "$WORK/report.json" \
        --counter-oracle "$PWD/scripts/check-capture-evidence.py" \
        --loopback-log "$WORK/workload.log" $STUB_ARGS
fi
OBS_ARGV_JSON=$(python3 -I -c "import json,sys; print(json.dumps(sys.argv[1:]))" "$@")
T_SPAWN=$(mono_ns)
owned_launch "$OBSERVER_PRIVILEGE" - "$WORK/observer.stdout" "$CFIFO" -- "$@"
SPID=$OWNED_PID; SPID_STARTTIME=$OWNED_STARTTIME
SPID_RECEIPT=$OWNED_RECEIPT
owned_verify_launch "$TSPID" "$TSPID_STARTTIME" "$TSPID_RECEIPT" || exit 1
owned_verify_launch "$SPID" "$SPID_STARTTIME" "$SPID_RECEIPT" || exit 1
STARGET_PID=$OWNED_COMMAND_PID
STARGET_STARTTIME=$OWNED_COMMAND_STARTTIME
owned_launch "$SAMPLER_PRIVILEGE" - "$WORK/sampler.stdout" "$WORK/sampler.stderr" -- \
    python3 -I "$PWD/scripts/system-scope-sample.py" \
    --pid "$STARGET_PID" --starttime "$STARGET_STARTTIME" \
    --out "$WORK/samples.jsonl" --interval 0.05
SMPID=$OWNED_PID
SMPID_STARTTIME=$OWNED_STARTTIME
SMPID_RECEIPT=$OWNED_RECEIPT
owned_verify_launch "$SMPID" "$SMPID_STARTTIME" "$SMPID_RECEIPT" || exit 1

if wait_attach "$WORK" "$STARGET_PID" "$STARGET_STARTTIME" 600; then
    :
else
    rc=$?
    if [ "$rc" -eq 2 ]; then
        echo "observer died during attach:" >&2
        cat "$WORK/stderr.txt" >&2
    elif [ "$rc" -eq 3 ]; then
        echo "observer identity became unknown during attach:" >&2
        cat "$WORK/stderr.txt" >&2
    else
        echo "attach never settled (see $WORK/stderr.txt)" >&2
    fi
    exit 1
fi
T_GO=$(mono_ns)
LOADAVG=$(cat /proc/loadavg)
owned_live_status=0
owned_require_live "$STARGET_PID" "$STARGET_STARTTIME" || owned_live_status=$?
case "$owned_live_status" in
    0) ;;
    1) echo "observer exited before owned calls were released" >&2; exit 1 ;;
    *) echo "observer identity unknown before owned calls were released" >&2; exit 1 ;;
esac
touch "$WORK/go"

if wait_file_alive "$WORK/mapped" "$STARGET_PID" "$STARGET_STARTTIME" \
    "$WTARGET_PID" "$WTARGET_STARTTIME" 60; then
    :
else
    rc=$?
    if [ "$rc" -eq 2 ]; then
        echo "observer exited before late workload mapping was receipted" >&2
    elif [ "$rc" -eq 3 ]; then
        echo "late workload exited before publishing its mapping" >&2
    elif [ "$rc" -eq 4 ]; then
        echo "observer identity became unknown before late workload mapping" >&2
    elif [ "$rc" -eq 5 ]; then
        echo "late workload identity became unknown before mapping" >&2
    else
        echo "late workload published no mapping handshake" >&2
    fi
    cat "$WORK/workload.log" >&2
    exit 1
fi
T_MAPPING_READY=$(mono_ns)
OWNERSHIP_NOTE="mapping receipt pinned"
if collect_receipt; then
    :
else
    if [ "$MODE" = live ]; then
        echo "could not pin late workload mapping" >&2
        exit 1
    fi
    OWNERSHIP_NOTE="dry-run: unprivileged mapping receipt refused; ownership gate must fail"
    echo "note: $OWNERSHIP_NOTE" >&2
    rm -f "$WORK/workload-mapping-receipt.json" "$WORK/receipt-metadata.json"
fi
owned_live_status=0
owned_require_live "$STARGET_PID" "$STARGET_STARTTIME" || owned_live_status=$?
case "$owned_live_status" in
    0) ;;
    1) echo "observer exited before owned calls were released" >&2; exit 1 ;;
    *) echo "observer identity unknown before owned calls were released" >&2; exit 1 ;;
esac
T_RECEIPT_READY=$(mono_ns)
touch "$WORK/receipt-ready"

if ! owned_finish "$WPID" "$WPID_STARTTIME" "$WPID_RECEIPT" $(( HORIZON + 300 )); then
    echo "workload settlement failed; left unreaped" >&2
    exit 1
fi
WORKLOAD_RC=$OWNED_EXIT
[ "$WORKLOAD_RC" -eq 0 ] || {
    echo "workload failed (exit=$WORKLOAD_RC)" >&2
    cat "$WORK/workload.log" >&2
    exit 1
}
WPID=
WPID_STARTTIME=

# The observer exits on its own after --duration + detach + publish; the
# escalation signals the real observer child, never just its sudo parent.
OBSERVER_TIMED_OUT=false
OBSERVER_SIGNAL=null
observer_wait_state=0
owned_wait_supervisor_terminal "$SPID_RECEIPT" $(( HORIZON + 600 )) || \
    observer_wait_state=$?
case "$observer_wait_state" in
    0) ;;
    1)
        echo "observer hung; interrupting" >&2
        OBSERVER_TIMED_OUT=true
        ;;
    *)
        echo "observer terminal state is unknown" >&2
        exit 1
        ;;
esac
owned_finish "$SPID" "$SPID_STARTTIME" "$SPID_RECEIPT" 0 || {
    echo "observer descendant settlement failed; left unreaped" >&2
    exit 1
}
owned_command_outcome "$SPID_RECEIPT" || {
    echo "observer receipt has no exact command outcome" >&2
    exit 1
}
OBS_RC=$OWNED_COMMAND_EXIT
OBSERVER_SIGNAL=$OWNED_COMMAND_SIGNAL
if [ "$OBSERVER_SIGNAL" = null ]; then
    OBSERVER_SIGNAL_JSON=null
else
    OBSERVER_SIGNAL_JSON="\"$OBSERVER_SIGNAL\""
fi
SPID=
SPID_STARTTIME=
T_EXIT=$(mono_ns)

if [ "$MODE" = live ]; then
    python3 -I scripts/system-scope-receipt.py verify-file \
        --identity "$WORK/installed-copy.identity.json" --path "$INSTALLED_COPY" >/dev/null || {
        echo "installed copy changed during the run" >&2
        exit 1
    }
    INSTALLED_SHA_POST=$(sha256sum "$INSTALLED" | cut -d' ' -f1)
fi

# Sampler/ts exit on their own once the observer is gone; bound the wait.
owned_finish "$SMPID" "$SMPID_STARTTIME" "$SMPID_RECEIPT" 15 || {
    echo "sampler teardown failed; left unreaped" >&2
    exit 1
}
SMPID=
SMPID_STARTTIME=
owned_command_outcome "$SMPID_RECEIPT" || {
    echo "sampler receipt has no exact command outcome" >&2
    exit 1
}
SAMPLER_EXIT=$OWNED_COMMAND_EXIT
SAMPLER_SIGNAL=$OWNED_COMMAND_SIGNAL
owned_finish "$TSPID" "$TSPID_STARTTIME" "$TSPID_RECEIPT" 15 || {
    echo "timestamp helper teardown failed; left unreaped" >&2
    exit 1
}
TSPID=
TSPID_STARTTIME=
rm -f "$CFIFO"
CFIFO=
# A nonzero observer exit with a report is still a measurement (the rc is
# recorded and the clean-exit gate judges it); a missing report is a
# harness failure and the run refuses before the oracle.
if [ ! -f "$WORK/report.json" ]; then
    echo "observer exit=$OBS_RC wrote no report:" >&2
    cat "$WORK/stderr.txt" >&2
    exit 1
fi
if [ "$MODE" = live ]; then
    reclaim_root_output "$WORK/report.json" "$WORK/samples.jsonl"
fi

WORKLOAD_ARGV_JSON=$(python3 -I -c "import json; print(json.dumps(['$WORK/workload', '$MODULE', '$N_CALLS', '$PACE_US', '0', '$WORK/ready', '$WORK/go', '$WORK/mapped', '$WORK/receipt-ready', '$EPOCH_CALLS']))")
cat > "$WORK/meta.json" <<EOF
{"harness": {"name": "system-scope-soak.sh", "git_rev": "$GIT_REV", "started_iso": "$HARNESS_START_ISO",
  "observer_exit": $OBS_RC, "observer_timed_out": $OBSERVER_TIMED_OUT,
  "observer_signal": $OBSERVER_SIGNAL_JSON},
 "condition": {"scope": "pid", "mode": "metrics", "duration_s": $HORIZON,
  "n_calls": $N_CALLS, "pace_us": $PACE_US, "seed": $SEED, "map_early": 0,
  "ring_bytes": "default", "drain_interval_ms": "default",
  "sink": "file", "gate": "frame",
  "manifest": "$WORK/manifest.json", "binary": "$OBSERVER_BIN", "build_profile": "$MODE",
  "observer_source_revision": null,
  "observer_argv": $OBS_ARGV_JSON, "workload_argv": $WORKLOAD_ARGV_JSON,
  "mapping_gate": "post-attach"},
 "host": {"kernel": "$KERNEL", "cpu": "$CPU", "ncpu": $NCPU, "possible_cpus": $POSSIBLE_CPUS, "loadavg": "$LOADAVG"},
 "timing": {"t_spawn_mono_ns": $T_SPAWN, "t_initial_go_mono_ns": $T_GO,
  "t_mapping_ready_mono_ns": $T_MAPPING_READY, "t_receipt_ready_mono_ns": $T_RECEIPT_READY,
  "t_go_mono_ns": $T_GO, "t_exit_mono_ns": $T_EXIT},
 "artifacts": {"dir": "$WORK", "report": "$WORK/report.json", "samples": "$WORK/samples.jsonl",
  "stderr_ts": "$WORK/stderr-ts.jsonl", "stderr": "$WORK/stderr.txt",
  "workload_log": "$WORK/workload.log", "mapping_receipt": "$WORK/workload-mapping-receipt.json"}}
EOF
if [ -f "$WORK/receipt-metadata.json" ]; then
    python3 -I - "$WORK/meta.json" "$WORK/receipt-metadata.json" <<'PY'
import json
import sys
from pathlib import Path
meta_path = Path(sys.argv[1])
receipt_path = Path(sys.argv[2])
meta = json.loads(meta_path.read_text(encoding="utf-8"))
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
meta["condition"].update(receipt)
meta_path.write_text(json.dumps(meta, sort_keys=True) + "\n", encoding="utf-8")
PY
fi
python3 -I scripts/system-scope-measure.py --meta "$WORK/meta.json" \
    --report "$WORK/report.json" --samples "$WORK/samples.jsonl" \
    --stderr-ts "$WORK/stderr-ts.jsonl" --workload-log "$WORK/workload.log" \
    --out "$WORK/record.json" --summary "$WORK/summary.txt"
cat "$WORK/summary.txt" || true

# run.json: the oracle's typed input. Built by python from exported facts
# so quoting cannot corrupt it; every value here is recorded, including
# the trial-only stub args and requirement overrides.
export WORK CELL TEST_ID KERNEL_PROFILE MODE HORIZON REQUIRE_DURATION EPOCH_S EPOCH_CALLS
export PACE_US SEED EPOCHS N_CALLS GIT_REV GIT_TREE HARNESS_START_ISO HARNESS_ARGV_JSON
export OBS_ARGV_JSON WORKLOAD_ARGV_JSON T_SPAWN T_GO T_EXIT
export WTARGET_PID WTARGET_STARTTIME WORKLOAD_RC
export OBS_RC OBSERVER_SIGNAL OBSERVER_TIMED_OUT SAMPLER_EXIT SAMPLER_SIGNAL
export OWNERSHIP_NOTE STUB_ARGS
export INSTALLED INSTALLED_SHA_PRE=${INSTALLED_SHA_PRE-} INSTALLED_SHA_POST=${INSTALLED_SHA_POST-}
export INSTALLED_SIZE=${INSTALLED_SIZE-} OBSERVER_STUB=${OBSERVER_STUB-} STUB_SHA=${STUB_SHA-}
python3 -I - <<'PY'
import json
import os
from pathlib import Path

work = Path(os.environ["WORK"])
mode = os.environ["MODE"]
live = mode == "live"


def integer(name):
    return int(os.environ[name])


def signal(name):
    value = os.environ[name]
    return None if value in ("null", "") else value


if live:
    installed = {"path": os.environ["INSTALLED"],
                 "sha256_pre": os.environ["INSTALLED_SHA_PRE"],
                 "sha256_post": os.environ["INSTALLED_SHA_POST"],
                 "size": integer("INSTALLED_SIZE")}
    stub = None
    installed_copy: str | None = "installed/p11scope"
else:
    installed = None
    stub = {"path": os.environ["OBSERVER_STUB"],
            "sha256": os.environ["STUB_SHA"]}
    installed_copy = None
mapping = "workload-mapping-receipt.json" if (work / "workload-mapping-receipt.json").is_file() else None
metadata = "receipt-metadata.json" if (work / "receipt-metadata.json").is_file() else None
run = {
    "schema": "p11scope/soak-run/v1",
    "cell_id": os.environ["CELL"],
    "test_ids": [os.environ["TEST_ID"]],
    "kernel_profile": os.environ["KERNEL_PROFILE"],
    "mode": mode,
    "horizon_s": integer("HORIZON"),
    "require_duration_s": integer("REQUIRE_DURATION"),
    "epoch_s": integer("EPOCH_S"),
    "epoch_calls": integer("EPOCH_CALLS"),
    "expected_epochs": integer("EPOCHS"),
    "pace_us": integer("PACE_US"),
    "subject": {"revision": os.environ["GIT_REV"], "tree": os.environ["GIT_TREE"]},
    "harness": {"name": "system-scope-soak.sh",
                "git_rev": os.environ["GIT_REV"],
                "started_iso": os.environ["HARNESS_START_ISO"],
                "argv": json.loads(os.environ["HARNESS_ARGV_JSON"]),
                "stub_args_raw": os.environ.get("STUB_ARGS", "")},
    "harness_argv": json.loads(os.environ["HARNESS_ARGV_JSON"]),
    "observer_argv": json.loads(os.environ["OBS_ARGV_JSON"]),
    "installed": installed,
    "stub": stub,
    "workload": {"pid": integer("WTARGET_PID"),
                 "starttime": integer("WTARGET_STARTTIME"),
                 "argv": json.loads(os.environ["WORKLOAD_ARGV_JSON"]),
                 "exit": integer("WORKLOAD_RC")},
    "observer": {"exit": integer("OBS_RC"), "signal": signal("OBSERVER_SIGNAL"),
                 "timed_out": os.environ["OBSERVER_TIMED_OUT"] == "true"},
    "sampler": {"exit": integer("SAMPLER_EXIT"), "signal": signal("SAMPLER_SIGNAL")},
    "timing": {"t_spawn_mono_ns": integer("T_SPAWN"),
               "t_go_mono_ns": integer("T_GO"),
               "start_mono_ns": integer("T_GO"),
               "end_mono_ns": integer("T_EXIT")},
    "ownership": {"mapping_receipt": mapping,
                  "note": os.environ["OWNERSHIP_NOTE"]},
    "artifacts": {"run": "run.json", "record": "record.json", "meta": "meta.json",
                  "report": "report.json", "samples": "samples.jsonl",
                  "stderr_ts": "stderr-ts.jsonl", "stderr": "stderr.txt",
                  "workload_log": "workload.log",
                  "mapping_receipt": mapping, "receipt_metadata": metadata,
                  "installed_copy": installed_copy},
}
(work / "run.json").write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
PY

echo "=== oracle ==="
if [ "$MODE" = live ]; then
    oracle_rc=0
    python3 -I scripts/system-scope-soak-oracle.py --evidence-dir "$WORK" \
        --out-verdict "$WORK/verdict.json" --out-receipt "$WORK/receipt.json" || \
        oracle_rc=$?
    echo "=== system-scope-soak: DONE ==="
    exit "$oracle_rc"
fi
python3 -I scripts/system-scope-soak-oracle.py --evidence-dir "$WORK" \
    --out-verdict "$WORK/verdict.json" --dry-run-receipt "$WORK/receipt.dryrun.json" || true
# A dry-run verdict FAILs by construction (no installed authority, and
# possibly no unprivileged mapping receipt); any other red gate is a
# wiring failure and fails the trial. The shape receipt still proves
# the writer ran. A dry-run never qualifies.
python3 -I - "$WORK/verdict.json" <<'PY'
import json
import sys
verdict = json.loads(open(sys.argv[1], encoding="utf-8").read())
red = sorted(name for name, gate in verdict["gates"].items() if not gate["pass"])
allowed = {"installed_identity", "ownership"}
if not set(red) <= allowed:
    print(f"dry-run wiring failure: unexpected red gates: {red}", file=sys.stderr)
    sys.exit(1)
print(f"dry-run complete: red gates {red} are the expected by-construction "
      f"failures; verdict in {sys.argv[1]} (never qualifying)", flush=True)
PY
echo "=== system-scope-soak: DONE ==="

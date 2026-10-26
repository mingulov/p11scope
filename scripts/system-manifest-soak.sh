#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# system-manifest-soak.sh — the M13 soak vehicle (cell 5.5): one long
# `inventory --system --manifest` capture over owned SoftHSM workloads
# on a private provider copy, with workload-ledger, loss and RSS/FD
# accounting judged by system-manifest-soak-oracle.py into a verdict.
#
# The workloads map the provider copy eagerly and wait at a gate; the
# gate opens once the observer publishes pass 0 (attach settled), so
# every ledgered main/teardown call is post-attach and the per-caller
# edge entries must equal the ledgers exactly. The sampler mirrors the
# bench-inventory-native.sh resource loop (1 Hz RSS, HWM, FD into
# resources.tsv). A PASS verdict in live mode qualifies; a dry-run
# PASS proves wiring only and never qualifies.
#
# Usage (live 30-minute qualification; run under the privileged lock,
# or as root on a dedicated guest/host):
#   flock /var/tmp/p11scope-ws-tmp/privileged.lock \
#     scripts/system-manifest-soak.sh --cell soak-manifest.1800s \
#       --installed /opt/p11scope/bin/p11scope --work /var/tmp/soak-manifest
# Short validation (5 minutes, 2 callers, root guest):
#   scripts/system-manifest-soak.sh --cell soak-manifest.1800s --horizon 300 \
#     --require-duration 300 --callers 2 --installed /root/p11scope --work /root/soak
# Dry-run wiring trial (unprivileged, short horizon, stub observer):
#   scripts/system-manifest-soak.sh --cell soak-manifest.1800s --dry-run \
#     --observer-stub scripts/fixtures/system-manifest-soak-stub.py \
#     --horizon 8 --require-duration 8 --observer-slack-s 5 --callers 1 \
#     --iters 4 --delay-ms 500 \
#     --work /var/tmp/p11scope-ws-tmp/manifest-soak-trial
#
# Pre-free rule: this script never invokes cargo and performs no builds
# beyond the lane-free gcc workload compile. Build and install the
# candidate first, FREE the cargo lane, then start the run; it refuses
# when the lane is busy at start (host paths only), and the controller
# keeps heavy builds off the host until the window closes. Live mode
# as non-root additionally requires an ancestor holding the privileged
# lock (the bench-count recipe) and passwordless sudo; as root (a
# dedicated guest or host) the machine itself is the quiet lane and no
# lock proof is required. It never nests qualify-release-matrix.sh.
set -eu
cd "$(dirname "$0")/.."
. scripts/lib.sh

CELL=
HORIZON=
REQUIRE_DURATION=
OBSERVER_SLACK_S=60
CALLERS=2
ITERS=
SLEEP_US=100000
DELAY_MS=15000
SEED=1
WORK=/var/tmp/p11scope-manifest-soak
INSTALLED=
DRY_RUN=0
OBSERVER_STUB=
KERNEL_PROFILE=current/default
TEST_ID=
SOURCE_MODULE=/usr/lib/softhsm/libsofthsm2.so
MODULE=
LOCK=${LOCK:-/var/tmp/p11scope-ws-tmp/privileged.lock}
CARGO_LANE=${CARGO_LANE:-/var/tmp/p11scope-ws-tmp/v040-cargo-lane.lock}
HARNESS_ARGV_JSON=$(python3 -I -c "import json,sys; print(json.dumps(sys.argv[1:]))" "$0" "$@")

while [ "$#" -gt 0 ]; do
    case "$1" in
        --cell) CELL=$2; shift 2 ;;
        --horizon) HORIZON=$2; shift 2 ;;
        --require-duration) REQUIRE_DURATION=$2; shift 2 ;;
        --observer-slack-s) OBSERVER_SLACK_S=$2; shift 2 ;;
        --callers) CALLERS=$2; shift 2 ;;
        --iters) ITERS=$2; shift 2 ;;
        --sleep-us) SLEEP_US=$2; shift 2 ;;
        --delay-ms) DELAY_MS=$2; shift 2 ;;
        --seed) SEED=$2; shift 2 ;;
        --work) WORK=$2; shift 2 ;;
        --installed) INSTALLED=$2; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --observer-stub) OBSERVER_STUB=$2; shift 2 ;;
        --kernel-profile) KERNEL_PROFILE=$2; shift 2 ;;
        --test-id) TEST_ID=$2; shift 2 ;;
        -h|--help) sed -n '2,39p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

refuse() {
    echo "system-manifest-soak: refused: $1" >&2
    exit 1
}

case "$CELL" in
    soak-manifest.1800s) CELL_MINIMUM=1800 ;;
    *) refuse "unknown --cell: $CELL (want soak-manifest.1800s)" ;;
esac
if [ -z "$HORIZON" ]; then HORIZON=$CELL_MINIMUM; fi
if [ -z "$REQUIRE_DURATION" ]; then REQUIRE_DURATION=$HORIZON; fi
if [ -z "$ITERS" ]; then ITERS=$(( HORIZON * 9 )); fi
if [ -z "$TEST_ID" ]; then TEST_ID="$CELL::system-manifest-owned-workload"; fi
case "$HORIZON" in *[!0-9]*|"") refuse "bad --horizon: $HORIZON" ;; esac
case "$REQUIRE_DURATION" in *[!0-9]*|"") refuse "bad --require-duration: $REQUIRE_DURATION" ;; esac
case "$OBSERVER_SLACK_S" in *[!0-9]*|"") refuse "bad --observer-slack-s: $OBSERVER_SLACK_S" ;; esac
case "$CALLERS" in *[!0-9]*|"") refuse "bad --callers: $CALLERS" ;; esac
case "$ITERS" in *[!0-9]*|"") refuse "bad --iters: $ITERS" ;; esac
case "$SLEEP_US" in *[!0-9]*|"") refuse "bad --sleep-us: $SLEEP_US" ;; esac
case "$DELAY_MS" in *[!0-9]*|"") refuse "bad --delay-ms: $DELAY_MS" ;; esac
[ "$HORIZON" -ge 1 ] || refuse "bad --horizon: $HORIZON"
[ "$REQUIRE_DURATION" -ge 1 ] || refuse "bad --require-duration: $REQUIRE_DURATION"
[ "$OBSERVER_SLACK_S" -ge 1 ] || refuse "bad --observer-slack-s: $OBSERVER_SLACK_S"
[ "$CALLERS" -ge 1 ] || refuse "bad --callers: $CALLERS"
[ "$ITERS" -ge 1 ] || refuse "bad --iters: $ITERS"
OBSERVER_DURATION=$(( HORIZON + OBSERVER_SLACK_S ))

if [ "$DRY_RUN" -eq 1 ]; then
    [ -z "$INSTALLED" ] || refuse "--dry-run refuses --installed (a stub carries no installed authority)"
    [ -n "$OBSERVER_STUB" ] || refuse "--dry-run requires --observer-stub"
    case "$OBSERVER_STUB" in /*) ;; *) OBSERVER_STUB="$PWD/$OBSERVER_STUB" ;; esac
    [ -f "$OBSERVER_STUB" ] || refuse "no stub at $OBSERVER_STUB"
    MODE=dry-run
else
    [ -n "$INSTALLED" ] || refuse "live mode requires --installed (the packaged observer artifact)"
    [ -z "$OBSERVER_STUB" ] || refuse "live mode refuses --observer-stub"
    case "$INSTALLED" in /*) ;; *) INSTALLED="$PWD/$INSTALLED" ;; esac
    [ -x "$INSTALLED" ] || refuse "no installed observer at $INSTALLED"
    DISCOVER="$(dirname "$INSTALLED")/p11scope-discover"
    [ -x "$DISCOVER" ] || refuse "no installed discover alongside $INSTALLED"
    MODE=live
fi
case "$WORK" in /*) ;; *) WORK="$PWD/$WORK" ;; esac

SAMPLER_PID=
OBSERVER_PID=
OBSERVER_STARTTIME=
OBSERVER_RECEIPT=
STAGE=
MANIFEST_TMP=
P11SCOPE_RECEIPT_HELPER="$PWD/scripts/system-scope-receipt.py"
export P11SCOPE_RECEIPT_HELPER
. scripts/system-scope-owned.sh

cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [ -n "$SAMPLER_PID" ] && kill -0 "$SAMPLER_PID" 2>/dev/null; then
        kill -KILL "$SAMPLER_PID" 2>/dev/null || true
        wait "$SAMPLER_PID" 2>/dev/null || true
    fi
    for id_file in "$WORK"/wl-*.id; do
        [ -f "$id_file" ] || continue
        read -r wpid wstart wreceipt _wcmd _wcmdstart < "$id_file"
        if [ -n "$wpid" ] && [ -n "$wstart" ] &&
           ! owned_finish "$wpid" "$wstart" "$wreceipt" 0; then
            echo "workload $id_file teardown failed; left unreaped" >&2
        fi
    done
    if [ -n "$OBSERVER_PID" ] && [ -n "$OBSERVER_STARTTIME" ] &&
       ! owned_finish "$OBSERVER_PID" "$OBSERVER_STARTTIME" "$OBSERVER_RECEIPT" 0; then
        echo "observer teardown failed; left unreaped" >&2
    fi
    if [ -n "$STAGE" ] && [ -d "$STAGE" ]; then
        rm -rf "$STAGE" || echo "stage $STAGE left behind" >&2
    fi
    if [ -n "$MANIFEST_TMP" ] && [ -f "$MANIFEST_TMP" ]; then
        rm -f "$MANIFEST_TMP" || echo "manifest tmp $MANIFEST_TMP left behind" >&2
    fi
    exit "$status"
}
. scripts/cleanup-traps.sh

umask 022
command -v gcc >/dev/null || refuse "gcc required"
command -v softhsm2-util >/dev/null || refuse "softhsm2-util required"
command -v python3 >/dev/null || refuse "python3 required"
command -v timeout >/dev/null || refuse "timeout required"
command -v flock >/dev/null || refuse "flock required"
IS_ROOT=0
[ "$(id -u)" -ne 0 ] || IS_ROOT=1
if [ "$MODE" = live ] && [ "$IS_ROOT" -eq 0 ]; then
    sudo -n true || refuse "passwordless sudo required for live mode as non-root"
fi
if [ ! -f "$SOURCE_MODULE" ]; then
    SOURCE_MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
fi
test -f "$SOURCE_MODULE" || refuse "SoftHSM2 not installed (tried both layouts)"
: "${TMPDIR:=/var/tmp/p11scope-ws-tmp}"
export TMPDIR
mkdir -p "$TMPDIR" "$WORK"
chmod 700 "$WORK"

# Pre-free rule: refuse when the cargo lane is busy at start (host
# paths only; a root guest owns its machine and carries no lane file).
if [ "$IS_ROOT" -eq 0 ]; then
    flock -n "$CARGO_LANE" true || \
        refuse "cargo lane $CARGO_LANE is busy: free it before the window"
fi

if [ "$MODE" = live ] && [ "$IS_ROOT" -eq 0 ]; then
    # An ancestor must hold the privileged lock: a concurrent privileged
    # test or capture would charge these samples. Run under
    # `flock "$LOCK" $0`. Dry-run takes no lock (nothing privileged runs)
    # and root owns its machine (no lock proof required).
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

# Best-effort source subject: a dirty tracked tree cannot be attested,
# and a staged guest carries no git at all (recorded honestly either way).
if git rev-parse HEAD >/dev/null 2>&1; then
    if [ -n "$(git status --porcelain | grep -v '^??')" ]; then
        refuse "tracked tree is dirty: commit before a soak run"
    fi
    GIT_REV=$(git rev-parse HEAD)
    GIT_TREE=$(git rev-parse 'HEAD^{tree}')
else
    GIT_REV=unknown
    GIT_TREE=unknown
fi
HARNESS_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

mono_ns() {
    python3 -I -c 'import time; print(time.monotonic_ns())'
}
# Wall-clock milliseconds, the bench-inventory-native.sh sampler clock.
now_ms() { echo $(($(date +%s%N) / 1000000)); }
KERNEL=$(uname -r)
CPU=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')
NCPU=$(nproc)

# Every run gets a private provider inode used only by the owned
# workloads, so ambient host calls can never charge the ledger join.
# As root the copy lives in a world-traversable stage dir: discover
# drops to nobody when run as root (provider code runs unprivileged
# by design), so a 0700 root dir would deny it the module.
if [ "$MODE" = live ] && [ "$IS_ROOT" -eq 1 ]; then
    STAGE=$(mktemp -d /tmp/manifest-soak-stage.XXXXXX)
    chmod 0755 "$STAGE"
    MODULE="$STAGE/libsofthsm2-owned.so"
else
    mkdir -p "$WORK/provider"
    chmod 700 "$WORK/provider"
    MODULE="$WORK/provider/libsofthsm2-owned.so"
    rm -f "$MODULE"
fi
install -m 0555 "$SOURCE_MODULE" "$MODULE"

echo "=== build ==="
gcc -O0 -o "$WORK/workload" tests/fixtures/public-cli/inventory-ledger.c -ldl -lpthread

if [ "$MODE" = live ]; then
    INSTALLED_SHA_PRE=$(sha256sum "$INSTALLED" | cut -d' ' -f1)
    INSTALLED_SIZE=$(stat -c%s "$INSTALLED")
    if [ "$IS_ROOT" -eq 1 ]; then
        # The dropped discover identity re-opens its own executable
        # mapping, so as root the private copies live in the
        # world-traversable stage dir rather than a 0700 root dir.
        rm -f "$STAGE/p11scope" "$STAGE/p11scope-discover"
        install -m 0555 "$INSTALLED" "$STAGE/p11scope"
        install -m 0555 "$DISCOVER" "$STAGE/p11scope-discover"
        INSTALLED_COPY="$STAGE/p11scope"
        DISCOVER_COPY="$STAGE/p11scope-discover"
    else
        mkdir -p "$WORK/installed"
        chmod 700 "$WORK/installed"
        rm -f "$WORK/installed/p11scope" "$WORK/installed/p11scope-discover"
        install -m 0555 "$INSTALLED" "$WORK/installed/p11scope"
        install -m 0555 "$DISCOVER" "$WORK/installed/p11scope-discover"
        INSTALLED_COPY="$WORK/installed/p11scope"
        DISCOVER_COPY="$WORK/installed/p11scope-discover"
        chmod 500 "$WORK/installed"
    fi
    OBSERVER_PRIVILEGE=user
    [ "$IS_ROOT" -eq 1 ] || OBSERVER_PRIVILEGE=root
else
    STUB_SHA=$(sha256sum "$OBSERVER_STUB" | cut -d' ' -f1)
    mkdir -p "$WORK/stub"
    chmod 700 "$WORK/stub"
    rm -f "$WORK/stub/manifest-soak-stub.py"
    install -m 0555 "$OBSERVER_STUB" "$WORK/stub/manifest-soak-stub.py"
    STUB_COPY="$WORK/stub/manifest-soak-stub.py"
    chmod 500 "$WORK/stub"
    OBSERVER_PRIVILEGE=user
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
softhsm2-util --init-token --free --label manifest-soak --so-pin 1234 --pin 1234 >/dev/null

echo "=== discover ==="
if [ "$MODE" = live ]; then
    if [ "$IS_ROOT" -eq 1 ]; then
        # The dropped discover identity cannot write into 0700 root
        # dirs: land the manifest in the sticky /tmp under a unique
        # name, then install it privately. The manifest file itself is
        # always checked: discover can report an error yet exit 0.
        MANIFEST_TMP=$(mktemp /tmp/manifest-soak-manifest.XXXXXX.json)
        env -u SOFTHSM2_CONF "$DISCOVER_COPY" --module "$MODULE" -o "$MANIFEST_TMP"
        [ -f "$MANIFEST_TMP" ] || refuse "discover wrote no manifest"
        install -m 0444 "$MANIFEST_TMP" "$WORK/manifest.json"
        rm -f "$MANIFEST_TMP"
    else
        env -u SOFTHSM2_CONF "$DISCOVER_COPY" --module "$MODULE" -o "$WORK/manifest.json"
        [ -f "$WORK/manifest.json" ] || refuse "discover wrote no manifest"
    fi
else
    cat > "$WORK/manifest.json" <<EOF
{"schema": "manifest-soak-dry-run-manifest/v1", "module": "$MODULE", "note": "shape stand-in; the stub checks existence only"}
EOF
fi

owned_require_live() {
    owned_live_state=$(owned_process_state "$1" "$2") || return 2
    case "$owned_live_state" in
        live) return 0 ;;
        terminal) return 1 ;;
        unknown) return 2 ;;
    esac
    return 2
}

# wait_attach — hold GO until pass 0 publishes (attach settled). Returns
# 2 if the observer is terminal and 3 if its identity is unknown.
wait_attach() {
    end=$(( $(date +%s) + $4 ))
    while :; do
        owned_live_status=0
        owned_require_live "$2" "$3" || owned_live_status=$?
        case "$owned_live_status" in 0) ;; 1) return 2 ;; *) return 3 ;; esac
        [ "$(date +%s)" -lt "$end" ] || return 1
        if grep -q "p11scope: pass 0:" "$1/observer.stderr" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
}

echo "=== soak: $CELL mode=$MODE horizon=${HORIZON}s callers=$CALLERS iters=$ITERS ==="
rm -f "$WORK/go"
index=1
while [ "$index" -le "$CALLERS" ]; do
    owned_launch user - "$WORK/workload-$(( index - 1 )).log" = -- \
        env SOFTHSM2_CONF="$SOFTHSM2_CONF" P11SCOPE_MEASURE_SEED="$SEED" \
        "$WORK/workload" mech --cell "W$(( index - 1 ))" --module "$MODULE" \
        --iters "$ITERS" --gate "$WORK/go" --delay-ms "$DELAY_MS" \
        --sleep-us "$SLEEP_US"
    owned_verify_launch "$OWNED_PID" "$OWNED_STARTTIME" "$OWNED_RECEIPT" || exit 1
    printf '%s %s %s %s %s\n' "$OWNED_PID" "$OWNED_STARTTIME" "$OWNED_RECEIPT" \
        "$OWNED_COMMAND_PID" "$OWNED_COMMAND_STARTTIME" > "$WORK/wl-$index.id"
    index=$(( index + 1 ))
done
index=1
while [ "$index" -le "$CALLERS" ]; do
    end=$(( $(date +%s) + 60 ))
    while ! grep -q "^READY " "$WORK/workload-$(( index - 1 )).log" 2>/dev/null; do
        [ "$(date +%s)" -lt "$end" ] || {
            echo "workload $(( index - 1 )) never became ready" >&2
            cat "$WORK/workload-$(( index - 1 )).log" >&2
            exit 1
        }
        sleep 0.1
    done
    index=$(( index + 1 ))
done

if [ "$MODE" = live ]; then
    set -- "$INSTALLED_COPY" inventory \
        --system --manifest "$WORK/manifest.json" \
        --duration "$OBSERVER_DURATION" --json -o "$WORK/report.json"
    SAMPLER_EXE_EXPECT=$INSTALLED_COPY
else
    set -- python3 -I "$STUB_COPY" inventory \
        --system --manifest "$WORK/manifest.json" \
        --duration "$OBSERVER_DURATION" --json -o "$WORK/report.json"
    loop_index=0
    while [ "$loop_index" -lt "$CALLERS" ]; do
        set -- "$@" --loopback-log "$WORK/workload-$loop_index.log"
        loop_index=$(( loop_index + 1 ))
    done
    SAMPLER_EXE_EXPECT=
fi
OBS_ARGV_JSON=$(python3 -I -c "import json,sys; print(json.dumps(sys.argv[1:]))" "$@")
T_SPAWN=$(mono_ns)
owned_launch "$OBSERVER_PRIVILEGE" - "$WORK/observer.stdout" "$WORK/observer.stderr" -- "$@"
OBSERVER_PID=$OWNED_PID; OBSERVER_STARTTIME=$OWNED_STARTTIME
OBSERVER_RECEIPT=$OWNED_RECEIPT
owned_verify_launch "$OBSERVER_PID" "$OBSERVER_STARTTIME" "$OBSERVER_RECEIPT" || exit 1
STARGET_PID=$OWNED_COMMAND_PID
STARGET_STARTTIME=$OWNED_COMMAND_STARTTIME

# The resource sampler mirrors the bench-inventory-native.sh loop: a
# separate process tracing the observer's RSS, HWM and FD count at
# 1 Hz into resources.tsv. Samples count once the pid runs the
# measured binary (live); a zombie or exiting observer is not a
# sample. In live non-root mode the loop crosses privilege with sudo
# so /proc/<observer>/fd stays readable; the file is reclaimed after.
echo "# ms rss_kb hwm_kb fds" > "$WORK/resources.tsv"
SAMPLER_START_MS=$(now_ms)
# The sampler body lives in a file so both privilege paths run the
# same bytes; values cross in (and through sudo) via env, never
# ambient exports. (An empty $sudo prefix followed by VAR=value words
# does not run under dash, hence the branch.)
cat > "$WORK/sampler-body.sh" <<'SAMPLER_EOF'
exe_ok=0
if [ -z "$SAMPLER_EXE_EXPECT" ]; then exe_ok=1; fi
while kill -0 "$SAMPLER_TARGET" 2>/dev/null; do
    if [ "$exe_ok" = 0 ]; then
        if [ "$(readlink "/proc/$SAMPLER_TARGET/exe" 2>/dev/null)" = "$SAMPLER_EXE_EXPECT" ]; then
            exe_ok=1
        fi
    fi
    if [ "$exe_ok" = 1 ]; then
        rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$SAMPLER_TARGET/status" 2>/dev/null)
        hwm=$(awk '/^VmHWM:/ {print $2}' "/proc/$SAMPLER_TARGET/status" 2>/dev/null)
        fds=$(find "/proc/$SAMPLER_TARGET/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
        ms=$(($(date +%s%N) / 1000000 - SAMPLER_START_MS))
        if [ -n "$rss" ] && [ -n "$hwm" ]; then
            echo "$ms $rss $hwm $fds" >> "$SAMPLER_OUT"
        fi
    fi
    sleep 1
done
SAMPLER_EOF
if [ "$MODE" = live ] && [ "$IS_ROOT" -eq 0 ]; then
    sudo -n env \
        "SAMPLER_TARGET=$STARGET_PID" \
        "SAMPLER_EXE_EXPECT=$SAMPLER_EXE_EXPECT" \
        "SAMPLER_START_MS=$SAMPLER_START_MS" \
        "SAMPLER_OUT=$WORK/resources.tsv" \
        sh "$WORK/sampler-body.sh" 2>"$WORK/sampler.stderr" &
else
    env \
        "SAMPLER_TARGET=$STARGET_PID" \
        "SAMPLER_EXE_EXPECT=$SAMPLER_EXE_EXPECT" \
        "SAMPLER_START_MS=$SAMPLER_START_MS" \
        "SAMPLER_OUT=$WORK/resources.tsv" \
        sh "$WORK/sampler-body.sh" 2>"$WORK/sampler.stderr" &
fi
SAMPLER_PID=$!

if wait_attach "$WORK" "$STARGET_PID" "$STARGET_STARTTIME" 600; then
    :
else
    rc=$?
    if [ "$rc" -eq 2 ]; then
        echo "observer died during attach:" >&2
        cat "$WORK/observer.stderr" >&2
    elif [ "$rc" -eq 3 ]; then
        echo "observer identity became unknown during attach:" >&2
        cat "$WORK/observer.stderr" >&2
    else
        echo "attach never settled (see $WORK/observer.stderr)" >&2
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

# Workloads finish their iters inside the horizon; the observer exits
# on its own after --duration + detach + publish.
index=1
while [ "$index" -le "$CALLERS" ]; do
    read -r wpid wstart wreceipt _wcmd _wcmdstart < "$WORK/wl-$index.id"
    if ! owned_finish "$wpid" "$wstart" "$wreceipt" $(( HORIZON + 600 )); then
        echo "workload $(( index - 1 )) settlement failed; left unreaped" >&2
        exit 1
    fi
    wrc=$OWNED_EXIT
    printf '%s %s\n' "$(cat "$WORK/wl-$index.id")" "$wrc" > "$WORK/wl-$index.done"
    rm -f "$WORK/wl-$index.id"
    [ "$wrc" -eq 0 ] || {
        echo "workload $(( index - 1 )) failed (exit=$wrc)" >&2
        cat "$WORK/workload-$(( index - 1 )).log" >&2
        exit 1
    }
    index=$(( index + 1 ))
done

OBSERVER_TIMED_OUT=false
OBSERVER_SIGNAL=null
observer_wait_state=0
owned_wait_supervisor_terminal "$OBSERVER_RECEIPT" $(( OBSERVER_DURATION + 600 )) || \
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
owned_finish "$OBSERVER_PID" "$OBSERVER_STARTTIME" "$OBSERVER_RECEIPT" 0 || {
    echo "observer descendant settlement failed; left unreaped" >&2
    exit 1
}
owned_command_outcome "$OBSERVER_RECEIPT" || {
    echo "observer receipt has no exact command outcome" >&2
    exit 1
}
OBS_RC=$OWNED_COMMAND_EXIT
OBSERVER_SIGNAL=$OWNED_COMMAND_SIGNAL
OBSERVER_PID=
OBSERVER_STARTTIME=
T_EXIT=$(mono_ns)

if [ "$MODE" = live ]; then
    INSTALLED_SHA_POST=$(sha256sum "$INSTALLED" | cut -d' ' -f1)
fi

# The sampler exits on its own once the observer is gone; bound the wait.
SAMPLER_EXIT=0
SAMPLER_SIGNAL=null
sampler_end=$(( $(date +%s) + 15 ))
while kill -0 "$SAMPLER_PID" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$sampler_end" ]; then
        kill -KILL "$SAMPLER_PID" 2>/dev/null || true
        wait "$SAMPLER_PID" 2>/dev/null || true
        SAMPLER_EXIT=137
        SAMPLER_SIGNAL=SIGKILL
        break
    fi
    sleep 0.2
done
if [ "$SAMPLER_EXIT" -eq 0 ]; then
    wait "$SAMPLER_PID" 2>/dev/null || SAMPLER_EXIT=$?
fi
SAMPLER_PID=

# A nonzero observer exit with a report is still a measurement (the rc
# is recorded and the finite-stop gate judges it); a missing report is
# a harness failure and the run refuses before the oracle.
if [ ! -f "$WORK/report.json" ]; then
    echo "observer exit=$OBS_RC wrote no report:" >&2
    cat "$WORK/observer.stderr" >&2
    exit 1
fi
if [ "$MODE" = live ] && [ "$IS_ROOT" -eq 0 ]; then
    reclaim_root_output "$WORK/report.json" "$WORK/resources.tsv" \
        "$WORK/observer.stdout" "$WORK/observer.stderr"
fi

export WORK CELL TEST_ID KERNEL_PROFILE MODE HORIZON REQUIRE_DURATION
export OBSERVER_SLACK_S OBSERVER_DURATION CALLERS ITERS SLEEP_US DELAY_MS SEED
export GIT_REV GIT_TREE HARNESS_START_ISO HARNESS_ARGV_JSON
export OBS_ARGV_JSON T_SPAWN T_GO T_EXIT MODULE
export OBS_RC OBSERVER_SIGNAL OBSERVER_TIMED_OUT SAMPLER_EXIT SAMPLER_SIGNAL
export INSTALLED INSTALLED_SHA_PRE=${INSTALLED_SHA_PRE-} INSTALLED_SHA_POST=${INSTALLED_SHA_POST-}
export INSTALLED_SIZE=${INSTALLED_SIZE-}
export OBSERVER_STUB=${OBSERVER_STUB-} STUB_SHA=${STUB_SHA-}
export KERNEL CPU NCPU LOADAVG
python3 -I - <<'PY'
import json
import os
from pathlib import Path

work = Path(os.environ["WORK"])
mode = os.environ["MODE"]
live = mode == "live"
callers = int(os.environ["CALLERS"])


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
else:
    installed = None
    stub = {"path": os.environ["OBSERVER_STUB"],
            "sha256": os.environ["STUB_SHA"]}
workloads = []
for index in range(1, callers + 1):
    fields = (work / f"wl-{index}.done").read_text(encoding="utf-8").split()
    workloads.append({
        "pid": int(fields[3]),
        "starttime": int(fields[4]),
        "log": f"workload-{index - 1}.log",
        "exit": int(fields[5]),
    })
run = {
    "schema": "p11scope/manifest-soak-run/v1",
    "cell_id": os.environ["CELL"],
    "test_ids": [os.environ["TEST_ID"]],
    "kernel_profile": os.environ["KERNEL_PROFILE"],
    "mode": mode,
    "horizon_s": integer("HORIZON"),
    "require_duration_s": integer("REQUIRE_DURATION"),
    "observer_slack_s": integer("OBSERVER_SLACK_S"),
    "observer_duration_s": integer("OBSERVER_DURATION"),
    "callers": callers,
    "iters": integer("ITERS"),
    "sleep_us": integer("SLEEP_US"),
    "delay_ms": integer("DELAY_MS"),
    "seed": integer("SEED"),
    "provider_copy": os.environ["MODULE"],
    "subject": {"revision": os.environ["GIT_REV"], "tree": os.environ["GIT_TREE"]},
    "harness": {"name": "system-manifest-soak.sh",
                "git_rev": os.environ["GIT_REV"],
                "started_iso": os.environ["HARNESS_START_ISO"],
                "argv": json.loads(os.environ["HARNESS_ARGV_JSON"])},
    "harness_argv": json.loads(os.environ["HARNESS_ARGV_JSON"]),
    "observer_argv": json.loads(os.environ["OBS_ARGV_JSON"]),
    "installed": installed,
    "stub": stub,
    "workloads": workloads,
    "observer": {"exit": integer("OBS_RC"), "signal": signal("OBSERVER_SIGNAL"),
                 "timed_out": os.environ["OBSERVER_TIMED_OUT"] == "true"},
    "sampler": {"exit": integer("SAMPLER_EXIT"), "signal": signal("SAMPLER_SIGNAL")},
    "timing": {"t_spawn_mono_ns": integer("T_SPAWN"),
               "t_go_mono_ns": integer("T_GO"),
               "start_mono_ns": integer("T_GO"),
               "end_mono_ns": integer("T_EXIT")},
    "host": {"kernel": os.environ["KERNEL"], "cpu": os.environ["CPU"],
             "ncpu": os.environ["NCPU"], "loadavg": os.environ["LOADAVG"]},
    "artifacts": {"run": "run.json", "report": "report.json",
                  "resources": "resources.tsv", "stderr": "observer.stderr"},
}
(work / "run.json").write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
PY

echo "=== oracle ==="
oracle_rc=0
python3 -I scripts/system-manifest-soak-oracle.py --evidence-dir "$WORK" \
    --out-verdict "$WORK/verdict.json" || oracle_rc=$?
echo "=== system-manifest-soak: DONE ==="
exit "$oracle_rc"

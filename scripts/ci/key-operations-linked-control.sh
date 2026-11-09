#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# key-operations-linked-control.sh — installed linked-control cells.
#
# Six cells pin the installed `--key-operations` posture at this HEAD:
#   linked-system          --system --capture native --key-operations --manifest
#   linked-pid             same with --pid (pre-seal fixture pid)
#   flag-off-s1            the workload without --key-operations at settle 0 (--s1 oracle)
#   flag-off-s1-settle10   the same workload at settle 10: no-receipt gap diagnostic (known issue)
#   flag-without-manifest  --key-operations without --manifest (finite behavior)
#   off-build-refusal      the flag on a build without the journal object
#
# Usage: flock "$LOCK" scripts/ci/key-operations-linked-control.sh P11SCOPE OUTDIR
# The script refuses unless an ancestor holds LOCK (default
# /var/tmp/p11scope-ws-tmp/privileged.lock). P11SCOPE is the observer under
# test; its sibling p11scope-discover prepares the manifest. OUTDIR receives
# results.jsonl (one row per cell: cell, pass, qualification, detail),
# per-cell evidence (ledgers, observer documents, oracle transcripts) and,
# when a linked shape is refused, the kept linked sample.
#
# Exit codes: 0 every qualified cell passed (expected-failure rows matched
# their expectation); 1 a cell failed or an expectation went stale; 2 a
# harness error; 77 a prerequisite is missing.
#
# Environment: P11SCOPE_OFF (optional off-build observer for
# off-build-refusal; without it that row is nonqualifying, never pass),
# MODULE (default: release-matrix-contract --select-module), LOCK,
# SETTLE_S (default 10: settle after the seal line before the G barrier;
# flag-off-s1 always forces 0 and the settle-10 diagnostic always uses 10),
# ADMIT_TIMEOUT_S (default 120: bound on waiting for the fixture's pid
# to be admitted before its G barrier; a timeout proceeds and records),
# DURATION (default 300: observer backstop; SIGINT after done stops it),
# FIXTURE_TIMEOUT_S (default 120: gated-fixture supervisor deadline),
# P11SCOPE_KEY_FIXTURE_TIMEOUT_MS (default 90000: the fixture's own alarm),
# TMPDIR (must be a disk filesystem; private work dir for observer output).
#
# Apt prerequisites on an ubuntu-26.04 runner: gcc, softhsm2,
# libp11-kit-dev (a real pkcs11.h), python3, sudo, flock (util-linux),
# time (GNU time for the sibling system script; harmless here).
#
# Scope note: flag-off-s1 and off-build-refusal run under --pid, not
# --system. The --s1 oracle path requires a pid-scoped document with
# exactly one callers/modules/edges/instances/semantic_edges row each;
# a --system document carries every scanned process and can never
# satisfy that singleton shape, on any host. The workload is the same
# fixture; only the scope follows the oracle's contract.
#
# Self-test-only knobs (production runs leave them unset): KEYOPS_SELFTEST_*
# (fixture/gated binaries, oracle paths, discover stub, scenario control).
# The self-test suite tests/python/test_key_operations_linked_control.py
# drives the whole script through fakes with these knobs.
set -eu
cd "$(dirname "$0")/../.."
REPO=$PWD
. scripts/lib.sh

LOCK=${LOCK:-/var/tmp/p11scope-ws-tmp/privileged.lock}
SETTLE_S=${SETTLE_S:-10}
ADMIT_TIMEOUT_S=${ADMIT_TIMEOUT_S:-120}
ADMIT_SETTLE_S=${ADMIT_SETTLE_S:-0}
REFUSE_WAIT_S=${REFUSE_WAIT_S:-15}
NOMANIFEST_CAP_S=${NOMANIFEST_CAP_S:-60}
DURATION=${DURATION:-300}
FIXTURE_TIMEOUT_S=${FIXTURE_TIMEOUT_S:-120}
FIXTURE_ALARM_MS=${P11SCOPE_KEY_FIXTURE_TIMEOUT_MS:-90000}
SEAL_LINE="p11scope: semantic lane ready"
SELFTEST=${KEYOPS_SELFTEST_NO_PRIV:-0}

is_positive_int() {
    case $1 in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -gt 0 ]
}

is_non_negative_int() {
    case $1 in ''|*[!0-9]*) return 1 ;; esac
    return 0
}

say() { echo "key-operations-linked-control: $*"; }
die() { echo "key-operations-linked-control: harness error: $*" >&2; exit 2; }
missing() { echo "key-operations-linked-control: missing prerequisite: $*" >&2; exit 77; }

[ "$#" -eq 2 ] || { echo "usage: $0 P11SCOPE OUTDIR" >&2; exit 2; }
P11SCOPE=$1 OUTDIR=$2
[ -x "$P11SCOPE" ] || { echo "usage: P11SCOPE is not executable: $P11SCOPE" >&2; exit 2; }
is_non_negative_int "$SETTLE_S" || { echo "usage: SETTLE_S is a non-negative integer" >&2; exit 2; }
is_positive_int "$ADMIT_TIMEOUT_S" || { echo "usage: ADMIT_TIMEOUT_S is a positive integer" >&2; exit 2; }
is_non_negative_int "$ADMIT_SETTLE_S" || { echo "usage: ADMIT_SETTLE_S is a non-negative integer" >&2; exit 2; }
is_positive_int "$REFUSE_WAIT_S" || { echo "usage: REFUSE_WAIT_S is a positive integer" >&2; exit 2; }
is_positive_int "$NOMANIFEST_CAP_S" || { echo "usage: NOMANIFEST_CAP_S is a positive integer" >&2; exit 2; }
is_positive_int "$DURATION" || { echo "usage: DURATION is a positive integer" >&2; exit 2; }
is_positive_int "$FIXTURE_TIMEOUT_S" || { echo "usage: FIXTURE_TIMEOUT_S is a positive integer" >&2; exit 2; }
is_positive_int "$FIXTURE_ALARM_MS" || { echo "usage: P11SCOPE_KEY_FIXTURE_TIMEOUT_MS is a positive integer" >&2; exit 2; }
case $P11SCOPE in /*) : ;; *) P11SCOPE=$REPO/$P11SCOPE ;; esac
mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"

CHECKS=$REPO/scripts/ci/key_operations_checks.py
DRIVER=$REPO/scripts/ci/key_operations_fixture.py
SIGNAL_EXEC=$REPO/scripts/ci/run_default_signals.py
QUALIFY=${KEYOPS_SELFTEST_QUALIFY:-$REPO/scripts/qualify-key-operations.py}
LEDGER_CHECK=${KEYOPS_SELFTEST_LEDGER_CHECK:-$REPO/scripts/key-operation-ledger.py}
FIXTURE_SRC_DEFAULT=$REPO/tests/fixtures/key-operations/rsa-ledger.c
GATED_SRC=$REPO/tests/fixtures/public-cli/gated.c
DISCOVER_DEFAULT=$(dirname "$P11SCOPE")/p11scope-discover
DISCOVER=${KEYOPS_SELFTEST_DISCOVER:-$DISCOVER_DEFAULT}

# Private work dir: the observer refuses an output directory below any
# group- or other-writable ancestor, so every -o file lives here and is
# copied to OUTDIR at the end of each cell.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-keyops-linked-XXXXXX")
chmod 0700 "$WORK"
BIN=$WORK/bin
mkdir -p "$BIN"

OBSERVER_PID=
DRIVER_PID=
SEED_PID=

# pid_alive PID: true while PID exists and has not exited. Not kill -0:
# the observer runs under sudo, whose front-end briefly holds every uid
# as root, and kill -0 from the caller then fails with EPERM although
# the observer lives (a false "observer died" with an empty stderr).
pid_alive() {
    [ -n "$1" ] || return 1
    state=$(sed -n 's/.*) \([A-Za-z]\) .*/\1/p' "/proc/$1/stat" 2>/dev/null)
    [ -n "$state" ] && [ "$state" != Z ] && [ "$state" != X ]
}

# signal_observer SIG: deliver SIG to the observer exactly once. A send
# refused with EPERM during sudo's root window was never delivered, so
# it is retried while the observer lives; one delivered signal stays one.
signal_observer() {
    [ -n "$OBSERVER_PID" ] || return 0
    tries=0
    while ! kill "-$1" "$OBSERVER_PID" 2>/dev/null; do
        pid_alive "$OBSERVER_PID" || return 0
        tries=$((tries + 1))
        [ "$tries" -lt 100 ] || { echo "could not signal observer $OBSERVER_PID with $1" >&2; return 1; }
        sleep 0.05
    done
    return 0
}
cleanup() {
    status=$?
    trap - EXIT INT TERM
    [ -z "$SEED_PID" ] || kill -TERM "$SEED_PID" 2>/dev/null || true
    [ -z "$DRIVER_PID" ] || kill -TERM "$DRIVER_PID" 2>/dev/null || true
    signal_observer TERM || true
    [ -z "$SEED_PID" ] || wait "$SEED_PID" 2>/dev/null || true
    [ -z "$DRIVER_PID" ] || wait "$DRIVER_PID" 2>/dev/null || true
    [ -z "$OBSERVER_PID" ] || wait "$OBSERVER_PID" 2>/dev/null || true
    exit "$status"
}
. scripts/cleanup-traps.sh

row() {
    # row CELL PASS QUALIFICATION DETAIL >> results.jsonl
    python3 -I - "$OUTDIR/results.jsonl" "$1" "$2" "$3" "$4" <<'EOF' || die "results write failed"
import json, sys
path, cell, passed, qual, detail = sys.argv[1:6]
row = {"cell": cell, "pass": passed == "1",
       "qualification": qual, "detail": detail}
with open(path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(row) + "\n")
print(json.dumps(row))
EOF
}

if [ "$SELFTEST" != 1 ]; then
    command -v gcc >/dev/null || missing "gcc"
    command -v softhsm2-util >/dev/null || missing "softhsm2-util"
    command -v flock >/dev/null || missing "flock"
    command -v sudo >/dev/null || missing "sudo"
    sudo -n true 2>/dev/null || missing "passwordless sudo"
    [ -x "$DISCOVER" ] || missing "p11scope-discover beside $P11SCOPE"
    # An ancestor must hold the privileged lock: a concurrent privileged
    # test or capture would corrupt these linked cells.
    python3 -I - "$LOCK" "$$" <<'EOF' || die "run under flock $LOCK: no ancestor holds the privileged lock"
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

if [ -n "${MODULE-}" ]; then
    PROVIDER=$MODULE
else
    PROVIDER=$(python3 -I scripts/release-matrix-contract.py --select-module 2>/dev/null) \
        || missing "no SoftHSM provider (release-matrix-contract --select-module failed)"
fi
[ -f "$PROVIDER" ] || missing "SoftHSM provider not a file: $PROVIDER"

find_header_dir() {
    if [ -n "${PKCS11_HEADER_DIR-}" ]; then
        [ -f "$PKCS11_HEADER_DIR/pkcs11.h" ] && { echo "$PKCS11_HEADER_DIR"; return 0; }
        return 1
    fi
    for dir in /usr/include /usr/include/softhsm /usr/include/p11-kit-1/p11-kit; do
        [ -f "$dir/pkcs11.h" ] && { echo "$dir"; return 0; }
    done
    # The workspace build populates the cargo registry beside the P11SCOPE
    # binary build; cryptoki-sys vendors the header there.
    for header in "$HOME"/.cargo/registry/src/*/cryptoki-sys-*/vendor/pkcs11.h; do
        [ -f "$header" ] && { dirname "$header"; return 0; }
    done
    return 1
}

if [ -n "${KEYOPS_SELFTEST_FIXTURE_BIN-}" ]; then
    FIXTURE=$KEYOPS_SELFTEST_FIXTURE_BIN
else
    HEADER_DIR=$(find_header_dir) || missing "no pkcs11.h (tried system dirs and cryptoki-sys vendor)"
    gcc -O2 -Wall -Wextra -Werror -I "$HEADER_DIR" -o "$BIN/rsa-ledger" \
        "$FIXTURE_SRC_DEFAULT" -ldl || die "rsa-ledger does not compile"
    FIXTURE=$BIN/rsa-ledger
fi
if [ -n "${KEYOPS_SELFTEST_GATED_BIN-}" ]; then
    GATED=$KEYOPS_SELFTEST_GATED_BIN
else
    command -v gcc >/dev/null || missing "gcc"
    gcc -O1 -Wall -Wextra -Werror -o "$BIN/gated" "$GATED_SRC" -ldl \
        || die "gated anchor does not compile"
    GATED=$BIN/gated
fi

say "provider: $PROVIDER"
say "fixture: $FIXTURE"

if [ "$SELFTEST" != 1 ]; then
    export SOFTHSM2_CONF=$WORK/softhsm2.conf
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
    softhsm2-util --init-token --free --label keyops-linked --so-pin 1234 --pin 1234 \
        >/dev/null || die "token init failed"
    "$DISCOVER" --module "$PROVIDER" -o "$WORK/manifest.json" || die "discover failed"
    MANIFEST=$WORK/manifest.json
else
    MANIFEST=${KEYOPS_SELFTEST_MANIFEST:-$WORK/manifest.json}
    [ -f "$MANIFEST" ] || echo '{"selftest": true}' > "$MANIFEST"
fi
export P11SCOPE_KEY_FIXTURE_PIN=1234
export P11SCOPE_KEY_FIXTURE_TIMEOUT_MS=$FIXTURE_ALARM_MS

# The root observer must see the disposable token: stock sudoers
# scrubs SOFTHSM2_CONF, so preserve it like the bench script does.
SUDO="sudo -n --preserve-env=SOFTHSM2_CONF"
[ "$SELFTEST" = 1 ] && SUDO=""

# wait_for_line FILE PREFIX TIMEOUT_S: the linked-ready signal is the
# semantic seal line (SEMANTIC_SEAL_LINE, src/inventory/mod.rs); linkage
# itself is judged from the document, never from stderr.
wait_for_line() {
    end=$(( $(date +%s) + $3 ))
    while ! grep -Fq "$2" "$1" 2>/dev/null; do
        if [ -n "$OBSERVER_PID" ] && ! pid_alive "$OBSERVER_PID"; then
            echo "observer died before [$2]" >&2
            return 1
        fi
        [ "$(date +%s)" -lt "$end" ] || { echo "never saw [$2] within $3s" >&2; return 1; }
        sleep 0.2
    done
    return 0
}

# start_seed CELLDIR: hold the provider mapped so pass 0 attaches.
start_seed() {
    "$GATED" "$PROVIDER" 0 0 "$1/gate-never" > "$1/seed.log" 2>&1 &
    SEED_PID=$!
    end=$(( $(date +%s) + 60 ))
    while ! grep -q "^READY" "$1/seed.log" 2>/dev/null; do
        kill -0 "$SEED_PID" 2>/dev/null || { echo "seed died" >&2; return 1; }
        [ "$(date +%s)" -lt "$end" ] || { echo "seed never READY" >&2; return 1; }
        sleep 0.05
    done
    return 0
}

stop_seed() {
    [ -z "$SEED_PID" ] || kill -TERM "$SEED_PID" 2>/dev/null || true
    [ -z "$SEED_PID" ] || wait "$SEED_PID" 2>/dev/null || true
    SEED_PID=
}

# reap_leftovers: a failed flow returns with its family alive (the
# observer keeps BPF loaded, the seed holds its session). Reap every
# tracked child before the next cell starts so a failure cannot corrupt
# it. TERM only; the one-SIGINT rule governs the observer's own stop.
reap_leftovers() {
    signal_observer TERM || true
    for pid in "$DRIVER_PID" "$SEED_PID"; do
        [ -n "$pid" ] || continue
        kill -TERM "$pid" 2>/dev/null || true
    done
    for pid in "$OBSERVER_PID" "$DRIVER_PID" "$SEED_PID"; do
        [ -n "$pid" ] || continue
        wait "$pid" 2>/dev/null || true
    done
    OBSERVER_PID=
    DRIVER_PID=
    SEED_PID=
}

# stop_observer: one SIGINT, then a bounded wait; a second signal would
# cancel the joint finish, so there is exactly one. Returns 1 only when
# the observer never stops; the observer's own exit lands in
# OBSERVER_STOP_EXIT (a nonzero observer exit is a cell verdict, never a
# harness death, so this function returns 0 for it).
OBSERVER_STOP_EXIT=0
stop_observer() {
    [ -n "$OBSERVER_PID" ] || return 0
    signal_observer INT || true
    end=$(( $(date +%s) + 180 ))
    while pid_alive "$OBSERVER_PID"; do
        [ "$(date +%s)" -lt "$end" ] || { echo "observer did not stop within 180s" >&2; return 1; }
        sleep 0.5
    done
    wait "$OBSERVER_PID" 2>/dev/null
    OBSERVER_STOP_EXIT=$?
    OBSERVER_PID=
    return 0
}

copy_evidence() {
    # copy_evidence CELLDIR NAME...: hand root-owned files back, then copy.
    dir=$1; shift
    for file in "$@"; do
        [ -f "$dir/$file" ] || continue
        if [ "$SELFTEST" != 1 ]; then
            reclaim_root_output "$dir/$file" || return 1
        fi
        cp "$dir/$file" "$OUTDIR/$file" || return 1
    done
    return 0
}

# run_linked_flow CELLDIR OBSERVER_BIN SCOPE_ARGS: seed, observer, gated
# fixture, SIGINT after done. Prints the fixture pid when SCOPE_ARGS
# needs it (linked-pid starts its observer after the fixture spawns).
# Sets OBSERVER_EXIT. Returns nonzero on harness failure.
# sync_and_release DIR: with the driver spawned and settled (DRIVER_PID
# set) and the observer running, parse the fixture pid, wait for a pass
# to admit it, release its G barrier and wait for done. Returns 1 on
# flow failure. An admission timeout proceeds and records: the workload
# may still attach on demand, and the oracle/counts judge vacuity.
sync_and_release() {
    dir=$1
    fixture_pid=$(sed -n 's/^pid=//p' "$dir/driver.log" 2>/dev/null | head -n 1)
    [ -n "$fixture_pid" ] || { echo "driver never spawned the fixture" >&2; return 1; }
    admit_end=$(( $(date +%s) + ADMIT_TIMEOUT_S ))
    admitted=no
    while ! grep -Fq "admitted (pid $fixture_pid)" "$dir/observer.stderr" 2>/dev/null; do
        if ! kill -0 "$DRIVER_PID" 2>/dev/null; then
            echo "driver exited before admission" >&2
            return 1
        fi
        if ! pid_alive "$OBSERVER_PID"; then
            echo "observer exited before admission" >&2
            return 1
        fi
        if [ "$(date +%s)" -ge "$admit_end" ]; then
            break
        fi
        sleep 0.5
    done
    if grep -Fq "admitted (pid $fixture_pid)" "$dir/observer.stderr" 2>/dev/null; then
        admitted=yes
    fi
    echo "fixture pid $fixture_pid admitted before G: $admitted" | tee "$dir/admit-sync.txt" >&2
    # Admission is the manifest/module grant; the semantic receipt and the
    # pre/post-boundary gating may still be settling. ADMIT_SETTLE_S holds
    # G back so a rerun can test whether the S1 count is settle-sensitive.
    sleep "$ADMIT_SETTLE_S"
    : > "$dir/gofile"
    end=$(( $(date +%s) + FIXTURE_TIMEOUT_S ))
    while [ ! -f "$dir/donefile" ]; do
        if ! kill -0 "$DRIVER_PID" 2>/dev/null; then
            echo "driver exited before done" >&2
            cat "$dir/driver.stderr" >&2 2>/dev/null || true
            return 1
        fi
        if ! pid_alive "$OBSERVER_PID"; then
            echo "observer exited before done" >&2
            tail -n 20 "$dir/observer.stderr" >&2 2>/dev/null || true
            return 1
        fi
        [ "$(date +%s)" -lt "$end" ] || { echo "fixture never done" >&2; return 1; }
        sleep 0.2
    done
    return 0
}

run_linked_flow() {
    dir=$1 observer=$2
    shift 2
    reap_leftovers
    mkdir -p "$dir" && chmod 0700 "$dir" || die "cell dir $dir"
    start_seed "$dir" || return 1
    if [ "$1" = "--pid-from-driver" ]; then
        shift
        rm -f "$dir/gofile" "$dir/donefile" "$dir/stopfile"
        python3 -I "$DRIVER" "$FIXTURE" "$PROVIDER" "$dir/ledger.jsonl" \
            "$dir/gofile" "$dir/donefile" "$dir/stopfile" \
            "$FIXTURE_TIMEOUT_S" > "$dir/driver.log" 2> "$dir/driver.stderr" &
        DRIVER_PID=$!
        end=$(( $(date +%s) + 60 ))
        while ! grep -q "^pid=" "$dir/driver.log" 2>/dev/null; do
            kill -0 "$DRIVER_PID" 2>/dev/null || { echo "driver died" >&2; return 1; }
            [ "$(date +%s)" -lt "$end" ] || { echo "driver never spawned" >&2; return 1; }
            sleep 0.1
        done
        fixture_pid=$(sed -n 's/^pid=//p' "$dir/driver.log" | head -n 1)
        # shellcheck disable=SC2086
        $SUDO python3 -I "$SIGNAL_EXEC" "$observer" inventory --pid "$fixture_pid" "$@" \
            -o "$dir/out.json" > "$dir/observer.log" 2> "$dir/observer.stderr" &
        OBSERVER_PID=$!
        # The fixture is already up (pre-seal); the workload must still
        # land post-attach, so seal and settle before its G barrier.
        wait_for_line "$dir/observer.stderr" "$SEAL_LINE" 120 || return 1
        sleep "$SETTLE_S"
    else
        rm -f "$dir/gofile" "$dir/donefile" "$dir/stopfile"
        # shellcheck disable=SC2086
        $SUDO python3 -I "$SIGNAL_EXEC" "$observer" inventory "$@" \
            -o "$dir/out.json" > "$dir/observer.log" 2> "$dir/observer.stderr" &
        OBSERVER_PID=$!
        wait_for_line "$dir/observer.stderr" "$SEAL_LINE" 120 || return 1
        sleep "$SETTLE_S"
        python3 -I "$DRIVER" "$FIXTURE" "$PROVIDER" "$dir/ledger.jsonl" \
            "$dir/gofile" "$dir/donefile" "$dir/stopfile" \
            "$FIXTURE_TIMEOUT_S" > "$dir/driver.log" 2> "$dir/driver.stderr" &
        DRIVER_PID=$!
        sleep 2
    fi
    sync_and_release "$dir" || return 1
    stop_observer || return 1
    OBSERVER_EXIT=$OBSERVER_STOP_EXIT
    : > "$dir/stopfile"
    wait "$DRIVER_PID" 2>/dev/null || { echo "driver failed" >&2; return 1; }
    DRIVER_PID=
    stop_seed
    return 0
}

# collect_failure_evidence CELLDIR PREFIX: best-effort copy of the
# failure diagnostics (never dies: the row below must still be written).
collect_failure_evidence() {
    copy_evidence "$1" observer.stderr driver.stderr flow.stderr || true
    for file in observer.stderr driver.stderr flow.stderr; do
        [ -f "$OUTDIR/$file" ] && mv "$OUTDIR/$file" "$OUTDIR/$2-$file"
    done
    return 0
}

# flow_reason PREFIX: the flow's own last words for a failed row.
flow_reason() {
    reason=$(tail -n 2 "$OUTDIR/$1-flow.stderr" 2>/dev/null | tr '\n' ';')
    echo "${reason:-no diagnostic captured}"
}

# refused_exit: true iff the flow's observer is already dead with a
# nonzero exit (a refused start, R-58). Never waits on a live
# observer: a still-running observer is not a refusal. Reaps the dead
# observer so the next cell's reap starts clean.
refused_exit() {
    [ -n "$OBSERVER_PID" ] || return 1
    if pid_alive "$OBSERVER_PID"; then
        return 1
    fi
    if wait "$OBSERVER_PID" 2>/dev/null; then
        OBSERVER_PID=
        return 1
    fi
    OBSERVER_PID=
    return 0
}

# run_no_manifest_cell: the flag without --manifest. No fixture, no seal
# wait: since DEMO-4 the semantic lane seals from scan-discovered tables
# after an engine-changing pass (or stays unsealed when no provider is
# discovered); either way the capture is accepted. A startup refusal exits
# inside REFUSE_WAIT_S; otherwise the capture is accepted and observed
# until stderr goes quiet for SETTLE_S or NOMANIFEST_CAP_S elapses (a
# continuous scanner never idles, so the bound stops it), then one
# SIGINT stops it and the row records what the capture holds. Sets
# NOMANIFEST_MODE (accept|refuse) and NOMANIFEST_EXIT. Returns 1 on
# flow failure (the observer exits mid-observe or never stops).
run_no_manifest_cell() {
    CELLDIR=$WORK/flag-without-manifest
    reap_leftovers
    mkdir -p "$CELLDIR" && chmod 0700 "$CELLDIR" || die "cell dir $CELLDIR"
    start_seed "$CELLDIR" || die "seed failed"
    # shellcheck disable=SC2086
    $SUDO python3 -I "$SIGNAL_EXEC" "$P11SCOPE" inventory --system --capture native --key-operations \
        --duration "$DURATION" -o "$CELLDIR/out.json" \
        > "$CELLDIR/observer.log" 2> "$CELLDIR/observer.stderr" &
    OBSERVER_PID=$!
    refuse_end=$(( $(date +%s) + REFUSE_WAIT_S ))
    while pid_alive "$OBSERVER_PID"; do
        [ "$(date +%s)" -lt "$refuse_end" ] || break
        sleep 0.5
    done
    if pid_alive "$OBSERVER_PID"; then
        NOMANIFEST_MODE=accept
        settle_end=$(( $(date +%s) + NOMANIFEST_CAP_S ))
        quiet_since=$(date +%s)
        last_size=$(wc -c < "$CELLDIR/observer.stderr" 2>/dev/null || echo 0)
        while :; do
            sleep 1
            size=$(wc -c < "$CELLDIR/observer.stderr" 2>/dev/null || echo 0)
            now=$(date +%s)
            if [ "$size" != "$last_size" ]; then
                last_size=$size
                quiet_since=$now
            fi
            if ! pid_alive "$OBSERVER_PID"; then
                echo "observer exited while observing" >&2
                return 1
            fi
            [ $(( now - quiet_since )) -lt "$SETTLE_S" ] || break
            if [ "$now" -ge "$settle_end" ]; then
                echo "observe bound ${NOMANIFEST_CAP_S}s reached" >&2
                break
            fi
        done
        stop_observer || return 1
        NOMANIFEST_EXIT=$OBSERVER_STOP_EXIT
        stop_seed
        copy_evidence "$CELLDIR" out.json observer.stderr || die "evidence copy failed"
        if [ -f "$OUTDIR/out.json" ]; then
            mv "$OUTDIR/out.json" "$OUTDIR/no-manifest.json" || die "evidence rename failed"
        fi
        mv "$OUTDIR/observer.stderr" "$OUTDIR/no-manifest-observer.stderr" || die "evidence rename failed"
    else
        NOMANIFEST_MODE=refuse
        NOMANIFEST_EXIT=0
        wait "$OBSERVER_PID" 2>/dev/null || NOMANIFEST_EXIT=$?
        OBSERVER_PID=
        stop_seed
        copy_evidence "$CELLDIR" observer.stderr || die "evidence copy failed"
        mv "$OUTDIR/observer.stderr" "$OUTDIR/no-manifest-observer.stderr" || die "evidence rename failed"
    fi
    return 0
}

# run_off_build_cell: the flag on the P11SCOPE_OFF build. Runs under
# --pid like flag-off-s1, so the accept branch's --s1 gate can qualify
# (a --system document can never satisfy the singleton shape). Sets
# OFF_MODE (accept|refuse) and OFF_EXIT. Returns 1 on flow failure.
run_off_build_cell() {
    CELLDIR=$WORK/off-build-refusal
    reap_leftovers
    mkdir -p "$CELLDIR" && chmod 0700 "$CELLDIR" || die "cell dir $CELLDIR"
    start_seed "$CELLDIR" || die "seed failed"
    rm -f "$CELLDIR/gofile" "$CELLDIR/donefile" "$CELLDIR/stopfile"
    python3 -I "$DRIVER" "$FIXTURE" "$PROVIDER" "$CELLDIR/ledger.jsonl" \
        "$CELLDIR/gofile" "$CELLDIR/donefile" "$CELLDIR/stopfile" \
        "$FIXTURE_TIMEOUT_S" > "$CELLDIR/driver.log" 2> "$CELLDIR/driver.stderr" &
    DRIVER_PID=$!
    end=$(( $(date +%s) + 60 ))
    while ! grep -q "^pid=" "$CELLDIR/driver.log" 2>/dev/null; do
        kill -0 "$DRIVER_PID" 2>/dev/null || { echo "driver died" >&2; return 1; }
        [ "$(date +%s)" -lt "$end" ] || { echo "driver never spawned" >&2; return 1; }
        sleep 0.1
    done
    fixture_pid=$(sed -n 's/^pid=//p' "$CELLDIR/driver.log" | head -n 1)
    # shellcheck disable=SC2086
    $SUDO python3 -I "$SIGNAL_EXEC" "$P11SCOPE_OFF" inventory --pid "$fixture_pid" --capture native \
        --key-operations --manifest "$MANIFEST" --duration "$DURATION" \
        -o "$CELLDIR/out.json" \
        > "$CELLDIR/observer.log" 2> "$CELLDIR/observer.stderr" &
    OBSERVER_PID=$!
    sleep 2
    if pid_alive "$OBSERVER_PID"; then
        OFF_MODE=accept
        wait_for_line "$CELLDIR/observer.stderr" "$SEAL_LINE" 120 || return 1
        sleep "$SETTLE_S"
        sync_and_release "$CELLDIR" || return 1
        stop_observer || return 1
        OFF_EXIT=$OBSERVER_STOP_EXIT
        : > "$CELLDIR/stopfile"
        wait "$DRIVER_PID" 2>/dev/null || { echo "driver failed" >&2; return 1; }
        DRIVER_PID=
        stop_seed
        copy_evidence "$CELLDIR" out.json ledger.jsonl observer.stderr driver.log admit-sync.txt \
            || die "evidence copy failed"
        mv "$OUTDIR/out.json" "$OUTDIR/off-build.json" || die "evidence rename failed"
        mv "$OUTDIR/ledger.jsonl" "$OUTDIR/off-build-ledger.jsonl" || die "evidence rename failed"
        mv "$OUTDIR/observer.stderr" "$OUTDIR/off-build-observer.stderr" || die "evidence rename failed"
        mv "$OUTDIR/driver.log" "$OUTDIR/off-build-driver.log" || die "evidence rename failed"
        mv "$OUTDIR/admit-sync.txt" "$OUTDIR/off-build-admit-sync.txt" || die "evidence rename failed"
    else
        OFF_MODE=refuse
        OFF_EXIT=0
        wait "$OBSERVER_PID" 2>/dev/null || OFF_EXIT=$?
        OBSERVER_PID=
        [ -z "$DRIVER_PID" ] || kill -TERM "$DRIVER_PID" 2>/dev/null || true
        [ -z "$DRIVER_PID" ] || wait "$DRIVER_PID" 2>/dev/null || true
        DRIVER_PID=
        stop_seed
        copy_evidence "$CELLDIR" observer.stderr || die "evidence copy failed"
        mv "$OUTDIR/observer.stderr" "$OUTDIR/off-build-observer.stderr" || die "evidence rename failed"
    fi
    return 0
}

FAILURES=0

# --- linked-system ---
say "--- linked-system ---"
CELLDIR=$WORK/linked-system
export KEYOPS_SELFTEST_SCENARIO=${KEYOPS_SELFTEST_SCENARIO_LINKED_SYSTEM:-}
mkdir -p "$CELLDIR" && chmod 0700 "$CELLDIR" || die "cell dir $CELLDIR"
if run_linked_flow "$CELLDIR" "$P11SCOPE" --system --capture native \
        --key-operations --manifest "$MANIFEST" --duration "$DURATION" \
        2> "$CELLDIR/flow.stderr"; then
    copy_evidence "$CELLDIR" out.json ledger.jsonl observer.stderr driver.log admit-sync.txt \
        || die "evidence copy failed"
    mv "$OUTDIR/out.json" "$OUTDIR/linked-system.json" || die "evidence rename failed"
    mv "$OUTDIR/ledger.jsonl" "$OUTDIR/linked-system-ledger.jsonl" || die "evidence rename failed"
    mv "$OUTDIR/observer.stderr" "$OUTDIR/linked-system-observer.stderr" || die "evidence rename failed"
    mv "$OUTDIR/driver.log" "$OUTDIR/linked-system-driver.log" || die "evidence rename failed"
    mv "$OUTDIR/admit-sync.txt" "$OUTDIR/linked-system-admit-sync.txt" || die "evidence rename failed"
    if python3 -I "$LEDGER_CHECK" "$OUTDIR/linked-system-ledger.jsonl" \
            > "$OUTDIR/linked-system-ledger-check.log" 2>&1; then
        if ! oo_line=$(python3 -I "$CHECKS" oo "$OUTDIR/linked-system.json"); then
            row linked-system 0 failed \
                "observer report missing or unparsable on exit $OBSERVER_EXIT"
            FAILURES=$((FAILURES + 1))
        else
            oo_status=${oo_line%% *}; oo_status=${oo_status#status=}
            oo_reason=${oo_line#*reason=}
            if [ "$OBSERVER_EXIT" -ne 0 ]; then
                row linked-system 0 failed \
                    "observer exit $OBSERVER_EXIT with object_observations $oo_status ($oo_reason): not the pinned signature (exit 0)"
                FAILURES=$((FAILURES + 1))
            elif [ "$oo_status" = "populated" ]; then
                if python3 -I "$QUALIFY" "$OUTDIR/linked-system-ledger.jsonl" \
                        "$OUTDIR/linked-system.json" \
                        > "$OUTDIR/linked-system-oracle.log" 2>&1; then
                    row linked-system 1 qualified \
                        "oracle compare passed on observer exit $OBSERVER_EXIT"
                else
                    cp "$OUTDIR/linked-system.json" "$OUTDIR/linked-sample.json" || die "sample copy failed"
                    oracle_text=$(tail -n 5 "$OUTDIR/linked-system-oracle.log" | tr '\n' ';')
                    row linked-system 0 failed \
                        "oracle refused the populated linked shape: $oracle_text (sample: linked-sample.json)"
                    FAILURES=$((FAILURES + 1))
                fi
            elif [ "$oo_status" = "unavailable" ] && [ "$oo_reason" = "journal_unavailable" ]; then
                if python3 -I "$QUALIFY" "$OUTDIR/linked-system-ledger.jsonl" \
                        "$OUTDIR/linked-system.json" \
                        > "$OUTDIR/linked-system-oracle.log" 2>&1; then
                    row linked-system 0 failed \
                        "oracle unexpectedly passed on unavailable (journal_unavailable); the pinned refusal went stale"
                    FAILURES=$((FAILURES + 1))
                else
                    oracle_text=" oracle: $(tail -n 3 "$OUTDIR/linked-system-oracle.log" | tr '\n' ';')"
                    cp "$OUTDIR/linked-system.json" "$OUTDIR/linked-sample.json" || die "sample copy failed"
                    row linked-system 0 failed \
                        "object_observations unavailable (journal_unavailable) on exit $OBSERVER_EXIT is a stale pin on a linked lane;$oracle_text (sample: linked-sample.json)"
                    FAILURES=$((FAILURES + 1))
                fi
            elif [ "$oo_status" = "unavailable" ] && [ "$oo_reason" = "bootstrap_unavailable" ]; then
                gap_text=$(python3 -I - "$OUTDIR/linked-system.json" <<'EOF' || echo "gaps unreadable"
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except Exception:
    print("report unparsable")
    sys.exit(0)
gaps = doc.get("gaps") or []
if not gaps:
    print("no gaps")
else:
    parts = []
    for gap in gaps:
        if type(gap) is not dict:
            continue
        parts.append("%s/%s x%s" % (gap.get("subject"), gap.get("reason"), gap.get("repeats")))
    print("gaps: %s" % ("; ".join(parts)[:500] if parts else "no gaps"))
EOF
                )
                cp "$OUTDIR/linked-system.json" "$OUTDIR/linked-sample.json" || die "sample copy failed"
                if python3 -I "$QUALIFY" "$OUTDIR/linked-system-ledger.jsonl" \
                        "$OUTDIR/linked-system.json" \
                        > "$OUTDIR/linked-system-oracle.log" 2>&1; then
                    oracle_note="oracle unexpectedly passed"
                else
                    oracle_note="oracle: $(tail -n 3 "$OUTDIR/linked-system-oracle.log" | tr '\n' ';')"
                fi
                row linked-system 0 failed \
                    "object_observations unavailable (bootstrap_unavailable) on exit $OBSERVER_EXIT: $gap_text; $oracle_note (sample: linked-sample.json)"
                FAILURES=$((FAILURES + 1))
            else
                row linked-system 0 failed \
                    "object_observations $oo_status ($oo_reason) on exit $OBSERVER_EXIT: not the pinned signature (exit 0 + populated with an oracle pass)"
                FAILURES=$((FAILURES + 1))
            fi
        fi
    else
        row linked-system 0 failed "application ledger failed validation"
        FAILURES=$((FAILURES + 1))
    fi
else
    collect_failure_evidence "$CELLDIR" linked-system
    if grep -q "journal-pair-unavailable-in-build" \
            "$OUTDIR/linked-system-observer.stderr" 2>/dev/null \
        && [ ! -f "$CELLDIR/out.json" ] && refused_exit; then
        row linked-system 1 expected-failure \
            "flag refused at start on this build: journal-pair-unavailable-in-build (R-58; the linked comparison is unproven here)"
    else
        row linked-system 0 failed \
            "flow failed: $(flow_reason linked-system)"
        FAILURES=$((FAILURES + 1))
    fi
fi

# --- linked-pid ---
say "--- linked-pid ---"
CELLDIR=$WORK/linked-pid
export KEYOPS_SELFTEST_SCENARIO=${KEYOPS_SELFTEST_SCENARIO_LINKED_PID:-}
mkdir -p "$CELLDIR" && chmod 0700 "$CELLDIR" || die "cell dir $CELLDIR"
if run_linked_flow "$CELLDIR" "$P11SCOPE" --pid-from-driver --capture native \
        --key-operations --manifest "$MANIFEST" --duration "$DURATION" \
        2> "$CELLDIR/flow.stderr"; then
    copy_evidence "$CELLDIR" out.json ledger.jsonl observer.stderr driver.log admit-sync.txt \
        || die "evidence copy failed"
    mv "$OUTDIR/out.json" "$OUTDIR/linked-pid.json" || die "evidence rename failed"
    mv "$OUTDIR/ledger.jsonl" "$OUTDIR/linked-pid-ledger.jsonl" || die "evidence rename failed"
    mv "$OUTDIR/observer.stderr" "$OUTDIR/linked-pid-observer.stderr" || die "evidence rename failed"
    mv "$OUTDIR/driver.log" "$OUTDIR/linked-pid-driver.log" || die "evidence rename failed"
    mv "$OUTDIR/admit-sync.txt" "$OUTDIR/linked-pid-admit-sync.txt" || die "evidence rename failed"
    if ! oo_line=$(python3 -I "$CHECKS" oo "$OUTDIR/linked-pid.json"); then
        row linked-pid 0 failed "observer report missing or unparsable"
        FAILURES=$((FAILURES + 1))
    else
        oo_status=${oo_line%% *}; oo_status=${oo_status#status=}
        oo_reason=${oo_line#*reason=}
        if [ "$oo_status" = "populated" ]; then
            if python3 -I "$QUALIFY" "$OUTDIR/linked-pid-ledger.jsonl" \
                    "$OUTDIR/linked-pid.json" \
                    > "$OUTDIR/linked-pid-oracle.log" 2>&1; then
                if [ "$OBSERVER_EXIT" -ne 0 ]; then
                    row linked-pid 0 failed \
                        "observer exit $OBSERVER_EXIT with object_observations $oo_status ($oo_reason): not the pinned signature (exit 0)"
                    FAILURES=$((FAILURES + 1))
                else
                    row linked-pid 1 qualified \
                        "post-closure exec observed under --pid; oracle compare passed"
                fi
            elif [ "$OBSERVER_EXIT" -eq 0 ]; then
                oracle_text=$(tail -n 5 "$OUTDIR/linked-pid-oracle.log" | tr '\n' ';')
                row linked-pid 0 failed \
                    "post-closure exec observed under --pid but oracle refused: $oracle_text"
                FAILURES=$((FAILURES + 1))
            else
                oracle_text=$(tail -n 5 "$OUTDIR/linked-pid-oracle.log" | tr '\n' ';')
                row linked-pid 0 failed \
                    "observer exit $OBSERVER_EXIT with a refused populated shape: $oracle_text: not the pinned signature (exit 0)"
                FAILURES=$((FAILURES + 1))
            fi
        elif [ "$oo_status" = "unavailable" ] && [ "$oo_reason" = "journal_unavailable" ]; then
            row linked-pid 0 failed \
                "object_observations unavailable (journal_unavailable): stale pin on a linked lane (want bootstrap_unavailable while no Joint feed exists); the named pid exec'd before the seal and PID scope pins an existing process"
            FAILURES=$((FAILURES + 1))
        else
            # The only namable pid exec'd before the seal: PID scope pins an
            # existing process, so no post-closure birth is observable there.
            # Linked lanes read bootstrap_unavailable while no Joint feed exists.
            row linked-pid 0 nonqualifying \
                "object_observations $oo_status ($oo_reason): the named pid exec'd before the seal and PID scope pins an existing process, so a post-closure exec is unobservable (linked lanes read bootstrap_unavailable while no Joint feed exists)"
        fi
    fi
else
    collect_failure_evidence "$CELLDIR" linked-pid
    if grep -q "journal-pair-unavailable-in-build" \
            "$OUTDIR/linked-pid-observer.stderr" 2>/dev/null \
        && [ ! -f "$CELLDIR/out.json" ] && refused_exit; then
        row linked-pid 1 expected-failure \
            "flag refused at start on this build: journal-pair-unavailable-in-build (R-58; the pid comparison is unproven here)"
    else
        row linked-pid 0 failed \
            "flow failed: $(flow_reason linked-pid)"
        FAILURES=$((FAILURES + 1))
    fi
fi

# --- flag-off-s1 (settle 0) ---
say "--- flag-off-s1 ---"
CELLDIR=$WORK/flag-off-s1
export KEYOPS_SELFTEST_SCENARIO=${KEYOPS_SELFTEST_SCENARIO_FLAG_OFF_S1:-}
mkdir -p "$CELLDIR" && chmod 0700 "$CELLDIR" || die "cell dir $CELLDIR"
FLAG_OFF_S1_SETTLE_SAVED=$SETTLE_S
SETTLE_S=0
FLAG_OFF_S1_EFFECTIVE=$SETTLE_S
if run_linked_flow "$CELLDIR" "$P11SCOPE" --pid-from-driver --capture native \
        --manifest "$MANIFEST" --duration "$DURATION" \
        2> "$CELLDIR/flow.stderr"; then
    SETTLE_S=$FLAG_OFF_S1_SETTLE_SAVED
    copy_evidence "$CELLDIR" out.json ledger.jsonl observer.stderr driver.log admit-sync.txt \
        || die "evidence copy failed"
    mv "$OUTDIR/out.json" "$OUTDIR/flag-off-s1.json" || die "evidence rename failed"
    mv "$OUTDIR/ledger.jsonl" "$OUTDIR/flag-off-s1-ledger.jsonl" || die "evidence rename failed"
    mv "$OUTDIR/observer.stderr" "$OUTDIR/flag-off-s1-observer.stderr" || die "evidence rename failed"
    mv "$OUTDIR/driver.log" "$OUTDIR/flag-off-s1-driver.log" || die "evidence rename failed"
    mv "$OUTDIR/admit-sync.txt" "$OUTDIR/flag-off-s1-admit-sync.txt" || die "evidence rename failed"
    if ! oo_line=$(python3 -I "$CHECKS" oo "$OUTDIR/flag-off-s1.json"); then
        row flag-off-s1 0 failed "observer report missing or unparsable"
        FAILURES=$((FAILURES + 1))
    else
        oo_status=${oo_line%% *}; oo_status=${oo_status#status=}
        oo_reason=${oo_line#*reason=}
        if [ "$oo_status" = "unavailable" ] && [ -n "$oo_reason" ]; then
            if python3 -I "$QUALIFY" --s1 "$OUTDIR/flag-off-s1-ledger.jsonl" \
                    "$OUTDIR/flag-off-s1.json" \
                    > "$OUTDIR/flag-off-s1-oracle.log" 2>&1; then
                row flag-off-s1 1 qualified \
                    "--s1 compare passed at settle $FLAG_OFF_S1_EFFECTIVE; object_observations unavailable ($oo_reason)"
            else
                oracle_text=$(tail -n 5 "$OUTDIR/flag-off-s1-oracle.log" | tr '\n' ';')
                row flag-off-s1 0 failed "--s1 compare failed at settle $FLAG_OFF_S1_EFFECTIVE: $oracle_text"
                FAILURES=$((FAILURES + 1))
            fi
        else
            row flag-off-s1 0 failed \
                "object_observations reads $oo_status ($oo_reason), want unavailable with a finite reason"
            FAILURES=$((FAILURES + 1))
        fi
    fi
else
    SETTLE_S=$FLAG_OFF_S1_SETTLE_SAVED
    collect_failure_evidence "$CELLDIR" flag-off-s1
    row flag-off-s1 0 failed \
        "flow failed: $(flow_reason flag-off-s1)"
    FAILURES=$((FAILURES + 1))
fi

# --- flag-off-s1-settle10 (diagnostic, known issue) ---
say "--- flag-off-s1-settle10 ---"
CELLDIR=$WORK/flag-off-s1-settle10
export KEYOPS_SELFTEST_SCENARIO=${KEYOPS_SELFTEST_SCENARIO_FLAG_OFF_S1_SETTLE10:-}
mkdir -p "$CELLDIR" && chmod 0700 "$CELLDIR" || die "cell dir $CELLDIR"
if [ "$SELFTEST" = 1 ]; then
    DIAG_SETTLE_S=${KEYOPS_SELFTEST_DIAG_SETTLE_S:-0}
else
    DIAG_SETTLE_S=10
fi
is_non_negative_int "$DIAG_SETTLE_S" || die "diagnostic settle is not a non-negative integer"
DIAG_SETTLE_SAVED=$SETTLE_S
SETTLE_S=$DIAG_SETTLE_S
if run_linked_flow "$CELLDIR" "$P11SCOPE" --pid-from-driver --capture native \
        --manifest "$MANIFEST" --duration "$DURATION" \
        2> "$CELLDIR/flow.stderr"; then
    SETTLE_S=$DIAG_SETTLE_SAVED
    copy_evidence "$CELLDIR" out.json ledger.jsonl observer.stderr driver.log admit-sync.txt \
        || die "evidence copy failed"
    mv "$OUTDIR/out.json" "$OUTDIR/flag-off-s1-settle10.json" || die "evidence rename failed"
    mv "$OUTDIR/ledger.jsonl" "$OUTDIR/flag-off-s1-settle10-ledger.jsonl" || die "evidence rename failed"
    mv "$OUTDIR/observer.stderr" "$OUTDIR/flag-off-s1-settle10-observer.stderr" || die "evidence rename failed"
    mv "$OUTDIR/driver.log" "$OUTDIR/flag-off-s1-settle10-driver.log" || die "evidence rename failed"
    mv "$OUTDIR/admit-sync.txt" "$OUTDIR/flag-off-s1-settle10-admit-sync.txt" || die "evidence rename failed"
    if ! oo_line=$(python3 -I "$CHECKS" oo "$OUTDIR/flag-off-s1-settle10.json"); then
        row flag-off-s1-settle10 0 failed "observer report missing or unparsable"
        FAILURES=$((FAILURES + 1))
    else
        oo_status=${oo_line%% *}; oo_status=${oo_status#status=}
        oo_reason=${oo_line#*reason=}
        if [ "$oo_status" = "unavailable" ] && [ -n "$oo_reason" ]; then
            gap_count=$(python3 -I - "$OUTDIR/flag-off-s1-settle10.json" <<'EOF' || echo "unreadable"
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except Exception:
    print("unreadable")
    sys.exit(0)
total = 0
for gap in doc.get("gaps") or []:
    if type(gap) is not dict:
        continue
    if gap.get("subject") == "semantic admission refused" \
            and gap.get("reason") == "semantic_unavailable:no_receipt" \
            and type(gap.get("repeats")) is int:
        total += gap["repeats"]
print(total)
EOF
            )
            case "$gap_count" in
                ''|*[!0-9]*)
                    row flag-off-s1-settle10 0 failed \
                        "no_receipt gap count unreadable ($gap_count)"
                    FAILURES=$((FAILURES + 1))
                    ;;
                *)
                    if python3 -I "$QUALIFY" --s1 "$OUTDIR/flag-off-s1-settle10-ledger.jsonl" \
                            "$OUTDIR/flag-off-s1-settle10.json" \
                            > "$OUTDIR/flag-off-s1-settle10-oracle.log" 2>&1; then
                        oracle_note="oracle passed"
                    else
                        oracle_note="oracle: $(tail -n 3 "$OUTDIR/flag-off-s1-settle10-oracle.log" | tr '\n' ';')"
                    fi
                    row flag-off-s1-settle10 1 qualified \
                        "settle-10 diagnostic: $gap_count no_receipt admission gaps (known issue, not a failure); object_observations unavailable ($oo_reason); $oracle_note"
                    ;;
            esac
        else
            row flag-off-s1-settle10 0 failed \
                "object_observations reads $oo_status ($oo_reason), want unavailable with a finite reason"
            FAILURES=$((FAILURES + 1))
        fi
    fi
else
    SETTLE_S=$DIAG_SETTLE_SAVED
    collect_failure_evidence "$CELLDIR" flag-off-s1-settle10
    row flag-off-s1-settle10 0 failed \
        "flow failed: $(flow_reason flag-off-s1-settle10)"
    FAILURES=$((FAILURES + 1))
fi

# --- flag-without-manifest ---
say "--- flag-without-manifest ---"
export KEYOPS_SELFTEST_SCENARIO=${KEYOPS_SELFTEST_SCENARIO_NO_MANIFEST:-}
mkdir -p "$WORK/flag-without-manifest" && chmod 0700 "$WORK/flag-without-manifest" || die "cell dir"
if run_no_manifest_cell 2> "$WORK/flag-without-manifest/flow.stderr"; then
    if [ "$NOMANIFEST_MODE" = accept ]; then
        # usage.md requires only --capture and the journal build for the
        # flag, so acceptance is a recorded outcome, not a refusal miss.
        if [ "$NOMANIFEST_EXIT" -eq 0 ] && [ -f "$OUTDIR/no-manifest.json" ]; then
            passes=$(grep -o "pass [0-9][0-9]*" "$OUTDIR/no-manifest-observer.stderr" 2>/dev/null | tail -n 1)
            passes=${passes:-pass none}
            shape=$(python3 -I -c '
import json,sys
try:
    doc=json.load(open(sys.argv[1]))
except Exception as exc:
    sys.exit("invalid JSON: %s" % exc)
if not isinstance(doc,dict):
    sys.exit("not an object")
oo=doc.get("object_observations")
oo=oo if isinstance(oo,dict) else {}
def count(key):
    val=doc.get(key)
    return len(val) if isinstance(val,list) else "?"
print("keys=%s; oo=%s(%s); callers=%s; semantic_edges=%s" % (
    ",".join(sorted(doc))[:160], oo.get("status"), oo.get("reason"),
    count("callers"), count("semantic_edges")))' "$OUTDIR/no-manifest.json") || shape=""
            if [ -n "$shape" ]; then
                row flag-without-manifest 1 qualified \
                    "accepted: exit 0, $passes, $shape"
            else
                row flag-without-manifest 0 failed \
                    "accepted but the output is not a JSON object (exit 0)"
                FAILURES=$((FAILURES + 1))
            fi
        elif [ "$NOMANIFEST_EXIT" -eq 0 ]; then
            row flag-without-manifest 0 failed \
                "accepted but no output file was written (exit 0)"
            FAILURES=$((FAILURES + 1))
        else
            row flag-without-manifest 0 failed \
                "accepted but the stop failed: exit $NOMANIFEST_EXIT"
            FAILURES=$((FAILURES + 1))
        fi
    else
        if [ -f "$WORK/flag-without-manifest/out.json" ]; then
            row flag-without-manifest 0 failed \
                "refused with exit $NOMANIFEST_EXIT but an output file was opened"
            FAILURES=$((FAILURES + 1))
        elif [ "$NOMANIFEST_EXIT" -eq 0 ]; then
            row flag-without-manifest 0 failed \
                "exited 0 within ${REFUSE_WAIT_S}s without running and without output"
            FAILURES=$((FAILURES + 1))
        else
            message=$(tail -n 3 "$OUTDIR/no-manifest-observer.stderr" | tr '\n' ';')
            row flag-without-manifest 1 qualified \
                "refused before any output file opened: exit $NOMANIFEST_EXIT: $message"
        fi
    fi
else
    collect_failure_evidence "$WORK/flag-without-manifest" no-manifest
    last_pass=$(grep "pass [0-9]" "$OUTDIR/no-manifest-observer.stderr" 2>/dev/null | tail -n 1 | tr '\n' ';')
    row flag-without-manifest 0 failed \
        "flow failed: $(flow_reason no-manifest); last pass: ${last_pass:-none}"
    FAILURES=$((FAILURES + 1))
fi

# --- off-build-refusal ---
say "--- off-build-refusal ---"
if [ -z "${P11SCOPE_OFF-}" ]; then
    row off-build-refusal 0 nonqualifying \
        "no P11SCOPE_OFF observer supplied; the refusal is unproven"
else
    [ -x "$P11SCOPE_OFF" ] || die "P11SCOPE_OFF is not executable: $P11SCOPE_OFF"
    CELLDIR=$WORK/off-build-refusal
    export KEYOPS_SELFTEST_SCENARIO=${KEYOPS_SELFTEST_SCENARIO_OFF_BUILD:-}
    mkdir -p "$CELLDIR" && chmod 0700 "$CELLDIR" || die "cell dir $CELLDIR"
    if run_off_build_cell 2> "$CELLDIR/flow.stderr"; then
        if [ "$OFF_MODE" != accept ]; then
            stderr_text=$(cat "$OUTDIR/off-build-observer.stderr")
            # R-58: a refused start prints its reason on stderr, exits nonzero
            # and writes no report. The journal object is missing at build, so
            # the flag refuses the start; S1-inside-a-running-capture does not
            # apply because no capture runs.
            case "$stderr_text" in
                *journal-pair-unavailable-in-build*)
                    if [ -f "$CELLDIR/out.json" ]; then
                        row off-build-refusal 0 failed \
                            "refused start but an output file was opened (exit $OFF_EXIT)"
                        FAILURES=$((FAILURES + 1))
                    elif [ "$OFF_EXIT" -eq 0 ]; then
                        row off-build-refusal 0 failed \
                            "refused start but exit 0"
                        FAILURES=$((FAILURES + 1))
                    else
                        row off-build-refusal 1 qualified \
                            "refused start: exit $OFF_EXIT, journal-pair-unavailable-in-build, no report (R-58)"
                    fi
                    ;;
                *)
                    row off-build-refusal 0 failed \
                        "off build exited $OFF_EXIT without the journal-pair-unavailable-in-build disclosure"
                    FAILURES=$((FAILURES + 1))
                    ;;
            esac
        else
            if ! oo_line=$(python3 -I "$CHECKS" oo "$OUTDIR/off-build.json"); then
                row off-build-refusal 0 failed "observer report missing or unparsable"
                FAILURES=$((FAILURES + 1))
            else
                oo_status=${oo_line%% *}; oo_status=${oo_status#status=}
                oo_reason=${oo_line#*reason=}
                stderr_text=$(cat "$OUTDIR/off-build-observer.stderr")
                case "$stderr_text" in
                    *journal-pair-unavailable-in-build*)
                        if [ "$OFF_EXIT" -eq 0 ] && [ "$oo_status" = "unavailable" ] && [ -n "$oo_reason" ] \
                            && python3 -I "$QUALIFY" --s1 "$OUTDIR/off-build-ledger.jsonl" \
                                "$OUTDIR/off-build.json" \
                                > "$OUTDIR/off-build-oracle.log" 2>&1; then
                            row off-build-refusal 1 qualified \
                                "finite journal-pair-unavailable-in-build disclosure with a completed S1 capture (exit $OFF_EXIT)"
                        else
                            row off-build-refusal 0 failed \
                                "disclosure present but no completed S1 capture: exit $OFF_EXIT, object_observations $oo_status ($oo_reason)"
                            FAILURES=$((FAILURES + 1))
                        fi
                        ;;
                    *)
                        row off-build-refusal 0 failed \
                            "no journal-pair-unavailable-in-build disclosure on exit $OFF_EXIT"
                        FAILURES=$((FAILURES + 1))
                        ;;
                esac
            fi
        fi
    else
        collect_failure_evidence "$CELLDIR" off-build
        row off-build-refusal 0 failed \
            "flow failed: $(flow_reason off-build)"
        FAILURES=$((FAILURES + 1))
    fi
fi

say "failures: $FAILURES"
[ "$FAILURES" -eq 0 ] || exit 1
exit 0

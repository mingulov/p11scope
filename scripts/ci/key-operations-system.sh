#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# key-operations-system.sh — 60 s linked churn: no discovery-ring loss.
#
# Runs `inventory --system --capture native --key-operations --manifest`
# for DURATION seconds (default 60) beside background churn (paced
# short-lived exec+exit at about 200/s, a paced SoftHSM caller loop, one
# gated rsa-ledger run after the seal), then the same run without the
# flag as a loss-attribution twin. Rows:
#   churn-on       loss gates on the flag run (exit, ring_loss, loss
#                  gaps, complete stop, churn floors) plus peak RSS/CPU
#   churn-on-ledger  the rsa-ledger rows: compared (pass), refused on
#                  a populated report (failed, sample kept), or
#                  unavailable (expected-failure)
#   churn-twin     the same loss gates on the flag-off twin
#
# Usage: flock "$LOCK" scripts/ci/key-operations-system.sh P11SCOPE OUTDIR
# OUTDIR receives results.jsonl plus per-run evidence. Exit codes: 0
# every qualified row passed; 1 a row failed or an expectation went
# stale; 2 a harness error; 77 a prerequisite is missing.
#
# Environment: MODULE (default: release-matrix-contract --select-module),
# LOCK, DURATION (default 60), SETTLE_S (default 10),
# ADMIT_TIMEOUT_S (default 120: bound on waiting for the fixture's pid
# to be admitted before its G barrier; a timeout proceeds and records),
# EXEC_FLOOR_PER_S (default 50: the vacuity floor for the exec churn —
# below this the churn proves nothing; the loop itself runs unpaced and
# the achieved rate, normally several hundred per second, is recorded),
# CALL_RATE (default 1k: gen-calls paced rate), FIXTURE_TIMEOUT_S
# (default 120), P11SCOPE_KEY_FIXTURE_TIMEOUT_MS (default 90000), TMPDIR.
#
# Apt prerequisites on an ubuntu-26.04 runner: gcc, softhsm2,
# libp11-kit-dev (a real pkcs11.h), python3, sudo, flock (util-linux),
# time (GNU time: peak RSS and CPU share of the observer).
#
# Self-test-only knobs (production runs leave them unset): KEYOPS_SELFTEST_*
# (fixture/gated/gencalls binaries, oracle paths, discover stub, scenario
# control). Suite: tests/python/test_key_operations_system.py.
set -eu
cd "$(dirname "$0")/../.."
REPO=$PWD
. scripts/lib.sh

LOCK=${LOCK:-/var/tmp/p11scope-ws-tmp/privileged.lock}
DURATION=${DURATION:-60}
SETTLE_S=${SETTLE_S:-10}
ADMIT_TIMEOUT_S=${ADMIT_TIMEOUT_S:-120}
EXEC_FLOOR_PER_S=${EXEC_FLOOR_PER_S:-50}
CALL_RATE=${CALL_RATE:-1k}
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

say() { echo "key-operations-system: $*"; }
die() { echo "key-operations-system: harness error: $*" >&2; exit 2; }
missing() { echo "key-operations-system: missing prerequisite: $*" >&2; exit 77; }

[ "$#" -eq 2 ] || { echo "usage: $0 P11SCOPE OUTDIR" >&2; exit 2; }
P11SCOPE=$1 OUTDIR=$2
[ -x "$P11SCOPE" ] || { echo "usage: P11SCOPE is not executable: $P11SCOPE" >&2; exit 2; }
is_positive_int "$DURATION" || { echo "usage: DURATION is a positive integer" >&2; exit 2; }
is_non_negative_int "$SETTLE_S" || { echo "usage: SETTLE_S is a non-negative integer" >&2; exit 2; }
is_positive_int "$ADMIT_TIMEOUT_S" || { echo "usage: ADMIT_TIMEOUT_S is a positive integer" >&2; exit 2; }
is_positive_int "$EXEC_FLOOR_PER_S" || { echo "usage: EXEC_FLOOR_PER_S is a positive integer" >&2; exit 2; }
is_positive_int "$FIXTURE_TIMEOUT_S" || { echo "usage: FIXTURE_TIMEOUT_S is a positive integer" >&2; exit 2; }
is_positive_int "$FIXTURE_ALARM_MS" || { echo "usage: P11SCOPE_KEY_FIXTURE_TIMEOUT_MS is a positive integer" >&2; exit 2; }
case $P11SCOPE in /*) : ;; *) P11SCOPE=$REPO/$P11SCOPE ;; esac
mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"

CHECKS=$REPO/scripts/ci/key_operations_checks.py
DRIVER=$REPO/scripts/ci/key_operations_fixture.py
QUALIFY=${KEYOPS_SELFTEST_QUALIFY:-$REPO/scripts/qualify-key-operations.py}
LEDGER_CHECK=${KEYOPS_SELFTEST_LEDGER_CHECK:-$REPO/scripts/key-operation-ledger.py}
FIXTURE_SRC_DEFAULT=$REPO/tests/fixtures/key-operations/rsa-ledger.c
GATED_SRC=$REPO/tests/fixtures/public-cli/gated.c
GENCALLS_SRC=$REPO/tests/fixtures/joint-throughput/gen-calls.c
DISCOVER_DEFAULT=$(dirname "$P11SCOPE")/p11scope-discover
DISCOVER=${KEYOPS_SELFTEST_DISCOVER:-$DISCOVER_DEFAULT}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-keyops-system-XXXXXX")
chmod 0700 "$WORK"
BIN=$WORK/bin
mkdir -p "$BIN"

OBSERVER_PID=
DRIVER_PID=
SEED_PID=
EXEC_PID=
CALLER_PID=
cleanup() {
    status=$?
    trap - EXIT INT TERM
    [ -z "$CALLER_PID" ] || kill -TERM "$CALLER_PID" 2>/dev/null || true
    [ -z "$EXEC_PID" ] || kill -TERM "$EXEC_PID" 2>/dev/null || true
    [ -z "$SEED_PID" ] || kill -TERM "$SEED_PID" 2>/dev/null || true
    [ -z "$DRIVER_PID" ] || kill -TERM "$DRIVER_PID" 2>/dev/null || true
    [ -z "$OBSERVER_PID" ] || kill -TERM "$OBSERVER_PID" 2>/dev/null || true
    [ -z "$CALLER_PID" ] || wait "$CALLER_PID" 2>/dev/null || true
    [ -z "$EXEC_PID" ] || wait "$EXEC_PID" 2>/dev/null || true
    [ -z "$SEED_PID" ] || wait "$SEED_PID" 2>/dev/null || true
    [ -z "$DRIVER_PID" ] || wait "$DRIVER_PID" 2>/dev/null || true
    [ -z "$OBSERVER_PID" ] || wait "$OBSERVER_PID" 2>/dev/null || true
    exit "$status"
}
. scripts/cleanup-traps.sh

row() {
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
    command -v time >/dev/null || missing "GNU time"
    sudo -n true 2>/dev/null || missing "passwordless sudo"
    [ -x "$DISCOVER" ] || missing "p11scope-discover beside $P11SCOPE"
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
TIME_BIN=$(command -v time) || missing "GNU time"

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
if [ -n "${KEYOPS_SELFTEST_GENCALLS_BIN-}" ]; then
    GENCALLS=$KEYOPS_SELFTEST_GENCALLS_BIN
else
    command -v gcc >/dev/null || missing "gcc"
    gcc -O2 -Wall -Wextra -Werror -o "$BIN/gen-calls" "$GENCALLS_SRC" -ldl -lpthread \
        || die "gen-calls does not compile"
    GENCALLS=$BIN/gen-calls
fi

say "provider: $PROVIDER"
say "duration: ${DURATION}s exec floor: ${EXEC_FLOOR_PER_S}/s call rate: $CALL_RATE"

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
    softhsm2-util --init-token --free --label keyops-system --so-pin 1234 --pin 1234 \
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

wait_for_line() {
    end=$(( $(date +%s) + $3 ))
    while ! grep -Fq "$2" "$1" 2>/dev/null; do
        if [ -n "$OBSERVER_PID" ] && ! kill -0 "$OBSERVER_PID" 2>/dev/null; then
            echo "observer died before [$2]" >&2
            return 1
        fi
        [ "$(date +%s)" -lt "$end" ] || { echo "never saw [$2] within $3s" >&2; return 1; }
        sleep 0.2
    done
    return 0
}

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

# reap_leftovers: a failed window returns with its family alive. Reap
# every tracked child before the next window starts so a failure cannot
# corrupt it.
reap_leftovers() {
    for pid in "$OBSERVER_PID" "$DRIVER_PID" "$SEED_PID" "$EXEC_PID" "$CALLER_PID"; do
        [ -n "$pid" ] || continue
        kill -TERM "$pid" 2>/dev/null || true
    done
    for pid in "$OBSERVER_PID" "$DRIVER_PID" "$SEED_PID" "$EXEC_PID" "$CALLER_PID"; do
        [ -n "$pid" ] || continue
        wait "$pid" 2>/dev/null || true
    done
    OBSERVER_PID=
    DRIVER_PID=
    SEED_PID=
    EXEC_PID=
    CALLER_PID=
}

copy_evidence() {
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

# run_churn_window DIR: one DURATION capture with churn. Extra observer
# args follow DIR. Sets RUN_EXIT, RUN_EXECS, RUN_EXEC_RATE, RUN_CALLS,
# RUN_CALLER_EXIT, RUN_RSS_KB, RUN_CPU_PCT. Returns nonzero on harness
# failure (never on a failed gate: gates are judged by the caller).
run_churn_window() {
    dir=$1
    shift
    reap_leftovers
    mkdir -p "$dir" && chmod 0700 "$dir" || die "cell dir $dir"
    start_seed "$dir" || return 1
    rm -f "$dir/gofile" "$dir/donefile" "$dir/stopfile"
    # shellcheck disable=SC2086
    $SUDO "$TIME_BIN" -v -o "$dir/time.txt" "$P11SCOPE" inventory "$@" \
        -o "$dir/out.json" > "$dir/observer.log" 2> "$dir/observer.stderr" &
    OBSERVER_PID=$!
    wait_for_line "$dir/observer.stderr" "$SEAL_LINE" 120 || return 1
    sleep "$SETTLE_S"
    # Short-lived exec+exit churn in the background, time-bounded and
    # counted. Unpaced: a shell loop body already costs more than a
    # 1/200 s pacing sleep, so pacing would only cap the rate below the
    # target; the clock is read every 100 iterations to amortize `date`.
    # The achieved rate is recorded; the floor below guards vacuity.
    (
        exec_end=$(( $(date +%s) + DURATION ))
        exec_i=0
        while :; do
            /bin/true
            exec_i=$((exec_i + 1))
            if [ $((exec_i % 100)) -eq 0 ] && [ "$(date +%s)" -ge "$exec_end" ]; then
                break
            fi
        done
        echo "EXEC_ITERS=$exec_i"
    ) > "$dir/exec.log" 2>&1 &
    EXEC_PID=$!
    "$GENCALLS" "$PROVIDER" single "$CALL_RATE" "$DURATION" "$dir/calls.jsonl" \
        > "$dir/caller.log" 2>&1 &
    CALLER_PID=$!
    python3 -I "$DRIVER" "$FIXTURE" "$PROVIDER" "$dir/ledger.jsonl" \
        "$dir/gofile" "$dir/donefile" "$dir/stopfile" \
        "$FIXTURE_TIMEOUT_S" > "$dir/driver.log" 2> "$dir/driver.stderr" &
    DRIVER_PID=$!
    sleep 2
    # Admit-sync: hold the fixture at its G barrier until a pass admits
    # its pid, so the workload lands on an admitted endpoint. A timeout
    # proceeds and records; the gates below judge vacuity, not this wait.
    fixture_pid=$(sed -n 's/^pid=//p' "$dir/driver.log" 2>/dev/null | head -n 1)
    [ -n "$fixture_pid" ] || { echo "driver never spawned the fixture" >&2; return 1; }
    admit_end=$(( $(date +%s) + ADMIT_TIMEOUT_S ))
    admitted=no
    while ! grep -Fq "admitted (pid $fixture_pid)" "$dir/observer.stderr" 2>/dev/null; do
        kill -0 "$DRIVER_PID" 2>/dev/null || { echo "driver exited before admission" >&2; return 1; }
        kill -0 "$OBSERVER_PID" 2>/dev/null || { echo "observer exited before admission" >&2; return 1; }
        if [ "$(date +%s)" -ge "$admit_end" ]; then
            break
        fi
        sleep 0.5
    done
    if grep -Fq "admitted (pid $fixture_pid)" "$dir/observer.stderr" 2>/dev/null; then
        admitted=yes
    fi
    echo "fixture pid $fixture_pid admitted before G: $admitted" > "$dir/admit-sync.txt"
    : > "$dir/gofile"
    end=$(( $(date +%s) + FIXTURE_TIMEOUT_S ))
    while [ ! -f "$dir/donefile" ]; do
        kill -0 "$DRIVER_PID" 2>/dev/null || { echo "driver exited before done" >&2; return 1; }
        kill -0 "$OBSERVER_PID" 2>/dev/null || { echo "observer exited before done" >&2; return 1; }
        [ "$(date +%s)" -lt "$end" ] || { echo "fixture never done" >&2; return 1; }
        sleep 0.2
    done
    : > "$dir/stopfile"
    wait "$DRIVER_PID" 2>/dev/null || { echo "driver failed" >&2; return 1; }
    DRIVER_PID=
    # The observer stops itself at --duration; the churn ends by its own
    # clock. Reap everything with a bound (DURATION + 300 s margin).
    end=$(( $(date +%s) + DURATION + 300 ))
    while kill -0 "$OBSERVER_PID" 2>/dev/null; do
        [ "$(date +%s)" -lt "$end" ] || { echo "observer never stopped" >&2; return 1; }
        sleep 1
    done
    RUN_EXIT=0
    wait "$OBSERVER_PID" 2>/dev/null || RUN_EXIT=$?
    OBSERVER_PID=
    wait "$EXEC_PID" 2>/dev/null || true
    EXEC_PID=
    RUN_CALLER_EXIT=0
    wait "$CALLER_PID" 2>/dev/null || RUN_CALLER_EXIT=$?
    CALLER_PID=
    stop_seed
    RUN_EXECS=$(sed -n 's/^EXEC_ITERS=//p' "$dir/exec.log" | tail -n 1)
    RUN_EXECS=${RUN_EXECS:-0}
    RUN_EXEC_RATE=$(python3 -I -c "print(int('$RUN_EXECS') / int('$DURATION'))")
    RUN_CALLS=$(grep -c '"kind":"call"' "$dir/calls.jsonl" 2>/dev/null || true)
    RUN_CALLS=${RUN_CALLS:-0}
    if [ "$SELFTEST" != 1 ]; then
        reclaim_root_output "$dir/time.txt" || return 1
    fi
    RUN_RSS_KB=$(sed -n 's/.*Maximum resident set size (kbytes): //p' "$dir/time.txt" | tail -n 1)
    RUN_CPU_PCT=$(sed -n 's/.*Percent of CPU this job got: //p' "$dir/time.txt" | tail -n 1)
    RUN_RSS_KB=${RUN_RSS_KB:-unknown}
    RUN_CPU_PCT=${RUN_CPU_PCT:-unknown}
    return 0
}

FAILURES=0

# --- churn-on ---
say "--- churn-on ---"
export KEYOPS_SELFTEST_SCENARIO=${KEYOPS_SELFTEST_SCENARIO_ON:-}
ON_FLOW_OK=1
if run_churn_window "$WORK/churn-on" --system --capture native \
        --key-operations --manifest "$MANIFEST" --duration "$DURATION"; then
    ON_EXIT=$RUN_EXIT
    ON_EXECS=$RUN_EXECS
    ON_EXEC_RATE=$RUN_EXEC_RATE
    ON_CALLS=$RUN_CALLS
    ON_CALLER_EXIT=$RUN_CALLER_EXIT
    ON_RSS=$RUN_RSS_KB
    ON_CPU=$RUN_CPU_PCT
    copy_evidence "$WORK/churn-on" out.json ledger.jsonl observer.stderr \
        driver.log exec.log caller.log calls.jsonl time.txt admit-sync.txt || die "evidence copy failed"
    for base in out.json ledger.jsonl observer.stderr driver.log exec.log caller.log time.txt admit-sync.txt; do
        mv "$OUTDIR/$base" "$OUTDIR/churn-on-$base" || die "evidence rename failed"
    done
    mv "$OUTDIR/calls.jsonl" "$OUTDIR/churn-on-calls.jsonl" || die "evidence rename failed"
else
    ON_FLOW_OK=0
    # Best-effort failure diagnostics for the row below.
    copy_evidence "$WORK/churn-on" observer.stderr driver.stderr || true
    for base in observer.stderr driver.stderr; do
        [ -f "$OUTDIR/$base" ] && mv "$OUTDIR/$base" "$OUTDIR/churn-on-$base"
    done
fi

# --- churn-twin ---
say "--- churn-twin ---"
export KEYOPS_SELFTEST_SCENARIO=${KEYOPS_SELFTEST_SCENARIO_TWIN:-}
TWIN_FLOW_OK=1
if run_churn_window "$WORK/churn-twin" --system --capture native \
        --manifest "$MANIFEST" --duration "$DURATION"; then
    TWIN_EXIT=$RUN_EXIT
    TWIN_EXECS=$RUN_EXECS
    TWIN_EXEC_RATE=$RUN_EXEC_RATE
    TWIN_CALLS=$RUN_CALLS
    TWIN_CALLER_EXIT=$RUN_CALLER_EXIT
    TWIN_RSS=$RUN_RSS_KB
    TWIN_CPU=$RUN_CPU_PCT
    copy_evidence "$WORK/churn-twin" out.json ledger.jsonl observer.stderr \
        driver.log exec.log caller.log calls.jsonl time.txt admit-sync.txt || die "evidence copy failed"
    for base in out.json ledger.jsonl observer.stderr driver.log exec.log caller.log time.txt admit-sync.txt; do
        mv "$OUTDIR/$base" "$OUTDIR/churn-twin-$base" || die "evidence rename failed"
    done
    mv "$OUTDIR/calls.jsonl" "$OUTDIR/churn-twin-calls.jsonl" || die "evidence rename failed"
else
    TWIN_FLOW_OK=0
fi

# Judge the on-run loss gates.
if [ "$ON_FLOW_OK" -eq 0 ]; then
    ON_RING_TXT="flow failed"
else
    ON_GATE_FAIL=""
    ring_out=$(python3 -I "$CHECKS" ring-loss "$OUTDIR/churn-on-out.json") \
        || ON_GATE_FAIL="ring-loss: $ring_out"
    gap_out=$(python3 -I "$CHECKS" no-loss-gap "$OUTDIR/churn-on-out.json") \
        || ON_GATE_FAIL="${ON_GATE_FAIL:+$ON_GATE_FAIL; }gaps: $gap_out"
    stop_out=$(python3 -I "$CHECKS" stop "$ON_EXIT" \
        "$OUTDIR/churn-on-observer.stderr" "$OUTDIR/churn-on-out.json") \
        || ON_GATE_FAIL="${ON_GATE_FAIL:+$ON_GATE_FAIL; }stop: $stop_out"
    exec_floor=$((EXEC_FLOOR_PER_S * DURATION))
    if [ "$ON_EXECS" -lt "$exec_floor" ]; then
        ON_GATE_FAIL="${ON_GATE_FAIL:+$ON_GATE_FAIL; }exec churn shortfall: $ON_EXECS below floor $exec_floor"
    fi
    if [ "$ON_CALLER_EXIT" -ne 0 ] || [ "$ON_CALLS" -le 0 ]; then
        ON_GATE_FAIL="${ON_GATE_FAIL:+$ON_GATE_FAIL; }caller churn failed: exit $ON_CALLER_EXIT calls $ON_CALLS"
    fi
    ON_RING_TXT=$ring_out
    ON_SUMMARY="exec $ON_EXECS (${ON_EXEC_RATE}/s), caller $ON_CALLS calls; peak RSS ${ON_RSS}KB CPU ${ON_CPU}"
    if [ -z "$ON_GATE_FAIL" ]; then
        ON_ROW_PASS=1
        ON_ROW_QUAL=qualified
        ON_ROW_DETAIL="exit 0, $ring_out, $gap_out, $stop_out; $ON_SUMMARY"
    else
        ON_ROW_PASS=0
        ON_ROW_QUAL=failed
        ON_ROW_DETAIL="$ON_GATE_FAIL; $ON_SUMMARY"
    fi
fi

# Judge the twin loss gates (no ledger comparison: attribution only).
if [ "$TWIN_FLOW_OK" -eq 0 ]; then
    TWIN_RING_TXT="flow failed"
else
    TWIN_GATE_FAIL=""
    ring_out=$(python3 -I "$CHECKS" ring-loss "$OUTDIR/churn-twin-out.json") \
        || TWIN_GATE_FAIL="ring-loss: $ring_out"
    gap_out=$(python3 -I "$CHECKS" no-loss-gap "$OUTDIR/churn-twin-out.json") \
        || TWIN_GATE_FAIL="${TWIN_GATE_FAIL:+$TWIN_GATE_FAIL; }gaps: $gap_out"
    stop_out=$(python3 -I "$CHECKS" stop "$TWIN_EXIT" \
        "$OUTDIR/churn-twin-observer.stderr" "$OUTDIR/churn-twin-out.json") \
        || TWIN_GATE_FAIL="${TWIN_GATE_FAIL:+$TWIN_GATE_FAIL; }stop: $stop_out"
    exec_floor=$((EXEC_FLOOR_PER_S * DURATION))
    if [ "$TWIN_EXECS" -lt "$exec_floor" ]; then
        TWIN_GATE_FAIL="${TWIN_GATE_FAIL:+$TWIN_GATE_FAIL; }exec churn shortfall: $TWIN_EXECS below floor $exec_floor"
    fi
    if [ "$TWIN_CALLER_EXIT" -ne 0 ] || [ "$TWIN_CALLS" -le 0 ]; then
        TWIN_GATE_FAIL="${TWIN_GATE_FAIL:+$TWIN_GATE_FAIL; }caller churn failed: exit $TWIN_CALLER_EXIT calls $TWIN_CALLS"
    fi
    TWIN_RING_TXT=$ring_out
    TWIN_SUMMARY="exec $TWIN_EXECS (${TWIN_EXEC_RATE}/s), caller $TWIN_CALLS calls; peak RSS ${TWIN_RSS}KB CPU ${TWIN_CPU}"
    if [ -z "$TWIN_GATE_FAIL" ]; then
        TWIN_ROW_PASS=1
        TWIN_ROW_QUAL=qualified
        TWIN_ROW_DETAIL="exit 0, $ring_out, $gap_out, $stop_out; $TWIN_SUMMARY"
    else
        TWIN_ROW_PASS=0
        TWIN_ROW_QUAL=failed
        TWIN_ROW_DETAIL="$TWIN_GATE_FAIL; $TWIN_SUMMARY"
    fi
fi

# Attribute an on-run ring loss against the twin, inside the row detail.
if [ "$ON_FLOW_OK" -eq 1 ] && [ "$TWIN_FLOW_OK" -eq 1 ]; then
    case "$ON_RING_TXT" in
        *"== 0"*) : ;;
        *)
            case "$TWIN_RING_TXT" in
                *"== 0"*) ON_ROW_DETAIL="$ON_ROW_DETAIL; attribution: twin clean, loss belongs to the flag run" ;;
                *) ON_ROW_DETAIL="$ON_ROW_DETAIL; attribution: twin also loses, loss is ambient or host-wide" ;;
            esac
            ;;
    esac
fi

if [ "$ON_FLOW_OK" -eq 0 ]; then
    if grep -q "journal-pair-unavailable-in-build" \
            "$OUTDIR/churn-on-observer.stderr" 2>/dev/null; then
        row churn-on 0 nonqualifying \
            "flag refused at start on this build: journal-pair-unavailable-in-build (R-58); loss gates unmeasured here"
    else
        row churn-on 0 failed "harness flow failed (see churn-on evidence)"
        FAILURES=$((FAILURES + 1))
    fi
else
    row churn-on "$ON_ROW_PASS" "$ON_ROW_QUAL" "$ON_ROW_DETAIL"
    [ "$ON_ROW_PASS" -eq 1 ] || FAILURES=$((FAILURES + 1))
fi
if [ "$TWIN_FLOW_OK" -eq 0 ]; then
    row churn-twin 0 failed "harness flow failed (see churn-twin evidence)"
    FAILURES=$((FAILURES + 1))
else
    row churn-twin "$TWIN_ROW_PASS" "$TWIN_ROW_QUAL" "$TWIN_ROW_DETAIL"
    [ "$TWIN_ROW_PASS" -eq 1 ] || FAILURES=$((FAILURES + 1))
fi

# --- churn-on-ledger ---
if [ "$ON_FLOW_OK" -eq 0 ]; then
    if grep -q "journal-pair-unavailable-in-build" \
            "$OUTDIR/churn-on-observer.stderr" 2>/dev/null; then
        row churn-on-ledger 0 nonqualifying \
            "flag refused at start on this build (R-58); no ledger to compare"
    else
        row churn-on-ledger 0 failed "flag run flow failed; no ledger to compare"
        FAILURES=$((FAILURES + 1))
    fi
elif python3 -I "$LEDGER_CHECK" "$OUTDIR/churn-on-ledger.jsonl" \
        > "$OUTDIR/churn-on-ledger-check.log" 2>&1; then
    if ! oo_line=$(python3 -I "$CHECKS" oo "$OUTDIR/churn-on-out.json"); then
        row churn-on-ledger 0 failed "observer report missing or unparsable"
        FAILURES=$((FAILURES + 1))
    else
        oo_status=${oo_line%% *}; oo_status=${oo_status#status=}
        oo_reason=${oo_line#*reason=}
        if [ "$ON_EXIT" -ne 0 ]; then
            row churn-on-ledger 0 failed \
                "observer exit $ON_EXIT with object_observations $oo_status ($oo_reason): not the pinned signature (exit 0)"
            FAILURES=$((FAILURES + 1))
        elif [ "$oo_status" = "populated" ]; then
            if python3 -I "$QUALIFY" "$OUTDIR/churn-on-ledger.jsonl" \
                    "$OUTDIR/churn-on-out.json" \
                    > "$OUTDIR/churn-on-oracle.log" 2>&1; then
                row churn-on-ledger 1 qualified "oracle compare passed"
            else
                cp "$OUTDIR/churn-on-out.json" "$OUTDIR/churn-linked-sample.json" || die "sample copy failed"
                oracle_text=$(tail -n 5 "$OUTDIR/churn-on-oracle.log" | tr '\n' ';')
                row churn-on-ledger 0 failed \
                    "oracle refused the populated linked shape: $oracle_text (sample: churn-linked-sample.json)"
                FAILURES=$((FAILURES + 1))
            fi
        # journal_unavailable stays expected-failure here, unlike the
        # stale-pin failure in key-operations-linked-control.sh: the
        # linked lane pins populated-with-an-oracle-pass, while this
        # churn cell still pins unavailable/journal_unavailable with
        # an oracle refusal as its exact signature (an oracle pass
        # goes stale below). WB4-2 forbids expected-failure without
        # an exact signature; this branch has one. When the linked
        # feed populates, move the churn pin to populated and fail
        # here like the linked lane.
        elif [ "$oo_status" = "unavailable" ] && [ "$oo_reason" = "journal_unavailable" ]; then
            if python3 -I "$QUALIFY" "$OUTDIR/churn-on-ledger.jsonl" \
                    "$OUTDIR/churn-on-out.json" \
                    > "$OUTDIR/churn-on-oracle.log" 2>&1; then
                row churn-on-ledger 0 failed \
                    "oracle unexpectedly passed on unavailable (journal_unavailable); the pinned refusal went stale"
                FAILURES=$((FAILURES + 1))
            else
                oracle_text=" oracle: $(tail -n 3 "$OUTDIR/churn-on-oracle.log" | tr '\n' ';')"
                cp "$OUTDIR/churn-on-out.json" "$OUTDIR/churn-linked-sample.json" || die "sample copy failed"
                row churn-on-ledger 1 expected-failure \
                    "product: object_observations unavailable (journal_unavailable);$oracle_text (sample: churn-linked-sample.json)"
            fi
        else
            row churn-on-ledger 0 failed \
                "object_observations $oo_status ($oo_reason) on exit $ON_EXIT: not the pinned signature (exit 0 + unavailable journal_unavailable with an oracle refusal, or populated with an oracle pass)"
            FAILURES=$((FAILURES + 1))
        fi
    fi
else
    row churn-on-ledger 0 failed "application ledger failed validation"
    FAILURES=$((FAILURES + 1))
fi

say "failures: $FAILURES"
[ "$FAILURES" -eq 0 ] || exit 1
exit 0

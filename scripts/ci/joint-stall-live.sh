#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# joint-stall-live.sh P11SCOPE OUTDIR: live Joint finish stall/wedge campaign.
#
# Runs the observer (p11scope inventory --system with a SoftHSM manifest)
# under route pressure (waves of short-lived callers), refresh churn
# (long-lived callers that exec/dlclose-dlopen), and fault bursts (hammer
# floods), SIGINTs each short run at a seeded random point inside a burst,
# and checks that the Joint finish neither stalls nor abandons.
#
# Cells (OUTDIR/results.jsonl, one row per cell):
#   stall-short-stops  every short run exits within D + slack with no
#                      "joint finish/audit made no progress" gap
#   wedge-no-abandon   every short run has no "joint finish abandoned for
#                      exit" gap, exits 0 with no disposition error and no
#                      progress gap or stderr line
#   stall-long-1800    the 1800 s run exits within D + slack with no
#                      progress gap (only with LONG=1800)
# With KEY_OPS=1 the same names carry a -linked suffix. The cross-binary
# "fewer abandons than base" check is a human comparison of two campaigns,
# not a script assertion.
#
# Env: RUNS (50), DMIN (20), DMAX (40), LONG (0 or 1800), KEY_OPS (0/1),
#   SEED (1), MODULE (provider override; else probed), SLACK_SHORT (60),
#   SLACK_LONG (180), CHURN_CALLERS (4), WAVE_MIN (32), WAVE_MAX (64),
#   HAMMER_CALLS (200000), HAMMER_JOBS (2), SIGINT_MIN (8),
#   SIGINT_END_MARGIN (5).
#
# Exit: 0 every qualified cell passed; 1 a cell failed; 2 harness error;
#   77 a prerequisite is missing (binary, gcc, python3, softhsm2-util,
#   SoftHSM module, p11scope-discover, or root for live runs).
#
# Live runs must be under the privileged lock and as root:
#   flock /var/tmp/p11scope-ws-tmp/privileged.lock \
#     sudo -n scripts/ci/joint-stall-live.sh P11SCOPE OUTDIR
# --help, --self-test and --check-run need no privileges.
#
# Apt prerequisites on a GitHub ubuntu-26.04 runner (root):
#   gcc python3 softhsm2 sudo procps
# plus a kernel with BTF and uprobe_multi for the observer itself.
#
# Design notes (decisions):
# - The brief command omits --manifest, but the Joint lane only starts
#   with an attested manifest (src/inventory/mod.rs: no manifests means
#   no Session and no semantic gap at all). Without it the cell would be
#   vacuous, so this script always generates one via p11scope-discover
#   and passes --manifest. The --module flag narrows the scan.
# - Fault bursts reuse the induced-gaps hammer (scripts/fixtures/hammer.c,
#   back-to-back C_GenerateRandom) that overflows small rings; inventory
#   has no --ring-bytes knob, so loss is recorded from
#   observation.lifecycle and loss gaps rather than gated.
# - KEY_OPS=1 adds --key-operations; on a binary that predates the flag
#   the linked cells are nonqualifying, not failed.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
REPO=$(cd "$HERE/../.." && pwd) || exit 2

usage() {
    sed -n '2,45p' "$0"
    echo "usage: $0 P11SCOPE OUTDIR"
    echo "       $0 --help | --self-test"
    echo "       $0 --check-run RUN_JSON STDERR_FILE DURATION_D WALL_S EXIT_CODE SLACK_S"
}

die() { echo "joint-stall-live: $1" >&2; exit "${2:-2}"; }

# --- Single-run oracle (also the --check-run entry point) ---
# Prints one JSON object to stdout; exit 0 pass, 1 fail, 2 harness error.
check_run() {
    [ $# -eq 6 ] || { echo "usage: $0 --check-run RUN_JSON STDERR D WALL EXIT SLACK" >&2; return 2; }
    python3 -I - "$@" <<'PY'
import json, re, sys
run_json, stderr_file, d_s, wall_s, exit_s, slack_s = sys.argv[1:7]
try:
    duration = int(d_s); wall = int(wall_s); exit_code = int(exit_s); slack = int(slack_s)
except ValueError:
    print(json.dumps({"error": "bad numbers"})); sys.exit(2)
out = {"duration": duration, "wall": wall, "exit": exit_code,
       "subjects": [], "abandons": 0, "no_progress": False,
       "trips": [], "stderr_no_progress": False,
       "stderr_disposition": False, "time_ok": wall <= duration + slack,
       "exit_ok": exit_code == 0, "run_json_ok": False}
try:
    with open(run_json, encoding="utf-8") as f:
        doc = json.load(f)
except (OSError, ValueError) as e:
    out["error"] = "run.json unreadable: %s" % e
    print(json.dumps(out)); sys.exit(1)
gaps = doc.get("gaps")
if not isinstance(gaps, list):
    out["error"] = "gaps is not a list"
    print(json.dumps(out)); sys.exit(1)
out["run_json_ok"] = True
for gap in gaps:
    if not isinstance(gap, dict):
        continue
    subject = gap.get("subject")
    reason = gap.get("reason")
    if isinstance(subject, str):
        out["subjects"].append(subject)
    if subject == "joint finish abandoned for exit":
        out["abandons"] += 1
    if subject in ("joint finish made no progress", "joint audit made no progress"):
        out["no_progress"] = True
        trip = {"subject": subject, "h0_below": None,
                "staged_max": None, "floor": None}
        if isinstance(reason, str):
            for key in ("h0_below", "staged_max", "floor"):
                m = re.search(key + r"=(Some\(([^)]*)\)|None)", reason)
                if m:
                    trip[key] = None if m.group(1) == "None" else m.group(2)
        out["trips"].append(trip)
try:
    with open(stderr_file, encoding="utf-8", errors="replace") as f:
        stderr_text = f.read()
except OSError as e:
    out["error"] = "stderr unreadable: %s" % e
    print(json.dumps(out)); sys.exit(1)
if ("joint finish made no progress" in stderr_text
        or "joint audit made no progress" in stderr_text
        or "live publication made no progress" in stderr_text):
    out["stderr_no_progress"] = True
if "joint finish disposition required" in stderr_text:
    out["stderr_disposition"] = True
# Lifecycle loss accounting (recorded, never gated).
try:
    lifecycle = doc.get("observation", {}).get("lifecycle", {})
    out["ring_loss"] = lifecycle.get("ring_loss")
    out["lifecycle_records"] = lifecycle.get("records")
except AttributeError:
    out["ring_loss"] = None
    out["lifecycle_records"] = None
out["stall_ok"] = bool(out["time_ok"] and not out["no_progress"] and out["run_json_ok"])
out["wedge_ok"] = bool(out["abandons"] == 0 and out["exit_ok"]
                       and not out["no_progress"] and not out["stderr_no_progress"]
                       and not out["stderr_disposition"] and out["run_json_ok"])
print(json.dumps(out))
sys.exit(0 if (out["stall_ok"] and out["wedge_ok"]) else 1)
PY
}

self_test() {
    work=$(mktemp -d "${TMPDIR:-/tmp}/joint-stall-selftest-XXXXXX") || exit 2
    trap 'rm -rf "$work"' EXIT INT TERM
    pass=0; fail=0
    expect() {
        # expect NAME WANT_RC --check-run-args...
        name=$1; want=$2; shift 2
        if "$0" --check-run "$@" > "$work/out-$name.json" 2> "$work/$name.err"; then rc=0; else rc=$?; fi
        if [ "$rc" = "$want" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "self-test FAIL: $name rc=$rc want=$want"; cat "$work/out-$name.json" "$work/$name.err"; fi
    }
    healthy_run="$work/in-healthy.json"; : > "$work/empty.stderr"
    cat > "$healthy_run" <<'EOF'
{"gaps": [{"subject": "native capture lifecycle evidence lost", "reason": "x"}],
 "observation": {"lifecycle": {"records": 10, "ring_loss": 3}}}
EOF
    expect healthy 0 "$healthy_run" "$work/empty.stderr" 30 35 0 60
    if python3 -I - "$work/out-healthy.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["stall_ok"] and d["wedge_ok"], d
assert d["ring_loss"] == 3, d
assert d["subjects"] == ["native capture lifecycle evidence lost"], d
PY
    then pass=$((pass + 1)); else fail=$((fail + 1)); echo "self-test FAIL: healthy fields"; fi
    trip_run="$work/in-trip.json"
    cat > "$trip_run" <<'EOF'
{"gaps": [{"subject": "joint finish made no progress",
           "reason": "6s without progress across 612 consecutive finish polls in Audited; abandoning the finish for exit; h0_below=Some(9), staged_max=Some(7), floor=Some(4)"}],
 "observation": {"lifecycle": {"records": 1, "ring_loss": 0}}}
EOF
    echo "joint finish made no progress for 6s across 612 polls; the lane is held for exit" > "$work/trip.stderr"
    expect trip 1 "$trip_run" "$work/trip.stderr" 30 40 0 60
    if python3 -I - "$work/out-trip.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert not d["stall_ok"] and not d["wedge_ok"], d
assert d["no_progress"] and d["stderr_no_progress"], d
assert d["trips"][0]["h0_below"] == "9", d
assert d["trips"][0]["staged_max"] == "7", d
assert d["trips"][0]["floor"] == "4", d
PY
    then pass=$((pass + 1)); else fail=$((fail + 1)); echo "self-test FAIL: trip fields"; fi
    abandon_run="$work/in-abandon.json"
    cat > "$abandon_run" <<'EOF'
{"gaps": [{"subject": "joint finish abandoned for exit", "reason": "joint finish disposition required"}]}
EOF
    echo "some line" > "$work/abandon.stderr"
    expect abandon 1 "$abandon_run" "$work/abandon.stderr" 30 35 0 60
    if python3 -I - "$work/out-abandon.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["stall_ok"] and not d["wedge_ok"], d
assert d["abandons"] == 1, d
PY
    then pass=$((pass + 1)); else fail=$((fail + 1)); echo "self-test FAIL: abandon fields"; fi
    echo "not json" > "$work/bad.json"
    expect badjson 1 "$work/bad.json" "$work/empty.stderr" 30 35 0 60
    expect missing 1 "$work/nope.json" "$work/empty.stderr" 30 35 0 60
    expect slow 1 "$healthy_run" "$work/empty.stderr" 30 200 0 60
    if python3 -I - "$work/out-slow.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert not d["time_ok"] and not d["stall_ok"], d
PY
    then pass=$((pass + 1)); else fail=$((fail + 1)); echo "self-test FAIL: slow fields"; fi
    echo "p11scope: live publication made no progress for 6 s; abandoned it, coverage is partial" > "$work/live.stderr"
    expect live 1 "$healthy_run" "$work/live.stderr" 30 35 0 60
    echo "joint finish disposition required" > "$work/dispo.stderr"
    expect dispo 1 "$healthy_run" "$work/dispo.stderr" 30 35 1 60
    echo "self-test: pass=$pass fail=$fail"
    [ "$fail" -eq 0 ]
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then usage; exit 0; fi
if [ "${1:-}" = "--self-test" ]; then shift; [ $# -eq 0 ] || { usage >&2; exit 2; }; self_test; exit $?; fi
if [ "${1:-}" = "--check-run" ]; then shift; check_run "$@"; exit $?; fi

[ $# -eq 2 ] || { usage >&2; exit 2; }
P11SCOPE=$1; OUTDIR=$2

RUNS=${RUNS:-50}; DMIN=${DMIN:-20}; DMAX=${DMAX:-40}; LONG=${LONG:-0}
KEY_OPS=${KEY_OPS:-0}; SEED=${SEED:-1}
SLACK_SHORT=${SLACK_SHORT:-60}; SLACK_LONG=${SLACK_LONG:-180}
CHURN_CALLERS=${CHURN_CALLERS:-4}; WAVE_MIN=${WAVE_MIN:-32}; WAVE_MAX=${WAVE_MAX:-64}
HAMMER_CALLS=${HAMMER_CALLS:-200000}; HAMMER_JOBS=${HAMMER_JOBS:-2}
SIGINT_MIN=${SIGINT_MIN:-8}; SIGINT_END_MARGIN=${SIGINT_END_MARGIN:-5}
case $RUNS in ''|*[!0-9]*) die "RUNS must be a number" 2 ;; esac
case $KEY_OPS in 0|1) ;; *) die "KEY_OPS must be 0 or 1" 2 ;; esac
case $LONG in 0|1800) ;; *) die "LONG must be 0 or 1800" 2 ;; esac
[ "$DMIN" -ge 15 ] 2>/dev/null || die "DMIN too small" 2
[ "$DMAX" -ge "$DMIN" ] 2>/dev/null || die "DMAX < DMIN" 2
[ "$WAVE_MAX" -ge "$WAVE_MIN" ] 2>/dev/null || die "WAVE_MAX < WAVE_MIN" 2

[ -x "$P11SCOPE" ] || { echo "joint-stall-live: P11SCOPE is not executable: $P11SCOPE" >&2; exit 77; }
P11SCOPE=$(realpath -e -- "$P11SCOPE") || exit 77
command -v gcc >/dev/null || { echo "joint-stall-live: gcc required" >&2; exit 77; }
command -v python3 >/dev/null || { echo "joint-stall-live: python3 required" >&2; exit 77; }
command -v softhsm2-util >/dev/null || { echo "joint-stall-live: softhsm2-util required" >&2; exit 77; }
[ "$(id -u)" = 0 ] || { echo "joint-stall-live: live runs need root (sudo -n under the privileged lock)" >&2; exit 77; }
CHURN_SRC=$REPO/tests/fixtures/joint-stall/refresh-churn.c
HAMMER_SRC=$REPO/scripts/fixtures/hammer.c
[ -f "$CHURN_SRC" ] || die "driver source missing: $CHURN_SRC" 77
[ -f "$HAMMER_SRC" ] || die "hammer source missing: $HAMMER_SRC" 77

SUFFIX=""; KEY_FLAG=()
if [ "$KEY_OPS" = 1 ]; then
    SUFFIX="-linked"
    if "$P11SCOPE" inventory --help 2>&1 | grep -q -- --key-operations; then
        KEY_FLAG=(--key-operations)
    else
        KEY_MISSING=1
    fi
fi

umask 022
mkdir -p "$OUTDIR" || exit 2
OUTDIR=$(realpath -e -- "$OUTDIR") || exit 2
BIN=$OUTDIR/bin; mkdir -p "$BIN" || exit 2
RUNS_DIR=$OUTDIR/runs; mkdir -p "$RUNS_DIR" || exit 2
: > "$OUTDIR/results.jsonl" || exit 2

log() { echo "joint-stall-live: $*"; }
emit_cell() {
    python3 -I - "$1" "$2" "$3" "$4" >> "$OUTDIR/results.jsonl" <<'PY'
import json, sys
cell, passed, qualification, detail = sys.argv[1:5]
print(json.dumps({"cell": cell, "pass": passed == "1",
                  "qualification": qualification, "detail": detail}))
PY
}

if [ "${KEY_MISSING:-0}" = 1 ]; then
    log "binary predates --key-operations; linked cells are nonqualifying"
    for base in stall-short-stops wedge-no-abandon; do
        emit_cell "$base$SUFFIX" 0 nonqualifying "binary predates --key-operations (KEY_OPS=1 on unlinked binary)"
    done
    if [ "$LONG" = 1800 ]; then
        emit_cell "stall-long-1800$SUFFIX" 0 nonqualifying "binary predates --key-operations (KEY_OPS=1 on unlinked binary)"
    fi
    exit 0
fi

log "building drivers"
gcc -std=c11 -O2 -Wall -Wextra -Werror -o "$BIN/refresh-churn" "$CHURN_SRC" -ldl \
    || die "refresh-churn build failed" 2
gcc -O2 -Wall -Wextra -o "$BIN/hammer" "$HAMMER_SRC" -ldl \
    || die "hammer build failed" 2
"$BIN/refresh-churn" --help >/dev/null || die "refresh-churn --help failed" 2

if [ -n "${MODULE:-}" ]; then
    [ -f "$MODULE" ] || { echo "joint-stall-live: MODULE not found: $MODULE" >&2; exit 77; }
else
    MODULE=$(python3 -I "$REPO/scripts/release-matrix-contract.py" --select-module) \
        || { echo "joint-stall-live: no SoftHSM module found" >&2; exit 77; }
fi
log "module: $MODULE"

log "setting up SoftHSM token"
SOFTHSM_DIR=$OUTDIR/softhsm; rm -rf "$SOFTHSM_DIR"; mkdir -p "$SOFTHSM_DIR/tokens" || exit 2
export SOFTHSM2_CONF=$SOFTHSM_DIR/softhsm2.conf
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $SOFTHSM_DIR/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF
softhsm2-util --init-token --free --label jointstall --so-pin 1234 --pin 1234 >/dev/null \
    || die "softhsm2-util --init-token failed" 2

DISCOVER=""
for candidate in "$(dirname "$P11SCOPE")/p11scope-discover" p11scope-discover; do
    case $candidate in */*) [ -x "$candidate" ] && DISCOVER=$candidate && break ;;
    *) command -v "$candidate" >/dev/null && DISCOVER=$(command -v "$candidate") && break ;; esac
done
[ -n "$DISCOVER" ] || { echo "joint-stall-live: p11scope-discover not found beside $P11SCOPE or on PATH" >&2; exit 77; }
log "discover: $DISCOVER"
"$DISCOVER" --module "$MODULE" -o "$OUTDIR/manifest.json" \
    || die "p11scope-discover failed" 2

HOST=$(hostname); KERNEL=$(uname -r)
log "host=$HOST kernel=$KERNEL seed=$SEED runs=$RUNS dmin=$DMIN dmax=$DMAX long=$LONG key_ops=$KEY_OPS"

# Seeded run parameters: index D sigint_delay (0 = no SIGINT, run to duration).
PARAMS=$OUTDIR/params.txt
python3 -I - "$SEED" "$RUNS" "$DMIN" "$DMAX" "$SIGINT_MIN" "$SIGINT_END_MARGIN" > "$PARAMS" <<'PY'
import random, sys
seed, runs, dmin, dmax, smin, margin = (int(x) for x in sys.argv[1:7])
rng = random.Random(seed)
for i in range(1, runs + 1):
    duration = rng.randint(dmin, dmax)
    latest = duration - margin
    if latest < smin:
        latest = smin
    delay = rng.randint(smin, latest)
    print(i, duration, delay)
PY
[ -s "$PARAMS" ] || die "param generation failed" 2

OBSERVER_PID=""; WORK_PIDS=""
cleanup_run() {
    if [ -n "$WORK_PIDS" ]; then
        # shellcheck disable=SC2086
        kill -TERM $WORK_PIDS 2>/dev/null || true
        sleep 1
        # shellcheck disable=SC2086
        kill -KILL $WORK_PIDS 2>/dev/null || true
        WORK_PIDS=""
    fi
    if [ -n "$OBSERVER_PID" ]; then
        kill -KILL "$OBSERVER_PID" 2>/dev/null || true
        wait "$OBSERVER_PID" 2>/dev/null || true
        OBSERVER_PID=""
    fi
}
trap 'cleanup_run' EXIT INT TERM

wave_once() {
    # wave_once OUT_PREFIX: one wave of WAVE_MIN..WAVE_MAX short callers,
    # waited here so churn and hammer keep running in the background.
    span=$((WAVE_MAX - WAVE_MIN + 1))
    count=$((WAVE_MIN + RANDOM % span))
    wave_pids=""
    i=0
    while [ "$i" -lt "$count" ]; do
        SOFTHSM2_CONF=$SOFTHSM2_CONF "$BIN/refresh-churn" --short "$MODULE" \
            >> "$1-wave.log" 2>> "$1-wave.stderr" &
        wave_pids="$wave_pids $!"
        i=$((i + 1))
    done
    # shellcheck disable=SC2086
    for pid in $wave_pids; do wait "$pid" 2>/dev/null || true; done
}

hammer_once() {
    # hammer_once OUT_PREFIX: HAMMER_JOBS parallel fault bursts.
    j=0
    while [ "$j" -lt "$HAMMER_JOBS" ]; do
        SOFTHSM2_CONF=$SOFTHSM2_CONF "$BIN/hammer" "$MODULE" "$HAMMER_CALLS" \
            >> "$1-hammer.log" 2>> "$1-hammer.stderr" &
        WORK_PIDS="$WORK_PIDS $!"
        j=$((j + 1))
    done
}

run_short() {
    idx=$1; duration=$2; delay=$3
    prefix=$RUNS_DIR/run-$(printf '%03d' "$idx")
    run_json=$prefix.json; run_diag=$prefix.diag.jsonl
    run_out=$prefix.stdout; run_err=$prefix.stderr
    : > "$prefix-wave.log"; : > "$prefix-wave.stderr"
    : > "$prefix-hammer.log"; : > "$prefix-hammer.stderr"
    RANDOM=$((SEED * 100000 + idx))
    bound=$((duration + SLACK_SHORT))
    log "run $idx/$RUNS: D=$duration SIGINT at ${delay}s (bound ${bound}s)"
    start=$(date +%s)
    "$P11SCOPE" inventory --system --module "$MODULE" --manifest "$OUTDIR/manifest.json" \
        "${KEY_FLAG[@]}" --json -o "$run_json" --max-gaps 256 \
        --diagnostics "$run_diag" --duration "$duration" \
        > "$run_out" 2> "$run_err" &
    OBSERVER_PID=$!
    # Wait for pass 0 (attach settled) before releasing the workload.
    waited=0
    while [ "$waited" -lt 180 ]; do
        kill -0 "$OBSERVER_PID" 2>/dev/null || break
        if grep -qa -- "p11scope: pass 0:" "$run_out" 2>/dev/null \
            || grep -qa -- "p11scope: pass 0:" "$run_err" 2>/dev/null; then break; fi
        sleep 1; waited=$((waited + 1))
    done
    if ! kill -0 "$OBSERVER_PID" 2>/dev/null; then
        wait "$OBSERVER_PID"; rc=$?; OBSERVER_PID=""
        wall=$(($(date +%s) - start))
        log "run $idx: observer exited early rc=$rc wall=${wall}s"
    else
        # Long-lived churn callers for the whole run.
        c=0
        while [ "$c" -lt "$CHURN_CALLERS" ]; do
            SOFTHSM2_CONF=$SOFTHSM2_CONF "$BIN/refresh-churn" "$MODULE" 100000 20 "$bound" \
                > "$prefix-churn$c.log" 2> "$prefix-churn$c.stderr" &
            WORK_PIDS="$WORK_PIDS $!"
            c=$((c + 1))
        done
        # Waves and fault bursts until the SIGINT point, then one final
        # burst with SIGINT 0.5 s into it.
        elapsed=0
        while [ "$elapsed" -lt "$delay" ]; do
            wave_once "$prefix"
            if [ $((elapsed % 6)) -eq 0 ]; then hammer_once "$prefix"; fi
            sleep 2; elapsed=$((elapsed + 2))
        done
        wave_once "$prefix"; hammer_once "$prefix"
        sleep 0.5
        kill -INT "$OBSERVER_PID" 2>/dev/null || true
        # Bounded wait: a hang is a FAIL with the run index, never retried.
        waited=0
        while kill -0 "$OBSERVER_PID" 2>/dev/null; do
            wall=$(($(date +%s) - start))
            if [ "$wall" -ge "$bound" ]; then
                log "run $idx: HANG past ${bound}s; killing observer"
                kill -KILL "$OBSERVER_PID" 2>/dev/null || true
                wait "$OBSERVER_PID" 2>/dev/null; rc=124; OBSERVER_PID=""
                wall=$(($(date +%s) - start))
                echo "HANG run=$idx bound=${bound}s" >> "$run_err"
                break
            fi
            sleep 0.5
        done
        if [ -n "$OBSERVER_PID" ]; then wait "$OBSERVER_PID"; rc=$?; OBSERVER_PID=""; wall=$(($(date +%s) - start)); fi
    fi
    # Stop the workload, keep every log.
    if [ -n "$WORK_PIDS" ]; then
        # shellcheck disable=SC2086
        kill -TERM $WORK_PIDS 2>/dev/null || true
        sleep 1
        # shellcheck disable=SC2086
        kill -KILL $WORK_PIDS 2>/dev/null || true
        wait 2>/dev/null || true
        WORK_PIDS=""
    fi
    if "$0" --check-run "$run_json" "$run_err" "$duration" "$wall" "$rc" "$SLACK_SHORT" \
        > "$prefix.check.json" 2> "$prefix.check.stderr"; then check_rc=0; else check_rc=$?; fi
    log "run $idx: rc=$rc wall=${wall}s check_rc=$check_rc abandons=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("abandons"))' "$prefix.check.json" 2>/dev/null || echo '?')"
    return "$check_rc"
}

run_long() {
    duration=1800
    prefix=$RUNS_DIR/run-long
    run_json=$prefix.json; run_diag=$prefix.diag.jsonl
    run_out=$prefix.stdout; run_err=$prefix.stderr
    : > "$prefix-wave.log"; : > "$prefix-wave.stderr"
    : > "$prefix-hammer.log"; : > "$prefix-hammer.stderr"
    RANDOM=$((SEED * 100000 + 999))
    bound=$((duration + SLACK_LONG))
    log "long run: D=$duration no SIGINT (bound ${bound}s)"
    start=$(date +%s)
    "$P11SCOPE" inventory --system --module "$MODULE" --manifest "$OUTDIR/manifest.json" \
        "${KEY_FLAG[@]}" --json -o "$run_json" --max-gaps 256 \
        --diagnostics "$run_diag" --duration "$duration" \
        > "$run_out" 2> "$run_err" &
    OBSERVER_PID=$!
    waited=0
    while [ "$waited" -lt 180 ]; do
        kill -0 "$OBSERVER_PID" 2>/dev/null || break
        if grep -qa -- "p11scope: pass 0:" "$run_out" 2>/dev/null \
            || grep -qa -- "p11scope: pass 0:" "$run_err" 2>/dev/null; then break; fi
        sleep 1; waited=$((waited + 1))
    done
    c=0
    while [ "$c" -lt "$CHURN_CALLERS" ]; do
        SOFTHSM2_CONF=$SOFTHSM2_CONF "$BIN/refresh-churn" "$MODULE" 100000 20 "$bound" \
            > "$prefix-churn$c.log" 2> "$prefix-churn$c.stderr" &
        WORK_PIDS="$WORK_PIDS $!"
        c=$((c + 1))
    done
    # Waves for the whole window; the observer stops itself at --duration.
    while kill -0 "$OBSERVER_PID" 2>/dev/null; do
        wave_once "$prefix"
        wall=$(($(date +%s) - start))
        if [ $((wall % 30)) -lt 3 ]; then hammer_once "$prefix"; fi
        wall=$(($(date +%s) - start))
        if [ "$wall" -ge "$bound" ]; then
            log "long run: HANG past ${bound}s; killing observer"
            kill -KILL "$OBSERVER_PID" 2>/dev/null || true
            wait "$OBSERVER_PID" 2>/dev/null; rc=124; OBSERVER_PID=""
            wall=$(($(date +%s) - start))
            echo "HANG run=long bound=${bound}s" >> "$run_err"
            break
        fi
        sleep 3
    done
    if [ -n "$OBSERVER_PID" ]; then wait "$OBSERVER_PID"; rc=$?; OBSERVER_PID=""; wall=$(($(date +%s) - start)); fi
    if [ -n "$WORK_PIDS" ]; then
        # shellcheck disable=SC2086
        kill -TERM $WORK_PIDS 2>/dev/null || true
        sleep 1
        # shellcheck disable=SC2086
        kill -KILL $WORK_PIDS 2>/dev/null || true
        wait 2>/dev/null || true
        WORK_PIDS=""
    fi
    if "$0" --check-run "$run_json" "$run_err" "$duration" "$wall" "$rc" "$SLACK_LONG" \
        > "$prefix.check.json" 2> "$prefix.check.stderr"; then check_rc=0; else check_rc=$?; fi
    log "long run: rc=$rc wall=${wall}s check_rc=$check_rc"
    return "$check_rc"
}

campaign_start=$(date +%s)
short_fail=0; short_pass=0
while read -r idx duration delay; do
    [ -n "$idx" ] || continue
    if run_short "$idx" "$duration" "$delay"; then short_pass=$((short_pass + 1)); else short_fail=$((short_fail + 1)); fi
done < "$PARAMS"

long_rc="skip"
if [ "$LONG" = 1800 ]; then
    if run_long; then long_rc=0; else long_rc=1; fi
fi
campaign_wall=$(($(date +%s) - campaign_start))

trap - EXIT INT TERM

python3 -I - "$RUNS_DIR" "$OUTDIR/results.jsonl" "$SUFFIX" "$HOST" "$KERNEL" "$SEED" \
    "$RUNS" "$LONG" "$KEY_OPS" "$campaign_wall" "$short_pass" "$short_fail" "$long_rc" <<'PY'
import glob, json, sys
runs_dir, results_path, suffix, host, kernel, seed = sys.argv[1:7]
runs, long_d, key_ops, wall, passed, failed, long_rc = sys.argv[7:14]
checks = []
for path in sorted(glob.glob(runs_dir + "/run-[0-9]*.check.json")):
    try:
        checks.append((path, json.load(open(path))))
    except (OSError, ValueError):
        checks.append((path, {"stall_ok": False, "wedge_ok": False,
                              "abandons": 0, "no_progress": True,
                              "error": "check.json unreadable"}))
abandons = sum(int(c.get("abandons") or 0) for _, c in checks)
trips = sum(1 for _, c in checks if c.get("no_progress"))
max_delay = None
for _, c in checks:
    try:
        delay = int(c["wall"]) - int(c["duration"])
        max_delay = delay if max_delay is None else max(max_delay, delay)
    except (KeyError, TypeError, ValueError):
        pass
stall_pass = failed == "0" and len(checks) == int(runs)
wedge_pass = all(c.get("wedge_ok") for _, c in checks) and len(checks) == int(runs)
rows = [
    ("stall-short-stops" + suffix, stall_pass, "qualified",
     "host=%s kernel=%s seed=%s runs=%s passed=%s failed=%s abandons=%d no_progress_runs=%d max_delay=%ss wall=%ss"
     % (host, kernel, seed, runs, passed, failed, abandons, trips,
        max_delay, wall)),
    ("wedge-no-abandon" + suffix, wedge_pass, "qualified",
     "host=%s kernel=%s seed=%s runs=%s abandons=%d no_progress_runs=%d max_delay=%ss"
     % (host, kernel, seed, runs, abandons, trips, max_delay)),
]
if long_d == "1800":
    try:
        long_check = json.load(open(runs_dir + "/run-long.check.json"))
    except (OSError, ValueError):
        long_check = {"stall_ok": False}
    long_pass = bool(long_check.get("stall_ok")) and long_rc == "0"
    try:
        long_delay = int(long_check["wall"]) - int(long_check["duration"])
    except (KeyError, TypeError, ValueError):
        long_delay = None
    rows.append(("stall-long-1800" + suffix, long_pass, "qualified",
                 "host=%s kernel=%s seed=%s wall=%ss delay=%ss rc=%s no_progress=%s abandons=%s"
                 % (host, kernel, seed, long_check.get("wall"),
                    long_delay, long_check.get("exit"),
                    long_check.get("no_progress"),
                    long_check.get("abandons"))))
with open(results_path, "w", encoding="utf-8") as f:
    for cell, passed_cell, qualification, detail in rows:
        f.write(json.dumps({"cell": cell, "pass": bool(passed_cell),
                            "qualification": qualification,
                            "detail": detail}) + "\n")
sys.exit(0 if all(p for _, p, _, _ in rows) else 1)
PY
rc=$?
if [ "$rc" -eq 0 ]; then log "campaign PASS"; else log "campaign FAIL"; fi
exit "$rc"

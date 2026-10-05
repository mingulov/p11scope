#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# measure-c5-campaign.sh — the Task 6 C5 measurement campaign (M0–M7), end to end.
#
#   measure-c5-campaign.sh --candidate BIN --baseline BIN [--r4-base BIN] [--loss-candidate BIN]
#       [--loss-churn RATE]
#       [--tier 1|2|all] [--scale full|smoke] [--only M1,M4,...] [--rounds N]
#       [--out DIR | --resume DIR] [--report FILE] [--gate-wait S] [--max-attempts N]
#       [--m0-advisory]   (smoke only: record an M0 failure and continue)
#       [--max-load1 X] [--max-builds N]   (defaults 4 and 0; raise them only for a
#                                          smoke run on a busy, building host)
#   measure-c5-campaign.sh ... --plan     (no privilege: list the units and the duration estimate)
#   measure-c5-campaign.sh --self-test    (no privilege: plan shapes, resume and gate logic)
#
# The campaign runs measurements M0–M7 plus the C5.6 R4 pool timing (base
# 570eb7d vs head on cores 10,11 and on the 4-core set 8,9,10,11). Binaries:
#   --candidate       the release build of the s2s3 tip under test
#   --baseline        the fresh v0.1.0 tag build (M1-match, M2, M6, M7)
#   --r4-base         a release build of 570eb7d (R4; the C5.6 base before the pool)
#   --loss-candidate  optional: the candidate built with P11SCOPE_SMALL_DISCOVERY_RING=1
#                     (a 4 KiB DISCOVERY ring) for M0's induced loss. In v0.2.0 the
#                     native Inventory loader refused that build (its exact-map
#                     validator pinned DISCOVERY at 65,536 bytes); since the 2 MiB
#                     lifecycle ring the validator expects each build's own size,
#                     so the small-ring build loads and M0 uses it when given.
#                     Without it, M0 induces the loss on the stock candidate with
#                     exec churn instead (--loss-churn, default 3000 execs/s).
#
# Order. M0 (harness validity) runs first and the campaign stops unless every
# M0 leg is classified as expected: a ledgered `--pid` capture is correct, a
# refused `--pid` is refused, the small-ring build under exec churn is lossy, a
# run whose sampler is killed is missing samples, and a clean host-namespace
# run is correct (the loss leg's churn is the only heavy moment of M0: by
# default 3000 execs/s for 30 s). Then the measurements in the plan's order
# (M1, M1-match, R4, M2, M3, M4, M5, M6, M7), each restricted to the cells of
# the chosen tier:
#   --tier 1   the must-have tier for v0.2.0's known-limitations numbers, sized
#              for a ~2 h quiet window: M1 at 448 and 4,096 processes (scan and
#              native), the C5.6 R4 pool timing at 4,096 on cores 8-11, and M4
#              exec churn at 100 and 1,000 execs/s at 448. Reduced repetition:
#              3 rounds of 3 samples (M4: 3 rounds of 2), i.e. 3 cold + 6 warm
#              per (cell, role) instead of the plan's 5 + 5.
#   --tier 2   everything else (v0.3.0): M1 at 10,000, M1-match, R4 at 2 cores
#              and at 448, M2, M3, M4 at churn 0 and at 4,096, M5, M6, M7, at
#              the plan's 5 rounds of 2 samples (1 cold + 1 warm).
#   --tier all both (default). Tier 2 can resume a tier-1 run's DIR.
# Within a measurement every round visits every cell that still has rounds,
# and within a cell the roles (candidate, baseline or control) alternate
# their order every round.
#
# Host-load discipline: the whole
# campaign holds `flock /var/tmp/p11scope-ws-tmp/privileged.lock` (it re-executes
# itself under flock -o); before every unit it waits (up to --gate-wait,
# default 1800 s) for load1 < 4 (M2 also load5 < 4) and records `uptime`
# before and after; observers are pinned with taskset (10,11; the R4 4-core
# set 8,9,10,11); 10,000-process cells run one at a time inside the bench's
# transient systemd scope and are followed by a cooldown (load1 < 4 and at
# least 60 s). No Cargo build may run: the bench refuses a sample started
# beside cargo/rustc. A unit whose attempt is invalid is retried, up to
# --max-attempts (default 3); every attempt is kept with its reason.
#
# Resume: every unit records units/<id>/unit.json when it ends; --resume DIR
# skips units whose status is valid (or whose attempts are exhausted) and
# continues with the rest, M0 included only if M0.verdict is not PASS.
#
# Output: raw data under DIR (default /var/tmp/p11scope-ws-tmp/c5-measure/<UTC
# timestamp>): campaign.json, units/<id>/{unit.json,attempt-N/}, bench runs
# under bench-root/, M0.verdict, campaign.log. After every unit the report is
# regenerated (scripts/measure-c5-analysis.py report) into --report (default
# the SDD's c5-measurements.md). On exit everything under DIR is chowned to
# RUNUID:RUNGID (default 1000:1000).
#
# Exit: 0 campaign complete (units may still be invalid: see the report),
# 2 M0 failed (nothing else ran), 3 lock not obtained, 64 usage, 70 harness.
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd) || exit 64
SELF=$REPO/scripts/$(basename "$0")
BENCH=$REPO/scripts/bench-inventory-native.sh
ANALYSIS=$REPO/scripts/measure-c5-analysis.py
LOCK=${LOCK:-/var/tmp/p11scope-ws-tmp/privileged.lock}
MODULE=${MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}
RUNUID=${RUNUID:-1000} RUNGID=${RUNGID:-1000}

die() { echo "measure-c5-campaign: $*" >&2; exit 70; }
log() { echo "[$(date '+%F %T')] $*" | tee -a "${OUT:-/dev/null}/campaign.log" >&2; }

# ---------------------------------------------------------------- the plan

# plan_units: one line per unit, in execution order:
#   id|measurement|kind|role|round|heavy|expect|estimate_s|args
# kind: bench (args are bench options), m0pid, m0refuse, m2 (args: threads).
plan_units() {
    local measures m r cell role roles args tier rounds max i
    case $TIER in
        1|2|all) measures="M0 M1 M1-match R4 M2 M3 M4 M5 M6 M7" ;;
    esac
    if [ -n "$ONLY" ]; then
        local keep="M0"
        for m in $measures; do case ",$ONLY," in *",$m,"*) keep="$keep $m" ;; esac; done
        measures=$keep
    fi
    local small=0
    [ "$SCALE" = smoke ] && small=1
    for m in $measures; do
        case $m in
            M0) emit_m0; continue ;;
        esac
        # This tier's cells of m, with their round counts.
        local cells=()
        while IFS='|' read -r tier rounds cell roles args; do
            [ -n "$cell" ] || continue
            [ "$TIER" = all ] || [ "$TIER" = "$tier" ] || continue
            [ -n "$ROUNDS" ] && rounds=$ROUNDS
            [ "$small" = 1 ] && rounds=1
            cells+=("$rounds|$cell|$roles|$args")
        done < <(cells_for "$m" "$small")
        max=0
        for i in "${cells[@]}"; do [ "${i%%|*}" -gt "$max" ] && max=${i%%|*}; done
        # Round-major: every round visits every cell that still has rounds;
        # within a cell the roles alternate their order every round.
        for ((r = 1; r <= max; r++)); do
            for i in "${cells[@]}"; do
                IFS='|' read -r rounds cell roles args <<< "$i"
                [ "$r" -le "$rounds" ] || continue
                # shellcheck disable=SC2206  # roles is a word list by design
                local list=($roles)
                if [ $((r % 2)) = 0 ]; then
                    local rev=() k
                    for ((k = ${#list[@]} - 1; k >= 0; k--)); do rev+=("${list[$k]}"); done
                    list=("${rev[@]}")
                fi
                for role in "${list[@]}"; do
                    emit_unit "$m" "$cell" "$role" "$r" "$args"
                done
            done
        done
    done
}

# cells_for M SMALL: "tier|rounds|cell|roles|bench args" lines. Roles name
# binaries (cand, base, r4base, loss) plus an observer suffix where one cell
# compares observers: -native/-scan (inventory capture), -profile
# (profile-metrics), control (no observer).
#
# Tier 1 is the must-have set that fits a ~2 h quiet window (owner,
# 2026-10-04, for v0.2.0's docs/known-limitations.md): M1 at 448 and 4,096
# (scan and native), the C5.6 R4 pool on cores 8-11 at 4,096, and M4 at 448
# with 100 and 1,000 execs/s. To fit, its cells run 3 rounds of 3 samples
# (1 cold + 2 warm): 3 cold + 6 warm per (cell, role) instead of the plan's
# 5 + 5, each sample a 30 s run with its own per-pass p50/p95 (M4: 3 rounds
# of 2 samples of 60 s). Tier 2 is everything else (v0.3.0).
cells_for() {
    local m=$1 s=$2
    local dur30=30 dur60=60 c448="--total 448 --callers 300" c4096="--total 4096 --callers 1000"
    local c10k="--total 10000 --callers 1000"
    local h448="--total 448 --callers 30 --mappers 20" h4096="--total 4096 --callers 100 --mappers 20"
    if [ "$s" = 1 ]; then
        dur30=10 dur60=25 c448="--total 64 --callers 8" c4096="--total 64 --callers 8 --mappers 4"
        c10k="--total 64 --callers 8 --mappers 8" h448="--total 64 --callers 8 --mappers 4"
        h4096=$h448
    fi
    local hi=1000
    [ "$s" = 1 ] && hi=100
    case $m in
        M1)
            echo "1|3|p448|cand-native cand-scan|$c448 --duration $dur30 --samples 3"
            echo "1|3|p4096|cand-native cand-scan|$c4096 --duration $dur30 --samples 3"
            if [ "$s" = 1 ]; then
                echo "2|5|p10000|cand-native cand-scan|$c10k --duration $dur30 --samples 2"
            else
                echo "2|5|p10000|cand-native cand-scan|$c10k --duration 45 --samples 2"
            fi ;;
        M1-match)
            echo "2|5|p448|base-profile cand-profile|$c448 --duration $dur30 --samples 2"
            echo "2|5|p4096|base-profile cand-profile|$c4096 --duration $dur30 --samples 2" ;;
        R4)
            echo "1|3|p4096-c4|r4base-scan cand-scan|$c4096 --duration $dur30 --samples 3 --cpus 8,9,10,11"
            echo "2|5|p4096-c2|r4base-scan cand-scan|$c4096 --duration $dur30 --samples 2 --cpus 10,11"
            echo "2|5|p448-c4|r4base-scan cand-scan|$c448 --duration $dur30 --samples 2 --cpus 8,9,10,11" ;;
        M3)
            echo "2|5|h448-short100|cand-native|$h448 --observer-ns host --events --churn 100 --provider-share 10 --caller-args 1_0 --duration $dur60 --samples 2"
            echo "2|5|h448-short$hi|cand-native|$h448 --observer-ns host --events --churn $hi --provider-share 10 --caller-args 1_0 --duration $dur60 --samples 2"
            echo "2|5|h448-long10|cand-native|$h448 --observer-ns host --events --churn 10 --provider-share 100 --caller-args 40_100000 --duration $dur60 --samples 2"
            echo "2|5|h4096-short100|cand-native|$h4096 --observer-ns host --events --churn 100 --provider-share 10 --caller-args 1_0 --duration $dur60 --samples 2"
            echo "2|5|h4096-short$hi|cand-native|$h4096 --observer-ns host --events --churn $hi --provider-share 10 --caller-args 1_0 --duration $dur60 --samples 2"
            echo "2|5|h4096-long10|cand-native|$h4096 --observer-ns host --events --churn 10 --provider-share 100 --caller-args 40_100000 --duration $dur60 --samples 2" ;;
        M4)
            echo "1|3|h448-churn100|cand-native|$h448 --observer-ns host --events --churn 100 --provider-share 0 --duration $dur60 --samples 2"
            echo "1|3|h448-churn$hi|cand-native|$h448 --observer-ns host --events --churn $hi --provider-share 0 --duration $dur60 --samples 2"
            echo "2|5|h448-churn0|cand-native|$h448 --observer-ns host --events --duration $dur60 --samples 2"
            echo "2|5|h4096-churn0|cand-native|$h4096 --observer-ns host --events --duration $dur60 --samples 2"
            echo "2|5|h4096-churn100|cand-native|$h4096 --observer-ns host --events --churn 100 --provider-share 0 --duration $dur60 --samples 2"
            echo "2|5|h4096-churn$hi|cand-native|$h4096 --observer-ns host --events --churn $hi --provider-share 0 --duration $dur60 --samples 2" ;;
        M5)
            if [ "$s" = 1 ]; then
                echo "2|2|h-endpoints|cand-native|$h4096 --observer-ns host --events --churn 50 --provider-share 10 --caller-args 1_0 --duration 30 --map-sample 5 --samples 1"
            else
                echo "2|2|h-endpoints|cand-native|--total 4096 --callers 1000 --mappers 500 --observer-ns host --events --churn 100 --provider-share 10 --caller-args 1_0 --duration 300 --map-sample 10 --samples 1"
            fi ;;
        M6)
            local lat=20 d6=60
            [ "$s" = 1 ] && lat=3 d6=15
            echo "2|5|p4096-lat|control cand-native base-profile cand-profile|$c4096 --latency $lat --mmap-every 100 --duration $d6 --samples 2" ;;
        M7)
            local rate=30 d7=30
            [ "$s" = 1 ] && rate=20 d7=25
            echo "2|3|h-dlopen|base-profile cand-profile|--total 64 --callers 4 --observer-ns host --churn $rate --provider-share 100 --caller-args 1_0 --duration $d7 --samples 1" ;;
        M2)
            echo "2|10|t1|round|1"
            if [ "$s" = 0 ]; then echo "2|10|t4|round|4"; echo "2|10|t12|round|12"; fi ;;
    esac
}

emit_m0() {
    # Host-namespace legs scan the whole host (~500 processes here): 30 s
    # gives the 3 stage-timed passes the stats check needs even when loaded.
    local d=30 loss_role=cand-native loss_rate=$LOSS_CHURN
    [ -n "$LOSS_CANDIDATE" ] && loss_role=loss-native loss_rate=300
    emit_raw "M0-correct" M0 m0pid cand 1 0 correct 40 ""
    emit_raw "M0-refused" M0 m0refuse cand 1 0 refused 5 ""
    emit_raw "M0-loss" M0 bench "$loss_role" 1 0 lossy $((d + 60)) \
        "--total 64 --callers 4 --mappers 4 --observer-ns host --events --churn $loss_rate --provider-share 0 --duration $d --samples 1"
    emit_raw "M0-killed-sampler" M0 bench cand-native 1 0 missing $((d + 50)) \
        "--total 64 --callers 4 --mappers 4 --duration $d --samples 1 FAULT=kill-sampler:3"
    emit_raw "M0-control" M0 bench cand-native 1 0 correct $((d + 60)) \
        "--total 64 --callers 4 --mappers 4 --observer-ns host --events --duration $d --samples 1"
}

emit_unit() { # M CELL ROLE ROUND ARGS
    local m=$1 cell=$2 role=$3 r=$4 args=$5 kind=bench heavy=0
    [ "$m" = M2 ] && kind=m2
    case $args in *"--total 10000"*) heavy=1 ;; esac
    emit_raw "$m-$cell-$role-r$r" "$m" "$kind" "$role" "$r" "$heavy" "" "$(estimate "$kind" "$args")" "$args"
}

emit_raw() { echo "$1|$2|$3|$4|$5|$6|$7|$8|$9"; }

# estimate KIND ARGS: wall seconds for one unit (calibrated on this host:
# see c5-measurement-readiness.md). Population build ~0.06 s per SoftHSM2
# caller plus ~3 ms per idle process; each sample costs its duration plus
# a stop and a per-sample cooldown that grows with the population (plus the
# host-namespace detach, below); teardown
# and the cooldown before the next unit grow with the population too.
estimate() {
    local kind=$1 args=$2
    case $kind in
        m2) echo 90; return ;;  # 4 conditions x (ready ~3 s + 5 s window + stop) + gate
    esac
    python3 -I - "$args" <<'EOF'
import re, sys
args = sys.argv[1]
def opt(name, default):
    m = re.search(rf"--{name} (\S+)", args)
    return float(m.group(1)) if m else default
total, callers = opt("total", 64), opt("callers", 0)
duration, samples, latency = opt("duration", 60), opt("samples", 2), opt("latency", 0)
build = 15 + 0.06 * callers + 0.003 * (total - callers)
per_sample = duration + latency + 5 + 0.002 * total + (0 if total < 1000 else 20)
# A host-namespace native observer retires its attachments one by one on
# stop (~30 s per sample before C5.11, measured in the smoke; C5.11's grouped
# detach should shrink it, so this stays an upper bound).
if "--observer-ns host" in args:
    per_sample += 30
teardown = 5 + 0.003 * total
cooldown = 10 if total < 1000 else 60 if total < 5000 else 240
print(int(build + samples * per_sample + teardown + cooldown))
EOF
}

# ---------------------------------------------------------------- helpers

load_ok() { # MAX [ALSO5]
    awk -v max="$1" -v five="${2:-0}" '{exit !($1 < max && (five == 0 || $2 < max))}' /proc/loadavg
}

wait_quiet() { # MAX ALSO5 LIMIT_S -> 0 quiet, 1 timed out
    local waited=0
    until load_ok "$1" "$2"; do
        [ "$waited" -ge "$3" ] && return 1
        sleep 10
        waited=$((waited + 10))
    done
    return 0
}

binary_for() {
    case ${1%%-*} in
        cand) echo "$CANDIDATE" ;;
        base) echo "$BASELINE" ;;
        r4base) echo "$R4_BASE" ;;
        loss) echo "$LOSS_CANDIDATE" ;;
        control) echo "$CANDIDATE" ;;
        *) return 1 ;;
    esac
}

json_unit() { # FILE key=value...
    python3 -I - "$@" <<'EOF'
import json, sys
path, pairs = sys.argv[1], sys.argv[2:]
data = {}
try:
    data = json.load(open(path))
except (OSError, ValueError):
    pass
for pair in pairs:
    key, _, value = pair.partition("=")
    if key in ("attempts", "round", "heavy", "estimate_s", "wall_s"):
        value = int(value or 0)
    elif key == "class_reasons":
        value = [line for line in value.split("\n") if line]
    data[key] = value
json.dump(data, open(path, "w"), indent=2)
EOF
}

unit_status() { # ID -> status or empty
    python3 -I -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get("status",""))
except Exception: print("")' "$OUT/units/$1/unit.json"
}

regen_report() {
    python3 -I "$ANALYSIS" report "$OUT" > "$OUT/c5-measurements.md.tmp" 2>> "$OUT/campaign.log" \
        && mv "$OUT/c5-measurements.md.tmp" "$OUT/c5-measurements.md" \
        && { [ -z "$REPORT" ] || install -m 0644 -o "$RUNUID" -g "$RUNGID" "$OUT/c5-measurements.md" "$REPORT"; }
}

# ---------------------------------------------------------------- unit kinds

# run_bench UNIT_DIR ROLE ARGS -> attempt status (valid|invalid|refused|failed)
run_bench() {
    local dir=$1 role=$2 args=$3 bin observer=inventory capture=native fault=""
    bin=$(binary_for "$role") || { echo failed; return; }
    case $role in
        *-scan) capture=scan ;;
        *-profile) observer=profile-metrics capture=scan ;;
        control) observer=none capture=scan ;;
    esac
    local words=() word
    for word in $args; do
        case $word in
            FAULT=*) fault=${word#FAULT=} ;;
            *_*) words+=("${word//_/ }") ;;  # --caller-args 1_0 -> "1 0"
            *) words+=("$word") ;;
        esac
    done
    local cpus=()
    case " $args " in *" --cpus "*) ;; *) cpus=(--cpus "10,11") ;; esac
    BENCH_NATIVE_FAULT=$fault timeout --kill-after=60 7200 "$BENCH" "$bin" --capture "$capture" \
        --observer "$observer" "${words[@]}" "${cpus[@]}" --base "$OUT/bench-root" \
        --label "$role" --cooldown 600 --max-load1 "$MAX_LOAD1" --max-builds "$MAX_BUILDS" > "$dir/bench.out" 2>&1
    local rc=$?
    local run
    run=$(sed -n 's/^run=\([^ ]*\) .*/\1/p' "$dir/bench.out" | head -1)
    { echo "run=$run"; echo "rc=$rc"; } > "$dir/attempt.kv"
    case $rc in
        0) echo valid ;;
        1) echo invalid ;;
        3) echo refused ;;
        *) echo failed ;;
    esac
}

# prepare_work: fixtures and a RUNUID token for the units outside the bench.
prepare_work() {
    W=$OUT/work
    [ -x "$W/bin/mt" ] && [ -f "$W/token/softhsm2.conf" ] && return 0
    install -d -m 0711 "$W" "$W/bin" || die "work dir"
    gcc -O2 -pthread -o "$W/bin/mt" "$REPO/tests/fixtures/public-cli/mt.c" -ldl || die "mt build"
    chmod 0755 "$W/bin/mt"
    install -d -o "$RUNUID" -g "$RUNGID" -m 0700 "$W/token" "$W/run" || die "token dir"
    printf 'directories.tokendir = %s/token/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$W" \
        > "$W/token/softhsm2.conf" && chmod 0644 "$W/token/softhsm2.conf"
    # shellcheck disable=SC2016
    setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups --no-new-privs \
        env -i PATH=/usr/bin:/bin HOME=/nonexistent SOFTHSM2_CONF="$W/token/softhsm2.conf" \
        sh -c 'mkdir -m 700 "$1" && softhsm2-util --init-token --free --label c5 --so-pin 5678 --pin 1234 >/dev/null' \
        _ "$W/token/tokens" || die "token init"
}

AS_USER() {
    setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups --no-new-privs \
        env -i PATH=/usr/bin:/bin HOME=/nonexistent SOFTHSM2_CONF="$W/token/softhsm2.conf" "$@"
}

# observe_mt DIR COND THREADS SECS STOP_AFTER: one ledgered mt run, observed
# by COND (control | cand-native | cand-metrics | base-metrics). Writes
# DIR/{target.kv,mt.out,stderr,rc,inventory.json|profile.json}.
observe_mt() {
    local d=$1 cond=$2 threads=$3 secs=$4 stop_after=$5
    local gate=$W/run/gate.$$ wcpus obs="" bin ready=0 t0 pid mtpid
    install -d -m 0700 "$d"
    rm -f "$gate"
    case $threads in 1) wcpus=2 ;; 4) wcpus=2-5 ;; *) wcpus=0-$(($(nproc) - 1)) ;; esac
    AS_USER taskset -c "$wcpus" timeout 300 "$W/bin/mt" "$MODULE" "$threads" "$secs" 0 "$gate" \
        > "$d/mt.out" 2> "$d/mt.err" &
    mtpid=$!
    for _ in $(seq 100); do grep -q '^READY' "$d/mt.out" && break; sleep 0.1; done
    pid=$(sed -n 's/^READY pid=//p' "$d/mt.out")
    if [ -z "$pid" ]; then
        kill "$mtpid" 2>/dev/null; wait "$mtpid"
        { echo "valid=0"; echo "reason=workload never became ready"; } > "$d/target.kv"
        return
    fi
    t0=$(date +%s%N)
    case $cond in
        control) ready=1 ;;
        *-native)
            bin=$(binary_for "$cond")
            env --default-signal=INT taskset -c 10,11 "$bin" inventory --pid "$pid" --capture native \
                --duration 120 -o "$d/inventory.json" --event-log "$d/events.jsonl" \
                > "$d/stdout" 2> "$d/stderr" &
            obs=$! ;;
        *-metrics)
            bin=$(binary_for "$cond")
            env --default-signal=INT taskset -c 10,11 "$bin" profile --pid "$pid" --mode metrics \
                --duration 120 -o "$d/profile.json" > "$d/stdout" 2> "$d/stderr" &
            obs=$! ;;
    esac
    if [ -n "$obs" ]; then
        for _ in $(seq 1200); do
            kill -0 "$obs" 2>/dev/null || break
            if grep -qE 'p11scope: capturing: [1-9]' "$d/stderr" 2>/dev/null \
                || grep -q 'pass_committed' "$d/events.jsonl" 2>/dev/null; then
                ready=1; break
            fi
            sleep 0.05
        done
    fi
    echo "ready_ms=$(( ($(date +%s%N) - t0) / 1000000 ))" > "$d/readiness.txt"
    touch "$gate"
    if [ -n "$obs" ] && [ "$stop_after" -gt 0 ]; then
        sleep "$stop_after"
        kill -INT "$obs" 2>/dev/null
    fi
    wait "$mtpid"
    local mtrc=$?
    if [ -n "$obs" ]; then
        kill -INT "$obs" 2>/dev/null
        wait "$obs"; echo "$?" > "$d/rc"
    else
        echo 0 > "$d/rc"
    fi
    local total
    total=$(sed -n 's/^TOTAL C_GenerateRandom=\([0-9]*\).*/\1/p' "$d/mt.out")
    local valid=1 reason=""
    [ "$ready" = 1 ] || { valid=0; reason="observer never became ready"; }
    [ "$mtrc" = 0 ] && [ -n "$total" ] || { valid=0; reason="workload rc=$mtrc, no TOTAL"; }
    case $(cat "$d/rc") in 0|130) ;; *) valid=0; reason="observer rc $(cat "$d/rc")" ;; esac
    if [ "$valid" = 1 ] && [ "$cond" != control ]; then
        # Equal coverage: the observer must have instrumented the target.
        if [ -f "$d/inventory.json" ]; then
            { echo "pid=$pid"; echo "total=$total"; } > "$d/target.kv"
            python3 -I "$ANALYSIS" m0-pid "$d" | grep -q '^CLASS=correct' \
                || { valid=0; reason="native capture did not witness the target"; }
        elif ! python3 -I -c 'import json,sys
d=json.load(open(sys.argv[1])); s=json.dumps(d)
sys.exit(0 if "C_GenerateRandom" in s else 1)' "$d/profile.json" 2>/dev/null; then
            valid=0; reason="metrics document names no C_GenerateRandom"
        fi
    fi
    { echo "pid=$pid"; echo "total=${total:-0}"; echo "threads=$threads"; echo "secs=$secs"
      echo "valid=$valid"; echo "reason=$reason"; echo "load=$(cut -d' ' -f1-3 /proc/loadavg)"; } > "$d/target.kv"
}

run_m0pid() { # DIR -> class
    observe_mt "$1/run" cand-native 1 6 4
    python3 -I "$ANALYSIS" m0-pid "$1/run" > "$1/class.txt"
    sed -n 's/^CLASS=//p' "$1/class.txt"
}

run_m0refuse() { # DIR -> class
    local d=$1/run pid
    install -d -m 0700 "$d"
    true & pid=$!; wait "$pid"
    { echo "pid=$pid"; echo "total=0"; } > "$d/target.kv"
    timeout 60 "$CANDIDATE" inventory --pid "$pid" --capture native --duration 5 \
        -o "$d/inventory.json" > "$d/stdout" 2> "$d/stderr"
    echo "$?" > "$d/rc"
    python3 -I "$ANALYSIS" m0-pid "$d" > "$1/class.txt"
    sed -n 's/^CLASS=//p' "$1/class.txt"
}

run_m2() { # DIR THREADS ROUND -> valid|invalid
    local d=$1/data threads=$2 r=$3 conds=(control base-metrics cand-native cand-metrics) i k
    local secs=5
    [ "$SCALE" = smoke ] && secs=2
    # Rotate the condition order every round.
    for ((i = 0; i < ${#conds[@]}; i++)); do
        k=$(( (i + r - 1) % ${#conds[@]} ))
        observe_mt "$d/${conds[$k]}" "${conds[$k]}" "$threads" "$secs" 0
    done
    if grep -q '^valid=0' "$d"/*/target.kv; then echo invalid; else echo valid; fi
}

# ---------------------------------------------------------------- one unit

run_unit() { # line
    local id m kind role r heavy expect est args
    IFS='|' read -r id m kind role r heavy expect est args <<< "$1"
    local U=$OUT/units/$id status attempts=0 started class=""
    install -d -m 0700 "$U"
    status=$(unit_status "$id")
    case $status in valid|exhausted) return 0 ;; esac
    # A resumed unit continues its attempt numbering; earlier attempts stay.
    [ -f "$U/unit.json" ] && attempts=$(python3 -I -c 'import json,sys
print(json.load(open(sys.argv[1])).get("attempts", 0))' "$U/unit.json")
    json_unit "$U/unit.json" "id=$id" "measurement=$m" "cell=${id#"$m"-}" "kind=$kind" "role=$role" \
        "round=$r" "heavy=$heavy" "expect=$expect" "estimate_s=$est" "args=$args" "status=running"
    while :; do
        attempts=$((attempts + 1))
        local A=$U/attempt-$attempts also5=0
        install -d -m 0700 "$A"
        [ "$m" = M2 ] && also5=1
        if ! wait_quiet "$MAX_LOAD1" "$also5" "$GATE_WAIT"; then
            echo "uptime_before=$(uptime)" > "$A/gate.kv"
            json_unit "$U/unit.json" "status=refused" "attempts=$attempts" \
                "reason=host load stayed at or above $MAX_LOAD1 for ${GATE_WAIT}s: $(cut -d' ' -f1-3 /proc/loadavg)"
            log "$id: REFUSED (load)"
            return 0
        fi
        { echo "uptime_before=$(uptime)"; echo "at_before=$(date --iso-8601=s)"; } > "$A/gate.kv"
        started=$(date +%s)
        log "$id attempt $attempts: start ($(cut -d' ' -f1-3 /proc/loadavg))"
        case $kind in
            bench) status=$(run_bench "$A" "$role" "$args") ;;
            m0pid) class=$(run_m0pid "$A"); status=valid ;;
            m0refuse) class=$(run_m0refuse "$A"); status=valid ;;
            m2) install -d -m 0700 "$U/data"; status=$(run_m2 "$A" "$args" "$r")
                rm -rf "$U/data"; cp -a "$A/data" "$U/data" ;;
        esac
        { echo "uptime_after=$(uptime)"; echo "at_after=$(date --iso-8601=s)"
          echo "wall_s=$(( $(date +%s) - started ))"; echo "status=$status"; } >> "$A/gate.kv"
        if [ "$m" = M0 ] && [ "$kind" = bench ]; then
            local run
            run=$(sed -n 's/^run=//p' "$A/attempt.kv")
            if [ -n "$run" ] && [ -d "$run" ]; then
                python3 -I "$ANALYSIS" --max-load1 "$MAX_LOAD1" --max-builds "$MAX_BUILDS" m0-run "$run" > "$A/class.txt"
                class=$(sed -n 's/^CLASS=//p' "$A/class.txt")
            else
                class=failed
            fi
            status=valid  # M0 judges the classification, not the run's validity
        fi
        if [ -n "$class" ]; then
            json_unit "$U/unit.json" "class=$class" \
                "class_reasons=$(sed -n 's/^  - //p' "$A/class.txt" 2>/dev/null | head -5)"
        fi
        log "$id attempt $attempts: $status${class:+ class=$class} ($(( $(date +%s) - started )) s)"
        if [ "$heavy" = 1 ]; then
            log "$id: 10k cooldown"
            sleep 60
            wait_quiet "$MAX_LOAD1" 0 "$GATE_WAIT" || log "$id: cooldown did not reach load1 < $MAX_LOAD1"
        fi
        if [ "$status" = valid ]; then
            json_unit "$U/unit.json" "status=valid" "attempts=$attempts" "wall_s=$(( $(date +%s) - started ))" "reason="
            break
        fi
        local reason
        reason=$(grep -m3 '^  - ' "$A/bench.out" 2>/dev/null | tr '\n' ' ')
        [ -n "$reason" ] || reason=$(tail -2 "$A/bench.out" 2>/dev/null | tr '\n' ' ')
        if [ "$attempts" -ge "$MAX_ATTEMPTS" ]; then
            json_unit "$U/unit.json" "status=exhausted" "attempts=$attempts" "reason=$status: $reason"
            break
        fi
        json_unit "$U/unit.json" "status=retrying" "attempts=$attempts" "reason=$status: $reason"
    done
    regen_report
}

m0_verdict() {
    python3 -I - "$OUT" <<'EOF'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
bad, seen = [], 0
for path in sorted(out.glob("units/M0-*/unit.json")):
    unit = json.load(open(path))
    seen += 1
    if unit.get("class") != unit.get("expect"):
        bad.append(f"{unit['id']}: classified {unit.get('class')!r}, expected {unit.get('expect')!r}")
if seen < 5:
    bad.append(f"only {seen} of 5 M0 legs ran")
print("PASS: all 5 legs classified as expected" if not bad else "FAIL: " + "; ".join(bad))
EOF
}

# ---------------------------------------------------------------- self-test

self_test() {
    local out n
    T=$(mktemp -d "${TMPDIR:-/var/tmp}/measure-c5-selftest.XXXXXX") || die "mktemp"
    trap 'rm -rf "$T"' EXIT
    TIER=1 SCALE=full ONLY="" ROUNDS=""
    out=$(plan_units)
    [ "$(echo "$out" | head -5 | cut -d'|' -f2 | sort -u)" = M0 ] || die "M0 does not come first"
    echo "$out" | head -5 | cut -d'|' -f7 | tr '\n' ' ' | grep -qx 'correct refused lossy missing correct ' \
        || die "M0 expectations wrong: $(echo "$out" | head -5 | cut -d'|' -f7 | tr '\n' ' ')"
    [ "$(echo "$out" | sed -n 6p | cut -d'|' -f2)" = M1 ] || die "M1 does not follow M0"
    # Tier 1: 3 rounds x 2 cells x 2 roles; roles alternate order every round.
    n=$(echo "$out" | grep -c '^M1-')
    [ "$n" = 12 ] || die "tier-1 M1 has $n units, want 12"
    echo "$out" | grep -q '^M1-p10000-' && die "tier 1 runs 10k cells"
    [ "$(echo "$out" | grep '^M1-p448-' | head -2 | cut -d'|' -f4 | tr '\n' ' ')" = "cand-native cand-scan " ] \
        || die "round 1 role order"
    [ "$(echo "$out" | grep '^M1-p448-.*-r2|' | cut -d'|' -f4 | tr '\n' ' ')" = "cand-scan cand-native " ] \
        || die "round 2 role order not reversed"
    [ "$(echo "$out" | grep '^M1-' | head -4 | cut -d'|' -f1 | sed 's/-cand.*//' | tr '\n' ' ')" = "M1-p448 M1-p448 M1-p4096 M1-p4096 " ] \
        || die "round 1 does not visit every cell first"
    echo "$out" | grep '^M1-' | cut -d'|' -f9 | grep -qv -- '--samples 3' && die "tier-1 M1 not 3 samples"
    echo "$out" | grep -c '^R4-' | grep -qx 6 || die "tier-1 R4 unit count"
    echo "$out" | grep '^R4-' | grep -qv -- '--cpus 8,9,10,11' && die "tier-1 R4 not on cores 8-11"
    echo "$out" | grep -c '^M4-' | grep -qx 6 || die "tier-1 M4 unit count"
    echo "$out" | grep '^M4-' | cut -d'|' -f1 | sed 's/-cand.*//' | sort -u | tr '\n' ' ' \
        | grep -qx 'M4-h448-churn100 M4-h448-churn1000 ' || die "tier-1 M4 cells"
    echo "$out" | cut -d'|' -f2 | uniq | tr '\n' ' ' | grep -qx 'M0 M1 R4 M4 ' || die "tier-1 order"
    TIER=2
    out=$(plan_units)
    echo "$out" | cut -d'|' -f2 | uniq | tr '\n' ' ' | grep -qx 'M0 M1 M1-match R4 M2 M3 M4 M5 M6 M7 ' \
        || die "tier-2 order: $(echo "$out" | cut -d'|' -f2 | uniq | tr '\n' ' ')"
    echo "$out" | grep -c '^M1-p10000-' | grep -qx 10 || die "tier-2 10k units"
    echo "$out" | grep '^M1-p10000-' | cut -d'|' -f6 | grep -qv 1 && die "10k units not heavy"
    echo "$out" | grep -E '^M1-p(448|4096)-' && die "tier 2 repeats tier-1 cells"
    TIER=all
    out=$(plan_units)
    echo "$out" | grep -c '^M1-p' | grep -qx 22 || die "all-tier M1 count"
    echo "$out" | grep -c '^R4-' | grep -qx 26 || die "all-tier R4 count"
    echo "$out" | grep -c '^M4-' | grep -qx 26 || die "all-tier M4 count"
    ROUNDS=2
    plan_units | grep -c '^M1-p' | grep -qx 12 || die "--rounds does not override"
    ROUNDS="" ONLY=M4
    plan_units | cut -d'|' -f2 | uniq | tr '\n' ' ' | grep -qx 'M0 M4 ' || die "--only keeps M0"
    TIER=all ONLY="" SCALE=smoke
    out=$(plan_units)
    echo "$out" | cut -d'|' -f9 | grep -oE -- '--total [0-9]+' | sort -u | grep -qx -- '--total 64' \
        || die "smoke scale exceeds 64 processes: $(echo "$out" | cut -d'|' -f9 | grep -oE -- '--total [0-9]+' | sort -u | tr '\n' ' ')"
    n=$(echo "$out" | grep -v '^M0-' | cut -d'|' -f9 | grep -oE -- '--churn [0-9]+' | cut -d' ' -f2 | sort -n | tail -1)
    [ "$n" -le 300 ] || die "smoke churn $n/s is above 300/s"
    echo "plan: M0 first, order, interleave, heavy flags, 4-core set, smoke bounds ok"
    # Load gate logic.
    load_ok 1000 1 || die "load_ok refused an impossible bound"
    load_ok 0 0 && die "load_ok accepted load below 0"
    wait_quiet 0 0 0 && die "wait_quiet did not time out"
    echo "load gate: bounds and timeout ok"
    # Resume: a valid unit is skipped, an invalid one is retried.
    OUT=$T/c
    install -d "$OUT/units/X-a" "$OUT/units/X-b"
    json_unit "$OUT/units/X-a/unit.json" status=valid attempts=1
    json_unit "$OUT/units/X-b/unit.json" status=retrying attempts=1
    [ "$(unit_status X-a)" = valid ] && [ "$(unit_status X-b)" = retrying ] && [ -z "$(unit_status X-c)" ] \
        || die "unit status readback"
    # M0 verdict: one wrong leg fails the gate.
    for leg in correct:correct refused:refused lossy:lossy missing:missing control:correct; do
        install -d "$OUT/units/M0-${leg%%:*}"
        json_unit "$OUT/units/M0-${leg%%:*}/unit.json" "id=M0-${leg%%:*}" "expect=${leg#*:}" "class=${leg#*:}"
    done
    m0_verdict | grep -q '^PASS' || die "M0 verdict refused correct legs"
    json_unit "$OUT/units/M0-lossy/unit.json" class=correct
    m0_verdict | grep -q '^FAIL: M0-lossy' || die "M0 verdict accepted a loss classified correct"
    rm -r "$OUT/units/M0-control"
    json_unit "$OUT/units/M0-lossy/unit.json" class=lossy
    m0_verdict | grep -q 'only 4 of 5' || die "M0 verdict accepted a missing leg"
    echo "resume and M0 verdict: ok"
    python3 -I "$ANALYSIS" --self-test > "$T/analysis.out" || { cat "$T/analysis.out"; die "analysis self-test"; }
    echo "measure-c5-campaign: self-test ok"
}

# ---------------------------------------------------------------- main

CANDIDATE="" BASELINE="" R4_BASE="" LOSS_CANDIDATE="" LOSS_CHURN=3000 TIER=all SCALE=full ONLY="" ROUNDS=""
OUT="" RESUME="" REPORT="" GATE_WAIT=1800 MAX_ATTEMPTS=3 PLAN=0 MAX_LOAD1=4 MAX_BUILDS=0 M0_ADVISORY=0
[ "${1:-}" = --self-test ] && { self_test; exit 0; }
ORIG_ARGS=("$@")
while [ $# -gt 0 ]; do
    case $1 in
        --plan) PLAN=1; shift; continue ;;
        --m0-advisory) M0_ADVISORY=1; shift; continue ;;
    esac
    [ $# -ge 2 ] || { echo "$1 needs a value" >&2; exit 64; }
    case $1 in
        --candidate) CANDIDATE=$2 ;;
        --baseline) BASELINE=$2 ;;
        --r4-base) R4_BASE=$2 ;;
        --loss-candidate) LOSS_CANDIDATE=$2 ;;
        --loss-churn) LOSS_CHURN=$2 ;;
        --tier) TIER=$2 ;;
        --scale) SCALE=$2 ;;
        --only) ONLY=$2 ;;
        --rounds) ROUNDS=$2 ;;
        --out) OUT=$2 ;;
        --resume) RESUME=$2 ;;
        --report) REPORT=$2 ;;
        --gate-wait) GATE_WAIT=$2 ;;
        --max-attempts) MAX_ATTEMPTS=$2 ;;
        --max-load1) MAX_LOAD1=$2 ;;
        --max-builds) MAX_BUILDS=$2 ;;
        *) echo "unknown argument $1" >&2; exit 64 ;;
    esac
    shift 2
done
case $TIER in must) TIER=1 ;; rest) TIER=2 ;; esac
case $TIER in 1|2|all) ;; *) echo "--tier 1|2|all" >&2; exit 64 ;; esac
case $SCALE in full|smoke) ;; *) echo "--scale full|smoke" >&2; exit 64 ;; esac

if [ "$PLAN" = 1 ]; then
    total=0
    printf '%-44s %-9s %-8s %-15s %6s  %s\n' unit measure kind role est_s args
    while IFS='|' read -r id m kind role r heavy expect est args; do
        printf '%-44s %-9s %-8s %-15s %6s  %s\n' "$id" "$m" "$kind" "$role" "$est" "$args"
        total=$((total + est))
    done < <(plan_units)
    echo "units: $(plan_units | wc -l)  estimate: $((total / 3600)) h $(((total % 3600) / 60)) min (tier $TIER, scale $SCALE)"
    exit 0
fi

[ "$(id -u)" = 0 ] || die "must run as root (sudo)"
for bin in CANDIDATE BASELINE; do [ -x "${!bin}" ] || die "--${bin,,} must name an executable"; done
R4_BASE=${R4_BASE:-}
LOSS_CANDIDATE=${LOSS_CANDIDATE:-}
if plan_units | cut -d'|' -f4 | grep -q '^r4base'; then [ -x "$R4_BASE" ] || die "--r4-base is required for R4"; fi
[ -z "$LOSS_CANDIDATE" ] || [ -x "$LOSS_CANDIDATE" ] || die "--loss-candidate must name an executable"
for tool in gcc python3 setpriv taskset flock softhsm2-util bpftool systemd-run; do
    command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
done
[ "$GATE_WAIT" -ge 0 ] 2>/dev/null || die "--gate-wait takes seconds"
{ sh -c 'kill -HUP $$' >/dev/null 2>&1; } 2>/dev/null
[ $? -eq 129 ] || die "SIGHUP is ignored here (nohup?): the bench refuses; run in a terminal or tmux"

# The lock for the whole campaign: re-execute under flock(1) once, so flock
# is every unit's ancestor (the bench verifies that in /proc/locks).
if [ -z "${MEASURE_C5_LOCKED:-}" ]; then
    [ -e "$LOCK" ] || { install -d -m 0700 "$(dirname "$LOCK")" && : >> "$LOCK"; } || die "cannot create $LOCK"
    echo "waiting for $LOCK" >&2
    MEASURE_C5_LOCKED=1 exec flock -o -w 7200 -E 3 "$LOCK" "$SELF" "${ORIG_ARGS[@]}"
fi

if [ -n "$RESUME" ]; then
    OUT=$(realpath -e "$RESUME") || die "--resume $RESUME"
else
    OUT=${OUT:-/var/tmp/p11scope-ws-tmp/c5-measure/$(date -u +%Y%m%dT%H%M%SZ)}
    [ -e "$OUT" ] && die "$OUT exists (use --resume)"
    install -d -m 0700 "$OUT" || die "cannot create $OUT"
fi
# The bench insists on a root-owned base; the exit trap hands everything
# back to RUNUID, so a resume takes it back first.
if ! { install -d -m 0711 "$OUT/bench-root" && chown -R root:root "$OUT" \
    && chmod 0711 "$OUT" "$OUT/bench-root"; }; then
    die "bench root"
fi
trap 'chown -R "$RUNUID:$RUNGID" "$OUT" 2>/dev/null' EXIT
cat /proc/loadavg > /dev/null
C5_MAX_LOAD1=$MAX_LOAD1 C5_MAX_BUILDS=$MAX_BUILDS python3 -I - "$OUT/campaign.json" "$CANDIDATE" "$BASELINE" "$R4_BASE" "$LOSS_CANDIDATE" "$TIER" \
    "$SCALE" "$ONLY" "$(git -C "$REPO" rev-parse HEAD 2>/dev/null)" "$(uname -r)" "$(uname -n)" <<'EOF' || exit 70
import hashlib, json, sys, time
path, cand, base, r4, loss, tier, scale, only, commit, kernel, host = sys.argv[1:]
def digest(p):
    if not p:
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return f"{p} sha256:{h.hexdigest()}"
try:
    data = json.load(open(path))
except (OSError, ValueError):
    data = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
# A resume must measure the same binaries: one campaign never mixes builds.
for key, new in (("candidate", digest(cand)), ("baseline", digest(base)), ("r4_base", digest(r4))):
    if data.get(key) and new and data[key] != new:
        sys.exit(f"measure-c5-campaign: --resume with a different {key}: was {data[key]}, now {new}")
data.update(max_load1=float(__import__("os").environ.get("C5_MAX_LOAD1", "4")),
            max_builds=int(__import__("os").environ.get("C5_MAX_BUILDS", "0")),
            candidate=digest(cand), baseline=digest(base), r4_base=digest(r4),
            loss_candidate=digest(loss), tier=tier, scale=scale, only=only or None,
            commit=commit, kernel=kernel, host=host)
data.setdefault("resumes", []).append(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} tier={tier} only={only or '-'}")
json.dump(data, open(path, "w"), indent=2)
EOF
prepare_work
log "campaign $OUT: tier $TIER scale $SCALE, $(plan_units | wc -l) units; load $(cut -d' ' -f1-3 /proc/loadavg)"
log "host activity at start: $(ps -eo comm= | sort | uniq -c | sort -rn | head -8 | tr -s ' ' | tr '\n' ';')"

mapfile -t UNITS < <(plan_units)
if [ "$M0_ADVISORY" = 1 ] && [ -s "$OUT/M0.verdict" ]; then
    log "M0 (advisory, kept from before): $(cat "$OUT/M0.verdict")"
elif [ "$(cut -c1-4 "$OUT/M0.verdict" 2>/dev/null)" != PASS ]; then
    # M0 is re-judged as a whole: every leg runs again (attempts continue).
    for line in "${UNITS[@]}"; do
        case $line in
            M0-*) [ -f "$OUT/units/${line%%|*}/unit.json" ] \
                      && json_unit "$OUT/units/${line%%|*}/unit.json" status=pending class=
                  run_unit "$line" ;;
        esac
    done
    m0_verdict > "$OUT/M0.verdict"
    regen_report
    log "M0: $(cat "$OUT/M0.verdict")"
    case $(cat "$OUT/M0.verdict") in
        PASS*) ;;
        *) if [ "$M0_ADVISORY" = 1 ]; then
               log "M0 failed; --m0-advisory: continuing, and no result of this campaign counts"
           else
               log "M0 failed: the harness did not classify every leg as expected; stopping"
               exit 2
           fi ;;
    esac
fi
for line in "${UNITS[@]}"; do
    case $line in M0-*) continue ;; esac
    run_unit "$line"
done
regen_report
log "campaign complete: $OUT (report: ${REPORT:-$OUT/c5-measurements.md})"
exit 0

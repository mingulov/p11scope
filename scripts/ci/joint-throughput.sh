#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Joint key-operations throughput cells (WU-7a): live keyed HMAC at
# 10,000 calls/s over a linked capture, judged by the --joint oracle.
#
# Usage: joint-throughput.sh P11SCOPE OUTDIR
#   P11SCOPE  observer binary (a journal+marker build for the joint
#             cells; p11scope-discover must sit beside it)
#   OUTDIR    fresh results directory (results.jsonl plus one
#             evidence subdirectory per cell)
#
# Environment:
#   RATE      paced calls/s: 1k, 2.5k, 5k, 6.25k, 7.5k, 10k or 100k (default 10k)
#   DURATION  hot-loop seconds, 1..3600 (default 20; gated cells need
#             >= 2 so a full 1 s window exists)
#   MIN_RATE  oracle floor in calls/s (default 10000; must not exceed
#             the RATE in Hz)
#   CELLS     blank-separated subset of the three cells below
#             (default: all three)
#   SOFTHSM_LIB
#             provider path override (default: probe the release
#             matrix selector, then the Debian/Fedora paths)
#   OBS_MARGIN
#             observer seconds beyond DURATION for startup, the two
#             admission passes and drain (default 90)
#   SETTLEMENT_LAT
#             =1 records the diagnostic per-call ENTRY-to-settle
#             delays in the observer (1 ms buckets) and prints the
#             cumulative p50/p99/max line beside the stop line in
#             observer.out (default unset records nothing)
#   STAGE_TIMINGS
#             =1 enables stage-timing telemetry in the observer,
#             including the lifecycle ring high-water mark on the
#             stop line (default unset records nothing)
#
# Cells:
#   joint-10k-single  --system --key-operations over keyed RATE/DURATION
#   joint-10k-churn   --system --key-operations over keyed-churn RATE/DURATION
#   s1-10k-twin       --pid digest single RATE/DURATION without the flag,
#                      judged by the S1 mode (proves the rate is reachable
#                      on the host at that moment)
#
# The joint cells spawn the generator after the observer's pass 0, so
# its exec lands after the linked lane seals and its key is created
# inside the observed window. The generator prints MAPPED once the
# provider is mapped but before its first call; the cell waits for an
# admission pass, opens the setup gate, waits for READY, waits for a
# second pass so bindings install, then opens GO. First use after
# admission keeps the usage edge counted (use before admission voids
# it for good), and the unpaced setup prologue stays outside the
# paced rate windows by oracle design. Every cell holds its target
# through the observer drain with the FINISH gate and proves the hold
# (live PID plus provider mapping) before releasing it. The oracle
# judges every emitted ledger.
#
# Scope note: the joint cells use --system, not --pid. A --pid target
# that execs after closure loses capture custody at HEAD (the
# observer discloses it and never seals linked), while --system with
# a post-closure spawn is the lane the product links.
#
# Results: OUTDIR/results.jsonl carries one JSON object per cell:
# {"cell", "pass", "qualification", "detail"}. qualification is
# qualified, nonqualifying, expected-failure or failed. A rate miss
# on a loaded host (max sampled load1 above nproc) is
# nonqualifying with the load in detail, never pass; conservation
# and loss failures are failed at any load. Evidence that never
# met the oracle's input shape (loader refusals, flow timeouts) is
# nonqualifying on a loaded host and failed on a quiet one. A
# failure that matches the known product gap (the Session-loop seal
# wire is pending in WU-2, so production captures stay
# journal_unavailable) is an expected-failure with that reason in
# detail; any other gate-4 reason stays failed. A joint cell whose
# report shows no Joint feed at all (object_observations missing or
# journal_unavailable) was an S1-only run: it is nonqualifying with
# "s1-only" in detail, whichever gate the oracle failed first; a
# Joint feed that ran and lost its output (authority_lost) stays
# judged. Exit 0 when every
# cell either passed or is nonqualifying/expected-failure, 1 when
# any cell failed, 2 for caller/infra errors, 77 when the
# environment cannot satisfy the cell contract (rows are written
# as nonqualifying with the missing prerequisite in detail).
#
# Privilege: the observer runs under sudo -n with the workspace
# privileged lock held. Each cell holds the lock only for its own
# run. This script kills only the children it spawned, by PID.
#
# Apt prerequisites (ubuntu-26.04 runner, also fine as root):
# gcc python3 sudo util-linux procps softhsm2. The runner also
# needs kernel BTF (/sys/kernel/btf/vmlinux); KVM is not used by
# these cells. As root,
# sudo -n is a no-op and OUTDIR carries all state (tokens,
# SoftHSM config, emitter build), so no $HOME or TMPDIR reliance
# affects the run.
set -eu
umask 022

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/../.." && pwd)
ORACLE=$ROOT/scripts/s1-throughput-compare.py
EMITTER_SRC=$ROOT/tests/fixtures/joint-throughput/gen-calls.c
LOCK_FILE=${P11SCOPE_PRIVILEGED_LOCK:-/var/tmp/p11scope-ws-tmp/privileged.lock}
EXPECTED_WU2="Session-loop seal wire pending (WU-2)"

log() {
    printf 'joint-throughput: %s\n' "$*" >&2
}

# --- library (the python suite sources this file with
# --- JOINT_TP_SOURCED=1 and calls these functions directly) ---

# Echo the sudo command-line passthrough for diagnostic toggles, or
# nothing. Sudo scrubs the environment, so SETTLEMENT_LAT=1 and
# STAGE_TIMINGS=1 must ride the sudo command line as explicit assignments;
# anything else prints nothing. Each line is exactly one assignment
# (never user text).
observer_env() {
    if [ "${SETTLEMENT_LAT:-0}" = "1" ]; then
        echo "P11SCOPE_DIAGNOSTIC_SETTLEMENT_LATENCY=1"
    fi
    if [ "${STAGE_TIMINGS:-0}" = "1" ]; then
        echo "P11SCOPE_STAGE_TIMINGS=1"
    fi
}

# Print the provider path, or nothing when no candidate exists.
select_provider() {
    if [ -n "${SOFTHSM_LIB:-}" ]; then
        printf '%s\n' "$SOFTHSM_LIB"
        return 0
    fi
    selected=$(python3 -I "$ROOT/scripts/release-matrix-contract.py" \
        --select-module 2>/dev/null) || selected=""
    if [ -n "$selected" ] && [ -f "$selected" ]; then
        printf '%s\n' "$selected"
        return 0
    fi
    for candidate in /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib64/pkcs11/libsofthsm2.so; do
        if [ -f "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 0
}

# RATE label (1k/2.5k/5k/6.25k/7.5k/10k/100k) to Hz; prints nothing for anything else.
rate_hz() {
    case "${1:-}" in
        1k) printf '1000\n' ;;
        2.5k) printf '2500\n' ;;
        5k) printf '5000\n' ;;
        6.25k) printf '6250\n' ;;
        7.5k) printf '7500\n' ;;
        10k) printf '10000\n' ;;
        100k) printf '100000\n' ;;
        *) return 0 ;;
    esac
}

# Validate RATE/DURATION/MIN_RATE/CELLS; return 0 or print why not.
validate_params() {
    hz=$(rate_hz "${RATE:-10k}")
    if [ -z "$hz" ]; then
        log "RATE must be 1k, 2.5k, 5k, 6.25k, 7.5k, 10k or 100k"
        return 1
    fi
    case "${DURATION:-20}" in
        ''|*[!0-9]*)
            log "DURATION must be an integer 1..3600"
            return 1
            ;;
    esac
    if [ "${DURATION:-20}" -lt 1 ] || [ "${DURATION:-20}" -gt 3600 ]; then
        log "DURATION must be an integer 1..3600"
        return 1
    fi
    case "${MIN_RATE:-10000}" in
        ''|*[!0-9]*)
            log "MIN_RATE must be an integer >= 0"
            return 1
            ;;
    esac
    if [ "${MIN_RATE:-10000}" -gt "$hz" ]; then
        log "MIN_RATE ${MIN_RATE:-10000} exceeds RATE ${RATE:-10k} ($hz/s)"
        return 1
    fi
    for cell in ${CELLS:-joint-10k-single joint-10k-churn s1-10k-twin}; do
        case "$cell" in
            joint-10k-single|joint-10k-churn|s1-10k-twin) ;;
            *)
                log "unknown cell $cell"
                return 1
                ;;
        esac
    done
    return 0
}

# Build the emitter with the pinned warnings; prints the binary path.
build_emitter() {
    dest=$1
    mkdir -p "$dest"
    gcc -std=c11 -O2 -Wall -Wextra -Werror "$EMITTER_SRC" \
        -o "$dest/gen-calls" -ldl -pthread
    printf '%s\n' "$dest/gen-calls"
}

# First load1 field.
load1() {
    awk '{print $1}' /proc/loadavg
}

nproc_() {
    nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1\n'
}

# True when the max sampled load1 exceeds the CPU count: the host
# was too loaded to judge this cell.
loaded_host() {
    awk "BEGIN{exit !(($1) > ($2))}"
}

# Map one oracle run to "pass|qualification|marker". $1 oracle rc,
# $2 oracle stdout file, $3 max sampled load1, $4 nproc. marker
# carries the expected-failure reason, else empty.
map_verdict() {
    rc=$1
    out=$2
    max_load=$3
    cpus=$4
    if [ "$rc" -eq 0 ]; then
        printf 'true|qualified|\n'
        return 0
    fi
    reason=$(python3 -c \
        'import json,sys; print(json.load(open(sys.argv[1])).get("reason",""))' \
        "$out" 2>/dev/null) || reason=""
    if [ -z "$reason" ]; then
        printf 'false|failed|\n'
        return 0
    fi
    case "$reason" in
        *"reason journal_unavailable, not the Joint marker"*|\
*"joint_journal_unavailable"*)
            printf 'false|expected-failure|%s\n' "$EXPECTED_WU2"
            return 0
            ;;
        *"below minimum"*)
            if loaded_host "$max_load" "$cpus"; then
                printf 'false|nonqualifying|\n'
            else
                printf 'false|failed|\n'
            fi
            return 0
            ;;
        *"loss gap"*|*"R59 stopped disclosure"*)
            # A counted loss is a real result, never a skip: fail it
            # at any load, ahead of the load-judged arm below.
            printf 'false|failed|\n'
            return 0
            ;;
        *"unreadable events"*|*"unreadable ledger"*|*"unreadable inventory"*|\
*"event stream incomplete"*|*"missing or duplicate"*|\
*"withheld semantic summary"*|*"not complete"*|*"no ledgers emitted"*|\
*"never published"*|*"never printed"*|*"never became"*|\
*"no admission pass"*|*"no binding pass"*|*"not held"*|\
*" rc="*|*"chmod failed"*)
            # Evidence never met the oracle's input shape: judgeable
            # only on a quiet host.
            if loaded_host "$max_load" "$cpus"; then
                printf 'false|nonqualifying|\n'
            else
                printf 'false|failed|\n'
            fi
            return 0
            ;;
        *)
            printf 'false|failed|\n'
            return 0
            ;;
    esac
}

# Append one results.jsonl row. $1 cell, $2 pass (true/false),
# $3 qualification, $4 detail.
write_row() {
    python3 - "$RESULTS_JSONL" "$1" "$2" "$3" "$4" <<'PYEOF'
import json, sys
path, cell, passed, qualification, detail = sys.argv[1:6]
row = {"cell": cell, "pass": passed == "true",
       "qualification": qualification, "detail": detail}
with open(path, "a", encoding="utf-8") as stream:
    stream.write(json.dumps(row, sort_keys=True) + "\n")
PYEOF
}

# --events arguments for every retained part, oldest first: the
# numeric suffixes in descending order (.2 before .1), then the
# live base. The oracle sorts by seq, so the order is for humans.
event_args() {
    dir=$1
    args=""
    parts=$(for part in "$dir"/events.jsonl.[0-9]*; do
        [ -f "$part" ] || continue
        printf '%s\n' "$part"
    done | awk -F. '{ print $NF "\t" $0 }' | sort -n -r -k1,1 | cut -f2-) || parts=""
    for part in $parts; do
        args="$args --events $part"
    done
    printf '%s --events %s\n' "$args" "$dir/events.jsonl"
}

# Capture bpftool EVIDENCE[0] sums while the observer still runs (maps are
# unpinned and vanish on exit). Runs after DONE, before the observer-stop
# wait returns. The privileged lock is held here, so no other p11scope
# observer runs concurrently and every EVIDENCE map found is ours (main plus
# journal objects; the double-count check needs both summed). Writes
# $dir/bpftool-evidence.json (helper summary JSON) and logs one line.
# Always succeeds: measurement failures warn and continue, never failing
# the cell.
capture_bpf_evidence() {
    dir=$1
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/bpf-evidence.XXXXXX") || return 0
    if ! sudo -n bpftool map show -j > "$tmp/show.json" 2>/dev/null; then
        log "$dir: bpftool map show failed; skipping EVIDENCE capture"
        rm -rf "$tmp"
        return 0
    fi
    ids=$(python3 -I "$ROOT/scripts/bpf-evidence-sum.py" \
        --show "$tmp/show.json" --list-ids 2>/dev/null) || ids=""
    if [ -z "$ids" ]; then
        log "$dir: no EVIDENCE maps visible; skipping EVIDENCE capture"
        rm -rf "$tmp"
        return 0
    fi
    args=""
    # shellcheck disable=SC2086 # ids are bpftool integers, one per line.
    for id in $ids; do
        case $id in ''|*[!0-9]*) continue ;; esac
        if sudo -n bpftool map dump id "$id" -j > "$tmp/dump-$id.json" \
            2>/dev/null; then
            args="$args --dump $id=$tmp/dump-$id.json"
        else
            log "$dir: bpftool dump of map $id raced away; skipping it"
        fi
    done
    # shellcheck disable=SC2086 # args are helper paths built above.
    if python3 -I "$ROOT/scripts/bpf-evidence-sum.py" \
        --show "$tmp/show.json" $args > "$dir/bpftool-evidence.json" \
        2>"$tmp/helper.err"; then
        log "$dir: bpftool EVIDENCE: $(cat "$dir/bpftool-evidence.json")"
    else
        log "$dir: bpf-evidence-sum failed: $(cat "$tmp/helper.err")"
    fi
    mkdir -p "$dir/bpftool-evidence-raw" 2>/dev/null
    cp "$tmp/show.json" "$dir/bpftool-evidence-raw/show.json" 2>/dev/null
    for raw in "$tmp"/dump-*.json; do
        [ -f "$raw" ] && cp "$raw" "$dir/bpftool-evidence-raw/" 2>/dev/null
    done
    rm -rf "$tmp"
    return 0
}

# Take evidence ownership after the observer stops: the report,
# the live event log and any rotated parts (rotation may leave a
# part root-only). Returns nonzero when the chmod fails.
take_evidence() {
    sudo -n chmod 644 "$1/report.json" "$1"/events.jsonl*
}

# Record a flow failure: rc 2 plus a machine-readable oracle.json
# carrying the reason, so the verdict mapping reads it uniformly.
fail_flow() {
    dir=$1
    ORACLE_RC=2
    ORACLE_REASON=$2
    printf '{"verdict": "fail", "reason": "%s"}\n' "$2" > "$dir/oracle.json"
}

# --- privileged cells (only main reaches these) ---

# Signal cleanup: kill the current cell's own children by pidfile.
# Installed for INT/TERM only; normal completion reaps everything
# explicitly, so no stale pidfile is ever trusted.
CURRENT_DIR=""
cleanup_current() {
    [ -n "$CURRENT_DIR" ] || return 0
    kill_pidfile "$CURRENT_DIR/gen.pid"
    kill_observer "$CURRENT_DIR/observer.pid"
    CURRENT_DIR=""
    return 0
}

# Wait until $1 appears in $2 (grep -q) or $3 seconds pass; return 0/1.
wait_for_line() {
    pattern=$1
    file=$2
    deadline=$(($(date +%s) + $3))
    while ! grep -q "$pattern" "$file" 2>/dev/null; do
        if [ "$(date +%s)" -ge "$deadline" ]; then
            return 1
        fi
        sleep 0.5
    done
    return 0
}

# Count observer pass lines in $1.
pass_count() {
    grep -c "p11scope: pass " "$1" 2>/dev/null || true
}

# Wait until $1 gains a pass line beyond $2, or $3 seconds pass.
wait_for_pass() {
    file=$1
    before=$2
    deadline=$(($(date +%s) + $3))
    while [ "$(pass_count "$file")" -le "$before" ]; do
        if [ "$(date +%s)" -ge "$deadline" ]; then
            return 1
        fi
        sleep 0.5
    done
    return 0
}

# Kill the PIDs in $1 (a pidfile) when still alive; ours only.
kill_pidfile() {
    [ -f "$1" ] || return 0
    pid=$(cat "$1")
    case "$pid" in
        ''|*[!0-9]*) return 0 ;;
    esac
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
    fi
    return 0
}

# Kill an observer pidfile: the sudo wrapper plus its own children
# (killing sudo alone would orphan the running observer).
kill_observer() {
    [ -f "$1" ] || return 0
    pid=$(cat "$1")
    case "$pid" in
        ''|*[!0-9]*) return 0 ;;
    esac
    # Children of our sudo only, never a broad pattern.
    pkill -P "$pid" 2>/dev/null || true
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
    fi
    return 0
}

# Sample load1 into $LOAD_TRACE (a/b/c) and track the max in $LOAD_MAX.
# Call directly, never in $(): the updates must land in this shell.
sample_load() {
    now=$(load1)
    LOAD_MAX=$(awk "BEGIN{a=$LOAD_MAX; b=$now; print (a > b) ? a : b}")
    if [ -z "${LOAD_TRACE:-}" ]; then
        LOAD_TRACE=$now
    else
        LOAD_TRACE="$LOAD_TRACE/$now"
    fi
}

# Prove the FINISH hold: DONE printed, PID alive, provider still mapped.
prove_hold() {
    dir=$1
    pid=$2
    provider=$3
    grep -q "DONE" "$dir/gen.out" 2>/dev/null || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    grep -qF "$provider" "/proc/$pid/maps" 2>/dev/null || return 1
    return 0
}

# Run the oracle over a finished cell dir.
# $1 dir, $2 joint-flag-or-empty; sets ORACLE_RC/ORACLE_REASON globals.
run_oracle() {
    dir=$1
    mode=$2
    ledger_args=""
    for ledger in "$dir"/hot*.jsonl; do
        [ -f "$ledger" ] || continue
        ledger_args="$ledger_args --ledger $ledger"
    done
    if [ -z "$ledger_args" ]; then
        fail_flow "$dir" "no ledgers emitted"
        return 0
    fi
    # Word-split the assembled --ledger/--events lists. An oracle
    # fail verdict is rc 1, not a shell error: capture it without
    # tripping set -e.
    # shellcheck disable=SC2086
    ORACLE_RC=0
    if [ -n "$mode" ]; then
        python3 -I "$ORACLE" --joint --min-rate "$MIN_RATE" $ledger_args \
            $(event_args "$dir") --inventory "$dir/report.json" \
            > "$dir/oracle.json" 2> "$dir/oracle.err" || ORACLE_RC=$?
    else
        python3 -I "$ORACLE" --min-rate "$MIN_RATE" $ledger_args \
            $(event_args "$dir") --inventory "$dir/report.json" \
            > "$dir/oracle.json" 2> "$dir/oracle.err" || ORACLE_RC=$?
    fi
    ORACLE_REASON=$(python3 -c \
        'import json,sys; print(json.load(open(sys.argv[1])).get("reason",""))' \
        "$dir/oracle.json" 2>/dev/null) || ORACLE_REASON="oracle output unparsable"
    return 0
}

# Whether a joint cell's capture ran a Joint feed at all, from its
# report: "absent" when object_observations is missing or reads
# journal_unavailable (the run was S1-only), "present" for any other
# reason (populated, authority_lost, ...), "unknown" when the report
# is missing or unreadable (the flow arms judge that).
joint_feed_state() {
    python3 -I -c '
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        doc = json.load(handle)
except (OSError, ValueError):
    print("unknown")
    sys.exit(0)
if type(doc) is not dict:
    print("unknown")
    sys.exit(0)
observed = doc.get("object_observations")
if type(observed) is not dict or observed.get("reason") == "journal_unavailable":
    print("absent")
else:
    print("present")
' "$1"
}

finish_cell() {
    cell=$1
    dir=$2
    detail_extra=$3
    cpus=$(nproc_)
    mapping=$(map_verdict "$ORACLE_RC" "$dir/oracle.json" "$LOAD_MAX" "$cpus")
    passed=${mapping%%|*}
    rest=${mapping#*|}
    qualification=${rest%%|*}
    marker=${rest#*|}
    detail="host=$(hostname) kernel=$(uname -r) rate=$RATE dur=$DURATION min_rate=$MIN_RATE load1=$LOAD_TRACE nproc=$cpus provider=$PROVIDER $detail_extra oracle_rc=$ORACLE_RC reason=$ORACLE_REASON dir=$dir"
    # A joint cell whose capture never ran a Joint feed is an S1-only
    # run: it says nothing about the Joint path, so it is never
    # judged (nonqualifying), whatever the oracle found first.
    case "$cell" in
        joint-*)
            if [ "$(joint_feed_state "$dir/report.json")" = "absent" ]; then
                passed=false
                qualification=nonqualifying
                marker=
                detail="$detail s1-only: no Joint feed (object_observations journal_unavailable)"
            fi
            ;;
    esac
    if [ -n "$marker" ]; then
        detail="$detail expected-failure: $marker"
    fi
    write_row "$cell" "$passed" "$qualification" "$detail"
    log "$cell: pass=$passed $qualification ${marker:+($marker) }:: $ORACLE_REASON"
    [ "$passed" = "true" ] || [ "$qualification" != "failed" ]
}

# One joint cell: --system --key-operations, spawn after pass 0, no GO.
# $1 cell, $2 gen-calls mode.
run_joint_cell() {
    cell=$1
    mode=$2
    dir=$OUTDIR/$cell
    rm -rf "$dir"
    mkdir -p "$dir"
    CURRENT_DIR=$dir
    LOAD_MAX=0
    LOAD_TRACE=""
    sample_load
    obs_dur=$((DURATION + OBS_MARGIN))
    log "$cell: acquiring the privileged lock"
    exec 9>"$LOCK_FILE"
    flock 9
    log "$cell: lock held; starting the observer for ${obs_dur}s"
    # The lock fd is inherited; run sudo directly under the held lock.
    # Stdout stays unprivileged by design (the -o outputs are chmodded
    # after the run); shellcheck SC2024 does not apply.
    # shellcheck disable=SC2046,SC2086 # observer_env is empty or one assignment per line.
    sudo -n $(observer_env) "$P11SCOPE" inventory --system --manifest "$MANIFEST" \
        --key-operations --duration "$obs_dur" --json -o "$dir/report.json" \
        --event-log "$dir/events.jsonl" > "$dir/observer.out" 2>&1 &
    echo $! > "$dir/observer.pid"
    if ! wait_for_line "p11scope: pass 0:" "$dir/observer.out" 300; then
        log "$cell: pass 0 never published"
        kill_observer "$dir/observer.pid"
        exec 9>&-
        fail_flow "$dir" "pass 0 never published"
        finish_cell "$cell" "$dir" "flow=pass0-timeout" || return 1
        return 0
    fi
    log "$cell: pass 0 published; spawning the keyed generator"
    GEN_CALLS_SETUP_GATE="$dir/setup_go" SOFTHSM2_CONF="$SOFT_CONF" \
        "$GEN" "$PROVIDER" "$mode" "$RATE" "$DURATION" \
        "$dir/hot.jsonl" "$dir/go" "$dir/finish" \
        > "$dir/gen.out" 2> "$dir/gen.err" &
    gen_pid=$!
    echo "$gen_pid" > "$dir/gen.pid"
    sample_load
    if ! wait_for_line "MAPPED pid=" "$dir/gen.out" 120; then
        log "$cell: generator never mapped the provider"
        kill_pidfile "$dir/gen.pid"
        kill_observer "$dir/observer.pid"
        wait 2>/dev/null || true
        exec 9>&-
        fail_flow "$dir" "MAPPED never printed"
        finish_cell "$cell" "$dir" "flow=mapped-timeout" || return 1
        return 0
    fi
    log "$cell: provider mapped; waiting for an admission pass"
    passes_before=$(pass_count "$dir/observer.out")
    if ! wait_for_pass "$dir/observer.out" "$passes_before" 180; then
        log "$cell: no admission pass after mapping"
        kill_pidfile "$dir/gen.pid"
        kill_observer "$dir/observer.pid"
        wait 2>/dev/null || true
        exec 9>&-
        fail_flow "$dir" "no admission pass after mapping"
        finish_cell "$cell" "$dir" "flow=admit-timeout" || return 1
        return 0
    fi
    log "$cell: opening the setup gate"
    touch "$dir/setup_go"
    if ! wait_for_line "READY pid=" "$dir/gen.out" 120; then
        log "$cell: generator never became ready"
        kill_pidfile "$dir/gen.pid"
        kill_observer "$dir/observer.pid"
        wait 2>/dev/null || true
        exec 9>&-
        fail_flow "$dir" "generator never became ready"
        finish_cell "$cell" "$dir" "flow=ready-timeout" || return 1
        return 0
    fi
    log "$cell: setup done; waiting for a binding pass before GO"
    passes_before=$(pass_count "$dir/observer.out")
    if ! wait_for_pass "$dir/observer.out" "$passes_before" 180; then
        log "$cell: no binding pass after setup"
        kill_pidfile "$dir/gen.pid"
        kill_observer "$dir/observer.pid"
        wait 2>/dev/null || true
        exec 9>&-
        fail_flow "$dir" "no binding pass after setup"
        finish_cell "$cell" "$dir" "flow=bind-timeout" || return 1
        return 0
    fi
    log "$cell: opening GO"
    touch "$dir/go"
    log "$cell: generator running; waiting for DONE"
    if ! wait_for_line "DONE" "$dir/gen.out" $((DURATION + 240)); then
        log "$cell: DONE never printed"
        kill_pidfile "$dir/gen.pid"
        kill_observer "$dir/observer.pid"
        wait 2>/dev/null || true
        exec 9>&-
        fail_flow "$dir" "DONE never printed"
        finish_cell "$cell" "$dir" "flow=done-timeout" || return 1
        return 0
    fi
    log "$cell: DONE printed; waiting for the observer to stop"
    capture_bpf_evidence "$dir"
    obs_rc=0
    wait "$(cat "$dir/observer.pid")" || obs_rc=$?
    sample_load
    log "$cell: observer rc=$obs_rc"
    if [ "$obs_rc" -ne 0 ]; then
        kill_pidfile "$dir/gen.pid"
        wait 2>/dev/null || true
        exec 9>&-
        fail_flow "$dir" "observer rc=$obs_rc"
        finish_cell "$cell" "$dir" "flow=observer-rc" || return 1
        return 0
    fi
    if ! prove_hold "$dir" "$gen_pid" "$PROVIDER"; then
        log "$cell: target not held through drain"
        kill_pidfile "$dir/gen.pid"
        wait 2>/dev/null || true
        exec 9>&-
        fail_flow "$dir" "target not held through drain"
        finish_cell "$cell" "$dir" "flow=hold-broken" || return 1
        return 0
    fi
    touch "$dir/finish"
    gen_rc=0
    wait "$gen_pid" || gen_rc=$?
    exec 9>&-
    log "$cell: generator rc=$gen_rc"
    if [ "$gen_rc" -ne 0 ]; then
        fail_flow "$dir" "generator rc=$gen_rc"
        finish_cell "$cell" "$dir" "flow=generator-rc" || return 1
        return 0
    fi
    if ! take_evidence "$dir"; then
        fail_flow "$dir" "evidence chmod failed"
        finish_cell "$cell" "$dir" "flow=chmod" || return 1
        return 0
    fi
    run_oracle "$dir" joint
    finish_cell "$cell" "$dir" "flow=ok" || return 1
    CURRENT_DIR=""
    return 0
}

# The S1 twin: --pid digest, setup before attach, GO after pass 0.
run_twin_cell() {
    cell=s1-10k-twin
    dir=$OUTDIR/$cell
    rm -rf "$dir"
    mkdir -p "$dir"
    CURRENT_DIR=$dir
    LOAD_MAX=0
    LOAD_TRACE=""
    sample_load
    obs_dur=$((DURATION + OBS_MARGIN))
    log "$cell: spawning the digest generator (setup precedes attach)"
    SOFTHSM2_CONF="$SOFT_CONF" "$GEN" "$PROVIDER" single "$RATE" "$DURATION" \
        "$dir/hot.jsonl" "$dir/go" "$dir/finish" \
        > "$dir/gen.out" 2> "$dir/gen.err" &
    gen_pid=$!
    echo "$gen_pid" > "$dir/gen.pid"
    if ! wait_for_line "READY pid=" "$dir/gen.out" 120; then
        log "$cell: generator never became ready"
        kill_pidfile "$dir/gen.pid"
        wait 2>/dev/null || true
        fail_flow "$dir" "generator never became ready"
        finish_cell "$cell" "$dir" "flow=ready-timeout" || return 1
        return 0
    fi
    log "$cell: acquiring the privileged lock"
    exec 9>"$LOCK_FILE"
    flock 9
    log "$cell: lock held; starting the observer for ${obs_dur}s"
    # The lock fd is inherited; run sudo directly under the held lock.
    # Stdout stays unprivileged by design (the -o outputs are chmodded
    # after the run); shellcheck SC2024 does not apply.
    # shellcheck disable=SC2046,SC2086 # observer_env is empty or one assignment per line.
    sudo -n $(observer_env) "$P11SCOPE" inventory --pid "$gen_pid" --manifest "$MANIFEST" \
        --duration "$obs_dur" --json -o "$dir/report.json" \
        --event-log "$dir/events.jsonl" > "$dir/observer.out" 2>&1 &
    echo $! > "$dir/observer.pid"
    if ! wait_for_line "p11scope: pass 0:" "$dir/observer.out" 300; then
        log "$cell: pass 0 never published"
        kill_pidfile "$dir/gen.pid"
        kill_observer "$dir/observer.pid"
        wait 2>/dev/null || true
        exec 9>&-
        fail_flow "$dir" "pass 0 never published"
        finish_cell "$cell" "$dir" "flow=pass0-timeout" || return 1
        return 0
    fi
    log "$cell: pass 0 published; opening GO"
    sample_load
    touch "$dir/go"
    log "$cell: waiting for DONE"
    if ! wait_for_line "DONE" "$dir/gen.out" $((DURATION + 240)); then
        log "$cell: DONE never printed"
        kill_pidfile "$dir/gen.pid"
        kill_observer "$dir/observer.pid"
        wait 2>/dev/null || true
        exec 9>&-
        fail_flow "$dir" "DONE never printed"
        finish_cell "$cell" "$dir" "flow=done-timeout" || return 1
        return 0
    fi
    log "$cell: DONE printed; waiting for the observer to stop"
    capture_bpf_evidence "$dir"
    obs_rc=0
    wait "$(cat "$dir/observer.pid")" || obs_rc=$?
    sample_load
    log "$cell: observer rc=$obs_rc"
    if [ "$obs_rc" -ne 0 ]; then
        kill_pidfile "$dir/gen.pid"
        wait 2>/dev/null || true
        exec 9>&-
        fail_flow "$dir" "observer rc=$obs_rc"
        finish_cell "$cell" "$dir" "flow=observer-rc" || return 1
        return 0
    fi
    if ! prove_hold "$dir" "$gen_pid" "$PROVIDER"; then
        log "$cell: target not held through drain"
        kill_pidfile "$dir/gen.pid"
        wait 2>/dev/null || true
        exec 9>&-
        fail_flow "$dir" "target not held through drain"
        finish_cell "$cell" "$dir" "flow=hold-broken" || return 1
        return 0
    fi
    touch "$dir/finish"
    gen_rc=0
    wait "$gen_pid" || gen_rc=$?
    exec 9>&-
    log "$cell: generator rc=$gen_rc"
    if [ "$gen_rc" -ne 0 ]; then
        fail_flow "$dir" "generator rc=$gen_rc"
        finish_cell "$cell" "$dir" "flow=generator-rc" || return 1
        return 0
    fi
    if ! take_evidence "$dir"; then
        fail_flow "$dir" "evidence chmod failed"
        finish_cell "$cell" "$dir" "flow=chmod" || return 1
        return 0
    fi
    run_oracle "$dir" ""
    finish_cell "$cell" "$dir" "flow=ok" || return 1
    CURRENT_DIR=""
    return 0
}

# results.jsonl rows when a prerequisite is missing: the run exits
# 77, and the cells are nonqualifying (never judged), with the
# missing prerequisite in detail.
skip_all() {
    why=$1
    for cell in ${CELLS:-joint-10k-single joint-10k-churn s1-10k-twin}; do
        write_row "$cell" "false" "nonqualifying" \
            "host=$(hostname) prerequisite missing: $why"
    done
}

usage() {
    cat >&2 <<'USAGE'
usage: joint-throughput.sh P11SCOPE OUTDIR
  P11SCOPE  observer binary (p11scope-discover beside it)
  OUTDIR    fresh results directory
  env RATE (1k/2.5k/5k/6.25k/7.5k/10k/100k, default 10k), DURATION seconds (default 20),
      MIN_RATE calls/s (default 10000), CELLS subset, SOFTHSM_LIB
      override, OBS_MARGIN observer seconds beyond DURATION (default 90),
      SETTLEMENT_LAT=1 for the diagnostic settlement-latency line
USAGE
}

main() {
    if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
        usage
        return 0
    fi
    if [ "$#" -ne 2 ]; then
        usage
        return 2
    fi
    P11SCOPE=$1
    OUTDIR=$2
    RATE=${RATE:-10k}
    DURATION=${DURATION:-20}
    MIN_RATE=${MIN_RATE:-10000}
    OBS_MARGIN=${OBS_MARGIN:-90}
    CELLS=${CELLS:-joint-10k-single joint-10k-churn s1-10k-twin}
    if [ ! -x "$P11SCOPE" ]; then
        log "observer binary $P11SCOPE is not executable"
        return 2
    fi
    validate_params || return 2
    mkdir -p "$OUTDIR" || return 2
    RESULTS_JSONL=$OUTDIR/results.jsonl
    : > "$RESULTS_JSONL"
    if ! command -v gcc >/dev/null 2>&1; then
        log "gcc is required to build the throughput driver"
        skip_all "no gcc"
        return 77
    fi
    if ! command -v softhsm2-util >/dev/null 2>&1; then
        log "softhsm2-util is required for the SoftHSM token"
        skip_all "no softhsm2-util"
        return 77
    fi
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        log "kernel BTF is required for native capture"
        skip_all "no kernel BTF"
        return 77
    fi
    if ! sudo -n true 2>/dev/null; then
        log "passwordless sudo is required for the observer"
        skip_all "no passwordless sudo"
        return 77
    fi
    PROVIDER=$(select_provider)
    if [ -z "$PROVIDER" ] || [ ! -f "$PROVIDER" ]; then
        log "no SoftHSM provider found"
        skip_all "no SoftHSM provider"
        return 77
    fi
    log "provider: $PROVIDER"
    DISCOVER=$(dirname "$P11SCOPE")/p11scope-discover
    if [ ! -x "$DISCOVER" ]; then
        log "discover binary $DISCOVER is not executable"
        skip_all "no p11scope-discover"
        return 77
    fi
    GEN=$(build_emitter "$OUTDIR/bin") || return 2
    log "emitter: $GEN"
    mkdir -p "$OUTDIR/tokens"
    SOFT_CONF=$OUTDIR/softhsm2.conf
    printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
        "$OUTDIR/tokens" > "$SOFT_CONF"
    if ! SOFTHSM2_CONF="$SOFT_CONF" softhsm2-util --init-token --free \
        --label joint-tp --so-pin 5678 --pin 1234 >/dev/null 2>&1; then
        log "SoftHSM token init failed"
        skip_all "token init failed"
        return 77
    fi
    MANIFEST=$OUTDIR/manifest.json
    if ! "$DISCOVER" --module "$PROVIDER" -o "$MANIFEST" >/dev/null 2>&1; then
        log "manifest minting failed"
        skip_all "manifest minting failed"
        return 77
    fi
    trap 'cleanup_current; exit 130' INT
    trap 'cleanup_current; exit 143' TERM
    failed=0
    for cell in $CELLS; do
        case "$cell" in
            joint-10k-single) run_joint_cell "$cell" keyed ;;
            joint-10k-churn) run_joint_cell "$cell" keyed-churn ;;
            s1-10k-twin) run_twin_cell ;;
        esac || failed=1
        CURRENT_DIR=""
    done
    if [ "$failed" -ne 0 ]; then
        return 1
    fi
    return 0
}

if [ "${JOINT_TP_SOURCED:-}" != "1" ]; then
    main "$@"
fi

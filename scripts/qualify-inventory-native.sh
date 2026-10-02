#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# qualify-inventory-native.sh — installed `p11scope inventory` acceptance (Task 6 C8).
#
#   qualify-inventory-native.sh P11SCOPE [--lane scan|native] [--base DIR] [--no-dashboard]
#   qualify-inventory-native.sh --self-test
#
# Host runs need a ROOT-OWNED --base (not group/other-writable); the default
# /var/tmp/p11scope-ws-tmp/c8-root is created 0711 by root when missing, and an
# existing non-root-owned BASE is refused before anything is created in it:
#   sudo install -d -o root -g root -m 0711 /var/tmp/p11scope-ws-tmp/c8-root
#
# Runs the shipped binary exactly as an operator would, against the ledgered
# SoftHSM2 workload tests/fixtures/public-cli/inventory-ledger.c, and judges the
# result with the independent oracle scripts/inventory-native-oracle.py:
#   run "system"     inventory --system, classic loop, -o + --event-log, over the cells
#                    P1 (attested A, mechanisms), P2 (byte copy B, distinct inode),
#                    P3 (maps A and C, never calls), P4 (~100 ms CLIs), P5 (exec chain:
#                    same binary, other binary, non-leader thread), P7 (late dlopen),
#                    LX (leader pthread_exit, worker keeps calling)
#   run "dashboard"  inventory --system --dashboard under a pty, -o + --event-log, over
#                    the still-held, now idle cells (frames must agree with the documents)
#   run "stop"       inventory --pid on P6 (a call held in the held provider until the
#                    harness releases it), SIGINT while the call is held
# --lane names the lane the run must prove (default native). --no-dashboard is
# recorded in run.json as a skipped run, which makes the verdict non-qualifying.
#
# Exit codes are the oracle's: 0 qualified, 1 failed, 2 non-qualifying (no
# failure, but native assertions absent — every `--lane scan` plumbing run — or a
# skipped run); 64 usage; any other nonzero is a harness failure before judging.
#
# The observer runs as root; every workload runs as RUNUID:RUNGID (default
# 1000:1000) under setpriv --no-new-privs with a clean environment. Temp state
# lives in BASE (default /var/tmp/p11scope-ws-tmp/c8-root), which must be
# root-owned and not group/other-writable (created 0711 when missing): an
# observer dir (root 0700: evidence, ledgers, run.json) and a workload dir (root
# 0711: root-owned binaries and providers, gates, and one RUNUID-owned 0700 dir
# per cell for its SoftHSM2 token). A virtme-ng guest hides /var/tmp and /tmp:
# pass --base with a guest-local root-owned dir (e.g. a tmpfs mounted in the guest).
#
# Clock: the oracle compares ledger CLOCK_MONOTONIC times with p11scope's
# CLOCK_MONOTONIC capture clock, so workloads and observer must share one time
# namespace (host and vng guests do; a container lane must translate).
#
# Environment: RUNUID/RUNGID, MODULE (provider A), ITERS, DURATION (system run
# window, default 90 s), LATE_MS, STOP_WAIT_S, SYSTEM_ARGS (extra --system flags,
# e.g. "--max-scan-pids 4096"), P11SCOPE_DISCOVER.
#
# --self-test is unprivileged and hosted-CI safe: it compiles the fixture, runs
# every workload mode as the calling user against SoftHSM2 (each under a timeout),
# checks the ledgers' self-consistency, and runs the oracle's synthetic self-test.
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd) || exit 64
SRC=$REPO/tests/fixtures/public-cli/inventory-ledger.c
ORACLE=$REPO/scripts/inventory-native-oracle.py
MODULE=${MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}
ITERS=${ITERS:-4}
ROTATE_BYTES=1024M  # far above any run: the oracle fails a rotated stream

die() { echo "qualify-inventory-native: $*" >&2; exit 70; }
mono_ns() { python3 -I -c 'import time; print(time.monotonic_ns())'; }
count_kind() { python3 -I "$ORACLE" count-kind "$1" "$2"; }

# Positive controls: signal tests are meaningless where SIGHUP is ignored (nohup,
# some CI wrappers), and a background SIGINT must actually be deliverable once
# its inherited ignore is reset. Never run this script under nohup.
positive_controls() {
    local status
    { sh -c 'kill -HUP $$' >/dev/null 2>&1; } 2>/dev/null
    status=$?
    [ "$status" -eq 129 ] || die "positive control failed: sh -c 'kill -HUP \$\$' exited $status, want 129 (SIGHUP ignored here?)"
    env --default-signal=INT true 2>/dev/null || die "env --default-signal is unsupported (coreutils >= 8.31 needed)"
    env --default-signal=INT sh -c 'kill -INT $$' >/dev/null 2>&1 &
    wait "$!"
    status=$?
    [ "$status" -eq 130 ] || die "positive control failed: background SIGINT exited $status, want 130"
}

need_tools() {
    for tool in gcc softhsm2-util python3 timeout "$@"; do
        command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
    done
    [ -r "$MODULE" ] || die "SoftHSM2 provider not found: $MODULE (set MODULE=)"
}

# build_fixtures DIR: workload, a byte copy at a distinct inode (the exec chain's
# "other binary"), the held provider, and provider copies B and C (byte-identical
# to A, distinct inodes).
build_fixtures() {
    local dir=$1
    gcc -O1 -Wall -Wextra -Werror -o "$dir/ledger" "$SRC" -ldl -lpthread || die "fixture build failed"
    cp "$dir/ledger" "$dir/ledger2" || die "copy ledger2"
    gcc -O1 -Wall -Wextra -Werror -shared -fPIC -DINVENTORY_LEDGER_HELD_PROVIDER -o "$dir/held.so" "$SRC" \
        || die "held provider build failed"
    mkdir -p "$dir/copyB" "$dir/copyC" || die "mkdir provider copies"
    { cp "$MODULE" "$dir/copyB/libsofthsm2.so" && cp "$MODULE" "$dir/copyC/libsofthsm2.so"; } || die "copy providers"
    chmod 755 "$dir/ledger" "$dir/ledger2" "$dir/held.so" "$dir/copyB" "$dir/copyC"
}

write_conf() { # DIR: a SoftHSM2 config whose token store is DIR/tokens
    printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$1" > "$1/softhsm2.conf"
}

waitfor() { # FILE PATTERN TIMEOUT_S
    local _
    for _ in $(seq $(($3 * 10))); do
        grep -qa -- "$2" "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

wait_kind() { # JSONL KIND N TIMEOUT_S: the stream holds at least N events of KIND
    local _
    for _ in $(seq $(($4 * 4))); do
        [ "$(count_kind "$1" "$2")" -ge "$3" ] && return 0
        sleep 0.25
    done
    return 1
}

# bounded_wait PID TIMEOUT_S: reap PID, SIGKILLing it at the deadline; BW_RC = status.
bounded_wait() {
    local _
    for _ in $(seq $(($2 * 10))); do
        kill -0 "$1" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$1" 2>/dev/null; then
        echo "pid $1 outlived ${2}s; SIGKILL" >&2
        kill -KILL "$1" 2>/dev/null
    fi
    wait "$1"
    BW_RC=$?
}

release_held() { # FIFO: let a held call return; never blocks (no reader = nothing held)
    [ -p "$1" ] || return 0
    python3 -I -c 'import errno,os,sys
try:
    os.close(os.open(sys.argv[1], os.O_WRONLY | os.O_NONBLOCK))
except OSError as e:
    if e.errno != errno.ENXIO:
        raise' "$1"
}

# cell NAME ROLE MODE PROVIDERS(comma) ITERS HOLD [EXTRA_JSON]: one run.json cell entry.
cell() {
    python3 -I -c 'import json,sys
n,role,mode,prov,iters,hold,extra=sys.argv[1:8]
spec={"role":role,"mode":mode,"providers":prov.split(","),"iters":int(iters),"hold":hold=="1","ledger":"ledgers/%s.out"%n}
spec.update(json.loads(extra or "{}"))
print(json.dumps({n:spec}))' "$1" "$2" "$3" "$4" "$5" "$6" "${7:-}" >> "$CELLS"
}

# write_manifest OUTDIR LANE ATTESTED NOTE CELLS RUNS SKIPPED A B C HELD: run.json.
write_manifest() {
    python3 -I -c 'import hashlib,json,os,sys
out,lane,attested,note,cells,runs,skipped,a,b,c,held=sys.argv[1:12]
def prov(path,att,private):
    real=os.path.realpath(path)
    with open(real,"rb") as f:
        digest=hashlib.sha256(f.read()).hexdigest()
    return {"path":real,"ino":os.stat(real).st_ino,"sha256":digest,"attested":att,"private":private}
m={"manifest":"p11scope-c8-run/2","expect_lane":lane,"attested_delivery":attested=="1","attested_note":note,
   "providers":{"A":prov(a,True,False),"B":prov(b,False,True),"C":prov(c,False,True),"BLK":prov(held,False,True)},
   "cells":{},"runs":[],"skipped_runs":[s for s in skipped.split(",") if s]}
for line in open(cells):
    m["cells"].update(json.loads(line))
if os.path.exists(runs):
    m["runs"]=[json.loads(line) for line in open(runs)]
with open(os.path.join(out,"run.json"),"w") as f:
    json.dump(m,f,indent=1,sort_keys=True)' "$@"
}

# run_entry NAME CELLS JSON JSONL FRAMES RC STOP_JSON [SETTLE_PASSES]: one observer run record.
run_entry() {
    python3 -I -c 'import json,sys
n,cells,j,jl,fr,rc,stop,settle=sys.argv[1:9]
print(json.dumps({"name":n,"cells":cells.split(","),"json":j or None,"jsonl":jl or None,"frames":fr or None,
                  "rc":int(rc),"stop":json.loads(stop) if stop else None,
                  "settle_passes":int(settle) if settle else None}))' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "${8:-}" >> "$RUNS"
}

self_test() {
    need_tools
    timeout 300 python3 -I "$ORACLE" --self-test || die "oracle self-test failed"
    SELFTEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/c8-selftest.XXXXXX") || die "mktemp"
    SELFTEST_HELD=""
    trap 'release_held "$SELFTEST_TMP/release"; [ -z "$SELFTEST_HELD" ] || kill -KILL "$SELFTEST_HELD" 2>/dev/null; rm -rf "$SELFTEST_TMP"' EXIT
    local tmp
    tmp=$(realpath -e "$SELFTEST_TMP") || die "realpath"
    chmod 700 "$tmp"
    build_fixtures "$tmp"
    mkdir -m 700 "$tmp/tokens" || die "token dir"
    write_conf "$tmp"
    export SOFTHSM2_CONF=$tmp/softhsm2.conf
    softhsm2-util --init-token --free --label c8 --so-pin 5678 --pin 1234 >/dev/null || die "token init failed"
    mkdir -p "$tmp/ledgers"
    CELLS=$tmp/cells.jsonl RUNS=$tmp/runs.jsonl
    : > "$CELLS"
    local A=$MODULE B=$tmp/copyB/libsofthsm2.so C=$tmp/copyC/libsofthsm2.so L=$tmp/ledger
    local T=(timeout --kill-after=5 60)
    "${T[@]}" "$L" mech --cell P1 --module "$A" --iters 3 > "$tmp/ledgers/P1.out" || die "P1 failed"
    cell P1 P1 mech A 3 0
    "${T[@]}" "$L" mech --cell P2 --module "$B" --iters 2 > "$tmp/ledgers/P2.out" || die "P2 failed"
    cell P2 P2 mech B 2 0
    "${T[@]}" "$L" mech --cell PB --module "$A" --module "$B" --iters 1 > "$tmp/ledgers/PB.out" || die "PB failed"
    cell PB P2 mech A,B 1 0
    "${T[@]}" "$L" map --cell P3 --module "$A" --module "$C" > "$tmp/ledgers/P3.out" || die "P3 failed"
    cell P3 P3 map A,C 0 0
    for _ in 1 2; do
        "${T[@]}" "$L" mech --cell P4 --module "$A" --iters 2 --sleep-us 1000 >> "$tmp/ledgers/P4.out" || die "P4 failed"
    done
    cell P4 P4 mech A 2 0 '{"instances": 2}'
    "${T[@]}" "$L" exec-chain --cell P5 --module "$A" --iters 1 --delay-ms 120 \
        --chain "leader:$L,leader:$tmp/ledger2,thread:$L" > "$tmp/ledgers/P5.out" || die "P5 failed"
    cell P5 P5 exec-chain A 1 0 "{\"exe\": \"$L\", \"chain\": [\"leader:$L\", \"leader:$tmp/ledger2\", \"thread:$L\"]}"
    mkfifo "$tmp/release" || die "mkfifo"
    INVENTORY_LEDGER_RELEASE=$tmp/release "${T[@]}" "$L" held --cell P6 --module "$tmp/held.so" \
        > "$tmp/ledgers/P6.out" &
    SELFTEST_HELD=$!
    waitfor "$tmp/ledgers/P6.out" '^HELD ' 10 || die "P6 never entered its held call"
    sleep 0.3
    kill -TERM "$SELFTEST_HELD"  # a signal must not end the held call ...
    sleep 0.3
    kill -0 "$SELFTEST_HELD" 2>/dev/null || die "P6 held call ended on SIGTERM; it must hold until released"
    release_held "$tmp/release"  # ... only the release does
    bounded_wait "$SELFTEST_HELD" 10
    SELFTEST_HELD=""
    grep -q '^RETURNED ' "$tmp/ledgers/P6.out" || die "P6 did not return after release (rc=$BW_RC)"
    cell P6 P6 held BLK 0 0
    "${T[@]}" "$L" mech --late --cell P7 --module "$A" --iters 2 --delay-ms 50 > "$tmp/ledgers/P7.out" || die "P7 failed"
    cell P7 P7 mech A 2 0
    "${T[@]}" "$L" leader-exit --cell LX --module "$A" --iters 2 > "$tmp/ledgers/LX.out" || die "LX failed"
    cell LX LX leader-exit A 2 0
    write_manifest "$tmp" scan 0 "self-test: no observer" "$CELLS" "$RUNS" "" "$A" "$B" "$C" "$tmp/held.so"
    timeout 60 python3 -I "$ORACLE" ledgers "$tmp" || die "ledger self-consistency failed"
    echo "qualify-inventory-native: self-test passed"
}

if [ "${1:-}" = "--self-test" ]; then
    positive_controls
    self_test
    exit 0
fi

# ---------------------------------------------------------------------------
# Privileged qualification
# ---------------------------------------------------------------------------
[ $# -ge 1 ] || { sed -n '3,11p' "$0" >&2; exit 64; }
P=$(realpath -e "$1") || { echo "binary not found: $1" >&2; exit 64; }
shift
LANE=native BASE=/var/tmp/p11scope-ws-tmp/c8-root DASHBOARD=1
while [ $# -gt 0 ]; do
    case $1 in
        --lane) LANE=$2; shift 2 ;;
        --base) BASE=$2; shift 2 ;;
        --no-dashboard) DASHBOARD=0; shift ;;
        *) echo "unknown argument $1" >&2; exit 64 ;;
    esac
done
case $LANE in scan|native) ;; *) echo "--lane must be scan or native" >&2; exit 64 ;; esac
RUNUID=${RUNUID:-1000} RUNGID=${RUNGID:-1000}
DURATION=${DURATION:-90} LATE_MS=${LATE_MS:-2500} STOP_WAIT_S=${STOP_WAIT_S:-60}
read -r -a SYSTEM_EXTRA <<< "${SYSTEM_ARGS:-}"
positive_controls
[ "$(id -u)" = 0 ] || die "must run as root (the observer needs it; workloads drop to RUNUID)"
[ "$RUNUID" != 0 ] || die "RUNUID must not be root"
need_tools setpriv stat install
umask 077
if [ ! -e "$BASE" ]; then
    { mkdir -p "$(dirname "$BASE")" && mkdir -m 0711 "$BASE"; } || die "cannot create $BASE"
fi
BASE=$(realpath -e "$BASE") || die "realpath $BASE"
read -r base_uid base_mode <<< "$(stat -c '%u %a' "$BASE")"
[ "$base_uid" = 0 ] || die "--base $BASE must be root-owned (owner uid $base_uid); create one with: install -d -o root -g root -m 0711 DIR"
[ $((8#$base_mode & 8#022)) -eq 0 ] || die "BASE $BASE is group/other-writable (mode $base_mode)"
dir=$(dirname "$BASE")
while [ "$dir" != / ]; do
    read -r d_uid d_mode <<< "$(stat -c '%u %a' "$dir")"
    if [ "$d_uid" != 0 ] || { [ $((8#$d_mode & 8#022)) -ne 0 ] && [ $((8#$d_mode & 8#1000)) -eq 0 ]; }; then
        echo "WARNING: ancestor $dir (uid $d_uid mode $d_mode) is writable by a non-root user" >&2
    fi
    dir=$(dirname "$dir")
done
OBS=$(mktemp -d "$BASE/c8-obs.XXXXXX") || die "mktemp obs"
WL=$(mktemp -d "$BASE/c8-wl.XXXXXX") || die "mktemp workload"
{ chmod 0711 "$WL" && install -d -m 0755 "$WL/bin" && install -d -m 0711 "$WL/gates" "$WL/cells" "$OBS/ledgers"; } \
    || die "workload layout"
(umask 022; build_fixtures "$WL/bin") || die "fixture build"
L=$WL/bin/ledger A=$MODULE B=$WL/bin/copyB/libsofthsm2.so C=$WL/bin/copyC/libsofthsm2.so BLK=$WL/bin/held.so
RELEASE=$WL/gates/release GATE=$WL/gates/gate GATE6=$WL/gates/gate6
mkfifo -m 0644 "$RELEASE" || die "mkfifo"

# as_cell CELL: AS = the argv prefix running a command as RUNUID for CELL. Never
# background a shell function: `f &` forks a subshell, so $! names that subshell
# and a signal sent to it never reaches the real process.
as_cell() {
    AS=(setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups --no-new-privs
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C
        SOFTHSM2_CONF="$WL/cells/$1/softhsm2.conf" INVENTORY_LEDGER_RELEASE="$RELEASE")
}
# setup_cell CELL: the cell's own RUNUID-owned 0700 dir and SoftHSM2 token.
setup_cell() {
    install -d -o "$RUNUID" -g "$RUNGID" -m 0700 "$WL/cells/$1" || die "cell dir $1"
    { write_conf "$WL/cells/$1" && chmod 0644 "$WL/cells/$1/softhsm2.conf"; } || die "conf $1"
    as_cell "$1"
    # shellcheck disable=SC2016  # $1 expands in the RUNUID shell, by design
    "${AS[@]}" sh -c 'mkdir -m 700 "$1" && softhsm2-util --init-token --free --label c8 --so-pin 5678 --pin 1234 >/dev/null' \
        _ "$WL/cells/$1/tokens" || die "token init for $1 as RUNUID $RUNUID failed (is $BASE traversable?)"
}
for c in P1 P2 P3 P4 P5 P6 P7 LX discover; do setup_cell "$c"; done
CELLS=$OBS/cells.jsonl RUNS=$OBS/runs.jsonl
: > "$CELLS"; : > "$RUNS"
echo "observer=$OBS workload=$WL lane=$LANE binary=$P"

WORKLOADS=() OBSERVERS=()
# Every exit path (including die) releases the held call and reaps what this
# run started: TERM, a grace period, then KILL. No cell may outlive the run.
cleanup() {
    local pid _
    release_held "$RELEASE"
    for pid in "${OBSERVERS[@]}" "${WORKLOADS[@]}"; do kill -TERM "$pid" 2>/dev/null; done
    for _ in $(seq 30); do  # 3 s grace, then KILL
        local alive=0
        for pid in "${OBSERVERS[@]}" "${WORKLOADS[@]}"; do kill -0 "$pid" 2>/dev/null && alive=1; done
        [ "$alive" = 0 ] && break
        sleep 0.1
    done
    for pid in "${OBSERVERS[@]}" "${WORKLOADS[@]}"; do kill -KILL "$pid" 2>/dev/null; done
    for pid in "${OBSERVERS[@]}" "${WORKLOADS[@]}"; do wait "$pid" 2>/dev/null; done
    OBSERVERS=() WORKLOADS=()
}
trap cleanup EXIT
launch() { # CELL ARGS...: a workload as RUNUID; stdout = its ledger; $! is the workload itself
    local name=$1; shift
    as_cell "$name"
    "${AS[@]}" "$L" "$@" >> "$OBS/ledgers/$name.out" 2>> "$OBS/ledgers/$name.err" &
    WORKLOADS+=("$!")
}
# Background jobs of a non-interactive shell inherit SIGINT/SIGQUIT as ignored;
# reset them so a SIGINT reaches the observer exactly as it would from a terminal.
OBSERVER=(env --default-signal=INT --default-signal=QUIT "$P")
EVENTS=(--event-rotate-bytes "$ROTATE_BYTES")

# Lane probe: what the binary under test can be asked for.
timeout 30 "$P" --help > "$OBS/help.txt" 2>&1 || echo "WARNING: $P --help exited nonzero" >&2
probe_capture=0 probe_manifest=0
while IFS='=' read -r key value; do
    case $key in capture) probe_capture=$value ;; manifest) probe_manifest=$value ;; esac
done < <(python3 -I "$ORACLE" probe-help < "$OBS/help.txt")
CAPTURE_ARGS=() MANIFEST_ARGS=() ATTESTED=0 NOTE="inventory has no --manifest flag (Task 6 C6)"
[ "$probe_capture" = 1 ] && CAPTURE_ARGS=(--capture "$LANE")
if [ "$probe_manifest" = 1 ]; then
    DISCOVER=${P11SCOPE_DISCOVER:-$(dirname "$P")/p11scope-discover}
    as_cell discover
    if [ -x "$DISCOVER" ] && timeout --kill-after=5 120 "${AS[@]}" "$DISCOVER" --module "$A" \
            -o "$WL/cells/discover/manifest-A.json" > "$OBS/discover.log" 2>&1; then
        cp "$WL/cells/discover/manifest-A.json" "$OBS/manifest-A.json" \
            && MANIFEST_ARGS=(--manifest "$OBS/manifest-A.json") && ATTESTED=1
    else
        NOTE="p11scope-discover unavailable or failed ($DISCOVER); see discover.log"
    fi
fi
echo "probe: capture_args=${CAPTURE_ARGS[*]:-none} manifest=${MANIFEST_ARGS[*]:-none}"

# ---- run "system" ----
"${OBSERVER[@]}" inventory --system --duration "$DURATION" -o "$OBS/system.json" --event-log "$OBS/system.jsonl" \
    "${EVENTS[@]}" "${SYSTEM_EXTRA[@]}" "${CAPTURE_ARGS[@]}" "${MANIFEST_ARGS[@]}" \
    > "$OBS/system.stdout" 2> "$OBS/system.stderr" &
SYS=$!
OBSERVERS+=("$SYS")
wait_kind "$OBS/system.jsonl" pass 1 120 || die "system observer never committed a pass (see $OBS/system.stderr)"
launch P1 mech --cell P1 --module "$A" --iters "$ITERS" --gate "$GATE" --hold
launch P2 mech --cell P2 --module "$B" --iters "$ITERS" --gate "$GATE" --hold
launch P3 map --cell P3 --module "$A" --module "$C" --gate "$GATE" --hold
launch P7 mech --late --cell P7 --module "$A" --iters "$ITERS" --gate "$GATE" --delay-ms "$LATE_MS" --hold
launch LX leader-exit --cell LX --module "$A" --iters "$ITERS" --gate "$GATE"
launch P5 exec-chain --cell P5 --module "$A" --iters 1 --gate "$GATE" --delay-ms 300 \
    --chain "leader:$L,leader:$WL/bin/ledger2,thread:$L"
for c in P1 P2 P3 P7 LX P5; do waitfor "$OBS/ledgers/$c.out" '^READY ' 30 || die "$c never became ready"; done
# Two more passes: the native lane admits and attaches the new mappings first.
base=$(count_kind "$OBS/system.jsonl" pass); wait_kind "$OBS/system.jsonl" pass $((base + 2)) 60 || die "observer stalled"
touch "$GATE"
as_cell P4
for i in 1 2 3; do  # P4: ~100 ms CLIs, ungated, while capture runs
    timeout --kill-after=5 60 "${AS[@]}" "$L" mech --cell P4 --module "$A" --iters 2 --sleep-us 10000 \
        >> "$OBS/ledgers/P4.out" 2>> "$OBS/ledgers/P4.err" || echo "P4 instance $i failed" >&2
    sleep 1
done
for c in P1 P2 P3 P7 LX P5; do waitfor "$OBS/ledgers/$c.out" '^DONE .*gen=0' 60 || echo "$c: no DONE" >&2; done
waitfor "$OBS/ledgers/P5.out" '^DONE .*gen=3' 60 || echo "P5: chain incomplete" >&2
# Exits and the late dlopen must be seen by a pass that STARTED after them:
# the oracle requires two commits after this point (WINDOW-SETTLED).
settled_at=$(count_kind "$OBS/system.jsonl" pass)
bounded_wait "$SYS" $((DURATION + 120)); SYS_RC=$BW_RC; OBSERVERS=()
SETTLE=$(( $(count_kind "$OBS/system.jsonl" pass) - settled_at ))
run_entry system P1,P2,P3,P4,P5,P7,LX system.json system.jsonl "" "$SYS_RC" "" "$SETTLE"
cell P1 P1 mech A "$ITERS" 1
cell P2 P2 mech B "$ITERS" 1
cell P3 P3 map A,C 0 1
cell P4 P4 mech A 2 0 '{"instances": 3}'
cell P5 P5 exec-chain A 1 0 "{\"exe\": \"$L\", \"chain\": [\"leader:$L\", \"leader:$WL/bin/ledger2\", \"thread:$L\"]}"
cell P7 P7 mech A "$ITERS" 1
cell LX LX leader-exit A "$ITERS" 0

# ---- run "dashboard" (held cells P1 P2 P3 P7 are alive and idle) ----
SKIPPED=""
if [ "$DASHBOARD" = 1 ]; then
    # --module narrows discovery to the cell providers, so every cell edge fits the
    # frame; the run is still --system scope.
    python3 -I "$ORACLE" record-pty "$OBS/dashboard.pty" 120 250 90 0 -- "$P" inventory --system --dashboard \
        --module "$A" --module "$B" --module "$C" "${SYSTEM_EXTRA[@]}" --duration 15 -o "$OBS/dashboard.json" \
        --event-log "$OBS/dashboard.jsonl" "${EVENTS[@]}" "${CAPTURE_ARGS[@]}" "${MANIFEST_ARGS[@]}" \
        > "$OBS/dashboard.rc" 2>&1
    DASH_RC=$(sed -n 's/^rc=//p' "$OBS/dashboard.rc")
    run_entry dashboard P1,P2,P3,P7 dashboard.json dashboard.jsonl dashboard.pty "${DASH_RC:-255}" ""
else
    SKIPPED=dashboard
fi

# ---- run "stop": a call held until released, SIGINT mid-capture ----
launch P6 held --cell P6 --module "$BLK" --gate "$GATE6"
P6=${WORKLOADS[-1]}
waitfor "$OBS/ledgers/P6.out" '^READY ' 30 || die "P6 never became ready"
P6PID=$(sed -n 's/^READY .* pid=\([0-9]*\) .*/\1/p' "$OBS/ledgers/P6.out" | head -1)
"${OBSERVER[@]}" inventory --pid "$P6PID" --duration 600 -o "$OBS/stop.json" --event-log "$OBS/stop.jsonl" \
    "${EVENTS[@]}" "${CAPTURE_ARGS[@]}" > "$OBS/stop.stdout" 2> "$OBS/stop.stderr" &
STOP=$!
OBSERVERS+=("$STOP")
wait_kind "$OBS/stop.jsonl" pass 2 120 || echo "stop observer slow to start" >&2
touch "$GATE6"
waitfor "$OBS/ledgers/P6.out" '^HELD ' 30 || echo "P6 never entered its held call" >&2
base=$(count_kind "$OBS/stop.jsonl" pass); wait_kind "$OBS/stop.jsonl" pass $((base + 2)) 60 || true
SENT=$(mono_ns)
kill -INT "$STOP"
bounded_wait "$STOP" "$STOP_WAIT_S"; STOP_RC=$BW_RC; OBSERVERS=()
EXITED=$(mono_ns)
release_held "$RELEASE"  # only now may the held call return (RETURNED t > SENT)
waitfor "$OBS/ledgers/P6.out" '^RETURNED ' 10 || echo "P6 did not return after release" >&2
bounded_wait "$P6" 10
STOP_JSON=""
[ -s "$OBS/stop.json" ] && STOP_JSON=stop.json
run_entry stop P6 "$STOP_JSON" stop.jsonl "" "$STOP_RC" \
    "{\"signal\": \"INT\", \"sent_ns\": $SENT, \"exited_ns\": $EXITED}"
cell P6 P6 held BLK 0 1

# ---- judge ----
cleanup
write_manifest "$OBS" "$LANE" "$ATTESTED" "$NOTE" "$CELLS" "$RUNS" "$SKIPPED" "$A" "$B" "$C" "$BLK"
timeout 300 python3 -I "$ORACLE" check "$OBS" | tee "$OBS/oracle.txt"
rc=${PIPESTATUS[0]}
echo "evidence: $OBS (workload state: $WL)"
exit "$rc"

#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# bench-inventory-native.sh — native inventory scale cells (Task 6 C5.5: M1, M3, M4).
#
#   bench-inventory-native.sh P11SCOPE --capture native|scan|auto --total N --callers C
#       [--mappers M] [--churn R] [--provider-share PCT] [--duration S] [--samples K]
#       [--cap N] [--cpus LIST] [--max-load1 X] [--cooldown S] [--base DIR] [--label TEXT]
#   bench-inventory-native.sh --self-test
#
# One invocation is one run of one cell: a fresh population of N processes in
# its own PID and mount namespace (unshare --pid --fork --mount, then a fresh
# /proc: the C1b population spawner's shape, so the host's own providers never compete and
# the kernel reaps everything with the namespace), then K observer samples
# back to back over it: sample 1 is cold (first observer over a fresh
# population), the rest warm. Global host caches are never dropped. The
# controller interleaves invocations (candidate, baseline or control) and
# collects at least five cold and five warm samples per cell.
#
# Population: C SoftHSM2 callers (tests/fixtures/public-cli/gated.c: Initialize,
# OpenSession, Login, then idle with the provider mapped), M `sleep`s that
# LD_PRELOAD the provider (mapped, never call), and idle `sleep`s up to N, all
# as RUNUID:RUNGID under setpriv --no-new-privs with a clean environment.
# Churn: --churn R runs scripts/fixtures/exec_churn.c during every sample:
# R fork+execs per second, PCT percent (default 10) of them a sub-second
# provider caller (`gated MODULE 1 0 -`), the rest /bin/true. Its per-pid
# ledger (EXEC/EXIT lines, one SUMMARY) is the independent record for false
# joins and the proof the rate was reached.
#
# Observer: `P11SCOPE_STAGE_TIMINGS=1 p11scope inventory --system --capture
# MODE --max-scan-pids CAP --duration S -o inventory.json`, run as root and
# pinned with taskset (default CPUs 10,11 when the host has 12 or more). A
# sampler records its RSS, RSS high-water mark and descriptor count every
# second. A binary without --capture can only be measured as --capture scan
# (recorded as capture_flag=absent); native and auto refuse.
#
# Host-load discipline (task6-c5-plan.md §2). The run holds the shared lock
# /var/tmp/p11scope-ws-tmp/privileged.lock: either an ancestor already holds it
# (`flock LOCK bench-inventory-native.sh ...`) or the script re-executes itself
# under flock(1), and /proc/locks must show an ancestor holding it before
# anything starts (lock.txt). It waits
# up to --cooldown seconds (default 300) for load1 <= --max-load1 (default 4)
# before the population is built, and again before every sample (the build
# and the previous sample's observer and churn heat the host); a host that
# stays hotter writes an invalid run.json and observes nothing further. Load
# and cargo/rustc activity are recorded at run and sample start and end
# (load.txt). Never run a Cargo build during a campaign, and never run this
# under nohup: the SIGHUP positive control refuses.
#
# Output: RUN=BASE/bench-native.XXXXXX (root 0700) with run.json, lock.txt,
# load.txt, population.txt and sample-N-cold|warm/{stderr,stdout,
# inventory.json,resources.tsv,load.txt,rc,churn.ledger}. The verdict is
# scripts/bench-inventory-native-stats.py check RUN (exit 0 valid, 1 invalid);
# summary over many RUNs gives the per-cell distributions. Invalid and failed
# runs are kept with their reasons. Exit codes: 0 valid, 1 invalid samples,
# 3 refused before observing (load or lock), 64 usage, 70 harness failure.
#
# BASE (default /var/tmp/p11scope-ws-tmp/bench-native-root) must be root-owned
# and not group/other-writable (created 0711 when missing). Ten-thousand-process
# cells run inside a transient systemd scope (TasksMax=16384) when systemd runs.
# The native lane inside the population's PID namespace depends on the C5
# ruling D1 (binding by pidfd cookies); a refusal there is an observer failure,
# recorded, never retried silently.
#
# --self-test is unprivileged: it compiles both fixtures, checks exec_churn's
# rate, share, reaping, usage refusal and exec-failure count, checks the
# lock-holder proof against real flocks (held by nobody, an ancestor, the
# process itself, another process), the SIGHUP control, runs
# the analysis script's self-test, and proves a run assembled by this
# script's own record_load/write_meta/lock record passes `stats check`.
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd) || exit 64
SELF=$REPO/scripts/$(basename "$0")
GATED_SRC=$REPO/tests/fixtures/public-cli/gated.c
CHURN_SRC=$REPO/scripts/fixtures/exec_churn.c
STATS=$REPO/scripts/bench-inventory-native-stats.py
MODULE=${MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}
RUNUID=${RUNUID:-1000} RUNGID=${RUNGID:-1000}
LOCK=${LOCK:-/var/tmp/p11scope-ws-tmp/privileged.lock}

die() { echo "bench-inventory-native: $*" >&2; exit 70; }

sighup_control() {
    local status
    { sh -c 'kill -HUP $$' >/dev/null 2>&1; } 2>/dev/null
    status=$?
    [ "$status" -eq 129 ] || die "positive control failed: sh -c 'kill -HUP \$\$' exited $status, want 129 (SIGHUP ignored here? never run under nohup)"
}

# Cargo/rustc processes on the host. Inside the population namespace /proc
# is the namespace's own, so the inner reads the host's through HOSTPROC.
build_processes() {
    cat "${HOSTPROC:-/proc}"/[0-9]*/comm 2>/dev/null | grep -cxE 'cargo|rustc'
}

# host_hot MAX: true when the 1-minute host load exceeds MAX.
host_hot() {
    awk -v max="$1" '{exit !($1 > max)}' /proc/loadavg
}

# record_load FILE PHASE: one load record (start or end).
record_load() {
    local loadavg
    loadavg=$(cat /proc/loadavg)
    {
        echo "uptime_$2=$(uptime)"
        echo "loadavg_$2=$loadavg"
        echo "load1_$2=${loadavg%% *}"
        echo "build_processes_$2=$(build_processes)"
        echo "at_$2=$(date --iso-8601=ns)"
    } >> "$1"
}

# write_lock_record FILE: the lock proof `stats check` reads: the lock path,
# the holder the /proc/locks scan attributed ($held), and the verification
# stamp. Shared by the outer run and the self-test handoff below.
write_lock_record() {
    { echo "lock=$LOCK"; echo "${held% *}"; echo "${held#* }"; echo "verified_in_proc_locks=1"
      echo "verified_at=$(date --iso-8601=ns)"; } > "$1"
}

# lock_holder LOCKFILE PID: "holder_pid=X relation=self|ancestor|other|none"
# for the FLOCK WRITE lock /proc/locks shows on LOCKFILE, judged from PID.
lock_holder() {
    python3 -I - "$1" "$2" <<'EOF'
import os, sys
path, me = sys.argv[1], int(sys.argv[2])
# By inode alone: /proc/locks prints the superblock device, which differs
# from st_dev on btrfs subvolumes. The holder must still be this process or
# an ancestor to count, so a same-inode lock elsewhere cannot pass.
inode = str(os.stat(path).st_ino)
holders = []
for line in open("/proc/locks"):
    fields = line.split()
    if "->" in fields:
        continue  # a blocked waiter, not a holder
    if (len(fields) >= 6 and fields[1] == "FLOCK" and fields[3] == "WRITE"
            and fields[5].rsplit(":", 1)[-1] == inode):
        holders.append(int(fields[4]))
chain, pid = [], me
while pid > 1:
    chain.append(pid)
    try:
        status = open(f"/proc/{pid}/status").read()
    except OSError:
        break
    pid = int(next(l.split()[1] for l in status.splitlines() if l.startswith("PPid:")))
if not holders:
    print("holder_pid= relation=none")
else:
    ancestors = [pid for pid in holders if pid in chain]
    holder = me if me in holders else ancestors[0] if ancestors else holders[0]
    relation = "self" if holder == me else "ancestor" if ancestors else "other"
    print(f"holder_pid={holder} relation={relation}")
EOF
}

# Defined early: the outer run and the self-test handoff below both call it.
write_meta() { # STATUS [REASON]
    python3 -I - "$RUN/run.json" "$1" "${2:-}" "$LABEL" "$P" "$(sha256sum "$P" | cut -d' ' -f1)" \
        "$CAPTURE" "$CAPFLAG" "$TOTAL" "$CALLERS" "$MAPPERS" "$CHURN" "$SHARE" "$DURATION" \
        "$SAMPLES" "$CAP" "$CPUS" "$MAX_LOAD1" "$MODULE" "$(uname -r)" "$(uname -n)" <<'EOF'
import json, sys
(path, status, reason, label, binary, digest, capture, capflag, total, callers, mappers,
 churn, share, duration, samples, cap, cpus, max_load1, module, kernel, host) = sys.argv[1:]
json.dump({
    "status": status, "reason": reason, "label": label,
    "binary": binary, "binary_sha256": digest, "capture": capture, "capture_flag": capflag,
    "processes": int(total), "callers": int(callers), "mappers": int(mappers),
    "churn_rate": int(churn), "churn_scope": "sample", "provider_share_pct": int(share),
    "duration_s": int(duration), "samples": int(samples), "max_scan_pids": int(cap),
    "observer_cpus": cpus, "max_load1": float(max_load1), "module": module,
    "kernel": kernel, "host": host,
}, open(path, "w"), indent=2)
EOF
}

# ---- inner: the population and its samples, pid 1 of the namespace ----
if [ "${1:-}" = --inner ]; then
    shift
    RUN=$1 WL=$2 P=$3 CAPTURE=$4 CALLERS=$5 IDLE=$6 MAPPERS=$7 CAP=$8 DURATION=$9
    CHURN=${10} SHARE=${11} SAMPLES=${12} CPUS=${13} CAPFLAG=${14}
    MAX_LOAD1=${15} COOLDOWN=${16}
    mount --make-rprivate / || die "make-rprivate"
    # Keep the host's /proc visible (for build activity in load records),
    # then mount this namespace's own. Both mounts die with the namespace.
    HOSTPROC=$WL/hostproc
    mount --bind /proc "$HOSTPROC" || die "bind host /proc"
    mount -t proc proc /proc || die "mount namespace /proc"
    AS=(setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups --no-new-privs
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C SOFTHSM2_CONF="$WL/token/softhsm2.conf")
    READY=$RUN/population.ready
    : > "$READY"
    for ((i = 0; i < CALLERS; i++)); do
        "${AS[@]}" "$WL/bin/gated" "$MODULE" 0 0 "$WL/gate" >> "$READY" 2>> "$RUN/callers.err" &
        sleep 0.01
    done
    for ((i = 0; i < MAPPERS; i++)); do "${AS[@]}" LD_PRELOAD="$MODULE" sleep 100000 & done
    for ((i = MAPPERS; i < IDLE; i++)); do "${AS[@]}" sleep 100000 & done
    for t in $(seq 3000); do
        [ "$(grep -c '^READY' "$READY")" -ge "$CALLERS" ] && break
        [ $((t % 100)) -eq 0 ] && echo "$(grep -c '^READY' "$READY") of $CALLERS callers ready after $((t / 10)) s" >&2
        sleep 0.1
    done
    ready=$(grep -c '^READY' "$READY")
    # SoftHSM2 setup on one shared token occasionally never finishes for one
    # caller under load (C1b): tolerate at most 1%, recorded.
    [ $((ready * 100)) -ge $((CALLERS * 99)) ] || die "only $ready of $CALLERS callers became ready"
    # Every launched process must have reached its final image first.
    for _ in $(seq 600); do
        cat /proc/[0-9]*/comm 2>/dev/null | grep -qxE 'setpriv|env' || break
        sleep 0.1
    done
    pids=(/proc/[0-9]*)
    { echo "processes=${#pids[@]}"; echo "callers_ready=$ready"; echo "callers=$CALLERS"
      echo "mappers=$MAPPERS"; } > "$RUN/population.txt"
    PIN=()
    [ -n "$CPUS" ] && PIN=(taskset -c "$CPUS")
    CAPTURE_ARGS=()
    [ "$CAPFLAG" = present ] && CAPTURE_ARGS=(--capture "$CAPTURE")
    for ((n = 1; n <= SAMPLES; n++)); do
        kind=warm
        [ "$n" = 1 ] && kind=cold
        S=$RUN/sample-$n-$kind
        install -d -m 0700 "$S" || die "sample dir"
        # Per-sample cooldown: the population build and the previous
        # sample's observer and churn heat the host, so a sample started
        # hot would only be refused by the stats check. Exit 3, like the
        # outer cooldown: refused before observing, not a harness failure.
        waited=0
        while host_hot "$MAX_LOAD1"; do
            if [ "$waited" -ge "$COOLDOWN" ]; then
                record_load "$S/load.txt" start
                echo "$n $(cut -d' ' -f1 /proc/loadavg)" > "$RUN/cooldown-refused-sample"
                exit 3
            fi
            sleep 5
            waited=$((waited + 5))
        done
        record_load "$S/load.txt" start
        churn_pid=""
        if [ "$CHURN" -gt 0 ]; then
            ledger=$WL/ledgers/churn-$n.ledger
            "${AS[@]}" "$WL/bin/exec_churn" "$CHURN" 0 "$SHARE" "$ledger" \
                -- "$WL/bin/gated" "$MODULE" 1 0 - > /dev/null 2> "$S/churn.err" &
            churn_pid=$!
        fi
        start_ms=$(($(date +%s%N) / 1000000))
        env --default-signal=INT P11SCOPE_STAGE_TIMINGS=1 "${PIN[@]}" "$P" inventory --system \
            "${CAPTURE_ARGS[@]}" --max-scan-pids "$CAP" --duration "$DURATION" \
            -o "$S/inventory.json" > "$S/stdout" 2> "$S/stderr" &
        observer=$!
        echo "# ms rss_kb hwm_kb fds" > "$S/resources.tsv"
        while kill -0 "$observer" 2>/dev/null; do
            rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$observer/status" 2>/dev/null)
            hwm=$(awk '/^VmHWM:/ {print $2}' "/proc/$observer/status" 2>/dev/null)
            fds=$(find "/proc/$observer/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
            # A zombie or exiting observer has no RSS: not a sample.
            [ -n "$rss" ] && [ -n "$hwm" ] \
                && echo "$(($(date +%s%N) / 1000000 - start_ms)) $rss $hwm $fds" >> "$S/resources.tsv"
            sleep 1
        done
        wait "$observer"
        echo "$?" > "$S/rc"
        if [ -n "$churn_pid" ]; then
            kill -TERM "$churn_pid" 2>/dev/null
            wait "$churn_pid"
            echo "exec_churn rc=$?" >> "$S/churn.err"
            cp "$ledger" "$S/churn.ledger" 2>> "$S/churn.err"
        fi
        record_load "$S/load.txt" end
    done
    exit 0  # pid 1 exits: the kernel reaps every process of the namespace
fi

# ---- self-test (unprivileged) ----
if [ "${1:-}" = --self-test ]; then
    sighup_control
    T=$(mktemp -d "${TMPDIR:-/var/tmp}/bench-native-selftest.XXXXXX") || die "mktemp"
    trap 'rm -rf "$T"' EXIT
    gcc -O1 -Wall -Wextra -Werror -o "$T/exec_churn" "$CHURN_SRC" || die "exec_churn does not compile"
    gcc -O1 -Wall -Wextra -Werror -o "$T/gated" "$GATED_SRC" -ldl || die "gated does not compile"
    # Rate is load-sensitive: below the floor, retry once after a pause
    # (a transient spike); above the ceiling fails fast (a bug, not load).
    # Bounds are unchanged; the final failure names the host load.
    attempt=0
    while :; do
        "$T/exec_churn" 200 1 20 "$T/churn.ledger" -- /bin/sh -c 'exit 0' || die "exec_churn failed"
        summary=$(grep '^SUMMARY ' "$T/churn.ledger") || die "exec_churn wrote no SUMMARY"
        read -r execs provider failed rate < <(echo "$summary" | tr ' ' '\n' | awk -F= '
            $1 == "execs" {e = $2} $1 == "provider" {p = $2} $1 == "exec_fail" {f = $2}
            $1 == "achieved_rate" {r = $2} END {print e, p, f, r}')
        [ "$execs" -le 201 ] || die "exec_churn issued $execs execs, want ~200"
        if [ "$execs" -ge 180 ] && awk -v r="$rate" 'BEGIN {exit !(r >= 180)}'; then
            break
        fi
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 2 ]; then
            die "exec_churn issued $execs execs at $rate/s, want ~200/s (load: $(cut -d' ' -f1-3 /proc/loadavg))"
        fi
        sleep 2
    done
    [ "$provider" = $((execs * 20 / 100)) ] || die "exec_churn provider share $provider of $execs, want 20%"
    [ "$failed" = 0 ] || die "exec_churn reported $failed failed execs"
    [ "$(grep -c '^EXEC ' "$T/churn.ledger")" = "$execs" ] || die "EXEC lines disagree with SUMMARY"
    [ "$(grep -c '^EXIT ' "$T/churn.ledger")" = "$execs" ] || die "not every churn child was reaped"
    "$T/exec_churn" 100 1 50 "$T/x" 2>/dev/null
    [ $? -eq 2 ] || die "exec_churn accepted a provider share without a CALLER"
    "$T/exec_churn" 100 1 0 "$T/fail.ledger" -- /nonexistent || die "exec_churn (no share) failed"
    "$T/exec_churn" 50 1 100 "$T/fail.ledger" -- /nonexistent/caller || die "exec_churn failed"
    grep -q '^SUMMARY .* exec_fail=[1-9]' "$T/fail.ledger" || die "a failed exec was not counted"
    echo "exec_churn: rate, share, reaping, usage and exec failure ok ($summary)"
    : > "$T/lock"
    out=$(lock_holder "$T/lock" $$)
    [ "${out#* }" = relation=none ] || die "unlocked file reported as held: $out"
    # flock(1) holds the lock in its own process and runs the command as its
    # child: exactly the controller's `flock LOCK bench-inventory-native.sh`.
    out=$(flock "$T/lock" bash -c "$(declare -f lock_holder); lock_holder '$T/lock' \$\$")
    [ "${out#* }" = relation=ancestor ] || die "an ancestor's lock not recognised: $out"
    out=$(python3 -I -c 'import fcntl, os, subprocess, sys
f = open(sys.argv[1], "a"); fcntl.flock(f, fcntl.LOCK_EX)
sys.stdout.write(subprocess.run(["bash", "-c", sys.argv[2] + "; lock_holder \"$0\" \"$1\"",
    sys.argv[1], str(os.getpid())], capture_output=True, text=True).stdout)' \
        "$T/lock" "$(declare -f lock_holder)")
    [ "${out#* }" = relation=self ] || die "own lock not recognised: $out"
    flock "$T/lock" sleep 2 &
    holder=$!
    sleep 0.5
    out=$(lock_holder "$T/lock" $$)
    [ "${out#* }" = relation=other ] || die "a foreign holder not recognised: $out"
    wait "$holder"
    echo "lock-holder proof: none, self, ancestor and other ok"
    python3 -I "$STATS" --self-test || die "analysis self-test failed"
    # Bash -> stats handoff: a run assembled by this script's own
    # record_load/write_meta/write_lock_record must pass `stats check`.
    # Bounds are stats' own business (covered by its self-test), so the
    # check runs with a wide load bound and pinned build counts: what is
    # proven here is that the record FORMAT is accepted. The stderr spans
    # name the real inventory spans stats requires by default; if either
    # side drifts, this fails loudly.
    H=$T/handoff
    install -d -m 0700 "$H/run/sample-1-cold" "$H/run/sample-2-warm" || die "handoff dirs"
    : > "$H/hlock"
    held=$(flock "$H/hlock" bash -c "$(declare -f lock_holder); lock_holder '$H/hlock' \$\$")
    [ "${held#* }" = relation=ancestor ] || die "handoff lock not held: $held"
    LOCK_SAVED=$LOCK
    LOCK=$H/hlock
    RUN=$H/run
    write_lock_record "$RUN/lock.txt"
    LOCK=$LOCK_SAVED
    LABEL=handoff P11SCOPE_BIN=/bin/true
    P=$P11SCOPE_BIN CAPTURE=native CAPFLAG=present TOTAL=448 CALLERS=300 MAPPERS=0
    CHURN=0 SHARE=10 DURATION=60 SAMPLES=2 CAP=256 CPUS="" MAX_LOAD1=4 LABEL=$LABEL
    write_meta complete
    record_load "$RUN/load.txt" start
    record_load "$RUN/load.txt" end
    sed -i 's/^build_processes_start=.*/build_processes_start=0/' "$RUN/load.txt"
    for sample in "$RUN/sample-1-cold" "$RUN/sample-2-warm"; do
        record_load "$sample/load.txt" start
        record_load "$sample/load.txt" end
        sed -i 's/^build_processes_start=.*/build_processes_start=0/' "$sample/load.txt"
        echo "0" > "$sample/rc"
        for index in 1 2 3 4; do
            echo "p11scope: pass $index: stage timings: sweep 12.000ms, deep_scan 3.000ms, assemble 1.000ms, confirm 1.000ms, absorb 1.000ms, reconcile 1.000ms, project 1.000ms"
        done > "$sample/stderr"
        printf '# ms rss_kb hwm_kb fds\n0 1000 1000 12\n1000 1200 1200 14\n2000 1100 1200 14\n' > "$sample/resources.tsv"
        python3 -I - "$sample/inventory.json" <<'EOF' || die "handoff inventory.json"
import json, sys
json.dump({"observation": {"lane": "native", "native_witnesses": {
    "rows": 4, "bound": 3, "unbound": 1, "pending": 0, "integrity": 0,
    "unbound_reasons": {"lifecycle_loss": 1}}}}, open(sys.argv[1], "w"))
EOF
    done
    out=$(python3 -I "$STATS" --max-load1 1000 check "$RUN") \
        || die "stats refused the handoff run: $out"
    case $out in *VALID*) ;; *) die "handoff run not valid: $out" ;; esac
    echo "bash->stats handoff: record_load/write_meta/lock record accepted"
    echo "bench-inventory-native: self-test ok"
    exit 0
fi

# ---- outer ----
[ $# -ge 1 ] || { sed -n '5,8p' "$0" >&2; exit 64; }
ORIG_ARGS=("$@")
P=$(realpath -e "$1") || die "binary $1"; shift
CAPTURE="" TOTAL="" CALLERS="" MAPPERS=0 CHURN=0 SHARE=10 DURATION=60 SAMPLES=2 CAP=256
CPUS="" MAX_LOAD1=4 COOLDOWN=300 BASE=/var/tmp/p11scope-ws-tmp/bench-native-root LABEL=""
[ "$(nproc)" -ge 12 ] && CPUS=10,11
while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || { echo "$1 needs a value" >&2; exit 64; }
    case $1 in
        --capture) CAPTURE=$2 ;;
        --total) TOTAL=$2 ;;
        --callers) CALLERS=$2 ;;
        --mappers) MAPPERS=$2 ;;
        --churn) CHURN=$2 ;;
        --provider-share) SHARE=$2 ;;
        --duration) DURATION=$2 ;;
        --samples) SAMPLES=$2 ;;
        --cap) CAP=$2 ;;
        --cpus) CPUS=$2 ;;
        --max-load1) MAX_LOAD1=$2 ;;
        --cooldown) COOLDOWN=$2 ;;
        --base) BASE=$2 ;;
        --label) LABEL=$2 ;;
        *) echo "unknown argument $1" >&2; exit 64 ;;
    esac
    shift 2
done
case $CAPTURE in native|scan|auto) ;; *) echo "--capture native|scan|auto is required" >&2; exit 64 ;; esac
for value in "$TOTAL" "$CALLERS" "$MAPPERS" "$CHURN" "$SHARE" "$DURATION" "$SAMPLES" "$CAP" "$COOLDOWN"; do
    case $value in ''|*[!0-9]*) echo "--total and --callers are required; numeric options take integers" >&2; exit 64 ;; esac
done
[ $((CALLERS + MAPPERS + 2)) -le "$TOTAL" ] || { echo "--callers + --mappers + 2 must fit in --total" >&2; exit 64; }
[ "$SAMPLES" -ge 1 ] && [ "$SHARE" -le 100 ] || { echo "--samples >= 1 and --provider-share <= 100" >&2; exit 64; }

[ "$(id -u)" = 0 ] || die "must run as root"
[ "$RUNUID" != 0 ] || die "RUNUID must not be root"
for tool in gcc softhsm2-util python3 setpriv unshare flock taskset; do
    command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
done
flock --help 2>&1 | grep -q -- '--conflict-exit-code' \
    || die "flock without --conflict-exit-code (util-linux >= 2.30 needed)"
[ -r "$MODULE" ] || die "SoftHSM2 provider not found: $MODULE"
sighup_control
env --default-signal=INT true 2>/dev/null || die "env --default-signal is unsupported (coreutils >= 8.31 needed)"

# The shared lock: an ancestor holds it (`flock LOCK bench-inventory-native.sh
# ...`), or this script re-executes itself under flock(1) once, which makes
# flock that ancestor. /proc/locks names the locking process, so a lock
# taken by a short-lived `flock FD` helper could not be attributed.
[ -e "$LOCK" ] || { install -d -m 0700 "$(dirname "$LOCK")" && : >> "$LOCK"; } || die "cannot create $LOCK"
held=$(lock_holder "$LOCK" $$)
if [ "${held#* }" != relation=ancestor ]; then
    [ -z "${BENCH_NATIVE_RELOCKED:-}" ] || die "lock not held after locking: $held"
    echo "waiting for $LOCK ($held)" >&2
    # -E 3: a lock timeout refuses (exit 3), like a hot host. Without it
    # flock exits 1, clashing with "invalid samples" from the stats check.
    BENCH_NATIVE_RELOCKED=1 exec flock -o -w 3600 -E 3 "$LOCK" "$SELF" "${ORIG_ARGS[@]}"
fi

umask 077
[ -e "$BASE" ] || { mkdir -p "$(dirname "$BASE")" && mkdir -m 0711 "$BASE"; } || die "cannot create $BASE"
BASE=$(realpath -e "$BASE") || die "realpath $BASE"
read -r base_uid base_mode <<< "$(stat -c '%u %a' "$BASE")"
[ "$base_uid" = 0 ] || die "--base $BASE must be root-owned (owner uid $base_uid)"
[ $((8#$base_mode & 8#022)) -eq 0 ] || die "BASE $BASE is group/other-writable (mode $base_mode)"
RUN=$(mktemp -d "$BASE/bench-native.XXXXXX") || die "mktemp run"
WL=$(mktemp -d "$BASE/bench-native-wl.XXXXXX") || die "mktemp workload"
chmod 0711 "$WL" || die "chmod workload"
# The workload dir is scratch: remove it on every exit, success or die().
# RUN stays behind in all cases (invalid and failed runs keep their reasons).
trap 'rm -rf "$WL"' EXIT
write_lock_record "$RUN/lock.txt"

CAPFLAG=absent
timeout 30 "$P" --help > "$RUN/help.txt" 2>&1
grep -q -- '--capture' "$RUN/help.txt" && CAPFLAG=present
[ "$CAPFLAG" = present ] || [ "$CAPTURE" = scan ] || die "$P has no --capture flag: only --capture scan can be measured"

# Cooldown: never start an observation on a hot host.
waited=0
while host_hot "$MAX_LOAD1"; do
    if [ "$waited" -ge "$COOLDOWN" ]; then
        record_load "$RUN/load.txt" start
        write_meta invalid "load1 $(cut -d' ' -f1 /proc/loadavg) above $MAX_LOAD1 after ${COOLDOWN}s cooldown"
        echo "REFUSED $RUN: load1 above $MAX_LOAD1 after ${COOLDOWN}s" >&2
        exit 3
    fi
    sleep 5
    waited=$((waited + 5))
done

(
    umask 022
    install -d -m 0755 "$WL/bin" \
        && gcc -O1 -Wall -Wextra -Werror -o "$WL/bin/gated" "$GATED_SRC" -ldl \
        && gcc -O1 -Wall -Wextra -Werror -o "$WL/bin/exec_churn" "$CHURN_SRC" \
        && : > "$WL/gate"
) || die "fixture build"
install -d -o "$RUNUID" -g "$RUNGID" -m 0700 "$WL/token" "$WL/ledgers" || die "token dir"
install -d -m 0755 "$WL/hostproc" || die "host /proc mountpoint"
{ printf 'directories.tokendir = %s/token/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$WL" \
    > "$WL/token/softhsm2.conf" && chmod 0644 "$WL/token/softhsm2.conf"; } || die "token conf"
# shellcheck disable=SC2016  # $1 expands in the RUNUID shell, by design
setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups --no-new-privs \
    env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C SOFTHSM2_CONF="$WL/token/softhsm2.conf" \
    sh -c 'mkdir -m 700 "$1" && softhsm2-util --init-token --free --label bench --so-pin 5678 --pin 1234 >/dev/null' \
    _ "$WL/token/tokens" || die "token init as $RUNUID failed (is $BASE traversable?)"

SCOPE=()
[ -d /run/systemd/system ] && command -v systemd-run >/dev/null 2>&1 \
    && SCOPE=(systemd-run --scope --quiet --collect --slice=system.slice -p TasksMax=16384)
write_meta running
record_load "$RUN/load.txt" start
echo "run=$RUN binary=$P capture=$CAPTURE total=$TOTAL callers=$CALLERS churn=$CHURN/s load: $(uptime)"
# The namespace holds the workload, the inner shell, and the observer.
"${SCOPE[@]}" unshare --pid --fork --mount --propagation private \
    "$SELF" --inner "$RUN" "$WL" "$P" "$CAPTURE" "$CALLERS" $((TOTAL - CALLERS - 2)) "$MAPPERS" \
    "$CAP" "$DURATION" "$CHURN" "$SHARE" "$SAMPLES" "$CPUS" "$CAPFLAG" \
    "$MAX_LOAD1" "$COOLDOWN" \
    2> "$RUN/inner.err" < /dev/null
inner=$?
record_load "$RUN/load.txt" end
if [ "$inner" = 0 ]; then
    write_meta complete
elif [ "$inner" = 3 ] && [ -f "$RUN/cooldown-refused-sample" ]; then
    read -r refused_sample refused_load < "$RUN/cooldown-refused-sample"
    write_meta invalid "load1 $refused_load above $MAX_LOAD1 before sample $refused_sample after ${COOLDOWN}s cooldown"
else
    write_meta failed "namespace exited $inner"
fi
echo "run=$RUN namespace exited $inner, load: $(uptime)"
python3 -I "$STATS" --max-load1 "$MAX_LOAD1" check "$RUN"

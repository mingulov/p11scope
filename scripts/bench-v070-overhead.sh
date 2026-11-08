#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# bench-v070-overhead.sh — today's real per-call overhead and maximum rates.
#
# Owner questions (2026-11-08): "what's the overall overhead?" and "do some
# kind of benchmark to get the real current maximum". The only published
# numbers (docs/usage.md "Overhead (measured)") are from v0.1.0; this
# script re-measures on the current build. One script plus one results doc
# (docs/notes/2026-11-08-overhead-v070.md); raw logs stay out of git.
#
# Parts (PARTS env, default "percall ramp ceiling"):
#   percall  per-call overhead, ns/call, median + min..max over RUNS
#            interleaved rounds: unobserved, profile metrics/profile,
#            trace, inventory --pid, inventory --system, inventory --pid
#            with --key-operations; workloads: C_GenerateRandom hammer
#            (1M calls) + C_Sign HMAC hammer (heavier call).
#   ramp     maximum sustainable rate per mode: paced 2k/10k/50k/100k
#            calls/s plus unthrottled mt_count threads 1..N; exact vs
#            loss/gaps + observer CPU per cell.
#   ceiling  p11scope's own ceiling on a null provider (two distinct
#            files) + SoftHSM2, multi-process multi-threaded, unthrottled:
#            total calls/s unobserved vs observed, per-dimension exactness
#            (function, provider, caller, CKR), observer/kernel CPU.
#   spy      p11perftest cross-check incl. pkcs11-spy shim comparison
#            (needs P11PERFTEST; see below).
#
# Method follows scripts/bench-overhead.sh: interleaved rounds, go-file
# synchronization, attach gate on the observer's "capturing:" line, and
# equal-coverage validation — a sample whose report counts differ from
# the workload's own totals is INVALID (excluded, counted, fails the
# run for percall; recorded for ramp/ceiling where loss is the finding).
# Inventory samples additionally hold the workload alive (P11SCOPE_HOLD)
# through observer stop, wait for a committed "pass N:" line plus ADMIT_S
# settle before releasing the burst, and hold POST_PID_S/POST_SYS_S after
# the burst for the binding pass: a caller that is not admitted sheds
# its rows by design (use_before_admission), rows bind only on pass
# boundaries, and stopping before pass 0 discards the collection.
#
# Observer CPU is sampled from /proc/<observer>/stat (utime+stime) at the
# measured window edges, so attach cost is excluded; VmHWM is recorded at
# window end. For --system cells ambient PKCS#11 use is reported
# separately; the cell validates only its own caller's edge.
#
# Requirements: caller builds the observer first (no cargo here, so this
# script never competes with the build locks during measurement):
#   P11SCOPE   path to the release p11scope binary (required)
#   DISCOVER   path to p11scope-discover (required)
#   MODULE     SoftHSM2 path (default: probed across distros)
#   P11PERFTEST path to p11perftest (spy part only)
#   RUNS=5 N_CALLS=1000000 WARMUP_CALLS=1000 N_SIGN=200000 WARMUP_SIGN=200
#   CONDITIONS="unobserved metrics profile trace inv-pid inv-system inv-pid-keys"
#   ADMIT_S=2 (settle after the first committed pass) ATTACH_TIMEOUT_S=60
#   PASS_TIMEOUT_S=180 POST_PID_S=3 POST_SYS_S=20 (post-burst binding hold)
#   Spy part: P11PERFTEST (required), P11_LD_PATH (its LD_LIBRARY_PATH),
#   SPY_SO (default probed), SPY_COV="rand ecdsa rsa aes", SPY_VEC=64,
#   SPY_ITERS="rand:30000 ecdsa:3000 rsa:400 aes:15000",
#   SPY_THREADS_BASE="1 2 4" (+nproc), TOOL_N=50,
#   SPY_CONDITIONS="plain inv-pid metrics trace spy-file spy-null tool"
#   PARTS="percall ramp ceiling" THREADS="1 2 4 8" RAMP_SECS=10
#   CEIL_SECS=10 CEIL_THREADS="1 2 4" (plus nproc when larger)
#   LOCK=/var/tmp/p11scope-ws-tmp/privileged.lock (must be held by an
#   ancestor; the script refuses otherwise, like bench-count-overhead.sh)
# Run privileged parts as a user with passwordless sudo.
set -eu
cd "$(dirname "$0")/.."
. scripts/lib.sh

RUNS=${RUNS:-5}
N_CALLS=${N_CALLS:-1000000}
WARMUP_CALLS=${WARMUP_CALLS:-1000}
N_SIGN=${N_SIGN:-200000}
WARMUP_SIGN=${WARMUP_SIGN:-200}
ADMIT_S=${ADMIT_S:-2}
PASS_TIMEOUT_S=${PASS_TIMEOUT_S:-180}
POST_PID_S=${POST_PID_S:-3}
POST_SYS_S=${POST_SYS_S:-20}
ATTACH_TIMEOUT_S=${ATTACH_TIMEOUT_S:-60}
WARMUP_TIMEOUT_S=${WARMUP_TIMEOUT_S:-30}
PARTS=${PARTS:-"percall ramp ceiling"}
CONDITIONS=${CONDITIONS:-"unobserved metrics profile trace inv-pid inv-system inv-pid-keys"}
want_cond() {
    echo " $CONDITIONS " | grep -q " $1 "
}
SPY_CONDITIONS=${SPY_CONDITIONS:-"plain inv-pid metrics trace spy-file spy-null tool"}
want_spy() {
    echo " $SPY_CONDITIONS " | grep -q " $1 "
}
SPY_THREADS_BASE=${SPY_THREADS_BASE:-"1 2 4"}
SPY_COV=${SPY_COV:-"rand ecdsa rsa aes"}
SPY_ITERS=${SPY_ITERS:-"rand:30000 ecdsa:3000 rsa:400 aes:15000"}
SPY_VEC=${SPY_VEC:-64}
P11_LD_PATH=${P11_LD_PATH:-}
probe_spy() {
    for cand in "/usr/lib/x86_64-linux-gnu/pkcs11/pkcs11-spy.so" \
            "/usr/lib64/pkcs11/pkcs11-spy.so"; do
        if [ -f "$cand" ]; then echo "$cand"; return 0; fi
    done
    return 1
}
SPY_SO=${SPY_SO:-$(probe_spy)}
THREADS=${THREADS:-"1 2 4 8"}
RAMP_SECS=${RAMP_SECS:-10}
TRACE_SECS=${TRACE_SECS:-5}
BPF_STATS=${BPF_STATS:-0}
CEIL_SECS=${CEIL_SECS:-10}
CEIL_THREADS=${CEIL_THREADS:-"1 2 4"}
LOCK=${LOCK:-/var/tmp/p11scope-ws-tmp/privileged.lock}
ATTACH_MARKER="p11scope: capturing: "
WORK=
FIX=scripts/fixtures
WPID=
SPID=
CLK_TCK=$(getconf CLK_TCK)

probe_module() {
    for cand in "/usr/lib/softhsm/libsofthsm2.so" \
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so" \
            "/usr/lib64/pkcs11/libsofthsm2.so"; do
        if [ -f "$cand" ]; then echo "$cand"; return 0; fi
    done
    return 1
}
MODULE=${MODULE:-$(probe_module)}

usage() { echo "usage: PARTS='percall ramp ceiling spy' P11SCOPE=... DISCOVER=... $0 [--self-test]" >&2; }

# --- wait helpers (same gates as bench-overhead.sh) ---
observer_attach_count() {
    sed -n "s/.*p11scope: capturing: \([0-9][0-9]*\) probe.*/\1/p" "$1" 2>/dev/null | tail -n 1
}
wait_for_observer_attach() {
    wfoa_end=$(( $(date +%s) + $2 ))
    while :; do
        if grep -Fq "$ATTACH_MARKER" "$1" 2>/dev/null; then
            wfoa_count=$(observer_attach_count "$1")
            case $wfoa_count in ''|*[!0-9]*)
                echo "unparseable attach count in $1" >&2; return 1 ;;
            esac
            if [ "$wfoa_count" -le 0 ]; then
                echo "observer attached 0 probes: $1" >&2; return 1
            fi
            return 0
        fi
        if [ -n "${SPID-}" ] && ! kill -0 "$SPID" 2>/dev/null; then
            echo "observer exited before attach completed: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        fi
        [ "$(date +%s)" -lt "$wfoa_end" ] || {
            echo "observer never reported attach completion within $2s: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        }
        sleep 0.05
    done
}
wait_for_workload_file() {
    wfwd_end=$(( $(date +%s) + $3 ))
    while [ ! -f "$1" ]; do
        if ! kill -0 "$2" 2>/dev/null; then
            echo "workload $2 died waiting for $4 ($1)" >&2; return 1
        fi
        [ "$(date +%s)" -lt "$wfwd_end" ] || {
            echo "timed out waiting for $4 ($1)" >&2; return 1
        }
        sleep 0.05
    done
    return 0
}
wait_for_trace_warmup() {
    wftw_end=$(( $(date +%s) + $3 ))
    wftw_pat=${4:-C_GenerateRandom}
    while :; do
        wftw_seen=$(grep -c "$wftw_pat" "$1" 2>/dev/null || true)
        case $wftw_seen in ''|*[!0-9]*) wftw_seen=0 ;; esac
        [ "$wftw_seen" -ge "$2" ] && return 0
        if [ -n "${SPID-}" ] && ! kill -0 "$SPID" 2>/dev/null; then
            echo "observer exited with only $wftw_seen/$2 warm-up lines: $1" >&2; return 1
        fi
        if [ -n "${WPID-}" ] && ! kill -0 "$WPID" 2>/dev/null; then
            echo "workload exited with only $wftw_seen/$2 warm-up lines: $1" >&2; return 1
        fi
        [ "$(date +%s)" -lt "$wftw_end" ] || {
            echo "only $wftw_seen/$2 warm-up lines within $3s: $1" >&2; return 1
        }
        sleep 0.05
    done
}
# wait_for_log_line <log> <pattern> <timeout_s>: for workloads that stop
# themselves (P11SCOPE_HOLD): completion is the "OK" line, since `wait`
# would block on the stopped process.
wait_for_log_line() {
    wfll_end=$(( $(date +%s) + $3 ))
    while ! grep -Fq "$2" "$1" 2>/dev/null; do
        if [ -n "${WPID-}" ] && ! kill -0 "$WPID" 2>/dev/null; then
            echo "workload $WPID died before '$2' landed in $1" >&2; return 1
        fi
        [ "$(date +%s)" -lt "$wfll_end" ] || {
            echo "timed out waiting for '$2' in $1" >&2; return 1
        }
        sleep 0.05
    done
    return 0
}

# --- observer CPU sampling ---
# find_observer_pid: $SPID is sudo's PID; the observer is its child.
find_observer_pid() {
    for cand in $(pgrep -P "$SPID" 2>/dev/null); do
        if [ "$(cat /proc/$cand/comm 2>/dev/null)" = "p11scope" ]; then
            echo "$cand"; return 0
        fi
    done
    return 1
}
# sample_ticks <pid>: prints "utime stime" (clock ticks) from /proc/stat.
sample_ticks() {
    awk '{print $14, $15}' /proc/$1/stat 2>/dev/null
}
# rss_hwm_kb <pid>: VmHWM in KiB, 0 when unreadable.
rss_hwm_kb() {
    awk '/^VmHWM:/{print $2}' /proc/$1/status 2>/dev/null || echo 0
}

# An ancestor must hold the privileged lock (same check as
# bench-count-overhead.sh): a concurrent privileged test or capture would
# charge these samples. Run under `flock "$LOCK" $0`.
lock_held_by_ancestor() {
python3 -I - "$LOCK" "$$" <<'EOF'
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
}
SELF_TEST=0
if [ "${1-}" = "--self-test" ]; then
    [ "$#" -eq 1 ] || { usage; exit 2; }
    SELF_TEST=1
fi
[ "$#" -eq 0 ] || { [ "$SELF_TEST" = 1 ] || { usage; exit 2; }; }

# All privileged setup (binaries, lock, work dir, fixtures, token,
# manifests) runs inside setup_work so --self-test can execute after
# every function definition without it.
setup_work() {
[ -n "${P11SCOPE-}" ] || { echo "P11SCOPE is required (build the release observer first)" >&2; exit 2; }
[ -x "$P11SCOPE" ] || { echo "P11SCOPE not executable: $P11SCOPE" >&2; exit 2; }
[ -n "${DISCOVER-}" ] || { echo "DISCOVER is required" >&2; exit 2; }
[ -x "$DISCOVER" ] || { echo "DISCOVER not executable: $DISCOVER" >&2; exit 2; }
[ -n "$MODULE" ] || { echo "SoftHSM2 not found (set MODULE)" >&2; exit 2; }
lock_held_by_ancestor || {
    echo "refusing: no ancestor holds $LOCK (wrap in flock; see header)" >&2; exit 2
}
# Another live capture's probes would charge these samples. Scan-only
# (`--capture scan`) attaches nothing and is allowed.
if sudo -n bpftool prog show 2>/dev/null | grep -q "p11_"; then
    echo "refusing: p11_* BPF programs are already loaded" >&2; exit 2
fi
live_observers=$(pgrep -x -a p11scope 2>/dev/null | grep -v -- "--capture scan" || true)
if [ -n "$live_observers" ]; then
    echo "refusing: a live p11scope capture is already running:" >&2
    echo "$live_observers" >&2
    exit 2
fi
if echo " $PARTS " | grep -q " spy "; then
    [ -n "${P11PERFTEST-}" ] || { echo "P11PERFTEST is required for the spy part" >&2; exit 2; }
    [ -x "$P11PERFTEST" ] || { echo "P11PERFTEST not executable: $P11PERFTEST" >&2; exit 2; }
    [ -n "$SPY_SO" ] || { echo "pkcs11-spy.so not found (set SPY_SO)" >&2; exit 2; }
    command -v pkcs11-tool >/dev/null || { echo "pkcs11-tool required for the spy part" >&2; exit 2; }
    command -v p11tool >/dev/null || { echo "p11tool required for the spy part" >&2; exit 2; }
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-v070bench-XXXXXX")
echo "work: $WORK"
RESULTS="$WORK/results.tsv"
printf 'part\tworkload\tmodule\tcondition\tround\tn_calls\twall_ns\tns_per_call\tobs_cpu_ticks\tobs_cpu_s\tobs_rss_kb\texact\tevent_loss\tcompleteness\tnotes\n' > "$RESULTS"

cleanup() {
    status=$?
    trap - EXIT INT TERM
    [ -z "$WPID" ] || kill "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || kill "$SPID" 2>/dev/null || true
    for cp in ${CEIL_PIDS-}; do kill "$cp" 2>/dev/null || true; done
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    if [ "${BPF_DIRTY-0}" = 1 ]; then
        sudo -n sysctl -w kernel.bpf_stats_enabled="${BPF_PREV-0}" >/dev/null 2>&1 || true
    fi
    exit "$status"
}
. scripts/cleanup-traps.sh

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
command -v pgrep >/dev/null || { echo "pgrep required"; exit 1; }

echo "=== fixtures ==="
gcc -O0 -o "$WORK/hammer" "$FIX/hammer.c" -ldl
gcc -O2 -o "$WORK/sign_hammer" "$FIX/sign_hammer.c" -ldl
gcc -O2 -pthread -o "$WORK/mt_count" "$FIX/mt_count.c" -ldl -pthread
gcc -shared -fPIC -O2 -DNULL_TAG_STR='"A"' -o "$WORK/nullA.so" "$FIX/null_provider.c"
gcc -shared -fPIC -O2 -DNULL_TAG_STR='"B"' -o "$WORK/nullB.so" "$FIX/null_provider.c"

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
softhsm2-util --init-token --free --label v070bench --so-pin 1234 --pin 1234 >/dev/null

echo "=== discover ==="
"$DISCOVER" --module "$MODULE" -o "$WORK/manifest-soft.json" >/dev/null
"$DISCOVER" --module "$WORK/nullA.so" -o "$WORK/manifest-nullA.json" >/dev/null
"$DISCOVER" --module "$WORK/nullB.so" -o "$WORK/manifest-nullB.json" >/dev/null

echo "=== machine ==="
KERNEL=$(uname -r)
CPU=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')
NPROC=$(nproc)
MEMKB=$(awk '/MemTotal/{print $2}' /proc/meminfo)
echo "kernel: $KERNEL"
echo "cpu: $CPU"
echo "vcpus: $NPROC mem_kb: $MEMKB"
echo "mitigations: $(grep -h . /sys/devices/system/cpu/vulnerabilities/* 2>/dev/null | sort | uniq -c | head -20 | tr '\n' ';')"
{
    echo "kernel=$KERNEL"; echo "cpu=$CPU"; echo "vcpus=$NPROC"; echo "mem_kb=$MEMKB"
    echo "observer=$P11SCOPE"; "$P11SCOPE" --version 2>&1 | head -1
    echo "date=$(date -u +%FT%TZ)"
} > "$WORK/host.txt"
cat "$WORK/host.txt"

write_validate_py
}

# --- validation: same fail-closed contract as lane-bench-overhead-oracle-3:
# exit 0 exact, 10 well-formed but mismatched (INVALID), 1 malformed ---
write_validate_py() {
cat > "$WORK/validate.py" <<'PYEOF'
import json, os, re, sys

VALID, INVALID, ERROR = 0, 10, 1

def fail(m):
    print(f"v070bench validate: {m}", file=sys.stderr)
    return ERROR

def cmd_profcheck(path, spec, expect_errors):
    try:
        with open(path, encoding="utf-8") as h: rep = json.load(h)
    except FileNotFoundError: return fail(f"missing profile report: {path}")
    except (OSError, ValueError) as e: return fail(f"unreadable profile report {path}: {e}")
    if not isinstance(rep, dict): return fail("profile report is not an object")
    want = {}
    for item in spec.split(","):
        name, eq, num = item.partition("=")
        if not eq or not num.isdigit(): return fail(f"bad spec item: {item!r}")
        want[name] = int(num)
    got = {}
    errors = 0
    rv_other = 0
    for row in rep.get("functions", []):
        for name in row.get("names", []):
            got[name] = got.get(name, 0) + (row.get("calls", 0) or 0)
        errors += row.get("errors", 0) or 0
        for rv, cnt in (row.get("rv_counts", {}) or {}).items():
            if int(rv, 16) != 0: rv_other += cnt
    ev = rep.get("evidence", {}) or {}
    print(f"event_loss={ev.get('event_loss', '?')} completeness={ev.get('completeness', '?')} "
          f"verdict={ev.get('verdict_detail', '?')} errors={errors} rv_other={rv_other}")
    for name, calls in want.items():
        if got.get(name) != calls:
            print(f"INVALID: {name}: observed {got.get(name)} != expected {calls}", file=sys.stderr)
            return INVALID
    try: ee = int(expect_errors)
    except ValueError: return fail(f"bad expect_errors: {expect_errors!r}")
    if errors != ee:
        print(f"INVALID: errors {errors} != expected {ee}", file=sys.stderr)
        return INVALID
    if rv_other != 0:
        print(f"INVALID: {rv_other} non-OK returns observed", file=sys.stderr)
        return INVALID
    return VALID

def cmd_tracecheck(path, expected):
    try:
        with open(path, encoding="utf-8", errors="replace") as h: text = h.read()
    except OSError as e: return fail(f"unreadable trace {path}: {e}")
    m = re.search(r"COUNT_EVIDENCE[^\n]*?\"raw_calls\"\s*[:=]\s*(\d+)", text)
    if not m: return fail("trace has no COUNT_EVIDENCE raw_calls")
    raw = int(m.group(1))
    lost = len(re.findall(r"\bLOST\b", text))
    ev_loss, compl = "?", "?"
    em = re.search(r"^EVIDENCE (\{.*\})$", text, re.M)
    if em:
        try:
            ev = json.loads(em.group(1))
            ev_loss = ev.get("event_loss", "?")
            compl = ev.get("completeness", "?")
        except ValueError:
            pass
    print(f"raw_calls={raw} lost_markers={lost} event_loss={ev_loss} completeness={compl}")
    if raw != int(expected):
        print(f"INVALID: raw_calls {raw} != expected {expected}", file=sys.stderr)
        return INVALID
    return VALID

def cmd_invcheck(path, pid, module_path, expected):
    try:
        with open(path, encoding="utf-8") as h: rep = json.load(h)
    except FileNotFoundError: return fail(f"missing inventory report: {path}")
    except (OSError, ValueError) as e: return fail(f"unreadable inventory report {path}: {e}")
    if not isinstance(rep, dict): return fail("inventory report is not an object")
    caller_ids = {c.get("id") for c in rep.get("callers", []) if str(c.get("pid")) == str(pid)}
    # Match the module by bytes (sha256), not path or (dev, ino): the
    # probed path may be a symlink of the canonical report path, and on
    # Btrfs the report's mountinfo device differs from stat's st_dev.
    import hashlib
    try:
        with open(module_path, "rb") as h: want_sha = hashlib.sha256(h.read()).hexdigest()
    except OSError as e: return fail(f"cannot hash module {module_path}: {e}")
    module_ids = {m.get("id") for m in rep.get("modules", [])
                  if (m.get("identity", {}) or {}).get("sha256") == want_sha}
    edge = None
    for e in rep.get("edges", []):
        if e.get("caller") in caller_ids and e.get("module") in module_ids:
            edge = e
            break
    if edge is None: return fail(f"no edge for pid {pid} module {module_path}")
    entries = edge.get("entries", {}) or {}
    cov = entries.get("coverage", {}) or {}
    unbound = 0
    for m in rep.get("modules", []):
        if m.get("id") in module_ids:
            uu = m.get("unbound_use") or {}
            unbound += uu.get("entries", 0) or 0
    ambient_edges, ambient_calls = 0, 0
    for e in rep.get("edges", []):
        if e.get("caller") not in caller_ids:
            n = ((e.get("entries", {}) or {}).get("count", 0)) or 0
            if n > 0:
                ambient_edges += 1
                ambient_calls += n
    gaps = rep.get("gaps", []) or []
    print(f"edge_count={entries.get('count')} state={cov.get('state')} lossy={cov.get('lossy')} "
          f"unbound={unbound} ambient_edges={ambient_edges} ambient_calls={ambient_calls} gaps={len(gaps)}")
    if entries.get("count") != int(expected):
        print(f"INVALID: edge count {entries.get('count')} != expected {expected}", file=sys.stderr)
        return INVALID
    if cov.get("state") != "counted":
        print(f"INVALID: edge state {cov.get('state')} != counted", file=sys.stderr)
        return INVALID
    if cov.get("lossy"):
        print("INVALID: edge is lossy", file=sys.stderr)
        return INVALID
    if unbound:
        print(f"INVALID: {unbound} unbound entries on our module", file=sys.stderr)
        return INVALID
    return VALID

def cmd_signlog(path, n, w):
    try:
        with open(path, encoding="utf-8", errors="replace") as h: text = h.read()
    except OSError as e: return fail(f"unreadable sign log {path}: {e}")
    m1 = re.search(r"^sign OK: (\d+) ops", text, re.M)
    m2 = re.search(r"^sign warm-up: (\d+) ops", text, re.M)
    if not m1 or int(m1.group(1)) != int(n): return fail("sign log published no valid main count")
    if int(w) > 0 and (not m2 or int(m2.group(1)) != int(w)):
        return fail("sign log published no valid warm-up count")
    return VALID

def cmd_mtlog(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as h: text = h.read()
    except OSError as e: return fail(f"unreadable mt log {path}: {e}")
    m = re.search(r"^MT_COUNT ops=(\d+) wall_ns=(\d+) threads=(\d+) pad=(\d+) attempts=(\d+) failed=(\d+)",
                  text, re.M)
    if not m: return fail("mt log has no MT_COUNT line")
    if int(m.group(6)) != 0: return fail("mt log reports failed calls")
    if int(m.group(1)) != int(m.group(5)): return fail("mt ops != attempts")
    print(f"ops={m.group(1)} wall_ns={m.group(2)} threads={m.group(3)}")
    return VALID

def cmd_profmodcheck(path, spec):
    try:
        with open(path, encoding="utf-8") as h: rep = json.load(h)
    except FileNotFoundError: return fail(f"missing profile report: {path}")
    except (OSError, ValueError) as e: return fail(f"unreadable profile report {path}: {e}")
    if not isinstance(rep, dict): return fail("profile report is not an object")
    want = {}
    for item in spec.split(","):
        key, eq, num = item.partition("=")
        if not eq or not num.isdigit(): return fail(f"bad spec item: {item!r}")
        want[key] = int(num)
    got = {}
    for row in rep.get("functions", []):
        mod = row.get("module", {}) or {}
        key = mod.get("sha256", "?")
        got[key] = got.get(key, 0) + (row.get("calls", 0) or 0)
    print("per_module=" + ",".join(f"{k}={v}" for k, v in sorted(got.items())))
    for key, calls in want.items():
        if got.get(key, 0) != calls:
            print(f"INVALID: module {key}: observed {got.get(key, 0)} != expected {calls}",
                  file=sys.stderr)
            return INVALID
    return VALID

def cmd_p11tps(path, substr):
    try:
        with open(path, encoding="utf-8") as h: rep = json.load(h)
    except FileNotFoundError: return fail(f"missing p11perftest json: {path}")
    except (OSError, ValueError) as e: return fail(f"unreadable p11perftest json {path}: {e}")
    if not isinstance(rep, dict): return fail("p11perftest json is not an object")
    for test, suites in rep.items():
        if substr not in test:
            continue
        for suite, vecs in (suites or {}).items():
            for vec, m in (vecs or {}).items():
                tps = ((m.get("tps") or {}).get("global") or {}).get("value")
                wall = (m.get("wallclock") or {}).get("value")
                tot = m.get("total iterations")
                th = m.get("threads")
                print(f"test={test[:60]} tps={tps} wall_ms={wall} total_iters={tot} threads={th} "
                      f"ntests={len(rep)}")
                return VALID
    return fail(f"no p11perftest test matches {substr!r}")

def cmd_spycount(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as h: text = h.read()
    except OSError as e: return fail(f"unreadable spy log {path}: {e}")
    counts = {}
    for m in re.finditer(r"(?m)^[0-9]+: (C_[A-Za-z0-9_]+)", text):
        counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    total = sum(counts.values())
    if total == 0: return fail("spy log has no call markers")
    top = ",".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:8])
    print(f"calls_total={total} top={top}")
    return VALID

def cmd_proftotals(path):
    try:
        with open(path, encoding="utf-8") as h: rep = json.load(h)
    except FileNotFoundError: return fail(f"missing profile report: {path}")
    except (OSError, ValueError) as e: return fail(f"unreadable profile report {path}: {e}")
    if not isinstance(rep, dict): return fail("profile report is not an object")
    total, errors, byname = 0, 0, {}
    for row in rep.get("functions", []):
        total += row.get("calls", 0) or 0
        errors += row.get("errors", 0) or 0
        for name in row.get("names", []):
            byname[name] = byname.get(name, 0) + (row.get("calls", 0) or 0)
    ev = rep.get("evidence", {}) or {}
    top = ",".join(f"{k}={v}" for k, v in sorted(byname.items(), key=lambda kv: -kv[1])[:8])
    print(f"calls_total={total} errors={errors} event_loss={ev.get('event_loss', '?')} "
          f"completeness={ev.get('completeness', '?')} init={byname.get('C_Initialize', 0)} top={top}")
    return VALID

def cmd_tracetotal(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as h: text = h.read()
    except OSError as e: return fail(f"unreadable trace {path}: {e}")
    m = re.search(r"COUNT_EVIDENCE[^\n]*?\"raw_calls\"\s*[:=]\s*(\d+)", text)
    if not m: return fail("trace has no COUNT_EVIDENCE raw_calls")
    print(f"raw_calls={m.group(1)}")
    return VALID

def cmd_invcount(path, pid, module_path):
    try:
        with open(path, encoding="utf-8") as h: rep = json.load(h)
    except FileNotFoundError: return fail(f"missing inventory report: {path}")
    except (OSError, ValueError) as e: return fail(f"unreadable inventory report {path}: {e}")
    if not isinstance(rep, dict): return fail("inventory report is not an object")
    import hashlib
    try:
        with open(module_path, "rb") as h: want_sha = hashlib.sha256(h.read()).hexdigest()
    except OSError as e: return fail(f"cannot hash module {module_path}: {e}")
    caller_ids = {c.get("id") for c in rep.get("callers", []) if str(c.get("pid")) == str(pid)}
    module_ids = {m.get("id") for m in rep.get("modules", [])
                  if (m.get("identity", {}) or {}).get("sha256") == want_sha}
    for e in rep.get("edges", []):
        if e.get("caller") in caller_ids and e.get("module") in module_ids:
            entries = e.get("entries", {}) or {}
            cov = entries.get("coverage", {}) or {}
            print(f"edge_count={entries.get('count')} state={cov.get('state')} lossy={cov.get('lossy')}")
            return VALID
    return fail(f"no edge for pid {pid} module {module_path}")

def cmd_invsumcheck(path, module_path, expected, pids):
    try:
        with open(path, encoding="utf-8") as h: rep = json.load(h)
    except FileNotFoundError: return fail(f"missing inventory report: {path}")
    except (OSError, ValueError) as e: return fail(f"unreadable inventory report {path}: {e}")
    if not isinstance(rep, dict): return fail("inventory report is not an object")
    import hashlib
    try:
        with open(module_path, "rb") as h: want_sha = hashlib.sha256(h.read()).hexdigest()
    except OSError as e: return fail(f"cannot hash module {module_path}: {e}")
    want_pids = set(pids.split(","))
    caller_ids = {c.get("id") for c in rep.get("callers", []) if str(c.get("pid")) in want_pids}
    module_ids = {m.get("id") for m in rep.get("modules", [])
                  if (m.get("identity", {}) or {}).get("sha256") == want_sha}
    total, edges, bad = 0, 0, 0
    for e in rep.get("edges", []):
        if e.get("caller") in caller_ids and e.get("module") in module_ids:
            entries = e.get("entries", {}) or {}
            cov = entries.get("coverage", {}) or {}
            total += entries.get("count", 0) or 0
            edges += 1
            if cov.get("state") != "counted":
                bad += 1
    print(f"edge_sum={total} edges={edges} not_counted={bad} want_pids={len(want_pids)}")
    if total != int(expected) or bad:
        print(f"INVALID: edge sum {total} != expected {expected} (bad={bad})", file=sys.stderr)
        return INVALID
    return VALID

CMDS = {"profcheck": (cmd_profcheck, 3), "tracecheck": (cmd_tracecheck, 2),
        "invcheck": (cmd_invcheck, 4), "signlog": (cmd_signlog, 3), "mtlog": (cmd_mtlog, 1),
        "profmodcheck": (cmd_profmodcheck, 2), "p11tps": (cmd_p11tps, 2),
        "spycount": (cmd_spycount, 1), "proftotals": (cmd_proftotals, 1),
        "tracetotal": (cmd_tracetotal, 1), "invcount": (cmd_invcount, 3),
        "invsumcheck": (cmd_invsumcheck, 4)}

def main(argv):
    if len(argv) < 2 or argv[1] not in CMDS:
        print(f"usage: validate.py {'|'.join(CMDS)} ...", file=sys.stderr)
        return 2
    fn, nargs = CMDS[argv[1]]
    if len(argv) != nargs + 2:
        print(f"usage: validate.py {argv[1]} ... ({nargs} args)", file=sys.stderr)
        return 2
    return fn(*argv[2:])

if __name__ == "__main__":
    sys.exit(main(sys.argv))
PYEOF
}

# record <part> <workload> <module> <condition> <round> <n> <wall> <ticks> <rss> <exact> <loss> <compl> <notes>
record() {
    ns_per_call=$(( $7 / $6 ))
    cpu_s=$(awk -v t="$8" -v hz="$CLK_TCK" 'BEGIN{printf "%.3f", t/hz}')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$ns_per_call" "$8" "$cpu_s" "$9" "${10}" "${11}" "${12}" "${13}" >> "$RESULTS"
    echo "CELL $1/$2/$3/$4 r$5: n=$6 wall_ns=$7 ns/call=$ns_per_call cpu_s=$cpu_s exact=${10} loss=${11} ${13}"
}

# --- sample runners ---
# start_hammer <tag> <binary> <module> <n> <w>: two-phase workload, WPID set.
start_hammer() {
    rm -f "$WORK/$1_warmup_go" "$WORK/$1_warmed" "$WORK/$1_main_go"
    # env(1), not prefix assignments: a word that is only an expansion is
    # never re-recognized as an assignment, so the optional HOLD/RATE
    # words would execute as commands.
    env ${P11SCOPE_HOLD:+P11SCOPE_HOLD=$P11SCOPE_HOLD} \
        ${P11SCOPE_HAMMER_RATE_PER_S:+P11SCOPE_HAMMER_RATE_PER_S=$P11SCOPE_HAMMER_RATE_PER_S} \
        P11SCOPE_HAMMER_WARMUP_GO="$WORK/$1_warmup_go" \
        P11SCOPE_HAMMER_WARMED="$WORK/$1_warmed" \
        P11SCOPE_HAMMER_MAIN_GO="$WORK/$1_main_go" \
        P11SCOPE_HAMMER_WARMUP_CALLS="$5" \
        "$2" "$3" "$4" > "$WORK/$1.ham.log" 2>&1 &
    WPID=$!
}
# wait_for_inv_ready <log> <timeout_s>: inventory prints no
# "capturing:" line; its ready marker is the native-lane line (which also
# names the uprobe kind: uprobe-multi or per-offset).
wait_for_inv_ready() {
    wfir_end=$(( $(date +%s) + $2 ))
    while ! grep -Fq "p11scope: native usage lane active" "$1" 2>/dev/null; do
        if [ -n "${SPID-}" ] && ! kill -0 "$SPID" 2>/dev/null; then
            echo "observer exited before inventory lane went active: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        fi
        [ "$(date +%s)" -lt "$wfir_end" ] || {
            echo "inventory lane never went active within $2s: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        }
        sleep 0.05
    done
    return 0
}
# wait_for_inv_pass <log> <timeout_s>: the first "pass N:" summary line
# proves a collection committed (callers admitted). Releasing the burst
# earlier risks use_before_admission; stopping earlier discards pass 0.
wait_for_inv_pass() {
    wfip_end=$(( $(date +%s) + $2 ))
    while ! grep -Eq "^p11scope: pass [0-9]+: " "$1" 2>/dev/null; do
        if [ -n "${SPID-}" ] && ! kill -0 "$SPID" 2>/dev/null; then
            echo "observer exited before the first pass completed: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        fi
        [ "$(date +%s)" -lt "$wfip_end" ] || {
            echo "no completed inventory pass within $2s: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        }
        sleep 0.2
    done
    return 0
}
# uprobe_kind <obs.log>: uprobe-multi | per-offset | unknown.
uprobe_kind() {
    if grep -Fq "uprobe-multi" "$1" 2>/dev/null; then echo "uprobe-multi";
    elif grep -Fq "per-offset" "$1" 2>/dev/null; then echo "per-offset";
    else echo "unknown"; fi
}
# start_observer <tag> [p11scope args...]: SPID set, attach gate passed.
start_observer() {
    tag=$1; shift
    sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" "$@" \
        > "$WORK/$tag.obs.log" 2>&1 &
    SPID=$!
    wait_for_observer_attach "$WORK/$tag.obs.log" "$ATTACH_TIMEOUT_S" \
        || { echo "$tag: attach gate failed" >&2; return 1; }
    if grep -q "attach failed" "$WORK/$tag.obs.log"; then
        echo "ATTACH FAILURE in $tag:" >&2
        cat "$WORK/$tag.obs.log" >&2
        return 1
    fi
}
stop_observer() {
    kill -INT "$SPID" 2>/dev/null || true
    if wait "$SPID"; then SPID=; else
        status=$?; SPID=
        echo "$1 observer exited $status" >&2
        cat "$WORK/$1.obs.log" >&2
        return 1
    fi
    if grep -q "attach failed" "$WORK/$1.obs.log"; then
        echo "ATTACH FAILURE in $1:" >&2
        cat "$WORK/$1.obs.log" >&2
        return 1
    fi
}
# cpu_window_begin: sets CPU_PID CPU_T0 (fails closed: no PID, no sample).
cpu_window_begin() {
    CPU_PID=$(find_observer_pid) || { echo "$1: observer PID not found" >&2; return 1; }
    CPU_T0=$(sample_ticks "$CPU_PID") || { echo "$1: no initial cpu sample" >&2; return 1; }
    [ -n "$CPU_T0" ] || { echo "$1: empty initial cpu sample" >&2; return 1; }
}
# cpu_window_end <tag>: sets CPU_TICKS CPU_RSS (ticks over the window).
cpu_window_end() {
    CPU_T1=$(sample_ticks "$CPU_PID" 2>/dev/null) || CPU_T1=""
    if [ -z "$CPU_T1" ]; then CPU_TICKS=0; else
        CPU_TICKS=$(echo "$CPU_T0 $CPU_T1" | awk '{print ($3-$1)+($4-$2)}')
    fi
    CPU_RSS=$(rss_hwm_kb "$CPU_PID" 2>/dev/null) || CPU_RSS=0
    [ -n "$CPU_RSS" ] || CPU_RSS=0
}

# sample_unobserved <part> <tag> <workload:rand|sign> <module> <n>
sample_unobserved() {
    rm -f "$WORK/$2_go"
    if [ "$3" = "rand" ]; then bin="$WORK/hammer"; else bin="$WORK/sign_hammer"; fi
    ( while [ ! -f "$WORK/$2_go" ]; do sleep 0.02; done
      exec "$bin" "$4" "$5" ) > "$WORK/$2.ham.log" 2>&1 &
    WPID=$!
    T0=$(date +%s%N)
    touch "$WORK/$2_go"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "$2 workload failed: $status" >&2; return "$status"; fi
    T1=$(date +%s%N)
    if [ "$3" = "rand" ]; then
        python3 -I scripts/lane-bench-overhead-oracle-3.py hammer "$WORK/$2.ham.log" "$5" 0 \
            || { echo "$2: workload published no valid count" >&2; return 1; }
    else
        python3 -I "$WORK/validate.py" signlog "$WORK/$2.ham.log" "$5" 0 \
            || { echo "$2: workload published no valid count" >&2; return 1; }
    fi
    record "$1" "$3" "$(basename "$4")" "unobserved" "$ROUND" "$5" "$((T1-T0))" 0 0 1 0 "n/a" ""
}

# sample_profile <part> <tag> <workload> <module> <manifest> <mode> <n> <w>
sample_profile() {
    if [ "$3" = "rand" ]; then
        bin="$WORK/hammer"; spec="C_GenerateRandom=$(($7+$8))"; okline="hammer OK:"
    else
        bin="$WORK/sign_hammer"; spec="C_Sign=$(($7+$8)),C_SignInit=$(($7+$8))"; okline="sign OK:"
    fi
    start_hammer "$2" "$bin" "$4" "$7" "$8"
    start_observer "$2" profile --manifest "$5" --pid "$WPID" --mode "$6" --duration 180 \
        -o "$WORK/$2.json" || return 1
    touch "$WORK/$2_warmup_go"
    wait_for_workload_file "$WORK/$2_warmed" "$WPID" "$WARMUP_TIMEOUT_S" "$2 warm-up" || return 1
    cpu_window_begin "$2" || return 1
    T0=$(date +%s%N)
    touch "$WORK/$2_main_go"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "$2 workload failed: $status" >&2; return "$status"; fi
    T1=$(date +%s%N)
    cpu_window_end "$2"
    stop_observer "$2" || return 1
    reclaim_root_output "$WORK/$2.json"
    if [ "$3" = "rand" ]; then
        python3 -I scripts/lane-bench-overhead-oracle-3.py hammer "$WORK/$2.ham.log" "$7" "$8" \
            || { echo "$2: workload published no valid count" >&2; return 1; }
    else
        python3 -I "$WORK/validate.py" signlog "$WORK/$2.ham.log" "$7" "$8" \
            || { echo "$2: workload published no valid count" >&2; return 1; }
    fi
    vstatus=0
    info=$(python3 -I "$WORK/validate.py" profcheck "$WORK/$2.json" "$spec" 0 2>"$WORK/$2.verdict") \
        || vstatus=$?
    if [ "$3" = "rand" ]; then
        # Continuity with the v0.1.0 oracle: both validators must agree.
        if python3 -I scripts/lane-bench-overhead-oracle-3.py profile "$WORK/$2.json" "$(($7+$8))" \
                2>/dev/null; then ostatus=0; else ostatus=$?; fi
        if [ "$ostatus" = 10 ] && [ "$vstatus" = 0 ]; then
            echo "$2: oracle disagreement (legacy INVALID, new VALID)" >&2; return 1
        fi
        if [ "$ostatus" = 0 ] && [ "$vstatus" = 10 ]; then
            echo "$2: oracle disagreement (legacy VALID, new INVALID)" >&2; return 1
        fi
        [ "$ostatus" = 0 ] || [ "$ostatus" = 10 ] || { echo "$2: legacy oracle error" >&2; return 1; }
    fi
    loss=$(echo "$info" | sed -n 's/.*event_loss=\([^ ]*\).*/\1/p')
    compl=$(echo "$info" | sed -n 's/.*completeness=\([^ ]*\).*/\1/p')
    if [ "$vstatus" = 10 ]; then
        record "$1" "$3" "$(basename "$4")" "$6" "$ROUND" "$7" "$((T1-T0))" "$CPU_TICKS" "$CPU_RSS" \
            0 "$loss" "$compl" "INVALID: $(cat "$WORK/$2.verdict")"
        if [ "$1" = "percall" ]; then INVALID_TOTAL=$((INVALID_TOTAL+1)); fi
        return 0
    fi
    [ "$vstatus" = 0 ] || { echo "$2: report validation failed" >&2; cat "$WORK/$2.verdict" >&2; return 1; }
    record "$1" "$3" "$(basename "$4")" "$6" "$ROUND" "$7" "$((T1-T0))" "$CPU_TICKS" "$CPU_RSS" \
        1 "$loss" "$compl" "$(echo "$info" | sed 's/.*verdict=/verdict=/')"
}

# sample_trace <part> <tag> <workload> <module> <manifest> <n> <w>
sample_trace() {
    if [ "$3" = "rand" ]; then
        bin="$WORK/hammer"; total=$(($6+$7+5)); warm_pat="C_GenerateRandom"
    else
        bin="$WORK/sign_hammer"; total=$((2*($6+$7)+7)); warm_pat="C_Sign"
    fi
    start_hammer "$2" "$bin" "$4" "$6" "$7"
    start_observer "$2" trace --manifest "$5" --pid "$WPID" --duration 180 \
        -o "$WORK/$2.txt" || return 1
    touch "$WORK/$2_warmup_go"
    wait_for_workload_file "$WORK/$2_warmed" "$WPID" "$WARMUP_TIMEOUT_S" "$2 warm-up" || return 1
    wait_for_trace_warmup "$WORK/$2.obs.log" "$7" "$WARMUP_TIMEOUT_S" "$warm_pat" \
        || { echo "$2: warm-up positive control failed" >&2; return 1; }
    cpu_window_begin "$2" || return 1
    T0=$(date +%s%N)
    touch "$WORK/$2_main_go"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "$2 workload failed: $status" >&2; return "$status"; fi
    T1=$(date +%s%N)
    cpu_window_end "$2"
    stop_observer "$2" || return 1
    reclaim_root_output "$WORK/$2.txt"
    if [ "$3" = "rand" ]; then
        python3 -I scripts/lane-bench-overhead-oracle-3.py hammer "$WORK/$2.ham.log" "$6" "$7" \
            || { echo "$2: workload published no valid count" >&2; return 1; }
    else
        python3 -I "$WORK/validate.py" signlog "$WORK/$2.ham.log" "$6" "$7" \
            || { echo "$2: workload published no valid count" >&2; return 1; }
    fi
    vstatus=0
    info=$(python3 -I "$WORK/validate.py" tracecheck "$WORK/$2.txt" "$total" 2>"$WORK/$2.verdict") \
        || vstatus=$?
    if [ "$3" = "rand" ]; then
        if python3 -I scripts/lane-bench-overhead-oracle-3.py trace "$WORK/$2.txt" "$total" \
                2>/dev/null; then ostatus=0; else ostatus=$?; fi
        if [ "$ostatus" != "$vstatus" ]; then
            echo "$2: oracle disagreement (legacy $ostatus, new $vstatus)" >&2; return 1
        fi
    fi
    bytes=$(wc -c < "$WORK/$2.txt")
    if [ "$bytes" -gt 52428800 ]; then
        lines=$(wc -l < "$WORK/$2.txt")
        head -c 1048576 "$WORK/$2.txt" > "$WORK/$2.txt.head"
        rm -f "$WORK/$2.txt"
        echo "$2: trace output truncated after validation ($bytes bytes, $lines lines)"
    fi
    tcompl=$(echo "$info" | sed -n 's/.*completeness=\([^ ]*\).*/\1/p')
    if [ "$vstatus" = 10 ]; then
        record "$1" "$3" "$(basename "$4")" "trace" "$ROUND" "$6" "$((T1-T0))" "$CPU_TICKS" "$CPU_RSS" \
            0 "$(echo "$info" | sed -n 's/.*lost_markers=\([^ ]*\).*/\1/p')" "$tcompl" \
            "INVALID bytes=$bytes: $(cat "$WORK/$2.verdict")"
        if [ "$1" = "percall" ]; then INVALID_TOTAL=$((INVALID_TOTAL+1)); fi
        return 0
    fi
    [ "$vstatus" = 0 ] || { echo "$2: report validation failed" >&2; cat "$WORK/$2.verdict" >&2; return 1; }
    record "$1" "$3" "$(basename "$4")" "trace" "$ROUND" "$6" "$((T1-T0))" "$CPU_TICKS" "$CPU_RSS" \
        1 "$(echo "$info" | sed -n 's/.*lost_markers=\([^ ]*\).*/\1/p')" "$tcompl" \
        "raw=$(echo "$info" | sed -n 's/raw_calls=\([^ ]*\).*/\1/p') bytes=$bytes"
}

# sample_inv <part> <tag> <workload> <module> <manifest> <scope:pid|system> <n> <w> [keyops:0|1]
sample_inv() {
    if [ "$3" = "rand" ]; then
        bin="$WORK/hammer"; total=$(($7+$8+5)); okline="hammer OK:"
    else
        bin="$WORK/sign_hammer"; total=$((2*($7+$8)+7)); okline="sign OK:"
    fi
    keyops=${9:-0}
    cond="inv-$6"
    [ "$keyops" = 1 ] && cond="$cond-keys"
    P11SCOPE_HOLD=1
    start_hammer "$2" "$bin" "$4" "$7" "$8"
    unset P11SCOPE_HOLD
    held_wpid=$WPID
    if [ "$6" = "pid" ]; then scope_args="--pid $held_wpid"; else scope_args="--system"; fi
    if [ "$keyops" = 1 ]; then key_args="--key-operations"; else key_args=""; fi
    # shellcheck disable=SC2086
    sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" inventory $scope_args --capture native \
        --manifest "$5" $key_args --duration 240 -o "$WORK/$2.json" \
        > "$WORK/$2.obs.log" 2>&1 &
    SPID=$!
    wait_for_inv_ready "$WORK/$2.obs.log" "$ATTACH_TIMEOUT_S" || return 1
    if grep -q "attach failed" "$WORK/$2.obs.log"; then
        echo "ATTACH FAILURE in $2:" >&2; cat "$WORK/$2.obs.log" >&2; return 1
    fi
    ukind=$(uprobe_kind "$WORK/$2.obs.log")
    echo "$ukind" > "$WORK/uprobe-kind.txt"
    wait_for_inv_pass "$WORK/$2.obs.log" "$PASS_TIMEOUT_S" || return 1
    sleep "$ADMIT_S"
    touch "$WORK/$2_warmup_go"
    wait_for_workload_file "$WORK/$2_warmed" "$held_wpid" "$WARMUP_TIMEOUT_S" "$2 warm-up" || return 1
    cpu_window_begin "$2" || return 1
    T0=$(date +%s%N)
    touch "$WORK/$2_main_go"
    wait_for_log_line "$WORK/$2.ham.log" "$okline" 300 || return 1
    T1=$(date +%s%N)
    cpu_window_end "$2"
    if [ "$6" = "pid" ]; then sleep "$POST_PID_S"; else sleep "$POST_SYS_S"; fi
    stop_observer "$2" || return 1
    kill -CONT "$held_wpid" 2>/dev/null || true
    if wait "$held_wpid"; then WPID=; else status=$?; WPID=; echo "$2 workload failed: $status" >&2; return "$status"; fi
    reclaim_root_output "$WORK/$2.json"
    if [ "$3" = "rand" ]; then
        python3 -I scripts/lane-bench-overhead-oracle-3.py hammer "$WORK/$2.ham.log" "$7" "$8" \
            || { echo "$2: workload published no valid count" >&2; return 1; }
    else
        python3 -I "$WORK/validate.py" signlog "$WORK/$2.ham.log" "$7" "$8" \
            || { echo "$2: workload published no valid count" >&2; return 1; }
    fi
    vstatus=0
    info=$(python3 -I "$WORK/validate.py" invcheck "$WORK/$2.json" "$held_wpid" "$4" "$total" \
        2>"$WORK/$2.verdict") || vstatus=$?
    keyline=$(grep -m1 "^key operations:" "$WORK/$2.obs.log" 2>/dev/null || echo "key operations: n/a")
    semline=$(grep -m1 "semantic calls:" "$WORK/$2.obs.log" 2>/dev/null || echo "semantic calls: n/a")
    notes="uprobe=$ukind $info :: $keyline :: $semline"
    if [ "$vstatus" = 10 ]; then
        record "$1" "$3" "$(basename "$4")" "$cond" "$ROUND" "$7" "$((T1-T0))" "$CPU_TICKS" "$CPU_RSS" \
            0 0 "n/a" "INVALID: $(cat "$WORK/$2.verdict") :: $notes"
        if [ "$1" = "percall" ]; then INVALID_TOTAL=$((INVALID_TOTAL+1)); fi
        return 0
    fi
    [ "$vstatus" = 0 ] || { echo "$2: report validation failed" >&2; cat "$WORK/$2.verdict" >&2; return 1; }
    record "$1" "$3" "$(basename "$4")" "$cond" "$ROUND" "$7" "$((T1-T0))" "$CPU_TICKS" "$CPU_RSS" \
        1 0 "n/a" "$notes"
}

INVALID_TOTAL=0
ROUND=0

if [ "$SELF_TEST" = 1 ]; then
    command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
    command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
    SELF_TEST_WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-v070bench-selftest-XXXXXX")
    trap 'rm -rf "$SELF_TEST_WORK"' EXIT INT TERM
    SPID=; WPID=
    printf 'p11scope: capturing: 12 probes attached; stop with Ctrl-C\n' > "$SELF_TEST_WORK/attached.log"
    wait_for_observer_attach "$SELF_TEST_WORK/attached.log" 5 \
        || { echo "self-test: attach wait missed the marker" >&2; exit 1; }
    : > "$SELF_TEST_WORK/empty.log"
    if wait_for_observer_attach "$SELF_TEST_WORK/empty.log" 1 2>/dev/null; then
        echo "self-test: missing attach marker accepted" >&2; exit 1
    fi
    printf 'p11scope: native usage lane active (Inventory capture activated, uprobe-multi links)\np11scope: pass 0: 1 scanned (0 maps-matched; 0 native, 1 scan-pinned)\n' \
        > "$SELF_TEST_WORK/inv.log"
    wait_for_inv_ready "$SELF_TEST_WORK/inv.log" 5 \
        || { echo "self-test: inv ready wait missed the marker" >&2; exit 1; }
    if wait_for_inv_ready "$SELF_TEST_WORK/empty.log" 1 2>/dev/null; then
        echo "self-test: missing inv marker accepted" >&2; exit 1
    fi
    wait_for_inv_pass "$SELF_TEST_WORK/inv.log" 5 \
        || { echo "self-test: inv pass wait missed the marker" >&2; exit 1; }
    if wait_for_inv_pass "$SELF_TEST_WORK/empty.log" 1 2>/dev/null; then
        echo "self-test: missing inv pass accepted" >&2; exit 1
    fi
    printf 'hammer OK: 3 C_GenerateRandom calls\n' > "$SELF_TEST_WORK/hammer.log"
    wait_for_log_line "$SELF_TEST_WORK/hammer.log" "hammer OK:" 5 \
        || { echo "self-test: log-line wait missed" >&2; exit 1; }
    if wait_for_log_line "$SELF_TEST_WORK/hammer.log" "sign OK:" 1 2>/dev/null; then
        echo "self-test: absent log line accepted" >&2; exit 1
    fi
    gcc -O0 -o "$SELF_TEST_WORK/hammer" "$FIX/hammer.c" -ldl \
        || { echo "self-test: hammer build failed" >&2; exit 1; }
    gcc -O2 -o "$SELF_TEST_WORK/sign_hammer" "$FIX/sign_hammer.c" -ldl \
        || { echo "self-test: sign_hammer build failed" >&2; exit 1; }
    gcc -shared -fPIC -O2 -o "$SELF_TEST_WORK/null.so" "$FIX/null_provider.c" \
        || { echo "self-test: null provider build failed" >&2; exit 1; }
    gcc -O2 -pthread -o "$SELF_TEST_WORK/mt_count" "$FIX/mt_count.c" -ldl -pthread \
        || { echo "self-test: mt_count build failed" >&2; exit 1; }
    "$SELF_TEST_WORK/hammer" "$SELF_TEST_WORK/null.so" 1000 2>&1 | grep -q "hammer OK: 1000" \
        || { echo "self-test: hammer/null run failed" >&2; exit 1; }
    touch "$SELF_TEST_WORK/gate"
    "$SELF_TEST_WORK/mt_count" "$SELF_TEST_WORK/null.so" 2 1 "$SELF_TEST_WORK/gate" 0 2>&1 | grep -q "^MT_COUNT" \
        || { echo "self-test: mt_count/null run failed" >&2; exit 1; }
    WORK=$SELF_TEST_WORK
    P11SCOPE_HOLD=1
    start_hammer "st-hold" "$SELF_TEST_WORK/hammer" "$SELF_TEST_WORK/null.so" 50 10
    unset P11SCOPE_HOLD
    touch "$SELF_TEST_WORK/st-hold_warmup_go"
    wait_for_workload_file "$SELF_TEST_WORK/st-hold_warmed" "$WPID" 10 "self-test warm-up" \
        || { echo "self-test: HOLD warm-up failed" >&2; exit 1; }
    touch "$SELF_TEST_WORK/st-hold_main_go"
    wait_for_log_line "$SELF_TEST_WORK/st-hold.ham.log" "hammer OK:" 10 \
        || { echo "self-test: HOLD completion failed" >&2; exit 1; }
    kill -CONT "$WPID" 2>/dev/null || true
    wait "$WPID" || { echo "self-test: HOLD workload failed" >&2; exit 1; }
    WPID=
    P11SCOPE_HOLD=1 "$SELF_TEST_WORK/mt_count" "$SELF_TEST_WORK/null.so" 1 1 \
        "$SELF_TEST_WORK/gate" 0 > "$SELF_TEST_WORK/mthold.log" 2>&1 &
    WPID=$!
    wait_for_log_line "$SELF_TEST_WORK/mthold.log" "MT_COUNT" 30 \
        || { echo "self-test: mt HOLD completion failed" >&2; exit 1; }
    sleep 0.3
    if ! kill -0 "$WPID" 2>/dev/null; then
        echo "self-test: mt HOLD exited instead of stopping" >&2; exit 1
    fi
    kill -CONT "$WPID" 2>/dev/null || true
    wait "$WPID" || { echo "self-test: mt HOLD workload failed" >&2; exit 1; }
    WPID=
    write_validate_py
    VPY="$SELF_TEST_WORK/validate.py"
    printf '%s' '{"functions": [{"names": ["C_GenerateRandom"], "calls": 100, "errors": 0, "rv_counts": {"0x0": 100}}], "evidence": {"event_loss": 0, "completeness": "COMPLETE", "verdict_detail": "x"}}' > "$SELF_TEST_WORK/prof.json"
    python3 -I "$VPY" profcheck "$SELF_TEST_WORK/prof.json" "C_GenerateRandom=100" 0 >/dev/null \
        || { echo "self-test: profcheck valid rejected" >&2; exit 1; }
    python3 -I "$VPY" profcheck "$SELF_TEST_WORK/prof.json" "C_GenerateRandom=99" 0 >/dev/null 2>&1 \
        && { echo "self-test: profcheck mismatch accepted" >&2; exit 1; }
    [ $? = 10 ] || { echo "self-test: profcheck mismatch is not INVALID" >&2; exit 1; }
    printf '%s\n' 'l0' 'COUNT_EVIDENCE {"raw_calls": 105}' 'EVIDENCE {"event_loss": 0, "completeness": "COMPLETE"}' > "$SELF_TEST_WORK/trace.txt"
    python3 -I "$VPY" tracecheck "$SELF_TEST_WORK/trace.txt" 105 >/dev/null \
        || { echo "self-test: tracecheck valid rejected" >&2; exit 1; }
    python3 -I "$VPY" tracetotal "$SELF_TEST_WORK/trace.txt" | grep -q "raw_calls=105" \
        || { echo "self-test: tracetotal wrong" >&2; exit 1; }
    python3 -I "$VPY" proftotals "$SELF_TEST_WORK/prof.json" | grep -q "calls_total=100" \
        || { echo "self-test: proftotals wrong" >&2; exit 1; }
    nullsha=$(sha256sum "$SELF_TEST_WORK/null.so" | cut -d' ' -f1)
    printf '{"callers": [{"id": "c0", "pid": 1234}], "modules": [{"id": "m0", "identity": {"sha256": "%s"}}], "edges": [{"caller": "c0", "module": "m0", "entries": {"count": 42, "coverage": {"state": "counted", "lossy": false}}}], "gaps": []}' "$nullsha" > "$SELF_TEST_WORK/inv.json"
    python3 -I "$VPY" invcheck "$SELF_TEST_WORK/inv.json" 1234 "$SELF_TEST_WORK/null.so" 42 >/dev/null \
        || { echo "self-test: invcheck valid rejected" >&2; exit 1; }
    python3 -I "$VPY" invsumcheck "$SELF_TEST_WORK/inv.json" "$SELF_TEST_WORK/null.so" 42 "1234" >/dev/null \
        || { echo "self-test: invsumcheck valid rejected" >&2; exit 1; }
    python3 -I "$VPY" invcount "$SELF_TEST_WORK/inv.json" 1234 "$SELF_TEST_WORK/null.so" | grep -q "edge_count=42" \
        || { echo "self-test: invcount wrong" >&2; exit 1; }
    printf '%s\n' 'sign OK: 7 ops (7 C_SignInit, 7 C_Sign)' 'sign warm-up: 3 ops' > "$SELF_TEST_WORK/sign.log"
    python3 -I "$VPY" signlog "$SELF_TEST_WORK/sign.log" 7 3 \
        || { echo "self-test: signlog valid rejected" >&2; exit 1; }
    printf '%s\n' 'READY gate' 'MT_COUNT ops=50 wall_ns=100 threads=2 pad=0 attempts=50 failed=0' > "$SELF_TEST_WORK/mt.log"
    python3 -I "$VPY" mtlog "$SELF_TEST_WORK/mt.log" | grep -q "ops=50" \
        || { echo "self-test: mtlog wrong" >&2; exit 1; }
    printf '%s' '{"Generate random numbers (C_GenerateRandom()) using rand-128": {"rand-128": {"testvec0064": {"tps": {"global": {"value": "750000"}}, "wallclock": {"value": "0.23"}, "total iterations": 50, "threads": 1}}}}' > "$SELF_TEST_WORK/p11.json"
    python3 -I "$VPY" p11tps "$SELF_TEST_WORK/p11.json" "C_GenerateRandom" | grep -q "tps=750000" \
        || { echo "self-test: p11tps wrong" >&2; exit 1; }
    printf '%s\n' '0: C_Initialize' '1: C_GenerateRandom' '2: C_GenerateRandom' > "$SELF_TEST_WORK/spy.log"
    python3 -I "$VPY" spycount "$SELF_TEST_WORK/spy.log" | grep -q "calls_total=3" \
        || { echo "self-test: spycount wrong" >&2; exit 1; }
    echo "bench-v070-overhead self-test: OK"
    exit 0
fi
setup_work

# sample_mt <part> <tag> <module> <manifest> <condition> <threads> <secs>
# condition: unobserved|metrics|profile|trace|inv-pid|inv-system
sample_mt() {
    rm -f "$WORK/$2_gate"
    case "$5" in inv-pid|inv-system) export P11SCOPE_HOLD=1;; *) unset P11SCOPE_HOLD;; esac
    "$WORK/mt_count" "$3" "$6" "$7" "$WORK/$2_gate" 0 > "$WORK/$2.ham.log" 2>&1 &
    WPID=$!
    mt_wpid=$WPID
    unset P11SCOPE_HOLD
    wait_for_log_line "$WORK/$2.ham.log" "READY" 60 || return 1
    if [ "$5" = "unobserved" ]; then
        T0=$(date +%s%N)
        touch "$WORK/$2_gate"
        wait_for_log_line "$WORK/$2.ham.log" "MT_COUNT" $(( $7 + 120 )) || return 1
        if wait "$mt_wpid"; then WPID=; else status=$?; WPID=; echo "$2 workload failed: $status" >&2; return "$status"; fi
        T1=$(date +%s%N)
        mtinfo=$(python3 -I "$WORK/validate.py" mtlog "$WORK/$2.ham.log") \
            || { echo "$2: mt log invalid" >&2; return 1; }
        ops=$(echo "$mtinfo" | sed -n 's/ops=\([0-9]*\).*/\1/p')
        wall=$(echo "$mtinfo" | sed -n 's/.*wall_ns=\([0-9]*\).*/\1/p')
        record "$1" "mt$6" "$(basename "$3")" "unobserved" "$ROUND" "$ops" "$wall" 0 0 1 0 "n/a" ""
        return 0
    fi
    mt_dur=$(( $7 + 120 ))
    case "$5" in
        metrics)
            start_observer "$2" profile --manifest "$4" --pid "$mt_wpid" --mode metrics \
                --duration "$mt_dur" -o "$WORK/$2.json" || return 1
            is_inv=0; ukind=""
            ;;
        profile)
            start_observer "$2" profile --manifest "$4" --pid "$mt_wpid" --mode profile \
                --duration "$mt_dur" -o "$WORK/$2.json" || return 1
            is_inv=0; ukind=""
            ;;
        trace)
            start_observer "$2" trace --manifest "$4" --pid "$mt_wpid" \
                --duration "$mt_dur" -o "$WORK/$2.txt" || return 1
            is_inv=0; ukind=""
            ;;
        inv-pid|inv-system)
            if [ "$5" = "inv-pid" ]; then scope_args="--pid $mt_wpid"; else scope_args="--system"; fi
            # shellcheck disable=SC2086
            sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" inventory $scope_args --capture native \
                --manifest "$4" --duration "$mt_dur" -o "$WORK/$2.json" \
                > "$WORK/$2.obs.log" 2>&1 &
            SPID=$!
            wait_for_inv_ready "$WORK/$2.obs.log" "$ATTACH_TIMEOUT_S" || return 1
            if grep -q "attach failed" "$WORK/$2.obs.log"; then
                echo "ATTACH FAILURE in $2:" >&2; cat "$WORK/$2.obs.log" >&2; return 1
            fi
            ukind=$(uprobe_kind "$WORK/$2.obs.log")
            echo "$ukind" > "$WORK/uprobe-kind.txt"
            wait_for_inv_pass "$WORK/$2.obs.log" "$PASS_TIMEOUT_S" || return 1
            sleep "$ADMIT_S"
            is_inv=1
            ;;
        *) echo "$2: bad condition $5" >&2; return 1 ;;
    esac
    cpu_window_begin "$2" || return 1
    touch "$WORK/$2_gate"
    wait_for_log_line "$WORK/$2.ham.log" "MT_COUNT" $(( $7 + 120 )) || return 1
    cpu_window_end "$2"
    if [ "$is_inv" = 1 ]; then
        if [ "$5" = "inv-pid" ]; then sleep "$POST_PID_S"; else sleep "$POST_SYS_S"; fi
    fi
    stop_observer "$2" || return 1
    if [ "$is_inv" = 1 ]; then kill -CONT "$mt_wpid" 2>/dev/null || true; fi
    if wait "$mt_wpid"; then WPID=; else status=$?; WPID=; echo "$2 workload failed: $status" >&2; return "$status"; fi
    mtinfo=$(python3 -I "$WORK/validate.py" mtlog "$WORK/$2.ham.log") \
        || { echo "$2: mt log invalid" >&2; return 1; }
    ops=$(echo "$mtinfo" | sed -n 's/ops=\([0-9]*\).*/\1/p')
    wall=$(echo "$mtinfo" | sed -n 's/.*wall_ns=\([0-9]*\).*/\1/p')
    vstatus=0
    case "$5" in
        metrics|profile)
            reclaim_root_output "$WORK/$2.json"
            spec="C_GenerateRandom=$ops,C_OpenSession=$6,C_CloseSession=$6,C_Finalize=1"
            info=$(python3 -I "$WORK/validate.py" profcheck "$WORK/$2.json" "$spec" 0 \
                2>"$WORK/$2.verdict") || vstatus=$?
            loss=$(echo "$info" | sed -n 's/.*event_loss=\([^ ]*\).*/\1/p')
            compl=$(echo "$info" | sed -n 's/.*completeness=\([^ ]*\).*/\1/p')
            notes="$info"
            ;;
        trace)
            reclaim_root_output "$WORK/$2.txt"
            total=$(( ops + 2*$6 + 1 ))
            info=$(python3 -I "$WORK/validate.py" tracecheck "$WORK/$2.txt" "$total" \
                2>"$WORK/$2.verdict") || vstatus=$?
            loss=$(echo "$info" | sed -n 's/.*lost_markers=\([^ ]*\).*/\1/p')
            compl=$(echo "$info" | sed -n 's/.*completeness=\([^ ]*\).*/\1/p')
            bytes=$(wc -c < "$WORK/$2.txt")
            if [ "$bytes" -gt 52428800 ]; then
                head -c 1048576 "$WORK/$2.txt" > "$WORK/$2.txt.head"; rm -f "$WORK/$2.txt"
            fi
            notes="$info bytes=$bytes"
            ;;
        inv-pid|inv-system)
            reclaim_root_output "$WORK/$2.json"
            total=$(( ops + 2*$6 + 1 ))
            info=$(python3 -I "$WORK/validate.py" invcheck "$WORK/$2.json" "$mt_wpid" "$3" "$total" \
                2>"$WORK/$2.verdict") || vstatus=$?
            loss=0; compl="n/a"
            notes="uprobe=$ukind $info"
            ;;
    esac
    if [ "$vstatus" = 10 ]; then exact=0; notes="INVALID: $(cat "$WORK/$2.verdict") :: $notes";
    elif [ "$vstatus" = 0 ]; then exact=1;
    else echo "$2: report validation failed" >&2; cat "$WORK/$2.verdict" >&2; return 1; fi
    record "$1" "mt$6" "$(basename "$3")" "$5" "$ROUND" "$ops" "$wall" "$CPU_TICKS" "$CPU_RSS" \
        "$exact" "$loss" "$compl" "$notes"
}

if echo " $PARTS " | grep -q " percall "; then
echo "=== part percall: $RUNS interleaved rounds ==="
echo "conditions: $CONDITIONS"
ROUND=1
while [ "$ROUND" -le "$RUNS" ]; do
    echo "--- percall round $ROUND/$RUNS (rand) ---"
    if want_cond unobserved; then
        sample_unobserved percall "pc-rand-unobs-$ROUND" rand "$MODULE" "$N_CALLS" || exit 1
    fi
    if want_cond metrics; then
        sample_profile percall "pc-rand-metrics-$ROUND" rand "$MODULE" "$WORK/manifest-soft.json" \
            metrics "$N_CALLS" "$WARMUP_CALLS" || exit 1
    fi
    if want_cond profile; then
        sample_profile percall "pc-rand-profile-$ROUND" rand "$MODULE" "$WORK/manifest-soft.json" \
            profile "$N_CALLS" "$WARMUP_CALLS" || exit 1
    fi
    if want_cond trace; then
        sample_trace percall "pc-rand-trace-$ROUND" rand "$MODULE" "$WORK/manifest-soft.json" \
            "$N_CALLS" "$WARMUP_CALLS" || exit 1
    fi
    if want_cond inv-pid; then
        sample_inv percall "pc-rand-invpid-$ROUND" rand "$MODULE" "$WORK/manifest-soft.json" \
            pid "$N_CALLS" "$WARMUP_CALLS" || exit 1
    fi
    if want_cond inv-system; then
        sample_inv percall "pc-rand-invsys-$ROUND" rand "$MODULE" "$WORK/manifest-soft.json" \
            system "$N_CALLS" "$WARMUP_CALLS" || exit 1
    fi
    if want_cond inv-pid-keys; then
        sample_inv percall "pc-rand-invkeys-$ROUND" rand "$MODULE" "$WORK/manifest-soft.json" \
            pid "$N_CALLS" "$WARMUP_CALLS" 1 || exit 1
    fi
    echo "--- percall round $ROUND/$RUNS (sign) ---"
    if want_cond unobserved; then
        sample_unobserved percall "pc-sign-unobs-$ROUND" sign "$MODULE" "$N_SIGN" || exit 1
    fi
    if want_cond metrics; then
        sample_profile percall "pc-sign-metrics-$ROUND" sign "$MODULE" "$WORK/manifest-soft.json" \
            metrics "$N_SIGN" "$WARMUP_SIGN" || exit 1
    fi
    if want_cond profile; then
        sample_profile percall "pc-sign-profile-$ROUND" sign "$MODULE" "$WORK/manifest-soft.json" \
            profile "$N_SIGN" "$WARMUP_SIGN" || exit 1
    fi
    if want_cond trace; then
        sample_trace percall "pc-sign-trace-$ROUND" sign "$MODULE" "$WORK/manifest-soft.json" \
            "$N_SIGN" "$WARMUP_SIGN" || exit 1
    fi
    if want_cond inv-pid; then
        sample_inv percall "pc-sign-invpid-$ROUND" sign "$MODULE" "$WORK/manifest-soft.json" \
            pid "$N_SIGN" "$WARMUP_SIGN" || exit 1
    fi
    if want_cond inv-system; then
        sample_inv percall "pc-sign-invsys-$ROUND" sign "$MODULE" "$WORK/manifest-soft.json" \
            system "$N_SIGN" "$WARMUP_SIGN" || exit 1
    fi
    if want_cond inv-pid-keys; then
        sample_inv percall "pc-sign-invkeys-$ROUND" sign "$MODULE" "$WORK/manifest-soft.json" \
            pid "$N_SIGN" "$WARMUP_SIGN" 1 || exit 1
    fi
    ROUND=$((ROUND+1))
done
echo "percall invalid samples: $INVALID_TOTAL"
fi

if echo " $PARTS " | grep -q " ramp "; then
echo "=== part ramp ==="
RAMP_THREADS="$THREADS"
case " $RAMP_THREADS " in *" $NPROC "*) ;; *) RAMP_THREADS="$RAMP_THREADS $NPROC" ;; esac
for rate in 2000 10000 50000 100000; do
    case $rate in 2000|10000) pace_n=$((rate*10));; *) pace_n=$((rate*5));; esac
    echo "--- ramp paced $rate/s (n=$pace_n) ---"
    ROUND="paced$rate"
    export P11SCOPE_HAMMER_RATE_PER_S=$rate
    if want_cond unobserved; then
        sample_unobserved ramp "ramp-p$rate-unobs" rand "$MODULE" "$pace_n" || exit 1
    fi
    if want_cond metrics; then
        sample_profile ramp "ramp-p$rate-metrics" rand "$MODULE" "$WORK/manifest-soft.json" \
            metrics "$pace_n" "$WARMUP_CALLS" || exit 1
    fi
    if want_cond profile; then
        sample_profile ramp "ramp-p$rate-profile" rand "$MODULE" "$WORK/manifest-soft.json" \
            profile "$pace_n" "$WARMUP_CALLS" || exit 1
    fi
    if want_cond trace; then
        sample_trace ramp "ramp-p$rate-trace" rand "$MODULE" "$WORK/manifest-soft.json" \
            "$pace_n" "$WARMUP_CALLS" || exit 1
    fi
    if want_cond inv-pid; then
        sample_inv ramp "ramp-p$rate-invpid" rand "$MODULE" "$WORK/manifest-soft.json" \
            pid "$pace_n" "$WARMUP_CALLS" || exit 1
    fi
    if want_cond inv-system; then
        sample_inv ramp "ramp-p$rate-invsys" rand "$MODULE" "$WORK/manifest-soft.json" \
            system "$pace_n" "$WARMUP_CALLS" || exit 1
    fi
    unset P11SCOPE_HAMMER_RATE_PER_S
done
for t in $RAMP_THREADS; do
    echo "--- ramp unthrottled mt$t (${RAMP_SECS}s) ---"
    ROUND="mt$t"
    if want_cond unobserved; then
        sample_mt ramp "ramp-mt$t-unobs" "$MODULE" "$WORK/manifest-soft.json" unobserved "$t" "$RAMP_SECS" || exit 1
    fi
    if want_cond metrics; then
        sample_mt ramp "ramp-mt$t-metrics" "$MODULE" "$WORK/manifest-soft.json" metrics "$t" "$RAMP_SECS" || exit 1
    fi
    if want_cond profile; then
        sample_mt ramp "ramp-mt$t-profile" "$MODULE" "$WORK/manifest-soft.json" profile "$t" "$RAMP_SECS" || exit 1
    fi
    if want_cond inv-pid; then
        sample_mt ramp "ramp-mt$t-invpid" "$MODULE" "$WORK/manifest-soft.json" inv-pid "$t" "$RAMP_SECS" || exit 1
    fi
    if want_cond inv-system; then
        sample_mt ramp "ramp-mt$t-invsys" "$MODULE" "$WORK/manifest-soft.json" inv-system "$t" "$RAMP_SECS" || exit 1
    fi
    case " 1 2 " in *" $t "*)
        if want_cond trace; then
            sample_mt ramp "ramp-mt$t-trace" "$MODULE" "$WORK/manifest-soft.json" trace "$t" "$TRACE_SECS" || exit 1
        fi
        ;;
    esac
done
fi

# sample_ceil <part> <tag> <condition> <threads> <secs>: three mt_count
# drivers (nullA, nullB, SoftHSM) behind one shared gate under one
# system-wide observer. condition: unobserved|inv-system|inv-system-keys|
# metrics|profile|trace.
sample_ceil() {
    rm -f "$WORK/$2_gate"
    case "$3" in inv-system|inv-system-keys) export P11SCOPE_HOLD=1;; *) unset P11SCOPE_HOLD;; esac
    "$WORK/mt_count" "$WORK/nullA.so" "$4" "$5" "$WORK/$2_gate" 0 > "$WORK/$2.nullA.log" 2>&1 &
    pid_a=$!
    "$WORK/mt_count" "$WORK/nullB.so" "$4" "$5" "$WORK/$2_gate" 0 > "$WORK/$2.nullB.log" 2>&1 &
    pid_b=$!
    "$WORK/mt_count" "$MODULE" "$4" "$5" "$WORK/$2_gate" 0 > "$WORK/$2.soft.log" 2>&1 &
    pid_s=$!
    unset P11SCOPE_HOLD
    CEIL_PIDS="$pid_a $pid_b $pid_s"
    WPID=$pid_a
    wait_for_log_line "$WORK/$2.nullA.log" "READY" 60 || return 1
    WPID=$pid_b
    wait_for_log_line "$WORK/$2.nullB.log" "READY" 60 || return 1
    WPID=$pid_s
    wait_for_log_line "$WORK/$2.soft.log" "READY" 60 || return 1
    WPID=
    if [ "$3" != "unobserved" ]; then
        dur=$(( $5 + 120 ))
        man_args="--manifest $WORK/manifest-nullA.json --manifest $WORK/manifest-nullB.json --manifest $WORK/manifest-soft.json"
        case "$3" in
            inv-system|inv-system-keys)
                if [ "$3" = "inv-system-keys" ]; then key_args="--key-operations"; else key_args=""; fi
                # shellcheck disable=SC2086
                sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" inventory --system --capture native \
                    $man_args $key_args --duration "$dur" -o "$WORK/$2.json" \
                    > "$WORK/$2.obs.log" 2>&1 &
                SPID=$!
                wait_for_inv_ready "$WORK/$2.obs.log" "$ATTACH_TIMEOUT_S" || return 1
                if grep -q "attach failed" "$WORK/$2.obs.log"; then
                    echo "ATTACH FAILURE in $2:" >&2; cat "$WORK/$2.obs.log" >&2; return 1
                fi
                ukind=$(uprobe_kind "$WORK/$2.obs.log")
                echo "$ukind" > "$WORK/uprobe-kind.txt"
                wait_for_inv_pass "$WORK/$2.obs.log" "$PASS_TIMEOUT_S" || return 1
                sleep "$ADMIT_S"
                ;;
            metrics)
                # shellcheck disable=SC2086
                sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" profile --system --mode metrics \
                    $man_args --duration "$dur" -o "$WORK/$2.json" \
                    > "$WORK/$2.obs.log" 2>&1 &
                SPID=$!
                wait_for_observer_attach "$WORK/$2.obs.log" "$ATTACH_TIMEOUT_S" || return 1
                ukind=""
                ;;
            profile)
                # shellcheck disable=SC2086
                sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" profile --system --mode profile \
                    $man_args --duration "$dur" -o "$WORK/$2.json" \
                    > "$WORK/$2.obs.log" 2>&1 &
                SPID=$!
                wait_for_observer_attach "$WORK/$2.obs.log" "$ATTACH_TIMEOUT_S" || return 1
                ukind=""
                ;;
            trace)
                # shellcheck disable=SC2086
                sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" trace --system \
                    $man_args --duration "$dur" -o "$WORK/$2.txt" \
                    > "$WORK/$2.obs.log" 2>&1 &
                SPID=$!
                wait_for_observer_attach "$WORK/$2.obs.log" "$ATTACH_TIMEOUT_S" || return 1
                ukind=""
                ;;
            *) echo "$2: bad condition $3" >&2; return 1 ;;
        esac
        if grep -q "attach failed" "$WORK/$2.obs.log"; then
            echo "ATTACH FAILURE in $2:" >&2; cat "$WORK/$2.obs.log" >&2; return 1
        fi
    fi
    if [ "$BPF_STATS" = 1 ] && [ "$3" != "unobserved" ]; then
        BPF_PREV=$(sysctl -n kernel.bpf_stats_enabled 2>/dev/null || echo 0)
        BPF_DIRTY=1
        sudo -n sysctl -w kernel.bpf_stats_enabled=1 >/dev/null 2>&1 || true
        sudo -n bpftool prog show > "$WORK/$2.bpf_before.txt" 2>&1 || true
    fi
    if [ "$3" != "unobserved" ]; then cpu_window_begin "$2" || return 1; fi
    touch "$WORK/$2_gate"
    WPID=$pid_a
    wait_for_log_line "$WORK/$2.nullA.log" "MT_COUNT" $(( $5 + 180 )) || return 1
    WPID=$pid_b
    wait_for_log_line "$WORK/$2.nullB.log" "MT_COUNT" $(( $5 + 180 )) || return 1
    WPID=$pid_s
    wait_for_log_line "$WORK/$2.soft.log" "MT_COUNT" $(( $5 + 180 )) || return 1
    WPID=
    if [ "$3" != "unobserved" ]; then cpu_window_end "$2"; fi
    case "$3" in inv-system|inv-system-keys) sleep "$POST_SYS_S";; esac
    if [ "$3" != "unobserved" ]; then
        if [ "$BPF_STATS" = 1 ]; then
            sudo -n bpftool prog show > "$WORK/$2.bpf_after.txt" 2>&1 || true
            sudo -n sysctl -w kernel.bpf_stats_enabled="$BPF_PREV" >/dev/null 2>&1 || true
            BPF_DIRTY=0
        fi
        stop_observer "$2" || return 1
    fi
    case "$3" in inv-system|inv-system-keys)
        for p in $pid_a $pid_b $pid_s; do kill -CONT "$p" 2>/dev/null || true; done
        ;;
    esac
    for p in $pid_a $pid_b $pid_s; do
        if wait "$p"; then :; else status=$?; echo "$2 workload $p failed: $status" >&2; return "$status"; fi
    done
    CEIL_PIDS=
    info_a=$(python3 -I "$WORK/validate.py" mtlog "$WORK/$2.nullA.log") \
        || { echo "$2: nullA mt log invalid" >&2; return 1; }
    info_b=$(python3 -I "$WORK/validate.py" mtlog "$WORK/$2.nullB.log") \
        || { echo "$2: nullB mt log invalid" >&2; return 1; }
    info_s=$(python3 -I "$WORK/validate.py" mtlog "$WORK/$2.soft.log") \
        || { echo "$2: soft mt log invalid" >&2; return 1; }
    ops_a=$(echo "$info_a" | sed -n 's/ops=\([0-9]*\).*/\1/p')
    ops_b=$(echo "$info_b" | sed -n 's/ops=\([0-9]*\).*/\1/p')
    ops_s=$(echo "$info_s" | sed -n 's/ops=\([0-9]*\).*/\1/p')
    wall_a=$(echo "$info_a" | sed -n 's/.*wall_ns=\([0-9]*\).*/\1/p')
    wall_b=$(echo "$info_b" | sed -n 's/.*wall_ns=\([0-9]*\).*/\1/p')
    wall_s=$(echo "$info_s" | sed -n 's/.*wall_ns=\([0-9]*\).*/\1/p')
    total=$(( ops_a + ops_b + ops_s ))
    wall=$wall_a
    [ "$wall_b" -gt "$wall" ] && wall=$wall_b
    [ "$wall_s" -gt "$wall" ] && wall=$wall_s
    per="nullA=$ops_a nullB=$ops_b soft=$ops_s"
    if [ "$3" = "unobserved" ]; then
        record "$1" "ceil3x$4" "multi" "unobserved" "$ROUND" "$total" "$wall" 0 0 1 0 "n/a" "$per"
        return 0
    fi
    vstatus=0
    case "$3" in
        inv-system|inv-system-keys)
            reclaim_root_output "$WORK/$2.json"
            exp_a=$(( ops_a + 2*$4 + 1 )); exp_b=$(( ops_b + 2*$4 + 1 )); exp_s=$(( ops_s + 2*$4 + 1 ))
            info=$(python3 -I "$WORK/validate.py" invcheck "$WORK/$2.json" "$pid_a" "$WORK/nullA.so" "$exp_a" \
                2>"$WORK/$2.verdict_a") || vstatus=$?
            if [ "$vstatus" = 0 ]; then
                info="$info :: $(python3 -I "$WORK/validate.py" invcheck "$WORK/$2.json" "$pid_b" "$WORK/nullB.so" "$exp_b" \
                    2>"$WORK/$2.verdict_b")" || vstatus=$?
            fi
            if [ "$vstatus" = 0 ]; then
                info="$info :: $(python3 -I "$WORK/validate.py" invcheck "$WORK/$2.json" "$pid_s" "$MODULE" "$exp_s" \
                    2>"$WORK/$2.verdict_s")" || vstatus=$?
            fi
            loss=0; compl="n/a"
            keyline=$(grep -m1 "^key operations:" "$WORK/$2.obs.log" 2>/dev/null || echo "key operations: n/a")
            notes="uprobe=$ukind $per :: $info :: $keyline"
            ;;
        metrics|profile)
            reclaim_root_output "$WORK/$2.json"
            spec="C_GenerateRandom=$total,C_OpenSession=$((3*$4)),C_CloseSession=$((3*$4)),C_Finalize=3"
            info=$(python3 -I "$WORK/validate.py" profcheck "$WORK/$2.json" "$spec" 0 \
                2>"$WORK/$2.verdict") || vstatus=$?
            if [ "$vstatus" = 0 ]; then
                key_a=$(sha256sum "$WORK/nullA.so" | cut -d' ' -f1)
                key_b=$(sha256sum "$WORK/nullB.so" | cut -d' ' -f1)
                key_s=$(sha256sum "$MODULE" | cut -d' ' -f1)
                modinfo=$(python3 -I "$WORK/validate.py" profmodcheck "$WORK/$2.json" \
                    "$key_a=$((ops_a+2*$4+1)),$key_b=$((ops_b+2*$4+1)),$key_s=$((ops_s+2*$4+1))" \
                    2>"$WORK/$2.verdict_mod") || vstatus=$?
                info="$info :: $modinfo"
            fi
            loss=$(echo "$info" | sed -n 's/.*event_loss=\([^ ]*\).*/\1/p')
            compl=$(echo "$info" | sed -n 's/.*completeness=\([^ ]*\).*/\1/p')
            notes="$per :: $info"
            ;;
        trace)
            reclaim_root_output "$WORK/$2.txt"
            exp_total=$(( total + 3*(2*$4+1) ))
            info=$(python3 -I "$WORK/validate.py" tracecheck "$WORK/$2.txt" "$exp_total" \
                2>"$WORK/$2.verdict") || vstatus=$?
            loss=$(echo "$info" | sed -n 's/.*lost_markers=\([^ ]*\).*/\1/p')
            compl=$(echo "$info" | sed -n 's/.*completeness=\([^ ]*\).*/\1/p')
            bytes=$(wc -c < "$WORK/$2.txt")
            if [ "$bytes" -gt 52428800 ]; then
                head -c 1048576 "$WORK/$2.txt" > "$WORK/$2.txt.head"; rm -f "$WORK/$2.txt"
            fi
            notes="$per :: $info bytes=$bytes"
            ;;
    esac
    if [ "$vstatus" = 10 ]; then exact=0; notes="INVALID: $(cat "$WORK/$2.verdict"* 2>/dev/null | tr '\n' ';') :: $notes";
    elif [ "$vstatus" = 0 ]; then exact=1;
    else echo "$2: report validation failed" >&2; cat "$WORK/$2.verdict"* >&2; return 1; fi
    record "$1" "ceil3x$4" "multi" "$3" "$ROUND" "$total" "$wall" "$CPU_TICKS" "$CPU_RSS" \
        "$exact" "$loss" "$compl" "$notes"
}

if echo " $PARTS " | grep -q " ceiling "; then
echo "=== part ceiling ==="
CEIL_T="$CEIL_THREADS"
case " $CEIL_T " in *" $NPROC "*) ;; *) CEIL_T="$CEIL_T $NPROC" ;; esac
for t in $CEIL_T; do
    echo "--- ceiling 3 providers x mt$t ---"
    ROUND="ceil$t"
    sample_ceil ceiling "ceil-t$t-unobs" unobserved "$t" "$CEIL_SECS" || exit 1
    sample_ceil ceiling "ceil-t$t-invsys" inv-system "$t" "$CEIL_SECS" || exit 1
    sample_ceil ceiling "ceil-t$t-metrics" metrics "$t" "$CEIL_SECS" || exit 1
    sample_ceil ceiling "ceil-t$t-profile" profile "$t" 5 || exit 1
    sample_ceil ceiling "ceil-t$t-trace" trace "$t" 3 || exit 1
    sample_ceil ceiling "ceil-t$t-invkeys" inv-system-keys "$t" "$CEIL_SECS" || exit 1
done
fi

# wait_for_pid_exit <pid> <timeout_s>: bounded wait (kills on timeout).
wait_for_pid_exit() {
    wfpe_end=$(( $(date +%s) + $2 ))
    while kill -0 "$1" 2>/dev/null; do
        [ "$(date +%s)" -lt "$wfpe_end" ] || {
            echo "pid $1 still alive after $2s, killing" >&2
            kill -9 "$1" 2>/dev/null || true
            return 1
        }
        sleep 0.2
    done
    return 0
}

# maps_gated_stop <pid> <libbase> <timeout_s>: STOP the process once
# libbase is mapped (for inventory, whose endpoint attach needs the
# mapping observed in a scan). Callers LD_PRELOAD the provider so the
# mapping appears during the loader, before any PKCS#11 call is possible.
maps_gated_stop() {
    mgse_end=$(( $(date +%s) + $3 ))
    while ! grep -Fq "$2" /proc/$1/maps 2>/dev/null; do
        if ! kill -0 "$1" 2>/dev/null; then
            echo "pid $1 exited before $2 was mapped" >&2; return 1
        fi
        [ "$(date +%s)" -lt "$mgse_end" ] || {
            echo "pid $1 never mapped $2 within $3s" >&2; return 1
        }
        sleep 0.005
    done
    kill -STOP "$1" 2>/dev/null || { echo "STOP of $1 failed" >&2; return 1; }
}

# iters_for_cov <cov>: iterations from SPY_ITERS ("rand:30000 ecdsa:3000 ...").
iters_for_cov() {
    for kv in $SPY_ITERS; do
        case $kv in "$1:"*) echo "${kv#*:}"; return 0;; esac
    done
    echo "unknown coverage $1 in SPY_ITERS" >&2
    return 1
}
# primary_substr <cov>: p11perftest primary test-name substring.
primary_substr() {
    case $1 in
        rand) echo "C_GenerateRandom" ;;
        ecdsa) echo "secp256r1" ;;
        rsa) echo "rsa-2048" ;;
        aes) echo "CKM_AES_ECB) using aes-128" ;;
        *) echo "unknown coverage $1" >&2; return 1 ;;
    esac
}

# sample_spy <tag> <config> <cov> <threads>
# config: plain|inv-pid|metrics|trace|spy-file|spy-null. Observed configs
# STOP-start p11perftest so the observer covers the whole run; coverage
# is proven post-hoc (C_Initialize observed / edge counted).
sample_spy() {
    iters=$(iters_for_cov "$3") || return 1
    skip=$(( iters / 10 ))
    if [ "$skip" -lt 20 ]; then skip=20; fi
    substr=$(primary_substr "$3") || return 1
    case "$2" in
        plain|inv-pid|metrics|trace) mod="$MODULE"; spy_out="" ;;
        spy-file) mod="$SPY_SO"; spy_out="$WORK/$1.spy.log" ;;
        spy-null) mod="$SPY_SO"; spy_out="/dev/null" ;;
        *) echo "$1: bad spy config $2" >&2; return 1 ;;
    esac
    case "$2" in plain|spy-file|spy-null)
        T0=$(date +%s%N)
        env ${P11_LD_PATH:+LD_LIBRARY_PATH=$P11_LD_PATH} \
            ${spy_out:+PKCS11SPY=$MODULE} ${spy_out:+PKCS11SPY_OUTPUT=$spy_out} \
            "$P11PERFTEST" -l "$mod" -s 0 -p 1234 -t "$4" -i "$iters" --skip "$skip" \
            -v "$SPY_VEC" -c "$3" -j -o "$WORK/$1.p11t.json" > "$WORK/$1.p11t.log" 2>&1 \
            || { echo "$1: p11perftest failed" >&2; tail -5 "$WORK/$1.p11t.log" >&2; return 1; }
        T1=$(date +%s%N)
        CPU_TICKS=0; CPU_RSS=0
        ;;
    *)
        case "$2" in inv-pid) preload=1;; *) preload="";; esac
        env ${preload:+LD_PRELOAD=$MODULE} ${P11_LD_PATH:+LD_LIBRARY_PATH=$P11_LD_PATH} \
            "$P11PERFTEST" -l "$mod" -s 0 -p 1234 -t "$4" -i "$iters" --skip "$skip" \
            -v "$SPY_VEC" -c "$3" -j -o "$WORK/$1.p11t.json" > "$WORK/$1.p11t.log" 2>&1 &
        P11PID=$!
        WPID=$P11PID
        case "$2" in
            inv-pid) maps_gated_stop "$P11PID" "$(basename "$MODULE")" 60 || return 1;;
            *) kill -STOP "$P11PID" 2>/dev/null || { echo "$1: STOP failed" >&2; return 1; };;
        esac
        case "$2" in
            inv-pid)
                sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" inventory --pid "$P11PID" \
                    --capture native --manifest "$WORK/manifest-soft.json" --duration 600 \
                    -o "$WORK/$1.json" > "$WORK/$1.obs.log" 2>&1 &
                SPID=$!
                wait_for_inv_ready "$WORK/$1.obs.log" "$ATTACH_TIMEOUT_S" || return 1
                if grep -q "attach failed" "$WORK/$1.obs.log"; then
                    echo "ATTACH FAILURE in $1:" >&2; cat "$WORK/$1.obs.log" >&2; return 1
                fi
                ukind=$(uprobe_kind "$WORK/$1.obs.log")
                echo "$ukind" > "$WORK/uprobe-kind.txt"
                wait_for_inv_pass "$WORK/$1.obs.log" "$PASS_TIMEOUT_S" || return 1
                sleep "$ADMIT_S"
                is_inv=1
                ;;
            metrics)
                start_observer "$1" profile --manifest "$WORK/manifest-soft.json" --pid "$P11PID" \
                    --mode metrics --duration 600 -o "$WORK/$1.json" || return 1
                is_inv=0; ukind=""
                ;;
            trace)
                start_observer "$1" trace --manifest "$WORK/manifest-soft.json" --pid "$P11PID" \
                    --duration 600 -o "$WORK/$1.txt" || return 1
                is_inv=0; ukind=""
                ;;
        esac
        cpu_window_begin "$1" || return 1
        kill -CONT "$P11PID" 2>/dev/null || { echo "$1: CONT failed" >&2; return 1; }
        T0=$(date +%s%N)
        wait_for_pid_exit "$P11PID" 600 || return 1
        if wait "$P11PID"; then WPID=; else status=$?; WPID=; echo "$1: p11perftest failed: $status" >&2; return "$status"; fi
        T1=$(date +%s%N)
        cpu_window_end "$1"
        if [ "$is_inv" = 1 ]; then sleep "$POST_PID_S"; fi
        stop_observer "$1" || return 1
        ;;
    esac
    tpsinfo=$(python3 -I "$WORK/validate.py" p11tps "$WORK/$1.p11t.json" "$substr") \
        || { echo "$1: p11perftest json invalid" >&2; return 1; }
    tps=$(echo "$tpsinfo" | sed -n 's/.*tps=\([^ ]*\).*/\1/p')
    wall_ms=$(echo "$tpsinfo" | sed -n 's/.*wall_ms=\([^ ]*\).*/\1/p')
    headline_n=$(awk -v t="$tps" -v w="$wall_ms" 'BEGIN{printf "%d", t*w/1000}')
    headline_wall=$(awk -v w="$wall_ms" 'BEGIN{printf "%d", w*1000000}')
    case "$tps" in ''|*[!0-9.]*) echo "$1: bad tps '$tps'" >&2; return 1;; esac
    case "$wall_ms" in ''|*[!0-9.]*) echo "$1: bad wall '$wall_ms'" >&2; return 1;; esac
    if [ "$headline_n" -le 0 ] || [ "$headline_wall" -le 0 ]; then
        echo "$1: bad headline n=$headline_n wall=$headline_wall" >&2; return 1
    fi
    notes="tps=$tps run_wall_ns=$((T1-T0)) $tpsinfo"
    exact=1
    case "$2" in
        spy-file)
            spyinfo=$(python3 -I "$WORK/validate.py" spycount "$WORK/$1.spy.log") \
                || { echo "$1: spy log invalid" >&2; return 1; }
            notes="$notes :: spy $spyinfo"
            ;;
        inv-pid)
            reclaim_root_output "$WORK/$1.json"
            info=$(python3 -I "$WORK/validate.py" invcount "$WORK/$1.json" "$P11PID" "$MODULE") \
                || { echo "$1: invcount failed" >&2; return 1; }
            semline=$(grep -m1 "semantic calls:" "$WORK/$1.obs.log" 2>/dev/null || echo "semantic calls: n/a")
            notes="$notes :: uprobe=$ukind obs $info :: $semline"
            case "$info" in *"state=counted"*) ;; *) exact=0;; esac
            ;;
        metrics)
            reclaim_root_output "$WORK/$1.json"
            info=$(python3 -I "$WORK/validate.py" proftotals "$WORK/$1.json") \
                || { echo "$1: proftotals failed" >&2; return 1; }
            notes="$notes :: obs $info"
            case "$info" in *"init=0 "*) exact=0; notes="$notes PARTIAL-COVERAGE";; esac
            ;;
        trace)
            reclaim_root_output "$WORK/$1.txt"
            info=$(python3 -I "$WORK/validate.py" tracetotal "$WORK/$1.txt") \
                || { echo "$1: tracetotal failed" >&2; return 1; }
            bytes=$(wc -c < "$WORK/$1.txt")
            if grep -q "C_Initialize" "$WORK/$1.txt" 2>/dev/null; then init_seen=1; else init_seen=0; fi
            if [ "$bytes" -gt 52428800 ]; then
                head -c 1048576 "$WORK/$1.txt" > "$WORK/$1.txt.head"; rm -f "$WORK/$1.txt"
            fi
            notes="$notes :: obs $info bytes=$bytes init_seen=$init_seen"
            if [ "$init_seen" = 0 ]; then exact=0; notes="$notes PARTIAL-COVERAGE"; fi
            ;;
    esac
    record "spy" "spy-$3-t$4" "$(basename "$mod")" "$2" 1 "$headline_n" "$headline_wall" \
        "$CPU_TICKS" "$CPU_RSS" "$exact" 0 "n/a" "$notes"
}

# tool_bg <tool> <tag>: start one CLI-tool signing op in background;
# sets TOOLOP_PID to the TOOL's pid (the leaf command is backgrounded
# directly: $! of a backgrounded function would be a subshell). The
# provider is LD_PRELOADed so it is mapped from birth (tool_k needs the
# mapping present for the attach scan); preloading adds no PKCS#11 calls.
tool_bg() {
    case $1 in
        pkcs11-tool)
            LD_PRELOAD="$MODULE" pkcs11-tool --module "$MODULE" --login --pin 1234 --sign \
                --mechanism SHA256-HMAC --label hmackey \
                --input-file "$WORK/tool-data.bin" --output-file "$WORK/$2.sig" \
                > "$WORK/$2.op.log" 2>&1 &
            TOOLOP_PID=$!
            ;;
        p11tool)
            LD_PRELOAD="$MODULE" p11tool --provider "$MODULE" --login --set-pin=1234 --test-sign \
                --hash=SHA256 --outfile="$WORK/$2.sig" \
                "pkcs11:token=v070bench;object=rsakey;type=private" < /dev/null \
                > "$WORK/$2.op.log" 2>&1 &
            TOOLOP_PID=$!
            ;;
    esac
}
# tool_k <tool>: PKCS#11 calls per tool op, via one STOP-started trace.
tool_k() {
    tool_bg "$1" "toolk-$1"
    TOOLPID=$TOOLOP_PID
    WPID=$TOOLPID
    maps_gated_stop "$TOOLPID" "$(basename "$MODULE")" 60 || return 1
    sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" trace --manifest "$WORK/manifest-soft.json" \
        --pid "$TOOLPID" --duration 120 -o "$WORK/toolk-$1.txt" \
        > "$WORK/toolk-$1.obs.log" 2>&1 &
    SPID=$!
    wait_for_observer_attach "$WORK/toolk-$1.obs.log" "$ATTACH_TIMEOUT_S" || return 1
    kill -CONT "$TOOLPID" 2>/dev/null || { echo "toolk-$1: CONT failed" >&2; return 1; }
    wait_for_pid_exit "$TOOLPID" 120 || return 1
    if wait "$TOOLPID"; then WPID=; else status=$?; WPID=; echo "toolk-$1: tool failed: $status" >&2; return "$status"; fi
    stop_observer "toolk-$1" || return 1
    reclaim_root_output "$WORK/toolk-$1.txt"
    info=$(python3 -I "$WORK/validate.py" tracetotal "$WORK/toolk-$1.txt") \
        || { echo "toolk-$1: tracetotal failed" >&2; return 1; }
    echo "$info" | sed -n 's/raw_calls=\([^ ]*\).*/\1/p'
}

# sample_toolloop <tag> <tool> <mode:unobserved|inv-system>
sample_toolloop() {
    n=${TOOL_N:-50}
    if [ "$3" = "inv-system" ]; then
        sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" inventory --system --capture native \
            --manifest "$WORK/manifest-soft.json" --duration 600 -o "$WORK/$1.json" \
            > "$WORK/$1.obs.log" 2>&1 &
        SPID=$!
        wait_for_inv_ready "$WORK/$1.obs.log" "$ATTACH_TIMEOUT_S" || return 1
        ukind=$(uprobe_kind "$WORK/$1.obs.log")
        echo "$ukind" > "$WORK/uprobe-kind.txt"
        wait_for_inv_pass "$WORK/$1.obs.log" "$PASS_TIMEOUT_S" || return 1
        sleep "$ADMIT_S"
        cpu_window_begin "$1" || return 1
    fi
    T0=$(date +%s%N)
    TOOLPIDS=""
    i=1
    while [ "$i" -le "$n" ]; do
        tool_bg "$2" "$1"
        oppid=$TOOLOP_PID
        WPID=$oppid
        if [ -z "$TOOLPIDS" ]; then TOOLPIDS="$oppid"; else TOOLPIDS="$TOOLPIDS,$oppid"; fi
        if wait "$oppid"; then WPID=; else status=$?; WPID=; echo "$1: tool op $i failed: $status" >&2; return "$status"; fi
        i=$((i + 1))
    done
    WPID=
    T1=$(date +%s%N)
    if [ "$3" = "inv-system" ]; then
        cpu_window_end "$1"
        sleep "$POST_SYS_S"
        stop_observer "$1" || return 1
        reclaim_root_output "$WORK/$1.json"
    else
        CPU_TICKS=0; CPU_RSS=0
    fi
    if [ "$3" = "inv-system" ]; then
        vstatus=0
        info=$(python3 -I "$WORK/validate.py" invsumcheck "$WORK/$1.json" "$MODULE" \
            $(( n * TOOLK )) "$TOOLPIDS") 2>"$WORK/$1.verdict" || vstatus=$?
        semline=$(grep -m1 "semantic calls:" "$WORK/$1.obs.log" 2>/dev/null || echo "semantic calls: n/a")
        notes="uprobe=$ukind $info K=$TOOLK :: $semline"
        if [ "$vstatus" = 10 ]; then exact=0; notes="INVALID: $(cat "$WORK/$1.verdict") :: $notes";
        elif [ "$vstatus" = 0 ]; then exact=1;
        else echo "$1: report validation failed" >&2; cat "$WORK/$1.verdict" >&2; return 1; fi
    else
        exact=1; notes=""
    fi
    record "spy" "tool-$2" "$(basename "$MODULE")" "$3" 1 "$n" "$((T1-T0))" \
        "$CPU_TICKS" "$CPU_RSS" "$exact" 0 "n/a" "$notes"
}

if echo " $PARTS " | grep -q " spy "; then
echo "=== part spy ==="
SPY_THREADS="$SPY_THREADS_BASE"
case " $SPY_THREADS " in *" $NPROC "*) ;; *) SPY_THREADS="$SPY_THREADS $NPROC" ;; esac
echo "threads: $SPY_THREADS coverages: $SPY_COV"
for cov in $SPY_COV; do
    for t in $SPY_THREADS; do
        echo "--- spy $cov threads=$t ---"
        ROUND="spy-$cov-t$t"
        if want_spy plain; then sample_spy "spy-$cov-t$t-plain" plain "$cov" "$t" || exit 1; fi
        if want_spy inv-pid; then sample_spy "spy-$cov-t$t-invpid" inv-pid "$cov" "$t" || exit 1; fi
        if want_spy metrics; then sample_spy "spy-$cov-t$t-metrics" metrics "$cov" "$t" || exit 1; fi
        if want_spy trace; then sample_spy "spy-$cov-t$t-trace" trace "$cov" "$t" || exit 1; fi
        if want_spy spy-file; then sample_spy "spy-$cov-t$t-spyfile" spy-file "$cov" "$t" || exit 1; fi
        if want_spy spy-null; then sample_spy "spy-$cov-t$t-spynull" spy-null "$cov" "$t" || exit 1; fi
    done
done
if want_spy tool; then
echo "--- spy tool loops ---"
echo "tool loop input data" > "$WORK/tool-data.bin"
pkcs11-tool --module "$MODULE" --login --pin 1234 --keygen --key-type generic:32 \
    --label hmackey --usage-sign > "$WORK/tool-keygen.log" 2>&1 \
    || { echo "tool hmackey keygen failed" >&2; tail -3 "$WORK/tool-keygen.log" >&2; exit 1; }
pkcs11-tool --module "$MODULE" --login --pin 1234 --keypairgen --key-type rsa:2048 \
    --label rsakey --usage-sign > "$WORK/tool-keypairgen.log" 2>&1 \
    || { echo "tool rsakey keypairgen failed" >&2; tail -3 "$WORK/tool-keypairgen.log" >&2; exit 1; }
for tool in pkcs11-tool p11tool; do
    tool_k "$tool" > "$WORK/toolk-$tool.K" || exit 1
    TOOLK=$(cat "$WORK/toolk-$tool.K")
    case "$TOOLK" in ''|*[!0-9]*) echo "tool $tool: bad K '$TOOLK'" >&2; exit 1;; esac
    echo "tool $tool: K=$TOOLK calls/op"
    ROUND="tool-$tool"
    sample_toolloop "spy-tool-$tool-unobs" "$tool" unobserved || exit 1
    sample_toolloop "spy-tool-$tool-invsys" "$tool" inv-system || exit 1
done
fi
fi

echo "=== results: $RESULTS ==="
if [ -f "$WORK/uprobe-kind.txt" ]; then echo "uprobe kind: $(cat "$WORK/uprobe-kind.txt")"; fi
cat "$RESULTS"
if echo " $PARTS " | grep -q " percall " && [ "$INVALID_TOTAL" -gt 0 ]; then
    echo "bench-v070-overhead: FAILED: $INVALID_TOTAL percall sample(s) had unequal coverage" >&2
    exit 1
fi
echo "=== bench-v070-overhead: DONE ==="

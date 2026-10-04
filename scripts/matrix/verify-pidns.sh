#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# verify-pidns.sh P11SCOPE OUTDIR — nested PID namespace honesty cells (DR-K8S-1/2).
#
# BPF numbers every task by its initial-namespace tgid (`bpf_get_current_pid_tgid`);
# an observer in a nested PID namespace (a kind/k3d node, an observer container
# without the host PID namespace) numbers the same task differently. This
# reproduces that without kind: the ledgered target and the observer both run
# inside `unshare --pid --fork --mount-proc`, so the observer sees nested PIDs
# while BPF sees initial-namespace PIDs.
#
# Cells (each appends one JSON line to OUTDIR/results.jsonl):
#   host-pid       control, no unshare: `profile --pid` counts exactly 6 x ITERS
#                  and reads `pid_namespace.observer: initial` (no false positive)
#   nested-pid     `profile --pid <nested pid>` inside the namespace: must be an
#                  explicit refusal naming `pid-namespace-mismatch` (before the
#                  fix: a silent zero that claimed exact observation)
#   nested-run     `run` inside the namespace: the same refusal, before any fork
#   nested-inventory-pid  `inventory --pid`: the same refusal
#   nested-doctor-pid     `doctor --pid`: the `PID namespace` row FAILs, exit 1
#   nested-cgroup  `profile --cgroup` inside the namespace: exact counts, but the
#                  observation is `lossy` with cause `pid_namespace`, never exact,
#                  and `completeness` stays PARTIAL even behind a proven drain
#   foreign-proc   an initial-namespace observer with a child namespace's /proc
#                  (`nsenter -m` without -p), `profile --pid <pid that /proc
#                  shows>`: the same named refusal (before the review fix: a
#                  silent zero), and doctor's PID namespace row names `foreign`
#   foreign-proc-system  the same observer, `profile --system`: that /proc has
#                  no entry for the observer, so it cannot read its own
#                  /proc/self; refused by name before discovery or the
#                  uretprobe self-probe, never pointed at the uretprobe
#                  override (DR-RETRO-PIDNS-2)
#   nested-trace   `trace --cgroup` inside the namespace: every call line, the
#                  printed PIDs are initial-namespace PIDs and the EVIDENCE line
#                  names the observer's namespace as `nested`
# Runs as root (sudo on a host). Workloads run as RUNUID/RUNGID (default 1000)
# against SoftHSM2 with an independent exact call ledger (public-cli/gated.c).
set -u
if [ "${1-}" = --inside ]; then INSIDE=1; shift; else INSIDE=0; fi
P=$(realpath -e "$1"); OUT=$2
SELF=$(realpath -e "$0")
SRC=$(cd "$(dirname "$SELF")/../../tests/fixtures/public-cli" && pwd) || exit 64
MODULE=${MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}
RUNUID=${RUNUID:-1000}; RUNGID=${RUNGID:-1000}
ITERS=${ITERS:-100}
[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 64; }
CG=/sys/fs/cgroup/p11scope-verify-pidns-$$

asuser() { exec setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups env SOFTHSM2_CONF="$OUT/softhsm2.conf" "$@"; }
result() { python3 -c 'import json,sys; print(json.dumps({"cell":sys.argv[1],"pass":sys.argv[2]=="1","detail":json.loads(sys.argv[3])}))' "$1" "$2" "$3" | tee -a "$OUT/results.jsonl"; }
waitfor() { local f=$1 pat=$2 t=${3:-60}; for _ in $(seq $((t*10))); do grep -qa -- "$pat" "$f" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

# Summarize a profile report as JSON: sorted call counts plus the honesty fields.
summ() { python3 - "$1" <<'PY'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception as e: print(json.dumps({"error":str(e)})); sys.exit()
e=d.get("evidence",{}); o=e.get("gap_classes",{}).get("observation",{})
print(json.dumps({"calls":sorted(f["calls"] for f in d.get("functions",[]) if f.get("calls")),
 "observation":o.get("status"),"causes":o.get("causes"),"verdict_detail":e.get("verdict_detail"),
 "pid_namespace":e.get("pid_namespace"),"completeness":e.get("completeness"),
 "drain_proven":e.get("drain_proven")}))
PY
}

# gated capture: $1=cell $2..=p11scope args before -o (@PID@ = the workload pid as
# this shell numbers it, @CG@ = the workload's cgroup)
gated() {
  local cell=$1; shift; local gate=$OUT/$cell.gate; rm -f "$gate"
  local cg=$CG-$cell
  mkdir "$cg" || return 1
  ( echo $BASHPID > "$cg/cgroup.procs"; asuser "$FIX/gated" "$MODULE" "$ITERS" 200 "$gate" ) > "$OUT/$cell.wl" 2>&1 & local wl=$!
  waitfor "$OUT/$cell.wl" READY 30 || { echo "workload not ready" > "$OUT/$cell.stderr"; kill $wl; rmdir "$cg"; return 1; }
  local args=("${@//@PID@/$wl}"); args=("${args[@]//@CG@/$cg}")
  "$P" "${args[@]}" > "$OUT/$cell.stdout" 2> "$OUT/$cell.stderr" & local pp=$!
  # Release the ledgered calls only once probes are attached, or once the
  # observer has already exited (a refusal).
  for _ in $(seq 1800); do
    grep -qa "p11scope: capturing:" "$OUT/$cell.stderr" 2>/dev/null && break
    kill -0 $pp 2>/dev/null || break
    sleep 0.1
  done
  sleep 0.5; touch "$gate"
  waitfor "$OUT/$cell.wl" LEDGER 60 || true; wait $pp; echo $? > "$OUT/$cell.rc"
  kill -TERM $wl 2>/dev/null; wait $wl 2>/dev/null
  rmdir "$cg" 2>/dev/null || true
}

refusal_detail() { python3 - "$@" <<'PY'
import json,sys
cell,out=sys.argv[1],sys.argv[2]
rc=open(f"{out}/{cell}.rc").read().strip() if len(sys.argv) < 4 else sys.argv[3]
err=open(f"{out}/{cell}.stderr",errors="replace").read()
print(json.dumps({"rc":int(rc),"named":"pid-namespace-mismatch" in err,
 "stderr_tail":err.strip().splitlines()[-1:] if err.strip() else [],
 "report_written":__import__("os").path.exists(f"{out}/{cell}.json")}))
PY
}

if [ $INSIDE = 1 ]; then
  FIX=$OUT/fix
  echo "inside: pid of this shell in the new namespace is $$; ns $(readlink /proc/self/ns/pid)" >&2
  # nested-pid
  gated nested-pid profile --pid @PID@ --duration 8 -o "$OUT/nested-pid.json"
  d=$(refusal_detail nested-pid "$OUT")
  if [ -s "$OUT/nested-pid.json" ]; then d=$(python3 -c 'import json,sys; a=json.loads(sys.argv[1]); a["report"]=json.loads(sys.argv[2]); print(json.dumps(a))' "$d" "$(summ "$OUT/nested-pid.json")"); fi
  result nested-pid $(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(1 if d["rc"]!=0 and d["named"] and not d["report_written"] else 0)' "$d") "$d"
  # nested-run
  SUDO_UID=$RUNUID SUDO_GID=$RUNGID SOFTHSM2_CONF=$OUT/softhsm2.conf "$P" run -o "$OUT/nested-run.json" -- "$FIX/gated" "$MODULE" 3 0 - > "$OUT/nested-run.stdout" 2> "$OUT/nested-run.stderr"; rc=$?
  d=$(refusal_detail nested-run "$OUT" $rc)
  if [ -s "$OUT/nested-run.json" ]; then d=$(python3 -c 'import json,sys; a=json.loads(sys.argv[1]); a["report"]=json.loads(sys.argv[2]); print(json.dumps(a))' "$d" "$(summ "$OUT/nested-run.json")"); fi
  result nested-run $(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(1 if d["rc"]!=0 and d["named"] and not d["report_written"] else 0)' "$d") "$d"
  # nested-inventory-pid: the same named refusal, before any scan
  "$P" inventory --pid $$ --json > "$OUT/nested-inventory-pid.stdout" 2> "$OUT/nested-inventory-pid.stderr"; rc=$?
  d=$(refusal_detail nested-inventory-pid "$OUT" $rc)
  result nested-inventory-pid $(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(1 if d["rc"]!=0 and d["named"] else 0)' "$d") "$d"
  # nested-doctor-pid: the PID namespace row FAILs a requested --pid lane
  "$P" doctor --pid $$ > "$OUT/nested-doctor-pid.out" 2>&1; rc=$?
  d=$(python3 - "$OUT/nested-doctor-pid.out" $rc <<'PY'
import json,sys
text=open(sys.argv[1],errors="replace").read().splitlines()
row=[l for l in text if l.startswith("PID namespace ")]
print(json.dumps({"rc":int(sys.argv[2]),"row":row,"tier":[l for l in text if l.startswith("capability tier")],
 "verdict":[l for l in text if l.startswith("verdict:")]}))
PY
)
  result nested-doctor-pid $(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(1 if d["rc"]==1 and d["row"] and "FAIL" in d["row"][0] and "pid-namespace-mismatch" in d["row"][0] and "PID scope unavailable" in d["verdict"][0] else 0)' "$d") "$d"
  # nested-cgroup
  gated nested-cgroup profile --cgroup @CG@ --duration 10 -o "$OUT/nested-cgroup.json"
  s=$(summ "$OUT/nested-cgroup.json")
  result nested-cgroup $(python3 -c 'import json,sys; s=json.loads(sys.argv[1]); n=int(sys.argv[2]); print(1 if s.get("calls")==[n]*6 and s.get("observation")=="lossy" and "pid_namespace" in (s.get("causes") or []) and (s.get("pid_namespace") or {}).get("observer")=="nested" and s.get("completeness")=="PARTIAL" else 0)' "$s" $ITERS) "$(python3 -c 'import json,sys; s=json.loads(sys.argv[1]); s["rc"]=int(open(sys.argv[2]).read()); print(json.dumps(s))' "$s" "$OUT/nested-cgroup.rc")"
  # nested-trace
  gated nested-trace trace --cgroup @CG@ --duration 10 -o "$OUT/nested-trace.txt"
  d=$(python3 - "$OUT" "$ITERS" <<'PY'
import json,re,sys
out,n=sys.argv[1],int(sys.argv[2])
text=open(f"{out}/nested-trace.txt",errors="replace").read()
lines=[l for l in text.splitlines() if " → " in l]
pids=sorted({int(m.group(1)) for l in lines for m in [re.search(r" pid (\d+) tid ",l)] if m})
ev=[json.loads(l[len("EVIDENCE "):]) for l in text.splitlines() if l.startswith("EVIDENCE ")]
wl=open(f"{out}/nested-trace.wl").read()
nested=int(re.search(r"READY pid=(\d+)",wl).group(1))
print(json.dumps({"call_lines":len(lines),"expected":6*n,"printed_pids":pids,"workload_nested_pid":nested,
 "pid_namespace":ev[-1].get("pid_namespace") if ev else None,
 "observation":ev[-1].get("gap_classes",{}).get("observation") if ev else None,
 "rc":int(open(f"{out}/nested-trace.rc").read())}))
PY
)
  result nested-trace $(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(1 if d["call_lines"]==d["expected"] and d["printed_pids"] and d["workload_nested_pid"] not in d["printed_pids"] and (d["pid_namespace"] or {}).get("observer")=="nested" and (d["pid_namespace"] or {}).get("kernel_pids")=="initial" else 0)' "$d") "$d"
  exit 0
fi

mkdir -p "$OUT" && chmod 755 "$OUT" && OUT=$(realpath -e "$OUT") && cd "$OUT" || exit 64
FIX=$OUT/fix; mkdir -p "$FIX"
gcc -O1 -o "$FIX/gated" "$SRC/gated.c" -ldl || { echo "fixture build failed" >&2; exit 65; }
chmod 755 "$FIX" "$FIX/gated"
: > results.jsonl
rm -rf tokens; mkdir -p tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$OUT" > softhsm2.conf
SOFTHSM2_CONF=$OUT/softhsm2.conf softhsm2-util --init-token --free --label pidns --so-pin 5678 --pin 1234 >/dev/null || { echo "token init failed" >&2; exit 65; }
chown -R "$RUNUID:$RUNGID" tokens; chmod 644 softhsm2.conf

# host-pid control
gated host-pid profile --pid @PID@ --duration 8 -o "$OUT/host-pid.json"
s=$(summ "$OUT/host-pid.json")
result host-pid $(python3 -c 'import json,sys; s=json.loads(sys.argv[1]); n=int(sys.argv[2]); print(1 if s.get("calls")==[n]*6 and s.get("observation")=="exact" and (s.get("pid_namespace") or {}).get("observer")=="initial" else 0)' "$s" $ITERS) "$(python3 -c 'import json,sys; s=json.loads(sys.argv[1]); s["rc"]=int(open(sys.argv[2]).read()); print(json.dumps(s))' "$s" "$OUT/host-pid.rc")"

# foreign-proc: an initial-namespace observer whose /proc is another
# namespace's (`nsenter -t <pid> -m` without -p). The ledgered target runs in
# a child PID namespace with its own /proc; the observer joins only that
# mount namespace and names the target by the PID that /proc shows.
rm -f "$OUT/foreign.gate" "$OUT/foreign.pid"
unshare --pid --fork --mount-proc bash -c '
  ( exec setpriv --reuid="$1" --regid="$2" --clear-groups env SOFTHSM2_CONF="$3/softhsm2.conf" "$3/fix/gated" "$4" "$5" 200 "$3/foreign.gate" ) > "$3/foreign.wl" 2>&1 &
  echo $! > "$3/foreign.pid"; wait' foreign "$RUNUID" "$RUNGID" "$OUT" "$MODULE" "$ITERS" & ns_wrap=$!
waitfor "$OUT/foreign.wl" READY 30
inner=$(pgrep -P "$ns_wrap" | head -1)
NPID=$(cat "$OUT/foreign.pid")
nsenter -t "$inner" -m "$P" profile --pid "$NPID" --duration 8 -o "$OUT/foreign-proc.json" > "$OUT/foreign-proc.stdout" 2> "$OUT/foreign-proc.stderr" & pp=$!
for _ in $(seq 1800); do
  grep -qa "p11scope: capturing:" "$OUT/foreign-proc.stderr" 2>/dev/null && break
  kill -0 $pp 2>/dev/null || break
  sleep 0.1
done
sleep 0.5; touch "$OUT/foreign.gate"; waitfor "$OUT/foreign.wl" LEDGER 60 || true
wait $pp; echo $? > "$OUT/foreign-proc.rc"
nsenter -t "$inner" -m "$P" doctor > "$OUT/foreign-doctor.out" 2>&1; frc=$?
nsenter -t "$inner" -m "$P" profile --system --duration 3 -o "$OUT/foreign-proc-system.json" > "$OUT/foreign-proc-system.stdout" 2> "$OUT/foreign-proc-system.stderr"; echo $? > "$OUT/foreign-proc-system.rc"
pkill -TERM -P "$inner" 2>/dev/null; wait $ns_wrap 2>/dev/null
d=$(refusal_detail foreign-proc "$OUT")
if [ -s "$OUT/foreign-proc.json" ]; then d=$(python3 -c 'import json,sys; a=json.loads(sys.argv[1]); a["report"]=json.loads(sys.argv[2]); print(json.dumps(a))' "$d" "$(summ "$OUT/foreign-proc.json")"); fi
d=$(python3 -c 'import json,sys; a=json.loads(sys.argv[1]); a["nested_target_pid"]=int(sys.argv[2]); a["doctor_rc"]=int(sys.argv[3]); a["doctor_row"]=[l for l in open(sys.argv[4]) if l.startswith("PID namespace ")]; print(json.dumps(a))' "$d" "$NPID" "$frc" "$OUT/foreign-doctor.out")
result foreign-proc $(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(1 if d["rc"]!=0 and d["named"] and not d["report_written"] and d["doctor_row"] and "foreign" in d["doctor_row"][0] else 0)' "$d") "$d"
d=$(refusal_detail foreign-proc-system "$OUT")
result foreign-proc-system $(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); t=" ".join(d["stderr_tail"]); print(1 if d["rc"]!=0 and d["named"] and not d["report_written"] and "no entry for this observer" in t and "allow-uretprobe" not in t else 0)' "$d") "$d"

unshare --pid --fork --mount-proc "$SELF" --inside "$P" "$OUT"
python3 -c 'import json; r=[json.loads(l) for l in open("results.jsonl")]; print("SUMMARY pass=%d fail=%d failed=%s" % (sum(x["pass"] for x in r), sum(not x["pass"] for x in r), [x["cell"] for x in r if not x["pass"]]))' | tee summary.txt

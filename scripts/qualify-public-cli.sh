#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# qualify-public-cli.sh P11SCOPE OUTDIR — public-command qualification cells.
# The shipped binary is exercised exactly as an operator would, against ledgered
# SoftHSM2 workloads (tests/fixtures/public-cli/*.c, compiled into OUTDIR/fix):
# exact per-function counts for profile/metrics/trace --pid, real function names,
# a truthful verdict, run of a short-lived child, a 12-thread exactness cell,
# --system admission of the real provider, SIGINT publication and -o FIFO refusal.
# Runs as root (sudo on a host, root inside a vng guest). Workloads run as RUNUID/RUNGID
# (default 1000) against SoftHSM2 with an independent exact call ledger. Every cell appends
# one JSON line to OUTDIR/results.jsonl: {"cell","pass","detail"}.
set -u
P=$(realpath -e "$1"); OUT=$2
SRC=$(cd "$(dirname "$0")/../tests/fixtures/public-cli" && pwd) || exit 64
MODULE=${MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}
RUNUID=${RUNUID:-1000}; RUNGID=${RUNGID:-1000}
ITERS=${ITERS:-500}; THREADS=${THREADS:-$(nproc)}
[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 64; }
mkdir -p "$OUT" && chmod 755 "$OUT" && OUT=$(realpath -e "$OUT") && cd "$OUT" || exit 64
FIX=$OUT/fix; mkdir -p "$FIX"
gcc -O1 -o "$FIX/gated" "$SRC/gated.c" -ldl && gcc -O2 -o "$FIX/mt" "$SRC/mt.c" -ldl -lpthread || { echo "fixture build failed" >&2; exit 65; }
chmod 755 "$FIX" "$FIX/gated" "$FIX/mt"
: > results.jsonl
export SOFTHSM2_CONF=$OUT/softhsm2.conf
rm -rf tokens; mkdir -p tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$OUT" > softhsm2.conf
softhsm2-util --init-token --free --label qual --so-pin 5678 --pin 1234 >/dev/null || { echo "token init failed" >&2; exit 65; }
chown -R "$RUNUID:$RUNGID" tokens; chmod 644 softhsm2.conf
# Positive control: a reset background SIGINT must be deliverable here (exit 130).
env --default-signal=INT sh -c 'kill -INT $$' >/dev/null 2>&1 & wait $!
[ $? = 130 ] || { echo "positive control failed: background SIGINT not deliverable (env --default-signal needs coreutils >= 8.31)" >&2; exit 65; }
asuser() { exec setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups env SOFTHSM2_CONF="$SOFTHSM2_CONF" "$@"; }
result() { python3 -c 'import json,sys; print(json.dumps({"cell":sys.argv[1],"pass":sys.argv[2]=="1","detail":sys.argv[3]}))' "$1" "$2" "$3" | tee -a results.jsonl; }
waitfor() { local f=$1 pat=$2 t=${3:-60}; for _ in $(seq $((t*10))); do grep -qa -- "$pat" "$f" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
# Summarize a report: per-row calls/names + evidence fields, as JSON on stdout.
summ() { python3 - "$1" <<'PY'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception as e: print(json.dumps({"error":str(e)})); sys.exit()
e=d.get("evidence",{})
rows=[{"calls":f["calls"],"names":f.get("names"),"path":None} for f in d.get("functions",[]) if f.get("calls")]
print(json.dumps({"rows":rows,"completeness":e.get("completeness"),"verdict_detail":e.get("verdict_detail"),
 "in_flight_at_end":e.get("in_flight_at_end"),"event_loss":e.get("event_loss"),"modules":[m.get("path") for m in d.get("capture",{}).get("modules",[])]}))
PY
}
# gated capture: $1=cell $2..=p11scope args before -o (pid substituted for @PID@)
gated() {
  local cell=$1; shift; local gate=$OUT/$cell.gate; rm -f "$gate"
  asuser "$FIX/gated" "$MODULE" "$ITERS" 200 "$gate" > $cell.wl 2>&1 & local wl=$!
  waitfor $cell.wl READY 30 || { result $cell 0 "workload not ready"; kill $wl; return; }
  local args=("${@//@PID@/$wl}")
  "$P" "${args[@]}" > $cell.stdout 2> $cell.stderr & local pp=$!
  # The product prints one readiness line once probes are attached and the
  # loop runs; only then may the ledgered calls start.
  waitfor $cell.stderr "p11scope: capturing:" 180 || true; sleep 0.5; touch "$gate"
  waitfor $cell.wl LEDGER 60 || true; wait $pp; local rc=$?
  kill -TERM $wl 2>/dev/null; wait $wl 2>/dev/null
  echo $rc > $cell.rc
}
exact6() { python3 - "$1" "$2" <<'PY'
import json,sys
s=json.loads(sys.argv[1]); n=int(sys.argv[2]); c=sorted(r["calls"] for r in s.get("rows",[]))
ok = c.count(n)==6 and all(x==n for x in c)
print("1" if ok else "0")
PY
}
# 1 doctor
"$P" doctor > doctor.out 2>&1; rc=$?; result doctor $([ $rc = 0 ] && grep -q 'capture available' doctor.out && echo 1 || echo 0) "rc=$rc $(grep -a verdict doctor.out)"
# 2 profile --pid exact
gated profile-pid profile --pid @PID@ --duration 12 -o $OUT/profile-pid.json; s=$(summ profile-pid.json)
result profile-pid $(exact6 "$s" $ITERS) "rc=$(cat profile-pid.rc) ledger=$ITERS x6 $s"
# 2b names and verdict on the clean pid capture (GT-2/GT-3)
python3 - "$OUT/profile-pid.json" "$ITERS" > names.out 2>&1 <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); n=int(sys.argv[2])
want={"C_GenerateRandom","C_DigestInit","C_Digest","C_FindObjectsInit","C_FindObjects","C_FindObjectsFinal"}
got={nm for f in d["functions"] if f["calls"]==n for nm in f.get("names",[])}
print("NAMES_OK" if got==want else "NAMES_BAD", sorted(got))
print("VERDICT", d["evidence"].get("verdict_detail"))
PY
result names-pid $(grep -q NAMES_OK names.out && echo 1 || echo 0) "$(tr '\n' ' ' < names.out)"
result verdict-pid $(grep -q 'VERDICT concrete_gap' names.out && echo 0 || echo 1) "$(grep VERDICT names.out)"
# 3 metrics exact
gated metrics-pid profile --mode metrics --pid @PID@ --duration 12 -o $OUT/metrics-pid.json; s=$(summ metrics-pid.json)
result metrics-pid $(exact6 "$s" $ITERS) "rc=$(cat metrics-pid.rc) $s"
# 4 trace exact line count
gated trace-pid trace --pid @PID@ --duration 12 -o $OUT/trace-pid.txt
lines=$(grep -ac ' → ' trace-pid.txt 2>/dev/null); result trace-pid $([ "${lines:-0}" = $((ITERS*6)) ] && echo 1 || echo 0) "rc=$(cat trace-pid.rc) call_lines=$lines expected=$((ITERS*6)) sample=$(grep -a ' → ' trace-pid.txt | head -1)"
# 5 run short-lived child (GT-1)
SUDO_UID=$RUNUID SUDO_GID=$RUNGID "$P" run --pause auto -o $OUT/run-short.json -- "$FIX/gated" "$MODULE" 3 0 - > run-short.stdout 2> run-short.stderr; rc=$?
result run-short $([ $rc = 0 ] && [ -s run-short.json ] && echo 1 || echo 0) "rc=$rc $(grep -a 'p11scope:' run-short.stderr | tail -1)"
# 6 run coverage (GT-4, informational pass = report written)
SUDO_UID=$RUNUID SUDO_GID=$RUNGID "$P" run --pause auto -o $OUT/run-cover.json -- "$FIX/gated" "$MODULE" 2000 300 - > run-cover.stdout 2> run-cover.stderr; rc=$?
s=$(summ run-cover.json); result run-cover $([ $rc = 0 ] && [ -s run-cover.json ] && echo 1 || echo 0) "rc=$rc ledger=2000 x6 $s"
# 7 multi-thread exactness (D1)
rm -f mt.gate; asuser "$FIX/mt" "$MODULE" "$THREADS" 5 0 "$OUT/mt.gate" > mt.wl 2>&1 & wl=$!
waitfor mt.wl READY 30; "$P" profile --pid $wl --duration 25 -o $OUT/mt.json > mt.stdout 2> mt.stderr & pp=$!
waitfor mt.stderr "p11scope: capturing:" 180 || true; sleep 0.5; touch mt.gate; wait $pp; rc=$?; wait $wl
tot=$(grep -ao 'TOTAL C_GenerateRandom=[0-9]*' mt.wl | cut -d= -f2); s=$(summ mt.json)
cap=$(python3 -c 'import json,sys; s=json.loads(sys.argv[1]); print(sum(r["calls"] for r in s.get("rows",[]) if "C_GenerateRandom" in (r.get("names") or [])))' "$s")
inf=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("in_flight_at_end"))' "$s")
result mt-exact $([ "$tot" = "$cap" ] && [ "$inf" = 0 ] && echo 1 || echo 0) "rc=$rc workload_total=$tot captured=$cap in_flight_at_end=$inf threads=$THREADS"
# 8 system scope (GT-5)
gated system profile --system --duration 25 -o $OUT/system.json; s=$(summ system.json)
hsm=$(python3 -c 'import json,sys; s=json.loads(sys.argv[1]); print(json.dumps(sorted(r["calls"] for r in s.get("rows",[]))))' "$s")
result system $(python3 -c 'import json,sys; c=json.loads(sys.argv[1]); n=int(sys.argv[2]); print(1 if c.count(n)>=6 else 0)' "$hsm" $ITERS) "rc=$(cat system.rc) calls=$hsm modules=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("modules"))' "$s") $(grep -a 'module refused' system.stderr | head -2 | tr '\n' ' ')"
# 9 SIGINT mid-capture
asuser "$FIX/gated" "$MODULE" 100000000 1000 - > sig.wl 2>&1 & wl=$!; waitfor sig.wl READY 30
# Background jobs of a non-interactive shell inherit SIGINT ignored; reset it so the
# cell proves SIGINT delivery instead of relying on p11scope installing its own handler.
env --default-signal=INT "$P" profile --pid $wl --duration 120 -o $OUT/sigint.json > sig.stdout 2> sig.stderr & pp=$!; waitfor sig.stderr "p11scope: capturing:" 180; sleep 1; kill -INT $pp; wait $pp; rc=$?; kill -TERM $wl; wait $wl 2>/dev/null
result sigint $([ $rc = 0 ] && python3 -c 'import json; json.load(open("sigint.json"))' 2>/dev/null && echo 1 || echo 0) "rc=$rc"
# 10 -o FIFO must be refused and left intact (B RB-1); never uses /dev
rm -f fifo; mkfifo fifo; asuser "$FIX/gated" "$MODULE" 100000000 1000 - > fifo.wl 2>&1 & wl=$!; waitfor fifo.wl READY 30
timeout 60 "$P" profile --pid $wl --duration 2 -o $OUT/fifo > fifo.stdout 2> fifo.stderr; rc=$?; kill -TERM $wl 2>/dev/null; wait $wl 2>/dev/null
result fifo-refused $([ $rc != 0 ] && [ -p fifo ] && grep -qai "fifo\|not a regular\|refus" fifo.stderr && echo 1 || echo 0) "rc=$rc still_fifo=$([ -p fifo ] && echo yes || echo no) $(tail -1 fifo.stderr)"
python3 -c 'import json; r=[json.loads(l) for l in open("results.jsonl")]; print("SUMMARY pass=%d fail=%d failed=%s" % (sum(x["pass"] for x in r), sum(not x["pass"] for x in r), [x["cell"] for x in r if not x["pass"]]))' | tee summary.txt

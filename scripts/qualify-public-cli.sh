#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# qualify-public-cli.sh P11SCOPE OUTDIR: independently ledgered public cells.
# Requires root for live cells. --control-gated OBSERVER OUTDIR FIXTURE [CELL]
# executes one bounded profile-pid, mt-exact or system lifecycle unprivileged.
# Every terminal result has cell/pass/detail/qualification. Exit 1 means failed
# evidence, 2 means valid smoke/nonqualifying evidence, 0 qualifies the subset.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 64
ORACLE=$HERE/public-cli-oracle.py
CONTROL=0
CONTROL_KIND=gated
if [ "${1:-}" = --control-gated ]; then CONTROL=1; shift
elif [ "${1:-}" = --control-second-sigint ]; then CONTROL=1; CONTROL_KIND=signal; shift
elif [ "${1:-}" = --control-fifo ]; then CONTROL=1; CONTROL_KIND=fifo; shift; fi
if [ "$CONTROL" = 1 ]; then
  if [ "$CONTROL_KIND" = signal ]; then
    [ $# = 2 ] || exit 64
    CONTROL_CELL=second-sigint
  elif [ "$CONTROL_KIND" = fifo ]; then
    [ $# = 3 ] || exit 64
    CONTROL_CELL=fifo-refused
  else
    [ $# -ge 3 ] && [ $# -le 4 ] || exit 64
    CONTROL_CELL=${4:-profile-pid}
    [[ "$CONTROL_CELL" = profile-pid || "$CONTROL_CELL" = mt-exact || "$CONTROL_CELL" = system ]] || exit 64
  fi
else
  [ $# = 2 ] || { echo 'usage: qualify-public-cli.sh P11SCOPE OUTDIR' >&2; exit 64; }
fi
P=$(realpath -e -- "$1") || exit 64
OUT=$2
RUNUID=${RUNUID:-1000}; RUNGID=${RUNGID:-1000}
ITERS=${ITERS:-500}; THREADS=${THREADS:-12}
if [ "$CONTROL" = 1 ]; then
  MODULE=${MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}
  if [ "$CONTROL_KIND" != signal ]; then GATED=$(realpath -e -- "$3") || exit 64; fi
  READY_TICKS=10; LEDGER_TICKS=10; EXIT_TICKS=20
else
  [ "$(id -u)" = 0 ] || { echo 'must run as root' >&2; exit 64; }
  MODULE_ARGS=(); [ -z "${MODULE+x}" ] || MODULE_ARGS=(--module "$MODULE")
  MODULE=$(python3 -I "$HERE/release-matrix-contract.py" --select-module "${MODULE_ARGS[@]}") || exit 64
  READY_TICKS=1800; LEDGER_TICKS=600; EXIT_TICKS=1800
fi
mkdir -p "$OUT" && chmod 755 "$OUT" && OUT=$(realpath -e -- "$OUT") && cd "$OUT" || exit 64
LOCAL_OUTPUT=$OUT
if [ -n "${P11SCOPE_LOCAL_OUTPUT_ROOT:-}" ]; then
  LOCAL_OUTPUT=$(python3 -I "$HERE/release-matrix-contract.py" --check-work-root "$P11SCOPE_LOCAL_OUTPUT_ROOT") || exit 64
fi
product_output() { printf '%s/%s\n' "$LOCAL_OUTPUT" "$1"; }
publish_output() {
  [ "$LOCAL_OUTPUT" != "$OUT" ] || return 0
  python3 -I "$HERE/release-matrix-contract.py" --copy-file "$LOCAL_OUTPUT/$1" "$OUT/$1"
}
: > results.jsonl
# PID generations limit cleanup to children created in this invocation.
declare -A CHILDREN
register() { local gen; gen=$(generation "$1") || return 1; CHILDREN[$1]=$gen; }
generation() {
  local line rest; IFS= read -r line 2>/dev/null < "/proc/$1/stat" || return 1
  rest=${line##*) }; read -ra fields <<< "$rest"
  [ ${#fields[@]} -ge 20 ] || return 1
  printf '%s\n' "${fields[19]}"
}
alive() {
  local line rest; IFS= read -r line 2>/dev/null < "/proc/$1/stat" || return 1
  rest=${line##*) }; read -ra fields <<< "$rest"
  [ "${fields[0]:-Z}" != Z ] && [ "${fields[19]:-}" = "${CHILDREN[$1]:-unknown}" ]
}
terminate() {
  local pid=$1
  if alive "$pid"; then
    kill -TERM "$pid" 2>/dev/null || true
    for ((i=0;i<20;i++)); do alive "$pid" || break; sleep 0.1; done
    alive "$pid" && kill -KILL "$pid" 2>/dev/null
    for ((i=0;i<20;i++)); do alive "$pid" || break; sleep 0.1; done
    if alive "$pid"; then LAST_EXIT=124; return 1; fi
  fi
  wait "$pid" 2>/dev/null; LAST_EXIT=$?
  unset 'CHILDREN[$pid]'
}
cleanup() { local pid; for pid in "${!CHILDREN[@]}"; do terminate "$pid"; done; }
trap cleanup EXIT
trap 'exit 1' HUP TERM INT
waitfor() {
  local file=$1 pattern=$2 pid=$3 ticks=$4 completed=${5:-0}
  for ((j=0;j<ticks;j++)); do
    if [ "$completed" = 1 ]; then grep -qa -- "$pattern" "$file" 2>/dev/null && return 0; fi
    alive "$pid" || return 1
    grep -qa -- "$pattern" "$file" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}
finish() {
  local pid=$1 ticks=$2
  for ((j=0;j<ticks;j++)); do alive "$pid" || break; sleep 0.1; done
  if alive "$pid"; then terminate "$pid"; return 1; fi
  wait "$pid"; LAST_EXIT=$?; unset 'CHILDREN[$pid]'; return 0
}
# Subprocess-free waits for captures that observe the whole machine: every
# fork/exec/exit during a system capture is a descendant gap, so the system
# cell polls with shell builtins only (one hot core while waiting). Patterns
# are coerced from the waitfor regex to a substring: a leading ^ is dropped.
# The completed flag needs no branch: the pattern is always checked first.
waitfor_quiet() {
  local file=$1 needle=$2 pid=$3 ticks=$4
  needle=${needle#^}
  local end=$((SECONDS + (ticks + 9) / 10)) content
  while [ "$SECONDS" -lt "$end" ]; do
    { content=$(<"$file"); } 2>/dev/null || content=''
    case $content in
      *"$needle"*) return 0 ;;
    esac
    alive "$pid" || return 1
  done
  { content=$(<"$file"); } 2>/dev/null || content=''
  case $content in
    *"$needle"*) return 0 ;;
  esac
  return 1
}
finish_quiet() {
  local pid=$1 ticks=$2
  local end=$((SECONDS + (ticks + 9) / 10))
  while alive "$pid" && [ "$SECONDS" -lt "$end" ]; do :; done
  if alive "$pid"; then terminate "$pid"; return 1; fi
  wait "$pid"; LAST_EXIT=$?; unset 'CHILDREN[$pid]'; return 0
}
touch_quiet() { : >> "$1"; }
result() {
  python3 - "$1" "$2" "$3" "${4:-command-contract}" <<'PY' | tee -a results.jsonl
import json,sys
print(json.dumps({'cell':sys.argv[1],'pass':sys.argv[2]=='1','detail':sys.argv[3],'qualification':sys.argv[4]}))
PY
}
asuser() {
  if [ "$CONTROL" = 1 ]; then exec "$@"; fi
  exec setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups env SOFTHSM2_CONF="$SOFTHSM2_CONF" "$@"
}
pin() {
  python3 -I "$HERE/mapped-provider-pin.py" "$MODULE"
}
receipt() {
  python3 - "$cell" "$scope" "$wl" "$gen" "$readygen" "$ready" "$capturing" "$released" "$observer_rc" "$workload_rc" "$before" "$after" <<'PY' > "$cell.receipt.json"
import json,re,sys
cell,scope,pid,gen,rgen,ready,capturing,released,observer,workload,before,after=sys.argv[1:]
lines=open(cell+'.wl').read().splitlines()
ready_pids=[int(m.group(1)) for line in lines if (m:=re.fullmatch(r'READY pid=(\d+)',line))]
print(json.dumps({'schema':'p11scope/public-cli-receipt/v1','cell':cell,'scope':scope,
 'count_domain':'owned-provider','launched_pid':int(pid),'generation':int(gen) if gen else None,
 'ready_generation':int(rgen) if rgen else None,'ready_pid':ready_pids[0] if len(ready_pids)==1 else None,
 'workload_ready':ready=='1','capture_ready':capturing=='1','gate_released':released=='1',
 'observer_exit':int(observer),'workload_exit':int(workload),
 'ledger_complete':sum(line.startswith('LEDGER ') for line in lines)==1,
 'provider_before':json.loads(before),'provider_after':json.loads(after)}))
PY
}
judge() {
  python3 -I "$ORACLE" --report "$1" --ledger "$2" --receipt "$3" --cell "$4" | tee -a results.jsonl
  return "${PIPESTATUS[0]}"
}
# The real lifecycle is also the unprivileged seam: clean every prior artifact,
# require both processes alive and capture readiness, then release exactly once.
gated() {
  local cell=$1 scope=$2 fixture=$3; shift 3
  local gate=$OUT/$cell.gate ext=json
  [ "$cell" = trace-pid ] && ext=txt
  rm -f -- "$gate" "$cell.$ext" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json"
  local output; output=$(product_output "$cell.$ext")
  [ "$LOCAL_OUTPUT" = "$OUT" ] || rm -f -- "$output"
  local before after gen='' readygen='' wl pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  local poll=waitfor settle=finish release=touch
  if [ "$cell" = system ]; then poll=waitfor_quiet settle=finish_quiet release=touch_quiet; fi
  before=$(pin) || { result "$cell" 0 'provider pin failed' failed; return 1; }
  if [ "$cell" = mt-exact ]; then
    asuser "$fixture" "$MODULE" "$THREADS" 5 0 "$gate" > "$cell.wl" 2>&1 &
  else
    asuser "$fixture" "$MODULE" "$ITERS" 200 "$gate" > "$cell.wl" 2>&1 &
  fi
  wl=$!; register "$wl" && gen=${CHILDREN[$wl]}
  if waitfor "$cell.wl" "^READY pid=$wl$" "$wl" "$READY_TICKS"; then
    ready=1; readygen=$(generation "$wl")
    local args=("${@//@PID@/$wl}")
    for ((i=0;i<${#args[@]}-1;i++)); do [ "${args[$i]}" != -o ] || args[$((i+1))]=$output; done
    "$P" "${args[@]}" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
    if "$poll" "$cell.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
      capturing=1
      if "$release" "$gate"; then
        released=1
        if "$poll" "$cell.wl" '^LEDGER ' "$wl" "$LEDGER_TICKS" 1; then
          if "$settle" "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
        fi
      fi
    fi
  fi
  if [ -n "$pp" ] && [ -n "${CHILDREN[$pp]:-}" ]; then terminate "$pp"; observer_rc=$LAST_EXIT; fi
  if [ "$cell" = mt-exact ] && [ "$released" = 1 ]; then
    if finish "$wl" "$LEDGER_TICKS"; then workload_rc=$LAST_EXIT; else workload_rc=124; fi
  else
    terminate "$wl"; workload_rc=$LAST_EXIT
  fi
  after=$(pin) || after='null'
  receipt || { result "$cell" 0 'receipt publication failed' failed; return 1; }
  publish_output "$cell.$ext" || { result "$cell" 0 'output copy failed' failed; return 1; }
  judge "$cell.$ext" "$cell.wl" "$cell.receipt.json" "$cell"
}
system_cell() {
  gated system system "$GATED" profile --system --module "$MODULE" --duration 25 -o "$OUT/system.json"
}
summary() {
  python3 - "$@" <<'PY' | tee summary.txt
import json,sys
rows=[json.loads(line) for line in open('results.jsonl')]
expected=sys.argv[1:]; ids=[row['cell'] for row in rows]
valid=len(ids)==len(set(ids)) and set(ids)==set(expected)
failed=[r['cell'] for r in rows if not r['pass'] and r['qualification']!='nonqualifying']
nonqual=[r['cell'] for r in rows if r['qualification']=='nonqualifying']
print('SUMMARY pass=%d fail=%d nonqualifying=%d failed=%s terminal_rows_valid=%s' % (sum(r['pass'] for r in rows),len(failed),len(nonqual),failed,valid))
sys.exit(1 if failed or not valid else 2 if nonqual else 0)
PY
  return "${PIPESTATUS[0]}"
}

# Register only a live direct child sampled while the recorded product parent
# is still owned. The kernel parent relation and generation authorize cleanup;
# the PID file alone never does.
register_owned_child() {
  local candidate=$1 parent=$2 line rest
  local -a observed_fields
  [[ "$candidate" =~ ^[1-9][0-9]*$ ]] && [ ${#candidate} -le 20 ] && alive "$parent" || return 1
  { IFS= read -r line < "/proc/$candidate/stat"; } 2>/dev/null || return 1
  rest=${line##*) }; read -ra observed_fields <<< "$rest"
  [ "${observed_fields[0]:-Z}" != Z ] && [ "${observed_fields[1]:-}" = "$parent" ] &&
    [[ "${observed_fields[19]:-}" =~ ^[0-9]+$ ]] || return 1
  CHILDREN[$candidate]=${observed_fields[19]}
  alive "$parent" && alive "$candidate"
}
await_signal_child() {
  local file=$1 parent=$2 candidate
  CUSTODY_CHILD=''
  for ((j=0;j<READY_TICKS;j++)); do
    alive "$parent" || return 1
    if [ -s "$file" ]; then
      candidate=$(cat -- "$file")
      if register_owned_child "$candidate" "$parent"; then CUSTODY_CHILD=$candidate; return 0; fi
    fi
    sleep 0.1
  done
  return 1
}
register_owned_descendants() {
  local parent=$1 file list candidate
  alive "$parent" || return 1
  for file in /proc/"$parent"/task/*/children; do
    list=''
    # proc children has no trailing newline; EOF still delivers its PID list.
    { IFS= read -r list < "$file"; } 2>/dev/null || [ -n "$list" ] || continue
    for candidate in $list; do register_owned_child "$candidate" "$parent" || true; done
  done
}
second_sigint() {
  local pp child='' rc=125 custody=0 cleanup_ok=1 pid
  local output; output=$(product_output sigint2.json)
  rm -f sigint2.json second-child.pid
  [ "$LOCAL_OUTPUT" = "$OUT" ] || rm -f -- "$output"
  : > second-child.pid
  if [ "$CONTROL" = 0 ]; then chown "$RUNUID:$RUNGID" second-child.pid; fi
  chmod 600 second-child.pid
  # shellcheck disable=SC2016
  env --default-signal=INT SUDO_UID="$RUNUID" SUDO_GID="$RUNGID" "$P" run -o "$output" -- sh -c 'echo $$ > "$1"; trap "" INT TERM; exec sleep 60' sh "$OUT/second-child.pid" > sig2.stdout 2> sig2.stderr & pp=$!; register "$pp" || true
  if waitfor sig2.stderr 'p11scope: capturing:' "$pp" "$READY_TICKS" && await_signal_child second-child.pid "$pp"; then
    child=$CUSTODY_CHILD; custody=1
    sleep 1; kill -INT "$pp"; sleep 1; kill -INT "$pp"
    if finish "$pp" "$EXIT_TICKS"; then rc=$LAST_EXIT; else rc=124; fi
  else
    # Failed publication cannot pass, but kernel-authenticated descendants still
    # belong to this invocation and must be collected before their parent exits.
    register_owned_descendants "$pp" || true
  fi
  [ -n "${CHILDREN[$pp]:-}" ] && terminate "$pp"
  for pid in "${!CHILDREN[@]}"; do
    terminate "$pid" || cleanup_ok=0
  done
  publish_output sigint2.json || cleanup_ok=0
  result second-sigint "$([ "$custody" = 1 ] && [ "$cleanup_ok" = 1 ] && [ "$rc" = 130 ] && grep -qa 'p11scope: cleanup incomplete' sig2.stderr && ! grep -qa panicked sig2.stderr && python3 -c 'import json; json.load(open("sigint2.json"))' 2>/dev/null && echo 1 || echo 0)" "rc=$rc child_custody=$custody child=${child:-unknown} cleanup_complete=$cleanup_ok"
}
fifo_refused() {
  local wl rc=125
  rm -f fifo; mkfifo fifo || return 1
  asuser "$GATED" "$MODULE" 100000000 1000 - > fifo.wl 2>&1 & wl=$!; register "$wl" || true
  if waitfor fifo.wl '^READY pid=' "$wl" "$READY_TICKS"; then
    # This negative must keep the actual FIFO destination, even in local-output mode.
    timeout 60 "$P" profile --pid "$wl" --duration 2 -o "$OUT/fifo" > fifo.stdout 2> fifo.stderr; rc=$?
  fi
  terminate "$wl"
  result fifo-refused "$([ "$rc" != 0 ] && [ "$rc" != 125 ] && [ "$rc" != 124 ] && [ -p fifo ] && grep -qai 'fifo\|not a regular\|refus' fifo.stderr && echo 1 || echo 0)" "rc=$rc"
}
if [ "$CONTROL" = 1 ]; then
  if [ "$CONTROL_KIND" = signal ]; then second_sigint
  elif [ "$CONTROL_KIND" = fifo ]; then fifo_refused
  elif [ "$CONTROL_CELL" = system ]; then system_cell
  else gated "$CONTROL_CELL" pid "$GATED" profile --pid @PID@ --duration 1 -o "$OUT/$CONTROL_CELL.json"; fi
  summary "$CONTROL_CELL"; exit $?
fi
SRC=$HERE/../tests/fixtures/public-cli
FIX=$OUT/fix; mkdir -p "$FIX"
gcc -O1 -o "$FIX/gated" "$SRC/gated.c" -ldl && gcc -O2 -o "$FIX/mt" "$SRC/mt.c" -ldl -lpthread || exit 65
GATED=$FIX/gated; MT=$FIX/mt
chmod 755 "$FIX" "$GATED" "$MT"
export SOFTHSM2_CONF=$OUT/softhsm2.conf
mkdir -p tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$OUT" > softhsm2.conf
softhsm2-util --init-token --free --label qual --so-pin 5678 --pin 1234 >/dev/null || exit 65
chown -R "$RUNUID:$RUNGID" tokens; chmod 644 softhsm2.conf
sh -c 'kill -HUP $$' >/dev/null 2>&1; status=$?
[ "$status" = 129 ] || { echo "SIGHUP positive control failed rc=$status" >&2; exit 65; }
env --default-signal=INT sh -c 'kill -INT $$' >/dev/null 2>&1 & wait $!
[ $? = 130 ] || { echo 'SIGINT positive control failed' >&2; exit 65; }
"$P" doctor > doctor.out 2>&1; rc=$?
result doctor "$([ "$rc" = 0 ] && grep -q 'capture available' doctor.out && echo 1 || echo 0)" "rc=$rc"
gated profile-pid pid "$GATED" profile --pid @PID@ --duration 12 -o "$OUT/profile-pid.json"
# The semantic assertions reuse the independently captured receipt, with their
# own cell binding; they cannot turn a failed capture into a second PASS.
for cell in names-pid verdict-pid; do
  python3 - "$cell" <<'PY' > "$cell.receipt.json"
import json,sys
d=json.load(open('profile-pid.receipt.json')); d['cell']=sys.argv[1]; print(json.dumps(d))
PY
  judge profile-pid.json profile-pid.wl "$cell.receipt.json" "$cell"
done
gated metrics-pid pid "$GATED" profile --mode metrics --pid @PID@ --duration 12 -o "$OUT/metrics-pid.json"
gated trace-pid pid "$GATED" trace --pid @PID@ --duration 12 -o "$OUT/trace-pid.txt"
# Run remains explicitly nonqualifying until an independent first-call contract
# exists. A report or a successful child exit alone does not establish coverage.
for cell in run-short run-cover; do
  n=3; [ "$cell" = run-cover ] && n=2000
  rm -f -- "$cell.json" "$cell.wl" "$cell.stderr" "$cell.stdout"
  output=$(product_output "$cell.json"); [ "$LOCAL_OUTPUT" = "$OUT" ] || rm -f -- "$output"
  before=$(pin) || before=null
  SUDO_UID=$RUNUID SUDO_GID=$RUNGID "$P" run --pause auto -o "$output" -- "$GATED" "$MODULE" "$n" 0 - > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
  if finish "$pp" "$EXIT_TICKS"; then rc=$LAST_EXIT; else rc=124; fi
  publish_output "$cell.json" || rc=1
  # run does not expose a separately authenticated fixture PID/exit/readiness
  # channel here. Validate the available smoke assertion without fabricating it.
  if [ "$rc" = 0 ] && python3 - "$cell.json" <<'PY'
import json,sys
with open(sys.argv[1]) as f: d=json.load(f)
assert d['schema']=='p11scope/observed-profile/v3'
PY
  then result "$cell" 0 'report smoke passed; first-call ledger and independent child exit remain unproved' nonqualifying
  else result "$cell" 0 "run smoke failed rc=$rc" failed; fi
done
gated mt-exact pid "$MT" profile --pid @PID@ --duration 25 -o "$OUT/mt-exact.json"
system_cell
# Signal cells retain distinct expected exits; readiness is mandatory.
rm -f sigint.json sig.gate
output=$(product_output sigint.json); [ "$LOCAL_OUTPUT" = "$OUT" ] || rm -f -- "$output"
asuser "$GATED" "$MODULE" 100000000 1000 "$OUT/sig.gate" > sig.wl 2>&1 & wl=$!; register "$wl" || true
rc=125
if waitfor sig.wl '^READY pid=' "$wl" "$READY_TICKS"; then
  env --default-signal=INT "$P" profile --pid "$wl" --duration 120 -o "$output" > sig.stdout 2> sig.stderr & pp=$!; register "$pp" || true
  if waitfor sig.stderr 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl"; then
    touch sig.gate; sleep 1; kill -INT "$pp"
    if finish "$pp" "$EXIT_TICKS"; then rc=$LAST_EXIT; else rc=124; fi
  fi
  [ -n "${CHILDREN[$pp]:-}" ] && terminate "$pp"
fi
terminate "$wl"
publish_output sigint.json || rc=1
result sigint "$([ "$rc" = 0 ] && python3 -c 'import json; json.load(open("sigint.json"))' 2>/dev/null && echo 1 || echo 0)" "rc=$rc"
second_sigint
fifo_refused
summary doctor profile-pid names-pid verdict-pid metrics-pid trace-pid run-short run-cover mt-exact system sigint second-sigint fifo-refused
exit $?

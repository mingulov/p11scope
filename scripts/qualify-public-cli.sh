#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# qualify-public-cli.sh P11SCOPE OUTDIR: independently ledgered public cells.
# Requires root for live cells. --control-gated OBSERVER OUTDIR FIXTURE [CELL]
# executes one bounded profile-pid, mt-exact or system lifecycle unprivileged.
# P11SCOPE_PUBLIC_CLI_CELLS="cell ..." runs only the named gated lifecycle
# cells (profile-pid, metrics-pid, trace-pid, mt-exact, system) instead of
# the full campaign; anything else fails closed here as a usage error.
# P11SCOPE_QUALIFY_GATED_BIN=PATH P11SCOPE_QUALIFY_MT_BIN=PATH: prebuilt
# gated/mt workloads for tests-only hosts (no gcc); when both are set the
# gcc builds are skipped. Setting only one, or a missing file, fails
# closed before any campaign starts.
# Every terminal result has cell/pass/detail/qualification. Exit 1 means failed
# evidence (including unexpected passes), 2 means valid smoke/nonqualifying or
# expected-failure evidence, 0 qualifies the subset with no caveats.
# P11SCOPE_ALLOW_PID_DESCENDANT_GAPS=1 (ruling CI-GAP-1) discloses hosted
# runner noise on the system cell only; default 0 keeps every cell strict.
set -u
_SRC=${BASH_SOURCE[0]:-$0}
HERE=$(cd "$(dirname "$_SRC")" && pwd) || exit 64
ORACLE=$HERE/public-cli-oracle.py
CONTROL=0
CONTROL_KIND=gated
if [ "${1:-}" = --control-gated ]; then CONTROL=1; shift
elif [ "${1:-}" = --control-second-sigint ]; then CONTROL=1; CONTROL_KIND=signal; shift
elif [ "${1:-}" = --control-fifo ]; then CONTROL=1; CONTROL_KIND=fifo; shift; fi
# The cell filter is validated before any setup, so a typo fails before a
# privileged campaign starts. Only the gated lifecycle cells are runnable
# as a subset; derived and smoke cells stay full-campaign-only.
if [ -n "${P11SCOPE_PUBLIC_CLI_CELLS:-}" ] && [ "$CONTROL" = 1 ]; then
  echo 'P11SCOPE_PUBLIC_CLI_CELLS cannot be combined with a --control mode' >&2
  exit 64
fi
# shellcheck disable=SC2086
for _cell in ${P11SCOPE_PUBLIC_CLI_CELLS:-}; do
  case $_cell in
    profile-pid|metrics-pid|trace-pid|mt-exact|system) ;;
    *) echo "unsupported subset cell: $_cell (supported: profile-pid metrics-pid trace-pid mt-exact system)" >&2; exit 64 ;;
  esac
done
unset _cell
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
# Owned cgroups for EXIT cleanup (prevents leaks if a cell fails before rmdir).
CGROUPS=()
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
cleanup() {
  local pid cg
  for pid in "${!CHILDREN[@]}"; do terminate "$pid"; done
  for cg in "${CGROUPS[@]:-}"; do rmdir "$cg" 2>/dev/null || true; done
}
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
  # SECONDS truncates to whole seconds, so without the extra second this
  # deadline yields a 0-to-N window (near zero when computed just before a
  # rollover) instead of the nominal ticks/10 seconds the ticking waiter
  # provides. The +1 keeps the window at least nominal with builtins only.
  local end=$((SECONDS + (ticks + 9) / 10 + 1)) content
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
  # Same SECONDS truncation as waitfor_quiet: the +1 keeps the window at
  # least the nominal ticks/10 seconds with builtins only.
  local end=$((SECONDS + (ticks + 9) / 10 + 1))
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
# Expected-failure reasons for known product gaps. Each names the gap and the
# product fix lane. Unexpected passes fail via summary() and the WP-1 template.
REASON_RUN="run exact loss (discovery_truncated/lossy observation); product fix lane for run pause/discovery"
REASON_CGROUP="cgroup fork observation gaps; product fix lane for cgroup fork"
REASON_TRACE_CGROUP="cgroup trace lossy observation; product fix lane for cgroup trace"
REASON_INVENTORY_7X="inventory cgroup owned-module gaps on 7.x (native endpoint attach failed, 68 deferred); product fix lane for inventory 7.x"
REASON_IA32="ia32 prereq missing (libsofthsm2:i386 cannot coexist with amd64); ia32-only job"
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
# Emit the final row for an oracle-judged cell, converting known product gaps
# to expected-failure. Args: cell oracle_rc oracle_json_line. Unknown failure
# signatures are never masked: they stay failed. Oracle passes and (for
# trace-cgroup) smoke where a gap was expected become unexpected passes.
emit_judged() {
  local cell=$1 rc=$2 line=$3
  local reason=""
  case "$cell" in
    run-short|run-cover) reason=$REASON_RUN ;;
    profile-cgroup|metrics-cgroup) reason=$REASON_CGROUP ;;
    trace-cgroup) reason=$REASON_TRACE_CGROUP ;;
  esac
  if [ -z "$reason" ]; then
    printf '%s\n' "$line" | tee -a results.jsonl
    return "$rc"
  fi
  if [ -z "$line" ]; then
    result "$cell" 0 "oracle produced no output rc=$rc" failed; return 1
  fi
  local qual detail
  qual=$(printf '%s' "$line" | python3 -c 'import json,sys; print(json.load(sys.stdin)["qualification"])') || qual=failed
  detail=$(printf '%s' "$line" | python3 -c 'import json,sys; print(json.load(sys.stdin)["detail"])') || detail="$line"
  if [ "$rc" = 0 ]; then
    result "$cell" 1 "UNEXPECTED PASS ($reason may have landed): [$qual] $detail" expected-failure
    return 1
  fi
  if [ "$rc" = 2 ]; then
    result "$cell" 1 "UNEXPECTED PASS ($reason may have landed): smoke [$qual] $detail" expected-failure
    return 1
  fi
  local known=0
  case "$cell" in
    run-short|run-cover)
      case "$detail" in
        *discovery_truncated*|*lossy\ or\ unknown\ observation*|*run\ pause*) known=1 ;;
      esac ;;
    profile-cgroup|metrics-cgroup)
      case "$detail" in
        *lossy\ or\ unknown\ observation\ gap\ class*) known=1 ;;
      esac ;;
    trace-cgroup)
      case "$detail" in
        *trace\ lossy\ or\ unknown\ observation*) known=1 ;;
      esac ;;
  esac
  if [ "$known" = 1 ]; then
    result "$cell" 0 "$reason: [$qual] $detail" expected-failure
    return 0
  fi
  printf '%s\n' "$line" | tee -a results.jsonl
  return 1
}
judge() {
  # Ruling CI-GAP-1: P11SCOPE_ALLOW_PID_DESCENDANT_GAPS=1 discloses hosted
  # runner noise on the system cell only. Every other cell stays strict,
  # and unset/0 keeps the system cell strict (fedora, sm1, vng guests).
  local -a extra=()
  if [ "${4:-}" = system ] && [ "${P11SCOPE_ALLOW_PID_DESCENDANT_GAPS:-0}" = 1 ]; then
    extra=(--allow-pid-descendant-gaps)
  fi
  local out rc
  out=$(python3 -I "$ORACLE" --report "$1" --ledger "$2" --receipt "$3" --cell "$4" "${extra[@]}"); rc=$?
  emit_judged "$4" "$rc" "$out"
}
# The real lifecycle is also the unprivileged seam: clean every prior artifact,
# require both processes alive and capture readiness, then release exactly once.
gated() {
  local cell=$1 scope=$2 fixture=$3; shift 3
  local gate=$OUT/$cell.gate ext=json
  case "$cell" in trace-*) ext=txt;; esac
  rm -f -- "$gate" "$cell.$ext" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json"
  local output; output=$(product_output "$cell.$ext")
  [ "$LOCAL_OUTPUT" = "$OUT" ] || rm -f -- "$output"
  local before after gen='' readygen='' wl pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  local poll=waitfor settle=finish release=touch
  if [ "$scope" = system ]; then poll=waitfor_quiet settle=finish_quiet release=touch_quiet; fi
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
failed=[r['cell'] for r in rows if not r['pass'] and r['qualification'] not in ('nonqualifying','expected-failure')]
failed+= [r['cell'] for r in rows if r['pass'] and r['qualification']=='expected-failure']
failed+= [r['cell'] for r in rows if r['pass'] and r['qualification']=='failed']
nonqual=[r['cell'] for r in rows if r['qualification']=='nonqualifying']
expectedfails=[r['cell'] for r in rows if r['qualification']=='expected-failure' and not r['pass']]
print('SUMMARY pass=%d fail=%d nonqualifying=%d expected=%d failed=%s terminal_rows_valid=%s' % (sum(r['pass'] for r in rows),len(failed),len(nonqual),len(expectedfails),failed,valid))
sys.exit(1 if failed or not valid else 2 if nonqual or expectedfails else 0)
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
  report_ok=0
  if python3 - sigint2.json <<'PY' 2>/dev/null; then report_ok=1; fi
import json,sys
report=json.load(open(sys.argv[1]))
assert report.get('schema')=='p11scope/observed-profile/v3', 'schema'
evidence=report['evidence']
assert evidence.get('completeness')=='PARTIAL', 'abandoned teardown cannot seal COMPLETE'
stop=evidence['stop_quiescence']
proven=stop.get('state')=='proven' and stop.get('post_q_events') is False and stop.get('post_q_discovery') is False
assert evidence.get('drain_proven') is proven, 'drain_proven must match the stop-gate evidence'
samples=evidence.get('scheduling',{}).get('inter_drain_gap',{}).get('samples')
assert isinstance(samples,int) and samples>0, 'report must carry this capture live-loop drain samples'
assert evidence.get('child_still_running') is False, 'owned child must be settled, not still running'
PY
  result second-sigint "$([ "$custody" = 1 ] && [ "$cleanup_ok" = 1 ] && [ "$rc" = 130 ] && [ "$report_ok" = 1 ] && grep -qa 'p11scope: cleanup incomplete' sig2.stderr && ! grep -qa panicked sig2.stderr && echo 1 || echo 0)" "rc=$rc child_custody=$custody child=${child:-unknown} cleanup_complete=$cleanup_ok report_ok=$report_ok"
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
  result fifo-refused "$([ "$rc" != 0 ] && [ "$rc" != 125 ] && [ "$rc" != 124 ] && [ -p fifo ] && grep -qF 'exists and is a FIFO; refusing to replace it' fifo.stderr && echo 1 || echo 0)" "rc=$rc"
}
# Cgroup capture: inside (cgroup-fork, parent+child) and outside (gated) use the
# same owned provider copy; a leak breaks equality. The fork child inherits the
# cgroup after attach and must be counted. The owned cgroup is removed afterwards.
cgroup_capture() {
  local cell=$1 kind=$2
  local ext=json; [ "$kind" = trace ] && ext=txt
  local CG=/sys/fs/cgroup/p11scope-qual-$cell-$$
  local inside_gate=$OUT/$cell-inside.gate outside_gate=$OUT/$cell-outside.gate
  rm -f -- "$inside_gate" "$outside_gate" "$cell.$ext" "$cell-inside.wl" "$cell-outside.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json"
  local output; output=$(product_output "$cell.$ext")
  [ "$LOCAL_OUTPUT" = "$OUT" ] || rm -f -- "$output"
  local before after gen='' readygen='' inside='' outside='' child='' pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  local scope=cgroup wl=''
  before=$(pin) || { result "$cell" 0 'provider pin failed' failed; return 1; }
  if [ -e "$CG" ]; then
    if [ -s "$CG/cgroup.procs" ]; then
      result "$cell" 0 "stale owned cgroup not empty $CG (prior leak, manual cleanup required)" failed; return 1
    fi
    rmdir "$CG" 2>/dev/null || { result "$cell" 0 "stale owned cgroup not removable $CG" failed; return 1; }
  fi
  mkdir -p "$CG" || { result "$cell" 0 "cgroup mkdir failed $CG" failed; return 1; }
  CGROUPS+=("$CG")
  asuser "$CFORK" "$MODULE" 250 200 "$inside_gate" > "$cell-inside.wl" 2>&1 & inside=$!; register "$inside" && gen=${CHILDREN[$inside]}
  asuser "$GATED" "$MODULE" 500 200 "$outside_gate" > "$cell-outside.wl" 2>&1 & outside=$!; register "$outside" || true
  local inside_ready=0 outside_ready=0 in_cgroup=0
  if waitfor "$cell-inside.wl" "^READY pid=$inside$" "$inside" "$READY_TICKS"; then
    inside_ready=1; readygen=$(generation "$inside")
    if echo "$inside" > "$CG/cgroup.procs" 2>/dev/null && grep -qw "$inside" "$CG/cgroup.procs" 2>/dev/null; then
      in_cgroup=1
    fi
  fi
  if waitfor "$cell-outside.wl" "^READY pid=$outside$" "$outside" "$READY_TICKS"; then
    outside_ready=1
  fi
  if [ "$inside_ready" = 1 ] && [ "$outside_ready" = 1 ] && [ "$in_cgroup" = 1 ]; then
    ready=1
    local args=()
    if [ "$kind" = profile ]; then args=(profile --cgroup "$CG" --duration 12 -o "$output")
    elif [ "$kind" = metrics ]; then args=(profile --mode metrics --cgroup "$CG" --duration 12 -o "$output")
    elif [ "$kind" = trace ]; then args=(trace --cgroup "$CG" --duration 12 -o "$output")
    else args=(inventory --cgroup "$CG" --duration 12 -o "$output"); fi
    "$P" "${args[@]}" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
    local observer_started=0
    if [ "$kind" = inventory ]; then
      sleep 2; alive "$pp" && observer_started=1 && capturing=1
    else
      if waitfor "$cell.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$inside" && alive "$outside" && alive "$pp"; then
        capturing=1; observer_started=1
      fi
    fi
    if [ "$observer_started" = 1 ]; then
      if touch "$inside_gate" && touch "$outside_gate"; then
        released=1
        if waitfor "$cell-inside.wl" '^LEDGER ' "$inside" "$LEDGER_TICKS" 1 && waitfor "$cell-outside.wl" '^LEDGER ' "$outside" "$LEDGER_TICKS" 1; then
          child=$(grep -m1 '^CHILD pid=' "$cell-inside.wl" 2>/dev/null | sed 's/^CHILD pid=//')
          [[ "$child" =~ ^[1-9][0-9]*$ ]] || child=''
          if [ -n "$child" ]; then register "$child" || true; fi
          if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
        fi
      fi
    fi
  fi
  if [ -n "$pp" ] && [ -n "${CHILDREN[$pp]:-}" ]; then terminate "$pp"; observer_rc=$LAST_EXIT; fi
  if [ -n "$inside" ]; then terminate "$inside"; workload_rc=$LAST_EXIT; wl=$inside; fi
  if [ -n "$outside" ] && [ -n "${CHILDREN[$outside]:-}" ]; then terminate "$outside" || true; fi
  if [ -n "$child" ] && [ -n "${CHILDREN[$child]:-}" ]; then terminate "$child" || true; fi
  after=$(pin) || after='null'
  rmdir "$CG" 2>/dev/null || true
  if [ -e "$CG" ]; then
    local leftover
    leftover=$(cat "$CG/cgroup.procs" 2>/dev/null || true)
    if [ -n "$leftover" ]; then
      # shellcheck disable=SC2086
      kill -KILL $leftover 2>/dev/null || true
      sleep 1
    fi
    rmdir "$CG" 2>/dev/null || true
  fi
  local cg_gone=0; [ ! -e "$CG" ] && cg_gone=1
  if [ "$cg_gone" != 1 ]; then result "$cell" 0 "owned cgroup not removed $CG (force cleanup attempted)" failed; return 1; fi
  if [ "$kind" = inventory ]; then
    publish_output "$cell.$ext" || { result "$cell" 0 'output copy failed' failed; return 1; }
    python3 - "$cell.$ext" "$cell-inside.wl" "$cell-outside.wl" "$before" <<'PY' > "$cell.detail" 2>&1
import json,sys
report=json.load(open(sys.argv[1]))
inside=open(sys.argv[2]).read(); outside=open(sys.argv[3]).read()
pin=json.loads(sys.argv[4])
assert report.get('schema')=='p11scope/inventory/v1', 'inventory schema'
assert report.get('scope')=='cgroup', 'inventory scope'
inside_pid=int([l for l in inside.splitlines() if l.startswith('READY pid=')][0].split('=')[1])
child_pid=int([l for l in inside.splitlines() if l.startswith('CHILD pid=')][0].split('=')[1])
outside_pid=int([l for l in outside.splitlines() if l.startswith('READY pid=')][0].split('=')[1])
assert sum(l.startswith('LEDGER ') for l in inside.splitlines())==1, 'inside ledger missing'
assert sum(l.startswith('LEDGER ') for l in outside.splitlines())==1, 'outside ledger missing (leak test invalid)'
modules={m['id']:m for m in report.get('modules',[])}
owned=None
for mid,m in modules.items():
    ident=m.get('identity',{})
    dev=ident.get('device',{})
    if [dev.get('major'),dev.get('minor')]==pin['dev'] and ident.get('inode')==pin['ino'] and ident.get('sha256')==pin['sha256']:
        owned=mid; break
assert owned is not None, 'owned provider not inventoried'
assert modules[owned].get('admission',{}).get('state')=='admitted', 'owned provider not admitted'
callers={c['id']:c for c in report.get('callers',[])}
inside_ids=[cid for cid,c in callers.items() if c.get('pid')==inside_pid]
child_ids=[cid for cid,c in callers.items() if c.get('pid')==child_pid]
outside_ids=[cid for cid,c in callers.items() if c.get('pid')==outside_pid]
assert inside_ids, 'inside parent not a caller'
assert child_ids, 'fork-after-attach child not a caller'
assert not outside_ids, 'outside workload leaked into cgroup inventory'
edges=report.get('edges',[])
assert any(e.get('caller') in inside_ids+child_ids and e.get('module')==owned for e in edges), 'no inside edge to owned module'
owned_gaps=[g for g in report.get('gaps',[]) if g.get('module')==owned]
assert owned_gaps==[], 'inventory gaps about owned module: %r' % owned_gaps
print('inventory cgroup: inside=%d child=%d outside=%d excluded module=%s gaps=%d' % (inside_pid,child_pid,outside_pid,owned,len(report.get('gaps',[]))))
PY
    rc=$?
    detail=$(cat "$cell.detail" 2>/dev/null || echo "inventory check failed rc=$rc")
    detail="$detail observer_rc=$observer_rc"
    if [ "$rc" = 0 ] && [ "$observer_rc" = 0 ]; then
      result "$cell" 1 "$detail"
    else
      case "$detail" in
        *inventory\ gaps\ about\ owned\ module*)
          result "$cell" 0 "$REASON_INVENTORY_7X: [failed] $detail" expected-failure ;;
        *) result "$cell" 0 "$detail" failed ;;
      esac
    fi
    return 0
  fi
  if ! grep -qa '^LEDGER ' "$cell-outside.wl" 2>/dev/null; then result "$cell" 0 'outside ledger missing (leak test invalid)' failed; return 1; fi
  cp -- "$cell-inside.wl" "$cell.wl"
  receipt || { result "$cell" 0 'receipt publication failed' failed; return 1; }
  publish_output "$cell.$ext" || { result "$cell" 0 'output copy failed' failed; return 1; }
  judge "$cell.$ext" "$cell.wl" "$cell.receipt.json" "$cell"
}
# Exact run: the gated workload prints TARGET/READY/LEDGER to the captured
# stdout (the child inherits the observer's stdout). Judge with the exact
# oracle and require pause confirmed; pass comes from the oracle.
run_exact() {
  local cell=$1 fixture=$2 iters=$3
  rm -f -- "$cell.json" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json"
  local output; output=$(product_output "$cell.json")
  [ "$LOCAL_OUTPUT" = "$OUT" ] || rm -f -- "$output"
  local before after wl='' pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  local gen='' readygen='' scope=pid
  before=$(pin) || { result "$cell" 0 'provider pin failed' failed; return 1; }
  SUDO_UID=$RUNUID SUDO_GID=$RUNGID "$P" run --pause auto -o "$output" -- "$fixture" "$MODULE" "$iters" 0 - > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
  if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
  workload_rc=$observer_rc
  [ -n "${CHILDREN[$pp]:-}" ] && { terminate "$pp"; observer_rc=$LAST_EXIT; workload_rc=$observer_rc; }
  after=$(pin) || after='null'
  cp -- "$cell.stdout" "$cell.wl" 2>/dev/null || : > "$cell.wl"
  if grep -qa '^READY pid=' "$cell.wl" 2>/dev/null; then ready=1; fi
  if grep -qa 'p11scope: capturing:' "$cell.stderr" 2>/dev/null; then capturing=1; fi
  wl=$(grep -m1 '^READY pid=' "$cell.wl" 2>/dev/null | sed 's/^READY pid=//')
  [[ "$wl" =~ ^[1-9][0-9]*$ ]] || wl=0
  receipt || { result "$cell" 0 'receipt publication failed' failed; return 1; }
  publish_output "$cell.json" || { result "$cell" 0 'output copy failed' failed; return 1; }
  judge "$cell.json" "$cell.wl" "$cell.receipt.json" "$cell"
}
run_prearm() {
  # Owned-run pre-arm exactness (packet 6.13, R2-D1-6): the pause-held
  # twin publishes unobserved_windows [] with exact ledger/trace counts;
  # the passive twin (--pause never) keeps its single pre_attach window.
  local name policy ledger output rc pp detail
  for name in held passive; do
    policy=auto; [ "$name" = passive ] && policy=never
    ledger=$OUT/run-prearm-$name.wl
    output=$(product_output "run-prearm-$name.txt")
    rm -f -- "run-prearm-$name.txt" "run-prearm-$name.wl" "run-prearm-$name.stderr" "run-prearm-$name.stdout"
    [ "$LOCAL_OUTPUT" = "$OUT" ] || rm -f -- "$output"
    # The owned child runs demoted to SUDO_UID and opens the ledger
    # itself: pre-create it owned (same precedent as second-child.pid).
    : > "$ledger" && chown "$RUNUID:$RUNGID" "$ledger" && chmod 600 "$ledger" || { result run-prearm 0 "$name ledger setup failed" prearm-exactness; return 1; }
    # shellcheck disable=SC2086
    SUDO_UID=$RUNUID SUDO_GID=$RUNGID "$P" run --trace --pause "$policy" --prearm-module "$MODULE" -o "$output" -- "$PREARM_LOADER" "$MODULE" "$ledger" 3 1500 > "run-prearm-$name.stdout" 2> "run-prearm-$name.stderr" & pp=$!; register "$pp" || true
    if finish "$pp" "$EXIT_TICKS"; then rc=$LAST_EXIT; else rc=124; fi
    publish_output "run-prearm-$name.txt" || rc=1
    [ "$rc" = 0 ] || { result run-prearm 0 "$name twin failed rc=$rc" prearm-exactness; return 1; }
  done
  detail=$(python3 - <<'PY' 2>&1
import json

def load(name):
    # EVIDENCE rides on the observer's stdout (diagnostics go to stderr).
    with open(f"run-prearm-{name}.stdout") as handle:
        evidence = None
        for line in handle:
            if line.startswith("EVIDENCE "):
                evidence = json.loads(line[len("EVIDENCE "):])
    if evidence is None:
        raise SystemExit(f"{name}: no EVIDENCE line")
    with open(f"run-prearm-{name}.wl") as handle:
        ledger = [json.loads(line) for line in handle if line.strip()]
    with open(f"run-prearm-{name}.txt") as handle:
        text = handle.read()
    return evidence, ledger, text

def prearmed_module(evidence):
    mods = [m for m in evidence["discovery"] if "prearm" in m.get("sources", [])]
    assert len(mods) == 1, f"one pre-armed module, got {len(mods)}"
    return mods[0]

def completed_calls(text, function):
    return sum(1 for line in text.splitlines()
               if f" {function} " in line and " \u2192 " in line)

held_evidence, held_ledger, held_text = load("held")
held = prearmed_module(held_evidence)
assert held["unobserved_windows"] == [], held["unobserved_windows"]
assert "scan" in held["sources"], held["sources"]
summary = held_ledger[-1]
assert (summary["initializes"], summary["finalizes"]) == (3, 3), summary
counts = tuple(completed_calls(held_text, name)
               for name in ("C_Initialize", "C_Finalize", "C_GetFunctionList"))
assert counts == (3, 3, 1), counts
passive = prearmed_module(load("passive")[0])
assert "scan" in passive["sources"], passive["sources"]
windows = passive["unobserved_windows"]
assert windows and len(windows) == 1 and windows[0]["reason"] == "pre_attach", windows
assert windows[0]["end_ns"] == passive["attached_at_ns"], windows
print("held [] with 3/3 ledger and 3/3/1 trace; passive keeps single pre_attach")
PY
) || { result run-prearm 0 "$(printf '%.600s' "$detail")" prearm-exactness; return 1; }
  result run-prearm 1 "$detail" prearm-exactness
}
if [ "$CONTROL" = 1 ]; then
  if [ "$CONTROL_KIND" = signal ]; then second_sigint
  elif [ "$CONTROL_KIND" = fifo ]; then fifo_refused
  elif [ "$CONTROL_CELL" = system ]; then system_cell
  else gated "$CONTROL_CELL" pid "$GATED" profile --pid @PID@ --duration 1 -o "$OUT/$CONTROL_CELL.json"; fi
  summary "$CONTROL_CELL"; exit $?
fi
if [ "${P11SCOPE_SOURCE_ONLY:-}" = 1 ]; then return 0 2>/dev/null || exit 0; fi
SRC=$HERE/../tests/fixtures/public-cli
FIX=$OUT/fix; mkdir -p "$FIX"
if [ -n "${P11SCOPE_QUALIFY_GATED_BIN:-}" ] || [ -n "${P11SCOPE_QUALIFY_MT_BIN:-}" ]; then
  [ -x "${P11SCOPE_QUALIFY_GATED_BIN:-}" ] && [ -x "${P11SCOPE_QUALIFY_MT_BIN:-}" ] || exit 65
  cp -- "$P11SCOPE_QUALIFY_GATED_BIN" "$FIX/gated" && cp -- "$P11SCOPE_QUALIFY_MT_BIN" "$FIX/mt" || exit 65
else
  gcc -O1 -o "$FIX/gated" "$SRC/gated.c" -ldl && gcc -O2 -o "$FIX/mt" "$SRC/mt.c" -ldl -lpthread || exit 65
fi
gcc -std=c11 -O2 -Wall -Wextra -Werror -o "$FIX/prearm-first-use" "$SRC/prearm-first-use.c" -ldl || exit 65
gcc -O1 -o "$FIX/cgroup-fork" "$SRC/cgroup-fork.c" -ldl || exit 65
GATED=$FIX/gated; MT=$FIX/mt; PREARM_LOADER=$FIX/prearm-first-use; CFORK=$FIX/cgroup-fork
chmod 755 "$FIX" "$GATED" "$MT" "$CFORK"
export SOFTHSM2_CONF=$OUT/softhsm2.conf
mkdir -p tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$OUT" > softhsm2.conf
softhsm2-util --init-token --free --label qual --so-pin 5678 --pin 1234 >/dev/null || exit 65
chown -R "$RUNUID:$RUNGID" tokens; chmod 644 softhsm2.conf
sh -c 'kill -HUP $$' >/dev/null 2>&1; status=$?
[ "$status" = 129 ] || { echo "SIGHUP positive control failed rc=$status" >&2; exit 65; }
env --default-signal=INT sh -c 'kill -INT $$' >/dev/null 2>&1 & wait $!
[ $? = 130 ] || { echo 'SIGINT positive control failed' >&2; exit 65; }
# Filtered subset (names validated above): run only the requested gated
# cells through the same lifecycles and judge exactly that set.
# scripts/ci/legacy32-shape.sh selects 'profile-pid system'.
if [ -n "${P11SCOPE_PUBLIC_CLI_CELLS:-}" ]; then
  # shellcheck disable=SC2086
  set -- $P11SCOPE_PUBLIC_CLI_CELLS
  for cell in "$@"; do
    case $cell in
      profile-pid) gated profile-pid pid "$GATED" profile --pid @PID@ --duration 12 -o "$OUT/profile-pid.json" ;;
      metrics-pid) gated metrics-pid pid "$GATED" profile --mode metrics --pid @PID@ --duration 12 -o "$OUT/metrics-pid.json" ;;
      trace-pid) gated trace-pid pid "$GATED" trace --pid @PID@ --duration 12 -o "$OUT/trace-pid.txt" ;;
      mt-exact) gated mt-exact pid "$MT" profile --pid @PID@ --duration 25 -o "$OUT/mt-exact.json" ;;
      system) system_cell ;;
    esac
  done
  summary "$@"; exit $?
fi
# Ia32-only job (P11SCOPE_PUBLIC_CLI_ONLY_IA32=1): run only the two ia32 cells.
# The ia32 job installs libsofthsm2:i386 (which cannot coexist with amd64 in the
# main job) and must have the prereq; missing prereq here is a harness failure.
if [ "${P11SCOPE_PUBLIC_CLI_ONLY_IA32:-0}" = 1 ]; then
  IA32_MODULE=${IA32_MODULE:-/usr/lib/i386-linux-gnu/softhsm/libsofthsm2.so}
  IA32_OK=0
  if [ -r "$IA32_MODULE" ] && gcc -m32 -O1 -o "$FIX/gated32" "$SRC/gated.c" -ldl 2>/dev/null; then
    chmod 755 "$FIX/gated32"
    IA32_OK=1
  fi
  if [ "$IA32_OK" = 1 ]; then
    MODULE_BAK=$MODULE; MODULE=$IA32_MODULE
    gated profile-pid-ia32 pid "$FIX/gated32" profile --pid @PID@ --duration 12 -o "$OUT/profile-pid-ia32.json"
    run_exact run-ia32 "$FIX/gated32" 3
    MODULE=$MODULE_BAK
  else
    for cell in profile-pid-ia32 run-ia32; do
      result "$cell" 0 "ia32-only job missing prereq: $IA32_MODULE not readable or -m32 build failed" failed
    done
  fi
  summary profile-pid-ia32 run-ia32; exit $?
fi
"$P" doctor > doctor.out 2>&1; rc=$?
result doctor "$([ "$rc" = 0 ] && grep -q 'capture available' doctor.out && grep -qE '^uprobe-multi attach \(own libc\) \.+ ok([ \t].*)?$' doctor.out && grep -qE '^uretprobe vs seccomp \.+ ok([ \t].*)?$' doctor.out && echo 1 || echo 0)" "rc=$rc"
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
run_exact run-short "$GATED" 3
run_exact run-cover "$GATED" 2000
run_prearm
gated mt-exact pid "$MT" profile --pid @PID@ --duration 25 -o "$OUT/mt-exact.json"
system_cell
# SIGINT exact: the workload does exactly K calls, emits LEDGER, then holds.
# SIGINT arrives after the ledger is complete; require exact counts, a proven
# drain and exact observation via the oracle.
sigint_exact() {
  local cell=sigint scope=pid gate=$OUT/sigint.gate
  rm -f -- "$gate" sigint.json sigint.wl sigint.stderr sigint.stdout sigint.receipt.json
  local output; output=$(product_output sigint.json)
  [ "$LOCAL_OUTPUT" = "$OUT" ] || rm -f -- "$output"
  local before after gen='' readygen='' wl='' pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  before=$(pin) || { result "$cell" 0 'provider pin failed' failed; return 1; }
  asuser "$GATED" "$MODULE" "$ITERS" 200 "$gate" > sigint.wl 2>&1 & wl=$!; register "$wl" && gen=${CHILDREN[$wl]}
  if waitfor sigint.wl "^READY pid=$wl$" "$wl" "$READY_TICKS"; then
    ready=1; readygen=$(generation "$wl")
    env --default-signal=INT "$P" profile --pid "$wl" --duration 120 -o "$output" > sigint.stdout 2> sigint.stderr & pp=$!; register "$pp" || true
    if waitfor sigint.stderr 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
      capturing=1
      if touch "$gate"; then
        released=1
        if waitfor sigint.wl '^LEDGER ' "$wl" "$LEDGER_TICKS" 1; then
          sleep 1; kill -INT "$pp"
          if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
        fi
      fi
    fi
  fi
  if [ -n "$pp" ] && [ -n "${CHILDREN[$pp]:-}" ]; then terminate "$pp"; observer_rc=$LAST_EXIT; fi
  terminate "$wl"; workload_rc=$LAST_EXIT
  after=$(pin) || after='null'
  receipt || { result "$cell" 0 'receipt publication failed' failed; return 1; }
  publish_output sigint.json || { result "$cell" 0 'output copy failed' failed; return 1; }
  judge sigint.json sigint.wl sigint.receipt.json sigint
}
sigint_exact
second_sigint
fifo_refused
# WP-4 breadth: cgroup scopes (S5).
cgroup_capture profile-cgroup profile
cgroup_capture metrics-cgroup metrics
cgroup_capture trace-cgroup trace
cgroup_capture inventory-cgroup inventory
# WP-4 breadth: counter modes and select-endpoint (S6).
gated counter-counts-pid pid "$GATED" profile --mode metrics --counter-mode counts --pid @PID@ --duration 12 -o "$OUT/counter-counts-pid.json"
gated counter-timestamps-pid pid "$GATED" profile --mode metrics --counter-mode timestamps --pid @PID@ --duration 12 -o "$OUT/counter-timestamps-pid.json"
gated counter-latency-pid pid "$GATED" profile --mode metrics --counter-mode latency --pid @PID@ --duration 12 -o "$OUT/counter-latency-pid.json"
gated counter-counts-system system "$GATED" profile --mode metrics --counter-mode counts --system --module "$MODULE" --duration 25 -o "$OUT/counter-counts-system.json"
gated counter-timestamps-system system "$GATED" profile --mode metrics --counter-mode timestamps --system --module "$MODULE" --duration 25 -o "$OUT/counter-timestamps-system.json"
gated counter-latency-system system "$GATED" profile --mode metrics --counter-mode latency --system --module "$MODULE" --duration 25 -o "$OUT/counter-latency-system.json"
gated select-endpoint-pid pid "$GATED" profile --mode metrics --counter-mode counts --select-endpoint C_Digest --module "$MODULE" --pid @PID@ --duration 12 -o "$OUT/select-endpoint-pid.json"
gated select-endpoint-system system "$GATED" profile --mode metrics --counter-mode counts --select-endpoint C_Digest --module "$MODULE" --system --duration 25 -o "$OUT/select-endpoint-system.json"
# WP-4 breadth: ia32 through the public command (S12). IA32_MODULE allows an
# unpacked i386 copy (apt i386 cannot coexist with amd64 in the main job); the
# ia32-only job (P11SCOPE_PUBLIC_CLI_ONLY_IA32=1 above) installs via apt.
IA32_MODULE=${IA32_MODULE:-/usr/lib/i386-linux-gnu/softhsm/libsofthsm2.so}
IA32_OK=0
if [ -r "$IA32_MODULE" ] && gcc -m32 -O1 -o "$FIX/gated32" "$SRC/gated.c" -ldl 2>/dev/null; then
  chmod 755 "$FIX/gated32"
  IA32_OK=1
fi
if [ "$IA32_OK" = 1 ]; then
  MODULE_BAK=$MODULE; MODULE=$IA32_MODULE
  gated profile-pid-ia32 pid "$FIX/gated32" profile --pid @PID@ --duration 12 -o "$OUT/profile-pid-ia32.json"
  # run-ia32 uses the 32-bit fixture and provider; run_exact reads $MODULE.
  run_exact run-ia32 "$FIX/gated32" 3
  MODULE=$MODULE_BAK
else
  for cell in profile-pid-ia32 run-ia32; do
    result "$cell" 0 "$REASON_IA32: $IA32_MODULE not readable or -m32 build failed; CI: ia32-only job with dpkg --add-architecture i386 && apt-get update && apt-get install -y libsofthsm2:i386 gcc-multilib libc6-dev-i386" expected-failure
  done
fi
# WP-4 breadth: startup latency as its own cell (S15). Bound is a harness
# parameter, not a user promise; record the three measured values.
# Default 45s: 7.2 guests measured 22213/23471/24553 ms (max 24.6s); 30s gives
# only 18% margin ((30-24.6)/30) and flakes on 7.3.1/busy runners. 45s gives
# 45% margin with 20s headroom, still far below the 180s capture ticks so hangs
# are caught. Override per environment with P11SCOPE_STARTUP_BOUND_S.
startup_cell() {
  local cell=startup-to-capturing bound_s=${P11SCOPE_STARTUP_BOUND_S:-${STARTUP_BOUND_S:-45}}
  local gate=$OUT/startup.gate
  rm -f -- "$gate" startup-to-capturing.json startup.wl startup.stderr startup.stdout
  local -a samples=()
  local trial_ok=1
  for _ in 1 2 3; do
    rm -f -- "$gate" startup.wl startup.stderr startup.stdout
    local wl pp start_ns end_ns delta_ms
    asuser "$GATED" "$MODULE" 500 200 "$gate" > startup.wl 2>&1 & wl=$!; register "$wl" || true
    if ! waitfor startup.wl "^READY pid=$wl$" "$wl" "$READY_TICKS"; then trial_ok=0; terminate "$wl" || true; break; fi
    start_ns=$(date +%s%N)
    "$P" profile --pid "$wl" --duration 2 -o "$OUT/startup-to-capturing.json" > startup.stdout 2> startup.stderr & pp=$!; register "$pp" || true
    if waitfor startup.stderr 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
      end_ns=$(date +%s%N)
      delta_ms=$(( (end_ns - start_ns) / 1000000 ))
      samples+=("$delta_ms")
      touch "$gate" || true
      if finish "$pp" "$EXIT_TICKS"; then :; else trial_ok=0; fi
    else
      trial_ok=0
    fi
    [ -n "${CHILDREN[$pp]:-}" ] && terminate "$pp" || true
    terminate "$wl" || true
  done
  local detail="startup_ms=${samples[*]:-none} bound_s=$bound_s trials=${#samples[@]}"
  if [ "$trial_ok" != 1 ] || [ "${#samples[@]}" != 3 ]; then result "$cell" 0 "$detail" failed; return 1; fi
  local bound_ms=$(( bound_s * 1000 ))
  for ms in "${samples[@]}"; do
    if [ "$ms" -gt "$bound_ms" ]; then result "$cell" 0 "$detail over_bound_ms=$ms" failed; return 1; fi
  done
  result "$cell" 1 "$detail"
}
startup_cell
summary doctor profile-pid names-pid verdict-pid metrics-pid trace-pid run-short run-cover run-prearm mt-exact system sigint second-sigint fifo-refused profile-cgroup metrics-cgroup trace-cgroup inventory-cgroup counter-counts-pid counter-timestamps-pid counter-latency-pid counter-counts-system counter-timestamps-system counter-latency-system select-endpoint-pid select-endpoint-system profile-pid-ia32 run-ia32 startup-to-capturing
exit $?

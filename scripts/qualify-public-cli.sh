#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
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
# runner noise on the system cells (`system`, `mt-system` and its mode
# twins `mt-system-metrics`, `mt-system-trace`) only; default 0 keeps
# every cell strict. Ruling U1: on `mt-system` only, the same flag
# also discloses the named {discovery subject, discovery unavailable}
# skips; each named cause prints its count, owned counts stay exact, and
# any other cause still fails.
set -u
_SRC=${BASH_SOURCE[0]:-$0}
HERE=$(cd "$(dirname "$_SRC")" && pwd) || exit 64
ORACLE=$HERE/public-cli-oracle.py
# Every structured-evidence decision below is one judge of the typed
# loader (strict records, run-bound inputs, declared rules).
RECORDS=$HERE/qualify_records.py
# Every input this shell reads is declared once in runner_inputs.py, the
# declaration the release stage is built from; a missing one refuses here,
# before any cell.
[ -f "$HERE/runner_inputs.py" ] && [ -r "$HERE/runner_inputs.py" ] || { echo "qualify-public-cli.sh: required input missing: $HERE/runner_inputs.py" >&2; exit 64; }
python3 -I "$HERE/runner_inputs.py" check "$HERE/.." scripts/qualify-public-cli.sh run || exit 64
CONTROL=0
CONTROL_KIND=gated
if [ "${1:-}" = --control-gated ]; then CONTROL=1; shift
elif [ "${1:-}" = --control-second-sigint ]; then CONTROL=1; CONTROL_KIND=signal; shift
elif [ "${1:-}" = --control-fifo ]; then CONTROL=1; CONTROL_KIND=fifo; shift
elif [ "${1:-}" = --control-event-stdout ]; then CONTROL=1; CONTROL_KIND=event; shift; fi
# The cell filter is validated before any setup, so a typo fails before a
# privileged campaign starts. Only the gated lifecycle cells are runnable
# as a subset; derived and smoke cells stay full-campaign-only.
if [ -n "${P11SCOPE_PUBLIC_CLI_CELLS:-}" ] && [ "$CONTROL" = 1 ]; then
  echo 'P11SCOPE_PUBLIC_CLI_CELLS cannot be combined with a --control mode' >&2
  exit 64
fi
if [ -n "${P11SCOPE_PUBLIC_CLI_CELLS:-}" ] && [ "${P11SCOPE_PUBLIC_CLI_ONLY_IA32:-0}" = 1 ]; then
  echo 'P11SCOPE_PUBLIC_CLI_CELLS cannot be combined with P11SCOPE_PUBLIC_CLI_ONLY_IA32=1' >&2
  exit 64
fi
# shellcheck disable=SC2086
for _cell in ${P11SCOPE_PUBLIC_CLI_CELLS:-}; do
  case $_cell in
    profile-pid|metrics-pid|trace-pid|mt-exact|system|mt-metrics|mt-errors|mt-shared|mt-churn|mt-trace|mt-system|mt-system-metrics|mt-system-trace|counter-latency-mt|inventory-mt-pid|inventory-mt-system|inventory-provider-info-pid) ;;
    *) echo "unsupported subset cell: $_cell (supported: profile-pid metrics-pid trace-pid mt-exact system mt-metrics mt-errors mt-shared mt-churn mt-trace mt-system mt-system-metrics mt-system-trace counter-latency-mt inventory-mt-pid inventory-mt-system inventory-provider-info-pid)" >&2; exit 64 ;;
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
  elif [ "$CONTROL_KIND" = event ]; then
    [ $# = 3 ] || exit 64
    CONTROL_CELL=inventory-event-stdout
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
  IA32_MODULE=${IA32_MODULE:-/usr/lib/i386-linux-gnu/softhsm/libsofthsm2.so}
  if [ "${P11SCOPE_PUBLIC_CLI_ONLY_IA32:-0}" = 1 ]; then
    # The ia32-only job carries no amd64 provider (libsofthsm2:i386
    # cannot coexist with it), so there is nothing to probe: take the
    # i386 module; the ia32 branch below validates the prereq and
    # fails harness-loud when it is missing.
    MODULE=$IA32_MODULE
  else
    MODULE_ARGS=(); [ -z "${MODULE+x}" ] || MODULE_ARGS=(--module "$MODULE")
    MODULE=$(python3 -I "$HERE/release-matrix-contract.py" --select-module "${MODULE_ARGS[@]}") || exit 64
  fi
  READY_TICKS=1800; LEDGER_TICKS=600; EXIT_TICKS=1800
fi
mkdir -p "$OUT" && chmod 755 "$OUT" && OUT=$(realpath -e -- "$OUT") && cd "$OUT" || exit 64
# This invocation's run id (a random nonce): every judged input must carry
# a stamp of it, and it names the private producer-output directory.
RUN_ID=$(cat /proc/sys/kernel/random/uuid) || exit 64
# setup_local_output: the product writes only into this invocation's own
# directory, created exclusively under $OUT or the configured local root,
# so two invocations sharing a root never see each other's reports.
setup_local_output() {
  LOCAL_BASE=$OUT
  if [ -n "${P11SCOPE_LOCAL_OUTPUT_ROOT:-}" ]; then
    LOCAL_BASE=$(python3 -I "$HERE/release-matrix-contract.py" --check-work-root "$P11SCOPE_LOCAL_OUTPUT_ROOT") || return 1
  fi
  LOCAL_OUTPUT=$LOCAL_BASE/run-$RUN_ID
  mkdir -m 755 -- "$LOCAL_OUTPUT"
}
setup_local_output || exit 64
product_output() { printf '%s/%s\n' "$LOCAL_OUTPUT" "$1"; }
# publish_output NAME: the published copy is this invocation's own
# completed report (a hard link beside it, or a verified copy off a
# separate local root); a missing report fails in both layouts.
publish_output() {
  if [ "$LOCAL_BASE" = "$OUT" ]; then ln -f -- "$LOCAL_OUTPUT/$1" "$OUT/$1"; return; fi
  python3 -I "$HERE/release-matrix-contract.py" --copy-file "$LOCAL_OUTPUT/$1" "$OUT/$1"
}
: > results.jsonl
# stamp_leg CELL PATH...: remove each destination, prove it absent, then
# stamp the run; a judged input must be written at or after the stamp.
stamp_leg() {
  local cell=$1 path; shift
  for path in "$cell.stamp" "$@"; do
    rm -f -- "$path" || return 1
    [ ! -e "$path" ] && [ ! -L "$path" ] || return 1
  done
  python3 -I "$RECORDS" stamp "$cell.stamp" "$RUN_ID" "$cell"
}
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
  python3 -I - "$1" "$2" "$3" "${4:-command-contract}" <<'PY' | tee -a results.jsonl
import json,sys
print(json.dumps({'cell':sys.argv[1],'pass':sys.argv[2]=='1','detail':sys.argv[3],'qualification':sys.argv[4]}))
PY
}
# Expected-failure reasons for known product gaps. Each names the gap and,
# where a fix is still pending, the product fix lane. Unexpected passes
# fail via summary() and the WP-1 template.
REASON_CGROUP="cgroup fork observation gaps; product fix lane for cgroup fork"
REASON_TRACE_CGROUP="cgroup trace lossy observation; product fix lane for cgroup trace"
REASON_IA32="ia32 prereq missing (libsofthsm2:i386 cannot coexist with amd64); ia32-only job"
REASON_COUNTER_SMALL="counter modes unavailable in this SMALL build (the build omits counter objects)"
# The documented build-gate refusal, byte-exact without the p11scope prefix
# (src/attach/counter_banks.rs check_counter_build; release builds emit
# the objects and can never print it). The probe and the per-cell arm
# share it.
COUNTER_BUILD_REFUSAL="counter-mode-unavailable-in-build: this build omits counter objects"
# No kernel can hold this pid (2^31 - 1 exceeds every pid_max), so the
# probe and the refusal arm never attach: the build gate fires first on
# builds without counter objects, and anything else fails later for
# another reason (bogus pid, privilege), which is the healthy arm.
COUNTER_BOGUS_PID=2147483647
asuser_conf() {
  local conf=$1; shift
  if [ "$CONTROL" = 1 ]; then SOFTHSM2_CONF="$conf" exec "$@"; fi
  exec setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups env SOFTHSM2_CONF="$conf" P11SCOPE_CGROUP_FORK_CHILD_CONF="${P11SCOPE_CGROUP_FORK_CHILD_CONF:-}" "$@"
}
asuser() {
  if [ "$CONTROL" = 1 ]; then exec "$@"; fi
  asuser_conf "$SOFTHSM2_CONF" "$@"
}
pin() {
  python3 -I "$HERE/mapped-provider-pin.py" "$MODULE"
}
receipt() {
  python3 -I - "$cell" "$scope" "$wl" "$gen" "$readygen" "$ready" "$capturing" "$released" "$observer_rc" "$workload_rc" "$before" "$after" <<'PY' > "$cell.receipt.json"
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
    profile-cgroup) reason=$REASON_CGROUP ;;
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
  qual=$(printf '%s' "$line" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["qualification"])') || qual=failed
  detail=$(printf '%s' "$line" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["detail"])') || detail="$line"
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
    profile-cgroup)
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
  # runner noise on the system cells (`system`, `mt-system`) only. Every
  # other cell stays strict, and unset/0 keeps the system cells strict
  # (fedora, sm1, vng guests). Ruling U1 extends the `mt-system`
  # allowance to the named discovery-skip pair; `system` keeps the
  # CI-GAP-1 cause set.
  local -a extra=()
  # The mt-system mode twins (mt-system-metrics, mt-system-trace) run the
  # same workload and inherit its rulings.
  if [[ "${4:-}" = system || "${4:-}" = mt-system || "${4:-}" = mt-system-metrics || "${4:-}" = mt-system-trace ]] \
      && [ "${P11SCOPE_ALLOW_PID_DESCENDANT_GAPS:-0}" = 1 ]; then
    extra=(--allow-pid-descendant-gaps)
  fi
  # Flake-66: the 6.6 leg rarely reports PARTIAL with exactly one
  # redacted discovery skip on select-endpoint-system (short-lived
  # kernel tasks racing system discovery while every count stays
  # exact). Disclose exactly that record on 6.6 kernels; every other
  # cell and kernel stays strict, and any other gap still fails.
  if [ "${4:-}" = select-endpoint-system ] && [[ $(uname -r) =~ ^6\.6\. ]]; then
    extra+=(--allow-66-discovery-gap)
  fi
  # Ambient-burst lane, evidence-only: the harness census of
  # out-of-tree exits annotates system-cell failures for triage; the
  # cells stay strict with or without it (a missing census never
  # weakens the gate).
  if [[ "${4:-}" = system || "${4:-}" = mt-system ]] && [ -s "$4.census.jsonl" ]; then
    extra+=(--census "$4.census.jsonl")
  fi
  local out rc
  case "${4:-}" in
    inventory-mt-*)
      out=$(python3 -I "$HERE/inventory-mt-oracle.py" --report "$1" --ledger "$2" --receipt "$3" --cell "$4" --event-log "$4.eventlog.jsonl" "${extra[@]}"); rc=$? ;;
    inventory-provider-info-pid)
      out=$(python3 -I "$HERE/inventory-provider-info-oracle.py" --report "$1" --ledger "$2" --receipt "$3" --cell "$4" --event-log "$4.eventlog.jsonl" "${extra[@]}"); rc=$? ;;
    *)
      out=$(python3 -I "$ORACLE" --report "$1" --ledger "$2" --receipt "$3" --cell "$4" "${extra[@]}"); rc=$? ;;
  esac
  emit_judged "$4" "$rc" "$out"
}
# The real lifecycle is also the unprivileged seam: clean every prior artifact,
# require both processes alive and capture readiness, then release exactly once.
gated() {
  local cell=$1 scope=$2 fixture=$3; shift 3
  local gate=$OUT/$cell.gate ext=json
  case "$cell" in trace-*|mt-trace|mt-system-trace) ext=txt;; esac
  rm -f -- "$gate" "$cell.$ext" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json" "$cell.eventlog.jsonl" \
    "$cell.census.jsonl" "$cell.census.stop" "$cell.census.capturing" "$cell.census.settled" "$cell.census.ready" "$cell.census.stderr"
  local output; output=$(product_output "$cell.$ext")
  rm -f -- "$output"
  local before after gen='' readygen='' wl pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  local poll=waitfor settle=finish release=touch
  if [ "$scope" = system ]; then poll=waitfor_quiet settle=finish_quiet release=touch_quiet; fi
  before=$(pin) || { result "$cell" 0 'provider pin failed' failed; return 1; }
  case "$cell" in
    mt-exact) asuser "$fixture" "$MODULE" "$THREADS" 5 0 "$gate" > "$cell.wl" 2>&1 & ;;
    mt-metrics) asuser "$fixture" "$MODULE" 8 1000 "$gate" sessions 0 > "$cell.wl" 2>&1 & ;;
    mt-errors) asuser "$fixture" "$MODULE" 8 1000 "$gate" sessions 5 > "$cell.wl" 2>&1 & ;;
    mt-shared) asuser "$fixture" "$MODULE" 32 250 "$gate" shared 0 > "$cell.wl" 2>&1 & ;;
    mt-churn) asuser "$fixture" "$MODULE" 32 250 "$gate" churn 0 > "$cell.wl" 2>&1 & ;;
    mt-trace) asuser "$fixture" "$MODULE" 8 100 "$gate" sessions 0 > "$cell.wl" 2>&1 & ;;
    counter-latency-mt) asuser "$fixture" "$MODULE" 8 500 "$gate" sessions 0 > "$cell.wl" 2>&1 & ;;
    mt-system|mt-system-metrics|mt-system-trace) asuser "$fixture" "$MODULE" 4 8 250 "$gate" 0 > "$cell.wl" 2>&1 & ;;
    inventory-mt-pid) asuser "$fixture" "$MODULE" 8 1000 "$gate" sessions 0 > "$cell.wl" 2>&1 & ;;
    inventory-mt-system) asuser "$fixture" "$MODULE" 4 8 250 "$gate" 0 > "$cell.wl" 2>&1 & ;;
    inventory-provider-info-pid) asuser "$fixture" "$MODULE" "$gate" > "$cell.wl" 2>&1 & ;;
    *) asuser "$fixture" "$MODULE" "$ITERS" 200 "$gate" > "$cell.wl" 2>&1 & ;;
  esac
  wl=$!; register "$wl" && gen=${CHILDREN[$wl]}
  local census_pid=''
  case "$cell" in system|mt-system) census_pid=pending;; esac
  if waitfor "$cell.wl" "^READY pid=$wl$" "$wl" "$READY_TICKS"; then
    ready=1; readygen=$(generation "$wl")
    # Ambient-burst lane: start the fork-free /proc census before the
    # observer exists and wait for its baseline, so every process born
    # inside the capture window gets ancestry. A census that never
    # becomes ready fails the cell on purpose: setup trouble means the
    # harness itself is broken, and a degraded cell must fail loud
    # rather than run silently uninstrumented.
    if [ "$census_pid" = pending ]; then
      python3 -I "$HERE/system-cell-census.py" --out "$cell.census.jsonl" --stop "$cell.census.stop" \
        --workload "$wl" --capturing "$cell.census.capturing" --settled "$cell.census.settled" \
        --ready "$cell.census.ready" --poll-ms 5 >"$cell.census.stderr" 2>&1 & census_pid=$!
      register "$census_pid" || true
      if ! waitfor "$cell.census.ready" "^ready$" "$census_pid" "$READY_TICKS"; then
        terminate "$census_pid" || true; census_pid=''
        terminate "$wl" || true
        result "$cell" 0 'census never became ready' failed; return 1
      fi
    fi
    local args=("${@//@PID@/$wl}")
    local evlog
    evlog=$(product_output "$cell.eventlog.jsonl")
    for ((i=0;i<${#args[@]}-1;i++)); do
      [ "${args[$i]}" != -o ] || args[$((i+1))]=$output
      [ "${args[$i]}" != --event-log ] || args[$((i+1))]=$evlog
    done
    # The inventory-mt stop below arrives by SIGINT (sigint_exact
    # precedent): reset an inherited SIGINT ignore so the observer's own
    # stop handler deterministically installs.
    local sigint_env=()
    case "$cell" in inventory-mt-*|inventory-provider-info-pid) sigint_env=(env --default-signal=INT);; esac
    "${sigint_env[@]}" "$P" "${args[@]}" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
    local ready_needle='p11scope: capturing:'
    case "$cell" in inventory-mt-*|inventory-provider-info-pid) ready_needle='native usage lane active';; esac
    if "$poll" "$cell.stderr" "$ready_needle" "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
      capturing=1
      # Capture window opens here (shell builtin only: every fork during
      # a system capture is a descendant gap).
      if [ -n "$census_pid" ] && [ "$census_pid" != pending ]; then : >> "$cell.census.capturing"; fi
      # Inventory counts only calls made after an edge is native-matched, so
      # the inventory-mt cells hold the workload gate until every workload
      # edge is matched in the event stream. The wait follows the product's
      # own progress (pass heartbeats), not a wall budget on the match: the
      # stall budget fails a wedged observer, the overall backstop bounds a
      # product that progresses but never matches. Budgets sized at ~4x over
      # measured loaded upper bounds (pid started-based match <= 14.5s with
      # steady pass gaps <= 3.8s; system <= 22.5s with gaps <= 4.8s; the
      # gate window from lane-active is strictly inside those spans).
      local match_ok=1 match_stall=0 match_overall=0
      case "$cell" in
        inventory-mt-pid|inventory-provider-info-pid) match_stall=10; match_overall=60 ;;
        inventory-mt-system) match_stall=20; match_overall=90 ;;
      esac
      if [ "$match_stall" != 0 ]; then
        if python3 -I "$HERE/inventory-mt-gate.py" --event-log "$evlog" --wl "$cell.wl" --timeout "$match_stall" --overall-timeout "$match_overall" --observer-pid "$pp"; then
          match_ok=1
        else
          match_ok=0
        fi
      fi
      if [ "$match_ok" = 1 ] && "$release" "$gate"; then
        released=1
        if "$poll" "$cell.wl" '^LEDGER ' "$wl" "$LEDGER_TICKS" 1; then
          case "$cell" in
            inventory-mt-*|inventory-provider-info-pid)
              # The workload is done (LEDGER holds its exact totals); let
              # the product count on its own cadence (two further passes
              # surely collected after the ledger, since pass collections
              # run sequentially), then stop it with SIGINT like
              # sigint_exact. A troubled settle still proceeds to the stop:
              # the unchanged oracle judges the stop-drain counts strictly.
              python3 -I "$HERE/inventory-mt-gate.py" --event-log "$evlog" --settle-passes 2 --timeout "$match_stall" --overall-timeout "$match_overall" --observer-pid "$pp" || true
              if alive "$pp"; then kill -INT "$pp" 2>/dev/null || true; fi
              ;;
          esac
          if "$settle" "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
        fi
      fi
    fi
  fi
  if [ -n "$pp" ] && [ -n "${CHILDREN[$pp]:-}" ]; then terminate "$pp"; observer_rc=$LAST_EXIT; fi
  # The observer is settled above, so the capture window is closed: mark
  # it before the harness tail (terminate sleeps) forks, or the tail
  # lands in-window and inflates the join. The harness root below keeps
  # any poll-quantum straggler out of the ambient join either way.
  if [ -n "$census_pid" ] && [ "$census_pid" != pending ]; then : >> "$cell.census.settled"; fi
  case "$cell" in
    mt-exact|mt-metrics|mt-errors|mt-shared|mt-churn|mt-trace|counter-latency-mt|mt-system|mt-system-metrics|mt-system-trace)
      # The mt workloads self-exit after LEDGER; every other workload holds.
      if [ "$released" = 1 ] && finish "$wl" "$LEDGER_TICKS"; then
        workload_rc=$LAST_EXIT
      elif [ "$released" = 1 ]; then
        workload_rc=124
      else
        terminate "$wl"; workload_rc=$LAST_EXIT
      fi ;;
    *)
      terminate "$wl"; workload_rc=$LAST_EXIT ;;
  esac
  # Post-capture: stop the census and bind the observer and harness
  # pids for tree roots. A census that died mid-cell leaves its stderr
  # behind and the oracle fails the census arm closed on the incomplete
  # window.
  if [ -n "$census_pid" ] && [ "$census_pid" != pending ]; then
    : >> "$cell.census.stop"
    finish "$census_pid" "$READY_TICKS" || true
    if [ -n "$pp" ]; then printf '{"type": "observer", "pid": %d}\n' "$pp" >> "$cell.census.jsonl"; fi
    printf '{"type": "harness", "pid": %d}\n' "$$" >> "$cell.census.jsonl"
  fi
  after=$(pin) || after='null'
  receipt || { result "$cell" 0 'receipt publication failed' failed; return 1; }
  publish_output "$cell.$ext" || { result "$cell" 0 'output copy failed' failed; return 1; }
  case "$cell" in inventory-mt-*|inventory-provider-info-pid) publish_output "$cell.eventlog.jsonl" || { result "$cell" 0 'event-log copy failed' failed; return 1; };; esac
  judge "$cell.$ext" "$cell.wl" "$cell.receipt.json" "$cell"
}
# Counter-build probe, once per campaign (CONTROL modes skip it: they run
# no counter cell and their fake observers answer nothing here). 0 when
# the observer passes the counter gate (release build: the bogus pid fails
# later for another reason), 1 when it refuses with the exact documented
# build reason (SMALL build), 64 when the outcome is inconclusive (an
# observer that captures against a bogus pid, or refuses noisily, fails
# loud before any cell runs).
counter_build_supported() {
  local probe_out=$OUT/counter-build-probe.json rc=0
  rm -f -- "$probe_out" "$OUT/counter-build-probe.stdout" "$OUT/counter-build-probe.stderr"
  "$P" profile --mode metrics --counter-mode counts --pid "$COUNTER_BOGUS_PID" --duration 1 -o "$probe_out" \
    >"$OUT/counter-build-probe.stdout" 2>"$OUT/counter-build-probe.stderr" || rc=$?
  if [ "$rc" = 1 ] && [ ! -e "$probe_out" ] && [ ! -s "$OUT/counter-build-probe.stdout" ] \
      && printf 'p11scope: %s\n' "$COUNTER_BUILD_REFUSAL" | cmp -s - "$OUT/counter-build-probe.stderr"; then
    return 1
  fi
  if [ "$rc" != 0 ] && ! grep -qF "$COUNTER_BUILD_REFUSAL" "$OUT/counter-build-probe.stderr"; then
    return 0
  fi
  echo "counter build probe inconclusive rc=$rc" >&2
  return 64
}
# Exact-refusal control for one counter/select-endpoint cell on a build
# without counter objects: run the cell's observer args (pid cells take
# the same bogus pid the probe used — the build gate fires before pid
# validation, so no workload is needed) and require exit 1, silent
# stdout, the exact documented refusal on stderr, and no output file.
# Emits expected-failure on the exact refusal; anything else stays failed.
counter_refused() {
  local cell=$1; shift
  local args=() out="" prev="" arg
  for arg in "$@"; do
    if [ "$prev" = -o ]; then out=$arg; fi
    prev=$arg
    case $arg in @PID@) args+=("$COUNTER_BOGUS_PID");; *) args+=("$arg");; esac
  done
  [ -n "$out" ] || { result "$cell" 0 "refusal control without -o target" failed; return 1; }
  rm -f -- "$out" "$cell.stderr" "$cell.stdout"
  local rc=0
  "$P" "${args[@]}" >"$cell.stdout" 2>"$cell.stderr" || rc=$?
  if [ "$rc" = 1 ] && [ ! -e "$out" ] && [ ! -s "$cell.stdout" ] \
      && printf 'p11scope: %s\n' "$COUNTER_BUILD_REFUSAL" | cmp -s - "$cell.stderr"; then
    result "$cell" 0 "$REASON_COUNTER_SMALL: [$cell] exit=1 refusal=$COUNTER_BUILD_REFUSAL" expected-failure
    return 0
  fi
  result "$cell" 0 "expected the documented counter-build refusal, got rc=$rc stderr=$(head -c 200 "$cell.stderr" | tr '\n' ' ')" failed
  return 1
}
# Counter/select-endpoint cells branch on the build: builds with counter
# objects capture through the ordinary gated lifecycle; builds without
# them prove the exact refusal instead.
counter_cell() {
  local cell=$1 scope=$2 fixture=$3; shift 3
  if [ "$COUNTER_SUPPORTED" = 1 ]; then
    gated "$cell" "$scope" "$fixture" "$@"
    return $?
  fi
  counter_refused "$cell" "$@"
}
system_cell() {
  gated system system "$GATED" profile --system --module "$MODULE" --duration 25 -o "$OUT/system.json"
}
summary() {
  python3 -I - "$@" <<'PY' | tee summary.txt
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
  stamp_leg second-sigint "$output" "$OUT/sigint2.json" sig2.stdout sig2.stderr second-sigint.verdict.json || { result second-sigint 0 'run stamp failed' failed; return 1; }
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
  local judged=0 detail
  detail=$(python3 -I "$RECORDS" second-sigint --stamp second-sigint.stamp --run-id "$RUN_ID" --verdict second-sigint.verdict.json --report "$output" --stderr sig2.stderr --rc "$rc" --custody "$custody" --cleanup "$cleanup_ok") && judged=1
  result second-sigint "$judged" "rc=$rc child_custody=$custody child=${child:-unknown} cleanup_complete=$cleanup_ok $(printf '%.300s' "$detail")"
}
fifo_refused() {
  local wl rc=125 judged=0 detail
  rm -f fifo; mkfifo fifo || return 1
  stamp_leg fifo-refused fifo.stdout fifo.stderr fifo-refused.verdict.json || { result fifo-refused 0 'run stamp failed' failed; return 1; }
  asuser "$GATED" "$MODULE" 100000000 1000 - > fifo.wl 2>&1 & wl=$!; register "$wl" || true
  if waitfor fifo.wl '^READY pid=' "$wl" "$READY_TICKS"; then
    # This negative must keep the actual FIFO destination, even in local-output mode.
    timeout 60 "$P" profile --pid "$wl" --duration 2 -o "$OUT/fifo" > fifo.stdout 2> fifo.stderr; rc=$?
  fi
  terminate "$wl"
  detail=$(python3 -I "$RECORDS" fifo-refusal --stamp fifo-refused.stamp --run-id "$RUN_ID" --verdict fifo-refused.verdict.json --stderr fifo.stderr --fifo "$OUT/fifo" --rc "$rc") && judged=1
  result fifo-refused "$judged" "rc=$rc $(printf '%.300s' "$detail")"
}
# Event stdout: `--event-log -` streams pure JSONL to stdout (Docker/
# Fluent Bit/Loki with no file mount) while the -o report agrees on
# the counts; a reader that closes early (`head -c`) sheds with
# counters, still commits its report, and exits 1.
inventory_event_stdout() {
  local wl rc1=125 rc2=125 full_out epipe_out judge_rc=1
  full_out=$(product_output event-stdout.json)
  epipe_out=$(product_output event-epipe.json)
  rm -f event-stdout.wl
  # Both report destinations (local and published) start absent, so only
  # this run's reports can be judged.
  stamp_leg inventory-event-stdout "$full_out" "$epipe_out" "$OUT/event-stdout.json" "$OUT/event-epipe.json" event-stdout.jsonl event-stdout.stderr event-epipe.stderr event-epipe.head event-stdout.judge inventory-event-stdout.verdict.json || { result inventory-event-stdout 0 'run stamp failed' failed; return 1; }
  asuser "$GATED" "$MODULE" 100000000 1000 - > event-stdout.wl 2>&1 & wl=$!; register "$wl" || true
  if waitfor event-stdout.wl '^READY pid=' "$wl" "$READY_TICKS"; then
    timeout 120 "$P" inventory --pid "$wl" --duration 6 -o "$full_out" --event-log - --event-interval 2s 2> event-stdout.stderr | cat > event-stdout.jsonl; rc1=${PIPESTATUS[0]}
    timeout 120 "$P" inventory --pid "$wl" --duration 4 -o "$epipe_out" --event-log - 2> event-epipe.stderr | head -c 200 > event-epipe.head; rc2=${PIPESTATUS[0]}
  fi
  terminate "$wl"
  local copied=1
  publish_output event-stdout.json || copied=0
  publish_output event-epipe.json || copied=0
  if [ "$copied" = 1 ]; then
    python3 -I "$RECORDS" event-stdout --stamp inventory-event-stdout.stamp --run-id "$RUN_ID" --verdict inventory-event-stdout.verdict.json --jsonl event-stdout.jsonl --full-report "$full_out" --epipe-report "$epipe_out" --epipe-head event-epipe.head --rc1 "$rc1" --rc2 "$rc2" > event-stdout.judge 2>&1 && judge_rc=0
  else
    echo 'report copy failed' > event-stdout.judge
  fi
  result inventory-event-stdout "$([ "$judge_rc" = 0 ] && echo 1 || echo 0)" "rc1=$rc1 rc2=$rc2 $(tail -n 1 event-stdout.judge 2>/dev/null | head -c 300)"
}
# Open a cell's workload gates only once the observer is ready and every
# named workload still runs. An inventory observer is ready after its first
# pass published (its endpoints attached): a fixed sleep let a loaded host
# run the whole workload before attach, so no row was ever read. The other
# kinds are ready when capturing starts.
observer_gate() {
  local kind=$1 stderr=$2 pp=$3; shift 3
  local pattern='p11scope: capturing:' pid
  [ "$kind" = inventory ] && pattern='^p11scope: pass 0: '
  waitfor "$stderr" "$pattern" "$pp" "$READY_TICKS" || return 1
  for pid in "$pp" "$@"; do alive "$pid" || return 1; done
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
  stamp_leg "$cell" "$output" "$OUT/$cell.$ext" "$cell.detail" "$cell.verdict.json" || { result "$cell" 0 'run stamp failed' failed; return 1; }
  local child_owned=''
  local before after gen='' childgen='' readygen='' inside='' outside='' child='' pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  local scope=cgroup wl=''
  before=$(pin) || { result "$cell" 0 'provider pin failed' failed; return 1; }
  if [ -e "$CG" ]; then
    # cgroupfs files report st_size 0 even with content, so test -s is
    # always false here; read the content instead.
    if [ -n "$(cat "$CG/cgroup.procs" 2>/dev/null)" ]; then
      result "$cell" 0 "stale owned cgroup not empty $CG (prior leak, manual cleanup required)" failed; return 1
    fi
    rmdir "$CG" 2>/dev/null || { result "$cell" 0 "stale owned cgroup not removable $CG" failed; return 1; }
  fi
  mkdir -p "$CG" || { result "$cell" 0 "cgroup mkdir failed $CG" failed; return 1; }
  CGROUPS+=("$CG")
  # One token per workload: concurrent C_OpenSession/C_Login on a shared
  # SoftHSM token fails intermittently under the cgroup thundering herd.
  # The inside parent keeps the campaign token; the fork child and the
  # outside workload get their own pre-inited tokens.
  local tokdir=$OUT/$cell-tokens
  mkdir -p "$tokdir/child/tokens" "$tokdir/outside/tokens" || { result "$cell" 0 'cgroup token dir failed' failed; return 1; }
  printf 'directories.tokendir = %s/child/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$tokdir" > "$tokdir/child/softhsm2.conf" || { result "$cell" 0 'cgroup token conf failed' failed; return 1; }
  printf 'directories.tokendir = %s/outside/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$tokdir" > "$tokdir/outside/softhsm2.conf" || { result "$cell" 0 'cgroup token conf failed' failed; return 1; }
  SOFTHSM2_CONF=$tokdir/child/softhsm2.conf softhsm2-util --init-token --free --label qual --so-pin 5678 --pin 1234 >/dev/null || { result "$cell" 0 'cgroup token init failed' failed; return 1; }
  SOFTHSM2_CONF=$tokdir/outside/softhsm2.conf softhsm2-util --init-token --free --label qual --so-pin 5678 --pin 1234 >/dev/null || { result "$cell" 0 'cgroup token init failed' failed; return 1; }
  chown -R "$RUNUID:$RUNGID" "$tokdir/child/tokens" "$tokdir/outside/tokens" || { result "$cell" 0 'cgroup token chown failed' failed; return 1; }
  chmod 644 "$tokdir/child/softhsm2.conf" "$tokdir/outside/softhsm2.conf" || { result "$cell" 0 'cgroup token conf failed' failed; return 1; }
  # Launched iterations (per inside member, and for the outside
  # workload): the oracle checks each ledger against exactly these.
  local inside_iters=250 outside_iters=500
  P11SCOPE_CGROUP_FORK_CHILD_CONF=$tokdir/child/softhsm2.conf asuser "$CFORK" "$MODULE" "$inside_iters" 200 "$inside_gate" > "$cell-inside.wl" 2>&1 & inside=$!; register "$inside" && gen=${CHILDREN[$inside]}
  asuser_conf "$tokdir/outside/softhsm2.conf" "$GATED" "$MODULE" "$outside_iters" 200 "$outside_gate" > "$cell-outside.wl" 2>&1 & outside=$!; register "$outside" || true
  local inside_ready=0 outside_ready=0 in_cgroup=0
  if waitfor "$cell-inside.wl" "^READY pid=$inside$" "$inside" "$READY_TICKS"; then
    inside_ready=1; readygen=$(generation "$inside")
    if echo "$inside" > "$CG/cgroup.procs" 2>/dev/null && python3 -I "$RECORDS" cgroup-member --procs "$CG/cgroup.procs" --pid "$inside" > /dev/null; then
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
    if observer_gate "$kind" "$cell.stderr" "$pp" "$inside" "$outside"; then
      observer_started=1; capturing=1
    fi
    if [ "$observer_started" = 1 ]; then
      if touch "$inside_gate" && touch "$outside_gate"; then
        released=1
        if waitfor "$cell-inside.wl" '^LEDGER ' "$inside" "$LEDGER_TICKS" 1 && waitfor "$cell-outside.wl" '^LEDGER ' "$outside" "$LEDGER_TICKS" 1; then
          child=$(grep -m1 '^CHILD pid=' "$cell-inside.wl" 2>/dev/null | sed 's/^CHILD pid=//')
          [[ "$child" =~ ^[1-9][0-9]*$ ]] || child=''
          # The fork child counts only as the kernel-verified live child
          # of the inside parent (never a generic registration).
          if [ -n "$child" ] && register_owned_child "$child" "$inside"; then childgen=${CHILDREN[$child]}; child_owned=$child; fi
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
    # stat(1) spells the type "overlayfs" (coreutils S_MAGIC_OVERLAYFS),
    # never the bare "overlay" of /proc/mounts.
    module_fs=$(stat -f -c %T "$MODULE" 2>/dev/null || echo unknown)
    python3 -I "$RECORDS" cgroup-inventory --stamp "$cell.stamp" --run-id "$RUN_ID" --verdict "$cell.verdict.json" --cell "$cell" --report "$output" --inside-wl "$cell-inside.wl" --outside-wl "$cell-outside.wl" --pin "$before" --inside-iters "$inside_iters" --outside-iters "$outside_iters" --module "$MODULE" --module-fs "$module_fs" --inside-pid "$inside" --inside-gen "$gen" --child-pid "${child_owned}" --child-gen "$childgen" --outside-pid "$outside" > "$cell.detail" 2>&1
    rc=$?
    detail=$(cat "$cell.detail" 2>/dev/null || echo "inventory check failed rc=$rc")
    detail="$detail observer_rc=$observer_rc"
    if [ "$rc" = 0 ] && [ "$observer_rc" = 0 ]; then
      result "$cell" 1 "$detail"
    else
      result "$cell" 0 "$detail" failed
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
  rm -f -- "$output"
  local before after wl='' pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  # Run-tree (v0.7.0): owned runs capture the command's child
  # processes at cgroup scope.
  local gen='' readygen='' scope=cgroup
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
  # On kernels before 6.8 the overlayfs scan/pre-arm split either
  # absorbs into the kept pre-arm object at absorb time (the same two
  # shapes as above) or joins live across an id change the exactness
  # proof cannot span (W8B-66: both twins disclose exactly
  # [late_discovery, mapped_unattached] instead). The oracle accepts
  # exactly these two disclosures per twin; anything else fails.
  local name policy ledger output rc pp detail
  stamp_leg run-prearm "$(product_output run-prearm-held.txt)" "$(product_output run-prearm-passive.txt)" run-prearm-held.txt run-prearm-passive.txt run-prearm-held.wl run-prearm-passive.wl run-prearm.verdict.json || { result run-prearm 0 'run stamp failed' prearm-exactness; return 1; }
  for name in held passive; do
    policy=auto; [ "$name" = passive ] && policy=never
    ledger=$OUT/run-prearm-$name.wl
    output=$(product_output "run-prearm-$name.txt")
    rm -f -- "run-prearm-$name.txt" "run-prearm-$name.wl" "run-prearm-$name.stderr" "run-prearm-$name.stdout"
    rm -f -- "$output"
    # The owned child runs demoted to SUDO_UID and opens the ledger
    # itself: pre-create it owned (same precedent as second-child.pid).
    : > "$ledger" && chown "$RUNUID:$RUNGID" "$ledger" && chmod 600 "$ledger" || { result run-prearm 0 "$name ledger setup failed" prearm-exactness; return 1; }
    # shellcheck disable=SC2086
    SUDO_UID=$RUNUID SUDO_GID=$RUNGID "$P" run --trace --pause "$policy" --prearm-module "$MODULE" -o "$output" -- "$PREARM_LOADER" "$MODULE" "$ledger" 3 1500 > "run-prearm-$name.stdout" 2> "run-prearm-$name.stderr" & pp=$!; register "$pp" || true
    if finish "$pp" "$EXIT_TICKS"; then rc=$LAST_EXIT; else rc=124; fi
    publish_output "run-prearm-$name.txt" || rc=1
    [ "$rc" = 0 ] || { result run-prearm 0 "$name twin failed rc=$rc" prearm-exactness; return 1; }
  done
  detail=$(python3 -I "$RECORDS" run-prearm --stamp run-prearm.stamp --run-id "$RUN_ID" --verdict run-prearm.verdict.json --held-report "$(product_output run-prearm-held.txt)" --held-ledger run-prearm-held.wl --passive-report "$(product_output run-prearm-passive.txt)" --passive-ledger run-prearm-passive.wl 2>&1) || { result run-prearm 0 "$(printf '%.600s' "$detail")" prearm-exactness; return 1; }
  result run-prearm 1 "$detail" prearm-exactness
}
# The launcher-chain cell (v0.7.0 parent-chain lane): a named parent
# launches the gated SoftHSM workload, and live pid inventory must
# report the chain in JSON, -v text and the concise default. The
# workload holds after its LEDGER, so one pair serves both legs.
parent_chain_cell() {
  local cell=parent-chain
  local gate=$OUT/$cell.gate
  rm -f -- "$gate" "$cell.json" "$cell-v.json" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell-v.stderr" "$cell-v.stdout"
  local output output_v
  output=$(product_output "$cell.json"); output_v=$(product_output "$cell-v.json")
  stamp_leg "$cell" "$output" "$output_v" "$OUT/$cell.json" "$OUT/$cell-v.json" "$cell.verdict.json" || { result "$cell" 0 'run stamp failed' failed; return 1; }
  local before wl='' pp='' parent='' observer_rc=125
  before=$(pin) || { result "$cell" 0 'provider pin failed' failed; return 1; }
  asuser "$CHAIN_PARENT" "$GATED" "$MODULE" "$ITERS" 200 "$gate" > "$cell.wl" 2>&1 & parent=$!; register "$parent" || { result "$cell" 0 'parent registration failed' failed; return 1; }
  local parent_gen=${CHILDREN[$parent]}
  if ! waitfor "$cell.wl" '^READY pid=' "$parent" "$READY_TICKS"; then result "$cell" 0 'workload never ready' failed; terminate "$parent" || true; return 1; fi
  wl=$(grep -m1 '^READY pid=' "$cell.wl" 2>/dev/null | sed 's/^READY pid=//')
  [[ "$wl" =~ ^[1-9][0-9]*$ ]] || { result "$cell" 0 'unparseable READY pid' failed; terminate "$parent" || true; return 1; }
  register_owned_child "$wl" "$parent" || { result "$cell" 0 'workload is not the named parent child' failed; terminate "$parent" || true; return 1; }
  local wl_gen=${CHILDREN[$wl]}
  "$P" inventory --pid "$wl" --duration 10 -o "$output" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
  sleep 2
  if ! alive "$pp"; then result "$cell" 0 'concise observer exited early' failed; terminate "$parent" || true; terminate "$wl" || true; return 1; fi
  touch "$gate" || { result "$cell" 0 'gate release failed' failed; terminate "$pp" || true; terminate "$parent" || true; terminate "$wl" || true; return 1; }
  if ! waitfor "$cell.wl" '^LEDGER ' "$wl" "$LEDGER_TICKS" 1; then result "$cell" 0 'ledger missing' failed; terminate "$pp" || true; terminate "$parent" || true; terminate "$wl" || true; return 1; fi
  if [ "$(grep -c '^LEDGER ' "$cell.wl")" != 1 ]; then result "$cell" 0 'ledger not exactly once' failed; terminate "$pp" || true; terminate "$parent" || true; terminate "$wl" || true; return 1; fi
  if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
  [ "$observer_rc" = 0 ] || { result "$cell" 0 "concise observer rc=$observer_rc" failed; terminate "$parent" || true; terminate "$wl" || true; return 1; }
  publish_output "$cell.json" || { result "$cell" 0 'output copy failed' failed; terminate "$parent" || true; terminate "$wl" || true; return 1; }
  "$P" inventory --pid "$wl" --duration 10 -v -o "$output_v" > "$cell-v.stdout" 2> "$cell-v.stderr" & pp=$!; register "$pp" || true
  sleep 2
  if ! alive "$pp"; then result "$cell" 0 'verbose observer exited early' failed; terminate "$parent" || true; terminate "$wl" || true; return 1; fi
  if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
  [ "$observer_rc" = 0 ] || { result "$cell" 0 "verbose observer rc=$observer_rc" failed; terminate "$parent" || true; terminate "$wl" || true; return 1; }
  publish_output "$cell-v.json" || { result "$cell" 0 'output copy failed' failed; terminate "$parent" || true; terminate "$wl" || true; return 1; }
  local detail
  detail=$(python3 -I "$RECORDS" parent-chain --stamp "$cell.stamp" --run-id "$RUN_ID" --verdict "$cell.verdict.json" --report "$output" --concise "$cell.stdout" --verbose "$cell-v.stdout" --workload-pid "$wl" --workload-gen "$wl_gen" --parent-pid "$parent" --parent-gen "$parent_gen" 2>&1) || { result "$cell" 0 "$(printf '%.600s' "$detail")" failed; terminate "$parent" || true; terminate "$wl" || true; return 1; }
  terminate "$parent" || true; terminate "$wl" || true
  result "$cell" 1 "$detail"
}
if [ "$CONTROL" = 1 ]; then
  if [ "$CONTROL_KIND" = signal ]; then second_sigint
  elif [ "$CONTROL_KIND" = fifo ]; then fifo_refused
  elif [ "$CONTROL_KIND" = event ]; then inventory_event_stdout
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
if [ -n "${P11SCOPE_QUALIFY_CHAIN_PARENT_BIN:-}" ]; then
  [ -x "$P11SCOPE_QUALIFY_CHAIN_PARENT_BIN" ] || exit 65
  cp -- "$P11SCOPE_QUALIFY_CHAIN_PARENT_BIN" "$FIX/chain-parent" || exit 65
else
  gcc -O1 -o "$FIX/chain-parent" "$SRC/chain-parent.c" || exit 65
fi
gcc -O2 -Wall -Wextra -Werror -o "$FIX/mt_mixed" "$SRC/mt_mixed.c" -ldl -lpthread || exit 65
gcc -O2 -Wall -Wextra -Werror -o "$FIX/mt_fork" "$SRC/mt_fork.c" -ldl -lpthread || exit 65
gcc -O2 -Wall -Wextra -Werror -o "$FIX/provider_info" "$SRC/provider_info.c" -ldl || exit 65
GATED=$FIX/gated; MT=$FIX/mt; PREARM_LOADER=$FIX/prearm-first-use; CFORK=$FIX/cgroup-fork
CHAIN_PARENT=$FIX/chain-parent
MTM=$FIX/mt_mixed; MTF=$FIX/mt_fork; PINFO=$FIX/provider_info
chmod 755 "$FIX" "$GATED" "$MT" "$CFORK" "$CHAIN_PARENT" "$MTM" "$MTF" "$PINFO"
export SOFTHSM2_CONF=$OUT/softhsm2.conf
mkdir -p tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$OUT" > softhsm2.conf
softhsm2-util --init-token --free --label qual --so-pin 5678 --pin 1234 >/dev/null || exit 65
chown -R "$RUNUID:$RUNGID" tokens; chmod 644 softhsm2.conf
sh -c 'kill -HUP $$' >/dev/null 2>&1; status=$?
[ "$status" = 129 ] || { echo "SIGHUP positive control failed rc=$status" >&2; exit 65; }
env --default-signal=INT sh -c 'kill -INT $$' >/dev/null 2>&1 & wait $!
[ $? = 130 ] || { echo 'SIGINT positive control failed' >&2; exit 65; }
# Counter support is a build property: probe once, before any campaign
# branch (the subset branch can select counter-latency-mt). CONTROL
# modes run no counter cell, so they skip the probe and their fake
# observers. Placed after every function definition it needs.
COUNTER_SUPPORTED=1
if [ "$CONTROL" = 0 ]; then
  if counter_build_supported; then COUNTER_SUPPORTED=1
  elif [ $? = 1 ]; then COUNTER_SUPPORTED=0
  else exit 64
  fi
fi
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
      mt-metrics) gated mt-metrics pid "$MTM" profile --mode metrics --pid @PID@ --duration 12 -o "$OUT/mt-metrics.json" ;;
      mt-errors) gated mt-errors pid "$MTM" profile --pid @PID@ --duration 12 -o "$OUT/mt-errors.json" ;;
      mt-shared) gated mt-shared pid "$MTM" profile --pid @PID@ --duration 12 -o "$OUT/mt-shared.json" ;;
      mt-churn) gated mt-churn pid "$MTM" profile --pid @PID@ --duration 12 -o "$OUT/mt-churn.json" ;;
      mt-trace) gated mt-trace pid "$MTM" trace --pid @PID@ --duration 12 -o "$OUT/mt-trace.txt" ;;
      counter-latency-mt) counter_cell counter-latency-mt pid "$MTM" profile --mode metrics --counter-mode latency --pid @PID@ --duration 12 -o "$OUT/counter-latency-mt.json" ;;
      mt-system) gated mt-system system "$MTF" profile --system --module "$MODULE" --duration 25 -o "$OUT/mt-system.json" ;;
      mt-system-metrics) gated mt-system-metrics system "$MTF" profile --mode metrics --system --module "$MODULE" --duration 25 -o "$OUT/mt-system-metrics.json" ;;
      mt-system-trace) gated mt-system-trace system "$MTF" trace --system --module "$MODULE" --duration 25 -o "$OUT/mt-system-trace.txt" ;;
      inventory-mt-pid) MT_MIXED_HOLD=1 gated inventory-mt-pid pid "$MTM" inventory --pid @PID@ --capture native --duration 120 --event-log "$OUT/inventory-mt-pid.eventlog.jsonl" -o "$OUT/inventory-mt-pid.json" ;;
      inventory-mt-system) MT_MIXED_HOLD=1 gated inventory-mt-system system "$MTF" inventory --system --module "$MODULE" --capture native --duration 120 --event-log "$OUT/inventory-mt-system.eventlog.jsonl" -o "$OUT/inventory-mt-system.json" ;;
      inventory-provider-info-pid) gated inventory-provider-info-pid pid "$PINFO" inventory --pid @PID@ --capture native --provider-info --duration 120 --event-log "$OUT/inventory-provider-info-pid.eventlog.jsonl" -o "$OUT/inventory-provider-info-pid.json" ;;
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
"$P" doctor -v > doctor.out 2>&1; rc=$?
result doctor "$([ "$rc" = 0 ] && grep -q 'capture available' doctor.out && grep -qE '^uprobe-multi attach \(own libc\) \.+ ok([ \t].*)?$' doctor.out && grep -qE '^uretprobe vs seccomp \.+ ok([ \t].*)?$' doctor.out && echo 1 || echo 0)" "rc=$rc"
gated profile-pid pid "$GATED" profile --pid @PID@ --duration 12 -o "$OUT/profile-pid.json"
# The semantic assertions reuse the independently captured receipt, with their
# own cell binding; they cannot turn a failed capture into a second PASS.
for cell in names-pid verdict-pid; do
  python3 -I - "$cell" <<'PY' > "$cell.receipt.json"
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
parent_chain_cell
gated mt-exact pid "$MT" profile --pid @PID@ --duration 25 -o "$OUT/mt-exact.json"
system_cell
# Multi-threaded same-provider exact cells: N threads in one process (and, for
# mt-system, several processes) hammer the same provider concurrently; every
# count, error and per-CKR total is asserted exactly against the v2 ledger.
gated mt-metrics pid "$MTM" profile --mode metrics --pid @PID@ --duration 12 -o "$OUT/mt-metrics.json"
gated mt-errors pid "$MTM" profile --pid @PID@ --duration 12 -o "$OUT/mt-errors.json"
gated mt-shared pid "$MTM" profile --pid @PID@ --duration 12 -o "$OUT/mt-shared.json"
gated mt-churn pid "$MTM" profile --pid @PID@ --duration 12 -o "$OUT/mt-churn.json"
gated mt-trace pid "$MTM" trace --pid @PID@ --duration 12 -o "$OUT/mt-trace.txt"
counter_cell counter-latency-mt pid "$MTM" profile --mode metrics --counter-mode latency --pid @PID@ --duration 12 -o "$OUT/counter-latency-mt.json"
gated mt-system system "$MTF" profile --system --module "$MODULE" --duration 25 -o "$OUT/mt-system.json"
# The same multi-process workload in metrics mode: its forked children
# exit mid-capture, so a proof-backed zero-mapper retire must stay exact
# there too (retire-window lane, audits F1/G1). The trace twin
# (mt-system-trace) is subset-only: its strict trace judge has no
# runner-noise arm for the hosted runner's ambient descendant exits.
gated mt-system-metrics system "$MTF" profile --mode metrics --system --module "$MODULE" --duration 25 -o "$OUT/mt-system-metrics.json"
# Inventory MT-exact cells: the held workload keeps its process alive across
# inventory passes; per-edge usage and the event-log stream are judged exact.
# The observer runs until the harness stops it after the ledger settles
# (sigint_exact shape); --duration is only the backstop behind that stop.
MT_MIXED_HOLD=1 gated inventory-mt-pid pid "$MTM" inventory --pid @PID@ --capture native --duration 120 --event-log "$OUT/inventory-mt-pid.eventlog.jsonl" -o "$OUT/inventory-mt-pid.json"
MT_MIXED_HOLD=1 gated inventory-mt-system system "$MTF" inventory --system --module "$MODULE" --capture native --duration 120 --event-log "$OUT/inventory-mt-system.eventlog.jsonl" -o "$OUT/inventory-mt-system.json"
# Provider-info exact cell: the single-process info workload above runs under
# `inventory --pid --capture native --provider-info`; the oracle asserts the
# C_GetInfo record, token/mechanism row counts and values, and serial/label
# absence exactly against the fixture ledger.
gated inventory-provider-info-pid pid "$PINFO" inventory --pid @PID@ --capture native --provider-info --duration 120 --event-log "$OUT/inventory-provider-info-pid.eventlog.jsonl" -o "$OUT/inventory-provider-info-pid.json"
# SIGINT exact: the workload does exactly K calls, emits LEDGER, then holds.
# SIGINT arrives after the ledger is complete; require exact counts, a proven
# drain and exact observation via the oracle.
sigint_exact() {
  local cell=sigint scope=pid gate=$OUT/sigint.gate
  rm -f -- "$gate" sigint.json sigint.wl sigint.stderr sigint.stdout sigint.receipt.json
  local output; output=$(product_output sigint.json)
  rm -f -- "$output"
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
inventory_event_stdout
# WP-4 breadth: cgroup scopes (S5).
cgroup_capture profile-cgroup profile
cgroup_capture metrics-cgroup metrics
cgroup_capture trace-cgroup trace
cgroup_capture inventory-cgroup inventory
# WP-4 breadth: counter modes and select-endpoint (S6).
counter_cell counter-counts-pid pid "$GATED" profile --mode metrics --counter-mode counts --pid @PID@ --duration 12 -o "$OUT/counter-counts-pid.json"
counter_cell counter-timestamps-pid pid "$GATED" profile --mode metrics --counter-mode timestamps --pid @PID@ --duration 12 -o "$OUT/counter-timestamps-pid.json"
counter_cell counter-latency-pid pid "$GATED" profile --mode metrics --counter-mode latency --pid @PID@ --duration 12 -o "$OUT/counter-latency-pid.json"
counter_cell counter-counts-system system "$GATED" profile --mode metrics --counter-mode counts --system --module "$MODULE" --duration 25 -o "$OUT/counter-counts-system.json"
counter_cell counter-timestamps-system system "$GATED" profile --mode metrics --counter-mode timestamps --system --module "$MODULE" --duration 25 -o "$OUT/counter-timestamps-system.json"
counter_cell counter-latency-system system "$GATED" profile --mode metrics --counter-mode latency --system --module "$MODULE" --duration 25 -o "$OUT/counter-latency-system.json"
counter_cell select-endpoint-pid pid "$GATED" profile --mode metrics --counter-mode counts --select-endpoint C_Digest --module "$MODULE" --pid @PID@ --duration 12 -o "$OUT/select-endpoint-pid.json"
counter_cell select-endpoint-system system "$GATED" profile --mode metrics --counter-mode counts --select-endpoint C_Digest --module "$MODULE" --system --duration 25 -o "$OUT/select-endpoint-system.json"
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
summary doctor profile-pid names-pid verdict-pid metrics-pid trace-pid run-short run-cover run-prearm parent-chain mt-exact system mt-metrics mt-errors mt-shared mt-churn mt-trace counter-latency-mt mt-system mt-system-metrics inventory-mt-pid inventory-mt-system inventory-provider-info-pid sigint second-sigint fifo-refused inventory-event-stdout profile-cgroup metrics-cgroup trace-cgroup inventory-cgroup counter-counts-pid counter-timestamps-pid counter-latency-pid counter-counts-system counter-timestamps-system counter-latency-system select-endpoint-pid select-endpoint-system profile-pid-ia32 run-ia32 startup-to-capturing
exit $?

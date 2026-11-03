#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# qualify-stop-races.sh P11SCOPE OUTDIR [--trials N] [--burst-trials M] [--seed S] [--cell sweep|burst|all]
# S3 stop-path races: a seeded SIGINT sweep over four commands plus the
# system newcomer burst. Requires root for live trials; --self-test needs
# nothing but bash and python3. Every terminal result has
# cell/pass/detail/qualification. Exit 1 means failed evidence, 2 means a
# harness error, 0 qualifies the subset, 77 means a prerequisite is missing.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 64
ORACLE=$HERE/stop-race-oracle.py
SWEEP_WINDOW_MS=6000
SWEEP_ITERS=120
SWEEP_SLEEP_US=20000
BURST_DURATION=12
BURST_AT_MS=11700
BURST_NEWCOMERS=16

if [ "${1:-}" = --self-test ]; then
  # No root, no fixtures: prove seed->offset determinism only.
  fail=0
  for cmd in profile-pid profile-system run inventory-system; do
    for seed in 1 2 3; do
      first=$(python3 -I -c 'import random,sys; print(int(random.Random(sys.argv[1]).random()*int(sys.argv[2])))' \
        "$cmd:$seed" "$SWEEP_WINDOW_MS") || exit 2
      second=$(python3 -I -c 'import random,sys; print(int(random.Random(sys.argv[1]).random()*int(sys.argv[2])))' \
        "$cmd:$seed" "$SWEEP_WINDOW_MS") || exit 2
      echo "SELFTEST cmd=$cmd seed=$seed offset_ms=$first"
      [ "$first" = "$second" ] || fail=1
      [ "$first" -ge 0 ] && [ "$first" -lt "$SWEEP_WINDOW_MS" ] || fail=1
    done
  done
  [ "$fail" = 0 ] || { echo 'SELFTEST: nondeterministic offsets' >&2; exit 1; }
  exit 0
fi

[ $# -ge 2 ] || { echo 'usage: qualify-stop-races.sh P11SCOPE OUTDIR [--trials N] [--burst-trials M] [--seed S] [--cell sweep|burst|all]' >&2; exit 64; }
P=$1; OUT=$2; shift 2
TRIALS=10; BURST_TRIALS=5; SEED=''; CELL=all
while [ $# -gt 0 ]; do
  case $1 in
    --trials) TRIALS=$2; shift 2 ;;
    --burst-trials) BURST_TRIALS=$2; shift 2 ;;
    --seed) SEED=$2; shift 2 ;;
    --cell) CELL=$2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done
case $TRIALS in *[!0-9]*|'') echo "bad --trials: $TRIALS" >&2; exit 64 ;; esac
[ "$TRIALS" -ge 1 ] && [ "$TRIALS" -le 1000 ] || { echo "bad --trials: $TRIALS" >&2; exit 64; }
case $BURST_TRIALS in *[!0-9]*|'') echo "bad --burst-trials: $BURST_TRIALS" >&2; exit 64 ;; esac
[ "$BURST_TRIALS" -ge 1 ] && [ "$BURST_TRIALS" -le 100 ] || { echo "bad --burst-trials: $BURST_TRIALS" >&2; exit 64; }
if [ -n "$SEED" ]; then case $SEED in *[!0-9]*|'') echo "bad --seed: $SEED" >&2; exit 64 ;; esac; fi
case $CELL in sweep|burst|all) ;; *) echo "bad --cell: $CELL" >&2; exit 64 ;; esac

refuse() { echo "qualify-stop-races: prerequisite missing: $1" >&2; exit 77; }
[ "$(id -u)" = 0 ] || refuse 'must run as root'
[ -n "${EPOCHREALTIME:-}" ] || refuse 'bash without EPOCHREALTIME'
command -v gcc >/dev/null 2>&1 || refuse 'gcc not installed'
command -v stdbuf >/dev/null 2>&1 || refuse 'stdbuf not installed'
command -v softhsm2-util >/dev/null 2>&1 || refuse 'softhsm2-util not installed'
command -v setpriv >/dev/null 2>&1 || refuse 'setpriv not installed'
P=$(realpath -e -- "$P") || refuse "observer not found: $P"
[ -x "$P" ] || refuse "observer not executable: $P"
DISCOVER=$(dirname "$P")/p11scope-discover
[ -x "$DISCOVER" ] || refuse "p11scope-discover missing beside observer: $DISCOVER"
RUNUID=${RUNUID:-1000}; RUNGID=${RUNGID:-1000}
MODULE=$(python3 -I "$HERE/release-matrix-contract.py" --select-module) || refuse 'no usable SoftHSM module'
READY_TICKS=1800; LEDGER_TICKS=600; EXIT_TICKS=1800
mkdir -p "$OUT" && chmod 755 "$OUT" && OUT=$(realpath -e -- "$OUT") && cd "$OUT" || exit 2
: > results.jsonl
: > trials.log

# Lifecycle and custody helpers below are copied from
# scripts/qualify-public-cli.sh at f939a5873 (its :56-70 PID-generation
# set, :101-148 quiet waits/result/asuser/pin, and :231-267 owned-child
# custody). asuser drops the CONTROL shim (this script is always live);
# pin() hashes the owned provider copy; the forking waitfor/finish are
# omitted because every capture window here uses the builtins-only waits.
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
waitfor_quiet() {
  local file=$1 needle=$2 pid=$3 ticks=$4
  needle=${needle#^}
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
asuser() {
  exec setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups env SOFTHSM2_CONF="$SOFTHSM2_CONF" "$@"
}
pin() {
  python3 -I "$HERE/mapped-provider-pin.py" "$COPY"
}
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
    { IFS= read -r list < "$file"; } 2>/dev/null || [ -n "$list" ] || continue
    for candidate in $list; do register_owned_child "$candidate" "$parent" || true; done
  done
}
cleanup_all() {
  local pid
  for pid in "${!CHILDREN[@]}"; do terminate "$pid" || true; done
}
trap cleanup_all INT TERM EXIT

now_us() { printf '%s' "${EPOCHREALTIME/./}"; }
sleep_ms_busy() {
  local target=$(( $(now_us) + $1 * 1000 )) now
  while :; do now=$(now_us); [ "$now" -lt "$target" ] || break; done
}
trial_offset() {
  python3 -I -c 'import random,sys; print(int(random.Random(sys.argv[1]).random()*int(sys.argv[2])))' \
    "$1:$2" "$SWEEP_WINDOW_MS"
}

SRC=$HERE/../tests/fixtures/public-cli
FIX=$OUT/fix; mkdir -p "$FIX"
gcc -O1 -o "$FIX/gated" "$SRC/gated.c" -ldl || exit 2
GATED=$FIX/gated
chmod 755 "$FIX" "$GATED"
export SOFTHSM2_CONF=$OUT/softhsm2.conf
mkdir -p tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$OUT" > softhsm2.conf
chmod 644 softhsm2.conf
softhsm2-util --init-token --free --label qual --so-pin 5678 --pin 1234 >/dev/null || exit 2
chown -R "$RUNUID:$RUNGID" tokens
COPY=$OUT/owned-copy.so
install -m 0555 "$MODULE" "$COPY" || exit 2
mkdir -p stage && chmod 1777 stage
STAGE_MANIFEST=$OUT/stage/manifest.$$.json
rm -f "$STAGE_MANIFEST"
env -u SOFTHSM2_CONF "$DISCOVER" --module "$COPY" -o "$STAGE_MANIFEST" || exit 2
[ -f "$STAGE_MANIFEST" ] || { echo 'discover wrote no manifest' >&2; exit 2; }
install -m 0444 "$STAGE_MANIFEST" "$OUT/manifest.json" || exit 2
rm -f "$STAGE_MANIFEST"
MANIFEST=$OUT/manifest.json
NAMES="C_GenerateRandom C_DigestInit C_Digest C_FindObjectsInit C_FindObjects C_FindObjectsFinal"
VERDICTS=0

trial_log() { echo "$*" | tee -a trials.log; }

sweep_trial() {
  local cmd=$1 seed=$2 n=$3
  local prefix="sweep-$cmd-t$n"
  local wl="$prefix.wl" stdout="$prefix.stdout" stderr="$prefix.stderr"
  local report="$prefix.json" gate="$prefix.gate"
  local ready='p11scope: capturing:' wlpid='' pp='' content
  local ledger_before=0 rc_obs=125 orc=125
  rm -f -- "$wl" "$stdout" "$stderr" "$report" "$gate" "$prefix.pin_before" \
    "$prefix.pin_after" "$prefix.oracle.json" "$prefix.childpid"
  local offset; offset=$(trial_offset "$cmd" "$seed") || return 2
  pin > "$prefix.pin_before" || return 2
  [ "$cmd" = inventory-system ] && ready='p11scope: pass 0:'
  if [ "$cmd" = run ]; then
    # The run child is unprivileged and cannot create files in this
    # root-owned outdir: pre-create its pid and ledger files world-writable.
    : > "$prefix.childpid"; : > "$wl"; chmod 666 "$prefix.childpid" "$wl"
    env --default-signal=INT "$P" run --pause auto -o "$report" -- sh -c \
      'pidfile=$1; wl=$2; shift 2; echo $$ > "$pidfile"; exec "$@" > "$wl" 2>&1' \
      sh "$prefix.childpid" "$wl" "$GATED" "$COPY" "$SWEEP_ITERS" "$SWEEP_SLEEP_US" \
      "$gate" > "$stdout" 2> "$stderr" & pp=$!; register "$pp" || return 2
  else
    asuser "$GATED" "$COPY" "$SWEEP_ITERS" "$SWEEP_SLEEP_US" "$gate" > "$wl" 2>&1 & wlpid=$!
    register "$wlpid" || return 2
    waitfor_quiet "$wl" 'READY pid=' "$wlpid" "$READY_TICKS" || {
      trial_log "TRIAL cmd=$cmd trial=$n seed=$seed offset_ms=$offset setup_fail=workload-ready"; return 2; }
    case $cmd in
      profile-pid)
        env --default-signal=INT "$P" profile --pid "$wlpid" --module "$COPY" \
          --duration 120 -o "$report" > "$stdout" 2> "$stderr" & pp=$! ;;
      profile-system)
        env --default-signal=INT "$P" profile --system --module "$COPY" \
          --duration 120 -o "$report" > "$stdout" 2> "$stderr" & pp=$! ;;
      inventory-system)
        env --default-signal=INT "$P" inventory --system --module "$COPY" --manifest "$MANIFEST" \
          --duration 120 --json -o "$report" > "$stdout" 2> "$stderr" & pp=$! ;;
    esac
    register "$pp" || return 2
  fi
  if [ "$cmd" = run ]; then
    waitfor_quiet "$stderr" "$ready" "$pp" "$READY_TICKS" || {
      trial_log "TRIAL cmd=$cmd trial=$n seed=$seed offset_ms=$offset setup_fail=observer-ready"; return 2; }
    await_signal_child "$prefix.childpid" "$pp" || {
      trial_log "TRIAL cmd=$cmd trial=$n seed=$seed offset_ms=$offset setup_fail=child-custody"; return 2; }
    wlpid=$CUSTODY_CHILD
  else
    waitfor_quiet "$stderr" "$ready" "$pp" "$READY_TICKS" || {
      trial_log "TRIAL cmd=$cmd trial=$n seed=$seed offset_ms=$offset setup_fail=observer-ready"; return 2; }
  fi
  touch_quiet "$gate"
  sleep_ms_busy "$offset"
  { content=$(<"$wl"); } 2>/dev/null || content=''
  case $content in
    *'LEDGER '*) ledger_before=1 ;;
  esac
  alive "$pp" || {
    trial_log "TRIAL cmd=$cmd trial=$n seed=$seed offset_ms=$offset setup_fail=observer-died"; return 2; }
  kill -INT "$pp"
  if finish_quiet "$pp" "$EXIT_TICKS"; then rc_obs=$LAST_EXIT; else rc_obs=124; fi
  waitfor_quiet "$wl" 'LEDGER ' "$wlpid" "$LEDGER_TICKS" || true
  if [ -n "${CHILDREN[$wlpid]:-}" ]; then terminate "$wlpid" || true; fi
  pin > "$prefix.pin_after" || return 2
  python3 -I "$ORACLE" --mode sweep --command "$cmd" --report "$report" --workload "$wl" \
    --stderr "$stderr" --exit "$rc_obs" --seed "$seed" --offset-ms "$offset" \
    --ledger-complete "$ledger_before" --provider-before "$prefix.pin_before" \
    --provider-after "$prefix.pin_after" > "$prefix.oracle.json" 2> "$prefix.oracle.stderr"; orc=$?
  VERDICTS=$((VERDICTS + 1))
  trial_log "TRIAL cmd=$cmd trial=$n seed=$seed offset_ms=$offset ledger_before=$ledger_before observer_rc=$rc_obs oracle_rc=$orc"
  return "$orc"
}

burst_trial() {
  local n=$1
  local seed=$n
  local prefix="burst-t$n"
  local wl="$prefix.wl" stdout="$prefix.stdout" stderr="$prefix.stderr"
  local report="$prefix.json" gate="$prefix.gate" content
  local rc_obs=125 orc=125
  rm -f -- "$wl" "$stdout" "$stderr" "$report" "$gate" "$prefix.pin_before" \
    "$prefix.pin_after" "$prefix".oracle.*.json "$prefix"-pv*.wl
  pin > "$prefix.pin_before" || return 2
  asuser "$GATED" "$COPY" 500 1000 "$gate" > "$wl" 2>&1 & local wlpid=$!
  register "$wlpid" || return 2
  waitfor_quiet "$wl" 'READY pid=' "$wlpid" "$READY_TICKS" || {
    trial_log "TRIAL cmd=burst trial=$n seed=$seed setup_fail=workload-ready"; return 2; }
  env --default-signal=INT "$P" profile --system --module "$COPY" \
    --duration "$BURST_DURATION" -o "$report" > "$stdout" 2> "$stderr" & local pp=$!
  register "$pp" || return 2
  waitfor_quiet "$stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS" || {
    trial_log "TRIAL cmd=burst trial=$n seed=$seed setup_fail=observer-ready"; return 2; }
  local t0; t0=$(now_us)
  touch_quiet "$gate"
  waitfor_quiet "$wl" 'LEDGER ' "$wlpid" "$LEDGER_TICKS" || {
    trial_log "TRIAL cmd=burst trial=$n seed=$seed setup_fail=workload-ledger"; return 2; }
  local now target=$((t0 + BURST_AT_MS * 1000)) remaining
  now=$(now_us)
  if [ "$now" -lt "$target" ]; then
    remaining=$(((target - now) / 1000))
    sleep_ms_busy "$remaining"
  fi
  local burst_start; burst_start=$(now_us)
  local -a pids=()
  local -A newcomer_of=()
  local i pid code
  for ((i=0;i<BURST_NEWCOMERS;i++)); do
    # Unbuffered so a crashing newcomer keeps its partial ledger.
    asuser stdbuf -o0 -e0 "$GATED" "$COPY" 1 0 - > "$prefix-pv$i.wl" 2>&1 & pid=$!
    register "$pid" || return 2
    pids+=("$pid"); newcomer_of[$pid]="pv$i"
  done
  for ((i=0;i<BURST_NEWCOMERS;i++)); do
    asuser /bin/true & pid=$!
    register "$pid" || return 2
    pids+=("$pid"); newcomer_of[$pid]="true$i"
  done
  local burst_end; burst_end=$(now_us)
  local failures=0 failed_codes=''
  for pid in "${pids[@]}"; do
    code=0; wait "$pid" || code=$?
    unset 'CHILDREN[$pid]'
    if [ "$code" != 0 ]; then
      failures=$((failures + 1))
      failed_codes="$failed_codes ${newcomer_of[$pid]:-pid$pid}=$code"
    fi
  done
  [ "$failures" = 0 ] || {
    trial_log "TRIAL cmd=burst trial=$n seed=$seed setup_fail=newcomer-exits-$failures codes:$failed_codes"; return 2; }
  if finish_quiet "$pp" "$EXIT_TICKS"; then rc_obs=$LAST_EXIT; else rc_obs=124; fi
  if [ -n "${CHILDREN[$wlpid]:-}" ]; then terminate "$wlpid" || true; fi
  pin > "$prefix.pin_after" || return 2
  python3 -I - "$prefix" "$BURST_NEWCOMERS" <<'PY' || {
import json,sys
prefix, population = sys.argv[1], int(sys.argv[2])
for i in range(population):
    lines = open("%s-pv%d.wl" % (prefix, i)).read().splitlines()
    ledgers = [json.loads(line[7:]) for line in lines if line.startswith("LEDGER ")]
    assert len(ledgers) == 1 and ledgers[0]["complete"] is True, "newcomer %d ledger" % i
    for row in ledgers[0]["functions"]:
        assert row["attempts"] == 1 and row["successful"] == 1, "newcomer %d calls" % i
PY
    trial_log "TRIAL cmd=burst trial=$n seed=$seed setup_fail=newcomer-ledgers"; return 2; }
  local newcomers
  newcomers=$(printf ',%s' $NAMES)
  newcomers=${newcomers#,}
  python3 -I "$ORACLE" --mode burst --command profile-system --report "$report" \
    --workload "$wl" --stderr "$stderr" --exit "$rc_obs" --seed "$seed" \
    --offset-ms "$BURST_AT_MS" --ledger-complete 1 --provider-before "$prefix.pin_before" \
    --provider-after "$prefix.pin_after" --newcomer-function "$newcomers" \
    --provider-newcomers "$BURST_NEWCOMERS" > "$prefix.oracle.burst.json" \
    2> "$prefix.oracle.burst.stderr"; orc=$?
  VERDICTS=$((VERDICTS + 1))
  trial_log "TRIAL cmd=burst trial=$n seed=$seed observer_rc=$rc_obs oracle_rc=$orc burst_us=$burst_start-$burst_end"
  return "$orc"
}

run_sweep_cmd() {
  local cmd=$1 n seed rc passed=0 total=0 failed=''
  local count=$TRIALS
  [ -n "$SEED" ] && count=1
  for ((n=1;n<=count;n++)); do
    seed=$n; [ -n "$SEED" ] && seed=$SEED
    total=$((total + 1))
    if sweep_trial "$cmd" "$seed" "$n"; then
      passed=$((passed + 1))
    else
      rc=$?
      failed="$failed trial$n-seed$seed(rc$rc)"
    fi
  done
  if [ "$passed" = "$total" ]; then
    result "stop-race-sweep.$cmd" 1 "$passed/$total trials passed" stop-race-sweep
  else
    result "stop-race-sweep.$cmd" 0 "$passed/$total trials passed; failed:$failed (see trials.log + sweep-$cmd-t*.oracle.json)" failed
  fi
}

run_burst() {
  local n rc passed=0 total=0 failed=''
  local count=$BURST_TRIALS
  [ -n "$SEED" ] && count=1
  for ((n=1;n<=count;n++)); do
    total=$((total + 1))
    if burst_trial "$n"; then
      passed=$((passed + 1))
    else
      rc=$?
      failed="$failed trial$n(rc$rc)"
    fi
  done
  if [ "$passed" = "$total" ]; then
    result system-newcomer-burst 1 "$passed/$total trials passed" newcomer-burst
  else
    result system-newcomer-burst 0 "$passed/$total trials passed; failed:$failed (see trials.log + burst-t*.oracle.*.json)" failed
  fi
}

case $CELL in
  sweep|all)
    run_sweep_cmd profile-pid
    run_sweep_cmd profile-system
    run_sweep_cmd run
    run_sweep_cmd inventory-system
    ;;
esac
case $CELL in
  burst|all) run_burst ;;
esac
if [ "$VERDICTS" = 0 ]; then
  echo 'qualify-stop-races: no oracle verdicts; environment cannot run live captures' >&2
  exit 77
fi
python3 - "$@" <<'PY' | tee summary.txt
import json,sys
rows=[json.loads(line) for line in open('results.jsonl')]
ids=[row['cell'] for row in rows]
valid=len(ids)==len(set(ids)) and len(ids) > 0
failed=[r['cell'] for r in rows if not r['pass']]
print('SUMMARY pass=%d fail=%d failed=%s terminal_rows_valid=%s' % (sum(r['pass'] for r in rows),len(failed),failed,valid))
sys.exit(1 if failed or not valid else 0)
PY
exit "${PIPESTATUS[0]}"

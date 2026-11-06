#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# qualify-lifecycle-cli.sh P11SCOPE OUTDIR: lifecycle cells through the public commands (S9/S10).
#
# Cells:
#   profile-pid-reload        reload across dlclose/dlopen; totals exact
#   run-exec-chain            exec chain; per-image totals or named gaps
#   profile-system-exec-churn churn beside owned workload; owned exact
#   profile-pid-reuse         PID reuse via ns_last_pid; reuser excluded
#   prearm-late-dlopen        late dlopen with --prearm-module (expected-failure until WU-13)
#   prearm-late-dlopen-noflag twin without the flag; documented late-load gap
#   track-short-lived-cgroup  20 short-lived callers; hint counts match
#   track-short-lived-refused --track-short-lived with --counter-mode refused by name
#   track-short-lived-pid     flag under --pid: target split, no gap split
#
# Requires root for live cells. Writes OUTDIR/results.jsonl, one row per cell.
# Exit 0 when every qualified cell passes, 1 when a cell fails, 2 on harness
# error, 77 when a prerequisite is missing.
#
# Apt prerequisites (ubuntu-26.04 runner, as root): gcc python3 softhsm2 procps
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 64
ORACLE=$HERE/../tests/fixtures/lifecycle-cli/oracle.py
[ $# = 2 ] || { echo 'usage: qualify-lifecycle-cli.sh P11SCOPE OUTDIR' >&2; exit 64; }
P=$(realpath -e -- "$1") || exit 64
OUT=$2
RUNUID=${RUNUID:-1000}; RUNGID=${RUNGID:-1000}
[ "$(id -u)" = 0 ] || { echo 'must run as root' >&2; exit 64; }
MODULE_ARGS=(); [ -z "${MODULE+x}" ] || MODULE_ARGS=(--module "$MODULE")
MODULE=$(python3 -I "$HERE/release-matrix-contract.py" --select-module "${MODULE_ARGS[@]}") || exit 64
READY_TICKS=1800; LEDGER_TICKS=600; EXIT_TICKS=1800
mkdir -p "$OUT" && chmod 755 "$OUT" && OUT=$(realpath -e -- "$OUT") && cd "$OUT" || exit 64
: > results.jsonl
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
  python3 -I "$HERE/mapped-provider-pin.py" "$MODULE"
}
judge() {
  python3 -I "$ORACLE" --cell "$4" --report "$1" --ledger "$2" --receipt "$3" ${5:+--stderr "$5"} | tee -a results.jsonl
  return "${PIPESTATUS[0]}"
}
summary() {
  python3 - "$@" <<'PY' | tee summary.txt
import json,sys
rows=[json.loads(line) for line in open('results.jsonl')]
expected=sys.argv[1:]; ids=[row['cell'] for row in rows]
valid=len(ids)==len(set(ids)) and set(ids)==set(expected)
# No lifecycle cell may be nonqualifying: any such row fails unless it
# is explicitly listed here.
allowed=set()
unexpected=[r['cell'] for r in rows if r['qualification']=='nonqualifying' and r['cell'] not in allowed]
if unexpected:
 print('NONQUALIFYING NOT IN ALLOW LIST: %s' % (unexpected,))
 sys.exit(1)
failed=[r['cell'] for r in rows if not r['pass'] and r['qualification'] not in ('nonqualifying','expected-failure')]
print('SUMMARY pass=%d fail=%d failed=%s terminal_rows_valid=%s' % (sum(r['pass'] for r in rows),len(failed),failed,valid))
sys.exit(1 if failed or not valid else 0)
PY
  return "${PIPESTATUS[0]}"
}
SRC=$HERE/../tests/fixtures/lifecycle-cli
PUBSRC=$HERE/../tests/fixtures/public-cli
FIXSRC=$HERE/fixtures
FIX=$OUT/fix; mkdir -p "$FIX"
gcc -O1 -Wall -Wextra -Werror -o "$FIX/reload-workload" "$SRC/reload-workload.c" -ldl || exit 65
gcc -O1 -Wall -Wextra -Werror -o "$FIX/late-dlopen" "$SRC/late-dlopen.c" -ldl || exit 65
gcc -O1 -Wall -Wextra -Werror -o "$FIX/short-lived-caller" "$SRC/short-lived-caller.c" -ldl || exit 65
gcc -O1 -Wall -Wextra -Werror -o "$FIX/inventory-ledger" "$PUBSRC/inventory-ledger.c" -ldl -lpthread || exit 65
gcc -O2 -Wall -Wextra -Werror -o "$FIX/exec_churn" "$FIXSRC/exec_churn.c" || exit 65
gcc -O1 -o "$FIX/gated" "$PUBSRC/gated.c" -ldl || exit 65
chmod 755 "$FIX" "$FIX"/*
export SOFTHSM2_CONF=$OUT/softhsm2.conf
mkdir -p tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$OUT" > softhsm2.conf
softhsm2-util --init-token --free --label lifecycle --so-pin 5678 --pin 1234 >/dev/null || exit 65
chown -R "$RUNUID:$RUNGID" tokens; chmod 644 softhsm2.conf

# profile-pid-reload: gated reload workload; per-function totals exact.
cell=profile-pid-reload
gate=$OUT/$cell.gate
rm -f -- "$gate" "$cell.json" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json"
before=$(pin) || { result "$cell" 0 'provider pin failed' failed; }
if [ -z "${before:-}" ]; then :; else
  gen='' readygen='' wl='' pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  ( asuser "$FIX/reload-workload" "$MODULE" 50 50 "$gate" > "$cell.wl" 2>&1 ) &
  wl=$!; register "$wl" && gen=${CHILDREN[$wl]}
  if waitfor "$cell.wl" "^READY pid=$wl$" "$wl" "$READY_TICKS"; then
    ready=1; readygen=$(generation "$wl")
    "$P" profile --pid "$wl" --duration 30 -o "$OUT/$cell.json" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
    if waitfor "$cell.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
      capturing=1
      if touch "$gate"; then
        released=1
        if waitfor "$cell.wl" '^LEDGER ' "$wl" "$LEDGER_TICKS" 1; then
          if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
        fi
      fi
    fi
  fi
  [ -n "${CHILDREN[$pp]:-}" ] && terminate "$pp" || true
  if [ "$released" = 1 ]; then observer_rc=${observer_rc:-$LAST_EXIT}; fi
  terminate "$wl"; workload_rc=$LAST_EXIT
  after=$(pin) || after='null'
  python3 - "$cell" pid "$wl" "$gen" "$readygen" "$ready" "$capturing" "$released" "$observer_rc" "$workload_rc" "$before" "$after" <<'PY' > "$cell.receipt.json"
import json,sys
cell,scope,pid,gen,rgen,ready,capturing,released,observer,workload,before,after=sys.argv[1:]
lines=open(cell+'.wl').read().splitlines()
print(json.dumps({'cell':cell,'scope':scope,'launched_pid':int(pid) if pid else None,
 'generation':int(gen) if gen else None,'ready_generation':int(rgen) if rgen else None,
 'workload_ready':ready=='1','capture_ready':capturing=='1','gate_released':released=='1',
 'observer_exit':int(observer),'workload_exit':int(workload),
 'ledger_complete':sum(line.startswith('LEDGER ') for line in lines)==1,
 'provider_before':json.loads(before),'provider_after':json.loads(after)}))
PY
  judge "$cell.json" "$cell.wl" "$cell.receipt.json" "$cell" || true
fi

# profile-pid-reuse: target exits; a reuser takes its PID via ns_last_pid.
# Counts equal the target ledger; the reuser's calls are excluded; the
# report ends with target_exit.
cell=profile-pid-reuse
gate=$OUT/$cell.gate; rgate=$OUT/$cell.rgate
rm -f -- "$gate" "$rgate" "$cell.json" "$cell.wl" "$cell.rwl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json"
before=$(pin) || result "$cell" 0 'provider pin failed' failed
if [ -n "${before:-}" ]; then
  if [ ! -w /proc/sys/kernel/ns_last_pid ]; then
    result "$cell" 0 'ns_last_pid not writable (needs CONFIG_CHECKPOINT_RESTORE and root)' failed
  else
    gen='' readygen='' wl='' pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
    ( asuser "$FIX/short-lived-caller" "$MODULE" 100 "$gate" > "$cell.wl" 2>&1 ) &
    wl=$!; register "$wl" && gen=${CHILDREN[$wl]} || true
    target_pid=$wl
    if waitfor "$cell.wl" "^READY pid=$wl$" "$wl" "$READY_TICKS"; then
      ready=1; readygen=$(generation "$wl")
      "$P" profile --pid "$wl" --duration 30 -o "$OUT/$cell.json" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
      if waitfor "$cell.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
        capturing=1
        if touch "$gate"; then
          released=1
          if waitfor "$cell.wl" '^LEDGER ' "$wl" "$LEDGER_TICKS" 1; then
            # Target exits on its own after LEDGER; wait for the exit.
            if finish "$wl" 100; then workload_rc=$LAST_EXIT; else workload_rc=124; fi
            # Force PID reuse: set ns_last_pid and spawn the reuser with a
            # gate so its PID is known before it calls. Retry: other host
            # processes may take the number first.
            reuser_pid=''; reuser_calls=0
            for attempt in $(seq 1 32); do
              rm -f -- "$rgate" "$cell.rwl"
              echo $((target_pid - 1)) > /proc/sys/kernel/ns_last_pid 2>/dev/null || break
              ( asuser "$FIX/short-lived-caller" "$MODULE" 200 "$rgate" > "$cell.rwl" 2>&1 ) &
              rp=$!; register "$rp" || true
              if waitfor "$cell.rwl" '^READY pid=' "$rp" 50; then
                got=$(sed -n 's/^READY pid=\([0-9]*\)/\1/p' "$cell.rwl" | head -1)
                if [ "$got" = "$target_pid" ]; then
                  reuser_pid=$rp; touch "$rgate"
                  if waitfor "$cell.rwl" '^LEDGER ' "$rp" "$LEDGER_TICKS" 1; then
                    if finish "$rp" 100; then :; else terminate "$rp" || true; fi
                  else
                    terminate "$rp" || true
                  fi
                  break
                fi
              fi
              terminate "$rp" || true
            done
            if [ -n "$reuser_pid" ]; then
              reuser_calls=$(python3 -c 'import json; print(sum(r["attempts"] for line in open("'"$cell.rwl"'") if line.startswith("LEDGER ") for r in json.loads(line[7:])["functions"]))' 2>/dev/null || echo 0)
            fi
            # The observer should end on target exit, not the full duration.
            if finish "$pp" 300; then observer_rc=$LAST_EXIT; else observer_rc=124; terminate "$pp" || true; fi
          fi
        fi
      fi
    fi
    [ -n "${CHILDREN[$pp]:-}" ] && terminate "$pp" || true
    after=$(pin) || after='null'
    python3 - "$cell" "$target_pid" "$gen" "$readygen" "$ready" "$capturing" "$released" "$observer_rc" "$workload_rc" "${reuser_calls:-0}" "$before" "$after" <<'PY' > "$cell.receipt.json"
import json,sys
cell,pid,gen,rgen,ready,capturing,released,observer,workload,reuser,before,after=sys.argv[1:]
lines=open(cell+'.wl').read().splitlines()
print(json.dumps({'cell':cell,'scope':'pid','launched_pid':int(pid),
 'generation':int(gen) if gen else None,'ready_generation':int(rgen) if rgen else None,
 'workload_ready':ready=='1','capture_ready':capturing=='1','gate_released':released=='1',
 'observer_exit':int(observer),'workload_exit':int(workload),'reuser_calls':int(reuser),
 'ledger_complete':sum(line.startswith('LEDGER ') for line in lines)==1,
 'provider_before':json.loads(before),'provider_after':json.loads(after)}))
PY
    judge "$cell.json" "$cell.wl" "$cell.receipt.json" "$cell" "$cell.stderr" || true
  fi
fi

# run-exec-chain: inventory-ledger exec-chain under run --pause auto.
cell=run-exec-chain
rm -f -- "$cell.json" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json"
before=$(pin) || result "$cell" 0 'provider pin failed' failed
if [ -n "${before:-}" ]; then
  output=$OUT/$cell.json
  SUDO_UID=$RUNUID SUDO_GID=$RUNGID "$P" run --pause auto -o "$output" -- \
    "$FIX/inventory-ledger" exec-chain --cell REX --module "$MODULE" \
    --iters 2 --delay-ms 100 --chain "leader:$FIX/inventory-ledger" \
    > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
  if finish "$pp" "$EXIT_TICKS"; then rc=$LAST_EXIT; else rc=124; fi
  after=$(pin) || after='null'
  # The run child stdout (ledgers) is captured in $cell.stdout.
  cp "$cell.stdout" "$cell.wl" 2>/dev/null || true
  python3 - "$cell" "$rc" "$before" "$after" <<'PY' > "$cell.receipt.json"
import json,sys
cell,rc,before,after=sys.argv[1:]
text=open(cell+'.wl').read() if __import__('os').path.exists(cell+'.wl') else ''
print(json.dumps({'cell':cell,'scope':'run','observer_exit':int(rc),
 'provider_before':json.loads(before),'provider_after':json.loads(after),
 'ledgers':sum(line.startswith('LEDGER ') for line in text.splitlines()),
 'dones':sum(line.startswith('DONE ') and 'status=ok' in line for line in text.splitlines())}))
PY
  judge "$cell.json" "$cell.wl" "$cell.receipt.json" "$cell" "$cell.stderr" || true
fi

# profile-system-exec-churn: exec_churn at 100/s beside the owned workload.
cell=profile-system-exec-churn
gate=$OUT/$cell.gate
rm -f -- "$gate" "$cell.json" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json" "$cell.churn"
mkdir -p "$OUT/churn-provider" && chmod 755 "$OUT/churn-provider"
CHURN_MOD="$OUT/churn-provider/libsofthsm2-owned.so"
rm -f -- "$CHURN_MOD"
before=$(pin) || result "$cell" 0 'provider pin failed' failed
if [ -n "${before:-}" ]; then
  install -m 0555 "$MODULE" "$CHURN_MOD"
  churn_pin=$(python3 -I "$HERE/mapped-provider-pin.py" "$CHURN_MOD") || churn_pin='null'
  gen='' wl='' cp='' pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  ( asuser "$FIX/gated" "$CHURN_MOD" 200 200 "$gate" > "$cell.wl" 2>&1 ) &
  wl=$!; register "$wl" || true
  if waitfor "$cell.wl" "^READY pid=$wl$" "$wl" "$READY_TICKS"; then
    ready=1
    "$P" profile --system --module "$CHURN_MOD" --duration 25 -o "$OUT/$cell.json" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
    if waitfor "$cell.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
      capturing=1
      # Churn beside the capture: 100/s unrelated execs, no provider calls.
      ( asuser "$FIX/exec_churn" 100 20 0 "$OUT/$cell.churn" > "$cell.churn.out" 2>&1 ) &
      cp=$!; register "$cp" || true
      sleep 1
      if touch "$gate"; then
        released=1
        if waitfor "$cell.wl" '^LEDGER ' "$wl" "$LEDGER_TICKS" 1; then
          if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
        fi
      fi
      terminate "$cp" || true
    fi
  fi
  [ -n "${CHILDREN[$pp]:-}" ] && terminate "$pp" || true
  terminate "$wl"; workload_rc=$LAST_EXIT
  after=$(pin) || after='null'
  python3 - "$cell" "$wl" "$ready" "$capturing" "$released" "$observer_rc" "$workload_rc" "$churn_pin" "$before" "$after" <<'PY' > "$cell.receipt.json"
import json,sys
cell,pid,ready,capturing,released,observer,workload,cmod,before,after=sys.argv[1:]
lines=open(cell+'.wl').read().splitlines()
print(json.dumps({'cell':cell,'scope':'system','launched_pid':int(pid) if pid else None,
 'workload_ready':ready=='1','capture_ready':capturing=='1','gate_released':released=='1',
 'observer_exit':int(observer),'workload_exit':int(workload),
 'ledger_complete':sum(line.startswith('LEDGER ') for line in lines)==1,
 'provider_before':json.loads(cmod),'provider_after':json.loads(cmod),
 'system_provider_before':json.loads(before),'system_provider_after':json.loads(after)}))
PY
  judge "$cell.json" "$cell.wl" "$cell.receipt.json" "$cell" "$cell.stderr" || true
fi

# prearm-late-dlopen and its twin: late dlopen with and without the flag.
for variant in prearm-late-dlopen prearm-late-dlopen-noflag; do
cell=$variant
gate=$OUT/$cell.gate
rm -f -- "$gate" "$cell.json" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json"
before=$(pin) || result "$cell" 0 'provider pin failed' failed
if [ -n "${before:-}" ]; then
  gen='' wl='' pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  ( asuser "$FIX/late-dlopen" "$MODULE" 100 "$gate" > "$cell.wl" 2>&1 ) &
  wl=$!; register "$wl" || true
  if waitfor "$cell.wl" "^READY pid=$wl$" "$wl" "$READY_TICKS"; then
    ready=1
    if [ "$cell" = prearm-late-dlopen ]; then
      "$P" profile --pid "$wl" --prearm-module "$MODULE" --duration 25 -o "$OUT/$cell.json" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
    else
      "$P" profile --pid "$wl" --duration 25 -o "$OUT/$cell.json" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
    fi
    if waitfor "$cell.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
      capturing=1
      if touch "$gate"; then
        released=1
        if waitfor "$cell.wl" '^LEDGER ' "$wl" "$LEDGER_TICKS" 1; then
          if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
        fi
      fi
    fi
  fi
  [ -n "${CHILDREN[$pp]:-}" ] && terminate "$pp" || true
  terminate "$wl"; workload_rc=$LAST_EXIT
  after=$(pin) || after='null'
  python3 - "$cell" "$wl" "$ready" "$capturing" "$released" "$observer_rc" "$workload_rc" "$before" "$after" <<'PY' > "$cell.receipt.json"
import json,sys
cell,pid,ready,capturing,released,observer,workload,before,after=sys.argv[1:]
lines=open(cell+'.wl').read().splitlines()
print(json.dumps({'cell':cell,'scope':'pid','launched_pid':int(pid) if pid else None,
 'workload_ready':ready=='1','capture_ready':capturing=='1','gate_released':released=='1',
 'observer_exit':int(observer),'workload_exit':int(workload),
 'ledger_complete':sum(line.startswith('LEDGER ') for line in lines)==1,
 'provider_before':json.loads(before),'provider_after':json.loads(after)}))
PY
  judge "$cell.json" "$cell.wl" "$cell.receipt.json" "$cell" "$cell.stderr" || true
fi
done

# track-short-lived-cgroup: 20 short-lived callers in an owned cgroup.
cell=track-short-lived-cgroup
gate=$OUT/$cell.gate
CG=/sys/fs/cgroup/p11scope-qual-$$
rm -f -- "$gate" "$cell.json" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json"
rmdir "$CG" 2>/dev/null || true
before=$(pin) || result "$cell" 0 'provider pin failed' failed
if [ -n "${before:-}" ]; then
  if ! mkdir -p "$CG" 2>/dev/null; then
    result "$cell" 0 "cannot create cgroup $CG" failed
  else
    pp='' pids='' ready=0 capturing=0 released=0 observer_rc=125
    : > "$cell.wl"
    # Start the observer first so the callers are post-attach newcomers
    # that exit before their first binding (the hint case). Spawning
    # before attach would bind them and record no hints.
    "$P" profile --cgroup "$CG" --track-short-lived --duration 30 -o "$OUT/$cell.json" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
    if waitfor "$cell.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS"; then
      capturing=1
      pids=''
      for i in $(seq 1 20); do
        ( asuser "$FIX/short-lived-caller" "$MODULE" 5 "$gate" >> "$cell.wl" 2>&1 ) &
        pids="$pids $!"
      done
      for p in $pids; do register "$p" || true; done
      ok=1
      for _ in $(seq 1 "$READY_TICKS"); do
        n=$(grep -c '^READY pid=' "$cell.wl" 2>/dev/null || echo 0)
        if [ "$n" -ge 20 ]; then ok=0; break; fi
        sleep 0.1
      done
      if [ "$ok" = 0 ]; then
        ready=1
        for p in $pids; do echo "$p" > "$CG/cgroup.procs" 2>/dev/null || true; done
        if touch "$gate"; then
          released=1
          for _ in $(seq 1 "$LEDGER_TICKS"); do
            n=$(grep -c '^LEDGER ' "$cell.wl" 2>/dev/null || echo 0)
            if [ "$n" -ge 20 ]; then break; fi
            sleep 0.1
          done
          if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
        fi
      fi
    fi
    [ -n "${CHILDREN[$pp]:-}" ] && terminate "$pp" || true
    for p in $pids; do [ -n "${CHILDREN[$p]:-}" ] && terminate "$p" || true; done
    rmdir "$CG" 2>/dev/null || true
    after=$(pin) || after='null'
    python3 - "$cell" "$ready" "$capturing" "$released" "$observer_rc" "$before" "$after" <<'PY' > "$cell.receipt.json"
import json,sys
cell,ready,capturing,released,observer,before,after=sys.argv[1:]
lines=open(cell+'.wl').read().splitlines()
print(json.dumps({'cell':cell,'scope':'cgroup',
 'workload_ready':ready=='1','capture_ready':capturing=='1','gate_released':released=='1',
 'observer_exit':int(observer),'workload_exit':0,
 'ledger_complete':sum(line.startswith('LEDGER ') for line in lines)==20,
 'provider_before':json.loads(before),'provider_after':json.loads(after)}))
PY
    judge "$cell.json" "$cell.wl" "$cell.receipt.json" "$cell" "$cell.stderr" || true
  fi
fi

# track-short-lived-refused: the flag with --counter-mode is refused by name.
cell=track-short-lived-refused
rm -f -- "$cell.stderr" "$cell.stdout"
"$P" profile --mode metrics --counter-mode counts --track-short-lived --pid 1 --duration 1 -o "$OUT/$cell.json" > "$cell.stdout" 2> "$cell.stderr"; rc=$?
if [ "$rc" -ne 0 ] && grep -q -- '--track-short-lived cannot be combined with --counter-mode' "$cell.stderr"; then
  result "$cell" 1 "refused by name rc=$rc" qualified
else
  result "$cell" 0 "rc=$rc without the named refusal" failed
fi

# track-short-lived-pid: the flag under --pid arms the PID consumer
# (target_exec_hints, zero here since the workload never execs) while
# the gap splits stay absent.
cell=track-short-lived-pid
gate=$OUT/$cell.gate
rm -f -- "$gate" "$cell.json" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json"
before=$(pin) || result "$cell" 0 'provider pin failed' failed
if [ -n "${before:-}" ]; then
  wl='' pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  ( asuser "$FIX/gated" "$MODULE" 100 200 "$gate" > "$cell.wl" 2>&1 ) &
  wl=$!; register "$wl" || true
  if waitfor "$cell.wl" "^READY pid=$wl$" "$wl" "$READY_TICKS"; then
    ready=1
    "$P" profile --pid "$wl" --track-short-lived --duration 20 -o "$OUT/$cell.json" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
    if waitfor "$cell.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
      capturing=1
      if touch "$gate"; then
        released=1
        if waitfor "$cell.wl" '^LEDGER ' "$wl" "$LEDGER_TICKS" 1; then
          if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
        fi
      fi
    fi
  fi
  [ -n "${CHILDREN[$pp]:-}" ] && terminate "$pp" || true
  terminate "$wl"; workload_rc=$LAST_EXIT
  after=$(pin) || after='null'
  python3 - "$cell" "$wl" "$ready" "$capturing" "$released" "$observer_rc" "$workload_rc" "$before" "$after" <<'PY' > "$cell.receipt.json"
import json,sys
cell,pid,ready,capturing,released,observer,workload,before,after=sys.argv[1:]
lines=open(cell+'.wl').read().splitlines()
print(json.dumps({'cell':cell,'scope':'pid','launched_pid':int(pid) if pid else None,
 'workload_ready':ready=='1','capture_ready':capturing=='1','gate_released':released=='1',
 'observer_exit':int(observer),'workload_exit':int(workload),
 'ledger_complete':sum(line.startswith('LEDGER ') for line in lines)==1,
 'provider_before':json.loads(before),'provider_after':json.loads(after)}))
PY
  judge "$cell.json" "$cell.wl" "$cell.receipt.json" "$cell" "$cell.stderr" || true
fi

summary profile-pid-reload run-exec-chain profile-system-exec-churn profile-pid-reuse prearm-late-dlopen prearm-late-dlopen-noflag track-short-lived-cgroup track-short-lived-refused track-short-lived-pid
exit $?

#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# p11kit-transparency.sh P11SCOPE OUTDIR [CELL...]: prove that calls through
# p11-kit are never silently hidden.
#
# For every module that really received calls, the report either counts those
# calls exactly at that module's identity, or is not exact and names that
# module, or a cause covering it, as a gap or skip.
#
# Ground truth (independent of p11scope): the workload's own LEDGER (calls it
# made into the proxy/client) and an OpenSC pkcs11-spy log between p11-kit and
# an owned SoftHSM copy (calls that reached the provider).
#
# Apt prerequisites (Ubuntu 26.04 runner): gcc, softhsm2, opensc
# (pkcs11-spy.so), p11-kit, p11-kit-modules (proxy, trust, client),
# python3, procps, util-linux, softhsm2-util (in softhsm2).
# Dnf prerequisites (Fedora 44): gcc, softhsm, opensc, p11-kit,
# p11-kit-server, p11-kit-client, python3, procps-ng, util-linux.
# SoftHSM 2.7 note: Fedora's stock provider has the legacy32 table shape
# (owned by exec-scan-legacy32); Fedora cells use an owned copy of a
# Debian SoftHSM build as the qualified provider (see P11KIT_SOFTHSM_SRC).
# Against stock 2.7 only p11kit-remote fails (server-side provider rows
# stay ["unknown"]-named); set P11KIT_EXPECT_LEGACY32=1 for that run.
#
# Usage: scripts/ci/p11kit-transparency.sh P11SCOPE OUTDIR [CELL...]
# Writes OUTDIR/results.jsonl, one row per cell:
#   {"cell": str, "pass": bool,
#    "qualification": "qualified"|"nonqualifying"|"expected-failure"|"failed",
#    "detail": str}
# With no CELL args all cells run. Exit 0: every row passed or met its
# expected failure; 1: a cell failed; 2: harness error; 77: prerequisite
# missing (never a silent skip). Must run as root (live capture); the
# workload runs as $RUNUID:$RUNGID. Never edits /etc or /usr: p11-kit
# isolation comes from an owned $XDG_CONFIG_HOME plus user-config.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd) || exit 64
ORACLE=$HERE/p11kit-transparency-oracle.py
FIXSRC=$HERE/../tests/fixtures/p11kit
[ $# -ge 2 ] || { echo 'usage: p11kit-transparency.sh P11SCOPE OUTDIR [CELL...]' >&2; exit 64; }
P=$(realpath -e -- "$1") || exit 64
OUT=$2; shift 2
WANT=("$@")
RUNUID=${RUNUID:-1000}; RUNGID=${RUNGID:-1000}
ITERS=${ITERS:-20}; SLEEP_US=${SLEEP_US:-200}; SETTLE_MS=${SETTLE_MS:-8000}
# Post-settle functions: the loop and teardown, which cannot race loader
# attach and must be exact at every layer. Setup calls race by construction
# (backends load inside C_Initialize) and are exact-or-covered.
LOOP_FUNCS=C_DigestInit,C_Digest,C_FindObjectsInit,C_FindObjects,C_FindObjectsFinal,C_CloseSession,C_Finalize
[ "$(id -u)" = 0 ] || { echo 'must run as root' >&2; exit 64; }
mkdir -p "$OUT" && chmod 755 "$OUT" && OUT=$(realpath -e -- "$OUT") && cd "$OUT" || exit 64
READY_TICKS=1800; LEDGER_TICKS=600; EXIT_TICKS=1800

prereq() { echo "PREREQ: $1" >&2; exit 77; }
command -v gcc >/dev/null || prereq 'gcc required'
command -v softhsm2-util >/dev/null || prereq 'softhsm2-util required'
command -v p11-kit >/dev/null || prereq 'p11-kit required'
command -v trust >/dev/null || prereq 'trust required'
command -v setpriv >/dev/null || prereq 'setpriv required'
command -v flock >/dev/null || prereq 'flock required'
[ -x "$P" ] || prereq "observer not executable: $P"
[ -f "$ORACLE" ] || prereq "oracle missing: $ORACLE"

probe_first() {
  local candidate
  for candidate in "$@"; do
    [ -f "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
  done
  return 1
}
# Provider paths are probed, never hard-coded (Debian then Fedora).
SOFTHSM_SRC=${P11KIT_SOFTHSM_SRC:-}
if [ -z "$SOFTHSM_SRC" ]; then
  SOFTHSM_SRC=$(python3 -I "$HERE/release-matrix-contract.py" --select-module) || prereq 'no SoftHSM candidate found'
fi
[ -f "$SOFTHSM_SRC" ] || prereq "SoftHSM source missing: $SOFTHSM_SRC"
PROXY=$(probe_first /usr/lib/x86_64-linux-gnu/p11-kit-proxy.so /usr/lib64/p11-kit-proxy.so) || prereq 'p11-kit-proxy.so not found'
SPY=$(probe_first /usr/lib/x86_64-linux-gnu/pkcs11/pkcs11-spy.so /usr/lib/x86_64-linux-gnu/pkcs11-spy.so /usr/lib64/pkcs11/pkcs11-spy.so /usr/lib64/pkcs11-spy.so) || prereq 'pkcs11-spy.so (opensc) not found'
CLIENT_SO=$(probe_first /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so /usr/lib64/pkcs11/p11-kit-client.so) || prereq 'p11-kit-client.so not found'
TRUST_SO=$(probe_first /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so /usr/lib64/pkcs11/p11-kit-trust.so) || prereq 'p11-kit-trust.so not found'
# The proxy closure array the inventory lane refuses is keyed on libp11-kit
# itself (version-specific soname; globbed, never hard-coded).
LIBP11KIT=$(ls /usr/lib/x86_64-linux-gnu/libp11-kit.so.0* /usr/lib64/libp11-kit.so.0* 2>/dev/null | head -n 1)
[ -n "$LIBP11KIT" ] && [ -f "$LIBP11KIT" ] || prereq 'libp11-kit.so.0 not found'
command -v p11-kit >/dev/null || prereq 'p11-kit server required'

echo "prereqs: softhsm=$SOFTHSM_SRC proxy=$PROXY spy=$SPY client=$CLIENT_SO trust=$TRUST_SO libp11kit=$LIBP11KIT"
: > results.jsonl

# --- child custody (same generation discipline as qualify-public-cli.sh) ---
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
# Subprocess-free waits for captures that observe the whole machine (see
# qualify-public-cli.sh: every fork/exec during a --system capture is a
# descendant gap, so poll with shell builtins only).
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
  python3 - "$1" "$2" "$3" "${4:-qualified}" <<'PY' | tee -a results.jsonl
import json,sys
print(json.dumps({'cell':sys.argv[1],'pass':sys.argv[2]=='1','detail':sys.argv[3],'qualification':sys.argv[4]}))
PY
}
HARNESS_ERROR=0
pin() { python3 -I "$HERE/mapped-provider-pin.py" "$1"; }

# --- expected failures: cell -> reason (a fix landing shows as a pass) ---
# EXPECTED_DETAIL names the bug's failure signature: an rc=1 becomes
# expected-failure only when its detail carries that cell's signature;
# any other rc=1 is a failed row, never green-washed as the known bug.
declare -A EXPECTED_FAIL=(
  [p11kit-proxy-pid-merge]='closure array crowds out backends; task/v060-p11kit-admission'
  [p11kit-real-trust]='closure array crowds out backends; task/v060-p11kit-admission'
)
declare -A EXPECTED_DETAIL=(
  [p11kit-proxy-pid-merge]='provider: observed {}'
  [p11kit-real-trust]='trust: observed {}'
  [p11kit-remote]='unattributed calls'
)
if [ "${P11KIT_EXPECT_LEGACY32:-0}" = 1 ]; then
  EXPECTED_FAIL[p11kit-remote]='stock SoftHSM 2.7 server rows unnamed; exec-scan-legacy32'
fi

judge_capture() {
  # judge_capture CELL REPORT LEDGER SPY RECEIPT -- <oracle args...>: run the
  # oracle, set JUDGE_RC/JUDGE_DETAIL, latch HARNESS_ERROR on rc 2 or a crash.
  # Writes no row (judge() maps to rows; composite cells combine captures).
  local cell=$1 report=$2 ledger=$3 spy=$4 receipt=$5; shift 5
  [ "${1:-}" = -- ] && shift
  local out rc=0
  # Empty LEDGER/SPY omit --ledger/--spy (tool cells; client side). /dev/null
  # must never be passed: it parses as empty.
  local ledger_arg=() spy_arg=()
  [ -n "$ledger" ] && ledger_arg=(--ledger "$ledger")
  [ -n "$spy" ] && spy_arg=(--spy "$spy")
  out=$(python3 -I "$ORACLE" --report "$report" "${ledger_arg[@]}" "${spy_arg[@]}" \
    --receipt "$receipt" --cell "$cell" "$@") || rc=$?
  JUDGE_RC=$rc
  JUDGE_DETAIL="oracle produced no verdict (rc=$rc)"
  [ -n "$out" ] && JUDGE_DETAIL=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["detail"])')
  if [ "$rc" = 2 ] || [ -z "$out" ]; then HARNESS_ERROR=1; fi
}
judge() {
  # judge CELL ...: judge_capture, then map the verdict to a contract
  # results.jsonl row honoring EXPECTED_FAIL. Oracle rc 0 (property holds)
  # becomes qualification qualified; rc 1 on an expected-failure cell becomes
  # expected-failure only when the detail carries EXPECTED_DETAIL[cell]
  # (pass false: the property genuinely did not hold); anything else is a
  # failed row.
  local cell=$1
  judge_capture "$@"
  if [ "$JUDGE_RC" = 0 ]; then
    if [ -n "${EXPECTED_FAIL[$cell]:-}" ]; then
      result "$cell" 1 "EXPECTED-FAILURE no longer reproduces (${EXPECTED_FAIL[$cell]}): $JUDGE_DETAIL" qualified
    else
      result "$cell" 1 "$JUDGE_DETAIL" qualified
    fi
    return 0
  fi
  if [ -n "${EXPECTED_FAIL[$cell]:-}" ] && [ "$JUDGE_RC" = 1 ] && [ -n "${EXPECTED_DETAIL[$cell]:-}" ]; then
    if printf '%s' "$JUDGE_DETAIL" | grep -F -q -- "${EXPECTED_DETAIL[$cell]}"; then
      result "$cell" 0 "expected-failure (${EXPECTED_FAIL[$cell]}): $JUDGE_DETAIL" expected-failure
      return 0
    fi
  fi
  result "$cell" 0 "$JUDGE_DETAIL" failed
  return 1
}
judge_composite() {
  # judge_composite CELL DETAIL RC...: map a composite verdict (T6, T7) to
  # a contract row honoring EXPECTED_FAIL, like judge(). Expected-failure
  # needs a genuine property failure (rc 1) with no harness error (rc 2)
  # and the detail carrying EXPECTED_DETAIL[cell]: a harness failure or a
  # wrong reason must never be swallowed as expected.
  local cell=$1 detail=$2; shift 2
  local r prop_fail=0 harness_fail=0
  for r in "$@"; do
    [ "$r" = 0 ] || prop_fail=1
    { [ "$r" = 0 ] || [ "$r" = 1 ]; } || harness_fail=1
  done
  if [ "$prop_fail" = 0 ]; then
    if [ -n "${EXPECTED_FAIL[$cell]:-}" ]; then
      result "$cell" 1 "EXPECTED-FAILURE no longer reproduces (${EXPECTED_FAIL[$cell]}): $detail" qualified
    else
      result "$cell" 1 "$detail" qualified
    fi
    return 0
  fi
  if [ -n "${EXPECTED_FAIL[$cell]:-}" ] && [ "$harness_fail" = 0 ] && [ -n "${EXPECTED_DETAIL[$cell]:-}" ]; then
    if printf '%s' "$detail" | grep -F -q -- "${EXPECTED_DETAIL[$cell]}"; then
      result "$cell" 0 "expected-failure (${EXPECTED_FAIL[$cell]}): $detail" expected-failure
      return 0
    fi
  fi
  result "$cell" 0 "$detail" failed
  return 1
}
judge_inventory_capture() {
  # judge_inventory_capture CELL INVFILE -- <oracle args...>: inventory-mode
  # verdict (admission whole / named refusal). Sets JUDGE_RC/JUDGE_DETAIL
  # like judge_capture; writes no row.
  local cell=$1 inv=$2; shift 2
  [ "${1:-}" = -- ] && shift
  local out rc=0
  out=$(python3 -I "$ORACLE" --inventory "$inv" --cell "$cell" "$@") || rc=$?
  JUDGE_RC=$rc
  JUDGE_DETAIL="oracle produced no verdict (rc=$rc)"
  [ -n "$out" ] && JUDGE_DETAIL=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["detail"])')
  if [ "$rc" = 2 ] || [ -z "$out" ]; then HARNESS_ERROR=1; fi
}

# --- setup: fixture, owned copy, token, isolated/merge configs, pins ---
FIX=$OUT/fix; mkdir -p "$FIX"
gcc -O1 -o "$FIX/through-proxy" "$FIXSRC/through-proxy.c" -ldl || exit 2
gcc -O1 -o "$FIX/run-with-env" "$FIXSRC/run-with-env.c" || exit 2
gcc -O1 -shared -fPIC -o "$FIX/premap.so" "$FIXSRC/premap.c" -ldl || exit 2
chmod 755 "$FIX" "$FIX/through-proxy" "$FIX/run-with-env" "$FIX/premap.so"
WORKLOAD=$FIX/through-proxy
WRAPPER=$FIX/run-with-env
PREMAP_SO=$FIX/premap.so

mkdir -p "$OUT/provider" "$OUT/home"
OWNED_COPY=$OUT/provider/libsofthsm2-owned.so
rm -f "$OWNED_COPY"
install -m 0555 "$SOFTHSM_SRC" "$OWNED_COPY" || exit 2
# Root-owned but world-readable: the unprivileged workload must map the
# owned copy, and nothing but this script may change it mid-run.
chmod 755 "$OUT/provider"
chown "$RUNUID:$RUNGID" "$OUT/home"; chmod 700 "$OUT/home"

export SOFTHSM2_CONF=$OUT/softhsm2.conf
mkdir -p tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\nslots.mechanisms = ALL\nlibrary.reset_on_fork = false\n' "$OUT" > softhsm2.conf
softhsm2-util --init-token --free --label wp3b --so-pin 5678 --pin 1234 >/dev/null || exit 2
chown -R "$RUNUID:$RUNGID" tokens; chmod 644 softhsm2.conf

for mode in isolated merge; do
  rm -rf "$OUT/xdg-$mode"
  mkdir -p "$OUT/xdg-$mode/pkcs11/modules"
  cp "$FIXSRC/pkcs11-$mode.conf" "$OUT/xdg-$mode/pkcs11/pkcs11.conf"
  sed "s|@PKCS11_SPY@|$SPY|" "$FIXSRC/owned-spy.module.in" > "$OUT/xdg-$mode/pkcs11/modules/owned-spy.module"
done
grep -q "^module: $SPY$" "$OUT/xdg-isolated/pkcs11/modules/owned-spy.module" || exit 2
# Trust override for T5b: copy the system p11-kit-trust entry and point only
# its module line at the spy, preserving distro priority/trust-policy lines.
TRUST_MOD=$(probe_first /usr/share/p11-kit/modules/p11-kit-trust.module /etc/pkcs11/modules/p11-kit-trust.module) || prereq 'system p11-kit-trust.module not found'
rm -rf "$OUT/xdg-trust"
mkdir -p "$OUT/xdg-trust/pkcs11/modules"
cp "$FIXSRC/pkcs11-merge.conf" "$OUT/xdg-trust/pkcs11/pkcs11.conf"
sed "s|^module:.*|module: $SPY|" "$TRUST_MOD" > "$OUT/xdg-trust/pkcs11/modules/p11-kit-trust.module"
grep -q "^module: $SPY$" "$OUT/xdg-trust/pkcs11/modules/p11-kit-trust.module" || exit 2
# Isolation proof before any capture: the isolated config must load exactly
# the owned spy module, the merge config the system set plus the owned one.
# These run as the workload user: p11-kit 0.26.2 does not load user config
# for root at all (verified by strace: no user-config path is even opened).
count_modules() {
  setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups \
    env HOME="$OUT/home" SOFTHSM2_CONF="$SOFTHSM2_CONF" XDG_CONFIG_HOME="$1" \
    PKCS11SPY="$OWNED_COPY" p11-kit list-modules 2>/dev/null | grep -c '^module: '
}
iso_modules=$(count_modules "$OUT/xdg-isolated") || iso_modules=0
[ "$iso_modules" = 1 ] || { echo "isolated config loads $iso_modules modules, want 1" >&2; exit 2; }
merge_modules=$(count_modules "$OUT/xdg-merge") || merge_modules=0
[ "$merge_modules" -ge 2 ] || { echo "merge config loads $merge_modules modules, want >= 2" >&2; exit 2; }
echo "p11-kit configs: isolated=$iso_modules merge=$merge_modules"

pin "$OWNED_COPY" > owned.pin || exit 2
pin "$PROXY" > proxy.pin || exit 2
pin "$SPY" > spy.pin || exit 2
pin "$CLIENT_SO" > client.pin || exit 2
pin "$TRUST_SO" > trust.pin || exit 2
pin "$LIBP11KIT" > libp11kit.pin || exit 2
chmod 644 owned.pin proxy.pin spy.pin client.pin trust.pin libp11kit.pin

asuser() {
  # Exec the workload as the unprivileged user with the cell's p11-kit/spy/
  # token environment (plus an owned HOME so no tool writes to a real home).
  # Callers set XDG_CELL and SPYLOG; LD_PRELOAD (premap wrapper),
  # P11KIT_PREMAPPED (premap path list) and P11_KIT_SERVER_ADDRESS (T7)
  # pass through when set.
  exec setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups \
    env HOME="$OUT/home" SOFTHSM2_CONF="$SOFTHSM2_CONF" XDG_CONFIG_HOME="$XDG_CELL" \
    PKCS11SPY="$OWNED_COPY" PKCS11SPY_OUTPUT="$SPYLOG" LD_PRELOAD="${LD_PRELOAD:-}" \
    P11KIT_PREMAPPED="${P11KIT_PREMAPPED:-}" \
    P11_KIT_SERVER_ADDRESS="${P11_KIT_SERVER_ADDRESS:-}" "$@"
}
receipt() {
  # receipt CELL SCOPE MODE WL GEN READYGEN READY CAPTURING RELEASED OBS_RC WL_RC SPYPID [SPYLOADED]
  # SPYLOADED defaults to the owned copy: the spy logs the provider path it
  # was told (PKCS11SPY), recorded verbatim, never resolved behind its back.
  python3 - "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}" "${12}" "${13:-$OWNED_COPY}" <<'PY' > "$1.receipt.json"
import json,re,sys
cell,scope,mode,pid,gen,rgen,ready,capturing,released,observer,workload,spypid,spyloaded=sys.argv[1:]
lines=open(cell+'.wl').read().splitlines()
ready_pids=[int(m.group(1)) for line in lines if (m:=re.fullmatch(r'READY pid=(\d+)',line))]
print(json.dumps({'schema':'p11scope/p11kit-receipt/v1','cell':cell,'scope':scope,'mode':mode,
 'launched_pid':int(pid),'generation':int(gen) if gen else None,
 'ready_generation':int(rgen) if rgen else None,'ready_pid':ready_pids[0] if len(ready_pids)==1 else None,
 'workload_ready':ready=='1','capture_ready':capturing=='1','gate_released':released=='1',
 'observer_exit':int(observer),'workload_exit':int(workload),
 'ledger_complete':sum(line.startswith('LEDGER ') for line in lines)==1,
 'spy_loaded':spyloaded,'spy_pid':(int(spypid) if spypid else None)}))
PY
}

pid_cell() {
  # pid_cell CELL MODE DURATION XDG PROXYWIRE SKIPS PROVIDERWIRE
  # [EXTRA-OBSERVER-ARGS...]:
  # gated --pid capture through the proxy (XDG isolated|merge). PROXYWIRE is
  # exact (proxy loop must equal) or cover (proxy loop may be refused when
  # the closure array crowds it, as long as the gap is named). SKIPS pins
  # gap text as "basename:substring;..." (empty for none); an entry prefixed
  # "any:" joins the --expect-skip-any disjunction instead (at least one
  # must appear). The workload runs as $RUNUID with the cell's p11-kit/spy
  # environment; the observer runs as root.
  local cell=$1 mode=$2 duration=$3 xdg=$4 proxywire=$5 skipspec=$6 providerwire=$7; shift 7
  local gate=$OUT/$cell.gate
  rm -f -- "$gate" "$cell.json" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json" "$cell.spy.log"
  : > "$OUT/$cell.spy.log" && chown "$RUNUID:$RUNGID" "$OUT/$cell.spy.log" && chmod 644 "$OUT/$cell.spy.log"
  local wl gen='' readygen='' pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  XDG_CELL=$OUT/xdg-$xdg SPYLOG=$OUT/$cell.spy.log \
    asuser "$WORKLOAD" "$PROXY" "$ITERS" "$SLEEP_US" "$SETTLE_MS" "$gate" > "$cell.wl" 2>&1 &
  wl=$!; register "$wl" && gen=${CHILDREN[$wl]}
  if waitfor "$cell.wl" "^READY pid=$wl$" "$wl" "$READY_TICKS"; then
    ready=1; readygen=$(generation "$wl")
    if [ "$mode" = metrics ]; then
      "$P" profile --mode metrics --pid "$wl" --duration "$duration" "$@" -o "$OUT/$cell.json" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
    else
      "$P" profile --pid "$wl" --duration "$duration" "$@" -o "$OUT/$cell.json" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
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
  if [ -n "$pp" ] && [ -n "${CHILDREN[$pp]:-}" ]; then terminate "$pp"; observer_rc=$LAST_EXIT; fi
  terminate "$wl"; workload_rc=$LAST_EXIT
  receipt "$cell" pid "$mode" "$wl" "$gen" "$readygen" "$ready" "$capturing" "$released" "$observer_rc" "$workload_rc" "$wl" \
    || { result "$cell" 0 'receipt publication failed' failed; return 1; }
  local proxy_exact=()
  [ "$proxywire" = exact ] && proxy_exact=(--exact-only proxy "$LOOP_FUNCS")
  local provider_wire=(--exact-only provider "$LOOP_FUNCS")
  [ "$providerwire" = whole ] && provider_wire=(--require-exact provider)
  local skips=() pair
  if [ -n "$skipspec" ]; then
    local IFS=';'
    for pair in $skipspec; do
      if [[ "$pair" == any:* ]]; then
        pair=${pair#any:}
        skips+=(--expect-skip-any "${pair%%:*}" "${pair#*:}")
      else
        skips+=(--expect-skip "${pair%%:*}" "${pair#*:}")
      fi
    done
    unset IFS
  fi
  judge "$cell" "$cell.json" "$cell.wl" "$cell.spy.log" "$cell.receipt.json" -- \
    --scope pid --mode "$mode" \
    --layer "proxy:$OUT/proxy.pin:workload:offset" --layer "spy:$OUT/spy.pin:spy" \
    --layer "provider:$OUT/owned.pin:spy" --target-identity "$OUT/proxy.pin" \
    "${proxy_exact[@]}" "${provider_wire[@]}" \
    --spy-binding provider --forbid-unknown "${skips[@]}"
}

# --- T1: profile --pid through the proxy, isolated config ---
# Brief T1 "exact" is implemented as loop-exact + setup-covered per the timing contract in through-proxy.c; spy whole-covered as harness infra.
t1() { pid_cell p11kit-proxy-pid-isolated profile 20 isolated exact "" loop; }

# --- T2: same as T1, metrics mode ---
t2() { pid_cell p11kit-proxy-pid-isolated-metrics metrics 20 isolated exact "" loop; }

# --- T5b: run --pause auto -- trust list, spy wrapped around p11-kit-trust ---
# The real trust tool drives the real trust module (merge config with the
# trust entry overridden to the spy). The trust layer must equal the spy
# ledger whole (744 calls on Ubuntu): pause covers the late loads, so every
# call is post-attach. Expected failure until the admission fix lands (the
# closure array crowds out trust: 7 counted against 744). A tool cell: no
# fixture LEDGER exists, so the oracle runs --no-workload on the exits plus
# the per-cell-fresh spy log.
t5b() {
  local cell=p11kit-real-trust
  rm -f -- "$cell.json" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json" "$cell.spy.log"
  : > "$OUT/$cell.spy.log" && chown "$RUNUID:$RUNGID" "$OUT/$cell.spy.log" && chmod 644 "$OUT/$cell.spy.log"
  local pp='' observer_rc=125
  SUDO_UID=$RUNUID SUDO_GID=$RUNGID \
    "$P" run --pause auto -o "$OUT/$cell.json" -- \
    "$WRAPPER" "HOME=$OUT/home" "SOFTHSM2_CONF=$SOFTHSM2_CONF" \
    "XDG_CONFIG_HOME=$OUT/xdg-trust" "PKCS11SPY=$TRUST_SO" \
    "PKCS11SPY_OUTPUT=$OUT/$cell.spy.log" -- \
    trust list --filter=ca-anchors > "$cell.wl" 2> "$cell.stderr" & pp=$!; register "$pp" || true
  if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
  grep -q 'trust: anchor' "$cell.wl" || {
    result "$cell" 0 'trust listed no anchors (tool did not run the expected query)' failed; return 1; }
  python3 - "$cell.receipt.json" "$cell" "$observer_rc" <<'PY'
import json,sys
json.dump({'schema':'p11scope/p11kit-receipt/v1','cell':sys.argv[2],'scope':'run','mode':'profile',
 'observer_exit':int(sys.argv[3]),'workload_exit':int(sys.argv[3])},open(sys.argv[1],'w'))
PY
  judge "$cell" "$cell.json" "" "$cell.spy.log" "$cell.receipt.json" --     --no-workload --scope run --mode profile     --layer "trust:$OUT/trust.pin:spy"     --require-exact trust --spy-binding trust
}

# --- T7: p11-kit server/client across a process boundary ---
# A `p11-kit server` (process S) exposes the spy-wrapped owned copy; the
# client workload uses p11-kit-client.so. Two sequential captures (never two
# observers at once): profile --pid CLIENT (client layer equals the workload
# ledger; nothing claimed for SoftHSM) and profile --system --module <owned>
# (server-side counts equal the server spy ledger). One row passes iff both
# verdicts pass, proving RPC hides nothing across the boundary.
t7() {
  local cell=p11kit-remote
  local sock=$OUT/$cell.sock server='' servergen=''
  rm -f -- "$sock" "$cell.server.log" "$cell.spy.log" "$cell.spy-ledger.log"
  rm -f -- "$cell.client."* "$cell.server."*
  : > "$OUT/$cell.spy.log" && chown "$RUNUID:$RUNGID" "$OUT/$cell.spy.log" && chmod 644 "$OUT/$cell.spy.log"
  # The premap wrapper maps the owned copy RTLD_LOCAL into the server
  # parent (the per-connection children inherit it): --system arms no loader
  # hooks, and the parent never loads the provider itself, so without the
  # premap the filtered module is "not mapped in the target" at scan time
  # and never picked up (as in T3). Local, never global (see system_run).
  setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups \
    env HOME="$OUT/home" SOFTHSM2_CONF="$SOFTHSM2_CONF" PKCS11SPY="$OWNED_COPY" \
    PKCS11SPY_OUTPUT="$OUT/$cell.spy.log" LD_PRELOAD="$PREMAP_SO" \
    P11KIT_PREMAPPED="$OWNED_COPY" \
    p11-kit server -f -n "$sock" -p "$SPY" -t 600 'pkcs11:token=wp3b' \
    > "$cell.server.log" 2>&1 &
  server=$!; register "$server" && servergen=${CHILDREN[$server]}
  if ! waitfor "$cell.server.log" '^P11_KIT_SERVER_ADDRESS=' "$server" "$READY_TICKS"; then
    terminate "$server" 2>/dev/null
    result "$cell" 0 'p11-kit server never listened' failed; return 1
  fi
  [ -S "$sock" ] && alive "$server" || {
    terminate "$server" 2>/dev/null
    result "$cell" 0 'p11-kit server socket missing or server died' failed; return 1
  }

  # Phase 1: client side. The client workload runs gated; MODULE is the
  # client .so and the server address reaches it via the environment.
  local gate=$OUT/$cell.client.gate c=c1
  local wl gen='' readygen='' pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  P11_KIT_SERVER_ADDRESS="unix:path=$sock" XDG_CELL=$OUT/xdg-isolated SPYLOG=/dev/null \
    asuser "$WORKLOAD" "$CLIENT_SO" "$ITERS" "$SLEEP_US" "$SETTLE_MS" "$gate" > "$cell.client.wl" 2>&1 &
  wl=$!; register "$wl" && gen=${CHILDREN[$wl]}
  if waitfor "$cell.client.wl" "^READY pid=$wl$" "$wl" "$READY_TICKS"; then
    ready=1; readygen=$(generation "$wl")
    "$P" profile --pid "$wl" --duration 20 -o "$OUT/$cell.client.json" > "$cell.client.stdout" 2> "$cell.client.stderr" & pp=$!; register "$pp" || true
    if waitfor "$cell.client.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
      capturing=1
      if touch "$gate"; then
        released=1
        if waitfor "$cell.client.wl" '^LEDGER ' "$wl" "$LEDGER_TICKS" 1; then
          if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
        fi
      fi
    fi
  fi
  if [ -n "$pp" ] && [ -n "${CHILDREN[$pp]:-}" ]; then terminate "$pp"; observer_rc=$LAST_EXIT; fi
  terminate "$wl"; workload_rc=$LAST_EXIT
  receipt "$cell.client" pid profile "$wl" "$gen" "$readygen" "$ready" "$capturing" "$released" "$observer_rc" "$workload_rc" 0 \
    || { terminate "$server" 2>/dev/null; rm -f -- "$sock";
         result "$cell" 0 'client receipt publication failed' failed; return 1; }
  # The phase receipts carry the phase in their cell field; rewrite to the
  # cell name for the oracle's cell check.
  python3 - "$cell.client.receipt.json" "$cell" <<'PY'
import json,sys
doc=json.load(open(sys.argv[1])); doc['cell']=sys.argv[2]; json.dump(doc,open(sys.argv[1],'w'))
PY
  judge_capture "$cell" "$cell.client.json" "$cell.client.wl" "" "$cell.client.receipt.json" -- \
    --scope pid --mode profile \
    --layer "client:$OUT/client.pin:workload:offset" --target-identity "$OUT/client.pin" \
    --forbid "$OUT/owned.pin" --exact-only client "$LOOP_FUNCS" --forbid-unknown
  local crc=$JUDGE_RC; local c_detail="$JUDGE_DETAIL"

  # Phase 2: server side. The server predates the capture, so every
  # server-side call the ledger names is post-attach and must be exact.
  # Gate on the phase-1 server child exiting first: its spy blocks must be
  # flushed before phase 2 appends, or the runs interleave.
  alive "$server" || { rm -f -- "$sock"; result "$cell" 0 'server died before phase 2' failed; return 1; }
  local waited=0 children
  while [ $waited -lt 300 ]; do
    children=$(tr ' ' '
' < "/proc/$server/task/$server/children" 2>/dev/null | grep -c .) || children=0
    [ "$children" = 0 ] && break
    sleep 0.1; waited=$((waited+1))
  done
  [ "$children" = 0 ] || { terminate "$server" 2>/dev/null; rm -f -- "$sock";
    result "$cell" 0 'phase-1 server child never exited' failed; return 1; }
  gate=$OUT/$cell.server.gate
  wl=''; gen=''; readygen=''; pp=''; ready=0; capturing=0; released=0; observer_rc=125; workload_rc=125
  P11_KIT_SERVER_ADDRESS="unix:path=$sock" XDG_CELL=$OUT/xdg-isolated SPYLOG=/dev/null \
    asuser "$WORKLOAD" "$CLIENT_SO" "$ITERS" "$SLEEP_US" "$SETTLE_MS" "$gate" > "$cell.server.wl" 2>&1 &
  wl=$!; register "$wl" && gen=${CHILDREN[$wl]}
  if waitfor "$cell.server.wl" "^READY pid=$wl$" "$wl" "$READY_TICKS"; then
    ready=1; readygen=$(generation "$wl")
    "$P" profile --system --module "$OWNED_COPY" --duration 30 -o "$OUT/$cell.server.json" > "$cell.server.stdout" 2> "$cell.server.stderr" & pp=$!; register "$pp" || true
    if waitfor_quiet "$cell.server.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
      capturing=1
      if touch_quiet "$gate"; then
        released=1
        if waitfor_quiet "$cell.server.wl" 'LEDGER ' "$wl" "$LEDGER_TICKS"; then
          if finish_quiet "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
        fi
      fi
    fi
  fi
  if [ -n "$pp" ] && [ -n "${CHILDREN[$pp]:-}" ]; then terminate "$pp"; observer_rc=$LAST_EXIT; fi
  terminate "$wl"; workload_rc=$LAST_EXIT
  terminate "$server" 2>/dev/null
  rm -f -- "$sock"
  # Split the server spy log at the snapshot: the phase ledger is exactly
  # the blocks appended after it (sequence numbers are contiguous).
  python3 - "$cell.spy.log" "$cell.spy-ledger.log" <<'PY'
import re,sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src).read()
# The server forks a child per connection; each child loads the spy fresh
# (own banner, sequences restart at 0). Split by banner run: exactly two
# runs are expected (one connection per phase, sequential).
runs = re.split(r'(?=^\*{15} OpenSC PKCS#11 spy)', text, flags=re.M)
runs = [run for run in runs if 'OpenSC PKCS#11 spy' in run[:4096]]
assert len(runs) == 2, 'want exactly 2 server runs, saw %d' % len(runs)
phase = runs[1]
headers = re.findall(r'^(\d+): C_', phase, flags=re.M)
seqs = [int(seq) for seq in headers]
assert seqs == list(range(len(seqs))), 'phase-2 sequences not contiguous from 0'
assert seqs, 'server saw no calls during phase 2'
pids = set(re.findall(r'^P:(\d+);', phase, flags=re.M))
assert len(pids) == 1, 'phase-2 run interleaved across pids: %r' % (pids,)
open(dst, 'w').write(phase)
PY
  [ $? = 0 ] || { result "$cell" 0 'server spy split failed' failed; return 1; }
  receipt "$cell.server" system profile "$wl" "$gen" "$readygen" "$ready" "$capturing" "$released" "$observer_rc" "$workload_rc" "" \
    || { result "$cell" 0 'server receipt publication failed' failed; return 1; }
  python3 - "$cell.server.receipt.json" "$cell" <<'PY'
import json,sys
doc=json.load(open(sys.argv[1])); doc['cell']=sys.argv[2]; json.dump(doc,open(sys.argv[1],'w'))
PY
  judge_capture "$cell" "$cell.server.json" "$cell.server.wl" "$cell.spy-ledger.log" "$cell.server.receipt.json" -- \
    --scope system --mode profile \
    --layer "provider:$OUT/owned.pin:spy" --target-identity "$OUT/client.pin" \
    --require-exact provider --spy-binding provider --forbid-unknown
  local s_rc=$JUDGE_RC; local s_detail="$JUDGE_DETAIL"
  judge_composite "$cell" "client(rc=$crc): $c_detail || server(rc=$s_rc): $s_detail" "$crc" "$s_rc"
}

# --- T5: profile --pid through the proxy, merge config (real-world case) ---
# The owned backend must be admitted whole (loop exact); the libp11-kit
# closure array may be refused as a named gap. Expected failure until the
# admission fix lands (closure array crowds out backends). The closure pin
# accepts either the pre-fix K4 prefix text (per p11-kit version: 410
# endpoints on 0.26.x, basename derived from the probed library) or the
# post-fix whole-refusal text (task/v060-p11kit-admission), so the cell
# flips automatically when the fix lands; a version change that moves the
# counts fails loudly for re-pinning.
t5() {
  local base
  base=$(basename "$LIBP11KIT")
  pid_cell p11kit-proxy-pid-merge profile 20 merge cover \
    "any:$base:kept its 410 attached endpoints;any:$base:a proxy closure array is admitted whole or not at all" loop
}

# --- T8: T1 with --prearm-module <owned copy> ---
# The first calls after the late load must be counted exactly: the owned
# layer is required whole-exact (no setup cover). Pending WU-13: if the flag
# is not active at this revision, the owned setup misses and the cell is
# marked expected-failure with that reason instead of passing.
t8() { pid_cell p11kit-prearm profile 20 isolated exact "" whole --prearm-module "$OWNED_COPY"; }

system_run() {
  # system_run PREFIX XDG PREMAP -- OBSERVER...: one gated workload plus one
  # --system observer (profile or inventory). Leaves $PREFIX.json/.wl/.spy.log
  # and run facts in SYS_WL/SYS_GEN/SYS_READYGEN/SYS_READY/SYS_CAPTURING/
  # SYS_RELEASED/SYS_OBSERVER_RC/SYS_WORKLOAD_RC for the caller's receipt.
  # Uses the quiet (subprocess-free) waits: every fork during a --system
  # capture is a descendant gap. PREMAP is a colon-separated path list (or
  # empty): the premap wrapper maps each RTLD_LOCAL before main, never
  # globally (a globally preloaded provider makes OpenSC 0.27.1's spy
  # return direct pointers from C_GetInterface, bypassing the log).
  local prefix=$1 xdg=$2 premap=$3; shift 3
  [ "${1:-}" = -- ] && shift
  local gate=$OUT/$prefix.gate
  rm -f -- "$gate" "$prefix.json" "$prefix.wl" "$prefix.stderr" "$prefix.stdout" "$prefix.spy.log"
  : > "$OUT/$prefix.spy.log" && chown "$RUNUID:$RUNGID" "$OUT/$prefix.spy.log" && chmod 644 "$OUT/$prefix.spy.log"
  local wl gen='' readygen='' pp='' ready=0 capturing=0 released=0 observer_rc=125 workload_rc=125
  local wrapper=
  [ -n "$premap" ] && wrapper=$PREMAP_SO
  LD_PRELOAD=$wrapper P11KIT_PREMAPPED=$premap XDG_CELL=$OUT/xdg-$xdg SPYLOG=$OUT/$prefix.spy.log \
    asuser "$WORKLOAD" "$PROXY" "$ITERS" "$SLEEP_US" "$SETTLE_MS" "$gate" > "$prefix.wl" 2>&1 &
  wl=$!; register "$wl" && gen=${CHILDREN[$wl]}
  if waitfor "$prefix.wl" "^READY pid=$wl$" "$wl" "$READY_TICKS"; then
    ready=1; readygen=$(generation "$wl")
    "$@" -o "$OUT/$prefix.json" > "$prefix.stdout" 2> "$prefix.stderr" & pp=$!; register "$pp" || true
    if waitfor_quiet "$prefix.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
      capturing=1
      if touch_quiet "$gate"; then
        released=1
        if waitfor_quiet "$prefix.wl" 'LEDGER ' "$wl" "$LEDGER_TICKS"; then
          if finish_quiet "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
        fi
      fi
    fi
  fi
  if [ -n "$pp" ] && [ -n "${CHILDREN[$pp]:-}" ]; then terminate "$pp"; observer_rc=$LAST_EXIT; fi
  terminate "$wl"; workload_rc=$LAST_EXIT
  SYS_WL=$wl SYS_GEN=$gen SYS_READYGEN=$readygen SYS_READY=$ready
  SYS_CAPTURING=$capturing SYS_RELEASED=$released
  SYS_OBSERVER_RC=$observer_rc SYS_WORKLOAD_RC=$workload_rc
}

# --- T3: profile --system --module <owned copy>, isolated config ---
# The owned copy is pre-mapped RTLD_LOCAL by the premap wrapper (same inode
# the spy later dlopens; refcount only): --system arms no loader hooks, so
# a filtered module that first appears after attach is never picked up
# ("not mapped in the target"). The mapping must stay local: a globally
# preloaded provider makes OpenSC 0.27.1's spy bypass its log (Fedora).
# Pre-mapping keeps T3's property (system-scope counts equal the spy
# ledger) while pid cells prove the late-load shape.
t3() {
  local cell=p11kit-proxy-system-isolated
  system_run "$cell" isolated "$OWNED_COPY" -- \
    "$P" profile --system --module "$OWNED_COPY" --duration 25
  receipt "$cell" system profile "$SYS_WL" "$SYS_GEN" "$SYS_READYGEN" "$SYS_READY" \
    "$SYS_CAPTURING" "$SYS_RELEASED" "$SYS_OBSERVER_RC" "$SYS_WORKLOAD_RC" "$SYS_WL" \
    || { result "$cell" 0 'receipt publication failed' failed; return 1; }
  judge "$cell" "$cell.json" "$cell.wl" "$cell.spy.log" "$cell.receipt.json" -- \
    --scope system --mode profile \
    --layer "provider:$OUT/owned.pin:spy" --target-identity "$OUT/proxy.pin" \
    --exact-only provider "$LOOP_FUNCS" --spy-binding provider --forbid-unknown
}

# --- T6: inventory + profile --system, merge config (the 8192 lane) ---
# Phase A runs inventory --system --max-endpoints 8192 while a merge
# workload maps its backends: the owned copy and p11-kit-trust must be
# admitted whole (exact endpoint counts, never >=) and the libp11-kit
# closure refusal must carry its pinned text. The backends are pre-mapped
# RTLD_LOCAL by the premap wrapper (same files the proxy later dlopens;
# refcount only): the gated workload's ~8 s life fits between inventory
# passes, so without the premap no pass ever sees the late dlopen and the
# identities are absent (late-load coverage itself is proven by T1). Phase B runs
# profile --system --module <owned copy> (T3 shape, merge config): the
# provider row equals the spy ledger. One row passes iff both do.
# Endpoint pins are per provider/p11-kit version (env-overridable for
# Fedora); the refusal pin is the stable closure text, never the
# needs-N-more number, which shifts with ambient machine state (other
# processes' mapped providers count as in-use). The full arithmetic from
# the qualified run is recorded in the task report, not here.
T6_OWNED_ENDPOINTS=${T6_OWNED_ENDPOINTS:-68}
T6_TRUST_ENDPOINTS=${T6_TRUST_ENDPOINTS:-68}
T6_CLOSURE_REFUSAL=${T6_CLOSURE_REFUSAL:-'a proxy closure array is admitted whole or not at all'}
t6() {
  local cell=p11kit-proxy-system-merge
  system_run "$cell.inv" merge "$OWNED_COPY:$TRUST_SO" -- \
    "$P" inventory --system --max-endpoints 8192 --duration 30
  judge_inventory_capture "$cell" "$cell.inv.json" -- \
    --expect-admitted "$OUT/owned.pin:$T6_OWNED_ENDPOINTS" \
    --expect-admitted "$OUT/trust.pin:$T6_TRUST_ENDPOINTS" \
    --expect-refused "$OUT/libp11kit.pin" "$T6_CLOSURE_REFUSAL"
  local irc=$JUDGE_RC; local i_detail="$JUDGE_DETAIL"
  system_run "$cell.prof" merge "$OWNED_COPY" -- \
    "$P" profile --system --module "$OWNED_COPY" --duration 25
  receipt "$cell.prof" system profile "$SYS_WL" "$SYS_GEN" "$SYS_READYGEN" "$SYS_READY" \
    "$SYS_CAPTURING" "$SYS_RELEASED" "$SYS_OBSERVER_RC" "$SYS_WORKLOAD_RC" "$SYS_WL" \
    || { result "$cell" 0 'profile receipt publication failed' failed; return 1; }
  python3 - "$cell.prof.receipt.json" "$cell" <<'PY'
import json,sys
doc=json.load(open(sys.argv[1])); doc['cell']=sys.argv[2]; json.dump(doc,open(sys.argv[1],'w'))
PY
  judge_capture "$cell" "$cell.prof.json" "$cell.prof.wl" "$cell.prof.spy.log" "$cell.prof.receipt.json" -- \
    --scope system --mode profile \
    --layer "provider:$OUT/owned.pin:spy" --target-identity "$OUT/proxy.pin" \
    --exact-only provider "$LOOP_FUNCS" --spy-binding provider --forbid-unknown
  local prc=$JUDGE_RC; local p_detail="$JUDGE_DETAIL"
  judge_composite "$cell" "inventory(rc=$irc): $i_detail || profile(rc=$prc): $p_detail" "$irc" "$prc"
}

# --- T9: passive inventory counts short callers at the backend (isolated) ---
# A silent premap holder anchors the owned backend (mapping only, zero
# calls: sleep under the premap wrapper); T9_SHORTS short ungated
# proxy-through runs (settle 0, a fraction of a second each) are never
# admitted, but their calls fold to module-level use. The oracle checks
# the two exact module-use equations (entries/spy/bindings, spy pids)
# plus drop-detection against the summed ledger and admission whole.
# Short lives are far below the inventory pass cadence; the exact
# equations hold or fail loud, never vacuous.
T9_SHORTS=${T9_SHORTS:-6}
t9() {
  local cell=p11kit-moduleuse-system-isolated
  rm -f -- "$cell.json" "$cell.stderr" "$cell.stdout" "$cell.spy.log" "$cell.ledger" "$cell".short*.wl
  : > "$OUT/$cell.spy.log" && chown "$RUNUID:$RUNGID" "$OUT/$cell.spy.log" && chmod 644 "$OUT/$cell.spy.log"
  local holder='' pp='' capturing=0 observer_rc=125
  LD_PRELOAD=$PREMAP_SO P11KIT_PREMAPPED=$OWNED_COPY \
    XDG_CELL=$OUT/xdg-isolated SPYLOG=$OUT/$cell.spy.log \
    asuser sleep 90 & holder=$!; register "$holder" \
    || { result "$cell" 0 'holder did not start' failed; return 1; }
  sleep 2
  "$P" inventory --system --duration 45 -o "$OUT/$cell.json" > "$cell.stdout" 2> "$cell.stderr" & pp=$!; register "$pp" || true
  # Pass 1, not lane activation: the pre-pass scan links no uprobes yet, so
  # calls made before the first pass completes are kernel-invisible (the
  # spy still sees them). Shorts must run with the links live.
  if waitfor_quiet "$cell.stderr" 'pass 1:' "$pp" "$READY_TICKS" && alive "$holder"; then
    capturing=1
    local i=0 ok=0
    while [ "$i" -lt "$T9_SHORTS" ]; do
      i=$((i+1))
      # Subshell: asuser execs, so a foreground call would replace this shell.
      ( XDG_CELL=$OUT/xdg-isolated SPYLOG=$OUT/$cell.spy.log \
        asuser "$WORKLOAD" "$PROXY" "$ITERS" 0 0 - > "$cell.short$i.wl" 2>&1 ) \
        && ok=$((ok+1))
    done
    if [ "$ok" != "$T9_SHORTS" ]; then
      result "$cell" 0 "short runs: $ok/$T9_SHORTS succeeded" failed
      terminate "$holder"; terminate "$pp"; return 1
    fi
  fi
  if [ "$capturing" = 1 ]; then
    if finish_quiet "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
  else
    terminate "$holder"; [ -n "$pp" ] && terminate "$pp"
    result "$cell" 0 'observer never captured' failed; return 1
  fi
  terminate "$holder"
  if [ "$observer_rc" != 0 ]; then
    result "$cell" 0 "observer exit $observer_rc" failed; return 1
  fi
  python3 - "$cell" "$T9_SHORTS" > "$cell.ledger" <<'PY' \
    || { result "$cell" 0 'ledger sum failed (harness)' failed; return 1; }
import json,sys
cell, n = sys.argv[1], int(sys.argv[2])
ledgers = []
for i in range(1, n + 1):
    lines = open('%s.short%d.wl' % (cell, i)).read().splitlines()
    ready = [line for line in lines if line.startswith('READY pid=')]
    payloads = [json.loads(line[7:]) for line in lines if line.startswith('LEDGER ')]
    assert len(ready) == 1 and len(payloads) == 1, 'short %d lacks READY/LEDGER' % i
    assert payloads[0].get('complete') is True, 'short %d ledger incomplete' % i
    assert payloads[0].get('pid') == int(ready[0][10:]), 'short %d pid mismatch' % i
    ledgers.append((int(ready[0][10:]), payloads[0]['functions']))
first = ledgers[0][0]
total = {}
for _, funcs in ledgers:
    for func in funcs:
        assert func['attempts'] == func['successful'] > 0, 'short had failed calls'
        total[func['name']] = total.get(func['name'], 0) + func['successful']
print('READY pid=%d' % first)
print('LEDGER ' + json.dumps({'schema': 'p11scope/p11kit-ledger/v1', 'pid': first,
      'complete': True, 'functions': [{'name': name, 'attempts': count, 'successful': count}
      for name, count in sorted(total.items())]}))
PY
  judge_inventory_capture "$cell" "$cell.json" -- \
    --expect-admitted "$OUT/owned.pin:$T6_OWNED_ENDPOINTS" \
    --expect-module-use "$OUT/owned.pin" \
    --ledger "$cell.ledger" --spy "$OUT/$cell.spy.log" \
    --bindings "$T9_SHORTS"
  judge_composite "$cell" "$JUDGE_DETAIL" "$JUDGE_RC"
}

# --- T4: run --pause auto through the proxy, isolated config ---
t4() {
  local cell=p11kit-proxy-run
  rm -f -- "$cell.json" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json" "$cell.spy.log"
  : > "$OUT/$cell.spy.log" && chown "$RUNUID:$RUNGID" "$OUT/$cell.spy.log" && chmod 644 "$OUT/$cell.spy.log"
  local pp='' capturing=0 observer_rc=125 ready_pid=0
  SUDO_UID=$RUNUID SUDO_GID=$RUNGID \
    "$P" run --pause auto -o "$OUT/$cell.json" -- \
    "$WRAPPER" "HOME=$OUT/home" "SOFTHSM2_CONF=$SOFTHSM2_CONF" \
    "XDG_CONFIG_HOME=$OUT/xdg-isolated" "PKCS11SPY=$OWNED_COPY" \
    "PKCS11SPY_OUTPUT=$OUT/$cell.spy.log" -- \
    "$WORKLOAD" "$PROXY" "$ITERS" "$SLEEP_US" "$SETTLE_MS" - > "$cell.wl" 2> "$cell.stderr" & pp=$!; register "$pp" || true
  if waitfor "$cell.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS"; then capturing=1; fi
  if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
  ready_pid=$(grep -o -m 1 '^READY pid=[0-9]*' "$cell.wl" 2>/dev/null | cut -d= -f2) || ready_pid=0
  [ -n "$ready_pid" ] || ready_pid=0
  # run exits with the owned child's exit code (src/main.rs), so the observer
  # exit doubles as the workload exit; the READY pid is the child's own
  # announcement (no separate custody channel exists for run children). The
  # observed CMD is run-with-env, which execs the workload in place (same
  # pid): a root observer allowlists the child environment, so the p11-kit
  # variables must be set past the fork, inside the child.
  receipt "$cell" run profile "$ready_pid" '' '' 1 "$capturing" 0 "$observer_rc" "$observer_rc" "$ready_pid" \
    || { result "$cell" 0 'receipt publication failed' failed; return 1; }
  judge "$cell" "$cell.json" "$cell.wl" "$cell.spy.log" "$cell.receipt.json" -- \
    --scope run --mode profile \
    --layer "proxy:$OUT/proxy.pin:workload:offset" --layer "spy:$OUT/spy.pin:spy" \
    --layer "provider:$OUT/owned.pin:spy" --target-identity "$OUT/proxy.pin" \
    --exact-only proxy "$LOOP_FUNCS" --exact-only provider "$LOOP_FUNCS" \
    --spy-binding provider --forbid-unknown --require-pause
}
# Note: the spy layer carries no --exact-only: the observer never attaches
# the spy (its scan is refused while mappings churn during the dlopen burst,
# and no table is decoded), so the spy is exact-or-covered whole. The layer
# still fails on phantom spy counts or an exact claim over missing spy calls.

ALL_CELLS=(p11kit-proxy-pid-isolated p11kit-proxy-pid-isolated-metrics p11kit-proxy-system-isolated p11kit-proxy-run p11kit-proxy-pid-merge p11kit-real-trust p11kit-proxy-system-merge p11kit-moduleuse-system-isolated p11kit-prearm p11kit-remote)
CELL_OK=0; CELL_FAIL=0
run_cell() {
  local cell=$1 fn=${2:-$1}
  if [ "${#WANT[@]}" -gt 0 ]; then
    local keep=0 want
    for want in "${WANT[@]}"; do [ "$want" = "$cell" ] && keep=1; done
    [ "$keep" = 1 ] || return 0
  fi
  echo "=== cell $cell ==="
  if "$fn"; then CELL_OK=$((CELL_OK+1)); else CELL_FAIL=$((CELL_FAIL+1)); fi
}
run_cell p11kit-proxy-pid-isolated t1
run_cell p11kit-proxy-pid-isolated-metrics t2
run_cell p11kit-proxy-system-isolated t3
run_cell p11kit-proxy-run t4
run_cell p11kit-proxy-pid-merge t5
run_cell p11kit-real-trust t5b
run_cell p11kit-proxy-system-merge t6
run_cell p11kit-moduleuse-system-isolated t9
run_cell p11kit-prearm t8
run_cell p11kit-remote t7
summary() {
  python3 - "$@" <<'PY' | tee summary.txt
import json,sys
rows=[json.loads(line) for line in open('results.jsonl') if line.strip()]
expected=sys.argv[1:]; ids=[row['cell'] for row in rows]
valid=len(ids)==len(set(ids)) and set(ids)==set(expected)
failed=[r['cell'] for r in rows if not r['pass'] and r['qualification'] not in ('nonqualifying','expected-failure')]
print('SUMMARY pass=%d fail=%d expected-failure=%d failed=%s terminal_rows_valid=%s' % (
  sum(r['pass'] for r in rows),len(failed),
  sum(1 for r in rows if r['qualification']=='expected-failure'),failed,valid))
sys.exit(1 if failed or not valid else 0)
PY
  return "${PIPESTATUS[0]}"
}
if [ "${#WANT[@]}" -gt 0 ]; then summary "${WANT[@]}"; else summary "${ALL_CELLS[@]}"; fi
rc=$?
[ "$HARNESS_ERROR" != 0 ] && exit 2
exit "$rc"

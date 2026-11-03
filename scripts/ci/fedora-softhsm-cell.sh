#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# fedora-softhsm-cell.sh P11SCOPE OUTDIR: real SoftHSM 2.7 exact cell.
#
# Cell (b) of the S2 package: the gated workload runs against the real
# Fedora SoftHSM 2.7 provider and the host observer runs profile --pid
# with the unchanged exact oracle. Until the scan fix lane
# (exec-scan-legacy32) lands, the 68-slot table labelled {3,2} walks as
# known_prefix and the cell fails; it is reported as expected-failure,
# and an unexpected pass flips the exit code so the change is noticed.
#
# Two modes:
#   container (default off Fedora): a fedora:44 container on the host
#     (dnf install softhsm gcc; gated.c and the shape probe are built
#     inside the container, which is a container build, not a host
#     build). The container shares the host PID namespace so the READY
#     pid is the host pid the observer attaches to; the provider is
#     pinned through /proc/<pid>/root. Owned containers are always
#     removed; the fedora:44 image is removed only when this run pulled
#     it. Needs docker or podman with a running daemon, else exit 77.
#   native (on Fedora, or FEDORA_NATIVE=1): the same cell against the
#     installed provider with the delivered observer. Tests only: GATED_BIN
#     and PROBE_BIN must be prebuilt binaries delivered with the observer
#     (default: next to P11SCOPE); nothing is built here, and a missing
#     binary exits 77.
#
# Rows in OUTDIR/results.jsonl: fedora27-shape (qualified: the provider
# really is the {3,2} 68-slot shape with no interface exports),
# fedora27-pid (expected-failure exact cell).
# Exit 0: shape held and the exact cell failed as expected.
# Exit 1: shape mismatch, or the exact cell unexpectedly passed.
# Exit 2: harness error. Exit 77: prerequisite missing (no container
# runtime, or no prebuilt workload on Fedora).
#
# Apt prerequisites (Ubuntu 26.04 runner): gcc jq procps python3
# util-linux, plus docker.io (or podman) for container mode. The dnf
# prerequisites inside the container are: softhsm gcc.
# Requires root. Invoke like:
#   sudo -n env RUNUID="$(id -u)" RUNGID="$(id -g)" \
#     scripts/ci/fedora-softhsm-cell.sh P11SCOPE OUTDIR
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 64
ROOT=$(cd "$HERE/../.." && pwd) || exit 64
ORACLE=$ROOT/scripts/public-cli-oracle.py
PIN=$ROOT/scripts/mapped-provider-pin.py
SELECT=$ROOT/scripts/release-matrix-contract.py
GATED_SRC=$ROOT/tests/fixtures/public-cli/gated.c
PROBE_SRC=$ROOT/tests/fixtures/legacy32-provider/shape-probe.c
REASON='SoftHSM 2.7 table shape; exec-scan-legacy32'
IMAGE=fedora:44
ITERS=${ITERS:-500}; SLEEPS=${SLEEPS:-200}; DURATION=${DURATION:-12}

[ $# = 2 ] || { echo 'usage: fedora-softhsm-cell.sh P11SCOPE OUTDIR' >&2; exit 64; }
P=$(realpath -e -- "$1") || exit 64
OUT=$2
[ "$(id -u)" = 0 ] || { echo 'must run as root' >&2; exit 64; }
mkdir -p "$OUT" && OUT=$(realpath -e -- "$OUT") || exit 64
mkdir -p "$OUT/shared"
: > "$OUT/results.jsonl"

NATIVE=0
if [ "${FEDORA_NATIVE:-0}" = 1 ]; then NATIVE=1; fi
if [ -r /etc/os-release ] && grep -qx 'ID=fedora' /etc/os-release; then NATIVE=1; fi

result() {
  python3 - "$1" "$2" "$3" "$4" <<'PY' | tee -a "$OUT/results.jsonl"
import json,sys
print(json.dumps({'cell':sys.argv[1],'pass':sys.argv[2]=='1','detail':sys.argv[3],'qualification':sys.argv[4]}))
PY
}

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
pin() { python3 -I "$PIN" "$1"; }

# Judge shape facts (probe output) for the real 2.7 contract. The ambient
# tail past slot 67 is not pinned: only the label, the complete distinct
# 68 prefix and the missing interface getters are.
shape_judge() {
  local facts=$1 fail=''
  printf '%s\n' "$facts" | grep -qx 'VERSION 3 2' || fail='want VERSION 3 2'
  if [ -z "$fail" ]; then
    for line in 'NONNULL68 68' 'DISTINCT68 1' 'GATED6 1' 'GETTER_SLOT 1' 'INTERFACES 0'; do
      printf '%s\n' "$facts" | grep -qx "$line" || fail="want $line"
      [ -z "$fail" ] || break
    done
  fi
  if [ -n "$fail" ]; then
    result fedora27-shape 0 "$fail; facts: $(printf '%s' "$facts" | tr '\n' ' ')" failed
    return 1
  fi
  result fedora27-shape 1 "real provider is the {3,2} 68-slot shape: $(printf '%s' "$facts" | tr '\n' ' ')" qualified
  return 0
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

# Run the oracle under its own cell name, then map the row onto fedora27-pid.
# Returns 3 on unexpected pass (mapped to exit 1 by the caller).
judge_exact() {
  local row pass qual detail
  row=$(python3 -I "$ORACLE" --report "$cell.json" --ledger "$cell.wl" --receipt "$cell.receipt.json" --cell "$cell") || true
  printf '%s\n' "$row" | tee -a oracle-row.json
  pass=$(printf '%s' "$row" | python3 -c 'import json,sys; print(1 if json.load(sys.stdin)["pass"] else 0)' 2>/dev/null) || {
    echo 'oracle produced no parseable row' >&2; return 2
  }
  qual=$(printf '%s' "$row" | python3 -c 'import json,sys; print(json.load(sys.stdin)["qualification"])')
  detail=$(printf '%s' "$row" | python3 -c 'import json,sys; print(json.load(sys.stdin)["detail"])')
  if [ "$pass" = 1 ]; then
    result fedora27-pid 1 "UNEXPECTED PASS ($REASON may have landed): [$qual] $detail" expected-failure
    return 3
  fi
  result fedora27-pid 0 "$REASON: [$qual] $detail" expected-failure
  return 0
}
# A lifecycle that never reached LEDGER with both exits 0 is a broken
# harness, not the expected observation failure. Fail without writing a
# misleading expected-failure row.
lifecycle_complete() {
  [ "$ready" = 1 ] && [ "$capturing" = 1 ] && [ "$released" = 1 ] && [ "$ledger" = 1 ] \
    && [ "$observer_rc" = 0 ] && [ "$workload_rc" = 0 ]
}
# TERM/KILL a registered pid that is not our child (container workload seen
# from the host PID namespace). Never wait(1) on it; the exec client below
# it carries the workload exit.
signal_registered() {
  local pid=$1
  if alive "$pid"; then
    kill -TERM "$pid" 2>/dev/null || true
    for ((i=0;i<20;i++)); do alive "$pid" || break; sleep 0.1; done
    alive "$pid" && kill -KILL "$pid" 2>/dev/null
    for ((i=0;i<20;i++)); do alive "$pid" || break; sleep 0.1; done
  fi
  unset 'CHILDREN[$pid]'
}

RT=''; NAME=''; IMAGE_OWNED=''
cleanup_container() {
  [ -n "$RT" ] || return 0
  if [ -n "$NAME" ]; then
    timeout --signal=TERM --kill-after=10s 60s "$RT" rm -f "$NAME" >/dev/null 2>&1 || true
  fi
  if [ -n "$IMAGE_OWNED" ]; then
    timeout --signal=TERM --kill-after=10s 120s "$RT" rmi "$IMAGE" >/dev/null 2>&1 || true
  fi
}
cleanup_children() { local pid; for pid in "${!CHILDREN[@]}"; do terminate "$pid" >/dev/null 2>&1; done; }
cleanup() { cleanup_children; cleanup_container; }
trap cleanup EXIT
trap 'exit 1' HUP TERM INT

READY_TICKS=1800; LEDGER_TICKS=600; EXIT_TICKS=1800

container_cell() {
  local facts wl='' gen='' readygen='' pp='' execpid='' ready=0 capturing=0 released=0 ledger=0
  local observer_rc=125 workload_rc=125 before after
  if [ -n "${CONTAINER_RUNTIME:-}" ]; then
    RT=$CONTAINER_RUNTIME
  elif command -v docker >/dev/null; then RT=docker
  elif command -v podman >/dev/null; then RT=podman
  fi
  if [ -z "$RT" ]; then
    result fedora27-shape 0 'SKIP: neither docker nor podman is installed' failed
    return 77
  fi
  command -v "$RT" >/dev/null || {
    result fedora27-shape 0 "SKIP: container runtime $RT is not installed" failed
    return 77
  }
  "$RT" info >/dev/null 2>&1 || {
    result fedora27-shape 0 "SKIP: $RT is installed but its daemon is unreachable" failed
    return 77
  }
  NAME="fedora-softhsm-$$-$(date +%s)"
  if [ -z "$("$RT" images -q "$IMAGE" 2>/dev/null)" ]; then
    "$RT" pull "$IMAGE" || { echo "cannot pull $IMAGE" >&2; return 2; }
    IMAGE_OWNED=1
  fi
  timeout --signal=TERM --kill-after=10s 120s "$RT" run -d --name "$NAME" \
    --pid=host -v "$OUT/shared:/shared" "$IMAGE" sleep infinity || return 2
  timeout --signal=TERM --kill-after=60s 600s "$RT" exec "$NAME" \
    dnf install -y softhsm gcc || return 2
  "$RT" cp "$GATED_SRC" "$NAME:/tmp/gated.c" || return 2
  "$RT" cp "$PROBE_SRC" "$NAME:/tmp/shape-probe.c" || return 2
  timeout --signal=TERM --kill-after=10s 120s "$RT" exec "$NAME" \
    gcc -O1 -o /tmp/gated /tmp/gated.c -ldl || return 2
  timeout --signal=TERM --kill-after=10s 120s "$RT" exec "$NAME" \
    gcc -O2 -o /tmp/shape-probe /tmp/shape-probe.c -ldl || return 2
  "$RT" exec -e SOFTHSM2_CONF=/tmp/softhsm2.conf "$NAME" sh -c \
    'mkdir -p /tmp/tokens && printf "directories.tokendir = /tmp/tokens\nobjectstore.backend = file\nlog.level = ERROR\n" > /tmp/softhsm2.conf && softhsm2-util --init-token --free --label fedora27 --so-pin 5678 --pin 1234' || return 2
  facts=$("$RT" exec "$NAME" /tmp/shape-probe /usr/lib64/pkcs11/libsofthsm2.so) || return 2
  shape_judge "$facts" || return 1
  cell=profile-pid; scope=pid
  cd "$OUT" || return 2
  rm -f -- shared/gate "$cell.json" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json"
  "$RT" exec -e SOFTHSM2_CONF=/tmp/softhsm2.conf "$NAME" \
    /tmp/gated /usr/lib64/pkcs11/libsofthsm2.so "$ITERS" "$SLEEPS" /shared/gate > "$cell.wl" 2>&1 &
  execpid=$!; register "$execpid" || return 2
  if waitfor "$cell.wl" '^READY pid=' "$execpid" "$READY_TICKS"; then
    wl=$(grep -a -m1 -o '^READY pid=[0-9]*' "$cell.wl" | cut -d= -f2)
    if [ -n "$wl" ] && [ -r "/proc/$wl/stat" ] && [ "$(cat "/proc/$wl/comm" 2>/dev/null)" = gated ]; then
      ready=1
      register "$wl" || return 2
      gen=${CHILDREN[$wl]}; readygen=$gen
      before=$(pin "/proc/$wl/root/usr/lib64/pkcs11/libsofthsm2.so") || return 2
      "$P" profile --pid "$wl" --module "/proc/$wl/root/usr/lib64/pkcs11/libsofthsm2.so" \
        --duration "$DURATION" -o "$OUT/$cell.json" > "$cell.stdout" 2> "$cell.stderr" &
      pp=$!; register "$pp" || true
      if waitfor "$cell.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
        capturing=1
        if : >> "$OUT/shared/gate"; then
          released=1
          if waitfor "$cell.wl" '^LEDGER ' "$wl" "$LEDGER_TICKS" 1; then
            ledger=1
            if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
          fi
        fi
      fi
    fi
  fi
  if [ -n "$pp" ] && [ -n "${CHILDREN[$pp]:-}" ]; then terminate "$pp"; observer_rc=$LAST_EXIT; fi
  if [ -n "$wl" ]; then
    after=$(pin "/proc/$wl/root/usr/lib64/pkcs11/libsofthsm2.so" 2>/dev/null) || after='null'
    signal_registered "$wl"
  else
    after='null'
  fi
  if [ -n "${CHILDREN[$execpid]:-}" ]; then
    if finish "$execpid" "$EXIT_TICKS"; then workload_rc=$LAST_EXIT; else workload_rc=124; fi
  fi
  lifecycle_complete || { echo 'container lifecycle incomplete: cannot judge' >&2; return 2; }
  receipt || return 2
  judge_exact || return $?
}

native_cell() {
  local module facts wl='' gen='' readygen='' pp='' ready=0 capturing=0 released=0 ledger=0
  local observer_rc=125 workload_rc=125 before after
  local gated=${GATED_BIN:-$(dirname "$P")/gated} probe=${PROBE_BIN:-$(dirname "$P")/shape-probe}
  [ -x "$gated" ] || {
    result fedora27-shape 0 "SKIP: prebuilt gated workload missing ($gated); Fedora runs tests only, never builds" failed
    return 77
  }
  [ -x "$probe" ] || {
    result fedora27-shape 0 "SKIP: prebuilt shape probe missing ($probe); Fedora runs tests only, never builds" failed
    return 77
  }
  module=$(python3 -I "$SELECT" --select-module) || return 2
  facts=$("$probe" "$module") || return 2
  shape_judge "$facts" || return 1
  export SOFTHSM2_CONF=$OUT/softhsm2.conf
  mkdir -p "$OUT/tokens"
  printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$OUT" > "$OUT/softhsm2.conf"
  softhsm2-util --init-token --free --label fedora27 --so-pin 5678 --pin 1234 >/dev/null || return 2
  cell=profile-pid; scope=pid
  cd "$OUT" || return 2
  rm -f -- "$cell.gate" "$cell.json" "$cell.wl" "$cell.stderr" "$cell.stdout" "$cell.receipt.json"
  before=$(pin "$module") || return 2
  "$gated" "$module" "$ITERS" "$SLEEPS" "$OUT/$cell.gate" > "$cell.wl" 2>&1 &
  wl=$!; register "$wl" || return 2
  gen=${CHILDREN[$wl]}
  if waitfor "$cell.wl" "^READY pid=$wl$" "$wl" "$READY_TICKS"; then
    ready=1; readygen=$(generation "$wl")
    "$P" profile --pid "$wl" --module "$module" --duration "$DURATION" -o "$OUT/$cell.json" \
      > "$cell.stdout" 2> "$cell.stderr" &
    pp=$!; register "$pp" || true
    if waitfor "$cell.stderr" 'p11scope: capturing:' "$pp" "$READY_TICKS" && alive "$wl" && alive "$pp"; then
      capturing=1
      if : >> "$OUT/$cell.gate"; then
        released=1
        if waitfor "$cell.wl" '^LEDGER ' "$wl" "$LEDGER_TICKS" 1; then
          ledger=1
          if finish "$pp" "$EXIT_TICKS"; then observer_rc=$LAST_EXIT; else observer_rc=124; fi
        fi
      fi
    fi
  fi
  if [ -n "$pp" ] && [ -n "${CHILDREN[$pp]:-}" ]; then terminate "$pp"; observer_rc=$LAST_EXIT; fi
  after=$(pin "$module") || after='null'
  # The workload exits with 0 through its SIGTERM handler, like qualify's.
  if [ -n "$wl" ] && [ -n "${CHILDREN[$wl]:-}" ]; then terminate "$wl"; workload_rc=$LAST_EXIT; fi
  lifecycle_complete || { echo 'native lifecycle incomplete: cannot judge' >&2; return 2; }
  receipt || return 2
  judge_exact || return $?
}

started=$(date +%s)
if [ "$NATIVE" = 1 ]; then native_cell; else container_cell; fi
rc=$?
if [ "$rc" = 3 ]; then rc=1; fi
ended=$(date +%s)
echo "fedora-softhsm-cell: elapsed $((ended - started))s"
exit "$rc"

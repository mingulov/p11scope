#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# check.sh: isolated lane-D self-check for the pressure-live fixtures.
# Unprivileged. Builds driver/static-head plus a tiny provider, runs a small
# retain+late+head population through the gate protocol, validates every
# TARGET/READY/LEDGER line and proves owned cleanup. It exercises no capture
# and registers nothing; exit 0 means the fixtures are fit to hand to the
# live cell. Exit 1 means a fixture defect, 64 means a setup refusal.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 64
REPO=$(cd "$HERE/../../.." && pwd) || exit 64
: "${TMPDIR:=/var/tmp/p11scope-ws-tmp}"
mkdir -p "$TMPDIR" || exit 64
WORK=$(mktemp -d "$TMPDIR/pressure-live-check.XXXXXX") || exit 64
REPEAT=20
fail() { echo "check.sh: FAIL: $1" >&2; exit 1; }
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
command -v gcc >/dev/null || { echo 'check.sh: gcc unavailable' >&2; exit 64; }
command -v python3 >/dev/null || { echo 'check.sh: python3 unavailable' >&2; exit 64; }

# Build. The tiny matrix provider is the same input the existing unprivileged
# late-provider cell compiles; only the flags here are this prep's choice.
gcc -shared -fPIC -DMATRIX_INTERFACES=1 -o "$WORK/early.so" \
  "$REPO/crates/discover/tests/fixture/version_matrix.c" || fail 'provider build'
cp "$WORK/early.so" "$WORK/late.so" || fail 'late provider copy'
gcc -std=c11 -O2 -Wall -Wextra -Werror -o "$WORK/driver" "$HERE/driver.c" -ldl || fail 'driver build'
if gcc -std=c11 -O2 -Wall -Wextra -Werror -static -o "$WORK/head" "$HERE/static-head.c" 2>/dev/null; then
  HEAD_LINK=static
else
  gcc -std=c11 -O2 -Wall -Wextra -Werror -o "$WORK/head" "$HERE/static-head.c" || fail 'head build'
  HEAD_LINK=dynamic
fi
echo "check.sh: built (head linkage: $HEAD_LINK)"

# Negative control: usage errors are loud and distinct from fixture failures.
"$WORK/driver" >/dev/null 2>&1 && fail 'driver without args must exit nonzero'
[ "$?" = 2 ] || fail 'driver usage exit must be 2'
"$WORK/head" >/dev/null 2>&1 && fail 'head without args must exit nonzero'
[ "$?" = 2 ] || fail 'head usage exit must be 2'

waitfor() {
  local file=$1 pattern=$2 pid=$3 ticks=$4 i
  for ((i=0;i<ticks;i++)); do
    kill -0 "$pid" 2>/dev/null || return 1
    grep -qa -- "$pattern" "$file" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}
PIDS=""
spawn() {
  local log=$1; shift
  "$@" >"$WORK/$log" 2>&1 &
  PIDS="$PIDS $log:$!"
}
reap() {
  local entry pid rc=0
  for entry in $PIDS; do
    pid=${entry#*:}
    kill -TERM "$pid" 2>/dev/null || true
  done
  for entry in $PIDS; do
    pid=${entry#*:}
    wait "$pid" 2>/dev/null || rc=1
  done
  PIDS=""
  return "$rc"
}

spawn retain0.log "$WORK/driver" "$WORK/early.so" retain "$REPEAT" "$WORK/gate"
spawn retain1.log "$WORK/driver" "$WORK/early.so" retain "$REPEAT" "$WORK/gate"
spawn late.log "$WORK/driver" "$WORK/late.so" late "$REPEAT" "$WORK/gate"
spawn head.log "$WORK/head" "$WORK/gate"
for entry in $PIDS; do
  log=${entry%%:*}; pid=${entry#*:}
  waitfor "$WORK/$log" '^READY pid=' "$pid" 100 || { reap; fail "no READY in $log"; }
done
touch "$WORK/gate" || { reap; fail 'gate release'; }
# LEDGER lines arrive while children hold; poll the files directly.
for log in retain0.log retain1.log late.log head.log; do
  ok=0
  for ((i=0;i<100;i++)); do
    if grep -qa '^LEDGER ' "$WORK/$log" 2>/dev/null; then ok=1; break; fi
    sleep 0.1
  done
  [ "$ok" = 1 ] || { reap; fail "no LEDGER in $log"; }
done

# Every provider child emits exactly three TARGET lines (the three
# publication surfaces) and a complete, fully successful ledger.
for log in retain0.log retain1.log late.log; do
  [ "$(grep -c '^TARGET ' "$WORK/$log")" = 3 ] || { reap; fail "TARGET count in $log"; }
  ledger=$(grep '^LEDGER ' "$WORK/$log" | head -1) || { reap; fail "LEDGER read in $log"; }
  echo "$ledger" | sed 's/^LEDGER //' | python3 -I -c \
    'import json,sys; d=json.load(sys.stdin);
assert d["schema"]=="p11scope/pressure-live-ledger/v1", d;
assert d["complete"] is True, d;
assert len(d["functions"])==3, d;
assert all(f["attempts"]==int(sys.argv[1]) and f["successful"]==int(sys.argv[1]) for f in d["functions"]), d' \
    "$REPEAT" || { reap; fail "LEDGER content in $log"; }
done
[ "$(grep -c '^TARGET ' "$WORK/head.log")" = 0 ] || { reap; fail 'head must emit no TARGET'; }
grep -q '^LEDGER {"schema":"p11scope/pressure-live-head/v1"' "$WORK/head.log" || { reap; fail 'head LEDGER'; }

# The running head maps no provider: provider-freedom from /proc, not trust.
head_pid=$(sed -n 's/^READY pid=\([0-9][0-9]*\)/\1/p' "$WORK/head.log" | head -1)
[ -n "$head_pid" ] || { reap; fail 'head READY pid'; }
if grep -q 'early\.so\|late\.so' "/proc/$head_pid/maps"; then reap; fail 'head maps a provider'; fi
if tr '\0' '\n' <"/proc/$head_pid/cmdline" | grep -q 'early\.so\|late\.so'; then reap; fail 'head argv names a provider'; fi
echo "check.sh: population validated (3 provider children + provider-free head)"

reap || fail 'children must exit 0 on SIGTERM'
for pid in $(sed -n 's/^READY pid=\([0-9][0-9]*\)/\1/p' "$WORK"/*.log); do
  kill -0 "$pid" 2>/dev/null && fail "owned child $pid survived"
done
echo 'check.sh: PASS'

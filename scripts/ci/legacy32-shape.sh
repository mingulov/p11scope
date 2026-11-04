#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# legacy32-shape.sh P11SCOPE OUTDIR: SoftHSM 2.7 table-shape exact cells.
#
# Cell (a) of the S2 package: a synthetic 68-slot provider labelled {3,2}
# with no interface exports (tests/fixtures/legacy32-provider/) runs the
# existing public-CLI exact cells (profile-pid, system) through
# scripts/qualify-public-cli.sh's MODULE= override and its
# P11SCOPE_PUBLIC_CLI_CELLS filter, so each leg runs two cells instead of
# the full campaign. Until the scan fix lane (exec-scan-legacy32) lands,
# p11scope walks the mislabelled table as known_prefix and render marks
# observation lossy, so both cells fail; they are reported as
# expected-failure, and an unexpected pass flips the exit code so the
# change is noticed. The same two cells against the stock module are a
# passing control.
#
# Rows in OUTDIR/results.jsonl: legacy32-pid, legacy32-system
# (expected-failure), stock-pid, stock-system (qualified control).
# Exit 0: shape held, legacy32 failed as expected, controls passed.
# Exit 1: a control failed, or a legacy32 cell unexpectedly passed.
# Exit 2: harness error (shape mismatch, missing row, unusable tool).
#
# Apt prerequisites (Ubuntu 26.04 runner, plus qualify-public-cli.sh's):
#   gcc binutils jq procps python3 softhsm2 util-linux
# Requires root (the underlying qualify script does). Invoke like:
#   sudo -n env RUNUID="$(id -u)" RUNGID="$(id -g)" \
#     scripts/ci/legacy32-shape.sh P11SCOPE OUTDIR
#
# Test seams (documented, not CI paths):
#   --shape-only OUTDIR [extra cc flags...]
#     build the fixture and judge its shape only; honors LEGACY32_CFLAGS
#     (extra cc flags, e.g. -DLEGACY32_MINOR=0 for the {3,0} variant),
#     LEGACY32_EXPECT_MAJOR/MINOR/SLOTS (default 3/2/68) and
#     LEGACY32_EXPECT_TAIL (default 0x1). Exit 0 on match, 2 otherwise.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 64
ROOT=$(cd "$HERE/../.." && pwd) || exit 64
QUALIFY=$ROOT/scripts/qualify-public-cli.sh
FIXSRC=$ROOT/tests/fixtures/legacy32-provider
REASON='SoftHSM 2.7 table shape; exec-scan-legacy32'

SHAPE_ONLY=0
if [ "${1:-}" = --shape-only ]; then SHAPE_ONLY=1; shift; fi
if [ "$SHAPE_ONLY" = 1 ]; then
  [ $# -ge 1 ] || { echo 'usage: legacy32-shape.sh --shape-only OUTDIR [extra cc flags...]' >&2; exit 64; }
  OUT=$1; shift
else
  [ $# = 2 ] || { echo 'usage: legacy32-shape.sh P11SCOPE OUTDIR' >&2; exit 64; }
  P=$(realpath -e -- "$1") || exit 64
  OUT=$2
  [ "$(id -u)" = 0 ] || { echo 'must run as root' >&2; exit 64; }
fi
command -v cc >/dev/null || { echo 'cc required' >&2; exit 64; }
command -v nm >/dev/null || { echo 'nm (binutils) required' >&2; exit 64; }
mkdir -p "$OUT" && OUT=$(realpath -e -- "$OUT") || exit 64
: > "$OUT/results.jsonl"

result() {
  python3 - "$1" "$2" "$3" "$4" <<'PY' | tee -a "$OUT/results.jsonl"
import json,sys
print(json.dumps({'cell':sys.argv[1],'pass':sys.argv[2]=='1','detail':sys.argv[3],'qualification':sys.argv[4]}))
PY
}

# Build the fixture and judge its published shape. Prints the facts on
# stdout; returns 0 on match, 2 with a results.jsonl row otherwise.
shape_build_and_judge() {
  local dir=$1; shift
  local so=$dir/legacy32.so probe=$dir/shape-probe facts
  # shellcheck disable=SC2086
  cc -std=c11 -O2 -fPIC -fno-ipa-icf -fno-merge-constants -Wall -Wextra -Werror \
    -shared -Wl,-z,defs ${LEGACY32_CFLAGS:-} "$@" -o "$so" "$FIXSRC/legacy32.c" || return 2
  cc -std=c11 -O2 -Wall -Wextra -Werror -o "$probe" "$FIXSRC/shape-probe.c" -ldl || return 2
  facts=$("$probe" "$so") || return 2
  printf '%s\n' "$facts"
  local major=${LEGACY32_EXPECT_MAJOR:-3} minor=${LEGACY32_EXPECT_MINOR:-2}
  local slots=${LEGACY32_EXPECT_SLOTS:-68} tail=${LEGACY32_EXPECT_TAIL:-0x1}
  local fail=''
  printf '%s\n' "$facts" | grep -qx "VERSION $major $minor" || fail="version gate: want VERSION $major $minor"
  [ "$slots" = 68 ] || fail="slot-count gate: fixture publishes 68 slots, expected $slots"
  if [ -z "$fail" ]; then
    printf '%s\n' "$facts" | grep -qx 'NONNULL68 68' || fail='slot-count gate: want NONNULL68 68'
  fi
  if [ -z "$fail" ]; then
    for line in 'DISTINCT68 1' "SLOT68 $tail" 'GATED6 1' 'GETTER_SLOT 1' 'INTERFACES 0'; do
      printf '%s\n' "$facts" | grep -qx "$line" || fail="shape gate: want $line"
      [ -z "$fail" ] || break
    done
  fi
  if [ -z "$fail" ]; then
    [ "$(nm -D --defined-only "$so" | grep -c ' T C_')" = 68 ] || fail='export gate: want exactly 68 defined C_ exports'
  fi
  if [ -z "$fail" ]; then
    nm -D --defined-only "$so" | grep -q 'C_GetInterface' && fail='export gate: interface getter exported'
  fi
  if [ -z "$fail" ]; then
    if nm -D --defined-only "$so" | grep ' T ' | grep -qv ' T C_'; then
      fail='export gate: non-C_ text export present'
    fi
  fi
  if [ -n "$fail" ]; then
    result legacy32-shape 0 "$fail; facts: $(printf '%s' "$facts" | tr '\n' ' ')" failed
    return 2
  fi
  return 0
}

if [ "$SHAPE_ONLY" = 1 ]; then
  if shape_build_and_judge "$OUT" "$@"; then
    result legacy32-shape 1 'fixture shape matches the SoftHSM 2.7 contract' qualified
    exit 0
  fi
  exit 2
fi

FIX=$OUT/fix; mkdir -p "$FIX"
shape_build_and_judge "$FIX" || exit 2
SO=$FIX/legacy32.so

started=$(date +%s)
run_qualify() {
  local module=$1 dest=$2 rc=0
  mkdir -p "$dest"
  # The filter must stay exactly the cells wrap_cell reads below; a drift
  # fails loudly as a missing oracle cell (harness error), never silently.
  if [ -n "$module" ]; then
    P11SCOPE_PUBLIC_CLI_CELLS='profile-pid system' MODULE=$module "$QUALIFY" "$P" "$dest" >"$dest/qual.log" 2>&1 || rc=$?
  else
    P11SCOPE_PUBLIC_CLI_CELLS='profile-pid system' env -u MODULE "$QUALIFY" "$P" "$dest" >"$dest/qual.log" 2>&1 || rc=$?
  fi
  [ "$rc" = 0 ] || [ "$rc" = 1 ] || [ "$rc" = 2 ] || {
    echo "qualify-public-cli.sh exited $rc (log: $dest/qual.log)" >&2
    return 2
  }
  return 0
}

# Emit one wrapper row from a qualify results.jsonl cell. $3 is the wrapper
# cell name, $4 the mode: expected-failure or control.
wrap_cell() {
  local results=$1 oracle_cell=$2 cell=$3 mode=$4
  local row pass qual detail
  row=$(python3 - "$results" "$oracle_cell" <<'PY'
import json,sys
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    row=json.loads(line)
    if row.get('cell')==sys.argv[2]:
        print(json.dumps(row)); break
PY
) || { result "$cell" 0 "cannot parse $results" failed; return 2; }
  [ -n "$row" ] || { result "$cell" 0 "missing oracle cell $oracle_cell in $results" failed; return 2; }
  pass=$(printf '%s' "$row" | python3 -c 'import json,sys; print(1 if json.load(sys.stdin)["pass"] else 0)')
  qual=$(printf '%s' "$row" | python3 -c 'import json,sys; print(json.load(sys.stdin)["qualification"])')
  detail=$(printf '%s' "$row" | python3 -c 'import json,sys; print(json.load(sys.stdin)["detail"])')
  if [ "$mode" = expected-failure ]; then
    if [ "$pass" = 1 ]; then
      result "$cell" 1 "UNEXPECTED PASS ($REASON may have landed): [$qual] $detail" expected-failure
      return 3
    fi
    result "$cell" 0 "$REASON: [$qual] $detail" expected-failure
    return 0
  fi
  if [ "$pass" = 1 ]; then
    result "$cell" 1 "control with stock module: [$qual] $detail" qualified
    return 0
  fi
  result "$cell" 0 "control FAILED with stock module: [$qual] $detail" failed
  return 1
}

failed=0; changed=0; harness=0
if run_qualify "$SO" "$OUT/legacy32"; then
  wrap_cell "$OUT/legacy32/results.jsonl" profile-pid legacy32-pid expected-failure || {
    rc=$?; [ "$rc" = 3 ] && changed=1 || harness=1
  }
  wrap_cell "$OUT/legacy32/results.jsonl" system legacy32-system expected-failure || {
    rc=$?; [ "$rc" = 3 ] && changed=1 || harness=1
  }
else
  harness=1
fi
if run_qualify '' "$OUT/stock"; then
  wrap_cell "$OUT/stock/results.jsonl" profile-pid stock-pid control || {
    rc=$?; [ "$rc" = 1 ] && failed=1 || harness=1
  }
  wrap_cell "$OUT/stock/results.jsonl" system stock-system control || {
    rc=$?; [ "$rc" = 1 ] && failed=1 || harness=1
  }
else
  harness=1
fi
ended=$(date +%s)
echo "legacy32-shape: elapsed $((ended - started))s (see $OUT/legacy32/qual.log $OUT/stock/qual.log)"
if [ "$harness" = 1 ]; then exit 2; fi
if [ "$failed" = 1 ] || [ "$changed" = 1 ]; then exit 1; fi
exit 0

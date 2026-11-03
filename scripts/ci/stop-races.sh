#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# scripts/ci/stop-races.sh P11SCOPE OUTDIR: S3 stop-path race cells for CI.
# Runs the seeded sweep + newcomer burst, then the Joint last-waiter library
# cell. Writes OUTDIR/results.jsonl rows
# {cell, pass, qualification, detail} with qualification in
# qualified|expected-failure|environment-precluded|failed. Exit 0 means
# every qualified cell passed; 1 means a cell failed; 2 means a harness
# error; 77 means a prerequisite is missing. Must run as root
# (passwordless sudo on hosted runners is fine); umask 022; TMPDIR on a
# disk filesystem.
#
# Apt prerequisites (Ubuntu 26.04): gcc python3 softhsm2 util-linux
#
# Environment:
#   STOP_RACES_TRIALS (default 2): sweep trials per command. The full
#     10/command campaign runs manually/weekly; 2 fits the CI time budget.
#   STOP_RACES_BURST_TRIALS (default 1): burst repetitions.
#   P11SCOPE_LIBTEST: path to the built library test executable that
#     contains the Joint cell. The workflow builds it once and passes it;
#     this script never builds. Missing/foreign binary fails the Joint row.
#   JOINT_EXPECTED_FAILURE (default 1): while the joint-wedge fix is
#     unlanded, the Joint cell fails with the wedge signature and is
#     recorded expected-failure. Set 0 once the fix lands; an unexpected
#     pass, or a failure without the wedge signature, fails the run. A
#     failure carrying the S1-preclusion tag is recorded
#     environment-precluded instead: the wedge path needs a Linked host,
#     so an S1-only host cannot evaluate the cell either way. This holds
#     whatever JOINT_EXPECTED_FAILURE says.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 64
ROOT=$(cd "$HERE/../.." && pwd) || exit 64
QUALIFY=$ROOT/scripts/qualify-stop-races.sh
JOINT_CELL=inventory::joint_stop_races_privileged_tests::privileged_joint_stop_after_last_waiter_resolves_publishes_final_lp64
JOINT_WEDGE_SIGNATURE='Published then WoundDown'
[ $# = 2 ] || { echo 'usage: stop-races.sh P11SCOPE OUTDIR' >&2; exit 64; }
P=$1; OUT=$2
TRIALS=${STOP_RACES_TRIALS:-2}
BURST=${STOP_RACES_BURST_TRIALS:-1}
LIBTEST=${P11SCOPE_LIBTEST:-}
EXPECT_JOINT_FAIL=${JOINT_EXPECTED_FAILURE:-1}
case $TRIALS in *[!0-9]*|'') echo "bad STOP_RACES_TRIALS: $TRIALS" >&2; exit 64 ;; esac
case $BURST in *[!0-9]*|'') echo "bad STOP_RACES_BURST_TRIALS: $BURST" >&2; exit 64 ;; esac
case $EXPECT_JOINT_FAIL in 0|1) ;; *) echo "bad JOINT_EXPECTED_FAILURE: $EXPECT_JOINT_FAIL" >&2; exit 64 ;; esac
[ "$(id -u)" = 0 ] || { echo 'stop-races.sh: prerequisite missing: must run as root' >&2; exit 77; }
umask 022
P=$(realpath -e -- "$P") || { echo "stop-races.sh: prerequisite missing: observer not found: $1" >&2; exit 77; }
mkdir -p "$OUT" && OUT=$(realpath -e -- "$OUT") || exit 2
cd "$OUT" || exit 2
"$QUALIFY" "$P" "$OUT" --trials "$TRIALS" --burst-trials "$BURST" --cell all > qualify.log 2>&1
qualify_rc=$?
[ -f results.jsonl ] || { echo 'stop-races.sh: harness error: qualify produced no results.jsonl' >&2; exit 2; }
python3 - "$qualify_rc" <<'PY'
import json,sys
rows=[]
for line in open('results.jsonl'):
    line=line.strip()
    if line:
        rows.append(json.loads(line))
mapped=[]
for row in rows:
    if row.get('pass') is True:
        row['qualification']='qualified'
    else:
        row['qualification']='failed'
    mapped.append(row)
with open('results.jsonl','w') as stream:
    for row in mapped:
        stream.write(json.dumps(row,sort_keys=True)+'\n')
PY
[ $? = 0 ] || { echo 'stop-races.sh: harness error: cannot map qualifications' >&2; exit 2; }
joint_detail=''
joint_qual='failed'
joint_pass=0
if [ -z "$LIBTEST" ]; then
  joint_detail='harness: P11SCOPE_LIBTEST not provided'
elif [ ! -x "$LIBTEST" ]; then
  joint_detail="harness: library test binary not executable: $LIBTEST"
elif ! "$LIBTEST" --list 2>/dev/null | grep -qx "$JOINT_CELL: test"; then
  joint_detail="harness: joint cell missing from test binary: $JOINT_CELL"
else
  set +e
  "$LIBTEST" --exact "$JOINT_CELL" --ignored > joint-cell.log 2>&1
  joint_rc=$?
  set -e
  if [ "$joint_rc" = 0 ] && [ "$EXPECT_JOINT_FAIL" = 0 ]; then
    joint_pass=1; joint_qual='qualified'; joint_detail='joint stop after last waiter resolves reaches Published then WoundDown'
  elif [ "$joint_rc" = 0 ]; then
    joint_detail='joint cell unexpectedly passed; set JOINT_EXPECTED_FAILURE=0 once the joint-wedge fix lands'
  elif [ "$EXPECT_JOINT_FAIL" = 1 ] && grep -q "$JOINT_WEDGE_SIGNATURE" joint-cell.log; then
    joint_detail='expected failure: joint finish wedges without the joint-wedge fix (task/v060-joint-wedge 244ac82ec); see joint-cell.log'
    joint_qual='expected-failure'
  elif grep -q 'P11SCOPE_CELL_BRANCH=.*:s1-precluded' joint-cell.log; then
    joint_detail='environment-precluded: S1-only host without joint feeds; wedge path unevaluated; see joint-cell.log'
    joint_qual='environment-precluded'
  else
    joint_detail='joint cell failed without the wedge signature (regression or new failure); see joint-cell.log'
  fi
fi
python3 - "$joint_pass" "$joint_detail" "$joint_qual" <<'PY' | tee -a results.jsonl
import json,sys
print(json.dumps({'cell':'joint-stop-after-last-waiter','pass':sys.argv[1]=='1','detail':sys.argv[2],'qualification':sys.argv[3]}))
PY
python3 - <<'PY' | tee summary.txt
import json,sys
rows=[json.loads(line) for line in open('results.jsonl') if line.strip()]
ids=[row['cell'] for row in rows]
valid=len(ids)==len(set(ids)) and len(ids)==6
failed=[r['cell'] for r in rows if not r['pass'] and r['qualification'] not in ('expected-failure','environment-precluded')]
print('SUMMARY pass=%d fail=%d expected-failures=%d precluded=%d failed=%s terminal_rows_valid=%s' % (
  sum(r['pass'] for r in rows),len(failed),
  sum(r['qualification']=='expected-failure' for r in rows),
  sum(r['qualification']=='environment-precluded' for r in rows),failed,valid))
sys.exit(1 if failed or not valid else 0)
PY
summary_rc="${PIPESTATUS[0]}"
if [ "$qualify_rc" = 2 ] || [ "$qualify_rc" = 77 ]; then
  exit "$qualify_rc"
fi
exit "$summary_rc"

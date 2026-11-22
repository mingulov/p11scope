#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# scripts/ci/stop-races.sh P11SCOPE OUTDIR: S3 stop-path race cells for CI.
# Runs the seeded sweep + newcomer burst, then the Joint linked-stop library
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
#   JOINT_EXPECTED_FAILURE (default 0): while the joint-wedge fix was
#     unlanded, the Joint cell failed with the wedge and was recorded
#     expected-failure. The cell now passes on the linked journal
#     session, so 0 is the default; set 1 to re-arm the expectation if
#     the wedge returns.
#   The Joint row is judged by scripts/ci/joint_stop_verdict.py, one
#     fail-closed parser shared with scripts/run-privileged-lib-tests.sh
#     (its docstring holds the grammar). It qualifies only an exit-0 run
#     with a strict one-test libtest pass summary as the terminal record
#     and the twelve wp7-stop cases in order, each exactly once as
#     linked tag, offset diagnostic bound to the case's offset with
#     finish=published, and completion marker, with no error, no-feed
#     record or stray framing. It records environment-precluded only
#     for a normal libtest failure (exit 101, strict one-test failure
#     summary) whose sole terminal error is the first case's own S1
#     receipt right after its S1 tag (this holds whatever
#     JOINT_EXPECTED_FAILURE says), and expected-failure only under
#     JOINT_EXPECTED_FAILURE=1 for the terminal Published-then-WoundDown
#     error of the linked case in progress, bound to its offset.
#     Everything else fails the row with the validator's named reason
#     in brackets: a signal or other exit status, a missing, malformed,
#     duplicated or non-terminal summary, a zero-test or foreign run,
#     a malformed or embedded record, a stray or mismatched no-feed
#     receipt, competing errors, an out-of-order, duplicated, short or
#     mixed case sequence, the unattributed no-feed cause, an
#     unexpected pass under 1, or a wedge under 0.
#   The entry forces the full 12-case matrix: inherited WP7_STOP_PREPS /
#     WP7_STOP_OFFSETS narrowing is unset for the cell (direct libtest
#     runs keep narrowing for exploration) and the cell runs with
#     --nocapture so its per-case records reach the log.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 64
ROOT=$(cd "$HERE/../.." && pwd) || exit 64
QUALIFY=$ROOT/scripts/qualify-stop-races.sh
JOINT_CELL=inventory::joint_stop_races_privileged_tests::privileged_joint_stop_after_last_waiter_resolves_publishes_final_lp64
JOINT_VERDICT=$HERE/joint_stop_verdict.py
[ $# = 2 ] || { echo 'usage: stop-races.sh P11SCOPE OUTDIR' >&2; exit 64; }
P=$1; OUT=$2
TRIALS=${STOP_RACES_TRIALS:-2}
BURST=${STOP_RACES_BURST_TRIALS:-1}
LIBTEST=${P11SCOPE_LIBTEST:-}
EXPECT_JOINT_FAIL=${JOINT_EXPECTED_FAILURE:-0}
case $TRIALS in *[!0-9]*|'') echo "bad STOP_RACES_TRIALS: $TRIALS" >&2; exit 64 ;; esac
case $BURST in *[!0-9]*|'') echo "bad STOP_RACES_BURST_TRIALS: $BURST" >&2; exit 64 ;; esac
case $EXPECT_JOINT_FAIL in 0|1) ;; *) echo "bad JOINT_EXPECTED_FAILURE: $EXPECT_JOINT_FAIL" >&2; exit 64 ;; esac
umask 022
mkdir -p "$OUT" && OUT=$(realpath -e -- "$OUT") || exit 2
cd "$OUT" || exit 2
: > results.jsonl
prereq_fail() {
  echo "stop-races.sh: prerequisite missing: $1" >&2
  python3 - "$1" <<'PY' >> results.jsonl
import json,sys
print(json.dumps({"cell":"stop-races-prerequisites","pass":False,"qualification":"environment-precluded","detail":"prerequisite missing: "+sys.argv[1]},sort_keys=True))
PY
  exit 77
}
[ "$(id -u)" = 0 ] || prereq_fail 'must run as root'
P=$(realpath -e -- "$P") || prereq_fail "observer not found: $1"
"$QUALIFY" "$P" "$OUT" --trials "$TRIALS" --burst-trials "$BURST" --cell all > qualify.log 2>&1
qualify_rc=$?
[ -f results.jsonl ] || { echo 'stop-races.sh: harness error: qualify produced no results.jsonl' >&2; exit 2; }
if python3 - "$qualify_rc" <<'PY'
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
then
  :
else
  echo 'stop-races.sh: harness error: cannot map qualifications' >&2; exit 2
fi
joint_detail=''
joint_qual='failed'
joint_pass=0
if [ -z "$LIBTEST" ]; then
  joint_detail='harness: P11SCOPE_LIBTEST not provided'
elif [ ! -x "$LIBTEST" ]; then
  joint_detail="harness: library test binary not executable: $LIBTEST"
elif ! "$LIBTEST" --list --ignored --exact "$JOINT_CELL" 2>/dev/null | grep -qx "$JOINT_CELL: test"; then
  joint_detail="harness: joint cell missing from test binary: $JOINT_CELL"
else
  joint_rc=0
  env -u WP7_STOP_PREPS -u WP7_STOP_OFFSETS "$LIBTEST" --exact "$JOINT_CELL" --ignored --nocapture > joint-cell.log 2>&1 || joint_rc=$?
  # One fail-closed validator judges the whole log (exit status, strict
  # libtest framing and summary, the ordered 12-case record sequence,
  # receipts bound to their tag and case); it is shared with the long
  # campaign runner. Anything it cannot positively classify fails.
  joint_verdict=()
  verdict_rc=0
  python3 -I "$JOINT_VERDICT" --cell "$JOINT_CELL" --status "$joint_rc" \
      --expect-wedge "$EXPECT_JOINT_FAIL" --format lines joint-cell.log \
      > joint-verdict.txt 2>&1 || verdict_rc=$?
  mapfile -t joint_verdict < joint-verdict.txt
  if [ "$verdict_rc" != 0 ] || [ "${#joint_verdict[@]}" != 4 ]; then
    joint_detail='harness: the joint verdict validator produced no verdict; see joint-cell.log'
  else
    joint_qual=${joint_verdict[0]}
    joint_detail="${joint_verdict[3]} [${joint_verdict[1]}]; see joint-cell.log"
    case $joint_qual in
      qualified) joint_pass=1 ;;
      expected-failure|environment-precluded|failed) ;;
      *) joint_qual='failed'; joint_detail="harness: unknown joint qualification; see joint-cell.log" ;;
    esac
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

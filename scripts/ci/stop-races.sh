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
#     unlanded, the Joint cell failed with the wedge signature and was
#     recorded expected-failure. The cell now passes on the linked
#     journal session, so 0 is the default; set 1 to re-arm the
#     expectation if the wedge returns. An unexpected pass (under 1),
#     or a failure without the wedge signature, fails the run. A
#     zero-test run (exit 0 without a passing test) fails the row too:
#     the cell must execute and pass, never merely list. A failure
#     carrying a full-line S1-preclusion tag for a valid case plus the
#     current unlinked-producer/zero-install receipt is recorded
#     environment-precluded instead: without joint feeds the cell
#     cannot evaluate either way. This holds whatever
#     JOINT_EXPECTED_FAILURE says. Preclusion holds only before any
#     linked case: a linked tag, a completion marker, a wedge
#     signature, or an unattributed tag beside the S1 tag fails the
#     row as mixed/ambiguous, as does an S1 tag without the receipt
#     (the old collapsed tag, an embedded lookalike, a suffixed
#     diagnostic). A failure carrying the full-line unattributed
#     no-feed tag plus its receipt (no feeds, no S1 seal) fails the
#     row with its cause: only the proven S1 pair is environmental.
#   The entry forces the full 12-case matrix: inherited WP7_STOP_PREPS /
#     WP7_STOP_OFFSETS narrowing is unset for the cell (direct libtest
#     runs keep narrowing for exploration), the cell runs with
#     --nocapture so its per-case tags reach the log, and the qualified
#     row requires all 12 post-stop completion lines by exact full-line
#     match. A pass with fewer completed cases fails the row as
#     matrix-short; pre-stop linkage tags alone never qualify.
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
  joint_matrix_missing=''
  if [ "$joint_rc" = 0 ]; then
    i=0
    while [ "$i" -lt 12 ]; do
      if ! grep -qxF "P11SCOPE_STOP_COMPLETE=wp7-stop$i" joint-cell.log; then
        joint_matrix_missing="$joint_matrix_missing $i"
      fi
      i=$((i + 1))
    done
  fi
  # No-feed evidence, full-line valid tags only: an embedded tag, a
  # suffixed diagnostic, or an out-of-range case never counts.
  s1_tag=0; s1_receipt=0; linked_tag=0; complete_tag=0
  unattributed_tag=0; unattributed_receipt=0
  if grep -qE '^P11SCOPE_CELL_BRANCH=wp7-stop(0|1|2|3|4|5|6|7|8|9|10|11):s1-precluded$' joint-cell.log; then s1_tag=1; fi
  if grep -qF 'no joint feeds with S1 seal (producers unlinked, zero installs)' joint-cell.log; then s1_receipt=1; fi
  if grep -qE '^P11SCOPE_CELL_BRANCH=wp7-stop(0|1|2|3|4|5|6|7|8|9|10|11):linked$' joint-cell.log; then linked_tag=1; fi
  if grep -qE '^P11SCOPE_STOP_COMPLETE=wp7-stop(0|1|2|3|4|5|6|7|8|9|10|11)$' joint-cell.log; then complete_tag=1; fi
  if grep -qE '^P11SCOPE_CELL_BRANCH=wp7-stop(0|1|2|3|4|5|6|7|8|9|10|11):no-feeds-unattributed$' joint-cell.log; then unattributed_tag=1; fi
  if grep -qF 'no joint feeds without S1 seal (producers linked, zero installs unexplained)' joint-cell.log; then unattributed_receipt=1; fi
  if [ "$joint_rc" = 0 ] && { [ "$s1_tag" = 1 ] || [ "$unattributed_tag" = 1 ]; }; then
    joint_detail='joint cell exited 0 with a no-feed preclusion tag (regression); a pass never precludes; see joint-cell.log'
  elif [ "$joint_rc" = 0 ] && [ "$EXPECT_JOINT_FAIL" = 0 ] \
      && grep -q '^test result: ok\. 1 passed' joint-cell.log \
      && [ -z "$joint_matrix_missing" ] \
      && [ "$s1_tag" = 0 ] && [ "$unattributed_tag" = 0 ]; then
    joint_pass=1; joint_qual='qualified'; joint_detail='linked joint stop reaches Published then WoundDown (12-case matrix)'
  elif [ "$joint_rc" = 0 ] && [ "$EXPECT_JOINT_FAIL" = 1 ]; then
    joint_detail='joint cell unexpectedly passed under JOINT_EXPECTED_FAILURE=1; set 0 once the wedge is gone for good'
  elif [ "$joint_rc" = 0 ] && [ "$EXPECT_JOINT_FAIL" = 0 ] \
      && grep -q '^test result: ok\. 1 passed' joint-cell.log; then
    joint_detail="joint cell passed without the full stop matrix (missing completed cases:$joint_matrix_missing); the qualifying entry forces all 12 wp7-stop cases"
  elif [ "$joint_rc" = 0 ]; then
    joint_detail='joint cell exited 0 without a passing test (zero selected or unmapped output); see joint-cell.log'
  elif [ "$s1_tag" = 1 ] && { [ "$linked_tag" = 1 ] || [ "$complete_tag" = 1 ]; }; then
    joint_detail='joint cell mixed linked operation with an S1 preclusion tag (regression); preclusion holds only before any linked case; see joint-cell.log'
  elif [ "$s1_tag" = 1 ] && [ "$unattributed_tag" = 1 ]; then
    joint_detail='joint cell mixed S1 and unattributed no-feed tags (regression); see joint-cell.log'
  elif [ "$s1_tag" = 1 ] && grep -q "$JOINT_WEDGE_SIGNATURE" joint-cell.log; then
    joint_detail='joint cell mixed wedge evidence with an S1 preclusion tag (regression); see joint-cell.log'
  elif [ "$s1_tag" = 1 ] && [ "$s1_receipt" = 0 ]; then
    joint_detail='joint cell S1 tag without the current unlinked-producer/zero-install receipt (ambiguous, possibly the old collapsed tag); see joint-cell.log'
  elif [ "$EXPECT_JOINT_FAIL" = 1 ] && grep -q "$JOINT_WEDGE_SIGNATURE" joint-cell.log; then
    joint_detail='expected failure: joint finish wedges (task/v060-joint-wedge owns the fix); see joint-cell.log'
    joint_qual='expected-failure'
  elif grep -q "$JOINT_WEDGE_SIGNATURE" joint-cell.log; then
    joint_detail='wedge reproduced under JOINT_EXPECTED_FAILURE=0 (regression); set 1 to re-arm the expectation; see joint-cell.log'
  elif [ "$s1_tag" = 1 ] && [ "$s1_receipt" = 1 ]; then
    joint_detail='environment-precluded: S1 seal without joint feeds (producers unlinked, zero installs); see joint-cell.log'
    joint_qual='environment-precluded'
  elif [ "$unattributed_tag" = 1 ] && [ "$unattributed_receipt" = 1 ]; then
    joint_detail='joint cell produced no feeds without an S1 seal (unattributed: producers linked, zero installs unexplained); not environmental; see joint-cell.log'
  elif [ "$unattributed_tag" = 1 ]; then
    joint_detail='joint cell unattributed tag without the current linked-producer/zero-install receipt (ambiguous); see joint-cell.log'
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

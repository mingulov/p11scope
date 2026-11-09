#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# run-cell-script.sh NAME P11SCOPE OUTDIR [--expected-failure CELL ...] [--allow-nonqualifying CELL ...] [--require CELL ...]
# Generic cell-script template: runs scripts/ci/<NAME>.sh P11SCOPE OUTDIR,
# then validates OUTDIR/results.jsonl with check-cell-results.py.
# Must run as root; the workflow invokes this wrapper through privilege
# escalation and restores ownership afterwards, so this file names no
# escalation tool itself. Exit 77 from the cell script (prerequisite
# missing) always fails: it is never a pass in CI.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
REPO=$(cd "$HERE/../.." && pwd) || exit 2
if [ $# -lt 3 ]; then echo "usage: run-cell-script.sh NAME P11SCOPE OUTDIR [--expected-failure CELL ...] [--allow-nonqualifying CELL ...] [--require CELL ...]" >&2; exit 2; fi
NAME=$1; P11SCOPE=$2; OUT=$3; shift 3
case $NAME in
  *[/.]*|"") echo "run-cell-script: NAME must be a bare script name without path" >&2; exit 2 ;;
esac
SCRIPT=$REPO/scripts/ci/$NAME.sh
[ -x "$SCRIPT" ] || { echo "run-cell-script: no executable cell script: $SCRIPT" >&2; exit 2; }
[ -x "$P11SCOPE" ] || { echo "run-cell-script: no executable observer: $P11SCOPE" >&2; exit 2; }
EXPECTED=()
while [ $# -gt 0 ]; do
  case $1 in
    --expected-failure) shift; [ $# -gt 0 ] || { echo "run-cell-script: --expected-failure needs a cell name" >&2; exit 2; }; EXPECTED+=(--expected-failure "$1"); shift ;;
    --allow-nonqualifying) shift; [ $# -gt 0 ] || { echo "run-cell-script: --allow-nonqualifying needs a cell name" >&2; exit 2; }; EXPECTED+=(--allow-nonqualifying "$1"); shift ;;
    --require) shift; [ $# -gt 0 ] || { echo "run-cell-script: --require needs a cell name" >&2; exit 2; }; EXPECTED+=(--require "$1"); shift ;;
    *) echo "run-cell-script: unknown option: $1" >&2; exit 2 ;;
  esac
done
if [ "$(id -u)" != 0 ]; then echo "run-cell-script: must run as root" >&2; exit 2; fi
mkdir -p "$OUT" || exit 2
OUT=$(cd "$OUT" && pwd) || exit 2
rc=0
"$SCRIPT" "$P11SCOPE" "$OUT" || rc=$?
echo "cell script $NAME rc=$rc"
if [ "$rc" -eq 77 ]; then echo "run-cell-script: prerequisite missing (exit 77) is never a pass in CI" >&2; exit 1; fi
RESULTS=$OUT/results.jsonl
[ -s "$RESULTS" ] || { echo "run-cell-script: missing results file: $RESULTS (rc=$rc)" >&2; exit 1; }
python3 -I "$REPO/scripts/ci/check-cell-results.py" "$RESULTS" "${EXPECTED[@]}" || exit 1
if [ "$rc" -ne 0 ]; then echo "run-cell-script: cell script exited $rc with passing results; exit must be 0" >&2; exit 1; fi
echo "run-cell-script: $NAME passed"

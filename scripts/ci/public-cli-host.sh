#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# public-cli-host.sh P11SCOPE OUTDIR: proof wrapper for the cell-script template.
# Runs the existing public-cli host cells (scripts/qualify-public-cli.sh) and
# leaves OUTDIR/results.jsonl for check-cell-results.py.
# Apt prerequisites: gcc jq procps python3 softhsm2 util-linux.
# Must run as root; the template wrapper calls this directly. Exit 0 means
# every qualified row passed, 1 means a cell failed, 2 means a harness
# error, 77 means a prerequisite is missing.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
REPO=$(cd "$HERE/../.." && pwd) || exit 2
if [ $# -ne 2 ]; then echo "usage: public-cli-host.sh P11SCOPE OUTDIR" >&2; exit 2; fi
P=$1; OUT=$2
[ -x "$P" ] || { echo "public-cli-host: no executable observer: $P" >&2; exit 2; }
if [ "$(id -u)" != 0 ]; then echo "public-cli-host: must run as root" >&2; exit 2; fi
for tool in gcc jq python3 softhsm2-util; do
  command -v "$tool" >/dev/null 2>&1 || { echo "public-cli-host: missing prerequisite: $tool" >&2; exit 77; }
done
mkdir -p "$OUT" || exit 2
OUT=$(cd "$OUT" && pwd) || exit 2
RUNUID=${RUNUID:-1000}; RUNGID=${RUNGID:-1000}
rc=0
RUNUID="$RUNUID" RUNGID="$RUNGID" "$REPO/scripts/qualify-public-cli.sh" "$P" "$OUT" || rc=$?
echo "qualify-public-cli rc=$rc"
[ -s "$OUT/results.jsonl" ] || { echo "public-cli-host: missing results.jsonl (rc=$rc)" >&2; exit 2; }
if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
  exit 0
fi
exit 1

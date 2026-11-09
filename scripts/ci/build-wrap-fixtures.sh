#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Build the diagnostics-wrap prebuilt32-object fixture for the privileged runner.
#
# Usage: scripts/ci/build-wrap-fixtures.sh OUTDIR
#        scripts/ci/build-wrap-fixtures.sh --self-test
#
# Runs tests/fixtures/operator-output/prepare-diagnostics-wrap.py with
# --out OUTDIR (an absolute path; any previous build there is replaced),
# which compiles the 97 inputs (32 common objects, 64 indexed providers
# and the workload driver) with cc and verifies them: 32 distinct
# physical targets bound to their held common FDs, exact indexed
# A_i/B_i linkage, a 192-call native ledger over a small schedule and
# the 96-call startup probe. Needs cc and python3.
# --self-test builds to a temporary dir and verifies the 97 outputs.
#
# Exit codes: 0 built and verified; 77 cc or python3 is missing (the
# last output line names the missing prerequisite); 1 a build or verify
# step failed; 2 bad usage.
set -uo pipefail

PROG=${0##*/}
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)

self_test() {
    work=$(mktemp -d) || exit 1
    trap 'rm -rf "$work"' EXIT
    rc=0
    "$0" "$work/prebuilt" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 77 ]; then
        echo "self-test SKIP: no cc or python3 on PATH"
        exit 77
    fi
    if [ "$rc" -ne 0 ]; then
        echo "self-test FAIL: build to $work/prebuilt exited $rc" >&2
        exit 1
    fi
    count=$(find "$work/prebuilt" -maxdepth 1 -type f | wc -l)
    if [ "$count" -ne 97 ]; then
        echo "self-test FAIL: $count regular files, want 97" >&2
        exit 1
    fi
    [ -x "$work/prebuilt/workload" ] || {
        echo "self-test FAIL: workload is not executable" >&2
        exit 1
    }
    echo "self-test: fixtures build and verify"
}

if [ "${1:-}" = "--self-test" ]; then
    shift
    [ $# -eq 0 ] || { echo "usage: $PROG --self-test" >&2; exit 2; }
    self_test
    exit $?
fi

if [ $# -ne 1 ]; then
    echo "usage: $PROG OUTDIR" >&2
    exit 2
fi
outdir=$1
case $outdir in
    /*) ;;
    *) echo "$PROG: OUTDIR must be absolute: $outdir" >&2; exit 2 ;;
esac

if ! command -v cc >/dev/null 2>&1; then
    echo "$PROG: no cc on PATH (apt: gcc)" >&2
    echo "missing: cc"
    exit 77
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "$PROG: no python3 on PATH (apt: python3)" >&2
    echo "missing: python3"
    exit 77
fi

parent=$(dirname "$outdir")
mkdir -p "$parent" || exit 1
rm -rf "$outdir" || exit 1
echo "build: $outdir (97 prebuilt32-object inputs)"
if ! python3 -I "$REPO_ROOT/tests/fixtures/operator-output/prepare-diagnostics-wrap.py" \
    --out "$outdir" >"$parent/wrap-fixtures-build.log" 2>&1; then
    echo "$PROG: fixture build failed, see $parent/wrap-fixtures-build.log" >&2
    exit 1
fi
count=$(find "$outdir" -maxdepth 1 -type f | wc -l)
if [ "$count" -ne 97 ]; then
    echo "$PROG: build left $count regular files, want 97" >&2
    exit 1
fi
[ -x "$outdir/workload" ] || {
    echo "$PROG: build left no executable workload" >&2
    exit 1
}
echo "fixtures ready in $outdir"

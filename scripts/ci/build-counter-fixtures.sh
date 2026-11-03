#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Build the counter-bank C fixtures for the privileged runner.
#
# Usage: scripts/ci/build-counter-fixtures.sh OUTDIR
#        scripts/ci/build-counter-fixtures.sh --self-test
#
# Compiles tests/fixtures/counter-banks.c and counter-bank-growth.c with
# cc (the same flags the in-repo fixture builders use: -std=c11 -O2
# -Wall -Wextra -Werror, plus -fPIC -shared -D..._PROVIDER for the
# providers and -ldl -lpthread for the drivers) into OUTDIR as:
#   counter-bank-provider.so counter-bank-driver
#   counter-bank-growth-provider.so counter-bank-growth-driver
# then smoke-tests both drivers (the bank READY/HELD/HOT/DONE protocol
# and the growth --self-test). Needs only cc (apt: gcc).
# --self-test builds to a temporary dir and verifies the four outputs.
#
# Exit codes: 0 built and smoke-tested; 77 cc is missing (the last
# output line names the missing prerequisite); 1 a build or smoke step
# failed; 2 bad usage.
set -uo pipefail

PROG=${0##*/}
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)

self_test() {
    work=$(mktemp -d) || exit 1
    trap 'rm -rf "$work"' EXIT
    rc=0
    "$0" "$work" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 77 ]; then
        echo "self-test SKIP: no cc on PATH"
        exit 77
    fi
    if [ "$rc" -ne 0 ]; then
        echo "self-test FAIL: build to $work exited $rc" >&2
        exit 1
    fi
    for f in counter-bank-provider.so counter-bank-driver \
        counter-bank-growth-provider.so counter-bank-growth-driver; do
        [ -s "$work/$f" ] || {
            echo "self-test FAIL: missing $f" >&2
            exit 1
        }
    done
    echo "self-test: fixtures build and smoke"
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
mkdir -p "$outdir" || exit 1
outdir=$(CDPATH='' cd "$outdir" && pwd) || exit 1

if ! command -v cc >/dev/null 2>&1; then
    echo "$PROG: no cc on PATH (apt: gcc)" >&2
    echo "missing: cc"
    exit 77
fi

build() {
    local src=$1 out=$2
    shift 2
    echo "build: $out"
    if ! cc -std=c11 -O2 -Wall -Wextra -Werror "$@" \
        "$REPO_ROOT/tests/fixtures/$src" -o "$outdir/$out"; then
        echo "$PROG: failed to build $out" >&2
        exit 1
    fi
    [ -s "$outdir/$out" ] || {
        echo "$PROG: build left no $out" >&2
        exit 1
    }
}

build counter-banks.c counter-bank-provider.so \
    -fPIC -shared -DCOUNTER_BANK_PROVIDER
build counter-banks.c counter-bank-driver -ldl -lpthread
build counter-bank-growth.c counter-bank-growth-provider.so \
    -fPIC -shared -DCOUNTER_BANK_GROWTH_PROVIDER
build counter-bank-growth.c counter-bank-growth-driver -ldl -lpthread

echo "smoke: counter-bank-driver protocol"
# No `-q`: under pipefail an early-exiting grep SIGPIPEs the driver and
# the pipeline returns 141 at random (the runner's binary_has_ignored
# failed this way). Without -q grep consumes the whole protocol.
if ! printf 'SHR' | "$outdir/counter-bank-driver" "$outdir/counter-bank-provider.so" \
    | grep -x 'DONE' >/dev/null; then
    echo "$PROG: counter-bank-driver smoke failed" >&2
    exit 1
fi
echo "smoke: counter-bank-growth-driver --self-test"
if ! "$outdir/counter-bank-growth-driver" --self-test \
    "$outdir/counter-bank-growth-provider.so" >/dev/null; then
    echo "$PROG: counter-bank-growth-driver --self-test failed" >&2
    exit 1
fi
echo "fixtures ready in $outdir"

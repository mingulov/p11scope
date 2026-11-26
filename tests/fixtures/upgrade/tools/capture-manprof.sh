#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Fixture capture helper: profile --pid --manifest with a given manifest.
# usage: capture-manprof.sh <observer-bin> <manifest> <tag> <outdir>
set -eu
BIN=$1; MANIFEST=$2; TAG=$3; OUT=$4
TMPDIR=${TMPDIR:-/var/tmp/p11scope-ws-tmp/v072-compat-071}
case $0 in */*) TOOLS_DIR=${0%/*};; *) TOOLS_DIR=.;; esac
# shellcheck source=capture-env.sh
. "$TOOLS_DIR/capture-env.sh"
PROV=$(probe_provider) || exit 2
export SOFTHSM2_CONF=$TMPDIR/f2/work/softhsm2.conf
ME=$(id -un)
LOCK="flock /var/tmp/p11scope-ws-tmp/privileged.lock"
rm -f $OUT/$TAG.mready
$TMPDIR/f2/bin/catalog-driver --ready $OUT/$TAG.mready --call --sleep 60 $PROV \
  </dev/null >$OUT/$TAG.manchor.log 2>&1 &
APID=$!
for i in $(seq 1 100); do
  [ -f $OUT/$TAG.mready ] && break
  sleep 0.1
done
[ -f $OUT/$TAG.mready ] || { echo "anchor never ready"; kill $APID; exit 3; }
echo "anchor pid=$APID manifest=$MANIFEST"
$LOCK sudo -n --preserve-env=TMPDIR $BIN profile --pid $APID --module $PROV \
  --manifest $MANIFEST --duration 6s -o $OUT/$TAG-manprof.json 2>$OUT/$TAG.manprof.stderr
echo "rc=$?"
$LOCK sudo -n chown $ME:$ME $OUT/$TAG-manprof.json
kill $APID 2>/dev/null || true
wait 2>/dev/null || true
ls -la $OUT/$TAG-manprof.json

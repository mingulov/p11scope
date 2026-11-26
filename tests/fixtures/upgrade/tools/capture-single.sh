#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Fixture capture helper: single-anchor
# inventory captures with a given observer binary.
# usage: capture-single.sh <observer-bin> <tag> <outdir>
set -eu
BIN=$1; TAG=$2; OUT=$3
TMPDIR=${TMPDIR:-/var/tmp/p11scope-ws-tmp/v072-compat-071}
case $0 in */*) TOOLS_DIR=${0%/*};; *) TOOLS_DIR=.;; esac
# shellcheck source=capture-env.sh
. "$TOOLS_DIR/capture-env.sh"
PROV=$(probe_provider) || exit 2
export SOFTHSM2_CONF=$TMPDIR/f2/work/softhsm2.conf
ME=$(id -un)
LOCK="flock /var/tmp/p11scope-ws-tmp/privileged.lock"

rm -f $OUT/$TAG.anchor.ready
$TMPDIR/f2/bin/catalog-driver --ready $OUT/$TAG.anchor.ready --call --sleep 120 $PROV \
  </dev/null >$OUT/$TAG.anchor.log 2>&1 &
APID=$!
for i in $(seq 1 100); do
  [ -f $OUT/$TAG.anchor.ready ] && break
  sleep 0.1
done
[ -f $OUT/$TAG.anchor.ready ] || { echo "anchor never ready"; kill $APID; exit 3; }
echo "anchor pid=$APID"

echo "== $TAG scan (unprivileged)"
$BIN inventory --pid $APID --module $PROV --capture scan -o $OUT/$TAG-inventory-scan.json 2>$OUT/$TAG.scan.stderr
echo "scan rc=$?"
echo "== $TAG native (root)"
$LOCK sudo -n --preserve-env=TMPDIR $BIN inventory --pid $APID --module $PROV \
  --capture native --duration 6s -o $OUT/$TAG-inventory-native.json 2>$OUT/$TAG.native.stderr
echo "native rc=$?"
$LOCK sudo -n chown $ME:$ME $OUT/$TAG-inventory-native.json
kill $APID 2>/dev/null || true
ANCHOR_RC=0
wait "$APID" 2>/dev/null || ANCHOR_RC=$?
case "$ANCHOR_RC" in
  0|143) ;;
  *) echo "$TAG single: anchor failed rc=$ANCHOR_RC" >&2; exit 1 ;;
esac
ls -la $OUT/$TAG-inventory-*.json

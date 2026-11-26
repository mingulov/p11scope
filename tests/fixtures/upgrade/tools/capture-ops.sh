#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Fixture capture helper: single signer
# anchor captures (key-operations inventory, profile, metrics).
# usage: capture-ops.sh <observer-bin> <tag> <mode> <outdir>
#   mode: keyops | profile | metrics
set -eu
BIN=$1; TAG=$2; MODE=$3; OUT=$4
TMPDIR=${TMPDIR:-/var/tmp/p11scope-ws-tmp/v072-compat-071}
PROV=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
export SOFTHSM2_CONF=$TMPDIR/f2/work/softhsm2.conf
ME=$(id -un)
LOCK="flock /var/tmp/p11scope-ws-tmp/privileged.lock"

case $MODE in
  keyops) ANCHOR="$TMPDIR/f2/bin/steady-keys $PROV 1234 45 ${HEXID:-d200}"; DUR=48s;;
  *) ANCHOR="$TMPDIR/f2/bin/shortlived-sign $PROV 1234 3000 30 500"; DUR=20s;;
esac
if [ "$MODE" = "keyops" ]; then
  export STEADY_GO=$OUT/$TAG.go
  rm -f $STEADY_GO
fi
$ANCHOR >$OUT/$TAG.$MODE.sign.log 2>&1 &
APID=$!
sleep 0.5
echo "anchor pid=$APID mode=$MODE"
case $MODE in
  keyops)
    export STEADY_GO=$OUT/$TAG.go
    rm -f $STEADY_GO
    $LOCK sudo -n --preserve-env=TMPDIR $BIN inventory --pid $APID --module $PROV \
      --capture native --key-operations --manifest $OUT/v071-manifest-softhsm.json --duration $DUR -o $OUT/$TAG-inventory-keyops.json \
      2>$OUT/$TAG.$MODE.stderr &
    OPID=$!
    for i in $(seq 1 600); do
      grep -q "semantic lane ready" $OUT/$TAG.$MODE.stderr 2>/dev/null && break
      sleep 0.2
    done
    grep -q "semantic lane ready" $OUT/$TAG.$MODE.stderr || echo "WARNING: semantic lane never ready"
    touch $STEADY_GO
    wait $OPID
    echo "rc=$?"
    $LOCK sudo -n chown $ME:$ME $OUT/$TAG-inventory-keyops.json
    ;;
  profile)
    $LOCK sudo -n --preserve-env=TMPDIR $BIN profile --pid $APID --module $PROV \
      --duration $DUR -o $OUT/$TAG-observed-profile.json 2>$OUT/$TAG.$MODE.stderr
    echo "rc=$?"
    $LOCK sudo -n chown $ME:$ME $OUT/$TAG-observed-profile.json
    ;;
  metrics)
    $LOCK sudo -n --preserve-env=TMPDIR $BIN profile --pid $APID --module $PROV \
      --mode metrics --duration $DUR -o $OUT/$TAG-observed-metrics.json 2>$OUT/$TAG.$MODE.stderr
    echo "rc=$?"
    $LOCK sudo -n chown $ME:$ME $OUT/$TAG-observed-metrics.json
    ;;
esac
wait $APID 2>/dev/null || true
ls -la $OUT/$TAG-*.json

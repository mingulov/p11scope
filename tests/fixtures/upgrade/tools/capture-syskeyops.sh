#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Fixture capture helper: --system key-operations capture with a gated
# steady-keys anchor.
# usage: capture-syskeyops.sh <observer-bin> <tag> <outdir>
set -eu
BIN=$1; TAG=$2; OUT=$3
TMPDIR=/var/tmp/p11scope-ws-tmp/v072-compat-071
PROV=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
export SOFTHSM2_CONF=$TMPDIR/f2/work/softhsm2.conf
export STEADY_GO=$OUT/$TAG.sysgo
ME=$(id -un)
LOCK="flock /var/tmp/p11scope-ws-tmp/privileged.lock"
rm -f $STEADY_GO
$TMPDIR/f2/bin/steady-keys $PROV 1234 90 ${HEXID:-e100} >$OUT/$TAG.syskeyops.sign.log 2>&1 &
APID=$!
sleep 1
echo "anchor pid=$APID"
$LOCK sudo -n --preserve-env=TMPDIR $BIN inventory --system --module $PROV \
  --capture native --key-operations --manifest $OUT/v071-manifest-softhsm.json \
  --duration 60s -o $OUT/$TAG-inventory-syskeyops.json 2>$OUT/$TAG.syskeyops.stderr &
OPID=$!
for i in $(seq 1 600); do
  grep -q "semantic lane ready" $OUT/$TAG.syskeyops.stderr 2>/dev/null && break
  sleep 0.2
done
grep -q "semantic lane ready" $OUT/$TAG.syskeyops.stderr || echo "WARNING: semantic lane never ready"
touch $STEADY_GO
wait $OPID
echo "rc=$?"
$LOCK sudo -n chown $ME:$ME $OUT/$TAG-inventory-syskeyops.json
kill $APID 2>/dev/null || true
wait 2>/dev/null || true
ls -la $OUT/$TAG-inventory-syskeyops.json

#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Fixture capture helper: --system key-operations capture with a gated
# steady-keys anchor.
# usage: capture-syskeyops.sh <observer-bin> <tag> <outdir>
set -eu
BIN=$1; TAG=$2; OUT=$3
TMPDIR=${TMPDIR:-/var/tmp/p11scope-ws-tmp/v072-compat-071}
case $0 in */*) TOOLS_DIR=${0%/*};; *) TOOLS_DIR=.;; esac
# shellcheck source=capture-env.sh
. "$TOOLS_DIR/capture-env.sh"
PROV=$(probe_provider) || exit 2
export SOFTHSM2_CONF=$TMPDIR/f2/work/softhsm2.conf
export STEADY_GO=$OUT/$TAG.sysgo
ME=$(id -un)
LOCK="flock /var/tmp/p11scope-ws-tmp/privileged.lock"
rm -f $STEADY_GO
$TMPDIR/f2/bin/steady-keys $PROV 1234 45 ${HEXID:-e100} >$OUT/$TAG.syskeyops.sign.log 2>&1 &
APID=$!
sleep 1
echo "anchor pid=$APID"
$LOCK sudo -n --preserve-env=TMPDIR $BIN inventory --system --module $PROV \
  --capture native --key-operations --manifest $OUT/v071-manifest-softhsm.json \
  --duration 60s -o $OUT/$TAG-inventory-syskeyops.json 2>$OUT/$TAG.syskeyops.stderr &
OPID=$!
for i in $(seq 1 ${READY_BUDGET:-600}); do
  grep -q "semantic lane ready" $OUT/$TAG.syskeyops.stderr 2>/dev/null && break
  sleep 0.2
done
READY_SEEN=0
if grep -q "semantic lane ready" $OUT/$TAG.syskeyops.stderr 2>/dev/null; then
  READY_SEEN=1
  touch "$STEADY_GO"
else
  echo "syskeyops: semantic lane never ready; gate left untouched" >&2
fi
wait $OPID
echo "rc=$?"
$LOCK sudo -n chown $ME:$ME $OUT/$TAG-inventory-syskeyops.json
ANCHOR_RC=0
wait "$APID" 2>/dev/null || ANCHOR_RC=$?
if [ "$ANCHOR_RC" -ne 0 ]; then
  echo "$TAG syskeyops: anchor failed rc=$ANCHOR_RC" >&2
  exit 1
fi
if [ "$READY_SEEN" != 1 ]; then
  echo "$TAG syskeyops: semantic lane never ready" >&2
  exit 1
fi
ls -la $OUT/$TAG-inventory-syskeyops.json

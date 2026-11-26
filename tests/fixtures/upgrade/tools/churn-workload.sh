#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Churn workload for capture-churn.sh: one long-lived anchor plus
# eight staggered short-lived signers.
# usage: churn-workload.sh <outdir> <tag> <bindir> <provider>
# SOFTHSM2_CONF must be exported. Exit nonzero when the anchor never
# becomes ready or any signer fails; the anchor itself is killed by
# design and its status is ignored.
set -eu
OUT=$1; TAG=$2; BIN=$3; PROV=$4
read _ < $OUT/$TAG.go
rm -f $OUT/$TAG.anchor.ready
$BIN/catalog-driver --ready $OUT/$TAG.anchor.ready --call --sleep 60 $PROV &
APID=$!
for i in $(seq 1 100); do
  [ -f $OUT/$TAG.anchor.ready ] && break
  sleep 0.1
done
[ -f $OUT/$TAG.anchor.ready ] || { echo "anchor never ready"; kill $APID; exit 3; }
echo "anchor pid=$APID"
SIGNERS=""
for i in 1 2 3 4 5 6 7 8; do
  sleep 2
  $BIN/shortlived-sign $PROV 1234 800 3 100 >$OUT/$TAG.sign-$i.log 2>&1 &
  SIGNERS="$SIGNERS $!"
done
sleep 16
SIGNER_RC=0
for pid in $SIGNERS; do
  wait $pid 2>/dev/null || SIGNER_RC=$?
done
kill $APID 2>/dev/null || true
wait 2>/dev/null || true
if [ "$SIGNER_RC" -ne 0 ]; then
  echo "signer failed rc=$SIGNER_RC" >&2
  exit 3
fi
echo workload-done

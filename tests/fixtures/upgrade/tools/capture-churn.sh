#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Fixture capture helper: cgroup churn
# capture (one long-lived anchor plus staggered short-lived signers)
# with a given observer binary.
# usage: capture-churn.sh <observer-bin> <tag> <outdir>
set -eu
BIN=$1; TAG=$2; OUT=$3
TMPDIR=${TMPDIR:-/var/tmp/p11scope-ws-tmp/v072-compat-071}
case $0 in */*) TOOLS_DIR=${0%/*};; *) TOOLS_DIR=.;; esac
# shellcheck source=capture-env.sh
. "$TOOLS_DIR/capture-env.sh"
PROV=$(probe_provider) || exit 2
export SOFTHSM2_CONF=$TMPDIR/f2/work/softhsm2.conf
ME=$(id -un)
CG=${CG:-/sys/fs/cgroup/p11compat071}
LOCK="flock /var/tmp/p11scope-ws-tmp/privileged.lock"

$LOCK sudo -n sh -c "mkdir -p $CG"
rm -f $OUT/$TAG.anchor.ready $OUT/$TAG.go
mkfifo $OUT/$TAG.go

"$TOOLS_DIR/churn-workload.sh" "$OUT" "$TAG" "$TMPDIR/f2/bin" "$PROV" >$OUT/$TAG.workload.log 2>&1 &
WPID=$!
# Root places the waiting launcher; everything it spawns inherits the cgroup.
$LOCK sudo -n sh -c "echo $WPID > $CG/cgroup.procs"
cat $CG/cgroup.procs
echo go > $OUT/$TAG.go
for i in $(seq 1 100); do
  [ -f $OUT/$TAG.anchor.ready ] && break
  sleep 0.1
done
[ -f $OUT/$TAG.anchor.ready ] || { echo "anchor never ready"; kill $WPID; exit 3; }
sleep 1
echo "== $TAG churn (root, 24s)"
$LOCK sudo -n --preserve-env=TMPDIR $BIN inventory --cgroup $CG --module $PROV \
  --capture native --duration 24s -o $OUT/$TAG-inventory-churn.json 2>$OUT/$TAG.churn.stderr
echo "churn rc=$?"
$LOCK sudo -n chown $ME:$ME $OUT/$TAG-inventory-churn.json
wait $WPID
rm -f $OUT/$TAG.go
$LOCK sudo -n rmdir $CG
ls -la $OUT/$TAG-inventory-churn.json

#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Fixture capture helper: cgroup
# --key-operations capture with mid-run key creation.
# usage: capture-keyops.sh <observer-bin> <tag> <outdir>
set -eu
BIN=$1; TAG=$2; OUT=$3
TMPDIR=${TMPDIR:-/var/tmp/p11scope-ws-tmp/v072-compat-071}
PROV=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
export SOFTHSM2_CONF=$TMPDIR/f2/work/softhsm2.conf
ME=$(id -un)
CG=/sys/fs/cgroup/p11compat071
LOCK="flock /var/tmp/p11scope-ws-tmp/privileged.lock"
HEXID=${HEXID:-b302}

$LOCK sudo -n sh -c "mkdir -p $CG"
rm -f $OUT/$TAG.anchor.ready $OUT/$TAG.go
mkfifo $OUT/$TAG.go

cat > $OUT/$TAG.workload.sh <<EOF
#!/bin/sh
set -eu
read _ < $OUT/$TAG.go
export SOFTHSM2_CONF=$SOFTHSM2_CONF
rm -f $OUT/$TAG.anchor.ready
$TMPDIR/f2/bin/catalog-driver --ready $OUT/$TAG.anchor.ready --call --sleep 60 $PROV &
APID=\$!
for i in \$(seq 1 100); do
  [ -f $OUT/$TAG.anchor.ready ] && break
  sleep 0.1
done
[ -f $OUT/$TAG.anchor.ready ] || { echo "anchor never ready"; kill \$APID; exit 3; }
echo "anchor pid=\$APID"
sleep 6
$TMPDIR/f2/bin/creator $PROV 1234 $HEXID >$OUT/$TAG.create.log 2>&1
sleep 3
$TMPDIR/f2/bin/shortlived-sign $PROV 1234 500 3 100 >$OUT/$TAG.sign-1.log 2>&1
sleep 3
$TMPDIR/f2/bin/shortlived-sign $PROV 1234 500 3 100 >$OUT/$TAG.sign-2.log 2>&1
sleep 6
kill \$APID 2>/dev/null || true
wait 2>/dev/null || true
echo workload-done
EOF
chmod +x $OUT/$TAG.workload.sh
sh $OUT/$TAG.workload.sh >$OUT/$TAG.workload.log 2>&1 &
WPID=$!
$LOCK sudo -n sh -c "echo $WPID > $CG/cgroup.procs"
echo go > $OUT/$TAG.go
for i in $(seq 1 100); do
  [ -f $OUT/$TAG.anchor.ready ] && break
  sleep 0.1
done
[ -f $OUT/$TAG.anchor.ready ] || { echo "anchor never ready"; kill $WPID; exit 3; }
sleep 1
echo "== $TAG keyops (root, 22s)"
$LOCK sudo -n --preserve-env=TMPDIR $BIN inventory --cgroup $CG --module $PROV \
  --capture native --key-operations --duration 22s -o $OUT/$TAG-inventory-keyops.json \
  2>$OUT/$TAG.keyops.stderr
echo "keyops rc=$?"
$LOCK sudo -n chown $ME:$ME $OUT/$TAG-inventory-keyops.json
wait $WPID
rm -f $OUT/$TAG.go
$LOCK sudo -n rmdir $CG
ls -la $OUT/$TAG-inventory-keyops.json
